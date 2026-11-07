#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <CoreFoundation/CoreFoundation.h>
#import <mach/mach.h>
#import <sys/utsname.h>
#import <sys/sysctl.h>
#import <dlfcn.h>
#import <fcntl.h>
#import <unistd.h>
#import <stdint.h>
#import <stdio.h>
#import <string.h>

// Adaptacion controlada de la idea de fuzzing IOKit de dawgyg/AppleResearch.
// No comparte conexiones entre hilos, no prueba punteros liberados, no intenta KernelRW.
// IOKit se resuelve dinamicamente porque sus cabeceras son privadas en el SDK iOS.
// API publica IOSurface: los SDK iOS no siempre publican <IOSurface/IOSurface.h>.
typedef struct __IOSurface *LabSurfaceRef;
typedef LabSurfaceRef (*LabCreateSurface)(CFDictionaryRef);
typedef uint32_t (*LabGetSurfaceID)(LabSurfaceRef);
typedef LabSurfaceRef (*LabLookupSurface)(uint32_t);
typedef size_t (*LabSurfaceDimension)(LabSurfaceRef);
typedef kern_return_t (*LabSurfaceLock)(LabSurfaceRef, uint32_t, uint32_t *);

typedef uint32_t lab_io_object_t;
typedef lab_io_object_t lab_io_service_t;
typedef lab_io_object_t lab_io_connect_t;
typedef CFMutableDictionaryRef (*LabMatching)(const char *);
typedef lab_io_service_t (*LabGetService)(mach_port_t, CFDictionaryRef);
typedef kern_return_t (*LabOpen)(lab_io_service_t, task_t, uint32_t, lab_io_connect_t *);
typedef kern_return_t (*LabClose)(lab_io_connect_t);
typedef kern_return_t (*LabRelease)(lab_io_object_t);
typedef kern_return_t (*LabCall)(lab_io_connect_t, uint32_t, const uint64_t *,
                                  uint32_t, const void *, size_t, uint64_t *,
                                  uint32_t *, void *, size_t *);

typedef struct {
    LabMatching matching;
    LabGetService get;
    LabOpen open;
    LabClose close;
    LabRelease release;
    LabCall call;
} LabIO;

static LabIO labLoadIO(void) {
    LabIO f = {0};
    void *lib = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit",
                      RTLD_LAZY | RTLD_LOCAL);
    if (!lib) return f;
    f.matching = (LabMatching)dlsym(lib, "IOServiceMatching");
    f.get = (LabGetService)dlsym(lib, "IOServiceGetMatchingService");
    f.open = (LabOpen)dlsym(lib, "IOServiceOpen");
    f.close = (LabClose)dlsym(lib, "IOServiceClose");
    f.release = (LabRelease)dlsym(lib, "IOObjectRelease");
    f.call = (LabCall)dlsym(lib, "IOConnectCallMethod");
    return f;
}

static BOOL labCanDiscover(LabIO f) {
    return f.matching && f.get && f.open && f.close && f.release;
}

static const char *const labRegistryServices[] = {
    "IOSurfaceRoot",        // La clase real del servicio; NO IOSurfaceRootUserClient.
    "AGXAccelerator",
    "AppleH13CamIn",
    "AppleH16CamIn",
    "H11ANEInDirectPathClient",
    "IOMobileFramebuffer",
    "AppleJPEGDriver",
    "AppleAVE2Driver",
    "AppleM2ScalerCSCDriver",
    "IOAccelerator",
    "AppleCLCD",
    "AppleKeyStore",
    NULL
};

static NSString *labKernelBuild(void) {
    char buf[256] = {0};
    size_t len = sizeof(buf);
    if (sysctlbyname("kern.osversion", buf, &len, NULL, 0) != 0) return @"UNAVAILABLE";
    return [NSString stringWithUTF8String:buf] ?: @"UNAVAILABLE";
}

static NSString *labMachine(void) {
    struct utsname u = {0};
    if (uname(&u) != 0) return @"UNAVAILABLE";
    return [NSString stringWithUTF8String:u.machine] ?: @"UNAVAILABLE";
}

static NSString *labHex(kern_return_t kr) {
    return [NSString stringWithFormat:@"0x%08x", (unsigned int)kr];
}

static NSString *labErrorName(kern_return_t kr) {
    switch ((uint32_t)kr) {
        case 0: return @"kIOReturnSuccess";
        case 0xe00002bc: return @"kIOReturnError";
        case 0xe00002bd: return @"kIOReturnNoMemory";
        case 0xe00002c1: return @"kIOReturnNotPrivileged";
        case 0xe00002c2: return @"kIOReturnBadArgument";
        case 0xe00002c7: return @"kIOReturnUnsupported";
        default: return @"OTHER";
    }
}

static uint64_t labDigest(const uint8_t *data, size_t length) {
    uint64_t h = 14695981039346656037ULL;
    for (size_t i = 0; i < length; i++) {
        h ^= data[i];
        h *= 1099511628211ULL;
    }
    return h;
}

@interface AppleIOKitLabController : UIViewController
@property(nonatomic, strong) UITextView *logView;
@property(nonatomic, strong) UILabel *selectedLabel;
@property(nonatomic, strong) NSMutableString *logText;
@property(nonatomic, copy) NSArray<NSString *> *openServices;
@property(nonatomic, copy) NSString *selectedService;
@property(atomic, assign) BOOL running;
@property(atomic, assign) BOOL stopRequested;
- (void)contractTapped:(id)sender;
- (void)directRoundTripTapped:(id)sender;
@end

@implementation AppleIOKitLabController

- (NSURL *)document:(NSString *)name {
    NSURL *dir = [[[NSFileManager defaultManager] URLsForDirectory:NSDocumentDirectory
                                                         inDomains:NSUserDomainMask] firstObject];
    return [dir URLByAppendingPathComponent:name];
}

- (void)saveJSON:(NSDictionary *)payload as:(NSString *)name {
    if (!payload) return;
    NSError *err = nil;
    NSData *data = [NSJSONSerialization dataWithJSONObject:payload
                                                   options:NSJSONWritingPrettyPrinted error:&err];
    if (!data || err) return;
    NSURL *target = [self document:name];
    if (![data writeToURL:target options:NSDataWritingAtomic error:&err]) return;
    // Checkpoint emitido ANTES de la llamada: durabilidad mejorada, no garantizada.
    int fd = open(target.fileSystemRepresentation, O_RDONLY);
    if (fd >= 0) { fsync(fd); close(fd); }
}

- (NSDictionary *)readJSON:(NSString *)name {
    NSData *data = [NSData dataWithContentsOfURL:[self document:name]];
    if (!data) return nil;
    id v = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
    return [v isKindOfClass:NSDictionary.class] ? v : nil;
}

- (void)log:(NSString *)message {
    if (![NSThread isMainThread]) {
        dispatch_async(dispatch_get_main_queue(), ^{ [self log:message]; });
        return;
    }
    NSString *line = [NSString stringWithFormat:@"%@  %@\n",
                      [NSDateFormatter localizedStringFromDate:[NSDate date]
                                                     dateStyle:NSDateFormatterNoStyle
                                                     timeStyle:NSDateFormatterMediumStyle],
                      message];
    [self.logText appendString:line];
    self.logView.text = self.logText;
    if (self.logText.length) {
        [self.logView scrollRangeToVisible:NSMakeRange(self.logText.length - 1, 1)];
    }
    [self.logText writeToURL:[self document:@"AppleIOKitLab-session.txt"]
                 atomically:YES encoding:NSUTF8StringEncoding error:nil];
}

- (UIButton *)button:(NSString *)label selector:(SEL)selector {
    UIButton *b = [UIButton buttonWithType:UIButtonTypeSystem];
    [b setTitle:label forState:UIControlStateNormal];
    b.titleLabel.font = [UIFont systemFontOfSize:16 weight:UIFontWeightSemibold];
    b.titleLabel.numberOfLines = 0;
    [b addTarget:self action:selector forControlEvents:UIControlEventTouchUpInside];
    [b.heightAnchor constraintEqualToConstant:50].active = YES;
    b.backgroundColor = UIColor.secondarySystemBackgroundColor;
    b.layer.cornerRadius = 10;
    return b;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = UIColor.systemBackgroundColor;
    self.logText = [NSMutableString new];
    self.openServices = @[];
    self.selectedService = @"";

    UILabel *title = [UILabel new];
    title.text = @"Apple IOKit Lab · v1.4";
    title.font = [UIFont boldSystemFontOfSize:25];

    UILabel *summary = [UILabel new];
    summary.text = @"Inventario real + llamadas IOKit acotadas. No es jailbreak. "
                   @"La prueba activa puede provocar un reinicio del dispositivo.";
    summary.numberOfLines = 0;
    summary.font = [UIFont systemFontOfSize:14];
    summary.textColor = UIColor.secondaryLabelColor;

    self.selectedLabel = [UILabel new];
    self.selectedLabel.text = @"Servicio: ninguno (primero inventariar)";
    self.selectedLabel.numberOfLines = 0;
    self.selectedLabel.font = [UIFont monospacedSystemFontOfSize:12 weight:UIFontWeightMedium];

    self.logView = [UITextView new];
    self.logView.editable = NO;
    self.logView.selectable = YES;
    self.logView.font = [UIFont monospacedSystemFontOfSize:11 weight:UIFontWeightRegular];
    self.logView.layer.borderColor = UIColor.separatorColor.CGColor;
    self.logView.layer.borderWidth = 1;
    self.logView.layer.cornerRadius = 8;
    [self.logView.heightAnchor constraintEqualToConstant:290].active = YES;

    UIStackView *stack = [[UIStackView alloc] initWithArrangedSubviews:@[
        title, summary, self.selectedLabel,
        [self button:@"1. Inventariar servicios y permisos reales" selector:@selector(inventoryTapped:)],
        [self button:@"2. Baseline pública IOSurface (64x64)" selector:@selector(publicBaselineTapped:)],
        [self button:@"3. Contrato IOSurface (selector 13, una consulta)" selector:@selector(contractTapped:)],
        [self button:@"4. Prueba funcional real: crear y leer superficie" selector:@selector(directRoundTripTapped:)],
        [self button:@"5. Elegir controlador accesible" selector:@selector(chooseTapped:)],
        [self button:@"6. Campaña legacy: 16 llamadas malformadas" selector:@selector(campaignTapped:)],
        [self button:@"7. Reproducir último caso legacy" selector:@selector(replayTapped:)],
        [self button:@"Detener entre casos" selector:@selector(stopTapped:)],
        [self button:@"Exportar CSV + JSON + registro" selector:@selector(exportTapped:)],
        self.logView
    ]];
    stack.axis = UILayoutConstraintAxisVertical;
    stack.spacing = 12;
    stack.translatesAutoresizingMaskIntoConstraints = NO;

    UIScrollView *scroll = [UIScrollView new];
    scroll.translatesAutoresizingMaskIntoConstraints = NO;
    [scroll addSubview:stack];
    [self.view addSubview:scroll];
    UILayoutGuide *safe = self.view.safeAreaLayoutGuide;
    [NSLayoutConstraint activateConstraints:@[
        [scroll.topAnchor constraintEqualToAnchor:safe.topAnchor],
        [scroll.bottomAnchor constraintEqualToAnchor:safe.bottomAnchor],
        [scroll.leadingAnchor constraintEqualToAnchor:safe.leadingAnchor],
        [scroll.trailingAnchor constraintEqualToAnchor:safe.trailingAnchor],
        [stack.topAnchor constraintEqualToAnchor:scroll.contentLayoutGuide.topAnchor constant:12],
        [stack.bottomAnchor constraintEqualToAnchor:scroll.contentLayoutGuide.bottomAnchor constant:-16],
        [stack.leadingAnchor constraintEqualToAnchor:scroll.contentLayoutGuide.leadingAnchor constant:16],
        [stack.trailingAnchor constraintEqualToAnchor:scroll.contentLayoutGuide.trailingAnchor constant:-16],
        [stack.widthAnchor constraintEqualToAnchor:scroll.frameLayoutGuide.widthAnchor constant:-32]
    ]];

    [self log:[NSString stringWithFormat:@"Dispositivo: %@; iOS %@; build %@",
               labMachine(), UIDevice.currentDevice.systemVersion, labKernelBuild()]];
    NSDictionary *old = [self readJSON:@"AppleIOKitLab-checkpoint.json"];
    if ([old[@"phase"] isEqualToString:@"IN_FLIGHT"]) {
        [self log:[NSString stringWithFormat:
            @"Ejecución anterior interrumpida: servicio=%@ caso=%@ selector=%@. "
             "No confirma kernel panic; revisar Analytics Data para clasificar.",
            old[@"service"], old[@"case"], old[@"selector"]]];
    }
    [self log:@"El modo de inventario no invoca métodos externos."];
}

- (void)inventoryTapped:(id)sender {
    if (self.running) { [self log:@"Otra tarea está en curso."]; return; }
    self.running = YES;
    [self log:@"Inventariando 12 clases de servicio (matching, open tipo 0, close)."];
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        LabIO f = labLoadIO();
        if (!labCanDiscover(f)) {
            [self log:@"IOKit no expone funciones de descubrimiento. Sin pruebas."];
            dispatch_async(dispatch_get_main_queue(), ^{ self.running = NO; });
            return;
        }
        NSMutableArray *rows = [NSMutableArray new];
        NSMutableArray<NSString *> *openable = [NSMutableArray new];
        for (unsigned i = 0; labRegistryServices[i]; i++) {
            NSString *name = [NSString stringWithUTF8String:labRegistryServices[i]];
            lab_io_service_t svc = f.get(MACH_PORT_NULL, f.matching(labRegistryServices[i]));
            BOOL present = (svc != MACH_PORT_NULL);
            kern_return_t openKr = KERN_FAILURE;
            if (present) {
                lab_io_connect_t cn = MACH_PORT_NULL;
                openKr = f.open(svc, mach_task_self(), 0, &cn);
                if (openKr == KERN_SUCCESS && cn != MACH_PORT_NULL) {
                    [openable addObject:name];
                    f.close(cn);
                }
                f.release(svc);
            }
            [rows addObject:@{
                @"registryService":name,
                @"matched":@(present),
                @"openType0":present ? labHex(openKr) : @"N/A",
                @"openable":@((openKr == KERN_SUCCESS) && present)
            }];
            [self log:[NSString stringWithFormat:@"%@ match=%@ open=%@",
                name, present ? @"YES" : @"NO", present ? labHex(openKr) : @"N/A"]];
        }
        [self saveJSON:@{
            @"schema":@"AppleIOKitLab.inventory.v1",
            @"device":labMachine(), @"iOS":UIDevice.currentDevice.systemVersion,
            @"build":labKernelBuild(), @"services":rows
        } as:@"AppleIOKitLab-inventory.json"];
        dispatch_async(dispatch_get_main_queue(), ^{
            self.openServices = [openable copy];
            self.selectedService =
                [openable containsObject:@"IOSurfaceRoot"] ? @"IOSurfaceRoot" :
                (openable.firstObject ?: @"");
            self.selectedLabel.text = self.selectedService.length
                ? [@"Servicio seleccionado: " stringByAppendingString:self.selectedService]
                : @"No se encontró un servicio abierto por la app.";
            self.running = NO;
            [self log:[NSString stringWithFormat:@"Inventario terminado: %lu accesibles.",
                       (unsigned long)openable.count]];
        });
    });
}


- (void)publicBaselineTapped:(id)sender {
    if (self.running) { [self log:@"Ya hay otra prueba en curso."]; return; }
    self.running = YES;
    [self log:@"Baseline: API pública IOSurface 64x64, sin métodos IOKit privados."];

    void *lib = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface",
                       RTLD_LAZY | RTLD_LOCAL);
    LabCreateSurface createSurface = lib ? (LabCreateSurface)dlsym(lib, "IOSurfaceCreate") : NULL;
    LabGetSurfaceID getID = lib ? (LabGetSurfaceID)dlsym(lib, "IOSurfaceGetID") : NULL;
    LabLookupSurface lookup = lib ? (LabLookupSurface)dlsym(lib, "IOSurfaceLookup") : NULL;
    LabSurfaceDimension getWidth = lib ? (LabSurfaceDimension)dlsym(lib, "IOSurfaceGetWidth") : NULL;
    LabSurfaceDimension getHeight = lib ? (LabSurfaceDimension)dlsym(lib, "IOSurfaceGetHeight") : NULL;
    LabSurfaceDimension getAllocSize = lib ? (LabSurfaceDimension)dlsym(lib, "IOSurfaceGetAllocSize") : NULL;
    LabSurfaceLock lockSurface = lib ? (LabSurfaceLock)dlsym(lib, "IOSurfaceLock") : NULL;
    LabSurfaceLock unlockSurface = lib ? (LabSurfaceLock)dlsym(lib, "IOSurfaceUnlock") : NULL;

    NSMutableDictionary *result = [@{
        @"schema":@"AppleIOKitLab.publicBaseline.v1",
        @"device":labMachine(), @"iOS":UIDevice.currentDevice.systemVersion,
        @"build":labKernelBuild(), @"created":@NO
    } mutableCopy];
    if (!createSurface || !getID || !lookup || !getWidth || !getHeight ||
        !getAllocSize || !lockSurface || !unlockSurface) {
        result[@"error"] = @"IOSurface.framework unavailable or missing public exports";
        [self log:@"Faltan funciones públicas de IOSurface en el dispositivo."];
    } else {
        NSDictionary *properties = @{
            @"IOSurfaceWidth": @64,
            @"IOSurfaceHeight": @64,
            @"IOSurfaceBytesPerElement": @4,
            @"IOSurfaceBytesPerRow": @256,
            @"IOSurfaceAllocSize": @(64 * 64 * 4),
            @"IOSurfacePixelFormat": @(0x42475241u)
        };
        LabSurfaceRef surface = createSurface((__bridge CFDictionaryRef)properties);
        if (surface) {
            result[@"created"] = @YES;
            uint32_t surfaceID = getID(surface);
            result[@"id"] = @(surfaceID);
            result[@"width"] = @(getWidth(surface));
            result[@"height"] = @(getHeight(surface));
            result[@"allocBytes"] = @(getAllocSize(surface));
            uint32_t seed = 0;
            kern_return_t kr = lockSurface(surface, 0, &seed);
            result[@"lockKR"] = labHex(kr);
            if (kr == KERN_SUCCESS)
                result[@"unlockKR"] = labHex(unlockSurface(surface, 0, &seed));
            LabSurfaceRef found = lookup(surfaceID);
            result[@"lookupOwnID"] = @(found != NULL);
            if (found) CFRelease(found);
            CFRelease(surface);
            [self log:[NSString stringWithFormat:
                 @"Baseline: %lux%lu lock=%@ lookupID=%@",
                 (unsigned long)[result[@"width"] unsignedIntegerValue],
                 (unsigned long)[result[@"height"] unsignedIntegerValue],
                 result[@"lockKR"], [result[@"lookupOwnID"] boolValue] ? @"OK" : @"NO"]];
        } else {
            result[@"error"] = @"IOSurfaceCreate returned NULL";
            [self log:@"IOSurfaceCreate devolvió NULL con parámetros públicos válidos."];
        }
    }
    [self saveJSON:result as:@"AppleIOKitLab-public-baseline.json"];
    if (lib) dlclose(lib);
    [self log:@"Baseline exportable; no demuestra acceso arbitrario al kernel."];
    self.running = NO;
}

- (void)chooseTapped:(id)sender {
    if (self.running) { [self log:@"Detén o termina la tarea actual."]; return; }
    if (!self.openServices.count) { [self log:@"Primero ejecuta inventario."]; return; }
    UIAlertController *panel = [UIAlertController alertControllerWithTitle:@"Seleccionar servicio"
        message:@"Solo se muestran servicios abiertos con éxito desde esta app."
        preferredStyle:UIAlertControllerStyleActionSheet];
    for (NSString *name in self.openServices) {
        [panel addAction:[UIAlertAction actionWithTitle:name style:UIAlertActionStyleDefault handler:^(UIAlertAction *a) {
            self.selectedService = name;
            self.selectedLabel.text = [@"Servicio seleccionado: " stringByAppendingString:name];
            [self log:[@"Seleccionado: " stringByAppendingString:name]];
        }]];
    }
    [panel addAction:[UIAlertAction actionWithTitle:@"Cancelar" style:UIAlertActionStyleCancel handler:nil]];
    panel.popoverPresentationController.sourceView = self.view;
    panel.popoverPresentationController.sourceRect = CGRectMake(self.view.bounds.size.width / 2, 120, 1, 1);
    [self presentViewController:panel animated:YES completion:nil];
}

- (void)appendCSVRun:(NSString *)run service:(NSString *)service index:(NSInteger)index
             selector:(uint32_t)sel mode:(unsigned)mode stage:(NSString *)stage
              match:(BOOL)matched openKR:(kern_return_t)openKr
             callKR:(kern_return_t)callKr outputCount:(uint32_t)count
          outputSize:(size_t)size digest:(uint64_t)digest {
    NSString *path = [self document:@"AppleIOKitLab-trace.csv"].path;
    BOOL exists = [[NSFileManager defaultManager] fileExistsAtPath:path];
    FILE *fp = fopen(path.fileSystemRepresentation, "a");
    if (!fp) return;
    if (!exists) {
        fprintf(fp, "timestamp_ms,run_id,service,case,selector,mode,stage,matched,open_kr,call_kr,out_scalars,out_bytes,output_hash\n");
    }
    uint64_t timestamp = (uint64_t)([NSDate.date timeIntervalSince1970] * 1000.0);
    fprintf(fp, "%llu,%s,%s,%ld,%u,%u,%s,%d,0x%08x,0x%08x,%u,%zu,%016llx\n",
            (unsigned long long)timestamp, run.UTF8String, service.UTF8String,
            (long)index, sel, mode, stage.UTF8String, matched ? 1 : 0,
            (unsigned int)openKr, (unsigned int)callKr, count, size,
            (unsigned long long)digest);
    fflush(fp);
    fsync(fileno(fp));
    fclose(fp);
}

- (kern_return_t)executeCase:(NSInteger)index on:(NSString *)service run:(NSString *)run
           function:(LabIO)f {
    // 4 selectores x 4 formas de entrada = 16 casos, sin hilos rivales ni punteros caducados.
    static const uint32_t selectors[] = {0, 1, 2, 17};
    uint32_t sel = selectors[index / 4];
    unsigned mode = (unsigned)(index % 4);
    uint32_t seed = 0xA17E2026u ^ (uint32_t)index;
    uint64_t scalars[4] = {0, 0, 0, 0};
    uint32_t scalarCount = mode == 0 ? 0 : (mode == 3 ? 2 : 1);
    if (mode == 2) scalars[0] = (seed % 8u) + 1u;
    if (mode == 3) { scalars[0] = 1; scalars[1] = 2; }
    uint8_t input[16] = {0};
    size_t inputLength = mode == 3 ? sizeof(input) : 0;
    if (mode == 3) {
        for (size_t j = 0; j < sizeof(input); j++) {
            input[j] = (uint8_t)(seed >> ((j % 4) * 8));
        }
    }

    NSDictionary *record = @{
        @"schema":@"AppleIOKitLab.case.v1", @"phase":@"IN_FLIGHT",
        @"service":service, @"case":@(index), @"selector":@(sel),
        @"mode":@(mode), @"seed":@(seed), @"scalarCount":@(scalarCount),
        @"structureBytes":@(inputLength), @"run":run,
        @"device":labMachine(), @"build":labKernelBuild()
    };
    // Ambas escrituras preceden matching, open e IOConnectCallMethod.
    [self saveJSON:record as:@"AppleIOKitLab-lastcase.json"];
    [self saveJSON:record as:@"AppleIOKitLab-checkpoint.json"];
    [self appendCSVRun:run service:service index:index selector:sel mode:mode
                stage:@"PRE" match:NO openKR:KERN_FAILURE callKR:KERN_FAILURE
          outputCount:0 outputSize:0 digest:0];

    lab_io_service_t svc = f.get(MACH_PORT_NULL, f.matching(service.UTF8String));
    BOOL matched = svc != MACH_PORT_NULL;
    kern_return_t openKr = KERN_FAILURE;
    kern_return_t callKr = KERN_FAILURE;
    uint32_t outputCount = 0;
    size_t outputSize = 0;
    uint64_t digest = 0;
    if (matched) {
        lab_io_connect_t cn = MACH_PORT_NULL;
        openKr = f.open(svc, mach_task_self(), 0, &cn);
        if (openKr == KERN_SUCCESS && cn != MACH_PORT_NULL) {
            if (f.call) {
                uint64_t outputScalars[4] = {0};
                uint32_t n = 4;
                uint8_t outputBytes[256] = {0};
                size_t bytes = sizeof(outputBytes);
                callKr = f.call(cn, sel, scalars, scalarCount,
                                inputLength ? input : NULL, inputLength,
                                outputScalars, &n, outputBytes, &bytes);
                // El driver puede dejar n y bytes intactos si rechaza la llamada.
                // Interpretar las capacidades iniciales como salida seria un falso positivo.
                if (callKr == KERN_SUCCESS) {
                    outputCount = n <= 4 ? n : 4;
                    outputSize = bytes <= 256 ? bytes : 256;
                    digest = labDigest(outputBytes, outputSize);
                    digest ^= labDigest((const uint8_t *)outputScalars,
                                        outputCount * sizeof(uint64_t));
                }
            }
            f.close(cn);
        }
        f.release(svc);
    }
    NSMutableDictionary *done = [record mutableCopy];
    done[@"phase"] = @"COMPLETED";
    done[@"matched"] = @(matched);
    done[@"openKR"] = labHex(openKr);
    done[@"callKR"] = labHex(callKr);
    done[@"callStatus"] = labErrorName(callKr);
    done[@"outputValid"] = @(callKr == KERN_SUCCESS);
    done[@"outputScalars"] = @(outputCount);
    done[@"outputBytes"] = @(outputSize);
    [self appendCSVRun:run service:service index:index selector:sel mode:mode
                stage:@"POST" match:matched openKR:openKr callKR:callKr
          outputCount:outputCount outputSize:outputSize digest:digest];
    [self saveJSON:done as:@"AppleIOKitLab-checkpoint.json"];
    [self saveJSON:done as:@"AppleIOKitLab-lastcase.json"];
    [self log:[NSString stringWithFormat:
        @"Caso %02ld: sel=%u modo=%u open=%@ call=%@ (%@) %@ hash=%016llx",
        (long)index, sel, mode, matched ? labHex(openKr) : @"SIN_SERVICIO",
        (openKr == KERN_SUCCESS && f.call) ? labHex(callKr) : @"NO_LLAMADO",
        labErrorName(callKr),
        callKr == KERN_SUCCESS
          ? [NSString stringWithFormat:@"out=%u/%zu",outputCount,outputSize]
          : @"out=N/A",
        (unsigned long long)digest]];
    return callKr;
}

- (void)runSelected:(NSString *)service replay:(NSNumber *)replay {
    if (self.running) { [self log:@"Prueba en curso."]; return; }
    self.running = YES;
    self.stopRequested = NO;
    NSString *run = [NSString stringWithFormat:@"r%llu",
                      (unsigned long long)([NSDate.date timeIntervalSince1970] * 1000.0)];
    [self log:[NSString stringWithFormat:@"Inicio %@ servicio=%@ seedBase=A17E2026",
               replay ? @"REPLAY" : @"CAMPAÑA", service]];
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        LabIO f = labLoadIO();
        if (!labCanDiscover(f) || !f.call) {
            [self log:@"IOConnectCallMethod o funciones IOKit no disponibles: no se ejecuta."];
            dispatch_async(dispatch_get_main_queue(), ^{ self.running = NO; });
            return;
        }
        NSInteger start = replay ? replay.integerValue : 0;
        NSInteger end = replay ? start + 1 : 16;
        NSUInteger total = 0;
        NSMutableDictionary<NSString *, NSNumber *> *returnCounts = [NSMutableDictionary new];
        for (NSInteger i = start; i < end; i++) {
            if (self.stopRequested) break;
            kern_return_t status = [self executeCase:i on:service run:run function:f];
            NSString *key = labHex(status);
            returnCounts[key] = @([returnCounts[key] unsignedIntegerValue] + 1);
            total++;
        }
        NSDictionary *finish = @{
            @"schema":@"AppleIOKitLab.run.v1.1",
            @"phase":self.stopRequested ? @"STOPPED" : @"FINISHED",
            @"run":run, @"service":service, @"completed":@(total),
            @"planned":@(end - start), @"build":labKernelBuild(),
            @"returnCounts":returnCounts,
            @"interpretation":@"A returned error is not evidence of memory corruption."
        };
        [self saveJSON:finish as:@"AppleIOKitLab-checkpoint.json"];
        [self saveJSON:finish as:@"AppleIOKitLab-summary.json"];
        dispatch_async(dispatch_get_main_queue(), ^{
            self.running = NO;
            [self log:[NSString stringWithFormat:@"Fin: %lu/%ld casos. Exportar CSV/JSON.",
                       (unsigned long)total, (long)(end - start)]];
        });
    });
}

- (void)confirmService:(NSString *)service replay:(NSNumber *)replay {
    if (!service.length) { [self log:@"Primero inventariar y seleccionar servicio."]; return; }
    NSString *build = labKernelBuild();
    BOOL sameBuild = [build isEqualToString:@"24A437"] && [labMachine() isEqualToString:@"iPhone14,3"];
    NSString *message = [NSString stringWithFormat:
        @"Servicio %@. Esta prueba invoca IOConnectCallMethod con entradas acotadas "
         "pero no necesariamente aceptadas por el controlador. Puede ocasionar un kernel panic, "
         "reinicio y pérdida de datos no guardados. Haz una copia de seguridad. "
         "Dispositivo %@, build %@%@. El registro no prueba por sí solo una vulnerabilidad.",
        service, labMachine(), build, sameBuild ? @"" : @" (DIFERENTE a la referencia 24A437)"];
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:
        replay ? @"Repetir caso guardado" : @"Confirmar prueba activa de IOKit"
        message:message preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"Cancelar"
               style:UIAlertActionStyleCancel handler:nil]];
    [alert addAction:[UIAlertAction actionWithTitle:@"Ejecutar bajo mi control"
               style:UIAlertActionStyleDestructive handler:^(UIAlertAction *a) {
        [self runSelected:service replay:replay];
    }]];
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)campaignTapped:(id)sender {
    if (self.running) { [self log:@"Prueba en curso."]; return; }
    if (![self.openServices containsObject:self.selectedService]) {
        [self log:@"Primero inventariar para verificar la apertura real del servicio."];
        return;
    }
    [self confirmService:self.selectedService replay:nil];
}

- (void)replayTapped:(id)sender {
    if (self.running) { [self log:@"Prueba en curso."]; return; }
    NSDictionary *saved = [self readJSON:@"AppleIOKitLab-lastcase.json"];
    NSString *service = saved[@"service"];
    NSNumber *caseNumber = saved[@"case"];
    if (![service isKindOfClass:NSString.class] ||
        ![caseNumber isKindOfClass:NSNumber.class] ||
        caseNumber.integerValue < 0 || caseNumber.integerValue >= 16) {
        [self log:@"No hay último caso válido para reproducir."];
        return;
    }
    [self confirmService:service replay:caseNumber];
}

- (void)stopTapped:(id)sender {
    self.stopRequested = YES;
    [self log:@"Cancelación solicitada. Se detendrá al completar la llamada actual."];
}

- (void)exportTapped:(id)sender {
    NSArray *names = @[@"AppleIOKitLab-session.txt", @"AppleIOKitLab-inventory.json",
                       @"AppleIOKitLab-checkpoint.json", @"AppleIOKitLab-lastcase.json",
                       @"AppleIOKitLab-trace.csv", @"AppleIOKitLab-public-baseline.json",
                       @"AppleIOKitLab-summary.json", @"AppleIOKitLab-contract.json",
                       @"AppleIOKitLab-direct-roundtrip.json"];
    NSMutableArray *urls = [NSMutableArray new];
    for (NSString *name in names) {
        NSURL *u = [self document:name];
        if ([[NSFileManager defaultManager] fileExistsAtPath:u.path]) [urls addObject:u];
    }
    if (!urls.count) { [self log:@"Aún no hay archivos para exportar."]; return; }
    UIActivityViewController *share = [[UIActivityViewController alloc] initWithActivityItems:urls
                                                                       applicationActivities:nil];
    share.popoverPresentationController.sourceView = self.view;
    share.popoverPresentationController.sourceRect =
        CGRectMake(self.view.bounds.size.width / 2, 120, 1, 1);
    [self presentViewController:share animated:YES completion:nil];
}
@end

@interface AppleIOKitLabDelegate : UIResponder <UIApplicationDelegate>
@property(nonatomic, strong) UIWindow *window;
@end

@implementation AppleIOKitLabDelegate
- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)options {
    self.window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    self.window.rootViewController = [AppleIOKitLabController new];
    [self.window makeKeyAndVisible];
    return YES;
}
@end

int main(int argc, char *argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass(AppleIOKitLabDelegate.class));
    }
}
