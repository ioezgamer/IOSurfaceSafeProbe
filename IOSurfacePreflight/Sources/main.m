#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <CoreFoundation/CoreFoundation.h>
#import <mach/mach.h>
#import <sys/utsname.h>
#import <sys/sysctl.h>
#import <dlfcn.h>

// Non-exploit, read-only preflight: one valid public surface and one IOKit connection.
// No method dispatch, intentional race, stale pointer use or kernel modification.
typedef struct __IOSurface * IOSurfaceRef;
typedef uint32_t IOSurfaceID;
typedef IOSurfaceRef (*CreateSurfaceFn)(CFDictionaryRef);
typedef IOSurfaceID (*GetSurfaceIDFn)(IOSurfaceRef);
typedef IOSurfaceRef (*LookupSurfaceFn)(IOSurfaceID);
typedef size_t (*GetSurfaceDimensionFn)(IOSurfaceRef);
typedef kern_return_t (*SurfaceLockFn)(IOSurfaceRef, uint32_t, uint32_t *);
typedef uint32_t io_object_t;
typedef io_object_t io_service_t;
typedef io_object_t io_connect_t;
typedef CFMutableDictionaryRef (*MatchingFn)(const char *);
typedef io_service_t (*GetMatchingFn)(mach_port_t, CFDictionaryRef);
typedef kern_return_t (*OpenServiceFn)(io_service_t, task_t, uint32_t, io_connect_t *);
typedef kern_return_t (*CloseServiceFn)(io_connect_t);
typedef kern_return_t (*ReleaseObjectFn)(io_object_t);

@interface ProbeController : UIViewController
@property(nonatomic, strong) UITextView *logView;
@property(nonatomic, strong) NSMutableString *events;
@end

@implementation ProbeController

- (void)note:(NSString *)message {
    if (!self.events) self.events = [NSMutableString new];
    NSDateFormatter *fmt = [NSDateFormatter new];
    fmt.dateFormat = @"yyyy-MM-dd HH:mm:ss";
    [self.events appendFormat:@"%@  %@\n", [fmt stringFromDate:[NSDate date]], message];
    self.logView.text = self.events;
    if (self.logView.text.length) {
        [self.logView scrollRangeToVisible:NSMakeRange(self.logView.text.length - 1, 1)];
    }
}

- (UIButton *)button:(NSString *)title action:(SEL)selector {
    UIButton *b = [UIButton buttonWithType:UIButtonTypeSystem];
    [b setTitle:title forState:UIControlStateNormal];
    b.titleLabel.font = [UIFont boldSystemFontOfSize:15];
    b.titleLabel.numberOfLines = 0;
    b.backgroundColor = [UIColor secondarySystemBackgroundColor];
    b.layer.cornerRadius = 10;
    [b addTarget:self action:selector forControlEvents:UIControlEventTouchUpInside];
    [b.heightAnchor constraintEqualToConstant:52].active = YES;
    return b;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = UIColor.systemBackgroundColor;
    self.events = [NSMutableString new];

    UILabel *title = [UILabel new];
    title.text = @"IOSurface Preflight v3";
    title.font = [UIFont boldSystemFontOfSize:26];
    UILabel *subtitle = [UILabel new];
    subtitle.text = @"Diagnóstico de acceso. No intenta provocar fallos ni obtener KernelRW.";
    subtitle.numberOfLines = 0;
    subtitle.textColor = UIColor.secondaryLabelColor;
    subtitle.font = [UIFont systemFontOfSize:14];

    self.logView = [UITextView new];
    self.logView.editable = NO;
    self.logView.font = [UIFont monospacedSystemFontOfSize:12 weight:UIFontWeightRegular];
    self.logView.layer.borderColor = UIColor.systemGray4Color.CGColor;
    self.logView.layer.borderWidth = 1;
    self.logView.layer.cornerRadius = 8;

    UIStackView *layout = [[UIStackView alloc] initWithArrangedSubviews:@[
      title, subtitle,
      [self button:@"1. API pública IOSurface" action:@selector(publicProbe:)],
      [self button:@"2. Servicio IOSurfaceRoot" action:@selector(rootProbe:)],
      [self button:@"3. Ciclo de vida público (3 pruebas)" action:@selector(lifecycleProbe:)],
      [self button:@"4. Identificadores simultáneos (A/B/C)" action:@selector(idReuseProbe:)],
      [self button:@"Exportar registro" action:@selector(shareLog:)],
      self.logView
    ]];
    layout.axis = UILayoutConstraintAxisVertical;
    layout.spacing = 12;
    layout.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:layout];
    UILayoutGuide *safe = self.view.safeAreaLayoutGuide;
    [NSLayoutConstraint activateConstraints:@[
      [layout.topAnchor constraintEqualToAnchor:safe.topAnchor constant:12],
      [layout.bottomAnchor constraintEqualToAnchor:safe.bottomAnchor constant:-12],
      [layout.leadingAnchor constraintEqualToAnchor:safe.leadingAnchor constant:16],
      [layout.trailingAnchor constraintEqualToAnchor:safe.trailingAnchor constant:-16]
    ]];
    [self.logView setContentCompressionResistancePriority:UILayoutPriorityDefaultLow forAxis:UILayoutConstraintAxisVertical];

    struct utsname info = {0};
    uname(&info);
    [self note:[NSString stringWithFormat:@"device=%s iOS=%@", info.machine, UIDevice.currentDevice.systemVersion]];
    char build[128] = {0}; size_t len = sizeof(build);
    if (sysctlbyname("kern.osversion", build, &len, NULL, 0) == 0)
        [self note:[NSString stringWithFormat:@"build=%s", build]];
    [self note:@"app=IOSurfacePreflight-v3"]; 
    [self note:@"Modo diagnóstico: sin carreras ni externalMethod."];
}

- (void)publicProbe:(id)sender {
    [self note:@"PUBLIC: comenzando operación secuencial."];
    void *framework = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY | RTLD_LOCAL);
    if (!framework) { [self note:@"PUBLIC: IOSurface.framework no cargable"]; return; }
    CreateSurfaceFn createSurface = (CreateSurfaceFn)dlsym(framework, "IOSurfaceCreate");
    GetSurfaceIDFn getID = (GetSurfaceIDFn)dlsym(framework, "IOSurfaceGetID");
    LookupSurfaceFn lookup = (LookupSurfaceFn)dlsym(framework, "IOSurfaceLookup");
    if (!createSurface || !getID || !lookup) {
        [self note:@"PUBLIC: funciones IOSurface no exportadas"]; dlclose(framework); return;
    }
    NSDictionary *params = @{
      @"IOSurfaceWidth": @64,
      @"IOSurfaceHeight": @64,
      @"IOSurfaceBytesPerElement": @4,
      @"IOSurfaceBytesPerRow": @256,
      @"IOSurfaceAllocSize": @(64 * 64 * 4),
      @"IOSurfacePixelFormat": @(0x42475241)
    };
    IOSurfaceRef first = createSurface((__bridge CFDictionaryRef)params);
    if (!first) { [self note:@"PUBLIC: FAIL IOSurfaceCreate=NULL"]; dlclose(framework); return; }
    IOSurfaceID identifier = getID(first);
    [self note:[NSString stringWithFormat:@"PUBLIC: PASS create ID=%u", (unsigned)identifier]];
    IOSurfaceRef second = lookup(identifier);
    [self note:second ? @"PUBLIC: PASS lookup" : @"PUBLIC: INFO lookup no disponible"];
    if (second) CFRelease(second);
    CFRelease(first);
    dlclose(framework);
    [self note:@"PUBLIC: referencias válidas liberadas."];
}


- (void)lifecycleProbe:(id)sender {
    [self note:@"LIFECYCLE: inicio de tres operaciones secuenciales con referencias propias."];
    [self note:@"LIFECYCLE: una búsqueda por ID nunca usa directamente un puntero liberado."];
    void *framework = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY | RTLD_LOCAL);
    if (!framework) { [self note:@"LIFECYCLE: FAIL framework no disponible"]; return; }

    CreateSurfaceFn createSurface = (CreateSurfaceFn)dlsym(framework, "IOSurfaceCreate");
    GetSurfaceIDFn getID = (GetSurfaceIDFn)dlsym(framework, "IOSurfaceGetID");
    LookupSurfaceFn lookup = (LookupSurfaceFn)dlsym(framework, "IOSurfaceLookup");
    GetSurfaceDimensionFn getWidth = (GetSurfaceDimensionFn)dlsym(framework, "IOSurfaceGetWidth");
    GetSurfaceDimensionFn getHeight = (GetSurfaceDimensionFn)dlsym(framework, "IOSurfaceGetHeight");
    GetSurfaceDimensionFn getAllocSize = (GetSurfaceDimensionFn)dlsym(framework, "IOSurfaceGetAllocSize");
    SurfaceLockFn lock = (SurfaceLockFn)dlsym(framework, "IOSurfaceLock");
    SurfaceLockFn unlock = (SurfaceLockFn)dlsym(framework, "IOSurfaceUnlock");
    if (!createSurface || !getID || !lookup || !getWidth || !getHeight ||
        !getAllocSize || !lock || !unlock) {
        [self note:@"LIFECYCLE: FAIL faltan funciones públicas"];
        dlclose(framework);
        return;
    }

    NSDictionary *params = @{
        @"IOSurfaceWidth": @64,
        @"IOSurfaceHeight": @64,
        @"IOSurfaceBytesPerElement": @4,
        @"IOSurfaceBytesPerRow": @256,
        @"IOSurfaceAllocSize": @(64 * 64 * 4),
        @"IOSurfacePixelFormat": @(0x42475241)
    };
    unsigned successes = 0;
    for (unsigned i = 1; i <= 3; i++) {
        @autoreleasepool {
            IOSurfaceRef original = createSurface((__bridge CFDictionaryRef)params);
            if (!original) {
                [self note:[NSString stringWithFormat:@"LIFECYCLE #%u: FAIL create=NULL", i]];
                continue;
            }
            IOSurfaceID identifier = getID(original);
            size_t width = getWidth(original), height = getHeight(original);
            size_t bytes = getAllocSize(original);
            [self note:[NSString stringWithFormat:@"LIFECYCLE #%u: create ID=%u size=%zux%zu bytes=%zu",
                        i, (unsigned)identifier, width, height, bytes]];

            IOSurfaceRef ownedLookup = lookup(identifier);
            if (!ownedLookup) {
                [self note:[NSString stringWithFormat:@"LIFECYCLE #%u: FAIL lookup antes del cierre", i]];
                CFRelease(original);
                continue;
            }

            // Dropping one owned reference must not invalidate the retained lookup.
            CFRelease(original);
            [self note:[NSString stringWithFormat:@"LIFECYCLE #%u: referencia de creación liberada; lookup retenido", i]];

            size_t retainedWidth = getWidth(ownedLookup), retainedHeight = getHeight(ownedLookup);
            uint32_t seed = 0;
            const uint32_t readOnly = 1; // kIOSurfaceLockReadOnly on lock AND unlock.
            kern_return_t lockCode = lock(ownedLookup, readOnly, &seed);
            [self note:[NSString stringWithFormat:@"LIFECYCLE #%u: retenido=%zux%zu LOCK kr=0x%08x",
                        i, retainedWidth, retainedHeight, (unsigned)lockCode]];
            kern_return_t unlockCode = KERN_SUCCESS;
            if (lockCode == KERN_SUCCESS) {
                unlockCode = unlock(ownedLookup, readOnly, NULL);
                [self note:[NSString stringWithFormat:@"LIFECYCLE #%u: UNLOCK kr=0x%08x",
                            i, (unsigned)unlockCode]];
            }

            // This is an ID lookup, not a dereference of the released pointer.
            CFRelease(ownedLookup);
            IOSurfaceRef afterRelease = lookup(identifier);
            [self note:[NSString stringWithFormat:@"LIFECYCLE #%u: lookup tras liberar referencias=%@",
                        i, afterRelease ? @"DISPONIBLE" : @"NO DISPONIBLE"]];
            if (afterRelease) CFRelease(afterRelease);

            if (width == 64 && height == 64 && bytes >= 16384 &&
                retainedWidth == width && retainedHeight == height &&
                lockCode == KERN_SUCCESS && unlockCode == KERN_SUCCESS) {
                successes++;
            }
        }
    }
    [self note:[NSString stringWithFormat:@"LIFECYCLE: fin %u/3 ciclos de lectura/bloqueo correctos", successes]];
    [self note:@"LIFECYCLE: el resultado no mide retainCount del kernel, ni prueba UAF o KernelRW."];
    dlclose(framework);
}


- (void)idReuseProbe:(id)sender {
    [self note:@"IDS: inicio. Prueba secuencial con tres objetos vivos simultáneamente."];
    [self note:@"IDS: un ID repetido entre objetos ya cerrados puede ser reciclaje legítimo."];
    void *framework = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY | RTLD_LOCAL);
    if (!framework) { [self note:@"IDS: FAIL no se puede cargar IOSurface"]; return; }
    CreateSurfaceFn create = (CreateSurfaceFn)dlsym(framework, "IOSurfaceCreate");
    LookupSurfaceFn lookup = (LookupSurfaceFn)dlsym(framework, "IOSurfaceLookup");
    GetSurfaceIDFn getID = (GetSurfaceIDFn)dlsym(framework, "IOSurfaceGetID");
    GetSurfaceDimensionFn getWidth = (GetSurfaceDimensionFn)dlsym(framework, "IOSurfaceGetWidth");
    if (!create || !lookup || !getID || !getWidth) {
        [self note:@"IDS: FAIL faltan APIs públicas"];
        dlclose(framework);
        return;
    }
    NSDictionary *params = @{
        @"IOSurfaceWidth": @64, @"IOSurfaceHeight": @64,
        @"IOSurfaceBytesPerElement": @4, @"IOSurfaceBytesPerRow": @256,
        @"IOSurfaceAllocSize": @(64 * 64 * 4), @"IOSurfacePixelFormat": @(0x42475241)
    };

    IOSurfaceRef a = create((__bridge CFDictionaryRef)params);
    IOSurfaceRef b = create((__bridge CFDictionaryRef)params);
    if (!a || !b) {
        [self note:@"IDS: FAIL no se pudieron crear A/B"];
        if (a) CFRelease(a);
        if (b) CFRelease(b);
        dlclose(framework);
        return;
    }
    IOSurfaceID ia = getID(a), ib = getID(b);
    [self note:[NSString stringWithFormat:@"IDS: A=%u B=%u (ambas vivas)", (unsigned)ia, (unsigned)ib]];
    if (ia == ib) {
        [self note:@"IDS: ANOMALIA A y B vivas tienen el mismo ID"];
    } else {
        [self note:@"IDS: PASS A/B vivas con IDs diferentes"];
    }

    IOSurfaceRef heldA = lookup(ia);
    if (!heldA) {
        [self note:@"IDS: FAIL lookup(A) mientras A está viva"];
        CFRelease(a); CFRelease(b); dlclose(framework);
        return;
    }
    CFRelease(a);
    a = NULL;
    [self note:@"IDS: referencia de creación A liberada, lookup(A) retenido"];
    IOSurfaceRef c = create((__bridge CFDictionaryRef)params);
    if (!c) {
        [self note:@"IDS: FAIL no se pudo crear C"];
        CFRelease(heldA); CFRelease(b); dlclose(framework);
        return;
    }
    IOSurfaceID ic = getID(c);
    BOOL distinct = (ia != ib && ia != ic && ib != ic);
    [self note:[NSString stringWithFormat:@"IDS: A=%u (retenida) B=%u C=%u (tres vivas) distintas=%@",
                (unsigned)ia, (unsigned)ib, (unsigned)ic, distinct ? @"SI" : @"NO"]];
    [self note:[NSString stringWithFormat:@"IDS: lookup A retenida, ancho=%zu", getWidth(heldA)]];

    CFRelease(heldA);
    heldA = NULL;
    IOSurfaceRef lookA = lookup(ia);
    [self note:[NSString stringWithFormat:@"IDS: lookup(A) tras soltar ambas referencias=%@",
                lookA ? @"DISPONIBLE" : @"NO DISPONIBLE"]];
    if (lookA) CFRelease(lookA);

    IOSurfaceRef lookB = lookup(ib);
    IOSurfaceRef lookC = lookup(ic);
    BOOL othersAlive = (lookB != NULL && lookC != NULL);
    [self note:[NSString stringWithFormat:@"IDS: B/C intactas tras cerrar A=%@",
                othersAlive ? @"SI" : @"NO"]];
    if (lookB) CFRelease(lookB);
    if (lookC) CFRelease(lookC);
    CFRelease(b);
    CFRelease(c);

    IOSurfaceRef postB = lookup(ib);
    IOSurfaceRef postC = lookup(ic);
    [self note:[NSString stringWithFormat:@"IDS: lookup(B) después de cierre=%@, lookup(C)=%@",
                postB ? @"DISPONIBLE" : @"NO DISPONIBLE",
                postC ? @"DISPONIBLE" : @"NO DISPONIBLE"]];
    if (postB) CFRelease(postB);
    if (postC) CFRelease(postC);

    IOSurfaceRef d = create((__bridge CFDictionaryRef)params);
    if (d) {
        IOSurfaceID id = getID(d);
        BOOL reused = (id == ia || id == ib || id == ic);
        [self note:[NSString stringWithFormat:@"IDS: D nueva ID=%u. ID anterior reutilizado=%@",
                    (unsigned)id, reused ? @"SI" : @"NO"]];
        CFRelease(d);
    } else {
        [self note:@"IDS: INFO D no pudo crearse"];
    }
    [self note:[NSString stringWithFormat:@"IDS: RESULTADO IDs vivos distintos=%@, independencia B/C=%@",
                distinct ? @"SI" : @"NO", othersAlive ? @"SI" : @"NO"]];
    [self note:@"IDS: reciclar un ID no implica acceder a memoria liberada ni demuestra KernelRW."];
    dlclose(framework);
}

- (void)rootProbe:(id)sender {
    [self note:@"ROOT: búsqueda y apertura únicas, sin llamadas a métodos."];
    void *lib = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY | RTLD_LOCAL);
    if (!lib) { [self note:@"ROOT: IOKit no cargable"]; return; }

    MatchingFn matching = (MatchingFn)dlsym(lib, "IOServiceMatching");
    GetMatchingFn get = (GetMatchingFn)dlsym(lib, "IOServiceGetMatchingService");
    OpenServiceFn open = (OpenServiceFn)dlsym(lib, "IOServiceOpen");
    CloseServiceFn close = (CloseServiceFn)dlsym(lib, "IOServiceClose");
    ReleaseObjectFn release = (ReleaseObjectFn)dlsym(lib, "IOObjectRelease");
    if (!matching || !get || !open || !close || !release) {
        [self note:@"ROOT: faltan símbolos IOKit"]; dlclose(lib); return;
    }
    CFMutableDictionaryRef criteria = matching("IOSurfaceRoot");
    if (!criteria) { [self note:@"ROOT: Matching=NULL"]; dlclose(lib); return; }
    io_service_t service = get(MACH_PORT_NULL, criteria);
    if (service == MACH_PORT_NULL) {
        [self note:@"ROOT: NO_VISIBLE"]; dlclose(lib); return;
    }
    [self note:@"ROOT: SERVICE_VISIBLE"];
    io_connect_t conn = MACH_PORT_NULL;
    kern_return_t kr = open(service, mach_task_self(), 0, &conn);
    [self note:[NSString stringWithFormat:@"ROOT: OPEN kr=0x%08x connection=%@",
               (unsigned)kr, conn ? @"si" : @"no"]];
    if (kr == KERN_SUCCESS && conn != MACH_PORT_NULL) {
        kern_return_t closed = close(conn);
        [self note:[NSString stringWithFormat:@"ROOT: CLOSE kr=0x%08x", (unsigned)closed]];
    }
    release(service);
    dlclose(lib);
    [self note:@"ROOT: finalizado."];
}

- (void)shareLog:(id)sender {
    NSString *p = [NSTemporaryDirectory() stringByAppendingPathComponent:@"IOSurfacePreflight-log.txt"];
    NSError *error = nil;
    if (![self.events writeToFile:p atomically:YES encoding:NSUTF8StringEncoding error:&error]) {
        [self note:[NSString stringWithFormat:@"EXPORT: %@", error.localizedDescription]];
        return;
    }
    UIActivityViewController *sharing = [[UIActivityViewController alloc]
      initWithActivityItems:@[[NSURL fileURLWithPath:p]] applicationActivities:nil];
    if (sharing.popoverPresentationController)
        sharing.popoverPresentationController.sourceView = (UIView *)sender;
    [self presentViewController:sharing animated:YES completion:nil];
}
@end

@interface AppDelegate : UIResponder <UIApplicationDelegate>
@property(nonatomic, strong) UIWindow *window;
@end
@implementation AppDelegate
- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)options {
    self.window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    self.window.rootViewController = [ProbeController new];
    [self.window makeKeyAndVisible];
    return YES;
}
@end

int main(int argc, char *argv[]) {
    @autoreleasepool { return UIApplicationMain(argc, argv, nil, NSStringFromClass(AppDelegate.class)); }
}
