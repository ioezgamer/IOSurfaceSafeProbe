#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <CoreFoundation/CoreFoundation.h>
#import <mach/mach.h>
#import <sys/utsname.h>
#import <sys/sysctl.h>
#import <dlfcn.h>
#import <string.h>
#import <unistd.h>

// Non-exploit, read-only preflight: one valid public surface and one IOKit connection.
// No method dispatch, intentional race, stale pointer use or kernel modification.
typedef struct __IOSurface * IOSurfaceRef;
typedef uint32_t IOSurfaceID;
typedef IOSurfaceRef (*CreateSurfaceFn)(CFDictionaryRef);
typedef IOSurfaceID (*GetSurfaceIDFn)(IOSurfaceRef);
typedef IOSurfaceRef (*LookupSurfaceFn)(IOSurfaceID);
typedef size_t (*GetSurfaceDimensionFn)(IOSurfaceRef);
typedef void *(*GetSurfaceBaseFn)(IOSurfaceRef);
typedef kern_return_t (*SurfaceLockFn)(IOSurfaceRef, uint32_t, uint32_t *);
typedef uint32_t io_object_t;
typedef io_object_t io_service_t;
typedef io_object_t io_connect_t;
typedef CFMutableDictionaryRef (*MatchingFn)(const char *);
typedef io_service_t (*GetMatchingFn)(mach_port_t, CFDictionaryRef);
typedef kern_return_t (*OpenServiceFn)(io_service_t, task_t, uint32_t, io_connect_t *);
typedef kern_return_t (*CloseServiceFn)(io_connect_t);
typedef kern_return_t (*ReleaseObjectFn)(io_object_t);

typedef struct {
    IOSurfaceRef held;
    IOSurfaceID identifier;
    size_t width, height, rowBytes, allocated;
    uint64_t marker;
} ProbeLiveSurface;

static uint32_t probeRandom(uint32_t *state) {
    uint32_t x = *state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *state = x;
    return x;
}

@interface ProbeController : UIViewController
@property(nonatomic, strong) UITextView *logView;
@property(nonatomic, strong) NSMutableString *events;
@property(nonatomic, assign) BOOL matrixRunning;
@property(nonatomic, assign) BOOL stressRunning;
@property(atomic, assign) BOOL stressStopRequested;
@property(nonatomic, strong) NSString *stressCSV;
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
    title.text = @"IOSurface Preflight v6";
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
      [self button:@"5. Firma, permisos y servicio" action:@selector(accessPolicyProbe:)],
      [self button:@"6. Matriz IOSurface 484 casos" action:@selector(matrixProbe:)],
      [self button:@"7. Fuzzing controlado (20.000 operaciones)" action:@selector(stressProbe:)],
      [self button:@"Detener fuzzing" action:@selector(stopStressProbe:)],
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
    [self note:@"app=IOSurfacePreflight-v6"]; 
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


- (void)accessPolicyProbe:(id)sender {
    [self note:@"POLICY: inicio. Solo lectura de metadatos y entitlements propios."];
    [self note:[NSString stringWithFormat:@"POLICY: bundle-id=%@", NSBundle.mainBundle.bundleIdentifier ?: @"NO_DISPONIBLE"]];
    void *security = dlopen("/System/Library/Frameworks/Security.framework/Security", RTLD_LAZY | RTLD_LOCAL);
    if (!security) {
        [self note:@"POLICY: Security.framework NO_DISPONIBLE"];
    } else {
        typedef CFTypeRef (*SelfTaskFn)(CFAllocatorRef);
        typedef CFTypeRef (*ReadEntitlementFn)(CFTypeRef, CFStringRef, CFErrorRef *);
        SelfTaskFn createSelf = (SelfTaskFn)dlsym(security, "SecTaskCreateFromSelf");
        ReadEntitlementFn readEntitlement = (ReadEntitlementFn)dlsym(security, "SecTaskCopyValueForEntitlement");
        if (!createSelf || !readEntitlement) {
            [self note:@"POLICY: interfaz SecTask NO_DISPONIBLE"];
        } else {
            CFTypeRef task = createSelf(kCFAllocatorDefault);
            if (!task) {
                [self note:@"POLICY: task de firma NO_DISPONIBLE"];
            } else {
                const CFStringRef keys[] = {
                    CFSTR("com.apple.private.gpu-restricted"),
                    CFSTR("com.apple.developer.gpu-restricted"),
                    CFSTR("get-task-allow"),
                    CFSTR("application-identifier")
                };
                const NSString *names[] = {
                    @"gpu-restricted(private)", @"gpu-restricted(developer)",
                    @"get-task-allow", @"application-identifier"
                };
                for (int i = 0; i < 4; i++) {
                    CFErrorRef err = NULL;
                    CFTypeRef value = readEntitlement(task, keys[i], &err);
                    NSString *state = @"AUSENTE";
                    if (value) {
                        state = @"PRESENTE";
                        if (CFGetTypeID(value) == CFBooleanGetTypeID()) {
                            state = CFBooleanGetValue((CFBooleanRef)value) ? @"TRUE" : @"FALSE";
                        }
                        CFRelease(value);
                    } else if (err) {
                        state = @"NO_DETERMINABLE";
                    }
                    [self note:[NSString stringWithFormat:@"POLICY: entitlement %@=%@", names[i], state]];
                    if (err) CFRelease(err);
                }
                CFRelease(task);
            }
        }
        dlclose(security);
    }
    void *io = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY | RTLD_LOCAL);
    if (!io) {
        [self note:@"POLICY: IOKit.framework NO_DISPONIBLE"];
        return;
    }
    MatchingFn matching = (MatchingFn)dlsym(io, "IOServiceMatching");
    GetMatchingFn get = (GetMatchingFn)dlsym(io, "IOServiceGetMatchingService");
    OpenServiceFn open = (OpenServiceFn)dlsym(io, "IOServiceOpen");
    CloseServiceFn close = (CloseServiceFn)dlsym(io, "IOServiceClose");
    ReleaseObjectFn release = (ReleaseObjectFn)dlsym(io, "IOObjectRelease");
    typedef kern_return_t (*ClassFn)(io_object_t, char *);
    typedef kern_return_t (*GetConnectionServiceFn)(io_connect_t, io_service_t *);
    ClassFn getClass = (ClassFn)dlsym(io, "IOObjectGetClass");
    GetConnectionServiceFn connectService = (GetConnectionServiceFn)dlsym(io, "IOConnectGetService");
    if (!matching || !get || !open || !close || !release) {
        [self note:@"POLICY: simbolos IOKit esenciales NO_DISPONIBLES"];
        dlclose(io);
        return;
    }
    CFMutableDictionaryRef query = matching("IOSurfaceRoot");
    if (!query) {
        [self note:@"POLICY: diccionario de busqueda NO_DISPONIBLE"];
        dlclose(io);
        return;
    }
    io_service_t service = get(MACH_PORT_NULL, query);
    if (!service) {
        [self note:@"POLICY: IOSurfaceRoot no visible"];
        dlclose(io);
        return;
    }
    if (getClass) {
        char cls[128] = {0};
        kern_return_t code = getClass(service, cls);
        [self note:[NSString stringWithFormat:@"POLICY: service-class kr=0x%08x class=%s",
                    (unsigned)code, code == KERN_SUCCESS ? cls : "NO_DISPONIBLE"]];
    }
    io_connect_t connection = MACH_PORT_NULL;
    kern_return_t code = open(service, mach_task_self(), 0, &connection);
    [self note:[NSString stringWithFormat:@"POLICY: IOServiceOpen kr=0x%08x", (unsigned)code]];
    if (code == KERN_SUCCESS && connection != MACH_PORT_NULL) {
        if (connectService) {
            io_service_t owner = MACH_PORT_NULL;
            kern_return_t ownerCode = connectService(connection, &owner);
            [self note:[NSString stringWithFormat:@"POLICY: IOConnectGetService kr=0x%08x",
                        (unsigned)ownerCode]];
            if (ownerCode == KERN_SUCCESS && owner) {
                if (getClass) {
                    char ownerClass[128] = {0};
                    kern_return_t classCode = getClass(owner, ownerClass);
                    [self note:[NSString stringWithFormat:@"POLICY: connection-owner-class kr=0x%08x class=%s",
                                (unsigned)classCode,
                                classCode == KERN_SUCCESS ? ownerClass : "NO_DISPONIBLE"]];
                }
                release(owner);
            }
        } else {
            [self note:@"POLICY: IOConnectGetService no exportado"];
        }
        kern_return_t closed = close(connection);
        [self note:[NSString stringWithFormat:@"POLICY: IOServiceClose kr=0x%08x", (unsigned)closed]];
    }
    release(service);
    dlclose(io);
    [self note:@"POLICY: sin IOConnectCallMethod, sin selector, sin carreras."];
    [self note:@"POLICY: no es posible determinar tabla interna A/B con estos metadatos por si solos."];
}


- (void)matrixProbe:(id)sender {
    if (self.matrixRunning) {
        [self note:@"MATRIX: prueba ya en curso; no se ejecuta en paralelo."];
        return;
    }
    self.matrixRunning = YES;
    [self note:@"MATRIX: iniciando 484 casos con parámetros válidos, secuenciales y deterministas."];
    [self note:@"MATRIX: 11 anchuras x 11 alturas x 2 paddings x 2 pasadas. Máximo 270336 bytes por superficie."];
    [self note:@"MATRIX: sin métodos privados, sin carreras, sin referencias obsoletas."];

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        @autoreleasepool {
            void *framework = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY | RTLD_LOCAL);
            CreateSurfaceFn create = framework ? (CreateSurfaceFn)dlsym(framework, "IOSurfaceCreate") : NULL;
            GetSurfaceIDFn getID = framework ? (GetSurfaceIDFn)dlsym(framework, "IOSurfaceGetID") : NULL;
            LookupSurfaceFn lookup = framework ? (LookupSurfaceFn)dlsym(framework, "IOSurfaceLookup") : NULL;
            GetSurfaceDimensionFn getWidth = framework ? (GetSurfaceDimensionFn)dlsym(framework, "IOSurfaceGetWidth") : NULL;
            GetSurfaceDimensionFn getHeight = framework ? (GetSurfaceDimensionFn)dlsym(framework, "IOSurfaceGetHeight") : NULL;
            GetSurfaceDimensionFn getSize = framework ? (GetSurfaceDimensionFn)dlsym(framework, "IOSurfaceGetAllocSize") : NULL;
            SurfaceLockFn lock = framework ? (SurfaceLockFn)dlsym(framework, "IOSurfaceLock") : NULL;
            SurfaceLockFn unlock = framework ? (SurfaceLockFn)dlsym(framework, "IOSurfaceUnlock") : NULL;
            if (!create || !getID || !lookup || !getWidth || !getHeight || !getSize || !lock || !unlock) {
                if (framework) dlclose(framework);
                dispatch_async(dispatch_get_main_queue(), ^{
                    self.matrixRunning = NO;
                    [self note:@"MATRIX: ERROR; faltan funciones públicas de IOSurface."];
                });
                return;
            }

            // Valid inputs only: all widths/heights are multiples of 8;
            // each row has width*4 or width*4+32 bytes, and allocSize covers all rows.
            const size_t dims[] = {8,16,24,32,48,64,96,128,160,192,256};
            const size_t n = sizeof(dims) / sizeof(dims[0]);
            const size_t paddings[] = {0,32};
            const unsigned total = 484;
            unsigned attempted = 0, passed = 0, anomalies = 0;
            NSMutableString *details = [NSMutableString stringWithString:
                @"MATRIX: sample,pass,width,height,padding,id,allocation,observed,lock,unlock,result\n"];
            CFAbsoluteTime begin = CFAbsoluteTimeGetCurrent();

            for (unsigned pass = 0; pass < 2; pass++) {
                for (size_t wi = 0; wi < n; wi++) {
                    for (size_t hi = 0; hi < n; hi++) {
                        for (size_t pi = 0; pi < 2; pi++) {
                            @autoreleasepool {
                                size_t width = dims[wi], height = dims[hi];
                                size_t padding = paddings[pi];
                                size_t rowBytes = width * 4 + padding;
                                size_t allocation = rowBytes * height;
                                NSDictionary *params = @{
                                    @"IOSurfaceWidth": @(width),
                                    @"IOSurfaceHeight": @(height),
                                    @"IOSurfaceBytesPerElement": @4,
                                    @"IOSurfaceBytesPerRow": @(rowBytes),
                                    @"IOSurfaceAllocSize": @(allocation),
                                    @"IOSurfacePixelFormat": @(0x42475241)
                                };
                                attempted++;
                                IOSurfaceRef surface = create((__bridge CFDictionaryRef)params);
                                IOSurfaceID identifier = 0;
                                size_t actualSize = 0;
                                kern_return_t lockCode = KERN_FAILURE, unlockCode = KERN_FAILURE;
                                const char *result = "CREATE_NULL";
                                BOOL ok = NO;
                                if (surface) {
                                    identifier = getID(surface);
                                    IOSurfaceRef retained = lookup(identifier);
                                    if (!retained) {
                                        result = "LOOKUP_NULL";
                                    } else {
                                        size_t observedWidth = getWidth(retained);
                                        size_t observedHeight = getHeight(retained);
                                        actualSize = getSize(retained);
                                        uint32_t seed = 0;
                                        const uint32_t readOnly = 1;
                                        lockCode = lock(retained, readOnly, &seed);
                                        if (lockCode == KERN_SUCCESS)
                                            unlockCode = unlock(retained, readOnly, NULL);
                                        ok = observedWidth == width && observedHeight == height &&
                                             actualSize >= allocation && lockCode == KERN_SUCCESS &&
                                             unlockCode == KERN_SUCCESS;
                                        result = ok ? "PASS" : "DIMENSION_OR_LOCK_MISMATCH";
                                        CFRelease(retained);
                                    }
                                    CFRelease(surface);
                                }
                                if (ok) passed++; else anomalies++;
                                [details appendFormat:
                                    @"MATRIX: %u,%u,%zu,%zu,%zu,%u,%zu,%zu,0x%08x,0x%08x,%s\n",
                                    attempted,pass+1,width,height,padding,(unsigned)identifier,
                                    allocation,actualSize,(unsigned)lockCode,(unsigned)unlockCode,result];
                                if (attempted % 64 == 0) {
                                    unsigned now = attempted;
                                    dispatch_async(dispatch_get_main_queue(), ^{
                                        [self note:[NSString stringWithFormat:
                                            @"MATRIX: progreso %u/%u casos completados.",now,total]];
                                    });
                                }
                            }
                        }
                    }
                }
            }
            double elapsed = CFAbsoluteTimeGetCurrent() - begin;
            dlclose(framework);
            dispatch_async(dispatch_get_main_queue(), ^{
                [self.events appendString:details];
                self.matrixRunning = NO;
                [self note:[NSString stringWithFormat:
                    @"MATRIX: RESULTADO intentos=%u correctos=%u anomalias=%u duracion=%.3fs",
                    attempted,passed,anomalies,elapsed]];
                [self note:@"MATRIX: exporta el registro para inspeccionar los 484 casos individuales."];
                [self note:@"MATRIX: una anomalía pública no demuestra por sí sola corrupción de memoria ni KernelRW."];
            });
        }
    });
}


- (void)stopStressProbe:(id)sender {
    if (!self.stressRunning) {
        [self note:@"FUZZ: no hay prueba activa."];
        return;
    }
    self.stressStopRequested = YES;
    [self note:@"FUZZ: detención solicitada; se liberarán las referencias vigentes."];
}

- (void)stressProbe:(id)sender {
    if (self.stressRunning || self.matrixRunning) {
        [self note:@"FUZZ: otra prueba está en curso; evitamos solaparlas."];
        return;
    }
    self.stressRunning = YES;
    self.stressStopRequested = NO;
    self.stressCSV = nil;
    [self note:@"FUZZ: inicio. 20000 operaciones deterministas sobre API pública; semilla 0xA17E2026."];
    [self note:@"FUZZ: 12 superficies vivas como máximo, dimensiones de 8 a 128, memoria de superficies menor de 1 MiB."];
    [self note:@"FUZZ: crea, escribe marcas de 64 bits, verifica con lookup, libera y vuelve a crear."];
    [self note:@"FUZZ: sin punteros liberados, métodos privados, carreras ni manipulación del kernel."];
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        @autoreleasepool {
            const unsigned capacity = 12;
            const unsigned totalSteps = 20000;
            const uint32_t initialSeed = 0xA17E2026;
            uint32_t state = initialSeed;
            const size_t dimensions[] = {8, 16, 24, 32, 48, 64, 96, 128};
            const size_t paddings[] = {0, 16, 32, 64};
            ProbeLiveSurface slots[12] = {0};
            unsigned executed = 0, creates = 0, checks = 0, releases = 0;
            unsigned anomalies = 0, maxLive = 0, live = 0;
            unsigned postReleaseAvailable = 0, postReleaseMissing = 0;
            unsigned createNull = 0, lookupNull = 0, contentMismatch = 0, dimensionsMismatch = 0, lockFailures = 0;
            unsigned duplicateIds = 0;
            CFAbsoluteTime begin = CFAbsoluteTimeGetCurrent();
            NSMutableString *csv = [NSMutableString stringWithString:
                @"step,operation,slot,id,width,height,row_bytes,alloc_size,expected_marker,observed_marker,result\n"];
            void *framework = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface",
                                     RTLD_LAZY | RTLD_LOCAL);
            CreateSurfaceFn create = framework ? (CreateSurfaceFn)dlsym(framework, "IOSurfaceCreate") : NULL;
            GetSurfaceIDFn getID = framework ? (GetSurfaceIDFn)dlsym(framework, "IOSurfaceGetID") : NULL;
            LookupSurfaceFn lookup = framework ? (LookupSurfaceFn)dlsym(framework, "IOSurfaceLookup") : NULL;
            GetSurfaceDimensionFn getWidth = framework ? (GetSurfaceDimensionFn)dlsym(framework, "IOSurfaceGetWidth") : NULL;
            GetSurfaceDimensionFn getHeight = framework ? (GetSurfaceDimensionFn)dlsym(framework, "IOSurfaceGetHeight") : NULL;
            GetSurfaceDimensionFn getAlloc = framework ? (GetSurfaceDimensionFn)dlsym(framework, "IOSurfaceGetAllocSize") : NULL;
            GetSurfaceBaseFn getBase = framework ? (GetSurfaceBaseFn)dlsym(framework, "IOSurfaceGetBaseAddress") : NULL;
            SurfaceLockFn lock = framework ? (SurfaceLockFn)dlsym(framework, "IOSurfaceLock") : NULL;
            SurfaceLockFn unlock = framework ? (SurfaceLockFn)dlsym(framework, "IOSurfaceUnlock") : NULL;
            BOOL available = create && getID && lookup && getWidth && getHeight && getAlloc &&
                             getBase && lock && unlock;
            if (!available) {
                if (framework) dlclose(framework);
                dispatch_async(dispatch_get_main_queue(), ^{
                    self.stressRunning = NO;
                    [self note:@"FUZZ: ERROR: faltan funciones públicas, no se ejecutó la prueba."];
                });
                return;
            }
            BOOL stopped = NO;
            for (unsigned step = 1; step <= totalSteps; step++) {
                if (self.stressStopRequested) {
                    stopped = YES;
                    break;
                }
                @autoreleasepool {
                    unsigned selected = probeRandom(&state) % capacity;
                    unsigned choice = probeRandom(&state) % 100;
                    ProbeLiveSurface *slot = &slots[selected];
                    const char *action = "NONE";
                    const char *result = "PASS";
                    IOSurfaceID reportID = slot->identifier;
                    size_t width = slot->width, height = slot->height;
                    size_t rowBytes = slot->rowBytes, bytes = slot->allocated;
                    uint64_t expected = slot->marker, observed = 0;
                    if (!slot->held) {
                        action = "CREATE";
                        width = dimensions[probeRandom(&state) % 8];
                        height = dimensions[probeRandom(&state) % 8];
                        size_t padding = paddings[probeRandom(&state) % 4];
                        rowBytes = width * 4 + padding;
                        bytes = rowBytes * height;
                        expected = 0xA17E2026F00D0000ULL ^
                                  (((uint64_t)step) << 17) ^
                                  (((uint64_t)selected) << 8) ^
                                  (uint64_t)probeRandom(&state);
                        NSDictionary *settings = @{
                            @"IOSurfaceWidth": @(width),
                            @"IOSurfaceHeight": @(height),
                            @"IOSurfaceBytesPerElement": @4,
                            @"IOSurfaceBytesPerRow": @(rowBytes),
                            @"IOSurfaceAllocSize": @(bytes),
                            @"IOSurfacePixelFormat": @(0x42475241)
                        };
                        IOSurfaceRef original = create((__bridge CFDictionaryRef)settings);
                        if (!original) {
                            result = "CREATE_NULL";
                            createNull++;
                        } else {
                            reportID = getID(original);
                            IOSurfaceRef retained = lookup(reportID);
                            CFRelease(original);
                            if (!retained) {
                                result = "LOOKUP_NULL";
                                lookupNull++;
                            } else {
                                uint32_t seed = 0;
                                kern_return_t lockResult = lock(retained, 0, &seed);
                                if (lockResult != KERN_SUCCESS) {
                                    result = "WRITE_LOCK_FAILED";
                                    lockFailures++;
                                } else {
                                    void *ptr = getBase(retained);
                                    if (!ptr) {
                                        result = "WRITE_BASE_NULL";
                                        lockFailures++;
                                    } else {
                                        memcpy(ptr, &expected, sizeof(expected));
                                    }
                                    kern_return_t unlockResult = unlock(retained, 0, NULL);
                                    if (unlockResult != KERN_SUCCESS) {
                                        result = "WRITE_UNLOCK_FAILED";
                                        lockFailures++;
                                    }
                                }
                                if (strcmp(result, "PASS") == 0) {
                                    for (unsigned k = 0; k < capacity; k++) {
                                        if (slots[k].held && slots[k].identifier == reportID) {
                                            result = "DUPLICATE_LIVE_ID";
                                            duplicateIds++;
                                            break;
                                        }
                                    }
                                }
                                if (strcmp(result, "PASS") == 0) {
                                    slot->held = retained;
                                    slot->identifier = reportID;
                                    slot->width = width;
                                    slot->height = height;
                                    slot->rowBytes = rowBytes;
                                    slot->allocated = bytes;
                                    slot->marker = expected;
                                    creates++;
                                    live++;
                                    if (live > maxLive) maxLive = live;
                                } else {
                                    CFRelease(retained);
                                }
                            }
                        }
                    } else if (choice < 29) {
                        action = "RELEASE";
                        CFRelease(slot->held);
                        slot->held = NULL;
                        releases++;
                        live--;
                        IOSurfaceRef after = lookup(reportID);
                        if (after) {
                            postReleaseAvailable++;
                            CFRelease(after);
                            result = "RELEASED_LOOKUP_AVAILABLE";
                        } else {
                            postReleaseMissing++;
                            result = "RELEASED_LOOKUP_MISSING";
                        }
                        memset(slot, 0, sizeof(*slot));
                    } else {
                        action = "VERIFY";
                        checks++;
                        IOSurfaceRef ref = lookup(reportID);
                        if (!ref) {
                            result = "LOOKUP_NULL_WHILE_RETAINED";
                            lookupNull++;
                        } else {
                            size_t observedWidth = getWidth(ref), observedHeight = getHeight(ref);
                            size_t observedAlloc = getAlloc(ref);
                            if (observedWidth != width || observedHeight != height || observedAlloc < bytes) {
                                result = "DIMENSIONS_MISMATCH";
                                dimensionsMismatch++;
                            }
                            kern_return_t lockResult = lock(ref, 1, NULL);
                            if (lockResult != KERN_SUCCESS) {
                                result = "READ_LOCK_FAILED";
                                lockFailures++;
                            } else {
                                void *ptr = getBase(ref);
                                if (!ptr) {
                                    result = "READ_BASE_NULL";
                                    lockFailures++;
                                } else {
                                    memcpy(&observed, ptr, sizeof(observed));
                                    if (observed != expected) {
                                        result = "CONTENT_MISMATCH";
                                        contentMismatch++;
                                    }
                                }
                                kern_return_t unlockResult = unlock(ref, 1, NULL);
                                if (unlockResult != KERN_SUCCESS) {
                                    result = "READ_UNLOCK_FAILED";
                                    lockFailures++;
                                }
                            }
                            CFRelease(ref);
                        }
                    }
                    if (strcmp(result, "PASS") != 0 &&
                        strcmp(result, "RELEASED_LOOKUP_AVAILABLE") != 0 &&
                        strcmp(result, "RELEASED_LOOKUP_MISSING") != 0) {
                        anomalies++;
                    }
                    [csv appendFormat:@"%u,%s,%u,%u,%zu,%zu,%zu,%zu,0x%016llx,0x%016llx,%s\n",
                        step, action, selected, (unsigned)reportID, width, height,
                        rowBytes, bytes, (unsigned long long)expected,
                        (unsigned long long)observed, result];
                    executed++;
                    if ((step % 1000) == 0) {
                        unsigned done = executed, issues = anomalies, maximum = maxLive;
                        dispatch_async(dispatch_get_main_queue(), ^{
                            [self note:[NSString stringWithFormat:
                                @"FUZZ: progreso %u/%u, anomalías=%u, máximo simultáneo=%u",
                                done, totalSteps, issues, maximum]];
                        });
                    }
                    if ((step % 250) == 0) usleep(1000);
                }
            }
            for (unsigned j = 0; j < capacity; j++) {
                if (slots[j].held) {
                    CFRelease(slots[j].held);
                    slots[j].held = NULL;
                }
            }
            if (framework) dlclose(framework);
            double elapsed = CFAbsoluteTimeGetCurrent() - begin;
            NSString *savedCSV = [csv copy];
            dispatch_async(dispatch_get_main_queue(), ^{
                self.stressCSV = savedCSV;
                self.stressRunning = NO;
                [self note:[NSString stringWithFormat:
                    @"FUZZ: RESULTADO pasos=%u/%u creaciones=%u verificaciones=%u liberaciones=%u anomalías=%u",
                    executed, totalSteps, creates, checks, releases, anomalies]];
                [self note:[NSString stringWithFormat:
                    @"FUZZ: detalles create_null=%u lookup_null=%u contenido=%u dimensiones=%u bloqueo=%u ids_vivos_duplicados=%u",
                    createNull, lookupNull, contentMismatch, dimensionsMismatch,
                    lockFailures, duplicateIds]];
                [self note:[NSString stringWithFormat:
                    @"FUZZ: consultas tras liberar disponible=%u ausente=%u; máximo_vivas=%u; duracion=%.3fs",
                    postReleaseAvailable, postReleaseMissing, maxLive, elapsed]];
                [self note:stopped ? @"FUZZ: DETENIDO por usuario; todos los objetos retenidos fueron liberados."
                                   : @"FUZZ: COMPLETADO; todos los objetos retenidos fueron liberados."];
                [self note:@"FUZZ: exporta registro y CSV para revisar cada operación. Ninguna señal equivale a KernelRW sin confirmación independiente."];
            });
        }
    });
}

- (void)shareLog:(id)sender {
    NSString *p = [NSTemporaryDirectory() stringByAppendingPathComponent:@"IOSurfacePreflight-log.txt"];
    NSError *error = nil;
    if (![self.events writeToFile:p atomically:YES encoding:NSUTF8StringEncoding error:&error]) {
        [self note:[NSString stringWithFormat:@"EXPORT: %@", error.localizedDescription]];
        return;
    }
    NSMutableArray *filesToShare = [NSMutableArray arrayWithObject:[NSURL fileURLWithPath:p]];
    if (self.stressCSV.length > 0) {
        NSString *csvPath = [NSTemporaryDirectory() stringByAppendingPathComponent:@"IOSurfacePreflight-v6-fuzz.csv"];
        NSError *csvError = nil;
        if ([self.stressCSV writeToFile:csvPath atomically:YES encoding:NSUTF8StringEncoding error:&csvError]) {
            [filesToShare addObject:[NSURL fileURLWithPath:csvPath]];
        } else {
            [self note:[NSString stringWithFormat:@"FUZZ: error exportando CSV: %@", csvError.localizedDescription]];
        }
    }
    UIActivityViewController *sharing = [[UIActivityViewController alloc]
      initWithActivityItems:filesToShare applicationActivities:nil];
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
