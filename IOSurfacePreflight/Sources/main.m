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
    title.text = @"IOSurface Preflight";
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
