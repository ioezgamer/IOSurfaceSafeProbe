#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <CoreFoundation/CoreFoundation.h>
#import <mach/mach.h>
#import <mach/mach_time.h>
#import <sys/utsname.h>
#import <sys/sysctl.h>
#import <sys/time.h>
#import <dlfcn.h>
#import <string.h>
#import <unistd.h>
#import <stdatomic.h>
#import "PFBootClassifier.h"

// Diagnostic public-API harness, with bounded IOSurface read/write and owned references.
// No private externalMethod dispatch, stale pointers or kernel modification.
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
    IOSurfaceRef extra;
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


static NSString *selector17Hex(const uint8_t *data, size_t len) {
    const char *digits="0123456789abcdef";
    char buf[49]={0};
    if (len!=24) return @"INVALID";
    for (size_t i=0;i<len;i++) {
        buf[i*2]=digits[data[i] >> 4];
        buf[i*2+1]=digits[data[i] & 15];
    }
    return [NSString stringWithUTF8String:buf];
}


static NSString *preflightBootStamp(void) {
    struct timeval boot={0};
    size_t bytes=sizeof(boot);
    if(sysctlbyname("kern.boottime",&boot,&bytes,NULL,0)!=0) return @"UNAVAILABLE";
    return [NSString stringWithFormat:@"%lld.%06d",
             (long long)boot.tv_sec,(int)boot.tv_usec];
}

static uint8_t preflightExpectedByte(unsigned caseNo,size_t offset) {
    return (uint8_t)(((uint64_t)caseNo*37ULL +
                      (uint64_t)offset*19ULL + (offset>>7))&255ULL);
}

// v19.2: requested-input groups are not proved reasons for a rejected call.
static NSString *PFBoundaryRequestedGroup(size_t width, size_t height, size_t elem,
                                          size_t row, size_t alloc,
                                          BOOL omitRow, BOOL omitAlloc) {
    if(omitRow && omitAlloc) return @"OMITTED_BOTH";
    if(omitRow) return @"OMITTED_STRIDE";
    if(omitAlloc) return @"OMITTED_ALLOC";
    if(width==0 || height==0) return @"ZERO_REQUEST_DIMENSION";
    if(row < width*elem) return @"REQUESTED_ROW_BELOW_PIXEL_WIDTH";
    size_t span=(height-1)*row+width*elem;
    if(alloc < span) return @"REQUESTED_ALLOC_BELOW_LAST_PIXEL";
    if(alloc < height*row) return @"REQUESTED_ALLOC_BELOW_FULL_ROWS";
    return @"OTHER_REQUEST";
}

static void PFCount(NSMutableDictionary<NSString *,NSNumber *> *group, NSString *name) {
    group[name]=@([group[name] unsignedIntegerValue]+1U);
}

@interface ProbeController : UIViewController
@property(nonatomic, strong) UITextView *logView;
@property(nonatomic, copy) NSString *bootSessionID;
@property(nonatomic, strong) NSMutableString *events;
@property(nonatomic, assign) BOOL matrixRunning;
@property(nonatomic, assign) BOOL stressRunning;
@property(atomic, assign) BOOL stressStopRequested;
@property(nonatomic, strong) NSString *stressCSV;
@property(atomic, assign) BOOL controlledCloseRequested;
@property(atomic, assign) BOOL controlledCloseRunning;
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

// Records observations, not kernel events or proof of a panic.
- (void)recordBootEvent:(NSString *)event {
    NSString *dir=[NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
    NSString *checkpoint=[dir stringByAppendingPathComponent:@"IOSurfaceBootMonitor-checkpoint.json"];
    NSString *tracePath=[dir stringByAppendingPathComponent:@"IOSurfaceBootMonitor-trace.csv"];
    NSData *oldBytes=[NSData dataWithContentsOfFile:checkpoint];
    id decoded=oldBytes?[NSJSONSerialization JSONObjectWithData:oldBytes options:0 error:NULL]:nil;
    NSDictionary *previous=[decoded isKindOfClass:NSDictionary.class] ? decoded : nil;

    double uptime=NSProcessInfo.processInfo.systemUptime;
    NSString *stamp=preflightBootStamp();
    BOOL haveEpoch=![stamp isEqualToString:@"UNAVAILABLE"];
    double epoch=haveEpoch?stamp.doubleValue:0;
    NSNumber *oldUptime=[previous[@"uptimeSeconds"] isKindOfClass:NSNumber.class] ?
        previous[@"uptimeSeconds"] : nil;
    NSNumber *oldEpoch=[previous[@"bootEpochSeconds"] isKindOfClass:NSNumber.class] ?
        previous[@"bootEpochSeconds"] : nil;
    PFBootResult verdict=PFDetermineBoot(
        oldUptime.doubleValue,oldUptime!=nil,uptime,YES,
        oldEpoch.doubleValue,oldEpoch!=nil,epoch,haveEpoch);
    NSString *status=previous?[NSString stringWithUTF8String:PFBootResultName(verdict)]:
        @"BASELINE_CREATED";
    NSString *date=[NSDate date].description;
    NSDictionary *sample=@{
        @"schema":@"v19-uptime-observations",
        @"event":event,@"sessionID":self.bootSessionID?:@"UNKNOWN",
        @"uptimeSeconds":@(uptime),
        @"bootEpochSeconds":haveEpoch?@(epoch):(id)NSNull.null,
        @"previousUptimeSeconds":oldUptime?:NSNull.null,
        @"previousBootEpochSeconds":oldEpoch?:NSNull.null,
        @"status":status,@"timestamp":date,
        @"rebootCause":@"NOT_DETERMINABLE_WITH_PUBLIC_API",
        @"kernelPanicProven":@NO
    };
    NSData *json=[NSJSONSerialization dataWithJSONObject:sample
                                      options:NSJSONWritingPrettyPrinted error:NULL];
    BOOL persisted=json && [json writeToFile:checkpoint
                                    options:NSDataWritingAtomic error:NULL];
    // Bounded append-only diagnostic trail, separate from the current state.
    NSString *header=@"timestamp,session,event,uptime_seconds,boot_epoch_seconds,previous_uptime_seconds,status,checkpoint_saved\n";
    NSString *line=[NSString stringWithFormat:
        @"%@,%@,%@,%.3f,%@,%@,%@,%d\n",
        [date stringByReplacingOccurrencesOfString:@"," withString:@" "],
        self.bootSessionID?:@"UNKNOWN",event,uptime,
        haveEpoch?[NSString stringWithFormat:@"%.6f",epoch]:@"NA",
        oldUptime?[NSString stringWithFormat:@"%.3f",oldUptime.doubleValue]:@"NA",
        status,(int)persisted];
    NSMutableData *csv=[[NSData dataWithContentsOfFile:tracePath] mutableCopy];
    if(!csv || csv.length>65536)
        csv=[[header dataUsingEncoding:NSUTF8StringEncoding] mutableCopy];
    [csv appendData:[line dataUsingEncoding:NSUTF8StringEncoding]];
    BOOL saved=[csv writeToFile:tracePath options:NSDataWritingAtomic error:NULL];
    [self note:[NSString stringWithFormat:
        @"BOOTMON: %@ resultado=%@ uptime=%.3f prev=%@ epoch=%@ checkpoint=%@ trace=%@",
        event,status,uptime,oldUptime?:@"NA",stamp,
        persisted?@"OK":@"ERROR",saved?@"OK":@"ERROR"]];
    if(verdict==PFBootUptimeRolledBack)
        [self note:@"BOOTMON: retroceso de uptime indica reinicio entre observaciones, NO su causa."];
    else if(verdict==PFBootBootEpochChangedUnconfirmed)
        [self note:@"BOOTMON: cambió kern.boottime sin retroceso del uptime; INDETERMINADO, posible ajuste de reloj."];
}

- (void)observeAppLifecycle:(NSNotification *)notification {
    NSString *event=[notification.name isEqualToString:UIApplicationDidEnterBackgroundNotification]?
        @"DID_ENTER_BACKGROUND":
        [notification.name isEqualToString:UIApplicationWillEnterForegroundNotification]?
        @"WILL_ENTER_FOREGROUND":
        [notification.name isEqualToString:UIApplicationDidBecomeActiveNotification]?
        @"DID_BECOME_ACTIVE":@"WILL_RESIGN_ACTIVE";
    [self recordBootEvent:event];
}

- (void)dealloc {
    [NSNotificationCenter.defaultCenter removeObserver:self];
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
    title.text = @"IOSurface Preflight v19.2";
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
      [self button:@"7. Campaña de estados (30.000 operaciones)" action:@selector(campaignProbe:)],
      [self button:@"8. Repetir última campaña" action:@selector(replayCampaignProbe:)],
      [self button:@"9. Fuzzing de límites (50.000 casos)" action:@selector(boundaryProbe:)],
      [self button:@"10. Repetir fuzzing de límites" action:@selector(replayBoundaryProbe:)],
      [self button:@"11. Fuzzing dirigido IOSurfaceRoot selector 17 (256 casos)" action:@selector(selector17Probe:)],
      [self button:@"12. Repetir selector 17 (misma semilla)" action:@selector(replaySelector17Probe:)],
      [self button:@"13. Comprobar contrato asíncrono (1 intento)" action:@selector(asyncContractProbe:)],
      [self button:@"14. Observar respuesta asíncrona (3 s)" action:@selector(asyncObserverProbe:)],
      [self button:@"15. Verificar integridad de buffers (256 casos)" action:@selector(integrityProbe:)],
      [self button:@"16. Preparar cierre controlado (superficie viva)" action:@selector(controlledCloseProbe:)],
      [self button:@"17. Ejecutar cierre ahora" action:@selector(fireControlledClose:)],
      [self button:@"18. Concurrencia publica controlada (256 x 2)" action:@selector(publicConcurrencyProbe:)],
      [self button:@"19. Mismo cliente: llamada 17 y cierre (12 ensayos)" action:@selector(sameClientProbe:)],
      [self button:@"20. Controles IPC: abierto y cerrado (3 pares)" action:@selector(ipcControlsProbe:)],
      [self button:@"21. Fuzzing corregido IOSurface (100.000 casos)" action:@selector(bruteForceProbe:)],
      [self button:@"22. Repetir fuerza bruta (misma semilla)" action:@selector(replayBruteForceProbe:)],
      [self button:@"Detener prueba activa" action:@selector(stopStressProbe:)],
      [self button:@"Exportar registro, CSV y checkpoint" action:@selector(shareLog:)],
      self.logView
    ]];
    layout.axis = UILayoutConstraintAxisVertical;
    layout.spacing = 12;
    layout.translatesAutoresizingMaskIntoConstraints = NO;
    UIScrollView *scroll = [[UIScrollView alloc] initWithFrame:CGRectZero];
    scroll.translatesAutoresizingMaskIntoConstraints = NO;
    scroll.alwaysBounceVertical = YES;
    [scroll addSubview:layout];
    [self.view addSubview:scroll];
    UILayoutGuide *safe = self.view.safeAreaLayoutGuide;
    [NSLayoutConstraint activateConstraints:@[
      [scroll.topAnchor constraintEqualToAnchor:safe.topAnchor],
      [scroll.bottomAnchor constraintEqualToAnchor:safe.bottomAnchor],
      [scroll.leadingAnchor constraintEqualToAnchor:safe.leadingAnchor],
      [scroll.trailingAnchor constraintEqualToAnchor:safe.trailingAnchor],
      [layout.topAnchor constraintEqualToAnchor:scroll.contentLayoutGuide.topAnchor constant:12],
      [layout.bottomAnchor constraintEqualToAnchor:scroll.contentLayoutGuide.bottomAnchor constant:-12],
      [layout.leadingAnchor constraintEqualToAnchor:scroll.contentLayoutGuide.leadingAnchor constant:16],
      [layout.trailingAnchor constraintEqualToAnchor:scroll.contentLayoutGuide.trailingAnchor constant:-16],
      [layout.widthAnchor constraintEqualToAnchor:scroll.frameLayoutGuide.widthAnchor constant:-32],
      [self.logView.heightAnchor constraintEqualToConstant:280]
    ]];

    struct utsname info = {0};
    uname(&info);
    [self note:[NSString stringWithFormat:@"device=%s iOS=%@", info.machine, UIDevice.currentDevice.systemVersion]];
    char build[128] = {0}; size_t len = sizeof(build);
    if (sysctlbyname("kern.osversion", build, &len, NULL, 0) == 0)
        [self note:[NSString stringWithFormat:@"build=%s", build]];
    [self note:@"app=IOSurfacePreflight-v19.2"]; 
    [self note:@"Modo diagnóstico: observaciones públicas sin afirmar fallos del kernel."];
    self.bootSessionID=NSUUID.UUID.UUIDString;
    [self recordBootEvent:@"APP_LAUNCHED"];
    for(NSString *name in @[UIApplicationDidEnterBackgroundNotification,
                              UIApplicationWillEnterForegroundNotification,
                              UIApplicationDidBecomeActiveNotification,
                              UIApplicationWillResignActiveNotification]) {
        [NSNotificationCenter.defaultCenter addObserver:self
            selector:@selector(observeAppLifecycle:) name:name object:nil];
    }
    NSString *brutePath=[NSHomeDirectory() stringByAppendingPathComponent:
        @"Documents/IOSurfaceBruteForce-checkpoint.json"];
    NSData *bruteBytes=[NSData dataWithContentsOfFile:brutePath];
    if(bruteBytes) {
        NSDictionary *prior=[NSJSONSerialization JSONObjectWithData:bruteBytes
                                                            options:0 error:NULL];
        if([prior isKindOfClass:NSDictionary.class]) {
            [self note:[NSString stringWithFormat:
                @"BRUTE (v17): anterior status=%@ paso=%@ seed=%@",
                prior[@"status"] ?: @"?",prior[@"step"] ?: @"?",prior[@"seed"] ?: @"?"]];
            if([prior[@"status"] isEqualToString:@"RUNNING"])
                [self note:@"BRUTE: ejecución previa incompleta; no significa vulnerabilidad por si sola."];
        }
    }
    NSString *v18Path=[NSHomeDirectory() stringByAppendingPathComponent:
        @"Documents/IOSurfaceBruteForce-v18-checkpoint.json"];
    NSData *v18Bytes=[NSData dataWithContentsOfFile:v18Path];
    if(v18Bytes) {
        NSDictionary *prior=[NSJSONSerialization JSONObjectWithData:v18Bytes options:0 error:NULL];
        if([prior isKindOfClass:NSDictionary.class])
            [self note:[NSString stringWithFormat:@"BRUTE v18: previo status=%@ paso=%@ seed=%@",
                prior[@"status"]?:@"?",prior[@"step"]?:@"?",prior[@"seed"]?:@"?"]];
    }
    NSString *ipcControlsPath=[NSHomeDirectory() stringByAppendingPathComponent:
        @"Documents/IOSurfaceIPCControls-checkpoint.json"];
    NSData *previousControlBytes=[NSData dataWithContentsOfFile:ipcControlsPath];
    if(previousControlBytes) {
        NSDictionary *oldControl=[NSJSONSerialization JSONObjectWithData:previousControlBytes options:0 error:NULL];
        if([oldControl isKindOfClass:NSDictionary.class]) {
            [self note:[NSString stringWithFormat:
                @"IPCCTRL: anterior status=%@ caso=%@",
                oldControl[@"status"] ?: @"?",oldControl[@"case"] ?: @"?"]];
            if([oldControl[@"status"] isEqualToString:@"RUNNING"])
                [self note:@"IPCCTRL: ejecucion anterior incompleta, sin evidencia de panic por si sola."];
        }
    }
    NSString *samePath=[NSHomeDirectory() stringByAppendingPathComponent:
        @"Documents/IOSurfaceSameClient-checkpoint.json"];
    NSData *sameBytes=[NSData dataWithContentsOfFile:samePath];
    if(sameBytes) {
        NSDictionary *prior=[NSJSONSerialization JSONObjectWithData:sameBytes options:0 error:NULL];
        if([prior isKindOfClass:NSDictionary.class]) {
            [self note:[NSString stringWithFormat:@"SAMECLIENT: anterior=%@ intento=%@ solapamiento=%@",
                prior[@"status"] ?: @"?",prior[@"trial"] ?: @"?",
                prior[@"userSpaceOverlap"] ?: @"?"]];
            if([prior[@"status"] isEqualToString:@"RUNNING"])
                [self note:@"SAMECLIENT: ejecución incompleta; no implica kernel panic ni UAF."];
        }
    }
    NSString *concurrentCheckpointPath=[NSHomeDirectory() stringByAppendingPathComponent:
        @"Documents/IOSurfaceConcurrency-checkpoint.json"];
    NSData *concurrentPrevious=[NSData dataWithContentsOfFile:concurrentCheckpointPath];
    if(concurrentPrevious) {
        NSDictionary *prior=[NSJSONSerialization JSONObjectWithData:concurrentPrevious
                                                             options:0 error:NULL];
        if([prior isKindOfClass:NSDictionary.class]) {
            [self note:[NSString stringWithFormat:@"CONCURRENT: previo status=%@ overlapped=%@",
                prior[@"status"] ?: @"?",prior[@"observedCreateOverlap"] ?: @"?"]];
            if([prior[@"status"] isEqualToString:@"RUNNING"])
                [self note:@"CONCURRENT: ejecucion anterior incompleta; no confirma reinicio causado por el kernel."];
        }
    }
    NSString *closeCheckpointPath = [NSHomeDirectory() stringByAppendingPathComponent:
        @"Documents/IOSurfaceControlledClose-checkpoint.json"];
    NSData *closePrevData=[NSData dataWithContentsOfFile:closeCheckpointPath];
    if(closePrevData) {
        NSDictionary *previousClose=[NSJSONSerialization JSONObjectWithData:closePrevData options:0 error:NULL];
        if([previousClose isKindOfClass:NSDictionary.class]) {
            NSString *lastStatus=previousClose[@"status"] ?: @"?";
            NSString *lastPhase=previousClose[@"phase"] ?: @"?";
            [self note:[NSString stringWithFormat:
                @"CIERRE: ejecución anterior status=%@ phase=%@", lastStatus,lastPhase]];
            if([lastStatus isEqualToString:@"RUNNING"])
                [self note:@"CIERRE: ejecución incompleta; no demuestra fallo ni liberación de memoria kernel."];
        }
    }
    NSString *integrityPath=[NSHomeDirectory() stringByAppendingPathComponent:
        @"Documents/IOSurfaceIntegrity-checkpoint.json"];
    NSData *integrityPrevious=[NSData dataWithContentsOfFile:integrityPath];
    if(integrityPrevious) {
        NSDictionary *last=[NSJSONSerialization JSONObjectWithData:integrityPrevious options:0 error:NULL];
        if([last isKindOfClass:NSDictionary.class]) {
            [self note:[NSString stringWithFormat:
                @"INTEGRITY: checkpoint previo status=%@ caso=%@ discrepancias=%@",
                last[@"status"] ?: @"?",last[@"case"] ?: @"?",last[@"mismatches"] ?: @"?"]];
            if(last[@"bootStamp"] && !last[@"uptimeSeconds"])
                [self note:@"INTEGRITY: checkpoint v18 solo contiene bootStamp: LEGACY_INDETERMINATE. No demuestra reinicio."];
            if([last[@"status"] isEqualToString:@"RUNNING"])
                [self note:@"INTEGRITY: ejecución incompleta; no equivale a kernel panic."];
        }
    }
    NSString *observerCheckpointPath=[NSHomeDirectory() stringByAppendingPathComponent:
        @"Documents/IOSurfaceAsyncObserver-checkpoint.json"];
    NSData *observerPrevious=[NSData dataWithContentsOfFile:observerCheckpointPath];
    if(observerPrevious) {
        NSDictionary *last=[NSJSONSerialization JSONObjectWithData:observerPrevious options:0 error:NULL];
        if([last isKindOfClass:NSDictionary.class]) {
            [self note:[NSString stringWithFormat:
                @"OBSERVE: previo status=%@ phase=%@ resultado=%@ mensajes=%@",
                last[@"status"] ?: @"?", last[@"phase"] ?: @"?",
                last[@"callReturn"] ?: @"?", last[@"messages"] ?: @"?"]];
        }
    }
    NSString *asyncCheckpointPath = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/IOSurfaceAsyncContract-checkpoint.json"];
    NSData *asyncPrevious = [NSData dataWithContentsOfFile:asyncCheckpointPath];
    if (asyncPrevious) {
        NSDictionary *previous = [NSJSONSerialization JSONObjectWithData:asyncPrevious options:0 error:NULL];
        if ([previous isKindOfClass:NSDictionary.class]) {
            [self note:[NSString stringWithFormat:
                @"ASYNC: checkpoint anterior %@ fase=%@ retorno=%@",
                previous[@"status"] ?: @"?", previous[@"phase"] ?: @"?", previous[@"callReturn"] ?: @"?"]];
        }
    }
    NSString *selectorCheckpointPath = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/IOSurfaceSelector17-checkpoint.json"];
    NSData *selectorCheckpointBytes = [NSData dataWithContentsOfFile:selectorCheckpointPath];
    if (selectorCheckpointBytes) {
        NSDictionary *last = [NSJSONSerialization JSONObjectWithData:selectorCheckpointBytes options:0 error:NULL];
        if ([last isKindOfClass:NSDictionary.class]) {
            NSString *status = last[@"status"] ?: @"?";
            NSString *phase = last[@"phase"] ?: @"?";
            NSString *warning = [status isEqualToString:@"RUNNING"] && [phase isEqualToString:@"BEFORE_IPC"]
                ? @" | ejecución interrumpida antes de registrar retorno; motivo NO confirmado" : @"";
            [self note:[NSString stringWithFormat:
                @"SELECTOR17: previo status=%@ phase=%@ caso=%@%@",
                status,phase,last[@"case"] ?: @"?",warning]];
        }
    }
    NSString *boundaryPath = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/IOSurfaceBoundary-checkpoint.json"];
    NSData *boundaryBytes = [NSData dataWithContentsOfFile:boundaryPath];
    if (boundaryBytes) {
        NSDictionary *b = [NSJSONSerialization JSONObjectWithData:boundaryBytes options:0 error:NULL];
        if ([b isKindOfClass:NSDictionary.class]) {
            [self note:[NSString stringWithFormat:@"BOUNDARY: última campaña %@ seed=%@ paso=%@",
                b[@"status"] ?: @"?", b[@"seed"] ?: @"?", b[@"step"] ?: @"?"]];
        }
    }
    NSString *p = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/IOSurfaceCampaign-checkpoint.json"];
    NSData *previous = [NSData dataWithContentsOfFile:p];
    if (previous) {
        NSDictionary *state = [NSJSONSerialization JSONObjectWithData:previous options:0 error:NULL];
        NSString *status = [state isKindOfClass:NSDictionary.class] ? state[@"status"] : nil;
        if ([status isEqualToString:@"RUNNING"]) {
            [self note:[NSString stringWithFormat:
                @"CAMPAIGN: EJECUCIÓN PREVIA INCOMPLETA seed=%@ paso=%@ (puede ser cierre, suspensión o reinicio)",
                state[@"seed"] ?: @"?",state[@"step"] ?: @"?"]];
        } else if ([status isEqualToString:@"DONE"] || [status isEqualToString:@"STOPPED"]) {
            [self note:[NSString stringWithFormat:@"CAMPAIGN: registro anterior %@ seed=%@",
                status,state[@"seed"] ?: @"?"]];
        }
    }
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
        [self note:@"CAMPAIGN: no hay prueba activa."];
        return;
    }
    self.stressStopRequested = YES;
    [self note:@"CAMPAIGN: detención solicitada; se liberarán las referencias vigentes."];
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


- (void)replayCampaignProbe:(id)sender {
    id value = [NSUserDefaults.standardUserDefaults objectForKey:@"IOSurfaceV7LastSeed"];
    if (![value isKindOfClass:NSNumber.class]) {
        [self note:@"CAMPAIGN: no hay una semilla anterior para repetir."];
        return;
    }
    uint32_t seed = (uint32_t)[(NSNumber *)value unsignedIntValue];
    [self runCampaignWithSeed:seed replay:YES];
}

- (void)campaignProbe:(id)sender {
    uint32_t seed = arc4random();
    if (!seed) seed = 0x71A72345;
    [self runCampaignWithSeed:seed replay:NO];
}

- (void)runCampaignWithSeed:(uint32_t)seed replay:(BOOL)replay {
    if (self.stressRunning || self.matrixRunning) {
        [self note:@"CAMPAIGN: ya hay una prueba activa; no ejecutamos simultáneamente."];
        return;
    }
    self.stressRunning = YES;
    self.stressStopRequested = NO;
    self.stressCSV = nil;
    [NSUserDefaults.standardUserDefaults setObject:@(seed) forKey:@"IOSurfaceV7LastSeed"];
    NSString *runID = NSUUID.UUID.UUIDString;
    NSString *checkPath = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/IOSurfaceCampaign-checkpoint.json"];
    [self note:[NSString stringWithFormat:@"CAMPAIGN: %@ run=%@ seed=%u (0x%08x)",
        replay ? @"REPLAY" : @"NEW", runID, seed, seed]];
    [self note:@"CAMPAIGN: 30000 operaciones, 20 objetos vivos máximo, referencias independientes, mutaciones y verificaciones."];
    [self note:@"CAMPAIGN: cada 500 casos se guarda el progreso en Documents; si se interrumpe, queda un checkpoint."];
    [self note:@"CAMPAIGN: se intercalan aperturas/cierres válidos de IOSurfaceRoot sin selector privado."];
    [self note:@"CAMPAIGN: no hay llamadas con punteros liberados ni competencia intencional entre hilos."];
    // Persist the initial marker before any work starts: early exits are visible on relaunch.
    NSDictionary *initialCheckpoint = @{
        @"run":runID, @"seed":@(seed), @"step":@0, @"status":@"RUNNING",
        @"anomalies":@0, @"timestamp":[NSDate date].description
    };
    NSData *initialData = [NSJSONSerialization dataWithJSONObject:initialCheckpoint options:0 error:NULL];
    if (initialData) [initialData writeToFile:checkPath options:NSDataWritingAtomic error:NULL];
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        @autoreleasepool {
            const unsigned limit=30000, capacity=20;
            const size_t dimensions[]={8,16,24,32,48,64,96,128};
            const size_t paddings[]={0,16,32,64};
            ProbeLiveSurface objects[20]={0};
            uint32_t state=seed;
            unsigned executed=0, created=0, verified=0, modified=0;
            unsigned closed=0, droppedExtra=0, retainedExtra=0, anomalies=0, peak=0, alive=0;
            unsigned badCreate=0, badLookup=0, badContent=0, badMetadata=0, badLock=0, duplicateLive=0;
            unsigned rootOpenOk=0, rootOpenError=0, postCloseAvailable=0;
            CFAbsoluteTime began=CFAbsoluteTimeGetCurrent();
            NSMutableString *records=[NSMutableString stringWithFormat:
                @"run,seed,step,action,slot,id,expected,observed,result\n%@,%u,0,START,-1,0,0,0,START\n",
                runID,seed];

            void *framework=dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY|RTLD_LOCAL);
            CreateSurfaceFn create=framework ? (CreateSurfaceFn)dlsym(framework,"IOSurfaceCreate") : NULL;
            GetSurfaceIDFn getID=framework ? (GetSurfaceIDFn)dlsym(framework,"IOSurfaceGetID") : NULL;
            LookupSurfaceFn lookup=framework ? (LookupSurfaceFn)dlsym(framework,"IOSurfaceLookup") : NULL;
            GetSurfaceDimensionFn getW=framework ? (GetSurfaceDimensionFn)dlsym(framework,"IOSurfaceGetWidth") : NULL;
            GetSurfaceDimensionFn getH=framework ? (GetSurfaceDimensionFn)dlsym(framework,"IOSurfaceGetHeight") : NULL;
            GetSurfaceDimensionFn getAlloc=framework ? (GetSurfaceDimensionFn)dlsym(framework,"IOSurfaceGetAllocSize") : NULL;
            GetSurfaceBaseFn base=framework ? (GetSurfaceBaseFn)dlsym(framework,"IOSurfaceGetBaseAddress") : NULL;
            SurfaceLockFn lock=framework ? (SurfaceLockFn)dlsym(framework,"IOSurfaceLock") : NULL;
            SurfaceLockFn unlock=framework ? (SurfaceLockFn)dlsym(framework,"IOSurfaceUnlock") : NULL;

            void *io=dlopen("/System/Library/Frameworks/IOKit.framework/IOKit",RTLD_LAZY|RTLD_LOCAL);
            MatchingFn matching=io ? (MatchingFn)dlsym(io,"IOServiceMatching") : NULL;
            GetMatchingFn getService=io ? (GetMatchingFn)dlsym(io,"IOServiceGetMatchingService") : NULL;
            OpenServiceFn openService=io ? (OpenServiceFn)dlsym(io,"IOServiceOpen") : NULL;
            CloseServiceFn closeService=io ? (CloseServiceFn)dlsym(io,"IOServiceClose") : NULL;
            ReleaseObjectFn releaseService=io ? (ReleaseObjectFn)dlsym(io,"IOObjectRelease") : NULL;

            BOOL ready=create && getID && lookup && getW && getH && getAlloc && base && lock && unlock;
            if (!ready) {
                NSDictionary *failed=@{
                    @"run":runID,@"seed":@(seed),@"step":@0,@"status":@"ERROR",
                    @"reason":@"MISSING_PUBLIC_SYMBOLS"
                };
                NSData *failedBytes=[NSJSONSerialization dataWithJSONObject:failed options:0 error:NULL];
                if(failedBytes) [failedBytes writeToFile:checkPath options:NSDataWritingAtomic error:NULL];
                if (framework) dlclose(framework);
                if (io) dlclose(io);
                dispatch_async(dispatch_get_main_queue(), ^{
                    self.stressRunning=NO;
                    [self note:@"CAMPAIGN: faltan símbolos IOSurface públicos; ejecución cancelada."];
                });
                return;
            }
            BOOL stopped=NO;
            for (unsigned step=1;step<=limit;step++) {
                if (self.stressStopRequested) { stopped=YES; break; }
                @autoreleasepool {
                    unsigned index=probeRandom(&state)%capacity;
                    unsigned op=probeRandom(&state)%100;
                    ProbeLiveSurface *v=&objects[index];
                    const char *action="CREATE", *result="PASS";
                    IOSurfaceID id=v->identifier;
                    uint64_t expected=v->marker,observed=0;

                    if (!v->held) {
                        size_t w=dimensions[probeRandom(&state)%8];
                        size_t h=dimensions[probeRandom(&state)%8];
                        size_t row=w*4+paddings[probeRandom(&state)%4];
                        size_t alloc=row*h;
                        expected=0x71A72026ABCD0000ULL ^ ((uint64_t)step<<21) ^
                                 ((uint64_t)index<<15) ^ probeRandom(&state);
                        NSDictionary *params=@{
                            @"IOSurfaceWidth":@(w),@"IOSurfaceHeight":@(h),
                            @"IOSurfaceBytesPerElement":@4,@"IOSurfaceBytesPerRow":@(row),
                            @"IOSurfaceAllocSize":@(alloc),@"IOSurfacePixelFormat":@(0x42475241)
                        };
                        IOSurfaceRef original=create((__bridge CFDictionaryRef)params);
                        if (!original) {
                            badCreate++; result="CREATE_NULL";
                        } else {
                            id=getID(original);
                            IOSurfaceRef held=lookup(id);
                            IOSurfaceRef extra=held ? lookup(id) : NULL;
                            CFRelease(original);
                            if (!held || !extra) {
                                badLookup++;result="LOOKUP_NULL";
                                if (held) CFRelease(held);
                                if (extra) CFRelease(extra);
                            } else {
                                kern_return_t kr=lock(held,0,NULL);
                                if (kr!=KERN_SUCCESS) {
                                    badLock++;result="INITIAL_LOCK";
                                } else {
                                    void *ptr=base(held);
                                    if (ptr) memcpy(ptr,&expected,sizeof(expected));
                                    else {badLock++;result="INITIAL_BASE_NULL";}
                                    kern_return_t u=unlock(held,0,NULL);
                                    if (u!=KERN_SUCCESS) {badLock++;result="INITIAL_UNLOCK";}
                                }
                                if (strcmp(result,"PASS")==0) {
                                    for(unsigned j=0;j<capacity;j++)
                                        if(objects[j].held && objects[j].identifier==id) {
                                            duplicateLive++;result="DUPLICATE_LIVE_ID";break;
                                        }
                                }
                                if (strcmp(result,"PASS")==0) {
                                    v->held=held;v->extra=extra;v->identifier=id;
                                    v->width=w;v->height=h;v->rowBytes=row;v->allocated=alloc;v->marker=expected;
                                    created++;alive++;if(alive>peak)peak=alive;
                                } else {
                                    CFRelease(held);CFRelease(extra);
                                }
                            }
                        }
                    } else if (op<20) {
                        action="RELEASE";
                        if(v->extra) CFRelease(v->extra);
                        CFRelease(v->held);
                        memset(v,0,sizeof(*v));
                        alive--;closed++;
                        IOSurfaceRef found=lookup(id);
                        if(found){postCloseAvailable++;CFRelease(found);result="RELEASED_ID_AVAILABLE";}
                        else result="RELEASED_ID_UNAVAILABLE";
                    } else if (op<34) {
                        action="EXTRA_REF";
                        if(v->extra) {
                            CFRelease(v->extra);v->extra=NULL;droppedExtra++;
                            result="DROPPED_ONE_REFERENCE";
                        } else {
                            v->extra=lookup(id);
                            if(!v->extra){badLookup++;result="EXTRA_LOOKUP_NULL";}
                            else {retainedExtra++;result="ACQUIRED_SECOND_REFERENCE";}
                        }
                    } else if (op<58) {
                        action="WRITE";
                        IOSurfaceRef ref=lookup(id);
                        if(!ref) {badLookup++;result="WRITE_LOOKUP_NULL";}
                        else {
                            uint64_t next=expected ^ ((uint64_t)step<<7) ^ probeRandom(&state);
                            kern_return_t kr=lock(ref,0,NULL);
                            if(kr!=KERN_SUCCESS){badLock++;result="WRITE_LOCK";}
                            else {
                                void *ptr=base(ref);
                                if(!ptr){badLock++;result="WRITE_BASE_NULL";}
                                else {memcpy(ptr,&next,sizeof(next));v->marker=next;expected=next;modified++;}
                                kern_return_t u=unlock(ref,0,NULL);
                                if(u!=KERN_SUCCESS){badLock++;result="WRITE_UNLOCK";}
                            }
                            CFRelease(ref);
                        }
                    } else {
                        action="VERIFY";verified++;
                        IOSurfaceRef ref=lookup(id);
                        if(!ref){badLookup++;result="VERIFY_LOOKUP_NULL";}
                        else {
                            if(getW(ref)!=v->width || getH(ref)!=v->height || getAlloc(ref)<v->allocated) {
                                badMetadata++;result="BAD_DIMENSIONS";
                            }
                            kern_return_t kr=lock(ref,1,NULL);
                            if(kr!=KERN_SUCCESS){badLock++;result="READ_LOCK";}
                            else {
                                void *ptr=base(ref);
                                if(!ptr){badLock++;result="READ_BASE_NULL";}
                                else {
                                    memcpy(&observed,ptr,sizeof(observed));
                                    if(observed!=expected){badContent++;result="BAD_CONTENT";}
                                }
                                kern_return_t u=unlock(ref,1,NULL);
                                if(u!=KERN_SUCCESS){badLock++;result="READ_UNLOCK";}
                            }
                            CFRelease(ref);
                        }
                    }
                    if(strcmp(result,"PASS")!=0 &&
                       strcmp(result,"DROPPED_ONE_REFERENCE")!=0 &&
                       strcmp(result,"ACQUIRED_SECOND_REFERENCE")!=0 &&
                       strcmp(result,"RELEASED_ID_AVAILABLE")!=0 &&
                       strcmp(result,"RELEASED_ID_UNAVAILABLE")!=0)
                        anomalies++;
                    [records appendFormat:@"%@,%u,%u,%s,%u,%u,0x%016llx,0x%016llx,%s\n",
                        runID,seed,step,action,index,(unsigned)id,
                        (unsigned long long)expected,(unsigned long long)observed,result];
                    executed++;
                }

                if ((step % 500)==0) {
                    // Close an independent, valid service connection while surfaces are alive.
                    if (matching && getService && openService && closeService && releaseService) {
                        CFMutableDictionaryRef dict=matching("IOSurfaceRoot");
                        if(dict) {
                            io_service_t service=getService(MACH_PORT_NULL,dict);
                            if(service) {
                                io_connect_t conn=MACH_PORT_NULL;
                                kern_return_t k=openService(service,mach_task_self(),0,&conn);
                                if(k==KERN_SUCCESS && conn) {
                                    rootOpenOk++;
                                    closeService(conn);
                                } else rootOpenError++;
                                releaseService(service);
                            } else rootOpenError++;
                        } else rootOpenError++;
                    }
                    NSDictionary *checkpoint=@{
                        @"run":runID,@"seed":@(seed),@"step":@(step),
                        @"status":@"RUNNING",@"created":@(created),@"verified":@(verified),
                        @"anomalies":@(anomalies),@"timestamp":[NSDate date].description
                    };
                    NSData *bytes=[NSJSONSerialization dataWithJSONObject:checkpoint options:0 error:NULL];
                    if(bytes) [bytes writeToFile:checkPath options:NSDataWritingAtomic error:NULL];
                    unsigned count=executed, issues=anomalies, aliveNow=alive;
                    dispatch_async(dispatch_get_main_queue(), ^{
                        [self note:[NSString stringWithFormat:
                            @"CAMPAIGN: %u/%u casos, anomalías=%u, objetos_vivos=%u",
                            count,limit,issues,aliveNow]];
                    });
                    usleep(200000);
                }
            }
            for(unsigned j=0;j<capacity;j++) {
                if(objects[j].extra) CFRelease(objects[j].extra);
                if(objects[j].held) CFRelease(objects[j].held);
                memset(&objects[j],0,sizeof(objects[j]));
            }
            if(framework) dlclose(framework);
            if(io) dlclose(io);
            NSDictionary *finish=@{
                @"run":runID,@"seed":@(seed),@"step":@(executed),
                @"status":stopped ? @"STOPPED" : @"DONE",
                @"created":@(created),@"verified":@(verified),@"modified":@(modified),
                @"released":@(closed),@"anomalies":@(anomalies),
                @"rootOpenOk":@(rootOpenOk),@"rootOpenError":@(rootOpenError),
                @"elapsed":@(CFAbsoluteTimeGetCurrent()-began),
                @"timestamp":[NSDate date].description
            };
            NSData *output=[NSJSONSerialization dataWithJSONObject:finish options:NSJSONWritingPrettyPrinted error:NULL];
            if(output) [output writeToFile:checkPath options:NSDataWritingAtomic error:NULL];
            NSString *csv=[records copy];
            dispatch_async(dispatch_get_main_queue(), ^{
                self.stressCSV=csv;
                self.stressRunning=NO;
                [self note:[NSString stringWithFormat:
                    @"CAMPAIGN: FINAL %@ run=%@ seed=%u pasos=%u/%u anomalias=%u",
                    stopped?@"STOPPED":@"DONE",runID,seed,executed,limit,anomalies]];
                [self note:[NSString stringWithFormat:
                    @"CAMPAIGN: create=%u verify=%u write=%u released=%u drop_ref=%u add_ref=%u peak=%u",
                    created,verified,modified,closed,droppedExtra,retainedExtra,peak]];
                [self note:[NSString stringWithFormat:
                    @"CAMPAIGN: ERR create=%u lookup=%u content=%u metadata=%u lock=%u duplicateID=%u",
                    badCreate,badLookup,badContent,badMetadata,badLock,duplicateLive]];
                [self note:[NSString stringWithFormat:
                    @"CAMPAIGN: IOSurfaceRoot open=%u failed=%u IDs disponibles tras cierre=%u",
                    rootOpenOk,rootOpenError,postCloseAvailable]];
                [self note:@"CAMPAIGN: exportá TXT, CSV y checkpoint JSON. Un cierre inesperado no demuestra corrupción del kernel."];
            });
        }
    });
}



- (void)bruteForceProbe:(id)sender {
    if(self.stressRunning || self.matrixRunning || self.controlledCloseRunning) {
        [self note:@"BRUTE: ya se esta ejecutando otra prueba."];
        return;
    }
    UIAlertController *confirm=[UIAlertController alertControllerWithTitle:
        @"Fuzzing de fuerza bruta: 100.000 casos"
        message:@"Ejecuta 100.000 combinaciones reproducibles de la API pública, con clasificación corregida y lectura/escritura/restauración de un solo píxel dentro de superficies nuevas y válidas (muestreo). Puede causar cierres inesperados. Guardá tus datos antes de comenzar."
        preferredStyle:UIAlertControllerStyleAlert];
    [confirm addAction:[UIAlertAction actionWithTitle:@"Cancelar"
           style:UIAlertActionStyleCancel handler:nil]];
    __weak typeof(self) weakSelf=self;
    [confirm addAction:[UIAlertAction actionWithTitle:@"Ejecutar fuzzing"
           style:UIAlertActionStyleDestructive handler:^(UIAlertAction *action) {
        uint32_t seed=arc4random();
        if(seed==0)seed=0xA1172026;
        [weakSelf runBoundaryProbeSeed:seed replay:NO totalCases:100000];
    }]];
    [self presentViewController:confirm animated:YES completion:nil];
}

- (void)replayBruteForceProbe:(id)sender {
    NSNumber *last=[NSUserDefaults.standardUserDefaults objectForKey:@"IOSurfaceBruteForceSeed"];
    if(![last isKindOfClass:NSNumber.class]) {
        [self note:@"BRUTE: todavía no existe una semilla guardada."];
        return;
    }
    [self runBoundaryProbeSeed:(uint32_t)last.unsignedIntValue replay:YES totalCases:100000];
}

- (void)replayBoundaryProbe:(id)sender {
    NSNumber *last = [NSUserDefaults.standardUserDefaults objectForKey:@"IOSurfaceV8BoundarySeed"];
    if (![last isKindOfClass:NSNumber.class]) {
        [self note:@"BOUNDARY: todavía no hay semilla guardada."];
        return;
    }
    [self runBoundaryProbeSeed:(uint32_t)last.unsignedIntValue replay:YES totalCases:50000];
}

- (void)boundaryProbe:(id)sender {
    uint32_t seed = arc4random();
    if (seed == 0) seed = 0xB80A2026;
    [self runBoundaryProbeSeed:seed replay:NO totalCases:50000];
}

- (void)runBoundaryProbeSeed:(uint32_t)seed replay:(BOOL)replay totalCases:(unsigned)limit {
    if (self.stressRunning || self.matrixRunning) {
        [self note:@"BOUNDARY: ya hay una prueba activa."];
        return;
    }
    self.stressRunning = YES;
    self.stressStopRequested = NO;
    self.stressCSV = nil;
    NSString *run = NSUUID.UUID.UUIDString;
    NSString *checkpointName=limit>50000?@"IOSurfaceBruteForce-v18-checkpoint.json":
                                               @"IOSurfaceBoundary-checkpoint.json";
    NSString *checkpoint=[[NSHomeDirectory() stringByAppendingPathComponent:@"Documents"]
                              stringByAppendingPathComponent:checkpointName];
    [NSUserDefaults.standardUserDefaults setObject:@(seed) forKey:@"IOSurfaceV8BoundarySeed"];
    if(limit>50000) [NSUserDefaults.standardUserDefaults setObject:@(seed)
                                                         forKey:@"IOSurfaceBruteForceSeed"];
    [self note:[NSString stringWithFormat:@"BOUNDARY: %@ run=%@ semilla=%u",
        replay ? @"REPLAY" : @"NEW",run,seed]];
    [self note:[NSString stringWithFormat:
        @"BOUNDARY: %u entradas públicas con combinaciones válidas y casi inválidas; memoria acotada.",limit]];
    [self note:@"BOUNDARY: longitudes 0..256, stride y allocSize alrededor del límite, formatos distintos."];
    [self note:@"BOUNDARY: se diferencia relleno de fila de la huella mínima del último píxel."];
    [self note:@"BOUNDARY: dimensiones cero son datos de borde; no son un fallo de seguridad."];
    [self note:@"BOUNDARY: muestreo limitado de escritura/lectura únicamente dentro de superficies BGRA propias."];
    [self note:@"BOUNDARY: un rechazo de entrada inválida es NORMAL, no una anomalía."];
    [self note:@"BOUNDARY: sin llamadas privadas ni punteros obsoletos; checkpoints cada 100 casos."];
    NSDictionary *initial = @{@"run":run,@"seed":@(seed),@"step":@0,@"status":@"RUNNING",
                              @"phase":@"STARTED",@"timestamp":[NSDate date].description};
    NSData *first = [NSJSONSerialization dataWithJSONObject:initial options:0 error:NULL];
    if (first) [first writeToFile:checkpoint options:NSDataWritingAtomic error:NULL];
    // Campaign UUID in the event allows time correlation with the separate trace.
    // A bracket is created before running any public IOSurface API operations.
    [self recordBootEvent:[NSString stringWithFormat:@"BOUNDARY_BEGIN_%@",run]];

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        @autoreleasepool {
            const size_t lengths[] = {0,1,2,3,7,8,15,16,31,32,63,64,127,128,255,256};
            const size_t elements[] = {1,2,3,4,8};
            const uint32_t formats[] = {0x42475241,0x52474241,0,0x41414141};
            uint32_t state = seed;
            unsigned attempts=0,accepted=0,rejected=0,exceptions=0,unusual=0;
            unsigned normalized=0,zeroDimensionAccepted=0,footprintShort=0,shortRow=0;
            unsigned legacyFullRowShort=0,invalidId=0,unexpectedBounds=0;
            unsigned review=0,regular=0,missingSize=0,missingStride=0;
            unsigned sampled=0,samplePassed=0,sampleMismatch=0,sampleLockFailed=0;
            unsigned sampleBaseNull=0,sampleUnlockFailed=0;
            unsigned eligibleIntegrity=0,skippedByBudget=0,byteChecks=0;
            NSMutableDictionary<NSString *,NSMutableDictionary<NSString *,NSNumber *> *> *coverageGroups=[NSMutableDictionary new];
            NSMutableDictionary<NSString *,NSNumber *> *classificationCounts=[NSMutableDictionary new];
            CFAbsoluteTime start=CFAbsoluteTimeGetCurrent();
            NSMutableString *csv = [NSMutableString stringWithFormat:
                @"run,seed,case,width,height,element,row_bytes,alloc_size,format,omit_stride,omit_alloc,id,observed_w,observed_h,observed_row,observed_alloc,min_pixel_span,classification,integrity,result\n"];
            void *framework = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface",RTLD_LAZY|RTLD_LOCAL);
            CreateSurfaceFn create=framework ? (CreateSurfaceFn)dlsym(framework,"IOSurfaceCreate") : NULL;
            GetSurfaceIDFn getID=framework ? (GetSurfaceIDFn)dlsym(framework,"IOSurfaceGetID") : NULL;
            GetSurfaceDimensionFn getW=framework ? (GetSurfaceDimensionFn)dlsym(framework,"IOSurfaceGetWidth") : NULL;
            GetSurfaceDimensionFn getH=framework ? (GetSurfaceDimensionFn)dlsym(framework,"IOSurfaceGetHeight") : NULL;
            GetSurfaceDimensionFn getRow=framework ? (GetSurfaceDimensionFn)dlsym(framework,"IOSurfaceGetBytesPerRow") : NULL;
            GetSurfaceDimensionFn getAlloc=framework ? (GetSurfaceDimensionFn)dlsym(framework,"IOSurfaceGetAllocSize") : NULL;
            GetSurfaceBaseFn getBase=framework ? (GetSurfaceBaseFn)dlsym(framework,"IOSurfaceGetBaseAddress") : NULL;
            SurfaceLockFn lock=framework ? (SurfaceLockFn)dlsym(framework,"IOSurfaceLock") : NULL;
            SurfaceLockFn unlock=framework ? (SurfaceLockFn)dlsym(framework,"IOSurfaceUnlock") : NULL;
            if (!create || !getID || !getW || !getH || !getRow || !getAlloc) {
                if (framework) dlclose(framework);
                NSDictionary *failure=@{@"run":run,@"seed":@(seed),@"step":@0,
                                        @"status":@"ERROR",@"reason":@"PUBLIC_API_UNAVAILABLE"};
                NSData *encoded=[NSJSONSerialization dataWithJSONObject:failure options:0 error:NULL];
                if(encoded) [encoded writeToFile:checkpoint options:NSDataWritingAtomic error:NULL];
                dispatch_async(dispatch_get_main_queue(), ^{
                    self.stressRunning=NO;
                    [self recordBootEvent:[NSString stringWithFormat:@"BOUNDARY_ERROR_%@",run]];
                    [self note:@"BOUNDARY: no están disponibles todas las funciones públicas; prueba cancelada."];
                });
                return;
            }

            BOOL stopped=NO;
            for (unsigned n=1;n<=limit;n++) {
                if (self.stressStopRequested) {stopped=YES;break;}
                @autoreleasepool {
                    // Xorshift PRNG with a saved seed; the same run can be replayed.
                    size_t width=lengths[probeRandom(&state)%16];
                    size_t height=lengths[probeRandom(&state)%16];
                    size_t elem=elements[probeRandom(&state)%5];
                    size_t nominalRow=width*elem;
                    size_t rowCandidates[6]={
                        0,nominalRow>0?nominalRow-1:0,nominalRow,
                        nominalRow+1,((nominalRow+15)/16)*16,nominalRow+64
                    };
                    size_t row=rowCandidates[probeRandom(&state)%6];
                    size_t nominalAlloc=row*height;
                    size_t allocCandidates[6]={
                        0,nominalAlloc>0?nominalAlloc-1:0,nominalAlloc,
                        nominalAlloc+1,nominalAlloc+64,nominalAlloc+256
                    };
                    size_t alloc=allocCandidates[probeRandom(&state)%6];
                    uint32_t format=formats[probeRandom(&state)%4];
                    BOOL omitRow=(n%37==0),omitAlloc=(n%41==0);
                    if (omitRow) missingStride++;
                    if (omitAlloc) missingSize++;
                    NSMutableDictionary *params=[@{
                        @"IOSurfaceWidth":@(width),@"IOSurfaceHeight":@(height),
                        @"IOSurfaceBytesPerElement":@(elem),
                        @"IOSurfaceBytesPerRow":@(row),
                        @"IOSurfaceAllocSize":@(alloc),
                        @"IOSurfacePixelFormat":@(format)
                    } mutableCopy];
                    if (omitRow) [params removeObjectForKey:@"IOSurfaceBytesPerRow"];
                    if (omitAlloc) [params removeObjectForKey:@"IOSurfaceAllocSize"];
                    NSString *requestedGroup=PFBoundaryRequestedGroup(
                        width,height,elem,row,alloc,omitRow,omitAlloc);
                    NSMutableDictionary<NSString *,NSNumber *> *groupStats=coverageGroups[requestedGroup];
                    if(!groupStats) {
                        groupStats=[NSMutableDictionary new];
                        coverageGroups[requestedGroup]=groupStats;
                    }
                    PFCount(groupStats,@"attempted");
                    IOSurfaceRef surface=NULL;
                    BOOL threw=NO;
                    @try {
                        surface=create((__bridge CFDictionaryRef)params);
                    } @catch(NSException *exception) {
                        threw=YES;
                    }
                    attempts++;
                    IOSurfaceID id=0;
                    size_t actualW=0,actualH=0,actualRow=0,actualAlloc=0,minimumSpan=0;
                    const char *outcome="REJECTED";
                    const char *classification="NONE";
                    const char *integrityResult="NOT_SAMPLED";
                    BOOL stopOnMismatch=NO;
                    if (threw) {
                        exceptions++;
                        outcome="NS_EXCEPTION";
                        PFCount(groupStats,@"exceptions");
                    } else if (!surface) {
                        rejected++;
                        PFCount(groupStats,@"rejected");
                    } else {
                        accepted++;
                        PFCount(groupStats,@"accepted");
                        id=getID(surface);
                        actualW=getW(surface);
                        actualH=getH(surface);
                        actualRow=getRow(surface);
                        actualAlloc=getAlloc(surface);
                        BOOL changed=(actualW!=width || actualH!=height || (!omitRow && actualRow!=row));
                        BOOL zero=(actualW==0 || actualH==0);
                        // Bound unexpected metadata before arithmetic or memory access.
                        BOOL inRange=(actualW<=4096 && actualH<=4096 && actualRow<=(1ULL<<24));
                        BOOL rowTooSmall=(!zero && inRange && actualRow<actualW*elem);
                        if(!zero && inRange) minimumSpan=(actualH-1)*actualRow+actualW*elem;
                        BOOL spanTooSmall=(!zero && inRange && actualAlloc<minimumSpan);
                        BOOL fullRowsShort=(inRange && actualH>0 && actualRow>0 &&
                                            actualAlloc<actualH*actualRow);
                        if(changed) normalized++;
                        if(zero) zeroDimensionAccepted++;
                        if(fullRowsShort) legacyFullRowShort++;
                        if(rowTooSmall) shortRow++;
                        if(spanTooSmall) footprintShort++;
                        if(id==0) invalidId++;
                        if(!inRange) unexpectedBounds++;
                        outcome="ACCEPTED";
                        if(id==0) {classification="REVIEW_ID_ZERO";review++;}
                        else if(zero) {classification="EDGE_ZERO_DIMENSION";}
                        else if(!inRange) {classification="REVIEW_METADATA_RANGE";review++;}
                        else if(rowTooSmall) {classification="REVIEW_ROW_STRIDE";review++;}
                        else if(spanTooSmall) {classification="REVIEW_LAST_PIXEL_SPAN";review++;}
                        else if(changed) {classification="NORMALIZED";}
                        else {classification="OK";regular++;}

                        // Probe fresh owned surfaces, never stale objects or bytes beyond
                        // the last declared pixel. Only uncompressed BGRA, 4 bytes/pixel.
                        BOOL safeCandidate=(format==0x42475241 && elem==4 &&
                                     !zero && inRange && actualW<=256 && actualH<=256 &&
                                     !rowTooSmall && !spanTooSmall && id!=0 &&
                                     minimumSpan>0 && getBase && lock && unlock);
                        if(safeCandidate) {
                            eligibleIntegrity++;
                            PFCount(groupStats,@"integrity_eligible");
                        }
                        // Each owned BGRA surface is eligible for bounded verification.
                        BOOL sample=safeCandidate && sampled<4096;
                        if(safeCandidate && !sample) skippedByBudget++;
                        if(sample) {
                            sampled++;
                            PFCount(groupStats,@"integrity_tested");
                            NSDictionary *pre=@{@"run":run,@"seed":@(seed),@"step":@(n),
                                @"status":@"RUNNING",@"phase":@"BEFORE_SAFE_INTEGRITY",
                                @"minimum_span":@(minimumSpan),@"observed_alloc":@(actualAlloc),
                                @"timestamp":[NSDate date].description};
                            NSData *preData=[NSJSONSerialization dataWithJSONObject:pre
                                                                         options:0 error:NULL];
                            if(preData)[preData writeToFile:checkpoint
                                                   options:NSDataWritingAtomic error:NULL];
                            kern_return_t lockCode=lock(surface,0,NULL);
                            if(lockCode!=KERN_SUCCESS) {
                                sampleLockFailed++;
                                integrityResult="LOCK_FAILED";
                            } else {
                                void *memory=getBase(surface);
                                if(!memory) {
                                    sampleBaseNull++;
                                    integrityResult="NO_CPU_MAPPING";
                                } else {
                                    // Only touch pixel bytes in the app's own mapped surface.
                                    // The midpoint accounts for observed row-stride padding.
                                    volatile uint8_t *bytes=(volatile uint8_t *)memory;
                                    size_t offsets[3]={0,
                                        (actualH/2)*actualRow+(actualW/2)*elem+1,
                                        minimumSpan-1};
                                    BOOL mismatch=NO;
                                    for(unsigned probeIndex=0;probeIndex<3;probeIndex++) {
                                        size_t offset=offsets[probeIndex];
                                        if(offset>=minimumSpan || offset>=actualAlloc) {
                                            mismatch=YES;
                                            break;
                                        }
                                        uint8_t original=bytes[offset];
                                        uint8_t marker=(uint8_t)(original ^ (0xA5u+probeIndex));
                                        bytes[offset]=marker;
                                        uint8_t observed=bytes[offset];
                                        bytes[offset]=original;
                                        byteChecks++;
                                        if(observed!=marker) {
                                            mismatch=YES;
                                            break;
                                        }
                                    }
                                    if(mismatch) {
                                        sampleMismatch++;
                                        integrityResult="MISMATCH";
                                        stopOnMismatch=YES;
                                    } else {
                                        samplePassed++;
                                        integrityResult="PASS";
                                    }
                                }
                                if(unlock(surface,0,NULL)!=KERN_SUCCESS) {
                                    sampleUnlockFailed++;
                                    integrityResult="UNLOCK_FAILED";
                                    stopOnMismatch=YES;
                                }
                            }
                        }
                        if(sample) {
                            PFCount(groupStats,strcmp(integrityResult,"PASS")==0 ?
                                    @"integrity_passed" : @"integrity_not_passed");
                        }
                        CFRelease(surface);
                    }
                    NSString *observedClass=[NSString stringWithUTF8String:
                        strcmp(outcome,"REJECTED")==0 ? "REJECTED_INPUT" :
                        strcmp(outcome,"NS_EXCEPTION")==0 ? "NS_EXCEPTION" : classification];
                    PFCount(classificationCounts,observedClass);
                    [csv appendFormat:@"%@,%u,%u,%zu,%zu,%zu,%zu,%zu,0x%08x,%d,%d,%u,%zu,%zu,%zu,%zu,%zu,%s,%s,%s\n",
                        run,seed,n,width,height,elem,row,alloc,(unsigned)format,omitRow,omitAlloc,
                        (unsigned)id,actualW,actualH,actualRow,actualAlloc,
                        minimumSpan,classification,integrityResult,outcome];
                    if(n%100==0) {
                        NSDictionary *saved=@{
                            @"run":run,@"seed":@(seed),@"step":@(n),@"status":@"RUNNING",
                            @"schema":@"v18-pixel-span",@"phase":@"IN_PROGRESS",
                            @"accepted":@(accepted),@"rejected":@(rejected),
                            @"exceptions":@(exceptions),@"review":@(review),
                            @"edge_zero_dimension":@(zeroDimensionAccepted),
                            @"legacy_full_rows_short":@(legacyFullRowShort),
                            @"integrity_tested":@(sampled),@"integrity_mismatch":@(sampleMismatch),
                            @"timestamp":[NSDate date].description
                        };
                        NSData *data=[NSJSONSerialization dataWithJSONObject:saved options:0 error:NULL];
                        if(data) [data writeToFile:checkpoint options:NSDataWritingAtomic error:NULL];
                    }
                    if(stopOnMismatch) {
                        stopped=YES;
                        NSDictionary *incident=@{@"run":run,@"seed":@(seed),@"step":@(n),
                            @"status":@"STOPPED_ON_INTEGRITY_ERROR",
                            @"integrity":@(sampleMismatch),@"unlock_errors":@(sampleUnlockFailed),
                            @"timestamp":[NSDate date].description};
                        NSData *incidentData=[NSJSONSerialization dataWithJSONObject:incident
                                                                          options:0 error:NULL];
                        if(incidentData)[incidentData writeToFile:checkpoint
                                                           options:NSDataWritingAtomic error:NULL];
                        break;
                    }
                    if(n%2500==0) {
                        unsigned done=n,ok=accepted,no=rejected,needsReview=review,passed=samplePassed;
                        dispatch_async(dispatch_get_main_queue(), ^{
                            if(done%10000==0)
                                [self recordBootEvent:[NSString stringWithFormat:
                                    @"BOUNDARY_PROGRESS_%@_%u",run,done]];
                            [self note:[NSString stringWithFormat:
                                @"BOUNDARY: %u/%u aceptadas=%u rechazadas=%u alertas=%u integridad_ok=%u",
                                done,limit,ok,no,needsReview,passed]];
                        });
                        usleep(50000);
                    }
                }
            }
            if(framework) dlclose(framework);
            NSDictionary *final=@{
                @"run":run,@"seed":@(seed),@"step":@(attempts),
                @"schema":@"v18-pixel-span",
                @"status":sampleMismatch||sampleUnlockFailed?@"STOPPED_ON_INTEGRITY_ERROR":(stopped?@"STOPPED":@"DONE"),
                @"accepted":@(accepted),@"rejected":@(rejected),@"exceptions":@(exceptions),
                @"review":@(review),@"normalized":@(normalized),
                @"zero_dim_accepted":@(zeroDimensionAccepted),
                @"undercovered":@(footprintShort),
                @"short_row_bytes":@(shortRow),@"invalid_id":@(invalidId),
                @"unexpected_metadata_range":@(unexpectedBounds),
                @"legacy_full_rows_short":@(legacyFullRowShort),
                @"integrity_eligible":@(eligibleIntegrity),
                @"integrity_byte_checks":@(byteChecks),
                @"integrity_skipped_by_budget":@(skippedByBudget),
                @"integrity_coverage_pct":@(eligibleIntegrity ?
                                      (100.0*(double)sampled/(double)eligibleIntegrity):0.0),
                @"integrity_tested":@(sampled),@"integrity_passed":@(samplePassed),
                @"integrity_mismatch":@(sampleMismatch),
                @"integrity_lock_failed":@(sampleLockFailed),
                @"integrity_base_null":@(sampleBaseNull),
                @"integrity_unlock_failed":@(sampleUnlockFailed),
                @"missing_stride_cases":@(missingStride),@"missing_alloc_cases":@(missingSize),
                @"elapsed":@(CFAbsoluteTimeGetCurrent()-start)
            };
            NSData *finalBytes=[NSJSONSerialization dataWithJSONObject:final options:NSJSONWritingPrettyPrinted error:NULL];
            if(finalBytes) [finalBytes writeToFile:checkpoint options:NSDataWritingAtomic error:NULL];
            NSString *exportCSV=[csv copy];
            NSString *persistedCSV=[NSHomeDirectory() stringByAppendingPathComponent:
                @"Documents/IOSurfaceBruteForce-v18-trace.csv"];
            [exportCSV writeToFile:persistedCSV atomically:YES encoding:NSUTF8StringEncoding error:NULL];
            NSDictionary *coverageReport=@{
                @"schema":@"v19.2-coverage-grouped-owned-memory",
                @"run":run, @"seed":@(seed), @"total_cases":@(attempts),
                @"accepted":@(accepted), @"rejected":@(rejected),
                @"exceptions":@(exceptions), @"review":@(review),
                @"integrity_eligible":@(eligibleIntegrity),
                @"integrity_tested":@(sampled), @"integrity_passed":@(samplePassed),
                @"integrity_byte_checks":@(byteChecks),
                @"integrity_skipped_by_budget":@(skippedByBudget),
                @"input_groups":coverageGroups,
                @"observed_classes":classificationCounts,
                @"scope":@"Own BGRA surfaces, public IOSurface API; no kernel object trace",
                @"warning":@"Requested input groups do not establish causes of rejection, and API errors do not establish kernel vulnerabilities."
            };
            NSString *docs=[NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
            NSString *coveragePath=[docs stringByAppendingPathComponent:@"IOSurfaceCoverage-v19_2.json"];
            NSData *coverageBytes=[NSJSONSerialization dataWithJSONObject:coverageReport
                                            options:NSJSONWritingPrettyPrinted error:NULL];
            if(coverageBytes)
                [coverageBytes writeToFile:coveragePath options:NSDataWritingAtomic error:NULL];
            NSMutableString *coverageCSV=[NSMutableString stringWithString:
                @"input_group,attempted,accepted,rejected,exceptions,integrity_eligible,integrity_tested,integrity_passed,integrity_not_passed\n"];
            NSArray<NSString *> *orderedGroups=[[coverageGroups allKeys]
                sortedArrayUsingSelector:@selector(compare:)];
            for(NSString *name in orderedGroups) {
                NSDictionary *g=coverageGroups[name];
                [coverageCSV appendFormat:@"%@,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu\n",name,
                   (unsigned long)[g[@"attempted"] unsignedIntegerValue],
                   (unsigned long)[g[@"accepted"] unsignedIntegerValue],
                   (unsigned long)[g[@"rejected"] unsignedIntegerValue],
                   (unsigned long)[g[@"exceptions"] unsignedIntegerValue],
                   (unsigned long)[g[@"integrity_eligible"] unsignedIntegerValue],
                   (unsigned long)[g[@"integrity_tested"] unsignedIntegerValue],
                   (unsigned long)[g[@"integrity_passed"] unsignedIntegerValue],
                   (unsigned long)[g[@"integrity_not_passed"] unsignedIntegerValue]];
            }
            NSString *coverageCsvPath=[docs stringByAppendingPathComponent:@"IOSurfaceCoverage-v19_2.csv"];
            [coverageCSV writeToFile:coverageCsvPath atomically:YES encoding:NSUTF8StringEncoding error:NULL];
            dispatch_async(dispatch_get_main_queue(), ^{
                [self note:[NSString stringWithFormat:
                    @"COVERAGE v19.2: elegibles=%u comprobadas=%u (%.2f%%) omitidas_por_limite=%u",
                    eligibleIntegrity,sampled,
                    eligibleIntegrity ? (100.0*(double)sampled/(double)eligibleIntegrity):0.0,
                    skippedByBudget]];
                self.stressCSV=exportCSV;
                self.stressRunning=NO;
                NSString *endStatus=(sampleMismatch||sampleUnlockFailed)?
                    @"STOPPED_ON_INTEGRITY_ERROR":stopped?@"STOPPED":@"DONE";
                [self recordBootEvent:[NSString stringWithFormat:
                    @"BOUNDARY_END_%@_%@",run,endStatus]];
                [self note:[NSString stringWithFormat:
                    @"BOUNDARY: %@ %u/%u seed=%u aceptadas=%u rechazadas=%u excepciones=%u",
                    stopped?@"STOPPED":@"DONE",attempts,limit,seed,accepted,rejected,exceptions]];
                [self note:[NSString stringWithFormat:
                    @"BOUNDARY: zero-dimension=%u full-rows-short(INFO)=%u min-pixel-span-short=%u stride-short=%u alertas=%u normales=%u",
                    zeroDimensionAccepted,legacyFullRowShort,footprintShort,shortRow,review,regular]];
                [self note:[NSString stringWithFormat:
                    @"BOUNDARY: muestras memoria=%u OK=%u error=%u lock_fallo=%u base_nula=%u unlock_fallo=%u",
                    sampled,samplePassed,sampleMismatch,sampleLockFailed,sampleBaseNull,sampleUnlockFailed]];
                [self note:[NSString stringWithFormat:@"BOUNDARY: tiempo=%.3fs; CSV persistente y checkpoint guardados.",
                    CFAbsoluteTimeGetCurrent()-start]];
                [self note:@"BOUNDARY: una anomalía de API no equivale a fallo del kernel, UAF o KernelRW."];
            });
        }
    });
}


- (void)selector17Probe:(id)sender {
    uint32_t seed=arc4random();
    if(!seed) seed=0x17172026;
    [self selector17RunWithSeed:seed replay:NO];
}

- (void)replaySelector17Probe:(id)sender {
    NSNumber *value=[NSUserDefaults.standardUserDefaults objectForKey:@"Selector17LastSeed"];
    if(![value isKindOfClass:NSNumber.class]) {
        [self note:@"SELECTOR17: no hay semilla guardada para repetir."];
        return;
    }
    [self selector17RunWithSeed:(uint32_t)value.unsignedIntValue replay:YES];
}

- (void)selector17RunWithSeed:(uint32_t)seed replay:(BOOL)replay {
    if(self.stressRunning || self.matrixRunning) {
        [self note:@"SELECTOR17: otra prueba está activa; no iniciamos otra."];
        return;
    }
    self.stressRunning=YES;
    self.stressStopRequested=NO;
    self.stressCSV=nil;
    [NSUserDefaults.standardUserDefaults setObject:@(seed) forKey:@"Selector17LastSeed"];
    NSString *run=NSUUID.UUID.UUIDString;
    NSString *rootPath=[NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
    NSString *checkpointPath=[rootPath stringByAppendingPathComponent:@"IOSurfaceSelector17-checkpoint.json"];
    NSString *csvPath=[rootPath stringByAppendingPathComponent:@"IOSurfaceSelector17-trace.csv"];
    [self note:[NSString stringWithFormat:@"SELECTOR17: %@ run=%@ seed=%u",replay?@"REPLAY":@"NEW",run,seed]];
    [self note:@"SELECTOR17: 256 llamadas REALES de IOConnectCallStructMethod(selector=17, struct=24 bytes), una conexión por caso."];
    [self note:@"SELECTOR17: entradas negativas, zeros, patrones de bits y valores aleatorios. Sin concurrencia ni punteros liberados."];
    [self note:@"SELECTOR17: ATENCIÓN: estos métodos del kernel no son APIs públicas y pueden reiniciar el iPhone."];
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY,0), ^{
        @autoreleasepool {
            const unsigned total=256;
            uint32_t randomState=seed;
            unsigned attempted=0,opened=0,failedOpen=0,accepted=0,denied=0,badarg=0,other=0;
            BOOL stopped=NO;
            CFAbsoluteTime began=CFAbsoluteTimeGetCurrent();
            NSMutableString *csv=[NSMutableString stringWithString:
                @"run,seed,case,payload_hex,open_code,call_code,result\n"];
            void *lib=dlopen("/System/Library/Frameworks/IOKit.framework/IOKit",RTLD_LAZY|RTLD_LOCAL);
            MatchingFn matching=lib?(MatchingFn)dlsym(lib,"IOServiceMatching"):NULL;
            GetMatchingFn getService=lib?(GetMatchingFn)dlsym(lib,"IOServiceGetMatchingService"):NULL;
            OpenServiceFn open=lib?(OpenServiceFn)dlsym(lib,"IOServiceOpen"):NULL;
            CloseServiceFn close=lib?(CloseServiceFn)dlsym(lib,"IOServiceClose"):NULL;
            ReleaseObjectFn release=lib?(ReleaseObjectFn)dlsym(lib,"IOObjectRelease"):NULL;
            typedef kern_return_t (*StructFn)(io_connect_t,uint32_t,const void*,size_t,void*,size_t*);
            StructFn call=lib?(StructFn)dlsym(lib,"IOConnectCallStructMethod"):NULL;
            if(!matching||!getService||!open||!close||!release||!call) {
                [@{@"run":run,@"seed":@(seed),@"status":@"ERROR",
                   @"reason":@"MISSING_IOKIT_SYMBOL",@"case":@0}
                    writeToFile:checkpointPath atomically:YES];
                if(lib)dlclose(lib);
                dispatch_async(dispatch_get_main_queue(),^{
                    self.stressRunning=NO;
                    [self note:@"SELECTOR17: faltan funciones IOKit. No se llamó al selector."];
                });
                return;
            }
            [csv writeToFile:csvPath atomically:YES encoding:NSUTF8StringEncoding error:NULL];
            for(unsigned i=0;i<total;i++) {
                if(self.stressStopRequested){stopped=YES;break;}
                @autoreleasepool {
                    uint8_t payload[24]={0};
                    if(i==1) memset(payload,0xff,sizeof(payload));
                    else if(i==2) memset(payload,1,sizeof(payload));
                    else if(i==3) memset(payload,0x80,sizeof(payload));
                    else if(i>=4 && i<196) {
                        unsigned bit=i-4;
                        payload[bit/8]=(uint8_t)(1U<<(bit%8));
                    } else if(i>=196) {
                        for(unsigned j=0;j<24;j++)payload[j]=(uint8_t)probeRandom(&randomState);
                    }
                    NSString *hex=selector17Hex(payload,sizeof(payload));
                    // Commit BEFORE entering kernel IPC. If the phone panics, this payload remains.
                    NSDictionary *before=@{
                        @"run":run,@"seed":@(seed),@"case":@(i),
                        @"status":@"RUNNING",@"phase":@"BEFORE_IPC",
                        @"selector":@17,@"inputLength":@24,@"payloadHex":hex,
                        @"timestamp":[NSDate date].description
                    };
                    NSData *state=[NSJSONSerialization dataWithJSONObject:before options:0 error:NULL];
                    if(state)[state writeToFile:checkpointPath options:NSDataWritingAtomic error:NULL];
                    io_service_t service=MACH_PORT_NULL;
                    CFMutableDictionaryRef query=matching("IOSurfaceRoot");
                    if(query)service=getService(MACH_PORT_NULL,query);
                    io_connect_t conn=MACH_PORT_NULL;
                    kern_return_t openCode=KERN_FAILURE, callCode=KERN_FAILURE;
                    if(service) openCode=open(service,mach_task_self(),0,&conn);
                    if(openCode==KERN_SUCCESS && conn) {
                        opened++;
                        size_t outputLen=0;
                        callCode=call(conn,17,payload,sizeof(payload),NULL,&outputLen);
                        close(conn);
                    } else failedOpen++;
                    if(service)release(service);
                    attempted++;
                    const char *tag="OTHER";
                    if(openCode!=KERN_SUCCESS){tag="OPEN_FAILED";}
                    else if(callCode==KERN_SUCCESS){accepted++;tag="CALL_SUCCESS";}
                    else if((uint32_t)callCode==0xe00002e2){denied++;tag="NOT_PERMITTED";}
                    else if((uint32_t)callCode==0xe00002c2){badarg++;tag="BAD_ARGUMENT";}
                    else{other++;}
                    [csv appendFormat:@"%@,%u,%u,%@,0x%08x,0x%08x,%s\n",
                        run,seed,i,hex,(unsigned)openCode,(unsigned)callCode,tag];
                    [csv writeToFile:csvPath atomically:YES encoding:NSUTF8StringEncoding error:NULL];
                    NSDictionary *after=@{
                        @"run":run,@"seed":@(seed),@"case":@(i),
                        @"status":@"RUNNING",@"phase":@"AFTER_IPC",
                        @"selector":@17,@"inputLength":@24,
                        @"lastReturn":[NSString stringWithFormat:@"0x%08x",(unsigned)callCode],
                        @"timestamp":[NSDate date].description
                    };
                    NSData *end=[NSJSONSerialization dataWithJSONObject:after options:0 error:NULL];
                    if(end)[end writeToFile:checkpointPath options:NSDataWritingAtomic error:NULL];
                    if((i+1)%16==0) {
                        unsigned count=attempted,success=accepted,d=denied;
                        dispatch_async(dispatch_get_main_queue(),^{
                            [self note:[NSString stringWithFormat:
                                @"SELECTOR17: %u/%u llamadas, success=%u, no_permitido=%u",count,total,success,d]];
                        });
                    }
                    // Do not continue after a successful mutating call of unknown semantics.
                    if(callCode==KERN_SUCCESS){
                        dispatch_async(dispatch_get_main_queue(),^{
                            [self note:@"SELECTOR17: la llamada devolvió éxito. Campaña terminada preventivamente para analizarla."];
                        });
                        break;
                    }
                    usleep(20000);
                }
            }
            if(lib)dlclose(lib);
            NSString *status=stopped?@"STOPPED":(accepted?@"STOPPED_ON_SUCCESS":@"DONE");
            NSDictionary *finish=@{
                @"run":run,@"seed":@(seed),@"case":@(attempted),
                @"status":status,@"phase":@"FINISHED",
                @"attempted":@(attempted),@"opened":@(opened),
                @"openErrors":@(failedOpen),@"success":@(accepted),
                @"notPermitted":@(denied),@"badArgument":@(badarg),
                @"other":@(other),@"duration":@(CFAbsoluteTimeGetCurrent()-began),
                @"timestamp":[NSDate date].description
            };
            NSData *data=[NSJSONSerialization dataWithJSONObject:finish options:NSJSONWritingPrettyPrinted error:NULL];
            if(data)[data writeToFile:checkpointPath options:NSDataWritingAtomic error:NULL];
            NSString *trace=[csv copy];
            dispatch_async(dispatch_get_main_queue(),^{
                self.stressCSV=trace;
                self.stressRunning=NO;
                [self note:[NSString stringWithFormat:
                    @"SELECTOR17: %@ intentos=%u abierta=%u fallos_apertura=%u éxito=%u negadas=%u arg_inválido=%u otros=%u",
                    status,attempted,opened,failedOpen,accepted,denied,badarg,other]];
                [self note:@"SELECTOR17: exportá el checkpoint y CSV para identificar la ruta y sus resultados. Un retorno no demuestra UAF o KernelRW."];
            });
        }
    });
}


- (void)asyncContractProbe:(id)sender {
    if(self.stressRunning || self.matrixRunning) {
        [self note:@"ASYNC: ya hay una prueba activa."];
        return;
    }
    self.stressRunning=YES;
    NSString *run=NSUUID.UUID.UUIDString;
    NSString *checkpointPath=[NSHomeDirectory() stringByAppendingPathComponent:
        @"Documents/IOSurfaceAsyncContract-checkpoint.json"];
    [self note:[NSString stringWithFormat:@"ASYNC: inicio run=%@",run]];
    [self note:@"ASYNC: exactamente 1 llamada IOConnectCallAsyncStructMethod, selector 17 y 24 bytes cero."];
    [self note:@"ASYNC: referencia asíncrona de 8 valores y puerto Mach de respuesta válido."];
    [self note:@"ASYNC: sin fuzz, sin concurrencia, sin referencias liberadas; puede devolver error de validación."];
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY,0), ^{
        @autoreleasepool {
            void *lib=dlopen("/System/Library/Frameworks/IOKit.framework/IOKit",RTLD_LAZY|RTLD_LOCAL);
            MatchingFn matching=lib ? (MatchingFn)dlsym(lib,"IOServiceMatching") : NULL;
            GetMatchingFn getService=lib ? (GetMatchingFn)dlsym(lib,"IOServiceGetMatchingService") : NULL;
            OpenServiceFn open=lib ? (OpenServiceFn)dlsym(lib,"IOServiceOpen") : NULL;
            CloseServiceFn close=lib ? (CloseServiceFn)dlsym(lib,"IOServiceClose") : NULL;
            ReleaseObjectFn release=lib ? (ReleaseObjectFn)dlsym(lib,"IOObjectRelease") : NULL;
            typedef kern_return_t (*CallAsyncStructFn)(io_connect_t,uint32_t,mach_port_t,
                      uint64_t *,uint32_t,const void *,size_t,void *,size_t *);
            CallAsyncStructFn call=lib ? (CallAsyncStructFn)dlsym(lib,
                                 "IOConnectCallAsyncStructMethod") : NULL;
            NSString *status=@"ERROR";
            NSString *phase=@"SETUP";
            kern_return_t openCode=KERN_FAILURE;
            kern_return_t callCode=KERN_FAILURE;
            kern_return_t portCode=KERN_FAILURE;
            kern_return_t sendCode=KERN_FAILURE;
            BOOL called=NO;
            mach_port_t replyPort=MACH_PORT_NULL;
            io_service_t service=MACH_PORT_NULL;
            io_connect_t connection=MACH_PORT_NULL;
            if(matching && getService && open && close && release && call) {
                CFMutableDictionaryRef query=matching("IOSurfaceRoot");
                if(query) service=getService(MACH_PORT_NULL,query);
                if(service) openCode=open(service,mach_task_self(),0,&connection);
                if(openCode==KERN_SUCCESS && connection!=MACH_PORT_NULL) {
                    portCode=mach_port_allocate(mach_task_self(),MACH_PORT_RIGHT_RECEIVE,&replyPort);
                    if(portCode==KERN_SUCCESS) {
                        sendCode=mach_port_insert_right(mach_task_self(),replyPort,
                                                      replyPort,MACH_MSG_TYPE_MAKE_SEND);
                        if(sendCode==KERN_SUCCESS) {
                            phase=@"BEFORE_ASYNC_IPC";
                            NSDictionary *before=@{
                                @"run":run,@"status":@"RUNNING",@"phase":phase,
                                @"selector":@17,@"inputBytes":@24,
                                @"referenceCount":@8,@"payload":@"ZERO",
                                @"timestamp":[NSDate date].description
                            };
                            NSData *pre=[NSJSONSerialization dataWithJSONObject:before options:0 error:NULL];
                            if(pre)[pre writeToFile:checkpointPath options:NSDataWritingAtomic error:NULL];

                            uint8_t payload[24]={0};
                            uint64_t reference[8]={0};
                            size_t outputBytes=0;
                            called=YES;
                            callCode=call(connection,17,replyPort,reference,8,
                                          payload,sizeof(payload),NULL,&outputBytes);
                            phase=@"AFTER_ASYNC_IPC";
                            status=@"DONE";
                        }
                    }
                }
            }
            if(connection!=MACH_PORT_NULL && close) close(connection);
            if(service!=MACH_PORT_NULL && release) release(service);
            if(replyPort!=MACH_PORT_NULL) mach_port_destroy(mach_task_self(),replyPort);
            if(lib)dlclose(lib);
            NSDictionary *final=@{
                @"run":run,@"status":status,@"phase":phase,
                @"called":@(called),@"selector":@17,
                @"openReturn":[NSString stringWithFormat:@"0x%08x",(unsigned)openCode],
                @"portReturn":[NSString stringWithFormat:@"0x%08x",(unsigned)portCode],
                @"sendReturn":[NSString stringWithFormat:@"0x%08x",(unsigned)sendCode],
                @"callReturn":[NSString stringWithFormat:@"0x%08x",(unsigned)callCode],
                @"timestamp":[NSDate date].description
            };
            NSData *out=[NSJSONSerialization dataWithJSONObject:final
                                            options:NSJSONWritingPrettyPrinted error:NULL];
            if(out)[out writeToFile:checkpointPath options:NSDataWritingAtomic error:NULL];
            dispatch_async(dispatch_get_main_queue(), ^{
                self.stressRunning=NO;
                [self note:[NSString stringWithFormat:
                   @"ASYNC: %@ ejecutada=%@ open=0x%08x puerto=0x%08x send=0x%08x retorno=0x%08x",
                   status,called?@"SI":@"NO",(unsigned)openCode,(unsigned)portCode,
                   (unsigned)sendCode,(unsigned)callCode]];
                [self note:@"ASYNC: exportá IOSurfaceAsyncContract-checkpoint.json; no se intentó obtener KernelRW."];
            });
        }
    });
}


- (void)asyncObserverProbe:(id)sender {
    if(self.stressRunning || self.matrixRunning) {
        [self note:@"OBSERVE: ya existe una prueba activa."];
        return;
    }
    self.stressRunning=YES;
    self.stressStopRequested=NO;
    NSString *run=NSUUID.UUID.UUIDString;
    NSString *directory=[NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
    NSString *checkpointPath=[directory stringByAppendingPathComponent:
        @"IOSurfaceAsyncObserver-checkpoint.json"];
    NSString *tracePath=[directory stringByAppendingPathComponent:
        @"IOSurfaceAsyncObserver-trace.csv"];
    [self note:[NSString stringWithFormat:@"OBSERVE: inicio run=%@",run]];
    [self note:@"OBSERVE: 1 llamada asíncrona al selector 17, estructura de 24 bytes cero."];
    [self note:@"OBSERVE: conexión y puerto Mach permanecen abiertos mientras escuchamos hasta 3 segundos."];
    [self note:@"OBSERVE: registramos cabeceras de mensajes, no interpretamos su contenido ni modificamos memoria del kernel."];
    [self note:@"OBSERVE: sin carreras, sin métodos adicionales, sin punteros liberados."];

    NSDictionary *initial=@{
        @"run":run,@"status":@"RUNNING",@"phase":@"PREPARING",
        @"selector":@17,@"timestamp":[NSDate date].description
    };
    NSData *initialBytes=[NSJSONSerialization dataWithJSONObject:initial options:0 error:NULL];
    if(initialBytes)[initialBytes writeToFile:checkpointPath options:NSDataWritingAtomic error:NULL];
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY,0), ^{
        @autoreleasepool {
            void *lib=dlopen("/System/Library/Frameworks/IOKit.framework/IOKit",RTLD_LAZY|RTLD_LOCAL);
            MatchingFn matching=lib?(MatchingFn)dlsym(lib,"IOServiceMatching"):NULL;
            GetMatchingFn getService=lib?(GetMatchingFn)dlsym(lib,"IOServiceGetMatchingService"):NULL;
            OpenServiceFn open=lib?(OpenServiceFn)dlsym(lib,"IOServiceOpen"):NULL;
            CloseServiceFn close=lib?(CloseServiceFn)dlsym(lib,"IOServiceClose"):NULL;
            ReleaseObjectFn release=lib?(ReleaseObjectFn)dlsym(lib,"IOObjectRelease"):NULL;
            typedef kern_return_t (*CallAsyncStructFn)(
                io_connect_t,uint32_t,mach_port_t,uint64_t*,uint32_t,
                const void*,size_t,void*,size_t*);
            CallAsyncStructFn call=lib?(CallAsyncStructFn)dlsym(lib,"IOConnectCallAsyncStructMethod"):NULL;

            mach_port_t replyPort=MACH_PORT_NULL;
            io_service_t service=MACH_PORT_NULL;
            io_connect_t connection=MACH_PORT_NULL;
            kern_return_t openCode=KERN_FAILURE,portCode=KERN_FAILURE;
            kern_return_t sendCode=KERN_FAILURE,callCode=KERN_FAILURE;
            kern_return_t closeCode=KERN_FAILURE,portDestroyCode=KERN_FAILURE;
            unsigned received=0,timeouts=0,receiveErrors=0,polls=0;
            BOOL invoked=NO;
            BOOL stopped=NO;
            NSString *phase=@"SETUP",*status=@"ERROR";
            CFAbsoluteTime started=CFAbsoluteTimeGetCurrent();
            NSMutableString *trace=[NSMutableString stringWithFormat:
                @"run,event,poll,receive_code,message_id,message_size,message_bits,elapsed_ms\n"];
            BOOL available=matching && getService && open && close && release && call;
            if(available) {
                CFMutableDictionaryRef request=matching("IOSurfaceRoot");
                if(request)service=getService(MACH_PORT_NULL,request);
                if(service)openCode=open(service,mach_task_self(),0,&connection);
                if(openCode==KERN_SUCCESS && connection!=MACH_PORT_NULL) {
                    portCode=mach_port_allocate(mach_task_self(),MACH_PORT_RIGHT_RECEIVE,&replyPort);
                    if(portCode==KERN_SUCCESS) {
                        sendCode=mach_port_insert_right(mach_task_self(),replyPort,
                                                      replyPort,MACH_MSG_TYPE_MAKE_SEND);
                        if(sendCode==KERN_SUCCESS) {
                            phase=@"BEFORE_IPC";
                            NSDictionary *before=@{
                                @"run":run,@"status":@"RUNNING",@"phase":phase,
                                @"selector":@17,@"inputBytes":@24,
                                @"referenceCount":@8,@"payload":@"ZERO",
                                @"timestamp":[NSDate date].description
                            };
                            NSData *pre=[NSJSONSerialization dataWithJSONObject:before
                                                                        options:0 error:NULL];
                            if(pre)[pre writeToFile:checkpointPath options:NSDataWritingAtomic error:NULL];
                            [trace appendFormat:@"%@,BEFORE_IPC,0,0x00000000,0,0,0,%.1f\n",
                                run,(CFAbsoluteTimeGetCurrent()-started)*1000.0];
                            [trace writeToFile:tracePath atomically:YES encoding:NSUTF8StringEncoding error:NULL];

                            uint8_t payload[24]={0};
                            uint64_t reference[8]={0};
                            size_t outputLength=0;
                            invoked=YES;
                            callCode=call(connection,17,replyPort,reference,8,
                                          payload,sizeof(payload),NULL,&outputLength);
                            phase=@"AFTER_IPC";
                            [trace appendFormat:@"%@,AFTER_IPC,0,0x%08x,0,0,0,%.1f\n",
                                run,(unsigned)callCode,(CFAbsoluteTimeGetCurrent()-started)*1000.0];
                            [trace writeToFile:tracePath atomically:YES encoding:NSUTF8StringEncoding error:NULL];
                            NSDictionary *after=@{
                                @"run":run,@"status":@"RUNNING",@"phase":phase,
                                @"callReturn":[NSString stringWithFormat:@"0x%08x",(unsigned)callCode],
                                @"timestamp":[NSDate date].description
                            };
                            NSData *afterBytes=[NSJSONSerialization dataWithJSONObject:after
                                                                                 options:0 error:NULL];
                            if(afterBytes)[afterBytes writeToFile:checkpointPath options:NSDataWritingAtomic error:NULL];

                            if(callCode==KERN_SUCCESS) {
                                phase=@"LISTENING";
                                // One thread, one outstanding read; bounded to three 1-second polls.
                                for(unsigned n=1;n<=3;n++) {
                                    if(self.stressStopRequested) {stopped=YES;break;}
                                    typedef struct {
                                        mach_msg_header_t header;
                                        uint8_t payload[4096];
                                    } ObserverMessage;
                                    ObserverMessage incoming={0};
                                    mach_msg_return_t result=mach_msg(&incoming.header,
                                        MACH_RCV_MSG|MACH_RCV_TIMEOUT,
                                        0,(mach_msg_size_t)sizeof(incoming),replyPort,1000,MACH_PORT_NULL);
                                    polls++;
                                    uint32_t msgID=0,msgBytes=0,msgBits=0;
                                    if(result==MACH_MSG_SUCCESS) {
                                        received++;
                                        msgID=(uint32_t)incoming.header.msgh_id;
                                        msgBytes=incoming.header.msgh_size;
                                        msgBits=incoming.header.msgh_bits;
                                        // The message is untrusted data. Read only its bounded header.
                                        // Dispose of any rights/descriptors it contains.
                                        mach_msg_destroy(&incoming.header);
                                    } else if(result==MACH_RCV_TIMED_OUT) {
                                        timeouts++;
                                    } else {
                                        receiveErrors++;
                                    }
                                    [trace appendFormat:
                                        @"%@,RECEIVE,%u,0x%08x,%u,%u,%u,%.1f\n",
                                        run,n,(unsigned)result,msgID,msgBytes,msgBits,
                                        (CFAbsoluteTimeGetCurrent()-started)*1000.0];
                                    [trace writeToFile:tracePath atomically:YES encoding:NSUTF8StringEncoding error:NULL];
                                    NSDictionary *pollData=@{
                                        @"run":run,@"status":@"RUNNING",@"phase":@"LISTENING",
                                        @"poll":@(n),@"messages":@(received),@"timeouts":@(timeouts),
                                        @"receiveErrors":@(receiveErrors),
                                        @"callReturn":[NSString stringWithFormat:@"0x%08x",(unsigned)callCode],
                                        @"timestamp":[NSDate date].description
                                    };
                                    NSData *pollBytes=[NSJSONSerialization dataWithJSONObject:pollData
                                                                                      options:0 error:NULL];
                                    if(pollBytes)[pollBytes writeToFile:checkpointPath
                                                                options:NSDataWritingAtomic error:NULL];
                                }
                            }
                            status=stopped?@"STOPPED":@"DONE";
                        }
                    }
                }
            }
            phase=@"CLEANUP";
            // Close the connection only after receive timeouts/notifications are recorded.
            if(connection!=MACH_PORT_NULL && close)closeCode=close(connection);
            if(service!=MACH_PORT_NULL && release)release(service);
            if(replyPort!=MACH_PORT_NULL)portDestroyCode=mach_port_destroy(mach_task_self(),replyPort);
            if(lib)dlclose(lib);
            [trace appendFormat:@"%@,CLEANUP,%u,0x%08x,0,0,0,%.1f\n",
                run,polls,(unsigned)closeCode,(CFAbsoluteTimeGetCurrent()-started)*1000.0];
            [trace writeToFile:tracePath atomically:YES encoding:NSUTF8StringEncoding error:NULL];

            NSDictionary *finished=@{
                @"run":run,@"status":status,@"phase":@"FINISHED",
                @"called":@(invoked),@"selector":@17,@"messages":@(received),
                @"polls":@(polls),@"timeouts":@(timeouts),
                @"receiveErrors":@(receiveErrors),
                @"openReturn":[NSString stringWithFormat:@"0x%08x",(unsigned)openCode],
                @"portReturn":[NSString stringWithFormat:@"0x%08x",(unsigned)portCode],
                @"sendReturn":[NSString stringWithFormat:@"0x%08x",(unsigned)sendCode],
                @"callReturn":[NSString stringWithFormat:@"0x%08x",(unsigned)callCode],
                @"closeReturn":[NSString stringWithFormat:@"0x%08x",(unsigned)closeCode],
                @"portDestroyReturn":[NSString stringWithFormat:@"0x%08x",(unsigned)portDestroyCode],
                @"elapsedMs":@((CFAbsoluteTimeGetCurrent()-started)*1000.0),
                @"timestamp":[NSDate date].description
            };
            NSData *end=[NSJSONSerialization dataWithJSONObject:finished
                                                        options:NSJSONWritingPrettyPrinted error:NULL];
            if(end)[end writeToFile:checkpointPath options:NSDataWritingAtomic error:NULL];
            dispatch_async(dispatch_get_main_queue(), ^{
                self.stressRunning=NO;
                [self note:[NSString stringWithFormat:
                    @"OBSERVE: %@ llamada=%@ retorno=0x%08x mensajes=%u timeouts=%u errores_recepcion=%u",
                    status,invoked?@"SI":@"NO",(unsigned)callCode,received,timeouts,receiveErrors]];
                [self note:[NSString stringWithFormat:
                    @"OBSERVE: cierre=0x%08x puerto_destroy=0x%08x",
                    (unsigned)closeCode,(unsigned)portDestroyCode]];
                [self note:@"OBSERVE: exportá el checkpoint y trace CSV. Sin mensajes en 3 s no demuestra que no existan respuestas posteriores."];
            });
        }
    });
}


- (void)integrityProbe:(id)sender {
    if(self.stressRunning || self.matrixRunning) {
        [self note:@"INTEGRITY: otra prueba está activa."];return;
    }
    self.stressRunning=YES;
    self.stressStopRequested=NO;
    NSString *run=NSUUID.UUID.UUIDString;
    NSString *boot=preflightBootStamp();
    NSString *directory=[NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
    NSString *checkpoint=[directory stringByAppendingPathComponent:
        @"IOSurfaceIntegrity-checkpoint.json"];
    NSString *tracePath=[directory stringByAppendingPathComponent:
        @"IOSurfaceIntegrity-trace.csv"];
    [self note:[NSString stringWithFormat:@"INTEGRITY: inicio run=%@ arranque=%@",run,boot]];
    [self note:@"INTEGRITY: 256 casos secuenciales; solo IOSurface APIs públicas y memoria de la aplicación."];
    [self note:@"INTEGRITY: escritura con patrón determinista, desbloqueo, segunda referencia válida y lectura de verificación."];
    [self note:@"INTEGRITY: ningún acceso fuera del tamaño asignado, sin carreras, sin referencias liberadas."];

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY,0), ^{
        @autoreleasepool {
            void *framework=dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface",
                                    RTLD_LAZY|RTLD_LOCAL);
            CreateSurfaceFn create=framework?(CreateSurfaceFn)dlsym(framework,"IOSurfaceCreate"):NULL;
            GetSurfaceIDFn getID=framework?(GetSurfaceIDFn)dlsym(framework,"IOSurfaceGetID"):NULL;
            LookupSurfaceFn lookup=framework?(LookupSurfaceFn)dlsym(framework,"IOSurfaceLookup"):NULL;
            GetSurfaceDimensionFn getWidth=framework?(GetSurfaceDimensionFn)dlsym(framework,"IOSurfaceGetWidth"):NULL;
            GetSurfaceDimensionFn getHeight=framework?(GetSurfaceDimensionFn)dlsym(framework,"IOSurfaceGetHeight"):NULL;
            GetSurfaceDimensionFn getSize=framework?(GetSurfaceDimensionFn)dlsym(framework,"IOSurfaceGetAllocSize"):NULL;
            GetSurfaceDimensionFn getRow=framework?(GetSurfaceDimensionFn)dlsym(framework,"IOSurfaceGetBytesPerRow"):NULL;
            GetSurfaceBaseFn getBase=framework?(GetSurfaceBaseFn)dlsym(framework,"IOSurfaceGetBaseAddress"):NULL;
            SurfaceLockFn lock=framework?(SurfaceLockFn)dlsym(framework,"IOSurfaceLock"):NULL;
            SurfaceLockFn unlock=framework?(SurfaceLockFn)dlsym(framework,"IOSurfaceUnlock"):NULL;
            NSMutableString *trace=[NSMutableString stringWithString:
                @"run,case,width,height,id,bytes,created,write_lock,write_unlock,lookup,read_lock,read_unlock,mismatches,first_mismatch,result\n"];
            const unsigned total=256;
            unsigned passed=0,errors=0,issues=0,attempted=0;
            BOOL stopped=NO;
            CFAbsoluteTime began=CFAbsoluteTimeGetCurrent();
            BOOL available=create&&getID&&lookup&&getWidth&&getHeight&&getSize&&getRow&&getBase&&lock&&unlock;
            if(available) {
                for(unsigned i=0;i<total;i++) {
                    if(self.stressStopRequested){stopped=YES;break;}
                    @autoreleasepool {
                        const size_t dims[]={16,32,64,128};
                        size_t w=dims[i%4],h=dims[(i/4)%4];
                        size_t bytes=w*h*4; // Max 65536 bytes. All accesses are checked.
                        size_t rowBytes=w*4;
                        NSDictionary *properties=@{
                            @"IOSurfaceWidth":@(w),@"IOSurfaceHeight":@(h),
                            @"IOSurfaceBytesPerElement":@4,
                            @"IOSurfaceBytesPerRow":@(rowBytes),
                            @"IOSurfaceAllocSize":@(bytes),
                            @"IOSurfacePixelFormat":@(0x42475241)
                        };
                        NSDictionary *before=@{
                            @"run":run,@"status":@"RUNNING",
                            @"phase":@"BEFORE_CASE",@"case":@(i),
                            @"tested":@(attempted),@"passed":@(passed),
                            @"mismatches":@(issues),@"errors":@(errors),
                            @"bootStamp":boot,@"timestamp":[NSDate date].description
                        };
                        NSData *b=[NSJSONSerialization dataWithJSONObject:before options:0 error:NULL];
                        if(b)[b writeToFile:checkpoint options:NSDataWritingAtomic error:NULL];

                        IOSurfaceRef surf=create((__bridge CFDictionaryRef)properties);
                        IOSurfaceID identifier=0;
                        kern_return_t writeCode=KERN_FAILURE,writeUnlock=KERN_FAILURE;
                        kern_return_t readCode=KERN_FAILURE,readUnlock=KERN_FAILURE;
                        BOOL found=NO,created=surf!=NULL,valid=NO;
                        unsigned bad=0;
                        long long first=-1;
                        NSString *result=@"ERROR";
                        if(surf) {
                            identifier=getID(surf);
                            size_t allocated=getSize(surf);
                            size_t actualRow=getRow(surf);
                            size_t actualWidth=getWidth(surf);
                            size_t actualHeight=getHeight(surf);
                            valid=allocated>=bytes && actualRow==rowBytes &&
                                  actualWidth==w && actualHeight==h;
                            if(valid) {
                                uint32_t writeSeed=0;
                                writeCode=lock(surf,0,&writeSeed);
                                if(writeCode==KERN_SUCCESS) {
                                    uint8_t *address=(uint8_t *)getBase(surf);
                                    if(address!=NULL) {
                                        for(size_t offset=0;offset<bytes;offset++)
                                            address[offset]=preflightExpectedByte(i,offset);
                                    } else valid=NO;
                                    writeUnlock=unlock(surf,0,&writeSeed);
                                }
                                if(writeCode==KERN_SUCCESS &&
                                   writeUnlock==KERN_SUCCESS && valid) {
                                    IOSurfaceRef second=lookup(identifier);
                                    found=second!=NULL;
                                    if(second) {
                                        if(getSize(second)>=bytes &&
                                           getRow(second)==rowBytes &&
                                           getWidth(second)==w &&
                                           getHeight(second)==h) {
                                            uint32_t readSeed=0;
                                            readCode=lock(second,0,&readSeed);
                                            if(readCode==KERN_SUCCESS) {
                                                uint8_t *readPtr=(uint8_t *)getBase(second);
                                                if(readPtr) {
                                                    for(size_t offset=0;offset<bytes;offset++) {
                                                        if(readPtr[offset]!=preflightExpectedByte(i,offset)) {
                                                            bad++;
                                                            if(first<0)first=(long long)offset;
                                                        }
                                                    }
                                                } else valid=NO;
                                                readUnlock=unlock(second,0,&readSeed);
                                            }
                                        } else valid=NO;
                                        CFRelease(second);
                                    }
                                }
                            }
                            CFRelease(surf);
                        }
                        if(created&&valid&&found&&writeCode==KERN_SUCCESS&&
                           writeUnlock==KERN_SUCCESS&&readCode==KERN_SUCCESS&&
                           readUnlock==KERN_SUCCESS) {
                            if(bad==0) { passed++; result=@"PASS"; }
                            else { issues++;result=@"DATA_MISMATCH"; }
                        } else { errors++;result=@"API_OR_METADATA_ERROR"; }
                        attempted++;
                        [trace appendFormat:
                            @"%@,%u,%zu,%zu,%u,%zu,%u,0x%08x,0x%08x,%u,0x%08x,0x%08x,%u,%lld,%@\n",
                            run,i,w,h,(unsigned)identifier,bytes,created?1U:0U,
                            (unsigned)writeCode,(unsigned)writeUnlock,found?1U:0U,
                            (unsigned)readCode,(unsigned)readUnlock,bad,first,result];
                        [trace writeToFile:tracePath atomically:YES
                                               encoding:NSUTF8StringEncoding error:NULL];
                        if((i+1)%32==0||bad>0) {
                            unsigned count=attempted,ok=passed,problems=issues,apiErrors=errors;
                            dispatch_async(dispatch_get_main_queue(), ^{
                                [self note:[NSString stringWithFormat:
                                    @"INTEGRITY: %u/%u PASS=%u diferencias=%u errores_API=%u",
                                    count,total,ok,problems,apiErrors]];
                            });
                        }
                        if(bad>0) {
                            unsigned idx=i,number=bad;long long offset=first;
                            dispatch_async(dispatch_get_main_queue(), ^{
                                [self note:[NSString stringWithFormat:
                                    @"INTEGRITY: diferencia caso=%u bytes=%u primer_offset=%lld",
                                    idx,number,offset]];
                            });
                        }
                    }
                }
            }
            if(framework)dlclose(framework);
            NSString *status=!available?@"ERROR_MISSING_SYMBOLS":stopped?@"STOPPED":@"DONE";
            NSDictionary *summary=@{
                @"run":run,@"status":status,@"phase":@"FINISHED",
                @"case":@(attempted),@"total":@(total),@"passed":@(passed),
                @"mismatches":@(issues),@"errors":@(errors),
                @"bootStamp":boot,@"elapsedMs":@((CFAbsoluteTimeGetCurrent()-began)*1000),
                @"timestamp":[NSDate date].description,
                @"interpretation":@"A mismatch is not proof of a kernel vulnerability or UAF"
            };
            NSData *end=[NSJSONSerialization dataWithJSONObject:summary
                                            options:NSJSONWritingPrettyPrinted error:NULL];
            if(end)[end writeToFile:checkpoint options:NSDataWritingAtomic error:NULL];
            dispatch_async(dispatch_get_main_queue(), ^{
                self.stressRunning=NO;
                [self note:[NSString stringWithFormat:
                    @"INTEGRITY: %@ total=%u PASS=%u discrepancias=%u errores_API=%u",
                    status,attempted,passed,issues,errors]];
                [self note:@"INTEGRITY: exportá IOSurfaceIntegrity-checkpoint.json y trace.csv. Una diferencia aislada no demuestra vulnerabilidad."];
            });
        }
    });
}


- (void)fireControlledClose:(id)sender {
    if (!self.controlledCloseRunning) {
        [self note:@"CIERRE: primero iniciá la prueba 16."];
        return;
    }
    self.controlledCloseRequested = YES;
    [self note:@"CIERRE: señal del usuario recibida. El worker cerrará su propia conexión en un punto de pausa de usuario."];
}

- (void)controlledCloseProbe:(id)sender {
    if (self.stressRunning || self.matrixRunning || self.controlledCloseRunning) {
        [self note:@"CIERRE: otra prueba está activa; no se solapan pruebas."];
        return;
    }
    self.stressRunning = YES;
    self.controlledCloseRunning = YES;
    self.controlledCloseRequested = NO;
    NSString *run = NSUUID.UUID.UUIDString;
    NSString *checkpointPath=[NSHomeDirectory() stringByAppendingPathComponent:
        @"Documents/IOSurfaceControlledClose-checkpoint.json"];
    NSString *tracePath=[NSHomeDirectory() stringByAppendingPathComponent:
        @"Documents/IOSurfaceControlledClose-trace.csv"];
    [self note:[NSString stringWithFormat:@"CIERRE: inicio run=%@", run]];
    [self note:@"CIERRE: se crea una IOSurface válida y se retiene una referencia por lookup."];
    [self note:@"CIERRE: botón 17 causa el cierre de una conexión IOSurfaceRoot explícita, con referencias vivas."];
    [self note:@"CIERRE: punto de pausa fuera del kernel. La conexión explícita NO se identifica con la conexión interna de IOSurfaceCreate."];
    [self note:@"CIERRE: no intenta carrera, corrupción, punteros obsoletos ni KernelRW."];

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY,0), ^{
        @autoreleasepool {
            __block uint32_t sid=0;
            __block kern_return_t openCode=KERN_FAILURE;
            __block kern_return_t closeCode=KERN_FAILURE;
            __block size_t retainedWidth=0;
            __block size_t afterCloseWidth=0;
            __block size_t afterReleaseWidth=0;
            __block BOOL userTriggered=NO;
            CFAbsoluteTime t0=CFAbsoluteTimeGetCurrent();
            NSMutableString *trace=[NSMutableString stringWithString:
                @"run,elapsed_ms,phase,status,id,open_kr,close_kr,source\n"];
            void (^checkpoint)(NSString *,NSString *) = ^(NSString *phase, NSString *status) {
                double ms=(CFAbsoluteTimeGetCurrent()-t0)*1000.0;
                NSDictionary *data=@{
                    @"run":run, @"phase":phase, @"status":status,
                    @"surfaceID":@(sid), @"openReturn":[NSString stringWithFormat:@"0x%08x",(unsigned)openCode],
                    @"closeReturn":[NSString stringWithFormat:@"0x%08x",(unsigned)closeCode],
                    @"userTriggered":@(userTriggered), @"elapsedMs":@(ms),
                    @"bootStamp":preflightBootStamp(),
                    @"timestamp":[NSDate date].description,
                    @"scope":@"User-space barrier, public IOSurface API, separately opened IOSurfaceRoot client",
                    @"noKernelTrace":@YES
                };
                NSData *json=[NSJSONSerialization dataWithJSONObject:data
                                            options:NSJSONWritingPrettyPrinted error:NULL];
                if(json)[json writeToFile:checkpointPath options:NSDataWritingAtomic error:NULL];
                [trace appendFormat:@"%@,%.1f,%@,%@,%u,0x%08x,0x%08x,%@\n",
                    run,ms,phase,status,(unsigned)sid,
                    (unsigned)openCode,(unsigned)closeCode,
                    userTriggered?@"USER":@"AUTO_OR_SETUP"];
                [trace writeToFile:tracePath atomically:YES
                          encoding:NSUTF8StringEncoding error:NULL];
            };
            checkpoint(@"SETUP",@"RUNNING");

            void *surfLib=dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface",
                                RTLD_LAZY|RTLD_LOCAL);
            void *ioLib=dlopen("/System/Library/Frameworks/IOKit.framework/IOKit",
                              RTLD_LAZY|RTLD_LOCAL);
            CreateSurfaceFn create=surfLib?(CreateSurfaceFn)dlsym(surfLib,"IOSurfaceCreate"):NULL;
            GetSurfaceIDFn getID=surfLib?(GetSurfaceIDFn)dlsym(surfLib,"IOSurfaceGetID"):NULL;
            LookupSurfaceFn lookup=surfLib?(LookupSurfaceFn)dlsym(surfLib,"IOSurfaceLookup"):NULL;
            GetSurfaceDimensionFn getWidth=surfLib?(GetSurfaceDimensionFn)dlsym(surfLib,"IOSurfaceGetWidth"):NULL;
            MatchingFn matching=ioLib?(MatchingFn)dlsym(ioLib,"IOServiceMatching"):NULL;
            GetMatchingFn getService=ioLib?(GetMatchingFn)dlsym(ioLib,"IOServiceGetMatchingService"):NULL;
            OpenServiceFn open=ioLib?(OpenServiceFn)dlsym(ioLib,"IOServiceOpen"):NULL;
            CloseServiceFn close=ioLib?(CloseServiceFn)dlsym(ioLib,"IOServiceClose"):NULL;
            ReleaseObjectFn release=ioLib?(ReleaseObjectFn)dlsym(ioLib,"IOObjectRelease"):NULL;
            IOSurfaceRef first=NULL,held=NULL;
            io_service_t service=MACH_PORT_NULL;
            io_connect_t connection=MACH_PORT_NULL;
            NSString *status=@"ERROR_SETUP";
            BOOL complete=create && getID && lookup && getWidth &&
                          matching && getService && open && close && release;
            if(complete) {
                NSDictionary *params=@{
                    @"IOSurfaceWidth":@64,@"IOSurfaceHeight":@64,
                    @"IOSurfaceBytesPerElement":@4,@"IOSurfaceBytesPerRow":@256,
                    @"IOSurfaceAllocSize":@(64*64*4),@"IOSurfacePixelFormat":@(0x42475241)
                };
                first=create((__bridge CFDictionaryRef)params);
                if(first) {
                    sid=getID(first);
                    held=lookup(sid);
                    if(held) {
                        retainedWidth=getWidth(held);
                        checkpoint(@"SURFACE_RETAINED",@"RUNNING");
                        CFMutableDictionaryRef request=matching("IOSurfaceRoot");
                        if(request) service=getService(MACH_PORT_NULL,request);
                        if(service) openCode=open(service,mach_task_self(),0,&connection);
                        if(openCode==KERN_SUCCESS && connection!=MACH_PORT_NULL) {
                            checkpoint(@"WAITING_USER_CLOSE",@"RUNNING");
                            dispatch_async(dispatch_get_main_queue(), ^{
                                [self note:[NSString stringWithFormat:
                                    @"CIERRE: ID=%u retenida, IOSurfaceRoot abierta; pulsá 17 para cerrar.",
                                    (unsigned)sid]];
                            });
                            // Voluntary user-space pause; it does not stop or preempt a kernel routine.
                            for(unsigned i=0;i<300;i++) {
                                if(self.controlledCloseRequested) {userTriggered=YES;break;}
                                usleep(100000);
                            }
                            checkpoint(@"BEFORE_CLIENT_CLOSE",@"RUNNING");
                            closeCode=close(connection);
                            connection=MACH_PORT_NULL;
                            checkpoint(@"AFTER_CLIENT_CLOSE",@"RUNNING");
                            // Both accesses use a live CF-owned IOSurfaceRef.
                            afterCloseWidth=getWidth(held);
                            CFRelease(first);
                            first=NULL;
                            afterReleaseWidth=getWidth(held);
                            CFRelease(held);
                            held=NULL;
                            checkpoint(@"REFERENCES_RELEASED",@"RUNNING");
                            status=closeCode==KERN_SUCCESS &&
                                   retainedWidth==64 && afterCloseWidth==64 &&
                                   afterReleaseWidth==64
                                  ? @"PASS_PUBLIC_LIFECYCLE" : @"OBSERVATION_NONPASS";
                        } else {
                            status=@"ERROR_OPEN_CONNECTION";
                        }
                    } else {
                        status=@"ERROR_LOOKUP";
                    }
                } else {
                    status=@"ERROR_CREATE_SURFACE";
                }
            }
            if(connection!=MACH_PORT_NULL && close)close(connection);
            if(held)CFRelease(held);
            if(first)CFRelease(first);
            if(service!=MACH_PORT_NULL && release)release(service);
            if(ioLib)dlclose(ioLib);
            if(surfLib)dlclose(surfLib);
            checkpoint(@"FINISHED",status);
            dispatch_async(dispatch_get_main_queue(), ^{
                self.stressRunning=NO;
                self.controlledCloseRunning=NO;
                self.controlledCloseRequested=NO;
                [self note:[NSString stringWithFormat:
                    @"CIERRE: %@ ID=%u, open=0x%08x close=0x%08x, ancho retenido=%zu, tras cierre=%zu, tras soltar creación=%zu, cierre voluntario=%@",
                    status,(unsigned)sid,(unsigned)openCode,(unsigned)closeCode,
                    retainedWidth,afterCloseWidth,afterReleaseWidth,userTriggered?@"SI":@"NO"]];
                [self note:@"CIERRE: exportá JSON y CSV. Este resultado NO implica interrupción dentro del kernel, UAF ni KernelRW."];
            });
        }
    });
}


- (void)publicConcurrencyProbe:(id)sender {
    if(self.stressRunning || self.matrixRunning || self.controlledCloseRunning) {
        [self note:@"CONCURRENT: otra prueba esta activa."];
        return;
    }
    self.stressRunning=YES;
    self.stressStopRequested=NO;
    NSString *run=NSUUID.UUID.UUIDString;
    NSString *directory=[NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
    NSString *checkpointPath=[directory stringByAppendingPathComponent:
        @"IOSurfaceConcurrency-checkpoint.json"];
    NSString *tracePath=[directory stringByAppendingPathComponent:
        @"IOSurfaceConcurrency-trace.csv"];
    [self note:[NSString stringWithFormat:@"CONCURRENT: inicio run=%@",run]];
    [self note:@"CONCURRENT: 2 hilos, hasta 256 IOSurfaceCreate y 256 conexiones IOSurfaceRoot abiertas/cerradas."];
    [self note:@"CONCURRENT: superficies propias, referencias validas, sin metodos privados ni acceso tras liberar."];
    [self note:@"CONCURRENT: el cierre se realiza sobre una conexion INDEPENDIENTE; no demuestra identidad del objeto kernel."];
    [self note:@"CONCURRENT: el solapamiento se mide a nivel aplicacion, NO demuestra carrera dentro del kernel."];

    NSDictionary *initial=@{
        @"run":run,@"status":@"RUNNING",@"phase":@"PREPARING",
        @"bootStamp":preflightBootStamp(),
        @"plannedCreate":@256,@"plannedClose":@256,
        @"timestamp":[NSDate date].description,
        @"sameKernelObjectEstablished":@NO,
        @"kernelLifetimeInstrumented":@NO
    };
    NSData *initialData=[NSJSONSerialization dataWithJSONObject:initial
                                        options:NSJSONWritingPrettyPrinted error:NULL];
    if(initialData)[initialData writeToFile:checkpointPath
                                   options:NSDataWritingAtomic error:NULL];

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY,0), ^{
        @autoreleasepool {
            CFAbsoluteTime begin=CFAbsoluteTimeGetCurrent();
            void *surfLib=dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface",
                                RTLD_LAZY|RTLD_LOCAL);
            void *ioLib=dlopen("/System/Library/Frameworks/IOKit.framework/IOKit",
                              RTLD_LAZY|RTLD_LOCAL);
            CreateSurfaceFn create=surfLib?(CreateSurfaceFn)dlsym(surfLib,"IOSurfaceCreate"):NULL;
            GetSurfaceIDFn getID=surfLib?(GetSurfaceIDFn)dlsym(surfLib,"IOSurfaceGetID"):NULL;
            LookupSurfaceFn lookup=surfLib?(LookupSurfaceFn)dlsym(surfLib,"IOSurfaceLookup"):NULL;
            GetSurfaceDimensionFn getWidth=surfLib?(GetSurfaceDimensionFn)dlsym(surfLib,"IOSurfaceGetWidth"):NULL;
            MatchingFn matching=ioLib?(MatchingFn)dlsym(ioLib,"IOServiceMatching"):NULL;
            GetMatchingFn getService=ioLib?(GetMatchingFn)dlsym(ioLib,"IOServiceGetMatchingService"):NULL;
            OpenServiceFn open=ioLib?(OpenServiceFn)dlsym(ioLib,"IOServiceOpen"):NULL;
            CloseServiceFn close=ioLib?(CloseServiceFn)dlsym(ioLib,"IOServiceClose"):NULL;
            ReleaseObjectFn release=ioLib?(ReleaseObjectFn)dlsym(ioLib,"IOObjectRelease"):NULL;
            BOOL available=create && getID && lookup && getWidth &&
                           matching && getService && open && close && release;
            __block unsigned createAttempts=0,createPasses=0,createErrors=0;
            __block unsigned closeAttempts=0,openPasses=0,closePasses=0;
            __block unsigned openErrors=0,closeErrors=0,overlaps=0;
            __block unsigned cancelledCreate=0,cancelledClose=0;
            NSMutableString *csv=[NSMutableString stringWithString:
                @"run,close_attempt,open_code,close_code,active_create_before,active_create_after,create_spanned_close,close_elapsed_ms\n"];
            if(available) {
                atomic_uint inCreate;
                atomic_init(&inCreate,0);
                atomic_uint *active=&inCreate;
                dispatch_group_t group=dispatch_group_create();
                dispatch_semaphore_t start=dispatch_semaphore_create(0);
                dispatch_queue_t q=dispatch_get_global_queue(QOS_CLASS_USER_INITIATED,0);

                dispatch_group_async(group,q,^{
                    @autoreleasepool {
                        NSDictionary *params=@{
                            @"IOSurfaceWidth":@32,@"IOSurfaceHeight":@32,
                            @"IOSurfaceBytesPerElement":@4,@"IOSurfaceBytesPerRow":@128,
                            @"IOSurfaceAllocSize":@(32*32*4),
                            @"IOSurfacePixelFormat":@(0x42475241)
                        };
                        dispatch_semaphore_wait(start,DISPATCH_TIME_FOREVER);
                        for(unsigned i=1;i<=256;i++) {
                            if(self.stressStopRequested) {
                                cancelledCreate=1;
                                break;
                            }
                            @autoreleasepool {
                                createAttempts++;
                                // The value is a unique iteration index, not a kernel pointer.
                                atomic_store_explicit(active,i,memory_order_release);
                                IOSurfaceRef first=create((__bridge CFDictionaryRef)params);
                                atomic_store_explicit(active,0,memory_order_release);
                                if(!first) {createErrors++;continue;}
                                IOSurfaceID sid=getID(first);
                                IOSurfaceRef held=lookup(sid);
                                BOOL ok=held && getWidth(held)==32;
                                if(held)CFRelease(held);
                                CFRelease(first);
                                if(ok)createPasses++;else createErrors++;
                            }
                            usleep(1000);
                        }
                    }
                });

                dispatch_group_async(group,q,^{
                    @autoreleasepool {
                        dispatch_semaphore_wait(start,DISPATCH_TIME_FOREVER);
                        for(unsigned i=1;i<=256;i++) {
                            if(self.stressStopRequested) {
                                cancelledClose=1;
                                break;
                            }
                            @autoreleasepool {
                                closeAttempts++;
                                CFMutableDictionaryRef request=matching("IOSurfaceRoot");
                                io_service_t service=request?getService(MACH_PORT_NULL,request):MACH_PORT_NULL;
                                io_connect_t connection=MACH_PORT_NULL;
                                kern_return_t openCode=service?
                                    open(service,mach_task_self(),0,&connection):KERN_FAILURE;
                                kern_return_t closeCode=KERN_FAILURE;
                                unsigned before=0,after=0;
                                BOOL spanned=NO;
                                double closeMs=0.0;
                                if(openCode==KERN_SUCCESS && connection!=MACH_PORT_NULL) {
                                    openPasses++;
                                    before=atomic_load_explicit(active,memory_order_acquire);
                                    CFAbsoluteTime closeBegin=CFAbsoluteTimeGetCurrent();
                                    closeCode=close(connection);
                                    closeMs=(CFAbsoluteTimeGetCurrent()-closeBegin)*1000.0;
                                    after=atomic_load_explicit(active,memory_order_acquire);
                                    spanned=before!=0 && before==after;
                                    if(spanned)overlaps++;
                                    if(closeCode==KERN_SUCCESS)closePasses++;
                                    else closeErrors++;
                                } else {
                                    openErrors++;
                                    if(connection!=MACH_PORT_NULL)close(connection);
                                }
                                if(service!=MACH_PORT_NULL)release(service);
                                [csv appendFormat:
                                    @"%@,%u,0x%08x,0x%08x,%u,%u,%u,%.3f\n",
                                    run,i,(unsigned)openCode,(unsigned)closeCode,
                                    before,after,spanned?1:0,closeMs];
                            }
                            usleep(1000);
                        }
                    }
                });

                dispatch_semaphore_signal(start);
                dispatch_semaphore_signal(start);
                dispatch_group_wait(group,DISPATCH_TIME_FOREVER);
            }

            NSString *status=!available?@"ERROR_MISSING_SYMBOLS":
                    (cancelledCreate || cancelledClose)?@"STOPPED":
                    (createErrors || openErrors || closeErrors)?@"DONE_WITH_API_ERRORS":
                    overlaps>0?@"DONE_APP_OVERLAP_OBSERVED":@"DONE_NO_APP_OVERLAP_OBSERVED";
            NSData *traceBytes=[csv dataUsingEncoding:NSUTF8StringEncoding];
            if(traceBytes)[traceBytes writeToFile:tracePath options:NSDataWritingAtomic error:NULL];
            NSDictionary *summary=@{
                @"run":run, @"status":status, @"phase":@"FINISHED",
                @"timestamp":[NSDate date].description,
                @"bootStamp":preflightBootStamp(),
                @"createAttempts":@(createAttempts),
                @"createPasses":@(createPasses),@"createErrors":@(createErrors),
                @"closeAttempts":@(closeAttempts),
                @"openPasses":@(openPasses),@"closePasses":@(closePasses),
                @"openErrors":@(openErrors),@"closeErrors":@(closeErrors),
                @"observedCreateOverlap":@(overlaps),
                @"elapsedMs":@((CFAbsoluteTimeGetCurrent()-begin)*1000.0),
                @"sameKernelObjectEstablished":@NO,
                @"kernelLifetimeInstrumented":@NO,
                @"uafProven":@NO,
                @"scope":@"Public IOSurface create/lookup versus separately opened and closed IOSurfaceRoot connection; app-level overlap only"
            };
            NSData *report=[NSJSONSerialization dataWithJSONObject:summary
                                             options:NSJSONWritingPrettyPrinted error:NULL];
            if(report)[report writeToFile:checkpointPath options:NSDataWritingAtomic error:NULL];
            if(surfLib)dlclose(surfLib);
            if(ioLib)dlclose(ioLib);
            dispatch_async(dispatch_get_main_queue(), ^{
                self.stressRunning=NO;
                [self note:[NSString stringWithFormat:
                    @"CONCURRENT: %@ create=%u/%u, open=%u/%u, close=%u/%u, overlap-app=%u, %.1fms",
                    status,createPasses,createAttempts,openPasses,closeAttempts,
                    closePasses,closeAttempts,overlaps,
                    (CFAbsoluteTimeGetCurrent()-begin)*1000.0]];
                [self note:@"CONCURRENT: exporta IOSurfaceConcurrency-checkpoint.json y trace.csv."];
                [self note:@"CONCURRENT: overlap-app > 0 NO demuestra que register/stop compartan cliente ni que exista UAF."];
            });
        }
    });
}


- (void)sameClientProbe:(id)sender {
    if(self.stressRunning || self.matrixRunning || self.controlledCloseRunning) {
        [self note:@"SAMECLIENT: otra prueba sigue activa."];
        return;
    }
    UIAlertController *warning=[UIAlertController alertControllerWithTitle:
        @"Ensayo de concurrencia sobre el mismo cliente"
        message:@"Esta prueba hace coincidir una llamada asíncrona real al selector 17 y el cierre de ESA misma conexión IOSurfaceRoot, en hasta 12 ensayos. Podría cerrar la app o reiniciar el dispositivo si existe un fallo. Guardá tus datos antes de continuar. No es un jailbreak."
        preferredStyle:UIAlertControllerStyleAlert];
    [warning addAction:[UIAlertAction actionWithTitle:@"Cancelar"
        style:UIAlertActionStyleCancel handler:nil]];
    __weak typeof(self) weakSelf=self;
    [warning addAction:[UIAlertAction actionWithTitle:@"Iniciar los 12 ensayos"
        style:UIAlertActionStyleDestructive handler:^(UIAlertAction *action) {
            [weakSelf runSameClientProbe];
        }]];
    [self presentViewController:warning animated:YES completion:nil];
}

- (void)runSameClientProbe {
    if(self.stressRunning || self.matrixRunning || self.controlledCloseRunning)return;
    self.stressRunning=YES;
    self.stressStopRequested=NO;
    NSString *run=NSUUID.UUID.UUIDString;
    NSString *directory=[NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
    NSString *checkpoint=[directory stringByAppendingPathComponent:
        @"IOSurfaceSameClient-checkpoint.json"];
    NSString *csvPath=[directory stringByAppendingPathComponent:
        @"IOSurfaceSameClient-trace.csv"];
    NSString *boot=preflightBootStamp();
    [self note:[NSString stringWithFormat:@"SAMECLIENT: inicio run=%@ boot=%@",run,boot]];
    [self note:@"SAMECLIENT: llamada asíncrona selector 17 con payload cero y cierre del MISMO io_connect_t."];
    [self note:@"SAMECLIENT: 12 ensayos máximo, cada uno usa una conexión nueva y un puerto de respuesta válido."];
    [self note:@"SAMECLIENT: barrera de hilos en usuario; solapamiento temporal NO implica solapamiento interno ni UAF."];
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY,0), ^{
        @autoreleasepool {
            void *lib=dlopen("/System/Library/Frameworks/IOKit.framework/IOKit",
                              RTLD_LAZY|RTLD_LOCAL);
            MatchingFn matching=lib?(MatchingFn)dlsym(lib,"IOServiceMatching"):NULL;
            GetMatchingFn getService=lib?(GetMatchingFn)dlsym(lib,"IOServiceGetMatchingService"):NULL;
            OpenServiceFn open=lib?(OpenServiceFn)dlsym(lib,"IOServiceOpen"):NULL;
            CloseServiceFn close=lib?(CloseServiceFn)dlsym(lib,"IOServiceClose"):NULL;
            ReleaseObjectFn release=lib?(ReleaseObjectFn)dlsym(lib,"IOObjectRelease"):NULL;
            typedef kern_return_t (*CallAsyncStructFn)(io_connect_t,uint32_t,
                       mach_port_t,uint64_t *,uint32_t,const void *,size_t,void *,size_t *);
            CallAsyncStructFn call=lib?(CallAsyncStructFn)dlsym(lib,
                                  "IOConnectCallAsyncStructMethod"):NULL;
            BOOL available=matching && getService && open && close && release && call;
            const unsigned maxTrials=12;
            unsigned attempts=0,openSuccess=0,callSuccess=0,closeSuccess=0;
            unsigned observedOverlap=0,errors=0;
            BOOL stopped=NO;
            CFAbsoluteTime began=CFAbsoluteTimeGetCurrent();
            mach_timebase_info_data_t tb={0,0};
            mach_timebase_info(&tb);
            NSMutableString *csv=[NSMutableString stringWithString:
                @"run,trial,open_kr,port_kr,call_kr,close_kr,call_start_us,call_end_us,close_start_us,close_end_us,user_space_overlap\n"];

            if(available) {
                dispatch_queue_t q=dispatch_get_global_queue(QOS_CLASS_USER_INITIATED,0);
                for(unsigned trial=1;trial<=maxTrials;trial++) {
                    if(self.stressStopRequested){stopped=YES;break;}
                    @autoreleasepool {
                        attempts++;
                        NSDictionary *progress=@{
                            @"run":run,@"status":@"RUNNING",@"phase":@"BEFORE_TRIAL",
                            @"trial":@(trial),@"attempts":@(attempts),
                            @"userSpaceOverlap":@(observedOverlap),
                            @"bootStamp":boot,@"timestamp":[NSDate date].description,
                            @"sameConnection":@YES,@"sameKernelObjectProven":@NO,
                            @"kernelMemoryObserved":@NO
                        };
                        NSData *progressData=[NSJSONSerialization dataWithJSONObject:progress
                                             options:NSJSONWritingPrettyPrinted error:NULL];
                        if(progressData)[progressData writeToFile:checkpoint options:NSDataWritingAtomic error:NULL];

                        CFMutableDictionaryRef request=matching("IOSurfaceRoot");
                        io_service_t service=request?
                             getService(MACH_PORT_NULL,request):MACH_PORT_NULL;
                        io_connect_t connection=MACH_PORT_NULL;
                        kern_return_t openCode=service?
                             open(service,mach_task_self(),0,&connection):KERN_FAILURE;
                        kern_return_t portCode=KERN_FAILURE;
                        kern_return_t sendCode=KERN_FAILURE;
                        kern_return_t callCode=KERN_FAILURE;
                        kern_return_t closeCode=KERN_FAILURE;
                        mach_port_t replyPort=MACH_PORT_NULL;
                        uint64_t callStart=0,callEnd=0,closeStart=0,closeEnd=0;
                        BOOL overlap=NO;
                        if(openCode==KERN_SUCCESS && connection!=MACH_PORT_NULL) {
                            openSuccess++;
                            portCode=mach_port_allocate(mach_task_self(),
                                MACH_PORT_RIGHT_RECEIVE,&replyPort);
                            if(portCode==KERN_SUCCESS) {
                                sendCode=mach_port_insert_right(mach_task_self(),
                                    replyPort,replyPort,MACH_MSG_TYPE_MAKE_SEND);
                            }
                            if(portCode==KERN_SUCCESS && sendCode==KERN_SUCCESS) {
                                dispatch_semaphore_t barrier=dispatch_semaphore_create(0);
                                dispatch_group_t group=dispatch_group_create();
                                __block kern_return_t asyncResult=KERN_FAILURE;
                                __block kern_return_t closeResult=KERN_FAILURE;
                                __block uint64_t tCall0=0,tCall1=0,tClose0=0,tClose1=0;
                                // Keep replyPort and payload alive until both tasks have completed.
                                dispatch_group_async(group,q,^{
                                    uint8_t payload[24]={0};
                                    uint64_t reference[8]={0};
                                    size_t outputBytes=0;
                                    tCall0=mach_absolute_time();
                                    dispatch_semaphore_signal(barrier);
                                    asyncResult=call(connection,17,replyPort,reference,8,
                                                     payload,sizeof(payload),NULL,&outputBytes);
                                    tCall1=mach_absolute_time();
                                });
                                dispatch_group_async(group,q,^{
                                    dispatch_semaphore_wait(barrier,DISPATCH_TIME_FOREVER);
                                    tClose0=mach_absolute_time();
                                    closeResult=close(connection);
                                    tClose1=mach_absolute_time();
                                });
                                dispatch_group_wait(group,DISPATCH_TIME_FOREVER);
                                callCode=asyncResult;
                                closeCode=closeResult;
                                callStart=tCall0;
                                callEnd=tCall1;
                                closeStart=tClose0;
                                closeEnd=tClose1;
                                overlap=callStart>0 && callEnd>=callStart &&
                                    closeStart>0 && closeEnd>=closeStart &&
                                    callStart<=closeEnd && closeStart<=callEnd;
                                if(overlap)observedOverlap++;
                                if(callCode==KERN_SUCCESS)callSuccess++;
                                if(closeCode==KERN_SUCCESS)closeSuccess++;
                            } else {
                                // The client is not shared with another thread if setup failed.
                                closeCode=close(connection);
                                if(closeCode==KERN_SUCCESS)closeSuccess++;
                            }
                        }
                        if(openCode!=KERN_SUCCESS || portCode!=KERN_SUCCESS ||
                           sendCode!=KERN_SUCCESS ||
                           callCode!=KERN_SUCCESS || closeCode!=KERN_SUCCESS)errors++;
                        if(replyPort!=MACH_PORT_NULL)
                            mach_port_destroy(mach_task_self(),replyPort);
                        if(service!=MACH_PORT_NULL)release(service);
                        double mul=(tb.denom!=0)?(double)tb.numer/(double)tb.denom/1000.0:0.0;
                        uint64_t base=callStart?callStart:closeStart;
                        [csv appendFormat:
                            @"%@,%u,0x%08x,0x%08x,0x%08x,0x%08x,%.3f,%.3f,%.3f,%.3f,%u\n",
                            run,trial,(unsigned)openCode,(unsigned)portCode,
                            (unsigned)callCode,(unsigned)closeCode,
                            callStart>=base?(callStart-base)*mul:0,
                            callEnd>=base?(callEnd-base)*mul:0,
                            closeStart>=base?(closeStart-base)*mul:0,
                            closeEnd>=base?(closeEnd-base)*mul:0,
                            overlap?1:0];
                        [csv writeToFile:csvPath atomically:YES
                            encoding:NSUTF8StringEncoding error:NULL];
                        // Checkpoint proves which iteration completed even after a later crash.
                        NSDictionary *after=@{
                            @"run":run,@"status":@"RUNNING",@"phase":@"AFTER_TRIAL",
                            @"trial":@(trial),@"attempts":@(attempts),
                            @"callReturn":[NSString stringWithFormat:@"0x%08x",(unsigned)callCode],
                            @"closeReturn":[NSString stringWithFormat:@"0x%08x",(unsigned)closeCode],
                            @"userSpaceOverlap":@(observedOverlap),
                            @"bootStamp":boot,@"timestamp":[NSDate date].description,
                            @"sameConnection":@YES,@"sameKernelObjectProven":@NO,
                            @"kernelMemoryObserved":@NO
                        };
                        NSData *afterData=[NSJSONSerialization dataWithJSONObject:after
                                        options:NSJSONWritingPrettyPrinted error:NULL];
                        if(afterData)[afterData writeToFile:checkpoint options:NSDataWritingAtomic error:NULL];
                        if(errors>0) {
                            // Keep anomalies inspectable; do not continue probing after an error.
                            break;
                        }
                    }
                }
            }
            NSString *status=!available?@"ERROR_MISSING_SYMBOLS":
                stopped?@"STOPPED":errors>0?@"STOPPED_ON_API_ERROR":
                @"DONE_NO_API_ERRORS";
            NSDictionary *summary=@{
                @"run":run,@"status":status,@"phase":@"FINISHED",
                @"timestamp":[NSDate date].description,
                @"bootStamp":boot,@"trial":@(attempts),@"maxTrials":@(maxTrials),
                @"openPasses":@(openSuccess),@"callPasses":@(callSuccess),
                @"closePasses":@(closeSuccess),@"apiErrors":@(errors),
                @"userSpaceOverlap":@(observedOverlap),
                @"elapsedMs":@((CFAbsoluteTimeGetCurrent()-began)*1000.0),
                @"sameConnection":@YES,
                @"sameKernelObjectProven":@NO,
                @"kernelMemoryObserved":@NO,@"uafProven":@NO,
                @"scope":@"same explicit io_connect_t, selector17 async vs IOServiceClose; user-space clock only"
            };
            NSData *result=[NSJSONSerialization dataWithJSONObject:summary
                                     options:NSJSONWritingPrettyPrinted error:NULL];
            if(result)[result writeToFile:checkpoint options:NSDataWritingAtomic error:NULL];
            if(lib)dlclose(lib);
            dispatch_async(dispatch_get_main_queue(), ^{
                self.stressRunning=NO;
                [self note:[NSString stringWithFormat:
                    @"SAMECLIENT: %@ intentos=%u open=%u call17=%u close=%u err=%u overlap-usuario=%u",
                    status,attempts,openSuccess,callSuccess,closeSuccess,errors,observedOverlap]];
                [self note:@"SAMECLIENT: exportá IOSurfaceSameClient-checkpoint.json y trace.csv."];
                [self note:@"SAMECLIENT: misma conexión, pero sin inspección del kernel. Ningún solapamiento usuario demuestra UAF."];
            });
        }
    });
}


- (void)ipcControlsProbe:(id)sender {
    if(self.stressRunning || self.matrixRunning || self.controlledCloseRunning) {
        [self note:@"IPCCTRL: otra prueba esta activa."];
        return;
    }
    self.stressRunning=YES;
    self.stressStopRequested=NO;
    NSString *run=NSUUID.UUID.UUIDString;
    NSString *boot=preflightBootStamp();
    NSString *directory=[NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
    NSString *checkpointPath=[directory stringByAppendingPathComponent:
        @"IOSurfaceIPCControls-checkpoint.json"];
    NSString *csvPath=[directory stringByAppendingPathComponent:
        @"IOSurfaceIPCControls-trace.csv"];
    [self note:[NSString stringWithFormat:@"IPCCTRL: run=%@ boot=%@",run,boot]];
    [self note:@"IPCCTRL: prueba causal. Control A: llamada al selector 17 con conexion abierta."];
    [self note:@"IPCCTRL: control B: cierre terminado y despues llamada al puerto ya cerrado."];
    [self note:@"IPCCTRL: 3 pares, sin simultaneidad, sin punteros de memoria de usuario liberados."];
    [self note:@"IPCCTRL: si B devuelve 0x10000003 como v15, eso respalda un fallo de transporte Mach, NO un UAF."];

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY,0), ^{
        @autoreleasepool {
            void *io=dlopen("/System/Library/Frameworks/IOKit.framework/IOKit",
                            RTLD_LAZY|RTLD_LOCAL);
            MatchingFn matching=io?(MatchingFn)dlsym(io,"IOServiceMatching"):NULL;
            GetMatchingFn getService=io?(GetMatchingFn)dlsym(io,"IOServiceGetMatchingService"):NULL;
            OpenServiceFn open=io?(OpenServiceFn)dlsym(io,"IOServiceOpen"):NULL;
            CloseServiceFn close=io?(CloseServiceFn)dlsym(io,"IOServiceClose"):NULL;
            ReleaseObjectFn release=io?(ReleaseObjectFn)dlsym(io,"IOObjectRelease"):NULL;
            typedef kern_return_t (*CallAsyncStructFn)(io_connect_t,uint32_t,
                 mach_port_t,uint64_t*,uint32_t,const void*,size_t,void*,size_t*);
            CallAsyncStructFn call=io?(CallAsyncStructFn)dlsym(io,
                                               "IOConnectCallAsyncStructMethod"):NULL;
            BOOL available=matching && getService && open && close && release && call;
            const unsigned totalPairs=3;
            __block unsigned attempts=0,openSuccess=0,healthyCall=0,closedInvalidDest=0;
            __block unsigned closeSuccess=0,setupErrors=0,unexpectedCodes=0;
            CFAbsoluteTime began=CFAbsoluteTimeGetCurrent();
            NSMutableString *csv=[NSMutableString stringWithString:
                 @"run,pair,control,open_kr,port_kr,send_kr,call_kr,close_kr,port_before_kr,port_after_kr,port_before_type,port_after_type,elapsed_ms\n"];
            void (^writeCheckpoint)(NSString*,NSString*,NSNumber*)=
            ^(NSString *phase,NSString *status,NSNumber *caseNumber) {
                NSDictionary *data=@{
                    @"run":run,@"phase":phase,@"status":status,
                    @"case":caseNumber,@"bootStamp":boot,
                    @"timestamp":[NSDate date].description,
                    @"attempts":@(attempts),@"openSuccess":@(openSuccess),
                    @"healthyCall":@(healthyCall),@"closedInvalidDest":@(closedInvalidDest),
                    @"closeSuccess":@(closeSuccess),@"setupErrors":@(setupErrors),
                    @"unexpectedCodes":@(unexpectedCodes),
                    @"interpretation":@"Transport-level sequential controls; no race, no kernel lifetime observation",
                    @"uafProven":@NO
                };
                NSData *bytes=[NSJSONSerialization dataWithJSONObject:data
                                             options:NSJSONWritingPrettyPrinted error:NULL];
                if(bytes)[bytes writeToFile:checkpointPath options:NSDataWritingAtomic error:NULL];
            };
            writeCheckpoint(@"SETUP",@"RUNNING",@0);
            BOOL cancelled=NO;
            if(available) {
                for(unsigned pair=1;pair<=totalPairs;pair++) {
                    for(unsigned condition=0;condition<2;condition++) {
                        if(self.stressStopRequested) {cancelled=YES;break;}
                        @autoreleasepool {
                            BOOL closedFirst=(condition==1);
                            attempts++;
                            writeCheckpoint(closedFirst?@"BEFORE_CLOSED_CONTROL":@"BEFORE_OPEN_CONTROL",
                                            @"RUNNING",@(attempts));
                            io_service_t service=MACH_PORT_NULL;
                            io_connect_t connection=MACH_PORT_NULL;
                            mach_port_t replyPort=MACH_PORT_NULL;
                            kern_return_t openCode=KERN_FAILURE,portCode=KERN_FAILURE;
                            kern_return_t sendCode=KERN_FAILURE,callCode=KERN_FAILURE;
                            kern_return_t closeCode=KERN_FAILURE;
                            kern_return_t typeBeforeCode=KERN_FAILURE,typeAfterCode=KERN_FAILURE;
                            mach_port_type_t typeBefore=0,typeAfter=0;
                            BOOL closed=NO;
                            CFMutableDictionaryRef request=matching("IOSurfaceRoot");
                            if(request)service=getService(MACH_PORT_NULL,request);
                            if(service)openCode=open(service,mach_task_self(),0,&connection);
                            if(openCode==KERN_SUCCESS && connection!=MACH_PORT_NULL) {
                                openSuccess++;
                                typeBeforeCode=mach_port_type(mach_task_self(),connection,&typeBefore);
                                portCode=mach_port_allocate(mach_task_self(),
                                    MACH_PORT_RIGHT_RECEIVE,&replyPort);
                                if(portCode==KERN_SUCCESS)
                                    sendCode=mach_port_insert_right(mach_task_self(),replyPort,
                                        replyPort,MACH_MSG_TYPE_MAKE_SEND);
                                if(portCode==KERN_SUCCESS && sendCode==KERN_SUCCESS) {
                                    uint8_t input[24]={0};
                                    uint64_t reference[8]={0};
                                    size_t outputBytes=0;
                                    if(closedFirst) {
                                        closeCode=close(connection);
                                        closed=closeCode==KERN_SUCCESS;
                                        typeAfterCode=mach_port_type(mach_task_self(),connection,&typeAfter);
                                        if(closed) {
                                            callCode=call(connection,17,replyPort,reference,8,
                                                          input,sizeof(input),NULL,&outputBytes);
                                        }
                                    } else {
                                        callCode=call(connection,17,replyPort,reference,8,
                                                      input,sizeof(input),NULL,&outputBytes);
                                        closeCode=close(connection);
                                        closed=closeCode==KERN_SUCCESS;
                                        typeAfterCode=mach_port_type(mach_task_self(),connection,&typeAfter);
                                    }
                                    if(closedFirst && callCode==(kern_return_t)0x10000003)
                                        closedInvalidDest++;
                                    if(!closedFirst && callCode==KERN_SUCCESS)
                                        healthyCall++;
                                    if(callCode!=(closedFirst?(kern_return_t)0x10000003:KERN_SUCCESS))
                                        unexpectedCodes++;
                                } else setupErrors++;
                            } else setupErrors++;
                            if(connection!=MACH_PORT_NULL && !closed) {
                                // Normal cleanup if setup failed or close itself returned an error.
                                if(closeCode==KERN_FAILURE)closeCode=close(connection);
                                if(closeCode==KERN_SUCCESS)closed=YES;
                            }
                            if(closeCode==KERN_SUCCESS)closeSuccess++;
                            if(replyPort!=MACH_PORT_NULL)mach_port_destroy(mach_task_self(),replyPort);
                            if(service!=MACH_PORT_NULL)release(service);
                            [csv appendFormat:
                                @"%@,%u,%@,0x%08x,0x%08x,0x%08x,0x%08x,0x%08x,0x%08x,0x%08x,0x%08x,0x%08x,%.3f\n",
                                run,pair,closedFirst?@"CLOSED_FIRST":@"OPEN_FIRST",
                                (unsigned)openCode,(unsigned)portCode,(unsigned)sendCode,
                                (unsigned)callCode,(unsigned)closeCode,
                                (unsigned)typeBeforeCode,(unsigned)typeAfterCode,
                                (unsigned)typeBefore,(unsigned)typeAfter,
                                (CFAbsoluteTimeGetCurrent()-began)*1000.0];
                            [csv writeToFile:csvPath atomically:YES
                                          encoding:NSUTF8StringEncoding error:NULL];
                            writeCheckpoint(@"AFTER_CASE",@"RUNNING",@(attempts));
                            if(setupErrors>0)break;
                        }
                    }
                    if(cancelled || setupErrors>0)break;
                }
            }
            NSString *status=!available?@"ERROR_MISSING_SYMBOLS":
                             cancelled?@"STOPPED":
                             setupErrors>0?@"ERROR_SETUP":
                             healthyCall==3 && closedInvalidDest==3?
                             @"EXPECTED_MACH_TRANSPORT_BEHAVIOR":
                             @"MIXED_RESULTS_REVIEW_REQUIRED";
            NSDictionary *summary=@{
                @"run":run,@"phase":@"FINISHED",@"status":status,
                @"case":@(attempts),@"bootStamp":boot,
                @"timestamp":[NSDate date].description,
                @"plannedPairs":@(totalPairs),@"attempts":@(attempts),
                @"healthyCall":@(healthyCall),@"closedInvalidDest":@(closedInvalidDest),
                @"openSuccess":@(openSuccess),@"closeSuccess":@(closeSuccess),
                @"setupErrors":@(setupErrors),@"unexpectedCodes":@(unexpectedCodes),
                @"elapsedMs":@((CFAbsoluteTimeGetCurrent()-began)*1000.0),
                @"kernelMemoryObserved":@NO,@"uafProven":@NO,
                @"meaning":@"Positive versus negative sequential controls for 0x10000003. Does not test UAF."
            };
            NSData *result=[NSJSONSerialization dataWithJSONObject:summary
                                          options:NSJSONWritingPrettyPrinted error:NULL];
            if(result)[result writeToFile:checkpointPath options:NSDataWritingAtomic error:NULL];
            if(io)dlclose(io);
            dispatch_async(dispatch_get_main_queue(), ^{
                self.stressRunning=NO;
                [self note:[NSString stringWithFormat:
                    @"IPCCTRL: %@ openSuccess=%u callWhileOpen=%u closedInvalidDest=%u closeSuccess=%u attempts=%u",
                    status,openSuccess,healthyCall,closedInvalidDest,closeSuccess,attempts]];
                [self note:@"IPCCTRL: exportá IOSurfaceIPCControls-checkpoint.json y trace.csv."];
                [self note:@"IPCCTRL: si el control B reproduce el error de v15, su origen puede ser IPC sin ningun acceso a un objeto liberado."];
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
        NSString *csvPath = [NSTemporaryDirectory() stringByAppendingPathComponent:@"IOSurfacePreflight-latest-campaign.csv"];
        NSError *csvError = nil;
        if ([self.stressCSV writeToFile:csvPath atomically:YES encoding:NSUTF8StringEncoding error:&csvError]) {
            [filesToShare addObject:[NSURL fileURLWithPath:csvPath]];
        } else {
            [self note:[NSString stringWithFormat:@"FUZZ: error exportando CSV: %@", csvError.localizedDescription]];
        }
    }
    NSString *checkpoint = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/IOSurfaceCampaign-checkpoint.json"];
    if ([[NSFileManager defaultManager] fileExistsAtPath:checkpoint]) {
        [filesToShare addObject:[NSURL fileURLWithPath:checkpoint]];
    }
    NSString *boundaryCheckpoint = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/IOSurfaceBoundary-checkpoint.json"];
    if ([[NSFileManager defaultManager] fileExistsAtPath:boundaryCheckpoint]) {
        [filesToShare addObject:[NSURL fileURLWithPath:boundaryCheckpoint]];
    }
    NSString *selectorFile=[NSHomeDirectory() stringByAppendingPathComponent:@"Documents/IOSurfaceSelector17-checkpoint.json"];
    NSString *selectorCSV=[NSHomeDirectory() stringByAppendingPathComponent:@"Documents/IOSurfaceSelector17-trace.csv"];
    if([[NSFileManager defaultManager] fileExistsAtPath:selectorFile])
        [filesToShare addObject:[NSURL fileURLWithPath:selectorFile]];
    if([[NSFileManager defaultManager] fileExistsAtPath:selectorCSV])
        [filesToShare addObject:[NSURL fileURLWithPath:selectorCSV]];
    NSString *asyncCheckpoint=[NSHomeDirectory() stringByAppendingPathComponent:
        @"Documents/IOSurfaceAsyncContract-checkpoint.json"];
    if([[NSFileManager defaultManager] fileExistsAtPath:asyncCheckpoint])
        [filesToShare addObject:[NSURL fileURLWithPath:asyncCheckpoint]];
    NSString *observerCheckpoint=[NSHomeDirectory() stringByAppendingPathComponent:
        @"Documents/IOSurfaceAsyncObserver-checkpoint.json"];
    NSString *observerTrace=[NSHomeDirectory() stringByAppendingPathComponent:
        @"Documents/IOSurfaceAsyncObserver-trace.csv"];
    if([[NSFileManager defaultManager] fileExistsAtPath:observerCheckpoint])
        [filesToShare addObject:[NSURL fileURLWithPath:observerCheckpoint]];
    if([[NSFileManager defaultManager] fileExistsAtPath:observerTrace])
        [filesToShare addObject:[NSURL fileURLWithPath:observerTrace]];
    NSString *integrityFile=[NSHomeDirectory() stringByAppendingPathComponent:
        @"Documents/IOSurfaceIntegrity-checkpoint.json"];
    NSString *integrityCSV=[NSHomeDirectory() stringByAppendingPathComponent:
        @"Documents/IOSurfaceIntegrity-trace.csv"];
    if([[NSFileManager defaultManager] fileExistsAtPath:integrityFile])
        [filesToShare addObject:[NSURL fileURLWithPath:integrityFile]];
    if([[NSFileManager defaultManager] fileExistsAtPath:integrityCSV])
        [filesToShare addObject:[NSURL fileURLWithPath:integrityCSV]];
    NSString *closeFile=[NSHomeDirectory() stringByAppendingPathComponent:
        @"Documents/IOSurfaceControlledClose-checkpoint.json"];
    NSString *closeTrace=[NSHomeDirectory() stringByAppendingPathComponent:
        @"Documents/IOSurfaceControlledClose-trace.csv"];
    if([[NSFileManager defaultManager] fileExistsAtPath:closeFile])
        [filesToShare addObject:[NSURL fileURLWithPath:closeFile]];
    if([[NSFileManager defaultManager] fileExistsAtPath:closeTrace])
        [filesToShare addObject:[NSURL fileURLWithPath:closeTrace]];
    NSString *concurrentCheckpoint=[NSHomeDirectory() stringByAppendingPathComponent:
        @"Documents/IOSurfaceConcurrency-checkpoint.json"];
    NSString *concurrentTrace=[NSHomeDirectory() stringByAppendingPathComponent:
        @"Documents/IOSurfaceConcurrency-trace.csv"];
    if([[NSFileManager defaultManager] fileExistsAtPath:concurrentCheckpoint])
        [filesToShare addObject:[NSURL fileURLWithPath:concurrentCheckpoint]];
    if([[NSFileManager defaultManager] fileExistsAtPath:concurrentTrace])
        [filesToShare addObject:[NSURL fileURLWithPath:concurrentTrace]];
    NSString *sameCheckpoint=[NSHomeDirectory() stringByAppendingPathComponent:
        @"Documents/IOSurfaceSameClient-checkpoint.json"];
    NSString *sameCSV=[NSHomeDirectory() stringByAppendingPathComponent:
        @"Documents/IOSurfaceSameClient-trace.csv"];
    if([[NSFileManager defaultManager] fileExistsAtPath:sameCheckpoint])
        [filesToShare addObject:[NSURL fileURLWithPath:sameCheckpoint]];
    if([[NSFileManager defaultManager] fileExistsAtPath:sameCSV])
        [filesToShare addObject:[NSURL fileURLWithPath:sameCSV]];
    NSString *controlsCheckpoint=[NSHomeDirectory() stringByAppendingPathComponent:
        @"Documents/IOSurfaceIPCControls-checkpoint.json"];
    NSString *controlsCSV=[NSHomeDirectory() stringByAppendingPathComponent:
        @"Documents/IOSurfaceIPCControls-trace.csv"];
    if([[NSFileManager defaultManager] fileExistsAtPath:controlsCheckpoint])
        [filesToShare addObject:[NSURL fileURLWithPath:controlsCheckpoint]];
    if([[NSFileManager defaultManager] fileExistsAtPath:controlsCSV])
        [filesToShare addObject:[NSURL fileURLWithPath:controlsCSV]];
    NSString *bruteCheckpoint=[NSHomeDirectory() stringByAppendingPathComponent:
        @"Documents/IOSurfaceBruteForce-checkpoint.json"];
    if([[NSFileManager defaultManager] fileExistsAtPath:bruteCheckpoint])
        [filesToShare addObject:[NSURL fileURLWithPath:bruteCheckpoint]];
    for(NSString *file in @[@"IOSurfaceBruteForce-v18-checkpoint.json",
                            @"IOSurfaceBruteForce-v18-trace.csv"]) {
        NSString *path=[[NSHomeDirectory() stringByAppendingPathComponent:@"Documents"]
                            stringByAppendingPathComponent:file];
        if([[NSFileManager defaultManager] fileExistsAtPath:path])
            [filesToShare addObject:[NSURL fileURLWithPath:path]];
    }
    for(NSString *name in @[@"IOSurfaceBootMonitor-checkpoint.json",
                            @"IOSurfaceBootMonitor-trace.csv"]) {
        NSString *p=[[NSHomeDirectory() stringByAppendingPathComponent:@"Documents"]
                       stringByAppendingPathComponent:name];
        if([[NSFileManager defaultManager] fileExistsAtPath:p])
            [filesToShare addObject:[NSURL fileURLWithPath:p]];
    }
    for(NSString *name in @[@"IOSurfaceCoverage-v19_2.json",
                            @"IOSurfaceCoverage-v19_2.csv"]) {
        NSString *p=[[NSHomeDirectory() stringByAppendingPathComponent:@"Documents"]
                       stringByAppendingPathComponent:name];
        if([[NSFileManager defaultManager] fileExistsAtPath:p])
            [filesToShare addObject:[NSURL fileURLWithPath:p]];
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
