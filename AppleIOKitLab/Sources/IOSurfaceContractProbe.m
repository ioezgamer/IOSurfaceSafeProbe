#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <CoreFoundation/CoreFoundation.h>
#import <mach/mach.h>
#import <sys/sysctl.h>
#import <sys/utsname.h>
#import <dlfcn.h>
#import <stdint.h>

// Contrato de IOSurface: inspeccion de registro y una consulta sin inputs.
// NO fuzzing, NO UAF, NO KernelRW y NO uso de selectores de escritura.
typedef uint32_t CService;
typedef CFMutableDictionaryRef (*CMatching)(const char *);
typedef CService (*CGetService)(mach_port_t, CFDictionaryRef);
typedef kern_return_t (*COpen)(CService, task_t, uint32_t, CService *);
typedef kern_return_t (*CClose)(CService);
typedef kern_return_t (*CRelease)(CService);
typedef kern_return_t (*CGetName)(CService, char *);
typedef kern_return_t (*CGetID)(CService, uint64_t *);
typedef kern_return_t (*CMethod)(CService, uint32_t, const uint64_t *, uint32_t,
                                  const void *, size_t, uint64_t *, uint32_t *,
                                  void *, size_t *);
typedef struct {
    CMatching matchClass, matchName;
    CGetService get;
    COpen open;
    CClose close;
    CRelease release;
    CGetName getName, getClass;
    CGetID getID;
    CMethod method;
} ContractIO;

static ContractIO contractLoad(void) {
    ContractIO f = {0};
    void *h = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY|RTLD_LOCAL);
    if (!h) return f;
    f.matchClass = (CMatching)dlsym(h,"IOServiceMatching");
    f.matchName = (CMatching)dlsym(h,"IOServiceNameMatching");
    f.get = (CGetService)dlsym(h,"IOServiceGetMatchingService");
    f.open = (COpen)dlsym(h,"IOServiceOpen");
    f.close = (CClose)dlsym(h,"IOServiceClose");
    f.release = (CRelease)dlsym(h,"IOObjectRelease");
    f.getName = (CGetName)dlsym(h,"IORegistryEntryGetName");
    f.getClass = (CGetName)dlsym(h,"IOObjectGetClass");
    f.getID = (CGetID)dlsym(h,"IORegistryEntryGetRegistryEntryID");
    f.method = (CMethod)dlsym(h,"IOConnectCallMethod");
    return f;
}
static NSString *contractCode(kern_return_t kr) {
    return [NSString stringWithFormat:@"0x%08x",(unsigned int)kr];
}
static NSString *contractBytesHex(const uint8_t *bytes, size_t n) {
    NSMutableString *s = [NSMutableString stringWithCapacity:n*2];
    for (size_t i=0;i<n;i++) [s appendFormat:@"%02x",bytes[i]];
    return s;
}
static NSString *contractBuild(void) {
    char b[128]={0}; size_t n=sizeof(b);
    if (sysctlbyname("kern.osversion",b,&n,NULL,0)!=0) return @"UNAVAILABLE";
    return [NSString stringWithUTF8String:b] ?: @"UNAVAILABLE";
}
static NSString *contractMachine(void) {
    struct utsname u={0}; if(uname(&u)!=0)return @"UNAVAILABLE";
    return [NSString stringWithUTF8String:u.machine] ?: @"UNAVAILABLE";
}

@interface AppleIOKitLabController : UIViewController
@property(atomic, assign) BOOL running;
- (void)log:(NSString *)text;
- (void)saveJSON:(NSDictionary *)payload as:(NSString *)name;
@end

@interface AppleIOKitLabController (IOSurfaceContractProbe)
- (void)contractTapped:(id)sender;
@end

@implementation AppleIOKitLabController (IOSurfaceContractProbe)

- (void)contractTapped:(id)sender {
    if (self.running) { [self log:@"Otra tarea está en curso."]; return; }
    UIAlertController *alert = [UIAlertController
        alertControllerWithTitle:@"Contrato IOSurface (1 consulta)"
        message:@"Primero leerá nombre, clase e ID del servicio. Después llamará UNA sola vez al selector 13 con cero entradas y 40 bytes de salida, como en investigaciones de iOS 27 beta 4. Puede existir riesgo de reinicio por fallo del controlador. No ejecutará fuzzing ni fuerza bruta."
        preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"Cancelar"
         style:UIAlertActionStyleCancel handler:nil]];
    [alert addAction:[UIAlertAction actionWithTitle:@"Comprobar"
         style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        self.running=YES;
        [self log:@"CONTRACT: comparando matching por clase y nombre."];
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED,0), ^{
            ContractIO f=contractLoad();
            if(!f.matchClass || !f.get || !f.open || !f.close || !f.release || !f.method){
                [self log:@"CONTRACT: faltan funciones esenciales IOKit."];
                dispatch_async(dispatch_get_main_queue(),^{self.running=NO;});
                return;
            }
            NSArray<NSString *> *queries=@[@"IOSurfaceRoot",@"IOCoreSurfaceRoot",
                                          @"IOSurfaceRoot",@"IOCoreSurfaceRoot"];
            NSMutableArray *rows=[NSMutableArray new];
            NSString *chosen=nil; BOOL chosenName=NO;
            NSString *classID=nil,*nameID=nil;

            for (NSUInteger i=0; i<queries.count; i++){
                NSString *name=queries[i]; BOOL byName=(i>=2);
                CMatching matching=byName ? f.matchName : f.matchClass;
                NSMutableDictionary *row=[@{
                    @"query":name, @"mode":byName?@"name":@"class",
                    @"matched":@NO, @"openType0":@"N/A"
                } mutableCopy];
                if(!matching){ row[@"note"]=@"matcher not exported";[rows addObject:row];continue; }
                CFMutableDictionaryRef cf=matching(name.UTF8String);
                CService svc=cf?f.get(MACH_PORT_NULL,cf):0;
                if(!svc){[rows addObject:row];continue;}
                row[@"matched"]=@YES;
                char textName[128]={0},textClass[128]={0};
                if(f.getName && f.getName(svc,textName)==KERN_SUCCESS)
                    row[@"actualName"]=[NSString stringWithUTF8String:textName]?:@"";
                if(f.getClass && f.getClass(svc,textClass)==KERN_SUCCESS)
                    row[@"actualClass"]=[NSString stringWithUTF8String:textClass]?:@"";
                uint64_t registryID=0;
                if(f.getID && f.getID(svc,&registryID)==KERN_SUCCESS){
                    NSString *idText=[NSString stringWithFormat:@"%016llx",
                                      (unsigned long long)registryID];
                    row[@"registryIDHex"]=idText;
                    if(i==0)classID=idText;
                    if(i==3)nameID=idText;
                }
                CService cn=0;
                kern_return_t op=f.open(svc,mach_task_self(),0,&cn);
                row[@"openType0"]=contractCode(op);
                if(op==KERN_SUCCESS && cn!=0){
                    if(!chosen){chosen=name;chosenName=byName;}
                    f.close(cn);
                }
                f.release(svc);
                [rows addObject:row];
                [self log:[NSString stringWithFormat:@"CONTRACT: %@ %@ -> class=%@ name=%@ id=%@ open=%@",
                    byName?@"name":@"class",name,row[@"actualClass"]?:@"?",
                    row[@"actualName"]?:@"?",row[@"registryIDHex"]?:@"?",
                    row[@"openType0"]]];
            }
            NSMutableDictionary *report=[@{
                @"schema":@"AppleIOKitLab.contract.v1",
                @"device":contractMachine(), @"iOS":UIDevice.currentDevice.systemVersion,
                @"build":contractBuild(), @"discovery":rows,
                @"selector":@13, @"scalarInputCount":@0, @"structureInputBytes":@0,
                @"scalarOutputCapacity":@0, @"structureOutputCapacity":@40,
                @"reference":@"iOS 27 beta 4 (24A5390f), different build and hardware",
                @"phase":@"DISCOVERY_COMPLETE"
            } mutableCopy];
            report[@"classVsNameSameEntry"]=(classID && nameID)
                ? ([classID isEqualToString:nameID]?@"YES":@"NO") : @"UNKNOWN";
            if(!chosen){
                report[@"phase"]=@"NO_OPENABLE_SERVICE";
                [self saveJSON:report as:@"AppleIOKitLab-contract.json"];
                [self log:@"CONTRACT: ninguna coincidencia accesible."];
                dispatch_async(dispatch_get_main_queue(),^{self.running=NO;});
                return;
            }
            CMatching matching=chosenName?f.matchName:f.matchClass;
            CService svc=f.get(MACH_PORT_NULL,matching(chosen.UTF8String));
            CService cn=0;
            kern_return_t op=svc?f.open(svc,mach_task_self(),0,&cn):KERN_FAILURE;
            if(svc)f.release(svc);
            report[@"selectedQuery"]=chosen;
            report[@"selectedMode"]=chosenName?@"name":@"class";
            report[@"openKR"]=contractCode(op);
            if(op!=KERN_SUCCESS || !cn){
                report[@"phase"]=@"OPEN_FAILED";
                [self saveJSON:report as:@"AppleIOKitLab-contract.json"];
                [self log:[NSString stringWithFormat:@"CONTRACT: apertura falló %@",contractCode(op)]];
                dispatch_async(dispatch_get_main_queue(),^{self.running=NO;});
                return;
            }
            report[@"phase"]=@"IN_FLIGHT";
            [self saveJSON:report as:@"AppleIOKitLab-contract.json"];
            uint8_t output[40]={0};
            uint32_t outScalar=0; size_t outLen=sizeof(output);
            kern_return_t kr=f.method(cn,13,NULL,0,NULL,0,NULL,&outScalar,output,&outLen);
            f.close(cn);
            report[@"phase"]=@"COMPLETED";
            report[@"callKR"]=contractCode(kr);
            report[@"observedExpectedContract"]=@(kr==KERN_SUCCESS && outScalar==0 && outLen==40);
            if(kr==KERN_SUCCESS){
                report[@"outputScalarCount"]=@(outScalar);
                report[@"outputBytesReported"]=@(outLen);
                report[@"outputHex"]=(outLen<=sizeof(output) && outScalar==0)
                    ? contractBytesHex(output,outLen):@"INCONSISTENT_OUTPUT_COUNTS";
            }else{
                report[@"outputHex"]=@"N/A (call failed)";
            }
            [self saveJSON:report as:@"AppleIOKitLab-contract.json"];
            [self log:[NSString stringWithFormat:
                @"CONTRACT: sel13=%@ out=%@ matchSameRegistry=%@",
                contractCode(kr),kr==KERN_SUCCESS
                    ?[NSString stringWithFormat:@"%zu bytes",outLen]:@"N/A",
                report[@"classVsNameSameEntry"]]];
            [self log:@"CONTRACT: éxito solo verifica esta consulta; no implica UAF/KernelRW."];
            dispatch_async(dispatch_get_main_queue(),^{self.running=NO;});
        });
    }]];
    [self presentViewController:alert animated:YES completion:nil];
}
@end
