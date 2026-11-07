#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <CoreFoundation/CoreFoundation.h>
#import <mach/mach.h>
#import <sys/sysctl.h>
#import <sys/utsname.h>
#import <dlfcn.h>
#import <stdint.h>
#import <string.h>

// One-shot notification lifecycle inspection for iPhone14,3 / 24A437.
// No concurrent callers, repeated registrations, stale ports, heap sprays,
// forced release races, or attempts to access arbitrary kernel memory.
typedef uint32_t NotifyIOService;
typedef CFMutableDictionaryRef (*NotifyMatching)(const char *);
typedef NotifyIOService (*NotifyGet)(mach_port_t, CFDictionaryRef);
typedef kern_return_t (*NotifyOpen)(NotifyIOService, task_t, uint32_t, NotifyIOService *);
typedef kern_return_t (*NotifyClose)(NotifyIOService);
typedef kern_return_t (*NotifyRelease)(NotifyIOService);
typedef kern_return_t (*NotifyCall)(NotifyIOService, uint32_t,
                                    const uint64_t *, uint32_t, const void *, size_t,
                                    uint64_t *, uint32_t *, void *, size_t *);
typedef kern_return_t (*NotifyAsyncCall)(NotifyIOService, uint32_t, mach_port_t,
                                         uint64_t *, uint32_t,
                                         const uint64_t *, uint32_t,
                                         const void *, size_t,
                                         uint64_t *, uint32_t *, void *, size_t *);

static NSString *NotifyError(kern_return_t r) {
    return [NSString stringWithFormat:@"0x%08x",(unsigned int)r];
}
static NSString *NotifyBuild(void) {
    char b[128]={0}; size_t len=sizeof(b);
    if(sysctlbyname("kern.osversion",b,&len,NULL,0)!=0)return @"UNAVAILABLE";
    return [NSString stringWithUTF8String:b]?:@"UNAVAILABLE";
}
static NSString *NotifyMachine(void) {
    struct utsname u={0};
    if(uname(&u)!=0)return @"UNAVAILABLE";
    return [NSString stringWithUTF8String:u.machine]?:@"UNAVAILABLE";
}
static NSNumber *NotifyTime(void) { return @([[NSDate date] timeIntervalSince1970]); }

@interface AppleIOKitLabController : UIViewController
@property(atomic,assign) BOOL running;
- (void)log:(NSString *)message;
- (void)saveJSON:(NSDictionary *)payload as:(NSString *)name;
@end

@interface AppleIOKitLabController (NotificationLifecycle)
- (void)notificationLifecycleTapped:(id)sender;
@end

@implementation AppleIOKitLabController (NotificationLifecycle)

- (void)notificationLifecycleTapped:(id)sender {
    if (self.running) { [self log:@"Otra prueba sigue en curso."]; return; }
    NSString *build=NotifyBuild(), *device=NotifyMachine();
    if(![build isEqualToString:@"24A437"] ||
       ![device isEqualToString:@"iPhone14,3"]) {
        [self log:[NSString stringWithFormat:
            @"NOTIFY: bloqueado para %@/%@; objetivo iPhone14,3/24A437.",
            device,build]];
        return;
    }
    UIAlertController *alert=[UIAlertController
       alertControllerWithTitle:@"IOSurface: notificación y cierre"
       message:@"Prueba real de contrato: crea UNA superficie propia, registra UNA "
               "notificación asíncrona con selector 17, intenta retirarla con "
               "selector 18 y cierra la conexión DESPUÉS de terminar las llamadas. "
               "No provoca carreras ni corrupción deliberada. El formato interno "
               "de los 24 bytes no está confirmado para todos los campos. Una "
               "llamada al controlador podría causar un kernel panic o reinicio. "
               "Guarda tus datos antes de ejecutar."
       preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"Cancelar"
                         style:UIAlertActionStyleCancel handler:nil]];
    [alert addAction:[UIAlertAction actionWithTitle:@"Ejecutar una vez"
                         style:UIAlertActionStyleDefault handler:^(UIAlertAction *a) {
        self.running=YES;
        [self log:@"NOTIFY: creando superficie y comprobando registro/retirada secuenciales."];
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED,0), ^{
            NSMutableArray *steps=[NSMutableArray new];
            NSMutableDictionary *report=[@{
               @"schema":@"AppleIOKitLab.notificationLifecycle.v1",
               @"phase":@"STARTED",
               @"device":device,@"build":build,
               @"ios":UIDevice.currentDevice.systemVersion,
               @"scope":@"sequential user-client notification lifecycle",
               @"contractReference":@"24A437 60-selector dispatch; sel17 async struct24; sel18 struct24",
               @"attemptedRace":@NO,
               @"kernelMemoryCorruptionProven":@NO,
               @"kernelRW":@NO,
               @"registrationAttempted":@NO,
               @"registrationAccepted":@NO,
               @"removalAttempted":@NO,
               @"removalAccepted":@NO,
               @"steps":steps
            } mutableCopy];
            NSString *filename=@"AppleIOKitLab-notification-lifecycle.json";
            void (^checkpoint)(NSString *)=^(NSString *step){
                report[@"phase"]=@"IN_FLIGHT";
                report[@"currentStep"]=step;
                report[@"updatedAtUnix"]=NotifyTime();
                [self saveJSON:report as:filename];
            };
            void (^finish)(NSString *)=^(NSString *verdict){
                report[@"phase"]=@"COMPLETED";
                report[@"verdict"]=verdict;
                report[@"finishedAtUnix"]=NotifyTime();
                [self saveJSON:report as:filename];
                [self log:[NSString stringWithFormat:@"NOTIFY: %@",verdict]];
                dispatch_async(dispatch_get_main_queue(),^{self.running=NO;});
            };
            checkpoint(@"load_iokit");
            void *library=dlopen("/System/Library/Frameworks/IOKit.framework/IOKit",
                                 RTLD_LAZY|RTLD_LOCAL);
            NotifyMatching match=library?(NotifyMatching)dlsym(library,"IOServiceMatching"):NULL;
            NotifyGet get=library?(NotifyGet)dlsym(library,"IOServiceGetMatchingService"):NULL;
            NotifyOpen open=library?(NotifyOpen)dlsym(library,"IOServiceOpen"):NULL;
            NotifyClose close=library?(NotifyClose)dlsym(library,"IOServiceClose"):NULL;
            NotifyRelease release=library?(NotifyRelease)dlsym(library,"IOObjectRelease"):NULL;
            NotifyCall method=library?(NotifyCall)dlsym(library,"IOConnectCallMethod"):NULL;
            NotifyAsyncCall async=library?(NotifyAsyncCall)dlsym(library,"IOConnectCallAsyncMethod"):NULL;
            report[@"asyncSymbolPresent"]=@(async!=NULL);
            if(!match || !get || !open || !close || !release || !method || !async){
                finish(@"UNAVAILABLE_IOKIT_SYMBOL");
                if(library)dlclose(library);
                return;
            }
            NotifyIOService svc=get(MACH_PORT_NULL,match("IOSurfaceRoot"));
            if(!svc){finish(@"NO_IOSURFACE_SERVICE");dlclose(library);return;}
            NotifyIOService cn=MACH_PORT_NULL;
            checkpoint(@"IOServiceOpen");
            kern_return_t kr=open(svc,mach_task_self(),0,&cn);
            release(svc);
            [steps addObject:@{@"step":@"IOServiceOpen",
                               @"returnCode":NotifyError(kr),
                               @"time":NotifyTime()}];
            [self saveJSON:report as:filename];
            if(kr!=KERN_SUCCESS || cn==MACH_PORT_NULL){
                finish(@"OPEN_REJECTED");dlclose(library);return;
            }
            // One owned 64x64 BGRA surface, known working on this exact build.
            uint8_t createArgs[32]={0};
            const uint32_t args[]={64,64,0x42475241u,4,256,16384};
            memcpy(createArgs+8,args,sizeof(args));
            uint8_t createResult[3176]={0};
            size_t resultSize=sizeof(createResult);uint32_t scalarCount=0;
            checkpoint(@"selector6_create");
            kr=method(cn,6,NULL,0,createArgs,sizeof(createArgs),
                      NULL,&scalarCount,createResult,&resultSize);
            uint32_t sid=0;
            if(kr==KERN_SUCCESS && scalarCount==0 && resultSize==sizeof(createResult))
                memcpy(&sid,createResult+0x18,sizeof(sid));
            report[@"surfaceID"]=@(sid);
            [steps addObject:@{@"step":@"selector6_create",
                               @"returnCode":NotifyError(kr),
                               @"surfaceID":@(sid),
                               @"returnedBytes":@(kr==KERN_SUCCESS?resultSize:0),
                               @"time":NotifyTime()}];
            [self saveJSON:report as:filename];
            if(kr!=KERN_SUCCESS || sid==0){
                checkpoint(@"IOServiceClose_after_create_failure");
                kern_return_t ck=close(cn);
                [steps addObject:@{@"step":@"IOServiceClose",@"returnCode":NotifyError(ck),
                                   @"time":NotifyTime()}];
                finish(@"CREATE_FAILED");dlclose(library);return;
            }
            [self log:[NSString stringWithFormat:@"NOTIFY: superficie propia %u creada.",sid]];
            mach_port_t wake=MACH_PORT_NULL;
            checkpoint(@"mach_port_allocate");
            kern_return_t mk=mach_port_allocate(mach_task_self(),MACH_PORT_RIGHT_RECEIVE,&wake);
            if(mk!=KERN_SUCCESS){
                report[@"portSetupKR"]=NotifyError(mk);
                checkpoint(@"IOServiceClose_after_port_failure");
                close(cn);finish(@"PORT_ALLOCATION_FAILED");dlclose(library);return;
            }
            kern_return_t ins=mach_port_insert_right(mach_task_self(),wake,wake,
                                                    MACH_MSG_TYPE_MAKE_SEND);
            report[@"portSetupKR"]=NotifyError(ins);
            if(ins!=KERN_SUCCESS){
                mach_port_destroy(mach_task_self(),wake);
                checkpoint(@"IOServiceClose_after_sendright_failure");
                close(cn);finish(@"PORT_SEND_RIGHT_FAILED");dlclose(library);return;
            }
            [steps addObject:@{@"step":@"mach_port_setup",
                               @"returnCode":NotifyError(ins),@"time":NotifyTime()}];

            // Struct size has been extracted from the 24A437 dispatch table.
            // Field semantics are NOT established. Provide the owned SID,
            // and zero every other field. Do not reuse a stale ID/port.
            uint64_t notifyArgs[3]={sid,0,0};
            uint64_t reference[1]={0};
            report[@"selector17StructureBytes"]=@24;
            report[@"selector17ArgumentFormat"]=@"u64 own SID, u64 zero, u64 zero (hypothesis)";
            report[@"selector17ReferenceCount"]=@1;
            checkpoint(@"selector17_register");
            report[@"registrationAttempted"]=@YES;
            [self saveJSON:report as:filename];
            kr=async(cn,17,wake,reference,1,
                     NULL,0,notifyArgs,sizeof(notifyArgs),
                     NULL,NULL,NULL,NULL);
            report[@"registerKR"]=NotifyError(kr);
            report[@"registrationAccepted"]=@(kr==KERN_SUCCESS);
            [steps addObject:@{@"step":@"selector17_async_register",
                               @"returnCode":NotifyError(kr),@"time":NotifyTime()}];
            [self saveJSON:report as:filename];
            [self log:[NSString stringWithFormat:@"NOTIFY: selector17 %@.",NotifyError(kr)]];
            if(kr==KERN_SUCCESS){
                checkpoint(@"selector18_remove");
                report[@"removalAttempted"]=@YES;
                [self saveJSON:report as:filename];
                kern_return_t rm=method(cn,18,NULL,0,notifyArgs,sizeof(notifyArgs),
                                        NULL,NULL,NULL,NULL);
                report[@"removeKR"]=NotifyError(rm);
                report[@"removalAccepted"]=@(rm==KERN_SUCCESS);
                [steps addObject:@{@"step":@"selector18_remove",
                                   @"returnCode":NotifyError(rm),@"time":NotifyTime()}];
                [self saveJSON:report as:filename];
                [self log:[NSString stringWithFormat:@"NOTIFY: selector18 %@.",NotifyError(rm)]];
            }
            // No user-originated call overlaps another. Close before destroying port.
            checkpoint(@"IOServiceClose");
            kern_return_t done=close(cn);
            report[@"closeKR"]=NotifyError(done);
            [steps addObject:@{@"step":@"IOServiceClose",
                               @"returnCode":NotifyError(done),@"time":NotifyTime()}];
            checkpoint(@"mach_port_destroy_after_close");
            kern_return_t drop=mach_port_destroy(mach_task_self(),wake);
            report[@"machPortDestroyKR"]=NotifyError(drop);
            [steps addObject:@{@"step":@"mach_port_destroy",
                               @"returnCode":NotifyError(drop),@"time":NotifyTime()}];
            NSString *verdict=@"REGISTER_REJECTED_NO_RACE";
            if([report[@"registrationAccepted"] boolValue])
                verdict=[report[@"removalAccepted"] boolValue]
                    ? @"SEQUENTIAL_NOTIFY_LIFECYCLE_ACCEPTED_NO_RACE"
                    : @"REGISTER_OK_REMOVE_REJECTED_NO_RACE";
            if(done!=KERN_SUCCESS)verdict=@"SERVICE_CLOSE_ERROR_NO_RACE";
            finish(verdict);
            dlclose(library);
        });
    }]];
    [self presentViewController:alert animated:YES completion:nil];
}
@end
