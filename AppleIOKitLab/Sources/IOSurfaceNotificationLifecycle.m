#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <CoreFoundation/CoreFoundation.h>
#import <mach/mach.h>
#import <mach/message.h>
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

// Una recepción, acotada por timeout. No desciframos payloads, datos ni punteros
// de mensajes potencialmente enviados por el controlador. Solo metadatos.
static NSDictionary *NotifyReceiveOnce(mach_port_t port, mach_msg_timeout_t timeoutMs) {
    union {
        mach_msg_header_t header;
        uint8_t bytes[2048];
    } buffer = {0};
    kern_return_t rc = mach_msg(&buffer.header,
                               MACH_RCV_MSG | MACH_RCV_TIMEOUT | MACH_RCV_LARGE,
                               0, (mach_msg_size_t)sizeof(buffer.bytes),
                               port, timeoutMs, MACH_PORT_NULL);
    NSMutableDictionary *result = [@{
        @"returnCode":NotifyError(rc),
        @"timeoutMs":@(timeoutMs),
        @"messageReceived":@(rc==MACH_MSG_SUCCESS),
        @"time":NotifyTime()
    } mutableCopy];
    if (rc==MACH_MSG_SUCCESS) {
        BOOL valid = buffer.header.msgh_size>=sizeof(mach_msg_header_t) &&
                     buffer.header.msgh_size<=sizeof(buffer.bytes);
        result[@"headerValid"]=@(valid);
        result[@"messageID"]=@(buffer.header.msgh_id);
        result[@"messageBytes"]=@(buffer.header.msgh_size);
        result[@"messageOriginVerified"]=@NO;
        // Descartar derechos Mach recibidos sin registrarlos ni transferirlos.
        mach_msg_destroy(&buffer.header);
    } else if(rc==MACH_RCV_TIMED_OUT) {
        result[@"status"]=@"TIMED_OUT";
    } else if(rc==MACH_RCV_TOO_LARGE) {
        result[@"status"]=@"MESSAGE_TOO_LARGE";
    } else {
        result[@"status"]=@"RECEIVE_ERROR";
    }
    return result;
}

typedef struct __IOSurface *NotifySurfaceRef;
typedef NotifySurfaceRef (*NotifyLookupSurface)(uint32_t);
typedef void (*NotifyAdjustUseCount)(NotifySurfaceRef);
typedef int32_t (*NotifyGetUseCount)(NotifySurfaceRef);

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
       alertControllerWithTitle:@"IOSurface: recibir notificación Mach"
       message:@"Crea UNA superficie propia, registra UNA notificación asíncrona, "
               "espera un mensaje Mach con límite temporal y, si la API pública "
               "puede recuperar la superficie, hace UN incremento y decremento "
               "de su contador de uso. Luego retira la notificación y cierra "
               "todo en orden. No ejecuta carreras ni corrupción deliberada. "
               "La recepción de un mensaje no verifica su origen ni demuestra "
               "una vulnerabilidad. Las llamadas IOKit pueden provocar reinicios. "
               "Guarda tus datos antes de ejecutar."
       preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"Cancelar"
                         style:UIAlertActionStyleCancel handler:nil]];
    [alert addAction:[UIAlertAction actionWithTitle:@"Ejecutar una vez"
                         style:UIAlertActionStyleDefault handler:^(UIAlertAction *a) {
        self.running=YES;
        [self log:@"NOTIFY v1.6: registro, transición propia y recepción Mach con timeout."];
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED,0), ^{
            NSMutableArray *steps=[NSMutableArray new];
            NSMutableDictionary *report=[@{
               @"schema":@"AppleIOKitLab.notificationDelivery.v1",
               @"phase":@"STARTED",
               @"device":device,@"build":build,
               @"ios":UIDevice.currentDevice.systemVersion,
               @"scope":@"single-thread notification registration, bounded Mach receive and one documented use-count transition",
               @"contractReference":@"24A437 60-selector dispatch; sel17 async struct24; sel18 struct24",
               @"attemptedRace":@NO,
               @"kernelMemoryCorruptionProven":@NO,
               @"kernelRW":@NO,
               @"registrationAttempted":@NO,
               @"registrationAccepted":@NO,
               @"removalAttempted":@NO,
               @"removalAccepted":@NO,
               @"messageDeliveryObserved":@NO,
               @"notificationOriginVerified":@NO,
               @"usageTransitionPerformed":@NO,
               @"receiveWindowMilliseconds":@1500,
               @"receivedMessages":[NSMutableArray new],
               @"steps":steps
            } mutableCopy];
            NSString *filename=@"AppleIOKitLab-notification-delivery.json";
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
            if(kr==KERN_SUCCESS) {
                NSMutableArray *receipts=report[@"receivedMessages"];
                checkpoint(@"receive_immediate_100ms");
                NSDictionary *immediate=NotifyReceiveOnce(wake,100);
                [receipts addObject:@{@"stage":@"immediate_after_registration",
                                      @"result":immediate}];
                BOOL received=[immediate[@"messageReceived"] boolValue];

                // Estímulo documentado SOLO sobre nuestra superficie. No se
                // invocan selectores del kernel en paralelo ni IDs ajenos.
                void *surfaceFramework=dlopen(
                    "/System/Library/Frameworks/IOSurface.framework/IOSurface",
                    RTLD_LAZY|RTLD_LOCAL);
                NotifyLookupSurface lookup=surfaceFramework
                    ? (NotifyLookupSurface)dlsym(surfaceFramework,"IOSurfaceLookup") : NULL;
                NotifyAdjustUseCount increment=surfaceFramework
                    ? (NotifyAdjustUseCount)dlsym(surfaceFramework,"IOSurfaceIncrementUseCount") : NULL;
                NotifyAdjustUseCount decrement=surfaceFramework
                    ? (NotifyAdjustUseCount)dlsym(surfaceFramework,"IOSurfaceDecrementUseCount") : NULL;
                NotifyGetUseCount getCount=surfaceFramework
                    ? (NotifyGetUseCount)dlsym(surfaceFramework,"IOSurfaceGetUseCount") : NULL;
                report[@"usageAPIAvailable"]=@(lookup && increment && decrement && getCount);
                if(lookup && increment && decrement && getCount) {
                    checkpoint(@"IOSurfaceLookup_owned");
                    NotifySurfaceRef own=lookup(sid);
                    report[@"publicSurfaceLookupSucceeded"]=@(own!=NULL);
                    if(own) {
                        int32_t before=getCount(own);
                        report[@"useCountBefore"]=@(before);
                        if(before>=0 && before<INT32_MAX) {
                            checkpoint(@"use_count_increment_once");
                            increment(own);
                            int32_t during=getCount(own);
                            report[@"useCountAfterIncrement"]=@(during);
                            [steps addObject:@{@"step":@"IOSurfaceIncrementUseCount",
                                               @"countBefore":@(before),
                                               @"countAfter":@(during),
                                               @"time":NotifyTime()}];
                            checkpoint(@"receive_after_increment_200ms");
                            NSDictionary *incReply=NotifyReceiveOnce(wake,200);
                            [receipts addObject:@{@"stage":@"after_increment",
                                                  @"result":incReply}];
                            received=received || [incReply[@"messageReceived"] boolValue];

                            checkpoint(@"use_count_decrement_once");
                            decrement(own);
                            int32_t after=getCount(own);
                            report[@"useCountAfterDecrement"]=@(after);
                            report[@"usageTransitionPerformed"]=@YES;
                            report[@"usageCountRestored"]=@(after==before);
                            [steps addObject:@{@"step":@"IOSurfaceDecrementUseCount",
                                               @"countAfter":@(after),
                                               @"time":NotifyTime()}];
                            checkpoint(@"receive_after_decrement_1200ms");
                            NSDictionary *decReply=NotifyReceiveOnce(wake,1200);
                            [receipts addObject:@{@"stage":@"after_decrement",
                                                  @"result":decReply}];
                            received=received || [decReply[@"messageReceived"] boolValue];
                        } else {
                            report[@"usageTransitionSkipReason"]=@"UNEXPECTED_INITIAL_USECOUNT";
                        }
                        CFRelease(own);
                    } else {
                        report[@"usageTransitionSkipReason"]=@"PUBLIC_LOOKUP_FAILED";
                    }
                } else {
                    report[@"usageTransitionSkipReason"]=@"PUBLIC_API_SYMBOLS_UNAVAILABLE";
                }
                if(surfaceFramework)dlclose(surfaceFramework);
                report[@"messageDeliveryObserved"]=@(received);
                report[@"notificationOriginVerified"]=@NO;
                report[@"deliveryInterpretation"]=received
                    ? @"Message received on the dedicated registered port; origin and payload semantics unverified."
                    : @"No message observed within bounded windows; does not prove notification is impossible.";
                [self saveJSON:report as:filename];
                [self log:[NSString stringWithFormat:
                    @"NOTIFY: mensaje en puerto=%@; uso propio restaurado=%@.",
                    received?@"SÍ":@"NO",
                    [report[@"usageCountRestored"] boolValue]?@"SÍ":@"NO"]];
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
            if([report[@"registrationAccepted"] boolValue]) {
                BOOL received=[report[@"messageDeliveryObserved"] boolValue];
                BOOL stimulated=[report[@"usageTransitionPerformed"] boolValue];
                verdict=received ? @"MESSAGE_ON_REGISTERED_PORT_ORIGIN_UNVERIFIED"
                    : (stimulated ? @"NO_CALLBACK_OBSERVED_AFTER_USECOUNT_TRANSITION"
                                  : @"NO_CALLBACK_OBSERVED_WITHOUT_STIMULUS");
                if(![report[@"removalAccepted"] boolValue])
                    report[@"cleanupWarning"]=@"NOTIFICATION_REMOVAL_REJECTED";
            }
            if(done!=KERN_SUCCESS)verdict=@"SERVICE_CLOSE_ERROR_NO_RACE";
            finish(verdict);
            dlclose(library);
        });
    }]];
    [self presentViewController:alert animated:YES completion:nil];
}
@end
