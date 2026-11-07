#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <CoreFoundation/CoreFoundation.h>
#import <mach/mach.h>
#import <sys/sysctl.h>
#import <sys/utsname.h>
#import <dlfcn.h>
#import <string.h>

// Prueba FUNCIONAL de operaciones del user client contra superficies propias.
// No apunta a memoria del kernel, no usa referencias liberadas y no intenta
// obtener privilegios; un resultado positivo NO equivale a un jailbreak.
typedef uint32_t DirectService;
typedef CFMutableDictionaryRef (*DirectMatching)(const char *);
typedef DirectService (*DirectGetService)(mach_port_t, CFDictionaryRef);
typedef kern_return_t (*DirectOpen)(DirectService, task_t, uint32_t, DirectService *);
typedef kern_return_t (*DirectClose)(DirectService);
typedef kern_return_t (*DirectRelease)(DirectService);
typedef kern_return_t (*DirectMethod)(DirectService, uint32_t, const uint64_t *,
                                     uint32_t, const void *, size_t, uint64_t *,
                                     uint32_t *, void *, size_t *);
typedef CFDataRef (*DirectSerialize)(CFTypeRef, CFOptionFlags);
typedef struct __IOSurface *DirectIOSurfaceRef;
typedef DirectIOSurfaceRef (*DirectSurfaceLookup)(uint32_t);
typedef CFTypeRef (*DirectSurfaceCopyValue)(DirectIOSurfaceRef, CFStringRef);

static NSString *DirectHex(kern_return_t kr) {
    return [NSString stringWithFormat:@"0x%08x", (uint32_t)kr];
}
static void DirectPut32(uint8_t *p, uint32_t v) { memcpy(p, &v, sizeof(v)); }
static uint32_t DirectRead32(const uint8_t *p) { uint32_t v=0; memcpy(&v,p,sizeof(v)); return v; }

static NSString *DirectBuild(void) {
    char b[128]={0}; size_t len=sizeof(b);
    return sysctlbyname("kern.osversion",b,&len,NULL,0)==0
        ? ([NSString stringWithUTF8String:b]?:@"UNAVAILABLE") : @"UNAVAILABLE";
}
static NSString *DirectMachine(void) {
    struct utsname u={0};
    return uname(&u)==0 ? ([NSString stringWithUTF8String:u.machine]?:@"UNAVAILABLE")
                       : @"UNAVAILABLE";
}

@interface AppleIOKitLabController : UIViewController
@property(atomic, assign) BOOL running;
- (void)log:(NSString *)message;
- (void)saveJSON:(NSDictionary *)payload as:(NSString *)name;
@end

@interface AppleIOKitLabController (DirectRoundTrip)
- (void)directRoundTripTapped:(id)sender;
@end

@implementation AppleIOKitLabController (DirectRoundTrip)

- (void)directRoundTripTapped:(id)sender {
    if (self.running) { [self log:@"Ya hay una prueba activa."]; return; }
    NSString *build=DirectBuild(), *device=DirectMachine();
    if (![build isEqualToString:@"24A437"] || ![device isEqualToString:@"iPhone14,3"]) {
        [self log:[NSString stringWithFormat:
          @"PRUEBA DIRECTA: no ejecutada en %@ build %@. Solo se habilita para iPhone14,3/24A437.",
          device, build]];
        return;
    }
    UIAlertController *alert=[UIAlertController
      alertControllerWithTitle:@"Prueba REAL IOSurface"
      message:@"Una sola ejecución: abrir IOSurfaceRoot, crear una superficie propia "
              "por IOKit, buscarla, bloquearla/desbloquearla y escribir/leer "
              "un valor propio. No modifica memoria arbitraria del kernel, "
              "pero una llamada al controlador podría ocasionar reinicio del iPhone. "
              "Guarda tus datos antes de continuar."
      preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"Cancelar"
                              style:UIAlertActionStyleCancel handler:nil]];
    [alert addAction:[UIAlertAction actionWithTitle:@"Ejecutar prueba real"
                              style:UIAlertActionStyleDefault handler:^(UIAlertAction *a) {
        self.running=YES;
        [self log:@"RAW: iniciando una secuencia de operaciones contra IOSurfaceRoot."];
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED,0), ^{
            NSMutableDictionary *r=[@{
                @"schema":@"AppleIOKitLab.directRoundTrip.v1",
                @"device":device, @"build":build, @"iOS":UIDevice.currentDevice.systemVersion,
                @"phase":@"STARTED", @"method":@"IOConnectCallMethod",
                @"testScope":@"owned IOSurface; raw user client selectors; no arbitrary kernel memory",
                @"steps":[NSMutableArray array],
                @"creationConfirmed":@NO, @"lookupConfirmed":@NO,
                @"propertyRoundTripConfirmed":@NO,
                @"kernelRW":@NO
            } mutableCopy];
            NSMutableArray *steps=r[@"steps"];
            __block NSString *current=@"LOAD";
            void (^savePhase)(NSString *)=^(NSString *stage){
                r[@"phase"]=@"IN_FLIGHT";r[@"currentStep"]=stage;
                [self saveJSON:r as:@"AppleIOKitLab-direct-roundtrip.json"];
            };
            void (^finish)(NSString *)=^(NSString *why){
                r[@"phase"]=@"COMPLETED"; r[@"conclusion"]=why;
                [self saveJSON:r as:@"AppleIOKitLab-direct-roundtrip.json"];
                [self log:[@"RAW: " stringByAppendingString:why]];
                dispatch_async(dispatch_get_main_queue(),^{self.running=NO;});
            };

            void *io=dlopen("/System/Library/Frameworks/IOKit.framework/IOKit",
                            RTLD_LAZY|RTLD_LOCAL);
            DirectMatching matching=io?(DirectMatching)dlsym(io,"IOServiceMatching"):NULL;
            DirectGetService get=io?(DirectGetService)dlsym(io,"IOServiceGetMatchingService"):NULL;
            DirectOpen open=io?(DirectOpen)dlsym(io,"IOServiceOpen"):NULL;
            DirectClose close=io?(DirectClose)dlsym(io,"IOServiceClose"):NULL;
            DirectRelease release=io?(DirectRelease)dlsym(io,"IOObjectRelease"):NULL;
            DirectMethod method=io?(DirectMethod)dlsym(io,"IOConnectCallMethod"):NULL;
            DirectSerialize serialize=io?(DirectSerialize)dlsym(io,"IOCFSerialize"):NULL;
            if(!matching || !get || !open || !close || !release || !method){
                finish(@"IOKit no ofrece las funciones necesarias.");
                if(io)dlclose(io);
                return;
            }

            savePhase(@"IOServiceOpen");
            DirectService service=get(MACH_PORT_NULL,matching("IOSurfaceRoot"));
            if(!service){finish(@"No se encontró IOSurfaceRoot.");dlclose(io);return;}
            DirectService cn=0;
            kern_return_t kr=open(service,mach_task_self(),0,&cn);
            release(service);
            [steps addObject:@{@"operation":@"IOServiceOpen/type0",@"kr":DirectHex(kr)}];
            [self saveJSON:r as:@"AppleIOKitLab-direct-roundtrip.json"];
            if(kr!=KERN_SUCCESS || !cn){finish(@"No pudo abrirse cliente IOKit.");dlclose(io);return;}
            [self log:[NSString stringWithFormat:@"RAW: cliente tipo 0 abierto (%@).",DirectHex(kr)]];

            // Forma macOS 27 e iOS 27 beta4; no se asume compatibilidad hasta
            // obtener resultados reales en iPhone14,3/24A437.
            uint8_t fast[32]={0};
            // addr=0; width,height,format,bytesPerElement,bytesPerRow,allocSize.
            DirectPut32(fast+8,64);
            DirectPut32(fast+12,64);
            DirectPut32(fast+16,0x42475241u); // BGRA
            DirectPut32(fast+20,4);
            DirectPut32(fast+24,256);
            DirectPut32(fast+28,16384);
            uint8_t createOut[3176]={0};
            size_t createLen=sizeof(createOut);uint32_t scOut=0;
            savePhase(@"selector6_create");
            kr=method(cn,6,NULL,0,fast,sizeof(fast),NULL,&scOut,createOut,&createLen);
            BOOL created=kr==KERN_SUCCESS && scOut==0 &&
                         createLen==sizeof(createOut);
            uint32_t sid=created ? DirectRead32(createOut+0x18) : 0;
            created=created && sid>0;
            r[@"creationConfirmed"]=@(created);
            if(created) r[@"createdSurfaceID"]=@(sid);
            [steps addObject:@{
                @"operation":@"selector6_create_fast_path",
                @"kr":DirectHex(kr),@"returnedBytes":@(kr==KERN_SUCCESS?createLen:0),
                @"surfaceID":@(sid),@"valid":@(created)
            }];
            [self saveJSON:r as:@"AppleIOKitLab-direct-roundtrip.json"];
            [self log:[NSString stringWithFormat:@"RAW: selector6 create %@; surfaceID=%u.",
                       DirectHex(kr),sid]];
            if(!created) {
                close(cn);finish(@"No se pudo validar creación directa de superficie.");
                dlclose(io);return;
            }

            // Consultar el mismo SID en LA MISMA conexión.
            uint64_t scalarID=sid; uint8_t lookupOut[3176]={0};
            size_t lookupLen=sizeof(lookupOut);scOut=0;
            savePhase(@"selector4_lookup");
            kr=method(cn,4,&scalarID,1,NULL,0,NULL,&scOut,lookupOut,&lookupLen);
            BOOL looked=kr==KERN_SUCCESS && scOut==0 &&
                        lookupLen==sizeof(lookupOut) &&
                        DirectRead32(lookupOut+0x18)==sid;
            r[@"lookupConfirmed"]=@(looked);
            [steps addObject:@{@"operation":@"selector4_lookup_same_connection",
                               @"kr":DirectHex(kr),@"valid":@(looked)}];
            [self saveJSON:r as:@"AppleIOKitLab-direct-roundtrip.json"];
            [self log:[NSString stringWithFormat:@"RAW: selector4 lookup %@; SID coincide=%@",
                       DirectHex(kr),looked?@"YES":@"NO"]];

            // Lock/unlock, solo de la superficie que acabamos de crear.
            uint8_t lockArg[12]={0}; DirectPut32(lockArg,sid);
            uint8_t lockOut[3176]={0};size_t lockLen=sizeof(lockOut);scOut=0;
            savePhase(@"selector2_lock");
            kr=method(cn,2,NULL,0,lockArg,sizeof(lockArg),NULL,&scOut,lockOut,&lockLen);
            BOOL locked=kr==KERN_SUCCESS && scOut==0 &&
                        lockLen==sizeof(lockOut) &&
                        DirectRead32(lockOut+0x18)==sid;
            [steps addObject:@{@"operation":@"selector2_lock",
                               @"kr":DirectHex(kr),@"valid":@(locked)}];
            [self saveJSON:r as:@"AppleIOKitLab-direct-roundtrip.json"];
            if(kr==KERN_SUCCESS){
                uint32_t seed=0;size_t uLen=sizeof(seed);scOut=0;
                savePhase(@"selector3_unlock");
                kern_return_t ukr=method(cn,3,NULL,0,lockArg,sizeof(lockArg),
                                         NULL,&scOut,&seed,&uLen);
                BOOL unlocked=ukr==KERN_SUCCESS && uLen==4 && scOut==0;
                [steps addObject:@{@"operation":@"selector3_unlock",
                                   @"kr":DirectHex(ukr),@"valid":@(unlocked)}];
                r[@"lockUnlockConfirmed"]=@(locked && unlocked);
                [self saveJSON:r as:@"AppleIOKitLab-direct-roundtrip.json"];
            }else r[@"lockUnlockConfirmed"]=@NO;

            // Escribir y leer un valor en nuestra propia superficie (no memoria kernel arbitraria).
            NSString *key=@"LAB_OWN_VALUE";
            NSString *value=[@"IOKIT-" stringByAppendingString:NSUUID.UUID.UUIDString];
            if(serialize){
                CFDataRef cf=serialize((__bridge CFTypeRef)@[value,key],1);
                if(cf && CFDataGetLength(cf)>0 && CFDataGetLength(cf)<=1024){
                    size_t plen=(size_t)CFDataGetLength(cf);
                    NSMutableData *payload=[NSMutableData dataWithLength:12+plen];
                    uint8_t *in=payload.mutableBytes;
                    DirectPut32(in,sid);
                    memcpy(in+12,CFDataGetBytePtr(cf),plen);
                    uint32_t token=0;size_t tokenLen=sizeof(token);scOut=0;
                    savePhase(@"selector9_set_value");
                    kr=method(cn,9,NULL,0,in,payload.length,
                              NULL,&scOut,&token,&tokenLen);
                    BOOL written=(kr==KERN_SUCCESS && tokenLen==4 && scOut==0);
                    r[@"propertyWriteConfirmed"]=@(written);
                    [steps addObject:@{@"operation":@"selector9_set_own_value",
                                       @"kr":DirectHex(kr),@"valid":@(written)}];
                    [self saveJSON:r as:@"AppleIOKitLab-direct-roundtrip.json"];

                    if(written){
                        NSData *kb=[key dataUsingEncoding:NSUTF8StringEncoding];
                        NSMutableData *query=[NSMutableData dataWithLength:12+kb.length+1];
                        DirectPut32(query.mutableBytes,sid);
                        memcpy((uint8_t*)query.mutableBytes+12,kb.bytes,kb.length);
                        uint8_t answer[2048]={0};size_t answerLen=sizeof(answer);scOut=0;
                        savePhase(@"selector10_get_value");
                        kern_return_t gkr=method(cn,10,NULL,0,query.bytes,query.length,
                                                NULL,&scOut,answer,&answerLen);
                        BOOL readBack=gkr==KERN_SUCCESS && answerLen>12 &&
                                      answerLen<=sizeof(answer) && scOut==0;
                        r[@"propertyReadConfirmed"]=@(readBack);
                        [steps addObject:@{@"operation":@"selector10_get_own_value",
                                           @"kr":DirectHex(gkr),
                                           @"returnedBytes":@(readBack?answerLen:0),
                                           @"valid":@(readBack)}];
                        [self saveJSON:r as:@"AppleIOKitLab-direct-roundtrip.json"];

                        // Comprobación de valor exacto por una segunda API (si el
                        // ownership permite hacer lookup desde IOSurface.framework).
                        void *surf=dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface",
                                          RTLD_LAZY|RTLD_LOCAL);
                        DirectSurfaceLookup look=surf?(DirectSurfaceLookup)dlsym(surf,"IOSurfaceLookup"):NULL;
                        DirectSurfaceCopyValue copy=surf?(DirectSurfaceCopyValue)dlsym(surf,"IOSurfaceCopyValue"):NULL;
                        BOOL equal=NO;
                        if(look && copy){
                            DirectIOSurfaceRef owned=look(sid);
                            if(owned){
                                CFTypeRef copied=copy(owned,(__bridge CFStringRef)key);
                                if(copied && CFGetTypeID(copied)==CFStringGetTypeID()){
                                    equal=[(__bridge NSString *)copied isEqualToString:value];
                                }
                                if(copied)CFRelease(copied);
                                CFRelease(owned);
                            }
                        }
                        if(surf)dlclose(surf);
                        r[@"publicCopyValueMatches"] = @(equal);
                        r[@"propertyRoundTripConfirmed"] = @(written && readBack && equal);
                        [steps addObject:@{@"operation":@"IOSurfaceCopyValue_cross_check",
                                           @"valid":@(equal)}];
                        [self saveJSON:r as:@"AppleIOKitLab-direct-roundtrip.json"];
                    }
                }else{
                    [steps addObject:@{@"operation":@"IOCFSerialize",
                                       @"status":@"not available or invalid data"}];
                }
                if(cf)CFRelease(cf);
            }else{
                [steps addObject:@{@"operation":@"IOCFSerialize",@"status":@"not exported"}];
            }
            // Cerrar el user client; no llamamos a métodos con IDs caducados.
            savePhase(@"IOServiceClose");
            kern_return_t closeKr=close(cn);
            [steps addObject:@{@"operation":@"IOServiceClose",@"kr":DirectHex(closeKr)}];
            [self saveJSON:r as:@"AppleIOKitLab-direct-roundtrip.json"];
            [self log:[NSString stringWithFormat:
                @"RAW: creación=%@ lookup=%@ propiedad=%@ cierre=%@",
                created?@"OK":@"NO",looked?@"OK":@"NO",
                [r[@"propertyRoundTripConfirmed"] boolValue]?@"OK":@"NO",
                DirectHex(closeKr)]];
            if([r[@"propertyRoundTripConfirmed"] boolValue]){
                finish(@"PASS: creada superficie y valor propio leído de vuelta por ruta independiente.");
            }else if(created && looked){
                finish(@"PARCIAL: creación y lookup reales; escritura/lectura requiere revisión.");
            }else{
                finish(@"PARCIAL: creación real; lookup o contrato de salida no confirmado.");
            }
            dlclose(io);
        });
    }]];
    [self presentViewController:alert animated:YES completion:nil];
}
@end
