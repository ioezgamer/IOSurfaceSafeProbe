#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <Metal/Metal.h>
#import <sys/sysctl.h>
#import <sys/utsname.h>
#import <stdint.h>
#import <string.h>

// Controlled GPU user-space experiment: all buffers belong to this process.
// No IOSurface F1 input, no private IOKit methods, no guessed device VA,
// no access to other processes, no kernel-memory attempt.
static NSString *GPUBuild(void) {
    char b[128]={0}; size_t n=sizeof(b);
    if(sysctlbyname("kern.osversion",b,&n,NULL,0)!=0) return @"UNAVAILABLE";
    return [NSString stringWithUTF8String:b] ?: @"UNAVAILABLE";
}
static NSString *GPUDeviceModel(void) {
    struct utsname u={0};
    if(uname(&u)!=0)return @"UNAVAILABLE";
    return [NSString stringWithUTF8String:u.machine] ?: @"UNAVAILABLE";
}
static NSNumber *GPUTime(void) { return @([[NSDate date] timeIntervalSince1970]); }
static NSString *GPUAddressHex(uint64_t addr) {
    return [NSString stringWithFormat:@"0x%016llx",(unsigned long long)addr];
}
static NSString *GPUValueHex(uint32_t v) {
    return [NSString stringWithFormat:@"0x%08x",(unsigned)v];
}

@interface AppleIOKitLabController : UIViewController
@property(atomic,assign) BOOL running;
- (void)log:(NSString *)message;
- (void)saveJSON:(NSDictionary *)payload as:(NSString *)name;
@end

@interface AppleIOKitLabController (GPUOwnedBuffer)
- (void)gpuOwnedBufferTapped:(id)sender;
@end

@implementation AppleIOKitLabController (GPUOwnedBuffer)

- (void)gpuOwnedBufferTapped:(id)sender {
    if(self.running){[self log:@"Ya hay otra prueba activa."];return;}
    NSString *model=GPUDeviceModel(),*build=GPUBuild();
    if(![model isEqualToString:@"iPhone14,3"] ||
       ![build isEqualToString:@"24A437"]) {
        [self log:[NSString stringWithFormat:
            @"GPU: solo permitido en iPhone14,3/24A437; detectado %@/%@",model,build]];
        return;
    }
    UIAlertController *alert=[UIAlertController
      alertControllerWithTitle:@"GPU: lectura y escritura entre búferes propios"
      message:@"Demostración real de Metal en el contexto GPU de ESTA aplicación. "
              "Se crean dos búferes propios de 64 KiB. Primero se confirma una "
              "escritura normal, luego se intenta leer un valor preexistente y "
              "escribir otro a través de la dirección GPU del segundo búfer. "
              "Cada resultado se comprueba desde CPU. Sin IOSurface F1, sin "
              "memoria de terceros ni privilegios kernel. "
              "Una operación GPU fuera de límites puede fallar o reiniciar "
              "el teléfono; guarda tus datos antes de ejecutar."
      preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"Cancelar"
         style:UIAlertActionStyleCancel handler:nil]];
    [alert addAction:[UIAlertAction actionWithTitle:@"Ejecutar una vez"
         style:UIAlertActionStyleDefault handler:^(UIAlertAction *a) {
        self.running=YES;
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED,0), ^{
            NSMutableDictionary *report=[@{
               @"schema":@"AppleIOKitLab.gpuOwnedBuffer.v1",
               @"device":model,@"build":build,
               @"ios":UIDevice.currentDevice.systemVersion,
               @"phase":@"STARTED",
               @"scope":@"same application GPU context; no IOSurface F1",
               @"gpuCrossObjectWriteVerified":@NO,
               @"gpuCrossObjectReadVerified":@NO,
               @"gpuReadPreexistingValueVerified":@NO,
               @"kernelMemoryAccessProven":@NO,
               @"kernelRW":@NO,@"jailbreak":@NO,
               @"wasF1Used":@NO
            } mutableCopy];
            NSString *output=@"AppleIOKitLab-gpu-owned-buffer.json";
            void (^checkpoint)(NSString *)=^(NSString *step){
                report[@"phase"]=@"IN_FLIGHT";
                report[@"currentStep"]=step;
                report[@"timestamp"]=GPUTime();
                [self saveJSON:report as:output];
            };
            void (^finish)(NSString *)=^(NSString *verdict){
                report[@"phase"]=@"COMPLETED";
                report[@"verdict"]=verdict;
                report[@"finishedAt"]=GPUTime();
                [self saveJSON:report as:output];
                [self log:[NSString stringWithFormat:@"GPU LAB: %@",verdict]];
                dispatch_async(dispatch_get_main_queue(),^{ self.running=NO; });
            };
            checkpoint(@"create_metal_device");
            id<MTLDevice> dev=MTLCreateSystemDefaultDevice();
            if(!dev){ finish(@"NO_METAL_DEVICE"); return; }
            report[@"gpuName"]=dev.name ?: @"UNKNOWN";
            id<MTLCommandQueue> queue=[dev newCommandQueue];
            NSError *err=nil;
            id<MTLLibrary> library=[dev newDefaultLibrary];
            if(!queue||!library){
                report[@"libraryPresent"]=@(library!=nil);
                finish(@"COMMAND_QUEUE_OR_METAL_LIBRARY_MISSING");return;
            }
            id<MTLFunction> warm=[library newFunctionWithName:@"gpu_owned_warm"];
            id<MTLFunction> rd=[library newFunctionWithName:@"gpu_owned_cross_read"];
            id<MTLFunction> wr=[library newFunctionWithName:@"gpu_owned_cross_write"];
            if(!warm||!rd||!wr){
                finish(@"METAL_SHADERS_NOT_FOUND");return;
            }
            id<MTLComputePipelineState> warmPipe=[dev newComputePipelineStateWithFunction:warm error:&err];
            if(!warmPipe){
                report[@"pipelineError"]=err.localizedDescription ?: @"UNAVAILABLE";
                finish(@"WARM_PIPELINE_ERROR");return;
            }
            err=nil;
            id<MTLComputePipelineState> readPipe=[dev newComputePipelineStateWithFunction:rd error:&err];
            if(!readPipe){
                report[@"pipelineError"]=err.localizedDescription ?: @"UNAVAILABLE";
                finish(@"READ_PIPELINE_ERROR");return;
            }
            err=nil;
            id<MTLComputePipelineState> writePipe=[dev newComputePipelineStateWithFunction:wr error:&err];
            if(!writePipe){
                report[@"pipelineError"]=err.localizedDescription ?: @"UNAVAILABLE";
                finish(@"WRITE_PIPELINE_ERROR");return;
            }

            const NSUInteger length=0x10000; // Own 64 KiB allocations, exactly once.
            checkpoint(@"allocate_two_owned_buffers");
            id<MTLBuffer> anchor=[dev newBufferWithLength:length options:MTLResourceStorageModeShared];
            id<MTLBuffer> victim=[dev newBufferWithLength:length options:MTLResourceStorageModeShared];
            id<MTLBuffer> answer=[dev newBufferWithLength:sizeof(uint32_t) options:MTLResourceStorageModeShared];
            if(!anchor||!victim||!answer||!anchor.contents||!victim.contents||!answer.contents){
                finish(@"OWN_BUFFER_ALLOCATION_FAILED");return;
            }
            memset(anchor.contents,0,length);
            memset(victim.contents,0,length);
            memset(answer.contents,0,sizeof(uint32_t));
            uint32_t *victimCPU=(uint32_t *)victim.contents;
            uint32_t *answerCPU=(uint32_t *)answer.contents;
            const uint32_t preexisting=0x11223344u;
            const uint32_t normal=0x47474747u;
            const uint32_t proposed=0x57524954u; // ASCII WRIT
            victimCPU[0]=preexisting;
            victimCPU[1]=0u;

            // Baseline: GPU writes inside the victim's logical allocation.
            // Shader warm deliberately writes element 1 and preserves element 0.
            checkpoint(@"baseline_gpu_own_buffer_write");
            id<MTLCommandBuffer> cb=[queue commandBuffer];
            id<MTLComputeCommandEncoder> enc=[cb computeCommandEncoder];
            if(!cb||!enc){ finish(@"WARM_ENCODING_UNAVAILABLE");return; }
            [enc setComputePipelineState:warmPipe];
            [enc setBuffer:victim offset:0 atIndex:0];
            [enc setBytes:&normal length:sizeof(normal) atIndex:1];
            [enc dispatchThreads:MTLSizeMake(1,1,1)
                   threadsPerThreadgroup:MTLSizeMake(1,1,1)];
            [enc endEncoding];
            [cb commit];
            [cb waitUntilCompleted];
            report[@"warmCommandStatus"]=@((NSUInteger)cb.status);
            if(cb.error)report[@"warmCommandError"]=cb.error.localizedDescription;
            report[@"warmReadback"]=GPUValueHex(victimCPU[1]);
            BOOL baselineOK=cb.status==MTLCommandBufferStatusCompleted &&
                            victimCPU[1]==normal && victimCPU[0]==preexisting;
            report[@"baselineVerified"]=@(baselineOK);
            if(!baselineOK){ finish(@"BASELINE_FAILED_NO_CROSS_OBJECT_ATTEMPT");return; }

            uint64_t anchorVA=(uint64_t)anchor.gpuAddress;
            uint64_t victimVA=(uint64_t)victim.gpuAddress;
            report[@"anchorGPUAddress"]=GPUAddressHex(anchorVA);
            report[@"victimGPUAddress"]=GPUAddressHex(victimVA);
            report[@"anchorLength"]=@(length);
            report[@"victimLength"]=@(length);
            report[@"preexistingValue"]=GPUValueHex(victimCPU[0]);
            if(anchorVA==0 || victimVA<=anchorVA){
                finish(@"GPU_VA_ORDER_UNSUPPORTED_NO_CROSS_OBJECT_ATTEMPT");return;
            }
            uint64_t delta=victimVA-anchorVA;
            report[@"gpuAddressDeltaBytes"]=@(delta);
            if(delta<length || delta>0x200000 || (delta%sizeof(uint32_t))!=0) {
                finish(@"GPU_VA_DISTANCE_REJECTED_NO_CROSS_OBJECT_ATTEMPT");return;
            }
            uint32_t index=(uint32_t)(delta/sizeof(uint32_t));
            report[@"indexInU32"]=@(index);
            report[@"indexBeyondAnchorLength"]=@(delta>=length);

            // Read PRE-EXISTING value from victim via anchor's GPU address.
            // victim is independently kept resident in the same GPU context.
            checkpoint(@"same_context_cross_buffer_read");
            id<MTLCommandBuffer> readCB=[queue commandBuffer];
            id<MTLComputeCommandEncoder> readEnc=[readCB computeCommandEncoder];
            if(!readCB||!readEnc){finish(@"READ_ENCODING_UNAVAILABLE");return;}
            [readEnc setComputePipelineState:readPipe];
            [readEnc setBuffer:anchor offset:0 atIndex:0];
            [readEnc setBytes:&index length:sizeof(index) atIndex:1];
            [readEnc setBuffer:answer offset:0 atIndex:2];
            [readEnc useResource:victim usage:MTLResourceUsageRead];
            [readEnc dispatchThreads:MTLSizeMake(1,1,1)
                 threadsPerThreadgroup:MTLSizeMake(1,1,1)];
            [readEnc endEncoding];
            [readCB commit];
            [readCB waitUntilCompleted];
            report[@"readCommandStatus"]=@((NSUInteger)readCB.status);
            if(readCB.error)report[@"readCommandError"]=readCB.error.localizedDescription;
            report[@"gpuReadViaAnchor"]=GPUValueHex(answerCPU[0]);
            BOOL readOK=readCB.status==MTLCommandBufferStatusCompleted &&
                        answerCPU[0]==preexisting;
            report[@"gpuCrossObjectReadVerified"]=@(readOK);
            report[@"gpuReadPreexistingValueVerified"]=@(readOK);

            // Mutate ONLY victim[0], which was created and initialized by us.
            checkpoint(@"same_context_cross_buffer_write");
            id<MTLCommandBuffer> writeCB=[queue commandBuffer];
            id<MTLComputeCommandEncoder> writeEnc=[writeCB computeCommandEncoder];
            if(!writeCB||!writeEnc){finish(@"WRITE_ENCODING_UNAVAILABLE");return;}
            [writeEnc setComputePipelineState:writePipe];
            [writeEnc setBuffer:anchor offset:0 atIndex:0];
            [writeEnc setBytes:&index length:sizeof(index) atIndex:1];
            [writeEnc setBytes:&proposed length:sizeof(proposed) atIndex:2];
            [writeEnc useResource:victim usage:MTLResourceUsageRead|MTLResourceUsageWrite];
            [writeEnc dispatchThreads:MTLSizeMake(1,1,1)
                   threadsPerThreadgroup:MTLSizeMake(1,1,1)];
            [writeEnc endEncoding];
            [writeCB commit];
            [writeCB waitUntilCompleted];
            report[@"writeCommandStatus"]=@((NSUInteger)writeCB.status);
            if(writeCB.error)report[@"writeCommandError"]=writeCB.error.localizedDescription;
            report[@"victimValueAfterGPUWrite"]=GPUValueHex(victimCPU[0]);
            BOOL writeOK=writeCB.status==MTLCommandBufferStatusCompleted &&
                         victimCPU[0]==proposed;
            report[@"gpuCrossObjectWriteVerified"]=@(writeOK);

            // Preserve the actual before/after values, do not synthesize green checks.
            report[@"readBackFromCPU"]=GPUValueHex(victimCPU[0]);
            report[@"writeMarkerExpected"]=GPUValueHex(proposed);
            report[@"originOfBothBuffers"]=@"OWNED_BY_CURRENT_APP";
            report[@"scopeLimit"]=@"Metal GPU VA mappings within app process; no entitlement bypass";
            NSString *verdict=(readOK&&writeOK)
                ? @"OWN_CONTEXT_GPU_CROSS_BUFFER_READ_AND_WRITE_CONFIRMED"
                : @"OWN_CONTEXT_GPU_CROSS_BUFFER_NOT_CONFIRMED";
            finish(verdict);
        });
    }]];
    [self presentViewController:alert animated:YES completion:nil];
}
@end
