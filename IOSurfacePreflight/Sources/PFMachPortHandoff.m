#import "PFMachPortHandoff.h"
#import "PFMachPortPattern.h"
#import <CoreFoundation/CoreFoundation.h>
#import <CoreGraphics/CoreGraphics.h>
#import <mach/mach.h>
#import <dlfcn.h>
#import <string.h>

// Real IOSurface storage, public Mach-port handoff, same-process ownership.
// This is NOT a stale pointer, IPC fuzzing, sandbox escape, or KernelRW.
typedef struct __IOSurface *PFHandoffRef;
typedef PFHandoffRef (*PFCreateFn)(CFDictionaryRef);
typedef mach_port_t (*PFMakePortFn)(PFHandoffRef);
typedef PFHandoffRef (*PFFromPortFn)(mach_port_t);
typedef size_t (*PFGetSizeFn)(PFHandoffRef);
typedef void *(*PFGetBaseFn)(PFHandoffRef);
typedef kern_return_t (*PFLockFn)(PFHandoffRef, uint32_t, uint32_t *);

static UIImage *PFHandoffMakeImage(NSData *pixels) {
    if (!pixels || pixels.length != PF_HANDOFF_BYTES) return nil;
    CGDataProviderRef provider = CGDataProviderCreateWithCFData((__bridge CFDataRef)pixels);
    if (!provider) return nil;
    CGColorSpaceRef colorspace = CGColorSpaceCreateDeviceRGB();
    if (!colorspace) { CGDataProviderRelease(provider); return nil; }
    CGImageRef cgimage = CGImageCreate(PF_HANDOFF_WIDTH, PF_HANDOFF_HEIGHT,
                                     8, 32, PF_HANDOFF_STRIDE,
                                     colorspace,
                                     kCGImageAlphaPremultipliedFirst |
                                     kCGBitmapByteOrder32Little,
                                     provider, NULL, false,
                                     kCGRenderingIntentDefault);
    CGColorSpaceRelease(colorspace);
    CGDataProviderRelease(provider);
    if (!cgimage) return nil;
    UIImage *image = [UIImage imageWithCGImage:cgimage];
    CGImageRelease(cgimage);
    return image;
}

NSDictionary<NSString *, id> *PFRunMachPortHandoff(UIImage * __autoreleasing *outputImage) {
    if (outputImage) *outputImage = nil;
    NSString *stage = @"LOAD";
    NSString *status = @"ERROR";
    NSString *detail = @"Uninitialized";
    PFHandoffRef original = NULL, reconstructed = NULL;
    mach_port_t port = MACH_PORT_NULL;
    void *lib = NULL;
    uint64_t before = 0, recovered = 0, after = 0;
    BOOL originalReleased = NO, portReleased = NO, reconstructionVerified = NO;
    UIImage *image = nil;

    do {
        lib = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface",
                     RTLD_NOW | RTLD_LOCAL);
        if (!lib) { status=@"UNAVAILABLE"; detail=@"IOSurface framework unavailable"; break; }

        PFCreateFn create = (PFCreateFn)dlsym(lib, "IOSurfaceCreate");
        PFMakePortFn makePort = (PFMakePortFn)dlsym(lib, "IOSurfaceCreateMachPort");
        PFFromPortFn fromPort = (PFFromPortFn)dlsym(lib, "IOSurfaceLookupFromMachPort");
        PFGetSizeFn width = (PFGetSizeFn)dlsym(lib, "IOSurfaceGetWidth");
        PFGetSizeFn height = (PFGetSizeFn)dlsym(lib, "IOSurfaceGetHeight");
        PFGetSizeFn stride = (PFGetSizeFn)dlsym(lib, "IOSurfaceGetBytesPerRow");
        PFGetSizeFn allocSize = (PFGetSizeFn)dlsym(lib, "IOSurfaceGetAllocSize");
        PFGetBaseFn baseAddress = (PFGetBaseFn)dlsym(lib, "IOSurfaceGetBaseAddress");
        PFLockFn lock = (PFLockFn)dlsym(lib, "IOSurfaceLock");
        PFLockFn unlock = (PFLockFn)dlsym(lib, "IOSurfaceUnlock");
        if (!create || !makePort || !fromPort || !width || !height ||
            !stride || !allocSize || !baseAddress || !lock || !unlock) {
            status=@"UNAVAILABLE";
            detail=@"Required public Mach-port or IOSurface symbols unavailable";
            break;
        }

        stage = @"CREATE";
        NSDictionary *properties = @{
            @"IOSurfaceWidth": @(PF_HANDOFF_WIDTH),
            @"IOSurfaceHeight": @(PF_HANDOFF_HEIGHT),
            @"IOSurfaceBytesPerElement": @(PF_HANDOFF_BPP),
            @"IOSurfaceBytesPerRow": @(PF_HANDOFF_STRIDE),
            @"IOSurfaceAllocSize": @(PF_HANDOFF_BYTES),
            @"IOSurfacePixelFormat": @(0x42475241)
        };
        original = create((__bridge CFDictionaryRef)properties);
        if (!original) { detail=@"IOSurfaceCreate rejected a valid BGRA buffer"; break; }
        if (width(original)!=PF_HANDOFF_WIDTH ||
            height(original)!=PF_HANDOFF_HEIGHT ||
            stride(original)!=PF_HANDOFF_STRIDE ||
            allocSize(original)<PF_HANDOFF_BYTES) {
            detail=@"Surface layout does not match bounded BGRA image"; break;
        }

        stage=@"FILL";
        kern_return_t kr = lock(original, 0, NULL);
        if (kr!=KERN_SUCCESS) { detail=@"Unable to lock created surface"; break; }
        uint8_t *ptr = (uint8_t *)baseAddress(original);
        BOOL filled = ptr && PFHandoffFill(ptr, PF_HANDOFF_BYTES);
        if (filled) before=PFHandoffHash(ptr, PF_HANDOFF_BYTES);
        kern_return_t unkr=unlock(original, 0, NULL);
        if (!filled || unkr!=KERN_SUCCESS) {
            detail=@"Initial pixel fill or unlock failed"; break;
        }

        stage=@"PORT";
        port=makePort(original);
        if (port==MACH_PORT_NULL || port==MACH_PORT_DEAD) {
            port=MACH_PORT_NULL;
            status=@"UNAVAILABLE";
            detail=@"IOSurfaceCreateMachPort did not return a usable port";
            break;
        }

        // The port is the only live handle held by this function at this stage.
        // It must prevent destruction of the owned surface until it is looked up.
        CFRelease(original);
        original=NULL;
        originalReleased=YES;

        stage=@"RECONSTRUCT";
        reconstructed=fromPort(port);
        if (!reconstructed) {
            detail=@"IOSurfaceLookupFromMachPort did not reconstruct a reference";
            break;
        }

        // Prove that the reconstructed reference owns its lifetime.
        kr=mach_port_deallocate(mach_task_self(), port);
        port=MACH_PORT_NULL;
        if (kr!=KERN_SUCCESS) {
            detail=@"mach_port_deallocate failed"; break;
        }
        portReleased=YES;
        if (width(reconstructed)!=PF_HANDOFF_WIDTH ||
            height(reconstructed)!=PF_HANDOFF_HEIGHT ||
            stride(reconstructed)!=PF_HANDOFF_STRIDE ||
            allocSize(reconstructed)<PF_HANDOFF_BYTES) {
            detail=@"Reconstructed surface has unexpected dimensions or span"; break;
        }

        stage=@"VERIFY_AND_STAMP";
        kr=lock(reconstructed, 0, NULL);
        if (kr!=KERN_SUCCESS) {
            detail=@"Unable to lock reconstructed surface"; break;
        }
        ptr=(uint8_t *)baseAddress(reconstructed);
        recovered=ptr ? PFHandoffHash(ptr, PF_HANDOFF_BYTES) : 0;
        reconstructionVerified=(ptr && recovered==before);
        BOOL stamped=NO;
        NSMutableData *resultPixels=nil;
        if (reconstructionVerified) {
            stamped=PFHandoffStamp(ptr, PF_HANDOFF_BYTES);
            if (stamped) {
                after=PFHandoffHash(ptr, PF_HANDOFF_BYTES);
                resultPixels=[NSMutableData dataWithBytes:ptr length:PF_HANDOFF_BYTES];
            }
        }
        unkr=unlock(reconstructed, 0, NULL);
        if (!reconstructionVerified) {
            detail=@"Pixel hash mismatch after reference reconstruction"; break;
        }
        if (!stamped || !resultPixels || unkr!=KERN_SUCCESS) {
            detail=@"Cannot stamp or copy recovered pixels"; break;
        }

        stage=@"CONFIRM_PIXEL_BYTES";
        NSMutableData *expected=[NSMutableData dataWithLength:PF_HANDOFF_BYTES];
        BOOL generated=PFHandoffFill(expected.mutableBytes,expected.length);
        BOOL expectedStamped=generated && PFHandoffStamp(expected.mutableBytes,expected.length);
        if (!expectedStamped ||
            memcmp(expected.bytes, resultPixels.bytes, PF_HANDOFF_BYTES)!=0 ||
            PFHandoffHash(expected.bytes,expected.length)!=after || before==after) {
            detail=@"Recovered data differs from independently generated image"; break;
        }

        stage=@"RENDER";
        image=PFHandoffMakeImage(resultPixels);
        if (!image) { detail=@"Could not create an image from verified BGRA bytes"; break; }
        status=@"PASS";
        detail=@"Original reference released, surface reacquired via Mach port, port released, pixels recovered, modified, verified and rendered";
        if (outputImage) *outputImage=image;
    } while(0);

    // Always release valid public handles. Never use raw/stale kernel pointers.
    if (original) CFRelease(original);
    if (reconstructed) CFRelease(reconstructed);
    if (port!=MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), port);
    if (lib) dlclose(lib);
    return @{
        @"schema":@"v19.8-iosurface-real-mach-handoff",
        @"status":status, @"stage":stage, @"detail":detail,
        @"bytes":@(PF_HANDOFF_BYTES),
        @"width":@(PF_HANDOFF_WIDTH),
        @"height":@(PF_HANDOFF_HEIGHT),
        @"original_released_before_lookup":@(originalReleased),
        @"port_released_after_lookup":@(portReleased),
        @"reconstructed_pixel_hash_matches":@(reconstructionVerified),
        @"original_pixel_hash_fnv1a64":[NSString stringWithFormat:@"%016llx", (unsigned long long)before],
        @"recovered_pixel_hash_fnv1a64":[NSString stringWithFormat:@"%016llx", (unsigned long long)recovered],
        @"modified_pixel_hash_fnv1a64":[NSString stringWithFormat:@"%016llx", (unsigned long long)after],
        @"kernel_read_write":@NO,
        @"privilege_escalation":@NO,
        @"same_process_handoff_only":@YES,
        @"timestamp":[NSDate date].description
    };
}
