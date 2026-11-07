#import "PFPortRevocationTest.h"
#import "PFPortRevocationClassifier.h"
#import <CoreFoundation/CoreFoundation.h>
#import <mach/mach.h>
#import <dlfcn.h>

typedef struct __IOSurface *PFRevocationSurface;
typedef PFRevocationSurface (*PFCreateSurface)(CFDictionaryRef);
typedef mach_port_t (*PFCreateMachPort)(PFRevocationSurface);
typedef PFRevocationSurface (*PFLookupFromMachPort)(mach_port_t);
typedef uint32_t (*PFGetSurfaceID)(PFRevocationSurface);

NSDictionary<NSString *, id> *PFRunPortRevocationTest(void) {
    PFPortEvidence evidence={0};
    NSString *stage=@"LOAD";
    NSString *detail=@"";
    NSString *initialStatus=@"NOT_RUN";
    NSString *lastRightStatus=@"NOT_RUN";
    NSString *revokedStatus=@"NOT_RUN";
    NSString *unrelatedStatus=@"NOT_RUN";
    NSString *nullStatus=@"NOT_RUN";
    kern_return_t duplicateKr=KERN_FAILURE;
    kern_return_t dropOneKr=KERN_FAILURE;
    kern_return_t dropFinalKr=KERN_FAILURE;
    kern_return_t portTypeKr=KERN_FAILURE;
    mach_port_type_t portType=0;
    kern_return_t unrelatedAllocateKr=KERN_FAILURE;
    kern_return_t unrelatedInsertKr=KERN_FAILURE;
    PFRevocationSurface original=NULL;
    PFRevocationSurface temp=NULL;
    void *lib=NULL;
    mach_port_t ownedPort=MACH_PORT_NULL;
    mach_port_t unrelatedPort=MACH_PORT_NULL;
    mach_port_t revokedName=MACH_PORT_NULL;
    int ownedSendRefs=0;
    uint32_t originalID=0;
    BOOL revokedReturnedOriginal=NO;
    BOOL unrelatedReturnedOriginal=NO;
    BOOL nullReturnedOriginal=NO;

    // A finite 1x positive baseline, 1x port-right revocation,
    // and at most 3 negative lookups. No concurrency or private IPC.
    do {
        lib=dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface",
                   RTLD_NOW|RTLD_LOCAL);
        if(!lib) {detail=@"IOSurface framework unavailable";break;}
        PFCreateSurface create=(PFCreateSurface)dlsym(lib,"IOSurfaceCreate");
        PFCreateMachPort makePort=(PFCreateMachPort)dlsym(lib,"IOSurfaceCreateMachPort");
        PFLookupFromMachPort lookup=(PFLookupFromMachPort)dlsym(lib,"IOSurfaceLookupFromMachPort");
        PFGetSurfaceID getID=(PFGetSurfaceID)dlsym(lib,"IOSurfaceGetID");
        if(!create || !makePort || !lookup || !getID) {
            detail=@"Required public IOSurface functions unavailable";break;
        }
        evidence.symbolsAvailable=true;

        stage=@"CREATE_OWNED_SURFACE";
        NSDictionary *params=@{
            @"IOSurfaceWidth":@64, @"IOSurfaceHeight":@64,
            @"IOSurfaceBytesPerElement":@4,
            @"IOSurfaceBytesPerRow":@256,
            @"IOSurfaceAllocSize":@(64*64*4),
            @"IOSurfacePixelFormat":@(0x42475241)
        };
        original=create((__bridge CFDictionaryRef)params);
        if(!original) {detail=@"IOSurfaceCreate returned null";break;}
        originalID=getID(original);
        evidence.surfaceCreated=(originalID!=0);
        if(!evidence.surfaceCreated) {detail=@"Created surface has no usable ID";break;}

        stage=@"POSITIVE_CONTROL";
        ownedPort=makePort(original);
        if(ownedPort==MACH_PORT_NULL || ownedPort==MACH_PORT_DEAD) {
            ownedPort=MACH_PORT_NULL;
            detail=@"IOSurfaceCreateMachPort returned no usable send right";break;
        }
        ownedSendRefs=1;
        temp=lookup(ownedPort);
        evidence.initialLookupValid=(temp!=NULL && getID(temp)==originalID);
        initialStatus=temp?(evidence.initialLookupValid?@"MATCH":@"OTHER_SURFACE"):@"NULL";
        if(temp) {CFRelease(temp);temp=NULL;}
        if(!evidence.initialLookupValid) {
            detail=@"Mach-port positive control failed";break;
        }

        // Create an extra *user reference* to the same Mach send right.
        // Deallocating one reference must leave a functioning control.
        stage=@"SEND_RIGHT_REFERENCE_CONTROL";
        duplicateKr=mach_port_mod_refs(mach_task_self(),ownedPort,
                                       MACH_PORT_RIGHT_SEND,1);
        if(duplicateKr!=KERN_SUCCESS) {
            detail=@"Unable to duplicate owned send right";break;
        }
        ownedSendRefs=2;
        dropOneKr=mach_port_deallocate(mach_task_self(),ownedPort);
        if(dropOneKr!=KERN_SUCCESS) {
            detail=@"Unable to drop first send right reference";break;
        }
        ownedSendRefs=1;
        evidence.rightsDuplicated=true;
        temp=lookup(ownedPort);
        evidence.lookupWithLastRightValid=(temp!=NULL && getID(temp)==originalID);
        lastRightStatus=temp?(evidence.lookupWithLastRightValid?@"MATCH":@"OTHER_SURFACE"):@"NULL";
        if(temp) {CFRelease(temp);temp=NULL;}
        if(!evidence.lookupWithLastRightValid) {
            detail=@"Remaining valid send right could not look up the surface";break;
        }

        stage=@"REVOKE_ALL_SEND_RIGHTS";
        revokedName=ownedPort; // Save only the numeric name, not a usable right.
        dropFinalKr=mach_port_deallocate(mach_task_self(),ownedPort);
        if(dropFinalKr!=KERN_SUCCESS) {
            detail=@"Unable to drop last send right reference";break;
        }
        ownedSendRefs=0;
        ownedPort=MACH_PORT_NULL;
        portTypeKr=mach_port_type(mach_task_self(),revokedName,&portType);
        evidence.invalidPortNameConfirmed=(portTypeKr!=KERN_SUCCESS ||
                                           (portType & MACH_PORT_TYPE_SEND)==0);
        if(!evidence.invalidPortNameConfirmed) {
            detail=@"Port name still has a send right, so negative test was skipped";
            break;
        }

        // Test once on our own revoked numeric Mach name.
        // Keep original alive to isolate port-right authorization
        // from IOSurface object destruction and ID reuse.
        stage=@"NEGATIVE_REVOKED_NAME";
        temp=lookup(revokedName);
        evidence.revokedLookupReturnedSurface=(temp!=NULL);
        revokedStatus=temp?@"UNEXPECTED_SURFACE":@"NULL_REJECTED";
        if(temp) {
            revokedReturnedOriginal=(getID(temp)==originalID);
            CFRelease(temp); temp=NULL;
        }

        // A valid Mach port with a different object type is not
        // an authorization token for this IOSurface.
        stage=@"NEGATIVE_UNRELATED_PORT";
        unrelatedAllocateKr=mach_port_allocate(mach_task_self(),
                                               MACH_PORT_RIGHT_RECEIVE,&unrelatedPort);
        if(unrelatedAllocateKr==KERN_SUCCESS) {
            unrelatedInsertKr=mach_port_insert_right(mach_task_self(),unrelatedPort,
                                                    unrelatedPort,MACH_MSG_TYPE_MAKE_SEND);
            if(unrelatedInsertKr==KERN_SUCCESS) {
                evidence.unrelatedPortTested=true;
                temp=lookup(unrelatedPort);
                evidence.unrelatedLookupReturnedSurface=(temp!=NULL);
                unrelatedStatus=temp?@"UNEXPECTED_SURFACE":@"NULL_REJECTED";
                if(temp) {
                    unrelatedReturnedOriginal=(getID(temp)==originalID);
                    CFRelease(temp);temp=NULL;
                }
            } else unrelatedStatus=@"SETUP_FAILED";
        } else unrelatedStatus=@"SETUP_FAILED";

        // A null Mach name must not authorize a surface lookup.
        stage=@"NEGATIVE_NULL_PORT";
        evidence.nullPortTested=true;
        temp=lookup(MACH_PORT_NULL);
        evidence.nullLookupReturnedSurface=(temp!=NULL);
        nullStatus=temp?@"UNEXPECTED_SURFACE":@"NULL_REJECTED";
        if(temp) {
            nullReturnedOriginal=(getID(temp)==originalID);
            CFRelease(temp);temp=NULL;
        }
        detail=@"All bounded cases executed; see verdict and per-control fields";
    } while(0);

    if(temp) CFRelease(temp);
    if(unrelatedPort!=MACH_PORT_NULL)
        mach_port_destroy(mach_task_self(),unrelatedPort);
    while(ownedSendRefs>0 && ownedPort!=MACH_PORT_NULL) {
        mach_port_deallocate(mach_task_self(),ownedPort);
        ownedSendRefs--;
    }
    if(original) CFRelease(original);
    if(lib) dlclose(lib);
    PFPortVerdict verdict=PFPortClassify(evidence);

    return @{
        @"schema":@"v19.9-mach-send-right-revocation",
        @"timestamp":[NSDate date].description,
        @"verdict":[NSString stringWithUTF8String:PFPortVerdictName(verdict)],
        @"stage":stage,
        @"detail":detail,
        @"own_surface_only":@YES,
        @"same_process_only":@YES,
        @"attempts_per_negative_control":@1,
        @"initial_valid_port_lookup":initialStatus,
        @"remaining_valid_send_right_lookup":lastRightStatus,
        @"revoked_port_lookup":revokedStatus,
        @"unrelated_port_lookup":unrelatedStatus,
        @"null_port_lookup":nullStatus,
        @"duplicate_send_right_kr":@((int)duplicateKr),
        @"deallocate_one_send_right_kr":@((int)dropOneKr),
        @"deallocate_last_send_right_kr":@((int)dropFinalKr),
        @"revoked_port_type_query_kr":@((int)portTypeKr),
        @"revoked_port_type_bits":@((unsigned)portType),
        @"unrelated_port_allocate_kr":@((int)unrelatedAllocateKr),
        @"unrelated_port_make_send_kr":@((int)unrelatedInsertKr),
        @"original_surface_id":@(originalID),
        @"valid_port_control_passed":@(evidence.initialLookupValid),
        @"remaining_send_right_control_passed":@(evidence.lookupWithLastRightValid),
        @"port_name_invalidated":@(evidence.invalidPortNameConfirmed),
        @"revoked_port_returned_surface":@(evidence.revokedLookupReturnedSurface),
        @"revoked_port_returned_original_id":@(revokedReturnedOriginal),
        @"unrelated_port_returned_surface":@(evidence.unrelatedLookupReturnedSurface),
        @"unrelated_port_returned_original_id":@(unrelatedReturnedOriginal),
        @"null_port_returned_surface":@(evidence.nullLookupReturnedSurface),
        @"null_port_returned_original_id":@(nullReturnedOriginal),
        @"kernel_read_write_proven":@NO,
        @"use_after_free_proven":@NO,
        @"security_vulnerability_proven":@NO
    };
}
