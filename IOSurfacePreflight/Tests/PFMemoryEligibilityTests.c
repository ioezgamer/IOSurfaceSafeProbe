#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "../Sources/PFMemoryEligibility.h"

int main(void) {
    // For a 16x16 BGRA image: stride=64 and allocation=1024.
    assert(PFClassifyMemorySurface(0x42475241,4,16,16,64,1024,5,true)==PFMemoryEligible);
    assert(PFClassifyMemorySurface(0x42475241,4,16,16,64,1024,5,false)==PFMemoryMissingAccessors);
    assert(PFClassifyMemorySurface(0x42475241,4,16,16,64,1024,0,true)==PFMemoryZeroID);
    assert(PFClassifyMemorySurface(0x42475241,4,0,16,64,1024,5,true)==PFMemoryZeroDimension);
    assert(PFClassifyMemorySurface(0x42475241,4,4097,16,16388,999999,5,true)==PFMemoryMetadataOutOfRange);
    assert(PFClassifyMemorySurface(0x42475241,4,16,16,63,1024,5,true)==PFMemoryRowTooShort);
    assert(PFClassifyMemorySurface(0x42475241,4,16,16,64,1023,5,true)==PFMemoryPixelSpanTooShort);
    assert(PFClassifyMemorySurface(0x52474241,4,16,16,64,1024,5,true)==PFMemoryUnsupportedFormat);
    assert(PFClassifyMemorySurface(0x42475241,2,16,16,64,1024,5,true)==PFMemoryUnsupportedElementSize);
    assert(PFClassifyMemorySurface(0x42475241,4,257,16,1028,16448,5,true)==PFMemoryOversize);
    assert(strcmp(PFRequestedPixelFormat(0x42475241),"BGRA_REQUESTED")==0);
    assert(strcmp(PFRequestedPixelFormat(0x52474241),"RGBA_REQUESTED")==0);
    assert(strcmp(PFRequestedPixelFormat(0x00000000),"ZERO_REQUESTED")==0);
    assert(strcmp(PFRequestedPixelFormat(0x41414141),"AAAA_REQUESTED")==0);
    assert(strcmp(PFRequestedPixelFormat(0x42424242),"OTHER_REQUESTED")==0);
    assert(strcmp(PFMemoryEligibilityLabel(PFMemoryUnsupportedFormat),"UNSUPPORTED_REQUESTED_FORMAT")==0);
    puts("16/16 memory eligibility and format tests passed");
    return 0;
}
