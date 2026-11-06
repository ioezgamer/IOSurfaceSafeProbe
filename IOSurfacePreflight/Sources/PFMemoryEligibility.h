#ifndef PF_MEMORY_ELIGIBILITY_H
#define PF_MEMORY_ELIGIBILITY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// These are REQUESTED FourCC formats. Do not infer the observed kernel format
// or undocumented driver behavior from an input dictionary.
static inline const char *PFRequestedPixelFormat(uint32_t fourcc) {
    switch(fourcc) {
        case 0x42475241U: return "BGRA_REQUESTED";
        case 0x52474241U: return "RGBA_REQUESTED";
        case 0x00000000U: return "ZERO_REQUESTED";
        case 0x41414141U: return "AAAA_REQUESTED";
        default: return "OTHER_REQUESTED";
    }
}

typedef enum {
    PFMemoryEligible=0,
    PFMemoryMissingAccessors,
    PFMemoryZeroID,
    PFMemoryZeroDimension,
    PFMemoryMetadataOutOfRange,
    PFMemoryRowTooShort,
    PFMemoryPixelSpanTooShort,
    PFMemoryUnsupportedFormat,
    PFMemoryUnsupportedElementSize,
    PFMemoryOversize
} PFMemoryEligibility;

// Ordered, mutually exclusive exclusion reasons for surfaces successfully
// created with public IOSurfaceCreate. They are app-safety limits, not
// assertions that an input was invalid or exploited.
static inline PFMemoryEligibility PFClassifyMemorySurface(
    uint32_t requestedFormat, size_t requestedElementSize,
    size_t width, size_t height, size_t bytesPerRow,
    size_t allocationSize, uint32_t surfaceID, bool accessorsAvailable) {

    if(!accessorsAvailable) return PFMemoryMissingAccessors;
    if(surfaceID==0) return PFMemoryZeroID;
    if(width==0 || height==0) return PFMemoryZeroDimension;
    if(width>4096 || height>4096 || bytesPerRow>(1ULL<<24) ||
       (requestedElementSize>0 && width>SIZE_MAX/requestedElementSize)) {
        return PFMemoryMetadataOutOfRange;
    }
    if(bytesPerRow<width*requestedElementSize) return PFMemoryRowTooShort;
    if(height>1 && bytesPerRow>SIZE_MAX/(height-1))
        return PFMemoryMetadataOutOfRange;
    size_t base=(height-1)*bytesPerRow;
    if(requestedElementSize>0 && width>SIZE_MAX/requestedElementSize)
        return PFMemoryMetadataOutOfRange;
    size_t lastPixel=width*requestedElementSize;
    if(base>SIZE_MAX-lastPixel) return PFMemoryMetadataOutOfRange;
    if(allocationSize<base+lastPixel) return PFMemoryPixelSpanTooShort;
    if(requestedFormat!=0x42475241U) return PFMemoryUnsupportedFormat;
    if(requestedElementSize!=4) return PFMemoryUnsupportedElementSize;
    if(width>256 || height>256) return PFMemoryOversize;
    return PFMemoryEligible;
}

static inline const char *PFMemoryEligibilityLabel(PFMemoryEligibility reason) {
    switch(reason) {
        case PFMemoryEligible: return "ELIGIBLE";
        case PFMemoryMissingAccessors: return "MISSING_CPU_ACCESSORS";
        case PFMemoryZeroID: return "ZERO_SURFACE_ID";
        case PFMemoryZeroDimension: return "ZERO_DIMENSION";
        case PFMemoryMetadataOutOfRange: return "METADATA_OUT_OF_RANGE";
        case PFMemoryRowTooShort: return "ROW_TOO_SHORT";
        case PFMemoryPixelSpanTooShort: return "PIXEL_SPAN_TOO_SHORT";
        case PFMemoryUnsupportedFormat: return "UNSUPPORTED_REQUESTED_FORMAT";
        case PFMemoryUnsupportedElementSize: return "UNSUPPORTED_ELEMENT_SIZE";
        case PFMemoryOversize: return "ABOVE_SAFE_DIMENSION_LIMIT";
    }
    return "UNKNOWN";
}

#endif
