#include <metal_stdlib>
using namespace metal;

// All allocations are owned by the same app and are part of one GPU context.
// This is a GPU pointer-boundary experiment, not IOSurface kernel exploitation.

kernel void gpu_owned_warm(device uint *victim [[buffer(0)]],
                           constant uint &value [[buffer(1)]],
                           uint tid [[thread_position_in_grid]]) {
    if (tid == 0) {
        victim[0] = value;
    }
}

// Intentionally uses a runtime-computed index beyond 'anchor' allocation.
// The host only permits the index to resolve to another buffer owned by this
// same application, and independently verifies the target address.
kernel void gpu_owned_cross_write(device uint *anchor [[buffer(0)]],
                                  constant uint &index [[buffer(1)]],
                                  constant uint &value [[buffer(2)]],
                                  uint tid [[thread_position_in_grid]]) {
    if (tid == 0) {
        anchor[index] = value;
    }
}

kernel void gpu_owned_cross_read(const device uint *anchor [[buffer(0)]],
                                 constant uint &index [[buffer(1)]],
                                 device uint *answer [[buffer(2)]],
                                 uint tid [[thread_position_in_grid]]) {
    if (tid == 0) {
        answer[0] = anchor[index];
    }
}
