#include <assert.h>
#include <math.h>
#include <stdio.h>
#include "../Sources/PFBootClassifier.h"

static PFBootResult evaluate(double past, bool havePast, double now,
                             bool haveNow, double oldBoot, bool haveOldBoot,
                             double newBoot, bool haveNewBoot) {
    return PFDetermineBoot(past, havePast, now, haveNow,
                           oldBoot, haveOldBoot, newBoot, haveNewBoot);
}

int main(void) {
    // The v18 checkpoint has only bootStamp, NOT systemUptimeSeconds.
    // A changed bootStamp must never be called a proven reboot.
    assert(evaluate(0, false, 50, true, 1000, true, 999999, true)
           == PFBootIndeterminate);
    // Normal app relaunch with uptime increasing.
    assert(evaluate(500, true, 506, true, 1000, true, 1000, true)
           == PFBootNoUptimeRollback);
    // Microsecond changes to bootStamp must be ignored.
    assert(evaluate(500, true, 506, true, 1000.000001, true, 1000.001, true)
           == PFBootNoUptimeRollback);
    // Uptime did not drop, so a changed epoch alone is not proof.
    assert(evaluate(500, true, 506, true, 1000, true, 2000, true)
           == PFBootBootEpochChangedUnconfirmed);
    // A large drop in uptime is evidence of a reboot between samples.
    assert(evaluate(500, true, 30, true, 1000, true, 2000, true)
           == PFBootUptimeRolledBack);
    // Small sampling jitter does not establish a reboot.
    assert(evaluate(500, true, 498, true, 1000, true, 1000, true)
           == PFBootNoUptimeRollback);
    // Missing or invalid uptime is indeterminate, even if epoch changed.
    assert(evaluate(500, true, NAN, true, 1000, true, 2000, true)
           == PFBootIndeterminate);
    // The decision still works if kern.boottime is unavailable.
    assert(evaluate(500, true, 502, true, 0, false, 0, false)
           == PFBootNoUptimeRollback);
    assert(evaluate(500, true, 20, true, 0, false, 0, false)
           == PFBootUptimeRolledBack);
    printf("9/9 boot classifier tests passed\n");
    return 0;
}
