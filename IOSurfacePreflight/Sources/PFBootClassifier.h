#ifndef PF_BOOT_CLASSIFIER_H
#define PF_BOOT_CLASSIFIER_H

#include <stdbool.h>
#include <math.h>

// Compare two app-visible uptime samples. A boottime epoch is NOT a reliable
// reboot identifier: clock corrections can change its value within one boot.
typedef enum {
    PFBootIndeterminate = 0,
    PFBootNoUptimeRollback = 1,
    PFBootBootEpochChangedUnconfirmed = 2,
    PFBootUptimeRolledBack = 3
} PFBootResult;

static inline PFBootResult PFDetermineBoot(
    double previousUptime, bool hasPreviousUptime,
    double currentUptime, bool hasCurrentUptime,
    double previousBootEpoch, bool hasPreviousBootEpoch,
    double currentBootEpoch, bool hasCurrentBootEpoch) {

    if (!hasPreviousUptime || !hasCurrentUptime ||
        !isfinite(previousUptime) || !isfinite(currentUptime) ||
        previousUptime < 0 || currentUptime < 0) {
        return PFBootIndeterminate;
    }

    // systemUptime should be monotonic within a boot. Allow a 5-second
    // observation margin. A rollback is evidence of a reboot, not its cause.
    if (previousUptime > currentUptime + 5.0) {
        return PFBootUptimeRolledBack;
    }

    // An epoch shift without uptime rollback is inconclusive. A reboot could
    // also go undetected if the second sample was taken much later.
    if (hasPreviousBootEpoch && hasCurrentBootEpoch &&
        isfinite(previousBootEpoch) && isfinite(currentBootEpoch) &&
        fabs(previousBootEpoch - currentBootEpoch) > 60.0) {
        return PFBootBootEpochChangedUnconfirmed;
    }
    return PFBootNoUptimeRollback;
}

static inline const char *PFBootResultName(PFBootResult result) {
    switch (result) {
        case PFBootUptimeRolledBack: return "UPTIME_ROLLBACK_REBOOT_INDICATED";
        case PFBootBootEpochChangedUnconfirmed: return "BOOT_EPOCH_SHIFT_UNCONFIRMED";
        case PFBootNoUptimeRollback: return "NO_UPTIME_ROLLBACK_OBSERVED";
        default: return "INDETERMINATE";
    }
}

#endif
