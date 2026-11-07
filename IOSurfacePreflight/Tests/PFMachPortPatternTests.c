#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "../Sources/PFMachPortPattern.h"

int main(void) {
    uint8_t buf[PF_HANDOFF_BYTES + 2];
    memset(buf, 0xA5, sizeof(buf));
    assert(!PFHandoffFill(NULL, PF_HANDOFF_BYTES));
    assert(!PFHandoffFill(buf, PF_HANDOFF_BYTES - 1));
    assert(buf[0] == 0xA5);
    assert(PFHandoffFill(buf, PF_HANDOFF_BYTES));
    assert(buf[PF_HANDOFF_BYTES] == 0xA5 && buf[PF_HANDOFF_BYTES + 1] == 0xA5);
    assert(buf[3] == 255);
    assert(buf[PF_HANDOFF_STRIDE * 127 + 127 * 4 + 3] == 255);
    uint64_t before = PFHandoffHash(buf, PF_HANDOFF_BYTES);
    assert(before != 0);
    assert(!PFHandoffStamp(buf, PF_HANDOFF_BYTES - 1));
    assert(PFHandoffStamp(buf, PF_HANDOFF_BYTES));
    assert(PFHandoffHash(buf, PF_HANDOFF_BYTES) != before);
    assert(buf[8 * PF_HANDOFF_STRIDE + 8 * 4] == 255);
    assert(buf[8 * PF_HANDOFF_STRIDE + 8 * 4 + 2] == 0);
    assert(buf[PF_HANDOFF_BYTES] == 0xA5 && buf[PF_HANDOFF_BYTES + 1] == 0xA5);
    puts("PFMachPortPatternTests PASS");
    return 0;
}
