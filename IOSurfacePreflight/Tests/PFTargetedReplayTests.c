#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include "../Sources/PFTargetedReplay.h"

int main(void) {
    const char *row[]={
        "RUN", "2819904857", "114", "16", "16", "4", "64", "1024",
        "0x42475241", "0", "0", "221", "16", "16", "16", "64",
        "1024", "OK", "PASS", "ACCEPTED", "BGRA_REQUESTED",
        "ELIGIBLE", "245"
    };
    PFTargetedCase c={0};
    assert(PFReplayParseCSV(row,PF_REPLAY_COLS,&c));
    assert(c.caseNumber==114 && c.candidateIndex==245);
    assert(c.seed==2819904857U && c.format==0x42475241U);
    assert(c.originallyAccepted);
    assert(PFReplaySameOutcome(&c,true,16,16,64,1024));
    assert(!PFReplaySameOutcome(&c,true,16,16,64,2048));
    assert(!PFReplaySameOutcome(&c,false,0,0,0,0));
    const char *badRange[PF_REPLAY_COLS];
    for(unsigned i=0;i<PF_REPLAY_COLS;i++) badRange[i]=row[i];
    badRange[3]="65535";
    assert(!PFReplayParseCSV(badRange,PF_REPLAY_COLS,&c));
    badRange[3]="16";
    badRange[9]="2";
    assert(!PFReplayParseCSV(badRange,PF_REPLAY_COLS,&c));
    badRange[9]="0";
    badRange[8]="0x00000001";
    assert(!PFReplayParseCSV(badRange,PF_REPLAY_COLS,&c));
    badRange[8]="0x42475241";
    badRange[19]="NS_EXCEPTION";
    assert(!PFReplayParseCSV(badRange,PF_REPLAY_COLS,&c));
    badRange[19]="REJECTED";
    badRange[13]="0";badRange[14]="0";badRange[15]="0";badRange[16]="0";
    assert(PFReplayParseCSV(badRange,PF_REPLAY_COLS,&c));
    assert(!c.originallyAccepted);
    assert(PFReplaySameOutcome(&c,false,0,0,0,0));
    assert(!PFReplaySameOutcome(&c,true,16,16,64,1024));
    assert(!PFReplayParseCSV(badRange,22,&c));
    puts("Targeted replay CSV parsing, bounds and outcome comparisons: PASS");
    return 0;
}
