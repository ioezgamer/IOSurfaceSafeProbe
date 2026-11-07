#!/usr/bin/env python3
"""Verify fixed code invariants in an extracted iPhone14,3 IOSurface diff artifact.
Usage: python3 scripts/verify_iosurface_lifecycle.py IOSurface-iPhone14-3-code-context.zip
This is a static binary comparison, not a CVE exploit or proof of CVE attribution.
"""
import json
import re
import sys
import zipfile

def verify(archive):
    with zipfile.ZipFile(archive) as z:
        data = json.loads(z.read("instruction-contexts.json"))
    assert data["device"] == "iPhone14,3"
    assert data["old_build"] == "24A437"
    assert data["new_build"] == "24B119"
    regions = {r["region"]: r for r in data["regions"]}
    assert len(regions) == 4

    def lines(region, side):
        return [row["asm"] for row in regions[region][side + "_window"]]

    def has(region, side, expression):
        return any(re.search(expression, line) for line in lines(region, side))

    def call_after_field_load(region, side):
        rows = lines(region, side)
        for i, line in enumerate(rows[:-1]):
            if re.search(r"\bldr\s+x0, \[x0, #0x150\]", line):
                m = re.search(r"\bbl\s+(0x[0-9a-f]+)", rows[i + 1])
                if m:
                    return m.group(1)
        return None

    old_clean = lines(4, "old")
    new_clean = lines(3, "new")
    old_B = next((i for i, line in enumerate(old_clean)
                  if "bl\t0xfffffff009c16074" in line), -1)
    new_B = next((i for i, line in enumerate(new_clean)
                  if "bl\t0xfffffff009c56014" in line), -1)

    checks = {
        "A_uses_x3_for_state_field": has(1,"new",r"\bmov\s+x21, x3"),
        "B_uses_x1_for_state_field": has(2,"new",r"\bmov\s+x20, x1"),
        "A_checks_0xf1": has(1,"new",r"\bldrb\s+w8, \[x21, #0xf1\]") and has(1,"new",r"\btbz\s+w8, #0x0"),
        "B_sets_0xf1": has(2,"new",r"\bmov\s+w8, #0x1") and has(2,"new",r"\bstrb\s+w8, \[x20, #0xf1\]"),
        "A_old_no_0xf1_check": not has(1,"old",r"\bldrb\s+w8, \[x21, #0xf1\]"),
        "B_old_no_0xf1_write": not has(2,"old",r"\bstrb\s+w8, \[x20, #0xf1\]"),
        "C_calls_B_in_new": has(3,"new",r"\bbl\s+0xfffffff009c56014"),
        "C_called_B_in_old": has(4,"old",r"\bbl\s+0xfffffff009c16074"),
        "A_B_share_old_helper": call_after_field_load(1,"old") is not None and call_after_field_load(1,"old") == call_after_field_load(2,"old"),
        "A_B_share_new_helper": call_after_field_load(1,"new") is not None and call_after_field_load(1,"new") == call_after_field_load(2,"new"),
        "C_old_calls_B_after_cleanup": old_B >= 0 and any("bl\t0xfffffff009c18620" in s for s in old_clean[:old_B]),
        "C_new_calls_B_before_cleanup": new_B >= 0 and any("bl\t0xfffffff009c585c8" in s for s in new_clean[new_B+1:]),
    }
    result = {"device":"iPhone14,3","old":"24A437","new":"24B119",
              "checks":checks,"verified":sum(checks.values()),
              "total":len(checks),
              "functional_link_verified":all(checks.values()),
              "CVE_specific_attribution":"NOT_CONFIRMED",
              "no_exploitation":True}
    print(json.dumps(result,indent=2))
    return all(checks.values())

if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: python3 scripts/verify_iosurface_lifecycle.py comparison-artifact.zip")
    raise SystemExit(0 if verify(sys.argv[1]) else 1)
