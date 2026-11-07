#!/usr/bin/env python3
"""Read-only inspection of IOSurface kernel-extension metadata for IPC locking.

The output reports evidence, not a live bit-field value from the running kernel.
"""
import argparse
import hashlib
import json
import pathlib
import re

def analyze(path):
    data = path.read_bytes()
    needles = {
        "IOUserClientDefaultLocking": b"IOUserClientDefaultLocking",
        "IOUserClientDefaultLockingSetProperties": b"IOUserClientDefaultLockingSetProperties",
        "IOUserClientDefaultLockingSingleThreadExternalMethod": b"IOUserClientDefaultLockingSingleThreadExternalMethod",
        "IOUserClient2022": b"IOUserClient2022",
        "IOSurfaceRootUserClient": b"IOSurfaceRootUserClient",
        "IOUserClient": b"IOUserClient",
    }
    matches = {}
    for label, needle in needles.items():
        locations = [m.start() for m in re.finditer(re.escape(needle), data)]
        matches[label] = {"present": bool(locations), "count": len(locations), "offsets": locations[:30]}
    return {"file": path.name, "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(), "literal_occurrences": matches}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("old")
    ap.add_argument("new")
    ap.add_argument("--output", required=True)
    args = ap.parse_args()
    old, new = pathlib.Path(args.old), pathlib.Path(args.new)
    findings = {"source": "KEXT Mach-O bytes extracted from official iPhone14,3 kernelcaches",
                "old_build": "24A437", "new_build": "24B119",
                "IOSurface_KEXT_is_its_own_identifier": True,
                "xnu_exception": "No implicit defaultLocking when owner KEXT hasDependency(IOSurface) and no property set",
                "xnu_hasDependency_matches_own_identifier": True,
                "live_defaultLocking_bit_proven": False,
                "limitation": "Absence of a constant-string literal is not proof that no runtime property is ever set",
                "old": analyze(old), "new": analyze(new)}
    out = pathlib.Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(findings, indent=2))
    print(json.dumps(findings, indent=2))

if __name__ == "__main__":
    main()
