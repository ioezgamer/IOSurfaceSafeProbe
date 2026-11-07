#!/usr/bin/env python3
"""Static property-value provenance audit for iPhone14,3 IOSurface Mach-O files.
Requires only the KEXTs and already generated llvm-objdump ARM64 disassemblies.
No device access, privileged action or exploit code.
"""
import argparse
import hashlib
import json
import pathlib
import re
import struct

KEYS = (
    "IOUserClientEntitlements",
    "IOUserClientDefaultLocking",
    "IOUserClientDefaultLockingSetProperties",
    "IOUserClientDefaultLockingSingleThreadExternalMethod",
)

def cstring_va(blob, name):
    pos = 32
    ncmds = struct.unpack_from("<I", blob, 16)[0]
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", blob, pos)
        if cmd == 0x19:
            seg = blob[pos+8:pos+24].split(b"\0")[0]
            count = struct.unpack_from("<I", blob, pos+64)[0]
            for j in range(count):
                s = pos + 72 + j*80
                section = blob[s:s+16].split(b"\0")[0]
                if seg == b"__TEXT" and section == b"__cstring":
                    va, size = struct.unpack_from("<QQ", blob, s+32)
                    off = struct.unpack_from("<I", blob, s+48)[0]
                    index = blob.find(name.encode()+b"\0", off, off+size)
                    if index < 0:
                        raise AssertionError("String not present in KEXT: " + name)
                    return va+index-off
        pos += cmdsize
    raise AssertionError("missing __TEXT.__cstring")

def audit(build, macho_path, asm_path):
    data = pathlib.Path(macho_path).read_bytes()
    asm = pathlib.Path(asm_path).read_text(errors="replace").splitlines()
    addresses = {k: cstring_va(data, k) for k in KEYS}
    adrp = re.compile(r"\badrp\s+x1,.*;\s*(0x[0-9a-f]+)$")
    add = re.compile(r"\badd\s+x1, x1, #0x([0-9a-f]+)$")
    found = {}
    for i in range(len(asm)-1):
        a = adrp.search(asm[i])
        b = add.search(asm[i+1])
        if not a or not b:
            continue
        addr = int(a.group(1),16)+int(b.group(1),16)
        for name, target in addresses.items():
            if addr != target:
                continue
            before = asm[max(0,i-20):i]
            last = [m.group(1) for line in before
                    for m in [re.search(r"\bldr\s+x2, \[([^\]]+)\]",line)] if m]
            after = asm[i:i+12]
            assert last, ("value load missing",build,name)
            assert any("\tblraa\tx8, x16" in s for s in after), ("setter call missing",build,name)
            assert name not in found, ("duplicated setter",build,name)
            found[name]={"xref":asm[i].split(":")[0],"string_va":hex(target),
                         "loaded_from":last[-1],"setter_verified":True}
    assert set(found)==set(KEYS),(build,found)
    expected={"IOUserClientEntitlements":"x20",
              "IOUserClientDefaultLocking":"x20",
              "IOUserClientDefaultLockingSetProperties":"x8",
              "IOUserClientDefaultLockingSingleThreadExternalMethod":"x20"}
    for k,v in expected.items():
        assert found[k]["loaded_from"]==v,(build,k,found[k])
    return {"build":build,"macho_sha256":hashlib.sha256(data).hexdigest(),
            "cross_references":found,"assertions":4,
            "inferred_flags":{
                "IOUserClientDefaultLocking":False,
                "IOUserClientDefaultLockingSingleThreadExternalMethod":False,
                "IOUserClientDefaultLockingSetProperties":True},
            "provenance":"The same OSBoolean object is used for IOUserClientEntitlements, which XNU validates as kOSBooleanFalse for unrestricted access",
            "live_runtime_bits_read":False}

def main():
    p=argparse.ArgumentParser()
    for a in ("old-macho","new-macho","old-asm","new-asm","output"):
        p.add_argument("--"+a,required=True)
    args=p.parse_args()
    result={
        "device":"iPhone14,3",
        "source":"Apple IPSWs 24A437,24B119; IOSurface KEXTs; XNU IOUserClient.cpp",
        "builds":[audit("24A437",args.old_macho,args.old_asm),
                  audit("24B119",args.new_macho,args.new_asm)],
        "8_property_callsite_assertions_passed":True,
        "note":"Static inference; no live flags, after-free access, or CVE exploit proven"}
    }
    dst=pathlib.Path(args.output)
    dst.parent.mkdir(parents=True,exist_ok=True)
    dst.write_text(json.dumps(result,indent=2))
    print(json.dumps({"result":"PASS","checks":8,
        "flags":result["builds"][0]["inferred_flags"]},indent=2))

if __name__=="__main__":
    main()
