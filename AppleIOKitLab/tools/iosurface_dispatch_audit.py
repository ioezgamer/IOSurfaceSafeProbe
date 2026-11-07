#!/usr/bin/env python3
"""Reproduce the IOSurfaceRootUserClient selector-4 audit from iPhone14,3 24A437.

Reads Apple's extracted Mach-O files; verifies identity, dispatch-table record
layouts and exact machine-code fingerprints. No dynamic fuzzing or exploitation.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import struct
import sys

root = Path(sys.argv[1])
out = root / "report"
out.mkdir(parents=True, exist_ok=True)
kexts = list((root / "kexts").rglob("com.apple.iokit.IOSurface"))
kernel_files = list((root / "extracted").rglob("kernelcache.*"))
if not kexts or not kernel_files:
    raise SystemExit("No kernelcache/KEXT from exact IPSW, no code attribution")
kext, kc = kexts[0].read_bytes(), kernel_files[0].read_bytes()
expected_sha = "3f95c45f629a8749775765980434ee927552e1cad4e568743062bf901aa018d8"
digest = hashlib.sha256(kext).hexdigest()
if digest != expected_sha:
    raise SystemExit("Unexpected IOSurface binary SHA256; check firmware identity")
if kext[:4] != b"\xcf\xfa\xed\xfe" or kc[:4] != b"\xcf\xfa\xed\xfe":
    raise SystemExit("Mach-O header missing")

def macho_sections(b):
    _, cpu, subtype, kind, ncmds, cmdsbytes, flags, reserved = struct.unpack_from("<8I", b)
    pos, segs, sections = 32, [], []
    for _ in range(ncmds):
        cmd, n = struct.unpack_from("<II", b, pos)
        if n < 8 or pos+n > len(b):
            raise RuntimeError("invalid Mach-O commands")
        if cmd == 0x19:
            name = b[pos+8:pos+24].rstrip(b"\0").decode()
            vm, sz, fileoff, filesz = struct.unpack_from("<4Q", b, pos+24)
            segs.append({"name": name, "vmaddr": vm, "offset": fileoff, "size": filesz})
            ns = struct.unpack_from("<I", b, pos+64)[0]
            for j in range(ns):
                secpos = pos+72+j*80
                sec,seg,va,size,off = struct.unpack_from("<16s16sQQI", b, secpos)
                sections.append({"name":sec.split(b"\0")[0].decode(),
                                 "segment":seg.split(b"\0")[0].decode(),
                                 "vmaddr":va,"size":size,"offset":off})
        pos += n
    return segs, sections

kseg,_=macho_sections(kc)
base = next(s["vmaddr"] for s in kseg if s["name"] == "__TEXT")
ksegs, ksections = macho_sections(kext)
const = next(x for x in ksections if x["segment"] == "__DATA_CONST" and x["name"] == "__const")

def entry(off):
    word,si,stin,so,stout,asyncword,acl = struct.unpack_from("<QIIIIQQ", kext, off)
    return {
        "signed_handler_word": f"0x{word:016x}",
        "scalar_input":si,"structure_input_bytes":stin,
        "scalar_output":so,"structure_output_bytes":stout,
        "async":bool(asyncword&1),
        "access_word":f"0x{acl:016x}",
    }
pref=[(1,0xffffffff,0,3176),(1,0,0,0),(0,12,0,3176),
      (0,12,0,4),(1,0,0,3176),(2,0,0,0),(0,32,0,3176)]
candidates=[]
for start in range(const["offset"], const["offset"]+const["size"]-60*40+1, 8):
    if all(tuple(entry(start+i*40)[x] for x in
          ("scalar_input","structure_input_bytes","scalar_output","structure_output_bytes")) == t
           for i,t in enumerate(pref)):
        if entry(start+13*40)["structure_output_bytes"]==40 and entry(start+17*40)["async"]:
            candidates.append(start)
if len(candidates)!=2 or candidates[1]-candidates[0]!=60*40:
    raise SystemExit(f"Unexpected IOSurface method table candidates: {candidates}")
normal, restricted=candidates
records=[]
for i in range(60):
    a,b=entry(normal+40*i),entry(restricted+40*i)
    a.update({"selector":i,"different_in_restricted_table":
              a["signed_handler_word"]!=b["signed_handler_word"]})
    records.append(a)

# MH_FILESET uses DYLD_CHAINED_PTR_64_KERNEL_CACHE auth pointers.
# target=30 bits, cacheLevel=2 bits; cache level 0 refers to __TEXT VM base.
word=int(records[4]["signed_handler_word"],16)
target=word & ((1<<30)-1)
cachelevel=(word>>30)&3
auth=(word>>63)&1
if not auth or cachelevel!=0:
    raise SystemExit("Method pointer format not the observed auth kernel-cache format")
method4_thunk=base+target

def vm_bytes(address,size):
    for seg in ksegs:
        if seg["vmaddr"] <= address < seg["vmaddr"]+seg["size"]:
            off=seg["offset"]+(address-seg["vmaddr"])
            if off+size <= len(kext):
                return kext[off:off+size]
    raise RuntimeError(f"Address not mapped {address:#x}")

# Disassembly of this exact file identified these simple instructions.
# All fingerprints must match before attributing the gate to 24A437.
insns = {
    0xfffffff009c1903c:("hint #0x22","5f2403d5"),
    0xfffffff009c1904c:("b 0xfffffff009c1bbc0","dd0a0014"),
    0xfffffff009c1bbfc:("mov w19, #0x2bd","b3578052"),
    0xfffffff009c1bc00:("movk w19, #0xe000, lsl #16","1300bc72"),
    0xfffffff009c1bc18:("bl 0xfffffff009c1f5dc","710e0094"),
    0xfffffff009c1bc1c:("tbnz w0, #0, 0xfffffff009c1bd04","40070037"),
    0xfffffff009c1bd0c:("add w19, w19, #0x5","73160011"),
    0xfffffff009c1bd28:("mov x0, x19","e00313aa"),
    0xfffffff009c1f5ec:("cbz w1, 0xfffffff009c1f6a8","e1050034"),
    0xfffffff009c1f69c:("str x16, [x2]","500000f9"),
    0xfffffff009c1f6a0:("mov w0, #0x1","20008052"),
    0xfffffff009c1f6a8:("mov w0, #0x0","00008052"),
}
if method4_thunk != 0xfffffff009c1903c:
    raise SystemExit(f"Method 4 target mismatch: {method4_thunk:#x}")
for address,(op,hexbytes) in insns.items():
    if vm_bytes(address,4).hex()!=hexbytes:
        raise SystemExit(f"Fingerprint mismatch: {address:#x} {op}")

facts={
    "model":"iPhone14,3","ios":"27.0","build":"24A437",
    "kernel_sha256":hashlib.sha256(kc).hexdigest(),
    "iosurface_sha256":digest,"kernel_text_base":f"0x{base:016x}",
    "method_table_60_entries":{"normal_file_offset":f"0x{normal:x}",
        "restricted_file_offset":f"0x{restricted:x}",
        "entry_size":40,
        "restricted_changed_indices":[r["selector"] for r in records if r["different_in_restricted_table"]]},
    "selector4_record":records[4],
    "selector4_method_thunk":f"0x{method4_thunk:016x}",
    "selector4_implementation":"0xfffffff009c1bbc0",
    "own_surface_index_helper":"0xfffffff009c1f5dc",
    "verified_instructions":{f"0x{a:016x}":{"mnemonic":v[0],"bytes":v[1]} for a,v in insns.items()},
    "derived_return_code_when_helper_returns_1":"0xe00002bd + 5 = 0xe00002c2",
    "interpretation":"Selector 4 immediately returns kIOReturnBadArgument if the client already has this surface ID in its own index; it is not a universal own-ID lookup.",
    "limitations":"Exact dynamic execution branch was not traced, but the own-ID path is explicit in machine code. No arbitrary kernel memory access or jailbreak demonstrated.",
    "records":records,
}
(out/"iosurface-selector4-24A437.json").write_text(json.dumps(facts,indent=2)+"\n")
print(json.dumps({k:v for k,v in facts.items() if k not in ("records","verified_instructions")},indent=2))
