#!/usr/bin/env python3
"""Read-only, exact-build IOSurface lifecycle gate audit.

Usage: python3 iosurface_lifecycle_gate.py OLD_IOSURFACE NEW_IOSURFACE OUTPUT_DIR
No dynamic calls, races, memory access, or exploit generation.
Requires llvm-objdump (or IOSURFACE_OBJDUMP=/path/to/llvm-objdump).
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys

SPEC = {
 "old": {
  "build": "24A437",
  "sha": "3f95c45f629a8749775765980434ee927552e1cad4e568743062bf901aa018d8",
  "funcs": {799: 0xfffffff009c15e00, 802: 0xfffffff009c16074, 945: 0xfffffff009c1afec},
  "wrapper": 0xfffffff009c19604,
  "lock": 0xfffffff009c29b4c,
  "unlock": 0xfffffff009c29b6c,
 },
 "fixed": {
  "build": "24B119",
  "sha": "a1d255c31648eb54385b32cb51277a262b7d99c246a5195e591ae8d827b3275c",
  "funcs": {799: 0xfffffff009c55d90, 802: 0xfffffff009c56014, 945: 0xfffffff009c5af94},
  "wrapper": 0xfffffff009c595ac,
  "lock": 0xfffffff009c69af4,
  "unlock": 0xfffffff009c69b14,
 },
}
INS = re.compile(r"^([0-9a-f]{16}):\s+([a-z][a-z0-9.]*)\s*(.*?)\s*$")

def function_starts(blob):
    if blob[:4] != b"\xcf\xfa\xed\xfe":
        raise ValueError("Not a 64-bit little-endian Mach-O")
    ncmds = struct.unpack_from("<I",blob,16)[0]
    pos, starts_info, text_address = 32,None,None
    for _ in range(ncmds):
        cmd,size=struct.unpack_from("<II",blob,pos)
        if size<8 or pos+size>len(blob): raise ValueError("Bad load command")
        if cmd==0x26: starts_info=struct.unpack_from("<II",blob,pos+8)
        if cmd==0x19:
            n=struct.unpack_from("<I",blob,pos+64)[0]
            for k in range(n):
                at=pos+72+k*80
                sec,seg,vm,sz,off=struct.unpack_from("<16s16sQQI",blob,at)
                if sec.split(b"\0")[0]==b"__text" and seg.split(b"\0")[0]==b"__TEXT_EXEC":
                    text_address=vm
        pos+=size
    if starts_info is None or text_address is None:
        raise ValueError("No __TEXT_EXEC.__text or LC_FUNCTION_STARTS")
    off,sz=starts_info
    if off+sz>len(blob):raise ValueError("Function-start data exceeds file")
    p,end,cumulative=off,off+sz,0
    starts=[]
    while p<end:
        num,shift=0,0
        while True:
            if p>=end or shift>63:raise ValueError("Bad ULEB128")
            octet=blob[p];p+=1
            num|=(octet&127)<<shift
            if not octet&128:break
            shift+=7
        if not num:break
        cumulative+=num
        starts.append(cumulative)
    if len(starts)!=1330:raise ValueError(f"Unexpected function count {len(starts)}")
    base=text_address-starts[0]
    return {i:base+v for i,v in enumerate(starts)}

def disass(path,start,end):
    tool=os.environ.get("IOSURFACE_OBJDUMP") or shutil.which("llvm-objdump")
    if not tool:raise RuntimeError("llvm-objdump unavailable")
    p=subprocess.run([tool,"--disassemble","--no-show-raw-insn",
        f"--start-address={start:#x}", f"--stop-address={end:#x}",str(path)],
        check=True,text=True,capture_output=True)
    out=[]
    for line in p.stdout.splitlines():
        m=INS.match(line)
        if m and start<=int(m[1],16)<end:
            out.append((int(m[1],16),m[2],m[3].split(";")[0].strip()))
    if not out or out[0][0]!=start:raise AssertionError(f"No code at {start:#x}")
    return out

def positions(lines,mnemonic,operand):
    return [i for i,(_,mn,op) in enumerate(lines) if mn==mnemonic and op==operand]

def exactly_one(lines,mnemonic,operand):
    found=positions(lines,mnemonic,operand)
    if len(found)!=1:raise AssertionError(f"Expected one {mnemonic} {operand}, found {len(found)}")
    return found[0]

def verify(path,spec):
    data=path.read_bytes()
    digest=hashlib.sha256(data).hexdigest()
    if digest!=spec["sha"]:raise AssertionError(f"Unexpected build SHA-256: {digest}")
    starts=function_starts(data)
    for idx,addr in spec["funcs"].items():
        if starts[idx]!=addr:raise AssertionError(f"Wrong function {idx}: {starts[idx]:#x}")
    record={}
    for idx,start in spec["funcs"].items():
        record[idx]=disass(path,start,starts[idx+1])
    reg,sweep,close=record[799],record[802],record[945]
    wrapper=disass(path,spec["wrapper"],spec["wrapper"]+0x24)
    exactly_one(wrapper,"mov","x3, x0")
    exactly_one(wrapper,"ldr","x0, [x0, #0xe8]")
    exactly_one(reg,"mov","x21, x3")
    exactly_one(reg,"mov","x19, x0")
    exactly_one(sweep,"mov","x20, x1")
    exactly_one(sweep,"mov","x19, x0")
    exactly_one(close,"mov","x20, x0")
    exactly_one(close,"ldr","x0, [x20, #0xe8]")
    exactly_one(close,"mov","x1, x20")
    lock_reg=exactly_one(reg,"bl",hex(spec["lock"]))
    unlock_reg=exactly_one(reg,"bl",hex(spec["unlock"]))
    lock_sweep=exactly_one(sweep,"bl",hex(spec["lock"]))
    unlock_sweep=exactly_one(sweep,"b",hex(spec["unlock"]))
    exactly_one(reg,"ldr","x0, [x0, #0x150]")
    exactly_one(sweep,"ldr","x0, [x0, #0x150]")
    list_reg=exactly_one(reg,"ldr","x8, [x19, #0x188]")
    list_sweep=exactly_one(sweep,"ldr","x21, [x19, #0x188]")
    assert lock_reg<list_reg<unlock_reg
    assert lock_sweep<list_sweep<unlock_sweep
    guard=positions(reg,"ldrb","w8, [x21, #0xf1]")
    mark=positions(sweep,"strb","w8, [x20, #0xf1]")
    calls=[(i,op) for i,(_,mn,op) in enumerate(close) if mn=="bl"]
    sweep_calls=[i for i,op in calls if op.startswith(f"{spec['funcs'][802]:#x} ")]
    if len(sweep_calls)!=1:raise AssertionError("Teardown sweep call not unique")
    early=not any(i<sweep_calls[0] for i,op in calls)
    if spec["build"]=="24B119":
        assert len(guard)==len(mark)==1
        g=guard[0]
        assert reg[g+1][1]=="tbz" and reg[g+1][2].startswith("w8, #0x0, ")
        assert lock_reg<g<list_reg
        m=mark[0]
        assert lock_sweep<m<list_sweep
        assert positions(sweep,"mov","w8, #0x1")
        assert early
    else:
        assert not guard and not mark and not early
    return {
        "build":spec["build"], "iosurface_sha256":digest,
        "function_count":len(starts),
        "functions":{str(i):f"0x{x:016x}" for i,x in spec["funcs"].items()},
        "client_from_registration_wrapper_x3":True,
        "manager_pointer_offset":"0xe8","manager_lock_offset":"0x150",
        "manager_list_offset":"0x188","client_state_offset":"0xf1",
        "registration_guard":bool(guard),"sweep_marks_state":bool(mark),
        "teardown_sweeps_first":early,
        "instructions":{str(i):len(v) for i,v in record.items()},
    }

def main():
    if len(sys.argv)!=4:raise SystemExit(__doc__)
    old,new,out=map(Path,sys.argv[1:])
    out.mkdir(parents=True,exist_ok=True)
    old_fact=verify(old,SPEC["old"])
    new_fact=verify(new,SPEC["fixed"])
    assert old_fact["registration_guard"] is False
    assert new_fact["registration_guard"] is True
    assert old_fact["sweep_marks_state"] is False
    assert new_fact["sweep_marks_state"] is True
    assert old_fact["teardown_sweeps_first"] is False
    assert new_fact["teardown_sweeps_first"] is True
    facts={
       "validated_builds":[old_fact,new_fact],
       "confirmed":"The 24B119 client state guard/mark and cleanup order differ from 24A437 under matching lock/list locations.",
       "CVE_attribution_proven":False,
       "memory_corruption_proven":False,
       "kernel_RW_proven":False,
       "exploit_generated":False
    }
    (out/"lifecycle_gate.json").write_text(json.dumps(facts,indent=2)+"\n")
    (out/"VERIFIED.txt").write_text(
      "PASS: original KEXT hashes; 1330 function starts each\n"
      "PASS: registration/cleanup client identity and manager lock/list\n"
      "PASS: corrected build adds state guard and mark under lock\n"
      "PASS: corrected build sweeps before remaining teardown calls\n"
      "NOT PROVEN: memory corruption, CVE attribution, KernelRW or jailbreak\n")
    print((out/"VERIFIED.txt").read_text())
if __name__=="__main__":main()
