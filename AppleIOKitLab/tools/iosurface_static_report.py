#!/usr/bin/env python3
"""Summarize exact-build 24A437 IOSurface extraction without guessing addresses."""
import hashlib
import json
import os
from pathlib import Path
import struct
import sys

ROOT=Path(sys.argv[1])
OUT=ROOT/"report"
OUT.mkdir(parents=True,exist_ok=True)

def info(path):
    data=path.read_bytes()
    res={"name":path.name,"size":len(data),"sha256":hashlib.sha256(data).hexdigest(),
         "macho":data[:4]==b"\xcf\xfa\xed\xfe","uuid":None,"segments":[]}
    if not res["macho"] or len(data)<32: return res
    vals=struct.unpack_from("<8I",data,0)
    res["cpu"]=hex(vals[1]);res["subtype"]=hex(vals[2]);res["filetype"]=hex(vals[3])
    pos=32
    for _ in range(min(vals[4],2000)):
        if pos+8>len(data):break
        cmd,size=struct.unpack_from("<II",data,pos)
        if size<8 or pos+size>len(data):break
        if cmd==0x1b and size>=24:
            b=data[pos+8:pos+24].hex()
            res["uuid"]="-".join([b[:8],b[8:12],b[12:16],b[16:20],b[20:]]).upper()
        if cmd==0x19 and size>=72:
            name=data[pos+8:pos+24].rstrip(b"\0").decode(errors="replace")
            vaddr,vsize,off,flen=struct.unpack_from("<4Q",data,pos+24)
            res["segments"].append({"name":name,"va":hex(vaddr),"size":vsize,
                                    "file_offset":off,"file_size":flen})
        if cmd==2 and size>=24:
            res["symbol_count"]=struct.unpack_from("<I",data,pos+12)[0]
        pos+=size
    return res

files=[p for p in (ROOT/"extracted").rglob("*") if p.is_file()] if (ROOT/"extracted").exists() else []
kc=sorted([p for p in files if "kernelcache." in p.name],key=lambda p:p.stat().st_size,reverse=True)
files=[p for p in (ROOT/"kexts").rglob("*") if p.is_file()] if (ROOT/"kexts").exists() else []
kext=[p for p in files if "iosurface" in p.name.lower()]
res={
    "target":"iPhone14,3 iOS27.0 build24A437",
    "source_url":"https://updates.cdn-apple.com/2026FallFCS/73d1826d-b08b-404a-92b6-94249593de65/iPhone14,3_27.0_24A437_Restore.ipsw",
    "github_run_id":os.getenv("GITHUB_RUN_ID",""),
    "kernel":info(kc[0]) if kc else None,
    "iosurface":info(kext[0]) if kext else None,
    "symbol_map":None,
    "iosurface_symbols":[],
}
symfiles=list((ROOT/"symbols").rglob("*.symbols.json")) if (ROOT/"symbols").exists() else []
if symfiles:
    s=symfiles[0]
    res["symbol_map"]={"file":s.name,"size":s.stat().st_size}
    if s.stat().st_size<120_000_000:
        try:
            sym=json.loads(s.read_text())
            hits=[]
            def visit(obj,addr=None,level=0):
                if level>5 or len(hits)>300:return
                if isinstance(obj,str):
                    if "IOSurface" in obj and any(x in obj.lower() for x in
                         ("lookup","retain","userclient","externalmethod","find_surface","s_get_limits")):
                        hits.append({"address":addr,"symbol":obj[:250]})
                elif isinstance(obj,dict):
                    for k,v in obj.items():visit(v,k if addr is None else addr,level+1)
                elif isinstance(obj,list):
                    for v in obj:visit(v,addr,level+1)
            visit(sym)
            res["iosurface_symbols"]=hits
        except Exception as e:res["symbol_error"]=str(e)

(OUT/"facts.json").write_text(json.dumps(res,indent=2,ensure_ascii=False))
rows=["# Análisis del binario IOSurface: build 24A437","",
      "Dispositivo: iPhone14,3. Fuente: Apple CDN.",
      "Ejecución GitHub Actions: "+str(res["github_run_id"]),"",
      "## Identidad de archivos obtenidos"]
for key in ("kernel","iosurface"):
    data=res[key]
    rows+=["", "### "+key]
    if data:
        for field in ("name","size","sha256","macho","uuid","cpu","filetype","symbol_count"):
            if field in data:rows.append("- "+field+": "+str(data[field]))
    else:
        rows.append("NO OBTENIDO. No se afirman conclusiones de análisis estático.")
rows+=["","## Métodos y evidencia", "",
    "Los reportes de la herramienta ipsw y los datos crudos están incluidos en el artefacto.",
    "Los resultados previos de nuestro iPhone son: selector 6 OK, selector 4 0xe00002c2;",
    "selectores 2, 3, 9 y 10 OK, con comprobación de lectura del valor propio.",
    "Esta información dinámica no basta para identificar la instrucción que rechazó selector 4.",
    "",
    "## Criterio de atribución", "",
    "Solamente una tabla de despacho y una traza estática verificables para este binario",
    "pueden atribuir el rechazo a comprobación de argumentos, ID o permisos.",
    "Sin esos elementos, queda SIN DETERMINAR. No existe prueba de KernelRW ni jailbreak."]
(OUT/"README_AUDITORIA.md").write_text("\n".join(rows)+"\n")
print(json.dumps({k:len(v) if k=="iosurface_symbols" else v
    for k,v in res.items() if k!="source_url"},indent=2))
