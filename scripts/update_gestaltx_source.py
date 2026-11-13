#!/usr/bin/env python3
"""Actualiza la fuente FlareStore con IPA oficiales de huamidev/GestaltX."""

import io
import json
import os
import plistlib
import re
import sys
from pathlib import Path
from urllib.request import Request, urlopen
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "gestaltx.json"
API = "https://api.github.com/repos/huamidev/GestaltX/releases?per_page=30"
BASE = "https://github.com/huamidev/GestaltX/releases/download/"
BUNDLE_ID = "com.huami.gestultx"


def get(url, binary=False):
    if url != API and not url.startswith(BASE):
        raise ValueError("La descarga no pertenece al GitHub oficial de GestaltX")
    headers = {"User-Agent": "ioezgamer-GestaltX-FlareStore/1.0"}
    if url == API and os.environ.get("GITHUB_TOKEN"):
        headers["Authorization"] = "Bearer " + os.environ["GITHUB_TOKEN"]
    with urlopen(Request(url, headers=headers), timeout=60) as response:
        data = response.read(100 * 1024 * 1024 + 1 if binary else 4 * 1024 * 1024)
    if binary and len(data) > 100 * 1024 * 1024:
        raise ValueError("IPA supera el limite de 100 MiB")
    return data


def ipa_metadata(blob):
    with ZipFile(io.BytesIO(blob)) as z:
        matches = [
            name for name in z.namelist()
            if re.fullmatch(r"Payload/[^/]+\.app/Info\.plist", name)
        ]
        if len(matches) != 1:
            raise ValueError("El IPA no contiene una app principal valida")
        info = plistlib.loads(z.read(matches[0]))
    return (
        str(info.get("CFBundleIdentifier", "")),
        str(info.get("CFBundleShortVersionString", "")),
        str(info.get("CFBundleVersion", "")),
        str(info.get("MinimumOSVersion", "")),
    )


def main():
    catalog = json.loads(SOURCE.read_text(encoding="utf-8"))
    app = catalog["apps"][0]
    if app["bundleIdentifier"] != BUNDLE_ID:
        raise ValueError("Bundle ID inesperado en el catalogo")
    releases = json.loads(get(API).decode("utf-8"))
    versions = app["versions"]
    latest_date = max((v["date"] for v in versions), default="")
    new = []
    for release in releases:
        if release.get("draft") or release.get("prerelease"):
            continue
        tag = release.get("tag_name", "")
        match = re.fullmatch(r"v?(\d+(?:\.\d+)+)", tag)
        if not match or (release.get("published_at") or "") <= latest_date:
            continue
        assets = [
            asset for asset in release.get("assets", [])
            if re.fullmatch(r"GestaltX.*\.ipa", asset.get("name", ""), re.I)
            and int(asset.get("size") or 0) > 0
        ]
        if len(assets) != 1:
            continue  # No inventar IPA cuando solo se publica un ZIP.
        asset = assets[0]
        link = asset["browser_download_url"]
        if not link.startswith(BASE + tag + "/"):
            raise ValueError("URL de descarga no coincide con la version")
        if any(v["downloadURL"] == link for v in versions):
            continue
        blob = get(link, binary=True)
        if len(blob) != int(asset["size"]):
            raise ValueError("Tamano del IPA incompatible con GitHub")
        bundle, version, build, min_ios = ipa_metadata(blob)
        if bundle != BUNDLE_ID or version != match.group(1) or not build:
            raise ValueError("El IPA no coincide con el ID/version publicados")
        if any(v["version"] == version and v.get("buildVersion") == build for v in versions):
            continue
        body = (release.get("body") or "").replace(chr(96), "").strip()
        new.append({
            "version": version,
            "buildVersion": build,
            "date": release["published_at"],
            "localizedDescription": body[:1200] or "Detalles disponibles en el release oficial.",
            "downloadURL": link,
            "size": len(blob),
            "minOSVersion": "27.0",  # Compatibilidad MobileGestalt declarada por el autor.
        })
    if not new:
        print("Sin versiones nuevas con IPA oficial.")
        return
    app["versions"] = sorted(
        versions + new, key=lambda v: (v["date"], v["version"]), reverse=True
    )
    SOURCE.write_text(json.dumps(catalog, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print("Actualizadas:", ", ".join(v["version"] for v in new))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print("Fallo:", exc, file=sys.stderr)
        sys.exit(1)
