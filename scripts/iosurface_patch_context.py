#!/usr/bin/env python3
"""Map already-observed ARM64 IOSurface changes to full instructions and symbols.

Static code comparison only. It does not attempt to trigger a bug or access a device.
"""
import bisect
import json
import pathlib
import re

ROOT = pathlib.Path("cmp")
OUT = ROOT / "out"

INS = re.compile(r"^\s*(?:0x)?([0-9a-fA-F]{8,16}):\s*(?:[0-9a-fA-F]{8}\s+)?([a-zA-Z][\w.]*)\b(.*)$")
LAB = re.compile(r"^([^\s:][^:]{2,200}):\s*$")

def read_asm(which):
    original = (ROOT / (which + ".asm")).read_text(errors="replace").splitlines()
    instructions = []
    label_marks = []
    for line in original:
        m = INS.match(line)
        if m:
            instructions.append({
                "index": len(instructions) + 1,
                "address": int(m.group(1), 16),
                "mnemonic": m.group(2).lower(),
                "asm": line.strip(),
            })
            continue
        lab = LAB.match(line)
        if lab:
            label_marks.append((len(instructions), lab.group(1)))
    return instructions, label_marks

def nearest_label(labels, one_index):
    if not labels:
        return None
    i = bisect.bisect_right([n for n, _ in labels], one_index - 1) - 1
    return labels[i][1] if i >= 0 else None

def around(rows, one_index, length, margin=24):
    lo = max(0, one_index - 1 - margin)
    hi = min(len(rows), one_index - 1 + length + margin)
    return rows[lo:hi]

def changed_hunks(diff_text):
    result = []
    block = None
    for line in diff_text.splitlines():
        m = re.match(r"^@@ -(\d+),(\d+) \+(\d+),(\d+) @@", line)
        if m:
            if block:
                result.append(block)
            block = {
                "header": line,
                "old_start": int(m.group(1)),
                "new_start": int(m.group(3)),
                "removed": [], "added": [],
            }
            continue
        if not block:
            continue
        if line.startswith("--- ") or line.startswith("+++ "):
            continue
        if line.startswith("-"):
            block["removed"].append(line[1:].strip())
        elif line.startswith("+"):
            block["added"].append(line[1:].strip())
    if block:
        result.append(block)
    return result

def full_changed_mapping(hunk, old_rows, new_rows):
    return {
        "old": around(old_rows, hunk["old_start"], 22, margin=18),
        "new": around(new_rows, hunk["new_start"], 25, margin=18),
    }

def print_region(region, mapping, old_labels, new_labels):
    lines = [
        "## Region %d" % region["region"],
        "",
        "Opcode-only diff: " + region["hunk_header"],
        "",
        "Removed opcodes: " + ", ".join(region["removed"]),
        "",
        "Added opcodes: " + ", ".join(region["added"]),
        "",
    ]
    for side, labels in (("old", old_labels), ("new", new_labels)):
        rows = mapping[side]
        label = nearest_label(labels, region[side + "_start"])
        lines += [
            "### " + ("iOS 27.0" if side == "old" else "iOS 27.2"),
            "Nearest symbol/label: " + str(label or "NOT_PRESENT_IN_DISASSEMBLY"),
            "",
            "~~~asm",
        ]
        lines.extend(r["asm"] for r in rows)
        lines.append("~~~")
        lines.append("")
    return "\n".join(lines)

def main():
    old, oldlabels = read_asm("old")
    new, newlabels = read_asm("new")
    source = (OUT / "mnemonic-hunks.txt").read_text()
    hunks = changed_hunks(source)
    if len(hunks) != 4:
        raise RuntimeError(f"Expected four change regions; got {len(hunks)}")
    expected = json.loads((OUT / "hunk-addresses.json").read_text())
    regions = []
    chunks = [
        "# IOSurface ARM64 patch contexts: iPhone14,3 24A437 vs 24B119",
        "",
        "Static binary disassembly, generated from original firmware for the same model.",
        "The opcodes and addresses do not establish a link to CVE-2026-112477.",
        "Labels are reported only if actually present in the extracted KEXT.",
        "",
    ]
    for n, (h, pos) in enumerate(zip(hunks, expected["regions"]), 1):
        if pos["old_start_instruction"] != h["old_start"] or pos["new_start_instruction"] != h["new_start"]:
            raise RuntimeError("Hunk locations disagree with previous artifact")
        mapping = full_changed_mapping(h, old, new)
        record = {
            "region": n,
            "hunk_header": h["header"],
            "old_start": h["old_start"],
            "new_start": h["new_start"],
            "old_nearest_symbol": nearest_label(oldlabels, h["old_start"]),
            "new_nearest_symbol": nearest_label(newlabels, h["new_start"]),
            "removed": h["removed"],
            "added": h["added"],
            "old_window": mapping["old"],
            "new_window": mapping["new"],
        }
        regions.append(record)
        chunks.append(print_region(record, mapping, oldlabels, newlabels))
    summary = {
        "device": "iPhone14,3",
        "old_build": "24A437",
        "new_build": "24B119",
        "old_parsed_instructions": len(old),
        "new_parsed_instructions": len(new),
        "old_disassembly_labels": len(oldlabels),
        "new_disassembly_labels": len(newlabels),
        "regions": regions,
        "cve_attribution": "NOT_ESTABLISHED",
    }
    OUT.mkdir(exist_ok=True)
    (OUT / "instruction-contexts.json").write_text(json.dumps(summary, indent=2))
    (OUT / "instruction-contexts.md").write_text("\n".join(chunks))
    print(json.dumps({
        "old_instructions": len(old),
        "new_instructions": len(new),
        "labels_old": len(oldlabels),
        "labels_new": len(newlabels),
        "region_symbols": [
            (x["region"], x["old_nearest_symbol"], x["new_nearest_symbol"])
            for x in regions
        ],
    }, indent=2))
    print("\n".join(chunks)[:23000])

if __name__ == "__main__":
    main()
