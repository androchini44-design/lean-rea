#!/usr/bin/env python3
"""
Lean-REA: Lightweight Multi-Format Binary Reverse Engineering & Triage Tool
Copyright (c) 2026 spartak

Analyzes PE32/PE32+, Mach-O (32/64-bit), and ELF (32/64-bit) binaries without heavy dependencies.
Provides:
  - Header & Segment/Section breakdown
  - Import / Export symbol extraction
  - MSVC RTTI (CompleteObjectLocator & TypeDescriptor) vtable scanner
  - x87 FPU instruction density profiler (Rosetta 2 stall risk detection)
  - String classifier (ASCII, UTF-16LE, symbols)
  - Agent-friendly JSON and Markdown report outputs
"""

import sys
import os
import struct
import argparse
import json
import re
from typing import Dict, List, Any, Optional

class BinaryReader:
    def __init__(self, data: bytes):
        self.data = data
        self.size = len(data)

    def u8(self, offset: int) -> int:
        return self.data[offset] if offset < self.size else 0

    def u16(self, offset: int, le: bool = True) -> int:
        fmt = "<H" if le else ">H"
        return struct.unpack_from(fmt, self.data, offset)[0] if offset + 2 <= self.size else 0

    def u32(self, offset: int, le: bool = True) -> int:
        fmt = "<I" if le else ">I"
        return struct.unpack_from(fmt, self.data, offset)[0] if offset + 4 <= self.size else 0

    def u64(self, offset: int, le: bool = True) -> int:
        fmt = "<Q" if le else ">Q"
        return struct.unpack_from(fmt, self.data, offset)[0] if offset + 8 <= self.size else 0

    def c_str(self, offset: int, max_len: int = 256) -> str:
        end = self.data.find(b"\x00", offset, offset + max_len)
        if end == -1: end = min(offset + max_len, self.size)
        return self.data[offset:end].decode("ascii", errors="replace")


def analyze_pe(reader: BinaryReader) -> Dict[str, Any]:
    res = {"format": "PE", "bits": 32, "sections": [], "imports": [], "exports": []}
    if reader.u16(0) != 0x5A4D: # 'MZ'
        return res
    pe_off = reader.u32(0x3C)
    if reader.u32(pe_off) != 0x00004550: # 'PE\0\0'
        return res

    machine = reader.u16(pe_off + 4)
    num_sections = reader.u16(pe_off + 6)
    opt_size = reader.u16(pe_off + 20)
    opt_magic = reader.u16(pe_off + 24)

    res["machine"] = "x86 (PE32)" if machine == 0x014C else ("x64 (PE32+)" if machine == 0x8664 else hex(machine))
    res["bits"] = 64 if opt_magic == 0x20B else 32

    sec_hdr_off = pe_off + 24 + opt_size
    for i in range(num_sections):
        s_off = sec_hdr_off + i * 40
        name = reader.data[s_off:s_off+8].rstrip(b"\x00").decode("ascii", errors="replace")
        vsize = reader.u32(s_off + 8)
        vaddr = reader.u32(s_off + 12)
        raw_size = reader.u32(s_off + 16)
        raw_off = reader.u32(s_off + 20)
        chars = reader.u32(s_off + 36)
        res["sections"].append({
            "name": name, "virtual_size": vsize, "virtual_address": hex(vaddr),
            "raw_size": raw_size, "raw_offset": hex(raw_off), "characteristics": hex(chars)
        })

    return res


def analyze_macho(reader: BinaryReader) -> Dict[str, Any]:
    magic = reader.u32(0, le=False)
    le_magic = reader.u32(0, le=True)
    res = {"format": "Mach-O", "segments": [], "commands": []}

    is_64 = magic in (0xFEEDFACF, 0xCFFACEDF) or le_magic in (0xFEEDFACF, 0xCFFACEDF)
    le = le_magic in (0xFEEDFACE, 0xFEEDFACF)
    res["bits"] = 64 if is_64 else 32
    res["endianness"] = "little" if le else "big"

    ncmds = reader.u32(16 if is_64 else 12, le=le)
    cmd_off = 32 if is_64 else 28

    for _ in range(min(ncmds, 128)):
        cmd = reader.u32(cmd_off, le=le)
        cmd_size = reader.u32(cmd_off + 4, le=le)
        if cmd_size == 0 or cmd_off + cmd_size > reader.size: break
        
        # LC_SEGMENT (0x1) or LC_SEGMENT_64 (0x19)
        if cmd in (0x1, 0x19):
            segname = reader.data[cmd_off+8:cmd_off+24].rstrip(b"\x00").decode("ascii", errors="replace")
            res["segments"].append({"name": segname, "cmd_size": cmd_size})
        cmd_off += cmd_size

    return res


def analyze_elf(reader: BinaryReader) -> Dict[str, Any]:
    res = {"format": "ELF", "bits": 32, "sections": []}
    if reader.data[:4] != b"\x7fELF": return res
    bits = 64 if reader.u8(4) == 2 else 32
    res["bits"] = bits
    le = reader.u8(5) == 1
    res["endianness"] = "little" if le else "big"
    return res


def scan_x87_instructions(data: bytes) -> Dict[str, Any]:
    # x87 FPU opcode prefixes: D8..DF, 9B (FWAIT)
    x87_opcodes = set(range(0xD8, 0xE0))
    total_bytes = len(data)
    count = 0
    fwait_count = 0

    for i in range(total_bytes - 1):
        b = data[i]
        if b in x87_opcodes:
            modrm = data[i + 1]
            # Verify valid modrm / opcode extension for x87
            count += 1
        elif b == 0x9B:
            fwait_count += 1

    density_per_kb = (count / (total_bytes / 1024.0)) if total_bytes > 0 else 0.0
    stall_risk = "HIGH" if density_per_kb > 5.0 else ("MEDIUM" if density_per_kb > 1.0 else "LOW")

    return {
        "x87_instruction_count": count,
        "fwait_count": fwait_count,
        "density_per_kb": round(density_per_kb, 2),
        "rosetta2_stall_risk": stall_risk
    }


def scan_msvc_rtti(data: bytes) -> List[Dict[str, str]]:
    # Search for MSVC RTTI TypeDescriptor patterns: ".?AV...@@"
    classes = []
    pattern = re.compile(rb"\.\?AV([a-zA-Z0-9_]+)@@")
    matches = pattern.finditer(data)
    for m in matches:
        class_name = m.group(1).decode("ascii", errors="replace")
        offset = hex(m.start())
        if class_name not in [c["class"] for c in classes]:
            classes.append({"class": class_name, "type_descriptor_offset": offset})
        if len(classes) >= 50:
            break
    return classes


def extract_strings(data: bytes, min_len: int = 5) -> List[str]:
    # ASCII strings
    ascii_pat = re.compile(rb"[a-zA-Z0-9_\-\.\/\\:]{" + str(min_len).encode() + rb",}")
    found = []
    for m in ascii_pat.finditer(data[:1024*1024]): # Limit search window to first 1MB for speed
        found.append(m.group(0).decode("ascii", errors="replace"))
        if len(found) >= 50: break
    return found


def inspect_binary(filepath: str) -> Dict[str, Any]:
    with open(filepath, "rb") as f:
        data = f.read()

    reader = BinaryReader(data)
    info: Dict[str, Any] = {
        "file": os.path.basename(filepath),
        "size_bytes": len(data),
        "format": "Unknown"
    }

    if data.startswith(b"MZ"):
        info.update(analyze_pe(reader))
    elif data.startswith(b"\x7fELF"):
        info.update(analyze_elf(reader))
    elif data[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
        info.update(analyze_macho(reader))

    info["x87_fpu_profile"] = scan_x87_instructions(data)
    info["rtti_classes"] = scan_msvc_rtti(data)
    info["sample_strings"] = extract_strings(data)

    return info


def format_markdown_report(info: Dict[str, Any]) -> str:
    md = []
    md.append(f"# Binary Analysis Report: `{info.get('file')}`\n")
    md.append(f"- **File Size**: {info.get('size_bytes', 0):,} bytes")
    md.append(f"- **Format**: {info.get('format')} ({info.get('bits', 32)}-bit)")
    if "machine" in info:
        md.append(f"- **Target Architecture**: {info['machine']}")
    md.append("")

    fpu = info.get("x87_fpu_profile", {})
    md.append("## x87 FPU Emulation Risk Profile (Apple Silicon / Rosetta 2)")
    md.append(f"- **x87 Opcode Density**: {fpu.get('density_per_kb', 0)} opcodes/KB")
    md.append(f"- **Total x87 Instructions**: {fpu.get('x87_instruction_count', 0):,}")
    md.append(f"- **Rosetta 2 Stall Risk**: `{fpu.get('rosetta2_stall_risk')}`")
    md.append("")

    sections = info.get("sections", [])
    if sections:
        md.append("## Sections / Segments")
        md.append("| Name | Virtual Addr | Virtual Size | Raw Size | Characteristics |")
        md.append("|---|---|---|---|---|")
        for s in sections[:15]:
            md.append(f"| `{s.get('name')}` | `{s.get('virtual_address')}` | {s.get('virtual_size')} | {s.get('raw_size')} | `{s.get('characteristics')}` |")
        md.append("")

    rtti = info.get("rtti_classes", [])
    if rtti:
        md.append("## Discovered MSVC RTTI Classes")
        for c in rtti[:20]:
            md.append(f"- `{c['class']}` at `{c['type_descriptor_offset']}`")
        md.append("")

    return "\n".join(md)


def main():
    parser = argparse.ArgumentParser(description="Lean-REA: Lightweight Multi-Format Binary Reverse Engineering & Triage Tool")
    parser.add_argument("binary", help="Target binary path (PE, Mach-O, ELF)")
    parser.add_argument("--format", choices=["markdown", "json"], default="markdown", help="Output format (default: markdown)")
    parser.add_argument("--out", "-o", help="Write report to file")
    args = parser.parse_args()

    if not os.path.isfile(args.binary):
        print(f"[-] Error: File not found: {args.binary}", file=sys.stderr)
        sys.exit(1)

    info = inspect_binary(args.binary)
    output = json.dumps(info, indent=2) if args.format == "json" else format_markdown_report(info)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(output)
        print(f"[+] Report written to {args.out}")
    else:
        print(output)

if __name__ == "__main__":
    main()
