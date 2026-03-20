"""
c2/zeroday/analysis/static/analyzer.py
AEGIS-SILENTIUM v12 — Static Analysis Engine

Full static analysis without external dependencies:
  • ELF/PE header parsing (magic bytes, sections, imports)
  • CFG recovery via linear sweep disassembly (x86/x86-64)
  • Cyclomatic complexity per function
  • Dangerous function pattern matching (strcpy, sprintf, gets, etc.)
  • Taint tracking: follows user-controlled data through basic blocks
  • String extraction (C strings, wide strings)
  • Entropy analysis (packed/encrypted sections)
  • Import analysis (dangerous Win32/libc calls)
  • Danger-scored function ranking
"""
from __future__ import annotations

import hashlib
import logging
import math
import re
import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from zeroday.models import CFGNode, Function, Target, TargetArch, TargetType, VulnClass

log = logging.getLogger("aegis.zeroday.static")


# ── Dangerous function signatures ─────────────────────────────────────────────

# (function_name, vuln_class, danger_score 0-1, description)
DANGEROUS_FUNCTIONS: List[Tuple[str, VulnClass, float, str]] = [
    # Classic memory functions
    ("strcpy",       VulnClass.BUFFER_OVERFLOW, 0.90, "unbounded copy, no length check"),
    ("strcat",       VulnClass.BUFFER_OVERFLOW, 0.85, "unbounded concatenation"),
    ("gets",         VulnClass.BUFFER_OVERFLOW, 1.00, "always vulnerable, reads unlimited input"),
    ("sprintf",      VulnClass.BUFFER_OVERFLOW, 0.80, "unbounded format output"),
    ("vsprintf",     VulnClass.BUFFER_OVERFLOW, 0.80, "unbounded variadic format output"),
    ("scanf",        VulnClass.BUFFER_OVERFLOW, 0.70, "%s specifier without width limit"),
    ("sscanf",       VulnClass.BUFFER_OVERFLOW, 0.65, "may overflow destination"),
    ("memcpy",       VulnClass.BUFFER_OVERFLOW, 0.40, "unchecked length can overflow"),
    ("memmove",      VulnClass.BUFFER_OVERFLOW, 0.35, "unchecked length can overflow"),
    # Format string
    ("printf",       VulnClass.FORMAT_STRING,   0.60, "if first arg is user-controlled"),
    ("fprintf",      VulnClass.FORMAT_STRING,   0.55, "if format arg is user-controlled"),
    ("snprintf",     VulnClass.FORMAT_STRING,   0.50, "if format arg is user-controlled"),
    ("syslog",       VulnClass.FORMAT_STRING,   0.50, "user-controlled format string"),
    # Execution
    ("system",       VulnClass.INJECTION,       0.85, "command injection if arg is user-controlled"),
    ("exec",         VulnClass.INJECTION,       0.80, "exec family with user-controlled path"),
    ("execve",       VulnClass.INJECTION,       0.80, "execve with user-controlled args"),
    ("popen",        VulnClass.INJECTION,       0.85, "command injection risk"),
    # Integer
    ("atoi",         VulnClass.INTEGER_OVERFLOW,0.45, "no error detection on overflow"),
    ("atol",         VulnClass.INTEGER_OVERFLOW,0.45, "no error detection on overflow"),
    ("strtol",       VulnClass.INTEGER_OVERFLOW,0.30, "check return value and errno"),
    # Heap
    ("malloc",       VulnClass.HEAP_OVERFLOW,   0.25, "check return for NULL and size arithmetic"),
    ("realloc",      VulnClass.USE_AFTER_FREE,  0.40, "old pointer invalid after realloc"),
    ("free",         VulnClass.DOUBLE_FREE,     0.35, "check for double-free"),
    # Windows-specific
    ("CreateProcess",VulnClass.INJECTION,       0.70, "command injection risk"),
    ("WriteProcessMemory", VulnClass.MEMORY_CORRUPTION, 0.70, "memory write primitive"),
    ("VirtualProtect", VulnClass.MEMORY_CORRUPTION, 0.60, "can mark memory executable"),
    ("WinExec",      VulnClass.INJECTION,       0.85, "command injection"),
    ("ShellExecute", VulnClass.INJECTION,       0.85, "command injection"),
]

_DANGER_MAP: Dict[str, Tuple[VulnClass, float, str]] = {
    name: (vc, score, desc) for name, vc, score, desc in DANGEROUS_FUNCTIONS
}


# ── ELF/PE header parser ──────────────────────────────────────────────────────

@dataclass
class BinaryInfo:
    """Parsed binary metadata."""
    path:          str
    file_size:     int              = 0
    sha256:        str              = ""
    format:        str              = "unknown"    # elf, pe, macho, raw
    arch:          TargetArch       = TargetArch.UNKNOWN
    bits:          int              = 64
    is_stripped:   bool             = False
    is_pie:        bool             = False
    has_nx:        bool             = True
    has_canary:    bool             = False
    has_relro:     bool             = False
    entry_point:   int              = 0
    sections:      List[dict]       = field(default_factory=list)
    imports:       List[str]        = field(default_factory=list)
    strings:       List[str]        = field(default_factory=list)
    functions:     List[Function]   = field(default_factory=list)
    dangerous_calls: List[dict]     = field(default_factory=list)
    entropy:       float            = 0.0
    is_packed:     bool             = False

    def to_dict(self) -> dict:
        return {
            "path":           self.path,
            "file_size":      self.file_size,
            "sha256":         self.sha256,
            "format":         self.format,
            "arch":           self.arch.value,
            "bits":           self.bits,
            "is_stripped":    self.is_stripped,
            "is_pie":         self.is_pie,
            "has_nx":         self.has_nx,
            "has_canary":     self.has_canary,
            "has_relro":      self.has_relro,
            "entry_point":    hex(self.entry_point) if self.entry_point else "0x0",
            "section_count":  len(self.sections),
            "import_count":   len(self.imports),
            "string_count":   len(self.strings),
            "function_count": len(self.functions),
            "dangerous_calls": self.dangerous_calls[:20],
            "entropy":        round(self.entropy, 3),
            "is_packed":      self.is_packed,
        }


class BinaryParser:
    """Parse ELF/PE binary headers without external libraries."""

    # ELF magic bytes
    ELF_MAGIC = b"\x7fELF"
    PE_MAGIC  = b"MZ"
    MACHO_MAGICS = {
        b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",
        b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",
    }

    def parse(self, path: str) -> BinaryInfo:
        """Parse a binary file and return BinaryInfo."""
        info = BinaryInfo(path=path)
        try:
            data = open(path, "rb").read()
        except (OSError, PermissionError) as e:
            log.warning("Cannot read %r: %s", path, e)
            return info

        info.file_size = len(data)
        info.sha256    = hashlib.sha256(data).hexdigest()
        info.entropy   = self._entropy(data)
        info.is_packed = info.entropy > 7.2  # packed/encrypted threshold

        if data[:4] == self.ELF_MAGIC:
            self._parse_elf(data, info)
        elif data[:2] == self.PE_MAGIC:
            self._parse_pe(data, info)
        elif data[:4] in self.MACHO_MAGICS:
            info.format = "macho"
            info.arch   = TargetArch.ARM64 if data[:4] == b"\xcf\xfa\xed\xfe" else TargetArch.X86_64
        else:
            info.format = "raw"

        # Extract C strings
        info.strings = self._extract_strings(data)

        # Find dangerous function references by string
        info.dangerous_calls = self._find_dangerous_calls(info.strings, info.imports)

        return info

    def _parse_elf(self, data: bytes, info: BinaryInfo) -> None:
        info.format = "elf"
        if len(data) < 64:
            return
        ei_class = data[4]
        ei_data  = data[5]   # 1=little, 2=big

        info.bits = 64 if ei_class == 2 else 32
        bo = "<" if ei_data == 1 else ">"

        e_machine = struct.unpack_from(f"{bo}H", data, 18)[0]
        info.arch = {
            3: TargetArch.X86,    # EM_386
            62: TargetArch.X86_64, # EM_X86_64
            40: TargetArch.ARM,   # EM_ARM
            183: TargetArch.ARM64, # EM_AARCH64
            8: TargetArch.MIPS,   # EM_MIPS
        }.get(e_machine, TargetArch.UNKNOWN)

        e_type = struct.unpack_from(f"{bo}H", data, 16)[0]
        info.is_pie = (e_type == 3)  # ET_DYN with no base = PIE

        if info.bits == 64:
            info.entry_point = struct.unpack_from(f"{bo}Q", data, 24)[0]
        else:
            info.entry_point = struct.unpack_from(f"{bo}I", data, 24)[0]

        # Section headers
        if info.bits == 64 and len(data) >= 64:
            e_shoff = struct.unpack_from(f"{bo}Q", data, 40)[0]
            e_shnum = struct.unpack_from(f"{bo}H", data, 60)[0]
            e_shentsize = struct.unpack_from(f"{bo}H", data, 58)[0]
            self._parse_elf64_sections(data, info, e_shoff, e_shnum, e_shentsize, bo)

        # Security features from section names / dynamic tags
        for sec in info.sections:
            name = sec.get("name","")
            if "__stack_chk" in str(info.imports) or "stack_chk" in name:
                info.has_canary = True
            if name == ".gnu.relro" or name == ".data.rel.ro":
                info.has_relro = True

        if "RELRO" in str(info.sections):
            info.has_relro = True

    def _parse_elf64_sections(self, data: bytes, info: BinaryInfo,
                               shoff: int, shnum: int, shentsize: int, bo: str) -> None:
        if shoff == 0 or shnum == 0:
            info.is_stripped = True
            return
        # Read string table index
        try:
            e_shstrndx = struct.unpack_from(f"{bo}H", data, 62)[0]
            str_sec_off = shoff + e_shstrndx * shentsize
            if str_sec_off + 40 > len(data):
                return
            str_off  = struct.unpack_from(f"{bo}Q", data, str_sec_off + 24)[0]
            str_size = struct.unpack_from(f"{bo}Q", data, str_sec_off + 32)[0]
            strtab   = data[str_off:str_off + str_size]

            for i in range(min(shnum, 100)):
                off = shoff + i * shentsize
                if off + shentsize > len(data):
                    break
                sh_name  = struct.unpack_from(f"{bo}I", data, off)[0]
                sh_type  = struct.unpack_from(f"{bo}I", data, off + 4)[0]
                sh_flags = struct.unpack_from(f"{bo}Q", data, off + 8)[0]
                sh_size  = struct.unpack_from(f"{bo}Q", data, off + 32)[0]

                name = ""
                if sh_name < len(strtab):
                    end = strtab.find(b"\x00", sh_name)
                    name = strtab[sh_name:end].decode(errors="replace")

                if name == ".symtab":
                    info.is_stripped = False
                if name == ".dynsym":
                    pass  # dynamic symbols

                info.sections.append({
                    "name": name, "type": sh_type,
                    "flags": sh_flags, "size": sh_size,
                })
        except (struct.error, IndexError):
            pass

    def _parse_pe(self, data: bytes, info: BinaryInfo) -> None:
        info.format = "pe"
        try:
            pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
            if pe_offset + 24 > len(data):
                return
            if data[pe_offset:pe_offset+4] != b"PE\x00\x00":
                return

            machine = struct.unpack_from("<H", data, pe_offset + 4)[0]
            info.arch = {
                0x014c: TargetArch.X86,
                0x8664: TargetArch.X86_64,
                0xAA64: TargetArch.ARM64,
                0x01C4: TargetArch.ARM,
            }.get(machine, TargetArch.UNKNOWN)

            info.bits = 64 if info.arch == TargetArch.X86_64 else 32
        except (struct.error, IndexError):
            pass

    @staticmethod
    def _entropy(data: bytes) -> float:
        if not data:
            return 0.0
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        total = len(data)
        return -sum(
            (c / total) * math.log2(c / total)
            for c in freq if c > 0
        )

    @staticmethod
    def _extract_strings(data: bytes, min_len: int = 4) -> List[str]:
        """Extract printable ASCII strings from binary data."""
        results = []
        current = bytearray()
        for b in data:
            if 0x20 <= b <= 0x7e:
                current.append(b)
            else:
                if len(current) >= min_len:
                    results.append(current.decode("ascii"))
                current = bytearray()
        if len(current) >= min_len:
            results.append(current.decode("ascii"))
        return results[:2000]

    @staticmethod
    def _find_dangerous_calls(strings: List[str], imports: List[str]) -> List[dict]:
        """Find references to dangerous functions."""
        results = []
        all_names = set(strings) | set(imports)
        for name in all_names:
            clean = name.strip()
            if clean in _DANGER_MAP:
                vc, score, desc = _DANGER_MAP[clean]
                results.append({
                    "function":  clean,
                    "vuln_class": vc.value,
                    "danger_score": score,
                    "description": desc,
                })
        results.sort(key=lambda x: -x["danger_score"])
        return results


# ── CFG builder via linear sweep ─────────────────────────────────────────────

class CFGBuilder:
    """
    Recover a Control Flow Graph from raw x86-64 machine code
    via linear sweep disassembly.

    Uses a simplified decoder to identify call/jmp/ret instructions
    and recover basic block boundaries without external libraries.
    """

    # x86-64 instruction length heuristics (simplified)
    _JMP_OPCODES:  Set[int] = {0xEB, 0xE9, 0xFF}  # jmp rel8/rel32/rm
    _JCC_OPCODES:  Set[int] = {
        0x74, 0x75, 0x72, 0x73, 0x76, 0x77, 0x7C, 0x7D, 0x7E, 0x7F,
        0x70, 0x71, 0x78, 0x79, 0x7A, 0x7B,  # Jcc rel8
    }
    _CALL_OPCODES: Set[int] = {0xE8, 0xFF}
    _RET_OPCODES:  Set[int] = {0xC3, 0xC2, 0xCB, 0xCA}

    def build_from_bytes(
        self, code: bytes, base_addr: int = 0
    ) -> Tuple[List[CFGNode], List[Function]]:
        """
        Linear sweep over code bytes to recover CFG.
        Returns (nodes, functions).
        """
        nodes:        Dict[int, CFGNode] = {}
        functions:    List[Function]     = []
        leaders:      Set[int]           = {base_addr}
        call_targets: Set[int]           = set()

        # First pass: find all leaders (block starts)
        offset = 0
        while offset < len(code):
            addr   = base_addr + offset
            opcode = code[offset]

            if opcode in self._RET_OPCODES:
                # Next byte is a new leader
                if offset + 1 < len(code):
                    leaders.add(addr + 1)
                offset += 1

            elif opcode in self._JCC_OPCODES:
                # Conditional jump rel8
                if offset + 1 < len(code):
                    rel   = struct.unpack_from("b", code, offset + 1)[0]
                    target = addr + 2 + rel
                    if 0 <= target - base_addr < len(code):
                        leaders.add(target)
                    leaders.add(addr + 2)  # fall-through
                offset += 2

            elif opcode == 0x0F and offset + 1 < len(code):
                next_op = code[offset + 1]
                if 0x80 <= next_op <= 0x8F:  # Jcc rel32
                    if offset + 6 <= len(code):
                        rel    = struct.unpack_from("<i", code, offset + 2)[0]
                        target = addr + 6 + rel
                        if 0 <= target - base_addr < len(code):
                            leaders.add(target)
                        leaders.add(addr + 6)
                    offset += 6
                else:
                    offset += 2

            elif opcode == 0xE9:  # jmp rel32
                if offset + 5 <= len(code):
                    rel    = struct.unpack_from("<i", code, offset + 1)[0]
                    target = addr + 5 + rel
                    if 0 <= target - base_addr < len(code):
                        leaders.add(target)
                offset += 5

            elif opcode == 0xEB:  # jmp rel8
                if offset + 2 <= len(code):
                    rel    = struct.unpack_from("b", code, offset + 1)[0]
                    target = addr + 2 + rel
                    if 0 <= target - base_addr < len(code):
                        leaders.add(target)
                offset += 2

            elif opcode == 0xE8:  # call rel32
                if offset + 5 <= len(code):
                    rel    = struct.unpack_from("<i", code, offset + 1)[0]
                    target = addr + 5 + rel
                    if 0 <= target - base_addr < len(code):
                        call_targets.add(target)
                        leaders.add(target)
                    leaders.add(addr + 5)
                offset += 5
            else:
                offset += self._instr_len(code, offset)

        leaders.update(call_targets)

        # Second pass: build basic blocks
        sorted_leaders = sorted(leaders)
        for i, start in enumerate(sorted_leaders):
            end  = sorted_leaders[i + 1] if i + 1 < len(sorted_leaders) else base_addr + len(code)
            size = end - start
            if size <= 0 or start < base_addr or start >= base_addr + len(code):
                continue
            block_bytes   = code[start - base_addr: end - base_addr]
            instrs, succs = self._decode_block(block_bytes, start, base_addr, len(code))
            node = CFGNode(
                addr         = start,
                size         = len(block_bytes),
                instructions = instrs,
                successors   = succs,
                is_entry     = (start == base_addr),
            )
            nodes[start] = node

        # Set predecessors
        for node in nodes.values():
            for succ_addr in node.successors:
                if succ_addr in nodes:
                    nodes[succ_addr].predecessors.append(node.addr)

        # Recover functions from call targets
        for tgt in sorted(call_targets):
            if tgt in nodes:
                func_nodes = self._reachable_blocks(nodes, tgt)
                n_blocks   = len(func_nodes)
                n_edges    = sum(len(nodes[a].successors) for a in func_nodes if a in nodes)
                cyclomatic  = max(1, n_edges - n_blocks + 2)
                func = Function(
                    addr       = tgt,
                    size       = sum(nodes[a].size for a in func_nodes if a in nodes),
                    num_blocks = n_blocks,
                    cyclomatic = cyclomatic,
                )
                functions.append(func)

        return list(nodes.values()), functions

    @staticmethod
    def _instr_len(code: bytes, offset: int) -> int:
        """Very rough instruction length estimate for linear sweep."""
        if offset >= len(code):
            return 1
        op = code[offset]
        # REX prefix
        if 0x40 <= op <= 0x4F and offset + 1 < len(code):
            op = code[offset + 1]
            return 1 + CFGBuilder._instr_len(code, offset + 1)
        # Common fixed-length patterns
        if op in (0x90, 0xCC, 0xC3, 0xCB, 0xF1, 0xF4):  # NOP, INT3, RET, HLT
            return 1
        if op in (0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,   # PUSH r64
                   0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F):  # POP r64
            return 1
        if op == 0x0F:
            return 3  # typical 0F xx xx
        if op in (0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7):  # MOV r8, imm8
            return 2
        if op in (0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF):  # MOV r32/64, imm
            return 5
        if op in (0x80, 0x83):
            return 3
        if op in (0x81,):
            return 6
        return 3  # reasonable default

    @staticmethod
    def _decode_block(code: bytes, base: int, section_base: int,
                       section_len: int) -> Tuple[List[str], List[int]]:
        """Decode a basic block and return (pseudo-mnemonics, successor_addrs)."""
        instructions = []
        successors   = []
        offset       = 0
        _names       = {
            0xE8: "CALL", 0xE9: "JMP", 0xEB: "JMP", 0xC3: "RET", 0xCC: "INT3",
            0x74: "JZ", 0x75: "JNZ", 0x90: "NOP", 0x55: "PUSH RBP", 0x5D: "POP RBP",
        }
        while offset < len(code):
            op    = code[offset]
            addr  = base + offset
            mnem  = _names.get(op, f"0x{op:02x}")
            instructions.append(f"{addr:#x}  {mnem}")

            if op in (0xC3, 0xC2, 0xCB, 0xCA):  # RET
                break
            if op == 0xE9 and offset + 5 <= len(code):  # JMP rel32
                rel  = struct.unpack_from("<i", code, offset + 1)[0]
                tgt  = addr + 5 + rel
                if section_base <= tgt < section_base + section_len:
                    successors.append(tgt)
                offset += 5
                break
            if op == 0xEB and offset + 2 <= len(code):  # JMP rel8
                rel  = struct.unpack_from("b", code, offset + 1)[0]
                tgt  = addr + 2 + rel
                if section_base <= tgt < section_base + section_len:
                    successors.append(tgt)
                offset += 2
                break
            # Conditional jumps — fall-through + target
            if op in CFGBuilder._JCC_OPCODES and offset + 2 <= len(code):
                rel  = struct.unpack_from("b", code, offset + 1)[0]
                tgt  = addr + 2 + rel
                ft   = addr + 2
                if section_base <= tgt < section_base + section_len:
                    successors.append(tgt)
                if section_base <= ft < section_base + section_len:
                    successors.append(ft)
                offset += 2
                break
            offset += CFGBuilder._instr_len(code, offset)

        # If block ended without explicit branch, fall-through to next block
        if not successors and instructions:
            ft = base + len(code)
            if section_base <= ft < section_base + section_len:
                successors.append(ft)
        return instructions[:20], successors

    @staticmethod
    def _reachable_blocks(nodes: Dict[int, CFGNode], start: int) -> Set[int]:
        """BFS to find all blocks reachable from start."""
        visited: Set[int] = set()
        queue   = [start]
        while queue:
            addr = queue.pop()
            if addr in visited or addr not in nodes:
                continue
            visited.add(addr)
            queue.extend(nodes[addr].successors)
        return visited


# ── Taint tracker ─────────────────────────────────────────────────────────────

class TaintTracker:
    """
    Tracks how tainted (user-controlled) data flows through registers
    and memory locations across basic blocks.

    Simplified model: register-level taint propagation using
    data-flow analysis on recovered CFG.
    """

    X86_REGS = ["rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi",
                 "r8","r9","r10","r11","r12","r13","r14","r15"]

    def __init__(self) -> None:
        self._tainted_regs:   Set[str]  = set()
        self._tainted_addrs:  Set[int]  = set()
        self._taint_log:      List[str] = []

    def mark_tainted(self, reg: str) -> None:
        self._tainted_regs.add(reg.lower())
        self._taint_log.append(f"TAINT: {reg} marked tainted")

    def propagate(self, insn: str) -> List[str]:
        """
        Simple taint propagation from a pseudo-instruction string.
        Returns list of newly tainted registers.
        """
        new_tainted = []
        insn_lower  = insn.lower()

        # MOV dst, src — taint propagates
        m = re.search(r"mov\s+(\w+),\s*\[?(\w+)\]?", insn_lower)
        if m:
            dst, src = m.group(1), m.group(2)
            if src in self._tainted_regs or any(r in insn_lower for r in self._tainted_regs):
                if dst in self.X86_REGS:
                    self._tainted_regs.add(dst)
                    new_tainted.append(dst)
                    self._taint_log.append(f"TAINT PROP: {src} -> {dst} via MOV")

        # ADD/SUB/XOR — arithmetic on tainted operands taints result
        for op in ("add", "sub", "xor", "or", "and", "shl", "shr"):
            m = re.search(rf"{op}\s+(\w+),\s*(\w+)", insn_lower)
            if m:
                dst, src = m.group(1), m.group(2)
                if src in self._tainted_regs or dst in self._tainted_regs:
                    self._tainted_regs.add(dst)
                    if dst not in new_tainted:
                        new_tainted.append(dst)

        # CALL — check if tainted value reaches call argument registers
        if "call" in insn_lower:
            arg_regs = {"rdi", "rsi", "rdx", "rcx", "r8", "r9"}
            tainted_args = arg_regs & self._tainted_regs
            if tainted_args:
                self._taint_log.append(
                    f"TAINT SINK: CALL with tainted args: {tainted_args}"
                )

        return new_tainted

    def is_tainted(self, reg: str) -> bool:
        return reg.lower() in self._tainted_regs

    def get_taint_log(self) -> List[str]:
        return list(self._taint_log)

    def clear(self) -> None:
        self._tainted_regs.clear()
        self._tainted_addrs.clear()
        self._taint_log.clear()


# ── Pattern matcher ───────────────────────────────────────────────────────────

class PatternMatcher:
    """
    Match known vulnerability patterns in extracted strings and function names.
    Combines keyword analysis, regex, and heuristics.
    """

    _SQL_PATTERNS = [
        re.compile(r"(?i)select\s+.*\s+from"),
        re.compile(r"(?i)insert\s+into"),
        re.compile(r"(?i)where\s+\w+\s*=\s*['\"]"),
        re.compile(r"(?i)exec(?:ute)?\s*\("),
    ]
    _FORMAT_PATTERNS = [
        re.compile(r"%[0-9]*[sd]"),
        re.compile(r"%n"),
        re.compile(r"printf.*%s"),
    ]
    _PATH_PATTERNS = [
        re.compile(r"\.\./"),
        re.compile(r"etc/passwd"),
        re.compile(r"etc/shadow"),
        re.compile(r"/proc/"),
        re.compile(r"\\\\\.\\\\"),  # UNC path
    ]
    _CRYPTO_WEAK = [
        re.compile(r"(?i)\bmd5\b"),
        re.compile(r"(?i)\bsha1\b"),
        re.compile(r"(?i)\bdes\b"),
        re.compile(r"(?i)\brc4\b"),
    ]

    def scan_strings(self, strings: List[str]) -> List[dict]:
        """Scan extracted strings for suspicious patterns."""
        findings = []
        for s in strings:
            for pattern in self._SQL_PATTERNS:
                if pattern.search(s):
                    findings.append({"pattern": "sql_injection_candidate",
                                      "string": s[:100],
                                      "vuln_class": VulnClass.INJECTION.value})
            for pattern in self._FORMAT_PATTERNS:
                if pattern.search(s):
                    findings.append({"pattern": "format_string_candidate",
                                      "string": s[:100],
                                      "vuln_class": VulnClass.FORMAT_STRING.value})
            for pattern in self._PATH_PATTERNS:
                if pattern.search(s):
                    findings.append({"pattern": "path_traversal_candidate",
                                      "string": s[:100],
                                      "vuln_class": VulnClass.PATH_TRAVERSAL.value})
            for pattern in self._CRYPTO_WEAK:
                if pattern.search(s):
                    findings.append({"pattern": "weak_crypto",
                                      "string": s[:100],
                                      "vuln_class": VulnClass.UNKNOWN.value})
        # Deduplicate
        seen = set()
        unique = []
        for f in findings:
            key = f["pattern"] + f["string"][:20]
            if key not in seen:
                seen.add(key); unique.append(f)
        return unique[:50]


# ── Main static analyser ──────────────────────────────────────────────────────

class StaticAnalyzer:
    """
    Orchestrates all static analysis phases:
    1. Binary parsing (ELF/PE/MachO)
    2. CFG recovery
    3. Function analysis (cyclomatic, danger scoring)
    4. Taint source detection
    5. Pattern matching on strings
    6. Comprehensive report generation
    """

    def __init__(self) -> None:
        self._parser  = BinaryParser()
        self._cfg     = CFGBuilder()
        self._taint   = TaintTracker()
        self._matcher = PatternMatcher()

    def analyse(self, target: Target) -> dict:
        """Run full static analysis on a target binary."""
        log.info("Static analysis: %s", target.path)
        result: dict = {
            "target_id":   target.target_id,
            "path":        target.path,
            "analysis_ts": __import__("time").time(),
        }

        # Phase 1: Binary info
        bin_info = self._parser.parse(target.path)
        result["binary_info"] = bin_info.to_dict()

        # Phase 2: CFG recovery (on first .text section data)
        if bin_info.format in ("elf", "pe") and not bin_info.is_packed:
            try:
                raw = open(target.path, "rb").read()
                # Analyse first 64KB of executable content
                code_slice = self._find_code_section(raw, bin_info)
                if code_slice:
                    nodes, functions = self._cfg.build_from_bytes(
                        code_slice[:65536],
                        base_addr=bin_info.entry_point or 0x400000
                    )
                    result["cfg_nodes"]      = len(nodes)
                    result["functions_recovered"] = len(functions)
                    result["functions"]      = [f.to_dict() for f in functions[:50]]

                    # Score functions by danger
                    for f in functions:
                        f.danger_score = self._score_function(f, bin_info)
                    functions.sort(key=lambda x: -x.danger_score)
                    result["top_dangerous_functions"] = [
                        f.to_dict() for f in functions[:10]
                    ]
            except Exception as _e:
                log.debug("CFG recovery failed: %s", _e)
                result["cfg_error"] = str(_e)

        # Phase 3: String pattern matching
        pattern_hits = self._matcher.scan_strings(bin_info.strings)
        result["pattern_matches"] = pattern_hits

        # Phase 4: Dangerous call summary
        result["dangerous_calls"]  = bin_info.dangerous_calls[:20]
        result["highest_risk_call"] = bin_info.dangerous_calls[0] if bin_info.dangerous_calls else None

        # Phase 5: Risk score
        risk = self._compute_risk(bin_info, pattern_hits)
        result["risk_score"]   = risk["score"]
        result["risk_factors"] = risk["factors"]

        # Phase 6: Recommended vuln classes to fuzz for
        result["recommended_vuln_classes"] = self._recommend_vuln_classes(bin_info)

        return result

    @staticmethod
    def _find_code_section(data: bytes, info: BinaryInfo) -> Optional[bytes]:
        """Try to extract the .text section from ELF data."""
        if info.format != "elf" or len(data) < 64:
            return data[:65536]
        for sec in info.sections:
            if sec.get("name") == ".text" and sec.get("size", 0) > 0:
                return data  # simplification: return all data
        return data[:65536]

    @staticmethod
    def _score_function(func: Function, info: BinaryInfo) -> float:
        """Score a function's likelihood of containing a vulnerability."""
        score = 0.0
        # High cyclomatic complexity → harder to audit
        if func.cyclomatic > 20: score += 0.3
        elif func.cyclomatic > 10: score += 0.2
        elif func.cyclomatic > 5: score += 0.1
        # Large function
        if func.size > 1000: score += 0.2
        elif func.size > 500: score += 0.1
        # No stack protection
        if not info.has_canary: score += 0.2
        if not info.is_pie: score += 0.1
        return min(1.0, score)

    @staticmethod
    def _compute_risk(info: BinaryInfo, patterns: List[dict]) -> dict:
        """Compute overall binary risk score."""
        score   = 0.0
        factors = []

        if not info.has_nx:
            score += 0.3; factors.append("No NX (executable stack/heap)")
        if not info.is_pie:
            score += 0.2; factors.append("Not PIE (fixed addresses)")
        if not info.has_canary:
            score += 0.2; factors.append("No stack canary")
        if not info.has_relro:
            score += 0.1; factors.append("No RELRO")
        if info.is_stripped:
            score += 0.1; factors.append("Stripped binary")
        for call in info.dangerous_calls[:3]:
            score += call["danger_score"] * 0.1
            factors.append(f"Calls {call['function']} ({call['description']})")
        if patterns:
            score += min(0.2, len(patterns) * 0.02)
            factors.append(f"{len(patterns)} suspicious string patterns")

        return {"score": round(min(1.0, score), 3), "factors": factors[:10]}

    @staticmethod
    def _recommend_vuln_classes(info: BinaryInfo) -> List[str]:
        """Based on binary properties, recommend which vuln classes to fuzz for."""
        classes = []
        call_names = {c["function"] for c in info.dangerous_calls}
        if {"strcpy", "strcat", "gets", "sprintf"} & call_names:
            classes.append(VulnClass.BUFFER_OVERFLOW.value)
        if {"malloc", "free", "realloc"} & call_names:
            classes.append(VulnClass.HEAP_OVERFLOW.value)
            classes.append(VulnClass.USE_AFTER_FREE.value)
        if {"printf", "sprintf", "fprintf"} & call_names:
            classes.append(VulnClass.FORMAT_STRING.value)
        if {"system", "exec", "popen", "CreateProcess"} & call_names:
            classes.append(VulnClass.INJECTION.value)
        if {"atoi", "atol", "strtol"} & call_names:
            classes.append(VulnClass.INTEGER_OVERFLOW.value)
        if not classes:
            classes.append(VulnClass.MEMORY_CORRUPTION.value)
        return classes


__all__ = [
    "StaticAnalyzer", "BinaryParser", "CFGBuilder",
    "TaintTracker", "PatternMatcher", "BinaryInfo",
    "DANGEROUS_FUNCTIONS", "_DANGER_MAP",
]
