#!/usr/bin/env python3
"""
R8C/Tiny disassembler for Hakko FM-203 firmware.

Produces annotated disassembly from hakko_fm203.bin with:
  - Recursive descent from reset + ISR entry points
  - Linear sweep for unreached regions
  - Auto-detected function labels (JSR/JSR.A targets)
  - SFR name annotations on memory accesses
  - Cross-reference comments
  - Missing code region stubs

Usage:
    python3 r8c_disassembler.py [firmware.bin]

Defaults to hakko_fm203.bin if no argument given.
"""

import os
import sys
from collections import defaultdict, deque

from r8c_opcode_table import get_instruction_length, decode_instruction
from r8c_sfr_names import get_sfr_name, sfr_comment

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ROM_START = 0x04000
ROM_END = 0x13FFF
BUFFER_SIZE = 0x14000

# Known entry points
KNOWN_LABELS = {
    0x0FBAE: 'reset_init',
    0x08C92: 'main',
    0x08B40: 'isr_timer_rc',
    0x08B4C: 'isr_timer_rd_overflow',
    0x08AEA: 'isr_uart0_tx',
    0x0FC4E: 'default_handler',
    0x05428: 'flash_self_program',
}

ENTRY_POINTS = [
    ('reset_init', 0x0FBAE),
    ('isr_timer_rc', 0x08B40),
    ('isr_timer_rd_overflow', 0x08B4C),
    ('isr_uart0_tx', 0x08AEA),
]

# Known missing code region (never captured from video)
MISSING_RANGE = (0x04810, 0x0498F)

# Known call targets in missing region (from FIRMWARE_VERIFICATION.md)
MISSING_TARGETS = {
    0x04812: ['$049DF (JMP.W)'],
    0x04830: ['$08B5A (JSR.W)'],
    0x0484C: ['$08AC8 (JSR.W)'],
    0x04883: ['$09086 (JMP.W)'],
    0x04904: ['$04A3D (JSR.A)'],
    0x0496E: ['$09D7E (JSR.W)', '$0A3C9 (JSR.W)'],
    0x0498A: ['$0A3DE (JSR.W)'],
}

# Genuinely erased regions
ERASED_RANGES = [
    (0x04000, 0x0480F),   # Block 1 erased head (before missing code)
    (0x107F0, 0x13FFF),   # Block 0 erased tail
]

# Instructions that terminate a basic block (no fall-through)
_TERMINATORS = {'RTS', 'REIT', 'EXITD', 'BRK', 'UND'}

# Instructions that are unconditional jumps (no fall-through)
_JUMP_MNEMONICS = {'JMP.S', 'JMP.B', 'JMP.W', 'JMP.A'}

# Instructions that are calls (fall-through + target)
_CALL_MNEMONICS = {'JSR.W', 'JSR.A'}

# Conditional branches (fall-through + target)
_COND_PREFIXES = ('JGEU', 'JGTU', 'JEQ', 'JN', 'JLTU', 'JLEU', 'JNE', 'JPZ',
                  'JLE', 'JO', 'JGE', 'JGT', 'JNO', 'JLT')


# ---------------------------------------------------------------------------
# Binary loader
# ---------------------------------------------------------------------------

def load_binary(path):
    """Load hakko_fm203.bin into a buffer at offset $04000."""
    with open(path, 'rb') as f:
        rom = f.read()
    fw = bytearray(BUFFER_SIZE)
    fw[ROM_START:ROM_START + len(rom)] = rom
    return fw


# ---------------------------------------------------------------------------
# Control flow helpers
# ---------------------------------------------------------------------------

def _in_rom(addr):
    return ROM_START <= addr <= ROM_END


def _is_erased(addr):
    return any(s <= addr <= e for s, e in ERASED_RANGES)


def _is_missing(addr):
    return MISSING_RANGE[0] <= addr <= MISSING_RANGE[1]


def _extract_branch_target(mnem, ops):
    """Extract branch/jump target address from operands string."""
    # Targets are formatted as $XXXXX
    if ops.startswith('$') and ',' not in ops:
        try:
            return int(ops[1:], 16)
        except ValueError:
            pass
    # For conditional branches, target might be last operand
    parts = ops.split(',')
    last = parts[-1].strip()
    if last.startswith('$') and len(last) == 6:
        try:
            return int(last[1:], 16)
        except ValueError:
            pass
    return None


def _is_cond_branch(mnem):
    """Check if mnemonic is a conditional branch."""
    return mnem.startswith('J') and mnem not in _JUMP_MNEMONICS and mnem not in _CALL_MNEMONICS


# ---------------------------------------------------------------------------
# Recursive descent disassembler
# ---------------------------------------------------------------------------

def _und_is_nop(fw):
    """Check if UND handler is REIT, making FF act as 1-byte NOP."""
    und_vec = 0x0FFDC
    handler = fw[und_vec] | (fw[und_vec + 1] << 8) | ((fw[und_vec + 2] & 0x0F) << 16)
    return _in_rom(handler) and fw[handler] == 0xFB


def recursive_descent(fw, entry_points):
    """Follow control flow from entry points, decoding instructions.

    Returns:
        instructions: dict of addr -> (length, mnemonic, operands)
        xrefs: dict of target_addr -> [caller_addrs]
    """
    instructions = {}
    xrefs = defaultdict(list)
    queue = deque()
    und_nop = _und_is_nop(fw)

    for name, addr in entry_points:
        queue.append(addr)

    while queue:
        addr = queue.popleft()

        if addr in instructions:
            continue
        if not _in_rom(addr):
            continue
        if _is_erased(addr) or _is_missing(addr):
            continue

        # Linear decode from this address
        while True:
            if addr in instructions:
                break
            if not _in_rom(addr):
                break
            if _is_erased(addr) or _is_missing(addr):
                break

            b1 = fw[addr]

            # FF (UND): skip if handler is REIT, else stop
            if b1 == 0xFF:
                if und_nop:
                    instructions[addr] = (1, 'UND', '')
                    addr += 1
                    continue
                break

            length, mnem, ops = decode_instruction(fw, addr)
            if length == 0:
                break

            # Check instruction stays in ROM
            if not _in_rom(addr + length - 1):
                break

            instructions[addr] = (length, mnem, ops)

            # Extract target for branches/jumps/calls
            target = _extract_branch_target(mnem, ops)

            # Terminators: stop
            if mnem in _TERMINATORS:
                break

            # Unconditional jumps: follow target, no fall-through
            if mnem in _JUMP_MNEMONICS:
                if target is not None:
                    xrefs[target].append(addr)
                    queue.append(target)
                break

            # Indirect jumps: can't follow
            if mnem in ('JMPI.A', 'JMPI.W'):
                break

            # Calls: follow target AND fall through
            if mnem in _CALL_MNEMONICS:
                if target is not None:
                    xrefs[target].append(addr)
                    queue.append(target)
                addr += length
                continue

            # Indirect calls: can't follow target but do fall through
            if mnem in ('JSRI.A', 'JSRI.W'):
                addr += length
                continue

            # Conditional branches: follow both paths
            if _is_cond_branch(mnem):
                if target is not None:
                    xrefs[target].append(addr)
                    queue.append(target)
                addr += length
                continue

            # ADJNZ/SBJNZ: loop branches
            if mnem.startswith('ADJNZ') or mnem.startswith('SBJNZ'):
                if target is not None:
                    xrefs[target].append(addr)
                    queue.append(target)
                addr += length
                continue

            # Normal instruction: fall through
            addr += length

    return instructions, xrefs


# ---------------------------------------------------------------------------
# Linear sweep for unreached regions
# ---------------------------------------------------------------------------

def linear_sweep(fw, instructions, start, end):
    """Decode sequentially in regions not covered by recursive descent."""
    new_instructions = {}
    addr = start
    while addr <= end:
        if addr in instructions or addr in new_instructions:
            # Skip past existing instruction
            if addr in instructions:
                addr += instructions[addr][0]
            else:
                addr += new_instructions[addr][0]
            continue

        if _is_erased(addr) or _is_missing(addr):
            addr += 1
            continue

        b1 = fw[addr]
        if b1 == 0xFF:
            addr += 1
            continue

        length, mnem, ops = decode_instruction(fw, addr)
        if length == 0:
            addr += 1
            continue

        if not _in_rom(addr + length - 1):
            break

        new_instructions[addr] = (length, mnem, ops)
        addr += length

    return new_instructions


# ---------------------------------------------------------------------------
# Function detection and label generation
# ---------------------------------------------------------------------------

def detect_functions(instructions, xrefs):
    """Identify function boundaries from JSR targets and known labels."""
    functions = dict(KNOWN_LABELS)

    # Every JSR/JSR.A target is a function entry
    for target, callers in xrefs.items():
        if target in functions:
            continue
        # Check if any caller is a JSR instruction
        for caller in callers:
            if caller in instructions:
                mnem = instructions[caller][1]
                if mnem in _CALL_MNEMONICS or mnem in ('JSRI.A', 'JSRI.W'):
                    functions[target] = f"sub_{target:05X}"
                    break

    return functions


def generate_labels(instructions, xrefs, functions):
    """Generate all labels: functions + jump targets."""
    labels = dict(functions)

    for target, callers in xrefs.items():
        if target in labels:
            continue
        # Jump targets get loc_ prefix
        labels[target] = f"loc_{target:05X}"

    return labels


# ---------------------------------------------------------------------------
# SFR annotation helper
# ---------------------------------------------------------------------------

def _annotate_sfr(ops):
    """If operands contain an SFR address, return annotation comment."""
    # Look for $XXXX patterns (4-digit hex addresses in operand range)
    import re
    for m in re.finditer(r'\$([0-9A-Fa-f]{4})\b', ops):
        addr = int(m.group(1), 16)
        name = get_sfr_name(addr)
        if name:
            return f"  ; {name}"
    return ""


# ---------------------------------------------------------------------------
# Output formatter
# ---------------------------------------------------------------------------

def format_listing(fw, instructions, xrefs, labels, functions):
    """Produce the complete disassembly listing."""
    lines = []

    # Header
    lines.append("; " + "=" * 68)
    lines.append("; Hakko FM-203 Firmware Disassembly")
    lines.append("; Target: R5F21258SNFP (R8C/25), 64KB ROM ($04000-$13FFF)")
    lines.append("; Generated by r8c_disassembler.py")
    lines.append("; " + "=" * 68)
    lines.append("")

    # Statistics
    code_bytes = sum(inst[0] for inst in instructions.values())
    lines.append(f"; Instructions decoded: {len(instructions)}")
    lines.append(f"; Code bytes: {code_bytes}")
    lines.append(f"; Functions detected: {len(functions)}")
    lines.append(f"; Cross-references: {sum(len(v) for v in xrefs.values())}")
    lines.append("")

    # Missing code stubs
    lines.append("; " + "-" * 68)
    lines.append(f"; Missing code region: ${MISSING_RANGE[0]:05X}-${MISSING_RANGE[1]:05X}")
    lines.append(";   (never captured from video, 7 known call targets)")
    lines.append("; " + "-" * 68)
    for target, callers in sorted(MISSING_TARGETS.items()):
        lines.append(f"sub_{target:05X}:")
        for c in callers:
            lines.append(f"        ; MISSING -- called from {c}")
        lines.append("")

    # Sort all instruction addresses
    all_addrs = sorted(instructions.keys())

    # Track which section we're in
    prev_addr = ROM_START
    in_data = False

    for addr in all_addrs:
        length, mnem, ops = instructions[addr]

        # Gap detection: if there's a gap, show separator
        if addr > prev_addr + 16 and not in_data:
            lines.append("")
            lines.append(f"; --- gap: ${prev_addr:05X}-${addr - 1:05X} ---")
            lines.append("")

        # Label
        if addr in labels:
            label = labels[addr]
            lines.append("")
            # Add xref comments for functions
            if addr in functions and addr in xrefs:
                callers = sorted(xrefs[addr])
                if len(callers) <= 5:
                    refs = ', '.join(f"${c:05X}" for c in callers)
                else:
                    refs = ', '.join(f"${c:05X}" for c in callers[:5]) + f" +{len(callers)-5} more"
                lines.append(f"; xrefs: {refs}")
            lines.append(f"{label}:")

        # Raw bytes
        raw = ' '.join(f'{fw[addr + j]:02X}' for j in range(length))

        # SFR annotation
        sfr_ann = _annotate_sfr(ops)

        # Format line
        op_str = f"{mnem} {ops}".strip() if ops else mnem
        line = f"${addr:05X}:  {raw:<20s} {op_str}{sfr_ann}"
        lines.append(line)

        prev_addr = addr + length

    return '\n'.join(lines)


# ---------------------------------------------------------------------------
# Vector table dump
# ---------------------------------------------------------------------------

def dump_vectors(fw):
    """Dump the interrupt vector table."""
    lines = []
    lines.append("; " + "-" * 68)
    lines.append("; Interrupt Vector Table ($0FF00-$0FFFB)")
    lines.append("; " + "-" * 68)

    vec_start = 0x0FF00
    for i in range(0, 0xFC, 4):
        base = vec_start + i
        addr = fw[base] | (fw[base + 1] << 8) | ((fw[base + 2] & 0x0F) << 16)
        vec_num = i // 4

        if addr == 0x0FC4E:
            note = "(default handler)"
        elif addr in KNOWN_LABELS:
            note = f"({KNOWN_LABELS[addr]})"
        elif addr == 0xFFFFF:
            note = "(erased)"
        else:
            note = ""

        raw = ' '.join(f'{fw[base + j]:02X}' for j in range(4))
        lines.append(f"  ${base:05X}: {raw}  -> ${addr:05X}  vec[{vec_num:2d}] {note}")

    # Reset vector
    base = 0x0FFFC
    addr = fw[base] | (fw[base + 1] << 8) | ((fw[base + 2] & 0x0F) << 16)
    raw = ' '.join(f'{fw[base + j]:02X}' for j in range(4))
    lines.append(f"  ${base:05X}: {raw}  -> ${addr:05X}  RESET ({KNOWN_LABELS.get(addr, '???')})")
    lines.append("")

    return '\n'.join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    path = sys.argv[1] if len(sys.argv) > 1 else 'hakko_fm203.bin'

    if not os.path.exists(path):
        print(f"Error: {path} not found", file=sys.stderr)
        sys.exit(1)

    fw = load_binary(path)

    # Phase 1: Recursive descent from known entry points
    instructions, xrefs = recursive_descent(fw, ENTRY_POINTS)
    rd_count = len(instructions)

    # Phase 2: Linear sweep for unreached regions
    sweep = linear_sweep(fw, instructions, ROM_START, ROM_END)
    instructions.update(sweep)
    ls_count = len(sweep)

    # Phase 3: Detect functions and generate labels
    functions = detect_functions(instructions, xrefs)
    labels = generate_labels(instructions, xrefs, functions)

    # Phase 4: Generate output
    output = []
    output.append(dump_vectors(fw))
    output.append(format_listing(fw, instructions, xrefs, labels, functions))

    # Summary footer
    code_bytes = sum(inst[0] for inst in instructions.values())
    total_rom = ROM_END - ROM_START + 1
    output.append("")
    output.append("; " + "=" * 68)
    output.append(f"; Summary:")
    output.append(f";   Recursive descent: {rd_count} instructions")
    output.append(f";   Linear sweep: {ls_count} additional instructions")
    output.append(f";   Total instructions: {len(instructions)}")
    output.append(f";   Code bytes: {code_bytes} / {total_rom} ({100*code_bytes/total_rom:.1f}%)")
    output.append(f";   Functions: {len(functions)}")
    output.append(f";   Labels: {len(labels)}")
    output.append("; " + "=" * 68)

    print('\n'.join(output))


if __name__ == '__main__':
    main()
