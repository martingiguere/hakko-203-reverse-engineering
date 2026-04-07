#!/usr/bin/env python3
"""
R8C/Tiny instruction length lookup table.

Source: INSTRUCTION_ENCODING.md (R8C/Tiny Series Software Manual REJ09B0001-0200)
Provides get_instruction_length() for walking through R8C machine code.

Encoding formats:
  :G  Generic  2-byte opcode (byte1 + byte2) with 4-bit SRC/DEST fields
  :Q  Quick    2-byte opcode with 4-bit immediate + 4-bit DEST in byte2
  :S  Short    1-byte opcode with 3-bit DEST or 2-bit SRC embedded
  :Z  Zero     1-byte opcode, implicit #0 immediate
"""


def _operand_extra(code):
    """Extra bytes for a 4-bit standard operand code (Section 2.1).

    0-7: register direct -> 0
    8-B: dsp:8[base]     -> 1
    C-E: dsp:16[base]    -> 2
      F: abs16           -> 2
    """
    if code <= 0x7:
        return 0
    if code <= 0xB:
        return 1
    return 2


def _short_dest_extra(ddd):
    """Extra bytes for 3-bit short DEST code (Section 2.2).

    011(3),100(4): register -> 0
    101(5),110(6): dsp8     -> 1
    111(7):        abs16    -> 2
    """
    if ddd <= 4:
        return 0
    if ddd <= 6:
        return 1
    return 2


def get_instruction_length(data, offset):
    """Return instruction length in bytes at given offset, or 0 if invalid.

    Args:
        data: bytes, bytearray, or list of ints
        offset: index of first byte of instruction
    """
    if offset >= len(data):
        return 0

    b1 = data[offset]

    # --- 0x00: BRK (1 byte) ---
    if b1 == 0x00:
        return 1

    # --- 0x01: MOV.B:S R0L, dsp8[SB] (2 bytes) ---
    # Documented as "undefined" but follows the MOV.B:S R0L/R0H,dest pattern:
    # 0x00=BRK, 0x01=dsp8[SB], 0x02=dsp8[FB], 0x03=abs16 (SRC=R0L)
    # Confirmed valid by firmware usage (1324 occurrences in ROM).
    if b1 == 0x01:
        return 2

    # --- 0x02-0x3F: :S format (AND/OR/ADD/SUB/MOV/CMP src,dest) ---
    # Low 2 bits encode operand: 00=reg(1), 01=dsp8(2), 10=dsp8(2), 11=abs16(3)
    # Exception: 0x04 = NOP (also has low2=00, returns 1 correctly)
    if b1 <= 0x3F:
        low2 = b1 & 0x03
        if low2 == 0:
            return 1
        if low2 <= 2:
            return 2
        return 3

    # --- 0x40-0x5F: Bit ops :S (BCLR/BSET/BNOT/BTST) + dsp8 ---
    if b1 <= 0x5F:
        return 2

    # --- 0x60-0x67: JMP.S (3-bit displacement, 1 byte) ---
    if b1 <= 0x67:
        return 1

    # --- 0x68-0x6F: JCnd:S + dsp8 (2 bytes) ---
    if b1 <= 0x6F:
        return 2

    # --- 0x70-0x7F: Multi-byte opcode prefixes ---
    if b1 <= 0x7F:
        return _decode_7x(data, offset)

    # --- 0x80-0x9F: :S #IMM8,dest and :G src,dest ---
    if b1 <= 0x9F:
        return _decode_80_9f(data, offset)

    # --- 0xA0-0xBF: INC/DEC/MOV:Z/NOT:S and :G src,dest ---
    if b1 <= 0xBF:
        return _decode_a0_bf(data, offset)

    # --- 0xC0-0xDF: MOV:S #IMM8, :Q, CMP:G ---
    if b1 <= 0xDF:
        return _decode_c0_df(data, offset)

    # --- 0xE0-0xFF: CMP:S, system ops, jumps ---
    return _decode_e0_ff(data, offset)


# ---- Internal dispatch helpers ----

def _g_src_dest_len(data, offset):
    """Length for :G two-operand src,dest (byte2 = SRC_DEST)."""
    if offset + 1 >= len(data):
        return 0
    b2 = data[offset + 1]
    return 2 + _operand_extra((b2 >> 4) & 0x0F) + _operand_extra(b2 & 0x0F)


def _q_dest_len(data, offset):
    """Length for :Q format (byte2 = IMM4_DEST)."""
    if offset + 1 >= len(data):
        return 0
    return 2 + _operand_extra(data[offset + 1] & 0x0F)


def _decode_7x(data, offset):
    """Decode 0x70-0x7F prefix group."""
    if offset + 1 >= len(data):
        return 0

    b1 = data[offset]
    b2 = data[offset + 1]
    upper = (b2 >> 4) & 0x0F
    lower = b2 & 0x0F

    # 0x70/0x71: MOVA or similar — :G src,dest format
    if b1 <= 0x71:
        return _g_src_dest_len(data, offset)

    # 0x72/0x73: MOV.size:G src,dest
    if b1 <= 0x73:
        return _g_src_dest_len(data, offset)

    # 0x74: MOVDir (2 bytes)
    if b1 == 0x74:
        return 2

    # 0x75: LDC/STC group
    if b1 == 0x75:
        # bit 7: 1=LDC src,creg  0=STC creg,dest
        return 2 + _operand_extra(lower)

    # 0x76/0x77: ALU :G (AND#/ADD#/SUB#/ADC#/SBB#/CMP#/MOV#/OR#/DIV/DIVU/DIVX/ADCF/ABS)
    if b1 <= 0x77:
        imm_size = 2 if b1 == 0x77 else 1
        dest_extra = _operand_extra(lower)
        # Upper nibble selects operation
        if upper in (0x0, 0x1, 0x2, 0x4, 0x5, 0x6, 0x7, 0x8, 0xA, 0xC):
            return 2 + dest_extra + imm_size   # #IMM,dest
        if upper in (0x9, 0xD):
            return 2 + _operand_extra(lower)   # unary src (DIV/DIVX)
        if upper == 0xE:
            if lower in (0x0, 0x1, 0x3):       # DIV/DIVU/DIVX #IMM
                return 2 + imm_size
            return 2 + dest_extra              # ADCF dest
        if upper == 0xF:
            return 2 + dest_extra              # ABS dest
        return 2 + dest_extra                  # fallback (0x3, 0xB)

    # 0x78/0x79: MUL group
    if b1 <= 0x79:
        imm_size = 2 if b1 == 0x79 else 1
        if upper in (0x4, 0x5):
            return 2 + _operand_extra(lower) + imm_size  # MUL/MULU #IMM
        if upper in (0x0, 0x1):
            return _g_src_dest_len(data, offset)          # MUL/MULU src,dest
        return 2 + _operand_extra(lower)

    # 0x7A: LDE/STE group
    if b1 == 0x7A:
        mode = (b2 >> 4) & 0x07  # bits [6:4]
        if mode in (0, 1, 4, 5):
            return 2 + _operand_extra(lower) + 3   # +abs20/dsp20
        return 2 + _operand_extra(lower)           # [A1A0] or other

    # 0x7B: MULU/PUSH/XCHG group
    if b1 == 0x7B:
        return 2 + _operand_extra(lower)

    # 0x7C/0x7D: Bit ops and special
    if b1 <= 0x7D:
        return _decode_7c_7d(data, offset)

    # 0x7E/0x7F: verify — treat as :G src,dest
    return _g_src_dest_len(data, offset)


def _decode_7c_7d(data, offset):
    """Decode 0x7C/0x7D prefix (bit operations, BCD, jumps, special)."""
    if offset + 1 >= len(data):
        return 0

    b1 = data[offset]
    b2 = data[offset + 1]
    upper = (b2 >> 4) & 0x0F
    lower = b2 & 0x0F
    is_word = (b1 == 0x7D)
    imm_size = 2 if is_word else 1

    # === 0x7D-only overrides ===
    if b1 == 0x7D:
        if upper <= 0x3:               # JMPI.A(0), JSRI.A(1), JMPI.W(2), JSRI.W(3)
            return 2 + _operand_extra(lower)
        if b2 & 0xF8 == 0xA0:         # LDIPL #IMM3 (byte2=1010_0xxx)
            return 2
        if upper == 0xB:               # ADD.Q #IMM4,SP
            return 2
        if upper == 0xC:               # JCnd:B + dsp8
            return 3
        if b2 == 0xF2:                 # EXITD
            return 2

    # === 0x7C-only overrides ===
    if b1 == 0x7C:
        if b2 == 0xF0:                 # LDCTX abs16,abs20
            return 7
        if b2 == 0xF2:                 # ENTER #IMM8
            return 3
        if b2 == 0xF3:                 # EXTS.W R0
            return 2

    # === BCD register forms (both): byte2=0110_1100..0110_1111 ===
    if upper == 0x6 and lower >= 0xC:
        return 2                       # DADD/DSUB/DADC/DSBB reg form

    # === Common bit/logic operations ===
    if upper <= 0x1:                   # BTSTC(0), BTSTS(1)
        return 2 + _operand_extra(lower)
    if upper == 0x2:                   # BMCnd dest + condition byte
        return 2 + _operand_extra(lower) + 1
    if upper <= 0x7:                   # BNTST(3),BAND(4),BNAND(5),BOR(6),BNOR(7)
        return 2 + _operand_extra(lower)
    if upper <= 0xA:                   # BCLR:G(8), BSET:G(9), BNOT:G(A)
        return 2 + _operand_extra(lower)
    if upper == 0xB:                   # BTST:G (0x7D handled above as ADD.Q)
        return 2 + _operand_extra(lower)
    if upper == 0xC:                   # BXOR (0x7D handled above as JCnd:B)
        return 2 + _operand_extra(lower)
    if upper == 0xD:                   # BNXOR / BMCnd C
        return 2 + _operand_extra(lower)
    if upper == 0xE:                   # ADD#SP, BCD #IMM
        if lower == 0xB:
            return 2 + imm_size        # ADD #IMM,SP
        if lower >= 0xC:
            return 2 + imm_size        # DADD/DSUB/DADC/DSBB #IMM
        return 2 + _operand_extra(lower)
    if upper == 0xF:
        return 2                       # unknown F-pattern fallback

    return 2


def _decode_80_9f(data, offset):
    """Decode 0x80-0x9F: :S #IMM8,dest (ADD/SUB/AND/OR) and :G src,dest."""
    b1 = data[offset]
    ddd = b1 & 0x07

    # DDD 0-2: :G two-operand src,dest (e.g. AND.B:G at 0x90)
    if ddd <= 2:
        return _g_src_dest_len(data, offset)

    # DDD 3-7: :S #IMM8,dest
    return 1 + _short_dest_extra(ddd) + 1


def _decode_a0_bf(data, offset):
    """Decode 0xA0-0xBF: INC/DEC/MOV:Z/NOT:S and :G src,dest."""
    b1 = data[offset]
    ddd = b1 & 0x07

    # DDD 0-1: :G two-operand (ADD:G, ADC:G etc.)
    if ddd <= 1:
        return _g_src_dest_len(data, offset)

    # DDD 2: 1-byte instructions (INC.W A0=0xB2, DEC.W A0/A1, etc.)
    if ddd == 2:
        return 1

    # DDD 3-7: :S no-immediate (INC/DEC/MOV:Z/NOT)
    return 1 + _short_dest_extra(ddd)


def _decode_c0_df(data, offset):
    """Decode 0xC0-0xDF: CMP:G, MOV:S #IMM8, :Q formats."""
    b1 = data[offset]
    ddd = b1 & 0x07

    # 0xC0/0xC1: CMP.size:G src,dest
    if b1 <= 0xC1:
        return _g_src_dest_len(data, offset)
    # 0xC2: uncertain — treat as :G
    if b1 == 0xC2:
        return _g_src_dest_len(data, offset)
    # 0xC3-0xC7: MOV.B:S #IMM8,dest
    if b1 <= 0xC7:
        return 1 + _short_dest_extra(ddd) + 1

    # 0xC8-0xDF: :Q format (ADD:Q, CMP:Q, MOV:Q, SHL:Q, SHA:Q, ROT:Q etc.)
    return _q_dest_len(data, offset)


def _decode_e0_ff(data, offset):
    """Decode 0xE0-0xFF: CMP:S, system ops, jumps, returns."""
    b1 = data[offset]
    ddd = b1 & 0x07

    # 0xE0-0xE2: uncertain — treat as :G src,dest
    if b1 <= 0xE2:
        return _g_src_dest_len(data, offset)
    # 0xE3-0xE7: CMP.B:S #IMM8,dest
    if b1 <= 0xE7:
        return 1 + _short_dest_extra(ddd) + 1

    if b1 == 0xE8: return 2    # STNZ #IMM8
    if b1 == 0xE9: return 2    # STZ #IMM8
    if b1 == 0xEA: return 3    # STZX #IMM1,#IMM2

    # 0xEB: multi-instruction prefix
    if b1 == 0xEB:
        return _decode_eb(data, offset)

    # 0xEC-0xEF: PUSH/POP/PUSHM/POPM (2 bytes)
    if b1 <= 0xEF:
        return 2

    # 0xF0/0xF1: :G format (verify)
    if b1 <= 0xF1:
        return _g_src_dest_len(data, offset)
    # 0xF2: uncertain instruction (2 bytes)
    if b1 == 0xF2:
        return 2

    if b1 == 0xF3: return 1    # RTS
    if b1 == 0xF4: return 3    # JMP.W + dsp16
    if b1 == 0xF5: return 3    # JSR.W + dsp16
    if b1 == 0xF6: return 1    # INTO
    if b1 == 0xF7: return 1    # uncertain (possibly SMOVF or WAIT)

    # 0xF8/0xF9: ADJNZ.B/ADJNZ.W, 0xFA: SBJNZ.B
    # Format: byte1 + byte2(IMM4_DEST) + dest_operands + label8
    if b1 <= 0xFA:
        if offset + 1 >= len(data):
            return 0
        dest = data[offset + 1] & 0x0F
        return 3 + _operand_extra(dest)

    if b1 == 0xFB: return 1    # REIT (return from interrupt)

    if b1 == 0xFC: return 4    # JMP.A + abs20
    if b1 == 0xFD: return 4    # JSR.A + abs20
    if b1 == 0xFE: return 2    # JMP.B + dsp8
    return 1                   # 0xFF: UND


def _decode_eb(data, offset):
    """Decode 0xEB multi-instruction prefix."""
    if offset + 1 >= len(data):
        return 0

    b2 = data[offset + 1]

    # INT #IMM: byte2 >= 0xC0 (11_IIIIII)
    if b2 >= 0xC0:
        return 2
    # LDC #IMM16: byte2 = 0DDD_0000 (includes INTBH when DDD=2, byte2=0x20)
    if (b2 & 0x8F) == 0x00:
        return 4
    # FSET: byte2 = 0DDD_0100
    if (b2 & 0x8F) == 0x04:
        return 2
    # FCLR: byte2 = 0DDD_0101
    if (b2 & 0x8F) == 0x05:
        return 2
    # STC: byte2 = 0DDD_0001 (verify — may need dest operand bytes)
    if (b2 & 0x8F) == 0x01:
        return 2

    return 2  # fallback for other 0xEB patterns


# =========================================================================
# Mnemonic decoder — returns (length, mnemonic, operands_string)
# =========================================================================

# 4-bit operand register names
_REG4_B = ['R0L', 'R0H', 'R1L', 'R1H', 'A0', 'A1', '[A0]', '[A1]']
_REG4_W = ['R0', 'R1', 'R2', 'R3', 'A0', 'A1', '[A0]', '[A1]']

# 3-bit short dest names (only 3-7 valid)
_DEST3 = {3: 'R0H', 4: 'R0L', 5: 'dsp8[SB]', 6: 'dsp8[FB]', 7: 'abs16'}

# Condition codes
_COND3 = ['GEU', 'GTU', 'EQ', 'N', 'LTU', 'LEU', 'NE', 'PZ']
_COND4 = ['GEU', 'GTU', 'EQ', 'N', 'LTU', 'LEU', 'NE', 'PZ',
          'LE', 'O', 'GE', '???', 'GT', 'NO', 'LT', '???']

# Control register names (3-bit code)
_CTRL_REG = ['???', 'INTBL', 'INTBH', 'FLG', 'ISP', 'SP', 'SB', 'FB']

# Flag names for FSET/FCLR (3-bit code)
_FLAG_NAMES = ['C', 'D', 'Z', 'S', 'B', 'O', 'I', 'U']

# 0x76/0x77 ALU group: upper nibble of byte2 -> mnemonic
_ALU76_MNEMONICS = {
    0x0: 'DIVU', 0x1: 'DIVX', 0x2: 'AND', 0x3: '???',
    0x4: 'ADD', 0x5: 'SUB', 0x6: 'ADC', 0x7: 'SBB',
    0x8: 'CMP', 0x9: 'DIVX', 0xA: 'OR', 0xB: '???',
    0xC: 'MOV', 0xD: 'DIV', 0xE: 'ADCF', 0xF: 'ABS',
}

# 0x7C/0x7D bit-op group: upper nibble of byte2 -> mnemonic
_BIT7C_MNEMONICS = {
    0x0: 'BTSTC', 0x1: 'BTSTS', 0x2: 'BMCnd', 0x3: 'BNTST',
    0x4: 'BAND', 0x5: 'BNAND', 0x6: 'BOR', 0x7: 'BNOR',
    0x8: 'BCLR', 0x9: 'BSET', 0xA: 'BNOT', 0xB: 'BTST',
    0xC: 'BXOR', 0xD: 'BNXOR',
}

# :G two-operand byte1 -> mnemonic (low bit = size)
_G_TWO_OP = {
    0x72: 'MOV.B', 0x73: 'MOV.W',
    0x90: 'AND.B', 0x91: 'AND.W',
    0x80: 'SUB.B', 0x81: 'SUB.W',   # verify
    0xA0: 'ADD.B', 0xA1: 'ADD.W',
    0xB0: 'ADC.B', 0xB1: 'ADC.W',
    0xC0: 'CMP.B', 0xC1: 'CMP.W',
    0xC2: 'SBB.B',                    # verify
    0xE0: 'TST.B', 0xE1: 'TST.W',   # verify
    0xE2: 'XOR.B',                    # verify
    0xF0: 'SHA.B', 0xF1: 'SHA.W',   # verify
}


def _read8(data, pos):
    """Read unsigned 8-bit value."""
    if pos < len(data):
        return data[pos]
    return 0


def _read8s(data, pos):
    """Read signed 8-bit value."""
    v = _read8(data, pos)
    return v - 256 if v >= 128 else v


def _read16(data, pos):
    """Read unsigned 16-bit little-endian value."""
    if pos + 1 < len(data):
        return data[pos] | (data[pos + 1] << 8)
    return 0


def _read16s(data, pos):
    """Read signed 16-bit little-endian value."""
    v = _read16(data, pos)
    return v - 65536 if v >= 32768 else v


def _read20(data, pos):
    """Read 20-bit little-endian address (3 bytes, top 4 bits masked)."""
    if pos + 2 < len(data):
        return data[pos] | (data[pos + 1] << 8) | ((data[pos + 2] & 0x0F) << 16)
    return 0


def _fmt_op4(code, data, pos, is_word):
    """Format a 4-bit standard operand code.
    Returns (formatted_string, number_of_extra_bytes_consumed)."""
    regs = _REG4_W if is_word else _REG4_B
    if code <= 7:
        return regs[code], 0
    _DSP8_BASE = {8: 'A0', 9: 'A1', 0xA: 'SB', 0xB: 'FB'}
    if code <= 0xB:
        dsp = _read8(data, pos)
        return f"${dsp:02X}[{_DSP8_BASE[code]}]", 1
    _DSP16_BASE = {0xC: 'A0', 0xD: 'A1', 0xE: 'SB'}
    if code <= 0xE:
        dsp = _read16(data, pos)
        return f"${dsp:04X}[{_DSP16_BASE[code]}]", 2
    # code == 0xF: abs16
    addr = _read16(data, pos)
    return f"${addr:04X}", 2


def _fmt_dest3(ddd, data, pos):
    """Format a 3-bit short dest operand (codes 3-7).
    Returns (formatted_string, extra_bytes_consumed)."""
    if ddd <= 4:
        return ('R0H' if ddd == 3 else 'R0L'), 0
    if ddd == 5:
        dsp = _read8(data, pos)
        return f"${dsp:02X}[SB]", 1
    if ddd == 6:
        dsp = _read8(data, pos)
        return f"${dsp:02X}[FB]", 1
    # ddd == 7: abs16
    addr = _read16(data, pos)
    return f"${addr:04X}", 2


def _fmt_short_src(ss, dest_bit, data, pos):
    """Format :S 2-bit SRC + 1-bit DEST (for ADD/AND/OR/SUB/CMP/MOV .B:S src,R0L/R0H).
    Returns (src_str, dst_str, extra_bytes)."""
    dst = 'R0H' if dest_bit else 'R0L'
    if ss == 0:
        # src is the OTHER half from dest
        src = 'R0L' if dest_bit else 'R0H'
        return src, dst, 0
    if ss == 1:
        dsp = _read8(data, pos)
        return f"${dsp:02X}[SB]", dst, 1
    if ss == 2:
        dsp = _read8(data, pos)
        return f"${dsp:02X}[FB]", dst, 1
    # ss == 3: abs16
    addr = _read16(data, pos)
    return f"${addr:04X}", dst, 2


def _fmt_g_src_dest(data, offset, is_word):
    """Format :G two-operand src,dest from byte2.
    Returns operands string."""
    if offset + 1 >= len(data):
        return "???"
    b2 = data[offset + 1]
    src_code = (b2 >> 4) & 0x0F
    dst_code = b2 & 0x0F
    pos = offset + 2
    src_str, src_extra = _fmt_op4(src_code, data, pos, is_word)
    pos += src_extra
    dst_str, _ = _fmt_op4(dst_code, data, pos, is_word)
    return f"{src_str},{dst_str}"


def _fmt_q_imm_dest(data, offset, is_word):
    """Format :Q #IMM4,dest from byte2.
    Returns operands string."""
    if offset + 1 >= len(data):
        return "???"
    b2 = data[offset + 1]
    imm4 = (b2 >> 4) & 0x0F
    # Sign-extend 4-bit value
    if imm4 >= 8:
        imm4 -= 16
    dst_code = b2 & 0x0F
    pos = offset + 2
    dst_str, _ = _fmt_op4(dst_code, data, pos, is_word)
    return f"#{imm4},{dst_str}"


def decode_instruction(data, offset):
    """Decode one R8C instruction at offset.

    Returns (length, mnemonic, operands_string) where length is in bytes,
    or (0, '???', '') if invalid.
    """
    length = get_instruction_length(data, offset)
    if length == 0:
        return (0, '???', '')

    if offset >= len(data):
        return (0, '???', '')

    b1 = data[offset]

    # === 0x00: BRK ===
    if b1 == 0x00:
        return (1, 'BRK', '')

    # === 0x01: MOV.B:S R0L,dsp:8[SB] ===
    if b1 == 0x01:
        dsp = _read8(data, offset + 1)
        return (2, 'MOV.B:S', f"R0L,${dsp:02X}[SB]")

    # === 0x02-0x03: MOV.B:S R0L,dest ===
    # === 0x04: NOP ===
    # === 0x05-0x07: MOV.B:S R0H,dest ===
    if b1 <= 0x07:
        if b1 == 0x04:
            return (1, 'NOP', '')
        src_bit = (b1 >> 2) & 1  # 0=R0L, 1=R0H
        dest_code = b1 & 0x03
        src = 'R0H' if src_bit else 'R0L'
        if dest_code == 1:
            dsp = _read8(data, offset + 1)
            dst = f"${dsp:02X}[SB]"
        elif dest_code == 2:
            dsp = _read8(data, offset + 1)
            dst = f"${dsp:02X}[FB]"
        else:  # 3 = abs16
            addr = _read16(data, offset + 1)
            dst = f"${addr:04X}"
        return (length, 'MOV.B:S', f"{src},{dst}")

    # === 0x08-0x0F: MOV.B:S src,R0L/R0H ===
    if b1 <= 0x0F:
        dest_bit = (b1 >> 2) & 1  # 0=R0L, 1=R0H
        ss = b1 & 0x03
        src, dst, _ = _fmt_short_src(ss, dest_bit, data, offset + 1)
        return (length, 'MOV.B:S', f"{src},{dst}")

    # === 0x10-0x17: AND.B:S src,R0L/R0H ===
    if b1 <= 0x17:
        dest_bit = (b1 >> 2) & 1
        ss = b1 & 0x03
        src, dst, _ = _fmt_short_src(ss, dest_bit, data, offset + 1)
        return (length, 'AND.B:S', f"{src},{dst}")

    # === 0x18-0x1F: OR.B:S src,R0L/R0H ===
    if b1 <= 0x1F:
        dest_bit = (b1 >> 2) & 1
        ss = b1 & 0x03
        src, dst, _ = _fmt_short_src(ss, dest_bit, data, offset + 1)
        return (length, 'OR.B:S', f"{src},{dst}")

    # === 0x20-0x27: ADD.B:S src,R0L/R0H ===
    if b1 <= 0x27:
        dest_bit = (b1 >> 2) & 1
        ss = b1 & 0x03
        src, dst, _ = _fmt_short_src(ss, dest_bit, data, offset + 1)
        return (length, 'ADD.B:S', f"{src},{dst}")

    # === 0x28-0x2F: SUB.B:S src,R0L/R0H ===
    if b1 <= 0x2F:
        dest_bit = (b1 >> 2) & 1
        ss = b1 & 0x03
        src, dst, _ = _fmt_short_src(ss, dest_bit, data, offset + 1)
        return (length, 'SUB.B:S', f"{src},{dst}")

    # === 0x30-0x37: MOV.B:S src,A0/A1 ===
    if b1 <= 0x37:
        dest_bit = (b1 >> 2) & 1  # 0=A0, 1=A1
        ss = b1 & 0x03
        dst = 'A1' if dest_bit else 'A0'
        if ss == 0:
            src = 'R0L'  # register direct
        elif ss == 1:
            dsp = _read8(data, offset + 1)
            src = f"${dsp:02X}[SB]"
        elif ss == 2:
            dsp = _read8(data, offset + 1)
            src = f"${dsp:02X}[FB]"
        else:
            addr = _read16(data, offset + 1)
            src = f"${addr:04X}"
        return (length, 'MOV.B:S', f"{src},{dst}")

    # === 0x38-0x3F: CMP.B:S src,R0L/R0H ===
    if b1 <= 0x3F:
        dest_bit = (b1 >> 2) & 1
        ss = b1 & 0x03
        src, dst, _ = _fmt_short_src(ss, dest_bit, data, offset + 1)
        return (length, 'CMP.B:S', f"{src},{dst}")

    # === 0x40-0x5F: Bit ops :S (BCLR/BSET/BNOT/BTST) ===
    if b1 <= 0x5F:
        bit_num = b1 & 0x07
        op_idx = (b1 >> 3) & 0x03  # 0=BCLR, 1=BSET, 2=BNOT, 3=BTST
        ops = ['BCLR', 'BSET', 'BNOT', 'BTST']
        dsp = _read8(data, offset + 1)
        return (length, f"{ops[op_idx]}:S", f"{bit_num},${dsp:02X}[SB]")

    # === 0x60-0x67: JMP.S ===
    if b1 <= 0x67:
        disp = b1 & 0x07
        target = offset + 2 + disp
        return (1, 'JMP.S', f"${target:05X}")

    # === 0x68-0x6F: JCnd:S ===
    if b1 <= 0x6F:
        cond = _COND3[b1 & 0x07]
        disp = _read8s(data, offset + 1)
        target = offset + 2 + disp
        return (2, f"J{cond}", f"${target:05X}")

    # === 0x70-0x7F: Multi-byte prefix ===
    if b1 <= 0x7F:
        return _decode_7x_mnem(data, offset, length)

    # === 0x80-0x9F ===
    if b1 <= 0x9F:
        return _decode_80_9f_mnem(data, offset, length)

    # === 0xA0-0xBF ===
    if b1 <= 0xBF:
        return _decode_a0_bf_mnem(data, offset, length)

    # === 0xC0-0xDF ===
    if b1 <= 0xDF:
        return _decode_c0_df_mnem(data, offset, length)

    # === 0xE0-0xFF ===
    return _decode_e0_ff_mnem(data, offset, length)


# ---- Mnemonic decode helpers ----

def _decode_7x_mnem(data, offset, length):
    """Decode mnemonic for 0x70-0x7F prefix group."""
    b1 = data[offset]
    if offset + 1 >= len(data):
        return (length, '???', '')
    b2 = data[offset + 1]
    upper = (b2 >> 4) & 0x0F
    lower = b2 & 0x0F
    is_word = b1 & 1

    # 0x70/0x71: MOVA or :G src,dest (verify)
    if b1 <= 0x71:
        sz = '.W' if is_word else '.B'
        ops = _fmt_g_src_dest(data, offset, is_word)
        return (length, f"MOVA{sz}", ops)

    # 0x72/0x73: MOV.size:G src,dest
    if b1 <= 0x73:
        sz = '.W' if is_word else '.B'
        ops = _fmt_g_src_dest(data, offset, is_word)
        return (length, f"MOV{sz}:G", ops)

    # 0x74: MOVDir (2 bytes)
    if b1 == 0x74:
        return (length, 'MOVDir', f"${b2:02X}")

    # 0x75: LDC/STC (control regs are 16-bit, use word operands)
    if b1 == 0x75:
        if b2 & 0x80:  # LDC src,creg
            creg = _CTRL_REG[(b2 >> 4) & 0x07]
            src_str, _ = _fmt_op4(lower, data, offset + 2, True)
            return (length, 'LDC', f"{src_str},{creg}")
        else:  # STC creg,dest
            creg = _CTRL_REG[(b2 >> 4) & 0x07]
            dst_str, _ = _fmt_op4(lower, data, offset + 2, True)
            return (length, 'STC', f"{creg},{dst_str}")

    # 0x76/0x77: ALU :G #IMM,dest / unary
    if b1 <= 0x77:
        sz = '.W' if is_word else '.B'
        imm_size = 2 if is_word else 1
        mnem_base = _ALU76_MNEMONICS.get(upper, '???')

        # Unary ops: DIV (0xD), DIVX (0x9) — src only
        if upper in (0x9, 0xD):
            src_str, _ = _fmt_op4(lower, data, offset + 2, is_word)
            return (length, f"{mnem_base}{sz}", src_str)

        # ABS (0xF, lower bit 3 set)
        if upper == 0xF:
            dst_str, _ = _fmt_op4(lower & 0x07, data, offset + 2, is_word)
            return (length, f"ABS{sz}", dst_str)

        # ADCF (0xE) — can also be DIVU#/DIV#/DIVX# for specific lower values
        if upper == 0xE:
            if lower in (0x0, 0x1, 0x3):
                names = {0x0: 'DIVU', 0x1: 'DIV', 0x3: 'DIVX'}
                imm_pos = offset + 2
                if is_word:
                    imm = _read16(data, imm_pos)
                    return (length, f"{names[lower]}{sz}", f"#${imm:04X}")
                else:
                    imm = _read8(data, imm_pos)
                    return (length, f"{names[lower]}{sz}", f"#${imm:02X}")
            dst_str, _ = _fmt_op4(lower, data, offset + 2, is_word)
            return (length, f"ADCF{sz}", dst_str)

        # Standard #IMM,dest
        pos = offset + 2
        dst_str, dst_extra = _fmt_op4(lower, data, pos, is_word)
        pos += dst_extra
        if is_word:
            imm = _read16(data, pos)
            return (length, f"{mnem_base}{sz}:G", f"#${imm:04X},{dst_str}")
        else:
            imm = _read8(data, pos)
            return (length, f"{mnem_base}{sz}:G", f"#${imm:02X},{dst_str}")

    # 0x78/0x79: MUL group
    if b1 <= 0x79:
        sz = '.W' if is_word else '.B'
        imm_size = 2 if is_word else 1
        if upper in (0x4, 0x5):
            mnem = 'MUL' if upper == 0x4 else 'MULU'
            pos = offset + 2
            dst_str, dst_extra = _fmt_op4(lower, data, pos, is_word)
            pos += dst_extra
            if is_word:
                imm = _read16(data, pos)
                return (length, f"{mnem}{sz}", f"#${imm:04X},{dst_str}")
            else:
                imm = _read8(data, pos)
                return (length, f"{mnem}{sz}", f"#${imm:02X},{dst_str}")
        if upper in (0x0, 0x1):
            mnem = 'MUL' if upper == 0x0 else 'MULU'
            ops = _fmt_g_src_dest(data, offset, is_word)
            return (length, f"{mnem}{sz}", ops)
        # Other sub-ops
        dst_str, _ = _fmt_op4(lower, data, offset + 2, is_word)
        return (length, f"MUL_OP{sz}", dst_str)

    # 0x7A: LDE/STE
    if b1 == 0x7A:
        size_bit = (b2 >> 7) & 1
        mode = (b2 >> 4) & 0x07
        sz = '.W' if size_bit else '.B'
        op_code = lower
        pos = offset + 2
        op_str, op_extra = _fmt_op4(op_code, data, pos, size_bit)
        pos += op_extra
        if mode in (0, 1):
            # LDE abs20/dsp20
            addr20 = _read20(data, pos)
            if mode == 0:
                return (length, f"LDE{sz}", f"${addr20:05X},{op_str}")
            else:
                return (length, f"LDE{sz}", f"${addr20:05X}[A0],{op_str}")
        if mode == 2:
            return (length, f"LDE{sz}", f"[A1A0],{op_str}")
        if mode in (4, 5):
            addr20 = _read20(data, pos)
            if mode == 4:
                return (length, f"STE{sz}", f"{op_str},${addr20:05X}")
            else:
                return (length, f"STE{sz}", f"{op_str},${addr20:05X}[A0]")
        if mode == 6:
            return (length, f"STE{sz}", f"{op_str},[A1A0]")
        return (length, f"LDE/STE{sz}", f"mode={mode}")

    # 0x7B: MULU/PUSH/XCHG group
    if b1 == 0x7B:
        op_str, _ = _fmt_op4(lower, data, offset + 2, upper & 1)
        if upper == 0x0:
            return (length, 'MULU.B', op_str)
        if upper == 0x1:
            return (length, 'MULU.W', op_str)
        if upper == 0x2:
            return (length, 'PUSH.B:G', op_str)
        if upper == 0x3:
            return (length, 'PUSH.W:G', op_str)
        if upper == 0x4:
            return (length, 'XCHG.B', op_str)
        if upper == 0x5:
            return (length, 'XCHG.W', op_str)
        return (length, f"OP7B_{upper:X}", op_str)

    # 0x7C/0x7D: Bit ops and special
    if b1 <= 0x7D:
        return _decode_7c_7d_mnem(data, offset, length)

    # 0x7E/0x7F: verify — treat as :G src,dest
    ops = _fmt_g_src_dest(data, offset, is_word)
    return (length, f"OP_{b1:02X}", ops)


def _decode_7c_7d_mnem(data, offset, length):
    """Decode mnemonic for 0x7C/0x7D prefix."""
    b1 = data[offset]
    b2 = data[offset + 1]
    upper = (b2 >> 4) & 0x0F
    lower = b2 & 0x0F
    is_word = (b1 == 0x7D)
    sz = '.W' if is_word else '.B'
    imm_size = 2 if is_word else 1

    # === 0x7D-only overrides ===
    if b1 == 0x7D:
        # JMPI.A / JSRI.A / JMPI.W / JSRI.W
        if upper <= 0x3:
            names = {0: 'JMPI.A', 1: 'JSRI.A', 2: 'JMPI.W', 3: 'JSRI.W'}
            src_str, _ = _fmt_op4(lower, data, offset + 2, False)
            return (length, names[upper], src_str)
        # LDIPL #IMM3
        if b2 & 0xF8 == 0xA0:
            imm3 = b2 & 0x07
            return (length, 'LDIPL', f"#{imm3}")
        # ADD.Q #IMM4,SP
        if upper == 0xB:
            imm4 = lower
            if imm4 >= 8:
                imm4 -= 16
            return (length, 'ADD.Q', f"#{imm4},SP")
        # JCnd:B
        if upper == 0xC:
            cond = _COND4[lower]
            disp = _read8s(data, offset + 2)
            target = offset + 3 + disp
            return (length, f"J{cond}", f"${target:05X}")
        # EXITD
        if b2 == 0xF2:
            return (length, 'EXITD', '')

    # === 0x7C-only overrides ===
    if b1 == 0x7C:
        # LDCTX
        if b2 == 0xF0:
            addr16 = _read16(data, offset + 2)
            addr20 = _read20(data, offset + 4)
            return (length, 'LDCTX', f"${addr16:04X},${addr20:05X}")
        # ENTER
        if b2 == 0xF2:
            imm = _read8(data, offset + 2)
            return (length, 'ENTER', f"#${imm:02X}")
        # EXTS.W R0
        if b2 == 0xF3:
            return (length, 'EXTS.W', 'R0')
        # EXTS.B dest (byte2 = 0110_DEST)
        if upper == 0x6 and lower <= 0xB:
            dst_str, _ = _fmt_op4(lower, data, offset + 2, False)
            return (length, 'EXTS.B', dst_str)

    # === BCD register forms: byte2=0110_11xx ===
    if upper == 0x6 and lower >= 0xC:
        bcd_ops = {0xC: 'DADD', 0xD: 'DSUB', 0xE: 'DADC', 0xF: 'DSBB'}
        mnem = bcd_ops[lower]
        if is_word:
            return (length, f"{mnem}.W", 'R1,R0')
        else:
            return (length, f"{mnem}.B", 'R0H,R0L')

    # === BCD #IMM forms: byte2=1110_11xx ===
    if upper == 0xE and lower >= 0xC:
        bcd_ops = {0xC: 'DADD', 0xD: 'DSUB', 0xE: 'DADC', 0xF: 'DSBB'}
        mnem = bcd_ops[lower]
        if is_word:
            imm = _read16(data, offset + 2)
            return (length, f"{mnem}.W", f"#${imm:04X},R0")
        else:
            imm = _read8(data, offset + 2)
            return (length, f"{mnem}.B", f"#${imm:02X},R0L")

    # === upper=0xE special encodings ===
    if upper == 0xE:
        # String and special 2-byte instructions
        _E_OPS = {
            0x0: 'SHL', 0x1: 'SHA', 0x2: 'RMPA',
            0x3: 'SMOVB', 0x4: 'SSTR', 0x5: 'SMOVF',
            0x6: 'SCMPU', 0x7: 'SOUT', 0x8: 'ROT',
            0x9: 'NEG', 0xA: 'ROLC',
        }
        if lower == 0xB:
            # ADD #IMM,SP
            if is_word:
                imm = _read16(data, offset + 2)
                return (length, 'ADD.W', f"#${imm:04X},SP")
            else:
                imm = _read8(data, offset + 2)
                return (length, 'ADD.B', f"#${imm:02X},SP")
        if lower >= 0xC:
            # BCD ops (already handled above, but just in case)
            bcd_ops = {0xC: 'DADD', 0xD: 'DSUB', 0xE: 'DADC', 0xF: 'DSBB'}
            mnem = bcd_ops[lower]
            if is_word:
                imm = _read16(data, offset + 2)
                return (length, f"{mnem}.W", f"#${imm:04X},R0")
            else:
                imm = _read8(data, offset + 2)
                return (length, f"{mnem}.B", f"#${imm:02X},R0L")
        if lower in _E_OPS:
            mnem = _E_OPS[lower]
            if lower <= 0x1 or lower == 0x8:
                # SHL/SHA/ROT R1H,dest — unary with implicit R1H count
                return (length, f"{mnem}{sz}", f"R1H,R0" if is_word else f"R1H,R0L")
            if lower in (0x9, 0xA):
                # NEG/ROLC dest — unary
                dst_str = 'R0' if is_word else 'R0L'
                return (length, f"{mnem}{sz}", dst_str)
            # RMPA/SMOVB/SSTR/SMOVF/SCMPU/SOUT — no explicit operands
            return (length, f"{mnem}{sz}", '')
        return (length, f"OP{sz}_{b1:02X}_E{lower:X}", '')

    # === Standard bit operations ===
    if upper <= 0xD:
        mnem_base = _BIT7C_MNEMONICS.get(upper, '???')
        op_str, op_extra = _fmt_op4(lower, data, offset + 2, is_word)

        if upper == 0x2:  # BMCnd: + condition byte after operand
            pos = offset + 2 + op_extra
            cnd_byte = _read8(data, pos)
            cond = _COND4[cnd_byte & 0x0F]
            return (length, f"BM{cond}", op_str)

        return (length, f"{mnem_base}{sz}", op_str)

    # Fallback for upper == 0xE (non-BCD, non-ADD#SP) and 0xF
    if upper == 0xF:
        return (length, f"OP_{b1:02X}_{b2:02X}", '')

    op_str, _ = _fmt_op4(lower, data, offset + 2, is_word)
    return (length, f"OP{sz}_{b1:02X}_{upper:X}x", op_str)


def _decode_80_9f_mnem(data, offset, length):
    """Decode mnemonic for 0x80-0x9F."""
    b1 = data[offset]
    ddd = b1 & 0x07
    group = (b1 >> 3) & 0x03  # 0=ADD/SUB, 1=SUB/?, 2=AND, 3=OR

    # DDD 0-2: :G two-operand src,dest
    if ddd <= 2:
        is_word = ddd & 1
        # Map byte1 to mnemonic
        base = b1 & 0xF8
        mnemonics = {
            0x80: 'ADD', 0x88: 'SUB',
            0x90: 'AND', 0x98: 'OR',
        }
        mnem = mnemonics.get(base, '???')
        sz = '.W' if is_word else '.B'
        # ddd==2 is uncertain, use :G format anyway
        ops = _fmt_g_src_dest(data, offset, is_word)
        return (length, f"{mnem}{sz}:G", ops)

    # DDD 3-7: :S #IMM8,dest  (byte order: byte1 | IMM8 | dest_operands)
    mnemonics = {0x80: 'ADD', 0x88: 'SUB', 0x90: 'AND', 0x98: 'OR'}
    mnem = mnemonics.get(b1 & 0xF8, '???')
    pos = offset + 1
    imm = _read8(data, pos)
    pos += 1
    dst_str, _ = _fmt_dest3(ddd, data, pos)
    return (length, f"{mnem}.B:S", f"#${imm:02X},{dst_str}")


def _decode_a0_bf_mnem(data, offset, length):
    """Decode mnemonic for 0xA0-0xBF."""
    b1 = data[offset]
    ddd = b1 & 0x07
    group = (b1 >> 3) & 0x03  # 0=ADD/INC, 1=SUB?/DEC, 2=MOV:Z/INC.W, 3=NOT/DEC.W?

    # DDD 0-1: :G two-operand src,dest
    if ddd <= 1:
        is_word = ddd & 1
        base = b1 & 0xF8
        mnemonics = {
            0xA0: 'ADD', 0xA8: 'SBB',
            0xB0: 'ADC', 0xB8: 'SBB',
        }
        mnem = mnemonics.get(base, '???')
        sz = '.W' if is_word else '.B'
        ops = _fmt_g_src_dest(data, offset, is_word)
        return (length, f"{mnem}{sz}:G", ops)

    # DDD 2: 1-byte special (INC.W A0, DEC.W, etc.)
    if ddd == 2:
        base = b1 & 0xF8
        if base == 0xB0:
            return (length, 'INC.W', 'A0')
        if base == 0xB8:
            return (length, 'DEC.W', 'A0')
        if base == 0xA0:
            return (length, 'INC.W', 'A1')  # verify
        if base == 0xA8:
            return (length, 'DEC.W', 'A1')  # verify
        return (length, f"OP_{b1:02X}", '')

    # DDD 3-7: INC.B / DEC.B / MOV.B:Z / NOT.B:S
    base = b1 & 0xF8
    pos = offset + 1
    dst_str, _ = _fmt_dest3(ddd, data, pos)

    if base == 0xA0:
        return (length, 'INC.B', dst_str)
    if base == 0xA8:
        return (length, 'DEC.B', dst_str)
    if base == 0xB0:
        return (length, 'MOV.B:Z', f"#0,{dst_str}")
    if base == 0xB8:
        return (length, 'NOT.B:S', dst_str)
    return (length, f"OP_{b1:02X}", dst_str)


def _decode_c0_df_mnem(data, offset, length):
    """Decode mnemonic for 0xC0-0xDF."""
    b1 = data[offset]
    ddd = b1 & 0x07

    # 0xC0/0xC1: CMP.size:G src,dest
    if b1 <= 0xC1:
        is_word = b1 & 1
        sz = '.W' if is_word else '.B'
        ops = _fmt_g_src_dest(data, offset, is_word)
        return (length, f"CMP{sz}:G", ops)

    # 0xC2: uncertain, treat as :G
    if b1 == 0xC2:
        ops = _fmt_g_src_dest(data, offset, False)
        return (length, 'SBB.B:G', ops)  # verify

    # 0xC3-0xC7: MOV.B:S #IMM8,dest  (byte order: byte1 | IMM8 | dest_operands)
    if b1 <= 0xC7:
        pos = offset + 1
        imm = _read8(data, pos)
        pos += 1
        dst_str, _ = _fmt_dest3(ddd, data, pos)
        return (length, 'MOV.B:S', f"#${imm:02X},{dst_str}")

    # 0xC8-0xDF: :Q format
    is_word = b1 & 1
    sz = '.W' if is_word else '.B'
    base = b1 & 0xFE
    mnemonics = {
        0xC8: 'ADD', 0xCA: 'SHL', 0xCC: 'SHA', 0xCE: 'ROT',
        0xD0: 'CMP', 0xD2: 'SHL', 0xD4: 'SHA', 0xD6: 'ROT',
        0xD8: 'MOV', 0xDA: 'SHL', 0xDC: 'SHA', 0xDE: 'ROT',
    }
    mnem = mnemonics.get(base, '???')
    ops = _fmt_q_imm_dest(data, offset, is_word)
    return (length, f"{mnem}{sz}:Q", ops)


def _decode_e0_ff_mnem(data, offset, length):
    """Decode mnemonic for 0xE0-0xFF."""
    b1 = data[offset]
    ddd = b1 & 0x07

    # 0xE0-0xE2: :G src,dest (TST/XOR/verify)
    if b1 <= 0xE2:
        is_word = b1 & 1
        mnem = _G_TWO_OP.get(b1, f"OP_{b1:02X}")
        ops = _fmt_g_src_dest(data, offset, is_word)
        return (length, mnem, ops)

    # 0xE3-0xE7: CMP.B:S #IMM8,dest  (byte order: byte1 | IMM8 | dest_operands)
    if b1 <= 0xE7:
        pos = offset + 1
        imm = _read8(data, pos)
        pos += 1
        dst_str, _ = _fmt_dest3(ddd, data, pos)
        return (length, 'CMP.B:S', f"#${imm:02X},{dst_str}")

    # 0xE8: STNZ #IMM8,R0L
    if b1 == 0xE8:
        imm = _read8(data, offset + 1)
        return (length, 'STNZ', f"#${imm:02X},R0L")

    # 0xE9: STZ #IMM8,R0L
    if b1 == 0xE9:
        imm = _read8(data, offset + 1)
        return (length, 'STZ', f"#${imm:02X},R0L")

    # 0xEA: STZX #IMM1,#IMM2,R0L
    if b1 == 0xEA:
        imm1 = _read8(data, offset + 1)
        imm2 = _read8(data, offset + 2)
        return (length, 'STZX', f"#${imm1:02X},#${imm2:02X},R0L")

    # 0xEB: multi-instruction prefix
    if b1 == 0xEB:
        return _decode_eb_mnem(data, offset, length)

    # 0xEC: PUSHM
    if b1 == 0xEC:
        b2 = _read8(data, offset + 1)
        regs = _pushm_regs(b2)
        return (length, 'PUSHM', regs)

    # 0xED: POPM
    if b1 == 0xED:
        b2 = _read8(data, offset + 1)
        regs = _pushm_regs(b2)
        return (length, 'POPM', regs)

    # 0xEE: PUSH.B:S src
    if b1 == 0xEE:
        b2 = _read8(data, offset + 1)
        src_str, _ = _fmt_op4(b2 & 0x0F, data, offset + 2, False)
        return (length, 'PUSH.B:S', src_str)

    # 0xEF: POP.B:S / POP.W:S
    if b1 == 0xEF:
        b2 = _read8(data, offset + 1)
        dst_str, _ = _fmt_op4(b2 & 0x0F, data, offset + 2, False)
        return (length, 'POP.B:S', dst_str)

    # 0xF0/0xF1: :G format (SHA/SHL/ROT etc.)
    if b1 <= 0xF1:
        is_word = b1 & 1
        mnem = _G_TWO_OP.get(b1, f"OP_{b1:02X}")
        ops = _fmt_g_src_dest(data, offset, is_word)
        return (length, mnem, ops)

    # 0xF2: uncertain (SMOVF or similar, 2 bytes)
    if b1 == 0xF2:
        b2 = _read8(data, offset + 1)
        return (length, 'SMOVF', f"${b2:02X}")

    # 0xF3: RTS
    if b1 == 0xF3:
        return (1, 'RTS', '')

    # 0xF4: JMP.W
    if b1 == 0xF4:
        disp = _read16s(data, offset + 1)
        target = offset + 3 + disp
        return (3, 'JMP.W', f"${target:05X}")

    # 0xF5: JSR.W
    if b1 == 0xF5:
        disp = _read16s(data, offset + 1)
        target = offset + 3 + disp
        return (3, 'JSR.W', f"${target:05X}")

    # 0xF6: INTO
    if b1 == 0xF6:
        return (1, 'INTO', '')

    # 0xF7: uncertain (WAIT or SMOVB)
    if b1 == 0xF7:
        return (1, 'WAIT', '')

    # 0xF8/0xF9: ADJNZ
    if b1 <= 0xF9:
        is_word = b1 & 1
        sz = '.W' if is_word else '.B'
        b2 = _read8(data, offset + 1)
        imm4 = (b2 >> 4) & 0x0F
        if imm4 >= 8:
            imm4 -= 16
        dst_code = b2 & 0x0F
        pos = offset + 2
        dst_str, dst_extra = _fmt_op4(dst_code, data, pos, is_word)
        pos += dst_extra
        disp = _read8s(data, pos)
        target = offset + length + disp  # label relative to next instruction
        return (length, f"ADJNZ{sz}", f"#{imm4},{dst_str},${target:05X}")

    # 0xFA: SBJNZ.B
    if b1 == 0xFA:
        b2 = _read8(data, offset + 1)
        imm4 = (b2 >> 4) & 0x0F
        if imm4 >= 8:
            imm4 -= 16
        dst_code = b2 & 0x0F
        pos = offset + 2
        dst_str, dst_extra = _fmt_op4(dst_code, data, pos, False)
        pos += dst_extra
        disp = _read8s(data, pos)
        target = offset + length + disp
        return (length, 'SBJNZ.B', f"#{imm4},{dst_str},${target:05X}")

    # 0xFB: REIT
    if b1 == 0xFB:
        return (1, 'REIT', '')

    # 0xFC: JMP.A
    if b1 == 0xFC:
        addr = _read20(data, offset + 1)
        return (4, 'JMP.A', f"${addr:05X}")

    # 0xFD: JSR.A
    if b1 == 0xFD:
        addr = _read20(data, offset + 1)
        return (4, 'JSR.A', f"${addr:05X}")

    # 0xFE: JMP.B
    if b1 == 0xFE:
        disp = _read8s(data, offset + 1)
        target = offset + 2 + disp
        return (2, 'JMP.B', f"${target:05X}")

    # 0xFF: UND
    return (1, 'UND', '')


def _decode_eb_mnem(data, offset, length):
    """Decode mnemonic for 0xEB prefix."""
    b2 = data[offset + 1]

    # INT #IMM: byte2 >= 0xC0
    if b2 >= 0xC0:
        imm = b2 & 0x3F
        return (length, 'INT', f"#{imm}")

    # LDC #IMM16,creg: byte2 = 0DDD_0000 (DDD=2 is INTBH, byte2=0x20)
    if (b2 & 0x8F) == 0x00:
        creg = _CTRL_REG[(b2 >> 4) & 0x07]
        imm = _read16(data, offset + 2)
        return (length, 'LDC', f"#${imm:04X},{creg}")

    # FSET: byte2 = 0DDD_0100
    if (b2 & 0x8F) == 0x04:
        flag = _FLAG_NAMES[(b2 >> 4) & 0x07]
        return (length, 'FSET', flag)

    # FCLR: byte2 = 0DDD_0101
    if (b2 & 0x8F) == 0x05:
        flag = _FLAG_NAMES[(b2 >> 4) & 0x07]
        return (length, 'FCLR', flag)

    # STC creg: byte2 = 0DDD_0001
    if (b2 & 0x8F) == 0x01:
        creg = _CTRL_REG[(b2 >> 4) & 0x07]
        return (length, 'STC', creg)

    return (length, f"EB_{b2:02X}", '')


def _pushm_regs(mask):
    """Format PUSHM/POPM register list from bitmask."""
    names = ['FB', 'SB', 'A1', 'A0', 'R3', 'R2', 'R1', 'R0']
    regs = [n for i, n in enumerate(names) if mask & (1 << (7 - i))]
    return ','.join(regs) if regs else '(none)'
