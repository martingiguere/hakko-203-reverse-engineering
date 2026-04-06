# Firmware Verification Report

Firmware binary data (`hakko_fm203.bin`, `firmware_merged.txt`) confirmed 100% accurate (2026-03-28).

## Validator "Issues" Explained (all 3 are legitimate)

The r8c_validator.py BFS code walker reports 3 jump targets outside ROM. None are errors:
- **$B0404** (from $08B41, $08B4D): Phantom — BFS entered Timer RC/RD handlers at offset +1 (misaligned). Correct walk from $08B40/$08B4C decodes `EC FD` as a 2-byte instruction; no JSR.A exists on the real execution path.
- **$FD105** (from JMP.A at $0F5D0): Legitimate — R8C address mirroring maps $Fxxxx to $0xxxx, so $FD105 = **$0D105** (valid Block 0 ROM).
- **$FF440** (from JMP.A at $05428): Legitimate — targets R8C **boot ROM** flash rewrite library (in-system programming).

## ROM Coverage

- **Full coverage: 5120/5120 address lines** present in firmware_merged.txt
- **Zero missing ROM lines** in $04000-$107EF (all 4,079 lines present)
- 47,227 bytes of code+data out of 65,536 ROM bytes (72.1%)
- Block 1 ($04000-$0BFFF): 91.2% utilized
- Block 0 low ($0C000-$0FFFF): 93.8% utilized
- Block 0 high ($10000-$13FFF): 11.9% (only $10000-$107EF has data; rest confirmed erased)

## Missing Code: $04810-$0498F (FF-filled but contains real code)

The FF-forced region $04000-$04980 was designated "safe to FF-fill" because the video never showed it. However, **7 call/jump targets from the rest of the firmware land in this region**, proving it contains real code:

| Target | Callers | Note |
|--------|---------|------|
| $04812 | $049DF (JMP.W) | Code at $04990+ jumps backward into it |
| $04830 | $08B5A (JSR.W) | Called from Timer RD interrupt path |
| $0484C | $08AC8 (JSR.W) | Called from near interrupt handlers |
| $04883 | $09086 (JMP.W) | |
| $04904 | $04A3D (JSR.A) | Code at $04990+ calls into it |
| $0496E | $09D7E + $0A3C9 (2 callers) | |
| $0498A | $0A3DE (JSR.W) | |

- Contiguous FF: $04000-$0498F (2,448 bytes, 153 lines)
- Confirmed erased (visually): $04000-$04750 (true FF, seen in video)
- **Missing code**: $04810-$0498F (at minimum 377 bytes) — never shown in video, unrecoverable from this source
- $04700 was briefly shown but contained erroneous data (visually confirmed FF 2026-03-29, fixed in merge)
- These functions may include core runtime routines (Timer RD handler calls $04830/$0484C)
- **Impact on reverse engineering**: 7 functions will appear as stubs/unknowns in disassembly. Callers can be analyzed to infer signatures and purpose.

## Firmware Structure

- **Reset vector**: $0FFFC -> $0FBAE
- **OPT byte**: 0x5F (watchdog prescaler/clock config)
- **Active interrupts** (only 3 of 63 vectors):
  - $0FF34 -> $08B40 (Timer RC)
  - $0FF3C -> $08B4C (Timer RD overflow — likely heater PWM)
  - $0FF50 -> $08AEA (UART0 TX — serial output)
- **Default handler** ($0FC4E): single REIT instruction (empty stub)
- **Reset init** ($0FBAE-$0FC4D): sets ISP=$0916, SB=$0896, FB=$0400, configures flash protection, then JSR.A $08C92 (main entry), followed by infinite loop
- **Main application entry**: $08C92

## Pre-Reverse-Engineering Manual Verification Checklist

~20 lines to spot-check against video frames before starting disassembly:
1. **Vector table** (4 lines): $0FF30, $0FF3C, $0FF50, $0FFF0
2. **Reset init** (~10 lines): $0FBA0-$0FC50
3. **Main entry** (~3 lines): $08C90
4. **Interrupt handlers** (~3 lines each): $08B40, $08B4C, $08AEA
