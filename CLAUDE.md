# Hakko FM-203 Reverse Engineering

## Project Overview

Reverse engineering the Hakko FM-203 soldering station firmware extracted from video of a Xeltek programmer reading a Renesas R5F21258SNFP (R8C/25) microcontroller.

**Goal**: Translate the firmware binary into annotated pseudocode to understand the soldering station's control logic (temperature regulation, heater PWM, serial communication).

## Target Architecture

- **MCU**: R5F21258SNFP (R8C/Tiny series)
- **CPU**: 16-bit CISC, 89 instructions, variable-length encoding (1-8 bytes)
- **ROM**: 64 KB ($04000-$13FFF) — Block 1 ($04000-$0BFFF) + Block 0 ($0C000-$13FFF)
- **RAM**: 3 KB ($00400-$00FFF)
- **Data Flash**: 2 KB ($02400-$02BFF) — A has calibration data, B is erased
- **Address space**: 20-bit (1 MB), but only 80 KB mapped on this chip

## Firmware Files

- `hakko_fm203.bin` — 64 KB ROM-only binary ($04000-$13FFF), use as primary for Ghidra/disassembly
- `hakko_fm203_full.bin` — 80 KB full image ($00000-$13FFF), includes SFR/RAM/DataFlash regions
- `firmware_merged.txt` — human-readable hex dump (16 bytes per line), all 5120 address lines present
- `memory_map.json` — machine-readable memory layout (regions, types, FF-forced overrides)

## Firmware Structure

- **Reset vector**: $0FFFC -> $0FBAE
- **Reset init** ($0FBAE-$0FC4D): sets ISP=$0916, SB=$0896, FB=$0400, configures flash protection, calls main
- **Main application entry**: $08C92
- **Active interrupts** (only 3 of 63):
  - $0FF34 -> $08B40 (Timer RC)
  - $0FF3C -> $08B4C (Timer RD overflow — heater PWM)
  - $0FF50 -> $08AEA (UART0 TX — serial output)
- **Default handler** ($0FC4E): single REIT (empty stub)
- **OPT byte**: 0x5F

## Known Data Gaps

- $04810-$0498F: FF-filled but contains real code (7 call targets proven). Never shown in video, unrecoverable. These will appear as unknown functions in disassembly.
- $04000-$04750: Genuinely erased (confirmed visually from video)
- $107F0-$13FFF: Genuinely erased ROM tail
- See `FIRMWARE_VERIFICATION.md` for full details

## Code Density

- 47,227 / 65,536 ROM bytes are non-FF (72.1%)
- Block 1: 91.2% utilized, Block 0 low: 93.8%, Block 0 high: 11.9%
- BFS code walker covers only 5.4% from entry points (limited by indirect jumps, not data errors)

## Key SFR Addresses (R8C/25)

| Peripheral | Base | Key Registers | FM-203 Role |
|------------|------|---------------|-------------|
| A/D Converter | $00C0 | AD, ADCON0, ADCON1 | Temperature sensing (10-bit) |
| Timer RD (16-bit) | $0140 | TRDCR0, TRD0, TRDGRA0 | Heater PWM |
| Timer RC | - | - | Periodic tick |
| UART0 | $00A0 | U0MR, U0BRG, U0TB, U0RB | Serial debug/comms |
| UART1 | $00A8 | U1MR, U1BRG, U1TB, U1RB | Serial comms |
| Port P0 | $00E0 | P0, PD0 | Analog inputs |
| Port P1 | $00E1 | P1, PD1 | Buttons/IO |
| Port P2 | $00E4 | P2, PD2 | Timer RD I/O |
| Interrupt Control | $0048 | Various ICR | Priority/enable |
| Flash Control | $01B3 | FMR0, FMR1 | Self-programming |

## R8C Address Mirroring

The R8C maps $Fxxxx to $0xxxx. A `JMP.A $FD105` is actually jumping to $0D105 (valid ROM). The boot ROM at $FF000-$FFFFF contains flash programming library routines — `JMP.A $FF440` is a legitimate call to write flash.

## Ghidra Setup

- Language: **M16C/60** (R8C/Tiny is an instruction-compatible subset of M16C)
- Import `hakko_fm203.bin` as raw binary, base address **$04000**
- Define memory regions: ROM ($04000-$0BFFF, $0C000-$13FFF), RAM ($00400-$00FFF), SFR ($00000-$002FF)
- Set entry points: $0FBAE (reset), $08B40, $08B4C, $08AEA (interrupts)
- Decompiler produces C-like pseudocode (confirmed working for M16C)
- Known Ghidra issues: SMOVF disassembly incomplete (#7376), INDEX emulation (#7468)
- Third-party plugins with SFR defs: `esaulenka/ghidra_m16c`, `silverchris/m16c`, `BitBangingBytes/m16c-62p`

## Existing Tools in This Repo

- `r8c_opcode_table.py` — instruction length decoder for all 89 R8C opcodes (used by validator)
- `r8c_validator.py` — BFS code walker from interrupt vectors, validates opcode sequences
- `memory_map.json` + `memory_map_utils.py` — memory layout queries

## Related Projects

- `../R5F21258SNFP_emulator/` — R8C emulator (partial, 4/89 opcodes), contains:
  - `INSTRUCTION_ENCODING.md` — complete R8C instruction set reference (62 KB)
  - `REFERENCE_IMPL.md` — analysis of GNU binutils-gdb R8C simulator
  - `r8c-tiny_series_Software_Manual.pdf` — official instruction set manual
  - `r8c24-r8c25-group-hardware-manual.pdf` — hardware reference (SFR details, flash structure)
  - `r8c24-r8c25-group-datasheet.pdf` — pin assignments, electrical specs
- `../hakko-203-firmware-video/` — OCR extraction pipeline (source of the firmware binary)
- `../hakko-202-firmware-video/claude/m740_disassembler.py` — working M740 disassembler (pattern for building R8C disassembler)

## Approach

1. **Ghidra** (primary) — import binary, auto-analyze, annotate SFRs, export pseudocode
2. **Custom Python disassembler** — extend `r8c_opcode_table.py` with mnemonic output for cross-validation
3. **Domain annotation** — label SFR accesses with hardware meaning (ADC=temperature, Timer RD=heater PWM, UART=serial)
4. Focus areas: reset init, main loop at $08C92, three interrupt handlers, flash programming routine at $05428
