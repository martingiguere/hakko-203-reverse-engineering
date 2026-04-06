# Reverse Engineering the Hakko FM-203 Firmware

Investigation into translating the R5F21258SNFP (R8C/25) firmware to pseudocode.

## Available Assets

- `hakko_fm203.bin` (64 KB ROM, $04000-$13FFF) — confirmed accurate
- `hakko_fm203_full.bin` (80 KB, full image with SFR/RAM/DataFlash)
- `r8c_opcode_table.py` — complete instruction length decoder (all 89 R8C instructions)
- `r8c_validator.py` — BFS code walker from interrupt vectors
- `INSTRUCTION_ENCODING.md` (in emulator repo) — complete R8C instruction set reference (62 KB)
- GNU binutils-gdb R8C simulator as reference (`../R5F21258SNFP_emulator/reference/`)
- FM-202 M740 disassembler (`../hakko-202-firmware-video/claude/m740_disassembler.py`) as pattern
- 3 PDFs: hardware manual, datasheet, software manual (in `../R5F21258SNFP_emulator/`)

## Validator Results

- Reset vector: $0FBAE, OPT byte: 0x5F
- 58 default vectors -> $0FC4E (single REIT), 2 erased (DBC, NMI), 3 active:
  - $0FF34 -> $08B40 (Timer RC)
  - $0FF3C -> $08B4C (Timer RD overflow — heater PWM)
  - $0FF50 -> $08AEA (UART0 TX)
- Main application entry: $08C92 (called from reset init at $0FC48)
- BFS coverage: 5.4% (3,519 / 65,536 bytes) — limited by indirect jumps and data sections, NOT by data errors
- 3 out-of-ROM jump targets all explained: 2 phantom (misaligned BFS), 1 mirrored ROM ($FD105->$0D105), 1 boot ROM call ($FF440 = flash library)
- **Zero missing ROM lines** in $04000-$107EF — full coverage achieved
- Code density: 47,227 / 65,536 bytes non-FF (72.1%); Block 1 91.2%, Block 0 low 93.8%

## Ghidra M16C/R8C Support

### Built-in support: YES
- Ghidra ships with `Ghidra/Processors/M16C/` — select **M16C/60** language for R8C/25
- R8C/Tiny is an instruction-compatible subset of M16C (same ISA, narrower data bus)
- Decompiler produces C-like pseudocode — confirmed working by users (Ghidra Discussion #4804)
- Used successfully for automotive ECU firmware (M16C/M32C)

### Import procedure
1. Import `hakko_fm203.bin` as raw binary, language **M16C/60**, base address $04000
2. Define memory regions manually (ROM, RAM, SFR, Data Flash)
3. Define R8C/25 SFR addresses manually (~50 registers from hardware manual)
4. Set entry points: reset $0FBAE, interrupts $08B40/$08B4C/$08AEA

### Known issues
- No R8C-specific SFR definitions built in — must define manually
- SMOVF instruction disassembly incomplete (Ghidra Issue #7376)
- INDEX instruction emulation issues (#7468)
- Some multiplication variants may be missing
- `.cspec` (calling conventions) may need adjustment for best decompiler output

### Third-party Ghidra M16C plugins (GitHub)
- `esaulenka/ghidra_m16c` (Nov 2023, 37 commits)
- `silverchris/m16c` (Dec 2022, 38 commits, referenced in Ghidra #6139)
- `BitBangingBytes/m16c-62p` (March 2024, fork with SFR defs for M16C/62P — may have reusable SFR patterns)

### Tool comparison

| Tool | Disassembly | Pseudocode | R8C support |
|------|-------------|------------|-------------|
| Ghidra | Yes (built-in M16C) | Yes (imperfect) | Best free option |
| IDA Pro | Yes (lists R8C/Tiny explicitly) | No (Hex-Rays doesn't cover M16C) | Assembly only |
| Binary Ninja | Plugin (dormant since 2020) | No lifting | Assembly only |
| radare2 | Not supported | N/A | Unimplemented |

**Ghidra is the only tool that produces pseudocode for this architecture.**

## Recommended Approach: Hybrid

1. **Ghidra** (primary) — M16C/60 language for decompilation to pseudocode
2. **Custom Python disassembler** (validation) — extend r8c_opcode_table.py with mnemonics and operand formatting
3. **GNU m32c-elf-objdump** (cross-check) — production-quality linear disassembly
4. **Domain annotation** — label SFR accesses with Hakko hardware meaning (ADC=temperature, Timer RD=heater PWM, UART=serial)

## Key Challenges

- Indirect calls/jump tables limit static analysis coverage (only 5.4% from entry points)
- Data tables interspersed with code ($10070-$10920 identified)
- 7 missing functions in $04810-$0498F (FF-filled but proven to contain real code — see FIRMWARE_VERIFICATION.md)
- SFR reads/writes need hardware context for meaningful pseudocode
- R8C address mirroring ($Fxxxx -> $0xxxx) and boot ROM calls ($FF440) need special handling in tools
