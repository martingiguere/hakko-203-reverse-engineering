# Hakko FM-203 Reverse Engineering — TODO

## Phase 1: Disassembly Foundation
- [x] Build Python R8C disassembler (`r8c_disassembler.py`) with recursive descent + linear sweep
- [x] Extend `r8c_opcode_table.py` with mnemonic decoding (`decode_instruction()`)
- [x] Create SFR name lookup table (`r8c_sfr_names.py`, ~120 registers)
- [x] Create Ghidra headless setup script (`ghidra_phase1_setup.py`) for when Ghidra is installed
- [x] Generate disassembly output (`fm203_disasm.txt` — 20,886 lines, 885 KB)
- **Output**: `fm203_disasm.txt` — 20,347 instructions, 39 functions, 197 labels, 126 SFR annotations

## Phase 2: SFR & Symbol Annotation
- [ ] Label all SFR addresses ($0000-$02FF) with register names from the hardware manual
- [ ] Apply a Ghidra plugin (`esaulenka/ghidra_m16c` or similar) if one has good R8C/25 coverage
- [ ] Label known RAM locations as you discover them (globals, buffers)
- **Output**: Disassembly where register accesses read as `ADCON0`, `U0TB`, `TRDGRA0` etc.

## Phase 3: Control Flow Mapping
- [ ] Trace from reset init ($0FBAE) through to main ($08C92)
- [ ] Map the main loop structure — what it polls, what it dispatches
- [ ] Trace each ISR ($08B40, $08B4C, $08AEA) to understand interrupt-driven behavior
- [ ] Resolve indirect jumps/calls (jump tables, function pointers) to expand BFS coverage beyond 5.4%
- [ ] Mark the 7 unreachable call targets in the $04810-$0498F gap
- **Output**: Call graph, main loop flowchart, ISR summaries

## Phase 4: Functional Block Analysis
Work through each subsystem independently:
- [ ] **Temperature sensing** — ADC config, conversion ISR, scaling/lookup tables
- [ ] **Heater PWM** — Timer RD setup, duty cycle calculation, safety limits
- [ ] **Serial comms** — UART0/UART1 protocol, packet format, command handling
- [ ] **UI/buttons** — Port P1 reads, debounce, mode/setpoint logic
- [ ] **Flash self-programming** — routine at $05428, what calibration data it stores
- **Output**: Per-subsystem annotated pseudocode

## Phase 5: PID / Control Logic
- [ ] Identify the temperature control algorithm (likely PID or on/off with hysteresis)
- [ ] Find where setpoint vs. measured temperature drives the PWM duty cycle
- [ ] Trace how the two heater channels (FM-203 has dual ports) are managed
- **Output**: Control algorithm pseudocode with tuning constants identified

## Phase 6: Cross-Validation & Documentation
- [ ] Build the Python disassembler (extend `r8c_opcode_table.py`) and diff against Ghidra output
- [ ] Verify key routines against expected behavior (e.g., known baud rates, PWM frequencies)
- [ ] Document the full firmware architecture with annotated pseudocode
- **Output**: Final annotated pseudocode + architecture document
