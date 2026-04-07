#!/usr/bin/env python3
"""
R8C/25 (R5F21258SNFP) Special Function Register name lookup.

Source: R8C/24, R8C/25 Group Hardware Manual and NEXT_STEP_SPEC.md
Maps SFR addresses ($0000-$02FF) to human-readable register names.
"""

# Address -> (name, description)
SFR_TABLE = {
    # 3.1 System Control
    0x0004: ("PM0",      "Processor Mode Register 0"),
    0x0005: ("PM1",      "Processor Mode Register 1"),
    0x0006: ("CM0",      "System Clock Control Register 0"),
    0x0007: ("CM1",      "System Clock Control Register 1"),
    0x000A: ("PRCR",     "Protect Register"),
    0x000C: ("OCD",      "Oscillation Stop Detection Register"),
    0x000F: ("WDC",      "Watchdog Timer Control Register"),

    # 3.2 Interrupt Control
    0x0048: ("TRD0IC",   "Timer RD0 Interrupt Control"),
    0x0049: ("TRD1IC",   "Timer RD1 Interrupt Control"),
    0x004A: ("TREIC",    "Timer RE Interrupt Control"),
    0x004D: ("KUPIC",    "Key Input Interrupt Control"),
    0x004E: ("ADIC",     "A/D Conversion Interrupt Control"),
    0x0051: ("S0TIC",    "UART0 Transmit Interrupt Control"),
    0x0052: ("S0RIC",    "UART0 Receive Interrupt Control"),
    0x0053: ("S1TIC",    "UART1 Transmit Interrupt Control"),
    0x0054: ("S1RIC",    "UART1 Receive Interrupt Control"),
    0x0055: ("INT2IC",   "INT2 Interrupt Control"),
    0x0056: ("TRAIC",    "Timer RA Interrupt Control"),
    0x0058: ("TRBIC",    "Timer RB Interrupt Control"),
    0x0059: ("INT1IC",   "INT1 Interrupt Control"),
    0x005A: ("INT3IC",   "INT3 Interrupt Control"),
    0x005D: ("INT0IC",   "INT0 Interrupt Control"),

    # 3.3 Timer RA (8-bit)
    0x0100: ("TRACR",    "Timer RA Control Register"),
    0x0101: ("TRAIOC",   "Timer RA I/O Control Register"),
    0x0102: ("TRAMR",    "Timer RA Mode Register"),
    0x0103: ("TRAPRE",   "Timer RA Prescaler Register"),
    0x0104: ("TRA",      "Timer RA Register"),

    # 3.4 Timer RB (8-bit)
    0x0108: ("TRBCR",    "Timer RB Control Register"),
    0x0109: ("TRBOCR",   "Timer RB One-Shot Control"),
    0x010A: ("TRBIOC",   "Timer RB I/O Control"),
    0x010B: ("TRBMR",    "Timer RB Mode Register"),
    0x010C: ("TRBPRE",   "Timer RB Prescaler Register"),
    0x010D: ("TRBSC",    "Timer RB Secondary Register"),
    0x010E: ("TRBPR",    "Timer RB Primary Register"),

    # 3.5 Timer RD (16-bit, 2 channels) -- FM-203 Heater PWM
    0x0137: ("TRDSTR",   "Timer RD Start Register"),
    0x0138: ("TRDMR",    "Timer RD Mode Register"),
    0x0139: ("TRDPMR",   "Timer RD PWM Mode Register"),
    0x013A: ("TRDFCR",   "Timer RD Function Control"),
    0x013B: ("TRDOER1",  "Timer RD Output Master Enable 1"),
    0x013C: ("TRDOER2",  "Timer RD Output Master Enable 2"),
    0x013D: ("TRDOCR",   "Timer RD Output Control Register"),
    0x013E: ("TRDDF0",   "Timer RD Digital Filter 0"),
    0x013F: ("TRDDF1",   "Timer RD Digital Filter 1"),
    0x0140: ("TRDCR0",   "Timer RD Control Register 0"),
    0x0141: ("TRDIORA0", "Timer RD I/O Control A0"),
    0x0142: ("TRDIORC0", "Timer RD I/O Control C0"),
    0x0143: ("TRDSR0",   "Timer RD Status Register 0"),
    0x0144: ("TRDIER0",  "Timer RD Interrupt Enable 0"),
    0x0145: ("TRDPOCR0", "Timer RD PWM Output Control 0"),
    0x0146: ("TRD0",     "Timer RD Counter 0 (16-bit)"),
    0x0148: ("TRDGRA0",  "Timer RD General Register A0 (16-bit)"),
    0x014A: ("TRDGRB0",  "Timer RD General Register B0 (16-bit)"),
    0x014C: ("TRDGRC0",  "Timer RD General Register C0 (16-bit)"),
    0x014E: ("TRDGRD0",  "Timer RD General Register D0 (16-bit)"),
    0x0150: ("TRDCR1",   "Timer RD Control Register 1"),
    0x0151: ("TRDIORA1", "Timer RD I/O Control A1"),
    0x0152: ("TRDIORC1", "Timer RD I/O Control C1"),
    0x0153: ("TRDSR1",   "Timer RD Status Register 1"),
    0x0154: ("TRDIER1",  "Timer RD Interrupt Enable 1"),
    0x0155: ("TRDPOCR1", "Timer RD PWM Output Control 1"),
    0x0156: ("TRD1",     "Timer RD Counter 1 (16-bit)"),
    0x0158: ("TRDGRA1",  "Timer RD General Register A1 (16-bit)"),
    0x015A: ("TRDGRB1",  "Timer RD General Register B1 (16-bit)"),
    0x015C: ("TRDGRC1",  "Timer RD General Register C1 (16-bit)"),
    0x015E: ("TRDGRD1",  "Timer RD General Register D1 (16-bit)"),

    # 3.6 Timer RE (Real-time clock)
    0x0118: ("TRESEC",   "Timer RE Second Data"),
    0x0119: ("TREMIN",   "Timer RE Minute Data"),
    0x011A: ("TREHR",    "Timer RE Hour Data"),
    0x011B: ("TREWK",    "Timer RE Day of Week Data"),
    0x011C: ("TRECR1",   "Timer RE Control Register 1"),
    0x011D: ("TRECR2",   "Timer RE Control Register 2"),
    0x011E: ("TRECSR",   "Timer RE Count Source Select"),

    # 3.7 A/D Converter (10-bit) -- FM-203 Temperature Sensing
    0x00C0: ("AD",       "A/D Register (16-bit)"),
    0x00D4: ("ADCON2",   "A/D Control Register 2"),
    0x00D6: ("ADCON0",   "A/D Control Register 0"),
    0x00D7: ("ADCON1",   "A/D Control Register 1"),

    # 3.8 UART0 / UART1
    0x00A0: ("U0MR",     "UART0 Transmit/Receive Mode"),
    0x00A1: ("U0BRG",    "UART0 Bit Rate Generator"),
    0x00A2: ("U0TB",     "UART0 Transmit Buffer (16-bit)"),
    0x00A4: ("U0C0",     "UART0 Transmit/Receive Control 0"),
    0x00A5: ("U0C1",     "UART0 Transmit/Receive Control 1"),
    0x00A6: ("U0RB",     "UART0 Receive Buffer (16-bit)"),
    0x00A8: ("U1MR",     "UART1 Transmit/Receive Mode"),
    0x00A9: ("U1BRG",    "UART1 Bit Rate Generator"),
    0x00AA: ("U1TB",     "UART1 Transmit Buffer (16-bit)"),
    0x00AC: ("U1C0",     "UART1 Transmit/Receive Control 0"),
    0x00AD: ("U1C1",     "UART1 Transmit/Receive Control 1"),
    0x00AE: ("U1RB",     "UART1 Receive Buffer (16-bit)"),

    # 3.9 I/O Ports
    0x00E0: ("P0",       "Port P0 Register"),
    0x00E1: ("P1",       "Port P1 Register"),
    0x00E2: ("PD0",      "Port P0 Direction"),
    0x00E3: ("PD1",      "Port P1 Direction"),
    0x00E4: ("P2",       "Port P2 Register"),
    0x00E5: ("P3",       "Port P3 Register"),
    0x00E6: ("PD2",      "Port P2 Direction"),
    0x00E7: ("PD3",      "Port P3 Direction"),
    0x00E8: ("P4",       "Port P4 Register"),
    0x00EA: ("PD4",      "Port P4 Direction"),
    0x00EC: ("P6",       "Port P6 Register"),
    0x00EE: ("PD6",      "Port P6 Direction"),
    0x00F8: ("PMR",      "Port Mode Register"),
    0x00F9: ("INTEN",    "External Input Enable Register"),

    # Flash Control
    0x01B3: ("FMR0",     "Flash Memory Control Register 0"),
    0x01B5: ("FMR1",     "Flash Memory Control Register 1"),
}

# Simple name-only lookup dict
SFR_NAMES = {addr: name for addr, (name, _) in SFR_TABLE.items()}


def get_sfr_name(addr):
    """Return SFR register name for address, or None if not an SFR."""
    return SFR_NAMES.get(addr)


def get_sfr_description(addr):
    """Return (name, description) tuple for address, or None."""
    return SFR_TABLE.get(addr)


def format_address(addr):
    """Return 'SFR_NAME' if known SFR, else '$XXXXX'."""
    name = SFR_NAMES.get(addr)
    return name if name else f"${addr:05X}"


def sfr_comment(addr):
    """Return '  ; SFR_NAME — description' if known SFR, else empty string."""
    entry = SFR_TABLE.get(addr)
    if entry:
        return f"  ; {entry[0]} -- {entry[1]}"
    return ""
