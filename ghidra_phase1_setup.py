# Ghidra headless script for Hakko FM-203 Phase 1 setup.
#
# Sets up memory regions, entry points, SFR labels, and missing code
# annotations for the R8C/25 firmware.
#
# Usage (headless):
#   analyzeHeadless /path/to/project FM203 \
#       -import hakko_fm203.bin \
#       -processor M16C \
#       -loader BinaryLoader -loader-baseAddr 0x4000 \
#       -postScript ghidra_phase1_setup.py
#
# Or run from Ghidra Script Manager after importing the binary.
#
# @category Hakko
# @description Phase 1 setup for Hakko FM-203 firmware (R8C/25)

from ghidra.program.model.symbol import SourceType
from ghidra.program.model.listing import CodeUnit


def setup_memory():
    """Create SFR and RAM memory regions."""
    mem = currentProgram.getMemory()
    try:
        mem.createUninitializedBlock("SFR", toAddr(0x0000), 0x300, False)
        println("Created SFR region: $0000-$02FF")
    except Exception as e:
        println("SFR region may already exist: " + str(e))
    try:
        mem.createUninitializedBlock("RAM", toAddr(0x0400), 0xC00, False)
        println("Created RAM region: $0400-$0FFF")
    except Exception as e:
        println("RAM region may already exist: " + str(e))


def create_functions():
    """Mark known entry points as functions."""
    entries = {
        0x0FBAE: "reset_init",
        0x08C92: "main",
        0x08B40: "isr_timer_rc",
        0x08B4C: "isr_timer_rd_overflow",
        0x08AEA: "isr_uart0_tx",
        0x0FC4E: "default_handler",
        0x05428: "flash_self_program",
    }
    listing = currentProgram.getListing()
    for addr, name in entries.items():
        a = toAddr(addr)
        try:
            createFunction(a, name)
            listing.setComment(a, CodeUnit.PLATE_COMMENT, "Entry: " + name)
            println("Created function: " + name + " at $" + format(addr, "05X"))
        except Exception as e:
            println("Function " + name + " may already exist: " + str(e))


def label_sfrs():
    """Label SFR addresses with register names."""
    sfrs = {
        # System Control
        0x0004: "PM0", 0x0005: "PM1", 0x0006: "CM0", 0x0007: "CM1",
        0x000A: "PRCR", 0x000C: "OCD", 0x000F: "WDC",
        # Interrupt Control
        0x0048: "TRD0IC", 0x0049: "TRD1IC", 0x004A: "TREIC",
        0x004D: "KUPIC", 0x004E: "ADIC",
        0x0051: "S0TIC", 0x0052: "S0RIC", 0x0053: "S1TIC", 0x0054: "S1RIC",
        0x0055: "INT2IC", 0x0056: "TRAIC", 0x0058: "TRBIC",
        0x0059: "INT1IC", 0x005A: "INT3IC", 0x005D: "INT0IC",
        # Timer RA
        0x0100: "TRACR", 0x0101: "TRAIOC", 0x0102: "TRAMR",
        0x0103: "TRAPRE", 0x0104: "TRA",
        # Timer RB
        0x0108: "TRBCR", 0x0109: "TRBOCR", 0x010A: "TRBIOC",
        0x010B: "TRBMR", 0x010C: "TRBPRE", 0x010D: "TRBSC", 0x010E: "TRBPR",
        # Timer RD
        0x0137: "TRDSTR", 0x0138: "TRDMR", 0x0139: "TRDPMR",
        0x013A: "TRDFCR", 0x013B: "TRDOER1", 0x013C: "TRDOER2",
        0x013D: "TRDOCR", 0x013E: "TRDDF0", 0x013F: "TRDDF1",
        0x0140: "TRDCR0", 0x0141: "TRDIORA0", 0x0142: "TRDIORC0",
        0x0143: "TRDSR0", 0x0144: "TRDIER0", 0x0145: "TRDPOCR0",
        0x0146: "TRD0", 0x0148: "TRDGRA0", 0x014A: "TRDGRB0",
        0x014C: "TRDGRC0", 0x014E: "TRDGRD0",
        0x0150: "TRDCR1", 0x0151: "TRDIORA1", 0x0152: "TRDIORC1",
        0x0153: "TRDSR1", 0x0154: "TRDIER1", 0x0155: "TRDPOCR1",
        0x0156: "TRD1", 0x0158: "TRDGRA1", 0x015A: "TRDGRB1",
        0x015C: "TRDGRC1", 0x015E: "TRDGRD1",
        # Timer RE
        0x0118: "TRESEC", 0x0119: "TREMIN", 0x011A: "TREHR",
        0x011B: "TREWK", 0x011C: "TRECR1", 0x011D: "TRECR2", 0x011E: "TRECSR",
        # A/D Converter
        0x00C0: "AD", 0x00D4: "ADCON2", 0x00D6: "ADCON0", 0x00D7: "ADCON1",
        # UART0 / UART1
        0x00A0: "U0MR", 0x00A1: "U0BRG", 0x00A2: "U0TB",
        0x00A4: "U0C0", 0x00A5: "U0C1", 0x00A6: "U0RB",
        0x00A8: "U1MR", 0x00A9: "U1BRG", 0x00AA: "U1TB",
        0x00AC: "U1C0", 0x00AD: "U1C1", 0x00AE: "U1RB",
        # I/O Ports
        0x00E0: "P0", 0x00E1: "P1", 0x00E2: "PD0", 0x00E3: "PD1",
        0x00E4: "P2", 0x00E5: "P3", 0x00E6: "PD2", 0x00E7: "PD3",
        0x00E8: "P4", 0x00EA: "PD4", 0x00EC: "P6", 0x00EE: "PD6",
        0x00F8: "PMR", 0x00F9: "INTEN",
        # Flash Control
        0x01B3: "FMR0", 0x01B5: "FMR1",
    }
    sym = currentProgram.getSymbolTable()
    count = 0
    for addr, name in sfrs.items():
        try:
            sym.createLabel(toAddr(addr), name, SourceType.USER_DEFINED)
            count += 1
        except Exception:
            pass
    println("Labeled " + str(count) + " SFR addresses")


def annotate_missing_code():
    """Add comments for the missing code region."""
    listing = currentProgram.getListing()

    missing_targets = {
        0x04812: "called from $049DF (JMP.W)",
        0x04830: "called from $08B5A (JSR.W)",
        0x0484C: "called from $08AC8 (JSR.W)",
        0x04883: "called from $09086 (JMP.W)",
        0x04904: "called from $04A3D (JSR.A)",
        0x0496E: "called from $09D7E/$0A3C9 (JSR.W)",
        0x0498A: "called from $0A3DE (JSR.W)",
    }

    listing.setComment(toAddr(0x04810), CodeUnit.PLATE_COMMENT,
        "MISSING CODE: $04810-$0498F\n"
        "Never captured from video. 7 known call targets land here.\n"
        "These functions are unrecoverable from this firmware source.")

    for addr, note in missing_targets.items():
        listing.setComment(toAddr(addr), CodeUnit.PRE_COMMENT,
            "MISSING FUNCTION - " + note)

    println("Annotated missing code region ($04810-$0498F)")


# --- Main ---
println("=" * 50)
println("Hakko FM-203 Phase 1 Setup")
println("=" * 50)

setup_memory()
create_functions()
label_sfrs()
annotate_missing_code()

println("")
println("Phase 1 setup complete.")
println("Auto-analysis will discover additional functions.")
