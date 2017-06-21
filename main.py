#   main.py
#
#   AArch64Emu
#   Copyright (C) 2017  Reisyukaku

from __future__ import print_function
from unicorn import *
from unicorn.arm64_const import *
import sys

from utils import *
from hooks import *

# Set breakpoint in emu
def breakpoint(uc, addr):
    pc = uc.reg_read(UC_ARM64_REG_PC)
    if pc == addr:
        stopEmu(uc, 'Breakpoint!')

# Halt emulation
def stopEmu(uc, reason):
    print(reason)
    uc.emu_stop()

# Setup and emulate AArch64 code (designed around switch)
def emulate(code, textAddr, heapAddr, tls, codeMem, stackMem, heapMem, entry, steps):    
    try:
        # Initialize emulator in AArch64
        mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        
        # Initialize memory
        mu.mem_map(textAddr, codeMem + stackMem)
        mu.mem_map(heapAddr, heapMem)
        mu.mem_write(textAddr, code)
        sp = textAddr + codeMem + 0x500
        fp = sp + 0x10
        
        # Initialize registers
        mu.reg_write(UC_ARM64_REG_SP, sp)
        mu.reg_write(UC_ARM64_REG_FP, fp)
        mu.reg_write(UC_ARM64_REG_TPIDRRO_EL0, tls)
        #ARGS GO HERE .. for now

        # Add hooks
        mu.hook_add(UC_HOOK_CODE, hook_code, user_data=textAddr)
        mu.hook_add(UC_HOOK_INTR, hook_intr)
        mu.hook_add(UC_HOOK_MEM_INVALID, hook_mem_invalid)

        # Emulate code in infinite time & X steps
        mu.emu_start(entry, textAddr + len(code), count = steps)
        
        print("Emulation done!\n")
        return mu
    except UcError as e:
        dumpData(mu, heapAddr, tls)
        print("ERROR: %s" % e)
        print("SP = %x\nPC = %x" %(mu.reg_read(UC_ARM64_REG_SP), mu.reg_read(UC_ARM64_REG_PC)))
        
    return None

def main(argv):
    # Base vars
    textStart = 0x252CA06000
    heapStart = 0x294c000000
    stackMem = 0x1000
    heapMem = 0x2000
    codeMem = 0x95A000
    tls = heapStart   # my custom IPC TLS hook
    
    # Parse args
    if argv[0].startswith("0x"):
        entry = int(argv[0][2:],16)
    else:
        entry = int(argv[0])
        
    steps = 0
    if len(argv) > 1:
        if argv[1].startswith("0x"):
            steps = int(argv[1][2:],16)
        else:
            steps = int(argv[1])
    
    # Code to be emulated (tested with webkit MOD)
    with open("code.bin", "rb") as binary_file:
        code = binary_file.read()

    # Emulate code
    res = emulate(code, textStart, heapStart, tls, codeMem, stackMem, heapMem, entry, steps)

    # Display resulting data
    dumpData(res, heapStart, tls)
    
if __name__ == "__main__":
    main(sys.argv[1:])