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
from profile import *
import struct

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
def emulate(prof, entry, steps):    
    try:
        # Read binary
        with open(prof.bin, "rb") as binary_file:
            code = binary_file.read()
        
        # Initialize emulator in AArch64
        mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        
        # Initialize memory
        mu.mem_map(prof.textStart, prof.codeMem + prof.stackMem)
        mu.mem_map(prof.heapStart, prof.heapMem)
        mu.mem_write(prof.textStart, code)
        sp = prof.textStart + prof.codeMem + 0x500
        fp = sp + 0x10
        
        # Initialize registers
        mu.reg_write(UC_ARM64_REG_SP, sp)
        mu.reg_write(UC_ARM64_REG_FP, fp)
        mu.reg_write(UC_ARM64_REG_TPIDRRO_EL0, prof.tls)
        #ARGS GO HERE .. for now

        # Add hooks
        mu.hook_add(UC_HOOK_CODE, hook_code, user_data=prof.textStart)
        mu.hook_add(UC_HOOK_INTR, hook_intr)
        mu.hook_add(UC_HOOK_MEM_INVALID, hook_mem_invalid)
        mu.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, hook_mem_rw)

        # Emulate code in infinite time & X steps
        mu.emu_start(entry, prof.textStart + len(code), count = steps)
        
        print("Emulation done!\n")
        return mu
    except UcError as e:
        dumpData(mu, prof.heapStart, prof.tls)
        print("ERROR: %s" % e)
        print("SP = %x\nPC = %x" %(mu.reg_read(UC_ARM64_REG_SP), mu.reg_read(UC_ARM64_REG_PC)))
        
    return None

def main(argv):
    # Base vars
    nsProf = Profile("ns_code.bin", 0x5EE3000000, 0x5EE4000000, 0x1000, 0x2000, 0x690000)
    wkcProf = Profile("wkc_code.bin", 0x252CA06000, 0x294c000000, 0x1000, 0x2000, 0x95A000)

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

    # Emulate code
    res = emulate(nsProf, entry, steps)

    # Display resulting data
    dumpData(res, nsProf.heapStart, nsProf.tls)
    
if __name__ == "__main__":
    main(sys.argv[1:])