#   hooks.py
#
#   AArch64Emu
#   Copyright (C) 2017  Reisyukaku

from __future__ import print_function
from unicorn import *
from unicorn.arm64_const import *

from svc import *

# Memory exception hook    
def hook_mem_invalid(uc, access, address, size, value, user_data):
    if access == UC_MEM_WRITE:
        print("Memory fault on WRITE @ 0x%08X, size = %u, value = 0x%08X" % (address, size, value))
    else:
        print("Memory fault on READ @ 0x%08X, size = %u" % (address, size))
        
# Memory read/write hook    
def hook_mem_rw(uc, access, address, size, value, user_data):
    if access == UC_MEM_WRITE:
        access = "WRITE"
    else:
        access = "READ"

    print("Memory %s @ 0x%X,\t[0x%08X]" % (access, address, value))

# Instruction exception hook
def hook_intr(uc, intno, user_data):
    if intno == 2:
        svcHandler(uc)
    else:
        stopEmu(uc, 'Uknown exception! [%u]' %(intno))

# Callback for tracing instructions
def hook_code(uc, address, size, user_data):
    pc = uc.reg_read(UC_ARM64_REG_PC)
    addr = user_data
    print("PC = 0x%X [0x%X]" %(pc, pc - addr))