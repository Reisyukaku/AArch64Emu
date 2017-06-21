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
        print("Memory fault on WRITE at 0x%x, data size = %u, data value = 0x%x" % (address, size, value))
    else:
        print("Memory fault on READ at 0x%x, data size = %u" % (address, size))

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
    if pc == addr + 0x3ACE5C:
        print("SendSyncRequest")
    print("PC = 0x%x" %pc)