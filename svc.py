#   svc.py
#
#   AArch64Emu
#   Copyright (C) 2017  Reisyukaku

from __future__ import print_function
from unicorn import *
from unicorn.arm64_const import *
import struct

from main import *

def svcSyncRequest(uc):
    breakpoint(uc, uc.reg_read(UC_ARM64_REG_PC))
    #uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))

# Svc Handler
def svcHandler(uc):
    svc = struct.unpack("<L", uc.mem_read(uc.reg_read(UC_ARM64_REG_PC)-4, 4))[0] >> 5 & 0xFF
    print('SVC 0x{:02X}'.format(svc))
    
    switcher = {
        0x21: svcSyncRequest,
    }
    func = switcher.get(svc, lambda: "Unsupported SVC!")
    return func(uc)