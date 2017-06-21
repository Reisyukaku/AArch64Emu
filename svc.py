#   svc.py
#
#   AArch64Emu
#   Copyright (C) 2017  Reisyukaku

from __future__ import print_function
from unicorn import *
from unicorn.arm64_const import *
import struct

from main import *

# Svc Handler
def svcHandler(uc):
    svc = struct.unpack("<L", uc.mem_read(uc.reg_read(UC_ARM64_REG_PC)-4, 4))[0] >> 5 & 0xFF
    stopEmu(uc, 'SVC 0x{:02X}'.format(svc))