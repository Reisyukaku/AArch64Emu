#   utils.py
#
#   AArch64Emu
#   Copyright (C) 2017  Reisyukaku

from __future__ import print_function
from unicorn import *
from unicorn.arm64_const import *
import struct

# Read from memory
def readMem(emu, addr, size):
    try:
        tmp = emu.mem_read(addr, size)
        print("[0x%X bytes @ 0x%x]:\n" %(size, addr), end="")
        str = ''
        for i in tmp:
            str += ''.join('{:02X}'.format(i))
            str += ' '
            size -= 1
            if size % 8 == 0:
                str += ' '
            if size % 16 == 0:
                print(str + ' ')
                str = ''
    except UcError as e:
            print("ERROR: %s" % e)
            
# Dump registers and memory
def dumpData(uc, heap, tls):
    if uc is not None:
        print("Registers:\n-----------------")
        cnt = 0
        for x in range(UC_ARM64_REG_X0, UC_ARM64_REG_X0 + 32):
            r = uc.reg_read(x)
            print("  X%d = 0x%x" %(cnt, r))
            cnt += 1
        print("  SP = 0x%x" %uc.reg_read(UC_ARM64_REG_SP))
        print("  PC = 0x%x\n" %uc.reg_read(UC_ARM64_REG_PC))
        
        print("Memory:\n-----------------")    
        print("Stack Pointer:")
        readMem(uc, uc.reg_read(UC_ARM64_REG_SP), 0x80)
        print("Frame Pointer:")
        readMem(uc, uc.reg_read(UC_ARM64_REG_FP), 0x80)
        
        print("IPC Command Buffer:")
        readMem(uc, tls, 0x100)