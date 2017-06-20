#   emu.py
#       by Reisyukaku
#
#   Emulates AArch64 code read from code.bin and displays debugging data.
#   Usage: emu.py <entryAddr> <steps>

from __future__ import print_function
from unicorn import *
from unicorn.arm64_const import *
import sys

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

# Set breakpoint in emu
def breakpoint(uc, addr):
    pc = uc.reg_read(UC_ARM64_REG_PC)
    if pc == addr:
        stopEmu(uc, 'Breakpoint!')

# Svc Handler
def svcHandler(uc):
    stopEmu(uc, 'SVC call!')

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
        stopEmu(uc, 'Uknown exception!')

# Callback for tracing instructions
def hook_code(uc, address, size, user_data):
    pc = uc.reg_read(UC_ARM64_REG_PC)
    addr = user_data
    if pc == addr + 0x3ACE5C:
        print("SendSyncRequest")
    print("PC = 0x%x" %pc)

# Halt emulation
def stopEmu(uc, reason):
    print(reason)
    uc.emu_stop()
    
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
        print("Heap Memory:")
        readMem(uc, heap, 0x100);
        
        print("IPC Command Buffer:")
        readMem(uc, tls, 0x100)

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