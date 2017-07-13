#   profile.py
#
#   AArch64Emu
#   Copyright (C) 2017  Reisyukaku

class Profile(object):
    bin = ""
    textStart = 0
    heapStart = 0
    stackMem = 0
    heapMem = 0
    codeMem = 0
    tls = 0

    def __init__(self, binStr, textStart, heapStart, stackMem, heapMem, codeMem):
        self.bin = binStr
        self.textStart = textStart
        self.heapStart = heapStart
        self.stackMem = stackMem
        self.heapMem = heapMem
        self.codeMem = codeMem
        self.tls = heapStart   # my custom IPC TLS hook