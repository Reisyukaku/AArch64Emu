# AArch64Emu
[![License (GPL version 3)](https://img.shields.io/badge/license-GNU%20GPL%20version%203-red.svg?style=flat-square)](http://opensource.org/licenses/GPL-3.0)

*Emulates ARM64 code*


**About:**

An emulator built from Unicorn-engine and designed for debugging switch (ARM64) code. 

**Usage:**

    emu.py <startAddress> [opt:steps]
 It looks for code.bin in the same directory.

**Requirements:** 

 - [Unicorn python bindings](https://github.com/unicorn-engine/unicorn/releases/)
 - [Python 3](https://www.python.org/downloads/)

**Credits:**

 - Unicorn-engine team for API