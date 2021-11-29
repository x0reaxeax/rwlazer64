# RWLAZER64
<p align="center">
  <img src="https://i.imgur.com/VCzE7eA.png" />
</p>

Win64 UEFI Driver-based tool for unrestricted memory R/W

## Current status
This is a complete rewrite of rwlazer-alpha in pure C, no bloat++.  
The rewrite is not usable yet and this repository is not up-to-date with current development process, I'm actively working on it in private repos.  


## What can OLD RWLAZER do?
* Read/Write operations from privileged mode
* Signature scans with wildcard support from privileged mode
* Memory scans from privileged mode and user-space
* Read/Write Model-Specific Registers (MSRs)
* Convert values between hexadecimal/decimal/float
* Screw up your computer

## What can NEW RWLAZER do?
* Everything listed above, but done better.
* Insert debugger traps into running code
* Calculate physical addresses
* Disassemble basic instructions in Intel syntax
* Threaded operations for continuous R/W
* Capture memory snapshots
* Store operation history and compare memory differences
* Hook functions
* Monitor instruction execution time using `rdtsc` (Time Stamp Counter)

## What are the goals?
* Make-shift x64 debugger
* Configurable installer
* Scripting interface
* Fully operational debugger and disassembler
* C API
* A lot more..
* .. Intel ME tool.. yea, right LOL
