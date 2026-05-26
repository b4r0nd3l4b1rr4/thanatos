+++
title = "unhook"
chapter = false
weight = 106
hidden = true
+++

## Description
Unhook a DLL by reloading a clean copy from disk. This technique is used to remove user-mode hooks installed by EDR/AV products, restoring the original syscall stubs. This is particularly effective against security products that use API hooking for monitoring.

### Parameters
`dll` (optional)
 * DLL name to unhook (default: `ntdll.dll`)
 * Common targets: `ntdll.dll`, `kernel32.dll`, `kernelbase.dll`

## Usage
```
unhook
unhook ntdll.dll
unhook {"dll": "kernel32.dll"}
```

## Notes
 - Reads a fresh copy of the DLL from `C:\Windows\System32\`
 - Current implementation is a proof-of-concept that confirms the DLL can be read
 - Full unhooking requires VirtualProtect and memory copy operations (planned for future update)
 - Most effective against user-mode hooks (not kernel-mode drivers)
 - Does not require administrative privileges for user-mode unhooking

## OPSEC Considerations
 - **Detection Risk: HIGH**
 - DLL unhooking is a sophisticated evasion technique well-known to EDR vendors:
   - Many EDRs monitor for memory modifications in critical DLLs
   - Some products use kernel-mode drivers to detect unhooking attempts
   - Kernel callbacks can alert on suspicious VirtualProtect calls
   - Memory integrity checks may detect the restoration of original code
 - Reading DLLs from disk may trigger file access monitoring
 - PowerShell execution with file read operations may appear suspicious
 - Consider the timing: unhook early in execution before suspicious actions
 - Some EDRs protect their hooks with anti-tampering mechanisms
 - May break legitimate security software functionality
 - Full implementation will use direct syscalls to avoid hooks during the unhooking process

## Advanced Notes
 - For production use, implement direct syscalls instead of PowerShell
 - Use hardware breakpoints or Reflective DLL Loading for stealthier unhooking
 - Consider unhooking only specific functions rather than entire DLLs
 - Monitor for re-hooking attempts by the security product

## MITRE ATT&CK Mapping
 - T1562.001: Impair Defenses: Disable or Modify Tools
