+++
title = "etw_patch"
chapter = false
weight = 105
hidden = true
+++

## Description
Patch ETW (Event Tracing for Windows) to disable event tracing in the current process. This technique prevents the process from generating ETW events, which are commonly used by security products for monitoring and detection.

### Parameters
None

## Usage
```
etw_patch
```

## Notes
 - Affects only the current process, not system-wide
 - Uses PowerShell reflection to modify the `EventProvider` class
 - Disables the `m_enabled` field to prevent ETW event generation
 - Does not require administrative privileges
 - Helps evade detection by security products that rely on ETW for monitoring

## OPSEC Considerations
 - **Detection Risk: MEDIUM-HIGH**
 - PowerShell execution will appear in process creation logs
 - ETW patching is a known evasion technique monitored by EDR:
   - Some EDRs detect attempts to disable ETW providers
   - Kernel-level monitoring may still capture events
   - Memory integrity checks may detect the modification
   - Process behavior (lack of expected ETW events) may trigger alerts
 - PowerShell Script Block Logging may still capture the command before ETW is disabled
 - Consider patching AMSI first to reduce script logging visibility
 - This only affects user-mode ETW; kernel ETW providers remain active

## MITRE ATT&CK Mapping
 - T1562.001: Impair Defenses: Disable or Modify Tools
