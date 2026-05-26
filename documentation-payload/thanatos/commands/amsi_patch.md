+++
title = "amsi_patch"
chapter = false
weight = 104
hidden = true
+++

## Description
Patch AMSI (Antimalware Scan Interface) in the current process to bypass script scanning. This technique disables AMSI by setting the `amsiInitFailed` field to true, effectively preventing AMSI from scanning PowerShell scripts, .NET assemblies, and other content in the current process.

### Parameters
None

## Usage
```
amsi_patch
```

## Notes
 - Affects only the current process, not system-wide
 - Uses PowerShell reflection to modify the `AmsiUtils` internal class
 - Sets the `amsiInitFailed` field to bypass AMSI initialization
 - Does not require administrative privileges
 - Effective against Windows Defender and other AMSI-integrated security products

## OPSEC Considerations
 - **Detection Risk: MEDIUM-HIGH**
 - PowerShell execution will appear in process creation logs
 - AMSI bypass attempts are well-known and may be detected by:
   - EDR behavioral monitoring for AMSI manipulation
   - PowerShell Script Block Logging (Event ID 4104)
   - ETW (Event Tracing for Windows) if not also patched
 - Consider using `etw_patch` in conjunction with this command
 - The PowerShell command line includes obvious AMSI bypass indicators
 - Some modern EDRs hook the AMSI bypass itself or monitor for memory modifications

## MITRE ATT&CK Mapping
 - T1562.001: Impair Defenses: Disable or Modify Tools
