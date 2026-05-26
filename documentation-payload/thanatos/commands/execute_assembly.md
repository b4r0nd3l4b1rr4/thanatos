+++
title = "execute_assembly"
chapter = false
weight = 107
hidden = true
+++

## Description
Load and execute a .NET assembly in-memory. This command downloads a .NET executable or DLL, loads it into memory using PowerShell's Assembly.Load, and executes its entry point with optional arguments. This technique avoids writing the assembly to disk in most cases.

### Parameters
`assembly`
 * .NET assembly file to upload and execute (via Mythic file upload)

`arguments` (optional)
 * Command-line arguments to pass to the assembly's Main method

## Usage
```
execute_assembly (modal popup - upload assembly and provide arguments)
```

## Notes
 - Assembly is downloaded from Mythic in chunks (512KB per chunk)
 - Written temporarily to disk (`%TEMP%\assembly_<task_id>.dll`) then deleted after execution
 - Uses PowerShell's Reflection.Assembly.Load for in-memory execution
 - Works with both EXE and DLL assemblies that have an entry point
 - Does not support assemblies requiring specific .NET Framework versions beyond what's installed
 - Arguments are passed as a single string and split by spaces
 - File is marked with `delete_after_fetch` for OPSEC

## OPSEC Considerations
 - **Detection Risk: MEDIUM-HIGH**
 - PowerShell execution will appear in process creation logs
 - .NET assembly loading generates multiple telemetry sources:
   - CLR ETW events show assembly loads
   - PowerShell Script Block Logging (Event ID 4104)
   - AMSI scans assembly content before loading
   - .NET event logs may record assembly execution
 - Temp file write is detectable by file system monitoring
 - Consider using `amsi_patch` and `etw_patch` before executing assemblies
 - Large assemblies may take time to transfer over C2 channel
 - Assembly execution in PowerShell process may be suspicious
 - Some EDRs hook CLR loading functions to inspect assemblies
 - Memory scanning may detect loaded assembly signatures

## Advanced Recommendations
 - Use obfuscation tools like ConfuserEx or .NET Reactor on assemblies
 - Patch AMSI and ETW before execution for better evasion
 - Consider splitting large assemblies into smaller chunks
 - Use native .NET hosting from Rust for better stealth (future enhancement)
 - Avoid using assemblies with well-known signatures (Rubeus, SharpHound, etc.)

## MITRE ATT&CK Mapping
 - T1059.001: Command and Scripting Interpreter: PowerShell
