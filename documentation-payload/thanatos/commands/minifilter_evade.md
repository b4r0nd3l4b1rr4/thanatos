+++
title = "minifilter_evade"
chapter = false
weight = 307
hidden = true
+++

## Description
Enable or disable minifilter driver evasion to bypass file system filter drivers used by antivirus and EDR products. When enabled, this technique prevents minifilter callbacks from being triggered during file operations performed by the agent, effectively blinding file-based monitoring.

### Parameters
- **action** (ChooseOne: "enable" | "disable", required): Action to perform

## Usage
```
minifilter_evade enable
minifilter_evade disable
```

## Notes
- Requires the minifilter_evasion feature to be compiled into the agent
- Only works on Windows systems
- Requires administrator privileges
- Affects file operations performed by the agent process
- Must be enabled before performing file operations to have effect
- Does not retroactively hide previous file operations
- May be detected by EDR kernel-mode components
- Effectiveness depends on the specific minifilter drivers present

## OPSEC Considerations
- **Detection Risk: HIGH**
- Kernel-mode techniques are heavily monitored:
  - EDR kernel drivers may detect minifilter manipulation attempts
  - Unusual kernel callbacks or SSDT hooks may trigger alerts
  - Process opening handles to minifilter device objects is suspicious
  - Some EDR products protect their minifilter drivers from tampering
- Benefits:
  - When successful, completely bypasses file system monitoring
  - Allows creation, modification, and deletion of files without alerts
  - Defeats minifilter-based DLP (Data Loss Prevention) solutions
  - Bypasses real-time file scanning by AV products
- Blue team detection vectors:
  - Minifilter altitude changes or unload attempts logged by Filter Manager
  - Kernel-mode callbacks being unregistered or modified
  - EDR product integrity checks detecting tampered drivers
  - Event Tracing for Windows (ETW) kernel events
  - PatchGuard violations on 64-bit systems
- Recommendations:
  - Use only on targets with verified weak or absent EDR
  - Enable just before critical file operations, disable immediately after
  - Prefer user-mode evasion techniques when possible
  - Test on similar environment before operational use
  - Have a cleanup/remediation plan if detection occurs

## MITRE ATT&CK Mapping
- T1562.006: Impair Defenses: Indicator Blocking
