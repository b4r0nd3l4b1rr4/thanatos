+++
title = "stealth_sleep"
chapter = false
weight = 305
hidden = true
+++

## Description
Execute an obfuscated sleep operation that encrypts the PE image in memory during the sleep interval. When compiled with the evasion feature, this command uses the Shelter library to fluctuate memory permissions and encrypt the agent in memory, making it harder for memory scanners to detect the implant during idle periods.

### Parameters
- **interval** (Number, default: 5): Sleep duration in seconds
- **encrypt_pe** (Boolean, default: true): Whether to encrypt the PE in memory during sleep (only effective with evasion feature)

## Usage
```
stealth_sleep
stealth_sleep -interval 10
stealth_sleep -interval 30 -encrypt_pe true
```

## Notes
- On agents compiled without the evasion feature, this falls back to standard sleep
- The evasion feature must be enabled at build time for memory encryption to work
- Only effective on Windows targets when evasion features are compiled in
- The PE encryption happens during the sleep interval, not just at the start
- Memory permissions are fluctuated between RW and no-access during encryption

## OPSEC Considerations
- **Detection Risk: LOW-MEDIUM (with evasion) / HIGH (without evasion)**
- With evasion features:
  - Significantly reduces memory scanning detection during sleep periods
  - Memory permissions changes may be detected by EDR monitoring VirtualProtect calls
  - Encrypted memory regions will not match expected PE structure
  - Behavioral detection may flag unusual memory permission patterns
- Without evasion features:
  - Equivalent to standard sleep, full PE visible in memory
  - Trivial for memory scanners to detect the implant
- Consider the sleep interval carefully:
  - Longer sleeps provide more time for memory scans but better evade behavioral detection
  - Shorter sleeps reduce encryption overhead but increase API call frequency
- Memory encryption provides time-based evasion, not persistent hiding

## MITRE ATT&CK Mapping
- T1497.003: Virtualization/Sandbox Evasion: Time Based Evasion
