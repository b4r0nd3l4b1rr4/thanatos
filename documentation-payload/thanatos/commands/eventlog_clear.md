+++
title = "eventlog_clear"
chapter = false
weight = 103
hidden = true
+++

## Description
Clear a Windows event log. Requires admin privileges.

### Parameters
`log`
 * Event log name to clear (e.g. Security, System, Application)

## Usage
```
eventlog_clear -log <Security|System|Application>
```

### Examples

Clear Security log:
```
eventlog_clear -log Security
```

## Notes
 - Requires administrator/SYSTEM privileges
 - Uses ClearEventLogW API
 - After clearing, Event ID 1102 is generated in the Security log (log cleared)

## OPSEC Considerations
 - Clearing the Security log generates Event ID 1102 (cannot be suppressed)
 - SIEM solutions typically alert on log clearing
 - Consider selective event deletion instead for stealth

## MITRE ATT&CK Mapping
 - T1070.001
