+++
title = "persist_registry"
chapter = false
weight = 103
hidden = true
+++

## Description
Create or delete a registry Run key for persistence. Registry Run keys execute programs automatically at user logon.

### Parameters
`action`
 * Action to perform: `create` or `delete`

`key`
 * Registry key path (default: HKCU\Software\Microsoft\Windows\CurrentVersion\Run)

`name`
 * Registry value name

`value`
 * Registry value data - the command to execute (required for create)

## Usage
```
persist_registry -action {create|delete} -key <key> -name <name> -value <data>
```

### Examples

Create a Run key in HKCU:
```
persist_registry -action create -name "Updater" -value "C:\Windows\System32\calc.exe"
```

Create a Run key in HKLM (requires admin):
```
persist_registry -action create -key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -name "ServiceHost" -value "C:\Program Files\service.exe"
```

Delete a Run key:
```
persist_registry -action delete -name "Updater"
```

## Notes
 - HKCU keys do not require admin privileges
 - HKLM keys require admin privileges
 - Programs execute when any user logs on (HKLM) or when specific user logs on (HKCU)

## OPSEC Considerations
 - Registry modifications generate Event ID 4657
 - Run keys are monitored by EDR and AV solutions
 - Easily detected by tools like Autoruns
 - Consider using less common registry persistence locations

## MITRE ATT&CK Mapping
 - T1547.001 (Boot or Logon Autostart Execution: Registry Run Keys)
