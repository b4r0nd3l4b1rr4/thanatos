+++
title = "persist_wmi"
chapter = false
weight = 103
hidden = true
+++

## Description
Create or delete a WMI event subscription for persistence. WMI event subscriptions can trigger commands based on system events. Requires administrator privileges.

### Parameters
`action`
 * Action to perform: `create` or `delete`

`name`
 * Name of the WMI event subscription

`command`
 * Command to execute (required for create)

`trigger`
 * Trigger condition: "startup" for system startup or custom WQL query

## Usage
```
persist_wmi -action {create|delete} -name <name> -command <cmd> -trigger <trigger>
```

### Examples

Create a WMI subscription that runs at startup:
```
persist_wmi -action create -name "SystemMonitor" -command "C:\Windows\System32\calc.exe" -trigger "startup"
```

Create a custom WMI event subscription:
```
persist_wmi -action create -name "ProcessWatch" -command "powershell.exe -enc <base64>" -trigger "SELECT * FROM __InstanceCreationEvent WITHIN 10 WHERE TargetInstance ISA 'Win32_Process'"
```

Delete a WMI subscription:
```
persist_wmi -action delete -name "SystemMonitor"
```

## Notes
 - Requires administrator privileges
 - WMI subscriptions persist across reboots
 - Creates three WMI objects: EventFilter, EventConsumer, and FilterToConsumerBinding
 - Delete action removes all three components

## OPSEC Considerations
 - WMI event subscriptions are less commonly monitored than Run keys
 - Can be detected by tools like Autoruns and WMI Explorer
 - Event ID 5861 logs WMI permanent event subscriptions
 - PowerShell logging may capture the creation commands
 - Subscriptions stored in root\subscription namespace

## MITRE ATT&CK Mapping
 - T1546.003 (Event Triggered Execution: Windows Management Instrumentation Event Subscription)
