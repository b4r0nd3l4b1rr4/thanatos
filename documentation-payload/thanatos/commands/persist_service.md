+++
title = "persist_service"
chapter = false
weight = 103
hidden = true
+++

## Description
Create or delete a Windows service for persistence. Services can run at system startup with SYSTEM privileges. Requires administrator privileges.

### Parameters
`action`
 * Action to perform: `create` or `delete`

`name`
 * Name of the service (internal name)

`display_name`
 * Display name of the service (required for create)

`bin_path`
 * Binary path for the service (required for create)

## Usage
```
persist_service -action {create|delete} -name <name> -display_name <name> -bin_path <path>
```

### Examples

Create a service:
```
persist_service -action create -name "WinUpdateSvc" -display_name "Windows Update Service Helper" -bin_path "C:\Windows\System32\svchost.exe"
```

Delete a service:
```
persist_service -action delete -name "WinUpdateSvc"
```

## Notes
 - Requires administrator privileges
 - Services run with SYSTEM privileges by default
 - Service is configured to start automatically (start=auto)
 - Delete action will stop the service before removing it

## OPSEC Considerations
 - Service creation generates Event ID 7045
 - Service deletion generates Event ID 7036
 - Services are easily enumerated by administrators
 - Unusual service names or paths are suspicious
 - Consider masquerading service names to blend with legitimate services

## MITRE ATT&CK Mapping
 - T1543.003 (Create or Modify System Process: Windows Service)
