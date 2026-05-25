+++
title = "cleanup"
chapter = false
weight = 103
hidden = true
+++

## Description
Clean up artifacts left by a specific technique. Designed for purple-team engagements
where controlled cleanup is required after each test.

### Parameters
`technique`
 * Which technique artifacts to clean: `tokens`, `socks`, `redirect`, `shellcode`, `files`, `registry`, `scheduled_task`, `service`, `all`

`target`
 * Optional target identifier (file path, task name, service name, registry key)

## Usage
```
cleanup -technique <technique> [-target <path|name>]
```

### Examples

Clean up all stored tokens:
```
cleanup -technique tokens
```

Remove a specific dropped file:
```
cleanup -technique files -target C:\Windows\Temp\payload.exe
```

Remove a persistence scheduled task:
```
cleanup -technique scheduled_task -target "UpdateCheck"
```

Clean up everything:
```
cleanup -technique all
```

## Notes
 - `tokens` - Closes all stolen/created token handles, reverts to self
 - `socks` - Stops all running SOCKS proxies
 - `redirect` - Stops all running port redirectors
 - `shellcode` - Frees allocated executable memory regions
 - `files` - Deletes specified file(s) dropped during the engagement
 - `registry` - Removes specified registry key/value
 - `scheduled_task` - Deletes specified scheduled task
 - `service` - Stops and deletes specified service
 - `all` - Runs cleanup for all supported techniques

## OPSEC Considerations
 - Cleanup operations themselves generate artifacts (deletion events, etc.)
 - Event ID 4689 (process termination) may be generated
 - Service deletion generates Event ID 7036

## MITRE ATT&CK Mapping
 - T1070
