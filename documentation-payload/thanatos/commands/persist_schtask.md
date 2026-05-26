+++
title = "persist_schtask"
chapter = false
weight = 103
hidden = true
+++

## Description
Create or delete a scheduled task for persistence. Scheduled tasks can execute commands at specific times or intervals.

### Parameters
`name`
 * Name of the scheduled task

`action`
 * Action to perform: `create` or `delete`

`command`
 * Command to execute (required for create)

`schedule`
 * Schedule specification (e.g., "DAILY /ST 09:00")

## Usage
```
persist_schtask -name <name> -action {create|delete} -command <cmd> -schedule <schedule>
```

### Examples

Create a daily scheduled task:
```
persist_schtask -name "UpdateCheck" -action create -command "C:\Windows\System32\calc.exe" -schedule "DAILY /ST 09:00"
```

Delete a scheduled task:
```
persist_schtask -name "UpdateCheck" -action delete
```

## Notes
 - Scheduled tasks can be created without admin privileges for current user tasks
 - Tasks will execute even when the user is not logged in
 - Use cleanup command to remove persistence artifacts

## OPSEC Considerations
 - Scheduled task creation generates Event ID 4698
 - Task deletion generates Event ID 4699
 - Tasks are stored in %SystemRoot%\System32\Tasks
 - Can be detected by tools like Autoruns

## MITRE ATT&CK Mapping
 - T1053.005 (Scheduled Task/Job: Scheduled Task)
