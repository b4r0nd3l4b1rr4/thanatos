+++
title = "psexec"
chapter = false
weight = 103
hidden = true
+++

## Description
Execute a command on a remote Windows host by creating and starting a Windows service (PsExec-style execution). This technique creates a temporary service on the target system, starts it to execute the command, and then deletes the service.

### Parameters
`host` (required)
 * Target hostname or IP address

`command` (required)
 * Command to execute on the remote host

`service_name` (optional, default: "thanatos_svc")
 * Name of the temporary service to create

`username` (optional)
 * Username for authentication (if not using current credentials)

`password` (optional)
 * Password for authentication

## Usage
```
psexec {"host":"TARGET","command":"COMMAND"}
```
```
psexec {"host":"TARGET","command":"COMMAND","service_name":"my_svc","username":"USER","password":"PASS"}
```

### Examples
```
psexec {"host":"192.168.1.100","command":"whoami > C:\\temp\\output.txt"}
```
```
psexec {"host":"WEB01.corp.local","command":"powershell -c Stop-Service -Name BadSvc","service_name":"admin_task","username":"CORP\\admin","password":"P@ssw0rd"}
```

### Popup
Command supports using the Mythic UI popup for entering parameters.

## OPSEC Considerations
{{% notice warning %}}
PsExec-style execution is highly visible and generates significant forensic artifacts:
- Event ID 7045 (Service Installation) in System log with service name and binary path
- Event ID 7036 (Service State Change) when service starts and stops
- Event ID 4697 (Service Installed) in Security log
- Event ID 4688 (Process Creation) for services.exe spawning the command
- Network connection on TCP 445 (SMB)
- Event ID 4624 (Logon) Type 3 if using explicit credentials
- Service creation is a common IOC for lateral movement
- EDR/SIEM solutions actively monitor for suspicious service creation
- Named pipe creation for service communication
{{% /notice %}}

{{% notice info %}}
Requires:
- Administrative privileges on the target system (specifically, rights to create and start services)
- Windows Firewall allowing SMB traffic (TCP 445)
- Remote Service Control Manager (SCM) access enabled
- Target system must allow remote service operations
{{% /notice %}}

{{% notice tip %}}
Defense recommendations:
- Change the default service_name to something more legitimate
- Clean up failed service creation attempts
- Consider that many EDR solutions specifically detect service-based lateral movement
- Service creation will trigger real-time alerts in mature security environments
{{% /notice %}}

## MITRE ATT&CK Mapping
 - T1021.002 - Remote Services: SMB/Windows Admin Shares
 - T1543.003 - Create or Modify System Process: Windows Service
