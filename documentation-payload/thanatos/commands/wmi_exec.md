+++
title = "wmi_exec"
chapter = false
weight = 103
hidden = true
+++

## Description
Execute a command on a remote Windows host using Windows Management Instrumentation (WMI). This technique is commonly used for lateral movement and remote code execution in Windows environments.

### Parameters
`host` (required)
 * Target hostname or IP address

`command` (required)
 * Command to execute on the remote host

`username` (optional)
 * Username for authentication (if not using current credentials)

`password` (optional)
 * Password for authentication

## Usage
```
wmi_exec {"host":"TARGET","command":"COMMAND"}
```
```
wmi_exec {"host":"TARGET","command":"COMMAND","username":"USER","password":"PASS"}
```

### Examples
```
wmi_exec {"host":"192.168.1.100","command":"whoami"}
```
```
wmi_exec {"host":"DC01.corp.local","command":"powershell -c Get-Process","username":"CORP\\admin","password":"P@ssw0rd"}
```

### Popup
Command supports using the Mythic UI popup for entering parameters.

## OPSEC Considerations
{{% notice warning %}}
WMI execution generates significant forensic artifacts:
- Event ID 4688 (Process Creation) on target system
- WMI Provider Host (WmiPrvSE.exe) will spawn the command
- Network connection on TCP 135 (RPC) and dynamic high ports
- Event ID 4624 (Logon) Type 3 if using explicit credentials
- WMI activity logged in Microsoft-Windows-WMI-Activity/Operational
- Security products may flag WMI-based lateral movement
{{% /notice %}}

{{% notice info %}}
Requires:
- Administrative privileges on the target system
- Windows Firewall allowing WMI/RPC traffic (TCP 135, 445, and dynamic ports)
- Remote access enabled in WMI configuration
- DCOM and WMI services running on target
{{% /notice %}}

## MITRE ATT&CK Mapping
 - T1047 - Windows Management Instrumentation
