+++
title = "winrm_exec"
chapter = false
weight = 103
hidden = true
+++

## Description
Execute a command on a remote Windows host using Windows Remote Management (WinRM) via PowerShell's Invoke-Command. WinRM is a Microsoft implementation of the WS-Management protocol and is commonly enabled in enterprise environments for remote administration.

### Parameters
`host` (required)
 * Target hostname or IP address

`command` (required)
 * Command to execute on the remote host (PowerShell syntax)

`username` (optional)
 * Username for authentication (if not using current credentials)

`password` (optional)
 * Password for authentication

## Usage
```
winrm_exec {"host":"TARGET","command":"COMMAND"}
```
```
winrm_exec {"host":"TARGET","command":"COMMAND","username":"USER","password":"PASS"}
```

### Examples
```
winrm_exec {"host":"192.168.1.100","command":"Get-Process | Where-Object {$_.CPU -gt 100}"}
```
```
winrm_exec {"host":"WEB01.corp.local","command":"Stop-Service -Name IIS","username":"CORP\\admin","password":"P@ssw0rd"}
```
```
winrm_exec {"host":"DC01","command":"Get-ADUser -Filter * | Select Name,Enabled"}
```

### Popup
Command supports using the Mythic UI popup for entering parameters.

## OPSEC Considerations
{{% notice warning %}}
WinRM execution generates forensic artifacts and network traffic:
- Event ID 4688 (Process Creation) for PowerShell and wsmprovhost.exe
- Event ID 4624 (Logon) Type 3 (Network) or Type 10 (RemoteInteractive)
- Event ID 4648 (Explicit Credential Use) if credentials provided
- WinRM activity logged in Microsoft-Windows-WinRM/Operational
- PowerShell ScriptBlock logging may capture command content (Event ID 4104)
- PowerShell Module logging and Transcription if enabled
- Network connection on TCP 5985 (HTTP) or 5986 (HTTPS)
- Process creation chain: wsmprovhost.exe -> powershell.exe
- Security products may monitor WinRM-based lateral movement
{{% /notice %}}

{{% notice info %}}
Requires:
- WinRM service enabled on target (default on Windows Server 2012+)
- Windows Firewall allowing WinRM traffic (TCP 5985/5986)
- Administrative privileges on the target (for most operations)
- Target must be configured to accept remote WinRM connections
- PowerShell remoting enabled via Enable-PSRemoting
- For non-domain environments, TrustedHosts may need configuration
{{% /notice %}}

{{% notice tip %}}
Advantages over other lateral movement methods:
- More stealthy than service-based execution (no Event ID 7045)
- Built-in encrypted communication channel (HTTPS option)
- Legitimate administrative tool with less suspicious profile
- Better integration with PowerShell capabilities
- Native support for credential delegation

Defense evasion considerations:
- WinRM is commonly whitelisted in enterprise environments
- Less likely to trigger alerts than PsExec or WMI in mature environments
- Can leverage existing Kerberos tickets with current user context
{{% /notice %}}

## MITRE ATT&CK Mapping
 - T1021.006 - Remote Services: Windows Remote Management
