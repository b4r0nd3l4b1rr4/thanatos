<p align="center">
  <img alt="Thanatos Logo" src="agent_icons/thanatos.svg" height="50%" width="50%">
</p>

# Thanatos

[![GitHub License](https://img.shields.io/github/license/MythicAgents/thanatos)](https://github.com/MythicAgents/thanatos/blob/main/LICENSE)
[![GitHub Release](https://img.shields.io/github/v/release/MythicAgents/thanatos)](https://github.com/MythicAgents/thanatos/releases/latest)
[![Release](https://github.com/MythicAgents/thanatos/workflows/Release/badge.svg)](https://github.com/MythicAgents/thanatos/actions/workflows/release.yml)

Thanatos is a Windows and Linux C2 agent written in Rust, designed for purple-team engagements.

## Installation
```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/thanatos
sudo ./mythic-cli payload start thanatos
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
sudo ./mythic-cli c2 start http
```

## Features
  - 69 commands covering the full kill chain
  - Background job management
  - Built-in SSH client (exec, upload/download, listing, agent spawning, ssh-agent hijack)
  - SOCKS5 proxy and TCP redirectors
  - Token manipulation (steal, create, impersonate, revert)
  - Native LDAP/AD enumeration
  - Windows credential dumping and browser cookie/credential extraction
  - Lateral movement (WMI, PsExec, WinRM)
  - Persistence (scheduled tasks, registry, services, WMI subscriptions)
  - Defense evasion (AMSI patch, ETW patch, DLL unhooking)
  - In-memory .NET assembly execution and BOF support
  - Cleanup-by-technique for purple-team engagements

## Commands (69 total)

### General Commands

Command | Syntax | Description
------- | ------ | -----------
cat | `cat [file]` | Output file contents
cd | `cd [dir]` | Change directory
cp | `cp [src] [dst]` | Copy a file
download | `download [path]` | Download file from target
exit | `exit` | Kill the agent
getenv | `getenv` | Get environment variables
getprivs | `getprivs` | Get session privileges
jobkill | `jobkill [id]` | Kill a background job
jobs | `jobs` | List background jobs
ls | `ls [dir]` | List directory
mkdir | `mkdir [dir]` | Create directory
mv | `mv [src] [dst]` | Move a file
netstat | `netstat` | Active network connections
ps | `ps` | List processes
pwd | `pwd` | Print working directory
rm | `rm [path]` | Remove file/directory
setenv | `setenv [name] [value]` | Set environment variable
shell | `shell [cmd]` | Run shell command
sleep | `sleep [interval][s/m/h] [jitter]` | Set sleep interval
unsetenv | `unsetenv [var]` | Unset environment variable
upload | `upload` | Upload file to host
whoami | `whoami` | Current user/groups/privs
workinghours | `workinghours HH:MM HH:MM` | Set working hours

### Network / Pivoting

Command | Syntax | Description
------- | ------ | -----------
portscan | `portscan` | Scan hosts for open ports
redirect | `redirect [bind:port:connect:port]` | TCP redirector
portfwd | `portfwd [bind:port:connect:port]` | Port forward (alias)
socks | `socks -port <n> -action {start\|stop}` | SOCKS5 proxy

### SSH

Command | Syntax | Description
------- | ------ | -----------
ssh | `ssh` | Execute/transfer via SSH
ssh-agent | `ssh-agent [-c socket] [-d] [-l]` | SSH agent interaction
ssh-spawn | `ssh-spawn` | Spawn agent via SSH

### Windows Commands

Command | Syntax | Description
------- | ------ | -----------
askcreds | `askcreds [reason]` | CredUI prompt
clipboard | `clipboard` | Get clipboard text
powershell | `powershell [cmd]` | Run PowerShell
screenshot | `screenshot` | Capture desktop
shinject | `shinject` | Execute shellcode in-process

### Credential Harvesting

Command | Syntax | Description
------- | ------ | -----------
credentials_dump | `credentials_dump -source <vault\|credman\|sam\|lsa_secrets>` | Dump credential stores
browser_creds | `browser_creds [-browser all]` | Extract browser saved passwords
browser_cookies | `browser_cookies [-browser all] [-domain .example.com]` | Extract browser cookies

### Token Manipulation

Command | Syntax | Description
------- | ------ | -----------
token_list | `token_list` | List stored tokens
token_steal | `token_steal -pid <pid>` | Steal process token
token_make | `token_make -domain <d> -username <u> -password <p>` | Create logon token
token_use | `token_use -token_id <id>` | Impersonate token
token_revert | `token_revert` | Revert to original

### Active Directory / LDAP

Command | Syntax | Description
------- | ------ | -----------
domain_info | `domain_info` | Domain/forest/DC info
domain_users | `domain_users [-group 'Domain Admins']` | Group members
domain_computers | `domain_computers [-filter all\|servers\|dcs]` | Domain computers
ldap_search | `ldap_search -filter '(objectClass=user)'` | Raw LDAP query

### Discovery

Command | Syntax | Description
------- | ------ | -----------
net_shares | `net_shares [-host 127.0.0.1]` | Enumerate SMB shares
net_sessions | `net_sessions [-host 127.0.0.1]` | Active sessions
net_loggedon | `net_loggedon [-host 127.0.0.1]` | Logged on users

### Lateral Movement

Command | Syntax | Description
------- | ------ | -----------
wmi_exec | `wmi_exec -host <h> -command <cmd>` | WMI remote execution
psexec | `psexec -host <h> -command <cmd>` | Service-based remote exec
winrm_exec | `winrm_exec -host <h> -command <cmd>` | WinRM remote execution

### Persistence

Command | Syntax | Description
------- | ------ | -----------
persist_schtask | `persist_schtask -name <n> -action create -command <cmd> -schedule DAILY` | Scheduled task
persist_registry | `persist_registry -action create -name <n> -value <v>` | Registry Run key
persist_service | `persist_service -action create -name <n> -bin_path <p>` | Windows service
persist_wmi | `persist_wmi -action create -name <n> -command <cmd>` | WMI subscription

### Defense Evasion

Command | Syntax | Description
------- | ------ | -----------
amsi_patch | `amsi_patch` | Patch AMSI
etw_patch | `etw_patch` | Disable ETW tracing
unhook | `unhook [-dll ntdll.dll]` | Unhook DLL from EDR

### Execution

Command | Syntax | Description
------- | ------ | -----------
execute_assembly | `execute_assembly` | Run .NET assembly in-memory
bof | `bof` | Run Beacon Object File

### Collection

Command | Syntax | Description
------- | ------ | -----------
keylogger_start | `keylogger_start` | Start keylogger
keylogger_stop | `keylogger_stop` | Stop and retrieve keys

### Cleanup / Anti-Forensics

Command | Syntax | Description
------- | ------ | -----------
cleanup | `cleanup -technique <t> [-target <path>]` | Clean artifacts by technique
timestomp | `timestomp -path <f> [-reference <r>]` | Modify file timestamps
eventlog_clear | `eventlog_clear -log Security` | Clear event log

### C2 Management

Command | Syntax | Description
------- | ------ | -----------
c2info | `c2info` | Show C2 config
killdate | `killdate -action get` | Get/set killdate
