<p align="center">
  <img alt="Thanatos Logo" src="agent_icons/thanatos.svg" height="50%" width="50%">
</p>

# Thanatos

[![GitHub License](https://img.shields.io/github/license/MythicAgents/thanatos)](https://github.com/MythicAgents/thanatos/blob/main/LICENSE)
[![GitHub Release](https://img.shields.io/github/v/release/MythicAgents/thanatos)](https://github.com/MythicAgents/thanatos/releases/latest)
[![Release](https://github.com/MythicAgents/thanatos/workflows/Release/badge.svg)](https://github.com/MythicAgents/thanatos/actions/workflows/release.yml)

Thanatos is a Windows and Linux C2 agent written in Rust.

## Installation
To install Thanatos, you will need [Mythic](https://github.com/its-a-feature/Mythic) set up on a machine.

In the Mythic root directory, use `mythic-cli` to install the agent.
```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/thanatos
sudo ./mythic-cli payload start thanatos
```

Thanatos supports the http C2 profile:  
```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
sudo ./mythic-cli c2 start http
```

## Features
  - Background job management
  - Built-in ssh client (execute, upload/download, directory listing, agent spawning, ssh-agent hijacking)
  - Streaming portscan
  - TCP redirectors and SOCKS5 proxy
  - Token manipulation (steal, create, impersonate, revert)
  - Native LDAP/AD enumeration (no PowerShell/SharpHound dependency)
  - Windows credential dumping (vault, credman, SAM, LSA secrets)
  - Cleanup-by-technique for purple-team engagements
  - In-memory shellcode execution

## Commands

### General Commands

Command | Syntax | Description
------- | ------ | -----------
cat | `cat [file]` | Output the contents of a file
cd | `cd [directory]` | Change directory
cp | `cp [source] [destination]` | Copy a file
download | `download [path]` | Download a file from target
exit | `exit` | Exit the agent
getenv | `getenv` | Get environment variables
getprivs | `getprivs` | Get agent session privileges
jobkill | `jobkill [id]` | Kill a background job
jobs | `jobs` | List running background jobs
ls | `ls [directory]` | List directory contents
mkdir | `mkdir [directory]` | Create directory
mv | `mv [source] [destination]` | Move a file
netstat | `netstat` | Get active network connections
ps | `ps` | List running processes
pwd | `pwd` | Print working directory
rm | `rm [path]` | Remove a file or directory
setenv | `setenv [name] [value]` | Set an environment variable
shell | `shell [command]` | Run shell command (bash/cmd.exe)
sleep | `sleep [interval][s/m/h] [jitter]` | Set sleep interval and jitter
unsetenv | `unsetenv [var]` | Unset an environment variable
upload | `upload [popup]` | Upload a file to the host
workinghours | `workinghours HH:MM HH:MM` | Set agent working hours

### Network / Pivoting

Command | Syntax | Description
------- | ------ | -----------
portscan | `portscan [popup]` | Scan hosts for open ports
redirect | `redirect [bindhost:bindport:connecthost:connectport]` | Set up a TCP redirector
portfwd | `portfwd [bindhost:bindport:connecthost:connectport]` | Port forwarding (alias for redirect)
socks | `socks -port <n> -action {start\|stop}` | SOCKS5 proxy through the agent

### SSH

Command | Syntax | Description
------- | ------ | -----------
ssh | `ssh [popup]` | Execute commands, transfer files via SSH
ssh-agent | `ssh-agent [-c socket] [-d] [-l]` | Interact with SSH agent sockets
ssh-spawn | `ssh-spawn [popup]` | Spawn a Mythic agent via SSH

### Windows Commands

Command | Syntax | Description
------- | ------ | -----------
askcreds | `askcreds [reason]` | Prompt user for credentials via CredUI
clipboard | `clipboard` | Retrieve clipboard text contents
powershell | `powershell [command]` | Run PowerShell command
screenshot | `screenshot` | Capture desktop screenshot
shinject | `shinject [popup]` | Execute shellcode in-process

### Credential Harvesting

Command | Syntax | Description
------- | ------ | -----------
credentials_dump | `credentials_dump -source <vault\|credman\|sam\|lsa_secrets>` | Dump Windows credential stores

### Token Manipulation

Command | Syntax | Description
------- | ------ | -----------
token_list | `token_list` | List stored tokens
token_steal | `token_steal -pid <pid>` | Steal token from a process
token_make | `token_make -domain <d> -username <u> -password <p>` | Create logon token from credentials
token_use | `token_use -token_id <id>` | Impersonate a stored token
token_revert | `token_revert` | Revert to original token

### Active Directory / LDAP

Command | Syntax | Description
------- | ------ | -----------
domain_info | `domain_info` | Query domain name, forest, DCs, functional level
domain_users | `domain_users [-group 'Domain Admins']` | Enumerate domain group members
domain_computers | `domain_computers [-filter all\|servers\|dcs]` | Enumerate domain computers
ldap_search | `ldap_search -filter '(objectClass=user)'` | Execute raw LDAP queries

### Cleanup / Anti-Forensics

Command | Syntax | Description
------- | ------ | -----------
cleanup | `cleanup -technique <technique> [-target <path>]` | Clean up artifacts by technique
timestomp | `timestomp -path <file> [-reference <ref>]` | Modify file timestamps
eventlog_clear | `eventlog_clear -log <Security\|System\|Application>` | Clear a Windows event log
