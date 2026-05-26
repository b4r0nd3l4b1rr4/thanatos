+++
title = "net_sessions"
chapter = false
weight = 201
hidden = true
+++

## Description
Enumerate active sessions on a remote Windows host. Uses `net session \\<host>`.

Windows only.

## Usage
```
net_sessions [host]
```

### Parameters
- **host** (optional): Target host to enumerate. Defaults to `127.0.0.1`.

### Examples
```
net_sessions
net_sessions 192.168.1.10
net_sessions DC01.corp.local
```

## MITRE ATT&CK Mapping
- T1049
