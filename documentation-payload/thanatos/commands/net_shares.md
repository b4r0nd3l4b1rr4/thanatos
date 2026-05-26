+++
title = "net_shares"
chapter = false
weight = 200
hidden = true
+++

## Description
Enumerate SMB shares on a target host. On Windows, uses `net view \\<host> /all`. On Linux, attempts to use `smbclient -L <host> -N`.

## Usage
```
net_shares [host]
```

### Parameters
- **host** (optional): Target host to enumerate. Defaults to `127.0.0.1`.

### Examples
```
net_shares
net_shares 192.168.1.10
net_shares DC01.corp.local
```

## MITRE ATT&CK Mapping
- T1135
