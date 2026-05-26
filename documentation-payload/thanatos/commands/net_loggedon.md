+++
title = "net_loggedon"
chapter = false
weight = 202
hidden = true
+++

## Description
List users logged on to a remote Windows host. Uses `query user /server:<host>`.

Windows only.

## Usage
```
net_loggedon [host]
```

### Parameters
- **host** (optional): Target host to enumerate. Defaults to `127.0.0.1`.

### Examples
```
net_loggedon
net_loggedon 192.168.1.10
net_loggedon WS01.corp.local
```

## MITRE ATT&CK Mapping
- T1033
