+++
title = "socks"
chapter = false
weight = 103
hidden = true
+++

## Description
Enable a SOCKS5 proxy on the Mythic server tunneled through this agent. Compatible with
proxychains/proxychains4.

### Parameters
`port`
 * Port number for the SOCKS proxy (use 0 for auto-assignment)

`action`
 * Action to perform: `start` or `stop`

`username`
 * Username for SOCKS authentication (optional)

`password`
 * Password for SOCKS authentication (optional)

## Usage
```
socks -port <number> -action {start|stop} [-username u] [-password p]
```

### Examples

Start with auto-assigned port:
```
socks -port 0 -action start
```

Start on specific port with authentication:
```
socks -port 1080 -action start -username myuser -password mypass
```

Stop:
```
socks -port 1080 -action stop
```

## Notes
 - The task stays alive while the SOCKS proxy is running
 - Use `jobkill` to terminate a running SOCKS proxy
 - Works with proxychains, proxychains4, and any SOCKS5 client

## OPSEC Considerations
 - The Mythic server opens a listening port
 - SOCKS traffic patterns may be detectable by network monitoring

## MITRE ATT&CK Mapping
 - T1090
