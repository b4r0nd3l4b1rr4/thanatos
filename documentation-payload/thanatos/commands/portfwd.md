+++
title = "portfwd"
chapter = false
weight = 103
hidden = true
+++

## Description
Port forwarding alias for the `redirect` command. Sets up a TCP redirector on the machine.

### Parameters
`bindhost`
 * Bind host address (default: 0.0.0.0)

`bindport`
 * Bind port

`connecthost`
 * Connect host address

`connectport`
 * Connect port

## Usage
```
portfwd -bindhost [host] -bindport [port] -connecthost [host] -connectport [port]
```

Short format:
```
portfwd bindport:connecthost:connectport
portfwd bindhost:bindport:connecthost:connectport
```

## Notes
 - This is an alias that delegates to the `redirect` command
 - Behavior is identical to `redirect`

## OPSEC Considerations
 - Agent will bind to a port
 - Machine firewall may block inbound or outbound connections

## MITRE ATT&CK Mapping
 - T1090
