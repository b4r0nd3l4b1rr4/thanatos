+++
title = "killdate"
chapter = false
weight = 221
hidden = true
+++

## Description
Get or set the agent killdate. The killdate is the date after which the agent will automatically terminate.

Note: The killdate is compiled into the agent binary at build time and cannot be modified at runtime in the current implementation.

## Usage
```
killdate -action <get|set> [-date YYYY-MM-DD]
```

### Parameters
- **action** (required): Action to perform. Options: `get`, `set`.
- **date** (optional): New killdate in YYYY-MM-DD format. Required for `set` action.

### Examples
```
killdate get
killdate set 2026-12-31
```

### Notes
- The killdate is set at compile time during agent build
- The `get` action returns the current killdate
- The `set` action is not supported at runtime and will return an informational message
- To change the killdate, rebuild the payload with the new killdate value

## MITRE ATT&CK Mapping
None (operational command)
