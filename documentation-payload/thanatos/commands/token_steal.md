+++
title = "token_steal"
chapter = false
weight = 103
hidden = true
+++

## Description
Steal a token from the specified process and store it for impersonation.

### Parameters
`pid`
 * Process ID to steal token from

## Usage
```
token_steal -pid <process_id>
```

## Notes
 - Requires SeDebugPrivilege or admin rights
 - Stolen token is stored and can be used with `token_use`
 - Use `token_list` to see stored tokens
 - Use `token_revert` to return to original token

## OPSEC Considerations
 - Opens a handle to the target process (detectable by EDR)
 - Calls OpenProcessToken / DuplicateTokenEx

## MITRE ATT&CK Mapping
 - T1134.001
