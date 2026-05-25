+++
title = "shinject"
chapter = false
weight = 103
hidden = true
+++

## Description
Execute shellcode in the current process using a separate thread.

### Parameters
`shellcode`
 * Shellcode file to upload and execute (via Mythic file upload)

## Usage
```
shinject (modal popup - upload shellcode file)
```

## Notes
 - Shellcode runs in the current agent process (not remote injection)
 - Executes in a background thread so the agent is not blocked
 - Uses VirtualAlloc with PAGE_EXECUTE_READWRITE
 - File is marked with delete_after_fetch for OPSEC
 - A valid shellcode file must be provided

## OPSEC Considerations
 - Allocates RWX memory (detectable by EDR)
 - Creates a new thread in the current process
 - In-process execution is more detectable than advanced injection techniques

## MITRE ATT&CK Mapping
 - T1055
