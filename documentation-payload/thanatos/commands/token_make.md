+++
title = "token_make"
chapter = false
weight = 103
hidden = true
+++

## Description
Create a new logon token using plaintext credentials (LogonUserW).

### Parameters
`domain`
 * Domain for the new logon token

`username`
 * Username for the new logon token

`password`
 * Password for the new logon token

## Usage
```
token_make -domain <domain> -username <user> -password <pass>
```

## Notes
 - Uses LOGON32_LOGON_NEW_CREDENTIALS for network-only impersonation
 - The created token is stored and can be used with `token_use`
 - Useful for lateral movement with known credentials

## OPSEC Considerations
 - Generates a logon event (Event ID 4624 type 9)
 - Credential validation occurs against the domain controller

## MITRE ATT&CK Mapping
 - T1134.003
