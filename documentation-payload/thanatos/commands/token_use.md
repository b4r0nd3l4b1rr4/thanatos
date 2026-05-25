+++
title = "token_use"
chapter = false
weight = 103
hidden = true
+++

## Description
Impersonate a stored token by its ID from token_list.

### Parameters
`token_id`
 * Token ID from token_list to impersonate

## Usage
```
token_use -token_id <id>
```

## Notes
 - After impersonation, subsequent commands run under the impersonated token
 - Use `token_revert` to return to the original identity
 - Token IDs can be obtained from `token_list`

## MITRE ATT&CK Mapping
 - T1134.001
