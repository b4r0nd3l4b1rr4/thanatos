+++
title = "credentials_dump"
chapter = false
weight = 103
hidden = true
+++

## Description
Dump credentials from the specified Windows credential store.

### Parameters
`source`
 * Credential source: `vault`, `credman`, `sam`, or `lsa_secrets`

## Usage
```
credentials_dump -source <vault|credman|sam|lsa_secrets>
```

### Examples

Dump Credential Manager:
```
credentials_dump -source credman
```

Dump SAM database:
```
credentials_dump -source sam
```

## Notes
 - Requires admin privileges
 - `vault` - Windows Vault (web credentials, etc.)
 - `credman` - Credential Manager stored credentials
 - `sam` - Local SAM database (NTLM hashes)
 - `lsa_secrets` - LSA secrets (service account credentials, DPAPI keys)

## OPSEC Considerations
 - High-risk operation - likely to trigger EDR alerts
 - SAM/LSA access requires SYSTEM-level privileges
 - Generates multiple API calls that are commonly monitored

## MITRE ATT&CK Mapping
 - T1003
 - T1555
