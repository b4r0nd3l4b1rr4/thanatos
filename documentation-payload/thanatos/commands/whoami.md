+++
title = "whoami"
chapter = false
weight = 203
hidden = true
+++

## Description
Get detailed information about the current user, including group memberships and privileges.

On Windows, uses `whoami /all`. On Linux, uses `id && groups`.

## Usage
```
whoami
```

### Examples
```
whoami
```

### Output
On Windows, displays:
- User information
- Group memberships
- Privileges
- Security identifiers (SIDs)

On Linux, displays:
- User ID and group ID
- Group memberships

## MITRE ATT&CK Mapping
- T1033
