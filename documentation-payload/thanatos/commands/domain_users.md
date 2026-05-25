+++
title = "domain_users"
chapter = false
weight = 103
hidden = true
+++

## Description
Enumerate members of a domain group via LDAP. Defaults to Domain Admins.

### Parameters
`group`
 * Group name to enumerate (default: "Domain Admins")

## Usage
```
domain_users [-group 'Domain Admins']
```

### Examples

List Domain Admins:
```
domain_users
```

List Enterprise Admins:
```
domain_users -group 'Enterprise Admins'
```

## Notes
 - Resolves nested group memberships
 - Returns samAccountName, distinguishedName, and last logon for each member

## OPSEC Considerations
 - LDAP query to the domain controller
 - Common reconnaissance pattern - may trigger alerts

## MITRE ATT&CK Mapping
 - T1069.002
