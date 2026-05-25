+++
title = "domain_computers"
chapter = false
weight = 103
hidden = true
+++

## Description
Enumerate domain computers via LDAP query.

### Parameters
`filter`
 * Filter type: `all`, `servers`, or `dcs` (default: "all")

## Usage
```
domain_computers [-filter all|servers|dcs]
```

### Examples

List all computers:
```
domain_computers
```

List only domain controllers:
```
domain_computers -filter dcs
```

## Notes
 - Uses LDAP objectCategory=computer queries
 - Returns hostname, OS version, and last logon timestamp

## OPSEC Considerations
 - LDAP query to the domain controller
 - Enumerating all computers generates a large query

## MITRE ATT&CK Mapping
 - T1018
