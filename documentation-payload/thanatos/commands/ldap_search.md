+++
title = "ldap_search"
chapter = false
weight = 103
hidden = true
+++

## Description
Execute an LDAP query against the domain controller using native Windows LDAP API.

### Parameters
`filter`
 * LDAP search filter (e.g. `(objectClass=user)`)

`base_dn`
 * Search base DN. Leave empty to use domain root (optional)

`attributes`
 * Comma-separated list of attributes to retrieve. Empty for all (optional)

`server`
 * Target domain controller. Empty for auto-discovery (optional)

## Usage
```
ldap_search -filter '(objectClass=user)' [-base_dn DC=corp,DC=local] [-attributes cn,samAccountName] [-server dc01.corp.local]
```

### Examples

Find all users:
```
ldap_search -filter '(&(objectClass=user)(objectCategory=person))'
```

Find computers with unconstrained delegation:
```
ldap_search -filter '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))'
```

Find SPNs for Kerberoasting:
```
ldap_search -filter '(&(objectClass=user)(servicePrincipalName=*))' -attributes samAccountName,servicePrincipalName
```

## Notes
 - Uses native Windows LDAP API (wldap32) - no PowerShell needed
 - Authenticates with the current user/token context
 - Use `token_make` or `token_steal` first to run queries as a different user

## OPSEC Considerations
 - LDAP queries generate network traffic to the DC
 - Large queries may trigger SIEM alerts
 - Queries are logged on the DC (Event ID 1644 if enabled)

## MITRE ATT&CK Mapping
 - T1087.002
 - T1069.002
