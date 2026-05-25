+++
title = "domain_info"
chapter = false
weight = 103
hidden = true
+++

## Description
Query basic domain information: domain name, forest, domain controllers, functional level.

### Parameters
None.

## Usage
```
domain_info
```

## Notes
 - Uses DsGetDcNameW / NetGetJoinInformation for domain discovery
 - Returns domain FQDN, NetBIOS name, forest name, DC list, functional level

## OPSEC Considerations
 - Standard domain API calls - low detection risk
 - Minimal network traffic

## MITRE ATT&CK Mapping
 - T1087.002
