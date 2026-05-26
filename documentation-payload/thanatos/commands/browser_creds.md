+++
title = "browser_creds"
chapter = false
weight = 212
hidden = true
+++

## Description
Extract saved credentials from web browsers. Enumerates credential file locations for Chrome, Edge, and Firefox.

Windows only. This is a v1 implementation that locates credential files but does not decrypt them.

## Usage
```
browser_creds [browser]
```

### Parameters
- **browser** (optional): Browser to target. Options: `chrome`, `edge`, `firefox`, `all`. Defaults to `all`.

### Examples
```
browser_creds
browser_creds chrome
browser_creds edge
browser_creds all
```

### Notes
- Current version enumerates credential file locations
- Full decryption requires DPAPI implementation for Chrome/Edge
- Firefox uses a different encryption scheme
- Credential files typically located in:
  - Chrome: `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data`
  - Edge: `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Login Data`
  - Firefox: `%APPDATA%\Mozilla\Firefox\Profiles`

## MITRE ATT&CK Mapping
- T1555.003
