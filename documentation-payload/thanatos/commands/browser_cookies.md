+++
title = "browser_cookies"
chapter = false
weight = 109
hidden = true
+++

## Description
Extract cookies from Chromium-based browsers (Chrome, Edge, Brave, Opera) for session hijacking analysis and credential theft operations.

### Parameters
`browser`
 * Target browser: `chrome`, `edge`, `brave`, `opera`, or `all` (default)

`domain_filter`
 * Optional domain filter to limit results (e.g., `.github.com`, `.google.com`)
 * Leave empty to extract all cookies

## Usage
```
browser_cookies [-browser <chrome|edge|brave|opera|all>] [-domain <domain_filter>]
```

### Examples

Extract cookies from all browsers:
```
browser_cookies
```

Extract cookies from Chrome only:
```
browser_cookies -browser chrome
```

Extract GitHub cookies from all browsers:
```
browser_cookies -domain .github.com
```

Extract Google cookies from Edge:
```
browser_cookies -browser edge -domain .google.com
```

## Data Extracted
The command extracts the following cookie metadata:
 - **browser**: Source browser (chrome/edge/brave/opera)
 - **host**: Cookie domain/host (e.g., `.github.com`)
 - **name**: Cookie name (e.g., `user_session`)
 - **path**: Cookie path scope
 - **expires_utc**: Expiration timestamp (Chromium epoch format)
 - **secure**: Boolean flag indicating HTTPS-only cookie
 - **httponly**: Boolean flag indicating no JavaScript access
 - **encrypted_value_length**: Length of encrypted cookie value in bytes

## Notes
 - **Does not extract raw cookie values**: The `encrypted_value` field is DPAPI-protected and requires additional decryption (not implemented in this version). The length is reported to indicate non-empty cookies.
 - Copies the browser's SQLite cookie database to a temporary location before reading
 - Uses Windows' built-in `winsqlite3.dll` (available on Windows 10+)
 - Limits results to 200 cookies per browser to prevent excessive output
 - Works on locked browser databases by creating a temporary copy
 - Supports both legacy (`Default\Cookies`) and modern (`Default\Network\Cookies`) Chromium cookie storage locations

## OPSEC Considerations
 - **Medium-High Risk**: Copying browser profile files may be detected by EDR solutions monitoring file system activity in browser directories
 - Creates temporary `.db` files in `%TEMP%` directory (automatically deleted after extraction)
 - PowerShell execution with SQLite native code may trigger behavioral detection
 - Consider using manual file exfiltration of the cookie database for offline decryption instead
 - Browser must be closed or database will be locked (command uses copy to work around this)

## MITRE ATT&CK Mapping
 - **T1539** - Steal Web Session Cookie
