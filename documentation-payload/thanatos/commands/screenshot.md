+++
title = "screenshot"
chapter = false
weight = 103
hidden = true
+++

## Description
Capture the full desktop using native WinAPI (StretchBlt) and upload it as a BMP image.

### Parameters
None.

## Usage
```
screenshot
```

## Notes
 - Uses native Windows API (StretchBlt) for screen capture
 - Saves as BMP in the system temp directory
 - Automatically triggers a download task to retrieve the file
 - Captured file appears in Mythic's file browser

## OPSEC Considerations
 - Creates a temporary BMP file on disk
 - Calls WinAPI screen capture functions (may be monitored by EDR)

## MITRE ATT&CK Mapping
 - T1113
