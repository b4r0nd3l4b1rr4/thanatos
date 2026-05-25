+++
title = "clipboard"
chapter = false
weight = 103
hidden = true
+++

## Description
Retrieve the text contents of the Windows clipboard.

### Parameters
None.

## Usage
```
clipboard
```

## Notes
 - Uses Windows API (OpenClipboard, GetClipboardData) for clipboard access
 - Supports CF_UNICODETEXT format
 - Returns empty message if clipboard contains no text data

## OPSEC Considerations
 - Clipboard access may be logged by EDR solutions
 - No artifacts written to disk

## MITRE ATT&CK Mapping
 - T1115
