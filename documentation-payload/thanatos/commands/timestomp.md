+++
title = "timestomp"
chapter = false
weight = 103
hidden = true
+++

## Description
Modify file timestamps to match a reference file or reset to a neutral value.

### Parameters
`path`
 * Path to the file to timestomp

`reference`
 * Copy timestamps from this reference file (optional - uses neutral value if omitted)

## Usage
```
timestomp -path <file> [-reference <ref_file>]
```

### Examples

Match timestamps to a system file:
```
timestomp -path C:\Windows\Temp\payload.exe -reference C:\Windows\System32\notepad.exe
```

## Notes
 - Modifies creation time, last access time, and last write time
 - If no reference file is specified, uses a neutral timestamp (January 2020)
 - Works on both Windows (SetFileTime) and Linux (utimensat)

## OPSEC Considerations
 - NTFS $MFT still contains the original timestamps in $STANDARD_INFORMATION
 - Forensic tools can detect timestomping via $MFT analysis
 - $FILE_NAME attribute timestamps are not modified

## MITRE ATT&CK Mapping
 - T1070.006
