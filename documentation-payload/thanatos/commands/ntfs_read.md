+++
title = "ntfs_read"
chapter = false
weight = 306
hidden = true
+++

## Description
Read files directly from an NTFS volume by parsing the Master File Table (MFT) and bypassing Windows file system APIs. This technique accesses raw disk sectors to read file content without generating File System Minifilter callbacks or using standard file handles, providing stealth access to files.

### Parameters
- **volume** (String, default: "C"): NTFS volume letter to read from (e.g., C, D, E)
- **path** (String, required): Full path to the file on the NTFS volume

## Usage
```
ntfs_read -volume C -path "C:\Windows\System32\config\SAM"
ntfs_read -volume D -path "D:\sensitive\credentials.txt"
```

## Notes
- Requires the advanced_collection feature to be compiled into the agent
- Only works on Windows systems with NTFS file systems
- Requires administrator privileges to access raw disk
- Bypasses file system filters and minifilter drivers
- Does not generate standard file access events
- Returns file content as base64-encoded data (truncated in output for large files)
- Can access files locked by the OS or other processes
- May be able to read files deleted but not yet overwritten on disk

## OPSEC Considerations
- **Detection Risk: MEDIUM-HIGH**
- Raw disk access requires admin privileges and may trigger alerts:
  - Opening `\\.\C:` raw disk device is highly suspicious
  - EDR may monitor CreateFile calls to physical volumes
  - Some security products specifically watch for MFT parsing techniques
- Benefits:
  - No file handle opened to target file
  - No File System Minifilter callbacks generated
  - Can access files without triggering SACL auditing
  - Bypasses user-mode file system hooks
- Blue team detection vectors:
  - Process accessing `\\.\PhysicalDrive*` or `\\.\C:` device paths
  - Unusual disk I/O patterns from non-system processes
  - ETW events for raw disk access
  - Sysmon Event ID 9 (RawAccessRead)
- Alternatives for better OPSEC:
  - Use Volume Shadow Copy Service (VSS) for locked files
  - Use standard file APIs if minifilter evasion is not required
  - Consider NTFS transaction log parsing for deleted files

## MITRE ATT&CK Mapping
- T1005: Data from Local System
- T1003.002: OS Credential Dumping: Security Account Manager
