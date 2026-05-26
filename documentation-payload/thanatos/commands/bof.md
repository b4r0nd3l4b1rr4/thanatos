+++
title = "bof"
chapter = false
weight = 108
hidden = true
+++

## Description
Execute a Beacon Object File (BOF/COFF). BOFs are small, position-independent code objects that can be loaded and executed in-memory without creating new processes. This is a highly stealthy execution technique popularized by Cobalt Strike.

### Parameters
`bof_file`
 * Beacon Object File (COFF format) to upload and execute (via Mythic file upload)

`arguments` (optional)
 * Arguments to pass to the BOF's `go()` function
 * Format depends on the specific BOF's argument packing scheme

## Usage
```
bof (modal popup - upload BOF file and provide arguments)
```

## Notes
 - BOF files are COFF (Common Object File Format) objects
 - Currently a **proof-of-concept implementation**
 - Full COFF loader implementation is planned for a future update
 - Current version downloads the BOF and confirms receipt but does not execute
 - File is marked with `delete_after_fetch` for OPSEC
 - BOF files are downloaded from Mythic in chunks (512KB per chunk)

## Future Implementation
A complete COFF loader requires:
 - Parsing COFF/PE headers and sections
 - Resolving relocations and fixing addresses
 - Resolving imports from Beacon API or Windows APIs
 - Executing the `go()` function entry point
 - Handling BOF output via callback functions
 - Memory management for in-memory execution

## OPSEC Considerations
 - **Detection Risk: LOW-MEDIUM (once fully implemented)**
 - BOF execution advantages over traditional methods:
   - No new process creation (executes in-process)
   - No DLL loads that appear in PEB
   - Smaller file sizes than full assemblies
   - Position-independent code is harder to signature
   - Direct syscalls can be used within BOFs
 - Detection challenges for defenders:
   - Memory-only execution with no disk artifacts
   - No ETW events for process creation
   - Minimal API calls from agent process
 - Potential detection vectors:
   - Memory scanning may detect loaded COFF objects
   - API call patterns from the BOF may be suspicious
   - Network traffic for BOF download
   - Behavioral detection of in-process code execution
 - Best practices when implemented:
   - Use BOFs for sensitive operations instead of assemblies
   - Combine with AMSI/ETW patching for defense-in-depth
   - Ensure BOFs use direct syscalls where possible
   - Avoid using public/known BOFs without modification

## Advanced BOF Usage
 - BOFs are ideal for:
   - Credential dumping (e.g., Mimikatz BOF)
   - Network enumeration
   - Registry manipulation
   - Token manipulation
   - Any operation that benefits from in-process execution
 - BOFs can call back to the agent via Beacon API functions
 - Custom BOFs can be compiled from C code using mingw or MSVC

## MITRE ATT&CK Mapping
 - T1106: Native API
