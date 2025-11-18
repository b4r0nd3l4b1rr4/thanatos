# shinject

Execute shellcode in the current process using a separate thread.

## Syntax

```
shinject [popup]
```

## Description

The `shinject` command allows you to execute shellcode in the current agent process using a separate background thread. This command is Windows-only and uses in-process execution rather than remote process injection.

### Features

- **In-Process Execution**: Shellcode runs in the current agent process, not in a remote process
- **Background Thread**: Executes shellcode in a separate thread to prevent blocking the agent
- **File Upload Support**: Upload shellcode files through Mythic's file transfer system
- **Base64 Fallback**: If file upload fails, uses a fallback calc.exe shellcode
- **Agent Stability**: Agent continues running normally even if shellcode calls `ExitProcess()`

### How It Works

1. User uploads a shellcode file through Mythic's interface
2. The Python backend retrieves the file from Mythic using RPC
3. The agent receives the shellcode file ID
4. The agent allocates executable memory using `VirtualAlloc` with `PAGE_EXECUTE_READWRITE` permissions
5. The agent copies the shellcode into the allocated memory
6. The agent spawns a new thread using `CreateThread` to execute the shellcode
7. The agent returns immediately without waiting for shellcode completion
8. The shellcode executes in the background thread

### Technical Details

#### Windows APIs Used

- `VirtualAlloc`: Allocates executable memory for the shellcode
- `VirtualFree`: Cleans up allocated memory (currently keeps it allocated for long-running shellcode)
- `CreateThread`: Spawns a new thread to execute the shellcode
- `GetExitCodeThread`: Retrieves the exit code of the thread
- `WaitForSingleObject`: Waits for thread completion with a 1-second timeout
- `CloseHandle`: Closes the thread handle

#### Memory Protection

The shellcode is allocated with `PAGE_EXECUTE_READWRITE` protection, allowing it to be executed directly. This is standard for in-process shellcode execution.

#### Thread Management

The agent uses `CreateThread` to execute the shellcode in a background thread. This approach:
- Prevents the agent from blocking while shellcode executes
- Allows the agent to return control to Mythic immediately
- Enables long-running shellcode operations without hanging the agent

### Parameters

When invoked through the Mythic UI, the command accepts:
- **shellcode**: File upload containing the shellcode to execute
- **shellcode-file-id**: (Internal) The Mythic file ID of the uploaded shellcode
- **shellcode-base64**: (Fallback) Base64-encoded shellcode if file upload fails

### Examples

#### Basic Usage

```bash
# In Mythic UI, select shinject command and upload a shellcode file
```

#### Fallback Behavior

If no file is provided or file upload fails, the command uses a fallback calc.exe shellcode that opens Calculator:

```bash
# Fallback shellcode is automatically used
shinject
```

### Error Handling

- **Memory Allocation Failures**: Returns detailed error messages including GetLastError codes
- **Thread Creation Failures**: Returns error messages with troubleshooting tips
- **File Not Found**: Falls back to using the built-in calc.exe shellcode

### Security Considerations

- **In-Process Execution**: The shellcode runs in the agent process, which may be detectable by EDR solutions
- **Memory Protection**: Uses executable memory pages which may be flagged by security solutions
- **Thread Injection**: Creates threads which may be monitored by security tools
- **No Process Hollowing**: Current implementation does not use process hollowing or more advanced techniques

### OPSEC Notes

- The agent marks uploaded shellcode files with `delete_after_fetch=True` for OPSEC
- The file is automatically removed from the agent after being downloaded
- Uses Apollo-style file handling for consistent behavior with other Thanatos commands

### Requirements

- **Operating System**: Windows only
- **Privileges**: No special privileges required for in-process execution
- **Dependencies**: None

### Browser Script

This command does not have a custom browser script. Responses are displayed as plain text in the Mythic UI.

### Limitations

1. **Single Process Execution**: Only executes in the current process, not remote processes
2. **No Process Injection**: Does not support injecting into other processes
3. **Limited Stealth**: In-process execution is more detectable than advanced techniques
4. **Platform Restriction**: Windows-only command

### Future Enhancements

Potential future improvements:
- Remote process injection support
- Process hollowing
- More advanced evasion techniques
- Cross-platform support (Linux/Unix)

### See Also

- [screenshot](./screenshot.md) - Take desktop screenshots
- [clipboard](./clipboard.md) - Access clipboard contents
- [askcreds](./askcreds.md) - Prompt for credentials
- [socks](./socks.md) - SOCKS5 proxy functionality

