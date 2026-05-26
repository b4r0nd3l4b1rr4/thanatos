+++
title = "keylogger_start"
chapter = false
weight = 210
hidden = true
+++

## Description
Start a keylogger in a background thread to capture keystrokes.

Windows only. This is a placeholder implementation in v1.

## Usage
```
keylogger_start
```

### Examples
```
keylogger_start
```

### Notes
- Full implementation would use `SetWindowsHookEx` to install a keyboard hook
- Current version registers the job but does not capture keystrokes
- Use `keylogger_stop` to stop the keylogger and retrieve captured keys

## MITRE ATT&CK Mapping
- T1056.001
