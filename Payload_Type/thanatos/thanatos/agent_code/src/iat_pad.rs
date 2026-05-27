// Import table padding — forces legitimate-looking imports into the IAT
// This makes the binary's import profile match a normal Windows application

#[cfg(target_os = "windows")]
use winapi::um::winuser::{GetDesktopWindow, IsWindow};
#[cfg(target_os = "windows")]
use winapi::um::synchapi::Sleep;
#[cfg(target_os = "windows")]
use winapi::um::processthreadsapi::GetCurrentProcessId;
#[cfg(target_os = "windows")]
use winapi::um::sysinfoapi::GetTickCount;
#[cfg(target_os = "windows")]
use winapi::um::errhandlingapi::SetLastError;

// Call these once during init to ensure the linker doesn't strip them
#[cfg(target_os = "windows")]
pub fn init_imports() {
    unsafe {
        let _ = GetDesktopWindow();
        let _ = GetCurrentProcessId();
        let _ = GetTickCount();
        let _ = IsWindow(std::ptr::null_mut());
        SetLastError(0);
        Sleep(0);
    }
}

#[cfg(not(target_os = "windows"))]
pub fn init_imports() {}
