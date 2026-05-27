// Dynamic Windows API resolution — removes high-risk imports from IAT
// Only LoadLibraryA and GetProcAddress appear in the import table

#[cfg(target_os = "windows")]
use std::ffi::CString;

#[cfg(target_os = "windows")]
use winapi::um::libloaderapi::{LoadLibraryA, GetProcAddress};

#[cfg(target_os = "windows")]
pub unsafe fn resolve(dll: &str, func: &str) -> Option<*mut std::ffi::c_void> {
    let dll_c = CString::new(dll).ok()?;
    let func_c = CString::new(func).ok()?;
    let module = LoadLibraryA(dll_c.as_ptr());
    if module.is_null() { return None; }
    let addr = GetProcAddress(module, func_c.as_ptr());
    if addr.is_null() { return None; }
    Some(addr as *mut std::ffi::c_void)
}

/// Macro to resolve and call a Windows API function dynamically
/// Usage: resolve_api!("kernel32.dll", "VirtualAlloc", fn(LPVOID, usize, u32, u32) -> LPVOID)
#[cfg(target_os = "windows")]
#[macro_export]
macro_rules! resolve_api {
    ($dll:expr, $func:expr, $ty:ty) => {{
        let ptr = crate::winapi_resolve::resolve($dll, $func)
            .expect(concat!("Failed to resolve ", $func));
        std::mem::transmute::<_, $ty>(ptr)
    }};
}
