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
