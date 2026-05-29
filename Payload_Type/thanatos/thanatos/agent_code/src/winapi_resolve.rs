#[cfg(target_os = "windows")]
pub unsafe fn resolve(dll: &str, func: &str) -> Option<*mut std::ffi::c_void> {
    use dinvoke_rs::dinvoke;

    let module_base = dinvoke::get_module_base_address(dll);
    if module_base == 0 {
        #[repr(C)]
        struct UnicodeString {
            length: u16,
            maximum_length: u16,
            buffer: *const u16,
        }
        type LdrLoadDllFn = unsafe extern "system" fn(*const u16, *mut u32, *const UnicodeString, *mut usize) -> i32;

        let ntdll_base = dinvoke::get_module_base_address(&crate::obfstr::d(crate::obfstr::IOC_NTDLL));
        if ntdll_base == 0 { return None; }
        let ldr_addr = dinvoke::get_function_address(ntdll_base, &crate::obfstr::d(crate::obfstr::IOC_LDRLOADDLL));
        if ldr_addr == 0 { return None; }

        let wide: Vec<u16> = dll.encode_utf16().chain(std::iter::once(0)).collect();
        let us = UnicodeString {
            length: ((wide.len() - 1) * 2) as u16,
            maximum_length: (wide.len() * 2) as u16,
            buffer: wide.as_ptr(),
        };
        let mut handle: usize = 0;
        let ldr: LdrLoadDllFn = std::mem::transmute(ldr_addr);
        if ldr(std::ptr::null(), std::ptr::null_mut(), &us, &mut handle) != 0 {
            return None;
        }

        let addr = dinvoke::get_function_address(handle, func);
        if addr == 0 { None } else { Some(addr as *mut std::ffi::c_void) }
    } else {
        let addr = dinvoke::get_function_address(module_base, func);
        if addr == 0 { None } else { Some(addr as *mut std::ffi::c_void) }
    }
}
