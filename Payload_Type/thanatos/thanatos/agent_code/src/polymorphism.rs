use memmap2::MmapOptions;
use object::{File, Object, ObjectSection};
use std::env;
use std::fs::{self, OpenOptions};

fn get_section(file: &File, name: &str) -> Option<(u64, u64)> {
    for section in file.sections() {
        match section.name() {
            Ok(n) if n == name => {
                return section.file_range();
            }
            _ => {}
        }
    }
    None
}

fn get_run_count() -> Option<u64> {
    let exe = env::current_exe().ok()?;
    let file = OpenOptions::new().read(true).write(true).open(&exe).ok()?;
    let buf = unsafe { MmapOptions::new().map_mut(&file) }.ok()?;
    let file = File::parse(&*buf).ok()?;
    match get_section(&file, ".rsrc") {
        Some(range) => {
            let section_size = range.1 as usize;
            let base = range.0 as usize;
            let base_buff = &buf[base..(base + section_size)];

            let resource_image_directory = &base_buff[..16];
            let named_entries = u16::from_le_bytes(resource_image_directory[12..14].try_into().unwrap());
            let id_entries = u16::from_le_bytes(resource_image_directory[14..].try_into().unwrap());
            let resource_entries = named_entries + id_entries;

            let mut actual_offset = 16;
            let mut section_contents = Vec::new();
            let mut max_offset = 0;
            for resouce in 0..resource_entries {
                let resource_entry_buffer = &base_buff[actual_offset..actual_offset + 8];
                let resource_type = u16::from_le_bytes(resource_entry_buffer[0..2].try_into().unwrap());
                let _name_is_string = u16::from_le_bytes(resource_entry_buffer[2..4].try_into().unwrap());
                let name_dir_offset = u16::from_le_bytes(resource_entry_buffer[4..6].try_into().unwrap()) as usize;

                let language_buffer = &base_buff[name_dir_offset..name_dir_offset + 24];
                let language_offset = u16::from_le_bytes(language_buffer[20..22].try_into().unwrap()) as usize;

                let language_buffer = &base_buff[language_offset..language_offset + 24];
                let data_entry_offset = u16::from_le_bytes(language_buffer[20..22].try_into().unwrap()) as usize;

                if data_entry_offset > max_offset {
                    max_offset = data_entry_offset;
                }

                let data_entry_buffer = &base_buff[data_entry_offset..data_entry_offset + 16];
                let file_entry_offset = u32::from_le_bytes(data_entry_buffer[0..4].try_into().unwrap()) as usize;
                let file_entry_size = u32::from_le_bytes(data_entry_buffer[4..8].try_into().unwrap()) as usize;

                section_contents.push((resouce, file_entry_offset, file_entry_size, resource_type));
                actual_offset += 8;
            }
            section_contents.sort_by(|a, b| (a.1).cmp(&b.1));
            let file_reposition = section_contents.get(0)?.1 - (max_offset + 16 + 8);
            for section in &section_contents {
                if section.3 == 3 {
                    let counter = &base_buff[section.1 - file_reposition + 256..section.1 - file_reposition + 264];
                    let counter = u64::from_le_bytes(counter.try_into().unwrap());
                    return Some(counter);
                }
            }

            None
        }
        None => None,
    }
}

fn edit_run_count(counter: u64) {
    let exe = match env::current_exe() {
        Ok(v) => v,
        Err(_) => return,
    };
    let tmp = exe.with_extension("tmp");
    if fs::copy(&exe, &tmp).is_err() {
        return;
    }
    let file = match OpenOptions::new().read(true).write(true).open(&tmp) {
        Ok(v) => v,
        Err(_) => return,
    };
    let mut buf = match unsafe { MmapOptions::new().map_mut(&file) } {
        Ok(v) => v,
        Err(_) => return,
    };
    let file = match File::parse(&*buf) {
        Ok(v) => v,
        Err(_) => return,
    };
    match get_section(&file, ".rsrc") {
        Some(range) => {
            let section_size = range.1 as usize;
            let base = range.0 as usize;
            let base_buff = &buf[base..(base + section_size)];

            let resource_image_directory = &base_buff[..16];
            let named_entries = u16::from_le_bytes(resource_image_directory[12..14].try_into().unwrap());
            let id_entries = u16::from_le_bytes(resource_image_directory[14..].try_into().unwrap());
            let resource_entries = named_entries + id_entries;

            let mut actual_offset = 16;
            let mut section_contents = Vec::new();
            let mut max_offset = 0;
            for resouce in 0..resource_entries {
                let resource_entry_buffer = &base_buff[actual_offset..actual_offset + 8];
                let resource_type = u16::from_le_bytes(resource_entry_buffer[0..2].try_into().unwrap());
                let _name_is_string = u16::from_le_bytes(resource_entry_buffer[2..4].try_into().unwrap());
                let name_dir_offset = u16::from_le_bytes(resource_entry_buffer[4..6].try_into().unwrap()) as usize;

                let language_buffer = &base_buff[name_dir_offset..name_dir_offset + 24];
                let language_offset = u16::from_le_bytes(language_buffer[20..22].try_into().unwrap()) as usize;

                let language_buffer = &base_buff[language_offset..language_offset + 24];
                let data_entry_offset = u16::from_le_bytes(language_buffer[20..22].try_into().unwrap()) as usize;

                if data_entry_offset > max_offset {
                    max_offset = data_entry_offset;
                }

                let data_entry_buffer = &base_buff[data_entry_offset..data_entry_offset + 16];
                let file_entry_offset = u32::from_le_bytes(data_entry_buffer[0..4].try_into().unwrap()) as usize;
                let file_entry_size = u32::from_le_bytes(data_entry_buffer[4..8].try_into().unwrap()) as usize;

                section_contents.push((resouce, file_entry_offset, file_entry_size, resource_type));
                actual_offset += 8;
            }
            section_contents.sort_by(|a, b| (a.1).cmp(&b.1));
            if let Some(first) = section_contents.get(0) {
                let file_reposition = first.1 - (max_offset + 16 + 8);
                for section in &section_contents {
                    if section.3 == 3 {
                        buf[(base + section.1 - file_reposition + 256)..(base + section.1 - file_reposition + 264)]
                            .copy_from_slice(&counter.to_ne_bytes());
                        return;
                    }
                }
            }
        }
        None => {}
    };
}

pub fn mutate_self() {
    if let Some(run_count) = get_run_count() {
        edit_run_count(run_count + 1);
        if let Ok(exe) = env::current_exe() {
            let tmp = exe.with_extension("tmp");
            if let Ok(perms) = fs::metadata(&exe).map(|m| m.permissions()) {
                let _ = fs::set_permissions(&tmp, perms);
                let _ = fs::rename(&tmp, &exe);
            }
        }
    }
}
