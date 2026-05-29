use crate::utils::parse_linux_mode;
use serde::Serialize;
use serde_json::json;
use std::error::Error;
use std::path::Path;
use std::result::Result;

use super::{RemoteFileStat, SshSession};

#[derive(Serialize)]
struct File {
    is_file: bool,
    permissions: FilePermissions,
    name: String,
    full_name: String,
    access_time: u64,
    modify_time: u64,
    size: u64,
}

#[derive(Serialize)]
struct FilePermissions {
    uid: u32,
    gid: u32,
    permissions: String,
}

#[derive(Serialize)]
struct FileBrowser {
    host: String,
    platform: String,
    is_file: bool,
    permissions: FilePermissions,
    name: String,
    parent_path: String,
    success: bool,
    access_time: u64,
    modify_time: u64,
    size: u64,
    update_deleted: bool,
    files: Vec<File>,
}

impl FilePermissions {
    fn from_stat(stat: &RemoteFileStat) -> Self {
        Self {
            uid: stat.uid,
            gid: stat.gid,
            permissions: parse_linux_mode(stat.perm),
        }
    }
}

impl File {
    fn from_entry(path: &str, stat: &RemoteFileStat) -> Self {
        let p = Path::new(path);
        let name = p
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| path.to_string());
        let full_name = path_clean::clean(&p.to_string_lossy());

        Self {
            is_file: !stat.is_dir,
            permissions: FilePermissions::from_stat(stat),
            name,
            full_name,
            access_time: stat.atime * 1000,
            modify_time: stat.mtime * 1000,
            size: stat.size,
        }
    }
}

pub fn ssh_list(
    sess: &SshSession,
    path: &str,
    task_id: &str,
    host: String,
) -> Result<serde_json::Value, Box<dyn Error>> {
    let path_obj = Path::new(path);
    let mut name = path_obj
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "/".to_string());

    if name == "\\" {
        name = "/".to_string();
    }

    let parent_path = path_obj
        .parent()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();

    let path_stat = sess.sftp_stat(path)?;
    let entries = sess.sftp_readdir(path)?;

    let files: Vec<File> = entries
        .iter()
        .map(|(entry_path, stat)| File::from_entry(entry_path, stat))
        .collect();

    let file_browser = FileBrowser {
        host,
        platform: "ssh".to_string(),
        is_file: !path_stat.is_dir,
        permissions: FilePermissions::from_stat(&path_stat),
        name,
        parent_path,
        success: true,
        access_time: path_stat.atime * 1000,
        modify_time: path_stat.mtime * 1000,
        size: path_stat.size,
        update_deleted: true,
        files,
    };

    Ok(json!({
        "task_id": task_id,
        "file_browser": &file_browser,
        "status": "success",
        "completed": true,
        "user_output": serde_json::to_string(&file_browser)?,
    }))
}
