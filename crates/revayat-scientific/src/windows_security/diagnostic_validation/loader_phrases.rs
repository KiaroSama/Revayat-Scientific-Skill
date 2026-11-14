//! Exact allowlisted phrase ordering from LoaderSnaps.cs:213–255.
pub const PHRASES: [(&str, &str); 31] = [
    ("manifest_probe", "Probing for the manifest of DLL "),
    (
        "active_actctx",
        "Querying the active activation context failed with status ",
    ),
    ("sxs_registry", "SXS: Unable to open registry key "),
    (
        "sxs_storage_subkey",
        "SXS: Unable to open storage root subkey ",
    ),
    (
        "sxs_storage_map",
        "SXS: RtlGetAssemblyStorageRoot() unable to resolve storage map entry.",
    ),
    (
        "current_directory",
        "Initializing the current directory to ",
    ),
    (
        "kernel32_init",
        "Calling LdrpInitializeKernel32Functions failed with status ",
    ),
    ("code_authz", "LdrpCodeAuthzInitialize failed with status "),
    (
        "mrdata_init",
        "LDR:MRDATA: Process initialization failed with status ",
    ),
    ("process_init", "Process initialization failed with status "),
    (
        "known_dll_link",
        "Querying the known DLL directory link object failed with status ",
    ),
    (
        "import_walk",
        "Walking the import tables of the executable and its static imports failed with status ",
    ),
    ("import_init", "Running the init routines of the executable"),
    ("tls_init", "Initializing TLS slots failed with status "),
    (
        "kernelbase_postinit",
        "Calling KernelbasePostInit failed with status ",
    ),
    (
        "sxs_storage_location",
        "SXS: Attempt to get storage location from subkey ",
    ),
    (
        "sxs_storage_insert",
        "SXS: Storage resolution failed to insert entry to storage map; Status = ",
    ),
    (
        "sxs_known_root",
        "SXS: Attempt to probe known root of assembly storage (",
    ),
    ("dll_load", "Unable to load DLL: "),
    (
        "sxs_storage_resolve",
        "SXS: Unable to resolve storage root for assembly directory ",
    ),
    ("sxs_streams", "BasepSxsCreateStreams() failed"),
    ("sxs_file_info", "NtQueryInformationFile failed. Status = "),
    ("sxs_resource_w", "BaseDllMapResourceIdW failed"),
    (
        "sxs_create_context",
        "SXS: RtlCreateActivationContext() failed ",
    ),
    ("sxs_create_section", "NtCreateSection() failed. Status = "),
    ("sxs_map_section", "NtMapViewOfSection failed"),
    ("sxs_csr_server", "Calling csrss server failed. Status = "),
    (
        "sxs_active_context",
        "Failure getting active activation context; ntstatus ",
    ),
    ("sxs_resource_a", "BaseDllMapResourceIdA failed"),
    (
        "sxs_csr_capture",
        "CsrCaptureMessageMultiUnicodeStringsInPlace failed",
    ),
    (
        "sxs_resource_flag",
        "ACTCTX_FLAG_RESOURCE_NAME_VALID set but lpResourceName == 0",
    ),
];
pub fn phrase_presence(text: &str) -> String {
    let ids = PHRASES
        .iter()
        .filter(|(_, phrase)| text.contains(phrase))
        .map(|(id, _)| *id)
        .collect::<Vec<_>>();
    if ids.is_empty() {
        String::new()
    } else {
        format!(
            " diagnostic_phrase_ids={} phrase_presence_only=True",
            ids.join(",")
        )
    }
}
