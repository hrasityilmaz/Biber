// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
//
// https://gist.github.com/JamesMenetrey/d3f494262bcab48af1d617c3d39f34cf
pub const DosHeader = extern struct {
    e_magic: u16,
    e_cblp: u16,
    e_cp: u16,
    e_crlc: u16,
    e_cparhdr: u16,
    e_minalloc: u16,
    e_maxalloc: u16,
    e_ss: u16,
    e_sp: u16,
    e_csum: u16,
    e_ip: u16,
    e_cs: u16,
    e_lfarlc: u16,
    e_ovno: u16,
    e_res: [4]u16,
    e_oemid: u16,
    e_oeminfo: u16,
    e_res2: [10]u16,
    e_lfanew: u32,
};

// https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_file_header
pub const PeFileHeader = extern struct {
    machine: u16,
    number_of_sections: u16,
    time_date_stamp: u32,
    pointer_to_symbol_table: u32,
    number_of_symbols: u32,
    size_of_optional_header: u16,
    characteristics: u16,
};

// https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header32
pub const PeOptionalHeader32 = extern struct {
    magic: u16,
    major_linker_version: u8,
    minor_linker_version: u8,
    size_of_code: u32,
    size_of_initialized_data: u32,
    size_of_uninitialized_data: u32,
    address_of_entry_point: u32,
    base_of_code: u32,
    base_of_data: u32,
    image_base: u32,
    section_alignment: u32,
    file_alignment: u32,
    major_os_version: u16,
    minor_os_version: u16,
    major_image_version: u16,
    minor_image_version: u16,
    major_subsystem_version: u16,
    minor_subsystem_version: u16,
    win32_version_value: u32,
    size_of_image: u32,
    size_of_headers: u32,
    checksum: u32,
    subsystem: u16,
    dll_characteristics: u16,
    size_of_stack_reserve: u32,
    size_of_stack_commit: u32,
    size_of_heap_reserve: u32,
    size_of_heap_commit: u32,
    loader_flags: u32,
    number_of_rva_and_sizes: u32,
};

//https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header64
pub const PeOptionalHeader64 = extern struct {
    magic: u16,
    major_linker_version: u8,
    minor_linker_version: u8,
    size_of_code: u32,
    size_of_initialized_data: u32,
    size_of_uninitialized_data: u32,
    address_of_entry_point: u32,
    base_of_code: u32,
    image_base: u64,
    section_alignment: u32,
    file_alignment: u32,
    major_os_version: u16,
    minor_os_version: u16,
    major_image_version: u16,
    minor_image_version: u16,
    major_subsystem_version: u16,
    minor_subsystem_version: u16,
    win32_version_value: u32,
    size_of_image: u32,
    size_of_headers: u32,
    checksum: u32,
    subsystem: u16,
    dll_characteristics: u16,
    size_of_stack_reserve: u64,
    size_of_stack_commit: u64,
    size_of_heap_reserve: u64,
    size_of_heap_commit: u64,
    loader_flags: u32,
    number_of_rva_and_sizes: u32,
};

// https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_section_header
pub const PeSectionHeader = extern struct {
    name: [8]u8,
    virtual_size: u32,
    virtual_address: u32,
    size_of_raw_data: u32,
    pointer_to_raw_data: u32,
    pointer_to_relocations: u32,
    pointer_to_linenumbers: u32,
    number_of_relocations: u16,
    number_of_linenumbers: u16,
    characteristics: u32,
};

pub const IMAGE_FILE_MACHINE_I386: u16 = 0x014C;
pub const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
pub const IMAGE_FILE_MACHINE_ARM64: u16 = 0xAA64;
pub const IMAGE_FILE_MACHINE_ARM: u16 = 0x01C0;

pub const DOS_MAGIC: u16 = 0x5A4D; //MZ
pub const PE_MAGIC: u32 = 0x4550;
pub const OPT_PE32: u16 = 0x010B;
pub const OPT_PE64: u16 = 0x020B;

pub const ImageDebugDirectory = extern struct {
    characteristics: u32,
    time_date_stamp: u32,
    major_version: u16,
    minor_version: u16,
    type: u32,
    size_of_data: u32,
    address_of_raw_data: u32,
    pointer_to_raw_data: u32,
};

pub const ImageBaseRelocation = extern struct {
    virtual_address: u32,
    size_of_block: u32,
};

pub const ImageDataDirectory = extern struct {
    virtual_address: u32,
    size: u32,
};

pub const ImageExportDirectory = extern struct {
    characteristics: u32,
    time_date_stamp: u32,
    major_version: u16,
    minor_version: u16,
    name: u32,
    base: u32,
    number_of_functions: u32,
    number_of_names: u32,
    address_of_functions: u32,
    address_of_names: u32,
    address_of_name_ordinals: u32,
};

pub const ImageImportDescriptor = extern struct {
    original_first_thunk: u32,
    time_date_stamp: u32,
    forwarder_chain: u32,
    name: u32,
    first_thunk: u32,
};
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
pub const IMAGE_DEBUG_TYPE_UNKNOWN: u32 = 0;
pub const IMAGE_DEBUG_TYPE_COFF: u32 = 1;
pub const IMAGE_DEBUG_TYPE_CODEVIEW: u32 = 2;
pub const IMAGE_DEBUG_TYPE_FPO: u32 = 3;
pub const IMAGE_DEBUG_TYPE_MISC: u32 = 4;
pub const IMAGE_DEBUG_TYPE_EXCEPTION: u32 = 5;
pub const IMAGE_DEBUG_TYPE_FIXUP: u32 = 6;
pub const IMAGE_DEBUG_TYPE_OMAP_TO_SRC: u32 = 7;
pub const IMAGE_DEBUG_TYPE_OMAP_FROM_SRC: u32 = 8;
pub const IMAGE_DEBUG_TYPE_BORLAND: u32 = 9;
pub const IMAGE_DEBUG_TYPE_RESERVED10: u32 = 10;
pub const IMAGE_DEBUG_TYPE_CLSID: u32 = 11;
pub const IMAGE_DEBUG_TYPE_VC_FEATURE: u32 = 12;
pub const IMAGE_DEBUG_TYPE_POGO: u32 = 13;
pub const IMAGE_DEBUG_TYPE_ILTCG: u32 = 14;
pub const IMAGE_DEBUG_TYPE_MPX: u32 = 15;
pub const IMAGE_DEBUG_TYPE_REPRO: u32 = 16;
pub const IMAGE_DEBUG_TYPE_EMBPDB: u32 = 17;
pub const CV_SIGNATURE_RSDS: u32 = 0x53445352;

pub const IMAGE_DIRECTORY_ENTRY_EXPORT: u32 = 0;
pub const IMAGE_DIRECTORY_ENTRY_IMPORT: u32 = 1;
pub const IMAGE_DIRECTORY_ENTRY_RESOURCE: u32 = 2;
pub const IMAGE_DIRECTORY_ENTRY_BASERELOC: u32 = 5;
pub const IMAGE_DIRECTORY_ENTRY_DEBUG: u32 = 6;
pub const IMAGE_DIRECTORY_ENTRY_TLS: u32 = 9;
pub const IMAGE_DIRECTORY_ENTRY_IAT: u32 = 12;
pub const IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT: u32 = 13;
pub const IMAGE_NUMBER_OF_DIRECTORY_ENTRIES: u32 = 16;

pub const IMAGE_SCN_CNT_CODE: u32 = 0x00000020;
pub const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x00000040;
pub const IMAGE_SCN_CNT_UNINITIALIZED_DATA: u32 = 0x00000080;
pub const IMAGE_SCN_MEM_EXECUTE: u32 = 0x20000000;
pub const IMAGE_SCN_MEM_READ: u32 = 0x40000000;
pub const IMAGE_SCN_MEM_WRITE: u32 = 0x80000000;

pub const ImageRuntimeFunctionEntry = extern struct {
    begin_address: u32,
    end_address: u32,
    unwind_info_address: u32,
};

// Unwind info header
pub const UNW_FLAG_NHANDLER: u8 = 0x0;
pub const UNW_FLAG_EHANDLER: u8 = 0x1;
pub const UNW_FLAG_UHANDLER: u8 = 0x2;
pub const UNW_FLAG_CHAININFO: u8 = 0x4;

// Load Config (64-bit)
pub const ImageLoadConfigDirectory64 = extern struct {
    size: u32,
    time_date_stamp: u32,
    major_version: u16,
    minor_version: u16,
    global_flags_clear: u32,
    global_flags_set: u32,
    critical_section_default_timeout: u32,
    de_commit_free_block_threshold: u64,
    de_commit_total_free_threshold: u64,
    lock_prefix_table: u64,
    maximum_allocation_size: u64,
    virtual_memory_threshold: u64,
    process_affinity_mask: u64,
    process_heap_flags: u32,
    csd_version: u16,
    dependent_load_flags: u16,
    edit_list: u64,
    security_cookie: u64,
    se_handler_table: u64,
    se_handler_count: u64,
    guard_cf_check_function_pointer: u64,
    guard_cf_dispatch_function_pointer: u64,
    guard_cf_function_table: u64,
    guard_cf_function_count: u64,
    guard_flags: u32,
};

pub const IMAGE_GUARD_CF_INSTRUMENTED: u32 = 0x00000100;
pub const IMAGE_GUARD_CFW_INSTRUMENTED: u32 = 0x00000200;
pub const IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT: u32 = 0x00000400;
pub const IMAGE_GUARD_SECURITY_COOKIE_UNUSED: u32 = 0x00000800;
pub const IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT: u32 = 0x00004000;
pub const IMAGE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION: u32 = 0x00008000;
pub const IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT: u32 = 0x00010000;

// Load Config (32-bit)
pub const ImageLoadConfigDirectory32 = extern struct {
    size: u32,
    time_date_stamp: u32,
    major_version: u16,
    minor_version: u16,
    global_flags_clear: u32,
    global_flags_set: u32,
    critical_section_default_timeout: u32,
    de_commit_free_block_threshold: u32,
    de_commit_total_free_threshold: u32,
    lock_prefix_table: u32,
    maximum_allocation_size: u32,
    virtual_memory_threshold: u32,
    process_heap_flags: u32,
    process_affinity_mask: u32,
    csd_version: u16,
    dependent_load_flags: u16,
    edit_list: u32,
    security_cookie: u32,
    se_handler_table: u32,
    se_handler_count: u32,
    guard_cf_check_function_pointer: u32,
    guard_cf_dispatch_function_pointer: u32,
    guard_cf_function_table: u32,
    guard_cf_function_count: u32,
    guard_flags: u32,
};

pub const ImageBoundImportDescriptor = extern struct {
    time_date_stamp: u32,
    offset_module_name: u16,
    number_of_module_forwarder_refs: u16,
};

pub const ImageDataDirectorySecurity = extern struct {
    length: u32,
    revision: u16,
    certificate_type: u16,
};

pub const WIN_CERT_REVISION_1_0: u16 = 0x0100;
pub const WIN_CERT_REVISION_2_0: u16 = 0x0200;
pub const WIN_CERT_TYPE_X509: u16 = 0x0001;
pub const WIN_CERT_TYPE_PKCS_SIGNED_DATA: u16 = 0x0002;
pub const WIN_CERT_TYPE_TS_STACK_SIGNED: u16 = 0x0004;

pub const IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG: u32 = 10;
pub const IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT: u32 = 11;
pub const IMAGE_DIRECTORY_ENTRY_SECURITY: u32 = 4;
pub const IMAGE_DIRECTORY_ENTRY_EXCEPTION: u32 = 3;
