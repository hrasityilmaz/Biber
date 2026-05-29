const win = @import("win.zig");

pub fn machineName(m: u16) []const u8 {
    return switch (m) {
        win.IMAGE_FILE_MACHINE_I386 => "x86",
        win.IMAGE_FILE_MACHINE_AMD64 => "x86-64",
        win.IMAGE_FILE_MACHINE_ARM64 => "ARM64",
        win.IMAGE_FILE_MACHINE_ARM => "ARM",
        else => "Unknown",
    };
}

pub fn subsystemName(s: u16) []const u8 {
    return switch (s) {
        1 => "Native",
        2 => "Windows GUI",
        3 => "Windows CUI",
        9 => "WinCE GUI",
        10 => "EFI Application",
        14 => "Xbox",
        16 => "Boot Application",
        else => "Unknown",
    };
}

pub fn sectionFlags(ch: u32) [4]u8 {
    var buf = [_]u8{ '-', '-', '-', '-' };
    if (ch & win.IMAGE_SCN_MEM_READ != 0) buf[0] = 'R';
    if (ch & win.IMAGE_SCN_MEM_WRITE != 0) buf[1] = 'W';
    if (ch & win.IMAGE_SCN_MEM_EXECUTE != 0) buf[2] = 'X';
    if (ch & win.IMAGE_SCN_CNT_CODE != 0) buf[3] = 'C';
    return buf;
}

pub fn rvaToOffset(rva: u32, sections: []const win.PeSectionHeader) ?u32 {
    // RVA - VirtAddr + RawOffset
    for (sections) |s| {
        if (rva >= s.virtual_address and rva < s.virtual_address + s.virtual_size) {
            return s.pointer_to_raw_data + (rva - s.virtual_address);
        }
    }
    return null;
}

pub const ResType = enum(u32) {
    Cursor = 1,
    Bitmap = 2,
    Icon = 3,
    Menu = 4,
    Dialog = 5,
    String = 6,
    FontDir = 7,
    Font = 8,
    Accelerator = 9,
    RcData = 10,
    MessageTable = 11,
    GroupCursor = 12,
    GroupIcon = 14,
    Version = 16,
    DlgInclude = 17,
    PlugPlay = 19,
    Vxd = 20,
    AniCursor = 21,
    AniIcon = 22,
    Html = 23,
    Manifest = 24,
    _,
};

pub fn debugTypeName(t: u32) []const u8 {
    return switch (t) {
        win.IMAGE_DEBUG_TYPE_UNKNOWN => "UNKNOWN",
        win.IMAGE_DEBUG_TYPE_COFF => "COFF",
        win.IMAGE_DEBUG_TYPE_CODEVIEW => "CODEVIEW",
        win.IMAGE_DEBUG_TYPE_FPO => "FPO",
        win.IMAGE_DEBUG_TYPE_MISC => "MISC",
        win.IMAGE_DEBUG_TYPE_EXCEPTION => "EXCEPTION",
        win.IMAGE_DEBUG_TYPE_FIXUP => "FIXUP",
        win.IMAGE_DEBUG_TYPE_OMAP_TO_SRC => "OMAP_TO_SRC",
        win.IMAGE_DEBUG_TYPE_OMAP_FROM_SRC => "OMAP_FROM_SRC",
        win.IMAGE_DEBUG_TYPE_BORLAND => "BORLAND",
        win.IMAGE_DEBUG_TYPE_RESERVED10 => "RESERVED10",
        win.IMAGE_DEBUG_TYPE_CLSID => "CLSID",
        win.IMAGE_DEBUG_TYPE_VC_FEATURE => "VC_FEATURE",
        win.IMAGE_DEBUG_TYPE_POGO => "POGO",
        win.IMAGE_DEBUG_TYPE_ILTCG => "ILTCG",
        win.IMAGE_DEBUG_TYPE_MPX => "MPX",
        win.IMAGE_DEBUG_TYPE_REPRO => "REPRO",
        win.IMAGE_DEBUG_TYPE_EMBPDB => "EMBPDB",
        else => "?",
    };
}

pub fn resTypeName(id: u32) []const u8 {
    return switch (@as(ResType, @enumFromInt(id))) {
        .Cursor => "CURSOR",
        .Bitmap => "BITMAP",
        .Icon => "ICON",
        .Menu => "MENU",
        .Dialog => "DIALOG",
        .String => "STRING",
        .FontDir => "FONTDIR",
        .Font => "FONT",
        .Accelerator => "ACCELERATOR",
        .RcData => "RCDATA",
        .MessageTable => "MESSAGETABLE",
        .GroupCursor => "GROUP_CURSOR",
        .GroupIcon => "GROUP_ICON",
        .Version => "VERSION",
        .DlgInclude => "DLGINCLUDE",
        .PlugPlay => "PLUGPLAY",
        .Vxd => "VXD",
        .AniCursor => "ANICURSOR",
        .AniIcon => "ANIICON",
        .Html => "HTML",
        .Manifest => "MANIFEST",
        _ => "UNKNOWN",
    };
}
