const std = @import("std");
const Io = std.Io;
const ELF = @import("elf.zig");

const e = std.log.err;

pub fn elfTypeName(t: u16) []const u8 {
    return switch (t) {
        ELF.ET_NONE => "ET_NONE",
        ELF.ET_REL => "ET_REL (relocatable)",
        ELF.ET_EXEC => "ET_EXEC (executable)",
        ELF.ET_DYN => "ET_DYN (shared object -- dynamic --)",
        ELF.ET_CORE => "ET_CORE (core object)",
        else => "unknown",
    };
}

pub fn elfMachineName(m: u16) []const u8 {
    return switch (m) {
        ELF.EM_X86_64 => "x86_64",
        ELF.EM_386 => "i386",
        ELF.EM_AARCH64 => "AArch64",
        ELF.EM_RISCV => "RISC-V",
        ELF.EM_ARM => "ARM",
        else => "unknown",
    };
}

pub fn sectionType(t: u32) []const u8 {
    return switch (t) {
        ELF.SHT_NULL => "NULL",
        ELF.SHT_PROGBITS => "PROGBITS",
        ELF.SHT_SYMTAB => "SYMTAB",
        ELF.SHT_STRTAB => "STRTAB",
        ELF.SHT_RELA => "RELA",
        ELF.SHT_NOBITS => "NOBITS",
        ELF.SHT_REL => "REL",
        else => "unknown",
    };
}

pub fn segmentTypeName(t: u32) []const u8 {
    return switch (t) {
        ELF.PT_NULL => "NULL",
        ELF.PT_LOAD => "LOAD",
        ELF.PT_DYNAMIC => "DYNAMIC",
        ELF.PT_INTERP => "INTERP",
        ELF.PT_NOTE => "NOTE",
        ELF.PT_PHDR => "PHDR",
        ELF.PT_GNU_EH_FRAME => "GNU_EH_FRAME",
        ELF.PT_GNU_STACK => "GNU_STACK",
        ELF.PT_GNU_RELRO => "GNU_RELRO",
        ELF.PT_GNU_PROPERTY => "GNU_PROPERTY",
        ELF.PT_GNU_SFRAME => "GNU_SFRAME",
        ELF.PT_TLS => "TLS",
        ELF.PT_LOSUW => "LOSUW",
        else => "unknown",
    };
}

pub fn segmentFlags(flags: u32) [3]u8 {
    return .{
        if (flags & 4 != 0) 'R' else '-',
        if (flags & 2 != 0) 'W' else '-',
        if (flags & 1 != 0) 'X' else '-',
    };
}

pub fn sectionFlags(flags: u64) [8]u8 {
    var buf = [_]u8{' '} ** 8;
    var i: usize = 0;
    if (flags & 0x1 != 0) {
        buf[i] = 'W';
        i += 1;
    }
    if (flags & 0x2 != 0) {
        buf[i] = 'A';
        i += 1;
    }
    if (flags & 0x4 != 0) {
        buf[i] = 'X';
        i += 1;
    }
    if (flags & 0x10 != 0) {
        buf[i] = 'M';
        i += 1;
    }
    if (flags & 0x20 != 0) {
        buf[i] = 'S';
        i += 1;
    }
    if (flags & 0x40 != 0) {
        buf[i] = 'I';
        i += 1;
    }
    if (flags & 0x80 != 0) {
        buf[i] = 'L';
        i += 1;
    }
    return buf;
}

pub fn symTypeName(t: u8) []const u8 {
    return switch (t) {
        0 => "NOTYPE",
        1 => "OBJECT",
        2 => "FUNC",
        3 => "SECTION",
        4 => "FILE",
        5 => "COMMON",
        6 => "TLS",
        else => "UNKNOWN",
    };
}

pub fn symBindName(b: u8) []const u8 {
    return switch (b) {
        0 => "LOCAL",
        1 => "GLOBAL",
        2 => "WEAK",
        else => "UNKNOWN",
    };
}

pub fn noteTypeName(owner: []const u8, ntype: u32) []const u8 {
    if (std.mem.eql(u8, owner, "GNU")) {
        return switch (ntype) {
            1 => "ABI_TAG",
            2 => "HWCAP",
            3 => "BUILD_ID",
            4 => "GOLD_VERSION",
            5 => "PROPERTY",
            else => "UNKNOWN",
        };
    }
    if (std.mem.eql(u8, owner, "CORE")) {
        return switch (ntype) {
            1 => "PRSTATUS",
            3 => "PRPSINFO",
            else => "UNKNOWN",
        };
    }
    return "UNKNOWN";
}

pub fn formatNoteData(owner: []const u8, ntype: u32, desc: []const u8, buf: []u8) []const u8 {
    if (std.mem.eql(u8, owner, "GNU") and ntype == 3) {
        var pos: usize = 0;
        for (desc) |b| {
            const s = std.fmt.bufPrint(buf[pos..], "{x:0>2}", .{b}) catch break;
            pos += s.len;
        }
        return buf[0..pos];
    }
    if (std.mem.eql(u8, owner, "GNU") and ntype == 1 and desc.len >= 16) {
        const os = std.mem.readInt(u32, desc[0..4], .little);
        const maj = std.mem.readInt(u32, desc[4..8], .little);
        const min = std.mem.readInt(u32, desc[8..12], .little);
        const sub = std.mem.readInt(u32, desc[12..16], .little);
        return std.fmt.bufPrint(buf, "{s} {d}.{d}.{d}", .{ os_name(os), maj, min, sub }) catch "?";
    }
    var pos: usize = 0;
    const limit = @min(desc.len, 16);
    for (desc[0..limit]) |b| {
        const s = std.fmt.bufPrint(buf[pos..], "{x:0>2} ", .{b}) catch break;
        pos += s.len;
    }
    if (desc.len > 16) {
        const s = std.fmt.bufPrint(buf[pos..], "...", .{}) catch return buf[0..pos];
        pos += s.len;
    }
    return buf[0..pos];
}

pub fn relaTypeName(t: u32) []const u8 {
    return switch (t) {
        0 => "R_NONE",
        1 => "R_64",
        2 => "R_PC32",
        5 => "R_COPY",
        6 => "R_GLOB_DAT",
        7 => "R_JUMP_SLOT",
        8 => "R_RELATIVE",
        10 => "R_32",
        else => "UNKNOWN",
    };
}

fn os_name(os: u32) []const u8 {
    return switch (os) {
        0 => "Linux",
        1 => "GNU/Hurd",
        2 => "Solaris",
        3 => "FreeBSD",
        else => "Unknown",
    };
}

pub fn dynTagName(tag: i64) []const u8 {
    return switch (tag) {
        1 => "DT_NEEDED",
        2 => "DT_PLTRELSZ",
        3 => "DT_PLTGOT",
        4 => "DT_HASH",
        5 => "DT_STRTAB",
        6 => "DT_SYMTAB",
        7 => "DT_RELA",
        8 => "DT_RELASZ",
        9 => "DT_RELAENT",
        10 => "DT_STRSZ",
        11 => "DT_SYMENT",
        12 => "DT_INIT",
        13 => "DT_FINI",
        14 => "DT_SONAME",
        15 => "DT_RPATH",
        20 => "DT_PLTREL",
        21 => "DT_DEBUG",
        23 => "DT_JMPREL",
        25 => "DT_INIT_ARRAY",
        26 => "DT_FINI_ARRAY",
        27 => "DT_INIT_ARRAYSZ",
        28 => "DT_FINI_ARRAYSZ",
        29 => "DT_RUNPATH",
        else => "UNKNOWN",
    };
}
