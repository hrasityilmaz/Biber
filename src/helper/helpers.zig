const std = @import("std");
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
