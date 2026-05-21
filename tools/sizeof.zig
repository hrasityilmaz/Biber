const std = @import("std");
const structs = @import("elf");

const print = std.debug.print;

pub fn main() void {
    print(
        \\Size of ELF32Header {d}
        \\Size of ELF64Header {d}
        \\Size of Elf32 Program Header {d} 
        \\Size of Elf32SectionHeader {d}
    , .{
        @sizeOf(structs.Elf32Header),
        @sizeOf(structs.Elf64Header),
        @sizeOf(structs.Elf32ProgramHeader),
        @sizeOf(structs.Elf32SectionHeader),
    });
}
