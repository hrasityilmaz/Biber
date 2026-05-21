const std = @import("std");
const structs = @import("elf");

const print = std.debug.print;

pub fn main() void {
    print(
        \\Size of ELF32Header {d}
        \\Size of ELF64Header {d}
        \\
    , .{
        @sizeOf(structs.Elf32Header),
        @sizeOf(structs.Elf64Header),
    });
}
