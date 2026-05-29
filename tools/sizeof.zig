const std = @import("std");
const linstructs = @import("elf");
const winstructs = @import("win");

const print = std.debug.print;

fn printStructLayout(comptime T: type) void {
    print("\n{s}\n", .{@typeName(T)});
    print("SIZE  : {d} bytes\n", .{@sizeOf(T)});
    print("ALIGN : {d}\n", .{@alignOf(T)});
    print("-----------------------------\n", .{});

    inline for (@typeInfo(T).@"struct".fields) |field| {
        std.debug.print("{s:<16} offset=0x{X:<4} size={d}\n", .{
            field.name,
            @offsetOf(T, field.name),
            @sizeOf(field.type),
        });
    }
}
pub fn main() void {
    // LIN
    printStructLayout(linstructs.Elf32Header);
    printStructLayout(linstructs.Elf64Header);
    printStructLayout(linstructs.Elf32ProgramHeader);
    printStructLayout(linstructs.Elf32SectionHeader);
    printStructLayout(linstructs.Elf64ProgramHeader);
    printStructLayout(linstructs.Elf64SectionHeader);
    // WIN
    printStructLayout(winstructs.DosHeader);
    printStructLayout(winstructs.PeFileHeader);
    printStructLayout(winstructs.PeOptionalHeader32);
    printStructLayout(winstructs.PeOptionalHeader64);
    printStructLayout(winstructs.PeSectionHeader);
}
