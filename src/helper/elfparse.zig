const std = @import("std");
const ELF = @import("elf.zig");
const elfHelper = @import("helpers.zig");

const e = std.log.err;
const print = std.debug.print;

pub fn parseElf(data: []const u8) !void {
    if (data.len < 16 or !std.mem.eql(u8, data[0..4], &ELF.ELFMAG)) {
        e("[ERROR] Not valid ELF file!", .{});
        return;
    }

    const class = data[4];
    if (class == ELF.ELFCLASS32) {
        // TODO: 32bit parse...
        // std.log.info("class 1 32 bit", .{});
        try elfParser(ELF.Elf32Header, ELF.Elf32ProgramHeader, ELF.Elf32SectionHeader, data);
    } else if (class == ELF.ELFCLASS64) {
        // TODO: 64bit parse...
        // std.log.info("class 2 64bit", .{});
        try elfParser(ELF.Elf64Header, ELF.Elf64ProgramHeader, ELF.Elf64SectionHeader, data);
    } else {
        e("[ERROR] Unknown ELF class {d}", .{class});
    }
}

pub fn elfParser(comptime header: type, comptime programHeader: type, comptime sectionHeader: type, data: []const u8) !void {
    if (data.len < @sizeOf(ELF.Elf32Header)) {
        e("[ERROR] so small for ELF32\n", .{});
        return;
    }

    const hdr = std.mem.bytesAsValue(header, data[0..@sizeOf(header)]);
    print("\n", .{});
    print("{s:<12}: {s}\n", .{ "CLASS", if (header == ELF.Elf32Header) "ELF32" else "ELF64" });
    print("{s:<12}: {s}\n", .{ "DATA", if (data[5] == 1) "LittleEndian" else "BigEndian" });
    print("{s:<12}: {s}\n", .{ "TYPE", elfHelper.elfTypeName(hdr.e_type) });
    print("{s:<12}: .{s}\n", .{ "MACHINE", elfHelper.elfMachineName(hdr.e_machine) });
    print("{s:<12}: 0x{X:0>8}\n", .{ "Entry", hdr.e_entry });
    print("{s:<12}: 0x{X} ({d} entries x {d} bytes)\n", .{ "P_OFFSET", hdr.e_phoff, hdr.e_phnum, hdr.e_phentsize });
    print("{s:<12}: 0x{X} ({d} entries x {d} bytes)\n", .{ "S_OFFSET", hdr.e_shoff, hdr.e_shnum, hdr.e_shentsize });
    print("{s:<12}: 0x{X}\n", .{ "FLAGS", hdr.e_flags });

    // Program Header
    print("\nPROGRAM HEADER", .{});
    print("\n\n  {s:<14} {s:<4} {s:<19} {s:<19} {s:<13} {s:<14}\n", .{ "Type", "Flg", "VAddr", "PAddr", "FileSize", "MemSize" });
    print("  {s}\n", .{"-" ** 86});

    for (0..hdr.e_phnum) |index| {
        //print("{d} {X}\n", .{ index, @as(usize, hdr.e_phoff) + @as(usize, index) * hdr.e_phentsize });
        const p_off = @as(usize, hdr.*.e_phoff) + @as(usize, index) * hdr.e_phentsize;
        if (p_off + @sizeOf(programHeader) > data.len) break;
        //print("{X}\n", .{off});
        const ph = std.mem.bytesAsValue(programHeader, data[p_off..][0..@sizeOf(programHeader)]);
        const flags = elfHelper.segmentFlags(ph.p_flags);
        //print("{s}\n", .{flags});
        print("  {s:<14} {s}  0x{X:0>16}  0x{X:0>16}  0x{X:0>10}  0x{X:0>10}\n", .{
            elfHelper.segmentTypeName(ph.p_type),
            flags, // what ı thougt...
            ph.p_vaddr,
            ph.p_paddr,
            ph.p_filesz,
            ph.p_memsz,
        });
    }
    print("\n", .{});

    print("SECTION HEADER", .{});
    print("\n\n  {s:<4} {s:<20} {s:<12} {s:<18} {s:<12} {s:<12} {s:<8}\n", .{
        "Nr", "Name", "Type", "Address", "Offset", "Size", "Align",
    });
    print("  {s}\n", .{"-" ** 94});

    for (0..hdr.e_shnum) |index| {
        //print("{d} {X}\n", .{ index, @as(usize, hdr.e_phoff) + @as(usize, index) * hdr.e_shentsize });
        const s_off = @as(usize, hdr.e_shoff) + @as(usize, index) * hdr.e_shentsize;
        if (s_off + @sizeOf(sectionHeader) > data.len) break;
        const sh = std.mem.bytesAsValue(sectionHeader, data[s_off..][0..@sizeOf(sectionHeader)]);

        const name = "---";
        print(
            "  {d:<4} {s:<20} {s:<12} 0x{X:0>16}  0x{X:0>8}  0x{X:0>8}   {d:<8}\n",
            .{
                index,
                name,
                elfHelper.sectionType(sh.sh_type),
                sh.sh_addr,
                sh.sh_offset,
                sh.sh_size,
                sh.sh_addralign,
            },
        );
    }
}
