const std = @import("std");
const Io = std.Io;
const ELF = @import("elf.zig");
const elfHelper = @import("helpers.zig");
const options = @import("mainhelper.zig").Options;

const e = std.log.err;
const print = std.debug.print;

pub fn parseElf(data: []const u8, opt: options) !void {
    //print("{any}", .{opt});

    if (data.len < 16 or !std.mem.eql(u8, data[0..4], &ELF.ELFMAG)) {
        e("[ERROR] Not valid ELF file!", .{});
        return;
    }

    const class = data[4];
    if (class == ELF.ELFCLASS32) {
        // TODO: 32bit parse...
        // std.log.info("class 1 32 bit", .{});
        try elfParser(ELF.Elf32Header, ELF.Elf32ProgramHeader, ELF.Elf32SectionHeader, data, opt);
    } else if (class == ELF.ELFCLASS64) {
        // TODO: 64bit parse...
        // std.log.info("class 2 64bit", .{});
        try elfParser(ELF.Elf64Header, ELF.Elf64ProgramHeader, ELF.Elf64SectionHeader, data, opt);
    } else {
        e("[ERROR] Unknown ELF class {d}", .{class});
    }
}

pub fn elfParser(comptime header: type, comptime programHeader: type, comptime sectionHeader: type, data: []const u8, opt: options) !void {
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
        const p_off = @as(usize, hdr.*.e_phoff) + @as(usize, index) * hdr.*.e_phentsize; // Not sure why suggest not working hdr.*.  hdr.e_phent... can ve wrong!!!
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

    print("\nSECTION HEADER", .{});
    print("\n\n  {s:<4} {s:<20} {s:<12} {s:<18} {s:<10} {s:<10} {s:<6} {s:<6} {s:<6} {s:<8}\n", .{
        "Nr", "Name", "Type", "Address", "Offset", "Size", "Flg", "Lnk", "Info", "Align",
    });

    print("  {s}\n", .{"-" ** 106});

    //Shrtab
    const str_index = @as(usize, hdr.e_shstrndx);
    const str_off = @as(usize, hdr.*.e_shoff) + str_index * @as(usize, hdr.*.e_shentsize);
    const str_sh = std.mem.bytesAsValue(sectionHeader, data[str_off..][0..@sizeOf(sectionHeader)]);
    const shstrtab = data[@as(usize, str_sh.sh_offset)..][0..@as(usize, str_sh.sh_size)];

    for (0..hdr.e_shnum) |index| {
        //print("{d} {X}\n", .{ index, @as(usize, hdr.e_phoff) + @as(usize, index) * hdr.e_shentsize });
        const s_off = @as(usize, hdr.*.e_shoff) + @as(usize, index) * hdr.*.e_shentsize;
        if (s_off + @sizeOf(sectionHeader) > data.len) break;
        const sh = std.mem.bytesAsValue(sectionHeader, data[s_off..][0..@sizeOf(sectionHeader)]);
        //print("{any}", .{shstrtab});
        const name = std.mem.sliceTo(shstrtab[@as(usize, sh.sh_name)..], 0);
        const flags = elfHelper.sectionFlags(@as(u64, sh.sh_flags));
        print(
            "  {d:<4} {s:<20} {s:<12} 0x{X:0>16}  0x{X:0>6}  0x{X:0>6}  {s:<6} {d:<6} {d:<6} {d:<8}\n",
            .{
                index,
                name,
                elfHelper.sectionType(sh.sh_type),
                sh.sh_addr,
                sh.sh_offset,
                sh.sh_size,
                flags,
                sh.sh_link,
                sh.sh_info,
                sh.sh_addralign,
            },
        );
    }

    if (opt.all or opt.symbols) {
        try printSymbols(header, sectionHeader, data, shstrtab, ".symtab");
        try printSymbols(header, sectionHeader, data, shstrtab, ".dynsym");
    }

    if (opt.all or opt.elf_relocs) {
        try printRelocations(header, sectionHeader, data, shstrtab);
    }

    if (opt.all or opt.elf_notes) {
        try printNotes(header, sectionHeader, data, shstrtab);
    }

    if (opt.all or opt.elf_dynamic) {
        try printDynamic(header, sectionHeader, data, shstrtab);
        try printSysVHash(header, sectionHeader, data, shstrtab);
        try printGnuHash(header, sectionHeader, data, shstrtab);
    }

    //try printSymbols(header, sectionHeader, data, shstrtab, ".symtab");
    //try printSymbols(header, sectionHeader, data, shstrtab, ".dynsym");
    //try printRelocations(header, sectionHeader, data, shstrtab);
    //try printNotes(header, sectionHeader, data, shstrtab);
    //try printDynamic(header, sectionHeader, data, shstrtab);
    //try printSysVHash(header, sectionHeader, data, shstrtab);
    //try printGnuHash(header, sectionHeader, data, shstrtab);
}

fn printSymbols(
    comptime header: type,
    comptime sectionHeader: type,
    data: []const u8,
    shstrtab: []const u8,
    target_name: []const u8,
) !void {
    const hdr = std.mem.bytesAsValue(header, data[0..@sizeOf(header)]);
    var strtab_data: ?[]const u8 = null; //undefined;
    const strtab_name: []const u8 = if (std.mem.eql(u8, target_name, ".dynsym")) ".dynstr" else ".strtab";
    for (0..hdr.*.e_shnum) |i| {
        const offset = @as(usize, hdr.*.e_shoff) + i * hdr.*.e_shentsize;
        if (offset + @sizeOf(sectionHeader) > data.len) break;
        const sh = std.mem.bytesAsValue(sectionHeader, data[offset..][0..@sizeOf(sectionHeader)]);
        const sname = std.mem.sliceTo(shstrtab[@as(usize, sh.sh_name)..], 0);
        if (std.mem.eql(u8, sname, strtab_name)) {
            strtab_data = data[@as(usize, sh.sh_offset)..][0..@as(usize, sh.sh_size)];
            break;
        }
    }

    for (0..hdr.*.e_shnum) |i| {
        const offset = @as(usize, hdr.*.e_shoff) + i * hdr.*.e_shentsize;
        if (offset + @sizeOf(sectionHeader) > data.len) break;
        const sh = std.mem.bytesAsValue(sectionHeader, data[offset..][0..@sizeOf(sectionHeader)]);
        const sname = std.mem.sliceTo(shstrtab[@as(usize, sh.sh_name)..], 0);
        if (!std.mem.eql(u8, sname, target_name)) continue;

        const sym_size = if (@sizeOf(header) == @sizeOf(ELF.Elf32Header)) @sizeOf(ELF.Elf32Sym) else @sizeOf(ELF.Elf64Sym);
        if (sym_size == 0) break;

        const sym_data = data[@as(usize, sh.sh_offset)..][0..@as(usize, sh.sh_size)];
        const sym_count = sym_data.len / sym_size;

        print("\n{s} ({d} symbol)\n", .{ target_name, sym_count });
        print("\n  {s:<6} {s:<18} {s:<8} {s:<8} {s:<8} {s:<6} {s}\n", .{
            "Nr", "Value", "Size", "Type", "Bind", "Ndx", "Name",
        });
        print("  {s}\n", .{"-" ** 80});

        const SymEntry = if (header == ELF.Elf32Header) ELF.Elf32Sym else ELF.Elf64Sym;
        for (0..sym_count) |sc| {
            const sym = std.mem.bytesAsValue(SymEntry, sym_data[sc * sym_size ..][0..sym_size]);
            const sym_name: []const u8 = if (strtab_data) |st|
                std.mem.sliceTo(st[@as(usize, sym.st_name)..], 0)
            else
                "<no strtab>";
            const sym_type = elfHelper.symTypeName(sym.st_info & 0xF);
            const sym_bind = elfHelper.symBindName(sym.st_info >> 4);
            print("  {d:<6} 0x{X:0>16}  {d:<8} {s:<8} {s:<8} {d:<6} {s}\n", .{
                sc,
                sym.st_value,
                sym.st_size,
                sym_type,
                sym_bind,
                sym.st_shndx,
                sym_name,
            });
        }
        break;
    }
}

fn printRelocations(
    comptime header: type,
    comptime sectionHeader: type,
    data: []const u8,
    shstrtab: []const u8,
) !void {
    const hdr = std.mem.bytesAsValue(header, data[0..@sizeOf(header)]);
    const is64 = (header == ELF.Elf64Header);

    for (0..hdr.*.e_shnum) |i| {
        const offset = @as(usize, hdr.*.e_shoff) + i * hdr.*.e_shentsize;
        if (offset + @sizeOf(sectionHeader) > data.len) break;
        const sh = std.mem.bytesAsValue(sectionHeader, data[offset..][0..@sizeOf(sectionHeader)]);
        const sname = std.mem.sliceTo(shstrtab[@as(usize, sh.sh_name)..], 0);
        const is_rela = (sh.sh_type == ELF.SHT_RELA);
        const is_rel = (sh.sh_type == ELF.SHT_REL);
        if (!is_rela and !is_rel) continue;

        print("\nRelocation Section: {s}\n\n", .{sname});
        print("  {s:<18} {s:<12} {s:<12}\n", .{ "Offset", "Type", "Addend" });
        print("  {s}\n", .{"-" ** 50});

        const rela_size: usize = if (is64) (if (is_rela) 24 else 16) else (if (is_rela) 12 else 8);
        const rela_data = data[@as(usize, sh.sh_offset)..][0..@as(usize, sh.sh_size)];
        const count = rela_data.len / rela_size;

        for (0..count) |rl| {
            const entry = rela_data[rl * rela_size ..][0..rela_size];
            if (is64) {
                const r_offset = std.mem.readInt(u64, entry[0..8], .little);
                const r_info = std.mem.readInt(u64, entry[8..16], .little);
                const r_type = @as(u32, @truncate(r_info));
                const addend: i64 = if (is_rela) std.mem.readInt(i64, entry[16..24], .little) else 0;
                print("  0x{X:0>16}  {s:<12} {d}\n", .{ r_offset, elfHelper.relaTypeName(r_type), addend });
            } else {
                const r_offset = std.mem.readInt(u32, entry[0..4], .little);
                const r_info = std.mem.readInt(u32, entry[4..8], .little);
                const r_type = r_info & 0xFF;
                const addend: i32 = if (is_rela) std.mem.readInt(i32, entry[8..12], .little) else 0;
                print("  0x{X:0>16}  {s:<12} {d}\n", .{ r_offset, elfHelper.relaTypeName(r_type), addend });
            }
        }
        print("\n", .{});
    }
}

fn printNotes(
    comptime header: type,
    comptime sectionHeader: type,
    data: []const u8,
    shstrtab: []const u8,
) !void {
    const hdr = std.mem.bytesAsValue(header, data[0..@sizeOf(header)]);
    var found = false;
    for (0..hdr.*.e_shnum) |i| {
        const offset = @as(usize, hdr.*.e_shoff) + i * hdr.*.e_shentsize;
        if (offset + @sizeOf(sectionHeader) > data.len) break;
        const sh = std.mem.bytesAsValue(sectionHeader, data[offset..][0..@sizeOf(sectionHeader)]);
        if (sh.sh_type != ELF.SHT_NOTE) continue;
        const sname = std.mem.sliceTo(shstrtab[@as(usize, sh.sh_name)..], 0);
        if (!found) {
            found = true;
            print("\nNOTES\n", .{});
            print("\n  {s:<20} {s:<12} {s:<12} {s}\n", .{ "Section", "Owner", "Type", "Data" });
            print("  {s}\n", .{"-" ** 60});
        }
        const note_data = data[@as(usize, sh.sh_offset)..][0..@as(usize, sh.sh_size)];
        var pos: usize = 0;
        while (pos + 12 <= note_data.len) {
            const namesz = std.mem.readInt(u32, note_data[pos..][0..4], .little);
            const descsz = std.mem.readInt(u32, note_data[pos + 4 ..][0..4], .little);
            const ntype = std.mem.readInt(u32, note_data[pos + 8 ..][0..4], .little);
            //print("{any} {any} {any} \n", .{ namesz, descsz, ntype });
            pos += 12;
            const name_raw = if (namesz > 0 and pos + namesz <= note_data.len)
                std.mem.sliceTo(note_data[pos..][0..namesz], 0)
            else
                "";
            // Without this crashing... READ SPEC CAREFULL!!!!!!
            pos += std.mem.alignForward(usize, namesz, 4);
            //pos += (namesz + 3) & ~@as(usize, 3);
            const desc = if (descsz > 0 and pos + descsz <= note_data.len)
                note_data[pos..][0..descsz]
            else
                &[_]u8{};
            pos += std.mem.alignForward(usize, descsz, 4);
            //pos += (descsz + 3) & ~@as(usize, 3);
            const type_name = elfHelper.noteTypeName(name_raw, ntype);
            var data_buf: [64]u8 = undefined;
            const data_str = elfHelper.formatNoteData(name_raw, ntype, desc, &data_buf);
            print("  {s:<20} {s:<12} {s:<12} {s}\n", .{ sname, name_raw, type_name, data_str });
        }
        print("\n", .{});
    }
}

fn printDynamic(
    comptime header: type,
    comptime sectionHeader: type,
    data: []const u8,
    shstrtab: []const u8,
) !void {
    const hdr = std.mem.bytesAsValue(header, data[0..@sizeOf(header)]);
    var dynstr: ?[]const u8 = null;
    for (0..hdr.e_shnum) |i| {
        const off = @as(usize, hdr.*.e_shoff) + i * hdr.*.e_shentsize;
        if (off + @sizeOf(sectionHeader) > data.len) break;
        const sh = std.mem.bytesAsValue(sectionHeader, data[off..][0..@sizeOf(sectionHeader)]);
        const sname = std.mem.sliceTo(shstrtab[@as(usize, sh.sh_name)..], 0);
        if (std.mem.eql(u8, sname, ".dynstr")) {
            dynstr = data[@as(usize, sh.sh_offset)..][0..@as(usize, sh.sh_size)];
            break;
        }
    }
    for (0..hdr.e_shnum) |i| {
        const off = @as(usize, hdr.*.e_shoff) + i * hdr.*.e_shentsize;
        if (off + @sizeOf(sectionHeader) > data.len) break;
        const sh = std.mem.bytesAsValue(sectionHeader, data[off..][0..@sizeOf(sectionHeader)]);
        const sname = std.mem.sliceTo(shstrtab[@as(usize, sh.sh_name)..], 0);
        if (!std.mem.eql(u8, sname, ".dynamic")) continue;

        const is64 = @sizeOf(header) == @sizeOf(ELF.Elf64Header);
        const entry_size: usize = if (is64) 16 else 8;
        const dyn_data = data[@as(usize, sh.sh_offset)..][0..@as(usize, sh.sh_size)];
        const count = dyn_data.len / entry_size;

        print("\nDYNAMIC SECTION\n", .{});
        print("\n  {s:<20} {s}\n", .{ "Tag", "Value" });
        print("  {s}\n", .{"-" ** 50});

        for (0..count) |ei| {
            const entry = dyn_data[ei * entry_size ..][0..entry_size];
            const tag: i64 = if (is64)
                @bitCast(std.mem.readInt(u64, entry[0..8], .little))
            else
                @as(i64, @bitCast(@as(i64, std.mem.readInt(u32, entry[0..4], .little))));
            const val: u64 = if (is64)
                std.mem.readInt(u64, entry[8..16], .little)
            else
                std.mem.readInt(u32, entry[4..8], .little);
            if (tag == 0) break;
            const tag_name = elfHelper.dynTagName(tag);
            if (tag == 1) {
                const lib = if (dynstr) |ds|
                    std.mem.sliceTo(ds[@as(usize, val)..], 0)
                else
                    "<no dynstr>";
                print("  {s:<20} {s}\n", .{ tag_name, lib });
            } else {
                print("  {s:<20} 0x{X}\n", .{ tag_name, val });
            }
        }
        break;
    }
}

fn printSysVHash(
    comptime header: type,
    comptime sectionHeader: type,
    data: []const u8,
    shstrtab: []const u8,
) !void {
    const hdr = std.mem.bytesAsValue(header, data[0..@sizeOf(header)]);

    for (0..hdr.*.e_shnum) |i| {
        const off = @as(usize, hdr.*.e_shoff) + i * hdr.*.e_shentsize;
        if (off + @sizeOf(sectionHeader) > data.len) break;
        const sh = std.mem.bytesAsValue(sectionHeader, data[off..][0..@sizeOf(sectionHeader)]);
        const sname = std.mem.sliceTo(shstrtab[@as(usize, sh.sh_name)..], 0);
        if (!std.mem.eql(u8, sname, ".hash")) continue;

        const hash_data = data[@as(usize, sh.sh_offset)..][0..@as(usize, sh.sh_size)];
        if (hash_data.len < 8) {
            print("\n.hash: too small\n", .{});
            return;
        }

        const nbucket = std.mem.readInt(u32, hash_data[0..4], .little);
        const nchain = std.mem.readInt(u32, hash_data[4..8], .little);

        print("\nSYSV HASH TABLE (.hash)\n", .{});
        print("  nbucket : {d}\n", .{nbucket});
        print("  nchain  : {d}  (== symbol count)\n\n", .{nchain});

        // bucket[]
        print("  Buckets:\n  ", .{});
        for (0..nbucket) |b| {
            const boff = 8 + b * 4;
            if (boff + 4 > hash_data.len) break;
            const val = std.mem.readInt(u32, hash_data[boff..][0..4], .little);
            print("{d} ", .{val});
        }
        print("\n", .{});

        // chain[]
        print("\n  Chains:\n  ", .{});
        for (0..nchain) |c| {
            const coff = 8 + nbucket * 4 + c * 4;
            if (coff + 4 > hash_data.len) break;
            const val = std.mem.readInt(u32, hash_data[coff..][0..4], .little);
            print("{d} ", .{val});
        }
        print("\n", .{});
        break;
    }
}

fn printGnuHash(
    comptime header: type,
    comptime sectionHeader: type,
    data: []const u8,
    shstrtab: []const u8,
) !void {
    const hdr = std.mem.bytesAsValue(header, data[0..@sizeOf(header)]);
    const is64 = (@sizeOf(header) == @sizeOf(ELF.Elf64Header));
    const bloom_word_size: usize = if (is64) 8 else 4;

    for (0..hdr.*.e_shnum) |i| {
        const off = @as(usize, hdr.*.e_shoff) + i * hdr.*.e_shentsize;
        if (off + @sizeOf(sectionHeader) > data.len) break;
        const sh = std.mem.bytesAsValue(sectionHeader, data[off..][0..@sizeOf(sectionHeader)]);
        const sname = std.mem.sliceTo(shstrtab[@as(usize, sh.sh_name)..], 0);
        if (!std.mem.eql(u8, sname, ".gnu.hash")) continue;

        const hash_data = data[@as(usize, sh.sh_offset)..][0..@as(usize, sh.sh_size)];
        if (hash_data.len < 16) {
            print("\n.gnu.hash: too small\n", .{});
            return;
        }

        const nbuckets = std.mem.readInt(u32, hash_data[0..4], .little);
        const symoffset = std.mem.readInt(u32, hash_data[4..8], .little);
        const bloom_size = std.mem.readInt(u32, hash_data[8..12], .little);
        const bloom_shift = std.mem.readInt(u32, hash_data[12..16], .little);

        print("\nGNU HASH TABLE (.gnu.hash)\n", .{});
        print("  nbuckets   : {d}\n", .{nbuckets});
        print("  symoffset  : {d}  (first hashed symbol index in .dynsym)\n", .{symoffset});
        print("  bloom_size : {d}  (bloom filter words)\n", .{bloom_size});
        print("  bloom_shift: {d}\n\n", .{bloom_shift});

        // Bloom filter
        const bloom_start: usize = 16;
        const bloom_bytes = bloom_size * bloom_word_size;
        print("  Bloom filter ({d}-bit words):\n  ", .{bloom_word_size * 8});
        for (0..bloom_size) |b| {
            const boff = bloom_start + b * bloom_word_size;
            if (boff + bloom_word_size > hash_data.len) break;
            if (is64) {
                const word = std.mem.readInt(u64, hash_data[boff..][0..8], .little);
                print("0x{X:0>16} ", .{word});
            } else {
                const word = std.mem.readInt(u32, hash_data[boff..][0..4], .little);
                print("0x{X:0>8} ", .{word});
            }
        }
        print("\n", .{});

        // Buckets
        const bucket_start = bloom_start + bloom_bytes;
        print("\n  Buckets ({d}):\n  ", .{nbuckets});
        for (0..nbuckets) |b| {
            const boff = bucket_start + b * 4;
            if (boff + 4 > hash_data.len) break;
            const val = std.mem.readInt(u32, hash_data[boff..][0..4], .little);
            print("{d} ", .{val});
        }
        print("\n", .{});

        // Chain
        const chain_start = bucket_start + nbuckets * 4;
        const chain_bytes = if (chain_start < hash_data.len) hash_data.len - chain_start else 0;
        const chain_count = chain_bytes / 4;

        print("\n  Hash values (chain, {d} entries):\n  ", .{chain_count});
        for (0..chain_count) |c| {
            const coff = chain_start + c * 4;
            if (coff + 4 > hash_data.len) break;
            const val = std.mem.readInt(u32, hash_data[coff..][0..4], .little);
            const is_last = (val & 1) == 1;
            print("0x{X:0>8}{s} ", .{ val & ~@as(u32, 1), if (is_last) "*" else "" });
        }
        print("\n  (* = last symbol in bucket)\n", .{});
        break;
    }
}
