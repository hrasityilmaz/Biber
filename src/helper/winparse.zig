const std = @import("std");
const win = @import("win.zig");
const winhelper = @import("winhelper.zig");

const print = std.debug.print;

pub fn parsePe(data: []const u8) !void {
    if (data.len < @sizeOf(win.DosHeader)) {
        print("[ERROR] Too small for DOS Header", .{});
        return;
    }

    const dos = std.mem.bytesAsValue(win.DosHeader, data[0..@sizeOf(win.DosHeader)]);
    //print("dos magic -> 0x{X} [{c}{c}]\n", .{ dos.*.e_magic, data[0], data[1] });
    if (dos.*.e_magic != win.DOS_MAGIC) {
        print("[ERROR] Invalid DOS magic!\n", .{});
        return;
    }

    const pe_offset = @as(usize, dos.*.e_lfanew);
    if (pe_offset + 4 > data.len) {
        print("[ERROR] PE offset out of bounds!\n", .{});
        return;
    }

    const pe_sig = std.mem.readInt(u32, data[pe_offset..][0..4], .little);
    //print("pe_sig -> 0x{X} {c}{c}{c}{c}\n", .{ pe_sig, data[pe_offset..][0], data[pe_offset..][1], data[pe_offset..][2], data[pe_offset..][3] });
    if (pe_sig != win.PE_MAGIC) {
        print("[ERROR] Invalid PE signature!\n", .{});
        return;
    }

    const fh_offset = pe_offset + 4;
    if (fh_offset + @sizeOf(win.PeFileHeader) > data.len) return;
    const fh = std.mem.bytesAsValue(win.PeFileHeader, data[fh_offset..][0..@sizeOf(win.PeFileHeader)]);
    const opt_offset = fh_offset + @sizeOf(win.PeFileHeader);
    if (opt_offset + 2 > data.len) return;
    const opt_magic = std.mem.readInt(u16, data[opt_offset..][0..2], .little);
    const is64 = (opt_magic == win.OPT_PE64);

    print("\n", .{});
    print("{s:<20}: {s}\n", .{ "FORMAT", if (is64) "PE32+" else "PE32" });
    print("{s:<20}: {s}\n", .{ "MACHINE", winhelper.machineName(fh.machine) });
    print("{s:<20}: {d}\n", .{ "SECTIONS", fh.number_of_sections });
    print("{s:<20}: 0x{X}\n", .{ "TIMESTAMP", fh.time_date_stamp });
    print("{s:<20}: 0x{X}\n", .{ "CHARACTERISTICS", fh.characteristics });

    var entry_point: u32 = 0;
    var image_base: u64 = 0;
    var data_dirs_rva: usize = 0; // opt_off'tan data dir'lara offset
    var num_dirs: u32 = 0;

    if (is64) {
        if (opt_offset + @sizeOf(win.PeOptionalHeader64) > data.len) return;
        const opt = std.mem.bytesAsValue(win.PeOptionalHeader64, data[opt_offset..][0..@sizeOf(win.PeOptionalHeader64)]);
        entry_point = opt.address_of_entry_point;
        image_base = opt.image_base;
        num_dirs = opt.number_of_rva_and_sizes;
        data_dirs_rva = opt_offset + @sizeOf(win.PeOptionalHeader64);
        print("{s:<20}: 0x{X}\n", .{ "IMAGE_BASE", image_base });
        print("{s:<20}: 0x{X}\n", .{ "ENTRY_POINT", entry_point });
        print("{s:<20}: {s}\n", .{ "SUBSYSTEM", winhelper.subsystemName(opt.subsystem) });
        print("{s:<20}: 0x{X:0>4}\n", .{ "DLL_CHARS", opt.dll_characteristics });
    } else {
        if (opt_offset + @sizeOf(win.PeOptionalHeader32) > data.len) return;
        const opt = std.mem.bytesAsValue(win.PeOptionalHeader32, data[opt_offset..][0..@sizeOf(win.PeOptionalHeader32)]);
        entry_point = opt.address_of_entry_point;
        image_base = opt.image_base;
        num_dirs = opt.number_of_rva_and_sizes;
        data_dirs_rva = opt_offset + @sizeOf(win.PeOptionalHeader32);
        print("{s:<20}: 0x{X}\n", .{ "IMAGE_BASE", image_base });
        print("{s:<20}: 0x{X}\n", .{ "ENTRY_POINT", entry_point });
        print("{s:<20}: {s}\n", .{ "SUBSYSTEM", winhelper.subsystemName(opt.subsystem) });
        print("{s:<20}: 0x{X:0>4}\n", .{ "DLL_CHARS", opt.dll_characteristics });
    }

    const dir_count = @min(num_dirs, win.IMAGE_NUMBER_OF_DIRECTORY_ENTRIES);
    const dir_names = [win.IMAGE_NUMBER_OF_DIRECTORY_ENTRIES][]const u8{
        "Export",    "Import",      "Resource",      "Exception",
        "Security",  "BaseReloc",   "Debug",         "Architecture",
        "GlobalPtr", "TLS",         "LoadConfig",    "BoundImport",
        "IAT",       "DelayImport", "COMDescriptor", "Reserved",
    };

    print("\nDATA DIRECTORIES\n", .{});
    print("\n  {s:<16} {s:<12} {s}\n", .{ "Name", "RVA", "Size" });
    print("  {s}\n", .{"-" ** 44});

    var dirs: [win.IMAGE_NUMBER_OF_DIRECTORY_ENTRIES]win.ImageDataDirectory = undefined;
    for (0..dir_count) |di| {
        const doff = data_dirs_rva + di * @sizeOf(win.ImageDataDirectory);
        if (doff + @sizeOf(win.ImageDataDirectory) > data.len) break;
        const d = std.mem.bytesAsValue(win.ImageDataDirectory, data[doff..][0..@sizeOf(win.ImageDataDirectory)]);
        dirs[di] = d.*;
        if (d.virtual_address == 0) continue;
        print("  {s:<16} 0x{X:0>8}   0x{X}\n", .{ dir_names[di], d.virtual_address, d.size });
    }

    const sh_off = opt_offset + fh.size_of_optional_header;
    const sec_count = fh.number_of_sections;
    var sections: [96]win.PeSectionHeader = undefined;
    const sc = @min(sec_count, 96);
    print("\nSECTION HEADERS\n", .{});
    print("\n  {s:<10} {s:<12} {s:<12} {s:<12} {s:<10} {s}\n", .{
        "Name", "VirtAddr", "VirtSize", "RawOffset", "RawSize", "Flags",
    });
    print("  {s}\n", .{"-" ** 72});

    for (0..sc) |si| {
        const soff = sh_off + si * @sizeOf(win.PeSectionHeader);
        if (soff + @sizeOf(win.PeSectionHeader) > data.len) break;
        const sh = std.mem.bytesAsValue(win.PeSectionHeader, data[soff..][0..@sizeOf(win.PeSectionHeader)]);
        sections[si] = sh.*;
        const name = std.mem.sliceTo(&sh.name, 0);
        const flags = winhelper.sectionFlags(sh.characteristics);
        print("  {s:<10} 0x{X:0>8}   0x{X:0>8}   0x{X:0>8}   0x{X:0>6}  {s}\n", .{
            name,
            sh.virtual_address,
            sh.virtual_size,
            sh.pointer_to_raw_data,
            sh.size_of_raw_data,
            flags,
        });
    }

    //const exp_dir = dirs[win.IMAGE_DIRECTORY_ENTRY_EXPORT];
    //if (exp_dir.virtual_address != 0) {
    //    try printExports(data, sections[0..sc], exp_dir);
    //}
    //
    //const imp_dir = dirs[win.IMAGE_DIRECTORY_ENTRY_IMPORT];
    //if (imp_dir.virtual_address != 0) {
    //    try printImports(data, sections[0..sc], imp_dir, is64, image_base);
    //}

    const secs = sections[0..sc];

    if (dirs[win.IMAGE_DIRECTORY_ENTRY_EXPORT].virtual_address != 0)
        try printExports(data, secs, dirs[win.IMAGE_DIRECTORY_ENTRY_EXPORT]);

    if (dirs[win.IMAGE_DIRECTORY_ENTRY_IMPORT].virtual_address != 0)
        try printImports(data, secs, dirs[win.IMAGE_DIRECTORY_ENTRY_IMPORT], is64);

    if (dirs[win.IMAGE_DIRECTORY_ENTRY_DEBUG].virtual_address != 0)
        printDebugDir(data, secs, dirs[win.IMAGE_DIRECTORY_ENTRY_DEBUG]);

    if (dirs[win.IMAGE_DIRECTORY_ENTRY_TLS].virtual_address != 0)
        printTls(data, secs, dirs[win.IMAGE_DIRECTORY_ENTRY_TLS], is64, image_base);

    if (dirs[win.IMAGE_DIRECTORY_ENTRY_BASERELOC].virtual_address != 0)
        printBaseReloc(data, secs, dirs[win.IMAGE_DIRECTORY_ENTRY_BASERELOC], false);

    if (dirs[win.IMAGE_DIRECTORY_ENTRY_RESOURCE].virtual_address != 0)
        printResources(data, secs, dirs[win.IMAGE_DIRECTORY_ENTRY_RESOURCE]);

    if (dirs[win.IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].virtual_address != 0)
        printDelayImports(data, secs, dirs[win.IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT], is64);
}

fn printExports(data: []const u8, sections: []const win.PeSectionHeader, dir: win.ImageDataDirectory) !void {
    const off = winhelper.rvaToOffset(dir.virtual_address, sections) orelse return;
    if (off + @sizeOf(win.ImageExportDirectory) > data.len) return;

    const exp = std.mem.bytesAsValue(win.ImageExportDirectory, data[off..][0..@sizeOf(win.ImageExportDirectory)]);
    const name_off = winhelper.rvaToOffset(exp.name, sections) orelse 0;
    const dll_name: []const u8 = if (name_off != 0 and name_off < data.len)
        std.mem.sliceTo(data[name_off..], 0)
    else
        "<unknown>";

    print("\nEXPORT TABLE\n", .{});
    print("  DLL Name  : {s}\n", .{dll_name});
    print("  Ordinal Base     : {d}\n", .{exp.base});
    print("  # Functions      : {d}\n", .{exp.number_of_functions});
    print("  # Named Exports  : {d}\n", .{exp.number_of_names});

    print("\n  {s:<6} {s:<10} {s}\n", .{ "Ord", "RVA", "Name" });
    print("  {s}\n", .{"-" ** 50});

    const eat_off = winhelper.rvaToOffset(exp.address_of_functions, sections) orelse return;
    const ent_off = winhelper.rvaToOffset(exp.address_of_names, sections) orelse return;
    const eot_off = winhelper.rvaToOffset(exp.address_of_name_ordinals, sections) orelse return;

    const n = exp.number_of_names;
    for (0..n) |ni| {
        const name_rva_off = ent_off + ni * 4;
        const ord_off_i = eot_off + ni * 2;
        if (name_rva_off + 4 > data.len or ord_off_i + 2 > data.len) break;

        const name_rva = std.mem.readInt(u32, data[name_rva_off..][0..4], .little);
        const ordinal = std.mem.readInt(u16, data[ord_off_i..][0..2], .little);
        const func_rva_off = eat_off + @as(usize, ordinal) * 4;
        if (func_rva_off + 4 > data.len) break;
        const func_rva = std.mem.readInt(u32, data[func_rva_off..][0..4], .little);

        const sym_off = winhelper.rvaToOffset(name_rva, sections) orelse continue;
        if (sym_off >= data.len) continue;
        const sym_name = std.mem.sliceTo(data[sym_off..], 0);

        print("  {d:<6} 0x{X:0>8} {s}\n", .{ @as(u32, ordinal) + exp.base, func_rva, sym_name });
    }
}

fn printImports(data: []const u8, sections: []const win.PeSectionHeader, dir: win.ImageDataDirectory, is64: bool) !void {
    print("\nIMPORT TABLE\n", .{});

    var desc_off: usize = @as(usize, winhelper.rvaToOffset(dir.virtual_address, sections) orelse return);
    const desc_size = @sizeOf(win.ImageImportDescriptor);

    while (desc_off + desc_size <= data.len) {
        const desc = std.mem.bytesAsValue(win.ImageImportDescriptor, data[desc_off..][0..desc_size]);
        if (desc.name == 0 and desc.first_thunk == 0) break;

        const dll_name_off = winhelper.rvaToOffset(desc.name, sections) orelse {
            desc_off += desc_size;
            continue;
        };
        const dll_name = if (dll_name_off < data.len)
            std.mem.sliceTo(data[dll_name_off..], 0)
        else
            "<unknown>";

        print("\n  {s}\n", .{dll_name});
        print("  {s:<6} {s}\n", .{ "Hint", "Name" });
        print("  {s}\n", .{"-" ** 40});

        // INT (OriginalFirstThunk) yoksa IAT'ı kullan
        const thunk_rva = if (desc.original_first_thunk != 0)
            desc.original_first_thunk
        else
            desc.first_thunk;

        var thunk_off: usize = @as(usize, winhelper.rvaToOffset(thunk_rva, sections) orelse {
            desc_off += desc_size;
            continue;
        });

        const thunk_size: usize = if (is64) 8 else 4;
        const ordinal_flag: u64 = if (is64) 0x8000000000000000 else 0x80000000;

        while (thunk_off + thunk_size <= data.len) {
            const thunk_val: u64 = if (is64)
                std.mem.readInt(u64, data[thunk_off..][0..8], .little)
            else
                @as(u64, std.mem.readInt(u32, data[thunk_off..][0..4], .little));

            if (thunk_val == 0) break;

            if (thunk_val & ordinal_flag != 0) {
                // Ordinal ile import
                const ord = @as(u16, @truncate(thunk_val & 0xFFFF));
                print("  {d:<6} <ordinal>\n", .{ord});
            } else {
                // İsimle import — hint/name entry
                const hint_rva = @as(u32, @truncate(thunk_val & 0x7FFFFFFF));
                const hint_off: usize = @as(usize, winhelper.rvaToOffset(hint_rva, sections) orelse {
                    thunk_off += thunk_size;
                    continue;
                });
                if (hint_off + 2 > data.len) {
                    thunk_off += thunk_size;
                    continue;
                }
                const hint = std.mem.readInt(u16, data[hint_off..][0..2], .little);
                const sym_name = if (hint_off + 2 < data.len)
                    std.mem.sliceTo(data[hint_off + 2 ..], 0)
                else
                    "<unknown>";
                print("  {d:<6} {s}\n", .{ hint, sym_name });
            }
            thunk_off += thunk_size;
        }

        desc_off += desc_size;
    }
}

fn printDelayImports(data: []const u8, sections: []const win.PeSectionHeader, dir: win.ImageDataDirectory, is64: bool) void {
    print("\nDELAY IMPORT TABLE\n", .{});

    const desc_size: usize = 32;
    var off: usize = @as(usize, winhelper.rvaToOffset(dir.virtual_address, sections) orelse return);
    while (off + desc_size <= data.len) {
        const attrs = std.mem.readInt(u32, data[off + 0 ..][0..4], .little);
        const name_rva = std.mem.readInt(u32, data[off + 4 ..][0..4], .little);
        const iat_rva = std.mem.readInt(u32, data[off + 12 ..][0..4], .little);
        const int_rva = std.mem.readInt(u32, data[off + 16 ..][0..4], .little);
        const timestamp = std.mem.readInt(u32, data[off + 28 ..][0..4], .little);
        _ = attrs;

        if (name_rva == 0 and iat_rva == 0) break;

        const dll_name_off: usize = @as(usize, winhelper.rvaToOffset(name_rva, sections) orelse {
            off += desc_size;
            continue;
        });
        const dll_name = if (dll_name_off < data.len)
            std.mem.sliceTo(data[dll_name_off..], 0)
        else
            "<unknown>";

        print("\n  {s}  (timestamp: 0x{X})\n", .{ dll_name, timestamp });
        print("  {s:<6} {s}\n", .{ "Hint", "Name" });
        print("  {s}\n", .{"-" ** 40});

        const thunk_rva = if (int_rva != 0) int_rva else iat_rva;
        var thunk_off: usize = @as(usize, winhelper.rvaToOffset(thunk_rva, sections) orelse {
            off += desc_size;
            continue;
        });

        const thunk_size: usize = if (is64) 8 else 4;
        const ordinal_flag: u64 = if (is64) 0x8000000000000000 else 0x80000000;

        while (thunk_off + thunk_size <= data.len) {
            const thunk_val: u64 = if (is64)
                std.mem.readInt(u64, data[thunk_off..][0..8], .little)
            else
                @as(u64, std.mem.readInt(u32, data[thunk_off..][0..4], .little));

            if (thunk_val == 0) break;

            if (thunk_val & ordinal_flag != 0) {
                const ord = @as(u16, @truncate(thunk_val & 0xFFFF));
                print("  {d:<6} <ordinal>\n", .{ord});
            } else {
                const hint_rva = @as(u32, @truncate(thunk_val & 0x7FFFFFFF));
                const hint_off: usize = @as(usize, winhelper.rvaToOffset(hint_rva, sections) orelse {
                    thunk_off += thunk_size;
                    continue;
                });
                if (hint_off + 2 > data.len) {
                    thunk_off += thunk_size;
                    continue;
                }
                const hint = std.mem.readInt(u16, data[hint_off..][0..2], .little);
                const sym_name = if (hint_off + 2 < data.len)
                    std.mem.sliceTo(data[hint_off + 2 ..], 0)
                else
                    "<unknown>";
                print("  {d:<6} {s}\n", .{ hint, sym_name });
            }
            thunk_off += thunk_size;
        }
        off += desc_size;
    }
}

fn printDebugDir(data: []const u8, sections: []const win.PeSectionHeader, dir: win.ImageDataDirectory) void {
    const off: usize = @as(usize, winhelper.rvaToOffset(dir.virtual_address, sections) orelse return);
    const dir_size = @sizeOf(win.ImageDebugDirectory);
    const count = @as(usize, dir.size) / dir_size;

    print("\nDEBUG DIRECTORY\n", .{});
    for (0..count) |i| {
        const doff = off + i * dir_size;
        if (doff + dir_size > data.len) break;
        const dbg = std.mem.bytesAsValue(win.ImageDebugDirectory, data[doff..][0..dir_size]);

        print("\n  [{d}] Type: {s}  Size: 0x{X:0>4}  RVA: 0x{X:0>8}  FileOff: 0x{X:0>8}\n", .{
            i,                       winhelper.debugTypeName(dbg.type), dbg.size_of_data,
            dbg.address_of_raw_data, dbg.pointer_to_raw_data,
        });

        if (dbg.type == win.IMAGE_DEBUG_TYPE_CODEVIEW) {
            const raw: usize = @as(usize, dbg.pointer_to_raw_data);
            //if (raw + 4 > data.len) continue; WTF!!!
            if (raw == 0 or raw + 4 > data.len) continue;
            const cv_sig = std.mem.readInt(u32, data[raw..][0..4], .little);
            if (cv_sig == win.CV_SIGNATURE_RSDS) {
                if (raw + 24 > data.len) continue;
                const guid = data[raw + 4 ..][0..16];
                const age = std.mem.readInt(u32, data[raw + 20 ..][0..4], .little);
                const pdb_path = if (raw + 24 < data.len)
                    std.mem.sliceTo(data[raw + 24 ..], 0)
                else
                    "<unknown>";
                print("      Signature : RSDS\n", .{});
                print("      GUID      : {{{X:0>8}-{X:0>4}-{X:0>4}-{X:0>2}{X:0>2}-{X:0>2}{X:0>2}{X:0>2}{X:0>2}{X:0>2}{X:0>2}}}\n", .{
                    std.mem.readInt(u32, guid[0..4], .big),
                    std.mem.readInt(u16, guid[4..6], .big),
                    std.mem.readInt(u16, guid[6..8], .big),
                    guid[8],
                    guid[9],
                    guid[10],
                    guid[11],
                    guid[12],
                    guid[13],
                    guid[14],
                    guid[15],
                });
                print("      Age       : {d}\n", .{age});
                print("      PDB Path  : {s}\n", .{pdb_path});
            } else {
                print("      CV Signature: 0x{X} (NB10 or unknown)\n", .{cv_sig});
            }
        }

        if (dbg.type == win.IMAGE_DEBUG_TYPE_REPRO) {
            const raw: usize = @as(usize, dbg.pointer_to_raw_data);
            //if (raw + 4 > data.len) continue;
            if (raw == 0 or dbg.size_of_data == 0 or raw + 4 > data.len) continue;
            const hash_len = std.mem.readInt(u32, data[raw..][0..4], .little);
            print("      Hash ({d} bytes): ", .{hash_len});
            const hend = @min(raw + 4 + @as(usize, hash_len), data.len);
            for (data[raw + 4 .. hend]) |b| print("{X:0>2}", .{b});
            print("\n", .{});
        }
    }
}

fn printTls(data: []const u8, sections: []const win.PeSectionHeader, dir: win.ImageDataDirectory, is64: bool, image_base: u64) void {
    const off: usize = @as(usize, winhelper.rvaToOffset(dir.virtual_address, sections) orelse return);

    print("\nTLS DIRECTORY\n", .{});
    if (is64) {
        if (off + 40 > data.len) return;
        const raw_start = std.mem.readInt(u64, data[off + 0 ..][0..8], .little);
        const raw_end = std.mem.readInt(u64, data[off + 8 ..][0..8], .little);
        const index_va = std.mem.readInt(u64, data[off + 16 ..][0..8], .little);
        const cb_va = std.mem.readInt(u64, data[off + 24 ..][0..8], .little);
        const zero_fill = std.mem.readInt(u32, data[off + 32 ..][0..4], .little);
        const chars = std.mem.readInt(u32, data[off + 36 ..][0..4], .little);

        print("  Raw Data Start   : 0x{X:0>16}\n", .{raw_start});
        print("  Raw Data End     : 0x{X:0>16}\n", .{raw_end});
        print("  TLS Index VA     : 0x{X:0>16}\n", .{index_va});
        print("  Callbacks VA     : 0x{X:0>16}\n", .{cb_va});
        print("  Zero Fill Size   : {d}\n", .{zero_fill});
        print("  Characteristics  : 0x{X}\n", .{chars});

        if (cb_va != 0 and cb_va >= image_base) {
            const cb_rva = @as(u32, @truncate(cb_va - image_base));
            var cb_off: usize = @as(usize, winhelper.rvaToOffset(cb_rva, sections) orelse return);
            print("\n  Callbacks:\n", .{});
            var idx: u32 = 0;
            while (cb_off + 8 <= data.len) {
                const fn_va = std.mem.readInt(u64, data[cb_off..][0..8], .little);
                if (fn_va == 0) break;
                const fn_rva = @as(u32, @truncate(fn_va - image_base));
                print("    [{d}] VA: 0x{X:0>16}  RVA: 0x{X:0>8}\n", .{ idx, fn_va, fn_rva });
                cb_off += 8;
                idx += 1;
            }
            if (idx == 0) print("    (none)\n", .{});
        }
    } else {
        if (off + 24 > data.len) return;
        const raw_start = std.mem.readInt(u32, data[off + 0 ..][0..4], .little);
        const raw_end = std.mem.readInt(u32, data[off + 4 ..][0..4], .little);
        const index_va = std.mem.readInt(u32, data[off + 8 ..][0..4], .little);
        const cb_va = std.mem.readInt(u32, data[off + 12 ..][0..4], .little);
        const zero_fill = std.mem.readInt(u32, data[off + 16 ..][0..4], .little);
        const chars = std.mem.readInt(u32, data[off + 20 ..][0..4], .little);

        print("  Raw Data Start   : 0x{X:0>8}\n", .{raw_start});
        print("  Raw Data End     : 0x{X:0>8}\n", .{raw_end});
        print("  TLS Index VA     : 0x{X:0>8}\n", .{index_va});
        print("  Callbacks VA     : 0x{X:0>8}\n", .{cb_va});
        print("  Zero Fill Size   : {d}\n", .{zero_fill});
        print("  Characteristics  : 0x{X}\n", .{chars});

        if (cb_va != 0) {
            const cb_rva = @as(u32, @truncate(@as(u64, cb_va) - image_base));
            var cb_off: usize = @as(usize, winhelper.rvaToOffset(cb_rva, sections) orelse return);
            print("\n  Callbacks:\n", .{});
            var idx: u32 = 0;
            while (cb_off + 4 <= data.len) {
                const fn_va = std.mem.readInt(u32, data[cb_off..][0..4], .little);
                if (fn_va == 0) break;
                const fn_rva = fn_va -% @as(u32, @truncate(image_base));
                print("    [{d}] VA: 0x{X:0>8}  RVA: 0x{X:0>8}\n", .{ idx, fn_va, fn_rva });
                cb_off += 4;
                idx += 1;
            }
            if (idx == 0) print("    (none)\n", .{});
        }
    }
}

fn printBaseReloc(data: []const u8, sections: []const win.PeSectionHeader, dir: win.ImageDataDirectory, verbose: bool) void {
    var off: usize = @as(usize, winhelper.rvaToOffset(dir.virtual_address, sections) orelse return);
    const end: usize = off + @as(usize, dir.size);

    print("\nBASE RELOCATIONS\n", .{});

    var total_entries: u32 = 0;
    var total_blocks: u32 = 0;

    while (off + @sizeOf(win.ImageBaseRelocation) <= end and
        off + @sizeOf(win.ImageBaseRelocation) <= data.len)
    {
        const blk = std.mem.bytesAsValue(win.ImageBaseRelocation, data[off..][0..@sizeOf(win.ImageBaseRelocation)]);
        if (blk.size_of_block < @sizeOf(win.ImageBaseRelocation)) break;
        if (blk.virtual_address == 0 and blk.size_of_block == 0) break;

        const entry_count = (blk.size_of_block - @sizeOf(win.ImageBaseRelocation)) / 2;
        total_blocks += 1;
        total_entries += entry_count;
        if (verbose) {
            print("\n  Page 0x{X:0>8}  ({d} entries)\n", .{ blk.virtual_address, entry_count });
            const entries_start = off + @sizeOf(win.ImageBaseRelocation);
            for (0..entry_count) |ei| {
                const eoff = entries_start + ei * 2;
                if (eoff + 2 > data.len) break;
                const entry = std.mem.readInt(u16, data[eoff..][0..2], .little);
                const rel_type: u4 = @truncate(entry >> 12);
                const rel_off: u16 = entry & 0x0FFF;
                if (rel_type == 0) continue;
                const type_name: []const u8 = switch (rel_type) {
                    1 => "HIGH   ",
                    2 => "LOW    ",
                    3 => "HIGHLOW",
                    4 => "HIGHADJ",
                    10 => "DIR64  ",
                    else => "UNKN   ",
                };
                print("    0x{X:0>8}  {s}  +0x{X:0>3}\n", .{
                    blk.virtual_address + rel_off, type_name, rel_off,
                });
            }
        }
        off += @as(usize, blk.size_of_block);
    }
    print("\n  Total: {d} blocks, {d} entries\n", .{ total_blocks, total_entries });
}

fn printResourceDir(
    data: []const u8,
    rsrc_base: usize,
    dir_off: usize,
    rsrc_va: u32,
    depth: u32,
) void {
    const abs_off = rsrc_base + dir_off;
    if (abs_off + 16 > data.len) return;

    const named_count = std.mem.readInt(u16, data[abs_off + 12 ..][0..2], .little);
    const id_count = std.mem.readInt(u16, data[abs_off + 14 ..][0..2], .little);
    const total = @as(u32, named_count) + @as(u32, id_count);

    for (0..total) |ei| {
        const entry_off = abs_off + 16 + ei * 8;
        if (entry_off + 8 > data.len) break;

        const name_or_id = std.mem.readInt(u32, data[entry_off + 0 ..][0..4], .little);
        const data_or_dir = std.mem.readInt(u32, data[entry_off + 4 ..][0..4], .little);

        const is_named = (name_or_id & 0x80000000) != 0;
        const is_dir = (data_or_dir & 0x80000000) != 0;
        const offset = data_or_dir & 0x7FFFFFFF;
        var ind: u32 = 0;
        while (ind < depth * 2) : (ind += 1) print(" ", .{});

        if (depth == 0) {
            if (is_named) {
                const str_off = rsrc_base + (name_or_id & 0x7FFFFFFF);
                if (str_off + 2 <= data.len) {
                    const str_len = std.mem.readInt(u16, data[str_off..][0..2], .little);
                    print("TYPE: \"", .{});
                    var ci: usize = 0;
                    while (ci < str_len and str_off + 2 + ci * 2 + 1 < data.len) : (ci += 1) {
                        const ch = std.mem.readInt(u16, data[str_off + 2 + ci * 2 ..][0..2], .little);
                        if (ch < 128) print("{c}", .{@as(u8, @truncate(ch))});
                    }
                    print("\"\n", .{});
                }
            } else {
                print("TYPE: {s} ({d})\n", .{ winhelper.resTypeName(name_or_id), name_or_id });
            }
        } else if (depth == 1) {
            if (is_named) {
                const str_off = rsrc_base + (name_or_id & 0x7FFFFFFF);
                if (str_off + 2 <= data.len) {
                    const str_len = std.mem.readInt(u16, data[str_off..][0..2], .little);
                    print("  ID: \"", .{});
                    var ci: usize = 0;
                    while (ci < str_len and str_off + 2 + ci * 2 + 1 < data.len) : (ci += 1) {
                        const ch = std.mem.readInt(u16, data[str_off + 2 + ci * 2 ..][0..2], .little);
                        if (ch < 128) print("{c}", .{@as(u8, @truncate(ch))});
                    }
                    print("\"\n", .{});
                }
            } else {
                print("  ID: {d}\n", .{name_or_id});
            }
        } else if (depth == 2) {
            const lang = name_or_id & 0xFFFF;
            print("    Lang: 0x{X:0>4}", .{lang});
            if (!is_dir) {
                const de_off = rsrc_base + offset;
                if (de_off + 16 <= data.len) {
                    const data_rva = std.mem.readInt(u32, data[de_off + 0 ..][0..4], .little);
                    const data_size = std.mem.readInt(u32, data[de_off + 4 ..][0..4], .little);
                    print("  RVA: 0x{X:0>8}  Size: {d} bytes\n", .{ data_rva, data_size });
                } else {
                    print("\n", .{});
                }
            } else {
                print("\n", .{});
            }
        }

        if (is_dir and depth < 2) {
            printResourceDir(data, rsrc_base, offset, rsrc_va, depth + 1);
        }
    }
}

fn printResources(data: []const u8, sections: []const win.PeSectionHeader, dir: win.ImageDataDirectory) void {
    // .rsrc section'ı bul
    var rsrc_va: u32 = 0;
    var rsrc_raw: u32 = 0;

    for (sections) |s| {
        if (s.virtual_address == dir.virtual_address or
            (dir.virtual_address >= s.virtual_address and
                dir.virtual_address < s.virtual_address + s.virtual_size))
        {
            rsrc_va = s.virtual_address;
            rsrc_raw = s.pointer_to_raw_data;
            break;
        }
    }
    if (rsrc_raw == 0) return;

    const rsrc_base: usize = @as(usize, rsrc_raw);
    const dir_off: usize = @as(usize, dir.virtual_address - rsrc_va);

    print("\nRESOURCE TABLE\n\n", .{});
    printResourceDir(data, rsrc_base, dir_off, rsrc_va, 0);
}
