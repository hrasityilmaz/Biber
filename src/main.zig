const std = @import("std");
const elf = @import("helper/elf.zig");
const win = @import("helper/win.zig");
const elfparser = @import("helper/elfparse.zig");
const winparser = @import("helper/winparse.zig");
const helper = @import("helper/mainhelper.zig");

const e = std.log.err;
const info = std.log.info;

fn usage() void {
    std.debug.print(
        \\
        \\biber v0.2
        \\Usage:
        \\  biber -f <file> [options]
        \\
        \\Common:
        \\  -headers
        \\  -sections
        \\  -symbols
        \\  -all
        \\
        \\PE only:
        \\  -pe-directories
        \\  -pe-imports
        \\  -pe-exports
        \\  -pe-debug
        \\  -pe-exceptions
        \\
        \\ELF only:
        \\  -elf-programs
        \\  -elf-dynamic
        \\  -elf-relocs
        \\  -elf-notes
        \\  -elf-arm-attrs
        \\
        \\Raw:
        \\  -dump <offset> <length>
        \\  -dis  <offset> <length>
        \\
        \\Examples:
        \\  biber -f limon.exe -headers
        \\  biber -f limon.exe -sections
        \\  biber -f limon.exe -pe-imports
        \\  biber -f kernel -elf-programs
        \\  biber -f zig.exe -all
        \\  biber -f tamgaos.elf -dump 0x400 128
        \\
    , .{});
}

fn hasNoAction(opt: helper.Options) bool {
    return !opt.all and
        !opt.headers and
        !opt.sections and
        !opt.symbols and
        !opt.pe_directories and
        !opt.pe_imports and
        !opt.pe_exports and
        !opt.pe_debug and
        !opt.pe_exceptions and
        !opt.elf_programs and
        !opt.elf_dynamic and
        !opt.elf_relocs and
        !opt.elf_notes and
        !opt.dump and
        !opt.dis;
}

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;

    //var start_point: [:0]const u8 = undefined;
    //var end_point: [:0]const u8 = undefined;
    //var exe_name: [:0]const u8 = undefined;

    const args = try init.minimal.args.toSlice(gpa);
    defer gpa.free(args); // !!! dont forget ...

    //std.debug.print("-- args len {d} --", .{args.len});
    //if (args.len != 4) {
    //    std.debug.print("biber v0.1\nbiber [app.exe] [start_point] [end_point]\n", .{});
    //    return;
    //}

    //if (args.len < 2) {
    //    std.debug.print(
    //        \\biber v0.1
    //        \\biber [filename]
    //        \\biber [filename] [start_point] [end_point]
    //    , .{});
    //}

    if (args.len < 2) {
        usage();
        return;
    }

    var opt = helper.parseArgs(args) catch |err| {
        std.debug.print("Error: {}\n", .{err});
        usage();
        return;
    };

    if (opt.file == null) {
        usage();
        return;
    }

    if (hasNoAction(opt)) {
        opt.headers = true;
    }

    //exe_name = args[1];
    //start_point = args[2];
    //end_point = args[3];

    //std.log.info("{s} {s} {s}", .{ exe_name, start_point, end_point });
    //const offset = try std.fmt.parseInt(usize, start_point, 10);
    //const length = try std.fmt.parseInt(usize, end_point, 10);
    const file = try std.Io.Dir.cwd().openFile(io, opt.file.?, .{ .mode = .read_only });
    defer file.close(io);

    // Diassembler part
    //if (args.len == 4) {}

    var read_buffer: [4096]u8 = undefined;
    var reader = file.reader(io, &read_buffer);

    //const data = try reader.interface.readAlloc(gpa, 64 * 1024 * 1024);
    //defer gpa.free(data);

    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);

    try reader.interface.appendRemainingUnlimited(gpa, &list);

    const data = list.items;
    if (opt.dump) {
        helper.hexDump(data, opt.offset, opt.length);
        return;
    }

    if (opt.dis) {
        std.debug.print("DISASSEMBLER VIEW\n", .{});
        // TODO: decode opcode
        // 0x1000  55             push rbp
        // 0x1001  48 89 E5       mov rbp, rsp
        // 0x1004  E8 12 00 00 00 call 0x101B
        helper.hexDump(data, opt.offset, opt.length);
        return;
    }
    // mach-o suppoer maybe later..
    switch (helper.detectFormat(data)) {
        .elf => try helper.runElf(data, opt),
        .pe => try helper.runPe(data, opt),
        .unknown => {
            e("[ERROR] Not supported On future release will be implement", .{});
            return;
        },
    } //std.debug.print("args.len: {d}\n", .{args.len});
    //std.debug.print("file magic: {x} {x} {x} {x}\n", .{ data[0], data[1], data[2], data[3] });
    // TODO: MACH-O eklemek lazım
    //if (data.len >= 4 and std.mem.eql(u8, data[0..4], &elf.ELFMAG)) {
    //info("content -> {s}", .{data[0..4]});
    //info("linux file", .{});
    //    try elfparser.parseElf(data);
    //} else if (data.len >= 2 and std.mem.readInt(u16, data[0..2], .little) == win.DOS_MAGIC) {
    //TODO: winfile support
    //info("content -> {s}", .{data[0..2]});
    //info("win file", .{});
    //try winparser.parsePe(data);
    //} else {
    //    e("[ERROR] Not supported", .{});
    //    return;
    //}:w
}
