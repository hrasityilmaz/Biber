const std = @import("std");
const elf = @import("helper/elf.zig");
const win = @import("helper/win.zig");

const e = std.log.err;
const info = std.log.info;
const elfparser = @import("helper/elfparse.zig");

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;

    var start_point: [:0]const u8 = undefined;
    var end_point: [:0]const u8 = undefined;
    var exe_name: [:0]const u8 = undefined;

    const args = try init.minimal.args.toSlice(gpa);
    //std.debug.print("-- args len {d} --", .{args.len});
    if (args.len != 4) {
        std.debug.print("biber v0.1\nbiber [app.exe] [start_point] [end_point]\n", .{});
        return;
    }

    exe_name = args[1];
    start_point = args[2];
    end_point = args[3];

    //std.log.info("{s} {s} {s}", .{ exe_name, start_point, end_point });
    //const offset = try std.fmt.parseInt(usize, start_point, 10);
    //const length = try std.fmt.parseInt(usize, end_point, 10);
    const file = try std.Io.Dir.cwd().openFile(io, exe_name, .{ .mode = .read_only });
    defer file.close(io);

    var read_buffer: [4096]u8 = undefined;
    var reader = file.reader(io, &read_buffer);

    //const data = try reader.interface.readAlloc(gpa, 64 * 1024 * 1024);
    //defer gpa.free(data);

    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);

    try reader.interface.appendRemainingUnlimited(gpa, &list);

    const data = list.items;

    if (data.len >= 4 and std.mem.eql(u8, data[0..4], &elf.ELFMAG)) {
        info("content -> {s}", .{data[0..4]});
        info("linux file", .{});
        try elfparser.parseElf(data);
    } else if (data.len >= 2 and std.mem.readInt(u16, data[0..2], .little) == win.DOS_MAGIC) {
        //TODO: winfile support
        info("content -> {s}", .{data[0..2]});
        info("win file", .{});
    } else {
        e("[ERROR] Not supported", .{});
        return;
    }

    //try reader.seekTo(offset);
    //const bytes = try reader.interface.readAlloc(gpa, @as(usize, length));
    //defer gpa.free(bytes);
    //std.log.info("{s}", .{bytes});
    //var i: usize = 0;
    //while (i < bytes.len) : (i += 16) {
    //    std.debug.print("{X:0>8}  ", .{offset + i});
    //    const row_end = @min(i + 16, bytes.len);
    //    for (bytes[i..row_end]) |b| std.debug.print("{X:0>2} ", .{b});
    //    std.debug.print("\n", .{});
    //}
}
