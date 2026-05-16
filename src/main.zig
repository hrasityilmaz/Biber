// Example:
//
// biber.exe .\kernel 4096 64 -> go to offset 4096 and read 64 bytes
//
// .\biber.exe .\kernel 4096 64
// 00001000  D6 50 52 E8 00 00 00 00 18 00 00 00 12 AF 7D 01
// 00001010  00 00 00 00 08 00 00 00 01 1B 03 3B 10 00 00 00
// 00001020  01 00 00 00 E8 0F 00 00 2C 00 00 00 14 00 00 00
// 00001030  00 00 00 00 01 7A 52 00 01 7C 08 01 1B 0C 04 04
//
// pwsh
// Format-Hex .\kernel -Offset 4096 -Count 64
//
//    Label: ...../kernel
//           Offset Bytes                                           Ascii
//                  00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
//           ------ ----------------------------------------------- -----
// 0000000000001000 D6 50 52 E8 00 00 00 00 18 00 00 00 12 AF 7D 01 ÖPRè    �   �¯}�
// 0000000000001010 00 00 00 00 08 00 00 00 01 1B 03 3B 10 00 00 00     �   ���;�
// 0000000000001020 01 00 00 00 E8 0F 00 00 2C 00 00 00 14 00 00 00 �   è�  ,   �
// 0000000000001030 00 00 00 00 01 7A 52 00 01 7C 08 01 1B 0C 04 04     �zR �|������
//
//

const std = @import("std");

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;

    var start_point: [:0]const u8 = undefined;
    var end_point: [:0]const u8 = undefined;
    var exe_name: [:0]const u8 = undefined;

    const args = try init.minimal.args.toSlice(gpa);
    //std.debug.print("-- args len {d} --", .{args.len});
    if (args.len != 4) {
        std.debug.print("biber.exe v0.1\nbiber.exe [app.exe] [start_point] [end_point]\n", .{});
        return;
    }

    exe_name = args[1];
    start_point = args[2];
    end_point = args[3];

    //std.log.info("{s} {s} {s}", .{ exe_name, start_point, end_point });
    const offset = try std.fmt.parseInt(usize, start_point, 10);
    const length = try std.fmt.parseInt(usize, end_point, 10);
    const file = try std.Io.Dir.cwd().openFile(io, exe_name, .{ .mode = .read_only });
    defer file.close(io);

    var read_buffer: [1024]u8 = undefined;
    var reader = file.reader(io, &read_buffer);

    try reader.seekTo(offset);
    const bytes = try reader.interface.readAlloc(gpa, @as(usize, length));
    defer gpa.free(bytes);
    //std.log.info("{s}", .{bytes});
    var i: usize = 0;
    while (i < bytes.len) : (i += 16) {
        std.debug.print("{X:0>8}  ", .{offset + i});
        const row_end = @min(i + 16, bytes.len);
        for (bytes[i..row_end]) |b| std.debug.print("{X:0>2} ", .{b});
        std.debug.print("\n", .{});
    }
}
