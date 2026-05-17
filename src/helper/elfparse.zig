const std = @import("std");
const ELF = @import("elf.zig");

const e = std.log.err;

pub fn parseElf(data: []const u8) !void {
    if (data.len < 16 or !std.mem.eql(u8, data[0..4], &ELF.ELFMAG)) {
        e("[ERROR] Not valid ELF file!", .{});
        return;
    }

    const class = data[4];
    if (class == ELF.ELFCLASS32) {
        // TODO: 32bit parse...
        std.log.info("class 1 32 bit", .{});
    } else if (class == ELF.ELFCLASS64) {
        // TODO: 64bit parse...
        std.log.info("class 2 64bit", .{});
    } else {
        e("[ERROR] Unknown ELF class {d}", .{class});
    }
}
