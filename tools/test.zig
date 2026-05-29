const std = @import("std");
// .so test
// zig build-lib test.zig -dynamic -target x86_64-linux
// zig build-lib lib_test.zig -dynamic -target x86_64-linux -Xlinker --build-id
export fn printHi() void {
    std.debug.print("Hello", .{});
}
