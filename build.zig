const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe = b.addExecutable(.{
        .name = "Biber",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    const sizeof_exe = b.addExecutable(.{
        .name = "sizeof",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/sizeof.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    const elf_mod = b.createModule(.{
        .root_source_file = b.path("src/helper/elf.zig"),
        .target = target,
        .optimize = optimize,
    });

    sizeof_exe.root_module.addImport("elf", elf_mod);

    b.installArtifact(exe);
    b.installArtifact(sizeof_exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);
    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    const exe_tests = b.addTest(.{
        .root_module = exe.root_module,
    });
    const run_exe_tests = b.addRunArtifact(exe_tests);
    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_exe_tests.step);
}
