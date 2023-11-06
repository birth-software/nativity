const std = @import("std");
var all: bool = false;

pub fn build(b: *std.Build) !void {
    all = b.option(bool, "all", "All") orelse false;
    const target = b.standardTargetOptions(.{});
    const optimization = b.standardOptimizeOption(.{});
    const exe = b.addExecutable(.{
        .name = "nativity",
        .root_source_file = .{ .path = "src/main.zig" },
        .target = target,
        .optimize = optimization,
        .use_llvm = true,
        .use_lld = false,
    });
    b.installArtifact(exe);
    b.installDirectory(.{
        .source_dir = std.Build.LazyPath.relative("lib"),
        .install_dir = .bin,
        .install_subdir = "lib",
    });

    const zig_tests = b.addTest(.{
        .root_source_file = .{ .path = "src/main.zig" },
        .target = target,
        .optimize = optimization,
    });

    const run_command = b.addRunArtifact(exe);

    const debug_command = switch (@import("builtin").os.tag) {
        .linux => blk: {
            const result = b.addSystemCommand(&.{"gf2"});
            result.addArg("--args");
            result.addArtifactArg(exe);
            break :blk result;
        },
        .windows => blk: {
            const result = b.addSystemCommand(&.{"remedybg"});
            result.addArg("-g");
            result.addArtifactArg(exe);

            break :blk result;
        },
        .macos => blk: {
            // not tested
            const result = b.addSystemCommand(&.{"lldb"});
            result.addArg("--");
            result.addArtifactArg(exe);
            break :blk result;
        },
        else => @compileError("OS not supported"),
    };

    const test_command = b.addRunArtifact(zig_tests);

    if (b.args) |args| {
        run_command.addArgs(args);
        test_command.addArgs(args);
        debug_command.addArgs(args);
    }

    const run_step = b.step("run", "Test the Nativity compiler");
    run_step.dependOn(&run_command.step);
    const test_step = b.step("test", "Test the Nativity compiler");
    test_step.dependOn(&test_command.step);
    const debug_step = b.step("debug", "Debug the Nativity compiler");
    debug_step.dependOn(&debug_command.step);
}
