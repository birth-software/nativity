const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe = b.addExecutable(.{
        .name = "compiler",
        .root_source_file = .{ .path = "src/main.zig" },
        .target = target,
        .optimize = optimize,
    });

    b.installArtifact(exe);
    b.installDirectory(.{
        .source_dir = std.Build.LazyPath.relative("lib"),
        .install_dir = .bin,
        .install_subdir = "lib",
    });

    const run_cmd = b.addRunArtifact(exe);

    run_cmd.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    const debug_command = addDebugCommand(b, exe);
    const debug_step = b.step("debug", "Debug the app");
    debug_step.dependOn(&debug_command.step);

    const unit_tests = b.addTest(.{
        .root_source_file = .{ .path = "src/main.zig" },
        .target = target,
        .optimize = optimize,
    });

    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);

    const debug_unit_tests_cmd = addDebugCommand(b, unit_tests);
    const debug_test_step = b.step("debug_test", "Run the tests through the debugger");
    debug_test_step.dependOn(&debug_unit_tests_cmd.step);
}

fn addDebugCommand(b: *std.Build, artifact: *std.Build.Step.Compile) *std.Build.Step.Run {
    return switch (@import("builtin").os.tag) {
        .linux => blk: {
            const result = b.addSystemCommand(&.{"gf2"});
            result.addArtifactArg(artifact);

            if (artifact.kind == .@"test") {
                result.addArgs(&.{ "-ex", "r" });
            }

            break :blk result;
        },
        .windows => blk: {
            const result = b.addSystemCommand(&.{"remedybg"});
            result.addArg("-g");
            result.addArtifactArg(artifact);

            break :blk result;
        },
        .macos => blk: {
            // not tested
            const result = b.addSystemCommand(&.{"gdb"});
            result.addArtifactArg(artifact);
            break :blk result;
        },
        else => @compileError("Operating system not supported"),
    };
}
