const std = @import("std");
var all: bool = false;

pub fn build(b: *std.Build) !void {
    all = b.option(bool, "all", "All") orelse false;
    const target = b.standardTargetOptions(.{});
    const optimization = b.standardOptimizeOption(.{});
    const use_llvm = b.option(bool, "use_llvm", "Use LLVM as the backend for generate the compiler binary") orelse true;
    const exe = b.addExecutable(.{
        .name = "nat",
        .root_source_file = .{ .path = "bootstrap/main.zig" },
        .target = target,
        .optimize = optimization,
        .use_llvm = use_llvm,
        .use_lld = false,
    });
    exe.unwind_tables = false;
    exe.omit_frame_pointer = false;

    const install_exe = b.addInstallArtifact(exe, .{});
    b.getInstallStep().dependOn(&install_exe.step);
    b.installDirectory(.{
        .source_dir = std.Build.LazyPath.relative("lib"),
        .install_dir = .bin,
        .install_subdir = "lib",
    });

    const compiler_exe_path = b.fmt("zig-out/bin/{s}", .{install_exe.dest_sub_path});
    const run_command = b.addSystemCommand(&.{compiler_exe_path});
    run_command.step.dependOn(b.getInstallStep());

    const debug_command = switch (@import("builtin").os.tag) {
        .linux => blk: {
            const result = b.addSystemCommand(&.{"gf2"});
            result.addArgs(&.{ "-ex", "set disassembly-flavor intel" });
            result.addArg("-ex=r");
            result.addArgs(&.{ "-ex", "up" });
            result.addArg("--args");
            break :blk result;
        },
        .windows => blk: {
            const result = b.addSystemCommand(&.{"remedybg"});
            result.addArg("-g");
            result.addArg(compiler_exe_path);

            break :blk result;
        },
        .macos => blk: {
            // not tested
            const result = b.addSystemCommand(&.{"lldb"});
            result.addArg("--");
            result.addArg(compiler_exe_path);
            break :blk result;
        },
        else => @compileError("OS not supported"),
    };
    debug_command.step.dependOn(b.getInstallStep());
    debug_command.addArg(compiler_exe_path);

    if (b.args) |args| {
        run_command.addArgs(args);
        debug_command.addArgs(args);
    }

    const run_step = b.step("run", "Test the Nativity compiler");
    run_step.dependOn(&run_command.step);
    const debug_step = b.step("debug", "Debug the Nativity compiler");
    debug_step.dependOn(&debug_command.step);
}
