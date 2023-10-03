const std = @import("std");
var all: bool = false;

fn everythingForTargetAndOptimization(b: *std.Build, target: std.zig.CrossTarget, optimization: std.builtin.OptimizeMode, unit_tests: []const []const u8, test_step: *std.Build.Step) !void {
    const name = if (all) try std.mem.concat(b.allocator, u8, &.{ "nativity_", @tagName(optimization) }) else "nativity";
    const exe = b.addExecutable(.{
        .name = name,
        .root_source_file = .{ .path = "src/main.zig" },
        .target = target,
        .optimize = optimization,
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

    const run_step = b.step(if (all) try std.mem.concat(b.allocator, u8, &.{ "run_", @tagName(optimization) }) else "run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    const debug_command = addDebugCommand(b, exe);
    const debug_step = b.step(if (all) try std.mem.concat(b.allocator, u8, &.{ "debug_", @tagName(optimization) }) else "debug", "Debug the app");
    debug_step.dependOn(&debug_command.step);

    const zig_tests = b.addTest(.{
        .root_source_file = .{ .path = "src/main.zig" },
        .target = target,
        .optimize = optimization,
    });

    const run_zig_tests = b.addRunArtifact(zig_tests);
    run_zig_tests.has_side_effects = true;
    test_step.dependOn(&run_zig_tests.step);

    for (unit_tests) |unit_test_main_source_file| {
        const unit_test = b.addRunArtifact(exe);
        unit_test.has_side_effects = true;
        unit_test.addArg(unit_test_main_source_file);
        test_step.dependOn(&unit_test.step);
    }
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

pub fn build(b: *std.Build) !void {
    all = b.option(bool, "all", "All") orelse false;

    var unit_test_list = std.ArrayList([]const u8).init(b.allocator);
    var test_dir = try std.fs.cwd().openIterableDir("test", .{ .access_sub_paths = true });
    defer test_dir.close();

    var test_dir_iterator = test_dir.iterate();

    while (try test_dir_iterator.next()) |entry| {
        switch (entry.kind) {
            .directory => {
                const dir_name = entry.name;
                const main_unit_test_source_file = try std.mem.concat(b.allocator, u8, &.{ "test/", dir_name, "/main.nat" });
                try unit_test_list.append(main_unit_test_source_file);
            },
            .file => {},
            else => @panic("Don't put crap on test directory"),
        }
    }

    const target = b.standardTargetOptions(.{});
    const unit_tests = unit_test_list.items;
    const test_step = b.step("test", "Test the Nativity compiler");

    if (all) {
        inline for (@typeInfo(std.builtin.OptimizeMode).Enum.fields) |enum_field| {
            const optimization = @field(std.builtin.OptimizeMode, enum_field.name);
            try everythingForTargetAndOptimization(b, target, optimization, unit_tests, test_step);
        }
    } else {
        const optimization = b.standardOptimizeOption(.{});
        _ = try everythingForTargetAndOptimization(b, target, optimization, unit_tests, test_step);
    }
}
