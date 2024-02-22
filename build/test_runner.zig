const std = @import("std");
const Allocator = std.mem.Allocator;

const TestError = error{
    junk_in_test_directory,
    abnormal_exit_code,
    signaled,
    stopped,
    unknown,
    fail,
};

fn collectDirectoryDirEntries(allocator: Allocator, path: []const u8) ![]const []const u8{
    var dir = try std.fs.cwd().openDir(path, .{
        .iterate = true,
    });
    var dir_iterator = dir.iterate();
    var dir_entries = std.ArrayListUnmanaged([]const u8){};

    while (try dir_iterator.next()) |entry| {
        switch (entry.kind) {
            .directory => try dir_entries.append(allocator, try allocator.dupe(u8, entry.name)),
            else => return error.junk_in_test_directory,
        }
    }

    dir.close();

    return dir_entries.items;
}

fn runStandaloneTests(allocator: Allocator) !void {
    const standalone_test_dir_path = "test/standalone";
    const standalone_test_names = try collectDirectoryDirEntries(allocator, standalone_test_dir_path);

    const total_compilation_count = standalone_test_names.len;
    var ran_compilation_count: usize = 0;
    var failed_compilation_count: usize = 0;

    var ran_test_count: usize = 0;
    var failed_test_count: usize = 0;
    const total_test_count = standalone_test_names.len;

    for (standalone_test_names) |standalone_test_name| {
        std.debug.print("{s}... ", .{standalone_test_name});
        const source_file_path = try std.mem.concat(allocator, u8, &.{standalone_test_dir_path, "/", standalone_test_name, "/main.nat"});
        const compile_run = try std.ChildProcess.run(.{
            .allocator = allocator, 
            // TODO: delete -main_source_file?
            .argv = &.{"zig-out/bin/nat", "exe", "-main_source_file", source_file_path},
        });
        ran_compilation_count += 1;

        const compilation_result: TestError!bool = switch (compile_run.term) {
            .Exited => |exit_code| if (exit_code == 0) true else error.abnormal_exit_code,
            .Signal => error.signaled,
            .Stopped => error.stopped,
            .Unknown => error.unknown,
        };

        const compilation_success = compilation_result catch b: {
            failed_compilation_count += 1;
            break :b false;
        };

        std.debug.print("[COMPILATION {s}] ", .{if (compilation_success) "\x1b[32mOK\x1b[0m" else "\x1b[31mFAILED\x1b[0m"});
        if (compile_run.stdout.len > 0) {
            std.debug.print("STDOUT:\n\n{s}\n\n", .{compile_run.stdout});
        }
        if (compile_run.stderr.len > 0) {
            std.debug.print("STDERR:\n\n{s}\n\n", .{compile_run.stderr});
        }

        if (compilation_success) {
            const test_path = try std.mem.concat(allocator, u8, &.{"nat/", standalone_test_name});
            const test_run = try std.ChildProcess.run(.{
                .allocator = allocator, 
                // TODO: delete -main_source_file?
                .argv = &.{ test_path },
            });
            ran_test_count += 1;
            const test_result: TestError!bool = switch (test_run.term) {
                .Exited => |exit_code| if (exit_code == 0) true else error.abnormal_exit_code,
                .Signal => error.signaled,
                .Stopped => error.stopped,
                .Unknown => error.unknown,
            };

            const test_success = test_result catch b: {
                failed_test_count += 1;
                break :b false;
            };
            std.debug.print("[TEST {s}]\n", .{if (test_success) "\x1b[32mOK\x1b[0m" else "\x1b[31mFAILED\x1b[0m"});
            if (test_run.stdout.len > 0) {
                std.debug.print("STDOUT:\n\n{s}\n\n", .{test_run.stdout});
            }
            if (test_run.stderr.len > 0) {
                std.debug.print("STDERR:\n\n{s}\n\n", .{test_run.stderr});
            }
        } else {
            std.debug.print("\n", .{});
        }
    }

    std.debug.print("\nTOTAL COMPILATIONS: {}. FAILED: {}\n", .{total_compilation_count, failed_compilation_count});
    std.debug.print("TOTAL TESTS: {}. RAN: {}. FAILED: {}\n", .{total_test_count, ran_test_count, failed_test_count});

    if (failed_compilation_count > 0 or failed_test_count > 0) {
        return error.fail;
    }
}

fn runBuildTests(allocator: Allocator) !void {
    std.debug.print("\n[BUILD TESTS]\n\n", .{});
    const test_dir_path = "test/build";
    const test_names = try collectDirectoryDirEntries(allocator, test_dir_path);
    const test_dir_realpath = try std.fs.cwd().realpathAlloc(allocator, test_dir_path);
    const compiler_realpath = try std.fs.cwd().realpathAlloc(allocator, "zig-out/bin/nat");
    try std.os.chdir(test_dir_realpath);

    const total_compilation_count = test_names.len;
    var ran_compilation_count: usize = 0;
    var failed_compilation_count: usize = 0;

    var ran_test_count: usize = 0;
    var failed_test_count: usize = 0;
    const total_test_count = test_names.len;

    for (test_names) |test_name| {
        std.debug.print("{s}... ", .{test_name});
        try std.os.chdir(test_name);

        const compile_run = try std.ChildProcess.run(.{
            .allocator = allocator, 
            // TODO: delete -main_source_file?
            .argv = &.{compiler_realpath, "build"},
        });

        ran_compilation_count += 1;

        const compilation_result: TestError!bool = switch (compile_run.term) {
            .Exited => |exit_code| if (exit_code == 0) true else error.abnormal_exit_code,
            .Signal => error.signaled,
            .Stopped => error.stopped,
            .Unknown => error.unknown,
        };

        const compilation_success = compilation_result catch b: {
            failed_compilation_count += 1;
            break :b false;
        };

        std.debug.print("[COMPILATION {s}] ", .{if (compilation_success) "\x1b[32mOK\x1b[0m" else "\x1b[31mFAILED\x1b[0m"});
        if (compile_run.stdout.len > 0) {
            std.debug.print("STDOUT:\n\n{s}\n\n", .{compile_run.stdout});
        }
        if (compile_run.stderr.len > 0) {
            std.debug.print("STDERR:\n\n{s}\n\n", .{compile_run.stderr});
        }

        if (compilation_success) {
            const test_path = try std.mem.concat(allocator, u8, &.{"nat/", test_name});
            const test_run = try std.ChildProcess.run(.{
                .allocator = allocator, 
                // TODO: delete -main_source_file?
                .argv = &.{ test_path },
            });
            ran_test_count += 1;
            const test_result: TestError!bool = switch (test_run.term) {
                .Exited => |exit_code| if (exit_code == 0) true else error.abnormal_exit_code,
                .Signal => error.signaled,
                .Stopped => error.stopped,
                .Unknown => error.unknown,
            };

            const test_success = test_result catch b: {
                failed_test_count += 1;
                break :b false;
            };
            std.debug.print("[TEST {s}]\n", .{if (test_success) "\x1b[32mOK\x1b[0m" else "\x1b[31mFAILED\x1b[0m"});
            if (test_run.stdout.len > 0) {
                std.debug.print("STDOUT:\n\n{s}\n\n", .{test_run.stdout});
            }
            if (test_run.stderr.len > 0) {
                std.debug.print("STDERR:\n\n{s}\n\n", .{test_run.stderr});
            }
        } else {
            std.debug.print("\n", .{});
        }

        try std.os.chdir(test_dir_realpath);
    }

    std.debug.print("\nTOTAL COMPILATIONS: {}. FAILED: {}\n", .{total_compilation_count, failed_compilation_count});
    std.debug.print("TOTAL TESTS: {}. RAN: {}. FAILED: {}\n", .{total_test_count, ran_test_count, failed_test_count});

    if (failed_compilation_count > 0 or failed_test_count > 0) {
        return error.fail;
    }
}

pub fn main() !void {
    std.debug.print("\n",.{});
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const allocator = arena.allocator();
    try runStandaloneTests(allocator);
    try runBuildTests(allocator);
}
