const std = @import("std");

const TestError = error{
    junk_in_test_directory,
    abnormal_exit_code,
    signaled,
    stopped,
    unknown,
    fail,
};

pub fn main() !void {
    std.debug.print("\n",.{});
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const allocator = arena.allocator();
    const standalone_test_dir_path = "test/standalone";
    var standalone_test_dir = try std.fs.cwd().openDir(standalone_test_dir_path, .{
        .iterate = true,
    });
    var standalone_iterator = standalone_test_dir.iterate();
    var standalone_test_names = std.ArrayListUnmanaged([]const u8){};

    while (try standalone_iterator.next()) |entry| {
        switch (entry.kind) {
            .directory => try standalone_test_names.append(allocator, entry.name),
            else => return error.junk_in_test_directory,
        }
    }

    standalone_test_dir.close();

    const total_compilation_count = standalone_test_names.items.len;
    var ran_compilation_count: usize = 0;
    var failed_compilation_count: usize = 0;

    var ran_test_count: usize = 0;
    var failed_test_count: usize = 0;
    const total_test_count = standalone_test_names.items.len;

    for (standalone_test_names.items) |standalone_test_name| {
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
        std.debug.print("[COMPILATION {s}] ", .{if (compilation_success) "OK" else "FAILED"});
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
            std.debug.print("[TEST {s}]\n", .{if (test_success) "OK" else "FAILED"});
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
    std.debug.print("\nTOTAL TESTS: {}. RAN: {}. FAILED: {}\n", .{total_test_count, ran_test_count, failed_test_count});

    if (failed_compilation_count > 0 or failed_test_count > 0) {
        return error.fail;
    }
}
