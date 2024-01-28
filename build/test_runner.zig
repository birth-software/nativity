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

    var ran_test_count: usize = 0;
    var failed_test_count: usize = 0;

    for (standalone_test_names.items) |standalone_test_name| {
        defer ran_test_count += 1;
        std.debug.print("{s}... ", .{standalone_test_name});
        const source_file_path = try std.mem.concat(allocator, u8, &.{standalone_test_dir_path, "/", standalone_test_name, "/main.nat"});
        const process_run = try std.ChildProcess.run(.{
            .allocator = allocator, 
            .argv = &.{"zig-out/bin/nat", "-main_source_file", source_file_path},
        });
        const result: TestError!bool = switch (process_run.term) {
            .Exited => |exit_code| if (exit_code == 0) true else error.abnormal_exit_code,
            .Signal => error.signaled,
            .Stopped => error.stopped,
            .Unknown => error.unknown,
        };

        const success = result catch b: {
            failed_test_count += 1;
            break :b false;
        };
        std.debug.print("[{s}]\n", .{if (success) "OK" else "FAIL"});
    }

    std.debug.print("\nTest count: {}. Failed test count: {}\n", .{ran_test_count, failed_test_count});
    if (failed_test_count > 0) {
        return error.fail;
    }
}
