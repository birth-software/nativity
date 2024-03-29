const std = @import("std");
const Allocator = std.mem.Allocator;

const TestError = error{
    junk_in_test_directory,
    abnormal_exit_code,
    signaled,
    stopped,
    unknown,
    internal,
    fail,
};

const TestGroup = struct {
    state: States = .{},
    tests: std.ArrayListUnmanaged(TestRecord) = .{},
    path: []const u8,
    path_policy: PathPolicy,
    category: Category,
    compilation_kind: CompilationKind,
    collect_directory_entries: ?[]const []const u8,

    const PathPolicy = enum {
        join_path,
        take_entry,
    };

    const CompilationKind = enum {
        exe,
        @"test",
        build,
        cmake,
    };
};

const TestRecord = struct {
    name: []const u8,
    configuration: ?TestResult = null,
    compilation: ?TestResult = null,
    execution: ?TestResult = null,
};

const TestResult = struct {
    stdout: []const u8 = &.{},
    stderr: []const u8 = &.{},
    error_union: RunError!void,
};

// const TestStep = struct{
//     kind: Kind,
//     result: TestResult,
//
//     const Kind = enum{
//         configuration,
//         compilation,
//         execution,
//     };
// };

const States = struct {
    failed: TestState = .{},
    total: TestState = .{},
};

const TestState = struct {
    compilations: u32 = 0,
    executions: u32 = 0,
    tests: u32 = 0,

    fn add(total: *TestState, state: *const TestState) void {
        total.compilations += state.compilations;
        total.executions += state.executions;
        total.tests += state.tests;
    }
};

const TestSuite = struct {
    allocator: Allocator,
    state: State = .{},
    compiler_path: []const u8,

    const State = struct {
        states: States = .{},
        category_map: std.EnumSet(Category) = .{},
        test_groups: std.ArrayListUnmanaged(TestGroup) = .{},
    };

    fn run_test_group(test_suite: *TestSuite, test_group: *TestGroup) !void {
        test_suite.state.category_map.setPresent(test_group.category, true);
        defer {
            test_suite.state.states.total.add(&test_group.state.total);
            test_suite.state.states.failed.add(&test_group.state.failed);
        }

        if (test_group.collect_directory_entries) |*directory_entries| {
            directory_entries.* = blk: {
                var dir = try std.fs.cwd().openDir(test_group.path, .{
                    .iterate = true,
                });
                var dir_iterator = dir.iterate();
                var dir_entries = std.ArrayListUnmanaged([]const u8){};

                while (try dir_iterator.next()) |entry| {
                    switch (entry.kind) {
                        .directory => try dir_entries.append(test_suite.allocator, try test_suite.allocator.dupe(u8, entry.name)),
                        else => return error.junk_in_test_directory,
                    }
                }

                dir.close();

                break :blk dir_entries.items;
            };
        } else {
            test_group.collect_directory_entries = &.{ test_group.path };
        }

        const directory_entries = test_group.collect_directory_entries orelse unreachable;
        try test_group.tests.ensureTotalCapacity(test_suite.allocator, directory_entries.len);

        for (directory_entries) |directory_entry| {
            var has_error = false;
            test_group.state.total.tests += 1;

            const relative_path = try std.mem.concat(test_suite.allocator, u8, &.{ test_group.path, "/", directory_entry });

            var test_record = TestRecord{
                .name = directory_entry,
            };

            const cmake_build_dir = "build";
            switch (test_group.category) {
                .cmake => {
                    const argv: []const []const u8 = &.{
                        "cmake",
                        "-S", ".",
                        "-B", cmake_build_dir,
                        "--fresh",
                        try std.fmt.allocPrint(test_suite.allocator, "-DCMAKE_C_COMPILER={s};cc", .{test_suite.compiler_path}),
                        try std.fmt.allocPrint(test_suite.allocator, "-DCMAKE_CXX_COMPILER={s};c++", .{test_suite.compiler_path}),
                        try std.fmt.allocPrint(test_suite.allocator, "-DCMAKE_ASM_COMPILER={s};cc", .{test_suite.compiler_path}),
                    };
                    test_record.configuration = try run_process(test_suite.allocator, argv, .{ .path = relative_path });
                    test_record.configuration.?.error_union catch {
                        has_error = true;
                        test_group.state.total.compilations += 1;
                        test_group.state.failed.compilations += 1;
                    };
                },
                .build, .standalone => {},
            }

            if (!has_error) {
                const compilation_cwd: Cwd = switch (test_group.category) {
                    .standalone => .none,
                    .build => .{ .path = relative_path },
                    .cmake => .{ .path = try std.mem.concat(test_suite.allocator, u8, &.{ relative_path, "/" ++ cmake_build_dir }) },
                };

                const arguments: []const []const u8 = switch (test_group.category) {
                    .standalone => blk: {
                        const source_file_path = switch (test_group.path_policy) {
                            .join_path => try std.mem.concat(test_suite.allocator, u8, &.{ test_group.path, "/", directory_entry, "/main.nat" }),
                            .take_entry => directory_entry,
                        };
                        const compilation_argument = @tagName(test_group.compilation_kind);
                        break :blk &.{ test_suite.compiler_path, compilation_argument, "-main_source_file", source_file_path };
                    },
                    .build => &.{ test_suite.compiler_path, "build" },
                    .cmake => &.{ "ninja" },
                };

                test_record.compilation = try run_process(test_suite.allocator, arguments, compilation_cwd);
                test_group.state.total.compilations += 1;

                if (test_record.compilation.?.error_union) |_| {
                    const executable_name = switch (test_group.path_policy) {
                        .join_path => directory_entry,
                        .take_entry => b: {
                            const slash_index = std.mem.lastIndexOfScalar(u8, directory_entry, '/') orelse unreachable;
                            const base = std.fs.path.basename(directory_entry[0..slash_index]);
                            break :b base;
                        },
                    };
                    const build_dir = switch (test_group.category) {
                        .cmake => cmake_build_dir ++ "/",
                        else => "nat/",
                    };
                    const execution_cwd: Cwd = switch (test_group.category) {
                        .cmake => .{ .path = relative_path },
                        else => compilation_cwd,
                    };
                    test_record.execution = try run_process(test_suite.allocator, &.{try std.mem.concat(test_suite.allocator, u8, &.{ build_dir, executable_name })}, execution_cwd);
                    test_group.state.total.executions += 1;

                    if (test_record.execution.?.error_union) |_| {} else |err| {
                        has_error = true;
                        err catch {};
                        test_group.state.failed.executions += 1;
                    }
                } else |err| {
                    err catch {};
                    has_error = true;
                    test_group.state.failed.compilations += 1;
                }
            }

                test_group.state.failed.tests += @intFromBool(has_error);

                test_group.tests.appendAssumeCapacity(test_record);
        }
    }
};

const RunError = error{
    unexpected_exit_code,
    signaled,
    stopped,
    unknown,
};

const Cwd = union(enum) {
    none,
    path: []const u8,
    descriptor: std.fs.Dir,
};

fn run_process(allocator: Allocator, argv: []const []const u8, cwd: Cwd) !TestResult {
    var path: ?[]const u8 = null;
    var descriptor: ?std.fs.Dir = null;
    switch (cwd) {
        .none => {},
        .path => |p| path = p,
        .descriptor => |d| descriptor = d,
    }
    const process_result = try std.ChildProcess.run(.{
        .allocator = allocator,
        .argv = argv,
        .max_output_bytes = std.math.maxInt(usize),
        .cwd = path,
        .cwd_dir = descriptor,
    });

    return TestResult{
        .stdout = process_result.stdout,
        .stderr = process_result.stderr,
        .error_union = switch (process_result.term) {
            .Exited => |exit_code| if (exit_code == 0) {} else error.unexpected_exit_code,
            .Signal => error.signaled,
            .Stopped => error.stopped,
            .Unknown => error.unknown,
        },
    };
}

const Category = enum {
    standalone,
    build,
    cmake,
};

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const allocator = arena.allocator();
    const compiler_relative_path = "zig-out/bin/nat";
    
    var test_suite = TestSuite{
        .allocator = allocator,
        .compiler_path = try std.fs.realpathAlloc(allocator, compiler_relative_path),
    };
    var test_groups = [_]TestGroup{
        .{
            .category = .standalone,
            .path = "test/standalone",
            .collect_directory_entries = &.{},
            .path_policy = .join_path,
            .compilation_kind = .exe,
        },
        .{
            .category = .standalone,
            .path = "test/tests",
            .collect_directory_entries = &.{},
            .path_policy = .join_path,
            .compilation_kind = .@"test",
        },
        .{
            .category = .standalone,
            .path = "lib/std/std.nat",
            .collect_directory_entries = null,
            .path_policy = .take_entry,
            .compilation_kind = .@"test",
        },
        .{
            .category = .build,
            .path = "test/build",
            .collect_directory_entries = &.{},
            .path_policy = .join_path,
            .compilation_kind = .@"exe",
        },
        .{
            .category = .cmake,
            .path = "test/cc",
            .collect_directory_entries = &.{},
            .path_policy = .join_path,
            .compilation_kind = .cmake,
        },
        .{
            .category = .cmake,
            .path = "test/c++",
            .collect_directory_entries = &.{},
            .path_policy = .join_path,
            .compilation_kind = .cmake,
        },
    } ++ switch (@import("builtin").os.tag) {
        .linux => [_]TestGroup{
            .{
                .category = .cmake,
                .path = "test/cc_linux",
                .collect_directory_entries = &.{},
                .path_policy = .join_path,
                .compilation_kind = .cmake,
            },
        },
        else => [_]TestGroup{},
    };

    for (&test_groups) |*test_group| {
        try test_suite.run_test_group(test_group);
    }

    const stdout = std.io.getStdOut();
    const stdout_writer = stdout.writer();
    var io_buffer = std.io.BufferedWriter(16 * 0x1000, @TypeOf(stdout_writer)){ .unbuffered_writer = stdout_writer };
    const io_writer = io_buffer.writer();
    try io_writer.writeByte('\n');

    for (&test_groups) |*test_group| {
        if (test_group.state.failed.tests > 0) {
            for (test_group.tests.items) |*test_result| {
                try io_writer.print("{s}\n", .{test_result.name});

                if (test_result.configuration) |result| {
                    if (result.stdout.len > 0) {
                        try io_writer.writeAll(result.stdout);
                        try io_writer.writeByte('\n');
                    }

                    if (result.stderr.len > 0) {
                        try io_writer.writeAll(result.stderr);
                        try io_writer.writeByte('\n');
                    }
                }

                if (test_result.compilation) |result| {
                    if (result.stdout.len > 0) {
                        try io_writer.writeAll(result.stdout);
                        try io_writer.writeByte('\n');
                    }

                    if (result.stderr.len > 0) {
                        try io_writer.writeAll(result.stderr);
                        try io_writer.writeByte('\n');
                    }
                }

                if (test_result.execution) |result| {
                    if (result.stdout.len > 0) {
                        try io_writer.writeAll(result.stdout);
                        try io_writer.writeByte('\n');
                    }

                    if (result.stderr.len > 0) {
                        try io_writer.writeAll(result.stderr);
                        try io_writer.writeByte('\n');
                    }
                }
            }
        }

        try io_writer.print("[{s}] [{s}] Ran {} tests ({} failed). Ran {} compilations ({} failed). Ran {} executions ({} failed).\n", .{
            @tagName(test_group.category),
            test_group.path,
            test_group.state.total.tests,
            test_group.state.failed.tests,
            test_group.state.total.compilations,
            test_group.state.failed.compilations,
            test_group.state.total.executions,
            test_group.state.failed.executions,
        });
    }

    try io_writer.print("Ran {} tests ({} failed). Ran {} compilations ({} failed). Ran {} executions ({} failed).\n", .{
        test_suite.state.states.total.tests,
        test_suite.state.states.failed.tests,
        test_suite.state.states.total.compilations,
        test_suite.state.states.failed.compilations,
        test_suite.state.states.total.executions,
        test_suite.state.states.failed.executions,
    });

    const success = test_suite.state.states.failed.tests == 0;
    if (success) {
        try io_writer.writeAll("\x1b[32mTESTS PASSED!\x1b[0m\n");
    } else {
        try io_writer.writeAll("\x1b[31mTESTS FAILED!\x1b[0m\n");
    }

    try io_buffer.flush();

    if (!success) {
        std.posix.exit(1);
    }
}
