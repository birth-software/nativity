const std = @import("std");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;

const Compilation = @import("Compilation.zig");
pub const panic = Compilation.panic;

const library = @import("library.zig");
const byte_equal = library.byte_equal;
const MyAllocator = library.MyAllocator;
const PageAllocator = library.PageAllocator;

const env_detecting_libc_paths = "NATIVITY_IS_DETECTING_LIBC_PATHS";

test {
    _ = library;
}

fn todo() noreturn {
    @setCold(true);
    @panic("TODO");
}

var my_allocator = PageAllocator{};

pub fn main() !void {
    var arena_allocator = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const allocator = arena_allocator.allocator();
    var arg_it = try std.process.ArgIterator.initWithAllocator(allocator);
    var args = library.UnpinnedArray([]const u8){};
    const context = try Compilation.createContext(allocator, &my_allocator.allocator);
    while (arg_it.next()) |arg| {
        try args.append(context.my_allocator, arg);
    }
    const arguments = args.slice();
    const debug_args = false;
    if (debug_args and @import("builtin").os.tag != .windows) {
        assert(arguments.len > 0);
        const home_dir = std.posix.getenv("HOME") orelse unreachable;
        const timestamp = std.time.milliTimestamp();
        var argument_list = std.ArrayList(u8).init(std.heap.page_allocator);
        for (arguments) |arg| {
            argument_list.appendSlice(arg) catch {};
            argument_list.append(' ') catch {};
        }
        argument_list.append('\n') catch {};
        std.fs.cwd().writeFile(std.fmt.allocPrint(std.heap.page_allocator, "{s}/dev/nativity/nat/invocation_log_{}", .{ home_dir, timestamp }) catch unreachable, argument_list.items) catch {};
    }

    if (arguments.len <= 1) {
        return error.InvalidInput;
    }

    if (std.process.can_execv and std.posix.getenvZ(env_detecting_libc_paths) != null) {
        todo();
    }

    const command = arguments[1];
    const command_arguments = arguments[2..];

    if (byte_equal(command, "build")) {
        try Compilation.compileBuildExecutable(context, command_arguments);
    } else if (byte_equal(command, "clang") or byte_equal(command, "-cc1") or byte_equal(command, "-cc1as")) {
        const exit_code = try Compilation.clangMain(allocator, arguments);
        std.process.exit(exit_code);
    } else if (byte_equal(command, "cc")) {
        try Compilation.compileCSourceFile(context, command_arguments, .c);
    } else if (byte_equal(command, "c++")) {
        try Compilation.compileCSourceFile(context, command_arguments, .cpp);
    } else if (byte_equal(command, "exe")) {
        try Compilation.buildExecutable(context, command_arguments, .{
            .is_test = false,
        });
    } else if (byte_equal(command, "lib")) {
        todo();
    } else if (byte_equal(command, "obj")) {
        todo();
    } else if (byte_equal(command, "test")) {
        try Compilation.buildExecutable(context, command_arguments, .{
            .is_test = true,
        });
    } else {
        todo();
    }
}

pub const std_options = std.Options{
    .enable_segfault_handler = false,
};
