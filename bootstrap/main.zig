const std = @import("std");
const Allocator = std.mem.Allocator;

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
pub export fn main(c_argc: c_int, c_argv: [*][*:0]c_char, c_envp: [*:null]?[*:0]c_char) callconv(.C) c_int {
    _ = c_envp; // autofix
    const argument_count: usize = @intCast(c_argc);
    const argument_values: [*][*:0]u8 = @ptrCast(c_argv);
    const arguments = argument_values[0..argument_count];
    if (entry_point(arguments)) |_| {
        return 0;
    } else |err| {
        const error_name: []const u8 = @errorName(err);
        Compilation.write(.panic, "Error: ") catch {};
        Compilation.write(.panic, error_name) catch {};
        Compilation.write(.panic, "\n") catch {};
        return 1;
    }
}

pub fn entry_point(arguments: [][*:0]u8) !void {
    var arena_allocator = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const allocator = arena_allocator.allocator();
    // const arguments = try std.process.argsAlloc(allocator);

    if (arguments.len <= 1) {
        return error.InvalidInput;
    }

    if (std.process.can_execv and std.os.getenvZ(env_detecting_libc_paths) != null) {
        todo();
    }

    const command = library.span(arguments[1]);
    const command_arguments = arguments[2..];

    const context = try Compilation.createContext(allocator, &my_allocator.allocator);
    if (byte_equal(command, "build")) {
        try Compilation.compileBuildExecutable(context, command_arguments);
    } else if (byte_equal(command, "clang") or byte_equal(command, "-cc1") or byte_equal(command, "-cc1as")) {
        // const exit_code = try clangMain(allocator, arguments);
        // std.process.exit(exit_code);
    } else if (byte_equal(command, "cc")) {
        // TODO: transform our arguments to Clang and invoke it
        try Compilation.compileCSourceFile(context, command_arguments);
    } else if (byte_equal(command, "c++")) {
        // TODO: transform our arguments to Clang and invoke it
        todo();
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
