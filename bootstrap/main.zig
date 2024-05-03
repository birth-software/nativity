const std = @import("std");
const assert = std.debug.assert;

const Compilation = @import("Compilation.zig");
pub const panic = Compilation.panic;

const library = @import("library.zig");
const byte_equal = library.byte_equal;

const configuration = @import("configuration");
const editor = @import("editor.zig");
const compiler = @import("compiler.zig");

const env_detecting_libc_paths = "NATIVITY_IS_DETECTING_LIBC_PATHS";

test {
    _ = library;
}

fn todo() noreturn {
    @setCold(true);
    @panic("TODO");
}

pub fn main() !void {
    if (configuration.editor) {
        editor.main();
    } else {
        compiler.make();
        // var arg_iterator = std.process.ArgIterator.init();
        // var buffer = library.BoundedArray([]const u8, 512){};
        // while (arg_iterator.next()) |argument| {
        //     buffer.appendAssumeCapacity(argument);
        // }
        // const arguments = buffer.slice();
        // const context = try Compilation.createContext();
        //
        // if (arguments.len <= 1) {
        //     return error.InvalidInput;
        // }
        //
        // if (std.process.can_execv and std.posix.getenvZ(env_detecting_libc_paths) != null) {
        //     todo();
        // }
        //
        // const command = arguments[1];
        // const command_arguments = arguments[2..];
        //
        // if (byte_equal(command, "build")) {
        //     try Compilation.compileBuildExecutable(context, command_arguments);
        // } else if (byte_equal(command, "clang") or byte_equal(command, "-cc1") or byte_equal(command, "-cc1as")) {
        //     const exit_code = try Compilation.clangMain(context.arena, arguments);
        //     std.process.exit(exit_code);
        // } else if (byte_equal(command, "cc")) {
        //     try Compilation.compileCSourceFile(context, command_arguments, .c);
        // } else if (byte_equal(command, "c++")) {
        //     try Compilation.compileCSourceFile(context, command_arguments, .cpp);
        // } else if (byte_equal(command, "exe")) {
        //     try Compilation.buildExecutable(context, command_arguments, .{
        //         .is_test = false,
        //     });
        // } else if (byte_equal(command, "lib")) {
        //     todo();
        // } else if (byte_equal(command, "obj")) {
        //     todo();
        // } else if (byte_equal(command, "test")) {
        //     try Compilation.buildExecutable(context, command_arguments, .{
        //         .is_test = true,
        //     });
        // } else {
        //     todo();
        // }
    }
}

pub const std_options = std.Options{
    .enable_segfault_handler = false,
};


