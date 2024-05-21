const std = @import("std");
const assert = std.debug.assert;

const builtin = @import("builtin");

const library = @import("library.zig");
const byte_equal = library.byte_equal;

const configuration = @import("configuration");
const editor = @import("editor.zig");
const compiler = @import("compiler.zig");
pub const panic = compiler.panic;

const env_detecting_libc_paths = "NATIVITY_IS_DETECTING_LIBC_PATHS";

test {
    _ = library;
}

pub fn main() !void {
    if (configuration.editor) {
        editor.main();
    } else {
        compiler.main();
    }
}

pub const std_options = std.Options{
    .enable_segfault_handler = false,
};
