const std = @import("std");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;

const Compilation = @import("Compilation.zig");

pub const seed = std.math.maxInt(u64);
const default_src_file = "src/test/main.nat";

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    const arguments = try std.process.argsAlloc(allocator);
    if (arguments.len == 2) {
        try singleCompilation(allocator, arguments[1]);
    } else {
        @panic("Wrong arguments");
    }
}

fn singleCompilation(allocator: Allocator, main_file_path: []const u8) !void {
    const compilation = try Compilation.init(allocator);

    try compilation.compileModule(.{
        .main_package_path = main_file_path,
    });
}

test {
    _ = Compilation;
}
