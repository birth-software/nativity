const std = @import("std");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;

const Compilation = @import("Compilation.zig");

pub const seed = std.math.maxInt(u64);
const default_src_file = "src/test/main.nat";

pub fn main() !void {
    try singleCompilation(default_src_file);
}

fn singleCompilation(main_file_path: []const u8) !void {
    const allocator = std.heap.page_allocator;
    const compilation = try Compilation.init(allocator);

    try compilation.compileModule(.{
        .main_package_path = main_file_path,
    });
}

test {
    _ = Compilation;
}

test "basic" {
    try singleCompilation(default_src_file);
}
