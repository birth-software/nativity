const std = @import("std");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;

const Compilation = @import("Compilation.zig");
const fs = @import("fs.zig");

pub const seed = std.math.maxInt(u64);
const default_src_file = "src/test/main.b";

pub fn main() !void {
    try singleCompilation(default_src_file);
}

fn singleCompilation(main_file_path: []const u8) !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    const compilation = try Compilation.init(gpa.allocator());
    defer compilation.deinit();

    try compilation.compileModule(.{
        .main_package_path = main_file_path,
    });
}

test "basic" {
    try singleCompilation(default_src_file);
}
