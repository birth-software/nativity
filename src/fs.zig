const std = @import("std");
const Allocator = std.mem.Allocator;

pub const first = "src/test/main.b";

pub fn readFile(allocator: Allocator, file_relative_path: []const u8) ![]const u8 {
    const file = try std.fs.cwd().readFileAlloc(allocator, file_relative_path, std.math.maxInt(usize));
    return file;
}
