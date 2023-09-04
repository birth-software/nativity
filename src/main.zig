const std = @import("std");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;

const compiler = @import("compiler.zig");
const fs = @import("fs.zig");

pub const seed = std.math.maxInt(u64);

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    try compiler.cycle(allocator, fs.first);
}

test {
    _ = compiler;
}
