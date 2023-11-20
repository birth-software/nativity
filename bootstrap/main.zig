const std = @import("std");
const Allocator = std.mem.Allocator;

const Compilation = @import("Compilation.zig");
pub const panic = Compilation.panic;

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    try Compilation.init(allocator);
}

test {
    _ = Compilation;
}
