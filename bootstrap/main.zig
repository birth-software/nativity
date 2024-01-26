const std = @import("std");
const Allocator = std.mem.Allocator;

const Compilation = @import("Compilation.zig");
pub const panic = Compilation.panic;

pub fn main() !void {
    var arena_allocator = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    try Compilation.init(arena_allocator.allocator());
}

test {
    _ = Compilation;
}
