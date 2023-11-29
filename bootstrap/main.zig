const std = @import("std");
const Allocator = std.mem.Allocator;

const Compilation = @import("Compilation.zig");
pub const panic = Compilation.panic;

pub fn main() !void {
    const GPA = std.heap.GeneralPurposeAllocator(.{});
    var gpa = GPA{};

    try Compilation.init(gpa.allocator());
}

test {
    _ = Compilation;
}
