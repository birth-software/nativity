const std = @import("std");
pub fn main () !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const allocator = arena.allocator();
    const args = try std.process.argsAlloc(allocator);
    if (args.len < 2) return;

    const test_name = args[1];
    try std.fs.cwd().makeDir(try std.mem.concat(allocator, u8, &.{"retest/standalone/", test_name}));
    try std.fs.cwd().writeFile(.{
        .sub_path = try std.mem.concat(allocator, u8, &.{"retest/standalone/", test_name, "/main.nat"}),
        .data =
            \\fn[cc(.c)] main[export]() s32 {
            \\    return 0;
            \\}
    });
}
