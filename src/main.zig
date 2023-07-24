const std = @import("std");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;

const fs = @import("fs.zig");

const lexer = @import("lexer.zig");
const parser = @import("parser.zig");
const ir = @import("ir.zig");
const emit = @import("emit.zig");

pub const seed = std.math.maxInt(u64);

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    try behaviorTest(allocator, fs.first);
}

fn behaviorTest(allocator: Allocator, file_relative_path: []const u8) !void {
    const file = try fs.readFile(allocator, file_relative_path);
    var lexer_result = try lexer.runTest(allocator, file);
    defer lexer_result.free(allocator);
    var parser_result = parser.runTest(allocator, &lexer_result) catch |err| {
        std.log.err("Lexer took {} ns", .{lexer_result.time});
        return err;
    };
    defer parser_result.free(allocator);
    var ir_result = try ir.runTest(allocator, &parser_result);
    defer ir_result.free(allocator);
    var emit_result = try emit.runTest(allocator, &ir_result);
    defer emit_result.free(allocator);
}

test {
    _ = lexer;
    _ = parser;
    _ = ir;
    _ = emit;
}

test "behavior test 1" {
    const allocator = std.testing.allocator;
    try behaviorTest(allocator, fs.first);
}
