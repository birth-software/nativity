const std = @import("std");

const Allocator = std.mem.Allocator;

const data_structures = @import("data_structures.zig");

const lexer = @import("lexer.zig");
const parser = @import("parser.zig");

test {
    _ = lexer;
    _ = parser;
}

pub fn cycle(allocator: Allocator, file_relative_path: []const u8) !void {
    const file = try std.fs.cwd().readFileAlloc(allocator, file_relative_path, std.math.maxInt(usize));
    std.debug.print("File:\n\n```\n{s}\n```\n", .{file});
    const lexer_result = try lexer.lex(allocator, file);
    const parser_result = try parser.parse(allocator, &lexer_result);
    _ = parser_result;
}
