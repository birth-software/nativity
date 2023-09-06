const std = @import("std");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;
const log = std.log;

const equal = std.mem.eql;

const data_structures = @import("../data_structures.zig");
const ArrayList = data_structures.ArrayList;

const Compilation = @import("../Compilation.zig");
const fs = @import("../fs.zig");

pub const Token = packed struct(u64) {
    start: u32,
    len: u24,
    id: Id,

    pub const Id = enum(u8) {
        identifier = 0,
        number = 1,
        string_literal = 2,
        left_parenthesis = '(',
        right_parenthesis = ')',
        left_brace = '{',
        right_brace = '}',
        equal = '=',
        colon = ':',
        semicolon = ';',
        hash = '#',
        comma = ',',
        bang = '!',
    };
};

pub const Result = struct {
    tokens: ArrayList(Token),
    time: u64,

    pub fn free(result: *Result, allocator: Allocator) void {
        result.tokens.clearAndFree(allocator);
    }
};

pub fn analyze(allocator: Allocator, text: []const u8) !Result {
    const time_start = std.time.Instant.now() catch unreachable;
    var tokens = try ArrayList(Token).initCapacity(allocator, text.len / 8);
    var index: usize = 0;

    while (index < text.len) {
        const start_index = index;
        const start_character = text[index];
        const token_id: Token.Id = switch (start_character) {
            'a'...'z', 'A'...'Z', '_' => blk: {
                while (true) {
                    const ch = text[index];
                    if ((ch >= 'a' and ch <= 'z') or (ch >= 'A' and ch <= 'Z') or ch == '_' or (ch >= '0' and ch <= '9')) {
                        index += 1;
                        continue;
                    }

                    break;
                }

                break :blk .identifier;
            },
            '(', ')', '{', '}', '-', '=', ';', '#' => |operator| blk: {
                index += 1;
                break :blk @enumFromInt(operator);
            },
            '0'...'9' => blk: {
                while (text[index] >= '0' and text[index] <= '9') {
                    index += 1;
                }

                break :blk .number;
            },
            '"' => blk: {
                index += 1;
                while (text[index] != '"') {
                    index += 1;
                }

                index += 1;

                break :blk .string_literal;
            },
            ' ', '\n', '\r', '\t' => {
                index += 1;
                continue;
            },
            else => |foo| {
                std.debug.panic("NI: '{c}'", .{foo});
            },
        };

        const end_index = index;

        try tokens.append(allocator, .{
            .start = @intCast(start_index),
            .len = @intCast(end_index - start_index),
            .id = token_id,
        });
    }

    const should_log = false;
    if (should_log) {
        for (tokens.items, 0..) |token, i| {
            std.debug.print("#{} {s}\n", .{ i, @tagName(token.id) });
        }
    }

    const time_end = std.time.Instant.now() catch unreachable;
    const time = time_end.since(time_start);

    return .{
        .tokens = tokens,
        .time = time,
    };
}
