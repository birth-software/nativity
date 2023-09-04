const std = @import("std");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;
const log = std.log;

const equal = std.mem.eql;

const data_structures = @import("data_structures.zig");
const ArrayList = data_structures.ArrayList;

const fs = @import("fs.zig");
const parser = @import("parser.zig");

pub const TokenTypeMap = blk: {
    var result: [@typeInfo(TokenId).Enum.fields.len]type = undefined;

    result[@intFromEnum(TokenId.identifier)] = Identifier;
    result[@intFromEnum(TokenId.operator)] = Operator;
    result[@intFromEnum(TokenId.number)] = Number;

    break :blk result;
};

pub const Identifier = parser.Node;

pub const TokenId = enum {
    identifier,
    operator,
    number,
};

pub const Operator = enum(u8) {
    left_parenthesis = '(',
    right_parenthesis = ')',
    left_brace = '{',
    right_brace = '}',
    equal = '=',
    colon = ':',
    semicolon = ';',
};

pub const Number = struct {
    content: union(enum) {
        float: f64,
        integer: Integer,
    },

    const Integer = struct {
        value: u64,
        is_negative: bool,
    };
};

pub const Result = struct {
    arrays: struct {
        identifier: ArrayList(Identifier),
        operator: ArrayList(Operator),
        number: ArrayList(Number),
        id: ArrayList(TokenId),
    },
    file: []const u8,
    time: u64 = 0,

    pub fn free(result: *Result, allocator: Allocator) void {
        inline for (@typeInfo(@TypeOf(result.arrays)).Struct.fields) |field| {
            @field(result.arrays, field.name).clearAndFree(allocator);
        }
    }

    fn appendToken(result: *Result, comptime token_id: TokenId, token_value: TokenTypeMap[@intFromEnum(token_id)]) void {
        // const index = result.arrays.id.items.len;
        @field(result.arrays, @tagName(token_id)).appendAssumeCapacity(token_value);
        result.arrays.id.appendAssumeCapacity(token_id);
        // log.err("Token #{}: {s} {}", .{ index, @tagName(token_id), token_value });
    }
};

pub fn lex(allocator: Allocator, text: []const u8) !Result {
    const time_start = std.time.Instant.now() catch unreachable;

    var index: usize = 0;

    var result = Result{
        .arrays = .{
            .identifier = try ArrayList(Identifier).initCapacity(allocator, text.len),
            .operator = try ArrayList(Operator).initCapacity(allocator, text.len),
            .number = try ArrayList(Number).initCapacity(allocator, text.len),
            .id = try ArrayList(TokenId).initCapacity(allocator, text.len),
        },
        .file = text,
    };

    defer {
        const time_end = std.time.Instant.now() catch unreachable;
        result.time = time_end.since(time_start);
    }

    while (index < text.len) {
        const first_char = text[index];
        switch (first_char) {
            'a'...'z', 'A'...'Z', '_' => {
                const start = index;
                while (true) {
                    const ch = text[index];
                    if ((ch >= 'a' and ch <= 'z') or (ch >= 'A' and ch <= 'Z') or ch == '_' or (ch >= '0' and ch <= '9')) {
                        index += 1;
                        continue;
                    }
                    break;
                }

                result.appendToken(.identifier, .{
                    .left = @intCast(start),
                    .right = @intCast(index),
                    .type = .identifier,
                });
            },
            '(', ')', '{', '}', '-', '=', ';' => |operator| {
                result.appendToken(.operator, @enumFromInt(operator));
                index += 1;
            },
            '0'...'9' => {
                const start = index;

                while (text[index] >= '0' and text[index] <= '9') {
                    index += 1;
                }
                const end = index;
                const number_slice = text[start..end];
                const number = try std.fmt.parseInt(u64, number_slice, 10);
                result.appendToken(.number, .{
                    .content = .{
                        .integer = .{
                            .value = number,
                            .is_negative = false,
                        },
                    },
                });
            },
            ' ', '\n', '\r', '\t' => index += 1,
            else => |foo| {
                index += 1;
                std.debug.panic("NI: {c} 0x{x}", .{ foo, foo });
            },
        }
    }

    return result;
}

test "lexer" {
    const allocator = std.testing.allocator;
    const file_path = fs.first;
    const file = try fs.readFile(allocator, file_path);
    defer allocator.free(file);
    var result = try lex(allocator, file);
    defer result.free(allocator);
}
