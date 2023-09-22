const std = @import("std");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;
const log = std.log;

const equal = std.mem.eql;

const data_structures = @import("../data_structures.zig");
const ArrayList = data_structures.ArrayList;
const enumFromString = data_structures.enumFromString;

const Compilation = @import("../Compilation.zig");
const fs = @import("../fs.zig");

pub const Token = packed struct(u64) {
    start: u32,
    len: u24,
    id: Id,

    pub const Id = enum(u8) {
        eof = 0x00,
        identifier = 0x01,
        number = 0x02,
        string_literal = 0x03,
        fixed_keyword_function = 0x04,
        fixed_keyword_const = 0x05,
        fixed_keyword_var = 0x06,
        fixed_keyword_void = 0x07,
        fixed_keyword_noreturn = 0x08,
        fixed_keyword_comptime = 0x09,
        fixed_keyword_while = 0x0a,
        fixed_keyword_bool = 0x0b,
        fixed_keyword_true = 0x0c,
        fixed_keyword_false = 0x0d,
        bang = '!', // 0x21
        hash = '#', // 0x23
        dollar_sign = '$', // 0x24
        modulus = '%', // 0x25
        ampersand = '&', // 0x26
        left_parenthesis = '(', // 0x28
        right_parenthesis = ')', // 0x29
        asterisk = '*', // 0x2a
        plus = '+', // 0x2b
        comma = ',', // 0x2c
        minus = '-', // 0x2d
        period = '.', // 0x2e
        slash = '/', // 0x2f
        colon = ':', // 0x3a
        semicolon = ';', // 0x3b
        less = '<', // 0x3c
        equal = '=', // 0x3d
        greater = '>', // 0x3e
        question_mark = '?', // 0x3f
        at = '@', // 0x40
        left_bracket = '[', // 0x5b
        backlash = '\\', // 0x5c
        right_bracket = ']', // 0x5d
        caret = '^', // 0x5e
        underscore = '_', // 0x5f
        grave = '`', // 0x60
        left_brace = '{', // 0x7b
        vertical_bar = '|', // 0x7c
        right_brace = '}', // 0x7d
        tilde = '~', // 0x7e
    };

    pub const Index = u32;
};

pub const FixedKeyword = enum {
    @"comptime",
    @"const",
    @"var",
    void,
    noreturn,
    function,
    @"while",
    bool,
    true,
    false,
};

pub const Result = struct {
    tokens: ArrayList(Token),
    time: u64,
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

                const identifier = text[start_index..][0 .. index - start_index];
                std.debug.print("Identifier: {s}\n", .{identifier});

                if (start_character == 'u' or start_character == 's') {
                    var index_integer = start_index + 1;
                    while (text[index_integer] >= '0' and text[index_integer] <= '9') {
                        index_integer += 1;
                    }

                    if (index_integer == index) {
                        unreachable;
                    }
                }

                break :blk if (enumFromString(FixedKeyword, text[start_index..][0 .. index - start_index])) |fixed_keyword| switch (fixed_keyword) {
                    inline else => |comptime_fixed_keyword| @field(Token.Id, "fixed_keyword_" ++ @tagName(comptime_fixed_keyword)),
                } else .identifier;
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
            '\'' => {
                unreachable;
            },
            '"' => blk: {
                index += 1;

                while (true) {
                    if (text[index] == '"' and text[index - 1] != '"') {
                        break;
                    }

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

    const should_log = true;
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
