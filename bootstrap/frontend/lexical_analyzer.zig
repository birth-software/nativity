const std = @import("std");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;
const log = std.log;

const equal = std.mem.eql;

const data_structures = @import("../data_structures.zig");
const ArrayList = data_structures.ArrayList;
const enumFromString = data_structures.enumFromString;

const Compilation = @import("../Compilation.zig");
const File = Compilation.File;
const logln = Compilation.logln;
const fs = @import("../fs.zig");

pub const Token = packed struct(u64) {
    start: u32,
    len: u24,
    id: Id,

    pub const Id = enum(u8) {
        eof = 0x00,
        identifier = 0x01,
        number_literal = 0x02,
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
        fixed_keyword_fn = 0x0e,
        fixed_keyword_unreachable = 0x0f,
        fixed_keyword_return = 0x10,
        fixed_keyword_ssize = 0x11,
        fixed_keyword_usize = 0x12,
        fixed_keyword_switch = 0x13,
        fixed_keyword_if = 0x14,
        fixed_keyword_else = 0x15,
        fixed_keyword_struct = 0x16,
        fixed_keyword_enum = 0x17,
        fixed_keyword_union = 0x18,
        fixed_keyword_extern = 0x19,
        fixed_keyword_null = 0x1a,
        fixed_keyword_align = 0x1b,
        fixed_keyword_export = 0x1c,
        fixed_keyword_cc = 0x1d,
        keyword_unsigned_integer = 0x1f,
        keyword_signed_integer = 0x20,
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
    @"fn",
    @"unreachable",
    @"return",
    ssize,
    usize,
    @"switch",
    @"if",
    @"else",
    @"struct",
    @"enum",
    @"union",
    @"extern",
    null,
    @"align",
    @"export",
    cc,
};

pub const Result = struct {
    tokens: ArrayList(Token),
    time: u64,
};

pub const Logger = enum {
    main,
    new_token,
    number_literals,

    pub var bitset = std.EnumSet(Logger).initMany(&.{
        // .new_token,
        .number_literals,
    });
};

pub fn analyze(allocator: Allocator, text: []const u8, file_index: File.Index) !Result {
    _ = file_index;
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

                // const identifier = text[start_index..][0 .. index - start_index];
                // logln("Identifier: {s}", .{identifier});

                if (start_character == 'u' or start_character == 's') {
                    var index_integer = start_index + 1;
                    while (text[index_integer] >= '0' and text[index_integer] <= '9') {
                        index_integer += 1;
                    }

                    if (index_integer == index) {
                        const id: Token.Id = switch (start_character) {
                            'u' => .keyword_unsigned_integer,
                            's' => .keyword_signed_integer,
                            else => unreachable,
                        };

                        break :blk id;
                    }
                }

                break :blk if (enumFromString(FixedKeyword, text[start_index..][0 .. index - start_index])) |fixed_keyword| switch (fixed_keyword) {
                    inline else => |comptime_fixed_keyword| @field(Token.Id, "fixed_keyword_" ++ @tagName(comptime_fixed_keyword)),
                } else .identifier;
            },
            '0'...'9' => blk: {
                // Detect other non-decimal literals
                if (text[index] == '0' and index + 1 < text.len) {
                    logln(.lexer, .number_literals, "Number starts with 0. Checking for non-decimal literals...", .{});
                    if (text[index + 1] == 'x') {
                        logln(.lexer, .number_literals, "Hex", .{});
                        index += 2;
                    } else if (text[index + 1] == 'b') {
                        logln(.lexer, .number_literals, "Bin", .{});
                        index += 2;
                    } else if (text[index + 1] == 'o') {
                        logln(.lexer, .number_literals, "Decimal", .{});
                        index += 2;
                    }
                }

                while (text[index] >= '0' and text[index] <= '9' or text[index] >= 'a' and text[index] <= 'f' or text[index] >= 'A' and text[index] <= 'F') {
                    index += 1;
                }

                break :blk .number_literal;
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
            '(', ')', '{', '}', '[', ']', '=', ';', '#', '@', ',', '.', ':', '>', '<', '!', '+', '-', '*', '\\', '/', '&', '|', '^', '?', '$' => |operator| blk: {
                index += 1;
                break :blk @enumFromInt(operator);
            },
            else => |ch| {
                std.debug.panic("NI: '{c}'", .{ch});
            },
        };

        const end_index = index;
        const token = Token{
            .start = @intCast(start_index),
            .len = @intCast(end_index - start_index),
            .id = token_id,
        };

        logln(.lexer, .new_token, "New token {s} added: {s}", .{ @tagName(token.id), text[token.start..][0..token.len] });

        try tokens.append(allocator, token);
    }

    for (tokens.items, 0..) |token, i| {
        logln(.lexer, .main, "#{} {s}\n", .{ i, @tagName(token.id) });
    }

    const time_end = std.time.Instant.now() catch unreachable;
    const time = time_end.since(time_start);

    return .{
        .tokens = tokens,
        .time = time,
    };
}
