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

// TODO: switch to packed struct when speed is important
pub const Token = struct {
    pub const Id = enum {
        keyword_unsigned_integer,
        keyword_signed_integer,
        identifier,
        number_literal,
        string_literal,
        character_literal,
        intrinsic,
        discard,
        // Operators
        operator_left_parenthesis,
        operator_right_parenthesis,
        operator_left_brace,
        operator_right_brace,
        operator_left_bracket,
        operator_right_bracket,
        operator_semicolon,
        operator_at,
        operator_comma,
        operator_dot,
        operator_colon,
        operator_bang,
        operator_optional,
        operator_dollar,
        operator_switch_case,
        // Binary
        operator_assign,
        operator_add,
        operator_minus,
        operator_asterisk,
        operator_div,
        operator_mod,
        operator_bar,
        operator_ampersand,
        operator_xor,
        operator_add_assign,
        operator_sub_assign,
        operator_mul_assign,
        operator_div_assign,
        operator_mod_assign,
        operator_or_assign,
        operator_and_assign,
        operator_xor_assign,
        operator_compare_equal,
        operator_compare_not_equal,
        operator_compare_less,
        operator_compare_less_equal,
        operator_compare_greater,
        operator_compare_greater_equal,
        // Fixed keywords
        fixed_keyword_function,
        fixed_keyword_const,
        fixed_keyword_var,
        fixed_keyword_void,
        fixed_keyword_noreturn,
        fixed_keyword_comptime,
        fixed_keyword_while,
        fixed_keyword_bool,
        fixed_keyword_true,
        fixed_keyword_false,
        fixed_keyword_fn,
        fixed_keyword_unreachable,
        fixed_keyword_return,
        fixed_keyword_ssize,
        fixed_keyword_usize,
        fixed_keyword_switch,
        fixed_keyword_if,
        fixed_keyword_else,
        fixed_keyword_struct,
        fixed_keyword_enum,
        fixed_keyword_union,
        fixed_keyword_extern,
        fixed_keyword_null,
        fixed_keyword_align,
        fixed_keyword_export,
        fixed_keyword_cc,
        fixed_keyword_for,
        fixed_keyword_undefined,
        fixed_keyword_break,
        anon0,
        anon1,
        anon2,
        anon3,
        anon4,
        anon5,
        anon6,
        anon7,
        anon8,
        anon9,
        anon20,
        anon21,
        anon22,
        anon23,
        anon24,
        anon25,
        anon26,
        anon27,
        anon28,
        anon29,
        anon30,
        anon31,
        anon32,
        anon33,
        anon34,
        anon35,
        anon36,
        anon37,
        anon38,
        anon39,
        anon40,
        anon41,
        anon42,
        anon43,
        anon44,
        anon45,
        anon46,
        anon47,
        anon48,
        anon49,
        anon50,
        anon51,
        anon52,
        anon53,
        anon54,
        anon55,
        anon56,
        anon57,
        anon58,
        anon59,
        anon60,
        anon61,
        anon62,
        anon63,
        anon64,
        anon65,
        anon66,
        anon67,
        anon68,
        anon69,

        comptime {
            assert(@bitSizeOf(@This()) == @bitSizeOf(u8));
        }
    };

    pub const Index = u32;
};

// Needed information
// Token: u8
// line: u32
// column: u16
// offset: u32
// len: u24

pub const Result = struct {
    ids: ArrayList(Token.Id) = .{},
    token_lines: ArrayList(u32) = .{},
    file_line_offsets: ArrayList(u32) = .{},
    token_offsets: ArrayList(u32) = .{},
    token_lengths: ArrayList(u32) = .{},
    time: u64 = 0,
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

pub fn analyze(allocator: Allocator, text: []const u8) !Result {
    assert(text.len <= std.math.maxInt(u32));
    var lexer = Result{};
    const time_start = std.time.Instant.now() catch unreachable;

    try lexer.file_line_offsets.append(allocator, 0);

    for (text, 0..) |byte, index| {
        if (byte == '\n') {
            try lexer.file_line_offsets.append(allocator, @intCast(index));
        }
    }

    var index: u32 = 0;
    var line_index: u32 = 0;
    const len: u32 = @intCast(text.len);

    lexer.ids = try ArrayList(Token.Id).initCapacity(allocator, text.len / 4);

    while (index < len) {
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

                if (start_character == 'u' or start_character == 's' and text[start_index + 1] >= '0' and text[start_index + 1] <= '9') {
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

                const string = text[start_index..][0 .. index - start_index];
                break :blk if (enumFromString(Compilation.FixedKeyword, string)) |fixed_keyword| switch (fixed_keyword) {
                    inline else => |comptime_fixed_keyword| @field(Token.Id, "fixed_keyword_" ++ @tagName(comptime_fixed_keyword)),
                } else if (equal(u8, string, "_")) .discard else .identifier;
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
            '\'' => blk: {
                index += 1;
                index += @intFromBool(text[index] == '\'');
                index += 1;
                const is_end_char_literal = text[index] == '\'';
                index += @intFromBool(is_end_char_literal);
                if (!is_end_char_literal) unreachable;

                break :blk .character_literal;
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
            '#' => blk: {
                index += 1;
                // const start_intrinsic = index;

                while (true) {
                    const ch = text[index];
                    if ((ch >= 'a' and ch <= 'z') or (ch >= 'A' and ch <= 'Z') or ch == '_') {
                        index += 1;
                    } else break;
                }

                // const end_intrinsic = index;
                // const intrinsic_identifier = text[start_intrinsic..][0 .. end_intrinsic - start_intrinsic];
                // _ = intrinsic_identifier;

                break :blk .intrinsic;
            },
            '\n' => {
                index += 1;
                line_index += 1;
                continue;
            },
            ' ', '\r', '\t' => {
                index += 1;
                continue;
            },
            '(' => blk: {
                index += 1;
                break :blk .operator_left_parenthesis;
            },
            ')' => blk: {
                index += 1;
                break :blk .operator_right_parenthesis;
            },
            '{' => blk: {
                index += 1;
                break :blk .operator_left_brace;
            },
            '}' => blk: {
                index += 1;
                break :blk .operator_right_brace;
            },
            '[' => blk: {
                index += 1;
                break :blk .operator_left_bracket;
            },
            ']' => blk: {
                index += 1;
                break :blk .operator_right_bracket;
            },
            '<' => blk: {
                index += 1;
                break :blk .operator_compare_less;
            },
            '>' => blk: {
                index += 1;
                break :blk .operator_compare_greater;
            },
            ';' => blk: {
                index += 1;
                break :blk .operator_semicolon;
            },
            '@' => blk: {
                index += 1;
                break :blk .operator_at;
            },
            ',' => blk: {
                index += 1;
                break :blk .operator_comma;
            },
            '.' => blk: {
                index += 1;
                break :blk .operator_dot;
            },
            ':' => blk: {
                index += 1;
                break :blk .operator_colon;
            },
            '!' => blk: {
                index += 1;
                break :blk .operator_bang;
            },
            '=' => blk: {
                index += 1;
                const token_id: Token.Id = switch (text[index]) {
                    '=' => b: {
                        index += 1;
                        break :b .operator_compare_equal;
                    },
                    '>' => b: {
                        index += 1;
                        break :b .operator_switch_case;
                    },
                    else => .operator_assign,
                };

                break :blk token_id;
            },
            '+' => blk: {
                index += 1;
                const token_id: Token.Id = switch (text[index]) {
                    '=' => b: {
                        index += 1;
                        break :b .operator_add_assign;
                    },
                    else => .operator_add,
                };

                break :blk token_id;
            },
            '-' => blk: {
                index += 1;
                const token_id: Token.Id = switch (text[index]) {
                    '=' => b: {
                        index += 1;
                        break :b .operator_sub_assign;
                    },
                    else => .operator_minus,
                };

                break :blk token_id;
            },
            '*' => blk: {
                index += 1;
                const token_id: Token.Id = switch (text[index]) {
                    '=' => b: {
                        index += 1;
                        break :b .operator_mul_assign;
                    },
                    else => .operator_asterisk,
                };

                break :blk token_id;
            },
            '/' => blk: {
                index += 1;
                const token_id: Token.Id = switch (text[index]) {
                    '=' => b: {
                        index += 1;
                        break :b .operator_div_assign;
                    },
                    else => .operator_div,
                };

                break :blk token_id;
            },
            '%' => blk: {
                index += 1;
                const token_id: Token.Id = switch (text[index]) {
                    '=' => b: {
                        index += 1;
                        break :b .operator_mod_assign;
                    },
                    else => .operator_mod,
                };

                break :blk token_id;
            },
            '|' => blk: {
                index += 1;
                const token_id: Token.Id = switch (text[index]) {
                    '=' => b: {
                        index += 1;
                        break :b .operator_or_assign;
                    },
                    else => .operator_bar,
                };

                break :blk token_id;
            },
            '&' => blk: {
                index += 1;
                const token_id: Token.Id = switch (text[index]) {
                    '=' => b: {
                        index += 1;
                        break :b .operator_and_assign;
                    },
                    else => .operator_ampersand,
                };

                break :blk token_id;
            },
            '^' => blk: {
                index += 1;
                const token_id: Token.Id = switch (text[index]) {
                    '=' => b: {
                        index += 1;
                        break :b .operator_xor_assign;
                    },
                    else => .operator_xor,
                };

                break :blk token_id;
            },
            '?' => blk: {
                index += 1;

                break :blk .operator_optional;
            },
            '$' => blk: {
                index += 1;

                break :blk .operator_dollar;
            },
            else => |ch| {
                std.debug.panic("NI: '{c}'", .{ch});
            },
        };

        const end_index = index;
        const token_length = end_index - start_index;

        try lexer.ids.append(allocator, token_id);
        try lexer.token_offsets.append(allocator, start_index);
        try lexer.token_lengths.append(allocator, token_length);
        try lexer.token_lines.append(allocator, line_index);
    }

    const time_end = std.time.Instant.now() catch unreachable;
    lexer.time = time_end.since(time_start);
    return lexer;
}
