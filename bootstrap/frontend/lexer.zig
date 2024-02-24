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
const Token = Compilation.Token;
const fs = @import("../fs.zig");

// Needed information
// Token: u8
// line: u32
// column: u16
// offset: u32
// len: u24

pub const Result = struct {
    offset: Token.Index,
    count: u32,
    line_offset: u32,
    line_count: u32,
    // ids: ArrayList(Token.Id) = .{},
    // token_lines: ArrayList(u32) = .{},
    // file_line_offsets: ArrayList(u32) = .{},
    // token_offsets: ArrayList(u32) = .{},
    // token_lengths: ArrayList(u32) = .{},
    time: u64 = 0,
};

pub const Logger = enum {
    start,
    end,
    new_token,
    number_literals,

    pub var bitset = std.EnumSet(Logger).initMany(&.{
        .new_token,
        .start,
        .end,
        .number_literals,
    });
};

pub fn analyze(allocator: Allocator, text: []const u8, token_buffer: *Token.Buffer) !Result {
    assert(text.len <= std.math.maxInt(u32));
    const len: u32 = @intCast(text.len);

    var lexer = Result{
        .offset = token_buffer.getOffset(),
        .line_offset = token_buffer.getLineOffset(),
        .count = 0,
        .line_count = 0,
    };

    const time_start = std.time.Instant.now() catch unreachable;

    try token_buffer.line_offsets.append(allocator, 0);

    for (text, 0..) |byte, index| {
        if (byte == '\n') {
            try token_buffer.line_offsets.append(allocator, @intCast(index + 1));
        }
    }

    var index: u32 = 0;
    var line_index: u32 = lexer.line_offset;

    try token_buffer.tokens.ensureUnusedCapacity(allocator, text.len / 4);

    logln(.lexer, .end, "START LEXER - TOKEN OFFSET: {} - LINE OFFSET: {}", .{ Token.unwrap(lexer.offset), lexer.line_offset });

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
                    if (text[index + 1] == 'x') {
                        index += 2;
                    } else if (text[index + 1] == 'b') {
                        index += 2;
                    } else if (text[index + 1] == 'o') {
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
                switch (text[index]) {
                    '<' => {
                        index += 1;
                        break :blk switch (text[index]) {
                            '=' => b: {
                                index += 1;
                                break :b .operator_shift_left_assign;
                            },
                            else => .operator_shift_left,
                        };
                    },
                    '=' => {
                        index += 1;
                        break :blk .operator_compare_less_equal;
                    },
                    else => break :blk .operator_compare_less,
                }
            },
            '>' => blk: {
                index += 1;
                switch (text[index]) {
                    '>' => {
                        index += 1;
                        break :blk switch (text[index]) {
                            '=' => b: {
                                index += 1;
                                break :b .operator_shift_right_assign;
                            },
                            else => .operator_shift_right,
                        };
                    },
                    '=' => {
                        index += 1;
                        break :blk .operator_compare_greater_equal;
                    },
                    else => break :blk .operator_compare_greater,
                }
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
                switch (text[index]) {
                    '=' => {
                        index += 1;
                        break :blk .operator_compare_not_equal;
                    },
                    else => break :blk .operator_bang,
                }
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

        token_buffer.tokens.appendAssumeCapacity(.{
            .id = token_id,
            .offset = start_index,
            .length = token_length,
            .line = line_index,
        });
        const line_offset = token_buffer.line_offsets.items[line_index];
        const column = start_index - line_offset;
        logln(.lexer, .new_token, "T at line {}, column {}, byte offset {}, with length {} -line offset: {}- ({s})", .{ line_index, column, start_index, token_length, line_offset, @tagName(token_id) });
    }

    logln(.lexer, .end, "END LEXER - TOKEN OFFSET: {} - LINE OFFSET: {}", .{ Token.unwrap(lexer.offset), lexer.line_offset });

    lexer.count = Token.sub(token_buffer.getOffset(), lexer.offset);
    lexer.line_count = token_buffer.getLineOffset() - lexer.line_offset;

    const time_end = std.time.Instant.now() catch unreachable;
    lexer.time = time_end.since(time_start);
    return lexer;
}
