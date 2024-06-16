const compiler = @This();
const configuration = @import("configuration");
const std = @import("std");
const builtin = @import("builtin");
const library = @import("library.zig");
const assert = library.assert;
const Arena = library.Arena;
const PinnedArray = library.PinnedArray;
const PinnedHashMap = library.PinnedHashMap;
const byte_equal = library.byte_equal;
const first_byte = library.first_byte;
const hash_bytes = library.my_hash;
const last_byte = library.last_byte;
const starts_with_slice = library.starts_with_slice;
const Atomic = std.atomic.Value;

const weak_memory_model = switch (builtin.cpu.arch) {
    .aarch64 => true,
    .x86_64 => false,
    else => @compileError("Error: unknown arch"),
};

const Instant = if (configuration.timers) std.time.Instant else void;
fn get_instant() Instant {
    if (configuration.timers) {
        return Instant.now() catch unreachable;
    }
}

fn fail() noreturn {
    @setCold(true);
    @breakpoint();
    std.posix.exit(1);
}

fn fail_term(message: []const u8, term: []const u8) noreturn {
    @setCold(true);
    write(message);
    write(": '");
    write(term);
    write("'\n");
    fail();
}

fn is_space(ch: u8, next_ch: u8) bool {
    const is_comment = ch == '/' and next_ch == '/';
    const is_whitespace = ch == ' ';
    const is_vertical_tab = ch == 0x0b;
    const is_horizontal_tab = ch == '\t';
    const is_line_feed = ch == '\n';
    const is_carry_return = ch == '\r';
    const result = ((is_vertical_tab or is_horizontal_tab) or (is_line_feed or is_carry_return)) or (is_comment or is_whitespace);
    return result;
}

pub fn write(string: []const u8) void {
    std.io.getStdOut().writeAll(string) catch unreachable;
}

fn fail_message(string: []const u8) noreturn {
    @setCold(true);
    write("error: ");
    write(string);
    write("\n");
    fail();
}

fn is_lower(ch: u8) bool {
    return ch >= 'a' and ch <= 'z';
}

fn is_upper(ch: u8) bool {
    return ch >= 'A' and ch <= 'Z';
}

fn is_decimal_digit(ch: u8) bool {
    return ch >= '0' and ch <= '9';
}

fn is_hex_digit(ch: u8) bool {
    return (is_decimal_digit(ch) or ((ch == 'a' or ch == 'A') or (ch == 'b' or ch == 'B'))) or (((ch == 'c' or ch == 'C') or (ch == 'd' or ch == 'D')) or ((ch == 'e' or ch == 'E') or (ch == 'f' or ch == 'F')));
}

fn is_alphabetic(ch: u8) bool {
    const lower =  is_lower(ch);
    const upper =  is_upper(ch);
    return lower or upper;
}

fn is_identifier_char_start(ch: u8) bool {
    const is_alpha = is_alphabetic(ch);
    const is_underscore = ch == '_';
    return is_alpha or is_underscore;
}

fn is_identifier_char(ch: u8) bool {
    const is_identifier_start_ch = is_identifier_char_start(ch);
    const is_digit = is_decimal_digit(ch);
    return is_identifier_start_ch or is_digit;
}

const Side = enum {
    left,
    right,
};

const GlobalSymbol = struct{
    attributes: Attributes = .{},
    global_declaration: GlobalDeclaration,
    type: *Type,
    pointer_type: *Type,
    alignment: u32,
    value: Value,
    id: GlobalSymbol.Id,

    const Id = enum{
        function_declaration,
        function_definition,
        global_variable,
    };

    const Attributes = struct{
        @"export": bool = false,
        @"extern": bool = false,
        mutability: Mutability = .@"var",
    };
    const Attribute = enum{
        @"export",
        @"extern",

        const Mask = std.EnumSet(Attribute);
    };

    const id_to_global_symbol_map = std.EnumArray(Id, type).init(.{
        .function_declaration = Function.Declaration,
        .function_definition = Function,
        .global_variable = GlobalVariable,
    });

    fn get_payload(global_symbol: *GlobalSymbol, comptime id: Id) *id_to_global_symbol_map.get(id) {
        if (id == .function_definition) {
            const function_declaration: *Function.Declaration = @alignCast(@fieldParentPtr("global_symbol", global_symbol));
            const function_definition: *Function = @alignCast(@fieldParentPtr("declaration", function_declaration));
            return function_definition;
        }

        return @fieldParentPtr("global_symbol", global_symbol);
    }
};

const GlobalVariable = struct {
    global_symbol: GlobalSymbol,
    initial_value: *Value,
};

const Mutability = enum(u1){
    @"const" = 0,
    @"var" = 1,
};

const ArgumentSymbol = struct {
    attributes: Attributes = .{},
    argument_declaration: ArgumentDeclaration,
    type: *Type,
    pointer_type: *Type,
    instruction: Instruction,
    alignment: u32,
    index: u32,

    const Attributes = struct{
    };
    const Attribute = enum{
        const Mask = std.EnumSet(Attribute);
    };
};

const LocalSymbol = struct {
    attributes: Attributes = .{},
    local_declaration: LocalDeclaration,
    type: *Type,
    pointer_type: *Type,
    instruction: Instruction,
    alignment: u32,

    const Attributes = struct{
        mutability: Mutability = .@"const",
    };
    const Attribute = enum{
        const Mask = std.EnumSet(Attribute);
    };
};

const Parser = struct{
    i: u64 = 0,
    line: u32 = 0,
    column: u32 = 0,

    fn get_debug_line(parser: *const Parser) u32 {
        return parser.line + 1;
    }

    fn get_debug_column(parser: *const Parser) u32 {
        return @intCast(parser.i - parser.column + 1);
    }

    fn safe_flag(value: anytype, boolean: bool) @TypeOf(value) {
        const result = value & (@as(@TypeOf(value), 0) -% @intFromBool(boolean));
        return result;
    }

    fn get_next_ch_safe(file: []const u8, index: u64) u8 {
        const next_index = index + 1;
        const is_in_range = next_index < file.len;
        const safe_index = safe_flag(next_index, is_in_range);
        const unsafe_result = file[safe_index];
        const safe_result = safe_flag(unsafe_result, is_in_range);
        return safe_result;
    }

    fn skip_space(parser: *Parser, file: []const u8) void {
        const original_i = parser.i;

        if (original_i == file.len or !is_space(file[original_i], get_next_ch_safe(file, original_i))) return;

        while (parser.i < file.len) : (parser.i += 1) {
            const ch = file[parser.i];
            const new_line = ch == '\n';
            parser.line += @intFromBool(new_line);

            if (new_line) {
                parser.column = @intCast(parser.i + 1);
            }

            if (!is_space(ch, get_next_ch_safe(file, parser.i))) {
                return;
            }

            if (file[parser.i] == '/') {
                parser.i += 2;

                while (parser.i < file.len) : (parser.i += 1) {
                    const is_line_feed = file[parser.i] == '\n';
                    if (is_line_feed) {
                        parser.line += 1;
                        break;
                    }
                }

                if (parser.i == file.len) break;
            }
        }
    }

    const ParseFieldData = struct{
        type: *Type,
        name: u32,
        line: u32,
        column: u32,
    };

    fn parse_field(parser: *Parser, thread: *Thread, file: *File) ?ParseFieldData{
        const src = file.source_code;
        parser.skip_space(src);

        if (src[parser.i] == brace_close) {
            return null;
        }

        const field_line = parser.get_debug_line();
        const field_column = parser.get_debug_column();
        const field_name = parser.parse_identifier(thread, src);

        parser.skip_space(src);

        parser.expect_character(src, ':');

        parser.skip_space(src);

        const field_type = parser.parse_type_expression(thread, file, &file.scope.scope);

        parser.skip_space(src);

        switch (src[parser.i]) {
            ',' => parser.i += 1,
            '=' => {
                fail_message("TODO: field default value");
            },
            else => fail(),
        }

        return ParseFieldData{
            .type = field_type,
            .name = field_name,
            .line = field_line,
            .column = field_column,
        };
    }

    const ExpectFailureAction = enum{
        @"unreachable",
        trap,
    };
    fn parse_boolean_expect_intrinsic(parser: *Parser, analyzer: *Analyzer, thread: *Thread, file: *File, failure_action: ExpectFailureAction, debug_line: u32, debug_column: u32) void {
        const condition = parser.parse_condition(analyzer, thread, file);
        const expect_true_block = create_basic_block(thread);
        const expect_false_block = create_basic_block(thread);
        _ = emit_branch(analyzer, thread, .{
            .condition = condition, 
            .taken = expect_true_block,
            .not_taken = expect_false_block,
            .line = debug_line,
            .column = debug_column,
            .scope = analyzer.current_scope,
        });
        analyzer.current_basic_block = expect_false_block;

        switch (failure_action) {
            .@"unreachable" => emit_unreachable(analyzer, thread, .{
                .line = debug_line,
                .column = debug_column,
                .scope = analyzer.current_scope,
            }),
            .trap => emit_trap(analyzer, thread, .{
                .line = debug_line,
                .column = debug_column,
                .scope = analyzer.current_scope,
            }),
        }

        analyzer.current_basic_block = expect_true_block;
    }

    fn parse_intrinsic(parser: *Parser, analyzer: *Analyzer, thread: *Thread, file: *File, ty: ?*Type) ?*Value {
        const src = file.source_code;
        const debug_line = parser.get_debug_line();
        const debug_column = parser.get_debug_column();
        parser.expect_character(src, '#');

        // TODO: make it more efficient
        const identifier = parser.parse_raw_identifier(src);
        if (identifier[0] == '"') {
            unreachable;
        } else {
            const intrinsic_id = inline for (@typeInfo(Intrinsic).Enum.fields) |i_field| {
                if (byte_equal(i_field.name, identifier)) {
                    break @field(Intrinsic, i_field.name);
                }
            } else {
                fail_term("Unknown intrinsic", identifier);
            };

            switch (intrinsic_id) {
                .assert => {
                    parser.parse_boolean_expect_intrinsic(analyzer, thread, file, .@"unreachable", debug_line, debug_column);
                    return null;
                },
                .require => {
                    parser.parse_boolean_expect_intrinsic(analyzer, thread, file, .trap, debug_line, debug_column);
                    return null;
                },
                .size => {
                    parser.skip_space(src);
                    parser.expect_character(src, '(');
                    parser.skip_space(src);
                    const size_type = parser.parse_type_expression(thread, file, analyzer.current_scope);
                    parser.skip_space(src);
                    parser.expect_character(src, ')');
                    const constant_int = create_constant_int(thread, .{
                        .n = size_type.size,
                        .type = ty orelse unreachable,
                    });
                    return &constant_int.value;
                },
                .trailing_zeroes => {
                    parser.skip_space(src);
                    parser.expect_character(src, '(');
                    parser.skip_space(src);
                    const value = parser.parse_expression(analyzer, thread, file, ty, .right);
                    parser.skip_space(src);
                    parser.expect_character(src, ')');
                    const tz = thread.trailing_zeroes.append(.{
                        .value = value,
                        .instruction = new_instruction(thread, .{
                            .id = .trailing_zeroes,
                            .line = debug_line,
                            .column = debug_column,
                            .scope = analyzer.current_scope,
                        }),
                    });
                    analyzer.append_instruction(&tz.instruction);
                    return &tz.instruction.value;
                },
                .leading_zeroes => {
                    parser.skip_space(src);
                    parser.expect_character(src, '(');
                    parser.skip_space(src);
                    const value = parser.parse_expression(analyzer, thread, file, ty, .right);
                    parser.skip_space(src);
                    parser.expect_character(src, ')');
                    const lz = thread.leading_zeroes.append(.{
                        .value = value,
                        .instruction = new_instruction(thread, .{
                            .id = .leading_zeroes,
                            .line = debug_line,
                            .column = debug_column,
                            .scope = analyzer.current_scope,
                        }),
                    });
                    analyzer.append_instruction(&lz.instruction);
                    return &lz.instruction.value;
                },
                .transmute => {
                    const destination_type = ty orelse fail();
                    parser.skip_space(src);
                    parser.expect_character(src, '(');
                    parser.skip_space(src);
                    const value = parser.parse_expression(analyzer, thread, file, null, .right);
                    parser.skip_space(src);
                    parser.expect_character(src, ')');

                    const source_type = value.get_type();
                    if (destination_type == source_type) {
                        fail();
                    }

                    const cast_id: Cast.Id = switch (destination_type.sema.id) {
                        .integer => block: {
                            const destination_integer = destination_type.get_payload(.integer);
                            _ = destination_integer; // autofix
                            switch (source_type.sema.id) {
                                .bitfield => {
                                    const source_bitfield = source_type.get_payload(.bitfield);
                                    if (source_bitfield.backing_type == destination_type) {
                                        break :block .int_from_bitfield;
                                    } else {
                                        fail();
                                    }
                                },
                                else => |t| @panic(@tagName(t)),
                            }
                        },
                        .bitfield => block: {
                            const destination_bitfield = destination_type.get_payload(.bitfield);
                            if (destination_bitfield.backing_type == source_type) {
                                break :block .int_from_bitfield;
                            } else {
                                fail();
                            }
                        },
                        else => |t| @panic(@tagName(t)),
                    };

                    const cast = emit_cast(analyzer, thread, .{
                        .line = debug_line,
                        .column = debug_column,
                        .scope = analyzer.current_scope,
                        .value = value,
                        .type = destination_type,
                        .id = cast_id,
                    });

                    return &cast.instruction.value;
                },
                .int_from_pointer => {
                    if (ty) |expected_type| {
                        _ = expected_type; // autofix
                        unreachable;
                    }

                    const expected_type = &thread.integers[63].type;

                    parser.skip_space(src);
                    parser.expect_character(src, '(');
                    parser.skip_space(src);
                    const value = parser.parse_expression(analyzer, thread, file, null, .right);
                    switch (value.get_type().sema.id) {
                        .typed_pointer => {},
                        else => |t| @panic(@tagName(t)),
                    }
                    parser.skip_space(src);
                    parser.expect_character(src, ')');

                    const cast = emit_cast(analyzer, thread, .{
                        .line = debug_line,
                        .column = debug_column,
                        .scope = analyzer.current_scope,
                        .value = value,
                        .type = expected_type,
                        .id = .int_from_pointer,
                    });
                    return &cast.instruction.value;
                },
                else => |t| @panic(@tagName(t)),
            }
        }
    }

    fn parse_raw_identifier(parser: *Parser, file: []const u8) []const u8 {
        const identifier_start = parser.i;
        const is_string_literal_identifier = file[identifier_start] == '"';
        parser.i += @intFromBool(is_string_literal_identifier);
        const start_ch = file[parser.i];
        const is_valid_identifier_start = is_identifier_char_start(start_ch);
        parser.i += @intFromBool(is_valid_identifier_start);

        if (is_valid_identifier_start) {
            while (parser.i < file.len) {
                const ch = file[parser.i];
                const is_ident = is_identifier_char(ch);
                parser.i += @intFromBool(is_ident);

                if (!is_ident) {
                    if (is_string_literal_identifier) {
                        if (file[parser.i] != '"') {
                            fail();
                        }
                    }

                    const identifier = file[identifier_start..parser.i];
                    return identifier;
                }
            } else {
                fail();
            }
        } else {
            fail();
        }
    }

    fn parse_identifier(parser: *Parser, thread: *Thread, file: []const u8) u32 {
        const identifier = parser.parse_raw_identifier(file);
        const keyword = parse_keyword(identifier);
        if (keyword != ~(@as(u32, 0))) {
            fail();
        }

        if (byte_equal(identifier, "_")) {
            return 0;
        } else return intern_identifier(&thread.identifiers, identifier);
    }

    fn parse_non_escaped_string_literal(parser: *Parser, src: []const u8) []const u8 {
        const start = parser.i;
        const is_double_quote = src[start] == '"';
        parser.i += @intFromBool(is_double_quote);

        if (!is_double_quote) {
            fail();
        }

        while (src[parser.i] != '"') : (parser.i += 1) {
            if (src[parser.i] == '\\') fail();
        }

        parser.i += 1;

        const end = parser.i;

        return src[start..end];
    }

    fn parse_non_escaped_string_literal_content(parser: *Parser, src: []const u8) []const u8 {
        const string_literal = parser.parse_non_escaped_string_literal(src);
        return string_literal[1..][0..string_literal.len - 2];
    }

    fn expect_character(parser: *Parser, file: []const u8, expected: u8) void {
        const index = parser.i;
        if (index < file.len) {
            const ch = file[index];
            const matches = ch == expected;
            parser.i += @intFromBool(matches);
            if (!matches) {
                fail();
            }
        } else {
            fail();
        }
    }

    pub fn parse_hex(slice: []const u8) u64 {
        var value: u64 = 0;
        for (slice) |ch| {
            const byte = switch (ch) {
                '0'...'9' => ch - '0',
                'a'...'f' => ch - 'a' + 10,
                'A'...'F' => ch - 'A' + 10,
                else => fail(),
            };
            value = (value << 4) | (byte & 0xf);
        }

        return value;
    }

    fn parse_type_expression(parser: *Parser, thread: *Thread, file: *File, current_scope: *Scope) *Type {
        const src = file.source_code;
        const starting_index = parser.i;
        const starting_ch = src[starting_index];
        const is_array_start = starting_ch == '[';
        const is_start_u = starting_ch == 'u';
        const is_start_s = starting_ch == 's';
        const float_start = starting_ch == 'f';
        const is_void_start = starting_ch == 'v';
        const is_pointer_sign_start = starting_ch == '*';
        const integer_start = is_start_s or is_start_u;
        const is_number_type_start = integer_start or float_start;

        if (is_void_start) {
            const id = parser.parse_raw_identifier(src);
            if (byte_equal(id, "void")) {
                return &thread.void;
            } else {
                parser.i = starting_index;
            }
        } else if (is_number_type_start) {
            const expected_digit_start = parser.i + 1;
            var i = expected_digit_start;
            var decimal_digit_count: u32 = 0;

            const top = i + 5;

            while (i < top) : (i += 1) {
                const ch = src[i];
                const is_digit = is_decimal_digit(ch);
                decimal_digit_count += @intFromBool(is_digit);
                if (!is_digit) {
                    const is_alpha = is_alphabetic(ch);
                    if (is_alpha) decimal_digit_count = 0;
                    break;
                }
            }

            if (decimal_digit_count != 0) {
                parser.i += 1;

                if (integer_start) {
                    const signedness: Type.Integer.Signedness = @enumFromInt(@intFromBool(is_start_s));
                    const bit_count: u32 = switch (decimal_digit_count) {
                        0 => unreachable,
                        1 => src[parser.i] - '0',
                        2 => @as(u32, src[parser.i] - '0') * 10 + (src[parser.i + 1] - '0'),
                        else => fail(),
                    };
                    parser.i += decimal_digit_count;

                    const index = bit_count - 1 + @intFromEnum(signedness) * @as(usize, 64);
                    const result = &thread.integers[index];
                    assert(result.type.bit_size == bit_count);
                    assert(result.signedness == signedness);
                    return &result.type;
                } else if (float_start) {
                    fail();
                } else {
                    unreachable;
                }
            } else {
                fail();
            }
        } else if (is_pointer_sign_start) {
            parser.i += 1;

            const pointee_type = parser.parse_type_expression(thread, file, current_scope);
            const typed_pointer = get_typed_pointer(thread, .{
                .pointee = pointee_type,
            });
            return typed_pointer;
        } else if (is_array_start) {
            parser.i += 1;

            parser.skip_space(src);

            const element_count = parser.parse_constant_expression(thread, file, null);
            switch (element_count.sema.id) {
                .constant_int => {
                    const constant_int = element_count.get_payload(.constant_int);
                    parser.skip_space(src);
                    parser.expect_character(src, ']');
                    parser.skip_space(src);

                    const element_type = parser.parse_type_expression(thread, file, current_scope);
                    const array_type = get_array_type(thread, .{
                        .element_type = element_type,
                        .element_count = constant_int.n,
                    });
                    return array_type;
                },
                else => |t| @panic(@tagName(t)),
            }
        }

        const identifier = parser.parse_identifier(thread, src);
        if (current_scope.get_declaration(identifier)) |lookup| {
            const declaration = lookup.declaration.*;
            switch (declaration.id) {
                .@"struct" => {
                    const struct_type = declaration.get_payload(.@"struct");
                    return &struct_type.type;
                },
                .bitfield => {
                    const bitfield_type = declaration.get_payload(.bitfield);
                    return &bitfield_type.type;
                },
                else => |t| @panic(@tagName(t)),
            }
        } else {
            fail_term("Unrecognized type expression", thread.identifiers.get(identifier).?);
        }
    }

    fn parse_constant_integer(parser: *Parser, thread: *Thread, file: *File, ty: *Type) *ConstantInt {
        const src = file.source_code;
        const starting_index = parser.i;
        const starting_ch = src[starting_index];
        if (starting_ch == '0') {
            const follow_up_character = src[parser.i + 1];
            const is_hex_start = follow_up_character == 'x';
            const is_octal_start = follow_up_character == 'o';
            const is_bin_start = follow_up_character == 'b';
            const is_prefixed_start = is_hex_start or is_octal_start or is_bin_start;
            const follow_up_alpha = is_alphabetic(follow_up_character);
            const follow_up_digit = is_decimal_digit(follow_up_character);
            const is_valid_after_zero = is_space(follow_up_character, get_next_ch_safe(src, follow_up_character)) or (!follow_up_digit and !follow_up_alpha);

            if (is_prefixed_start) {
                const Prefix = enum {
                    hexadecimal,
                    octal,
                    binary,
                };
                const prefix: Prefix = switch (follow_up_character) {
                    'x' => .hexadecimal,
                    'o' => .octal,
                    'b' => .binary,
                    else => unreachable,
                };

                parser.i += 2;

                const start = parser.i;

                switch (prefix) {
                    .hexadecimal => {
                        while (is_hex_digit(src[parser.i])) {
                            parser.i += 1;
                        }

                        const slice = src[start..parser.i];
                        const number = parse_hex(slice);

                        const constant_int = create_constant_int(thread, .{
                            .n = number,
                            .type = ty,
                        });
                        return constant_int;
                    },
                    .octal => {
                        unreachable;
                    },
                    .binary => {
                        unreachable;
                    },
                }
                fail();
            } else if (is_valid_after_zero) {
                parser.i += 1;
                const constant_int = create_constant_int(thread, .{
                    .n = 0,
                    .type = ty,
                });
                return constant_int;
            } else {
                fail();
            }
        }

        while (is_decimal_digit(src[parser.i])) {
            parser.i += 1;
        }

        const character_count = parser.i - starting_index;
        const slice = src[starting_index..][0..character_count];
        var i = character_count;
        var integer: u64 = 0;
        var factor: u64 = 1;

        while (i > 0) {
            i -= 1;
            const ch = slice[i];
            const int = ch - '0';
            const extra = int * factor;
            integer += extra;
            factor *= 10;
        }

        const constant_int = create_constant_int(thread, .{
            .n = integer,
            .type = ty,
        });

        return constant_int;
    }

    const ParseFieldInitialization = struct{
        value: *Value,
        name: u32,
        index: u32,
        line: u32,
        column: u32,
    };

    fn parse_field_initialization(parser: *Parser, analyzer: *Analyzer, thread: *Thread, file: *File, names_initialized: []const u32, fields: []const *Type.AggregateField) ?ParseFieldInitialization{
        const src = file.source_code;
        parser.skip_space(src);

        if (src[parser.i] == brace_close) {
            return null;
        }

        const line = parser.get_debug_line();
        const column = parser.get_debug_column();

        parser.expect_character(src, '.');
        const name = parser.parse_identifier(thread, src);
        for (names_initialized) |initialized_name| {
            if (initialized_name == name) {
                fail();
            }
        }
        const field_index = for (fields) |field| {
            if (field.name == name) {
                break field.index;
            }
        } else {
            fail();
        };
        const field_type = fields[field_index].type;
        parser.skip_space(src);
        parser.expect_character(src, '=');
        parser.skip_space(src);

        const field_value = parser.parse_expression(analyzer, thread, file, field_type, .right);

        parser.skip_space(src);

        switch (src[parser.i]) {
            brace_close => {},
            ',' => parser.i += 1,
            else => fail(),
        }

        return ParseFieldInitialization{
            .value = field_value,
            .name = name,
            .index = field_index,
            .line = line,
            .column = column,
        };
    }

    fn parse_single_expression(parser: *Parser, analyzer: *Analyzer, thread: *Thread, file: *File, maybe_type: ?*Type, side: Side) *Value {
        const src = file.source_code;
        const Unary = enum{
            none,
            one_complement,
            negation,
        };

        const unary: Unary = switch (src[parser.i]) {
            'A'...'Z', 'a'...'z', '_' => Unary.none,
            '0'...'9' => Unary.none,
            '-' => block: {
                parser.i += 1;
                break :block .negation;
            },
            '~' => block: {
                parser.i += 1;
                break :block .one_complement;
            },
            '#' => {
                // parse intrinsic
                const value = parser.parse_intrinsic(analyzer, thread, file, maybe_type) orelse unreachable;
                return value;
            },
            brace_open => {
                parser.i += 1;

                // This is a composite initialization
                const ty = maybe_type orelse fail();
                switch (ty.sema.id) {
                    .@"struct" => {
                        const struct_type = ty.get_payload(.@"struct");

                        var names_initialized = PinnedArray(u32){};
                        var is_constant = true;
                        var values = PinnedArray(*Value){};
                        var field_index: u32 = 0;
                        var is_field_ordered = true;
                        var line_info = PinnedArray(struct{ line: u32, column: u32 }){};

                        while (parser.parse_field_initialization(analyzer, thread, file, names_initialized.const_slice(), struct_type.fields)) |field_data| : (field_index += 1) {
                            is_field_ordered = is_field_ordered and field_index == field_data.index;
                            _ = names_initialized.append(field_data.name);
                            _ = values.append(field_data.value);
                            _ = line_info.append(.{ .line = field_data.line, .column = field_data.column });
                            is_constant = is_constant and field_data.value.is_constant();
                        }

                        parser.i += 1;

                        if (is_field_ordered and field_index == struct_type.fields.len) {
                            if (is_constant) {
                                const constant_struct = thread.constant_structs.append(.{
                                    .value = .{
                                        .sema = .{
                                            .thread = thread.get_index(),
                                            .resolved = true,
                                            .id = .constant_struct,
                                        },
                                    },
                                    .values = values.const_slice(),
                                    .type = ty,
                                });
                                return &constant_struct.value;
                            } else {
                                const undefined_value = thread.undefined_values.append(.{
                                    .value = .{
                                        .sema = .{
                                            .id = .undefined,
                                            .resolved = true,
                                            .thread = thread.get_index(),
                                        },
                                    },
                                    .type = ty,
                                });

                                if (true) unreachable;
                                var aggregate = &undefined_value.value;
                                for (values.const_slice(), line_info.const_slice(), 0..) |value, li, index| {
                                    if (true) unreachable;
                                    const insert_value = emit_insert_value(thread, analyzer, .{
                                        .aggregate = aggregate,
                                        .value = value,
                                        .index = @intCast(index),
                                        .line = li.line,
                                        .column = li.column,
                                        .scope = analyzer.current_scope,
                                        .type = ty,
                                    });
                                    aggregate = &insert_value.instruction.value;
                                }

                                return aggregate;
                            }
                        } else {
                            fail();
                        }
                    },
                    .bitfield => {
                        const bitfield_type = ty.get_payload(.bitfield);

                        var names_initialized = PinnedArray(u32){};
                        var is_constant = true;
                        var values = PinnedArray(*Value){};

                        var field_index: u32 = 0;
                        var is_field_ordered = true;
                        while (parser.parse_field_initialization(analyzer, thread, file, names_initialized.const_slice(), bitfield_type.fields)) |field_data| : (field_index += 1) {
                            is_field_ordered = is_field_ordered and field_index == field_data.index;
                            _ = names_initialized.append(field_data.name);
                            _ = values.append(field_data.value);
                            is_constant = is_constant and field_data.value.is_constant();
                        }

                        parser.i += 1;

                        if (is_constant) {
                            if (is_field_ordered and field_index == bitfield_type.fields.len) {
                                var result: u64 = 0;
                                var bit_offset: u16 = 0;
                                for (values.const_slice()) |value| {
                                    switch (value.sema.id) {
                                        .constant_int => {
                                            const constant_int = value.get_payload(.constant_int);
                                            const field_bit_count = constant_int.type.bit_size;
                                            const field_value = constant_int.n;
                                            const offset_value = field_value << @as(u6, @intCast(bit_offset));
                                            result |= offset_value;
                                            bit_offset += @intCast(field_bit_count);
                                        },
                                        else => |t| @panic(@tagName(t)),
                                    }
                                }

                                const constant_int = create_constant_int(thread, .{
                                    .n = result,
                                    .type = bitfield_type.backing_type,
                                });
                                return &constant_int.value; // autofix
                            } else {
                                unreachable;
                            }
                        } else {
                            fail_message("TODO: runtime struct initialization");
                        }
                    },
                    else => |t| @panic(@tagName(t)),
                }
            },
            '[' => {
                // This is an array expression
                parser.i += 1;

                const ty = maybe_type orelse fail();
                const array_type = ty.get_payload(.array);
                const element_count = array_type.descriptor.element_count;
                const element_type = array_type.descriptor.element_type;

                parser.skip_space(src);

                var values = PinnedArray(*Value){};
                
                var is_constant = true;
                while (true) {
                    parser.skip_space(src);

                    if (src[parser.i] == ']') {
                        break;
                    }

                    const value = parser.parse_expression(analyzer, thread, file, element_type, .right);
                    is_constant = is_constant and value.is_constant();
                    _ = values.append(value);

                    parser.skip_space(src);

                    switch (src[parser.i]) {
                        ']' => {},
                        ',' => parser.i += 1,
                        else => unreachable,
                    }
                }

                parser.i += 1;

                if (values.length != element_count) {
                    fail();
                }

                if (is_constant) {
                    const constant_array = thread.constant_arrays.append(.{
                        .value = .{
                            .sema = .{
                                .thread = thread.get_index(),
                                .resolved = true,
                                .id = .constant_array,
                            },
                        },
                        .values = values.const_slice(),
                        .type = ty,
                    });
                    return &constant_array.value;
                } else {
                    unreachable;
                }
            },
            else => unreachable,
        };

        const starting_index = parser.i;
        const starting_ch = src[starting_index];
        const is_digit_start = is_decimal_digit(starting_ch);
        const is_alpha_start = is_alphabetic(starting_ch);
        const debug_line = parser.get_debug_line();
        const debug_column = parser.get_debug_column();

        if (is_digit_start) {
            const ty = maybe_type orelse switch (unary) {
                .none => &thread.integers[63].type,
                .one_complement => fail(),
                .negation => fail(),
            };

            switch (ty.sema.id) {
                .integer => {
                    const constant_int = parser.parse_constant_integer(thread, file, ty);
                    switch (unary) {
                        .none => return &constant_int.value,
                        .one_complement => unreachable,
                        .negation => {
                            const integer_ty = ty.get_payload(.integer);
                            switch (integer_ty.signedness) {
                                .signed => {
                                    var n: i64 = @intCast(constant_int.n);
                                    n = 0 - n;
                                    const result = create_constant_int(thread, .{
                                        .n = @bitCast(n),
                                        .type = ty,
                                    });
                                    return &result.value;
                                },
                                .unsigned => fail(),
                            }
                        },
                    }
                },
                else => unreachable,
            }
        } else if (is_alpha_start) {
            var resolved = true;
            const name = parser.parse_raw_identifier(src);
            const keyword = parse_keyword(name);
            if (keyword != ~(@as(u32, 0))) {
                switch (@as(Keyword, @enumFromInt(keyword))) {
                    .undefined => {
                        const ty = maybe_type orelse fail();
                        const undef = thread.undefined_values.append(.{
                            .value = .{
                                .sema = .{
                                    .thread = thread.get_index(),
                                    .resolved = true,
                                    .id = .undefined,
                                },
                            },
                            .type = ty,
                        });

                        return &undef.value;
                    },
                    else => |t| @panic(@tagName(t)),
                }
            }

            const identifier: u32 = if (byte_equal(name, "_")) 0 else intern_identifier(&thread.identifiers, name);

            var initial_type: ?*Type = null;
            const initial_value = if (analyzer.current_scope.get_declaration(identifier)) |lookup_result| blk: {
                switch (lookup_result.declaration.*.id) {
                    .local => {
                        const local_declaration = lookup_result.declaration.*.get_payload(.local);
                        const local_symbol = local_declaration.to_symbol();
                        initial_type = local_symbol.type;
                        break :blk &local_symbol.instruction.value;
                    },
                    .global => {
                        const global_declaration = lookup_result.declaration.*.get_payload(.global);
                        switch (global_declaration.id) {
                            .global_symbol => {
                                const global_symbol = global_declaration.to_symbol();
                                initial_type = global_symbol.type;
                                break :blk &global_symbol.value;
                            },
                            .unresolved_import => {
                                const import: *Import = global_declaration.get_payload(.unresolved_import);
                                assert(!import.resolved);
                                resolved = false;
                                const import_index = for (file.imports.slice(), 0..) |existing_import, i| {
                                    if (import == existing_import) break i;
                                } else unreachable;
                                const lazy_expression = thread.lazy_expressions.append(LazyExpression.init(@ptrCast(lookup_result.declaration), thread));

                                while (true) {
                                    switch (src[parser.i]) {
                                        '.' => {
                                            parser.i += 1;
                                            const right = parser.parse_identifier(thread, src);
                                            lazy_expression.add(right);
                                        },
                                        '(' => break,
                                        else => @panic((src.ptr + parser.i)[0..1]),
                                    }
                                }

                                switch (src[parser.i]) {
                                    '(' => {
                                        parser.i += 1;
                                        // TODO: arguments
                                        parser.expect_character(src, ')');

                                        const call = thread.calls.append(.{
                                            .instruction = new_instruction(thread, .{
                                                .id = .call,
                                                .line = debug_line,
                                                .column = debug_column,
                                                .scope = analyzer.current_scope,
                                                .resolved = false,
                                            }),
                                            .callable = &lazy_expression.value,
                                            .arguments = &.{},
                                            .calling_convention = .c,
                                        });
                                        analyzer.append_instruction(&call.instruction);

                                        _ = file.values_per_import.get(@enumFromInt(import_index)).append(&call.instruction.value);
                                        return &call.instruction.value;
                                    },
                                    else => @panic((src.ptr + parser.i)[0..1]),
                                }
                            },
                            else => |t| @panic(@tagName(t)),
                        }
                    },
                    .argument => {
                        const argument_declaration = lookup_result.declaration.*.get_payload(.argument);
                        const argument_symbol = argument_declaration.to_symbol();
                        initial_type = argument_symbol.type;
                        break :blk &argument_symbol.instruction.value;
                    },
                    else => |t| @panic(@tagName(t)),
                }
            } else blk: {
                resolved = false;
                const lazy_expression = thread.local_lazy_expressions.append(.{
                    .value = .{
                        .sema = .{
                            .id = .local_lazy_expression,
                            .thread = thread.get_index(),
                            .resolved = false,
                        },
                    },
                    .name = identifier,
                });
                _ = file.local_lazy_expressions.append(lazy_expression);
                break :blk &lazy_expression.value;
            };

            switch (src[parser.i]) {
                ' ', ',', ';', ')' => {
                    return switch (unary) {
                        .none => switch (side) {
                            .right => right: {
                                const ty = if (initial_type) |source_ty| if (maybe_type) |destination_ty| blk: {
                                        switch (typecheck(destination_ty, source_ty)) {
                                            .success => {},
                                        }
                                        break :blk source_ty;
                                    } else source_ty
                                else if (maybe_type) |ty| ty else fail();

                                const load = emit_load(analyzer, thread, .{
                                    .value = initial_value,
                                    .type = ty,
                                    .line = debug_line,
                                    .column = debug_column,
                                    .scope = analyzer.current_scope,
                                });
                                break :right &load.instruction.value;
                            },
                            .left => initial_value,
                        },
                        .negation => neg: {
                            assert(side == .right);
                            var r = initial_value;
                            if (initial_value.get_type() != initial_type.?) {
                                const load = emit_load(analyzer, thread, .{
                                    .value = initial_value,
                                    .type = initial_type.?,
                                    .line = debug_line,
                                    .column = debug_column,
                                    .scope = analyzer.current_scope,
                                });
                                r = &load.instruction.value;
                            }

                            const operand = create_constant_int(thread, .{
                                .type = initial_type.?,
                                .n = 0,
                            });

                            const sub = emit_integer_binary_operation(analyzer, thread, .{
                                .line = debug_line,
                                .column = debug_column,
                                .scope = analyzer.current_scope,
                                .left = &operand.value,
                                .right = r,
                                .id = .sub,
                                .type = initial_type.?,
                            });
                            break :neg &sub.instruction.value;
                        },
                        .one_complement => oc: {
                            assert(side == .right);
                            var r = initial_value;
                            if (initial_value.get_type() != initial_type.?) {
                                const load = emit_load(analyzer, thread, .{
                                    .value = initial_value,
                                    .type = initial_type.?,
                                    .line = debug_line,
                                    .column = debug_column,
                                    .scope = analyzer.current_scope,
                                });
                                r = &load.instruction.value;
                            }

                            const operand = create_constant_int(thread, .{
                                .type = initial_type.?,
                                .n = std.math.maxInt(u64),
                            });

                            const xor = emit_integer_binary_operation(analyzer, thread, .{
                                .line = debug_line,
                                .column = debug_column,
                                .scope = analyzer.current_scope,
                                .left = r,
                                .right = &operand.value,
                                .id = .xor,
                                .type = initial_type.?,
                            });
                            break :oc &xor.instruction.value;
                        },
                    };
                },
                '&' => {
                    parser.i += 1;

                    return initial_value;
                },
                '(' => {
                    parser.i += 1;
                    parser.skip_space(src);

                    switch (initial_value.sema.resolved) {
                        true => {
                            const FunctionCallData = struct{
                                type: *Type.Function,
                                value: *Value,
                                calling_convention: CallingConvention,
                            };

                            const function_call_data: FunctionCallData = switch (initial_type.?.sema.id) {
                                .function => .{
                                    .type = initial_type.?.get_payload(.function),
                                    .value = initial_value,
                                    .calling_convention = switch (initial_value.sema.id) {
                                        .global_symbol => b: {
                                            const global_symbol = initial_value.get_payload(.global_symbol);
                                            switch (global_symbol.id) {
                                                .function_definition => {
                                                    const function_definition = global_symbol.get_payload(.function_definition);
                                                    break :b function_definition.declaration.get_function_type().abi.calling_convention;
                                                },
                                                .function_declaration => {
                                                    const function_declaration = global_symbol.get_payload(.function_declaration);
                                                    break :b function_declaration.get_function_type().abi.calling_convention;
                                                },
                                                else => |t| @panic(@tagName(t)),
                                            }
                                        },
                                        else => |t| @panic(@tagName(t)),
                                    },
                                },
                                .typed_pointer => switch (initial_value.sema.id) {
                                    .instruction => blk: {
                                        const instruction = initial_value.get_payload(.instruction);
                                        switch (instruction.id) {
                                            .local_symbol => {
                                                const local_symbol = instruction.get_payload(.local_symbol);
                                                const pointer_type = local_symbol.type.get_payload(.typed_pointer);
                                                const function_type = pointer_type.descriptor.pointee.get_payload(.function);

                                                const load = emit_load(analyzer, thread, .{
                                                    .value = &local_symbol.instruction.value,
                                                    .type = local_symbol.type,
                                                    .line = debug_line,
                                                    .column = debug_column,
                                                    .scope = analyzer.current_scope,
                                                });
                                                break :blk .{
                                                    .type = function_type,
                                                    .value = &load.instruction.value,
                                                    // TODO:
                                                    .calling_convention = .c,
                                                };
                                            },
                                            else => |t| @panic(@tagName(t)),
                                        }
                                    },
                                    else => |t| @panic(@tagName(t)),
                                },
                                else => |t| @panic(@tagName(t)),
                            };

                            const function_type = function_call_data.type;
                            const function_value = function_call_data.value;

                            var abi_argument_values = PinnedArray(*Value){};

                            const indirect_return_value: ?*Value = switch (function_type.abi.return_type_abi.kind) {
                                .indirect => |indirect| ind: {
                                    if (indirect.alignment <= indirect.type.alignment) {
                                        const return_local = emit_local_symbol(analyzer, thread, .{
                                            .name = 0,
                                            .initial_value = null,
                                            .type = indirect.type,
                                            .line = 0,
                                            .column = 0,
                                        });
                                        const return_value = &return_local.instruction.value;
                                        _ = abi_argument_values.append(return_value);

                                        break :ind return_value;
                                    } else {
                                        unreachable;
                                    }
                                },
                                else => null,
                            };

                            var original_argument_i: u32 = 0;
                            const declaration_argument_count = function_type.abi.original_argument_types.len;
                            while (true) {
                                parser.skip_space(src);

                                if (src[parser.i] == ')') {
                                    break;
                                }
                                
                                const argument_index = original_argument_i;
                                if (argument_index >= declaration_argument_count) {
                                    fail();
                                }

                                const argument_abi = function_type.abi.argument_types_abi[argument_index];
                                const argument_type = function_type.abi.original_argument_types[argument_index];
                                const argument_value = parser.parse_expression(analyzer, thread, file, argument_type, .right);
                                const argument_value_type = argument_value.get_type();

                                parser.skip_space(src);

                                switch (src[parser.i]) {
                                    ',' => parser.i += 1,
                                    ')' => {},
                                    else => unreachable,
                                }

                                switch (argument_abi.kind) {
                                    .direct => {
                                        assert(argument_value_type == argument_type);
                                        _ = abi_argument_values.append(argument_value);
                                    },
                                    .direct_coerce => |coerced_type| {
                                        const coerced_value = emit_direct_coerce(analyzer, thread, .{
                                            .original_value = argument_value,
                                            .coerced_type = coerced_type,
                                        });
                                        _ = abi_argument_values.append(coerced_value);
                                    },
                                    .indirect => |indirect| {
                                        assert(argument_type == indirect.type);
                                        const direct = if (!argument_abi.attributes.by_value) false else switch (argument_type.sema.id) {
                                            .typed_pointer => unreachable,
                                            else => false,
                                        };

                                        if (direct) {
                                            unreachable;
                                        } else {
                                            const indirect_local = emit_local_symbol(analyzer, thread, .{
                                                .type = argument_type,
                                                .name = 0,
                                                .initial_value = argument_value,
                                                .line = 0,
                                                .column = 0,
                                            });
                                            _ = abi_argument_values.append(&indirect_local.instruction.value);
                                        }
                                    },
                                    .direct_pair => |pair| {
                                        const pair_struct_type = get_anonymous_two_field_struct(thread, pair);
                                        const are_similar = b: {
                                            if (pair_struct_type == argument_type) {
                                                break :b true;
                                            } else {
                                                switch (argument_type.sema.id) {
                                                    .@"struct" => {
                                                        const original_struct_type = argument_type.get_payload(.@"struct");
                                                        if (original_struct_type.fields.len == 2) {
                                                            for (original_struct_type.fields, pair) |field, pair_type| {
                                                                if (field.type != pair_type) break :b false;
                                                            }
                                                            break :b true;
                                                        } else break :b false;
                                                    },
                                                    else => |t| @panic(@tagName(t)),
                                                }
                                            }
                                        };

                                        if (are_similar) {
                                            const extract_0 = emit_extract_value(thread, analyzer, .{
                                                .aggregate = argument_value,
                                                .index = 0,
                                                .line = 0,
                                                .column = 0,
                                                .scope = analyzer.current_scope,
                                                .type = pair[0],
                                            });
                                            _ = abi_argument_values.append(&extract_0.instruction.value);
                                            const extract_1 = emit_extract_value(thread, analyzer, .{
                                                .aggregate = argument_value,
                                                .index = 1,
                                                .line = 0,
                                                .column = 0,
                                                .scope = analyzer.current_scope,
                                                .type = pair[1],
                                            });
                                            _ = abi_argument_values.append(&extract_1.instruction.value);
                                        } else {
                                            const local_value = if (argument_type.alignment < pair_struct_type.alignment) b: {
                                                const coerced_local = emit_local_symbol(analyzer, thread, .{
                                                    .type = pair_struct_type,
                                                    .name = 0,
                                                    .initial_value = argument_value,
                                                    .line = 0,
                                                    .column = 0,
                                                });
                                                break :b &coerced_local.instruction.value;
                                            } else b: {
                                                const argument_local = emit_local_symbol(analyzer, thread, .{
                                                    .type = argument_type,
                                                    .name = 0,
                                                    .initial_value = argument_value,
                                                    .line = 0,
                                                    .column = 0,
                                                });
                                                break :b &argument_local.instruction.value;
                                            };
                                            const gep0 = emit_gep(thread, analyzer, .{
                                                .pointer = local_value,
                                                .type = pair[0],
                                                .aggregate_type = pair_struct_type,
                                                .is_struct = true,
                                                .index = &create_constant_int(thread, .{
                                                    .n = 0,
                                                    .type = &thread.integers[31].type,
                                                }).value,
                                                .line = 0,
                                                .column = 0,
                                                .scope = analyzer.current_scope,
                                            });
                                            const load0 = emit_load(analyzer, thread, .{
                                                .type = pair[0],
                                                .value = &gep0.instruction.value,
                                                .scope = analyzer.current_scope,
                                                .line = 0,
                                                .column = 0,
                                            });
                                            _ = abi_argument_values.append(&load0.instruction.value);
                                            const gep1 = emit_gep(thread, analyzer, .{
                                                .pointer = local_value,
                                                .type = pair[1],
                                                .aggregate_type = pair_struct_type,
                                                .is_struct = true,
                                                .index = &create_constant_int(thread, .{
                                                    .n = 1,
                                                    .type = &thread.integers[31].type,
                                                }).value,
                                                .line = 0,
                                                .column = 0,
                                                .scope = analyzer.current_scope,
                                            });
                                            const load1 = emit_load(analyzer, thread, .{
                                                .type = pair[1],
                                                .value = &gep1.instruction.value,
                                                .scope = analyzer.current_scope,
                                                .line = 0,
                                                .column = 0,
                                            });
                                            _ = abi_argument_values.append(&load1.instruction.value);
                                        }
                                    },
                                    else => |t| @panic(@tagName(t)),
                                }

                                original_argument_i += 1;
                            }

                            parser.i += 1;
                            const call = thread.calls.append(.{
                                .instruction = new_instruction(thread, .{
                                    .id = .call,
                                    .line = debug_line,
                                    .column = debug_column,
                                    .scope = analyzer.current_scope,
                                }),
                                .callable = function_value,
                                .arguments = abi_argument_values.const_slice(),
                                .calling_convention = function_call_data.calling_convention,
                            });
                            analyzer.append_instruction(&call.instruction);

                            if (indirect_return_value) |irv| {
                                const load = emit_load(analyzer, thread, .{
                                    .value = irv,
                                    .type = function_type.abi.original_return_type,
                                    .line = 0,
                                    .column = 0,
                                    .scope = analyzer.current_scope,
                                });
                                return &load.instruction.value;
                            } else {
                                return &call.instruction.value;
                            }
                        },
                        false => {
                            var argument_values = PinnedArray(*Value){};

                            while (true) {
                                parser.skip_space(src);

                                if (src[parser.i] == ')') {
                                    break;
                                }

                                const passed_argument_value = parser.parse_expression(analyzer, thread, file, null, .right);
                                _ = argument_values.append(passed_argument_value);

                                parser.skip_space(src);

                                switch (src[parser.i]) {
                                    ',' => parser.i += 1,
                                    ')' => {},
                                    else => unreachable,
                                }
                            }

                            parser.i += 1;

                            const call = thread.calls.append(.{
                                .instruction = new_instruction(thread, .{
                                    .id = .call,
                                    .line = debug_line,
                                    .column = debug_column,
                                    .scope = analyzer.current_scope,
                                    .resolved = false,
                                }),
                                .callable = initial_value,
                                .arguments = argument_values.const_slice(),
                                .calling_convention = .c,
                            });
                            switch (initial_value.sema.id) {
                                .local_lazy_expression => {
                                    const local_lazy_expression = initial_value.get_payload(.local_lazy_expression);
                                    _ = local_lazy_expression.values.append(&call.instruction.value);
                                },
                                else => |t| @panic(@tagName(t)),
                            }
                            analyzer.append_instruction(&call.instruction);
                            return &call.instruction.value;
                        },
                    }
                },
                '[' => {
                    parser.i += 1;

                    parser.skip_space(src);

                    const declaration_element_type = switch (initial_type.?.sema.id) {
                        .array => block: {
                            const array_type = initial_type.?.get_payload(.array);
                            break :block array_type.descriptor.element_type;
                        },
                        else => |t| @panic(@tagName(t)),
                    };

                    const index = parser.parse_expression(analyzer, thread, file, null, .right);

                    parser.skip_space(src);

                    parser.expect_character(src, ']');
                    const gep = emit_gep(thread, analyzer, .{
                        .pointer = initial_value,
                        .index = index,
                        .type = declaration_element_type,
                        .aggregate_type = initial_type.?,
                        .is_struct = false,
                        .line = debug_line,
                        .column = debug_column,
                        .scope = analyzer.current_scope,
                    });

                    return switch (side) {
                        .left => &gep.instruction.value,
                        .right => block: {
                            const load = emit_load(analyzer, thread, .{
                                .value = &gep.instruction.value,
                                .type = declaration_element_type,
                                .line = debug_line,
                                .column = debug_column,
                                .scope = analyzer.current_scope,
                            });
                            break :block &load.instruction.value;
                        },
                    };
                },
                '.' => {
                    const result = parser.parse_field_access(analyzer, thread, file, maybe_type, side, initial_value, initial_type.?, debug_line, debug_column);
                    return result;
                },
                '@' => {
                    parser.i += 1;

                    assert(initial_type.?.sema.id == .typed_pointer);

                    const load = emit_load(analyzer, thread, .{
                        .value = initial_value,
                        .type = initial_type.?,
                        .line = debug_line,
                        .column = debug_column,
                        .scope = analyzer.current_scope,
                    });

                    return switch (side) {
                        .left => &load.instruction.value,
                        .right => block: {
                            const pointer_load_type = switch (initial_type.?.sema.id) {
                                .typed_pointer => b: {
                                    const typed_pointer = initial_type.?.get_payload(.typed_pointer);
                                    break :b typed_pointer.descriptor.pointee;
                                },
                                else => |t| @panic(@tagName(t)),
                            };

                            if (maybe_type) |ty| {
                                switch (typecheck(ty, pointer_load_type)) {
                                    .success => {},
                                }
                            }

                            const pointer_load = emit_load(analyzer, thread, .{
                                .value = &load.instruction.value,
                                .type = pointer_load_type,
                                .line = debug_line,
                                .column = debug_column,
                                .scope = analyzer.current_scope,
                            });

                            break :block &pointer_load.instruction.value;
                        },
                    };
                },
                else => unreachable,
            }
        } else {
            fail();
        }
    }

    const CurrentOperation = enum{
        none,
        assign,
        add,
        add_assign,
        sub,
        sub_assign,
        mul,
        mul_assign,
        udiv,
        udiv_assign,
        sdiv,
        sdiv_assign,
        @"and",
        and_assign,
        @"or",
        or_assign,
        @"xor",
        xor_assign,
        shift_left,
        shift_left_assign,
        arithmetic_shift_right,
        arithmetic_shift_right_assign,
        logical_shift_right,
        logical_shift_right_assign,

        compare_equal,
        compare_not_equal,
        compare_unsigned_greater,
        compare_unsigned_greater_equal,
        compare_signed_greater,
        compare_signed_greater_equal,
        compare_unsigned_less,
        compare_unsigned_less_equal,
        compare_signed_less,
        compare_signed_less_equal,

        @"orelse",
    };

    fn parse_constant_expression(parser: *Parser, thread: *Thread, file: *File, maybe_type: ?*Type) *Value {
        const src = file.source_code;
        const starting_index = parser.i;
        const starting_ch = src[starting_index];
        const is_digit_start = is_decimal_digit(starting_ch);
        if (is_digit_start) {
            const ty = maybe_type orelse &thread.integers[63].type;
            switch (ty.sema.id) {
                .integer => {
                    const constant_int = parser.parse_constant_integer(thread, file, ty);
                    return &constant_int.value;
                },
                else => unreachable,
            }
        } else {
            unreachable;
        }
    }

    fn parse_field_access(parser: *Parser, analyzer: *Analyzer, thread: *Thread, file: *File, expected_type: ?*Type, side: Side, value: *Value, ty: *Type, line: u32, column: u32) *Value{
        const src = file.source_code;
        parser.expect_character(src, '.');

        switch (ty.sema.id) {
            .@"struct" => {
                const struct_type = ty.get_payload(.@"struct");
                const field_name = parser.parse_identifier(thread, src);
                const field_index = for (struct_type.fields) |field| {
                    if (field.name == field_name) {
                        break field.index;
                    }
                } else fail();

                const index_value = create_constant_int(thread, .{
                    .type = &thread.integers[31].type,
                    .n = field_index,
                });

                const gep = emit_gep(thread, analyzer, .{
                    .line = line,
                    .column = column,
                    .scope = analyzer.current_scope,
                    .pointer = value,
                    .index = &index_value.value,
                    .aggregate_type = ty,
                    .type = struct_type.fields[field_index].type,
                    .is_struct = true,
                });

                const result = switch (side) {
                    .right => block: {
                        const load = emit_load(analyzer, thread, .{
                            .value = &gep.instruction.value,
                            .type = gep.type,
                            .scope = analyzer.current_scope,
                            .line = line,
                            .column = column,
                        });

                        break :block &load.instruction.value;
                    },
                    else => |t| @panic(@tagName(t)),
                };

                const result_type = result.get_type();
                if (expected_type) |expected| {
                    switch (typecheck(expected, result_type)) {
                        .success => {},
                    }
                }

                return result;
            },
            .bitfield => {
                const bitfield_type = ty.get_payload(.bitfield);
                const field_name = parser.parse_identifier(thread, src);
                const field_index = for (bitfield_type.fields) |field| {
                    if (field.name == field_name) {
                        break field.index;
                    }
                } else fail();
                const field = bitfield_type.fields[field_index];

                const load = emit_load(analyzer, thread, .{
                    .value = value,
                    .type = bitfield_type.backing_type,
                    .line = line,
                    .column = column,
                    .scope = analyzer.current_scope,
                });

                var result = &load.instruction.value;
                if (field.member_offset > 0) {
                    const shifter = create_constant_int(thread, .{
                        .n = field.member_offset,
                        .type = ty,
                    });
                    const shift = emit_integer_binary_operation(analyzer, thread, .{
                        .line = line,
                        .column = column,
                        .scope = analyzer.current_scope,
                        .left = result,
                        .right = &shifter.value,
                        .id = .logical_shift_right,
                        .type = bitfield_type.backing_type,
                    });
                    result = &shift.instruction.value;
                }

                if (field.type != bitfield_type.backing_type) {
                    const cast = emit_cast(analyzer, thread, .{
                        .value = result,
                        .type = field.type,
                        .id = .truncate,
                        .line = line,
                        .column = column,
                        .scope = analyzer.current_scope,
                    });
                    result = &cast.instruction.value;
                }

                assert(result != value);
                return result;
            },
            else => |t| @panic(@tagName(t)),
        }
    }

    fn parse_expression(parser: *Parser, analyzer: *Analyzer, thread: *Thread, file: *File, ty: ?*Type, side: Side) *Value {
        const src = file.source_code;

        var current_operation = CurrentOperation.none;
        var previous_value: *Value = undefined;
        var iterations: usize = 0;
        var it_ty: ?*Type = ty;

        while (true) {
            if (iterations == 1 and it_ty == null) {
                it_ty = previous_value.get_type();
            }
            const debug_line = parser.get_debug_line();
            const debug_column = parser.get_debug_column();

            var current_value: *Value = undefined;
            if (src[parser.i] == '(') {
                parser.i += 1;
                current_value = parser.parse_expression(analyzer, thread, file, it_ty, side);
                parser.expect_character(src, ')');
            } else {
                current_value = parser.parse_single_expression(analyzer, thread, file, it_ty, side);
            }

            parser.skip_space(src);

            switch (current_operation) {
                .none => {
                    previous_value = current_value;
                },
                .compare_equal, .compare_not_equal, .compare_unsigned_greater, .compare_unsigned_greater_equal, .compare_signed_greater, .compare_signed_greater_equal, .compare_unsigned_less, .compare_unsigned_less_equal, .compare_signed_less, .compare_signed_less_equal => {
                    switch (current_operation) {
                        else => unreachable,
                        inline .compare_equal, .compare_not_equal, .compare_unsigned_greater, .compare_unsigned_greater_equal, .compare_signed_greater, .compare_signed_greater_equal, .compare_unsigned_less, .compare_unsigned_less_equal, .compare_signed_less, .compare_signed_less_equal => |co| {
                            const string = @tagName(co)["compare_".len..];
                            const comparison = @field(IntegerCompare.Id, string);
                            const compare = thread.integer_compares.append(.{
                                .instruction = new_instruction(thread, .{
                                    .id = .integer_compare,
                                    .line = debug_line,
                                    .column = debug_column,
                                    .scope = analyzer.current_scope,
                                }),
                                .left = previous_value,
                                .right = current_value,
                                .id = comparison,
                            });
                            analyzer.append_instruction(&compare.instruction);
                            previous_value = &compare.instruction.value;
                        }
                    }
                },
                .add, .sub, .mul, .udiv, .sdiv, .@"and", .@"or", .xor, .shift_left, .arithmetic_shift_right, .logical_shift_right => {
                    const i = emit_integer_binary_operation(analyzer, thread, .{
                        .line = debug_line,
                        .column = debug_column,
                        .scope = analyzer.current_scope,
                        .left = previous_value,
                        .right = current_value,
                        .id = switch (current_operation) {
                            else => unreachable,
                            inline
                                .add,
                            .sub,
                            .mul,
                            .udiv,
                            .sdiv,
                            .@"and",
                            .@"or",
                            .@"xor",
                            .shift_left,
                            .arithmetic_shift_right,
                            .logical_shift_right,
                            => |co| @field(IntegerBinaryOperation.Id, @tagName(co)),
                        },
                        .type = if (it_ty) |t| t else current_value.get_type(),
                    });
                    previous_value = &i.instruction.value;
                },
                .assign, .add_assign, .sub_assign, .mul_assign, .udiv_assign, .sdiv_assign, .and_assign, .or_assign, .xor_assign, .shift_left_assign, .logical_shift_right_assign, .arithmetic_shift_right_assign => unreachable,
                .@"orelse" => {
                    const orelse_type = ty orelse unreachable;
                    const condition = emit_condition(analyzer, thread, .{
                        .condition = previous_value,
                        .line = debug_line,
                        .column = debug_column,
                        .scope = analyzer.current_scope,
                    });
                    const true_block = create_basic_block(thread);
                    const false_block = create_basic_block(thread);
                    const phi_block = create_basic_block(thread);
                    _ = emit_branch(analyzer, thread, .{
                        .condition = condition,
                        .taken = true_block,
                        .not_taken = false_block,
                        .line = debug_line,
                        .column = debug_column,
                        .scope = analyzer.current_scope,
                    });
                    const phi = thread.phis.append(.{
                        .instruction = new_instruction(thread, .{
                            .id = .phi,
                            .line = debug_line,
                            .column = debug_column,
                            .scope = analyzer.current_scope,
                        }),
                        .type = orelse_type,
                    });
                    _ = phi.nodes.append(.{
                        .value = previous_value,
                        .basic_block = true_block,
                    });
                    _ = phi.nodes.append(.{
                        .value = current_value,
                        .basic_block = false_block,
                    });
                    analyzer.current_basic_block = true_block;
                    _ = emit_jump(analyzer, thread, .{
                        .basic_block = phi_block,
                            .line = debug_line,
                            .column = debug_column,
                            .scope = analyzer.current_scope,
                    });
                    analyzer.current_basic_block = false_block;
                    _ = emit_jump(analyzer, thread, .{
                        .basic_block = phi_block,
                            .line = debug_line,
                            .column = debug_column,
                            .scope = analyzer.current_scope,
                    });

                    analyzer.current_basic_block = phi_block;
                    analyzer.append_instruction(&phi.instruction);

                    previous_value = &phi.instruction.value;
                },
            }

            const original_index = parser.i;
            const original = src[original_index];
            switch (original) {
                ')', ';', ',', ']' => return previous_value,
                'o' => {
                    const identifier = parser.parse_raw_identifier(src);
                    if (byte_equal(identifier, "orelse")) {
                        current_operation = .@"orelse";
                    } else {
                        parser.i = original;
                        fail();
                    }

                    parser.skip_space(src);
                },
                '=' => {
                    current_operation = .assign;
                    parser.i += 1;

                    switch (src[parser.i]) {
                        '=' => {
                            current_operation = .compare_equal;
                            parser.i += 1;
                        },
                        else => {},
                    }

                    parser.skip_space(src);
                },
                '!' => {
                    current_operation = undefined;
                    parser.i += 1;

                    switch (src[parser.i]) {
                        '=' => {
                            current_operation = .compare_not_equal;
                            parser.i += 1;
                        },
                        else => unreachable,
                    }

                    parser.skip_space(src);
                },
                '+' => {
                    current_operation = .add;
                    parser.i += 1;

                    switch (src[parser.i]) {
                        '=' => {
                            current_operation = .add_assign;
                            parser.i += 1;
                        },
                        else => {},
                    }

                    parser.skip_space(src);
                },
                '-' => {
                    current_operation = .sub;
                    parser.i += 1;

                    switch (src[parser.i]) {
                        '=' => {
                            current_operation = .sub_assign;
                            parser.i += 1;
                        },
                        else => {},
                    }

                    parser.skip_space(src);
                },
                '*' => {
                    current_operation = .mul;
                    parser.i += 1;

                    switch (src[parser.i]) {
                        '=' => {
                            current_operation = .mul_assign;
                            parser.i += 1;
                        },
                        else => {},
                    }

                    parser.skip_space(src);
                },
                '/' => {
                    const int_ty = it_ty orelse previous_value.get_type();
                    const integer_type = int_ty.get_payload(.integer);
                    current_operation = switch (integer_type.signedness) {
                        .unsigned => .udiv,
                        .signed => .sdiv,
                    };
                    parser.i += 1;

                    switch (src[parser.i]) {
                        '=' => {
                            current_operation = switch (integer_type.signedness) {
                                .unsigned => .udiv_assign,
                                .signed => .sdiv_assign,
                            };
                            parser.i += 1;
                        },
                        else => {},
                    }

                    parser.skip_space(src);
                },
                '&' => {
                    current_operation = .@"and";
                    parser.i += 1;

                    switch (src[parser.i]) {
                        '=' => {
                            current_operation = .and_assign;
                            parser.i += 1;
                        },
                        else => {},
                    }

                    parser.skip_space(src);
                },
                '|' => {
                    current_operation = .@"or";
                    parser.i += 1;

                    switch (src[parser.i]) {
                        '=' => {
                            current_operation = .or_assign;
                            parser.i += 1;
                        },
                        else => {},
                    }

                    parser.skip_space(src);
                },
                '^' => {
                    current_operation = .@"xor";
                    parser.i += 1;

                    switch (src[parser.i]) {
                        '=' => {
                            current_operation = .xor_assign;
                            parser.i += 1;
                        },
                        else => {},
                    }

                    parser.skip_space(src);
                },
                '<' => {
                    const int_ty = it_ty orelse previous_value.get_type();
                    const integer_type = int_ty.get_payload(.integer);
                    current_operation = switch (integer_type.signedness) {
                        .unsigned => .compare_unsigned_less,
                        .signed => .compare_signed_less,
                    };
                    parser.i += 1;

                    switch (src[parser.i]) {
                        '<' => {
                            current_operation = .shift_left;
                            parser.i += 1;

                            switch (src[parser.i]) {
                                '=' => {
                                    current_operation = .shift_left_assign;
                                    parser.i += 1;
                                },
                                else => {},
                            }
                        },
                        '=' => {
                            unreachable;
                        },
                        else => {},
                    }

                    parser.skip_space(src);
                },
                '>' => {
                    const int_ty = it_ty orelse previous_value.get_type();
                    const integer_type = int_ty.get_payload(.integer);
                    current_operation = switch (integer_type.signedness) {
                        .unsigned => .compare_unsigned_greater,
                        .signed => .compare_signed_greater,
                    };
                    parser.i += 1;

                    switch (src[parser.i]) {
                        '>' => {
                            current_operation = switch (integer_type.signedness) {
                                .unsigned => .logical_shift_right,
                                .signed => .arithmetic_shift_right,
                            };
                            parser.i += 1;

                            switch (src[parser.i]) {
                                '=' => {
                                    current_operation = switch (integer_type.signedness) {
                                        .unsigned => .logical_shift_right_assign,
                                        .signed => .arithmetic_shift_right_assign,
                                    };

                                    parser.i += 1;
                                },
                                else => {},
                            }
                        },
                        '=' => {
                            current_operation = switch (integer_type.signedness) {
                                .unsigned => .compare_unsigned_greater_equal,
                                .signed => .compare_signed_greater_equal,
                            };

                            parser.i += 1;
                        },
                        else => {},
                    }

                    parser.skip_space(src);
                },
                else => @panic((src.ptr + parser.i)[0..1]),
            }

            iterations += 1;
        }
    }

    const IfResult = struct {
        terminated: bool,
    };

    fn parse_condition(parser: *Parser, analyzer: *Analyzer, thread: *Thread, file: *File) *Value {
        const src = file.source_code;
        parser.expect_character(src, '(');

        parser.skip_space(src);

        const debug_line = parser.get_debug_line();
        const debug_column = parser.get_debug_column();
        const scope = analyzer.current_scope;
        const condition = parser.parse_expression(analyzer, thread, file, null, .right);

        parser.skip_space(src);

        parser.expect_character(src, ')');

        parser.skip_space(src);

        return emit_condition(analyzer, thread, .{
            .condition = condition,
            .line = debug_line,
            .column = debug_column,
            .scope = scope,
        });
    }

    fn parse_if_expression(parser: *Parser, analyzer: *Analyzer, thread: *Thread, file: *File) IfResult {
        const src = file.source_code;
        parser.i += 2;

        parser.skip_space(src);

        const debug_line = parser.get_debug_line();
        const debug_column = parser.get_debug_line();
        const compare = parser.parse_condition(analyzer, thread, file);

        const original_block = analyzer.current_basic_block;

        const taken_block = create_basic_block(thread);
        const exit_block = create_basic_block(thread);
        _ = analyzer.exit_blocks.append(exit_block);
        const exit_block_count = analyzer.exit_blocks.length;

        const branch_emission = emit_branch(analyzer, thread, .{
            .condition = compare,
            .taken = taken_block,
            .not_taken = exit_block,
            .line = debug_line,
            .column = debug_column,
            .scope = analyzer.current_scope,
        });
        _ = branch_emission; // autofix

        analyzer.current_basic_block = taken_block;

        var if_terminated = false;
        var else_terminated = false;
        var if_jump_emission: JumpEmission = undefined;
        switch (src[parser.i]) {
            brace_open => { 
                const if_block = analyze_local_block(thread, analyzer, parser, file);
                if_terminated = if_block.terminated;

                if (!if_terminated) {
                    if_jump_emission = emit_jump(analyzer, thread, .{
                        .basic_block = exit_block,
                        .line = 0,
                        .column = 0,
                        .scope = analyzer.current_scope,
                    });
                }
            },
            else => @panic((src.ptr + parser.i)[0..1]),
        }

        parser.skip_space(src);

        if (src[parser.i] == 'e' and byte_equal(src[parser.i..][0.."else".len], "else")) {
            // TODO: create not taken block
            parser.i += "else".len;
            analyzer.current_basic_block = exit_block;

            parser.skip_space(src);

            switch (src[parser.i]) {
                brace_open => { 
                    const else_block = analyze_local_block(thread, analyzer, parser, file);
                    else_terminated = else_block.terminated;
                },
                'i' => {
                    if (src[parser.i + 1] == 'f') {
                        const else_if = parser.parse_if_expression(analyzer, thread, file);
                        else_terminated = else_if.terminated;
                    } else {
                        unreachable;
                    }
                },
                else => @panic((src.ptr + parser.i)[0..1]),
            }

            if (!if_terminated or !else_terminated) {
                const new_exit_block = create_basic_block(thread);
                const not_taken_block = exit_block;
                // Fix jump

                if (!if_terminated) {
                    assert(if_jump_emission.jump.basic_block == not_taken_block);
                    if_jump_emission.jump.basic_block.predecessors.length = 0;
                    _ = if_jump_emission.jump.basic_block.predecessors.append(original_block);
                    _ = new_exit_block.predecessors.append(if_jump_emission.jump.basic_block);
                    if_jump_emission.jump.basic_block = new_exit_block;
                }

                if (!else_terminated) {
                    // Emit jump to the new exit block
                    _ = emit_jump(analyzer, thread, .{
                        .basic_block = new_exit_block,
                        .line = 0,
                        .column = 0,
                        .scope = analyzer.current_scope,
                    });
                }

                analyzer.current_basic_block = new_exit_block;
            }
        } else {
            _ = exit_block.predecessors.append(original_block);
            analyzer.current_basic_block = exit_block;
        }

        if (!if_terminated and !else_terminated) {
            assert(analyzer.exit_blocks.length == exit_block_count);
            analyzer.exit_blocks.length -= 1;
        }

        return .{
            .terminated = if_terminated and else_terminated,
        };
    }
};

const LocalLazyExpression = struct{
    value: Value,
    name: u32,
    values: PinnedArray(*Value) = .{},
};

const LazyExpression = struct {
    value: Value,
    u: union(enum) {
        dynamic: struct{
            names: PinnedArray(u32) = .{},
            outsider: GlobalDeclaration.Reference,
        },
        static: struct {
            names: [4]u32 = .{0} ** 4,
            outsider: GlobalDeclaration.Reference,
        },
    },

    fn init(global_declaration: GlobalDeclaration.Reference, thread: *Thread) LazyExpression {
        return .{
            .value = .{
                .sema = .{
                    .thread = thread.get_index(),
                    .resolved = false,
                    .id = .lazy_expression,
                },
            },
            .u = .{
                .static = .{
                    .outsider = global_declaration,
                },
            }
        };
    }

    fn length(lazy_expression: *LazyExpression) u32 {
        return switch (lazy_expression.u) {
            .dynamic => |*d| d.names.length,
            .static => |*s| for (s.names, 0..) |n, i| {
                if (n == 0) break @intCast(i);
            } else s.names.len,
        };
    }

    fn names(lazy_expression: *LazyExpression) []const u32 {
        return switch (lazy_expression.u) {
            .dynamic => |*d| d.names.slice(),
            .static => |*s| s.names[0.. for (s.names, 0..) |n, i| {
                if (n == 0) break @intCast(i);
            } else s.names.len],
        };
    }

    fn add(lazy_expression: *LazyExpression, name: u32) void {
        const index = lazy_expression.length();
        if (index < 4) {
            lazy_expression.u.static.names[index] = name;
        } else {
            unreachable;
        }
    }
};

const Value = struct {
    llvm: ?*LLVM.Value = null,
    sema: struct {
        thread: u16,
        resolved: bool,
        reserved: u7 = 0,
        id: Id,
    },
    reserved: u32 = 0,

    const Id = enum(u8){
        argument,
        basic_block,
        constant_array,
        constant_struct,
        constant_bitfield,
        constant_int,
        instruction,
        global_symbol,
        lazy_expression,
        local_lazy_expression,
        undefined,
    };

    const id_to_value_map = std.EnumArray(Id, type).init(.{
        .argument = ArgumentSymbol,
        .basic_block = BasicBlock,
        .constant_array = ConstantArray,
        .constant_struct = ConstantStruct,
        .constant_bitfield = ConstantBitfield,
        .constant_int = ConstantInt,
        .global_symbol = GlobalSymbol,
        .instruction = Instruction,
        .lazy_expression = LazyExpression,
        .local_lazy_expression = LocalLazyExpression,
        .undefined = Undefined,
    });

    fn is_constant(value: *Value) bool {
        return switch (value.sema.id) {
            .constant_int,
            .constant_struct,
            .undefined,
            => true,
            .instruction => false,
            else => |t| @panic(@tagName(t)),
        };
    }

    fn get_payload(value: *Value, comptime id: Id) *id_to_value_map.get(id) {
        assert(value.sema.id == id);
        return @fieldParentPtr("value", value);
    }

    fn get_type(value: *Value) *Type {
        return switch (value.sema.id) {
            .instruction => blk: {
                const instruction = value.get_payload(.instruction);
                break :blk switch (instruction.id) {
                    .integer_binary_operation => block: {
                        const bin_op = instruction.get_payload(.integer_binary_operation);
                        break :block bin_op.type;
                    },
                    .load => block: {
                        const load = instruction.get_payload(.load);
                        break :block load.type;
                    },
                    .call => {
                        const call = instruction.get_payload(.call);
                        const function_type = call.get_function_type();
                        return function_type.abi.original_return_type;
                    },
                    .integer_compare => {
                        return &instance.threads[value.sema.thread].integers[0].type;
                    },
                    .trailing_zeroes => {
                        const tz = instruction.get_payload(.trailing_zeroes);
                        return tz.value.get_type();
                    },
                    .leading_zeroes => {
                        const lz = instruction.get_payload(.leading_zeroes);
                        return lz.value.get_type();
                    },
                    .local_symbol => {
                        const local_symbol = instruction.get_payload(.local_symbol);
                        return local_symbol.pointer_type;
                    },
                    .argument_storage => {
                        const argument_symbol = instruction.get_payload(.argument_storage);
                        return argument_symbol.pointer_type;
                    },
                    .cast => {
                        const cast = instruction.get_payload(.cast);
                        return cast.type;
                    },
                    .insert_value => {
                        const insert_value = instruction.get_payload(.insert_value);
                        return insert_value.type;
                    },
                    .phi => {
                        const phi = instruction.get_payload(.phi);
                        return phi.type;
                    },
                    else => |t| @panic(@tagName(t)),
                };
            },
            .constant_int => {
                const constant_int = value.get_payload(.constant_int);
                return constant_int.type;
            },
            .global_symbol => {
                const global_symbol = value.get_payload(.global_symbol);
                return global_symbol.pointer_type;
            },
            .constant_struct => {
                const constant_struct = value.get_payload(.constant_struct);
                return constant_struct.type;
            },
            else => |t| @panic(@tagName(t)),
        };
    }
};

const Type = struct {
    llvm: ?*LLVM.Type = null,
    llvm_debug: ?*LLVM.DebugInfo.Type = null,
    // TODO: ZIG BUG: if this is a packed struct, the initialization is broken
    sema: struct {
        thread: u16,
        id: Id,
        resolved: bool,
        reserved: u7 = 0,
    },
    size: u64,
    bit_size: u64,
    alignment: u32,

    const Id = enum(u8){
        unresolved,
        void,
        noreturn,
        integer,
        array,
        opaque_pointer,
        typed_pointer,
        function,
        @"struct",
        bitfield,
        anonymous_struct,
    };

    const Integer = struct {
        type: Type,
        signedness: Signedness,

        const Signedness = enum(u1){
            unsigned,
            signed,
        };
    };

    const Array = struct {
        type: Type,
        descriptor: Descriptor,

        const Descriptor = struct{
            element_count: u64,
            element_type: *Type,
        };
    };

    const Function = struct{
        type: Type,
        abi: compiler.Function.Abi,
    };

    const Struct = struct {
        type: Type,
        declaration: Declaration,
        fields: []const *AggregateField,
    };

    const AnonymousStruct = struct{
        type: Type,
        fields: []const *AggregateField,
    };

    const Bitfield = struct{
        type: Type,
        declaration: Declaration,
        fields: []const *AggregateField,
        backing_type: *Type,
    };

    const AggregateField = struct{
        type: *Type,
        parent: *Type,
        member_offset: u64,
        name: u32,
        index: u32,
        line: u32,
        column: u32,
    };

    const TypedPointer = struct{
        type: Type,
        descriptor: Descriptor,

        const Descriptor = struct{
            pointee: *Type,
        };
    };

    const id_to_type_map = std.EnumArray(Id, type).init(.{
        .unresolved = void,
        .void = void,
        .noreturn = void,
        .integer = Integer,
        .array = Array,
        .opaque_pointer = void,
        .function = Type.Function,
        .@"struct" = Type.Struct,
        .bitfield = Type.Bitfield,
        .typed_pointer = TypedPointer,
        .anonymous_struct = AnonymousStruct,
    });

    fn get_payload(ty: *Type, comptime id: Id) *id_to_type_map.get(id) {
        assert(ty.sema.id == id);
        return @fieldParentPtr("type", ty);
    }

    fn clone(ty: *Type, args: struct{
        destination_thread: *Thread,
        source_thread_index: u16,
    }) *Type {
        assert(args.destination_thread.get_index() == 0);
        const result: *Type = if (args.destination_thread.cloned_types.get(ty)) |result| blk: {
            assert(result.sema.thread == args.destination_thread.get_index());
            break :blk result;
        } else blk: {
            assert(ty.sema.resolved);
            assert(ty.sema.thread == args.source_thread_index);

            const result: *Type = switch (ty.sema.id) {
                .integer => {
                    const source_thread = &instance.threads[args.source_thread_index];
                    const source_integer_type = ty.get_payload(.integer);
                    const index = @divExact(@intFromPtr(source_integer_type) - @intFromPtr(&source_thread.integers), @sizeOf(Type.Integer));
                    break :blk &args.destination_thread.integers[index].type;
                },
                .function => block: {
                    const source_function_type = ty.get_payload(.function);
                    const original_return_type = source_function_type.abi.original_return_type.clone(.{
                        .destination_thread = args.destination_thread,
                        .source_thread_index = args.source_thread_index,
                    });
                    const abi_return_type = source_function_type.abi.abi_return_type.clone(.{
                        .destination_thread = args.destination_thread,
                        .source_thread_index = args.source_thread_index,
                    });
                    const return_type_abi = source_function_type.abi.return_type_abi.clone(.{
                        .destination_thread = args.destination_thread,
                        .source_thread_index = args.source_thread_index,
                    });

                    var original_argument_types = PinnedArray(*Type){};
                    for (source_function_type.abi.original_argument_types) |original_argument_type| {
                        const new = original_argument_type.clone(.{
                            .destination_thread = args.destination_thread,
                            .source_thread_index = args.source_thread_index,
                        });
                        _ = original_argument_types.append(new);
                    }
                    var abi_argument_types = PinnedArray(*Type){};
                    for (source_function_type.abi.original_argument_types) |abi_argument_type| {
                        const new = abi_argument_type.clone(.{
                            .destination_thread = args.destination_thread,
                            .source_thread_index = args.source_thread_index,
                        });
                        _ = abi_argument_types.append(new);
                    }

                    var argument_type_abis = PinnedArray(compiler.Function.Abi.Information){};
                    for (source_function_type.abi.argument_types_abi) |argument_type_abi| {
                        const new = argument_type_abi.clone(.{
                            .destination_thread = args.destination_thread,
                            .source_thread_index = args.source_thread_index,
                        });
                        _ = argument_type_abis.append(new);
                    }

                    const function_type = args.destination_thread.function_types.append(.{
                        .type = source_function_type.type,
                        .abi = .{
                            .return_type_abi = return_type_abi,
                            .original_argument_types = original_argument_types.const_slice(),
                            .original_return_type = original_return_type,
                            .abi_return_type = abi_return_type,
                            .abi_argument_types = abi_argument_types.const_slice(),
                            .argument_types_abi = argument_type_abis.const_slice(),
                            .calling_convention = source_function_type.abi.calling_convention,
                        },
                    });
                    break :block &function_type.type;
                },
                else => |t| @panic(@tagName(t)),
            };

            result.llvm = null;
            result.sema.thread = args.destination_thread.get_index();

            args.destination_thread.cloned_types.put_no_clobber(ty, result);

            break :blk result;
        };

        assert(result.llvm == null);
        assert(result.sema.thread == args.destination_thread.get_index());
        return result;
    }

    fn is_aggregate(ty: *Type) bool {
        return switch (ty.sema.id) {
            .unresolved => unreachable,
            .array => unreachable,
            .function => unreachable,
            .void,
            .noreturn, 
            .integer,
            .opaque_pointer,
            .typed_pointer,
            .bitfield,
            =>
            false,
            .@"struct", .anonymous_struct => true,
        };
    }

    fn returns_nothing(ty: *Type) bool {
        return switch (ty.sema.id) {
            .void, .noreturn => true,
            else => false,
        };
    }

    const HomogeneousAggregate = struct{
        type: *Type,
        count: u32,
    };

    fn get_homogeneous_aggregate(ty: *Type) ?HomogeneousAggregate {
        switch (ty.sema.id) {
            .@"struct" => {
                const struct_type = ty.get_payload(.@"struct");
                for (struct_type.fields) |field| {
                    while (field.type.sema.id == .array) {
                        unreachable;
                    }

                    if (field.type.get_homogeneous_aggregate()) |homogeneous_aggregate| {
                        _ = homogeneous_aggregate; // autofix
                        unreachable;
                    } else {
                        return null;
                    }

                    unreachable;
                }

                unreachable;
            },
            .integer => {
                return null;
            },
            else => |t| @panic(@tagName(t)),
        }
    }

    fn get_integer_index(ty: *Type) usize {
        assert(ty.sema.id == .integer);
        const thread = &instance.threads[ty.sema.thread];
        comptime assert(@offsetOf(Type.Integer, "type") == 0);
        const index = @divExact(@intFromPtr(ty) - @intFromPtr(&thread.integers[0]), @sizeOf(Type.Integer));
        return index;
    }
};

const Keyword = enum{
    @"break",
    @"else",
    @"for",
    @"if",
    @"loop",
    @"orelse",
    @"undefined",
};

const Intrinsic = enum{
    assert,
    int_from_pointer,
    leading_zeroes,
    require,
    size,
    trailing_zeroes,
    trap,
    transmute,
    @"unreachable",
};

fn parse_keyword(identifier: []const u8) u32 {
    assert(identifier.len > 0);
    if (identifier[0] != '"') {
        inline for (@typeInfo(Keyword).Enum.fields) |keyword| {
            if (byte_equal(identifier, keyword.name)) {
                return keyword.value;
            }
        }
    }

    return ~@as(u32, 0);
}

const Scope = struct {
    declarations: PinnedHashMap(u32, *Declaration) = .{},
    parent: ?*Scope,
    llvm: ?*LLVM.DebugInfo.Scope = null,
    line: u32,
    column: u32,
    file: u32,
    id: Id,

    pub fn get_global_declaration(scope: *Scope, name: u32) ?*GlobalDeclaration {
        assert(scope.id == .file);
        if (scope.get_declaration_one_level(name)) |decl_ref| {
            return decl_ref.*.get_payload(.global);
        } else {
            return null;
        }
    }

    pub fn get_declaration_one_level(scope: *Scope, name: u32) ?Declaration.Reference {
        const result = scope.declarations.get_pointer(name);
        return result;
    }

    const DeclarationLookupResult = struct {
        declaration: Declaration.Reference,
        scope: *Scope,
    };

    pub fn get_declaration(scope: *Scope, name: u32) ?DeclarationLookupResult{ 
        var s: ?*Scope = scope;
        while (s) |search_scope| {
            if (search_scope.get_declaration_one_level(name)) |declaration| {
                return .{
                    .declaration = declaration,
                    .scope = search_scope,
                };
            }

            s = search_scope.parent;
        }

        return null;
    }

    const Id = enum{
        file,
        function,
        local,
    };
};

const Range = struct{
    start: u32,
    end: u32,
};

const ArgumentDeclaration = struct {
    declaration: Declaration,

    fn to_symbol(argument_declaration: *ArgumentDeclaration) *ArgumentSymbol {
        return @alignCast(@fieldParentPtr("argument_declaration", argument_declaration));
    }
};

const LocalDeclaration = struct {
    declaration: Declaration,

    fn to_symbol(local_declaration: *LocalDeclaration) *LocalSymbol {
        return @alignCast(@fieldParentPtr("local_declaration", local_declaration));
    }
};

const GlobalDeclaration = struct {
    declaration: Declaration,
    id: Id,

    const Id = enum(u8) {
        file,
        unresolved_import,
        global_symbol,
    };

    const id_to_global_declaration_map = std.EnumArray(Id, type).init(.{
        .file = File,
        .global_symbol = GlobalSymbol,
        .unresolved_import = Import,
    });

    fn get_payload(global_declaration: *GlobalDeclaration, comptime id: Id) *id_to_global_declaration_map.get(id) {
        assert(global_declaration.id == id);

        return @alignCast(@fieldParentPtr("global_declaration", global_declaration));
    }

    fn to_symbol(global_declaration: *GlobalDeclaration) *GlobalSymbol {
        assert(global_declaration.id == .global_symbol);
        return @alignCast(@fieldParentPtr("global_declaration", global_declaration));
    }

    const Reference = **GlobalDeclaration;
};

const BasicBlock = struct{
    value: Value,
    instructions: PinnedArray(*Instruction) = .{},
    predecessors: PinnedArray(*BasicBlock) = .{},
    is_terminated: bool = false,
    command_node: CommandList.Node = .{
        .data = {},
    },

    pub const Reference = **BasicBlock;

    const CommandList = std.DoublyLinkedList(void);

    pub fn get_llvm(basic_block: *BasicBlock) *LLVM.Value.BasicBlock{
        return basic_block.value.llvm.?.toBasicBlock() orelse unreachable; 
    }
};

const Declaration = struct {
    name: u32,
    id: Id,
    line: u32,
    column: u32,
    scope: *Scope,

    const Reference = **Declaration;

    const Id = enum {
        local,
        global,
        argument,
        @"struct",
        @"bitfield",
    };

    const id_to_declaration_map = std.EnumArray(Id, type).init(.{
        .global = GlobalDeclaration,
        .local = LocalDeclaration,
        .argument = ArgumentDeclaration,
        .@"struct" = Type.Struct,
        .bitfield = Type.Bitfield,
    });

    fn get_payload(declaration: *Declaration, comptime id: Id) *id_to_declaration_map.get(id) {
        assert(declaration.id == id);
        return @fieldParentPtr("declaration", declaration);
    }
};

const Function = struct{
    declaration: Function.Declaration,
    entry_block: *BasicBlock,
    stack_slots: PinnedArray(*LocalSymbol) = .{},
    scope: Function.Scope,
    arguments: PinnedArray(*ArgumentSymbol) = .{},

    const Attributes = struct{
    };

    const Attribute = enum{
        cc,

        pub const Mask = std.EnumSet(Function.Attribute);
    };

    const Abi = struct{
        original_return_type: *Type,
        original_argument_types: []const *Type,
        abi_return_type: *Type,
        abi_argument_types: []const *Type,
        return_type_abi: Function.Abi.Information,
        argument_types_abi: []const Function.Abi.Information,
        calling_convention: CallingConvention,

        const Kind = union(enum) {
            ignore,
            direct,
            direct_pair: [2]*Type,
            direct_coerce: *Type,
            direct_coerce_int,
            direct_split_struct_i32,
            expand_coerce,
            indirect: struct {
                type: *Type,
                alignment: u32,
            },
            expand,
        };
 
        const Attributes = struct {
            by_reg: bool = false,
            zero_extend: bool = false,
            sign_extend: bool = false,
            realign: bool = false,
            by_value: bool = false,
        };

        const Information = struct{
            kind: Kind = .direct,
            indices: [2]u16 = .{0, 0},
            attributes: Function.Abi.Attributes = .{},

            fn clone(abi_info: *const Information, args: struct{
                destination_thread: *Thread,
                source_thread_index: u16,
            }) Information {
                _ = args;
                const kind: Kind = switch (abi_info.kind) {
                    .direct => .direct,
                    else => |t| @panic(@tagName(t)),
                };
                const indices = abi_info.indices;
                const attributes = abi_info.attributes;
                return .{
                    .kind = kind,
                    .indices = indices,
                    .attributes = attributes,
                };
            }
        };
    };
    
    const Declaration = struct {
        attributes: Attributes = .{},
        global_symbol: GlobalSymbol,


        fn get_function_type(declaration: *Function.Declaration) *Type.Function {
            const ty = declaration.global_symbol.type;
            const function_type = ty.get_payload(.function);
            return function_type;
        }

        fn clone(declaration: Function.Declaration, destination_thread: *Thread) *Function.Declaration{
            assert(declaration.global_symbol.value.sema.resolved);

            const source_thread_index = declaration.global_symbol.value.sema.thread;
            const source_thread = &instance.threads[source_thread_index];
            assert(source_thread != destination_thread);

            const type_cloned = declaration.global_symbol.type.clone(.{
                .destination_thread = destination_thread,
                .source_thread_index = source_thread_index,
            });
            assert(type_cloned.sema.thread == destination_thread.get_index());

            const result = destination_thread.external_functions.append(.{
                .global_symbol = .{
                    .type = type_cloned,
                    .pointer_type = get_typed_pointer(destination_thread, .{
                        .pointee = type_cloned,
                    }),
                    .attributes = declaration.global_symbol.attributes,
                    .global_declaration = declaration.global_symbol.global_declaration,
                    .alignment = declaration.global_symbol.alignment,
                    .value = declaration.global_symbol.value,
                    .id = declaration.global_symbol.id,
                },
            });

            result.global_symbol.attributes.@"export" = false;
            result.global_symbol.attributes.@"extern" = true;
            result.global_symbol.value.sema.thread = destination_thread.get_index();
            result.global_symbol.value.llvm = null;
            return result;
        }
    };

    const Scope = struct {
        scope: compiler.Scope,

        pub fn lookup_declaration(scope: *Function.Scope, parent: bool) ?*compiler.Declaration {
            _ = scope;
            _ = parent;
            unreachable;
        }
    };
};

const ConstantInt = struct{
    value: Value,
    n: u64,
    type: *Type,
};

const ConstantArray = struct{
    value: Value,
    values: []const *Value,
    type: *Type,
};

const ConstantStruct = struct{
    value: Value,
    values: []const *Value,
    type: *Type,
};

const Undefined = struct{
    value: Value,
    type: *Type,
};

const ConstantBitfield = struct{
    value: Value,
    n: u64,
    type: *Type,
};

const Instruction = struct{
    value: Value,
    basic_block: ?*BasicBlock = null,
    scope: *Scope,
    line: u32,
    column: u32,
    id: Id,

    const Id = enum{
        abi_argument,
        abi_indirect_argument,
        argument_storage,
        branch,
        call,
        cast,
        debug_argument,
        debug_local,
        extract_value,
        get_element_pointer,
        insert_value,
        integer_binary_operation,
        integer_compare,
        jump,
        leading_zeroes,
        load,
        local_symbol,
        memcpy,
        phi,
        ret,
        ret_void,
        store,
        trailing_zeroes,
        trap,
        @"unreachable",
    };

    const id_to_instruction_map = std.EnumArray(Id, type).init(.{
        .abi_argument = AbiArgument,
        .abi_indirect_argument = ArgumentSymbol,
        .argument_storage = ArgumentSymbol,
        .branch = Branch,
        .call = Call,
        .cast = Cast,
        .debug_argument = DebugArgument,
        .debug_local = DebugLocal,
        .extract_value = ExtractValue,
        .get_element_pointer = GEP,
        .insert_value = InsertValue,
        .integer_binary_operation = IntegerBinaryOperation,
        .integer_compare = IntegerCompare,
        .jump = Jump,
        .leading_zeroes = LeadingZeroes,
        .local_symbol = LocalSymbol,
        .load = Load,
        .memcpy = Memcpy,
        .phi = Phi,
        .ret = Return,
        .ret_void = Instruction,
        .store = Store,
        .trailing_zeroes = TrailingZeroes,
        .trap = Instruction,
        .@"unreachable" = Instruction,
    });

    fn get_payload(instruction: *Instruction, comptime id: Id) *id_to_instruction_map.get(id) {
        assert(instruction.id == id);
        return @fieldParentPtr("instruction", instruction);
    }
};

const AbiArgument = struct{
    instruction: Instruction,
    index: u32,
};

const ExtractValue = struct{
    instruction: Instruction,
    aggregate: *Value,
    index: u32,
    type: *Type,
};

const InsertValue = struct{
    instruction: Instruction,
    aggregate: *Value,
    value: *Value,
    index: u32,
    type: *Type,
};

const GEP = struct {
    instruction: Instruction,
    pointer: *Value,
    index: *Value,
    aggregate_type: *Type,
    type: *Type,
    is_struct: bool,
};

const IntegerBinaryOperation = struct {
    instruction: Instruction,
    left: *Value,
    right: *Value,
    type: *Type,
    id: Id,

    const Id = enum{
        add,
        sub,
        mul,
        udiv,
        sdiv,
        @"and",
        @"or",
        @"xor",
        shift_left,
        arithmetic_shift_right,
        logical_shift_right,
    };
};

const IntegerCompare = struct {
    instruction: Instruction,
    left: *Value,
    right: *Value,
    id: Id,

    const Id = enum{
        unsigned_greater,
        unsigned_greater_equal,
        signed_greater,
        signed_greater_equal,
        unsigned_less,
        unsigned_less_equal,
        signed_less,
        signed_less_equal,
        equal,
        not_equal,
        not_zero,
    };
};

const Branch = struct {
    instruction: Instruction,
    condition: *Value,
    taken: *BasicBlock,
    not_taken: *BasicBlock,
};

const Jump = struct {
    instruction: Instruction,
    basic_block: *BasicBlock,
};

const Call = struct{
    instruction: Instruction,
    callable: *Value,
    arguments: []const *Value,
    calling_convention: CallingConvention,

    fn get_function_type(call: *Call) *Type.Function{
        switch (call.callable.sema.id) {
            .global_symbol => {
                const global_symbol = call.callable.get_payload(.global_symbol);
                switch (global_symbol.id) {
                    .function_definition, .function_declaration => {
                        const function_declaration = global_symbol.get_payload(.function_declaration);
                        const function_type = function_declaration.get_function_type();
                        return function_type;
                    },
                    else => |t| @panic(@tagName(t)),
                }
            },
            .instruction => {
                const callable_instruction = call.callable.get_payload(.instruction);
                _ = callable_instruction; // autofix
                const callable_type = call.callable.get_type();
                switch (callable_type.sema.id) {
                    .typed_pointer => {
                        const typed_pointer = callable_type.get_payload(.typed_pointer);
                        switch (typed_pointer.descriptor.pointee.sema.id) {
                            .function => {
                                const function_type = typed_pointer.descriptor.pointee.get_payload(.function);
                                return function_type;
                            },
                            else => |t| @panic(@tagName(t)),
                        }
                    },
                    else => |t| @panic(@tagName(t)),
                }
            },
            else => |t| @panic(@tagName(t)),
        }
    }
};

const Cast = struct{
    instruction: Instruction,
    value: *Value,
    type: *Type,
    id: Id,

    const Id = enum{
        bitfield_from_int,
        int_from_bitfield,
        int_from_pointer,
        truncate,
    };
};

const Load = struct {
    instruction: Instruction,
    value: *Value,
    type: *Type,
    alignment: u32,
    is_volatile: bool,
};

const Store = struct {
    instruction: Instruction,
    destination: *Value,
    source: *Value,
    alignment: u32,
    is_volatile: bool,
};

const Phi = struct {
    instruction: Instruction,
    type: *Type,
    nodes: PinnedArray(Node) = .{},

    const Node = struct {
        value: *Value,
        basic_block: *BasicBlock,
    };
};

const Return = struct{
    instruction: Instruction,
    value: *Value,
};

const Import = struct {
    global_declaration: GlobalDeclaration,
    hash: u32,
    resolved: bool = false,
    files: PinnedArray(*File) = .{},
};

const LocalBlock = struct {
    scope: Scope,
    terminated: bool = false,
};

fn get_power_of_two_byte_count_from_bit_count(bit_count: u32) u32 {
    if (bit_count == 0) unreachable;
    if (bit_count <= 8) return 1;
    if (bit_count <= 16) return 2;
    if (bit_count <= 32) return 4;
    if (bit_count <= 64) return 8;
    unreachable;
}

const LeadingZeroes = struct{
    instruction: Instruction,
    value: *Value,
};

const TrailingZeroes = struct{
    instruction: Instruction,
    value: *Value,
};

const DebugLocal = struct{
    instruction: Instruction,
    local: *LocalSymbol,
};

const DebugArgument = struct{
    instruction: Instruction,
    argument: *ArgumentSymbol,
};

const Thread = struct{
    arena: *Arena = undefined,
    functions: PinnedArray(Function) = .{},
    external_functions: PinnedArray(Function.Declaration) = .{},
    identifiers: PinnedHashMap(u32, []const u8) = .{},
    constant_ints: PinnedArray(ConstantInt) = .{},
    constant_arrays: PinnedArray(ConstantArray) = .{},
    constant_structs: PinnedArray(ConstantStruct) = .{},
    constant_bitfields: PinnedArray(ConstantBitfield) = .{},
    basic_blocks: PinnedArray(BasicBlock) = .{},
    task_system: TaskSystem = .{},
    debug_info_file_map: PinnedHashMap(u32, LLVMFile) = .{},
    branches: PinnedArray(Branch) = .{},
    jumps: PinnedArray(Jump) = .{},
    calls: PinnedArray(Call) = .{},
    integer_binary_operations: PinnedArray(IntegerBinaryOperation) = .{},
    integer_compares: PinnedArray(IntegerCompare) = .{},
    loads: PinnedArray(Load) = .{},
    stores: PinnedArray(Store) = .{},
    phis: PinnedArray(Phi) = .{},
    returns: PinnedArray(Return) = .{},
    geps: PinnedArray(GEP) = .{},
    lazy_expressions: PinnedArray(LazyExpression) = .{},
    local_lazy_expressions: PinnedArray(LocalLazyExpression) = .{},
    imports: PinnedArray(Import) = .{},
    local_blocks: PinnedArray(LocalBlock) = .{},
    local_symbols: PinnedArray(LocalSymbol) = .{},
    argument_symbols: PinnedArray(ArgumentSymbol) = .{},
    global_variables: PinnedArray(GlobalVariable) = .{},
    abi_arguments: PinnedArray(AbiArgument) = .{},
    standalone_instructions: PinnedArray(Instruction) = .{},
    leading_zeroes: PinnedArray(LeadingZeroes) = .{},
    trailing_zeroes: PinnedArray(TrailingZeroes) = .{},
    casts: PinnedArray(Cast) = .{},
    memcopies: PinnedArray(Memcpy) = .{},
    undefined_values: PinnedArray(Undefined) = .{},
    insert_values: PinnedArray(InsertValue) = .{},
    extract_values: PinnedArray(ExtractValue) = .{},
    debug_arguments: PinnedArray(DebugArgument) = .{},
    debug_locals: PinnedArray(DebugLocal) = .{},
    function_types: PinnedArray(Type.Function) = .{},
    array_type_map: PinnedHashMap(Type.Array.Descriptor, *Type) = .{},
    typed_pointer_type_map: PinnedHashMap(Type.TypedPointer.Descriptor, *Type) = .{},
    array_types: PinnedArray(Type.Array) = .{},
    typed_pointer_types: PinnedArray(Type.TypedPointer) = .{},
    structs: PinnedArray(Type.Struct) = .{},
    anonymous_structs: PinnedArray(Type.AnonymousStruct) = .{},
    two_struct_map: PinnedHashMap([2]*Type, *Type) = .{},
    fields: PinnedArray(Type.AggregateField) = .{},
    bitfields: PinnedArray(Type.Bitfield) = .{},
    cloned_types: PinnedHashMap(*Type, *Type) = .{},
    analyzed_file_count: u32 = 0,
    assigned_file_count: u32 = 0,
    llvm: struct {
        context: *LLVM.Context,
        module: *LLVM.Module,
        attributes: LLVM.Attributes,
        target_machine: *LLVM.Target.Machine,
        object: ?[]const u8 = null,
        intrinsic_ids: std.EnumArray(LLVMIntrinsic, LLVM.Value.IntrinsicID),
        fixed_intrinsic_functions: std.EnumArray(LLVMFixedIntrinsic, *LLVM.Value.Constant.Function),
        intrinsic_id_map: PinnedHashMap([]const u8, LLVM.Value.IntrinsicID) = .{},
        intrinsic_function_map: PinnedHashMap(LLVMIntrinsic.Parameters, *LLVM.Value.Constant.Function) = .{},
    } = undefined,
    integers: [128]Type.Integer = blk: {
        var integers: [128]Type.Integer = undefined;
        for ([_]Type.Integer.Signedness{.unsigned, .signed }) |signedness| {
            for (1..64 + 1) |bit_count| {
                const integer_type_index = @intFromEnum(signedness) * @as(usize, 64) + bit_count - 1; 
                const byte_count = get_power_of_two_byte_count_from_bit_count(bit_count);
                integers[integer_type_index] = .{
                    .type = .{
                        .sema = .{
                            .thread = undefined,
                            .id = .integer,
                            .resolved = true,
                        },
                        .size = byte_count,
                        .bit_size = bit_count,
                        .alignment = byte_count,
                    },
                    .signedness = signedness,
                };
            }
        }
        break :blk integers;
    },
    void: Type = .{
        .sema = .{
            .thread = undefined,
            .id = .void,
            .resolved = true,
        },
        .size = 0,
        .bit_size = 0,
        .alignment = 0,
    },
    noreturn: Type = .{
        .sema = .{
            .thread = undefined,
            .id = .noreturn,
            .resolved = true,
        },
        .size = 0,
        .bit_size = 0,
        .alignment = 0,
    },
    opaque_pointer: Type = .{
        .sema = .{
            .thread = undefined,
            .id = .opaque_pointer,
            .resolved = true,
        },
        .bit_size = 64,
        .size = 8,
        .alignment = 8,
    },
    discard_count: u64 = 0,
    handle: std.Thread = undefined,
    generate_debug_information: bool = true,
    time: if (configuration.timers) Time else void = if (configuration.timers) .{} else {},
    const Timers = std.EnumArray(Timer, TimeRange);
    const Time = struct{
        timestamp: Instant = std.mem.zeroes(Instant),
        timers: Timers = Timers.initFill(std.mem.zeroes(TimeRange)),
    };

    const Timer = enum{
        setup,
        analysis,
        llvm_build_ir,
        llvm_emit_object,
    };

    fn add_thread_work(thread: *Thread, job: Job) void {
        @atomicStore(@TypeOf(thread.task_system.state), &thread.task_system.state, .running, .seq_cst);
        assert(@atomicLoad(@TypeOf(thread.task_system.program_state), &thread.task_system.program_state, .seq_cst) != .none);
        thread.task_system.job.queue_job(job);
    }

    fn add_control_work(thread: *Thread, job: Job) void {
        thread.task_system.ask.queue_job(job);
    }

    fn get_worker_job(thread: *Thread) ?Job {
        if (thread.task_system.job.get_next_job()) |job| {
            // std.debug.print("[WORKER] Thread #{} getting job {s}\n", .{thread.get_index(), @tagName(job.id)});
            return job;
        }

        return null;
    }

    fn get_control_job(thread: *Thread) ?Job {
        if (thread.task_system.ask.get_next_job()) |job| {
            // std.debug.print("[CONTROL] Getting job {s} from thread #{}\n", .{@tagName(job.id), thread.get_index()});
            return job;
        }

        return null;
    }

    pub fn get_index(thread: *Thread) u16 {
        const index = @divExact(@intFromPtr(thread) - @intFromPtr(instance.threads.ptr), @sizeOf(Thread));
        return @intCast(index);
    }
};

const LLVMFixedIntrinsic = enum{
    trap,
};
const LLVMIntrinsic = enum{
    leading_zeroes,
    trailing_zeroes,

    const Parameters = struct{
        id: LLVM.Value.IntrinsicID,
        types: []const *LLVM.Type,
    };
};

const LLVMFile = struct {
    file: *LLVM.DebugInfo.File,
    compile_unit: *LLVM.DebugInfo.CompileUnit,
    builder: *LLVM.DebugInfo.Builder,
};

const Job = packed struct(u64) {
    offset: u32 = 0,
    count: u24 = 0,
    id: Id,

    const Id = enum(u8){
        analyze_file,
        notify_file_resolved,
        notify_analysis_complete,
        llvm_generate_ir,
        llvm_notify_ir_done,
        llvm_optimize,
        llvm_emit_object,
        llvm_notify_object_done,
        compile_c_source_file,
    };
};

const TaskSystem = struct{
    job: JobQueue = .{},
    ask: JobQueue = .{},
    program_state: ProgramState = .none,
    state: ThreadState = .idle,

    const ProgramState = enum{
        none,
        c_source_file,
        c_source_file_done,
        analysis,
        llvm_generate_ir,
        llvm_emit_object,
        llvm_finished_object,
    };

    const ThreadState = enum{
        idle,
        running,
    };
};

const JobQueue = struct{
    entries: [job_entry_count]Job align(cache_line_size) = [1]Job{@bitCast(@as(u64, 0))} ** job_entry_count,
    queuer: struct {
        to_do: u64 = 0,
        next_write: u64 = 0,
    } = .{},
    worker: struct {
        completed: u64 = 0,
        next_read: u64 = 0,
    } = .{},
    reserved: [padding_byte_count]u8 = [1]u8{0} ** padding_byte_count,

    const job_entry_count = 64;
    const valuable_size = job_entry_count * @sizeOf(Job) + 4 * @sizeOf(u64);
    const real_size = std.mem.alignForward(usize, valuable_size, cache_line_size);
    const padding_byte_count = real_size - valuable_size;

    comptime {
        assert(@sizeOf(JobQueue) % cache_line_size == 0);
    }

    fn queue_job(job_queue: *JobQueue, job: Job) void {
        // std.debug.print("[0x{x}] Queueing job '{s}'\n", .{@intFromPtr(job_queue) & 0xfff, @tagName(job.id)});
        const index = job_queue.queuer.next_write;
        if (weak_memory_model) @fence(.seq_cst);
        assert(index + 1 != @atomicLoad(@TypeOf(job_queue.worker.next_read), &job_queue.worker.next_read, .seq_cst));
        if (weak_memory_model)         @fence(.seq_cst);
        const ptr = &job_queue.entries[index];
        //if (job.id == .analyze_file and job.count == 0 and job.offset == 0) unreachable;
        // std.debug.print("Before W 0x{x} - 0x{x}\n", .{@intFromPtr(ptr), job.offset});
        ptr.* = job;
        if (weak_memory_model) @fence(.seq_cst);
        // std.debug.print("After W 0x{x}\n", .{@intFromPtr(ptr)});
        job_queue.queuer.to_do += 1;
        if (weak_memory_model) @fence(.seq_cst);
        job_queue.queuer.next_write = index + 1;
        if (weak_memory_model) @fence(.seq_cst);
    }

    fn get_next_job(job_queue: *JobQueue) ?Job{
        const index = job_queue.worker.next_read;
        if (weak_memory_model) @fence(.seq_cst);
        const nw = @atomicLoad(@TypeOf(job_queue.queuer.next_write), &job_queue.queuer.next_write, .seq_cst);
        if (weak_memory_model) @fence(.seq_cst);
        if (index != nw) {
            if (weak_memory_model) @fence(.seq_cst);
            job_queue.worker.next_read += 1;
            if (weak_memory_model) @fence(.seq_cst);
            const job_ptr = &job_queue.entries[index];
            if (weak_memory_model) @fence(.seq_cst);
            const job = job_ptr.*;
            if (weak_memory_model) @fence(.seq_cst);
            // std.debug.print("[0x{x}] Getting job #{} (0x{x} -\n{}\n) (nw: {})\n", .{@intFromPtr(job_queue) & 0xfff, index, @intFromPtr(job), job.*, nw});
            //if (job.id == .analyze_file and job.count == 0 and job.offset == 0) unreachable;
            return job;
        }

        return null;
    }

    fn complete_job(job_queue: *JobQueue) void {
        job_queue.worker.completed += 1;
    }
};

const Instance = struct{
    files: PinnedArray(File) = .{},
    file_paths: PinnedArray(u32) = .{},
    file_mutex: std.Thread.Mutex = .{},
    units: PinnedArray(Unit) = .{},
    arena: *Arena = undefined,
    threads: []Thread = undefined,
    paths: struct {
        cwd: []const u8,
        executable: []const u8,
        executable_directory: []const u8,
    } = .{
        .cwd = &.{},
        .executable = &.{},
        .executable_directory = &.{},
    },

    fn path_from_cwd(i: *Instance, arena: *Arena, relative_path: []const u8) []const u8 {
        return arena.join(&.{i.paths.cwd, "/", relative_path}) catch unreachable;
    }

    fn path_from_compiler(i: *Instance, arena: *Arena, relative_path: []const u8) []const u8 {
        return arena.join(&.{i.paths.executable_directory, "/", relative_path}) catch unreachable;
    }
};

const TimeRange = if (configuration.timers) struct{
    start: Instant,
    end: Instant,
} else void;

const TimeUnion = if (configuration.timers) union(enum){
    range: TimeRange,
    accumulating: struct{
        sum: u64,
        previous: Instant,
    },
} else void;

const File = struct{
    global_declaration: GlobalDeclaration,
    scope: File.Scope,
    source_code: []const u8,
    path: []const u8,
    functions: Range = .{
        .start = 0,
        .end = 0,
    },
    state: State,
    thread: u32 = 0,
    interested_threads: PinnedArray(u32) = .{},
    interested_files: PinnedArray(*File) = .{},
    imports: PinnedArray(*Import) = .{},
    values_per_import: PinnedArray(PinnedArray(*Value)) = .{},
    resolved_import_count: u32 = 0,
    local_lazy_expressions: PinnedArray(*LocalLazyExpression) = .{},
    time: if (configuration.timers) Time else void,
    const Time = struct{
        timestamp: Instant,
        timers: Timers = Timers.initFill(.{ .range = std.mem.zeroes(TimeRange) }),
        top_level_declaration_timers: PinnedArray(struct {
            name: []const u8,
            start: Instant,
            end: Instant,
        }) = .{},
    };
    const Timers = std.EnumArray(Timer, TimeUnion);
    const Timer = enum{
        queue,
        read,
        analysis,
        wait_for_dependencies,
    };

    pub fn get_index(file: *File) u32 {
        return instance.files.get_index(file);
    }

    pub fn get_directory_path(file: *const File) []const u8 {
        return std.fs.path.dirname(file.path) orelse unreachable;
    }

    const State = enum{
        queued,
        reading,
        analyzing,
        waiting_for_dependencies,
        analyzed,
    };

    const Scope = struct {
        scope: compiler.Scope,
    };
};

var instance = Instance{};
const do_codegen = true;
const codegen_backend = CodegenBackend.llvm;

const CodegenBackend = union(enum){
    llvm: struct {
        split_object_per_thread: bool,
    },
};

fn add_file(file_absolute_path: []const u8, interested_threads: []const u32) u32 {
    instance.file_mutex.lock();
    defer instance.file_mutex.unlock();

    const hash = hash_bytes(file_absolute_path);
    const new_file = instance.files.add_one();
    _ = instance.file_paths.append(hash);
    const new_file_index = instance.files.get_index(new_file);
    new_file.* = .{
        .global_declaration = .{
            .declaration = .{
                .name = std.math.maxInt(u32),
                .id = .global,
                .line = 1,
                .column = 1,
                .scope = &new_file.scope.scope,
            },
            .id = .file,
        },
        .scope = .{
            .scope = .{
                .id = .file,
                .parent = null,
                .line = 1,
                .column = 1,
                .file = new_file_index,
            },
        },
        .source_code = &.{},
        .path = file_absolute_path,
        .state = .queued,
        .time = if (configuration.timers) .{
            .timestamp = get_instant(),
        } else {},
    };

    new_file.interested_threads.append_slice(interested_threads);

    return new_file_index;
}
const Arch = enum {
    x86_64,
    aarch64,
};

const Os = enum {
    linux,
    macos,
    windows,
};

const Abi = enum {
    none,
    gnu,
    musl,
};

const Optimization = enum {
    none,
    debug_prefer_fast,
    debug_prefer_size,
    lightly_optimize_for_speed,
    optimize_for_speed,
    optimize_for_size,
    aggressively_optimize_for_speed,
    aggressively_optimize_for_size,
};

fn error_insufficient_arguments_command(command: []const u8) noreturn {
    @setCold(true);
    write("Command '");
    write(command);
    write("' requires at least one argument\n");
    fail();
}

fn error_unterminated_argument(argument: []const u8) noreturn {
    @setCold(true);
    write("Argument '");
    write(argument);
    write("' must be terminated\n");
    fail();
}

const Target = struct {
    arch: Arch,
    os: Os,
    abi: Abi,
};

const Unit = struct {
    descriptor: Descriptor,

    const Descriptor = struct {
        main_source_file_path: []const u8,
        executable_path: []const u8,
        object_path: []const u8,
        c_source_files: []const []const u8,
        c_object_files: []const []const u8,
        target: Target,
        optimization: Optimization,
        generate_debug_information: bool,
        link_libc: bool,
        link_libcpp: bool,
        codegen_backend: CodegenBackend,
    };

    fn compile(descriptor: Descriptor) *Unit {
        const unit = instance.units.add_one();
        unit.* = .{
            .descriptor = descriptor,
        };

        if (descriptor.c_source_files.len > 0) {
            LLVM.initializeAll();
        } else {
            switch (unit.descriptor.target.arch) {
                inline else => |a| {
                    const arch = @field(LLVM, @tagName(a));
                    arch.initializeTarget();
                    arch.initializeTargetInfo();
                    arch.initializeTargetMC();
                    arch.initializeAsmPrinter();
                    arch.initializeAsmParser();
                },
            }
        }

        var last_assigned_thread_index: u32 = 0;
        var c_objects = PinnedArray([]const u8){};

        for (descriptor.c_source_files) |source_file| {
            const extension_start = last_byte(source_file, '.') orelse fail();
            const name = std.fs.path.basename(source_file[0..extension_start]);
            const object_path = instance.arena.join(&.{"nat/o/", name, ".o"}) catch unreachable;
            _ = c_objects.append(object_path);
        }

        unit.descriptor.c_object_files = c_objects.slice();

        const main_source_file_absolute = instance.path_from_cwd(instance.arena, unit.descriptor.main_source_file_path);
        const new_file_index = add_file(main_source_file_absolute, &.{});
        instance.threads[last_assigned_thread_index].task_system.program_state = .analysis;
        instance.threads[last_assigned_thread_index].add_thread_work(Job{
            .offset = new_file_index,
            .count = 1,
            .id = .analyze_file,
        });
        last_assigned_thread_index += 1;

        for (descriptor.c_source_files, 0..) |_, index| {
            const thread_index = last_assigned_thread_index % instance.threads.len;
            const thread = &instance.threads[thread_index];
            thread.task_system.program_state = .analysis;
            thread.add_thread_work(Job{
                .offset = @intCast(index),
                .count = 1,
                .id = .compile_c_source_file,
            });
            last_assigned_thread_index += 1;
        }

        control_thread(unit, last_assigned_thread_index);

        return unit;
    }
};

fn control_thread(unit: *Unit, lati: u32) void {
    var last_assigned_thread_index: u32 = lati;
    var first_ir_done = false;
    var total_is_done: bool = false;
    var iterations_without_work_done: u32 = 0;

    while (!total_is_done) {
        total_is_done = first_ir_done;

        var task_done_this_iteration: u32 = 0;

        for (instance.threads, 0..) |*thread, i| {
            const completed = @atomicLoad(u64, &thread.task_system.job.worker.completed, .seq_cst);
            // INFO: No need to do an atomic load here since it's only this thread writing to the value
            const program_state = thread.task_system.program_state;
            const to_do = thread.task_system.job.queuer.to_do;
            total_is_done = total_is_done and completed == to_do and if (@intFromEnum(program_state) >= @intFromEnum(TaskSystem.ProgramState.analysis) and (thread.functions.length > 0 or thread.global_variables.length > 0)) program_state == .llvm_finished_object else true;

            var previous_job: Job = undefined;
            while (thread.get_control_job()) |job| {
                assert(!(previous_job.id == job.id and previous_job.offset == job.offset and previous_job.count == job.count));
                switch (job.id) {
                    .analyze_file => {
                        const analyze_file_path_hash = job.offset;
                        const interested_file_index = job.count;
                        // std.debug.print("[CONTROL] Trying to retrieve file path hash (0x{x}) interested file index: {} in thread #{}\n", .{analyze_file_path_hash, interested_file_index, thread.get_index()});
                        assert(analyze_file_path_hash != 0);

                        for (instance.file_paths.slice()) |file_path_hash| {
                            if (analyze_file_path_hash == file_path_hash) {
                                fail();
                            }
                        } else {
                            const thread_index = last_assigned_thread_index % instance.threads.len;
                            last_assigned_thread_index += 1;
                            const file_absolute_path = thread.identifiers.get(analyze_file_path_hash).?;
                            const interested_thread_index: u32 = @intCast(i);
                            const file_index = add_file(file_absolute_path, &.{interested_thread_index});
                            _ = instance.files.get_unchecked(file_index).interested_files.append(&instance.files.pointer[interested_file_index]);
                            const assigned_thread = &instance.threads[thread_index];

                            assigned_thread.task_system.program_state = .analysis;
                            assigned_thread.add_thread_work(Job{
                                .offset = file_index,
                                .id = .analyze_file,
                                .count = 1,
                            });
                        }
                    },
                    .notify_file_resolved => {
                        const file_index = job.offset;
                        const thread_index = job.count;
                        const destination_thread = &instance.threads[thread_index];
                        const file = instance.files.get(@enumFromInt(file_index));
                        const file_path_hash = hash_bytes(file.path);

                        destination_thread.add_thread_work(.{
                            .id = .notify_file_resolved,
                            .count = @intCast(file_index),
                            .offset = file_path_hash,
                        });
                    },
                    .notify_analysis_complete => {
                        thread.add_thread_work(.{
                            .id = .llvm_generate_ir,
                        });
                    },
                    .llvm_notify_ir_done => {
                        thread.add_thread_work(.{
                            .id = .llvm_emit_object,
                        });
                    },
                    .llvm_notify_object_done => {
                        thread.task_system.program_state = .llvm_finished_object;
                        first_ir_done = true;
                    },
                    else => |t| @panic(@tagName(t)),
                }

                thread.task_system.ask.complete_job();
                previous_job = job;
                task_done_this_iteration += 1;
            }
        }

        total_is_done = total_is_done and task_done_this_iteration == 0;
        iterations_without_work_done += @intFromBool(task_done_this_iteration == 0);

        if (configuration.sleep_on_thread_hot_loops) {
            if (iterations_without_work_done > 5) {
                std.time.sleep(100);
            }
        } else {
            std.atomic.spinLoopHint();
        }
    }

    var objects = PinnedArray([]const u8){};
    for (instance.threads) |*thread| {
        if (thread.llvm.object) |object| {
            _ = objects.append(object);
        }
    }

    for (unit.descriptor.c_object_files) |object_path| {
        _ = objects.append(object_path);
    }

    // for (instance.threads) |*thread| {
    //     std.debug.print("Thread #{}: {s}\n", .{thread.get_index(), @tagName(thread.task_system.program_state)});
    // }

    assert(objects.length > 0);

    link_start = get_instant();
    link(.{
        .output_file_path = unit.descriptor.executable_path,
        .extra_arguments = &.{},
        .objects = objects.const_slice(),
        .libraries = &.{},
        .link_libc = true,
        .link_libcpp = false,
    });
    link_end = get_instant();
}

var link_start: Instant = undefined;
var link_end: Instant = undefined;

fn command_exe(arguments: []const []const u8) void {
    if (arguments.len == 0) {
        error_insufficient_arguments_command("exe");
    }
        // TODO: make these mutable
    const arch: Arch = switch (builtin.cpu.arch) {
        .aarch64 => .aarch64,
        .x86_64 => .x86_64,
        else => unreachable,
    };
    const os: Os = switch (builtin.os.tag) {
        .linux => .linux,
        .macos => .macos,
        .windows => .windows,
        else => unreachable,
    };
    const abi: Abi = switch (builtin.os.tag) {
        .linux => .gnu,
        .macos => .none,
        .windows => .gnu,
        else => unreachable,
    };


    var maybe_executable_path: ?[]const u8 = null;
    var maybe_executable_name: ?[]const u8 = null;
    var maybe_main_source_file_path: ?[]const u8 = null;

    var c_source_files = PinnedArray([]const u8){};

    var optimization = Optimization.none;
    var generate_debug_information = true;
    var link_libc = true;
    const link_libcpp = false;

    var i: usize = 0;
    while (i < arguments.len) : (i += 1) {
        const current_argument = arguments[i];
        if (byte_equal(current_argument, "-o")) {
            if (i + 1 != arguments.len) {
                maybe_executable_path = arguments[i + 1];
                assert(maybe_executable_path.?.len != 0);
                i += 1;
            } else {
                error_unterminated_argument(current_argument);
            }
        } else if (byte_equal(current_argument, "-link_libc")) {
            if (i + 1 != arguments.len) {
                i += 1;

                const arg = arguments[i];
                if (byte_equal(arg, "true")) {
                    link_libc = true;
                } else if (byte_equal(arg, "false")) {
                    link_libc = false;
                } else {
                    unreachable;
                }
            } else {
                error_unterminated_argument(current_argument);
            }
        } else if (byte_equal(current_argument, "-main_source_file")) {
            if (i + 1 != arguments.len) {
                i += 1;

                const arg = arguments[i];
                maybe_main_source_file_path = arg;
            } else {
                error_unterminated_argument(current_argument);
            }
        } else if (byte_equal(current_argument, "-name")) {
            if (i + 1 != arguments.len) {
                i += 1;

                const arg = arguments[i];
                maybe_executable_name = arg;
            } else {
                error_unterminated_argument(current_argument);
            }
        } else if (byte_equal(current_argument, "-c_source_files")) {
            if (i + 1 != arguments.len) {
                i += 1;

                c_source_files.append_slice(arguments[i..]);
                i = arguments.len;
            } else {
                error_unterminated_argument(current_argument);
            }
        } else if (byte_equal(current_argument, "-optimize")) {
            if (i + 1 != arguments.len) {
                i += 1;

                const optimize_string = arguments[i];
                optimization = library.enumFromString(Optimization, optimize_string) orelse unreachable;
            } else {
                error_unterminated_argument(current_argument);
            }
        } else if (byte_equal(current_argument, "-debug")) {
            if (i + 1 != arguments.len) {
                i += 1;

                const debug_string = arguments[i];
                generate_debug_information = if (byte_equal(debug_string, "true")) true else if (byte_equal(debug_string, "false")) false else unreachable;
            } else {
                error_unterminated_argument(current_argument);
            }
        } else if (byte_equal(current_argument, "-c_source_files_start")) {
            i += 1;
            var sentinel = false;
            while (i < arguments.len) : (i += 1) {
                const arg = arguments[i];
                if (byte_equal(arg, "-c_source_files_end")) {
                    sentinel = true;
                    break;
                }

                _ = c_source_files.append(arg);
            }

            if (!sentinel) {
                fail_message("No sentinel for C source files arguments");
            }
        } else {
            @panic(current_argument);
            // std.debug.panic("Unrecognized argument: {s}", .{current_argument});
        }
    }

    const main_source_file_path = maybe_main_source_file_path orelse fail_message("Main source file must be specified with -main_source_file");
    // TODO: undo this incongruency
    const executable_name = if (maybe_executable_name) |executable_name| executable_name else std.fs.path.basename(main_source_file_path[0..main_source_file_path.len - "/main.nat".len]);
    const executable_path = maybe_executable_path orelse blk: {
        assert(executable_name.len > 0);
        const result = instance.arena.join(&.{"nat/", executable_name }) catch unreachable;
        break :blk result;
    };

    const object_path = instance.arena.join(&.{"nat/o/", executable_name, ".o"}) catch unreachable;

    _ = Unit.compile(.{
        .target = .{
            .arch = arch,
            .os = os,
            .abi = abi,
        },
        .link_libc = link_libc,
        .link_libcpp = link_libcpp,
        .main_source_file_path = main_source_file_path,
        .object_path = object_path,
        .executable_path = executable_path,
        .c_source_files = c_source_files.slice(),
        .c_object_files = &.{},
        .optimization = optimization,
        .generate_debug_information = generate_debug_information,
        .codegen_backend = .{
            .llvm = .{
                .split_object_per_thread = true,
            },
        },
    });
}

pub fn main() void {
    const program_start = get_instant();
    instance.arena = library.Arena.init(4 * 1024 * 1024) catch unreachable;
    const executable_path = library.self_exe_path(instance.arena) catch unreachable;
    const executable_directory = std.fs.path.dirname(executable_path).?;
    std.fs.cwd().makePath("nat") catch |err| switch (err) {
        else => @panic(@errorName(err)),
    };
    std.fs.cwd().makePath("nat/o") catch |err| switch (err) {
        else => @panic(@errorName(err)),
    };
    instance.paths = .{
        .cwd = library.realpath(instance.arena, std.fs.cwd(), ".") catch unreachable,
        .executable = executable_path,
        .executable_directory = executable_directory,
    };
    const thread_count = std.Thread.getCpuCount() catch unreachable;
    const cpu_count = &cpu_count_buffer[0];
    instance.arena.align_forward(@alignOf(Thread));
    instance.threads = instance.arena.new_array(Thread, thread_count - 1) catch unreachable;
    cpu_count.* = @intCast(thread_count - 2);
    for (instance.threads) |*thread| {
        thread.* = .{};
    }

    const thread_index = cpu_count.*;
    instance.threads[thread_index].handle = std.Thread.spawn(.{}, worker_thread, .{thread_index, cpu_count}) catch unreachable;

    var arg_iterator = std.process.args();
    var argument_buffer = PinnedArray([]const u8){};

    while (arg_iterator.next()) |arg| {
        _ = argument_buffer.append(arg);
    }

    const arguments = argument_buffer.const_slice();
    if (arguments.len < 2) {
        fail_message("Insufficient number of arguments");
    }

    const command = arguments[1];
    const command_arguments = arguments[2..];

    if (byte_equal(command, "exe")) {
        command_exe(command_arguments);
    } else if (byte_equal(command, "clang") or byte_equal(command, "-cc1") or byte_equal(command, "-cc1as")) {
        fail_message("TODO: clang");
    } else if (byte_equal(command, "cc")) {
        fail_message("TODO: clang");
    } else if (byte_equal(command, "c++")) {
        fail_message("TODO: clang");
    } else {
        fail_message("Unrecognized command");
    }

    const program_end = get_instant();

    const print_timers = configuration.timers;
    if (print_timers) {
        for (instance.files.slice()) |*file| {
            std.debug.print("File {s}:\nStages:\n", .{file.path});
            var it = file.time.timers.iterator();
            while (it.next()) |timer_entry| {
                const ns = switch (timer_entry.value.*) {
                    .accumulating => |t| t.sum,
                    .range => |range| range.end.since(range.start),
                };
                const ms = @as(f64, @floatFromInt(ns)) / 1000_000.0;
                std.debug.print("- {s}: {d} ns ({d:.02} ms)\n", .{@tagName(timer_entry.key), ns, ms});
            }

            std.debug.print("Top level declarations:\n", .{});
            for (file.time.top_level_declaration_timers.slice()) |timer| {
                const ns = timer.end.since(timer.start);
                const ms = @as(f64, @floatFromInt(ns)) / 1000_000.0;
                std.debug.print("- {s}: {d} ns ({d:.02} ms)\n", .{timer.name, ns, ms});
            }
        }

        for (instance.threads) |*thread| {
            std.debug.print("Thread {}:\n", .{thread.get_index()});
            var it = thread.time.timers.iterator();
            while (it.next()) |timer_entry| {
                const ns = timer_entry.value.end.since(timer_entry.value.start);
                const ms = @as(f64, @floatFromInt(ns)) / 1000_000.0;
                std.debug.print("- {s}: {d} ns ({d:.02} ms)\n", .{@tagName(timer_entry.key), ns, ms});
            }
        }

        {
            const ns = link_end.since(link_start);
            const ms = @as(f64, @floatFromInt(ns)) / 1000_000.0;
            std.debug.print("Link time: {} ns ({d:.02} ms)\n", .{ns, ms});
        }

        {
            const ns = program_end.since(program_start);
            const ms = @as(f64, @floatFromInt(ns)) / 1000_000.0;

            std.debug.print("Program took {} ns ({d:.02} ms) to execute!\n", .{ns, ms});
        }
    }
}

const LinkerOptions = struct {
    output_file_path: []const u8,
    extra_arguments: []const []const u8,
    objects: []const []const u8,
    libraries: []const []const u8,
    link_libc: bool,
    link_libcpp: bool,
};

pub fn link(options: LinkerOptions) void {
    var argv = PinnedArray([]const u8){};
    const driver_program = switch (builtin.os.tag) {
        .windows => "lld-link",
        .linux => "ld.lld",
        .macos => "ld64.lld",
        else => @compileError("OS not supported"),
    };
    _ = argv.append(driver_program);
    _ = argv.append("--error-limit=0");

    switch (builtin.cpu.arch) {
        .aarch64 => switch (builtin.os.tag) {
            .linux => {
                _ = argv.append("-znow");
                _ = argv.append_slice(&.{ "-m", "aarch64linux" });
            },
            else => {},
        },
        else => {},
    }

    // const output_path = out_path orelse "a.out";
    _ = argv.append("-o");
    _ = argv.append(options.output_file_path);

    argv.append_slice(options.extra_arguments);

    for (options.objects) |object| {
        _ = argv.append(object);
    }

    const ci = configuration.ci;
    switch (builtin.os.tag) {
        .macos => {
            _ = argv.append("-dynamic");
            argv.append_slice(&.{ "-platform_version", "macos", "13.4.1", "13.3" });
            _ = argv.append("-arch");
            _ = argv.append(switch (builtin.cpu.arch) {
                .aarch64 => "arm64",
                else => |t| @panic(@tagName(t)),
            });

            argv.append_slice(&.{ "-syslibroot", "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk" });

            if (!library.ends_with_slice(options.output_file_path, ".dylib")) {
                argv.append_slice(&.{ "-e", "_main" });
            }

            _ = argv.append("-lSystem");

            if (options.link_libcpp) {
                _ = argv.append("-L/Library/Developer/CommandLineTools/SDKs/MacOSX13.3.sdk/usr/lib");
                _ = argv.append("-lc++");
            }
        },
        .linux => {
            if (ci) {
                if (options.link_libcpp) {
                    assert(options.link_libc);
                    _ = argv.append("/lib/x86_64-linux-gnu/libstdc++.so.6");
                }

                if (options.link_libc) {
                    _ = argv.append("/lib/x86_64-linux-gnu/crt1.o");
                    _ = argv.append("/lib/x86_64-linux-gnu/crti.o");
                    argv.append_slice(&.{ "-L", "/lib/x86_64-linux-gnu" });
                    argv.append_slice(&.{ "-dynamic-linker", "/lib64/ld-linux-x86-64.so.2" });
                    _ = argv.append("--as-needed");
                    _ = argv.append("-lm");
                    _ = argv.append("-lpthread");
                    _ = argv.append("-lc");
                    _ = argv.append("-ldl");
                    _ = argv.append("-lrt");
                    _ = argv.append("-lutil");
                    _ = argv.append("/lib/x86_64-linux-gnu/crtn.o");
                }
            } else {
                if (options.link_libcpp) {
                    assert(options.link_libc);
                    _ = argv.append("/usr/lib64/libstdc++.so.6");
                }

                if (options.link_libc) {
                    _ = argv.append("/usr/lib64/crt1.o");
                    _ = argv.append("/usr/lib64/crti.o");
                    argv.append_slice(&.{ "-L", "/usr/lib64" });

                    _ = argv.append("-dynamic-linker");
                    switch (builtin.cpu.arch) {
                        .x86_64 => _ = argv.append("/lib64/ld-linux-x86-64.so.2"),
                        .aarch64 => _ = argv.append("/lib/ld-linux-aarch64.so.1"),
                        else => unreachable,
                    }

                    _ = argv.append("--as-needed");
                    _ = argv.append("-lm");
                    _ = argv.append("-lpthread");
                    _ = argv.append("-lc");
                    _ = argv.append("-ldl");
                    _ = argv.append("-lrt");
                    _ = argv.append("-lutil");

                    _ = argv.append("/usr/lib64/crtn.o");
                }
            }
        },
        .windows => {},
        else => @compileError("OS not supported"),
    }

    for (options.libraries) |lib| {
        _ = argv.append(instance.arena.join(&.{ "-l", lib }) catch unreachable);
    }

    const argv_zero_terminated = library.argument_copy_zero_terminated(instance.arena, argv.const_slice()) catch unreachable;

    var stdout_ptr: [*]const u8 = undefined;
    var stdout_len: usize = 0;
    var stderr_ptr: [*]const u8 = undefined;
    var stderr_len: usize = 0;
    const result = switch (builtin.os.tag) {
        .linux => NativityLLDLinkELF(argv_zero_terminated.ptr, argv_zero_terminated.len, &stdout_ptr, &stdout_len, &stderr_ptr, &stderr_len),
        .macos => NativityLLDLinkMachO(argv_zero_terminated.ptr, argv_zero_terminated.len, &stdout_ptr, &stdout_len, &stderr_ptr, &stderr_len),
        .windows => NativityLLDLinkCOFF(argv_zero_terminated.ptr, argv_zero_terminated.len, &stdout_ptr, &stdout_len, &stderr_ptr, &stderr_len),
        else => @compileError("OS not supported"),
    };

    if (!result) {
        const stdout = stdout_ptr[0..stdout_len];
        const stderr = stderr_ptr[0..stderr_len];
        for (argv.const_slice()) |arg| {
            write(arg);
            write(" ");
        }
        write("\n");
        if (stdout.len > 0) {
            write(stdout);
            write("\n");
        }

        if (stderr.len > 0) {
            write(stderr);
            write("\n");
        }

        @panic("Linking with LLD failed");
    }
}

extern fn NativityLLDLinkELF(argument_ptr: [*:null]?[*:0]u8, argument_count: usize, stdout_ptr: *[*]const u8, stdout_len: *usize, stderr_ptr: *[*]const u8, stderr_len: *usize) bool;
extern fn NativityLLDLinkCOFF(argument_ptr: [*:null]?[*:0]u8, argument_count: usize, stdout_ptr: *[*]const u8, stdout_len: *usize, stderr_ptr: *[*]const u8, stderr_len: *usize) bool;
extern fn NativityLLDLinkMachO(argument_ptr: [*:null]?[*:0]u8, argument_count: usize, stdout_ptr: *[*]const u8, stdout_len: *usize, stderr_ptr: *[*]const u8, stderr_len: *usize) bool;
extern fn NativityLLDLinkWasm(argument_ptr: [*:null]?[*:0]u8, argument_count: usize, stdout_ptr: *[*]const u8, stdout_len: *usize, stderr_ptr: *[*]const u8, stderr_len: *usize) bool;

fn intern_identifier(pool: *PinnedHashMap(u32, []const u8), identifier: []const u8) u32 {
    const start_index = @intFromBool(identifier[0] == '"');
    const end_index = identifier.len - start_index;
    const hash = hash_bytes(identifier[start_index..end_index]);
    pool.put(hash, identifier);

    return hash;
}

const CallingConvention = enum{
    c,
    custom,
};

const Analyzer = struct{
    current_basic_block: *BasicBlock,
    current_function: *Function,
    current_scope: *Scope,
    exit_blocks: PinnedArray(*BasicBlock) = .{},
    loops: PinnedArray(LoopData) = .{},
    return_block: ?*BasicBlock = null,
    return_phi: ?*Phi = null,
    return_pointer: ?*Instruction = null,

    fn append_instruction(analyzer: *Analyzer, instruction: *Instruction) void {
        assert(!analyzer.current_basic_block.is_terminated);
        assert(instruction.basic_block == null);
        instruction.basic_block = analyzer.current_basic_block;
        _ = analyzer.current_basic_block.instructions.append(instruction);
    }
};

const LoopData = struct {
    break_block: *BasicBlock,
    continue_block: *BasicBlock,
};

const brace_open = '{';
const brace_close = '}';

const pointer_token = '*';

const cache_line_size = switch (builtin.os.tag) {
    .macos => 128,
    else => 64,
};

var cpu_count_buffer = [1]u32{0} ** @divExact(cache_line_size, @sizeOf(u32));

const address_space = 0;

fn try_end_analyzing_file(file: *File) void {
    _ = file; // autofix
}

fn worker_thread(thread_index: u32, cpu_count: *u32) void {
    const thread_start = get_instant();
    while (true) {
        const local_cpu_count = cpu_count.*;
        if (local_cpu_count == 0) {
            break;
        }

        if (@cmpxchgWeak(u32, cpu_count, local_cpu_count, local_cpu_count - 1, .seq_cst, .seq_cst) == null) {
            const new_thread_index = local_cpu_count - 1;
            instance.threads[thread_index].handle = std.Thread.spawn(.{}, worker_thread, .{new_thread_index, cpu_count}) catch unreachable;
        }
    }

    const thread = &instance.threads[thread_index];
    thread.arena = Arena.init(4 * 1024 * 1024) catch unreachable;

    for (&thread.integers) |*integer| {
        integer.type.sema.thread = @intCast(thread_index);
    }
    thread.opaque_pointer.sema.thread = @intCast(thread_index);
    thread.void.sema.thread = @intCast(thread_index);
    thread.noreturn.sema.thread = @intCast(thread_index);

    const thread_setup_end = get_instant();
    if (configuration.timers) {
        thread.time.timers.set(.setup, .{ .start = thread_start, .end = thread_setup_end });
    }

    while (true) {
        while (thread.get_worker_job()) |job| {
            const c = thread.task_system.job.worker.completed;
            switch (job.id) {
                .analyze_file => {
                    if (configuration.timers) {
                        const t = thread.time.timers.get(.analysis);
                        if (t.end.order(t.start) == .eq) {
                            thread.time.timers.getPtr(.analysis).start = get_instant();
                        }
                    }
                    const file_index = job.offset;
                    const file = &instance.files.slice()[file_index];
                    file.thread = thread_index;
                    thread.assigned_file_count += 1;
                    const queue_end = get_instant();
                    if (configuration.timers) {
                        const queue_start = file.time.timestamp;
                        file.time.timers.set(.queue, .{
                            .range = .{
                                .start = queue_start,
                                .end = queue_end,
                            },
                            });
                    }
                    const read_start = queue_end;
                    file.state = .reading;
                    file.source_code = library.read_file(thread.arena, std.fs.cwd(), file.path);
                    const read_end = get_instant();
                    if (configuration.timers) {
                        file.time.timers.set(.read, .{
                            .range = .{
                                .start = read_start,
                                .end = read_end,
                            },
                            });

                        file.time.timestamp = read_end;
                    }
                    file.state = .analyzing;
                    analyze_file(thread, file_index);
                },
                .notify_file_resolved => {
                    const file_index = job.count;
                    const file = &instance.files.pointer[file_index];

                    if (thread == &instance.threads[file.thread]) {
                        fail_message("Threads match!");
                    } else {
                        const file_path_hash = job.offset;
                        for (file.interested_files.slice()) |interested_file| {
                            if (interested_file.thread == thread.get_index()) {
                                assert(interested_file.resolved_import_count != interested_file.imports.length);
                                for (interested_file.imports.slice(), 0..) |import, i| {
                                    if (import.hash == file_path_hash) {
                                        const values_per_import = interested_file.values_per_import.get(@enumFromInt(i));
                                        for (values_per_import.slice()) |value| {
                                            assert(value.sema.thread == thread.get_index());
                                            assert(!value.sema.resolved);
                                            if (!value.sema.resolved) {
                                                switch (value.sema.id) {
                                                    .instruction => {
                                                        const instruction = value.get_payload(.instruction);
                                                        switch (instruction.id) {
                                                            .call => {
                                                                const call: *Call = instruction.get_payload(.call);
                                                                assert(!call.callable.sema.resolved);

                                                                switch (call.callable.sema.id) {
                                                                    .lazy_expression => {
                                                                        const lazy_expression = call.callable.get_payload(.lazy_expression);
                                                                        const names = lazy_expression.names();
                                                                        assert(names.len > 0);

                                                                        switch (lazy_expression.u) {
                                                                            .static => |*static| {
                                                                                _ = static; // autofix
                                                                            },
                                                                            .dynamic => unreachable,
                                                                        }

                                                                        const declaration_reference = lazy_expression.u.static.outsider;
                                                                        switch (declaration_reference.*.id) {
                                                                            .file => {
                                                                                assert(names.len == 1);
                                                                                const file_declaration = declaration_reference.*.get_payload(.file);
                                                                                assert(file_declaration == file);

                                                                                if (file.scope.scope.declarations.get(names[0])) |callable_declaration| {
                                                                                    const global_declaration = callable_declaration.get_payload(.global);
                                                                                    switch (global_declaration.id) {
                                                                                        .global_symbol => {
                                                                                            const global_symbol = global_declaration.to_symbol();
                                                                                            switch (global_symbol.id) {
                                                                                                .function_definition => {
                                                                                                    const function_definition = global_symbol.get_payload(.function_definition);
                                                                                                    const external_fn = function_definition.declaration.clone(thread);
                                                                                                    
                                                                                                    call.callable = &external_fn.global_symbol.value;
                                                                                                    value.sema.resolved = true;
                                                                                                },
                                                                                                else => |t| @panic(@tagName(t)),
                                                                                            }
                                                                                        },
                                                                                        else => |t| @panic(@tagName(t)),
                                                                                    }
                                                                                } else {
                                                                                    unreachable;
                                                                                }
                                                                            },
                                                                            else => |t| @panic(@tagName(t)),
                                                                        }
                                                                    },
                                                                    else => |t| @panic(@tagName(t)),
                                                                }
                                                            },
                                                            else => |t| @panic(@tagName(t)),
                                                        }
                                                    },
                                                    .lazy_expression => {
                                                        const lazy_expression = value.get_payload(.lazy_expression);
                                                        assert(lazy_expression.u == .static);
                                                        for (lazy_expression.u.static.names) |n| {
                                                            assert(n == 0);
                                                        }
                                                        const declaration_reference = lazy_expression.u.static.outsider;

                                                        switch (declaration_reference.*.id) {
                                                            .unresolved_import => {
                                                                declaration_reference.* = &file.global_declaration;
                                                                value.sema.resolved = true;
                                                            },
                                                            else => |t| @panic(@tagName(t)),
                                                        }
                                                    },
                                                    else => |t| @panic(@tagName(t)),
                                                }
                                            }
                                        }
                                    }
                                }

                                interested_file.resolved_import_count += 1;

                                try_resolve_file(thread, interested_file);
                            }
                        }
                    }
                },
                .llvm_generate_ir => {
                    if (thread.functions.length > 0 or thread.global_variables.length > 0) {
                        const llvm_start = get_instant();
                        const context = LLVM.Context.create();
                        const module_name: []const u8 = "thread";
                        const module = LLVM.Module.create(module_name.ptr, module_name.len, context);
                        const builder = LLVM.Builder.create(context);
                        const attributes = LLVM.Attributes{
                            .naked = context.getAttributeFromEnum(.Naked, 0),
                            .noreturn = context.getAttributeFromEnum(.NoReturn, 0),
                            .nounwind = context.getAttributeFromEnum(.NoUnwind, 0),
                            .inreg = context.getAttributeFromEnum(.InReg, 0),
                            .@"noalias" = context.getAttributeFromEnum(.NoAlias, 0),
                            .sign_extend = context.getAttributeFromEnum(.SExt, 0),
                            .zero_extend = context.getAttributeFromEnum(.ZExt, 0),
                        };

                        const target_triple = switch (builtin.os.tag) {
                            .linux => switch (builtin.cpu.arch) {
                                .aarch64 => "aarch64-linux-none",
                                .x86_64 => "x86_64-unknown-linux-gnu",
                                else => @compileError("CPU not supported"),
                            },
                            .macos => "aarch64-apple-macosx-none",
                            .windows => "x86_64-windows-gnu",
                            else => @compileError("OS not supported"),
                        };
                        const cpu = builtin.cpu.model.llvm_name.?;

                        var features = PinnedArray(u8){
                            .pointer = @constCast(""),
                        };

                        const temp_use_native_features = true;
                        if (temp_use_native_features) {
                            const feature_list = builtin.cpu.arch.allFeaturesList();
                            if (feature_list.len > 0) {
                                for (feature_list, 0..) |feature, index_usize| {
                                    const index = @as(std.Target.Cpu.Feature.Set.Index, @intCast(index_usize));
                                    const is_enabled = builtin.cpu.features.isEnabled(index);

                                    if (feature.llvm_name) |llvm_name| {
                                        const plus_or_minus = "-+"[@intFromBool(is_enabled)];
                                        _ = features.append(plus_or_minus);
                                        features.append_slice(llvm_name);
                                        features.append_slice(",");
                                    }
                                }

                                assert(std.mem.endsWith(u8, features.slice(), ","));
                                features.length -= 1;
                            }
                        }

                        const target = blk: {
                            var error_message: [*]const u8 = undefined;
                            var error_message_len: usize = 0;

                            const optional_target = LLVM.bindings.NativityLLVMGetTarget(target_triple.ptr, target_triple.len, &error_message, &error_message_len);
                            const target = optional_target orelse {
                                fail_message(error_message[0..error_message_len]);
                            };
                            break :blk target;
                        };
                        const jit = false;
                        const code_model: LLVM.CodeModel = undefined;
                        const is_code_model_present = false;

                        // TODO:
                        const codegen_optimization_level: LLVM.CodegenOptimizationLevel = switch (Optimization.none) {
                            .none => .none,
                            .debug_prefer_fast, .debug_prefer_size => .none,
                            .lightly_optimize_for_speed => .less,
                            .optimize_for_speed, .optimize_for_size => .default,
                            .aggressively_optimize_for_speed, .aggressively_optimize_for_size => .aggressive,
                        };
                        const target_machine = target.createTargetMachine(target_triple.ptr, target_triple.len, cpu.ptr, cpu.len, features.pointer, features.length, LLVM.RelocationModel.static, code_model, is_code_model_present, codegen_optimization_level, jit);

                        module.setTargetMachineDataLayout(target_machine);
                        module.setTargetTriple(target_triple.ptr, target_triple.len);


                        thread.llvm = .{
                            .context = context,
                            .module = module,
                            .attributes = attributes,
                            .target_machine = target_machine,
                            .intrinsic_ids = @TypeOf(thread.llvm.intrinsic_ids).init(.{
                                .leading_zeroes = llvm_get_intrinsic_id("llvm.ctlz"),
                                .trailing_zeroes = llvm_get_intrinsic_id("llvm.cttz"),
                            }),
                            .fixed_intrinsic_functions = @TypeOf(thread.llvm.fixed_intrinsic_functions).init(.{
                                .trap = llvm_get_intrinsic_function(thread, .{
                                    .id = llvm_get_intrinsic_id("llvm.trap"),
                                    .types = &.{},
                                }),
                            }),
                        };

                        for (thread.external_functions.slice()) |*nat_function| {
                            llvm_emit_function_declaration(thread, nat_function);
                        }

                        for (thread.functions.slice()) |*nat_function| {
                            assert(nat_function.declaration.global_symbol.id == .function_definition);
                            llvm_emit_function_declaration(thread, &nat_function.declaration);
                        }

                        for (thread.global_variables.slice()) |*nat_global| {
                            const global_type = llvm_get_type(thread, nat_global.global_symbol.type);
                            const linkage: LLVM.Linkage = switch (nat_global.global_symbol.attributes.@"export") {
                                true => .@"extern",
                                false => .internal,
                            };
                            const constant = switch (nat_global.global_symbol.attributes.mutability) {
                                .@"var" => false,
                                .@"const" => true,
                            };
                            const initializer = llvm_get_value(thread, nat_global.initial_value).toConstant() orelse unreachable;
                            const thread_local_mode = LLVM.ThreadLocalMode.not_thread_local;
                            const externally_initialized = false;
                            const name = thread.identifiers.get(nat_global.global_symbol.global_declaration.declaration.name).?;
                            const global_variable = module.addGlobalVariable(global_type, constant, linkage, initializer, name.ptr, name.len, null, thread_local_mode, address_space, externally_initialized);
                            global_variable.toGlobalObject().setAlignment(nat_global.global_symbol.alignment);
                            nat_global.global_symbol.value.llvm = global_variable.toValue();

                            if (thread.generate_debug_information) {
                                const file_index = nat_global.global_symbol.global_declaration.declaration.scope.file;
                                const file_struct = llvm_get_file(thread, file_index);
                                const file = file_struct.file;
                                const scope = file.toScope();

                                const debug_type = llvm_get_debug_type(thread, file_struct.builder, nat_global.global_symbol.type);
                                const is_local_to_unit = !nat_global.global_symbol.attributes.@"export";
                                const is_defined = !nat_global.global_symbol.attributes.@"extern";
                                const expression = null;
                                const declaration = null;
                                const template_parameters = null;
                                const alignment = 0;
                                const line = nat_global.global_symbol.global_declaration.declaration.line;
                                const debug_global_variable = file_struct.builder.createGlobalVariableExpression(scope, name.ptr, name.len, name.ptr, name.len, file, line, debug_type, is_local_to_unit, is_defined, expression, declaration, template_parameters, alignment);
                                global_variable.addDebugInfo(debug_global_variable);
                            }
                        }

                        for (thread.functions.slice()) |*nat_function| {
                            const function = nat_function.declaration.global_symbol.value.llvm.?.toFunction() orelse unreachable;
                            const file_index = nat_function.declaration.global_symbol.global_declaration.declaration.scope.file;
                            var basic_block_command_buffer = BasicBlock.CommandList{};
                            var emit_allocas = true;
                            {
                                const nat_entry_basic_block = nat_function.entry_block;
                                assert(nat_entry_basic_block.predecessors.length == 0);
                                const entry_block_name = "entry";
                                const entry_block = thread.llvm.context.createBasicBlock(entry_block_name, entry_block_name.len, function, null);
                                nat_entry_basic_block.value.llvm = entry_block.toValue();

                                basic_block_command_buffer.append(&nat_entry_basic_block.command_node);
                            }

                            var phis = PinnedArray(*Phi){};
                            var llvm_phi_nodes = PinnedArray(*LLVM.Value.Instruction.PhiNode){};

                            while (basic_block_command_buffer.len != 0) {
                                const basic_block_node = basic_block_command_buffer.first orelse unreachable;
                                const basic_block: *BasicBlock = @fieldParentPtr("command_node", basic_block_node);
                                const llvm_basic_block = basic_block.get_llvm();
                                builder.setInsertPoint(llvm_basic_block);

                                var last_block = basic_block_node;

                                if (emit_allocas) {
                                    for (nat_function.arguments.slice(), nat_function.declaration.get_function_type().abi.argument_types_abi) |argument, abi| {
                                        _ = abi; // autofix
                                        switch (argument.instruction.id) {
                                            .argument_storage => {
                                                const alloca_type = llvm_get_type(thread, argument.type);
                                                argument.instruction.value.llvm = builder.createAlloca(alloca_type, address_space, null, "", "".len, argument.alignment).toValue();
                                            },
                                            .abi_indirect_argument => {
                                                const llvm_argument = function.getArgument(argument.index);
                                                argument.instruction.value.llvm = llvm_argument.toValue();
                                            },
                                            else => |t| @panic(@tagName(t)),
                                        }
                                    }

                                    for (nat_function.stack_slots.slice()) |local_slot| {
                                        const alloca_type = llvm_get_type(thread, local_slot.type);
                                        local_slot.instruction.value.llvm = builder.createAlloca(alloca_type, address_space, null, "", "".len, local_slot.alignment).toValue();
                                    }

                                    emit_allocas = false;
                                }

                                for (basic_block.instructions.slice()) |instruction| {
                                    if (thread.generate_debug_information) {
                                        if (instruction.line != 0) {
                                            const scope = llvm_get_scope(thread, instruction.scope);
                                            builder.setCurrentDebugLocation(context, instruction.line, instruction.column, scope, function);
                                        } else {
                                            builder.clearCurrentDebugLocation();
                                        }
                                    }

                                    const value: *LLVM.Value = switch (instruction.id) {
                                        .abi_argument => block: {
                                            const abi_argument = instruction.get_payload(.abi_argument);
                                            const llvm_argument = function.getArgument(abi_argument.index);
                                            break :block llvm_argument.toValue();
                                        },
                                        .debug_argument => block: {
                                            assert(thread.generate_debug_information);
                                            const debug_argument = instruction.get_payload(.debug_argument);
                                            const argument_symbol = debug_argument.argument;
                                            const name_hash = argument_symbol.argument_declaration.declaration.name;
                                            assert(name_hash != 0);
                                            const name = thread.identifiers.get(name_hash).?;
                                            const file_struct = llvm_get_file(thread, file_index);
                                            const scope = llvm_get_scope(thread, instruction.scope);

                                            const debug_declaration_type = llvm_get_debug_type(thread, file_struct.builder, argument_symbol.type);
                                            const always_preserve = true;
                                            const flags = LLVM.DebugInfo.Node.Flags{
                                                .visibility = .none,
                                                .forward_declaration = false,
                                                .apple_block = false,
                                                .block_by_ref_struct = false,
                                                .virtual = false,
                                                .artificial = false,
                                                .explicit = false,
                                                .prototyped = false,
                                                .objective_c_class_complete = false,
                                                .object_pointer = false,
                                                .vector = false,
                                                .static_member = false,
                                                .lvalue_reference = false,
                                                .rvalue_reference = false,
                                                .reserved = false,
                                                .inheritance = .none,
                                                .introduced_virtual = false,
                                                .bit_field = false,
                                                .no_return = false,
                                                .type_pass_by_value = false,
                                                .type_pass_by_reference = false,
                                                .enum_class = false,
                                                .thunk = false,
                                                .non_trivial = false,
                                                .big_endian = false,
                                                .little_endian = false,
                                                .all_calls_described = false,
                                            };
                                            const argument_index = argument_symbol.index + 1;
                                            const line = argument_symbol.argument_declaration.declaration.line;
                                            const column = argument_symbol.argument_declaration.declaration.column;
                                            const debug_parameter_variable = file_struct.builder.createParameterVariable(scope, name.ptr, name.len, argument_index, file_struct.file, line, debug_declaration_type, always_preserve, flags);
                                            const argument_alloca = argument_symbol.instruction.value.llvm.?;

                                            const insert_declare = file_struct.builder.insertDeclare(argument_alloca, debug_parameter_variable, context, line, column, function.getSubprogram().toLocalScope().toScope(), builder.getInsertBlock());
                                            break :block insert_declare.toValue();
                                        },
                                        .debug_local => block: {
                                            assert(thread.generate_debug_information);
                                            const file = llvm_get_file(thread, file_index);
                                            const debug_local = instruction.get_payload(.debug_local);
                                            const local_symbol = debug_local.local;
                                            const debug_declaration_type = llvm_get_debug_type(thread, file.builder, local_symbol.type);
                                            const always_preserve = true;
                                            const flags = LLVM.DebugInfo.Node.Flags{
                                                .visibility = .none,
                                                .forward_declaration = false,
                                                .apple_block = false,
                                                .block_by_ref_struct = false,
                                                .virtual = false,
                                                .artificial = false,
                                                .explicit = false,
                                                .prototyped = false,
                                                .objective_c_class_complete = false,
                                                .object_pointer = false,
                                                .vector = false,
                                                .static_member = false,
                                                .lvalue_reference = false,
                                                .rvalue_reference = false,
                                                .reserved = false,
                                                .inheritance = .none,
                                                .introduced_virtual = false,
                                                .bit_field = false,
                                                .no_return = false,
                                                .type_pass_by_value = false,
                                                .type_pass_by_reference = false,
                                                .enum_class = false,
                                                .thunk = false,
                                                .non_trivial = false,
                                                .big_endian = false,
                                                .little_endian = false,
                                                .all_calls_described = false,
                                            };

                                            const alignment = 0;
                                            const declaration_name = thread.identifiers.get(local_symbol.local_declaration.declaration.name).?;
                                            const line = local_symbol.local_declaration.declaration.line;
                                            const column = local_symbol.local_declaration.declaration.column;
                                            const scope = llvm_get_scope(thread, local_symbol.local_declaration.declaration.scope);
                                            const debug_local_variable = file.builder.createAutoVariable(scope, declaration_name.ptr, declaration_name.len, file.file, line, debug_declaration_type, always_preserve, flags, alignment);

                                            const insert_declare = file.builder.insertDeclare(local_symbol.instruction.value.llvm.?, debug_local_variable, context, line, column, (function.getSubprogram()).toLocalScope().toScope(), builder.getInsertBlock());
                                            break :block insert_declare.toValue();
                                        },
                                        .store => block: {
                                            const store = instruction.get_payload(.store);
                                            const destination = llvm_get_value(thread, store.destination);
                                            const source = llvm_get_value(thread, store.source);
                                            const store_instruction = builder.createStore(source, destination, store.is_volatile, store.alignment);
                                            builder.setInstructionDebugLocation(@ptrCast(store_instruction));
                                            break :block store_instruction.toValue();
                                        },
                                        .load => block: {
                                            const load = instruction.get_payload(.load);
                                            const load_value = llvm_get_value(thread, load.value);
                                            const load_type = llvm_get_type(thread, load.type);
                                            // TODO: precise alignment
                                            const load_instruction = builder.createLoad(load_type, load_value, load.is_volatile, "", "".len, load.alignment);
                                            builder.setInstructionDebugLocation(@ptrCast(load_instruction));
                                            break :block load_instruction.toValue();
                                        },
                                        .ret => block: {
                                            const return_instruction = instruction.get_payload(.ret);
                                            const return_value = llvm_get_value(thread, return_instruction.value);
                                            const ret = builder.createRet(return_value);
                                            break :block ret.toValue();
                                        },
                                        .ret_void => block: {
                                            const ret = builder.createRet(null);
                                            break :block ret.toValue();
                                        },
                                        .integer_binary_operation => block: {
                                            const integer_binary_operation = instruction.get_payload(.integer_binary_operation);
                                            const left = llvm_get_value(thread, integer_binary_operation.left);
                                            const right = llvm_get_value(thread, integer_binary_operation.right);
                                            const integer_type = integer_binary_operation.type.get_payload(.integer);
                                            const no_unsigned_wrapping = integer_type.signedness == .unsigned;
                                            const no_signed_wrapping = integer_type.signedness == .signed;
                                            const name = "";
                                            const is_exact = false;
                                            break :block switch (integer_binary_operation.id) {
                                                .add => builder.createAdd(left, right, name, name.len, no_unsigned_wrapping, no_signed_wrapping),
                                                .sub => builder.createSub(left, right, name, name.len, no_unsigned_wrapping, no_signed_wrapping),
                                                .mul => builder.createMultiply(left, right, name, name.len, no_unsigned_wrapping, no_signed_wrapping),
                                                .udiv => builder.createUDiv(left, right, name, name.len, is_exact),
                                                .sdiv => builder.createSDiv(left, right, name, name.len, is_exact),
                                                .@"and" => builder.createAnd(left, right, name, name.len),
                                                .@"or" => builder.createOr(left, right, name, name.len),
                                                .@"xor" => builder.createXor(left, right, name, name.len),
                                                .shift_left => builder.createShiftLeft(left, right, name, name.len, no_unsigned_wrapping, no_signed_wrapping),
                                                .arithmetic_shift_right => builder.createArithmeticShiftRight(left, right, name, name.len, is_exact),
                                                .logical_shift_right => builder.createLogicalShiftRight(left, right, name, name.len, is_exact),
                                            };
                                        },
                                        .call => block: {
                                            const call = instruction.get_payload(.call);
                                            const nat_function_type = call.get_function_type();
                                            const function_type = llvm_get_type(thread, &nat_function_type.type);
                                            const callee = llvm_get_value(thread, call.callable);

                                            var arguments = std.BoundedArray(*LLVM.Value, 512){};
                                            for (call.arguments) |argument| {
                                                const llvm_argument = llvm_get_value(thread, argument); 
                                                _ = arguments.appendAssumeCapacity(llvm_argument);
                                            }


                                            const args = arguments.constSlice();
                                            const call_i = builder.createCall(function_type.toFunction() orelse unreachable, callee, args.ptr, args.len, "", "".len, null);

                                            var parameter_attribute_sets = std.BoundedArray(*const LLVM.Attribute.Set, 512){};
                                            const function_attributes = llvm_emit_function_attributes(thread, nat_function_type, &parameter_attribute_sets);
                                            call_i.setAttributes(thread.llvm.context, function_attributes.function_attributes, function_attributes.return_attribute_set, function_attributes.parameter_attribute_sets.ptr, function_attributes.parameter_attribute_sets.len);

                                            const calling_convention = calling_convention_map.get(nat_function_type.abi.calling_convention);
                                            call_i.setCallingConvention(calling_convention);

                                            break :block call_i.toValue();
                                        },
                                        .integer_compare => block: {
                                            const compare = instruction.get_payload(.integer_compare);
                                            const type_a = compare.left.get_type();
                                            const type_b = compare.right.get_type();
                                            assert(type_a == type_b);
                                            const left = llvm_get_value(thread, compare.left);
                                            if (compare.id == .not_zero) {
                                                const is_not_null = builder.createIsNotNull(left, "", "".len);
                                                break :block is_not_null;
                                            } else {
                                                const right = llvm_get_value(thread, compare.right);
                                                const name = "";
                                                const comparison: LLVM.Value.Instruction.ICmp.Kind = switch (compare.id) {
                                                    .equal => .eq,
                                                    .not_equal => .ne,
                                                    .not_zero => unreachable,
                                                    .unsigned_greater_equal => .uge,
                                                    .unsigned_greater => .ugt,
                                                    .signed_greater_equal => .sge,
                                                    .signed_greater => .sgt,
                                                    .unsigned_less_equal => .ule,
                                                    .unsigned_less => .ult,
                                                    .signed_less_equal => .sle,
                                                    .signed_less => .slt,
                                                };

                                                const cmp = builder.createICmp(comparison, left, right, name, name.len);
                                                break :block cmp;
                                            }
                                        },
                                        .branch => block: {
                                            const branch = instruction.get_payload(.branch);
                                            basic_block_command_buffer.insertAfter(last_block, &branch.taken.command_node);
                                            basic_block_command_buffer.insertAfter(&branch.taken.command_node, &branch.not_taken.command_node);
                                            last_block = &branch.not_taken.command_node;

                                            const taken = thread.llvm.context.createBasicBlock("", "".len, function, null);
                                            branch.taken.value.llvm = taken.toValue();
                                            assert(taken.toValue().toBasicBlock() != null);
                                            const not_taken = thread.llvm.context.createBasicBlock("", "".len, function, null);
                                            assert(not_taken.toValue().toBasicBlock() != null);
                                            branch.not_taken.value.llvm = not_taken.toValue();

                                            const condition = llvm_get_value(thread, branch.condition);
                                            const branch_weights = null;
                                            const unpredictable = null;
                                            const br = builder.createConditionalBranch(condition, taken, not_taken, branch_weights, unpredictable);
                                            break :block br.toValue();
                                        },
                                        .jump => block: {
                                            const jump = instruction.get_payload(.jump);
                                            const target_block = jump.basic_block;
                                            assert(target_block.value.sema.thread == thread.get_index());
                                            const llvm_target_block = if (target_block.value.llvm) |llvm| llvm.toBasicBlock() orelse unreachable else bb: {
                                                const block = thread.llvm.context.createBasicBlock("", "".len, function, null);
                                                assert(block.toValue().toBasicBlock() != null);
                                                target_block.value.llvm = block.toValue();
                                                basic_block_command_buffer.insertAfter(last_block, &target_block.command_node);
                                                last_block = &target_block.command_node;
                                                break :bb block;
                                            };
                                            const br = builder.createBranch(llvm_target_block);
                                            break :block br.toValue();
                                        },
                                        .phi => block: {
                                            const phi = instruction.get_payload(.phi);
                                            const phi_type = llvm_get_type(thread, phi.type);
                                            const reserved_value_count = phi.nodes.length;
                                            const phi_node = builder.createPhi(phi_type, reserved_value_count, "", "".len);
                                            _ = phis.append(phi);
                                            _ = llvm_phi_nodes.append(phi_node);
                                            break :block phi_node.toValue();
                                        },
                                        .@"unreachable" => block: {
                                            const ur = builder.createUnreachable();
                                            break :block ur.toValue();
                                        },
                                        .trap => block: {
                                            const args: []const *LLVM.Value = &.{};
                                            const intrinsic = thread.llvm.fixed_intrinsic_functions.get(.trap);
                                            const call_i = builder.createCall(intrinsic.getType(), intrinsic.toValue(), args.ptr, args.len, "", "".len, null);
                                            break :block call_i.toValue();
                                        },
                                        .leading_zeroes => block: {
                                            const leading_zeroes = instruction.get_payload(.leading_zeroes);
                                            const v = llvm_get_value(thread, leading_zeroes.value);
                                            const v_type = v.getType();
                                            const lz_id = thread.llvm.intrinsic_ids.get(.leading_zeroes);
                                            const parameters = LLVMIntrinsic.Parameters{
                                                .id = lz_id,
                                                .types = &.{v_type},
                                            };
                                            const intrinsic_function = llvm_get_intrinsic_function(thread, parameters);
                                            const intrinsic_function_type = intrinsic_function.getType();
                                            const is_poison = context.getConstantInt(1, 0, false);
                                            const args: []const *LLVM.Value = &.{v, is_poison.toValue()};
                                            const call_i = builder.createCall(intrinsic_function_type, intrinsic_function.toValue(), args.ptr, args.len, "", "".len, null);
                                            break :block call_i.toValue();
                                        },
                                        .trailing_zeroes => block: {
                                            const trailing_zeroes = instruction.get_payload(.trailing_zeroes);
                                            const v = llvm_get_value(thread, trailing_zeroes.value);
                                            const v_type = v.getType();
                                            const tz_id = thread.llvm.intrinsic_ids.get(.trailing_zeroes);
                                            const parameters = LLVMIntrinsic.Parameters{
                                                .id = tz_id,
                                                .types = &.{v_type},
                                            };
                                            const intrinsic_function = llvm_get_intrinsic_function(thread, parameters);
                                            const intrinsic_function_type = intrinsic_function.getType();
                                            const is_poison = context.getConstantInt(1, 0, false);
                                            const args: []const *LLVM.Value = &.{v, is_poison.toValue()};
                                            const call_i = builder.createCall(intrinsic_function_type, intrinsic_function.toValue(), args.ptr, args.len, "", "".len, null);
                                            break :block call_i.toValue();
                                        },
                                        .get_element_pointer => block: {
                                            const gep = instruction.get_payload(.get_element_pointer);
                                            const aggregate_type = llvm_get_type(thread, gep.aggregate_type);
                                            const pointer = llvm_get_value(thread, gep.pointer);
                                            const in_bounds = true;
                                            const index = llvm_get_value(thread, gep.index);
                                            const struct_index = context.getConstantInt(@bitSizeOf(u32), 0, false);
                                            const index_buffer = [2]*LLVM.Value{ struct_index.toValue(), index };
                                            const indices = index_buffer[@intFromBool(!gep.is_struct)..];
                                            const get_element_pointer = builder.createGEP(aggregate_type, pointer, indices.ptr, indices.len, "".ptr, "".len, in_bounds);
                                            break :block get_element_pointer;
                                        },
                                        .cast => block: {
                                            const cast = instruction.get_payload(.cast);
                                            const cast_value = llvm_get_value(thread, cast.value);
                                            const v = switch (cast.id) {
                                                .int_from_bitfield => cast_value,
                                                .truncate, .int_from_pointer => |cast_id| b: {
                                                    const cast_type = llvm_get_type(thread, cast.type);
                                                    const cast_i = builder.createCast(switch (cast_id) {
                                                        .truncate => .truncate,
                                                        .int_from_pointer => .pointer_to_int,
                                                        else => |t| @panic(@tagName(t)),
                                                    }, cast_value, cast_type, "", "".len);
                                                    break :b cast_i;
                                                },
                                                else => |t| @panic(@tagName(t)),
                                            };
                                            break :block v;
                                        },
                                        .memcpy => block: {
                                            const memcpy = instruction.get_payload(.memcpy);
                                            const destination = llvm_get_value(thread, memcpy.destination);
                                            const source = llvm_get_value(thread, memcpy.source);
                                            const memcopy = builder.createMemcpy(destination, memcpy.destination_alignment, source, memcpy.source_alignment, memcpy.size, memcpy.is_volatile);
                                            break :block memcopy.toValue();
                                        },
                                        .extract_value => block: {
                                            const extract_value = instruction.get_payload(.extract_value);
                                            const aggregate = llvm_get_value(thread, extract_value.aggregate);
                                            const indices = [1]c_uint{extract_value.index};
                                            const i = builder.createExtractValue(aggregate, &indices, indices.len, "", "".len);
                                            break :block i;
                                        },
                                        else => |t| @panic(@tagName(t)),
                                    };

                                    instruction.value.llvm = value;
                                }

                                _ = basic_block_command_buffer.popFirst();
                            }

                            for (phis.const_slice(), llvm_phi_nodes.const_slice()) |phi, llvm_phi| {
                                for (phi.nodes.const_slice()) |phi_node| {
                                    const llvm_value = llvm_get_value(thread, phi_node.value);
                                    const llvm_basic_block = phi_node.basic_block.get_llvm();
                                    llvm_phi.addIncoming(llvm_value, llvm_basic_block);
                                }
                            }

                            if (thread.generate_debug_information) {
                                const llvm_file = thread.debug_info_file_map.get_pointer(file_index).?;
                                const subprogram = function.getSubprogram();
                                llvm_file.builder.finalizeSubprogram(subprogram, function);
                            }

                            const verify_function = false;
                            if (verify_function) {
                                var message: []const u8 = undefined;
                                const verification_success = function.verify(&message.ptr, &message.len);
                                if (!verification_success) {
                                    var function_msg: []const u8 = undefined;
                                    function.toString(&function_msg.ptr, &function_msg.len);
                                    write(function_msg);
                                    write("\n");
                                    fail_message(message);
                                }
                            }
                        }

                        if (thread.generate_debug_information) {
                            for (thread.debug_info_file_map.values()) |v| {
                                v.builder.finalize();
                            }
                        }

                        const verify_module = builtin.mode == .Debug;
                        const print_module_at_failure = true;
                        const print_module = false;

                        if (verify_module) {
                            var verification_message: []const u8 = undefined;
                            const verification_success = thread.llvm.module.verify(&verification_message.ptr, &verification_message.len);
                            if (!verification_success) {
                                if (print_module_at_failure) {
                                    var module_content: []const u8 = undefined;
                                    thread.llvm.module.toString(&module_content.ptr, &module_content.len);
                                    write(module_content);
                                    write("\n");
                                }

                                fail_message(verification_message);
                            }
                        }

                        if (print_module) {
                            var module_content: []const u8 = undefined;
                            thread.llvm.module.toString(&module_content.ptr, &module_content.len);
                            write(module_content);
                            write("\n");
                        }

                        const llvm_end = get_instant();

                        if (configuration.timers) {
                            thread.time.timers.set(.llvm_build_ir, .{
                                .start = llvm_start,
                                .end = llvm_end,
                            });
                        }

                        thread.add_control_work(.{
                            .id = .llvm_notify_ir_done,
                        });
                    }
                },
                .llvm_emit_object => {
                    const llvm_start = get_instant();
                    const timestamp = get_instant();
                    const thread_object = std.fmt.allocPrint(std.heap.page_allocator, "nat/o/{s}_thread{}_{}.o", .{std.fs.path.basename(std.fs.path.dirname(instance.files.get(@enumFromInt(0)).path).?), thread.get_index(), timestamp}) catch unreachable;
                    thread.llvm.object = thread_object;
                    const disable_verify = builtin.mode != .Debug;
                    const result = thread.llvm.module.addPassesToEmitFile(thread.llvm.target_machine, thread_object.ptr, thread_object.len, LLVM.CodeGenFileType.object, disable_verify);
                    if (!result) {
                        @panic("can't generate machine code");
                    }

                    const llvm_end = get_instant();

                    if (configuration.timers) {
                        thread.time.timers.set(.llvm_emit_object, .{
                            .start = llvm_start,
                            .end = llvm_end,
                        });
                    }

                    thread.add_control_work(.{
                        .id = .llvm_notify_object_done,
                    });
                    // std.debug.print("Thread #{} emitted object and notified\n", .{thread_index});
                },
                .compile_c_source_file => {
                    // TODO: FIXME
                    const unit = instance.units.get_unchecked(0);
                    const c_source_file_index = job.offset;
                    const source_file = unit.descriptor.c_source_files[c_source_file_index];
                    const object_path = unit.descriptor.c_object_files[c_source_file_index];
                    compile_c_source_files(thread, &.{ "-c", source_file, "-o", object_path, "-std=c99"});
                },
                else => |t| @panic(@tagName(t)),
            }

            thread.task_system.job.complete_job();
            assert(thread.task_system.job.worker.completed == c + 1);
        }

        if (configuration.sleep_on_thread_hot_loops) {
            std.time.sleep(1000);
        } else {
            std.atomic.spinLoopHint();
        }
    }
}

const CSourceFileCompilationInvoker = enum{
    nat,
    external,
};

fn compile_c_source_files(thread: *Thread, arguments: []const []const u8) void {
    var argument_index: usize = 0;
    _ = &argument_index;
    const Mode = enum {
        object,
        link,
    };
    var out_path: ?[]const u8 = null;
    var out_mode: ?Mode = null;
    const Extension = enum {
        c,
        cpp,
        assembly,
        object,
        static_library,
        shared_library,
    };
    const CSourceFile = struct {
        path: []const u8,
        extension: Extension,
    };
    const DebugInfo = enum {
        yes,
        no,
    };
    const LinkArch = enum {
        arm64,
    };
    var debug_info: ?DebugInfo = null;
    var stack_protector: ?bool = null;
    var link_arch: ?LinkArch = null;

    var cc_argv = std.BoundedArray([]const u8, 4096){};
    var ld_argv = std.BoundedArray([]const u8, 4096){};
    var c_source_files = std.BoundedArray(CSourceFile, 4096){};
    var link_objects = std.BoundedArray([]const u8, 4096){};
    var link_libraries = std.BoundedArray([]const u8, 4096){};

    while (argument_index < arguments.len) {
        const argument = arguments[argument_index];

        if (argument[0] != '-') {
            if (last_byte(argument, '.')) |dot_index| {
                const extension_string = argument[dot_index..];
                const extension: Extension =
                    if (byte_equal(extension_string, ".c")) .c else if (byte_equal(extension_string, ".cpp") or byte_equal(extension_string, ".cxx") or byte_equal(extension_string, ".cc")) .cpp else if (byte_equal(extension_string, ".S")) .assembly else if (byte_equal(extension_string, ".o")) .object else if (byte_equal(extension_string, ".a")) .static_library else if (byte_equal(extension_string, ".so") or
                    byte_equal(extension_string, ".dll") or
                    byte_equal(extension_string, ".dylib") or
                    byte_equal(extension_string, ".tbd")) .shared_library else {
                    write(argument);
                    write("\n");
                    @panic("Unable to recognize extension for the file above");
                };
                switch (extension) {
                    .c, .cpp, .assembly => {
                        c_source_files.appendAssumeCapacity(.{
                            .path = argument,
                            .extension = extension,
                        });
                    },
                    .object, .static_library, .shared_library => {
                        link_objects.appendAssumeCapacity(argument);
                    },
                }
            } else {
                write(argument);
                write("\n");
                @panic("Positional argument without extension");
            }
        } else if (byte_equal(argument, "-c")) {
            out_mode = .object;
        } else if (byte_equal(argument, "-o")) {
            argument_index += 1;
            out_path = arguments[argument_index];
        } else if (byte_equal(argument, "-g")) {
            debug_info = .yes;
        } else if (byte_equal(argument, "-fno-stack-protector")) {
            stack_protector = false;
        } else if (byte_equal(argument, "-arch")) {
            argument_index += 1;
            const arch_argument = arguments[argument_index];
            if (byte_equal(arch_argument, "arm64")) {
                link_arch = .arm64;
                cc_argv.appendAssumeCapacity("-arch");
                cc_argv.appendAssumeCapacity("arm64");
            } else {
                unreachable;
            }
        } else if (byte_equal(argument, "-bundle")) {
            ld_argv.appendAssumeCapacity(argument);
        } else if (byte_equal(argument, "-pthread")) {
            cc_argv.appendAssumeCapacity(argument);
        } else if (byte_equal(argument, "-fPIC")) {
            cc_argv.appendAssumeCapacity(argument);
        } else if (byte_equal(argument, "-MD")) {
            cc_argv.appendAssumeCapacity(argument);
        } else if (byte_equal(argument, "-MT")) {
            cc_argv.appendAssumeCapacity(argument);
            argument_index += 1;
            const arg = arguments[argument_index];
            cc_argv.appendAssumeCapacity(arg);
        } else if (byte_equal(argument, "-MF")) {
            cc_argv.appendAssumeCapacity(argument);
            argument_index += 1;
            const arg = arguments[argument_index];
            cc_argv.appendAssumeCapacity(arg);
        } else if (byte_equal(argument, "-isysroot")) {
            cc_argv.appendAssumeCapacity(argument);
            argument_index += 1;
            const arg = arguments[argument_index];
            cc_argv.appendAssumeCapacity(arg);
        } else if (byte_equal(argument, "-isystem")) {
            cc_argv.appendAssumeCapacity(argument);
            argument_index += 1;
            const arg = arguments[argument_index];
            cc_argv.appendAssumeCapacity(arg);
        } else if (byte_equal(argument, "-h")) {
            cc_argv.appendAssumeCapacity(argument);
        } else if (byte_equal(argument, "-framework")) {
            ld_argv.appendAssumeCapacity(argument);
            argument_index += 1;
            const framework = arguments[argument_index];
            ld_argv.appendAssumeCapacity(framework);
        } else if (byte_equal(argument, "--coverage")) {
            cc_argv.appendAssumeCapacity(argument);
        } else if (byte_equal(argument, "-pedantic")) {
            cc_argv.appendAssumeCapacity(argument);
        } else if (byte_equal(argument, "-pedantic-errors")) {
            cc_argv.appendAssumeCapacity(argument);
        } else if (byte_equal(argument, "-?")) {
            cc_argv.appendAssumeCapacity(argument);
        } else if (byte_equal(argument, "-v")) {
            cc_argv.appendAssumeCapacity(argument);
        } else if (byte_equal(argument, "-V")) {
            cc_argv.appendAssumeCapacity(argument);
        } else if (byte_equal(argument, "--version")) {
            cc_argv.appendAssumeCapacity(argument);
        } else if (byte_equal(argument, "-version")) {
            cc_argv.appendAssumeCapacity(argument);
        } else if (byte_equal(argument, "-qversion")) {
            cc_argv.appendAssumeCapacity(argument);
        } else if (byte_equal(argument, "-print-resource-dir")) {
            cc_argv.appendAssumeCapacity(argument);
        } else if (byte_equal(argument, "-shared")) {
            ld_argv.appendAssumeCapacity(argument);
        } else if (byte_equal(argument, "-compatibility_version")) {
            ld_argv.appendAssumeCapacity(argument);
            argument_index += 1;
            const arg = arguments[argument_index];
            ld_argv.appendAssumeCapacity(arg);
        } else if (byte_equal(argument, "-current_version")) {
            ld_argv.appendAssumeCapacity(argument);
            argument_index += 1;
            const arg = arguments[argument_index];
            ld_argv.appendAssumeCapacity(arg);
        } else if (byte_equal(argument, "-install_name")) {
            ld_argv.appendAssumeCapacity(argument);
            argument_index += 1;
            const arg = arguments[argument_index];
            ld_argv.appendAssumeCapacity(arg);
        } else if (starts_with_slice(argument, "-f")) {
            cc_argv.appendAssumeCapacity(argument);
        } else if (starts_with_slice(argument, "-wd")) {
            cc_argv.appendAssumeCapacity(argument);
        } else if (starts_with_slice(argument, "-D")) {
            cc_argv.appendAssumeCapacity(argument);
        } else if (starts_with_slice(argument, "-I")) {
            cc_argv.appendAssumeCapacity(argument);
        } else if (starts_with_slice(argument, "-W")) {
            cc_argv.appendAssumeCapacity(argument);
        } else if (starts_with_slice(argument, "-l")) {
            link_libraries.appendAssumeCapacity(argument[2..]);
        } else if (starts_with_slice(argument, "-O")) {
            cc_argv.appendAssumeCapacity(argument);
        } else if (starts_with_slice(argument, "-std=")) {
            cc_argv.appendAssumeCapacity(argument);
        } else if (starts_with_slice(argument, "-rdynamic")) {
            ld_argv.appendAssumeCapacity("-export_dynamic");
        } else if (starts_with_slice(argument, "-dynamiclib")) {
            ld_argv.appendAssumeCapacity("-dylib");
        } else if (starts_with_slice(argument, "-Wl,")) {
            const wl_arg = argument["-Wl,".len..];
            if (first_byte(wl_arg, ',')) |comma_index| {
                const key = wl_arg[0..comma_index];
                const value = wl_arg[comma_index + 1 ..];
                ld_argv.appendAssumeCapacity(key);
                ld_argv.appendAssumeCapacity(value);
            } else {
                ld_argv.appendAssumeCapacity(wl_arg);
            }
        } else if (starts_with_slice(argument, "-m")) {
            cc_argv.appendAssumeCapacity(argument);
        } else {
            fail_term("Unhandled argument", argument);
        }

        argument_index += 1;
    }

    const link_libcpp = true;
    const mode = out_mode orelse .link;

    var argv = std.BoundedArray([]const u8, 4096){};
    if (c_source_files.len > 0) {
        for (c_source_files.slice()) |c_source_file| {
            argv.appendAssumeCapacity(instance.paths.executable);
            argv.appendAssumeCapacity("clang");
            argv.appendAssumeCapacity("--no-default-config");

            argv.appendAssumeCapacity(c_source_file.path);

            if (c_source_file.extension == .cpp) {
                argv.appendAssumeCapacity("-nostdinc++");
            }

            const caret = true;
            if (!caret) {
                argv.appendAssumeCapacity("-fno-caret-diagnostics");
            }

            const function_sections = false;
            if (function_sections) {
                argv.appendAssumeCapacity("-ffunction-sections");
            }

            const data_sections = false;
            if (data_sections) {
                argv.appendAssumeCapacity("-fdata-sections");
            }

            const use_builtin = true;
            if (!use_builtin) {
                argv.appendAssumeCapacity("-fno-builtin");
            }

            if (link_libcpp) {
                // include paths

            }

            const link_libc = c_source_file.extension == .c;
            if (link_libc) {}

            const link_libunwind = false;
            if (link_libunwind) {
                unreachable;
            }

            var target_triple_buffer = std.BoundedArray(u8, 512){};
            const target_triple = blk: {
                // Emit target
                switch (@import("builtin").target.cpu.arch) {
                    .x86_64 => {
                        target_triple_buffer.appendSliceAssumeCapacity("x86_64-");
                    },
                    .aarch64 => {
                        target_triple_buffer.appendSliceAssumeCapacity("aarch64-");
                    },
                    else => @compileError("Architecture not supported"),
                }

                if (@import("builtin").target.cpu.arch == .aarch64 and @import("builtin").target.os.tag == .macos) {
                    target_triple_buffer.appendSliceAssumeCapacity("apple-");
                } else {
                    target_triple_buffer.appendSliceAssumeCapacity("pc-");
                }

                switch (@import("builtin").target.os.tag) {
                    .linux => {
                        target_triple_buffer.appendSliceAssumeCapacity("linux-");
                    },
                    .macos => {
                        target_triple_buffer.appendSliceAssumeCapacity("macos-");
                    },
                    .windows => {
                        target_triple_buffer.appendSliceAssumeCapacity("windows-");
                    },
                    else => @compileError("OS not supported"),
                }

                switch (@import("builtin").target.abi) {
                    .musl => {
                        target_triple_buffer.appendSliceAssumeCapacity("musl");
                    },
                    .gnu => {
                        target_triple_buffer.appendSliceAssumeCapacity("gnu");
                    },
                    .none => {
                        target_triple_buffer.appendSliceAssumeCapacity("unknown");
                    },
                    else => @compileError("OS not supported"),
                }

                break :blk target_triple_buffer.slice();
            };
            argv.appendSliceAssumeCapacity(&.{ "-target", target_triple });

            const object_path = switch (mode) {
                .object => out_path.?,
                .link => thread.arena.join(&.{ if (out_path) |op| op else "a.o", ".o" }) catch unreachable,
            };

            link_objects.appendAssumeCapacity(object_path);

            switch (c_source_file.extension) {
                .c, .cpp => {
                    argv.appendAssumeCapacity("-nostdinc");
                    argv.appendAssumeCapacity("-fno-spell-checking");

                    const lto = false;
                    if (lto) {
                        argv.appendAssumeCapacity("-flto");
                    }

                    const mm = false;
                    if (mm) {
                        argv.appendAssumeCapacity("-ObjC++");
                    }

                    const libc_framework_dirs: []const []const u8 = switch (@import("builtin").os.tag) {
                        .macos => &.{"/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/System/Library/Frameworks"},
                        else => &.{},
                    };
                    for (libc_framework_dirs) |framework_dir| {
                        argv.appendSliceAssumeCapacity(&.{ "-iframework", framework_dir });
                    }

                    const framework_dirs = &[_][]const u8{};
                    for (framework_dirs) |framework_dir| {
                        argv.appendSliceAssumeCapacity(&.{ "-F", framework_dir });
                    }

                    // TODO: c headers dir

                    const libc_include_dirs: []const []const u8 = switch (@import("builtin").os.tag) {
                        .macos => &.{
                            "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/c++/v1",
                            "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/clang/15.0.0/include",
                            "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include",
                        },
                        .linux => configuration.include_paths,
                        //     .gnu => if (@import("configuration").ci) &.{
                        //         "/usr/include/c++/11",
                        //         "/usr/include/x86_64-linux-gnu/c++/11",
                        //         "/usr/lib/clang/17/include",
                        //         "/usr/include",
                        //         "/usr/include/x86_64-linux-gnu",
                        //     } else switch (@import("builtin").cpu.arch) {
                        //         .x86_64 => &.{
                        //             "/usr/include/c++/14",
                        //             "/usr/include/c++/14/x86_64-pc-linux-gnu",
                        //             "/usr/lib/clang/17/include",
                        //             "/usr/include",
                        //             "/usr/include/linux",
                        //         },
                        //         .aarch64 => &.{
                        //             "/usr/include/c++/14",
                        //             "/usr/include/c++/14/aarch64-redhat-linux",
                        //             "/usr/lib/clang/18/include",
                        //             "/usr/include",
                        //             "/usr/include/linux",
                        //         },
                        //         else => unreachable,
                        //     },
                        //     else => unreachable, //@compileError("ABI not supported"),
                        // },
                        .windows => &.{},
                        else => @compileError("OS not supported"),
                    };

                    for (libc_include_dirs) |include_dir| {
                        argv.appendSliceAssumeCapacity(&.{ "-isystem", include_dir });
                    }

                    // TODO: cpu model
                    // TODO: cpu features
                    // TODO: code model
                    // TODO: OS-specific flags
                    // TODO: sanitize flags
                    // const red_zone = true;
                    // if (red_zone) {
                    //     argv.appendAssumeCapacity("-mred-zone");
                    // } else {
                    //     unreachable;
                    // }

                    const omit_frame_pointer = false;
                    if (omit_frame_pointer) {
                        argv.appendAssumeCapacity("-fomit-frame-pointer");
                    } else {
                        argv.appendAssumeCapacity("-fno-omit-frame-pointer");
                    }

                    if (stack_protector orelse false) {
                        argv.appendAssumeCapacity("-fstack-protector-strong");
                    } else {
                        argv.appendAssumeCapacity("-fno-stack-protector");
                    }

                    const is_debug = true;
                    if (is_debug) {
                        argv.appendAssumeCapacity("-D_DEBUG");
                        argv.appendAssumeCapacity("-O0");
                    } else {
                        unreachable;
                    }

                    const pic = false;
                    if (pic) {
                        argv.appendAssumeCapacity("-fPIC");
                    }

                    const unwind_tables = false;
                    if (unwind_tables) {
                        argv.appendAssumeCapacity("-funwind-tables");
                    } else {
                        argv.appendAssumeCapacity("-fno-unwind-tables");
                    }
                },
                .assembly => {
                    // TODO:
                },
                .object, .static_library, .shared_library => unreachable,
            }

            const has_debug_info = true;
            if (has_debug_info) {
                argv.appendAssumeCapacity("-g");
            } else {
                unreachable;
            }

            // TODO: machine ABI
            const freestanding = false;
            if (freestanding) {
                argv.appendAssumeCapacity("-ffrestanding");
            }

            // TODO: native system include paths
            // TODO: global cc argv

            argv.appendSliceAssumeCapacity(cc_argv.slice());

            // TODO: extra flags
            // TODO: cache exempt flags
            argv.appendSliceAssumeCapacity(&.{ "-c", "-o", object_path });
            // TODO: emit ASM/LLVM IR

            const debug_clang_args = false;
            if (debug_clang_args) {
                std.debug.print("Argv: {s}\n", .{argv.slice()});
            }

            clang_main(thread.arena, argv.slice());
        }
    } else if (link_objects.len == 0) {
        unreachable;
        // argv.appendAssumeCapacity(context.executable_absolute_path);
        // argv.appendAssumeCapacity("clang");
        // argv.appendAssumeCapacity("--no-default-config");
        // argv.appendSliceAssumeCapacity(cc_argv.slice());
        // const result = try clangMain(context.arena, argv.slice());
        // if (result != 0) {
        //     unreachable;
        // }
        // return;
    }

    // if (mode == .link) {
    //     unreachable;
    //     // assert(link_objects.len > 0);
    //     // try linker.link(context, .{
    //     //     .backend = .lld,
    //     //     .output_file_path = out_path orelse "a.out",
    //     //     .objects = link_objects.slice(),
    //     //     .libraries = link_libraries.slice(),
    //     //     .extra_arguments = ld_argv.slice(),
    //     //     .link_libc = true,
    //     //     .link_libcpp = link_libcpp,
    //     // });
    // }
}

extern "c" fn nat_clang_main(argc: c_int, argv: [*:null]?[*:0]u8) c_int;
fn clang_main(arena: *Arena, arguments: []const []const u8) void {
    const argv = library.argument_copy_zero_terminated(arena, arguments) catch unreachable;
    const exit_code = nat_clang_main(@as(c_int, @intCast(arguments.len)), argv.ptr);
    if (exit_code != 0) {
        @breakpoint();
        std.posix.exit(@intCast(exit_code));
    }
}

fn llvm_emit_parameter_attributes(thread: *Thread, abi: Function.Abi.Information, is_return: bool) *const LLVM.Attribute.Set{
    var attributes = std.BoundedArray(*LLVM.Attribute, 64){};
    if (abi.attributes.zero_extend) {
        attributes.appendAssumeCapacity(thread.llvm.attributes.zero_extend);
    }
    if (abi.attributes.sign_extend) {
        attributes.appendAssumeCapacity(thread.llvm.attributes.sign_extend);
    }
    if (abi.attributes.by_reg) {
        attributes.appendAssumeCapacity(thread.llvm.attributes.inreg);
    }

    switch (abi.kind) {
        .ignore => {
            assert(is_return);
        },
        .direct, .direct_pair, .direct_coerce => {},
        .indirect => |indirect| {
            const indirect_type = llvm_get_type(thread, indirect.type);
            if (is_return) {
                const sret = thread.llvm.context.getAttributeFromType(.StructRet, indirect_type);
                attributes.appendAssumeCapacity(sret);
                attributes.appendAssumeCapacity(thread.llvm.attributes.@"noalias");
                // TODO: alignment
            } else {
                if (abi.attributes.by_value) {
                    const byval = thread.llvm.context.getAttributeFromType(.ByVal, indirect_type);
                    attributes.appendAssumeCapacity(byval);
                }
                //TODO: alignment
            }
        },
        else => |t| @panic(@tagName(t)),
    }

    const attribute_set = thread.llvm.context.getAttributeSet(&attributes.buffer, attributes.len);
    return attribute_set;
}

const LLVMFunctionAttributes = struct {
    function_attributes: *const LLVM.Attribute.Set,
    return_attribute_set: *const LLVM.Attribute.Set,
    parameter_attribute_sets: []const *const LLVM.Attribute.Set,
};

fn llvm_emit_function_attributes(thread: *Thread, function_type: *Type.Function, parameter_attribute_sets: *std.BoundedArray(*const LLVM.Attribute.Set, 512)) LLVMFunctionAttributes {
    const function_attributes = blk: {
        var function_attributes = std.BoundedArray(*LLVM.Attribute, 256){};
        function_attributes.appendAssumeCapacity(thread.llvm.attributes.nounwind);

        switch (function_type.abi.original_return_type.sema.id) {
            .noreturn => {
                function_attributes.appendAssumeCapacity(thread.llvm.attributes.noreturn);
            },
            else => {},
        }

        // const naked = false;
        // if (naked) {
        //     function_attributes.appendAssumeCapacity(thread.llvm.attributes.naked);
        // }

        const function_attribute_set = thread.llvm.context.getAttributeSet(&function_attributes.buffer, function_attributes.len);
        break :blk function_attribute_set;
    };

    const return_attribute_set = blk: {
        const attribute_set = llvm_emit_parameter_attributes(thread, function_type.abi.return_type_abi, true);
        break :blk switch (function_type.abi.return_type_abi.kind) {
            .indirect => b: {
                parameter_attribute_sets.appendAssumeCapacity(attribute_set);
                break :b thread.llvm.context.getAttributeSet(null, 0);
            },
            else => attribute_set,
        };
    };

    for (function_type.abi.argument_types_abi) |abi| {
        const attribute_set = llvm_emit_parameter_attributes(thread, abi, false);
        parameter_attribute_sets.appendAssumeCapacity(attribute_set);
    }

    return .{
        .function_attributes = function_attributes,
        .return_attribute_set = return_attribute_set,
        .parameter_attribute_sets = parameter_attribute_sets.constSlice(),
    };
}

fn llvm_get_intrinsic_id(intrinsic: []const u8) LLVM.Value.IntrinsicID{
    const intrinsic_id = LLVM.lookupIntrinsic(intrinsic.ptr, intrinsic.len);
    assert(intrinsic_id != .none);
    return intrinsic_id;
}

fn llvm_get_intrinsic_function_from_map(thread: *Thread, parameters: LLVMIntrinsic.Parameters) *LLVM.Value.Constant.Function{
    if (thread.llvm.intrinsic_function_map.get(parameters)) |llvm| return llvm else {
        const intrinsic_function = llvm_get_intrinsic_function(thread, parameters);
        thread.llvm.intrinsic_function_map.put_no_clobber(parameters, intrinsic_function);
        return intrinsic_function;
    }
}

fn llvm_get_intrinsic_function(thread: *Thread, parameters: LLVMIntrinsic.Parameters) *LLVM.Value.Constant.Function{
    const intrinsic_function = thread.llvm.module.getIntrinsicDeclaration(parameters.id, parameters.types.ptr, parameters.types.len);
    return intrinsic_function;
}

fn llvm_get_value(thread: *Thread, value: *Value) *LLVM.Value {
    if (value.llvm) |llvm| {
        assert(value.sema.thread == thread.get_index());
        if (llvm.getContext() != thread.llvm.context) {
            std.debug.print("Value was assigned to thread #{} ", .{thread.get_index()});
            const thread_index = for (instance.threads, 0..) |*t, i| {
                if (t.functions.length > 0) {
                    if (t.llvm.context == llvm.getContext()) {
                        break i;
                    }
                }
            } else unreachable;
            std.debug.print("but context from which it was generated belongs to thread #{}\n", .{thread_index});
            @panic("internal error");
        }
        return llvm;
    } else {
        const value_id = value.sema.id;
        const llvm_value: *LLVM.Value = switch (value_id) {
            .constant_int => b: {
                const constant_int = value.get_payload(.constant_int);
                const integer_type = switch (constant_int.type.sema.id) {
                    .integer => i: {
                        const integer_type = constant_int.type.get_payload(.integer);
                        break :i integer_type;
                    },
                    .bitfield => bf: {
                        const bitfield_type = constant_int.type.get_payload(.bitfield);
                        const integer_type = bitfield_type.backing_type.get_payload(.integer);
                        break :bf integer_type;
                    },
                    else => |t| @panic(@tagName(t)),
                };
                const result = thread.llvm.context.getConstantInt(@intCast(integer_type.type.bit_size), constant_int.n, @intFromEnum(integer_type.signedness) != 0);
                break :b result.toValue();
            },
            .constant_array => b: {
                const constant_array = value.get_payload(.constant_array);
                const array_type = llvm_get_type(thread, constant_array.type);
                var values = PinnedArray(*LLVM.Value.Constant){};
                for (constant_array.values) |v| {
                    const val = llvm_get_value(thread, v);
                    _ = values.append(val.toConstant() orelse unreachable);
                }
                const result = array_type.toArray().?.getConstant(values.pointer, values.length);
                break :b result.toValue();
            },
            .constant_struct => b: {
                const constant_struct = value.get_payload(.constant_struct);
                const struct_type = llvm_get_type(thread, constant_struct.type);
                var values = PinnedArray(*LLVM.Value.Constant){};
                for (constant_struct.values) |v| {
                    const val = llvm_get_value(thread, v);
                    _ = values.append(val.toConstant() orelse unreachable);
                }
                const result = struct_type.toStruct().?.getConstant(values.pointer, values.length);
                break :b result.toValue();
            },
            .constant_bitfield => b: {
                const constant_bitfield = value.get_payload(.constant_bitfield);
                const bitfield_type = constant_bitfield.type.get_payload(.bitfield);
                const bitfield_backing_type = bitfield_type.backing_type.get_payload(.integer);
                const result = thread.llvm.context.getConstantInt(@intCast(bitfield_backing_type.type.bit_size), constant_bitfield.n, @intFromEnum(bitfield_backing_type.signedness) != 0);
                break :b result.toValue();
            },
            .undefined => b: {
                const undef = value.get_payload(.undefined);
                const ty = llvm_get_type(thread, undef.type);
                const poison = ty.getPoison();
                break :b poison.toValue();
            },
            else => |t| @panic(@tagName(t)),
        };

        value.llvm = llvm_value;

        return llvm_value;
    }
}

fn llvm_get_debug_type(thread: *Thread, builder: *LLVM.DebugInfo.Builder, ty: *Type) *LLVM.DebugInfo.Type {
    if (ty.llvm_debug) |llvm| return llvm else {
        const llvm_debug_type = switch (ty.sema.id) {
            .integer => block: {
                const integer = ty.get_payload(.integer);
                const dwarf_encoding: LLVM.DebugInfo.AttributeType = switch (integer.signedness) {
                    .unsigned => .unsigned,
                    .signed => .signed,
                };
                const flags = LLVM.DebugInfo.Node.Flags{
                    .visibility = .none,
                    .forward_declaration = false,
                    .apple_block = false,
                    .block_by_ref_struct = false,
                    .virtual = false,
                    .artificial = false,
                    .explicit = false,
                    .prototyped = false,
                    .objective_c_class_complete = false,
                    .object_pointer = false,
                    .vector = false,
                    .static_member = false,
                    .lvalue_reference = false,
                    .rvalue_reference = false,
                    .reserved = false,
                    .inheritance = .none,
                    .introduced_virtual = false,
                    .bit_field = false,
                    .no_return = false,
                    .type_pass_by_value = false,
                    .type_pass_by_reference = false,
                    .enum_class = false,
                    .thunk = false,
                    .non_trivial = false,
                    .big_endian = false,
                    .little_endian = false,
                    .all_calls_described = false,
                };
                var buffer: [65]u8 = undefined;
                const format = library.format_int(&buffer, integer.type.bit_size, 10, false);
                const slice_ptr = format.ptr - 1;
                const slice = slice_ptr[0 .. format.len + 1];
                slice[0] = switch (integer.signedness) {
                    .signed => 's',
                    .unsigned => 'u',
                };

                const name = thread.arena.duplicate_bytes(slice) catch unreachable;
                const integer_type = builder.createBasicType(name.ptr, name.len, integer.type.bit_size, dwarf_encoding, flags);
                break :block integer_type;
            },
            .array => block: {
                const array = ty.get_payload(.array);
                const bitsize = array.type.size * 8;
                const element_type = llvm_get_debug_type(thread, builder, array.descriptor.element_type);
                const array_type = builder.createArrayType(bitsize, array.type.alignment * 8, element_type, array.descriptor.element_count);
                break :block array_type.toType();
            },
            .typed_pointer => block: {
                const typed_pointer = ty.get_payload(.typed_pointer);
                const element_type = llvm_get_debug_type(thread, builder, typed_pointer.descriptor.pointee);
                const alignment = 3;
                const pointer_width = @bitSizeOf(usize);
                // TODO:
                const pointer_type = builder.createPointerType(element_type, pointer_width, alignment, "ptr", "ptr".len);
                break :block pointer_type.toType();
            },
            .@"struct" => block: {
                const nat_struct_type = ty.get_payload(.@"struct");
                const file_struct = llvm_get_file(thread, nat_struct_type.declaration.scope.file);
                const flags = LLVM.DebugInfo.Node.Flags{
                    .visibility = .none,
                    .forward_declaration = false,
                    .apple_block = false,
                    .block_by_ref_struct = false,
                    .virtual = false,
                    .artificial = false,
                    .explicit = false,
                    .prototyped = false,
                    .objective_c_class_complete = false,
                    .object_pointer = false,
                    .vector = false,
                    .static_member = false,
                    .lvalue_reference = false,
                    .rvalue_reference = false,
                    .reserved = false,
                    .inheritance = .none,
                    .introduced_virtual = false,
                    .bit_field = false,
                    .no_return = false,
                    .type_pass_by_value = false,
                    .type_pass_by_reference = false,
                    .enum_class = false,
                    .thunk = false,
                    .non_trivial = false,
                    .big_endian = false,
                    .little_endian = false,
                    .all_calls_described = false,
                };
                const file = file_struct.file;
                const name = thread.identifiers.get(nat_struct_type.declaration.name).?;
                const line = nat_struct_type.declaration.line;

                const bitsize = nat_struct_type.type.size * 8;
                const alignment = nat_struct_type.type.alignment;
                var member_types = PinnedArray(*LLVM.DebugInfo.Type){};

                const struct_type = builder.createStructType(file.toScope(), name.ptr, name.len, file, line, bitsize, alignment, flags, null, member_types.pointer, member_types.length, null);
                ty.llvm_debug = struct_type.toType();

                for (nat_struct_type.fields) |field| {
                    const field_type = llvm_get_debug_type(thread, builder, field.type);
                    const field_name = thread.identifiers.get(field.name).?;
                    const field_bitsize = field.type.size * 8;
                    const field_alignment = field.type.alignment * 8;
                    const field_offset = field.member_offset * 8;
                    const member_type = builder.createMemberType(file.toScope(), field_name.ptr, field_name.len, file, field.line, field_bitsize, field_alignment, field_offset, flags, field_type);
                    _ = member_types.append(member_type.toType());
                }

                builder.replaceCompositeTypes(struct_type, member_types.pointer, member_types.length);
                break :block struct_type.toType();
            },
            .bitfield => block: {
                const nat_bitfield_type = ty.get_payload(.bitfield);
                const file_struct = llvm_get_file(thread, nat_bitfield_type.declaration.scope.file);
                const flags = LLVM.DebugInfo.Node.Flags{
                    .visibility = .none,
                    .forward_declaration = false,
                    .apple_block = false,
                    .block_by_ref_struct = false,
                    .virtual = false,
                    .artificial = false,
                    .explicit = false,
                    .prototyped = false,
                    .objective_c_class_complete = false,
                    .object_pointer = false,
                    .vector = false,
                    .static_member = false,
                    .lvalue_reference = false,
                    .rvalue_reference = false,
                    .reserved = false,
                    .inheritance = .none,
                    .introduced_virtual = false,
                    .bit_field = false,
                    .no_return = false,
                    .type_pass_by_value = false,
                    .type_pass_by_reference = false,
                    .enum_class = false,
                    .thunk = false,
                    .non_trivial = false,
                    .big_endian = false,
                    .little_endian = false,
                    .all_calls_described = false,
                };
                const file = file_struct.file;
                const name = thread.identifiers.get(nat_bitfield_type.declaration.name).?;
                const line = nat_bitfield_type.declaration.line;

                const bitsize = nat_bitfield_type.type.size * 8;
                const alignment = nat_bitfield_type.type.alignment;
                var member_types = PinnedArray(*LLVM.DebugInfo.Type){};

                const struct_type = builder.createStructType(file.toScope(), name.ptr, name.len, file, line, bitsize, alignment, flags, null, member_types.pointer, member_types.length, null);
                ty.llvm_debug = struct_type.toType();

                const nat_backing_type = &thread.integers[nat_bitfield_type.type.bit_size - 1];
                const backing_type = llvm_get_debug_type(thread, builder, &nat_backing_type.type);

                for (nat_bitfield_type.fields) |field| {
                    const field_name = thread.identifiers.get(field.name).?;
                    const field_bitsize = field.type.bit_size;
                    const field_offset = field.member_offset;
                    const member_flags = LLVM.DebugInfo.Node.Flags{
                        .visibility = .none,
                        .forward_declaration = false,
                        .apple_block = false,
                        .block_by_ref_struct = false,
                        .virtual = false,
                        .artificial = false,
                        .explicit = false,
                        .prototyped = false,
                        .objective_c_class_complete = false,
                        .object_pointer = false,
                        .vector = false,
                        .static_member = false,
                        .lvalue_reference = false,
                        .rvalue_reference = false,
                        .reserved = false,
                        .inheritance = .none,
                        .introduced_virtual = false,
                        .bit_field = true,
                        .no_return = false,
                        .type_pass_by_value = false,
                        .type_pass_by_reference = false,
                        .enum_class = false,
                        .thunk = false,
                        .non_trivial = false,
                        .big_endian = false,
                        .little_endian = false,
                        .all_calls_described = false,
                    };
                    const member_type = builder.createBitfieldMemberType(file.toScope(), field_name.ptr, field_name.len, file, field.line, field_bitsize, field_offset, 0, member_flags, backing_type);
                    _ = member_types.append(member_type.toType());
                }

                builder.replaceCompositeTypes(struct_type, member_types.pointer, member_types.length);
                break :block struct_type.toType();
            },
            else => |t| @panic(@tagName(t)),
        };

        ty.llvm_debug = llvm_debug_type;

        return llvm_debug_type;
    }
}

fn llvm_get_type(thread: *Thread, ty: *Type) *LLVM.Type {
    if (ty.llvm) |llvm| {
        assert(ty.sema.thread == thread.get_index());
        assert(llvm.getContext() == thread.llvm.context);
        return llvm;
    } else {
        const llvm_type: *LLVM.Type = switch (ty.sema.id) {
            .void => b: {
                const void_type = thread.llvm.context.getVoidType();
                break :b void_type;
            },
            .integer => b: {
                const integer_type = thread.llvm.context.getIntegerType(@intCast(ty.bit_size));
                break :b integer_type.toType();
            },
            .array => b: {
                const array_ty = ty.get_payload(.array);
                const element_type = llvm_get_type(thread, array_ty.descriptor.element_type);
                const array_type = LLVM.Type.Array.get(element_type, array_ty.descriptor.element_count);
                break :b array_type.toType();
            },
            .opaque_pointer, .typed_pointer => b: {
                const pointer_type = thread.llvm.context.getPointerType(address_space);
                break :b pointer_type.toType();
            },
            .function => b: {
                const nat_function_type = ty.get_payload(.function);
                const return_type = llvm_get_type(thread, nat_function_type.abi.abi_return_type);
                var argument_types = PinnedArray(*LLVM.Type){};
                _ = &argument_types;
                for (nat_function_type.abi.abi_argument_types) |argument_type| {
                    const llvm_arg_type = llvm_get_type(thread, argument_type);
                    _ = argument_types.append(llvm_arg_type);
                }
                const is_var_args = false;
                const function_type = LLVM.getFunctionType(return_type, argument_types.pointer, argument_types.length, is_var_args);
                break :b function_type.toType();
            },
            .@"struct" => b: {
                const nat_struct_type = ty.get_payload(.@"struct");
                var struct_types = PinnedArray(*LLVM.Type){};
                for (nat_struct_type.fields) |field| {
                    const field_type = llvm_get_type(thread, field.type);
                    _ = struct_types.append(field_type);
                }

                const types = struct_types.const_slice();
                const is_packed = false;
                const name = thread.identifiers.get(nat_struct_type.declaration.name).?;
                const struct_type = thread.llvm.context.createStructType(types.ptr, types.len, name.ptr, name.len, is_packed);
                break :b struct_type.toType();
            },
            .anonymous_struct => b: {
                const nat_struct_type = ty.get_payload(.anonymous_struct);
                var struct_types = PinnedArray(*LLVM.Type){};
                for (nat_struct_type.fields) |field| {
                    const field_type = llvm_get_type(thread, field.type);
                    _ = struct_types.append(field_type);
                }

                const types = struct_types.const_slice();
                const is_packed = false;
                const struct_type = thread.llvm.context.getStructType(types.ptr, types.len, is_packed);
                break :b struct_type.toType();
            },
            .bitfield => b: {
                const nat_bitfield_type = ty.get_payload(.bitfield);
                const backing_type = llvm_get_type(thread, nat_bitfield_type.backing_type);
                break :b backing_type;
            },
            else => |t| @panic(@tagName(t)),
        };

        ty.llvm = llvm_type;

        return llvm_type;
    }
}

fn llvm_get_file(thread: *Thread, file_index: u32) *LLVMFile {
    assert(thread.generate_debug_information);
    if (thread.debug_info_file_map.get_pointer(file_index)) |llvm| return llvm else {
        const builder = thread.llvm.module.createDebugInfoBuilder();
        const file = &instance.files.slice()[file_index];
        const filename = std.fs.path.basename(file.path);
        const directory = file.path[0..file.path.len - filename.len];
        const llvm_file = builder.createFile(filename.ptr, filename.len, directory.ptr, directory.len);
        const producer = "nativity";
        const is_optimized = false;
        const flags = "";
        const runtime_version = 0;
        const splitname = "";
        const DWOId = 0;
        const debug_info_kind = LLVM.DebugInfo.CompileUnit.EmissionKind.full_debug;
        const split_debug_inlining = true;
        const debug_info_for_profiling = false;
        const name_table_kind = LLVM.DebugInfo.CompileUnit.NameTableKind.default;
        const ranges_base_address = false;
        const sysroot = "";
        const sdk = "";
        const compile_unit = builder.createCompileUnit(LLVM.DebugInfo.Language.c11, llvm_file, producer, producer.len, is_optimized, flags, flags.len, runtime_version, splitname, splitname.len, debug_info_kind, DWOId, split_debug_inlining, debug_info_for_profiling, name_table_kind, ranges_base_address, sysroot, sysroot.len, sdk, sdk.len);

        thread.debug_info_file_map.put_no_clobber(file_index, .{
            .file = llvm_file,
            .compile_unit = compile_unit,
            .builder = builder,
        });

        return thread.debug_info_file_map.get_pointer(file_index).?;
    }
}

fn llvm_get_scope(thread: *Thread, scope: *Scope) *LLVM.DebugInfo.Scope {
    assert(scope.id != .file);

    if (scope.llvm) |llvm| {
        return llvm;
    } else {
        const llvm_scope = switch (scope.id) {
            .local => block: {
                const local_block: *LocalBlock = @fieldParentPtr("scope", scope);
                const file = llvm_get_file(thread, local_block.scope.file);
                const parent_scope = llvm_get_scope(thread, scope.parent.?);
                const lexical_block = file.builder.createLexicalBlock(parent_scope, file.file, scope.line, scope.column);
                break :block lexical_block.toScope();
            },
            else => |t| @panic(@tagName(t)),
        };
        scope.llvm = llvm_scope;
        return llvm_scope;
    }
}

const calling_convention_map = std.EnumArray(CallingConvention, LLVM.Value.Constant.Function.CallingConvention).init(.{
    .c = .C,
    .custom = .Fast,
});

fn llvm_emit_function_declaration(thread: *Thread, nat_function: *Function.Declaration) void {
    assert(nat_function.global_symbol.value.llvm == null);
    const function_name = thread.identifiers.get(nat_function.global_symbol.global_declaration.declaration.name) orelse unreachable;
    const nat_function_type = nat_function.get_function_type();
    const function_type = llvm_get_type(thread, &nat_function_type.type);
    const is_extern_function = nat_function.global_symbol.attributes.@"extern";
    const export_or_extern = nat_function.global_symbol.attributes.@"export" or is_extern_function; 
    const linkage: LLVM.Linkage = switch (export_or_extern) {
        true => .@"extern",
        false => .internal,
    };
    const function = thread.llvm.module.createFunction(function_type.toFunction() orelse unreachable, linkage, address_space, function_name.ptr, function_name.len);

    var parameter_attribute_sets = std.BoundedArray(*const LLVM.Attribute.Set, 512){};
    const function_attributes = llvm_emit_function_attributes(thread, nat_function_type, &parameter_attribute_sets);
    function.setAttributes(thread.llvm.context, function_attributes.function_attributes, function_attributes.return_attribute_set, function_attributes.parameter_attribute_sets.ptr, function_attributes.parameter_attribute_sets.len);

    const calling_convention = calling_convention_map.get(nat_function_type.abi.calling_convention);
    function.setCallingConvention(calling_convention);

    if (thread.generate_debug_information) {
        const file_index = nat_function.global_symbol.global_declaration.declaration.scope.file;
        const llvm_file = llvm_get_file(thread, file_index);
        // TODO: emit original arguments
        var debug_argument_types = PinnedArray(*LLVM.DebugInfo.Type){};
        for (nat_function.get_function_type().abi.original_argument_types) |argument_type| {
            const arg_type = llvm_get_debug_type(thread, llvm_file.builder, argument_type);
            _ = debug_argument_types.append(arg_type);
        }

        const subroutine_type_flags = LLVM.DebugInfo.Node.Flags{
            .visibility = .none,
            .forward_declaration = is_extern_function,
            .apple_block = false,
            .block_by_ref_struct = false,
            .virtual = false,
            .artificial = false,
            .explicit = false,
            .prototyped = false,
            .objective_c_class_complete = false,
            .object_pointer = false,
            .vector = false,
            .static_member = false,
            .lvalue_reference = false,
            .rvalue_reference = false,
            .reserved = false,
            .inheritance = .none,
            .introduced_virtual = false,
            .bit_field = false,
            .no_return = false,
            .type_pass_by_value = false,
            .type_pass_by_reference = false,
            .enum_class = false,
            .thunk = false,
            .non_trivial = false,
            .big_endian = false,
            .little_endian = false,
            .all_calls_described = false,
        };
        const subroutine_type_calling_convention = LLVM.DebugInfo.CallingConvention.none;
        const subroutine_type = llvm_file.builder.createSubroutineType(debug_argument_types.pointer, debug_argument_types.length, subroutine_type_flags, subroutine_type_calling_convention);
        const subprogram_flags = LLVM.DebugInfo.Subprogram.Flags{
            .virtuality = .none,
            .local_to_unit = !export_or_extern,
            .definition = !is_extern_function,
            .optimized = false,
            .pure = false,
            .elemental = false,
            .recursive = false,
            .main_subprogram = false,
            .deleted = false,
            .object_c_direct = false,
        };
        const subprogram_declaration = null;
        const file = llvm_file.file;
        const scope = file.toScope();
        const line = nat_function.global_symbol.global_declaration.declaration.line;
        const scope_line = line + 1;

        const subprogram = llvm_file.builder.createFunction(scope, function_name.ptr, function_name.len, function_name.ptr, function_name.len, file, line, subroutine_type, scope_line, subroutine_type_flags, subprogram_flags, subprogram_declaration);
        nat_function.global_symbol.type.llvm_debug = subroutine_type.toType();
        function.setSubprogram(subprogram);
        if (nat_function.global_symbol.id == .function_definition) {
            const function_definition = nat_function.global_symbol.get_payload(.function_definition);
            function_definition.scope.scope.llvm = subprogram.toLocalScope().toScope();
        }
    }

    nat_function.global_symbol.value.llvm = function.toValue();
}

fn create_constant_int(thread: *Thread, args: struct {
    n: u64,
    type: *Type,
    resolved: bool = true,
}) *ConstantInt {
    const constant_int = thread.constant_ints.append(.{
        .value = .{
            .sema = .{
                .thread = thread.get_index(),
                .resolved = args.resolved,
                .id = .constant_int,
            },
            },
        .n = args.n,
        .type = args.type,
    });
    return constant_int;
}

fn create_basic_block(thread: *Thread) *BasicBlock {
    const block = thread.basic_blocks.append(.{
        .value = .{
            .sema = .{
                .thread = thread.get_index(),
                .resolved = true,
                .id = .basic_block,
            },
        },
    });
    return block;
}

fn emit_gep(thread: *Thread, analyzer: *Analyzer, args: struct{
    pointer: *Value,
    index: *Value,
    type: *Type,
    aggregate_type: *Type,
    is_struct: bool,
    line: u32,
    column: u32,
    scope: *Scope,
}) *GEP{
    const gep = thread.geps.append(.{
        .instruction = new_instruction(thread, .{
            .scope = args.scope,
            .line = args.line,
            .column = args.column,
            .id = .get_element_pointer,
        }),
        .pointer = args.pointer,
        .index = args.index,
        .type = args.type,
        .aggregate_type = args.aggregate_type,
        .is_struct = args.is_struct,
    });
    analyzer.append_instruction(&gep.instruction);
    return gep;
}

fn emit_extract_value(thread: *Thread, analyzer: *Analyzer, args: struct{
    aggregate: *Value,
    index: u32,
    type: *Type,
    line: u32,
    column: u32,
    scope: *Scope,
}) *ExtractValue{
    const extract_value = thread.extract_values.append(.{
        .instruction = new_instruction(thread, .{
            .scope = args.scope,
            .line = args.line,
            .column = args.column,
            .id = .extract_value,
        }),
        .aggregate = args.aggregate,
        .index = args.index,
        .type = args.type,
    });
    analyzer.append_instruction(&extract_value.instruction);
    return extract_value;
}

fn emit_insert_value(thread: *Thread, analyzer: *Analyzer, args: struct{
    aggregate: *Value,
    value: *Value,
    index: u32,
    type: *Type,
    line: u32,
    column: u32,
    scope: *Scope,
}) *InsertValue{
    const insert_value = thread.insert_values.append(.{
        .instruction = new_instruction(thread, .{
            .scope = args.scope,
            .line = args.line,
            .column = args.column,
            .id = .insert_value,
        }),
        .value = args.value,
        .aggregate = args.aggregate,
        .index = args.index,
        .type = args.type,
    });
    analyzer.append_instruction(&insert_value.instruction);
    return insert_value;
}

fn emit_ret_void(thread: *Thread, analyzer: *Analyzer, args: RawEmitArgs) void {
    const return_expression = thread.standalone_instructions.append(new_instruction(thread, .{
        .id = .ret_void,
        .line = args.line,
        .column = args.column,
        .scope = args.scope,
    }));

    analyzer.append_instruction(return_expression);
    analyzer.current_basic_block.is_terminated = true;
}

fn emit_direct_coerce(analyzer: *Analyzer, thread: *Thread, args: struct{
    coerced_type: *Type,
    original_value: *Value,
}) *Value {
    const source_type = args.original_value.get_type();
    const local = emit_local_symbol(analyzer, thread, .{
        .type = source_type,
        .name = 0,
        .initial_value = args.original_value,
        .line = 0,
        .column = 0,
    });

    const target_type = args.coerced_type;
    const target_size = args.coerced_type.size;
    const target_alignment = args.coerced_type.alignment;
    const source_size = source_type.size;
    const source_alignment = source_type.alignment;
    const target_is_scalable_vector_type = false;
    const source_is_scalable_vector_type = false;
    if (source_size >= target_size and !source_is_scalable_vector_type and !target_is_scalable_vector_type) {
        const load = emit_load(analyzer, thread, .{
            .value = &local.instruction.value,
            .type = target_type,
            .scope = analyzer.current_scope,
            .line = 0,
            .column = 0,
        });
        return &load.instruction.value;
    } else {
        const alignment = @max(target_alignment, source_alignment);
        const temporal = emit_local_symbol(analyzer, thread, .{
            .name = 0,
            .initial_value = null,
            .type = args.coerced_type,
            .line = 0,
            .column = 0,
        });
        emit_memcpy(analyzer, thread, .{
            .destination = &temporal.instruction.value,
            .source = &local.instruction.value,
            .destination_alignment = .{
                .alignment = alignment,
            },
            .source_alignment = .{
                .alignment = source_alignment,
            },
            .size = source_size,
            .line = 0,
            .column = 0,
            .scope = analyzer.current_scope,
        });

        const load = emit_load(analyzer, thread, .{
            .value = &temporal.instruction.value,
            .type = args.coerced_type,
            .line = 0,
            .column = 0,
            .scope = analyzer.current_scope,
        });
        return &load.instruction.value;
    }
}

fn emit_return(thread: *Thread, analyzer: *Analyzer, args: struct {
    return_value: *Value,
    scope: *Scope,
    line: u32,
    column: u32,
}) void {
    const function = analyzer.current_function;
    const function_type = function.declaration.get_function_type();
    const abi_value: *Value = switch (function_type.abi.return_type_abi.kind) {
        .ignore => unreachable,
        .direct => args.return_value,
        // TODO: 
        .direct_coerce => |coerced_type| emit_direct_coerce(analyzer, thread, .{
            .original_value = args.return_value,
            .coerced_type = coerced_type,
        }),
        .direct_pair => |pair| b: {
            const pair_struct_type = get_anonymous_two_field_struct(thread, pair);
            assert(pair_struct_type == function_type.abi.abi_return_type);

            const return_value_type = args.return_value.get_type();
            if (pair_struct_type == return_value_type) {
                unreachable;
            } else {
                const local = emit_local_symbol(analyzer, thread, .{
                    .type = return_value_type,
                    .name = 0,
                    .initial_value = args.return_value,
                    .line = 0,
                    .column = 0,
                });
                const source_is_scalable_vector_type = false;
                const target_is_scalable_vector_type = false;
                if (return_value_type.size >= pair_struct_type.size and !source_is_scalable_vector_type and !target_is_scalable_vector_type) {
                    const load = emit_load(analyzer, thread, .{
                        .value = &local.instruction.value,
                        .type = pair_struct_type,
                        .line = 0,
                        .column = 0,
                        .scope = analyzer.current_scope,
                    });
                    break :b &load.instruction.value;
                } else {
                    const alignment = @max(return_value_type.alignment, pair_struct_type.alignment);
                    const temporal = emit_local_symbol(analyzer, thread, .{
                        .name = 0,
                        .initial_value = null,
                        .type = pair_struct_type,
                        .alignment = alignment,
                        .line = 0,
                        .column = 0,
                    });
                    emit_memcpy(analyzer, thread, .{
                        .destination = &temporal.instruction.value,
                        .destination_alignment = .{ .alignment = alignment },
                        .source = &local.instruction.value,
                        .source_alignment = .{ .alignment = local.alignment },
                        .size = local.type.size,
                        .line = 0,
                        .column = 0,
                        .scope = analyzer.current_scope,
                    });

                    const load = emit_load(analyzer, thread, .{
                        .value = &temporal.instruction.value,
                        .type = pair_struct_type,
                        .line = 0,
                        .column = 0,
                        .scope = analyzer.current_scope,
                    });
                    break :b &load.instruction.value;
                }
            }
        },
        .indirect => {
            const return_pointer = analyzer.return_pointer orelse unreachable;
            emit_store(analyzer, thread, .{
                .destination = &return_pointer.value,
                .source = args.return_value,
                .alignment = function_type.abi.original_return_type.alignment,
                .line = args.line,
                .column = args.column,
                .scope = args.scope,
            });
            emit_ret_void(thread, analyzer, .{
                .line = args.line,
                .column = args.column,
                .scope = args.scope,
            });
            return;
        },
        else => |t| @panic(@tagName(t)),
    };

    const return_expression = thread.returns.append(.{
        .instruction = new_instruction(thread, .{
            .id = .ret,
            .line = args.line,
            .column = args.column,
            .scope = args.scope,
        }),
        .value = abi_value,
    });
    analyzer.append_instruction(&return_expression.instruction);
    analyzer.current_basic_block.is_terminated = true;
}

pub fn analyze_local_block(thread: *Thread, analyzer: *Analyzer, parser: *Parser, file: *File) *LocalBlock {
    const src = file.source_code;
    const function = analyzer.current_function;
    const block_line = parser.get_debug_line();
    const block_column = parser.get_debug_column();
    parser.expect_character(src, brace_open);
    const local_block = thread.local_blocks.append(.{
        .scope = .{
            .id = .local,
            .parent = analyzer.current_scope,
            .line = block_line,
            .column = @intCast(block_column),
            .file = file.scope.scope.file,
        },
    });
    analyzer.current_scope = &local_block.scope;
    parser.skip_space(src);

    while (true) {
        parser.skip_space(src);

        const statement_start_ch_index = parser.i;
        const statement_start_ch = src[statement_start_ch_index];

        if (statement_start_ch == brace_close) {
            break;
        }

        const debug_line = parser.get_debug_line();
        const debug_column = parser.get_debug_column();

        switch (statement_start_ch) {
            // Local variable
            '>' => {
                parser.i += 1;

                parser.skip_space(src);

                const local_name = parser.parse_identifier(thread, src);
                if (analyzer.current_scope.get_declaration(local_name)) |lookup_result| {
                    _ = lookup_result;
                    fail_message("Existing declaration with the same name");
                }

                const has_local_attributes = src[parser.i] == '[';
                parser.i += @intFromBool(has_local_attributes);

                if (has_local_attributes) {
                    fail_message("TODO: local attributes");
                }

                parser.skip_space(src);

                const LocalResult = struct {
                    initial_value: *Value,
                    type: *Type,
                };

                const result: LocalResult = switch (src[parser.i]) {
                    ':' => block: {
                        parser.i += 1;

                        parser.skip_space(src);

                        const local_type = parser.parse_type_expression(thread, file, analyzer.current_scope);

                        parser.skip_space(src);
                        parser.expect_character(src, '=');

                        parser.skip_space(src);

                        const local_initial_value = parser.parse_expression(analyzer, thread, file, local_type, .right);

                        break :block .{
                            .initial_value = local_initial_value,
                            .type = local_type,
                        };
                    },
                    '=' => block: {
                        parser.i += 1;

                        parser.skip_space(src);

                        const local_initial_value = parser.parse_expression(analyzer, thread, file, null, .right);

                        const local_type = local_initial_value.get_type();

                        break :block .{
                            .initial_value = local_initial_value,
                            .type = local_type,
                        };
                    },
                    else => fail(),
                };

                parser.skip_space(src);

                parser.expect_character(src, ';');

                _ = emit_local_symbol(analyzer, thread, .{
                    .name = local_name,
                    .initial_value = result.initial_value,
                    .type = result.type,
                    .line = debug_line,
                    .column = debug_column,
                });
            },
            'b' => {
                const identifier = parser.parse_raw_identifier(src);
                const break_kw = "break";
                if (byte_equal(identifier, break_kw)) {
                    parser.skip_space(src);

                    parser.expect_character(src, ';');

                    if (analyzer.loops.length == 0) {
                        fail_message("break when no loop");
                    }

                    const inner_loop = analyzer.loops.const_slice()[analyzer.loops.length - 1];
                    _ = emit_jump(analyzer, thread, .{
                        .basic_block = inner_loop.break_block,
                        .line = debug_line,
                        .column = debug_column,
                        .scope = analyzer.current_scope,
                    });
                    local_block.terminated = true;
                } else {
                    parser.i = statement_start_ch_index;
                }
            },
            'c' => {
                const identifier = parser.parse_raw_identifier(src);
                const continue_kw = "continue";
                if (byte_equal(identifier, continue_kw)) {
                    parser.skip_space(src);

                    parser.expect_character(src, ';');

                    if (analyzer.loops.length == 0) {
                        fail_message("continue when no loop");
                    }

                    const inner_loop = analyzer.loops.const_slice()[analyzer.loops.length - 1];
                    _ = emit_jump(analyzer, thread, .{
                        .basic_block = inner_loop.continue_block,
                        .line = debug_line,
                        .column = debug_column,
                        .scope = analyzer.current_scope,
                    });
                    local_block.terminated = true;
                } else {
                    parser.i = statement_start_ch_index;
                }
            },
            'i' => {
                if (src[parser.i + 1] == 'f') {
                    const if_block = parser.parse_if_expression(analyzer, thread, file);
                    local_block.terminated = local_block.terminated or if_block.terminated;
                }
            },
            'l' => {
                const identifier = parser.parse_raw_identifier(src);

                const loop_text = "loop";
                if (byte_equal(identifier, loop_text)) {
                    parser.skip_space(src);

                    const loop_header_block = create_basic_block(thread);
                    const loop_body_block = create_basic_block(thread);
                    const loop_exit_block = create_basic_block(thread);
                    _ = emit_jump(analyzer, thread, .{
                        .basic_block = loop_header_block,
                        .line = debug_line,
                        .column = debug_column,
                        .scope = analyzer.current_scope,
                    });
                    analyzer.current_basic_block = loop_header_block;

                    if (src[parser.i] == '(') {
                        const condition = parser.parse_condition(analyzer, thread, file);

                        _ = emit_branch(analyzer, thread, .{
                            .condition = condition,
                            .taken = loop_body_block,
                            .not_taken = loop_exit_block,
                            .line = debug_line,
                            .column = debug_column,
                            .scope = analyzer.current_scope,
                        });
                    } else {
                        _ = emit_jump(analyzer, thread, .{
                            .basic_block = loop_body_block,
                            .line = debug_line,
                            .column = debug_column,
                            .scope = analyzer.current_scope,
                        });
                    }

                    parser.skip_space(src);

                    analyzer.current_basic_block = loop_body_block;
                    _ = analyzer.loops.append(.{
                        .continue_block = loop_header_block,
                        .break_block = loop_exit_block,
                    });

                    switch (src[parser.i]) {
                        brace_open => {
                            const loop_block = analyze_local_block(thread, analyzer, parser, file);
                            if (!loop_block.terminated) {
                                _ = emit_jump(analyzer, thread, .{
                                    .basic_block = loop_header_block,
                                    .line = debug_line,
                                    .column = debug_column,
                                    .scope = analyzer.current_scope,
                                });
                            }
                        },
                        else => unreachable,
                    }

                    analyzer.current_basic_block = loop_exit_block;
                    analyzer.loops.length -= 1;
                } else {
                    parser.i = statement_start_ch_index;
                }
            },
            'r' => {
                const identifier = parser.parse_raw_identifier(src);

                if (byte_equal(identifier, "return")) {
                    parser.skip_space(src);

                    const function_type = function.declaration.get_function_type();
                    if (!function_type.abi.original_return_type.sema.resolved) {
                        fail_message("Return type not resolved");
                    }
                    const return_value = parser.parse_expression(analyzer, thread, file, function_type.abi.original_return_type, .right);
                    parser.expect_character(src, ';');

                    if (analyzer.return_block) |return_block| {
                        const return_phi = analyzer.return_phi.?;
                        _ = return_phi.nodes.append(.{
                            .value = return_value,
                            .basic_block = analyzer.current_basic_block,
                        });
                        assert(analyzer.current_basic_block != return_block);

                        _ = emit_jump(analyzer, thread, .{
                            .basic_block = return_block,
                            .line = debug_line,
                            .column = debug_column,
                            .scope = analyzer.current_scope,
                        });
                    } else if (analyzer.exit_blocks.length > 0) {
                        const return_phi = thread.phis.append(.{
                            .instruction = new_instruction(thread, .{
                                .id = .phi,
                                .line = debug_line,
                                .column = debug_column,
                                .scope = analyzer.current_scope,
                            }),
                            .type = function_type.abi.original_return_type,
                        });
                        analyzer.return_phi = return_phi;
                        const return_block = create_basic_block(thread);
                        analyzer.return_block = return_block;
                        _ = return_phi.nodes.append(.{
                            .value = return_value,
                            .basic_block = analyzer.current_basic_block,
                        });

                        _ = emit_jump(analyzer, thread, .{
                            .basic_block = return_block,
                            .line = debug_line,
                            .column = debug_column,
                            .scope = analyzer.current_scope,
                        });
                    } else {
                        emit_return(thread, analyzer, .{
                            .return_value = return_value,
                            .line = debug_line,
                            .column = debug_column,
                            .scope = analyzer.current_scope,
                        });
                    }
                        local_block.terminated = true;
                } else {
                    parser.i = statement_start_ch_index;
                }
            },
            '#' => {
                const intrinsic = parser.parse_intrinsic(analyzer, thread, file, &thread.void);
                assert(intrinsic == null);
                parser.skip_space(src);
                parser.expect_character(src, ';');
            },
            else => {},
        }

        if (statement_start_ch_index == parser.i) {
            const left = parser.parse_single_expression(analyzer, thread, file, null, .left);
            parser.skip_space(src);

            const operation_index = parser.i;
            const operation_ch = src[operation_index];
            var is_binary_operation = false;
            switch (operation_ch) {
                '+', '-', '*', '/', '=' => {
                    if (operation_ch != '=') {
                        if (src[parser.i + 1] == '=') {
                            parser.i += 2;

                            is_binary_operation = true;
                        } else {
                            unreachable;
                        }
                    } else {
                        parser.i += 1;
                    }

                    parser.skip_space(src);

                    const expected_right_type = switch (left.sema.id) {
                        .instruction => b: {
                            const instruction = left.get_payload(.instruction);
                            switch (instruction.id) {
                                .load => {
                                    const load = instruction.get_payload(.load);
                                    switch (load.value.sema.id) {
                                        .instruction => {
                                            const load_instruction = load.value.get_payload(.instruction);
                                            switch (load_instruction.id) {
                                                .local_symbol => {
                                                    const local_symbol = load_instruction.get_payload(.local_symbol);
                                                    if (local_symbol.type.sema.id == .typed_pointer) {
                                                        const pointer_type = local_symbol.type.get_payload(.typed_pointer);
                                                        break :b pointer_type.descriptor.pointee;
                                                    } else if (local_symbol.type.sema.id == .opaque_pointer) {
                                                        unreachable;
                                                    } else {
                                                        break :b local_symbol.type;
                                                    }
                                                },
                                                else => |t| @panic(@tagName(t)),
                                            }
                                        },
                                        else => |t| @panic(@tagName(t)),
                                    }
                                },
                                .local_symbol => {
                                    const local_symbol = instruction.get_payload(.local_symbol);
                                    break :b local_symbol.type;
                                },
                                else => |t| @panic(@tagName(t)),
                            }
                        },
                        .global_symbol => b: {
                            const global_symbol = left.get_payload(.global_symbol);
                            const global_type = global_symbol.type;
                            break :b global_type;
                        },
                        else => |t| @panic(@tagName(t)),
                    };

                    const source = switch (is_binary_operation) {
                        false => parser.parse_expression(analyzer, thread, file, expected_right_type, .right),
                        true => block: {
                            const left_load = emit_load(analyzer, thread, .{
                                .value = left,
                                .type = expected_right_type,
                                .line = debug_line,
                                .column = debug_column,
                                .scope = analyzer.current_scope,
                            });

                            const right = parser.parse_expression(analyzer, thread, file, expected_right_type, .right);

                            const binary_operation_id: IntegerBinaryOperation.Id = switch (operation_ch) {
                                '+' => .add,
                                else => unreachable,
                            };
                            const binary_operation = emit_integer_binary_operation(analyzer, thread, .{
                                .id = binary_operation_id,
                                .line = debug_line,
                                .column = debug_column,
                                .scope = analyzer.current_scope,
                                .left = &left_load.instruction.value,
                                .right = right,
                                .type = expected_right_type,
                            });
                            break :block &binary_operation.instruction.value;
                        },
                    };
                    parser.skip_space(src);

                    parser.expect_character(src, ';');
                    emit_store(analyzer, thread, .{
                        .destination = left,
                        .source = source,
                        .alignment = expected_right_type.alignment,
                        .line = debug_line,
                        .column = debug_column,
                        .scope = analyzer.current_scope,
                    });
                },
                ';' => {
                    switch (left.sema.id) {
                        .instruction => {
                            const instruction = left.get_payload(.instruction);
                            switch (instruction.id) {
                                .call => parser.i += 1,
                                else => |t| @panic(@tagName(t)),
                            }
                        },
                        else => |t| @panic(@tagName(t)),
                    }
                },
                else => @panic((src.ptr + parser.i)[0..1]),
            }
        }
    }

    analyzer.current_scope = analyzer.current_scope.parent.?;

    parser.expect_character(src, brace_close);

    return local_block;
}

const Aarch64 = struct{
};

const SystemV = struct{
    const RegisterCount = struct{
        gp_registers: u32,
        sse_registers: u32,
    };
    const Class = enum {
        no_class,
        memory,
        integer,
        sse,
        sseup,

        fn merge(accumulator: Class, field: Class) Class {
            assert(accumulator != .memory);
            if (accumulator == field) {
                return accumulator;
            } else {
                var a = accumulator;
                var f = field;
                if (@intFromEnum(accumulator) > @intFromEnum(field)) {
                    a = field;
                    f = accumulator;
                }

                return switch (a) {
                    .no_class => f,
                    .memory => .memory,
                    .integer => .integer,
                    .sse, .sseup => .sse,
                };
            }
        }
    };

    fn classify(ty: *Type, base_offset: u64) [2]Class {
        var result: [2]Class = undefined;
        const is_memory = base_offset >= 8;
        const current_index = @intFromBool(is_memory);
        const not_current_index = @intFromBool(!is_memory);
        assert(current_index != not_current_index);
        result[current_index] = .memory;
        result[not_current_index] = .no_class;

        switch (ty.sema.id) {
            .void, .noreturn => result[current_index] = .no_class,
            .bitfield => result[current_index] = .integer,
            .integer => {
                const integer_index = ty.get_integer_index();
                switch (integer_index) {
                    8 - 1, 16 - 1, 32 - 1, 64 - 1,
                    64 + 8 - 1, 64 + 16 - 1, 64 + 32 - 1, 64 + 64 - 1,
                    => result[current_index] = .integer,
                    else => unreachable,
                }
            },
            .typed_pointer => result[current_index] = .integer,
            .@"struct" => {
                if (ty.size <= 64) {
                    const has_variable_array = false;
                    if (!has_variable_array) {
                        const struct_type = ty.get_payload(.@"struct");
                        result[current_index] = .no_class;
                        const is_union = false;
                        var member_offset: u32 = 0;
                        for (struct_type.fields) |field| {
                            const offset = base_offset + member_offset;
                            const member_size = field.type.size;
                            const member_alignment = field.type.alignment;
                            member_offset = @intCast(library.align_forward(member_offset + member_size, ty.alignment));
                            const native_vector_size = 16;
                            if (ty.size > 16 and ((!is_union and ty.size != member_size) or ty.size > native_vector_size)) {
                                result[0] = .memory;
                                const r = classify_post_merge(ty.size, result);
                                return r;
                            }

                            if (offset % member_alignment != 0) {
                                result[0] = .memory;
                                const r = classify_post_merge(ty.size, result);
                                return r;
                            }

                            const member_classes = classify(field.type, offset);
                            for (&result, member_classes) |*r, m| {
                                const merge_result = r.merge(m);
                                r.* = merge_result;
                            }

                            if (result[0] == .memory or result[1] == .memory) break;
                        }

                        const final = classify_post_merge(ty.size, result);
                        result = final;
                    }
                }
            },
            .array => {
                if (ty.size <= 64) {
                    if (base_offset % ty.alignment == 0) {
                        const array_type = ty.get_payload(.array);
                        result[current_index] = .no_class;

                        const vector_size = 16;
                        if (ty.size > 16 and (ty.size != array_type.descriptor.element_type.size or ty.size > vector_size)) {
                            unreachable;
                        } else {
                            var offset = base_offset;

                            for (0..array_type.descriptor.element_count) |_| {
                                const element_classes = classify(array_type.descriptor.element_type, offset);
                                offset += array_type.descriptor.element_type.size;
                                const merge_result = [2]Class{ result[0].merge(element_classes[0]), result[1].merge(element_classes[1]) };
                                result = merge_result;
                                if (result[0] == .memory or result[1] == .memory) {
                                    break;
                                }
                            }

                            const final_result = classify_post_merge(ty.size, result);
                            assert(final_result[1] != .sseup or final_result[0] != .sse);
                            result = final_result;
                        }
                    }
                }
            },
            else => |t| @panic(@tagName(t)),
        }

        return result;
    }

    fn classify_post_merge(size: u64, classes: [2]Class) [2]Class{
        if (classes[1] == .memory) {
            return .{ .memory, .memory };
        } else if (size > 16 and (classes[0] != .sse or classes[1] != .sseup)) {
            return .{ .memory, classes[1] };
        } else if (classes[1] == .sseup and classes[0] != .sse and classes[0] != .sseup) {
            return .{ classes[0], .sse };
        } else {
            return classes;
        }
    }

    fn get_int_type_at_offset(ty: *Type, offset: u32, source_type: *Type, source_offset: u32) *Type {
        switch (ty.sema.id) {
            .bitfield => {
                const bitfield = ty.get_payload(.bitfield);
                return get_int_type_at_offset(bitfield.backing_type, offset, if (source_type == ty) bitfield.backing_type else source_type, source_offset);
            },
            .integer => {
                const integer_index = ty.get_integer_index();
                switch (integer_index) {
                    64 - 1, 64 + 64 - 1 => return ty,
                    8 - 1, 16 - 1, 32 - 1, 64 + 8 - 1, 64 + 16 - 1, 64 + 32 - 1 => {
                        if (offset != 0) unreachable;
                        const start = source_offset + ty.size;
                        const end = source_offset + 8;
                        if (contains_no_user_data(source_type, start, end)) {
                            return ty;
                        }
                    },
                    else => unreachable,
                }
            },
            .typed_pointer => return if (offset == 0) ty else unreachable,
            .@"struct" => {
                if (get_member_at_offset(ty, offset)) |field| {
                    return get_int_type_at_offset(field.type, @intCast(offset - field.member_offset), source_type, source_offset);
                }
                unreachable;
            },
            .array => {
                const array_type = ty.get_payload(.array);
                const element_type = array_type.descriptor.element_type;
                const element_size = element_type.size;
                const element_offset = (offset / element_size) * element_size;
                return get_int_type_at_offset(element_type, @intCast(offset - element_offset), source_type, source_offset);
            },
            else => |t| @panic(@tagName(t)),
        }


        if (source_type.size - source_offset > 8) {
            return &instance.threads[ty.sema.thread].integers[63].type;
        } else {
            const byte_count =  source_type.size - source_offset;
            const bit_count = byte_count * 8;
            return &instance.threads[ty.sema.thread].integers[bit_count - 1].type;
        }

        unreachable;
    }

    fn get_member_at_offset(ty: *Type, offset: u32) ?*Type.AggregateField{
        if (ty.size <= offset) {
            return null;
        }

        var offset_it: u32 = 0;
        var last_match: ?*Type.AggregateField = null;

        const struct_type = ty.get_payload(.@"struct");
        for (struct_type.fields) |field| {
            if (offset_it > offset) {
                break;
            }

            last_match = field;
            offset_it = @intCast(library.align_forward(offset_it + field.type.size, ty.alignment));
        }

        assert(last_match != null);
        return last_match;
    }

    fn contains_no_user_data(ty: *Type, start: u64, end: u64) bool {
        if (ty.size <= start) {
            return true;
        }

        switch (ty.sema.id) {
            .@"struct" => {
                const struct_type = ty.get_payload(.@"struct");
                var offset: u64 = 0;

                for (struct_type.fields) |field| {
                    if (offset >= end) break;
                    const field_start = if (offset < start) start - offset else 0;
                    if (!contains_no_user_data(field.type, field_start, end - offset)) return false;
                    offset += field.type.size;
                }

                return true;
            },
            .array => {
                const array_type = ty.get_payload(.array);
                for (0..array_type.descriptor.element_count) |i| {
                    const offset = i * array_type.descriptor.element_type.size;
                    if (offset >= end) break;
                    const element_start = if (offset < start) start - offset else 0;
                    if (!contains_no_user_data(array_type.descriptor.element_type, element_start, end - offset)) return false;
                }

                return true;
            },
            .anonymous_struct => unreachable,
            else => return false,
        }
    }

    fn get_argument_pair(types: [2]*Type) Function.Abi.Information{
        const low_size = types[0].size;
        const high_alignment = types[1].alignment;
        const high_start = library.align_forward(low_size, high_alignment);
        assert(high_start == 8);
        return .{
            .kind = .{
                .direct_pair = types,
            },
        };
    }

    fn indirect_argument(ty: *Type, free_integer_registers: u32) Function.Abi.Information{
        const is_illegal_vector = false;
        if (!ty.is_aggregate() and !is_illegal_vector) {
            if (ty.sema.id == .integer and ty.bit_size < 32) {
                unreachable;
            } else {
                return .{
                    .kind = .direct,
                };
            }
        } else {
            if (free_integer_registers == 0) {
                if (ty.alignment <= 8 and ty.size <= 8) {
                    unreachable;
                }
            }

            if (ty.alignment < 8) {
                return .{
                    .kind = .{
                        .indirect = .{
                            .type = ty,
                            .alignment = 8,
                        },
                    },
                    .attributes = .{
                        .realign = true,
                        .by_value = true,
                    },
                };
            } else {
                return .{
                    .kind = .{
                        .indirect = .{
                            .type = ty,
                            .alignment = ty.alignment,
                        },
                    },
                    .attributes = .{
                        .by_value = true,
                    },
                };
            }
        }
        unreachable;
    }

    fn indirect_return(ty: *Type) Function.Abi.Information{
        if (ty.is_aggregate()) {
            return .{
                .kind = .{
                    .indirect = .{
                        .type = ty,
                        .alignment = ty.alignment,
                    },
                },
            };
        } else {
            unreachable;
        }
    }
};

fn get_declaration_value(analyzer: *Analyzer, thread: *Thread, declaration: *Declaration, maybe_type: ?*Type, side: Side) *Value {
    var declaration_type: *Type = undefined;
    const declaration_value = switch (declaration.id) {
        .local => block: {
            const local_declaration = declaration.get_payload(.local);
            const local_symbol = local_declaration.to_symbol();
            declaration_type = local_symbol.type;
            break :block &local_symbol.instruction.value;
        },
        .argument => block: {
            const argument_declaration = declaration.get_payload(.argument);
            const argument_symbol = argument_declaration.to_symbol();
            declaration_type = argument_symbol.type;
            break :block &argument_symbol.instruction.value;
        },
        .global => block: {
            const global_declaration = declaration.get_payload(.global);
            const global_symbol = global_declaration.to_symbol();
            const global_type = global_symbol.get_type();
            declaration_type = global_type;
            break :block &global_symbol.value;
        },
    };
    
    if (maybe_type) |ty| {
        switch (typecheck(ty, declaration_type)) {
            .success => {},
        }
    }

    return switch (side) {
        .left => declaration_value,
        .right => block: {
            const load = emit_load(analyzer, thread, .{
                .value = declaration_value,
                .type = declaration_type,
            });
            break :block &load.instruction.value;
        },
    };
}

pub fn analyze_file(thread: *Thread, file_index: u32) void {
    const file = instance.files.get(@enumFromInt(file_index));
    const src = file.source_code;

    if (src.len > std.math.maxInt(u32)) {
        fail_message("File too big");
    }

    file.functions.start = @intCast(thread.functions.length);
    
    var parser = Parser{};

    while (true) {
        parser.skip_space(src);

        if (parser.i >= src.len) {
            break;
        }

        const declaration_start_i = parser.i;
        const declaration_start_ch = src[declaration_start_i];
        const declaration_line = parser.get_debug_line();
        const declaration_column = parser.get_debug_column();

        var top_level_declaration_name: []const u8 = "anonymous";
        const top_level_declaration_start = get_instant();

        switch (declaration_start_ch) {
            '>' => {
                parser.i += 1;
                parser.skip_space(src);
                const global_name = parser.parse_identifier(thread, src);

                if (global_name == 0) {
                    fail_message("discard identifier '_' cannot be used as a global variable name");
                }

                top_level_declaration_name = thread.identifiers.get(global_name).?;

                if (file.scope.scope.get_global_declaration(global_name)) |existing_global| {
                    _ = existing_global; // autofix
                    fail();
                }

                parser.skip_space(src);

                parser.expect_character(src, ':');

                parser.skip_space(src);

                const global_type = parser.parse_type_expression(thread, file, &file.scope.scope);

                parser.skip_space(src);

                parser.expect_character(src, '=');

                parser.skip_space(src);

                const global_initial_value = parser.parse_constant_expression(thread, file, global_type);

                parser.expect_character(src, ';');

                const global_variable = thread.global_variables.append(.{
                    .global_symbol = .{
                        .global_declaration = .{
                            .declaration = .{
                                .id = .global,
                                .name = global_name,
                                .line = declaration_line,
                                .column = declaration_column,
                                .scope = &file.scope.scope,
                            },
                            .id = .global_symbol,
                        },
                        .value = .{
                            .sema = .{
                                .thread = thread.get_index(),
                                .resolved = global_type.sema.resolved and global_initial_value.sema.resolved,
                                .id = .global_symbol,
                            },
                        },
                        .alignment = global_type.alignment,
                        .id = .global_variable,
                        .type = global_type,
                        .pointer_type = get_typed_pointer(thread, .{
                            .pointee = global_type,
                        }),
                    },
                    .initial_value = global_initial_value,
                });

                file.scope.scope.declarations.put_no_clobber(global_name, &global_variable.global_symbol.global_declaration.declaration);
            },
            'b' => {
                const identifier = parser.parse_raw_identifier(src);
                if (byte_equal(identifier, "bitfield")) {
                    parser.expect_character(src, '(');
                    const backing_type = parser.parse_type_expression(thread, file, &file.scope.scope);
                    parser.expect_character(src, ')');

                    switch (backing_type.sema.id) {
                        .integer => {
                            if (backing_type.bit_size > 64) {
                                fail();
                            }

                            if (backing_type.bit_size % 8 != 0) {
                                fail();
                            }

                            parser.skip_space(src);

                            const bitfield_name = parser.parse_identifier(thread, src);
                            top_level_declaration_name = thread.identifiers.get(bitfield_name).?;

                            const bitfield_type = thread.bitfields.append(.{
                                .type = .{
                                    .sema = .{
                                        .id = .bitfield,
                                        .thread = thread.get_index(),
                                        .resolved = true,
                                    },
                                    .size = backing_type.size,
                                    .alignment = backing_type.alignment,
                                    .bit_size = backing_type.bit_size,
                                },
                                .declaration = .{
                                    .name = bitfield_name,
                                    .id = .bitfield,
                                    .line = declaration_line,
                                    .column = declaration_column,
                                    .scope = &file.scope.scope,
                                },
                                .fields = &.{},
                                .backing_type = backing_type,
                            });
                            file.scope.scope.declarations.put_no_clobber(bitfield_name, &bitfield_type.declaration);

                            parser.skip_space(src);

                            parser.expect_character(src, brace_open);

                            var fields = PinnedArray(*Type.AggregateField){};
                            var total_bit_count: u64 = 0;
                            while (parser.parse_field(thread, file)) |field_data| {
                                const field_bit_offset = total_bit_count;
                                const field_bit_count = field_data.type.bit_size;
                                if (field_bit_count == 0) {
                                    fail();
                                }
                                total_bit_count += field_bit_count;
                                const field = thread.fields.append(.{
                                    .type = field_data.type,
                                    .parent = &bitfield_type.type,
                                    .name = field_data.name,
                                    .index = fields.length,
                                    .line = field_data.line,
                                    .column = field_data.column,
                                    .member_offset = field_bit_offset,
                                });
                                _ = fields.append(field);
                            }

                            parser.i += 1;

                            if (total_bit_count != backing_type.bit_size) {
                                fail();
                            }

                            bitfield_type.fields = fields.const_slice();
                        },
                        else => |t| @panic(@tagName(t)),
                    }
                } else {
                    fail();
                }
            },
            'f' => {
                if (src[parser.i + 1] == 'n') {
                    parser.i += 2;
                    parser.skip_space(src);

                    // This variable lives in the stack as mere data collector,
                    // so it will be consumed by other data structure later when
                    // it is certain if this declaration is an external function or
                    // a function definition
                    var function_declaration_data = Function.Declaration{
                        .global_symbol = .{
                            .global_declaration = .{
                                .declaration = .{
                                    .name = std.math.maxInt(u32),
                                    .id = .global,
                                    .line = declaration_line,
                                    .column = declaration_column,
                                    .scope = &file.scope.scope,
                                },
                                .id = .global_symbol,
                            },
                            .alignment = 1,
                            .value = .{
                                .sema = .{
                                    .thread = thread.get_index(),
                                    .resolved = true, // TODO: is this correct?
                                    .id = .global_symbol,
                                },
                                },
                            .id = .function_definition,
                            .type = undefined,
                            .pointer_type = undefined,
                        },
                    };

                    const has_function_attributes = src[parser.i] == '[';
                    parser.i += @intFromBool(has_function_attributes);

                    var calling_convention = CallingConvention.custom;

                    if (has_function_attributes) {
                        var attribute_mask = Function.Attribute.Mask.initEmpty();

                        while (true) {
                            parser.skip_space(src);

                            if (src[parser.i] == ']') break;

                            const attribute_identifier = parser.parse_raw_identifier(src);
                            b: inline for (@typeInfo(Function.Attribute).Enum.fields) |fa_field| {
                                if (byte_equal(fa_field.name, attribute_identifier)) {
                                    const function_attribute = @field(Function.Attribute, fa_field.name);
                                    if (attribute_mask.contains(function_attribute)) {
                                        fail();
                                    }

                                    attribute_mask.setPresent(function_attribute, true);

                                    switch (function_attribute) {
                                        .cc => {
                                            parser.skip_space(src);

                                            parser.expect_character(src, '(');

                                            parser.skip_space(src);

                                            parser.expect_character(src, '.');

                                            const cc_identifier = parser.parse_raw_identifier(src);

                                            parser.skip_space(src);

                                            parser.expect_character(src, ')');

                                            inline for (@typeInfo(CallingConvention).Enum.fields) |cc_field| {
                                                if (byte_equal(cc_field.name, cc_identifier)) {
                                                    calling_convention = @field(CallingConvention, cc_field.name);
                                                    break :b;
                                                }
                                            } else {
                                                fail();
                                            }
                                        },
                                    }
                                }
                            } else {
                                fail();
                            }

                            parser.skip_space(src);

                            const after_ch = src[parser.i];
                            switch (after_ch) {
                                ']' => {},
                                else => unreachable,
                            }
                        }

                        parser.i += 1;

                        parser.skip_space(src);
                    }

                    const function_name = parser.parse_identifier(thread, src);
                    function_declaration_data.global_symbol.global_declaration.declaration.name = function_name;
                    top_level_declaration_name = thread.identifiers.get(function_name).?;

                    parser.skip_space(src);

                    const has_global_attributes = src[parser.i] == '[';
                    parser.i += @intFromBool(has_global_attributes);

                    if (has_global_attributes) {
                        var attribute_mask = GlobalSymbol.Attribute.Mask.initEmpty();

                        while (true) {
                            parser.skip_space(src);

                            if (src[parser.i] == ']') break;

                            const attribute_identifier = parser.parse_raw_identifier(src);
                            inline for (@typeInfo(GlobalSymbol.Attribute).Enum.fields) |fa_field| {
                                if (byte_equal(fa_field.name, attribute_identifier)) {
                                    const global_attribute = @field(GlobalSymbol.Attribute, fa_field.name);
                                    if (attribute_mask.contains(global_attribute)) {
                                        fail();
                                    }

                                    attribute_mask.setPresent(global_attribute, true);

                                    switch (global_attribute) {
                                        .@"export" => {
                                            function_declaration_data.global_symbol.attributes.@"export" = true;
                                        },
                                        .@"extern" => {
                                            function_declaration_data.global_symbol.attributes.@"extern" = true;
                                        },
                                    }

                                    const after_ch =src[parser.i];
                                    switch (after_ch) {
                                        ']' => {},
                                        else => unreachable,
                                    }

                                    break;
                                }
                            } else {
                                fail();
                            }

                            parser.skip_space(src);

                            const after_ch = src[parser.i];
                            switch (after_ch) {
                                ']' => {},
                                else => unreachable,
                            }
                        }

                        parser.i += 1;

                        parser.skip_space(src);
                    }

                    if (function_declaration_data.global_symbol.attributes.@"export" and function_declaration_data.global_symbol.attributes.@"extern") {
                        fail();
                    }

                    const split_modules = true;
                    if (split_modules and !function_declaration_data.global_symbol.attributes.@"extern") {
                        function_declaration_data.global_symbol.attributes.@"export" = true;
                    }

                    parser.expect_character(src, '(');

                    const ArgumentData = struct{
                        type: *Type,
                        name: u32,
                        line: u32,
                        column: u32,
                    };

                    var original_arguments = PinnedArray(ArgumentData){};
                    var original_argument_types = PinnedArray(*Type){};
                    var fully_resolved = true;

                    while (true) {
                        parser.skip_space(src);

                        if (src[parser.i] == ')') break;

                        const argument_line = parser.get_debug_line();
                        const argument_column = parser.get_debug_column();

                        const argument_name = parser.parse_identifier(thread, src);

                        parser.skip_space(src);
                        
                        parser.expect_character(src, ':');

                        parser.skip_space(src);
                        
                        const argument_type = parser.parse_type_expression(thread, file, &file.scope.scope);
                        fully_resolved = fully_resolved and argument_type.sema.resolved;
                        _ = original_arguments.append(.{
                            .type = argument_type,
                            .name = argument_name,
                            .line = argument_line,
                            .column = argument_column,
                        });
                        _ = original_argument_types.append(argument_type);

                        parser.skip_space(src);

                        switch (src[parser.i]) {
                            ',' => parser.i += 1,
                            ')' => {},
                            else => fail(),
                        }
                    }

                    parser.expect_character(src, ')');

                    parser.skip_space(src);

                    const original_return_type = parser.parse_type_expression(thread, file, &file.scope.scope);
                    fully_resolved = fully_resolved and original_return_type.sema.resolved;

                    const function_abi: Function.Abi = if (fully_resolved) switch (calling_convention) {
                        .c => abi: {
                            var argument_type_abis = PinnedArray(Function.Abi.Information){};
                            const return_type_abi: Function.Abi.Information = switch (builtin.cpu.arch) {
                                .x86_64 => block: {
                                    switch (builtin.os.tag) {
                                        .linux => {
                                            const return_type_abi: Function.Abi.Information = rta: {
                                                const type_classes = SystemV.classify(original_return_type, 0);
                                                assert(type_classes[1] != .memory or type_classes[0] == .memory);
                                                assert(type_classes[1] != .sseup or type_classes[0] == .sse);

                                                const result_type = switch (type_classes[0]) {
                                                    .no_class => switch (type_classes[1]) {
                                                        .no_class => break :rta .{
                                                            .kind = .ignore,
                                                        },
                                                        else => |t| @panic(@tagName(t)),
                                                    },
                                                    .integer => b: {
                                                        const result_type = SystemV.get_int_type_at_offset(original_return_type, 0, original_return_type, 0);
                                                        if (type_classes[1] == .no_class and original_return_type.bit_size < 32) {
                                                            const signed = switch (original_return_type.sema.id) {
                                                                .integer => @intFromEnum(original_return_type.get_payload(.integer).signedness) != 0,
                                                                .bitfield => false,
                                                                else => |t| @panic(@tagName(t)),
                                                            };

                                                            break :rta .{
                                                                .kind = .{
                                                                    .direct_coerce = original_return_type,
                                                                },
                                                                .attributes = .{
                                                                    .sign_extend = signed,
                                                                    .zero_extend = !signed,
                                                                },
                                                            };
                                                        }
                                                        break :b result_type;
                                                    },
                                                    .memory => break :rta SystemV.indirect_return(original_return_type),
                                                    else => |t| @panic(@tagName(t)),
                                                };
                                                const high_part: ?*Type = switch (type_classes[1]) {
                                                    .no_class, .memory => null,
                                                    .integer => b: {
                                                        assert(type_classes[0] != .no_class);
                                                        const high_part = SystemV.get_int_type_at_offset(original_return_type, 8, original_return_type, 8);
                                                        break :b high_part;
                                                    },
                                                    else => |t| @panic(@tagName(t)),
                                                };

                                                if (high_part) |hp| {
                                                    break :rta SystemV.get_argument_pair(.{ result_type, hp });
                                                } else {
                                                    // TODO
                                                    const is_type = true;
                                                    if (is_type) {
                                                        if (result_type == original_return_type) {
                                                            break :rta Function.Abi.Information{
                                                                .kind = .direct,
                                                            };
                                                        } else {
                                                            break :rta Function.Abi.Information{
                                                                .kind = .{
                                                                    .direct_coerce = result_type,
                                                                },
                                                            };
                                                        }
                                                    } else {
                                                        unreachable;
                                                    }
                                                }
                                            };
                                            var available_registers = SystemV.RegisterCount{
                                                .gp_registers = 6,
                                                .sse_registers = 8,
                                            };

                                            if (return_type_abi.kind == .indirect) {
                                                available_registers.gp_registers -= 1;
                                            }

                                            const return_by_reference = false;
                                            if (return_by_reference) {
                                                unreachable;
                                            }

                                            for (original_argument_types.const_slice()) |original_argument_type| {
                                                var needed_registers = SystemV.RegisterCount{
                                                    .gp_registers = 0,
                                                    .sse_registers = 0,
                                                };
                                                const argument_type_abi_classification: Function.Abi.Information = ata: {
                                                    const type_classes = SystemV.classify(original_argument_type, 0);
                                                    assert(type_classes[1] != .memory or type_classes[0] == .memory);
                                                    assert(type_classes[1] != .sseup or type_classes[0] == .sse);

                                                    _ = &needed_registers; // autofix

                                                    const result_type = switch (type_classes[0]) {
                                                        .integer => b: {
                                                            needed_registers.gp_registers += 1;
                                                            const result_type = SystemV.get_int_type_at_offset(original_argument_type, 0, original_argument_type, 0);
                                                            if (type_classes[1] == .no_class and original_argument_type.bit_size < 32) {
                                                                const signed = switch (original_argument_type.sema.id) {
                                                                    .integer => @intFromEnum(original_argument_type.get_payload(.integer).signedness) != 0,
                                                                    .bitfield => false,
                                                                    else => |t| @panic(@tagName(t)),
                                                                };

                                                                break :ata .{
                                                                    .kind = .{
                                                                        .direct_coerce = original_argument_type,
                                                                    },
                                                                    .attributes = .{
                                                                        .sign_extend = signed,
                                                                        .zero_extend = !signed,
                                                                    },
                                                                };
                                                            }
                                                            break :b result_type;
                                                        },
                                                        .memory => break :ata SystemV.indirect_argument(original_argument_type, available_registers.gp_registers),
                                                        else => |t| @panic(@tagName(t)),
                                                    };
                                                    const high_part: ?*Type = switch (type_classes[1]) {
                                                        .no_class, .memory => null,
                                                        .integer => b: {
                                                            assert(type_classes[0] != .no_class);
                                                            needed_registers.gp_registers += 1;
                                                            const high_part = SystemV.get_int_type_at_offset(original_argument_type, 8, original_argument_type, 8);
                                                            break :b high_part;
                                                        },
                                                        else => |t| @panic(@tagName(t)),
                                                    };

                                                    if (high_part) |hp| {
                                                        break :ata SystemV.get_argument_pair(.{ result_type, hp });
                                                    } else {
                                                        // TODO
                                                        const is_type = true;
                                                        if (is_type) {
                                                            if (result_type == original_argument_type) {
                                                                break :ata Function.Abi.Information{
                                                                    .kind = .direct,
                                                                };
                                                            } else if (result_type.sema.id == .integer and original_argument_type.sema.id == .integer and original_argument_type.size == result_type.size) {
                                                                unreachable;
                                                            } else {
                                                                break :ata Function.Abi.Information{
                                                                    .kind = .{
                                                                        .direct_coerce = result_type,
                                                                    },
                                                                };
                                                            }
                                                        }
                                                        unreachable;
                                                    }
                                                };
                                                const argument_type_abi = if (available_registers.sse_registers < needed_registers.sse_registers or available_registers.gp_registers < needed_registers.gp_registers) b: {
                                                    break :b SystemV.indirect_argument(original_argument_type, available_registers.gp_registers);
                                                } else b: {
                                                    available_registers.gp_registers -= needed_registers.gp_registers;
                                                    available_registers.sse_registers -= needed_registers.sse_registers;
                                                    break :b argument_type_abi_classification;
                                                };

                                                _ = argument_type_abis.append(argument_type_abi);
                                            }

                                            break :block return_type_abi;
                                        },
                                        else => |t| @panic(@tagName(t)),
                                    }
                                },
                                .aarch64 => block: {
                                    const return_type_abi: Function.Abi.Information = blk: {
                                        if (original_return_type.returns_nothing()) {
                                            break :blk .{
                                                .kind = .ignore,
                                            };
                                        }

                                        const size = original_return_type.size;
                                        const alignment = original_return_type.alignment;

                                        const is_vector = false;
                                        if (is_vector and size > 16) {
                                            unreachable;
                                        }

                                        if (!original_return_type.is_aggregate()) {
                                            const extend = builtin.os.tag.isDarwin() and switch (original_return_type.sema.id) {
                                                .integer => original_return_type.bit_size < 32,
                                                .bitfield => original_return_type.bit_size < 32,
                                                else => |t| @panic(@tagName(t)),
                                            };

                                            if (extend) {
                                                const signed = switch (original_return_type.sema.id) {
                                                    else => |t| @panic(@tagName(t)),
                                                    .bitfield => @intFromEnum(original_return_type.get_payload(.bitfield).backing_type.get_payload(.integer).signedness) != 0,
                                                    .integer => @intFromEnum(original_return_type.get_payload(.integer).signedness) != 0,
                                                    .typed_pointer => false,
                                                };

                                                break :blk Function.Abi.Information{
                                                    .kind = .direct,
                                                    .attributes = .{
                                                        .zero_extend = !signed,
                                                        .sign_extend = signed,
                                                    },
                                                };
                                            } else break :blk .{
                                                .kind = .direct,
                                            };
                                        } else {
                                            assert(size > 0);
                                            const is_variadic = false;
                                            const is_aarch64_32 = false;
                                            const maybe_homogeneous_aggregate = original_return_type.get_homogeneous_aggregate();
                                            if (maybe_homogeneous_aggregate != null and !(is_aarch64_32 and is_variadic)) {
                                                unreachable;
                                            } else if (size <= 16) {
                                                if (size <= 8 and builtin.cpu.arch.endian() == .little) {
                                                    break :blk .{
                                                        .kind = .{
                                                            .direct_coerce = &thread.integers[size * 8 - 1].type,
                                                        },
                                                    };
                                                } else {
                                                    const aligned_size = library.align_forward(size, 8);
                                                    if (alignment < 16 and aligned_size == 16) {
                                                        break :blk .{
                                                            .kind = .{
                                                                .direct_coerce = get_array_type(thread, .{
                                                                    .element_type = &thread.integers[63].type,
                                                                    .element_count = 2,
                                                                }),
                                                            },
                                                        };
                                                    } else {
                                                        unreachable;
                                                    }
                                                    unreachable;
                                                }
                                            } else {
                                                assert(alignment > 0);
                                                break :blk .{
                                                    .kind = .{
                                                        .indirect = .{
                                                            .type = original_return_type,
                                                            .alignment = alignment,
                                                        },
                                                    },
                                                    .attributes = .{
                                                        .by_value = true,
                                                    },
                                                };
                                            }
                                        }
                                    };

                                    for (original_argument_types.const_slice()) |argument_type| {
                                        const argument_type_abi: Function.Abi.Information = blk: {
                                            if (argument_type.returns_nothing()) {
                                                break :blk .{
                                                    .kind = .ignore,
                                                };
                                            }

                                            // TODO:
                                            const is_illegal_vector = false;
                                            if (is_illegal_vector) {
                                                unreachable;
                                            }

                                            if (!argument_type.is_aggregate()) {
                                                const extend = builtin.os.tag.isDarwin() and switch (argument_type.sema.id) {
                                                    else => |t| @panic(@tagName(t)),
                                                    .bitfield => argument_type.bit_size < 32,
                                                    .integer => argument_type.bit_size < 32,
                                                    .typed_pointer => false,
                                                };

                                                if (extend) {
                                                    const signed = switch (argument_type.sema.id) {
                                                        else => |t| @panic(@tagName(t)),
                                                        .bitfield => @intFromEnum(argument_type.get_payload(.bitfield).backing_type.get_payload(.integer).signedness) != 0,
                                                        .integer => @intFromEnum(argument_type.get_payload(.integer).signedness) != 0,
                                                        .typed_pointer => false,
                                                    };

                                                    break :blk Function.Abi.Information{
                                                        .kind = .direct,
                                                        .attributes = .{
                                                            .zero_extend = !signed,
                                                            .sign_extend = signed,
                                                        },
                                                    };
                                                } else break :blk .{
                                                    .kind = .direct,
                                                };
                                            } else {
                                                assert(argument_type.size > 0);

                                                if (argument_type.get_homogeneous_aggregate()) |homogeneous_aggregate| {
                                                    _ = homogeneous_aggregate; // autofix
                                                    unreachable;
                                                } else if (argument_type.size <= 16) {
                                                    const base_alignment = argument_type.alignment;
                                                    const is_aapcs = false;
                                                    const alignment = switch (is_aapcs) {
                                                        true => if (base_alignment < 16) 8 else 16,
                                                        false => @max(base_alignment, 8),
                                                    };
                                                    assert(alignment == 8 or alignment == 16);
                                                    const aligned_size = library.align_forward(argument_type.size, alignment);
                                                    if (alignment == 16) {
                                                        unreachable;
                                                    } else {
                                                        const element_count = @divExact(aligned_size, alignment);
                                                        if (element_count > 1) {
                                                            break :blk .{
                                                                .kind = .{
                                                                    .direct_coerce = get_array_type(thread, .{
                                                                        .element_type = &thread.integers[63].type,
                                                                        .element_count = element_count,
                                                                    }),
                                                                }
                                                            };
                                                        } else break :blk .{
                                                            .kind = .{
                                                                .direct_coerce = &thread.integers[63].type,
                                                            },
                                                        };
                                                    }
                                                } else {
                                                    const alignment = argument_type.alignment;
                                                    assert(alignment > 0);

                                                    break :blk .{
                                                        .kind = .{
                                                            .indirect = .{
                                                                .type = argument_type,
                                                                .alignment = alignment,
                                                            },
                                                        },
                                                    };
                                                }
                                            }
                                        };
                                        _ = argument_type_abis.append(argument_type_abi);
                                    }

                                    break :block return_type_abi;
                                },
                                else => fail_message("ABI not supported"),
                            };

                            var abi_argument_types = PinnedArray(*Type){};
                            const abi_return_type = switch (return_type_abi.kind) {
                                .ignore, .direct => original_return_type,
                                .direct_coerce => |coerced_type| coerced_type,
                                .indirect => |indirect| b: {
                                    _ = abi_argument_types.append(get_typed_pointer(thread, .{
                                        .pointee = indirect.type,
                                    }));
                                    break :b &thread.void;
                                },
                                .direct_pair => |pair| get_anonymous_two_field_struct(thread, pair),
                                else => |t| @panic(@tagName(t)),
                            };

                            for (argument_type_abis.slice(), original_argument_types.const_slice()) |*argument_abi, original_argument_type| {
                                const start: u16 = @intCast(abi_argument_types.length);
                                switch (argument_abi.kind) {
                                    .direct => _ = abi_argument_types.append(original_argument_type),
                                    .direct_coerce => |coerced_type| _ = abi_argument_types.append(coerced_type),
                                    .direct_pair => |pair| {
                                        _ = abi_argument_types.append(pair[0]);
                                        _ = abi_argument_types.append(pair[1]);
                                    },
                                    .indirect => |indirect| _ = abi_argument_types.append(get_typed_pointer(thread, .{
                                        .pointee = indirect.type,
                                    })),
                                    else => |t| @panic(@tagName(t)),
                                }

                                const end: u16 = @intCast(abi_argument_types.length);
                                argument_abi.indices = .{start, end};
                            }

                            break :abi Function.Abi{
                                .original_return_type = original_return_type,
                                .original_argument_types = original_argument_types.const_slice(),
                                .abi_return_type = abi_return_type,
                                .abi_argument_types = abi_argument_types.const_slice(),
                                .return_type_abi = return_type_abi,
                                .argument_types_abi = argument_type_abis.const_slice(),
                                .calling_convention = calling_convention,
                            };
                        },
                        .custom => custom: {
                            break :custom Function.Abi{
                                .original_return_type = original_return_type,
                                .original_argument_types = original_argument_types.const_slice(),
                                .abi_return_type = original_return_type,
                                .abi_argument_types = original_argument_types.const_slice(),
                                .return_type_abi = .{
                                    .kind = .direct,
                                },
                                .argument_types_abi = blk: {
                                    var argument_abis = PinnedArray(Function.Abi.Information){};
                                    for (0..original_argument_types.length) |i| {
                                        _ = argument_abis.append(.{
                                            .indices = .{@intCast(i), @intCast(i + 1) },
                                            .kind = .direct,
                                        });
                                    }

                                    break :blk argument_abis.const_slice();
                                },
                                .calling_convention = calling_convention,
                            };
                        },
                        } else {
                            unreachable;
                    };

                    const function_type = thread.function_types.append(.{
                        .type = .{
                            .sema = .{
                                .id = .function,
                                .resolved = true,
                                .thread = thread.get_index(),
                            },
                            .size = 0,
                            .alignment = 0,
                            .bit_size = 0,
                        },
                        .abi = function_abi,
                    });

                    function_declaration_data.global_symbol.type = &function_type.type;
                    function_declaration_data.global_symbol.pointer_type = get_typed_pointer(thread, .{
                        .pointee = function_declaration_data.global_symbol.type,
                    });

                    parser.skip_space(src);

                    switch (src[parser.i]) {
                        brace_open => {
                            if (function_declaration_data.global_symbol.attributes.@"extern") {
                                fail();
                            }
                            

                            const function = thread.functions.add_one();
                            const entry_block = create_basic_block(thread);
                            function.* = .{
                                .declaration = function_declaration_data,
                                .scope = .{
                                    .scope = .{
                                        .id = .function,
                                        .parent = &file.scope.scope,
                                        .line = declaration_line + 1,
                                        .column = declaration_column + 1,
                                        .file = file_index,
                                    },
                                },
                                .entry_block = entry_block,
                            };
                            file.scope.scope.declarations.put_no_clobber(function.declaration.global_symbol.global_declaration.declaration.name, &function.declaration.global_symbol.global_declaration.declaration);
                            var analyzer = Analyzer{
                                .current_function = function,
                                .current_basic_block = entry_block,
                                .current_scope = &function.scope.scope,
                            };
                            analyzer.current_scope = &analyzer.current_function.scope.scope;

                            switch (function_type.abi.return_type_abi.kind) {
                                .indirect => |indirect| {
                                    _ = indirect; // autofix
                                    const abi_argument = thread.abi_arguments.append(.{
                                        .instruction = new_instruction(thread, .{
                                            .scope = analyzer.current_scope,
                                            .line = 0,
                                            .column = 0,
                                            .id = .abi_argument,
                                        }),
                                        .index = 0,
                                    });

                                    analyzer.append_instruction(&abi_argument.instruction);
                                    analyzer.return_pointer = &abi_argument.instruction;
                                },
                                else => {},
                            }

                            if (original_arguments.length > 0) {
                                // var runtime_parameter_count: u64 = 0;
                                for (original_arguments.const_slice(), function_abi.argument_types_abi, 0..) |argument, argument_abi, argument_index| {
                                    if (analyzer.current_scope.declarations.get(argument.name) != null)  {
                                        fail_message("A declaration already exists with such name");
                                    }

                                    var argument_abi_instructions = std.BoundedArray(*Instruction, 12){};

                                    const argument_abi_count = argument_abi.indices[1] - argument_abi.indices[0];
                                    const argument_symbol = if (argument_abi.kind == .indirect) blk: {
                                        assert(argument_abi_count == 1);
                                        const argument_symbol = emit_argument_symbol(&analyzer, thread, .{
                                            .type = argument.type,
                                            .name = argument.name,
                                            .line = argument.line,
                                            .column = argument.column,
                                            .index = @intCast(argument_index),
                                            .indirect_argument = argument_abi.indices[0],
                                        });
                                        argument_symbol.instruction.id = .abi_indirect_argument;
                                        break :blk argument_symbol;
                                    } else blk: {
                                        for (0..argument_abi_count) |abi_argument_index| {
                                            const abi_argument = thread.abi_arguments.append(.{
                                                .instruction = new_instruction(thread, .{
                                                    .scope = analyzer.current_scope,
                                                    .line = 0,
                                                    .column = 0,
                                                    .id = .abi_argument,
                                                }),
                                                .index = @intCast(abi_argument_index + argument_abi.indices[0]),
                                            });
                                            analyzer.append_instruction(&abi_argument.instruction);
                                            argument_abi_instructions.appendAssumeCapacity(&abi_argument.instruction);
                                        }
                                        const LowerKind = union(enum) {
                                            direct,
                                            direct_pair: [2]*Type,
                                            direct_coerce: *Type,
                                            indirect,
                                        };
                                        const lower_kind: LowerKind = switch (argument_abi.kind) {
                                            .direct => .direct,
                                            .direct_coerce => |coerced_type| if (argument.type == coerced_type) .direct else .{ .direct_coerce = coerced_type },
                                            .direct_pair => |pair| .{ .direct_pair = pair },
                                            .indirect => .indirect,
                                            else => |t| @panic(@tagName(t)),
                                        };

                                        const argument_symbol = switch (lower_kind) {
                                            .indirect => unreachable,
                                            .direct => block: {
                                                assert(argument_abi_count == 1);
                                                const argument_symbol = emit_argument_symbol(&analyzer, thread, .{
                                                    .type = argument.type,
                                                    .name = argument.name,
                                                    .line = argument.line,
                                                    .column = argument.column,
                                                    .index = @intCast(argument_index),
                                                });
                                                _ = emit_store(&analyzer, thread, .{
                                                    .destination = &argument_symbol.instruction.value,
                                                    .source = &argument_abi_instructions.slice()[0].value,
                                                    .alignment = argument.type.alignment,
                                                    .line = 0,
                                                    .column = 0,
                                                    .scope = analyzer.current_scope,
                                                });
                                                break :block argument_symbol;
                                            },
                                            .direct_coerce => |coerced_type| block: {
                                                assert(coerced_type != argument.type);
                                                assert(argument_abi_count == 1);
                                                const argument_symbol = emit_argument_symbol(&analyzer, thread, .{
                                                    .type = argument.type,
                                                    .name = argument.name,
                                                    .line = argument.line,
                                                    .column = argument.column,
                                                    .index = @intCast(argument_index),
                                                });

                                                switch (argument.type.sema.id) {
                                                    .@"struct" => {
                                                        // TODO:
                                                        const is_vector = false;

                                                        if (coerced_type.size <= argument.type.size and !is_vector) {
                                                            _ = emit_store(&analyzer, thread, .{
                                                                .destination = &argument_symbol.instruction.value,
                                                                .source = &argument_abi_instructions.slice()[0].value,
                                                                .alignment = coerced_type.alignment,
                                                                .line = 0,
                                                                .column = 0,
                                                                .scope = analyzer.current_scope,
                                                            });
                                                        }  else {
                                                            const temporal = emit_local_symbol(&analyzer, thread, .{
                                                                .name = 0,
                                                                .initial_value = &argument_abi_instructions.slice()[0].value,
                                                                .type = coerced_type,
                                                                .line = 0,
                                                                .column = 0,
                                                            });
                                                            emit_memcpy(&analyzer, thread, .{
                                                                .destination = &argument_symbol.instruction.value,
                                                                .source = &temporal.instruction.value,
                                                                .destination_alignment = .{
                                                                    .type = argument_symbol.type,
                                                                },
                                                                .source_alignment = .{
                                                                    .type = temporal.type,
                                                                },
                                                                .size = argument.type.size,
                                                                .line = 0,
                                                                .column = 0,
                                                                .scope = analyzer.current_scope,
                                                            });
                                                        }

                                                        break :block argument_symbol;
                                                    },
                                                    else => |t| @panic(@tagName(t)),
                                                }
                                                unreachable;
                                            },
                                            .direct_pair => |pair| b: {
                                                assert(argument_abi_count == 2);
                                                assert(argument_abi_instructions.len == 2);
                                                assert(pair[0].sema.id == .integer);
                                                assert(pair[1].sema.id == .integer);
                                                const alignments = [2]u32{ pair[0].alignment, pair[1].alignment };
                                                const sizes = [2]u64{ pair[0].size, pair[1].size };
                                                const alignment = @max(alignments[0], alignments[1]);
                                                _ = alignment; // autofix
                                                const high_aligned_size: u32 = @intCast(library.align_forward(sizes[1], alignments[1]));
                                                _ = high_aligned_size; // autofix
                                                const high_offset: u32 = @intCast(library.align_forward(sizes[0], alignments[1]));
                                                assert(high_offset + sizes[1] <= argument.type.size);
                                                const argument_symbol = emit_argument_symbol(&analyzer, thread, .{
                                                    .type = argument.type,
                                                    .name = argument.name,
                                                    .line = argument.line,
                                                    .column = argument.column,
                                                    .index = @intCast(argument_index),
                                                });

                                                _ = emit_store(&analyzer, thread, .{
                                                    .destination = &argument_symbol.instruction.value,
                                                    .source = &argument_abi_instructions.slice()[0].value,
                                                    .alignment = pair[0].alignment,
                                                    .line = 0,
                                                    .column = 0,
                                                    .scope = analyzer.current_scope,
                                                });

                                                const gep = emit_gep(thread, &analyzer, .{
                                                    .pointer = &argument_symbol.instruction.value,
                                                    .type = pair[1],
                                                    .aggregate_type = pair[0],
                                                    .index = &create_constant_int(thread, .{
                                                        .n = 1,
                                                        .type = &thread.integers[31].type,
                                                    }).value,
                                                    .is_struct = false,
                                                    .line = 0,
                                                    .column = 0,
                                                    .scope = analyzer.current_scope,
                                                });

                                                _ = emit_store(&analyzer, thread, .{
                                                    .destination = &gep.instruction.value,
                                                    .source = &argument_abi_instructions.slice()[1].value,
                                                    .alignment = pair[1].alignment,
                                                    .line = 0,
                                                    .column = 0,
                                                    .scope = analyzer.current_scope,
                                                });
                                                break :b argument_symbol;
                                            },
                                        };

                                        break :blk argument_symbol;
                                    };

                                    if (argument.name != 0) {
                                        analyzer.current_scope.declarations.put_no_clobber(argument.name, &argument_symbol.argument_declaration.declaration);
                                        if (thread.generate_debug_information) {
                                            emit_debug_argument(&analyzer, thread, .{
                                                .argument_symbol = argument_symbol,
                                            });
                                        }
                                    }
                                }
                            }
                            
                            const result = analyze_local_block(thread, &analyzer, &parser, file);
                            _ = result;

                            const current_basic_block = analyzer.current_basic_block;
                            if (analyzer.return_phi) |return_phi| {
                                analyzer.current_basic_block = analyzer.return_block.?;
                                analyzer.append_instruction(&return_phi.instruction);
                                emit_return(thread, &analyzer, .{
                                    .return_value = &return_phi.instruction.value,
                                    .line = parser.get_debug_line(),
                                    .column = parser.get_debug_column(),
                                    .scope = analyzer.current_scope,
                                });
                                analyzer.current_basic_block = current_basic_block;
                            }
                            
                            if (!current_basic_block.is_terminated and (current_basic_block.instructions.length > 0 or current_basic_block.predecessors.length > 0)) {
                                if (analyzer.return_block == null) {
                                    switch (original_return_type.sema.id) {
                                        .void => {
                                            emit_ret_void(thread, &analyzer, .{
                                                .line = parser.get_debug_line(),
                                                .column = parser.get_debug_column(),
                                                .scope = analyzer.current_scope,
                                            });
                                        },
                                        else => |t| @panic(@tagName(t)),
                                    }
                                } else {
                                    unreachable;
                                }
                            }
                        },
                        ';' => {
                            parser.i += 1;

                            if (!function_declaration_data.global_symbol.attributes.@"extern") {
                                fail();
                            }
                            function_declaration_data.global_symbol.id = .function_declaration;

                            const function_declaration = thread.external_functions.append(function_declaration_data);
                            file.scope.scope.declarations.put_no_clobber(function_declaration.global_symbol.global_declaration.declaration.name, &function_declaration.global_symbol.global_declaration.declaration);
                        },
                        else => fail_message("Unexpected character to close function declaration"),
                    }
                } else {
                    fail();
                }
            },
            'i' => {
                const import_keyword = "import";
                if (byte_equal(src[parser.i..][0..import_keyword.len], import_keyword)) {
                    parser.i += import_keyword.len;

                    parser.skip_space(src);

                    const string_literal = parser.parse_non_escaped_string_literal_content(src);
                    top_level_declaration_name = string_literal;
                    parser.skip_space(src);

                    parser.expect_character(src, ';');

                    const filename = std.fs.path.basename(string_literal);
                    const has_right_extension = filename.len > ".nat".len and byte_equal(filename[filename.len - ".nat".len..], ".nat");
                    if (!has_right_extension) {
                        fail();
                    }

                    const filename_without_extension = filename[0..filename.len - ".nat".len];
                    const filename_without_extension_hash = hash_bytes(filename_without_extension);
                    const directory_path = file.get_directory_path();
                    const directory = std.fs.openDirAbsolute(directory_path, .{}) catch unreachable;
                    const file_path = library.realpath(thread.arena, directory, string_literal) catch unreachable;
                    const file_path_hash = intern_identifier(&thread.identifiers, file_path);
                    // std.debug.print("Interning '{s}' (0x{x}) in thread #{}\n", .{file_path, file_path_hash, thread.get_index()});
                    
                    for (thread.imports.slice()) |import| {
                        const pending_file_hash = import.hash;
                        if (pending_file_hash == file_path_hash) {
                            fail();
                        }
                    } else {
                        const import = thread.imports.append(.{
                            .global_declaration = .{
                                .declaration = .{
                                    .id = .global,
                                    .name = std.math.maxInt(u32),
                                    .line = declaration_line,
                                    .column = declaration_column,
                                    .scope = &file.scope.scope,
                                },
                                .id = .unresolved_import,
                            },
                            .hash = file_path_hash,
                        });
                        _ = import.files.append(file);
                        _ = file.imports.append(import);
                        file.scope.scope.declarations.put_no_clobber(filename_without_extension_hash, &import.global_declaration.declaration);
                        const global_declaration_reference: **GlobalDeclaration = @ptrCast(file.scope.scope.declarations.get_pointer(filename_without_extension_hash) orelse unreachable);
                        const import_values = file.values_per_import.append(.{});
                        const lazy_expression = thread.lazy_expressions.append(LazyExpression.init(global_declaration_reference, thread));
                        _ = import_values.append(&lazy_expression.value);

                        thread.add_control_work(.{
                            .id = .analyze_file,
                            .offset = file_path_hash,
                            .count = @intCast(file_index),
                        });
                    }
                } else {
                    fail();
                }
            },
            's' => {
                const lead_identifier = parser.parse_raw_identifier(src);
                if (byte_equal(lead_identifier, "struct")) {
                    parser.skip_space(src);

                    const struct_name = parser.parse_identifier(thread, src);
                    top_level_declaration_name = thread.identifiers.get(struct_name).?;
                    const struct_type = thread.structs.append(.{
                        .type = .{
                            .sema = .{
                                .id = .@"struct",
                                .thread = thread.get_index(),
                                .resolved = true,
                            },
                            .size = 0,
                            .alignment = 1,
                            .bit_size = 0,
                        },
                        .declaration = .{
                            .name = struct_name,
                            .id = .@"struct",
                            .line = declaration_line,
                            .column = declaration_column,
                            .scope = &file.scope.scope,
                        },
                        .fields = &.{},
                    });
                    file.scope.scope.declarations.put_no_clobber(struct_name, &struct_type.declaration);

                    parser.skip_space(src);

                    parser.expect_character(src, brace_open);

                    var fields = PinnedArray(*Type.AggregateField){};

                    while (parser.parse_field(thread, file)) |field_data| {
                        struct_type.type.alignment = @max(struct_type.type.alignment, field_data.type.alignment);
                        const aligned_offset = library.align_forward(struct_type.type.size, field_data.type.alignment);
                        const field = thread.fields.append(.{
                            .type = field_data.type,
                            .parent = &struct_type.type,
                            .name = field_data.name,
                            .index = fields.length,
                            .line = field_data.line,
                            .column = field_data.column,
                            .member_offset = aligned_offset,
                        });
                        struct_type.type.size = aligned_offset + field.type.size;
                        _ = fields.append(field);
                    }

                    parser.i += 1;

                    struct_type.type.size = library.align_forward(struct_type.type.size, struct_type.type.alignment);
                    struct_type.type.bit_size = struct_type.type.size * 8;
                    struct_type.fields = fields.const_slice();
                } else {
                    fail();
                }
            },
            else => fail(),
        }

        if (configuration.timers) {
            const top_level_declaration_end = get_instant();
            _ = file.time.top_level_declaration_timers.append(.{
                .name = top_level_declaration_name,
                .start = top_level_declaration_start,
                .end = top_level_declaration_end,
            });
        }
    } 

    for (file.local_lazy_expressions.slice()) |local_lazy_expression| {
        const name = local_lazy_expression.name;
        if (file.scope.scope.get_global_declaration(name)) |global_declaration| {
            switch (global_declaration.id) {
                .global_symbol => {
                    const global_symbol = global_declaration.to_symbol();
                    switch (global_symbol.id) {
                        .function_definition => {
                            const function_definition = global_symbol.get_payload(.function_definition);
                            for (local_lazy_expression.values.slice()) |value| {
                                switch (value.sema.id) {
                                    .instruction => {
                                        const instruction = value.get_payload(.instruction);
                                        switch (instruction.id) {
                                            .call => {
                                                const call = instruction.get_payload(.call);
                                                call.callable = &function_definition.declaration.global_symbol.value;
                                                call.instruction.value.sema.resolved = true;
                                            },
                                            else => |t| @panic(@tagName(t)),
                                        }
                                    },
                                    else => |t| @panic(@tagName(t)),
                                }
                            }
                        },
                        else => |t| @panic(@tagName(t)),
                    }
                },
                else => |t| @panic(@tagName(t)),
            }
        } else {
            fail_term("Unable to find lazy expression", thread.identifiers.get(name).?);
        }
    }

    try_resolve_file(thread, file);
}

fn try_resolve_file(thread: *Thread, file: *File) void {
    const analysis_end = get_instant();
    const analysis_start = if (configuration.timers) file.time.timestamp else {};
    if (configuration.timers) {
        file.time.timestamp = analysis_end;
    }
    const timer_tag: File.Timer = switch (file.state) {
        .analyzing => .analysis,
        .waiting_for_dependencies => .wait_for_dependencies,
        else => unreachable,
    };

    if (file.imports.length == file.resolved_import_count) {
        if (configuration.timers) {
            file.time.timers.set(timer_tag, .{
                .range = .{
                    .start = analysis_start,
                    .end = analysis_end,
                },
            });
        }
        file.state = .analyzed;
        thread.analyzed_file_count += 1;

        // If the thread has analyzed the same files it has been assigned, tell the control thread
        // that the thread has finished file analysis so it can proceed to the next step
        if (thread.analyzed_file_count == thread.assigned_file_count) {
            if (@atomicLoad(@TypeOf(thread.task_system.job.queuer.to_do), &thread.task_system.job.queuer.to_do, .seq_cst) == thread.task_system.job.worker.completed + 1) {
                if (configuration.timers) {
                    thread.time.timers.getPtr(.analysis).end = get_instant();
                }
                thread.add_control_work(.{
                    .id = .notify_analysis_complete,
                });
            } else {
                unreachable;
            }
        }

        for (file.interested_threads.slice()) |ti| {
            thread.add_control_work(.{
                .id = .notify_file_resolved,
                .offset = file.get_index(),
                .count = @intCast(ti),
            });
        }
    } else {
        file.state = .waiting_for_dependencies;
        if (configuration.timers) {
            switch (file.time.timers.get(timer_tag)) {
                .range => |range| {
                    const order = range.end.order(range.start);
                    switch (order) {
                        .eq => file.time.timers.set(timer_tag, .{
                            .range = .{
                                .start = analysis_start,
                                .end = analysis_end,
                            },
                            }),
                        else => |t| @panic(@tagName(t)),
                    }
                },
                .accumulating => unreachable,
            }
        }
    }
}

const TypecheckResult = enum{
    success,
};

fn typecheck(expected: *Type, have: *Type) TypecheckResult {
    if (expected == have) {
        return TypecheckResult.success;
    } else {
        fail();
    }
}

fn emit_integer_binary_operation(analyzer: *Analyzer, thread: *Thread, args: struct{
    left: *Value,
    right: *Value,
    type: *Type,
    id: IntegerBinaryOperation.Id,
    scope: *Scope,
    line: u32,
    column: u32,
}) *IntegerBinaryOperation{
    const integer_binary_operation = thread.integer_binary_operations.append(.{
        .instruction = new_instruction(thread, .{
            .id = .integer_binary_operation,
            .line = args.line,
            .column = args.column,
            .scope = analyzer.current_scope,
        }),
        .left = args.left,
        .right = args.right,
        .type = args.type,
        .id = args.id,
    });
    analyzer.append_instruction(&integer_binary_operation.instruction);

    return integer_binary_operation;
}

fn emit_cast(analyzer: *Analyzer, thread: *Thread, args: struct{
    value: *Value,
    type: *Type,
    id: Cast.Id,
    scope: *Scope,
    line: u32,
    column: u32,
}) *Cast{
    const cast = thread.casts.append(.{
        .instruction = new_instruction(thread, .{
            .id = .cast,
            .line = args.line,
            .column = args.column,
            .scope = analyzer.current_scope,
        }),
        .value = args.value,
        .type = args.type,
        .id = args.id,
    });
    analyzer.append_instruction(&cast.instruction);

    return cast;
}

fn emit_load(analyzer: *Analyzer, thread: *Thread, args: struct {
    value: *Value,
    type: *Type,
    scope: *Scope,
    line: u32,
    column: u32,
    is_volatile: bool = false,
}) *Load {
    const load = thread.loads.append(.{
        .instruction = new_instruction(thread, .{
            .id = .load,
            .line = args.line,
            .column = args.column,
            .scope = args.scope,
        }),
        .value = args.value,
        .type = args.type,
        .alignment = args.type.alignment,
        .is_volatile = args.is_volatile,
    });

    analyzer.append_instruction(&load.instruction);

    return load;
}

fn emit_argument_symbol(analyzer: *Analyzer, thread: *Thread, args: struct{
    type: *Type,
    name: u32,
    line: u32,
    column: u32,
    index: u32,
    indirect_argument: ?u32 = null,
}) *ArgumentSymbol{
    const argument_symbol = thread.argument_symbols.append(.{
        .argument_declaration = .{
            .declaration = .{
                .id = .argument,
                .name = args.name,
                .line = args.line,
                .column = args.column,
                .scope = analyzer.current_scope,
            },
        },
        .type = args.type,
        .pointer_type = get_typed_pointer(thread, .{
            .pointee = args.type,
        }),
        .alignment = args.type.alignment,
        .index = if (args.indirect_argument) |i| i else args.index,
        .instruction = new_instruction(thread, .{
            .scope = analyzer.current_scope,
            .id = if (args.indirect_argument) |_| .abi_indirect_argument else .argument_storage,
            .line = args.line,
            .column = args.column,
        }),
    });
    _ = analyzer.current_function.arguments.append(argument_symbol);

    return argument_symbol;
}

fn emit_debug_argument(analyzer: *Analyzer, thread: *Thread, args: struct {
    argument_symbol: *ArgumentSymbol,
}) void {
    assert(thread.generate_debug_information);
    var i = args.argument_symbol.instruction;
    i.id = .debug_argument;
    const debug_argument = thread.debug_arguments.append(.{
        .argument = args.argument_symbol,
        .instruction = i,
    });
    analyzer.append_instruction(&debug_argument.instruction);
}

fn emit_local_symbol(analyzer: *Analyzer, thread: *Thread, args: struct{
    name: u32,
    initial_value: ?*Value,
    type: *Type,
    line: u32,
    column: u32,
    alignment: ?u32 = null,
}) *LocalSymbol {
    const local_symbol = thread.local_symbols.append(.{
        .local_declaration = .{
            .declaration = .{
                .id = .local,
                .name = args.name,
                .line = args.line,
                .column = args.column,
                .scope = analyzer.current_scope,
            },
        },
        .type = args.type,
        .pointer_type = get_typed_pointer(thread, .{
            .pointee = args.type,
        }),
        .instruction = new_instruction(thread, .{
            .resolved = args.type.sema.resolved and if (args.initial_value) |iv| iv.sema.resolved else true,
            .id = .local_symbol,
            .line = args.line,
            .column = args.column,
            .scope = analyzer.current_scope,
        }),
        .alignment = if (args.alignment) |a| a else args.type.alignment,
    });

    _ = analyzer.current_function.stack_slots.append(local_symbol);

    if (args.name != 0) {
        analyzer.current_scope.declarations.put_no_clobber(args.name, &local_symbol.local_declaration.declaration);
        if (thread.generate_debug_information) {
            emit_debug_local(analyzer, thread, .{
                .local_symbol = local_symbol,
            });
        }
    }

    if (args.initial_value) |initial_value| {
        emit_store(analyzer, thread, .{
            .destination = &local_symbol.instruction.value,
            .source = initial_value,
            .alignment = local_symbol.alignment,
            .line = args.line,
            .column = args.column,
            .scope = analyzer.current_scope,
        });
    }

    return local_symbol;
}

fn emit_debug_local(analyzer: *Analyzer, thread: *Thread, args: struct {
    local_symbol: *LocalSymbol,
}) void {
    assert(thread.generate_debug_information);
    var i = args.local_symbol.instruction;
    i.id = .debug_local;
    const debug_local = thread.debug_locals.append(.{
        .local = args.local_symbol,
        .instruction = i,
    });
    analyzer.append_instruction(&debug_local.instruction);
}

fn emit_store(analyzer: *Analyzer, thread: *Thread, args: struct {
    destination: *Value,
    source: *Value,
    alignment: u32,
    line: u32,
    column: u32,
    scope: *Scope,
    is_volatile: bool = false,
}) void {
    const store = thread.stores.append(.{
        .instruction = new_instruction(thread, .{
            .id = .store,
            .line = args.line,
            .column = args.column,
            .scope = args.scope,
        }),
        .destination = args.destination,
        .source = args.source,
        .alignment = args.alignment,
        .is_volatile = args.is_volatile,
    });

    analyzer.append_instruction(&store.instruction);
}

const Memcpy = struct{
    instruction: Instruction,
    destination: *Value,
    destination_alignment: u32,
    source: *Value,
    source_alignment: u32,
    size: u64,
    is_volatile: bool,
    const Alignment = union(enum){
        alignment: u32,
        type: *Type,
    };
};

fn emit_memcpy(analyzer: *Analyzer, thread: *Thread, args: struct{ 
    destination: *Value,
    destination_alignment: Memcpy.Alignment,
    source: *Value,
    source_alignment: Memcpy.Alignment,
    size: u64,
    is_volatile: bool = false,
    line: u32,
    column: u32,
    scope: *Scope,
}) void {
    const memcpy = thread.memcopies.append(.{
        .instruction = new_instruction(thread, .{
            .scope = args.scope,
            .line = args.line,
            .column = args.column,
            .id = .memcpy,
        }),
        .destination = args.destination,
        .destination_alignment = switch (args.destination_alignment) {
            .alignment => |a| a,
            .type => |t| t.alignment,
        },
        .source = args.source,
        .source_alignment = switch (args.source_alignment) {
            .alignment => |a| a,
            .type => |t| t.alignment,
        },
        .size = args.size,
        .is_volatile = args.is_volatile,
    });
    analyzer.append_instruction(&memcpy.instruction);
}

const RawEmitArgs = struct{
    line: u32,
    column: u32,
    scope: *Scope,
};

fn emit_unreachable(analyzer: *Analyzer, thread: *Thread, args: RawEmitArgs) void {
    assert(!analyzer.current_basic_block.is_terminated);
    const ur = thread.standalone_instructions.append(new_instruction(thread, .{
            .scope = args.scope,
            .line = args.line,
            .column = args.column,
            .id = .@"unreachable",
        }));
    analyzer.append_instruction(ur);
    analyzer.current_basic_block.is_terminated = true;
}

fn emit_trap(analyzer: *Analyzer, thread: *Thread, args: RawEmitArgs) void {
    assert(!analyzer.current_basic_block.is_terminated);
    const trap = thread.standalone_instructions.append(new_instruction(thread, .{
        .scope = args.scope,
        .line = args.line,
        .column = args.column,
        .id = .@"trap",
    }));
    analyzer.append_instruction(trap);

    emit_unreachable(analyzer, thread, args);
}

fn new_instruction(thread: *Thread, args: struct {
    scope: *Scope,
    line: u32,
    column: u32,
    id: Instruction.Id,
    resolved: bool = true,
}) Instruction {
    return Instruction{
        .id = args.id,
        .value = .{
            .sema = .{
                .thread = thread.get_index(),
                .id = .instruction,
                .resolved = args.resolved,
            },
        },
        .scope = args.scope,
        .line = args.line,
        .column = args.column,
    };
}

const JumpEmission = struct {
    jump: *Jump,
    basic_block: *BasicBlock,
};

fn emit_jump(analyzer: *Analyzer, thread: *Thread, args: struct {
    basic_block: *BasicBlock,
    line: u32,
    column: u32,
    scope: *Scope,
}) JumpEmission {
    assert(!analyzer.current_basic_block.is_terminated);
    const jump = thread.jumps.append(.{
        .instruction = new_instruction(thread, .{
            .id = .jump,
            .line = args.line,
            .column = args.column,
            .scope = args.scope,
        }),
        .basic_block = args.basic_block,
    });
    const original_block = analyzer.current_basic_block;
    analyzer.append_instruction(&jump.instruction);
    analyzer.current_basic_block.is_terminated = true;
    _ = args.basic_block.predecessors.append(analyzer.current_basic_block);

    return .{
        .jump = jump,
        .basic_block = original_block,
    };
}

const BranchEmission = struct {
    branch: *Branch,
    basic_block: *BasicBlock,
    // index: u32,
};

fn emit_branch(analyzer: *Analyzer, thread: *Thread, args: struct {
    condition: *Value,
    taken: *BasicBlock,
    not_taken: *BasicBlock,
    line: u32,
    column: u32,
    scope: *Scope,
}) BranchEmission {
    assert(!analyzer.current_basic_block.is_terminated);
    const branch = thread.branches.append(.{
        .instruction = new_instruction(thread, .{
            .id = .branch,
            .line = args.line,
            .column = args.column,
            .scope = args.scope,
        }),
        .condition = args.condition,
        .taken = args.taken,
        .not_taken = args.not_taken,
    });
    const original_block = analyzer.current_basic_block;
    analyzer.append_instruction(&branch.instruction);
    analyzer.current_basic_block.is_terminated = true;
    _ = args.taken.predecessors.append(analyzer.current_basic_block);
    _ = args.not_taken.predecessors.append(analyzer.current_basic_block);

    return .{
        .branch = branch,
        .basic_block = original_block,
    };
}

fn emit_condition(analyzer: *Analyzer, thread: *Thread, args: struct {
    condition: *Value,
    line: u32,
    column: u32,
    scope: *Scope,
}) *Value {
    const condition_type = args.condition.get_type();
    const compare = switch (condition_type.sema.id) {
        .integer => int: {
            if (condition_type.bit_size == 1) {
                break :int args.condition;
            } else {
                const zero = create_constant_int(thread, .{
                    .n = 0,
                    .type = condition_type,
                });

                const compare = thread.integer_compares.append(.{
                    .instruction = new_instruction(thread, .{
                        .line = args.line,
                        .column = args.column,
                        .scope = args.scope,
                        .id = .integer_compare,
                    }),
                    .left = args.condition,
                    .right = &zero.value,
                    .id = .not_zero,
                });
                analyzer.append_instruction(&compare.instruction);

                break :int &compare.instruction.value;
            }
        },
        else => |t| @panic(@tagName(t)),
    };

    return compare;
}

fn get_typed_pointer(thread: *Thread, descriptor: Type.TypedPointer.Descriptor) *Type {
    assert(descriptor.pointee.sema.resolved);
    if (thread.typed_pointer_type_map.get(descriptor)) |result| return result else {
        const typed_pointer_type = thread.typed_pointer_types.append(.{
            .type = .{
                .sema = .{
                    .thread = thread.get_index(),
                    .id = .typed_pointer,
                    .resolved = true,
                },
                .size = 8,
                .alignment = 8,
                .bit_size = 64,
            },
            .descriptor = descriptor,
        });

        thread.typed_pointer_type_map.put_no_clobber(descriptor, &typed_pointer_type.type);
        return &typed_pointer_type.type;
    }
}

fn get_anonymous_two_field_struct(thread: *Thread, types: [2]*Type) *Type {
    if (thread.two_struct_map.get(types)) |result| return result else {
        const anonymous_struct = thread.anonymous_structs.add_one();
        const first_field = thread.fields.append(.{
            .type = types[0],
            .parent = &anonymous_struct.type,
            .member_offset = 0,
            .name = 0,
            .index = 0,
            .line = 0,
            .column = 0,
        });
        const second_field = thread.fields.append(.{
            .type = types[1],
            .parent = &anonymous_struct.type,
            .member_offset = types[0].alignment,
            .name = 0,
            .index = 1,
            .line = 0,
            .column = 0,
        });
        const fields = thread.arena.new_array(*Type.AggregateField, 2) catch unreachable;
        fields[0] = first_field;
        fields[1] = second_field;
        const alignment = @max(types[0].alignment, types[1].alignment);
        const size = library.align_forward(types[0].size + types[1].size, alignment);
        anonymous_struct.* = .{
            .type = .{
                .sema = .{
                    .id = .anonymous_struct,
                    .thread = thread.get_index(),
                    .resolved = true,
                },
                .size = size,
                .alignment = alignment,
                .bit_size = @intCast(size * 8),
            },
            .fields = fields,
        };

        thread.two_struct_map.put_no_clobber(types, &anonymous_struct.type);

        return &anonymous_struct.type;
    }
}

fn get_array_type(thread: *Thread, descriptor: Type.Array.Descriptor) *Type {
    assert(descriptor.element_type.sema.resolved);
    if (thread.array_type_map.get(descriptor)) |result| return result else {
        const array_type = thread.array_types.append(.{
            .type = .{
                .sema = .{
                    .thread = thread.get_index(),
                    .id = .array,
                    .resolved = true,
                },
                .size = descriptor.element_type.size * descriptor.element_count,
                .alignment = descriptor.element_type.alignment,
                .bit_size = 0,
            },
            .descriptor = descriptor,
        });

        thread.array_type_map.put_no_clobber(descriptor, &array_type.type);
        return &array_type.type;
    }
}

pub const LLVM = struct {
    const bindings = @import("backend/llvm_bindings.zig");
    pub const initializeAll = bindings.NativityLLVMInitializeAll;
    pub const x86_64 = struct {
        pub const initializeTarget = bindings.LLVMInitializeX86Target;
        pub const initializeTargetInfo = bindings.LLVMInitializeX86TargetInfo;
        pub const initializeTargetMC = bindings.LLVMInitializeX86TargetMC;
        pub const initializeAsmPrinter = bindings.LLVMInitializeX86AsmPrinter;
        pub const initializeAsmParser = bindings.LLVMInitializeX86AsmParser;
    };

    pub const aarch64 = struct {
        pub const initializeTarget = bindings.LLVMInitializeAArch64Target;
        pub const initializeTargetInfo = bindings.LLVMInitializeAArch64TargetInfo;
        pub const initializeTargetMC = bindings.LLVMInitializeAArch64TargetMC;
        pub const initializeAsmPrinter = bindings.LLVMInitializeAArch64AsmPrinter;
        pub const initializeAsmParser = bindings.LLVMInitializeAArch64AsmParser;
    };

    pub const Attributes = struct {
        noreturn: *Attribute,
        naked: *Attribute,
        nounwind: *Attribute,
        inreg: *Attribute,
        @"noalias": *Attribute,
        sign_extend: *Attribute,
        zero_extend: *Attribute,
    };

    pub const Linkage = enum(c_uint) {
        @"extern" = 0,
        available_external = 1,
        link_once_any = 2,
        link_once_odr = 3,
        weak_any = 4,
        weak_odr = 5,
        appending = 6,
        internal = 7,
        private = 8,
        external_weak = 9,
        common = 10,
    };

    pub const ThreadLocalMode = enum(c_uint) {
        not_thread_local = 0,
    };

    const getFunctionType = bindings.NativityLLVMGetFunctionType;

    pub const Context = opaque {
        const create = bindings.NativityLLVMCreateContext;
        const createBasicBlock = bindings.NativityLLVMCreateBasicBlock;
        const getConstantInt = bindings.NativityLLVMContextGetConstantInt;
        const getConstString = bindings.NativityLLVMContextGetConstString;
        const getVoidType = bindings.NativityLLVMGetVoidType;
        const getIntegerType = bindings.NativityLLVMGetIntegerType;
        const getPointerType = bindings.NativityLLVMGetPointerType;
        const getStructType = bindings.NativityLLVMGetStructType;
        const createStructType = bindings.NativityLLVMCreateStructType;
        const getIntrinsicType = bindings.NativityLLVMContextGetIntrinsicType;
        const getAttributeFromEnum = bindings.NativityLLVMContextGetAttributeFromEnum;
        const getAttributeFromString = bindings.NativityLLVMContextGetAttributeFromString;
        const getAttributeFromType = bindings.NativityLLVMContextGetAttributeFromType;
        const getAttributeSet = bindings.NativityLLVMContextGetAttributeSet;
    };

    pub const Module = opaque {
        const addGlobalVariable = bindings.NativityLLVMModuleAddGlobalVariable;
        const create = bindings.NativityLLVMCreateModule;
        const getFunction = bindings.NativityLLVMModuleGetFunction;
        const createFunction = bindings.NativityLLVModuleCreateFunction;
        const verify = bindings.NativityLLVMVerifyModule;
        const toString = bindings.NativityLLVMModuleToString;
        const getIntrinsicDeclaration = bindings.NativityLLVMModuleGetIntrinsicDeclaration;
        const createDebugInfoBuilder = bindings.NativityLLVMModuleCreateDebugInfoBuilder;
        const setTargetMachineDataLayout = bindings.NativityLLVMModuleSetTargetMachineDataLayout;
        const setTargetTriple = bindings.NativityLLVMModuleSetTargetTriple;
        const runOptimizationPipeline = bindings.NativityLLVMRunOptimizationPipeline;
        const addPassesToEmitFile = bindings.NativityLLVMModuleAddPassesToEmitFile;
        const link = bindings.NativityLLVMLinkModules;
    };

    pub const LinkFlags = packed struct(c_uint) {
        override_from_source: bool,
        link_only_needed: bool,
        _: u30 = 0,
    };

    pub const Builder = opaque {
        const create = bindings.NativityLLVMCreateBuilder;
        const setInsertPoint = bindings.NativityLLVMBuilderSetInsertPoint;
        const createAdd = bindings.NativityLLVMBuilderCreateAdd;
        const createAlloca = bindings.NativityLLVMBuilderCreateAlloca;
        const createAnd = bindings.NativityLLVMBuilderCreateAnd;
        const createOr = bindings.NativityLLVMBuilderCreateOr;
        const createCall = bindings.NativityLLVMBuilderCreateCall;
        const createCast = bindings.NativityLLVMBuilderCreateCast;
        const createBranch = bindings.NativityLLVMBuilderCreateBranch;
        const createConditionalBranch = bindings.NativityLLVMBuilderCreateConditionalBranch;
        const createSwitch = bindings.NativityLLVMBuilderCreateSwitch;
        const createGEP = bindings.NativityLLVMBuilderCreateGEP;
        const createICmp = bindings.NativityLLVMBuilderCreateICmp;
        const createIsNotNull = bindings.NativityLLVMBuilderCreateIsNotNull;
        const createLoad = bindings.NativityLLVMBuilderCreateLoad;
        const createMultiply = bindings.NativityLLVMBuilderCreateMultiply;
        const createRet = bindings.NativityLLVMBuilderCreateRet;
        const createShiftLeft = bindings.NativityLLVMBuilderCreateShiftLeft;
        const createArithmeticShiftRight = bindings.NativityLLVMBuilderCreateArithmeticShiftRight;
        const createLogicalShiftRight = bindings.NativityLLVMBuilderCreateLogicalShiftRight;
        const createStore = bindings.NativityLLVMBuilderCreateStore;
        const createSub = bindings.NativityLLVMBuilderCreateSub;
        const createUnreachable = bindings.NativityLLVMBuilderCreateUnreachable;
        const createXor = bindings.NativityLLVMBuilderCreateXor;
        const createUDiv = bindings.NativityLLVMBuilderCreateUDiv;
        const createSDiv = bindings.NativityLLVMBuilderCreateSDiv;
        const createURem = bindings.NativityLLVMBuilderCreateURem;
        const createSRem = bindings.NativityLLVMBuilderCreateSRem;
        const createExtractValue = bindings.NativityLLVMBuilderCreateExtractValue;
        const createInsertValue = bindings.NativityLLVMBuilderCreateInsertValue;
        const createGlobalString = bindings.NativityLLVMBuilderCreateGlobalString;
        const createGlobalStringPointer = bindings.NativityLLVMBuilderCreateGlobalStringPointer;
        const createPhi = bindings.NativityLLVMBuilderCreatePhi;
        const createMemcpy = bindings.NativityLLVMBuilderCreateMemcpy;

        const getInsertBlock = bindings.NativityLLVMBuilderGetInsertBlock;
        const isCurrentBlockTerminated = bindings.NativityLLVMBuilderIsCurrentBlockTerminated;
        const setCurrentDebugLocation = bindings.NativityLLVMBuilderSetCurrentDebugLocation;
        const clearCurrentDebugLocation = bindings.NativityLLVMBuilderClearCurrentDebugLocation;
        const setInstructionDebugLocation = bindings.NativityLLVMBuilderSetInstructionDebugLocation;
    };

    pub const DebugInfo = struct {
        pub const AttributeType = enum(c_uint) {
            address = 0x01,
            boolean = 0x02,
            complex_float = 0x03,
            float = 0x04,
            signed = 0x05,
            signed_char = 0x06,
            unsigned = 0x07,
            unsigned_char = 0x08,
            imaginary_float = 0x09,
            packed_decimal = 0x0a,
            numeric_string = 0x0b,
            edited = 0x0c,
            signed_fixed = 0x0d,
            unsigned_fixed = 0x0e,
            decimal_float = 0x0f,
            UTF = 0x10,
            UCS = 0x11,
            ASCII = 0x12,
        };

        pub const CallingConvention = enum(c_uint) {
            none = 0,
            normal = 0x01,
            program = 0x02,
            nocall = 0x03,
            pass_by_reference = 0x04,
            pass_by_value = 0x05,
            // Vendor extensions
            GNU_renesas_sh = 0x40,
            GNU_borland_fastcall_i386 = 0x41,
            BORLAND_safecall = 0xb0,
            BORLAND_stdcall = 0xb1,
            BORLAND_pascal = 0xb2,
            BORLAND_msfastcall = 0xb3,
            BORLAND_msreturn = 0xb4,
            BORLAND_thiscall = 0xb5,
            BORLAND_fastcall = 0xb6,
            LLVM_vectorcall = 0xc0,
            LLVM_Win64 = 0xc1,
            LLVM_X86_64SysV = 0xc2,
            LLVM_AAPCS = 0xc3,
            LLVM_AAPCS_VFP = 0xc4,
            LLVM_IntelOclBicc = 0xc5,
            LLVM_SpirFunction = 0xc6,
            LLVM_OpenCLKernel = 0xc7,
            LLVM_Swift = 0xc8,
            LLVM_PreserveMost = 0xc9,
            LLVM_PreserveAll = 0xca,
            LLVM_X86RegCall = 0xcb,
            GDB_IBM_OpenCL = 0xff,
        };

        pub const Builder = opaque {
            const createCompileUnit = bindings.NativityLLVMDebugInfoBuilderCreateCompileUnit;
            const createFile = bindings.NativityLLVMDebugInfoBuilderCreateFile;
            const createFunction = bindings.NativityLLVMDebugInfoBuilderCreateFunction;
            const createSubroutineType = bindings.NativityLLVMDebugInfoBuilderCreateSubroutineType;
            const createLexicalBlock = bindings.NativityLLVMDebugInfoBuilderCreateLexicalBlock;
            const createParameterVariable = bindings.NativityLLVMDebugInfoBuilderCreateParameterVariable;
            const createAutoVariable = bindings.NativityLLVMDebugInfoBuilderCreateAutoVariable;
            const createGlobalVariableExpression = bindings.NativityLLVMDebugInfoBuilderCreateGlobalVariableExpression;
            const createExpression = bindings.NativityLLVMDebugInfoBuilderCreateExpression;
            const createBasicType = bindings.NativityLLVMDebugInfoBuilderCreateBasicType;
            const createPointerType = bindings.NativityLLVMDebugInfoBuilderCreatePointerType;
            const createStructType = bindings.NativityLLVMDebugInfoBuilderCreateStructType;
            const createArrayType = bindings.NativityLLVMDebugInfoBuilderCreateArrayType;
            const createEnumerationType = bindings.NativityLLVMDebugInfoBuilderCreateEnumerationType;
            const createEnumerator = bindings.NativityLLVMDebugInfoBuilderCreateEnumerator;
            const createReplaceableCompositeType = bindings.NativityLLVMDebugInfoBuilderCreateReplaceableCompositeType;
            const createMemberType = bindings.NativityLLVMDebugInfoBuilderCreateMemberType;
            const createBitfieldMemberType = bindings.NativityLLVMDebugInfoBuilderCreateBitfieldMemberType;
            const insertDeclare = bindings.NativityLLVMDebugInfoBuilderInsertDeclare;
            const finalizeSubprogram = bindings.NativityLLVMDebugInfoBuilderFinalizeSubprogram;
            const finalize = bindings.NativityLLVMDebugInfoBuilderFinalize;
            const replaceCompositeTypes = bindings.NativityLLVMDebugInfoBuilderCompositeTypeReplaceTypes;
        };

        pub const CompileUnit = opaque {
            fn toScope(this: *@This()) *LLVM.DebugInfo.Scope {
                return @ptrCast(this);
            }

            pub const EmissionKind = enum(c_uint) {
                no_debug = 0,
                full_debug = 1,
                line_tables_only = 2,
                debug_directives_only = 3,
            };

            pub const NameTableKind = enum(c_uint) {
                default = 0,
                gnu = 1,
                none = 2,
            };
        };

        pub const Expression = opaque {};

        pub const GlobalVariableExpression = opaque {};

        pub const LocalVariable = opaque {};
        pub const LexicalBlock = opaque {
            fn toScope(this: *@This()) *LLVM.DebugInfo.Scope {
                return @ptrCast(this);
            }
        };

        pub const Node = opaque {
            pub const Flags = packed struct(u32) {
                visibility: Visibility,
                forward_declaration: bool,
                apple_block: bool,
                block_by_ref_struct: bool,
                virtual: bool,
                artificial: bool,
                explicit: bool,
                prototyped: bool,
                objective_c_class_complete: bool,
                object_pointer: bool,
                vector: bool,
                static_member: bool,
                lvalue_reference: bool,
                rvalue_reference: bool,
                reserved: bool = false,
                inheritance: Inheritance,
                introduced_virtual: bool,
                bit_field: bool,
                no_return: bool,
                type_pass_by_value: bool,
                type_pass_by_reference: bool,
                enum_class: bool,
                thunk: bool,
                non_trivial: bool,
                big_endian: bool,
                little_endian: bool,
                all_calls_described: bool,
                _: u3 = 0,

                const Visibility = enum(u2) {
                    none = 0,
                    private = 1,
                    protected = 2,
                    public = 3,
                };
                const Inheritance = enum(u2) {
                    none = 0,
                    single = 1,
                    multiple = 2,
                    virtual = 3,
                };
            };
        };

        pub const File = opaque {
            fn toScope(this: *@This()) *LLVM.DebugInfo.Scope {
                return @ptrCast(this);
            }
        };

        pub const Language = enum(c_uint) {
            c = 0x02,
            c11 = 0x1d,
        };

        pub const Scope = opaque {
            const toSubprogram = bindings.NativityLLVMDebugInfoScopeToSubprogram;
        };

        pub const LocalScope = opaque {
            fn toScope(this: *@This()) *LLVM.DebugInfo.Scope {
                return @ptrCast(this);
            }
        };
        pub const Subprogram = opaque {
            const getFile = bindings.NativityLLVMDebugInfoSubprogramGetFile;
            const getArgumentType = bindings.NativityLLVMDebugInfoSubprogramGetArgumentType;
            fn toLocalScope(this: *@This()) *LocalScope {
                return @ptrCast(this);
            }

            pub const Flags = packed struct(u32) {
                virtuality: Virtuality,
                local_to_unit: bool,
                definition: bool,
                optimized: bool,
                pure: bool,
                elemental: bool,
                recursive: bool,
                main_subprogram: bool,
                deleted: bool,
                reserved: bool = false,
                object_c_direct: bool,
                _: u20 = 0,

                const Virtuality = enum(u2) {
                    none = 0,
                    virtual = 1,
                    pure_virtual = 2,
                };
            };
        };

        pub const Type = opaque {
            const isResolved = bindings.NativityLLLVMDITypeIsResolved;
            fn toScope(this: *@This()) *LLVM.DebugInfo.Scope {
                return @ptrCast(this);
            }

            pub const Derived = opaque {
                fn toType(this: *@This()) *LLVM.DebugInfo.Type {
                    return @ptrCast(this);
                }
            };

            pub const Composite = opaque {
                fn toType(this: *@This()) *LLVM.DebugInfo.Type {
                    return @ptrCast(this);
                }
            };

            pub const Enumerator = opaque {};
            pub const Subroutine = opaque {
                fn toType(this: *@This()) *LLVM.DebugInfo.Type {
                    return @ptrCast(this);
                }
            };
        };
    };

    pub const FloatAbi = enum(c_uint) {
        default = 0,
        soft = 1,
        hard = 2,
    };

    pub const FloatOperationFusionMode = enum(c_uint) {
        fast = 0,
        standard = 1,
        strict = 2,
    };

    pub const JumpTableType = enum(c_uint) {
        single = 0,
        arity = 1,
        simplified = 2,
        full = 3,
    };

    pub const ThreadModel = enum(c_uint) {
        posix = 0,
        single = 1,
    };

    pub const BasicBlockSection = enum(c_uint) {
        all = 0,
        list = 1,
        labels = 2,
        preset = 3,
        none = 4,
    };

    pub const EAbi = enum(c_uint) {
        unknown = 0,
        default = 1,
        eabi4 = 2,
        eabi5 = 3,
        gnu = 4,
    };

    pub const DebuggerKind = enum(c_uint) {
        default = 0,
        gdb = 1,
        lldb = 2,
        sce = 3,
        dbx = 4,
    };

    pub const GlobalISelAbortMode = enum(c_uint) {
        disable = 0,
        enable = 1,
        disable_with_diagnostic = 2,
    };

    pub const DebugCompressionType = enum(c_uint) {
        none = 0,
        zlib = 1,
        zstd = 2,
    };

    pub const RelocationModel = enum(c_uint) {
        static = 0,
        pic = 1,
        dynamic_no_pic = 2,
        ropi = 3,
        rwpi = 4,
        ropi_rwpi = 5,
    };

    pub const CodeModel = enum(c_uint) {
        tiny = 0,
        small = 1,
        kernel = 2,
        medium = 3,
        large = 4,
    };

    pub const PicLevel = enum(c_uint) {
        not_pic = 0,
        small_pic = 1,
        big_pic = 2,
    };

    pub const PieLevel = enum(c_uint) {
        default = 0,
        small = 1,
        large = 2,
    };

    pub const TlsModel = enum(c_uint) {
        general_dynamic = 0,
        local_dynamic = 1,
        initial_exec = 2,
        local_exec = 3,
    };

    pub const CodegenOptimizationLevel = enum(c_int) {
        none = 0,
        less = 1,
        default = 2,
        aggressive = 3,
    };

    pub const OptimizationLevel = extern struct {
        speed_level: c_uint,
        size_level: c_uint,
    };

    pub const FramePointerKind = enum(c_uint) {
        none = 0,
        non_leaf = 1,
        all = 2,
    };

    pub const CodeGenFileType = enum(c_uint) {
        assembly = 0,
        object = 1,
        null = 2,
    };

    pub const Target = opaque {
        const createTargetMachine = bindings.NativityLLVMTargetCreateTargetMachine;

        pub const Machine = opaque {};

        // This is a non-LLVM struct
        const Options = extern struct {
            bin_utils_version: struct { i32, i32 },
            fp_math: extern struct {
                unsafe: bool,
                no_infs: bool,
                no_nans: bool,
                no_traping: bool,
                no_signed_zeroes: bool,
                approx_func: bool,
                enable_aix_extended_altivec_abi: bool,
                honor_sign_dependent_rounding: bool,
            },
            no_zeroes_in_bss: bool,
            guaranteed_tail_call_optimization: bool,
            stack_symbol_ordering: bool,
            enable_fast_isel: bool,
            enable_global_isel: bool,
            global_isel_abort_mode: GlobalISelAbortMode,
            use_init_array: bool,
            disable_integrated_assembler: bool,
            debug_compression_type: DebugCompressionType,
            relax_elf_relocations: bool,
            function_sections: bool,
            data_sections: bool,
            ignore_xcoff_visibility: bool,
            xcoff_traceback_table: bool,
            unique_section_names: bool,
            unique_basic_block_section_names: bool,
            trap_unreachable: bool,
            no_trap_after_noreturn: bool,
            tls_size: u8,
            emulated_tls: bool,
            enable_ipra: bool,
            emit_stack_size_section: bool,
            enable_machine_outliner: bool,
            enable_machine_function_splitter: bool,
            support_default_outlining: bool,
            emit_address_significance_table: bool,
            bb_sections: BasicBlockSection,
            emit_call_site_info: bool,
            support_debug_entry_values: bool,
            enable_debug_entry_values: bool,
            value_tracking_variable_locations: bool,
            force_dwarf_frame_section: bool,
            xray_function_index: bool,
            debug_strict_dwarf: bool,
            hotpatch: bool,
            ppc_gen_scalar_mass_entries: bool,
            jmc_instrument: bool,
            cfi_fixup: bool,
            loop_alignment: u32 = 0,
            float_abi_type: FloatAbi,
            fp_operation_fusion: FloatOperationFusionMode,
            thread_model: ThreadModel,
            eabi_version: EAbi,
            debugger_tuning: DebuggerKind,
        };
    };

    const lookupIntrinsic = bindings.NativityLLVMLookupIntrinsic;
    const newPhiNode = bindings.NativityLLVMCreatePhiNode;

    pub const Metadata = opaque {
        pub const Node = opaque {};
        pub const Tuple = opaque {};
    };

    pub const Attribute = opaque {
        pub const Set = opaque {};
        pub const Id = enum(u32) {
            AllocAlign = 1,
            AllocatedPointer = 2,
            AlwaysInline = 3,
            Builtin = 4,
            Cold = 5,
            Convergent = 6,
            CoroDestroyOnlyWhenComplete = 7,
            DeadOnUnwind = 8,
            DisableSanitizerInstrumentation = 9,
            FnRetThunkExtern = 10,
            Hot = 11,
            ImmArg = 12,
            InReg = 13,
            InlineHint = 14,
            JumpTable = 15,
            MinSize = 16,
            MustProgress = 17,
            Naked = 18,
            Nest = 19,
            NoAlias = 20,
            NoBuiltin = 21,
            NoCallback = 22,
            NoCapture = 23,
            NoCfCheck = 24,
            NoDuplicate = 25,
            NoFree = 26,
            NoImplicitFloat = 27,
            NoInline = 28,
            NoMerge = 29,
            NoProfile = 30,
            NoRecurse = 31,
            NoRedZone = 32,
            NoReturn = 33,
            NoSanitizeBounds = 34,
            NoSanitizeCoverage = 35,
            NoSync = 36,
            NoUndef = 37,
            NoUnwind = 38,
            NonLazyBind = 39,
            NonNull = 40,
            NullPointerIsValid = 41,
            OptForFuzzing = 42,
            OptimizeForDebugging = 43,
            OptimizeForSize = 44,
            OptimizeNone = 45,
            PresplitCoroutine = 46,
            ReadNone = 47,
            ReadOnly = 48,
            Returned = 49,
            ReturnsTwice = 50,
            SExt = 51,
            SafeStack = 52,
            SanitizeAddress = 53,
            SanitizeHWAddress = 54,
            SanitizeMemTag = 55,
            SanitizeMemory = 56,
            SanitizeThread = 57,
            ShadowCallStack = 58,
            SkipProfile = 59,
            Speculatable = 60,
            SpeculativeLoadHardening = 61,
            StackProtect = 62,
            StackProtectReq = 63,
            StackProtectStrong = 64,
            StrictFP = 65,
            SwiftAsync = 66,
            SwiftError = 67,
            SwiftSelf = 68,
            WillReturn = 69,
            Writable = 70,
            WriteOnly = 71,
            ZExt = 72,
            ByRef = 73,
            ByVal = 74,
            ElementType = 75,
            InAlloca = 76,
            Preallocated = 77,
            StructRet = 78,
            Alignment = 79,
            AllocKind = 80,
            AllocSize = 81,
            Dereferenceable = 82,
            DereferenceableOrNull = 83,
            Memory = 84,
            NoFPClass = 85,
            StackAlignment = 86,
            UWTable = 87,
            VScaleRange = 88,
        };
    };

    pub const Type = opaque {
        const compare = bindings.NativityLLVMCompareTypes;
        const toStruct = bindings.NativityLLVMTypeToStruct;
        const toFunction = bindings.NativityLLVMTypeToFunction;
        const toArray = bindings.NativityLLVMTypeToArray;
        const toPointer = bindings.NativityLLVMTypeToPointer;
        const isPointer = bindings.NativityLLVMTypeIsPointer;
        const isInteger = bindings.NativityLLVMTypeIsInteger;
        const isVoid = bindings.NativityLLVMTypeIsVoid;
        const assertEqual = bindings.NativityLLVMTypeAssertEqual;
        const getPoison = bindings.NativityLLVMGetPoisonValue;
        const getContext = bindings.NativityLLVMTypeGetContext;

        pub const Array = opaque {
            fn toType(integer: *@This()) *LLVM.Type {
                return @ptrCast(integer);
            }
            const get = bindings.NativityLLVMGetArrayType;
            const getConstant = bindings.NativityLLVMGetConstantArray;
            const getElementType = bindings.NativityLLVMArrayTypeGetElementType;
        };

        pub const Integer = opaque {
            fn toType(integer: *@This()) *LLVM.Type {
                return @ptrCast(integer);
            }
        };

        pub const Function = opaque {
            fn toType(integer: *@This()) *LLVM.Type {
                return @ptrCast(integer);
            }

            const getArgumentType = bindings.NativityLLVMFunctionTypeGetArgumentType;
            const getReturnType = bindings.NativityLLVMFunctionTypeGetReturnType;
        };

        pub const Pointer = opaque {
            fn toType(integer: *@This()) *LLVM.Type {
                return @ptrCast(integer);
            }

            const getNull = bindings.NativityLLVMPointerTypeGetNull;
        };

        pub const Struct = opaque {
            const getConstant = bindings.NativityLLVMGetConstantStruct;
            fn toType(integer: *@This()) *LLVM.Type {
                return @ptrCast(integer);
            }
        };

        pub const Error = error{
            void,
            function,
            integer,
            pointer,
            @"struct",
            intrinsic,
            array,
        };

    };

    pub const Value = opaque {
        const setName = bindings.NativityLLVMValueSetName;
        const getType = bindings.NativityLLVMValueGetType;
        const getContext = bindings.NativityLLVMValueGetContext;
        const toConstant = bindings.NativityLLVMValueToConstant;
        const toFunction = bindings.NativityLLVMValueToFunction;
        const toAlloca = bindings.NativityLLVMValueToAlloca;
        const toBasicBlock = bindings.NativityLLVMValueToBasicBlock;
        const toString = bindings.NativityLLVMValueToString;

        pub const IntrinsicID = enum(u32) {
            none = 0,
            _,
        };

        pub const BasicBlock = opaque {
            const remove = bindings.NativityLLVMBasicBlockRemoveFromParent;
            fn toValue(this: *@This()) *LLVM.Value {
                return @ptrCast(this);
            }
        };

        pub const Argument = opaque {
            const getIndex = bindings.NativityLLVMArgumentGetIndex;
            fn toValue(this: *@This()) *LLVM.Value {
                return @ptrCast(this);
            }
        };

        pub const Instruction = opaque {
            fn toValue(this: *@This()) *LLVM.Value {
                return @ptrCast(this);
            }

            pub const Alloca = opaque {
                fn toValue(this: *@This()) *LLVM.Value {
                    return @ptrCast(this);
                }

                const getAllocatedType = bindings.NativityLLVMAllocatGetAllocatedType;
            };

            pub const Branch = opaque {
                fn toValue(this: *@This()) *LLVM.Value {
                    return @ptrCast(this);
                }
            };

            pub const Call = opaque {
                const setCallingConvention = bindings.NativityLLVMCallSetCallingConvention;
                const setAttributes = bindings.NativityLLVMCallSetAttributes;
                fn toValue(this: *@This()) *LLVM.Value {
                    return @ptrCast(this);
                }
            };

            pub const Cast = opaque {
                pub const Type = enum(c_uint) {
                    truncate = 38,
                    zero_extend = 39,
                    sign_extend = 40,
                    float_to_unsigned_integer = 41,
                    float_to_signed_integer = 42,
                    unsigned_integer_to_float = 43,
                    signed_integer_to_float = 44,
                    float_truncate = 45,
                    float_extend = 46,
                    pointer_to_int = 47,
                    int_to_pointer = 48,
                    bitcast = 49,
                    address_space_cast = 50,
                };

                fn toValue(this: *@This()) *LLVM.Value {
                    return @ptrCast(this);
                }
            };

            pub const ICmp = opaque {
                fn toValue(this: *@This()) *LLVM.Value {
                    return @ptrCast(this);
                }

                pub const Kind = enum(c_uint) {
                    eq = 32, // equal
                    ne = 33, // not equal
                    ugt = 34, // unsigned greater than
                    uge = 35, // unsigned greater or equal
                    ult = 36, // unsigned less than
                    ule = 37, // unsigned less or equal
                    sgt = 38, // signed greater than
                    sge = 39, // signed greater or equal
                    slt = 40, // signed less than
                    sle = 41, // signed less or equal
                };
            };

            pub const Load = opaque {
                fn toValue(this: *@This()) *LLVM.Value {
                    return @ptrCast(this);
                }
            };

            pub const PhiNode = opaque {
                pub const addIncoming = bindings.NativityLLVMPhiAddIncoming;

                fn toValue(this: *@This()) *LLVM.Value {
                    return @ptrCast(this);
                }
            };

            pub const Store = opaque {
                fn toValue(this: *@This()) *LLVM.Value {
                    return @ptrCast(this);
                }
            };

            pub const Switch = opaque {
                fn toValue(this: *@This()) *LLVM.Value {
                    return @ptrCast(this);
                }
            };

            pub const Ret = opaque {
                fn toValue(this: *@This()) *LLVM.Value {
                    return @ptrCast(this);
                }
            };

            pub const Unreachable = opaque {
                fn toValue(this: *@This()) *LLVM.Value {
                    return @ptrCast(this);
                }
            };

            pub const Error = error{
                add,
                alloca,
                @"and",
                arithmetic_shift_right,
                call,
                cast,
                conditional_branch,
                extract_value,
                gep,
                icmp,
                insert_value,
                load,
                logical_shift_right,
                multiply,
                @"or",
                ret,
                sdiv,
                shift_left,
                store,
                udiv,
                @"unreachable",
                xor,
            };
        };

        pub const Constant = opaque {
            pub const Function = opaque {
                const getArgument = bindings.NativityLLVMFunctionGetArgument;
                const getArguments = bindings.NativityLLVMFunctionGetArguments;
                const getType = bindings.NativityLLVMFunctionGetType;
                // const addAttributeKey = bindings.NativityLLVMFunctionAddAttributeKey;
                const verify = bindings.NativityLLVMVerifyFunction;
                const toString = bindings.NativityLLVMFunctionToString;
                const setCallingConvention = bindings.NativityLLVMFunctionSetCallingConvention;
                const getCallingConvention = bindings.NativityLLVMFunctionGetCallingConvention;
                const setSubprogram = bindings.NativityLLVMFunctionSetSubprogram;
                const getSubprogram = bindings.NativityLLVMFunctionGetSubprogram;
                const setAttributes = bindings.NativityLLVMFunctionSetAttributes;

                fn toValue(this: *@This()) *LLVM.Value {
                    return @ptrCast(this);
                }

                fn toConstant(this: *@This()) *Constant {
                    return @ptrCast(this);
                }

                pub const CallingConvention = enum(c_uint) {
                    /// The default llvm calling convention, compatible with C. This convention
                    /// is the only one that supports varargs calls. As with typical C calling
                    /// conventions, the callee/caller have to tolerate certain amounts of
                    /// prototype mismatch.
                    C = 0,

                    // Generic LLVM calling conventions. None of these support varargs calls,
                    // and all assume that the caller and callee prototype exactly match.

                    /// Attempts to make calls as fast as possible (e.g. by passing things in
                    /// registers).
                    Fast = 8,

                    /// Attempts to make code in the caller as efficient as possible under the
                    /// assumption that the call is not commonly executed. As such, these calls
                    /// often preserve all registers so that the call does not break any live
                    /// ranges in the caller side.
                    Cold = 9,

                    /// Used by the Glasgow Haskell Compiler (GHC).
                    GHC = 10,

                    /// Used by the High-Performance Erlang Compiler (HiPE).
                    HiPE = 11,

                    /// Used for stack based JavaScript calls
                    WebKit_JS = 12,

                    /// Used for dynamic register based calls (e.g. stackmap and patchpoint
                    /// intrinsics).
                    AnyReg = 13,

                    /// Used for runtime calls that preserves most registers.
                    PreserveMost = 14,

                    /// Used for runtime calls that preserves (almost) all registers.
                    PreserveAll = 15,

                    /// Calling convention for Swift.
                    Swift = 16,

                    /// Used for access functions.
                    CXX_FAST_TLS = 17,

                    /// Attemps to make calls as fast as possible while guaranteeing that tail
                    /// call optimization can always be performed.
                    Tail = 18,

                    /// Special calling convention on Windows for calling the Control Guard
                    /// Check ICall funtion. The function takes exactly one argument (address of
                    /// the target function) passed in the first argument register, and has no
                    /// return value. All register values are preserved.
                    CFGuard_Check = 19,

                    /// This follows the Swift calling convention in how arguments are passed
                    /// but guarantees tail calls will be made by making the callee clean up
                    /// their stack.
                    SwiftTail = 20,

                    /// This is the start of the target-specific calling conventions, e.g.
                    /// fastcall and thiscall on X86.
                    // FirstTargetCC = 64,

                    /// stdcall is mostly used by the Win32 API. It is basically the same as the
                    /// C convention with the difference in that the callee is responsible for
                    /// popping the arguments from the stack.
                    X86_StdCall = 64,

                    /// 'fast' analog of X86_StdCall. Passes first two arguments in ECX:EDX
                    /// registers, others - via stack. Callee is responsible for stack cleaning.
                    X86_FastCall = 65,

                    /// ARM Procedure Calling Standard (obsolete, but still used on some
                    /// targets).
                    ARM_APCS = 66,

                    /// ARM Architecture Procedure Calling Standard calling convention (aka
                    /// EABI). Soft float variant.
                    ARM_AAPCS = 67,

                    /// Same as ARM_AAPCS, but uses hard floating point ABI.
                    ARM_AAPCS_VFP = 68,

                    /// Used for MSP430 interrupt routines.
                    MSP430_INTR = 69,

                    /// Similar to X86_StdCall. Passes first argument in ECX, others via stack.
                    /// Callee is responsible for stack cleaning. MSVC uses this by default for
                    /// methods in its ABI.
                    X86_ThisCall = 70,

                    /// Call to a PTX kernel. Passes all arguments in parameter space.
                    PTX_Kernel = 71,

                    /// Call to a PTX device function. Passes all arguments in register or
                    /// parameter space.
                    PTX_Device = 72,

                    /// Used for SPIR non-kernel device functions. No lowering or expansion of
                    /// arguments. Structures are passed as a pointer to a struct with the
                    /// byval attribute. Functions can only call SPIR_FUNC and SPIR_KERNEL
                    /// functions. Functions can only have zero or one return values. Variable
                    /// arguments are not allowed, except for printf. How arguments/return
                    /// values are lowered are not specified. Functions are only visible to the
                    /// devices.
                    SPIR_FUNC = 75,

                    /// Used for SPIR kernel functions. Inherits the restrictions of SPIR_FUNC,
                    /// except it cannot have non-void return values, it cannot have variable
                    /// arguments, it can also be called by the host or it is externally
                    /// visible.
                    SPIR_KERNEL = 76,

                    /// Used for Intel OpenCL built-ins.
                    Intel_OCL_BI = 77,

                    /// The C convention as specified in the x86-64 supplement to the System V
                    /// ABI, used on most non-Windows systems.
                    X86_64_SysV = 78,

                    /// The C convention as implemented on Windows/x86-64 and AArch64. It
                    /// differs from the more common \c X86_64_SysV convention in a number of
                    /// ways, most notably in that XMM registers used to pass arguments are
                    /// shadowed by GPRs, and vice versa. On AArch64, this is identical to the
                    /// normal C (AAPCS) calling convention for normal functions, but floats are
                    /// passed in integer registers to variadic functions.
                    Win64 = 79,

                    /// MSVC calling convention that passes vectors and vector aggregates in SSE
                    /// registers.
                    X86_VectorCall = 80,

                    /// Used by HipHop Virtual Machine (HHVM) to perform calls to and from
                    /// translation cache, and for calling PHP functions. HHVM calling
                    /// convention supports tail/sibling call elimination.
                    HHVM = 81,

                    /// HHVM calling convention for invoking C/C++ helpers.
                    HHVM_C = 82,

                    /// x86 hardware interrupt context. Callee may take one or two parameters,
                    /// where the 1st represents a pointer to hardware context frame and the 2nd
                    /// represents hardware error code, the presence of the later depends on the
                    /// interrupt vector taken. Valid for both 32- and 64-bit subtargets.
                    X86_INTR = 83,

                    /// Used for AVR interrupt routines.
                    AVR_INTR = 84,

                    /// Used for AVR signal routines.
                    AVR_SIGNAL = 85,

                    /// Used for special AVR rtlib functions which have an "optimized"
                    /// convention to preserve registers.
                    AVR_BUILTIN = 86,

                    /// Used for Mesa vertex shaders, or AMDPAL last shader stage before
                    /// rasterization (vertex shader if tessellation and geometry are not in
                    /// use, or otherwise copy shader if one is needed).
                    AMDGPU_VS = 87,

                    /// Used for Mesa/AMDPAL geometry shaders.
                    AMDGPU_GS = 88,

                    /// Used for Mesa/AMDPAL pixel shaders.
                    AMDGPU_PS = 89,

                    /// Used for Mesa/AMDPAL compute shaders.
                    AMDGPU_CS = 90,

                    /// Used for AMDGPU code object kernels.
                    AMDGPU_KERNEL = 91,

                    /// Register calling convention used for parameters transfer optimization
                    X86_RegCall = 92,

                    /// Used for Mesa/AMDPAL hull shaders (= tessellation control shaders).
                    AMDGPU_HS = 93,

                    /// Used for special MSP430 rtlib functions which have an "optimized"
                    /// convention using additional registers.
                    MSP430_BUILTIN = 94,

                    /// Used for AMDPAL vertex shader if tessellation is in use.
                    AMDGPU_LS = 95,

                    /// Used for AMDPAL shader stage before geometry shader if geometry is in
                    /// use. So either the domain (= tessellation evaluation) shader if
                    /// tessellation is in use, or otherwise the vertex shader.
                    AMDGPU_ES = 96,

                    /// Used between AArch64 Advanced SIMD functions
                    AArch64_VectorCall = 97,

                    /// Used between AArch64 SVE functions
                    AArch64_SVE_VectorCall = 98,

                    /// For emscripten __invoke_* functions. The first argument is required to
                    /// be the function ptr being indirectly called. The remainder matches the
                    /// regular calling convention.
                    WASM_EmscriptenInvoke = 99,

                    /// Used for AMD graphics targets.
                    AMDGPU_Gfx = 100,

                    /// Used for M68k interrupt routines.
                    M68k_INTR = 101,

                    /// Preserve X0-X13, X19-X29, SP, Z0-Z31, P0-P15.
                    AArch64_SME_ABI_Support_Routines_PreserveMost_From_X0 = 102,

                    /// Preserve X2-X15, X19-X29, SP, Z0-Z31, P0-P15.
                    AArch64_SME_ABI_Support_Routines_PreserveMost_From_X2 = 103,

                    /// The highest possible ID. Must be some 2^k - 1.
                    MaxID = 1023,
                };
            };

            pub const Int = opaque {
                fn toValue(this: *@This()) *LLVM.Value {
                    return @ptrCast(this);
                }
                fn toConstant(this: *@This()) *Constant {
                    return @ptrCast(this);
                }
            };

            pub const GlobalObject = opaque{
                const setAlignment = bindings.NativityLLVMGlobalObjectSetAlignment;
            };

            pub const GlobalVariable = opaque {
                pub const setInitializer = bindings.NativityLLVMGlobalVariableSetInitializer;
                pub const addDebugInfo = bindings.NativityLLVMDebugInfoGlobalVariableAddDebugInfo;

                fn toValue(this: *@This()) *LLVM.Value {
                    return @ptrCast(this);
                }
                fn toConstant(this: *@This()) *Constant {
                    return @ptrCast(this);
                }

                fn toGlobalObject(this: *@This()) *LLVM.Value.Constant.GlobalObject{
                    return @ptrCast(this);
                }
            };

            pub const PointerNull = opaque {
                fn toValue(this: *@This()) *LLVM.Value {
                    return @ptrCast(this);
                }
                fn toConstant(this: *@This()) *Constant {
                    return @ptrCast(this);
                }
            };

            pub const Undefined = opaque {
                fn toConstant(this: *@This()) *Constant {
                    return @ptrCast(this);
                }
                fn toValue(this: *@This()) *LLVM.Value {
                    return @ptrCast(this);
                }
            };

            pub const Poison = opaque {
                fn toConstant(this: *@This()) *Constant {
                    return @ptrCast(this);
                }
                fn toValue(this: *@This()) *LLVM.Value {
                    return @ptrCast(this);
                }
            };

            fn toValue(this: *@This()) *LLVM.Value {
                return @ptrCast(this);
            }

            const toInt = bindings.NativityLLVMConstantToInt;
        };

        pub const InlineAssembly = opaque {
            pub const Dialect = enum(c_uint) {
                @"at&t",
                intel,
            };
            const get = bindings.NativityLLVMGetInlineAssembly;
            fn toValue(this: *@This()) *LLVM.Value {
                return @ptrCast(this);
            }
        };

        pub const Error = error{
            constant_struct,
            constant_int,
            constant_array,
            inline_assembly,
            global_variable,
            intrinsic,
        };
    };
};

pub fn panic(message: []const u8, stack_trace: ?*std.builtin.StackTrace, return_address: ?usize) noreturn {
    @setCold(true);
    const print_stack_trace = configuration.print_stack_trace;
    switch (print_stack_trace) {
        true => @call(.always_inline, std.builtin.default_panic, .{ message, stack_trace, return_address }),
        false => {
            compiler.write("\nPANIC: ");
            compiler.write(message);
            compiler.write("\n");
            fail();
        },
    }
}
