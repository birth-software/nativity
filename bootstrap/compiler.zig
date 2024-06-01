const compiler = @This();
const configuration = @import("configuration");
const std = @import("std");
const builtin = @import("builtin");
const library = @import("library.zig");
const assert = library.assert;
const Arena = library.Arena;
const PinnedArray = library.PinnedArray;
const PinnedHashMap = library.PinnedHashMap;
const hash_bytes = library.my_hash;
const byte_equal = library.byte_equal;
const Atomic = std.atomic.Value;

const weak_memory_model = switch (builtin.cpu.arch) {
    .aarch64 => true,
    .x86_64 => false,
    else => @compileError("Error: unknown arch"),
};

fn exit(exit_code: u8) noreturn {
    @setCold(true);
    // if (builtin.mode == .Debug) {
        if (exit_code != 0) @breakpoint();
    // }
    std.posix.exit(exit_code);
}

fn is_space(ch: u8) bool {
    const is_whitespace = ch == ' ';
    const is_tab = ch == '\t';
    const is_line_feed = ch == '\n';
    const is_carry_return = ch == '\r';
    const result = (is_whitespace or is_tab) or (is_line_feed or is_carry_return);
    return result;
}

pub fn write(string: []const u8) void {
    std.io.getStdOut().writeAll(string) catch unreachable;
}

fn exit_with_error(string: []const u8) noreturn {
    @setCold(true);
    write("error: ");
    write(string);
    write("\n");
    exit(1);
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

    const Attributes = struct{
        @"export": bool = false,
        @"extern": bool = false,
    };
    const Attribute = enum{
        @"export",
        @"extern",

        const Mask = std.EnumSet(Attribute);
    };
};

const Mutability = enum(u1){
    @"const" = 0,
    @"var" = 1,
};

const ArgumentSymbol = struct {
    attributes: Attributes = .{},
    argument_declaration: ArgumentDeclaration,
    type: *Type,
    value: Value,
    instruction: Instruction,
    alignment: u32,

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
    current_line: u32 = 0,
    line_offset: u32 = 0,

    fn skip_space(parser: *Parser, file: []const u8) void {
        const original_i = parser.i;

        if (!is_space(file[original_i])) return;

        while (parser.i < file.len) : (parser.i += 1) {
            const ch = file[parser.i];
            const new_line = ch == '\n';
            parser.current_line += @intFromBool(new_line);

            if (new_line) {
                parser.line_offset = @intCast(parser.i);
            }

            if (!is_space(ch)) {
                return;
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
                            exit(1);
                        }
                    }

                    const identifier = file[identifier_start..parser.i];
                    return identifier;
                }
            } else {
                exit(1);
            }
        } else {
            exit(1);
        }
    }

    fn parse_identifier(parser: *Parser, thread: *Thread, file: []const u8) u32 {
        const identifier = parser.parse_raw_identifier(file);
        if (identifier[0] != '"') {
            const keyword = parse_keyword(identifier);
            if (keyword != ~(@as(u32, 0))) {
                exit(1);
            }
        }
        const hash = intern_identifier(&thread.identifiers, identifier);
        return hash;
    }

    fn parse_non_escaped_string_literal(parser: *Parser, src: []const u8) []const u8 {
        const start = parser.i;
        const is_double_quote = src[start] == '"';
        parser.i += @intFromBool(is_double_quote);

        if (!is_double_quote) {
            exit(1);
        }

        while (src[parser.i] != '"') : (parser.i += 1) {
            if (src[parser.i] == '\\') exit(1);
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
                exit(1);
            }
        } else {
            exit(1);
        }
    }

    pub fn parse_hex(slice: []const u8) u64 {
        var i = slice.len;
        var integer: u64 = 0;
        var factor: u64 = 1;

        while (i > 0) {
            i -= 1;
            const ch = slice[i];
            switch (ch) {
                '0'...'9' => {
                    const int = ch - '0';
                    const extra = int * factor;
                    integer += extra;
                    factor *= 16;
                },
                'a'...'f' => {
                    const int = ch - 'a' + 10;
                    const extra = int * factor;
                    integer += extra;
                    factor *= 16;
                },
                'A'...'F' => {
                    const int = ch - 'A' + 10;
                    const extra = int * factor;
                    integer += extra;
                    factor *= 16;
                },
                else => exit(1),
            }
        }

        return integer;
    }

    fn parse_type_expression(parser: *Parser, thread: *Thread, src: []const u8) *Type {
        const starting_ch = src[parser.i];
        const is_start_u = starting_ch == 'u';
        const is_start_s = starting_ch == 's';
        const float_start = starting_ch == 'f';
        const integer_start = is_start_s or is_start_u;
        const is_number_type_start = integer_start or float_start;

        if (is_number_type_start) {
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
                        else => exit(1),
                    };
                    parser.i += decimal_digit_count;

                    const index = bit_count - 1 + @intFromEnum(signedness) * @as(usize, 64);
                    const result = &thread.integers[index];
                    assert(result.bit_count == bit_count);
                    assert(result.signedness == signedness);
                    return &result.type;
                } else if (float_start) {
                    exit(1);
                } else {
                    unreachable;
                }
            } else {
                exit(1);
            }
        } else {
            exit_with_error("Unrecognized type expression");
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
            const is_valid_after_zero = is_space(follow_up_character) or (!follow_up_digit and !follow_up_alpha);

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

                        const constant_int = thread.constant_ints.append(.{
                            .value = .{
                                .sema = .{
                                    .thread = thread.get_index(),
                                    .resolved = true,
                                    .id = .constant_int,
                                },
                            },
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
                exit(1);
            } else if (is_valid_after_zero) {
                parser.i += 1;
                const constant_int = thread.constant_ints.append(.{
                    .value = .{
                        .sema = .{
                            .thread = thread.get_index(),
                            .resolved = true,
                            .id = .constant_int,
                        },
                        },
                    .n = 0,
                    .type = ty,
                });
                return constant_int;
            } else {
                exit(1);
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

        const constant_int = thread.constant_ints.append(.{
            .value = .{
                .sema = .{
                    .thread = thread.get_index(),
                    .resolved = true,
                    .id = .constant_int,
                },
                },
            .n = integer,
            .type = ty,
        });

        return constant_int;
    }

    fn parse_single_expression(parser: *Parser, analyzer: *Analyzer, thread: *Thread, file: *File, maybe_type: ?*Type, side: Side) *Value {

        const src = file.source_code;
        const Unary = enum{
            none,
            one_complement,
        };
        const unary: Unary = switch (src[parser.i]) {
            'A'...'Z', 'a'...'z', '_' => Unary.none,
            '0'...'9' => Unary.none,
            '~' => block: {
                parser.i += 1;
                break :block .one_complement;
            },
            else => unreachable,
        };
        _ = side; // autofix
        const starting_index = parser.i;
        const starting_ch = src[starting_index];
        const is_digit_start = is_decimal_digit(starting_ch);
        const is_alpha_start = is_alphabetic(starting_ch);

        if (is_digit_start) {
            assert(unary == .none);
            const ty = maybe_type orelse exit(1);
            switch (ty.sema.id) {
                .integer => {
                    const constant_int = parser.parse_constant_integer(thread, file, ty);
                    return &constant_int.value;
                },
                else => unreachable,
            }
        } else if (is_alpha_start) {
            var resolved = true;
            const identifier = parser.parse_identifier(thread, src);

            if (analyzer.current_scope.get_declaration(identifier)) |lookup_result| {
                switch (src[parser.i]) {
                    '(' => {
                        parser.i += 1;
                        parser.skip_space(src);

                        switch (lookup_result.declaration.*.id) {
                            .local => unreachable,
                            .global => {
                                const global = lookup_result.declaration.*.get_payload(.global);
                                switch (global.id) {
                                    .function_definition => {
                                        const function_definition = global.get_payload(.function_definition);
                                        const declaration_argument_count = function_definition.declaration.argument_types.len;
                                        var argument_values = PinnedArray(*Value){};
                                        while (true) {
                                            parser.skip_space(src);

                                            if (src[parser.i] == ')') {
                                                break;
                                            }

                                            const argument_index = argument_values.length;
                                            if (argument_index >= declaration_argument_count) {
                                                exit(1);
                                            }
                                            const expected_argument_type = function_definition.declaration.argument_types[argument_index];
                                            const passed_argument_value = parser.parse_expression(analyzer, thread, file, expected_argument_type, .right);
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
                                            .instruction = .{
                                                .value = .{
                                                    .sema = .{
                                                        .thread = thread.get_index(),
                                                        .resolved = true,
                                                        .id = .instruction,
                                                    },
                                                },
                                                .id = .call,
                                            },
                                            .callable = &function_definition.declaration.value,
                                            .arguments = argument_values.const_slice(),
                                        });
                                        _ = analyzer.current_basic_block.instructions.append(&call.instruction);
                                        return &call.instruction.value;
                                    },
                                    else => |t| @panic(@tagName(t)),
                                }
                            },
                            .argument => unreachable,
                        }

                    },
                    '.' => {
                        switch (lookup_result.declaration.*.id) {
                            .global => {
                                const global_declaration = lookup_result.declaration.*.get_payload(.global);
                                switch (global_declaration.id) {
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
                                                    .instruction = .{
                                                        .value = .{
                                                            .sema = .{
                                                                .thread = thread.get_index(),
                                                                .resolved = false,
                                                                .id = .instruction,
                                                            },
                                                        },
                                                        .id = .call,
                                                    },
                                                    .callable = &lazy_expression.value,
                                                    .arguments = &.{},
                                                });
                                                _ = analyzer.current_basic_block.instructions.append(&call.instruction);

                                                _ = file.values_per_import.get(@enumFromInt(import_index)).append(&call.instruction.value);
                                                return &call.instruction.value;
                                            },
                                            else => @panic((src.ptr + parser.i)[0..1]),
                                        }
                                    },
                                    else => |t| @panic(@tagName(t)),
                                }
                            },
                            else => |t| @panic(@tagName(t)),
                        }
                    },
                    ' ', ',', ';', ')' => {
                        const local = switch (lookup_result.declaration.*.id) {
                            .local => block: {
                                const local_declaration = lookup_result.declaration.*.get_payload(.local);
                                const local_symbol = local_declaration.to_symbol();

                                if (maybe_type) |ty| {
                                    switch (typecheck(ty, local_symbol.type)) {
                                        .success => {},
                                    }
                                }

                                const load = thread.loads.append(.{
                                    .instruction = .{
                                        .value = .{
                                            .sema = .{
                                                .thread = thread.get_index(),
                                                .resolved = true,
                                                .id = .instruction,
                                            },
                                        },
                                        .id = .load,
                                    },
                                    .value = &local_symbol.instruction.value,
                                    .type = local_symbol.type,
                                    .alignment = local_symbol.type.alignment,
                                    .is_volatile = false,
                                });
                                _ = analyzer.current_basic_block.instructions.append(&load.instruction);
                                break :block &load.instruction.value;
                            },
                            .argument => block: {
                                const argument_declaration = lookup_result.declaration.*.get_payload(.argument);
                                const argument_symbol = argument_declaration.to_symbol();
                                if (maybe_type) |ty| {
                                    switch (typecheck(ty, argument_symbol.type)) {
                                        .success => {},
                                    }
                                }
                                const load = thread.loads.append(.{
                                    .instruction = .{
                                        .value = .{
                                            .sema = .{
                                                .thread = thread.get_index(),
                                                .resolved = true,
                                                .id = .instruction,
                                            },
                                        },
                                        .id = .load,
                                    },
                                    .value = &argument_symbol.instruction.value,
                                    .type = argument_symbol.type,
                                    .alignment = argument_symbol.type.alignment,
                                    .is_volatile = false,
                                });
                                _ = analyzer.current_basic_block.instructions.append(&load.instruction);
                                break :block &load.instruction.value;
                            },
                            else => |t| @panic(@tagName(t)),
                        };

                        const local_type = local.get_type();

                        return switch (unary) {
                            .none => local,
                            .one_complement => block: {
                                const operand = thread.constant_ints.append(.{
                                    .type = local_type,
                                    .value = .{
                                        .sema = .{
                                            .thread = thread.get_index(),
                                            .resolved = true,
                                            .id = .constant_int,
                                        },
                                    },
                                    .n = std.math.maxInt(u64),
                                });
                                const xor = thread.integer_binary_operations.append(.{
                                    .instruction = .{
                                        .value = .{
                                            .sema = .{
                                                .thread = thread.get_index(),
                                                .resolved = true,
                                                .id = .instruction,
                                            },
                                            },
                                        .id = .integer_binary_operation,
                                    },
                                    .left = local,
                                    .right = &operand.value,
                                    .id = .xor,
                                    .type = local_type,
                                });
                                _ = analyzer.current_basic_block.instructions.append(&xor.instruction);
                                break :block &xor.instruction.value;
                            },
                        };
                    },
                    else => exit(1),
                }
            } else {
                exit_with_error("Unable to find declaration");
            }
        } else {
            exit(1);
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
        compare_unsigned_greater,
        compare_unsigned_greater_equal,
        compare_signed_greater,
        compare_signed_greater_equal,
    };

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
                .compare_equal, .compare_unsigned_greater, .compare_unsigned_greater_equal, .compare_signed_greater, .compare_signed_greater_equal => {
                    switch (current_operation) {
                        else => unreachable,
                        inline .compare_equal, .compare_unsigned_greater, .compare_unsigned_greater_equal, .compare_signed_greater, .compare_signed_greater_equal => |co| {
                            const string = @tagName(co)["compare_".len..];
                            const comparison = @field(IntegerCompare.Id, string);
                            const compare = thread.integer_compares.append(.{
                                .instruction = .{
                                    .value = .{
                                        .sema = .{
                                            .thread = thread.get_index(),
                                            .resolved = true,
                                            .id = .instruction,
                                        },
                                    },
                                    .id = .integer_compare,
                                },
                                .left = previous_value,
                                .right = current_value,
                                .id = comparison,
                            });
                            _ = analyzer.current_basic_block.instructions.append(&compare.instruction);
                            previous_value = &compare.instruction.value;
                        }
                    }
                },
                .add, .sub, .mul, .udiv, .sdiv, .@"and", .@"or", .xor, .shift_left, .arithmetic_shift_right, .logical_shift_right => {
                    const i = thread.integer_binary_operations.append(.{
                        .instruction = .{
                            .value = .{
                                .sema = .{
                                    .thread = thread.get_index(),
                                    .resolved = true,
                                    .id = .instruction,
                                },
                            },
                            .id = .integer_binary_operation,
                        },
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
                    _ = analyzer.current_basic_block.instructions.append(&i.instruction);
                    previous_value = &i.instruction.value;
                },
                .assign, .add_assign, .sub_assign, .mul_assign, .udiv_assign, .sdiv_assign, .and_assign, .or_assign, .xor_assign, .shift_left_assign, .logical_shift_right_assign, .arithmetic_shift_right_assign => unreachable,
            }

            switch (src[parser.i]) {
                ')', ';', ',' => return previous_value,
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
                    // TODO
                    current_operation = undefined;
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
                        else => unreachable,
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

    fn parse_if_expression(parser: *Parser, analyzer: *Analyzer, thread: *Thread, file: *File) void {
        const src = file.source_code;
        parser.i += 2;

        parser.skip_space(src);

        parser.expect_character(src, '(');

        parser.skip_space(src);

        const condition = parser.parse_expression(analyzer, thread, file, null, .right);

        parser.skip_space(src);

        parser.expect_character(src, ')');

        parser.skip_space(src);

        const condition_type = condition.get_type();
        const compare = switch (condition_type.sema.id) {
            .integer => int: {
                const integer_ty = condition_type.get_payload(.integer);
                if (integer_ty.bit_count == 1) {
                    break :int condition;
                } else {
                    const zero = thread.constant_ints.append(.{
                        .value = .{
                            .sema = .{
                                .thread = thread.get_index(),
                                .resolved = true,
                                .id = .constant_int,
                            },
                            },
                        .n = 0,
                        .type = condition_type,
                    });

                    const compare = thread.integer_compares.append(.{
                        .instruction = .{
                            .value = .{
                                .sema = .{
                                    .thread = thread.get_index(),
                                    .resolved = true,
                                    .id = .instruction,
                                },
                                },
                            .id = .integer_compare,
                        },
                        .left = condition,
                        .right = &zero.value,
                        .id = .not_zero,
                    });
                    _ = analyzer.current_basic_block.instructions.append(&compare.instruction);

                    break :int &compare.instruction.value;
                }
            },
            else => |t| @panic(@tagName(t)),
        };

        const original_block = analyzer.current_basic_block;

        const taken_block = create_basic_block(thread);
        const exit_block = create_basic_block(thread);
        _ = analyzer.exit_blocks.append(exit_block);

        const branch = thread.branches.append(.{
            .instruction = .{
                .value = .{
                    .sema = .{
                        .thread = thread.get_index(),
                        .resolved = true,
                        .id = .instruction,
                    },
                    },
                .id = .branch,
            },
            .condition = compare,
            .taken = taken_block,
            .not_taken = exit_block,
        });
        _ = analyzer.current_basic_block.instructions.append(&branch.instruction);
        analyzer.current_basic_block.is_terminated = true;

        analyzer.current_basic_block = branch.taken;
        _ = branch.taken.predecessors.append(original_block);

        switch (src[parser.i]) {
            brace_open => { 
                analyze_local_block(thread, analyzer, parser, file);
            },
            else => @panic((src.ptr + parser.i)[0..1]),
        }

        parser.skip_space(src);

        if (src[parser.i] == 'e') {
            if (byte_equal(src[parser.i..][0.."else".len], "else")) {
                parser.i += "else".len;
                _ = branch.taken.predecessors.append(original_block);
                analyzer.current_basic_block = branch.not_taken;

                parser.skip_space(src);

                switch (src[parser.i]) {
                    brace_open => { 
                        analyze_local_block(thread, analyzer, parser, file);
                    },
                    'i' => {
                        if (src[parser.i + 1] == 'f') {
                            parser.parse_if_expression(analyzer, thread, file);
                        } else {
                            unreachable;
                        }
                    },
                    else => @panic((src.ptr + parser.i)[0..1]),
                }
            } else {
                unreachable;
            }
        } else {
            unreachable;
        }
    }
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
    sema: packed struct(u32) {
        thread: u16,
        resolved: bool,
        reserved: u7 = 0,
        id: Id,
    },
    reserved: u32 = 0,

    const Id = enum(u8){
        basic_block,
        constant_int,
        lazy_expression,
        instruction,
        function_declaration,
        argument,
    };

    const id_to_value_map = std.EnumArray(Id, type).init(.{
        .argument = ArgumentSymbol,
        .basic_block = BasicBlock,
        .constant_int = ConstantInt,
        .function_declaration = Function.Declaration,
        .instruction = Instruction,
        .lazy_expression = LazyExpression,
    });

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
                        switch (call.callable.sema.id) {
                            .function_declaration => {
                                const function_declaration = call.callable.get_payload(.function_declaration);
                                return function_declaration.return_type;
                            },
                            else => |t| @panic(@tagName(t)),
                        }
                    },
                    .integer_compare => {
                        return &instance.threads[value.sema.thread].integers[0].type;
                    },
                    else => |t| @panic(@tagName(t)),
                };
            },
            .constant_int => {
                const constant_int = value.get_payload(.constant_int);
                return constant_int.type;
            },
            else => |t| @panic(@tagName(t)),
        };
    }
};

const Type = struct {
    llvm: ?*LLVM.Type = null,
    // TODO: ZIG BUG: if this is a packed struct, the initialization is broken
    sema: struct {
        thread: u16,
        id: Id,
        resolved: bool,
        reserved: u7 = 0,
    },
    size: u64,
    alignment: u32,

    const Id = enum(u8){
        unresolved,
        void,
        integer,
    };

    const Integer = struct {
        type: Type,
        signedness: Signedness,
        bit_count: u16,

        const Signedness = enum(u1){
            unsigned,
            signed,
        };
    };

    const id_to_type_map = std.EnumArray(Id, type).init(.{
        .unresolved = void,
        .void = void,
        .integer = Integer,
    });

    fn get_payload(ty: *Type, comptime id: Id) *id_to_type_map.get(id) {
        assert(ty.sema.id == id);
        return @fieldParentPtr("type", ty);
    }
};

const Keyword = enum{
    @"else",
    @"for",
    @"if",
};

fn parse_keyword(identifier: []const u8) u32 {
    inline for (@typeInfo(Keyword).Enum.fields) |keyword| {
        if (byte_equal(identifier, keyword.name)) {
            return keyword.value;
        }
    } else {
        return ~@as(u32, 0);
    }
}

const Scope = struct {
    declarations: PinnedHashMap(u32, *Declaration) = .{},
    parent: ?*Scope,
    id: Id,

    pub fn get_global_declaration(scope: *Scope, name: u32) ?*GlobalDeclaration {
        assert(scope.id == .file);
        return @ptrCast(scope.get_declaration_one_level(name));
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
        function_definition,
        function_declaration,
        file,
        unresolved_import,
    };

    const id_to_global_declaration_map = std.EnumArray(Id, type).init(.{
        .function_definition = Function,
        .function_declaration = Function.Declaration,
        .file = File,
        .unresolved_import = Import,
    });

    fn get_payload(global_declaration: *GlobalDeclaration, comptime id: Id) *id_to_global_declaration_map.get(id) {
        assert(global_declaration.id == id);
        // Function definition has to be upcast twice
        if (id == .function_definition) {
            const global_symbol: *GlobalSymbol = @alignCast(@fieldParentPtr("global_declaration", global_declaration));
            const function_declaration: *Function.Declaration = @alignCast(@fieldParentPtr("global_symbol", global_symbol));
            const function_definition: *Function = @alignCast(@fieldParentPtr("declaration", function_declaration));
            return function_definition;
        }

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

    const Reference = **Declaration;

    const Id = enum {
        local,
        global,
        argument,
    };

    const id_to_declaration_map = std.EnumArray(Id, type).init(.{
        .global = GlobalDeclaration,
        .local = LocalDeclaration,
        .argument = ArgumentDeclaration,
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
        calling_convention: CallingConvention = .custom,
    };

    const Attribute = enum{
        cc,

        pub const Mask = std.EnumSet(Function.Attribute);
    };

    const Declaration = struct {
        attributes: Attributes = .{},
        value: Value,
        global_symbol: GlobalSymbol,
        return_type: *Type,
        argument_types: []const *Type = &.{},
        file: u32,
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

const Instruction = struct{
    value: Value,
    id: Id,

    const Id = enum{
        argument_storage,
        branch,
        call,
        integer_binary_operation,
        integer_compare,
        jump,
        load,
        local_symbol,
        phi,
        ret,
        ret_void,
        store,
    };

    const id_to_instruction_map = std.EnumArray(Id, type).init(.{
        .argument_storage = ArgumentSymbol,
        .branch = Branch,
        .call = Call,
        .integer_binary_operation = IntegerBinaryOperation,
        .integer_compare = IntegerCompare,
        .jump = Jump,
        .local_symbol = LocalSymbol,
        .load = Load,
        .phi = Phi,
        .ret = Return,
        .ret_void = void,
        .store = Store,
    });

    fn get_payload(instruction: *Instruction, comptime id: Id) *id_to_instruction_map.get(id) {
        assert(instruction.id == id);
        return @fieldParentPtr("instruction", instruction);
    }
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
};

fn get_power_of_two_byte_count_from_bit_count(bit_count: u32) u32 {
    if (bit_count == 0) unreachable;
    if (bit_count <= 8) return 1;
    if (bit_count <= 16) return 2;
    if (bit_count <= 32) return 4;
    if (bit_count <= 64) return 8;
    unreachable;
}

const Thread = struct{
    arena: *Arena = undefined,
    functions: PinnedArray(Function) = .{},
    external_functions: PinnedArray(Function.Declaration) = .{},
    identifiers: PinnedHashMap(u32, []const u8) = .{},
    constant_ints: PinnedArray(ConstantInt) = .{},
    basic_blocks: PinnedArray(BasicBlock) = .{},
    task_system: TaskSystem = .{},
    debug_info_file_map: PinnedHashMap(u32, LLVMFile) = .{},
    // pending_values_per_file: PinnedArray(PinnedArray(*Value)) = .{},
    branches: PinnedArray(Branch) = .{},
    jumps: PinnedArray(Jump) = .{},
    calls: PinnedArray(Call) = .{},
    integer_binary_operations: PinnedArray(IntegerBinaryOperation) = .{},
    integer_compares: PinnedArray(IntegerCompare) = .{},
    loads: PinnedArray(Load) = .{},
    stores: PinnedArray(Store) = .{},
    phis: PinnedArray(Phi) = .{},
    returns: PinnedArray(Return) = .{},
    lazy_expressions: PinnedArray(LazyExpression) = .{},
    imports: PinnedArray(Import) = .{},
    local_blocks: PinnedArray(LocalBlock) = .{},
    local_symbols: PinnedArray(LocalSymbol) = .{},
    argument_symbols: PinnedArray(ArgumentSymbol) = .{},
    analyzed_file_count: u32 = 0,
    assigned_file_count: u32 = 0,
    llvm: struct {
        context: *LLVM.Context,
        module: *LLVM.Module,
        builder: *LLVM.Builder,
        attributes: LLVM.Attributes,
        target_machine: *LLVM.Target.Machine,
        object: ?[]const u8 = null,
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
                            // We can fieldParentPtr to the thread
                            .thread = undefined,
                            .id = .integer,
                            .resolved = true,
                        },
                        .size = byte_count,
                        .alignment = byte_count,
                    },
                    .bit_count = bit_count,
                    .signedness = signedness,
                };
            }
        }
        break :blk integers;
    },
    handle: std.Thread = undefined,

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
    };
};

const TaskSystem = struct{
    job: JobQueue = .{},
    ask: JobQueue = .{},
    program_state: ProgramState = .none,
    state: ThreadState = .idle,

    const ProgramState = enum{
        none,
        analysis,
        analysis_resolution,
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

const File = struct{
    global_declaration: GlobalDeclaration,
    scope: File.Scope,
    source_code: []const u8,
    path: []const u8,
    functions: Range = .{
        .start = 0,
        .end = 0,
    },
    state: State = .queued,
    thread: u32 = 0,
    interested_threads: PinnedArray(u32) = .{},
    interested_files: PinnedArray(*File) = .{},
    imports: PinnedArray(*Import) = .{},
    values_per_import: PinnedArray(PinnedArray(*Value)) = .{},
    resolved_import_count: u32 = 0,

    pub fn get_index(file: *File) u32 {
        return instance.files.get_index(file);
    }

    pub fn get_directory_path(file: *const File) []const u8 {
        return std.fs.path.dirname(file.path) orelse unreachable;
    }

    const State = enum{
        queued,
        analyzing,
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
            },
            .id = .file,
        },
        .scope = .{
            .scope = .{
                .id = .file,
                .parent = null,
            },
        },
        .source_code = &.{},
        .path = file_absolute_path,
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
    exit(1);
}

fn error_unterminated_argument(argument: []const u8) noreturn {
    @setCold(true);
    write("Argument '");
    write(argument);
    write("' must be terminated\n");
    exit(1);
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


        const main_source_file_absolute = instance.path_from_cwd(instance.arena, unit.descriptor.main_source_file_path);
        const new_file_index = add_file(main_source_file_absolute, &.{});
        instance.threads[0].task_system.program_state = .analysis;
        instance.threads[0].add_thread_work(Job{
            .offset = new_file_index,
            .count = 1,
            .id = .analyze_file,
        });
        control_thread(unit);

        return unit;
    }
};

fn control_thread(unit: *Unit) void {
    var last_assigned_thread_index: u32 = 1;
    var first_ir_done = false;
    var total_is_done: bool = false;
    var iterations_without_work_done: u32 = 0;

    while (!total_is_done) {
        total_is_done = first_ir_done;

        var task_done_this_iteration: u32 = 0;

        for (instance.threads, 0..) |*thread, i| {
            // INFO: No need to do an atomic load here since it's only this thread writing to the value
            const program_state = thread.task_system.program_state;
            total_is_done = total_is_done and if (@intFromEnum(program_state) >= @intFromEnum(TaskSystem.ProgramState.analysis)) program_state == .llvm_finished_object else true;

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
                                exit(1);
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

    // for (instance.threads) |*thread| {
    //     std.debug.print("Thread #{}: {s}\n", .{thread.get_index(), @tagName(thread.task_system.program_state)});
    // }

    assert(objects.length > 0);

    link(.{
        .output_file_path = unit.descriptor.executable_path,
        .extra_arguments = &.{},
        .objects = objects.const_slice(),
        .libraries = &.{},
        .link_libc = true,
        .link_libcpp = false,
    });
}

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
        } else {
            @panic(current_argument);
            // std.debug.panic("Unrecognized argument: {s}", .{current_argument});
        }
    }

    const main_source_file_path = maybe_main_source_file_path orelse exit_with_error("Main source file must be specified with -main_source_file");
    // TODO: undo this incongruency
    const executable_name = if (maybe_executable_name) |executable_name| executable_name else std.fs.path.basename(main_source_file_path[0..main_source_file_path.len - "/main.nat".len]);
    const executable_path = maybe_executable_path orelse blk: {
        assert(executable_name.len > 0);
        const result = instance.arena.join(&.{"nat/", executable_name }) catch unreachable;
        break :blk result;
    };

    const object_path = blk: {
        const slice = instance.arena.new_array(u8, executable_path.len + 2) catch unreachable;
        @memcpy(slice[0..executable_path.len], executable_path);
        slice[executable_path.len] = '.';
        slice[executable_path.len + 1] = 'o';
        break :blk slice;
    };

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
    instance.arena = library.Arena.init(4 * 1024 * 1024) catch unreachable;
    const executable_path = library.self_exe_path(instance.arena) catch unreachable;
    const executable_directory = std.fs.path.dirname(executable_path).?;
    std.fs.cwd().makePath("nat") catch |err| switch (err) {
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
        exit_with_error("Insufficient number of arguments");
    }

    const command = arguments[1];
    const command_arguments = arguments[2..];

    if (byte_equal(command, "exe")) {
        command_exe(command_arguments);
    } else if (byte_equal(command, "clang") or byte_equal(command, "-cc1") or byte_equal(command, "-cc1as")) {
        exit_with_error("TODO: clang");
    } else if (byte_equal(command, "cc")) {
        exit_with_error("TODO: clang");
    } else if (byte_equal(command, "c++")) {
        exit_with_error("TODO: clang");
    } else {
        exit_with_error("Unrecognized command");
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
    return_block: ?*BasicBlock = null,
    return_phi: ?*Phi = null,
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

    while (true) {
        while (thread.get_worker_job()) |job| {
            const c = thread.task_system.job.worker.completed;
            switch (job.id) {
                .analyze_file => {
                    thread.assigned_file_count += 1;
                    const file_index = job.offset;
                    const file = &instance.files.slice()[file_index];
                    file.state = .analyzing;
                    file.source_code = library.read_file(thread.arena, std.fs.cwd(), file.path);
                    file.thread = thread_index;
                    analyze_file(thread, file_index);
                },
                .notify_file_resolved => {
                    const file_index = job.count;
                    const file = &instance.files.pointer[file_index];

                    if (thread == &instance.threads[file.thread]) {
                        exit_with_error("Threads match!");
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
                                                                                        .function_definition => {
                                                                                            const function_definition = global_declaration.get_payload(.function_definition);
                                                                                            assert(function_definition.declaration.value.sema.resolved);
                                                                                            assert(function_definition.declaration.value.sema.resolved);
                                                                                            assert(function_definition.declaration.return_type.sema.thread == thread.get_index());
                                                                                            // TODO: here we are duplicating the function declaration, but not the types. It could be interesting to duplicate the types so in the LLVM IR no special case has to take place to deduplicate work done in different threads
                                                                                            const external_fn = thread.external_functions.append(function_definition.declaration);
                                                                                            external_fn.global_symbol.attributes.@"export" = false;
                                                                                            external_fn.global_symbol.attributes.@"extern" = true;
                                                                                            external_fn.value.sema.thread = thread.get_index();
                                                                                            external_fn.value.llvm = null;

                                                                                            call.callable = &external_fn.value;
                                                                                            value.sema.resolved = true;
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
                    if (thread.functions.length > 0) {
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
                                exit_with_error(error_message[0..error_message_len]);
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
                            .builder = builder,
                            .attributes = attributes,
                            .target_machine = target_machine,
                        };
                        const debug_info = false;

                        for (thread.external_functions.slice()) |*nat_function| {
                            _ = llvm_get_function(thread, nat_function, true);
                        }

                        for (thread.functions.slice()) |*nat_function| {
                            _ = llvm_get_function(thread, &nat_function.declaration, false);
                        }

                        for (thread.functions.slice()) |*nat_function| {
                            const function = nat_function.declaration.value.llvm.?.toFunction() orelse unreachable;
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
                                thread.llvm.builder.setInsertPoint(llvm_basic_block);

                                var last_block = basic_block_node;

                                if (emit_allocas) {
                                    for (nat_function.arguments.slice(), 0..) |argument, argument_index| {
                                        const alloca_type = llvm_get_type(thread, argument.type);
                                        argument.instruction.value.llvm = thread.llvm.builder.createAlloca(alloca_type, address_space, null, "", "".len, argument.alignment).toValue();
                                        const llvm_argument = function.getArgument(@intCast(argument_index));
                                        argument.value.llvm = llvm_argument.toValue();
                                    }

                                    for (nat_function.stack_slots.slice()) |local_slot| {
                                        const alloca_type = llvm_get_type(thread, local_slot.type);
                                        local_slot.instruction.value.llvm = thread.llvm.builder.createAlloca(alloca_type, address_space, null, "", "".len, local_slot.alignment).toValue();
                                    }

                                    emit_allocas = false;
                                }

                                for (basic_block.instructions.slice()) |instruction| {
                                    const value: *LLVM.Value = switch (instruction.id) {
                                        .store => block: {
                                            const store = instruction.get_payload(.store);
                                            const destination = llvm_get_value(thread, store.destination);
                                            const source = llvm_get_value(thread, store.source);
                                            const store_instruction = builder.createStore(source, destination, store.is_volatile, store.alignment);
                                            break :block store_instruction.toValue();
                                        },
                                        .load => block: {
                                            const load = instruction.get_payload(.load);
                                            const load_value = llvm_get_value(thread, load.value);
                                            const load_type = llvm_get_type(thread, load.type);
                                            // TODO: precise alignment
                                            const load_instruction = builder.createLoad(load_type, load_value, load.is_volatile, "", "".len, load.alignment);
                                            break :block load_instruction.toValue();
                                        },
                                        .ret => block: {
                                            const return_instruction = instruction.get_payload(.ret);
                                            const return_value = llvm_get_value(thread, return_instruction.value);
                                            const ret = thread.llvm.builder.createRet(return_value);
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
                                            const callee = llvm_get_value(thread, call.callable);
                                            const callee_function = callee.toFunction() orelse unreachable;
                                            const function_type = callee_function.getType();

                                            var arguments = std.BoundedArray(*LLVM.Value, 512){};
                                            for (call.arguments) |argument| {
                                                const llvm_argument = llvm_get_value(thread, argument); 
                                                _ = arguments.appendAssumeCapacity(llvm_argument);
                                            }

                                            const args = arguments.constSlice();

                                            const call_i = thread.llvm.builder.createCall(function_type, callee, args.ptr, args.len, "", "".len, null);
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
                                            const not_taken = thread.llvm.context.createBasicBlock("", "".len, function, null);
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
                                            const llvm_target_block = if (target_block.value.llvm) |llvm| llvm.toBasicBlock() orelse unreachable else bb: {
                                                const block = thread.llvm.context.createBasicBlock("", "".len, function, null);
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

                            if (debug_info) {
                                const file_index = nat_function.declaration.file;
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
                                    exit_with_error(message);
                                }
                            }
                        }

                        if (debug_info) {
                            for (thread.debug_info_file_map.values()) |v| {
                                v.builder.finalize();
                            }
                        }

                        const verify_module = true;
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

                                exit_with_error(verification_message);
                            }
                        }

                        if (print_module) {
                            var module_content: []const u8 = undefined;
                            thread.llvm.module.toString(&module_content.ptr, &module_content.len);
                            write(module_content);
                            write("\n");
                        }

                        thread.add_control_work(.{
                            .id = .llvm_notify_ir_done,
                        });
                    }
                },
                .llvm_emit_object => {
                    const timestamp = std.time.nanoTimestamp();
                    const thread_object = std.fmt.allocPrint(std.heap.page_allocator, "nat/{s}_thread{}_{}.o", .{std.fs.path.basename(std.fs.path.dirname(instance.files.get(@enumFromInt(0)).path).?), thread.get_index(), timestamp}) catch unreachable;
                    thread.llvm.object = thread_object;
                    const disable_verify = false;
                    const result = thread.llvm.module.addPassesToEmitFile(thread.llvm.target_machine, thread_object.ptr, thread_object.len, LLVM.CodeGenFileType.object, disable_verify);
                    if (!result) {
                        @panic("can't generate machine code");
                    }

                    thread.add_control_work(.{
                        .id = .llvm_notify_object_done,
                    });
                    // std.debug.print("Thread #{} emitted object and notified\n", .{thread_index});
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
                const integer_type = constant_int.type.get_payload(.integer);
                const result = thread.llvm.context.getConstantInt(integer_type.bit_count, constant_int.n, @intFromEnum(integer_type.signedness) != 0);
                break :b result.toValue();
            },
            .instruction => {
                const instruction = value.get_payload(.instruction);
                switch (instruction.id) {
                    else => |t| @panic(@tagName(t)),
                }
            },
            else => |t| @panic(@tagName(t)),
        };

        value.llvm = llvm_value;

        return llvm_value;
    }
}

fn llvm_get_type(thread: *Thread, ty: *Type) *LLVM.Type {
    if (ty.llvm) |llvm| {
        assert(ty.sema.thread == thread.get_index());
        assert(llvm.getContext() == thread.llvm.context);
        return llvm;
    } else {
        const llvm_type: *LLVM.Type = switch (ty.sema.id) {
            .integer => b: {
                const int_ty = ty.get_payload(.integer);
                const integer_type = thread.llvm.context.getIntegerType(int_ty.bit_count);
                break :b integer_type.toType();
            },
            else => |t| @panic(@tagName(t)),
        };
        return llvm_type;
    }
}

fn llvm_get_file(thread: *Thread, file_index: u32) *LLVMFile {
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
        const compile_unit = builder.createCompileUnit(LLVM.DebugInfo.Language.c, llvm_file, producer, producer.len, is_optimized, flags, flags.len, runtime_version, splitname, splitname.len, debug_info_kind, DWOId, split_debug_inlining, debug_info_for_profiling, name_table_kind, ranges_base_address, sysroot, sysroot.len, sdk, sdk.len);

        thread.debug_info_file_map.put_no_clobber(file_index, .{
            .file = llvm_file,
            .compile_unit = compile_unit,
            .builder = builder,
        });

        return thread.debug_info_file_map.get_pointer(file_index).?;
    }
}

fn llvm_get_function(thread: *Thread, nat_function: *Function.Declaration, override_extern: bool) *LLVM.Value.Constant.Function {
    if (nat_function.value.llvm) |llvm| return llvm.toFunction() orelse unreachable else {
        _ = override_extern; // autofix
        const function_name = thread.identifiers.get(nat_function.global_symbol.global_declaration.declaration.name) orelse unreachable;
        const return_type = llvm_get_type(thread, nat_function.return_type);
        var argument_types = PinnedArray(*LLVM.Type){};
        _ = &argument_types;
        for (nat_function.argument_types) |argument_type| {
            const llvm_arg_type = llvm_get_type(thread, argument_type);
            _ = argument_types.append(llvm_arg_type);
        }
        const is_var_args = false;
        const function_type = LLVM.getFunctionType(return_type, argument_types.pointer, argument_types.length, is_var_args);
        const is_extern_function = nat_function.global_symbol.attributes.@"extern";
        const export_or_extern = nat_function.global_symbol.attributes.@"export" or is_extern_function; 
        const linkage: LLVM.Linkage = switch (export_or_extern) {
            true => .@"extern",
            false => .internal,
        };
        const function = thread.llvm.module.createFunction(function_type, linkage, address_space, function_name.ptr, function_name.len);

        const debug_info = false;
        if (debug_info) {
            const file_index = nat_function.file;
            const llvm_file = llvm_get_file(thread, file_index);
            var debug_argument_types = PinnedArray(*LLVM.DebugInfo.Type){};
            _ = &debug_argument_types;
            for (nat_function.argument_types) |argument_type| {
                _ = argument_type; // autofix
                exit(1);
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
            const line = 0;
            const scope_line = 0;

            const subprogram = llvm_file.builder.createFunction(scope, function_name.ptr, function_name.len, function_name.ptr, function_name.len, file, line, subroutine_type, scope_line, subroutine_type_flags, subprogram_flags, subprogram_declaration);
            function.setSubprogram(subprogram);
        }

        nat_function.value.llvm = function.toValue();
        return function;
    }
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

fn build_return(thread: *Thread, analyzer: *Analyzer, return_value: *Value) void {
    const return_expression = thread.returns.append(.{
        .instruction = .{
            .value = .{
                .sema = .{
                    .thread = thread.get_index(),
                    .resolved = return_value.sema.resolved,
                    .id = .instruction,
                },
                },
            .id = .ret,
        },
        .value = return_value,
    });

    _ = analyzer.current_basic_block.instructions.append(&return_expression.instruction);
    analyzer.current_basic_block.is_terminated = true;
}

pub fn analyze_local_block(thread: *Thread, analyzer: *Analyzer, parser: *Parser, file: *File) void {
    const src = file.source_code;
    const function = analyzer.current_function;
    const block_start = parser.i;
    const block_line = parser.current_line + 1;
    _ = block_line; // autofix
    const block_column = block_start - parser.line_offset + 1;
    _ = block_column; // autofix
    parser.expect_character(src, brace_open);
    const local_block = thread.local_blocks.append(.{
        .scope = .{
            .id = .local,
            .parent = analyzer.current_scope,
        },
    });
    analyzer.current_scope = &local_block.scope;
    parser.skip_space(src);

    while (true) {
        parser.skip_space(src);

        const statement_start_ch = src[parser.i];

        if (statement_start_ch == brace_close) {
            break;
        }

        switch (statement_start_ch) {
            'r' => {
                const identifier = parser.parse_raw_identifier(src);

                if (byte_equal(identifier, "return")) {
                    parser.skip_space(src);

                    if (function.declaration.return_type.sema.id != .unresolved) {
                        const return_type = function.declaration.return_type;
                        const return_value = parser.parse_expression(analyzer, thread, file, return_type, .right);
                        parser.expect_character(src, ';');

                        if (analyzer.return_block) |return_block| {
                            const return_phi = analyzer.return_phi.?;
                            _ = return_phi.nodes.append(.{
                                .value = return_value,
                                .basic_block = analyzer.current_basic_block,
                            });
                            assert(analyzer.current_basic_block != return_block);

                            const jump = thread.jumps.append(.{
                                .instruction = .{
                                    .id = .jump,
                                    .value = .{
                                        .sema = .{
                                            .id = .instruction,
                                            .resolved = true,
                                            .thread = thread.get_index(),
                                        },
                                    },
                                },
                                .basic_block = return_block,
                            });
                            _ = analyzer.current_basic_block.instructions.append(&jump.instruction);
                            analyzer.current_basic_block.is_terminated = true;

                            _ = return_block.predecessors.append(analyzer.current_basic_block);
                        } else if (analyzer.exit_blocks.length > 0) {
                            const return_phi = thread.phis.append(.{
                                .instruction = .{
                                    .id = .phi,
                                    .value = .{
                                        .sema = .{
                                            .id = .instruction,
                                            .thread = thread.get_index(),
                                            .resolved = true,
                                        },
                                    },
                                },
                                .type = return_type,
                            });
                            analyzer.return_phi = return_phi;
                            const return_block = create_basic_block(thread);
                            analyzer.return_block = return_block;
                            _ = return_phi.nodes.append(.{
                                .value = return_value,
                                .basic_block = analyzer.current_basic_block,
                            });

                            const jump = thread.jumps.append(.{
                                .instruction = .{
                                    .id = .jump,
                                    .value = .{
                                        .sema = .{
                                            .id = .instruction,
                                            .resolved = true,
                                            .thread = thread.get_index(),
                                        },
                                    },
                                },
                                .basic_block = return_block,
                            });
                            _ = analyzer.current_basic_block.instructions.append(&jump.instruction);
                            analyzer.current_basic_block.is_terminated = true;

                            _ = return_block.predecessors.append(analyzer.current_basic_block);
                        } else {
                            build_return(thread, analyzer, return_value);
                        }
                    } else  {
                        exit(1);
                    }
                } else {
                    exit(1);
                }
            },
            // Local variable
            '>' => {
                parser.i += 1;

                parser.skip_space(src);

                const local_name = parser.parse_identifier(thread, src);
                if (analyzer.current_scope.get_declaration(local_name)) |lookup_result| {
                    _ = lookup_result;
                    exit_with_error("Existing declaration with the same name");
                }


                const has_local_attributes = src[parser.i] == '[';
                parser.i += @intFromBool(has_local_attributes);

                if (has_local_attributes) {
                    exit_with_error("TODO: local attributes");
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

                        const local_type = parser.parse_type_expression(thread, src);

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
                    else => exit(1),
                };

                parser.skip_space(src);

                parser.expect_character(src, ';');

                const local_symbol = thread.local_symbols.append(.{
                    .local_declaration = .{
                        .declaration = .{
                            .id = .local,
                            .name = local_name,
                        },
                    },
                    .type = result.type,
                    .instruction = .{
                        .value = .{
                            .sema = .{
                                .thread = thread.get_index(),
                                .resolved = result.type.sema.resolved and result.initial_value.sema.resolved,
                                .id = .instruction,
                            },
                            },
                        .id = .local_symbol,
                    },
                    .alignment = result.type.alignment,
                });

                _ = analyzer.current_function.stack_slots.append(local_symbol);

                const store = thread.stores.append(.{
                    .instruction = .{
                        .value = .{
                            .sema = .{
                                .thread = thread.get_index(),
                                .resolved = true,
                                .id = .instruction,
                            },
                            },
                        .id = .store,
                    },
                    .destination = &local_symbol.instruction.value,
                    .source = result.initial_value,
                    .alignment = local_symbol.alignment,
                    .is_volatile = false,
                });
                _ = analyzer.current_basic_block.instructions.append(&store.instruction);

                local_block.scope.declarations.put_no_clobber(local_name, &local_symbol.local_declaration.declaration);
            },
            'i' => {
                if (src[parser.i + 1] == 'f') {
                    parser.parse_if_expression(analyzer, thread, file);
                } else {
                    unreachable;
                }
            },
            else => {
                exit_with_error("Unrecognized statement initial char");
            },
        }
    }

    parser.expect_character(src, brace_close);
}


pub fn analyze_file(thread: *Thread, file_index: u32) void {
    const file = instance.files.get(@enumFromInt(file_index));
    const src = file.source_code;

    if (src.len > std.math.maxInt(u32)) {
        exit_with_error("File too big");
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

        switch (declaration_start_ch) {
            '>' => {
                parser.i += 1;
                parser.skip_space(src);
                const symbol_identifier_start = parser.i;
                _ = symbol_identifier_start; // autofix
                const identifier = parser.parse_identifier(thread, src);
                _ = identifier; // autofix


                exit(1);
            },
            'f' => {
                if (src[parser.i + 1] == 'n') {
                    parser.i += 2;
                    parser.skip_space(src);

                    const function = thread.functions.add_one();
                    const entry_block = create_basic_block(thread);
                    function.* = .{
                        .declaration = .{
                            .return_type = undefined,
                            .global_symbol = .{
                                .global_declaration = .{
                                    .declaration = .{
                                        .name = std.math.maxInt(u32),
                                        .id = .global,
                                    },
                                    .id = .function_definition,
                                },
                            },
                            .file = file_index,
                            .value = .{
                                .sema = .{
                                    .thread = thread.get_index(),
                                    .resolved = true, // TODO: is this correct?
                                    .id = .function_declaration,
                                },
                            },
                        },
                        .scope = .{
                            .scope = .{
                                .id = .function,
                                .parent = &file.scope.scope,
                            },
                        },
                        .entry_block = entry_block,
                    };

                    var analyzer = Analyzer{
                        .current_function = function,
                        .current_basic_block = entry_block,
                        .current_scope = &function.scope.scope,
                    };

                    const has_function_attributes = src[parser.i] == '[';
                    parser.i += @intFromBool(has_function_attributes);

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
                                        exit(1);
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
                                                    const calling_convention = @field(CallingConvention, cc_field.name);
                                                    function.declaration.attributes.calling_convention = calling_convention;
                                                    break :b;
                                                }
                                            } else {
                                                exit(1);
                                            }
                                        },
                                    }
                                }
                            } else {
                                exit(1);
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

                    function.declaration.global_symbol.global_declaration.declaration.name = parser.parse_identifier(thread, src);

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
                                        exit(1);
                                    }

                                    attribute_mask.setPresent(global_attribute, true);

                                    switch (global_attribute) {
                                        .@"export" => {},
                                        .@"extern" => {},
                                    }

                                    const after_ch =src[parser.i];
                                    switch (after_ch) {
                                        ']' => {},
                                        else => unreachable,
                                    }

                                    break;
                                }
                            } else {
                                exit(1);
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

                    file.scope.scope.declarations.put_no_clobber(function.declaration.global_symbol.global_declaration.declaration.name, &function.declaration.global_symbol.global_declaration.declaration);

                    const split_modules = true;
                    if (split_modules) {
                        function.declaration.global_symbol.attributes.@"export" = true;
                    }

                    parser.expect_character(src, '(');

                    const ArgumentData = struct{
                        type: *Type,
                        name: u32,
                    };
                    var arguments = PinnedArray(ArgumentData){};
                    var argument_types = PinnedArray(*Type){};
                    while (true) {
                        parser.skip_space(src);

                        if (src[parser.i] == ')') break;

                        parser.skip_space(src);

                        const argument_name = parser.parse_identifier(thread, src);

                        parser.skip_space(src);
                        
                        parser.expect_character(src, ':');

                        parser.skip_space(src);
                        
                        const argument_type = parser.parse_type_expression(thread, src);
                        _ = arguments.append(.{
                            .type = argument_type,
                            .name = argument_name,
                        });
                        _ = argument_types.append(argument_type);

                        parser.skip_space(src);

                        switch (src[parser.i]) {
                            ',' => parser.i += 1,
                            ')' => {},
                            else => exit(1),
                        }
                    }

                    function.declaration.argument_types = argument_types.const_slice();

                    parser.expect_character(src, ')');

                    parser.skip_space(src);

                    function.declaration.return_type = parser.parse_type_expression(thread, src);

                    parser.skip_space(src);

                    switch (src[parser.i]) {
                        brace_open => {
                            analyzer.current_scope = &analyzer.current_function.scope.scope;

                            for (arguments.const_slice()) |argument| {
                                if (analyzer.current_scope.declarations.get(argument.name) != null)  {
                                    exit_with_error("A declaration already exists with such name");
                                }

                                const argument_symbol = thread.argument_symbols.append(.{
                                    .argument_declaration = .{
                                        .declaration = .{
                                            .id = .argument,
                                            .name = argument.name,
                                        },
                                    },
                                    .type = argument.type,
                                    .alignment = argument.type.alignment,
                                    .value = .{
                                        .sema = .{
                                            .id = .argument,
                                            .resolved = true,
                                            .thread = thread.get_index(),
                                        },
                                    },
                                    .instruction = .{
                                        .value = .{
                                            .sema = .{
                                                .id = .instruction,
                                                .thread = thread.get_index(),
                                                .resolved = true,
                                            },
                                        },
                                        .id = .argument_storage,
                                    },
                                });
                                _ = analyzer.current_function.arguments.append(argument_symbol);

                                analyzer.current_scope.declarations.put_no_clobber(argument.name, &argument_symbol.argument_declaration.declaration);

                                const store = thread.stores.append(.{
                                    .instruction = .{
                                        .id = .store,
                                        .value = .{
                                            .sema = .{
                                                .id = .instruction,
                                                .thread = thread.get_index(),
                                                .resolved = true,
                                            },
                                        },
                                    },
                                    .destination = &argument_symbol.instruction.value,
                                    .source = &argument_symbol.value,
                                    .alignment = argument.type.alignment,
                                    .is_volatile = false,
                                });
                                _ = analyzer.current_basic_block.instructions.append(&store.instruction);
                            }

                            analyze_local_block(thread, &analyzer, &parser, file);

                            const current_basic_block = analyzer.current_basic_block;
                            if (analyzer.return_phi) |return_phi| {
                                analyzer.current_basic_block = analyzer.return_block.?;
                                _ = analyzer.current_basic_block.instructions.append(&return_phi.instruction);
                                build_return(thread, &analyzer, &return_phi.instruction.value);
                                analyzer.current_basic_block = current_basic_block;
                            }
                            
                            const return_type = function.declaration.return_type;
                            _ = return_type;

                            if (!current_basic_block.is_terminated and (current_basic_block.instructions.length > 0 or current_basic_block.predecessors.length > 0)) {
                                unreachable;
                            }
                        },
                        ';' => {
                            unreachable;
                        },
                        else => exit_with_error("Unexpected character to close function declaration"),
                    }
                } else {
                    exit(1);
                }
            },
            'i' => {
                const import_keyword = "import";
                if (byte_equal(src[parser.i..][0..import_keyword.len], import_keyword)) {
                    parser.i += import_keyword.len;

                    parser.skip_space(src);

                    const string_literal = parser.parse_non_escaped_string_literal_content(src);
                    parser.skip_space(src);

                    parser.expect_character(src, ';');

                    const filename = std.fs.path.basename(string_literal);
                    const has_right_extension = filename.len > ".nat".len and byte_equal(filename[filename.len - ".nat".len..], ".nat");
                    if (!has_right_extension) {
                        exit(1);
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
                            exit(1);
                        }
                    } else {
                        const import = thread.imports.append(.{
                            .global_declaration = .{
                                .declaration = .{
                                    .id = .global,
                                    .name = std.math.maxInt(u32),
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
                    exit(1);
                }
            },
            else => exit(1),
        }
    }

    try_resolve_file(thread, file);
}

fn try_resolve_file(thread: *Thread, file: *File) void {
    if (file.imports.length == file.resolved_import_count) {
        thread.analyzed_file_count += 1;

        if (thread.analyzed_file_count == thread.assigned_file_count) {
            if (@atomicLoad(@TypeOf(thread.task_system.job.queuer.to_do), &thread.task_system.job.queuer.to_do, .seq_cst) == thread.task_system.job.worker.completed + 1) {
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
    }
}

const TypecheckResult = enum{
    success,
};
fn typecheck(expected: *Type, have: *Type) TypecheckResult {
    if (expected == have) {
        return TypecheckResult.success;
    } else {
        exit(1);
    }
}

pub const LLVM = struct {
    const bindings = @import("backend/llvm_bindings.zig");
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
        const createStructGEP = bindings.NativityLLVMBuilderCreateStructGEP;
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
            DisableSanitizerInstrumentation = 7,
            FnRetThunkExtern = 8,
            Hot = 9,
            ImmArg = 10,
            InReg = 11,
            InlineHint = 12,
            JumpTable = 13,
            MinSize = 14,
            MustProgress = 15,
            Naked = 16,
            Nest = 17,
            NoAlias = 18,
            NoBuiltin = 19,
            NoCallback = 20,
            NoCapture = 21,
            NoCfCheck = 22,
            NoDuplicate = 23,
            NoFree = 24,
            NoImplicitFloat = 25,
            NoInline = 26,
            NoMerge = 27,
            NoProfile = 28,
            NoRecurse = 29,
            NoRedZone = 30,
            NoReturn = 31,
            NoSanitizeBounds = 32,
            NoSanitizeCoverage = 33,
            NoSync = 34,
            NoUndef = 35,
            NoUnwind = 36,
            NonLazyBind = 37,
            NonNull = 38,
            NullPointerIsValid = 39,
            OptForFuzzing = 40,
            OptimizeForSize = 41,
            OptimizeNone = 42,
            PresplitCoroutine = 43,
            ReadNone = 44,
            ReadOnly = 45,
            Returned = 46,
            ReturnsTwice = 47,
            SExt = 48,
            SafeStack = 49,
            SanitizeAddress = 50,
            SanitizeHWAddress = 51,
            SanitizeMemTag = 52,
            SanitizeMemory = 53,
            SanitizeThread = 54,
            ShadowCallStack = 55,
            SkipProfile = 56,
            Speculatable = 57,
            SpeculativeLoadHardening = 58,
            StackProtect = 59,
            StackProtectReq = 60,
            StackProtectStrong = 61,
            StrictFP = 62,
            SwiftAsync = 63,
            SwiftError = 64,
            SwiftSelf = 65,
            WillReturn = 66,
            WriteOnly = 67,
            ZExt = 68,
            ByRef = 69,
            ByVal = 70,
            ElementType = 71,
            InAlloca = 72,
            Preallocated = 73,
            StructRet = 74,
            Alignment = 75,
            AllocKind = 76,
            AllocSize = 77,
            Dereferenceable = 78,
            DereferenceableOrNull = 79,
            Memory = 80,
            StackAlignment = 81,
            UWTable = 82,
            VScaleRange = 83,
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

            pub const GlobalVariable = opaque {
                pub const setInitializer = bindings.NativityLLVMGlobalVariableSetInitializer;
                fn toValue(this: *@This()) *LLVM.Value {
                    return @ptrCast(this);
                }
                fn toConstant(this: *@This()) *Constant {
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
            exit(1);
        },
    }
}
