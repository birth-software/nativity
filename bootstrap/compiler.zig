const std = @import("std");
const library = @import("library.zig");
const assert = library.assert;
const Arena = library.Arena;
const PinnedArray = library.PinnedArray;
const PinnedHashMap = library.PinnedHashMap;
const hash_bytes = library.my_hash;
const byte_equal = library.byte_equal;

fn exit(exit_code: u8) noreturn {
    @setCold(true);
    if (@import("builtin").mode == .Debug) {
        if (exit_code != 0) @trap();
    }
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

fn write(string: []const u8) void {
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

fn is_alphabetic(ch: u8) bool {
    const lower = is_lower(ch);
    const upper = is_upper(ch);
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

const GlobalSymbol = struct {
    attributes: Attributes = .{},
    name: u32,
    const Attributes = struct {
        @"export": bool = false,
        @"extern": bool = false,
    };
    const Attribute = enum {
        @"export",
        @"extern",

        const Mask = std.EnumSet(Attribute);
    };
};

const Parser = struct {
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
        return string_literal[1..][0 .. string_literal.len - 2];
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

                    const index = bit_count + (@intFromEnum(signedness) * @as(u32, 64) + @intFromEnum(signedness));
                    const t = &thread.types.slice()[index];
                    return t;
                } else if (float_start) {
                    exit(1);
                } else {
                    unreachable;
                }
            } else {
                exit(1);
            }
        } else {
            exit(1);
        }
    }

    fn parse_typed_expression(parser: *Parser, analyzer: *Analyzer, thread: *Thread, file: *File, ty: *Type) *Value {
        const src = file.source_code;
        assert(ty.sema.id != .unresolved);
        const starting_ch = src[parser.i];
        const is_digit_start = is_decimal_digit(starting_ch);
        const is_alpha_start = is_alphabetic(starting_ch);

        if (is_digit_start) {
            switch (ty.sema.id) {
                .integer => {
                    if (starting_ch == '0') {
                        const follow_up_character = src[parser.i + 1];
                        const is_hex_start = follow_up_character == 'x';
                        const is_octal_start = follow_up_character == 'o';
                        const is_bin_start = follow_up_character == 'b';
                        const is_prefixed_start = is_hex_start or is_octal_start or is_bin_start;
                        const follow_up_alpha = is_alphabetic(follow_up_character);
                        const follow_up_digit = is_decimal_digit(follow_up_character);
                        const is_valid_after_zero = is_space(follow_up_character) or (!follow_up_digit and !follow_up_alpha);
                        //
                        if (is_prefixed_start) {
                            exit(1);
                        } else if (is_valid_after_zero) {
                            parser.i += 1;
                            const constant_int_index = thread.constant_ints.append_index(.{
                                .value = 0,
                                .type = ty,
                            });

                            const value = thread.values.append(.{
                                .sema = .{
                                    .id = .constant_int,
                                    .index = @intCast(constant_int_index),
                                    .thread = @intCast(thread.get_index()),
                                    .resolved = true,
                                },
                            });
                            return value;
                        } else {
                            exit(1);
                        }
                    }
                    exit(0);
                },
                else => unreachable,
            }
        } else if (is_alpha_start) {
            const file_scope = thread.file_scopes.get(@enumFromInt(file.scope.index));

            var resolved = true;
            const identifier = parser.parse_identifier(thread, src);
            const lazy_expression = thread.lazy_expressions.add_one();

            if (file_scope.declarations.get_pointer(identifier)) |declaration| {
                switch (declaration.id) {
                    .unresolved_import => {
                        resolved = false;
                        lazy_expression.* = LazyExpression.init(declaration);

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

                        const expression = thread.values.append(.{
                            .sema = .{
                                .id = .lazy_expression,
                                .index = thread.lazy_expressions.get_index(lazy_expression),
                                .thread = thread.get_index(),
                                .resolved = false,
                            },
                        });

                        switch (src[parser.i]) {
                            '(' => {
                                parser.i += 1;
                                // TODO: arguments
                                parser.expect_character(src, ')');

                                const call = thread.calls.append_index(.{
                                    .value = expression,
                                });
                                const call_i = thread.instructions.append(.{
                                    .id = .call,
                                    .index = @intCast(call),
                                });
                                _ = analyzer.current_basic_block.instructions.append(call_i);

                                const call_value = thread.values.append(.{
                                    .sema = .{
                                        .id = .instruction,
                                        .index = thread.instructions.get_index(call_i),
                                        .thread = thread.get_index(),
                                        .resolved = false,
                                    },
                                });

                                _ = thread.pending_file_values.get(@enumFromInt(declaration.index)).append(call_value);
                                return call_value;
                            },
                            else => @panic((src.ptr + parser.i)[0..1]),
                        }
                    },
                    else => |t| @panic(@tagName(t)),
                }
            } else {
                exit(1);
            }
        } else {
            exit(1);
        }
    }
};

const LazyExpression = union(enum) {
    dynamic: struct {
        names: PinnedArray(u32) = .{},
        outsider: *GlobalSymbolReference,
    },
    static: struct {
        names: [4]u32 = .{0} ** 4,
        outsider: *GlobalSymbolReference,
    },

    fn init(gsr: *GlobalSymbolReference) LazyExpression {
        return .{
            .static = .{
                .outsider = gsr,
            },
        };
    }

    fn length(lazy_expression: *LazyExpression) u32 {
        return switch (lazy_expression.*) {
            .dynamic => |d| d.names.length,
            .static => |*s| for (s.names, 0..) |n, i| {
                if (n == 0) break @intCast(i);
            } else s.names.len,
        };
    }

    fn names(lazy_expression: *LazyExpression) []const u32 {
        return switch (lazy_expression.*) {
            .dynamic => |*d| d.names.slice(),
            .static => |*s| s.names[0..for (s.names, 0..) |n, i| {
                if (n == 0) break @intCast(i);
            } else s.names.len],
        };
    }

    fn add(lazy_expression: *LazyExpression, name: u32) void {
        const index = lazy_expression.length();
        if (index < 4) {
            lazy_expression.static.names[index] = name;
        } else {
            unreachable;
        }
    }
};

fn Descriptor(comptime Id: type, comptime Integer: type) type {
    return packed struct(Integer) {
        index: @Type(.{
            .Int = .{
                .signedness = .unsigned,
                .bits = @typeInfo(Integer).Int.bits - @typeInfo(@typeInfo(Id).Enum.tag_type).Int.bits,
            },
        }),
        id: Id,

        pub const Index = PinnedArray(@This()).Index;
    };
}

const Expression = struct {
    type: *Type,
    value: *Value,
};

const Value = struct {
    llvm: ?*LLVM.Value = null,
    sema: packed struct(u64) {
        index: u32,
        thread: u16,
        resolved: bool,
        reserved: u7 = 0,
        id: Id,
    },
    const Id = enum(u8) {
        constant_int,
        lazy_expression,
        instruction,
        global_symbol,
    };
};

const Type = struct {
    llvm: ?*LLVM.Type = null,
    sema: packed struct(u32) {
        index: u24,
        id: Id,
    },

    const Id = enum(u8) {
        unresolved,
        void,
        integer,
    };

    const Integer = packed struct(u32) {
        bit_count: u16,
        signedness: Signedness,
        reserved: u7 = 0,
        id: Id = .integer,

        const Signedness = enum(u1) {
            unsigned,
            signed,
        };
    };
};

fn integer_bit_count(t: *Type) u16 {
    const integer: Type.Integer = @bitCast(t.sema);
    return integer.bit_count;
}

fn integer_signedness(t: *Type) Type.Integer.Signedness {
    const integer: Type.Integer = @bitCast(t.sema);
    return integer.signedness;
}

const IntegerType = struct {};

const Keyword = enum {
    @"for",
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

const Scope = Descriptor(enum(u3) {
    file,
    function,
    local,
}, u32);
const Range = struct {
    start: u32,
    end: u32,
};

const FileScope = struct {
    declarations: PinnedHashMap(u32, GlobalSymbolReference) = .{},
};

const GlobalSymbolReference = Descriptor(enum(u3) {
    function_definition,
    function_declaration,
    file,
    unresolved_import,
}, u32);

const BasicBlock = struct {
    instructions: PinnedArray(*Instruction) = .{},
    predecessors: PinnedArray(u32) = .{},
    is_terminated: bool = false,

    const Index = PinnedArray(BasicBlock).Index;
};

const Function = struct {
    declaration: Function.Declaration,
    entry_block: BasicBlock.Index,

    const Attributes = struct {
        calling_convention: CallingConvention = .custom,
    };

    const Attribute = enum {
        cc,

        pub const Mask = std.EnumSet(Function.Attribute);
    };
    const Declaration = struct {
        attributes: Attributes = .{},
        global: GlobalSymbol,
        return_type: *Type,
        argument_types: []const Type = &.{},
        file: u32,
        llvm: ?*LLVM.Value.Constant.Function = null,
    };
};

const Instruction = struct {
    index: u24,
    id: Id,
    llvm: ?*LLVM.Value = null,

    const Id = enum {
        call,
        ret,
        ret_void,
    };
};

const ConstantInt = struct {
    value: u64,
    type: *Type,
};

const Call = struct {
    value: *Value,
    const Index = PinnedArray(Call).Index;
};

const Return = struct {
    value: *Value,
    const Index = PinnedArray(Call).Index;
};

const Thread = struct {
    arena: *Arena = undefined,
    functions: PinnedArray(Function) = .{},
    external_functions: PinnedArray(Function.Declaration) = .{},
    identifiers: PinnedHashMap(u32, []const u8) = .{},
    instructions: PinnedArray(Instruction) = .{},
    constant_ints: PinnedArray(ConstantInt) = .{},
    basic_blocks: PinnedArray(BasicBlock) = .{},
    task_system: TaskSystem = .{},
    analyzed_file_count: u32 = 0,
    debug_info_file_map: PinnedHashMap(u32, LLVMFile) = .{},
    local_files: PinnedHashMap(u32, u32) = .{},
    pending_files: PinnedArray(u32) = .{},
    pending_file_values: PinnedArray(PinnedArray(*Value)) = .{},
    file_scopes: PinnedArray(FileScope) = .{},
    expressions: PinnedArray(Expression) = .{},
    calls: PinnedArray(Call) = .{},
    returns: PinnedArray(Return) = .{},
    types: PinnedArray(Type) = .{},
    values: PinnedArray(Value) = .{},
    lazy_expressions: PinnedArray(LazyExpression) = .{},
    llvm: struct {
        context: *LLVM.Context,
        module: *LLVM.Module,
        builder: *LLVM.Builder,
        attributes: LLVM.Attributes,
    } = undefined,

    fn add_thread_work(thread: *Thread, job: Job) void {
        thread.task_system.job.queue_job(job);
    }

    fn add_control_work(thread: *Thread, job: Job) void {
        thread.task_system.ask.queue_job(job);
    }

    pub fn get_index(thread: *Thread) u16 {
        const index = @divExact(@intFromPtr(thread) - @intFromPtr(threads.ptr), @sizeOf(Thread));
        return @intCast(index);
    }
};

const instrument = true;

const LLVMFile = struct {
    file: *LLVM.DebugInfo.File,
    compile_unit: *LLVM.DebugInfo.CompileUnit,
    builder: *LLVM.DebugInfo.Builder,
};

const Job = packed struct(u64) {
    offset: u32 = 0,
    count: u24 = 0,
    id: Id,

    const Id = enum(u8) {
        analyze_file,
        llvm_setup,
        notify_file_resolved,
        resolve_thread_module,
        llvm_codegen_thread_module,
    };
};

const TaskSystem = struct {
    job: JobQueue = .{},
    ask: JobQueue = .{},
};

const JobQueue = struct {
    entries: [64]Job = [1]Job{@bitCast(@as(u64, 0))} ** 64,
    to_do: u64 = 0,
    completed: u64 = 0,

    fn queue_job(job_queue: *JobQueue, job: Job) void {
        const index = job_queue.to_do;
        job_queue.entries[index] = job;
        job_queue.to_do += 1;
    }
};

var threads: []Thread = undefined;

const Instance = struct {
    files: PinnedArray(File) = .{},
    file_paths: PinnedArray(u32) = .{},
    arena: *Arena = undefined,
};

const File = struct {
    scope: Scope,
    source_code: []const u8,
    path: []const u8,
    functions: Range = .{
        .start = 0,
        .end = 0,
    },
    state: State = .queued,
    thread: u32 = 0,
    interested_threads: PinnedArray(u32) = .{},

    pub fn get_directory_path(file: *const File) []const u8 {
        return std.fs.path.dirname(file.path) orelse unreachable;
    }

    const State = enum {
        queued,
        analyzing,
    };

    const Index = PinnedArray(File).Index;
};

var instance = Instance{};
const do_codegen = true;
const codegen_backend = CodegenBackend.llvm;

const CodegenBackend = enum {
    llvm,
};

fn add_file(file_absolute_path: []const u8, interested_threads: []const u32) File.Index {
    const hash = hash_bytes(file_absolute_path);
    const new_file = instance.files.add_one();
    _ = instance.file_paths.append(hash);
    const new_file_index = instance.files.get_typed_index(new_file);
    new_file.* = .{
        .scope = @bitCast(@as(u32, 0)),
        .source_code = &.{},
        .path = file_absolute_path,
    };

    new_file.interested_threads.append_slice(interested_threads);

    return new_file_index;
}

const debug_main_bitcode align(@sizeOf(u32)) = [_]u8 {
    0x42, 0x43, 0xc0, 0xde, 
    0x35, 0x14, 0x00, 0x00, 
    0x05, 0x00, 0x00, 0x00, 
    0x62, 0x0c, 0x30, 0x24, 
    0x4a, 0x59, 0xbe, 0x66, 
    0xcd, 0xfb, 0xb5, 0xaf, 
    0x0b, 0x51, 0x80, 0x4c, 
    0x01, 0x00, 0x00, 0x00, 
    0x21, 0x0c, 0x00, 0x00, 
    0x77, 0x02, 0x00, 0x00, 
    0x0b, 0x02, 0x21, 0x00, 
    0x02, 0x00, 0x00, 0x00, 
    0x17, 0x00, 0x00, 0x00, 
    0x07, 0x81, 0x23, 0x91, 
    0x41, 0xc8, 0x04, 0x49, 
    0x06, 0x10, 0x32, 0x39, 
    0x92, 0x01, 0x84, 0x0c, 
    0x25, 0x05, 0x08, 0x19, 
    0x1e, 0x04, 0x8b, 0x62, 
    0x80, 0x0c, 0x45, 0x02, 
    0x42, 0x92, 0x0b, 0x42, 
    0x64, 0x10, 0x32, 0x14, 
    0x38, 0x08, 0x18, 0x4b, 
    0x0a, 0x32, 0x32, 0x88, 
    0x48, 0x70, 0xc4, 0x21, 
    0x23, 0x44, 0x12, 0x87, 
    0x8c, 0x10, 0x41, 0x92, 
    0x02, 0x64, 0xc8, 0x08, 
    0xb1, 0x14, 0x20, 0x43, 
    0x46, 0x88, 0x20, 0xc9, 
    0x01, 0x32, 0x32, 0x84, 
    0x58, 0x0e, 0x90, 0x91, 
    0x21, 0x44, 0x90, 0xa1, 
    0x82, 0xa2, 0x02, 0x19, 
    0xc3, 0x07, 0xcb, 0x15, 
    0x09, 0x32, 0x8c, 0x0c, 
    0x89, 0x20, 0x00, 0x00, 
    0x0b, 0x00, 0x00, 0x00, 
    0x22, 0x66, 0x04, 0x10, 
    0xb2, 0x42, 0x82, 0xc9, 
    0x10, 0x52, 0x42, 0x82, 
    0xc9, 0x90, 0x71, 0xc2, 
    0x50, 0x48, 0x0a, 0x09, 
    0x26, 0x43, 0xc6, 0x05, 
    0x42, 0x32, 0x26, 0x08, 
    0x0c, 0x9a, 0x23, 0x00, 
    0x83, 0x32, 0x24, 0x18, 
    0x01, 0x18, 0x08, 0x28, 
    0xc4, 0x48, 0x02, 0x00, 
    0x51, 0x18, 0x00, 0x00, 
    0x51, 0x00, 0x00, 0x00, 
    0x1b, 0x54, 0x23, 0xf8, 
    0xff, 0xff, 0xff, 0xff, 
    0x01, 0x70, 0x00, 0x09, 
    0x28, 0x83, 0x20, 0x0c, 
    0x04, 0xc2, 0x1c, 0xe4, 
    0x21, 0x1c, 0xda, 0xa1, 
    0x1c, 0xda, 0x00, 0x1e, 
    0xde, 0x21, 0x1d, 0xdc, 
    0x81, 0x1e, 0xca, 0x41, 
    0x1e, 0x80, 0x70, 0x60, 
    0x07, 0x76, 0x00, 0x88, 
    0x76, 0x48, 0x07, 0x77, 
    0x68, 0x03, 0x76, 0x28, 
    0x87, 0x73, 0x08, 0x07, 
    0x76, 0x68, 0x03, 0x7b, 
    0x28, 0x87, 0x71, 0xa0, 
    0x87, 0x77, 0x90, 0x87, 
    0x36, 0xb8, 0x87, 0x74, 
    0x20, 0x07, 0x7a, 0x40, 
    0x07, 0x00, 0x0e, 0x00, 
    0xc2, 0x1d, 0xde, 0xa1, 
    0x0d, 0xe8, 0x41, 0x1e, 
    0xc2, 0x01, 0x1e, 0xe0, 
    0x21, 0x1d, 0xdc, 0xe1, 
    0x1c, 0xda, 0xa0, 0x1d, 
    0xc2, 0x81, 0x1e, 0xd0, 
    0x01, 0xa0, 0x07, 0x79, 
    0xa8, 0x87, 0x72, 0x00, 
    0x88, 0x79, 0xa0, 0x87, 
    0x70, 0x18, 0x87, 0x75, 
    0x68, 0x03, 0x78, 0x90, 
    0x87, 0x77, 0xa0, 0x87, 
    0x72, 0x18, 0x07, 0x7a, 
    0x78, 0x07, 0x79, 0x68, 
    0x03, 0x71, 0xa8, 0x07, 
    0x73, 0x30, 0x87, 0x72, 
    0x90, 0x87, 0x36, 0x98, 
    0x87, 0x74, 0xd0, 0x87, 
    0x72, 0x00, 0xf0, 0x00, 
    0x20, 0xe8, 0x21, 0x1c, 
    0xe4, 0xe1, 0x1c, 0xca, 
    0x81, 0x1e, 0xda, 0x60, 
    0x1c, 0xe0, 0xa1, 0x1e, 
    0x00, 0x7c, 0xc0, 0x03, 
    0x3b, 0x68, 0x03, 0x3b, 
    0xa0, 0x03, 0x80, 0xa0, 
    0x87, 0x70, 0x90, 0x87, 
    0x73, 0x28, 0x07, 0x7a, 
    0x68, 0x03, 0x73, 0x28, 
    0x87, 0x70, 0xa0, 0x87, 
    0x7a, 0x90, 0x87, 0x72, 
    0x98, 0x07, 0x60, 0x0d, 
    0xc6, 0xa1, 0x1d, 0xde, 
    0xc1, 0x1e, 0xd8, 0x60, 
    0x0d, 0xc6, 0x01, 0x1f, 
    0xf0, 0x80, 0x0d, 0xd6, 
    0xc0, 0x1c, 0xf0, 0x61, 
    0x1e, 0xe4, 0x81, 0x0d, 
    0xd6, 0xa0, 0x1d, 0xda, 
    0x01, 0x1f, 0xd8, 0x60, 
    0x0d, 0xe6, 0x61, 0x1e, 
    0xca, 0x81, 0x0d, 0xd6, 
    0x60, 0x1e, 0xe6, 0xa1, 
    0x1c, 0xe4, 0x80, 0x0d, 
    0xd6, 0x00, 0x1f, 0xf0, 
    0xe0, 0x0e, 0x00, 0x82, 
    0x1e, 0xea, 0xc1, 0x1d, 
    0xca, 0xa1, 0x0d, 0xc6, 
    0x01, 0x1e, 0xea, 0x01, 
    0x38, 0x87, 0x72, 0x70, 
    0x87, 0x72, 0x90, 0x87, 
    0x74, 0x18, 0x07, 0x60, 
    0x03, 0x21, 0x04, 0x00, 
    0x29, 0x6c, 0x20, 0x06, 
    0x01, 0x20, 0x85, 0x0d, 
    0x11, 0xf1, 0xff, 0xff, 
    0xff, 0xff, 0x03, 0x70, 
    0x0a, 0x80, 0x1f, 0x00, 
    0x7f, 0x00, 0x48, 0x40, 
    0x1d, 0x00, 0x7d, 0x10, 
    0xd8, 0x02, 0x00, 0x00, 
    0x49, 0x18, 0x00, 0x00, 
    0x02, 0x00, 0x00, 0x00, 
    0x13, 0x86, 0x40, 0x18, 
    0x26, 0x04, 0x04, 0x00, 
    0x13, 0x30, 0x7c, 0xc0, 
    0x03, 0x3b, 0xf8, 0x05, 
    0x3b, 0xa0, 0x83, 0x36, 
    0xa8, 0x07, 0x77, 0x58, 
    0x07, 0x77, 0x78, 0x87, 
    0x7b, 0x70, 0x87, 0x36, 
    0x60, 0x87, 0x74, 0x70, 
    0x87, 0x7a, 0xc0, 0x87, 
    0x36, 0x38, 0x07, 0x77, 
    0xa8, 0x87, 0x0d, 0xaf, 
    0x50, 0x0e, 0x6d, 0xd0, 
    0x0e, 0x7a, 0x50, 0x0e, 
    0x6d, 0x00, 0x0f, 0x72, 
    0x70, 0x07, 0x70, 0xa0, 
    0x07, 0x73, 0x20, 0x07, 
    0x7a, 0x30, 0x07, 0x72, 
    0xd0, 0x06, 0xf0, 0x20, 
    0x07, 0x77, 0x10, 0x07, 
    0x7a, 0x30, 0x07, 0x72, 
    0xa0, 0x07, 0x73, 0x20, 
    0x07, 0x6d, 0x00, 0x0f, 
    0x72, 0x70, 0x07, 0x72, 
    0xa0, 0x07, 0x76, 0x40, 
    0x07, 0x7a, 0x60, 0x07, 
    0x74, 0xd0, 0x06, 0xe9, 
    0x60, 0x07, 0x74, 0xa0, 
    0x07, 0x76, 0x40, 0x07, 
    0x6d, 0x90, 0x0e, 0x71, 
    0x20, 0x07, 0x78, 0xa0, 
    0x07, 0x71, 0x20, 0x07, 
    0x78, 0xd0, 0x06, 0xe6, 
    0x80, 0x07, 0x70, 0xa0, 
    0x07, 0x71, 0x20, 0x07, 
    0x78, 0xd0, 0x06, 0xee, 
    0x80, 0x07, 0x7a, 0x10, 
    0x07, 0x76, 0xa0, 0x07, 
    0x73, 0x20, 0x07, 0x7a, 
    0x60, 0x07, 0x74, 0xd0, 
    0x06, 0xb3, 0x10, 0x07, 
    0x72, 0x80, 0x07, 0x1a, 
    0x21, 0x0c, 0x69, 0x30, 
    0x00, 0xd2, 0xf8, 0xc2, 
    0x90, 0x0a, 0x20, 0x04, 
    0x00, 0x00, 0x02, 0x00, 
    0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x08, 0x00, 
    0x02, 0x18, 0x52, 0x11, 
    0x50, 0x01, 0x04, 0x80, 
    0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 
    0x00, 0x40, 0x00, 0x12, 
    0x1b, 0x04, 0x8a, 0xee, 
    0x09, 0x00, 0x00, 0x64, 
    0x81, 0x00, 0x00, 0x00, 
    0x07, 0x00, 0x00, 0x00, 
    0x32, 0x1e, 0x98, 0x10, 
    0x19, 0x11, 0x4c, 0x90, 
    0x8c, 0x09, 0x26, 0x47, 
    0xc6, 0x04, 0x43, 0x4a, 
    0x39, 0x94, 0x42, 0x11, 
    0x94, 0x41, 0x09, 0x14, 
    0x42, 0x41, 0x00, 0x00, 
    0xb1, 0x18, 0x00, 0x00, 
    0xc1, 0x00, 0x00, 0x00, 
    0x33, 0x08, 0x80, 0x1c, 
    0xc4, 0xe1, 0x1c, 0x66, 
    0x14, 0x01, 0x3d, 0x88, 
    0x43, 0x38, 0x84, 0xc3, 
    0x8c, 0x42, 0x80, 0x07, 
    0x79, 0x78, 0x07, 0x73, 
    0x98, 0x71, 0x0c, 0xe6, 
    0x00, 0x0f, 0xed, 0x10, 
    0x0e, 0xf4, 0x80, 0x0e, 
    0x33, 0x0c, 0x42, 0x1e, 
    0xc2, 0xc1, 0x1d, 0xce, 
    0xa1, 0x1c, 0x66, 0x30, 
    0x05, 0x3d, 0x88, 0x43, 
    0x38, 0x84, 0x83, 0x1b, 
    0xcc, 0x03, 0x3d, 0xc8, 
    0x43, 0x3d, 0x8c, 0x03, 
    0x3d, 0xcc, 0x78, 0x8c, 
    0x74, 0x70, 0x07, 0x7b, 
    0x08, 0x07, 0x79, 0x48, 
    0x87, 0x70, 0x70, 0x07, 
    0x7a, 0x70, 0x03, 0x76, 
    0x78, 0x87, 0x70, 0x20, 
    0x87, 0x19, 0xcc, 0x11, 
    0x0e, 0xec, 0x90, 0x0e, 
    0xe1, 0x30, 0x0f, 0x6e, 
    0x30, 0x0f, 0xe3, 0xf0, 
    0x0e, 0xf0, 0x50, 0x0e, 
    0x33, 0x10, 0xc4, 0x1d, 
    0xde, 0x21, 0x1c, 0xd8, 
    0x21, 0x1d, 0xc2, 0x61, 
    0x1e, 0x66, 0x30, 0x89, 
    0x3b, 0xbc, 0x83, 0x3b, 
    0xd0, 0x43, 0x39, 0xb4, 
    0x03, 0x3c, 0xbc, 0x83, 
    0x3c, 0x84, 0x03, 0x3b, 
    0xcc, 0xf0, 0x14, 0x76, 
    0x60, 0x07, 0x7b, 0x68, 
    0x07, 0x37, 0x68, 0x87, 
    0x72, 0x68, 0x07, 0x37, 
    0x80, 0x87, 0x70, 0x90, 
    0x87, 0x70, 0x60, 0x07, 
    0x76, 0x28, 0x07, 0x76, 
    0xf8, 0x05, 0x76, 0x78, 
    0x87, 0x77, 0x80, 0x87, 
    0x5f, 0x08, 0x87, 0x71, 
    0x18, 0x87, 0x72, 0x98, 
    0x87, 0x79, 0x98, 0x81, 
    0x2c, 0xee, 0xf0, 0x0e, 
    0xee, 0xe0, 0x0e, 0xf5, 
    0xc0, 0x0e, 0xec, 0x30, 
    0x03, 0x62, 0xc8, 0xa1, 
    0x1c, 0xe4, 0xa1, 0x1c, 
    0xcc, 0xa1, 0x1c, 0xe4, 
    0xa1, 0x1c, 0xdc, 0x61, 
    0x1c, 0xca, 0x21, 0x1c, 
    0xc4, 0x81, 0x1d, 0xca, 
    0x61, 0x06, 0xd6, 0x90, 
    0x43, 0x39, 0xc8, 0x43, 
    0x39, 0x98, 0x43, 0x39, 
    0xc8, 0x43, 0x39, 0xb8, 
    0xc3, 0x38, 0x94, 0x43, 
    0x38, 0x88, 0x03, 0x3b, 
    0x94, 0xc3, 0x2f, 0xbc, 
    0x83, 0x3c, 0xfc, 0x82, 
    0x3b, 0xd4, 0x03, 0x3b, 
    0xb0, 0xc3, 0x0c, 0xc7, 
    0x69, 0x87, 0x70, 0x58, 
    0x87, 0x72, 0x70, 0x83, 
    0x74, 0x68, 0x07, 0x78, 
    0x60, 0x87, 0x74, 0x18, 
    0x87, 0x74, 0xa0, 0x87, 
    0x19, 0xce, 0x53, 0x0f, 
    0xee, 0x00, 0x0f, 0xf2, 
    0x50, 0x0e, 0xe4, 0x90, 
    0x0e, 0xe3, 0x40, 0x0f, 
    0xe1, 0x20, 0x0e, 0xec, 
    0x50, 0x0e, 0x33, 0x20, 
    0x28, 0x1d, 0xdc, 0xc1, 
    0x1e, 0xc2, 0x41, 0x1e, 
    0xd2, 0x21, 0x1c, 0xdc, 
    0x81, 0x1e, 0xdc, 0xe0, 
    0x1c, 0xe4, 0xe1, 0x1d, 
    0xea, 0x01, 0x1e, 0x66, 
    0x18, 0x51, 0x38, 0xb0, 
    0x43, 0x3a, 0x9c, 0x83, 
    0x3b, 0xcc, 0x50, 0x24, 
    0x76, 0x60, 0x07, 0x7b, 
    0x68, 0x07, 0x37, 0x60, 
    0x87, 0x77, 0x78, 0x07, 
    0x78, 0x98, 0x51, 0x4c, 
    0xf4, 0x90, 0x0f, 0xf0, 
    0x50, 0x0e, 0x33, 0x1e, 
    0x6a, 0x1e, 0xca, 0x61, 
    0x1c, 0xe8, 0x21, 0x1d, 
    0xde, 0xc1, 0x1d, 0x7e, 
    0x01, 0x1e, 0xe4, 0xa1, 
    0x1c, 0xcc, 0x21, 0x1d, 
    0xf0, 0x61, 0x06, 0x54, 
    0x85, 0x83, 0x38, 0xcc, 
    0xc3, 0x3b, 0xb0, 0x43, 
    0x3d, 0xd0, 0x43, 0x39, 
    0xfc, 0xc2, 0x3c, 0xe4, 
    0x43, 0x3b, 0x88, 0xc3, 
    0x3b, 0xb0, 0xc3, 0x8c, 
    0xc5, 0x0a, 0x87, 0x79, 
    0x98, 0x87, 0x77, 0x18, 
    0x87, 0x74, 0x08, 0x07, 
    0x7a, 0x28, 0x07, 0x72, 
    0x98, 0x81, 0x5c, 0xe3, 
    0x10, 0x0e, 0xec, 0xc0, 
    0x0e, 0xe5, 0x50, 0x0e, 
    0xf3, 0x30, 0x23, 0xc1, 
    0xd2, 0x41, 0x1e, 0xe4, 
    0xe1, 0x17, 0xd8, 0xe1, 
    0x1d, 0xde, 0x01, 0x1e, 
    0x66, 0x48, 0x19, 0x3b, 
    0xb0, 0x83, 0x3d, 0xb4, 
    0x83, 0x1b, 0x84, 0xc3, 
    0x38, 0x8c, 0x43, 0x39, 
    0xcc, 0xc3, 0x3c, 0xb8, 
    0xc1, 0x39, 0xc8, 0xc3, 
    0x3b, 0xd4, 0x03, 0x3c, 
    0xcc, 0x48, 0xb4, 0x71, 
    0x08, 0x07, 0x76, 0x60, 
    0x07, 0x71, 0x08, 0x87, 
    0x71, 0x58, 0x87, 0x19, 
    0xdb, 0xc6, 0x0e, 0xec, 
    0x60, 0x0f, 0xed, 0xe0, 
    0x06, 0xf0, 0x20, 0x0f, 
    0xe5, 0x30, 0x0f, 0xe5, 
    0x20, 0x0f, 0xf6, 0x50, 
    0x0e, 0x6e, 0x10, 0x0e, 
    0xe3, 0x30, 0x0e, 0xe5, 
    0x30, 0x0f, 0xf3, 0xe0, 
    0x06, 0xe9, 0xe0, 0x0e, 
    0xe4, 0x50, 0x0e, 0xf8, 
    0x30, 0x23, 0xe2, 0xec, 
    0x61, 0x1c, 0xc2, 0x81, 
    0x1d, 0xd8, 0xe1, 0x17, 
    0xec, 0x21, 0x1d, 0xe6, 
    0x21, 0x1d, 0xc4, 0x21, 
    0x1d, 0xd8, 0x21, 0x1d, 
    0xe8, 0x21, 0x1f, 0x66, 
    0x20, 0x9d, 0x3b, 0xbc, 
    0x43, 0x3d, 0xb8, 0x03, 
    0x39, 0x94, 0x83, 0x39, 
    0xcc, 0x58, 0xbc, 0x70, 
    0x70, 0x07, 0x77, 0x78, 
    0x07, 0x7a, 0x08, 0x07, 
    0x7a, 0x48, 0x87, 0x77, 
    0x70, 0x87, 0x19, 0xcb, 
    0xe7, 0x0e, 0xef, 0x30, 
    0x0f, 0xe1, 0xe0, 0x0e, 
    0xe9, 0x40, 0x0f, 0xe9, 
    0xa0, 0x0f, 0xe5, 0x30, 
    0xc3, 0x01, 0x03, 0x73, 
    0xa8, 0x07, 0x77, 0x18, 
    0x87, 0x5f, 0x98, 0x87, 
    0x70, 0x70, 0x87, 0x74, 
    0xa0, 0x87, 0x74, 0xd0, 
    0x87, 0x72, 0x98, 0x81, 
    0x84, 0x41, 0x39, 0xe0, 
    0xc3, 0x38, 0xb0, 0x43, 
    0x3d, 0x90, 0x43, 0x39, 
    0xcc, 0x40, 0xc4, 0xa0, 
    0x1d, 0xca, 0xa1, 0x1d, 
    0xe0, 0x41, 0x1e, 0xde, 
    0xc1, 0x1c, 0x66, 0x24, 
    0x63, 0x30, 0x0e, 0xe1, 
    0xc0, 0x0e, 0xec, 0x30, 
    0x0f, 0xe9, 0x40, 0x0f, 
    0xe5, 0x30, 0x43, 0x21, 
    0x83, 0x75, 0x18, 0x07, 
    0x73, 0x48, 0x87, 0x5f, 
    0xa0, 0x87, 0x7c, 0x80, 
    0x87, 0x72, 0x98, 0xb1, 
    0x94, 0x01, 0x3c, 0x8c, 
    0xc3, 0x3c, 0x94, 0xc3, 
    0x38, 0xd0, 0x43, 0x3a, 
    0xbc, 0x83, 0x3b, 0xcc, 
    0xc3, 0x8c, 0xc5, 0x0c, 
    0x48, 0x21, 0x15, 0x42, 
    0x61, 0x1e, 0xe6, 0x21, 
    0x1d, 0xce, 0xc1, 0x1d, 
    0x52, 0x81, 0x14, 0x66, 
    0x4c, 0x67, 0x30, 0x0e, 
    0xef, 0x20, 0x0f, 0xef, 
    0xe0, 0x06, 0xef, 0x50, 
    0x0f, 0xf4, 0x30, 0x0f, 
    0xe9, 0x40, 0x0e, 0xe5, 
    0xe0, 0x06, 0xe6, 0x20, 
    0x0f, 0xe1, 0xd0, 0x0e, 
    0xe5, 0x00, 0x00, 0x00, 
    0x79, 0x20, 0x00, 0x00, 
    0x6a, 0x00, 0x00, 0x00, 
    0x72, 0x1e, 0x48, 0x20, 
    0x43, 0x88, 0x0c, 0x19, 
    0x09, 0x72, 0x32, 0x48, 
    0x20, 0x23, 0x81, 0x8c, 
    0x91, 0x91, 0xd1, 0x44, 
    0xa0, 0x10, 0x28, 0x64, 
    0x3c, 0x31, 0x32, 0x42, 
    0x8e, 0x90, 0x21, 0xa3, 
    0xb8, 0x30, 0xf4, 0x01, 
    0xc6, 0x02, 0x06, 0xe8, 
    0xd0, 0x48, 0x4a, 0x92, 
    0x1c, 0x0d, 0x00, 0x00, 
    0x6d, 0x61, 0x69, 0x6e, 
    0x2e, 0x63, 0x2f, 0x68, 
    0x6f, 0x6d, 0x65, 0x2f, 
    0x64, 0x61, 0x76, 0x69, 
    0x64, 0x64, 0x35, 0x36, 
    0x65, 0x30, 0x63, 0x30, 
    0x39, 0x62, 0x30, 0x32, 
    0x32, 0x33, 0x37, 0x61, 
    0x61, 0x37, 0x38, 0x63, 
    0x61, 0x62, 0x39, 0x39, 
    0x64, 0x35, 0x36, 0x65, 
    0x65, 0x65, 0x36, 0x63, 
    0x63, 0x63, 0x6c, 0x61, 
    0x6e, 0x67, 0x20, 0x76, 
    0x65, 0x72, 0x73, 0x69, 
    0x6f, 0x6e, 0x20, 0x31, 
    0x38, 0x2e, 0x31, 0x2e, 
    0x36, 0x20, 0x28, 0x68, 
    0x74, 0x74, 0x70, 0x73, 
    0x3a, 0x2f, 0x2f, 0x67, 
    0x69, 0x74, 0x68, 0x75, 
    0x62, 0x2e, 0x63, 0x6f, 
    0x6d, 0x2f, 0x6c, 0x6c, 
    0x76, 0x6d, 0x2f, 0x6c, 
    0x6c, 0x76, 0x6d, 0x2d, 
    0x70, 0x72, 0x6f, 0x6a, 
    0x65, 0x63, 0x74, 0x2e, 
    0x67, 0x69, 0x74, 0x20, 
    0x62, 0x63, 0x65, 0x39, 
    0x33, 0x39, 0x33, 0x32, 
    0x39, 0x31, 0x61, 0x32, 
    0x64, 0x61, 0x61, 0x38, 
    0x30, 0x30, 0x36, 0x64, 
    0x31, 0x64, 0x61, 0x36, 
    0x32, 0x39, 0x61, 0x61, 
    0x32, 0x37, 0x36, 0x35, 
    0x65, 0x30, 0x30, 0x66, 
    0x34, 0x65, 0x37, 0x30, 
    0x29, 0x44, 0x77, 0x61, 
    0x72, 0x66, 0x20, 0x56, 
    0x65, 0x72, 0x73, 0x69, 
    0x6f, 0x6e, 0x44, 0x65, 
    0x62, 0x75, 0x67, 0x20, 
    0x49, 0x6e, 0x66, 0x6f, 
    0x20, 0x56, 0x65, 0x72, 
    0x73, 0x69, 0x6f, 0x6e, 
    0x77, 0x63, 0x68, 0x61, 
    0x72, 0x5f, 0x73, 0x69, 
    0x7a, 0x65, 0x50, 0x49, 
    0x43, 0x20, 0x4c, 0x65, 
    0x76, 0x65, 0x6c, 0x50, 
    0x49, 0x45, 0x20, 0x4c, 
    0x65, 0x76, 0x65, 0x6c, 
    0x75, 0x77, 0x74, 0x61, 
    0x62, 0x6c, 0x65, 0x66, 
    0x72, 0x61, 0x6d, 0x65, 
    0x2d, 0x70, 0x6f, 0x69, 
    0x6e, 0x74, 0x65, 0x72, 
    0x23, 0x08, 0x81, 0x30, 
    0x82, 0x10, 0x0c, 0x23, 
    0x08, 0x01, 0x31, 0x82, 
    0x10, 0x14, 0x23, 0x08, 
    0x81, 0x31, 0x82, 0x10, 
    0x1c, 0x23, 0x08, 0x01, 
    0x32, 0x94, 0x15, 0x74, 
    0x14, 0x01, 0x00, 0x00, 
    0x10, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 
    0x02, 0x00, 0x00, 0x03, 
    0x15, 0x40, 0x20, 0x04, 
    0xc3, 0x0c, 0x03, 0x53, 
    0x34, 0x33, 0x0c, 0x8e, 
    0xf1, 0xcc, 0x30, 0x40, 
    0x47, 0x34, 0xc3, 0x20, 
    0x21, 0xce, 0x0c, 0x03, 
    0x93, 0x38, 0x33, 0x0c, 
    0x8c, 0xe2, 0xcc, 0x30, 
    0x30, 0x8b, 0x33, 0x43, 
    0x40, 0xc8, 0x48, 0x60, 
    0x82, 0x72, 0x61, 0x63, 
    0xb3, 0x6b, 0x73, 0x21, 
    0x13, 0x3b, 0x73, 0x19, 
    0xab, 0x1b, 0x25, 0x90, 
    0x32, 0x62, 0x63, 0xb3, 
    0x6b, 0x73, 0x69, 0x7b, 
    0x23, 0xab, 0x63, 0x2b, 
    0x73, 0x31, 0x63, 0x0b, 
    0x3b, 0x9b, 0x1b, 0xe5, 
    0xa0, 0x2a, 0xeb, 0xc2, 
    0x32, 0x2d, 0x15, 0x36, 
    0x36, 0xbb, 0x36, 0x97, 
    0x34, 0xb2, 0x32, 0x37, 
    0xba, 0x51, 0x82, 0x0d, 
    0x00, 0x00, 0x00, 0x00, 
    0xa9, 0x18, 0x00, 0x00, 
    0x2d, 0x00, 0x00, 0x00, 
    0x0b, 0x0a, 0x72, 0x28, 
    0x87, 0x77, 0x80, 0x07, 
    0x7a, 0x58, 0x70, 0x98, 
    0x43, 0x3d, 0xb8, 0xc3, 
    0x38, 0xb0, 0x43, 0x39, 
    0xd0, 0xc3, 0x82, 0xe6, 
    0x1c, 0xc6, 0xa1, 0x0d, 
    0xe8, 0x41, 0x1e, 0xc2, 
    0xc1, 0x1d, 0xe6, 0x21, 
    0x1d, 0xe8, 0x21, 0x1d, 
    0xde, 0xc1, 0x1d, 0x16, 
    0x34, 0xe3, 0x60, 0x0e, 
    0xe7, 0x50, 0x0f, 0xe1, 
    0x20, 0x0f, 0xe4, 0x40, 
    0x0f, 0xe1, 0x20, 0x0f, 
    0xe7, 0x50, 0x0e, 0xf4, 
    0xb0, 0x80, 0x81, 0x07, 
    0x79, 0x28, 0x87, 0x70, 
    0x60, 0x07, 0x76, 0x78, 
    0x87, 0x71, 0x08, 0x07, 
    0x7a, 0x28, 0x07, 0x72, 
    0x58, 0x70, 0x9c, 0xc3, 
    0x38, 0xb4, 0x01, 0x3b, 
    0xa4, 0x83, 0x3d, 0x94, 
    0xc3, 0x02, 0x6b, 0x1c, 
    0xd8, 0x21, 0x1c, 0xdc, 
    0xe1, 0x1c, 0xdc, 0x20, 
    0x1c, 0xe4, 0x61, 0x1c, 
    0xdc, 0x20, 0x1c, 0xe8, 
    0x81, 0x1e, 0xc2, 0x61, 
    0x1c, 0xd0, 0xa1, 0x1c, 
    0xc8, 0x61, 0x1c, 0xc2, 
    0x81, 0x1d, 0xd8, 0x61, 
    0xc1, 0x01, 0x0f, 0xf4, 
    0x20, 0x0f, 0xe1, 0x50, 
    0x0f, 0xf4, 0x80, 0x0e, 
    0x0b, 0x88, 0x75, 0x18, 
    0x07, 0x73, 0x48, 0x87, 
    0x05, 0xcf, 0x38, 0xbc, 
    0x83, 0x3b, 0xd8, 0x43, 
    0x39, 0xc8, 0xc3, 0x39, 
    0x94, 0x83, 0x3b, 0x8c, 
    0x43, 0x39, 0x8c, 0x03, 
    0x3d, 0xc8, 0x03, 0x3b, 
    0x00, 0x00, 0x00, 0x00, 
    0xd1, 0x10, 0x00, 0x00, 
    0x06, 0x00, 0x00, 0x00, 
    0x07, 0xcc, 0x3c, 0xa4, 
    0x83, 0x3b, 0x9c, 0x03, 
    0x3b, 0x94, 0x03, 0x3d, 
    0xa0, 0x83, 0x3c, 0x94, 
    0x43, 0x38, 0x90, 0xc3, 
    0x01, 0x00, 0x00, 0x00, 
    0x61, 0x20, 0x00, 0x00, 
    0x4d, 0x00, 0x00, 0x00, 
    0x13, 0x04, 0x41, 0x2c, 
    0x10, 0x00, 0x00, 0x00, 
    0x01, 0x00, 0x00, 0x00, 
    0x94, 0x11, 0x00, 0x00, 
    0xf1, 0x30, 0x00, 0x00, 
    0x24, 0x00, 0x00, 0x00, 
    0x22, 0x47, 0xc8, 0x90, 
    0x51, 0x16, 0xc4, 0x05, 
    0xc4, 0x40, 0x10, 0x04, 
    0x6d, 0x61, 0x69, 0x6e, 
    0x69, 0x6e, 0x74, 0x63, 
    0x68, 0x61, 0x72, 0x61, 
    0x72, 0x67, 0x63, 0x61, 
    0x72, 0x67, 0x76, 0x00, 
    0xab, 0xa8, 0x83, 0xea, 
    0x00, 0x2a, 0x40, 0x03, 
    0x01, 0x40, 0x00, 0x10, 
    0x99, 0x00, 0x20, 0x0d, 
    0x00, 0x00, 0x00, 0xf6, 
    0x1c, 0x00, 0x19, 0x78, 
    0x60, 0x00, 0x14, 0xc0, 
    0x9e, 0x03, 0x20, 0x83, 
    0x0f, 0x01, 0x0c, 0x60, 
    0x91, 0x03, 0x3c, 0x00, 
    0x00, 0x00, 0x64, 0x00, 
    0x0a, 0x00, 0x00, 0x00, 
    0x00, 0xb0, 0xc8, 0x01, 
    0x1e, 0x00, 0x00, 0x80, 
    0x32, 0x00, 0x05, 0x00, 
    0x00, 0x00, 0x00, 0xd8, 
    0x30, 0x8c, 0xc1, 0x18, 
    0x98, 0xc1, 0x26, 0x42, 
    0x00, 0xce, 0x00, 0xd8, 
    0x00, 0x8c, 0x53, 0x04, 
    0x31, 0x00, 0x03, 0x2a, 
    0x18, 0x83, 0x00, 0x00, 
    0x80, 0x75, 0x81, 0x31, 
    0x4e, 0x11, 0xc4, 0x20, 
    0x0c, 0xa8, 0xc0, 0x0c, 
    0x04, 0x00, 0x00, 0x26, 
    0x08, 0x40, 0x33, 0x41, 
    0x00, 0x1c, 0x00, 0x00, 
    0x33, 0x11, 0x41, 0x60, 
    0x8c, 0xc2, 0x4c, 0x44, 
    0x10, 0x18, 0xa3, 0x30, 
    0x13, 0x01, 0x04, 0x06, 
    0x29, 0x0c, 0x1b, 0x10, 
    0x03, 0x31, 0x00, 0xc3, 
    0x06, 0x84, 0x60, 0x0c, 
    0xc0, 0x88, 0xc1, 0x01, 
    0x80, 0x20, 0x18, 0x14, 
    0xce, 0xf8, 0xff, 0xff, 
    0xff, 0x0f, 0xe6, 0xff, 
    0xff, 0xff, 0x3f, 0x94, 
    0xff, 0xff, 0xff, 0xff, 
    0x30, 0x63, 0x50, 0x04, 
    0x8e, 0x18, 0x00, 0xc0, 
    0xb0, 0x01, 0x11, 0x14, 
    0x04, 0x30, 0x62, 0x70, 
    0x00, 0x20, 0x08, 0x06, 
    0x85, 0x23, 0xfe, 0xff, 
    0xff, 0xff, 0x03, 0xf9, 
    0xff, 0xff, 0xff, 0x0f, 
    0xe5, 0xff, 0xff, 0xff, 
    0x3f, 0xcc, 0x18, 0x14, 
    0xc1, 0x26, 0x06, 0x00, 
    0xc0, 0xc4, 0x8c, 0x41, 
    0x31, 0x14, 0x62, 0x00, 
    0x00, 0x01, 0x31, 0x00, 
    0x02, 0x00, 0x00, 0x00, 
    0x5b, 0x04, 0x20, 0x0c, 
    0x00, 0x00, 0x00, 0x00, 
    0x21, 0x31, 0x00, 0x00, 
    0x02, 0x00, 0x00, 0x00, 
    0x0b, 0x86, 0x00, 0x08, 
    0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 
    0x71, 0x20, 0x00, 0x00, 
    0x03, 0x00, 0x00, 0x00, 
    0x32, 0x0e, 0x10, 0x22, 
    0x84, 0x00, 0xac, 0x04, 
    0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 
    0x65, 0x0c, 0x00, 0x00, 
    0x25, 0x00, 0x00, 0x00, 
    0x12, 0x03, 0x94, 0x28, 
    0x01, 0x00, 0x00, 0x00, 
    0x03, 0x00, 0x00, 0x00, 
    0x14, 0x00, 0x00, 0x00, 
    0x2f, 0x00, 0x00, 0x00, 
    0x4c, 0x00, 0x00, 0x00, 
    0x01, 0x00, 0x00, 0x00, 
    0x58, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 
    0x58, 0x00, 0x00, 0x00, 
    0x02, 0x00, 0x00, 0x00, 
    0x88, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 
    0x43, 0x00, 0x00, 0x00, 
    0x18, 0x00, 0x00, 0x00, 
    0x5b, 0x00, 0x00, 0x00, 
    0x06, 0x00, 0x00, 0x00, 
    0x04, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 
    0x88, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 
    0x02, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 
    0x04, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 
    0x04, 0x00, 0x00, 0x00, 
    0xff, 0xff, 0xff, 0xff, 
    0x00, 0x24, 0x00, 0x00, 
    0x04, 0x00, 0x00, 0x00, 
    0x10, 0x00, 0x00, 0x00, 
    0x04, 0x00, 0x00, 0x00, 
    0x10, 0x00, 0x00, 0x00, 
    0xff, 0xff, 0xff, 0xff, 
    0x08, 0x2c, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 
    0x5d, 0x0c, 0x00, 0x00, 
    0x1c, 0x00, 0x00, 0x00, 
    0x12, 0x03, 0x94, 0xe1, 
    0x00, 0x00, 0x00, 0x00, 
    0x6d, 0x61, 0x69, 0x6e, 
    0x6c, 0x6c, 0x76, 0x6d, 
    0x2e, 0x64, 0x62, 0x67, 
    0x2e, 0x64, 0x65, 0x63, 
    0x6c, 0x61, 0x72, 0x65, 
    0x31, 0x38, 0x2e, 0x31, 
    0x2e, 0x36, 0x20, 0x62, 
    0x63, 0x65, 0x39, 0x33, 
    0x39, 0x33, 0x32, 0x39, 
    0x31, 0x61, 0x32, 0x64, 
    0x61, 0x61, 0x38, 0x30, 
    0x30, 0x36, 0x64, 0x31, 
    0x64, 0x61, 0x36, 0x32, 
    0x39, 0x61, 0x61, 0x32, 
    0x37, 0x36, 0x35, 0x65, 
    0x30, 0x30, 0x66, 0x34, 
    0x65, 0x37, 0x30, 0x78, 
    0x38, 0x36, 0x5f, 0x36, 
    0x34, 0x2d, 0x75, 0x6e, 
    0x6b, 0x6e, 0x6f, 0x77, 
    0x6e, 0x2d, 0x6c, 0x69, 
    0x6e, 0x75, 0x78, 0x2d, 
    0x67, 0x6e, 0x75, 0x6d, 
    0x61, 0x69, 0x6e, 0x2e, 
    0x63, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 
};

pub fn make() void {
    instance.arena = library.Arena.init(4 * 1024 * 1024) catch unreachable;
    // var modules: [2]*LLVM.Module = undefined;
    // {
    //     const context = LLVM.Context.create();
    //     const module_name: []const u8 = "thread";
    //     const module = LLVM.Module.create(module_name.ptr, module_name.len, context);
    //     const builder = LLVM.Builder.create(context);
    //     // const attributes = LLVM.Attributes{
    //     //     .naked = context.getAttributeFromEnum(.Naked, 0),
    //     //     .noreturn = context.getAttributeFromEnum(.NoReturn, 0),
    //     //     .nounwind = context.getAttributeFromEnum(.NoUnwind, 0),
    //     //     .inreg = context.getAttributeFromEnum(.InReg, 0),
    //     //     .@"noalias" = context.getAttributeFromEnum(.NoAlias, 0),
    //     // };
    //     const int32 = context.getIntegerType(32);
    //     const function_type = LLVM.getFunctionType(int32.toType(), undefined, 0, false);
    //     const function = module.createFunction(function_type, .internal, 0, "foo", "foo".len);
    //     const entry_basic_block = context.createBasicBlock("", "".len, function, null);
    //     builder.setInsertPoint(entry_basic_block);
    //
    //     const call_function = module.createFunction(function_type, .@"extern", 0, "fa", "fa".len);
    //
    //     const call = builder.createCall(function_type, call_function.toValue(), undefined, 0, "", "".len, null);
    //     _ = builder.createRet(call.toValue());
    //     var message: []const u8 = undefined;
    //     //_ = message; // autofix
    //     const v = module.verify(&message.ptr, &message.len);
    //     if (!v) exit_with_error(message);
    //     modules[0] = module;
    // }
    //
    // {
    //     const context = LLVM.Context.create();
    //     const module_name: []const u8 = "thread";
    //     const module = LLVM.Module.create(module_name.ptr, module_name.len, context);
    //     const builder = LLVM.Builder.create(context);
    //     // const attributes = LLVM.Attributes{
    //     //     .naked = context.getAttributeFromEnum(.Naked, 0),
    //     //     .noreturn = context.getAttributeFromEnum(.NoReturn, 0),
    //     //     .nounwind = context.getAttributeFromEnum(.NoUnwind, 0),
    //     //     .inreg = context.getAttributeFromEnum(.InReg, 0),
    //     //     .@"noalias" = context.getAttributeFromEnum(.NoAlias, 0),
    //     // };
    //     const int32 = context.getIntegerType(32);
    //     const function_type = LLVM.getFunctionType(int32.toType(), undefined, 0, false);
    //     const function = module.createFunction(function_type, .@"internal", 0, "fa", "fa".len);
    //     const entry_basic_block = context.createBasicBlock("", "".len, function, null);
    //     builder.setInsertPoint(entry_basic_block);
    //
    //     const constant_int = context.getConstantInt(32, 5, false);
    //     _ = builder.createRet(constant_int.toValue());
    //     var message: []const u8 = undefined;
    //     const v = module.verify(&message.ptr, &message.len);
    //     if (!v) exit_with_error(message);
    //     modules[1] = module;
    // }
    //
    // const result = LLVMLinkModules2(modules[0], modules[1]);
    // var foo: []const u8 = undefined;
    // modules[0].toString(&foo.ptr, &foo.len);
    // std.debug.print("Result: {}\n{s}\n", .{result, foo});

    const thread_count = std.Thread.getCpuCount() catch unreachable;
    cpu_count = @intCast(thread_count);
    threads = instance.arena.new_array(Thread, cpu_count - 1) catch unreachable;
    for (threads) |*thread| {
        thread.* = .{};
    }
    cpu_count -= 2;
    _ = std.Thread.spawn(.{}, thread_callback, .{cpu_count}) catch unreachable;

    // Initialize LLVM in all threads
    if (do_codegen) {
        const llvm_job = Job{
            .offset = 0,
            .count = 0,
            .id = .llvm_setup,
        };
        for (threads) |*thread| {
            thread.add_thread_work(llvm_job);
        }
    }

    const first_file_relative_path = "retest/standalone/first/main.nat";
    const first_file_absolute_path = library.realpath(instance.arena, std.fs.cwd(), first_file_relative_path) catch unreachable;
    const new_file_index = add_file(first_file_absolute_path, &.{});
    var last_assigned_thread_index: u32 = 0;
    threads[last_assigned_thread_index].add_thread_work(Job{
        .offset = @intFromEnum(new_file_index),
        .id = .analyze_file,
    });

    while (true) {
        var worker_pending_tasks: u64 = 0;
        var control_pending_tasks: u64 = 0;
        for (threads) |*thread| {
            worker_pending_tasks += thread.task_system.job.to_do - thread.task_system.job.completed;
            control_pending_tasks += thread.task_system.ask.to_do - thread.task_system.ask.completed;
        }

        const pending_tasks = worker_pending_tasks + control_pending_tasks;
        if (pending_tasks == 0) {
            break;
        }

        if (control_pending_tasks > 0) {
            for (threads, 0..) |*thread, i| {
                const control_pending = thread.task_system.ask.to_do - thread.task_system.ask.completed;
                if (control_pending != 0) {
                    const jobs_to_do = thread.task_system.ask.entries[thread.task_system.ask.completed..thread.task_system.ask.to_do];

                    for (jobs_to_do) |job| {
                        switch (job.id) {
                            .analyze_file => {
                                last_assigned_thread_index += 1;
                                const analyze_file_path_hash = job.offset;
                                for (instance.file_paths.slice()) |file_path_hash| {
                                    if (analyze_file_path_hash == file_path_hash) {
                                        exit(1);
                                    }
                                } else {
                                    last_assigned_thread_index += 1;
                                    const thread_index = last_assigned_thread_index % threads.len;
                                    const file_absolute_path = thread.identifiers.get(analyze_file_path_hash).?;
                                    const interested_thread_index: u32 = @intCast(i);
                                    const file_index = add_file(file_absolute_path, &.{interested_thread_index});
                                    const assigned_thread = &threads[thread_index];
                                    assigned_thread.add_thread_work(Job{
                                        .offset = @intFromEnum(file_index),
                                        .id = .analyze_file,
                                    });
                                }
                            },
                            .notify_file_resolved => {
                                const file_index = job.offset;
                                const thread_index = job.count;
                                const destination_thread = &threads[thread_index];
                                const file = instance.files.get(@enumFromInt(file_index));
                                const file_path_hash = hash_bytes(file.path);
                                destination_thread.add_thread_work(.{
                                    .id = .notify_file_resolved,
                                    .count = @intCast(file_index),
                                    .offset = file_path_hash,
                                });
                            },
                            else => |t| @panic(@tagName(t)),
                        }
                    }

                    thread.task_system.ask.completed += jobs_to_do.len;
                }
            }
        }
    }

    {
        // finish thread semantic analysis
        for (threads) |*thread| {
            thread.add_thread_work(Job{
                .id = .resolve_thread_module,
            });
        }
    }

    // TODO: Prune
    if (do_codegen) {
        for (threads) |*thread| {
            thread.add_thread_work(Job{
                .id = switch (codegen_backend) {
                    .llvm => .llvm_codegen_thread_module,
                },
            });
        }

        while (true) {
            var to_do: u64 = 0;
            for (threads) |*thread| {
                const jobs_to_do = thread.task_system.job.to_do - thread.task_system.job.completed;
                const asks_to_do = thread.task_system.ask.to_do - thread.task_system.ask.completed;
                assert(asks_to_do == 0);

                to_do += jobs_to_do;
            }

            if (to_do == 0) {
                break;
            }
        }

        var modules_present = PinnedArray(usize){};
        for (threads, 0..) |*thread, i| {
            if (thread.functions.length > 0) {
                _ = modules_present.append(i);
            }
        }

        switch (modules_present.length) {
            0 => unreachable,
            1 => {},
            2 => {
                // const first = modules_present.slice()[0];
                // const second = modules_present.slice()[1];
                // const destination = threads[first].llvm.module;
                // {
                //     var message: []const u8 = undefined;
                //     destination.toString(&message.ptr, &message.len);
                //     std.debug.print("{s}\n", .{message});
                // }
                // const source = threads[second].llvm.module;
                // {
                //     var message: []const u8 = undefined;
                //     source.toString(&message.ptr, &message.len);
                //     std.debug.print("{s}\n", .{message});
                // }
                //
                // if (!destination.link(source, .{
                //     .override_from_source = true,
                //     .link_only_needed = false,
                // })) {
                //     exit(1);
                // }
                //
                // var message: []const u8 = undefined;
                // destination.toString(&message.ptr, &message.len);
                // std.debug.print("============\n===========\n{s}\n", .{message});
            },
            else => unreachable,
        }
    }

    while (true) {}
}

fn intern_identifier(pool: *PinnedHashMap(u32, []const u8), identifier: []const u8) u32 {
    const start_index = @intFromBool(identifier[0] == '"');
    const end_index = identifier.len - start_index;
    const hash = hash_bytes(identifier[start_index..end_index]);
    pool.put(hash, identifier);

    return hash;
}

// fn resolve_call(thread: *Thread, file_index: u32, expression: *Expression) void {
//     assert(expression.kind == .unresolved and expression.kind.unresolved == .call_expression);
//     const unresolved_call_expression = expression.kind.unresolved.call_expression;
//     resolve_expression(thread, file_index, unresolved_call_expression.callee);
//     const function_expression = unresolved_call_expression.callee;
//     switch (function_expression.kind) {
//         .resolved => |resolved| switch (resolved) {
//             .declaration => |declaration| switch (declaration.id) {
//                 .function_definition => |fn_def| {
//                     _ = fn_def; // autofix
//                     _ = expression.instruction;
//                     const basic_block = thread.basic_blocks.get(expression.basic_block);
//                     const call = thread.calls.append_index(.{});
//                     const instruction = thread.instructions.append(.{
//                         .id = .call,
//                         .index = @intCast(@intFromEnum(call)),
//                     });
//                     _ = basic_block.instructions.append(instruction);
//                     expression.kind = .{
//                         .resolved = .{
//                             .instruction = instruction,
//                         },
//                     };
//                 },
//                 else => |t| @panic(@tagName(t)),
//             },
//             else => |t| @panic(@tagName(t)),
//         },
//         else => |t| @panic(@tagName(t)),
//     }
// }

fn resolve_value(thread: *Thread, file_index: u32, value: *Value) void {
    _ = thread; // autofix
    _ = file_index; // autofix
    _ = value; // autofix
    unreachable;
    // switch (expression.kind) {
    //     .unresolved => |unresolved_expression| switch (unresolved_expression) {
    //         .import => |declaration| {
    //             declaration.* = .{
    //                 .id = .file,
    //                 .index = @intCast(file_index),
    //             };
    //
    //             expression.kind = .{
    //                 .resolved = .{
    //                     .import = declaration,
    //                 },
    //             };
    //         },
    //         .call_expression => resolve_call(thread, file_index, expression),
    //         .field_expression => |field_expression| {
    //             resolve_expression(thread, file_index, field_expression.left);
    //
    //             switch (field_expression.left.kind) {
    //                 .resolved => |resolved_expression| switch (resolved_expression) {
    //                     .import => |declaration| {
    //                         assert(declaration.id == .file);
    //                         const resolved_file_index = declaration.index;
    //                         const file = &instance.files.pointer[resolved_file_index];
    //
    //                         const file_scope = &threads[file.thread].file_scopes.pointer[file.scope.index];
    //                         if (file_scope.declarations.get_pointer(field_expression.right)) |symbol| {
    //                             expression.kind = .{
    //                                 .resolved = .{
    //                                     .declaration = symbol,
    //                                 },
    //                             };
    //                         } else {
    //                             exit(1);
    //                         }
    //                     },
    //                     else => |t| @panic(@tagName(t)),
    //                 },
    //                 else => |t| @panic(@tagName(t)),
    //             }
    //         },
    //     },
    //     .resolved => {},
    // }
}

const Bitcode = struct {
    const Block = struct{
        start_size_index: u32,
        previous_code_size: u32,
        previous_abbreviations: PinnedArray(*Abbreviation) = .{},
    };

    const BlockInfo = struct{
        id: u32,
        abbreviations: PinnedArray(*Abbreviation) = .{},
    };

    const BlockId = enum(u8){
        block_info = 0,
        module = 8,
        parameter_attribute = 9,
        parameter_attribute_group = 10,
        constant = 11,
        function = 12,
        identification = 13,
        value_symtab = 14,
        metadata = 15,
        metadata_attachment = 16,
        type = 17,
        uselist = 18,
        module_strtab = 19,
        global_value_summary = 20,
        operand_bundle_tags = 21,
        metadata_kind = 22,
        strtab = 23,
        full_lto_global_value_summary = 24,
        symtab = 25,
        sync_scope_names = 26,
    };

    const ValueSymtabAbbreviationId = enum(u8){
        const base = @intFromEnum(FixedAbbreviationId.first_application_abbrev);
        entry8 = base + 0,
        entry7 = base + 1,
        entry6 = base + 2,
        bb_entry6 = base + 3,
    };

    const ConstantAbbreviationId = enum(u8) {
        const base = @intFromEnum(FixedAbbreviationId.first_application_abbrev);
        set_type = base + 0,
        integer = base + 1,
        cast = base + 2,
        null = base + 3,
    };

    const FunctionAbbreviationId = enum(u8) {
        const base = @intFromEnum(FixedAbbreviationId.first_application_abbrev);
        load = base + 0,
        unary_op = base + 1,
        unary_op_flags = base + 2,
        binary_op = base + 3,
        binary_op_flags = base + 4,
        cast = base + 5,
        cast_flags = base + 6,
        ret_void = base + 7,
        ret_val = base + 8,
        @"unreachable" = base + 9,
        gep = base + 10,
    };

    const Abbreviation = struct{
        operands: PinnedArray(Op) = .{},

        const Op = struct{
            value: u64,
            encoding: Encoding,
            is_literal: bool,

            const Encoding = enum(u3) {
                fixed = 1,
                vbr = 2,
                array = 3,
                char6 = 4,
                blob = 5,
                _,
            };

            pub fn get_encoding_data(operand: Op) ?u64 {
                return switch (operand.encoding) {
                    .fixed, .vbr => operand.value,
                    .array, .char6, .blob => null,
                    _ => unreachable,
                };
            }
        };

        pub fn add_literal(abbreviation: *Abbreviation, value: u64) void {
            abbreviation.add_with_encoding_advanced(.{
                .value = value,
                .encoding = @enumFromInt(0),
                .is_literal = true,
            });
        }

        pub fn add_with_encoding(abbreviation: *Abbreviation, data: struct {
            encoding: Op.Encoding,
            value: u64 = 0,
        }) void {
            abbreviation.add_with_encoding_advanced(.{
                .value = data.value,
                .encoding = data.encoding,
                .is_literal = false,
            });
        }

        pub fn add_with_encoding_advanced(abbreviation: *Abbreviation, op: Op) void {
            _ = abbreviation.operands.append(op);
        }
    };


    const FixedAbbreviationId = enum(u8) {
        end_block = 0,
        enter_subblock = 1,
        define_abbrev = 2,
        unabbrev_record = 3,
        first_application_abbrev = 4,
    };

    const width = struct {
        const block_id = 8;
        const code_length = 8;
        const block_size = 32;
    };

    const IdentificationCode = enum(u2) {
        string = 1,
        epoch = 2,
    };

    const ModuleCode = enum(u8) {
        version = 1,
        triple = 2,
        data_layout = 3,
        @"asm" = 4,
        section_name = 5,
        dep_lib = 6,
        global_var = 7,
        function = 8,
        alias_old = 9,
        gc_name = 11,
        comdat = 12,
        vst_offset = 13,
        alias = 14,
        metadata_values_unused = 15,
        source_filename = 16,
        hash = 17,
        ifunc = 18,
    };

    const ValueSymtabCode = enum(u8) {
        entry = 1,
        bb_entry = 2,
        fn_entry = 3,
        combined_entry = 5,
    };

    const ConstantCode = enum(u8) {
        set_type = 1,
        null = 2,
        undef = 3,
        integer = 4,
        wide_integer = 5,
        float = 6,
        aggregate = 7,
        string = 8,
        cstring = 9,
        binary_op = 10,
        cast = 11,
        gep = 12,
        select = 13,
        extract_element = 14,
        insert_element = 15,
        shuffle_vector = 16,
        cmp = 17,
        inline_assembly_old = 18,
        shuffle_vector_ex = 19,
        inbounds_gep = 20,
        block_address = 21,
        data = 22,
        inline_asm_old2 = 23,
        gep_with_inrange_index = 24,
        unary_op = 25,
        poison = 26,
        dso_local_equivalent = 27,
        inline_asm_old3 = 28,
        no_cfi_value = 29,
        inline_asm = 30,
    };

    const FunctionCode = enum(u8) {
        declare_blocks = 1,
        binary_op = 2,
        cast = 3,
        gep_old = 4,
        select = 5,
        extract_element = 6,
        insert_element = 7,
        shuffle_vector = 8,
        cmp = 9,
        ret = 10,
        br = 11,
        @"switch" = 12,
        invoke = 13,
        @"unreachable" = 15,
        phi = 16,
        alloca = 19,
        load = 20,
        vaarg = 23,
        store_old = 24,
        extract_value = 26,
        insert_value = 27,
        cmp2 = 28,
        vselect = 29,
        inbounds_gep_old = 30,
        indirect_br = 31,
        debug_loc_again = 33,
        call = 34,
        debug_loc = 35,
        fence = 36,
        cmpxchg_old = 37,
        atomic_rmw_old = 38,
        @"resume" = 39,
        landing_pad_old = 40,
        load_atomic = 41,
        store_atomic_old = 42,
        gep = 43,
        store = 44,
        store_atomic = 45,
        cmpxchg = 46,
        landing_pad = 47,
        cleanup_ret = 48,
        catch_ret = 49,
        catch_pad = 50,
        cleanup_pad = 51,
        catch_switch = 52,
        operand_bundle = 55,
        unary_op = 56,
        call_br = 57,
        freeze = 58,
        atomic_rmw = 59,
        block_addr_users = 60,
    };

    const TypeCode = enum(u8) {
        num_entry = 1,
        void = 2,
        float = 3,
        double = 4,
        label = 5,
        @"opaque" = 6,
        integer = 7,
        pointer = 8,
        function_old = 9,
        half = 10,
        array = 11,
        vector = 12,
        x86_fp80 = 13,
        fp128 = 14,
        ppc_fp128 = 15,
        metadata = 16,
        x86_mmx = 17,
        struct_anon = 18,
        struct_name = 19,
        struct_named = 20,
        function = 21,
        token = 22,
        bfloat = 23,
        x86_amx = 24,
        opaque_pointer = 25,
        target_type = 26,
    };

    const BlockInfoCode = enum(u8) {
        set_bid = 1,
        block_name = 2,
        set_record_name = 3,
    };

    const AttributeKindCode = enum(u8) {
        alignment = 1,
        always_inline = 2,
        by_val = 3,
        inline_hint = 4,
        in_reg = 5,
        min_size = 6,
        naked = 7,
        nest = 8,
        no_alias = 9,
        no_builtin = 10,
        no_capture = 11,
        no_duplicate = 12,
        no_implicit_float = 13,
        no_inline = 14,
        non_lazy_bind = 15,
        no_red_zone = 16,
        no_return = 17,
        no_unwind = 18,
        optimize_for_size = 19,
        read_none = 20,
        read_only = 21,
        returned = 22,
        returns_twice = 23,
        s_ext = 24,
        stack_alignment = 25,
        stack_protect = 26,
        stack_protect_req = 27,
        stack_protect_strong = 28,
        struct_ret = 29,
        sanitize_address = 30,
        sanitize_thread = 31,
        sanitize_memory = 32,
        uw_table = 33,
        z_ext = 34,
        builtin = 35,
        cold = 36,
        optimize_none = 37,
        in_alloca = 38,
        non_null = 39,
        jump_table = 40,
        dereferenceable = 41,
        dereferenceable_or_null = 42,
        convergent = 43,
        safestack = 44,
        argmemonly = 45,
        swift_self = 46,
        swift_error = 47,
        no_recurse = 48,
        inaccessiblemem_only = 49,
        inaccessiblemem_or_argmemonly = 50,
        alloc_size = 51,
        writeonly = 52,
        speculatable = 53,
        strict_fp = 54,
        sanitize_hwaddress = 55,
        nocf_check = 56,
        opt_for_fuzzing = 57,
        shadowcallstack = 58,
        speculative_load_hardening = 59,
        immarg = 60,
        willreturn = 61,
        nofree = 62,
        nosync = 63,
        sanitize_memtag = 64,
        preallocated = 65,
        no_merge = 66,
        null_pointer_is_valid = 67,
        noundef = 68,
        byref = 69,
        mustprogress = 70,
        no_callback = 71,
        hot = 72,
        no_profile = 73,
        vscale_range = 74,
        swift_async = 75,
        no_sanitize_coverage = 76,
        elementtype = 77,
        disable_sanitizer_instrumentation = 78,
        no_sanitize_bounds = 79,
        alloc_align = 80,
        allocated_pointer = 81,
        alloc_kind = 82,
        presplit_coroutine = 83,
        fnretthunk_extern = 84,
        skip_profile = 85,
        memory = 86,
        nofpclass = 87,
        optimize_for_debugging = 88,
        writable = 89,
        coro_only_destroy_when_complete = 90,
        dead_on_unwind = 91,

        pub fn is_enum(attribute_kind: AttributeKindCode) bool {
            return switch (attribute_kind) {
                .alloc_align,
                .allocated_pointer,
                .always_inline,
                .builtin,
                .cold,
                .convergent,
                .disable_sanitizer_instrumentation,
                .fnretthunk_extern,
                .hot,
                .immarg,
                .inreg,
                .inline_hint,
                .jump_table,
                .min_size,
                .mustprogress,
                .naked,
                .nest,
                .no_alias,
                .no_builtin,
                .no_callback,
                .no_capture,
                .nocf_check,
                .no_duplicate,
                .nofree,
                .no_implicit_float,
                .no_inline,
                .no_merge,
                .no_profile,
                .no_recurse,
                .no_red_zone,
                .no_return,
                .no_sanitize_bounds,
                .no_sanitize_coverage,
                .no_sync,
                .noundef,
                .no_unwind,
                .non_lazy_bind,
                .non_null,
                .null_pointer_is_valid,
                .opt_for_fuzzing,
                .optimize_for_size,
                .optimize_none,
                .presplit_coroutine,
                .read_none,
                .read_only,
                .returned,
                .returns_twice,
                .s_ext,
                .safestack,
                .sanitize_address,
                .sanitize_hwaddress,
                .sanitize_memtag,
                .sanitize_memory,
                .sanitize_thread,
                .shadowcallstack,
                .skip_profile,
                .speculatable,
                .speculative_load_hardening,
                .stack_protect,
                .stack_protect_req,
                .stack_protect_strong,
                .strict_fp,
                .swift_async,
                .swift_error,
                .swift_self,
                .willreturn,
                .writeonly,
                .z_ext,
                => true,
                else => false,
            };
        }

        pub fn is_int(attribute_kind: AttributeKindCode) bool {
            return switch (attribute_kind) {
                .alignment,
                .alloc_kind,
                .alloc_size,
                .dereferenceable,
                .dereferenceable_or_null,
                .memory,
                .nofpclass,
                .stack_alignment,
                .uw_table,
                .vscale_range,
                => true,
                else => false,
            };
        }

        pub fn is_type(attribute_kind: AttributeKindCode) bool {
            return switch (attribute_kind) {
                .byref,
                .byval,
                .elementtype,
                .in_alloca,
                .preallocated,
                .struct_ret,
                => true,
                else => false,
            };
        }
    };

    const AttributeCode = enum(u8) {
        entry_old = 1,
        entry = 2,
        group_entry = 3,
    };

    fn print_hex_slice(bytes: []const u8) void {
        for (bytes, 0..) |b, i| {
            if (i % 4 == 0) {
                std.debug.print("\n    ", .{});
            }
            std.debug.print("0x{x:0>2}, ", .{b});
        }
    }

    const Writer = struct {
        buffer: PinnedArray(u32) = .{},
        block_scope: PinnedArray(Block) = .{},
        current_abbreviations: PinnedArray(*Abbreviation) = .{},
        abbreviation_buffer: PinnedArray(Abbreviation) = .{},
        block_info_records: PinnedArray(BlockInfo) = .{},
        vst_offset_placeholder: u64 = 0,
        current_bit: u32 = 0,
        current_value: u32 = 0,
        current_codesize: u32 = 2,
        block_info_current_block_id: u32 = 0,
        strtab_content: PinnedArray(u8) = .{},

        fn get_type_count(writer: *Writer) u32 {
            _ = writer; // autofix
            return dummy_types.len;
        }

        fn compute_bits_required_for_type_indices(writer: *Writer) u32 {
            if (true) {
                return std.math.log2_int_ceil(u32, writer.get_type_count() + 1);
            } else {
                const n = (writer.get_type_count() + 1);
                const result = 32 - @ctz(n);
                return result;
            }
        }

        fn get_byte_slice(writer: *Writer) []const u8 {
            const final_slice_len = writer.buffer.length * @sizeOf(u32);
            const final_slice_ptr: [*]const u8 = @alignCast(@ptrCast(writer.buffer.pointer));
            const final_slice = final_slice_ptr[0..final_slice_len];
            return final_slice;
        }

        // TODO: fix?
        fn get_byte_position(writer: *Writer) u32 {
            return writer.buffer.length * @sizeOf(u32);
        }

        fn write_module_block(writer: *Writer) void {
            const raw = false;
            if (raw) {
                const module_block align(4) = [_]u8 {
                    0x21, 0x0c, 0x00, 0x00, 
                    0x77, 0x02, 0x00, 0x00, 
                    0x0b, 0x02, 0x21, 0x00, 
                    0x02, 0x00, 0x00, 0x00, 
                    0x17, 0x00, 0x00, 0x00, 
                    0x07, 0x81, 0x23, 0x91, 
                    0x41, 0xc8, 0x04, 0x49, 
                    0x06, 0x10, 0x32, 0x39, 
                    0x92, 0x01, 0x84, 0x0c, 
                    0x25, 0x05, 0x08, 0x19, 
                    0x1e, 0x04, 0x8b, 0x62, 
                    0x80, 0x0c, 0x45, 0x02, 
                    0x42, 0x92, 0x0b, 0x42, 
                    0x64, 0x10, 0x32, 0x14, 
                    0x38, 0x08, 0x18, 0x4b, 
                    0x0a, 0x32, 0x32, 0x88, 
                    0x48, 0x70, 0xc4, 0x21, 
                    0x23, 0x44, 0x12, 0x87, 
                    0x8c, 0x10, 0x41, 0x92, 
                    0x02, 0x64, 0xc8, 0x08, 
                    0xb1, 0x14, 0x20, 0x43, 
                    0x46, 0x88, 0x20, 0xc9, 
                    0x01, 0x32, 0x32, 0x84, 
                    0x58, 0x0e, 0x90, 0x91, 
                    0x21, 0x44, 0x90, 0xa1, 
                    0x82, 0xa2, 0x02, 0x19, 
                    0xc3, 0x07, 0xcb, 0x15, 
                    0x09, 0x32, 0x8c, 0x0c, 
                    0x89, 0x20, 0x00, 0x00, 
                    0x0b, 0x00, 0x00, 0x00, 
                    0x22, 0x66, 0x04, 0x10, 
                    0xb2, 0x42, 0x82, 0xc9, 
                    0x10, 0x52, 0x42, 0x82, 
                    0xc9, 0x90, 0x71, 0xc2, 
                    0x50, 0x48, 0x0a, 0x09, 
                    0x26, 0x43, 0xc6, 0x05, 
                    0x42, 0x32, 0x26, 0x08, 
                    0x0c, 0x9a, 0x23, 0x00, 
                    0x83, 0x32, 0x24, 0x18, 
                    0x01, 0x18, 0x08, 0x28, 
                    0xc4, 0x48, 0x02, 0x00, 
                    0x51, 0x18, 0x00, 0x00, 
                    0x51, 0x00, 0x00, 0x00, 
                    0x1b, 0x54, 0x23, 0xf8, 
                    0xff, 0xff, 0xff, 0xff, 
                    0x01, 0x70, 0x00, 0x09, 
                    0x28, 0x83, 0x20, 0x0c, 
                    0x04, 0xc2, 0x1c, 0xe4, 
                    0x21, 0x1c, 0xda, 0xa1, 
                    0x1c, 0xda, 0x00, 0x1e, 
                    0xde, 0x21, 0x1d, 0xdc, 
                    0x81, 0x1e, 0xca, 0x41, 
                    0x1e, 0x80, 0x70, 0x60, 
                    0x07, 0x76, 0x00, 0x88, 
                    0x76, 0x48, 0x07, 0x77, 
                    0x68, 0x03, 0x76, 0x28, 
                    0x87, 0x73, 0x08, 0x07, 
                    0x76, 0x68, 0x03, 0x7b, 
                    0x28, 0x87, 0x71, 0xa0, 
                    0x87, 0x77, 0x90, 0x87, 
                    0x36, 0xb8, 0x87, 0x74, 
                    0x20, 0x07, 0x7a, 0x40, 
                    0x07, 0x00, 0x0e, 0x00, 
                    0xc2, 0x1d, 0xde, 0xa1, 
                    0x0d, 0xe8, 0x41, 0x1e, 
                    0xc2, 0x01, 0x1e, 0xe0, 
                    0x21, 0x1d, 0xdc, 0xe1, 
                    0x1c, 0xda, 0xa0, 0x1d, 
                    0xc2, 0x81, 0x1e, 0xd0, 
                    0x01, 0xa0, 0x07, 0x79, 
                    0xa8, 0x87, 0x72, 0x00, 
                    0x88, 0x79, 0xa0, 0x87, 
                    0x70, 0x18, 0x87, 0x75, 
                    0x68, 0x03, 0x78, 0x90, 
                    0x87, 0x77, 0xa0, 0x87, 
                    0x72, 0x18, 0x07, 0x7a, 
                    0x78, 0x07, 0x79, 0x68, 
                    0x03, 0x71, 0xa8, 0x07, 
                    0x73, 0x30, 0x87, 0x72, 
                    0x90, 0x87, 0x36, 0x98, 
                    0x87, 0x74, 0xd0, 0x87, 
                    0x72, 0x00, 0xf0, 0x00, 
                    0x20, 0xe8, 0x21, 0x1c, 
                    0xe4, 0xe1, 0x1c, 0xca, 
                    0x81, 0x1e, 0xda, 0x60, 
                    0x1c, 0xe0, 0xa1, 0x1e, 
                    0x00, 0x7c, 0xc0, 0x03, 
                    0x3b, 0x68, 0x03, 0x3b, 
                    0xa0, 0x03, 0x80, 0xa0, 
                    0x87, 0x70, 0x90, 0x87, 
                    0x73, 0x28, 0x07, 0x7a, 
                    0x68, 0x03, 0x73, 0x28, 
                    0x87, 0x70, 0xa0, 0x87, 
                    0x7a, 0x90, 0x87, 0x72, 
                    0x98, 0x07, 0x60, 0x0d, 
                    0xc6, 0xa1, 0x1d, 0xde, 
                    0xc1, 0x1e, 0xd8, 0x60, 
                    0x0d, 0xc6, 0x01, 0x1f, 
                    0xf0, 0x80, 0x0d, 0xd6, 
                    0xc0, 0x1c, 0xf0, 0x61, 
                    0x1e, 0xe4, 0x81, 0x0d, 
                    0xd6, 0xa0, 0x1d, 0xda, 
                    0x01, 0x1f, 0xd8, 0x60, 
                    0x0d, 0xe6, 0x61, 0x1e, 
                    0xca, 0x81, 0x0d, 0xd6, 
                    0x60, 0x1e, 0xe6, 0xa1, 
                    0x1c, 0xe4, 0x80, 0x0d, 
                    0xd6, 0x00, 0x1f, 0xf0, 
                    0xe0, 0x0e, 0x00, 0x82, 
                    0x1e, 0xea, 0xc1, 0x1d, 
                    0xca, 0xa1, 0x0d, 0xc6, 
                    0x01, 0x1e, 0xea, 0x01, 
                    0x38, 0x87, 0x72, 0x70, 
                    0x87, 0x72, 0x90, 0x87, 
                    0x74, 0x18, 0x07, 0x60, 
                    0x03, 0x21, 0x04, 0x00, 
                    0x29, 0x6c, 0x20, 0x06, 
                    0x01, 0x20, 0x85, 0x0d, 
                    0x11, 0xf1, 0xff, 0xff, 
                    0xff, 0xff, 0x03, 0x70, 
                    0x0a, 0x80, 0x1f, 0x00, 
                    0x7f, 0x00, 0x48, 0x40, 
                    0x1d, 0x00, 0x7d, 0x10, 
                    0xd8, 0x02, 0x00, 0x00, 
                    0x49, 0x18, 0x00, 0x00, 
                    0x02, 0x00, 0x00, 0x00, 
                    0x13, 0x86, 0x40, 0x18, 
                    0x26, 0x04, 0x04, 0x00, 
                    0x13, 0x30, 0x7c, 0xc0, 
                    0x03, 0x3b, 0xf8, 0x05, 
                    0x3b, 0xa0, 0x83, 0x36, 
                    0xa8, 0x07, 0x77, 0x58, 
                    0x07, 0x77, 0x78, 0x87, 
                    0x7b, 0x70, 0x87, 0x36, 
                    0x60, 0x87, 0x74, 0x70, 
                    0x87, 0x7a, 0xc0, 0x87, 
                    0x36, 0x38, 0x07, 0x77, 
                    0xa8, 0x87, 0x0d, 0xaf, 
                    0x50, 0x0e, 0x6d, 0xd0, 
                    0x0e, 0x7a, 0x50, 0x0e, 
                    0x6d, 0x00, 0x0f, 0x72, 
                    0x70, 0x07, 0x70, 0xa0, 
                    0x07, 0x73, 0x20, 0x07, 
                    0x7a, 0x30, 0x07, 0x72, 
                    0xd0, 0x06, 0xf0, 0x20, 
                    0x07, 0x77, 0x10, 0x07, 
                    0x7a, 0x30, 0x07, 0x72, 
                    0xa0, 0x07, 0x73, 0x20, 
                    0x07, 0x6d, 0x00, 0x0f, 
                    0x72, 0x70, 0x07, 0x72, 
                    0xa0, 0x07, 0x76, 0x40, 
                    0x07, 0x7a, 0x60, 0x07, 
                    0x74, 0xd0, 0x06, 0xe9, 
                    0x60, 0x07, 0x74, 0xa0, 
                    0x07, 0x76, 0x40, 0x07, 
                    0x6d, 0x90, 0x0e, 0x71, 
                    0x20, 0x07, 0x78, 0xa0, 
                    0x07, 0x71, 0x20, 0x07, 
                    0x78, 0xd0, 0x06, 0xe6, 
                    0x80, 0x07, 0x70, 0xa0, 
                    0x07, 0x71, 0x20, 0x07, 
                    0x78, 0xd0, 0x06, 0xee, 
                    0x80, 0x07, 0x7a, 0x10, 
                    0x07, 0x76, 0xa0, 0x07, 
                    0x73, 0x20, 0x07, 0x7a, 
                    0x60, 0x07, 0x74, 0xd0, 
                    0x06, 0xb3, 0x10, 0x07, 
                    0x72, 0x80, 0x07, 0x1a, 
                    0x21, 0x0c, 0x69, 0x30, 
                    0x00, 0xd2, 0xf8, 0xc2, 
                    0x90, 0x0a, 0x20, 0x04, 
                    0x00, 0x00, 0x02, 0x00, 
                    0x00, 0x00, 0x00, 0x00, 
                    0x00, 0x00, 0x08, 0x00, 
                    0x02, 0x18, 0x52, 0x11, 
                    0x50, 0x01, 0x04, 0x80, 
                    0x00, 0x00, 0x00, 0x00, 
                    0x00, 0x00, 0x00, 0x00, 
                    0x00, 0x40, 0x00, 0x12, 
                    0x1b, 0x04, 0x8a, 0xee, 
                    0x09, 0x00, 0x00, 0x64, 
                    0x81, 0x00, 0x00, 0x00, 
                    0x07, 0x00, 0x00, 0x00, 
                    0x32, 0x1e, 0x98, 0x10, 
                    0x19, 0x11, 0x4c, 0x90, 
                    0x8c, 0x09, 0x26, 0x47, 
                    0xc6, 0x04, 0x43, 0x4a, 
                    0x39, 0x94, 0x42, 0x11, 
                    0x94, 0x41, 0x09, 0x14, 
                    0x42, 0x41, 0x00, 0x00, 
                    0xb1, 0x18, 0x00, 0x00, 
                    0xc1, 0x00, 0x00, 0x00, 
                    0x33, 0x08, 0x80, 0x1c, 
                    0xc4, 0xe1, 0x1c, 0x66, 
                    0x14, 0x01, 0x3d, 0x88, 
                    0x43, 0x38, 0x84, 0xc3, 
                    0x8c, 0x42, 0x80, 0x07, 
                    0x79, 0x78, 0x07, 0x73, 
                    0x98, 0x71, 0x0c, 0xe6, 
                    0x00, 0x0f, 0xed, 0x10, 
                    0x0e, 0xf4, 0x80, 0x0e, 
                    0x33, 0x0c, 0x42, 0x1e, 
                    0xc2, 0xc1, 0x1d, 0xce, 
                    0xa1, 0x1c, 0x66, 0x30, 
                    0x05, 0x3d, 0x88, 0x43, 
                    0x38, 0x84, 0x83, 0x1b, 
                    0xcc, 0x03, 0x3d, 0xc8, 
                    0x43, 0x3d, 0x8c, 0x03, 
                    0x3d, 0xcc, 0x78, 0x8c, 
                    0x74, 0x70, 0x07, 0x7b, 
                    0x08, 0x07, 0x79, 0x48, 
                    0x87, 0x70, 0x70, 0x07, 
                    0x7a, 0x70, 0x03, 0x76, 
                    0x78, 0x87, 0x70, 0x20, 
                    0x87, 0x19, 0xcc, 0x11, 
                    0x0e, 0xec, 0x90, 0x0e, 
                    0xe1, 0x30, 0x0f, 0x6e, 
                    0x30, 0x0f, 0xe3, 0xf0, 
                    0x0e, 0xf0, 0x50, 0x0e, 
                    0x33, 0x10, 0xc4, 0x1d, 
                    0xde, 0x21, 0x1c, 0xd8, 
                    0x21, 0x1d, 0xc2, 0x61, 
                    0x1e, 0x66, 0x30, 0x89, 
                    0x3b, 0xbc, 0x83, 0x3b, 
                    0xd0, 0x43, 0x39, 0xb4, 
                    0x03, 0x3c, 0xbc, 0x83, 
                    0x3c, 0x84, 0x03, 0x3b, 
                    0xcc, 0xf0, 0x14, 0x76, 
                    0x60, 0x07, 0x7b, 0x68, 
                    0x07, 0x37, 0x68, 0x87, 
                    0x72, 0x68, 0x07, 0x37, 
                    0x80, 0x87, 0x70, 0x90, 
                    0x87, 0x70, 0x60, 0x07, 
                    0x76, 0x28, 0x07, 0x76, 
                    0xf8, 0x05, 0x76, 0x78, 
                    0x87, 0x77, 0x80, 0x87, 
                    0x5f, 0x08, 0x87, 0x71, 
                    0x18, 0x87, 0x72, 0x98, 
                    0x87, 0x79, 0x98, 0x81, 
                    0x2c, 0xee, 0xf0, 0x0e, 
                    0xee, 0xe0, 0x0e, 0xf5, 
                    0xc0, 0x0e, 0xec, 0x30, 
                    0x03, 0x62, 0xc8, 0xa1, 
                    0x1c, 0xe4, 0xa1, 0x1c, 
                    0xcc, 0xa1, 0x1c, 0xe4, 
                    0xa1, 0x1c, 0xdc, 0x61, 
                    0x1c, 0xca, 0x21, 0x1c, 
                    0xc4, 0x81, 0x1d, 0xca, 
                    0x61, 0x06, 0xd6, 0x90, 
                    0x43, 0x39, 0xc8, 0x43, 
                    0x39, 0x98, 0x43, 0x39, 
                    0xc8, 0x43, 0x39, 0xb8, 
                    0xc3, 0x38, 0x94, 0x43, 
                    0x38, 0x88, 0x03, 0x3b, 
                    0x94, 0xc3, 0x2f, 0xbc, 
                    0x83, 0x3c, 0xfc, 0x82, 
                    0x3b, 0xd4, 0x03, 0x3b, 
                    0xb0, 0xc3, 0x0c, 0xc7, 
                    0x69, 0x87, 0x70, 0x58, 
                    0x87, 0x72, 0x70, 0x83, 
                    0x74, 0x68, 0x07, 0x78, 
                    0x60, 0x87, 0x74, 0x18, 
                    0x87, 0x74, 0xa0, 0x87, 
                    0x19, 0xce, 0x53, 0x0f, 
                    0xee, 0x00, 0x0f, 0xf2, 
                    0x50, 0x0e, 0xe4, 0x90, 
                    0x0e, 0xe3, 0x40, 0x0f, 
                    0xe1, 0x20, 0x0e, 0xec, 
                    0x50, 0x0e, 0x33, 0x20, 
                    0x28, 0x1d, 0xdc, 0xc1, 
                    0x1e, 0xc2, 0x41, 0x1e, 
                    0xd2, 0x21, 0x1c, 0xdc, 
                    0x81, 0x1e, 0xdc, 0xe0, 
                    0x1c, 0xe4, 0xe1, 0x1d, 
                    0xea, 0x01, 0x1e, 0x66, 
                    0x18, 0x51, 0x38, 0xb0, 
                    0x43, 0x3a, 0x9c, 0x83, 
                    0x3b, 0xcc, 0x50, 0x24, 
                    0x76, 0x60, 0x07, 0x7b, 
                    0x68, 0x07, 0x37, 0x60, 
                    0x87, 0x77, 0x78, 0x07, 
                    0x78, 0x98, 0x51, 0x4c, 
                    0xf4, 0x90, 0x0f, 0xf0, 
                    0x50, 0x0e, 0x33, 0x1e, 
                    0x6a, 0x1e, 0xca, 0x61, 
                    0x1c, 0xe8, 0x21, 0x1d, 
                    0xde, 0xc1, 0x1d, 0x7e, 
                    0x01, 0x1e, 0xe4, 0xa1, 
                    0x1c, 0xcc, 0x21, 0x1d, 
                    0xf0, 0x61, 0x06, 0x54, 
                    0x85, 0x83, 0x38, 0xcc, 
                    0xc3, 0x3b, 0xb0, 0x43, 
                    0x3d, 0xd0, 0x43, 0x39, 
                    0xfc, 0xc2, 0x3c, 0xe4, 
                    0x43, 0x3b, 0x88, 0xc3, 
                    0x3b, 0xb0, 0xc3, 0x8c, 
                    0xc5, 0x0a, 0x87, 0x79, 
                    0x98, 0x87, 0x77, 0x18, 
                    0x87, 0x74, 0x08, 0x07, 
                    0x7a, 0x28, 0x07, 0x72, 
                    0x98, 0x81, 0x5c, 0xe3, 
                    0x10, 0x0e, 0xec, 0xc0, 
                    0x0e, 0xe5, 0x50, 0x0e, 
                    0xf3, 0x30, 0x23, 0xc1, 
                    0xd2, 0x41, 0x1e, 0xe4, 
                    0xe1, 0x17, 0xd8, 0xe1, 
                    0x1d, 0xde, 0x01, 0x1e, 
                    0x66, 0x48, 0x19, 0x3b, 
                    0xb0, 0x83, 0x3d, 0xb4, 
                    0x83, 0x1b, 0x84, 0xc3, 
                    0x38, 0x8c, 0x43, 0x39, 
                    0xcc, 0xc3, 0x3c, 0xb8, 
                    0xc1, 0x39, 0xc8, 0xc3, 
                    0x3b, 0xd4, 0x03, 0x3c, 
                    0xcc, 0x48, 0xb4, 0x71, 
                    0x08, 0x07, 0x76, 0x60, 
                    0x07, 0x71, 0x08, 0x87, 
                    0x71, 0x58, 0x87, 0x19, 
                    0xdb, 0xc6, 0x0e, 0xec, 
                    0x60, 0x0f, 0xed, 0xe0, 
                    0x06, 0xf0, 0x20, 0x0f, 
                    0xe5, 0x30, 0x0f, 0xe5, 
                    0x20, 0x0f, 0xf6, 0x50, 
                    0x0e, 0x6e, 0x10, 0x0e, 
                    0xe3, 0x30, 0x0e, 0xe5, 
                    0x30, 0x0f, 0xf3, 0xe0, 
                    0x06, 0xe9, 0xe0, 0x0e, 
                    0xe4, 0x50, 0x0e, 0xf8, 
                    0x30, 0x23, 0xe2, 0xec, 
                    0x61, 0x1c, 0xc2, 0x81, 
                    0x1d, 0xd8, 0xe1, 0x17, 
                    0xec, 0x21, 0x1d, 0xe6, 
                    0x21, 0x1d, 0xc4, 0x21, 
                    0x1d, 0xd8, 0x21, 0x1d, 
                    0xe8, 0x21, 0x1f, 0x66, 
                    0x20, 0x9d, 0x3b, 0xbc, 
                    0x43, 0x3d, 0xb8, 0x03, 
                    0x39, 0x94, 0x83, 0x39, 
                    0xcc, 0x58, 0xbc, 0x70, 
                    0x70, 0x07, 0x77, 0x78, 
                    0x07, 0x7a, 0x08, 0x07, 
                    0x7a, 0x48, 0x87, 0x77, 
                    0x70, 0x87, 0x19, 0xcb, 
                    0xe7, 0x0e, 0xef, 0x30, 
                    0x0f, 0xe1, 0xe0, 0x0e, 
                    0xe9, 0x40, 0x0f, 0xe9, 
                    0xa0, 0x0f, 0xe5, 0x30, 
                    0xc3, 0x01, 0x03, 0x73, 
                    0xa8, 0x07, 0x77, 0x18, 
                    0x87, 0x5f, 0x98, 0x87, 
                    0x70, 0x70, 0x87, 0x74, 
                    0xa0, 0x87, 0x74, 0xd0, 
                    0x87, 0x72, 0x98, 0x81, 
                    0x84, 0x41, 0x39, 0xe0, 
                    0xc3, 0x38, 0xb0, 0x43, 
                    0x3d, 0x90, 0x43, 0x39, 
                    0xcc, 0x40, 0xc4, 0xa0, 
                    0x1d, 0xca, 0xa1, 0x1d, 
                    0xe0, 0x41, 0x1e, 0xde, 
                    0xc1, 0x1c, 0x66, 0x24, 
                    0x63, 0x30, 0x0e, 0xe1, 
                    0xc0, 0x0e, 0xec, 0x30, 
                    0x0f, 0xe9, 0x40, 0x0f, 
                    0xe5, 0x30, 0x43, 0x21, 
                    0x83, 0x75, 0x18, 0x07, 
                    0x73, 0x48, 0x87, 0x5f, 
                    0xa0, 0x87, 0x7c, 0x80, 
                    0x87, 0x72, 0x98, 0xb1, 
                    0x94, 0x01, 0x3c, 0x8c, 
                    0xc3, 0x3c, 0x94, 0xc3, 
                    0x38, 0xd0, 0x43, 0x3a, 
                    0xbc, 0x83, 0x3b, 0xcc, 
                    0xc3, 0x8c, 0xc5, 0x0c, 
                    0x48, 0x21, 0x15, 0x42, 
                    0x61, 0x1e, 0xe6, 0x21, 
                    0x1d, 0xce, 0xc1, 0x1d, 
                    0x52, 0x81, 0x14, 0x66, 
                    0x4c, 0x67, 0x30, 0x0e, 
                    0xef, 0x20, 0x0f, 0xef, 
                    0xe0, 0x06, 0xef, 0x50, 
                    0x0f, 0xf4, 0x30, 0x0f, 
                    0xe9, 0x40, 0x0e, 0xe5, 
                    0xe0, 0x06, 0xe6, 0x20, 
                    0x0f, 0xe1, 0xd0, 0x0e, 
                    0xe5, 0x00, 0x00, 0x00, 
                    0x79, 0x20, 0x00, 0x00, 
                    0x6a, 0x00, 0x00, 0x00, 
                    0x72, 0x1e, 0x48, 0x20, 
                    0x43, 0x88, 0x0c, 0x19, 
                    0x09, 0x72, 0x32, 0x48, 
                    0x20, 0x23, 0x81, 0x8c, 
                    0x91, 0x91, 0xd1, 0x44, 
                    0xa0, 0x10, 0x28, 0x64, 
                    0x3c, 0x31, 0x32, 0x42, 
                    0x8e, 0x90, 0x21, 0xa3, 
                    0xb8, 0x30, 0xf4, 0x01, 
                    0xc6, 0x02, 0x06, 0xe8, 
                    0xd0, 0x48, 0x4a, 0x92, 
                    0x1c, 0x0d, 0x00, 0x00, 
                    0x6d, 0x61, 0x69, 0x6e, 
                    0x2e, 0x63, 0x2f, 0x68, 
                    0x6f, 0x6d, 0x65, 0x2f, 
                    0x64, 0x61, 0x76, 0x69, 
                    0x64, 0x64, 0x35, 0x36, 
                    0x65, 0x30, 0x63, 0x30, 
                    0x39, 0x62, 0x30, 0x32, 
                    0x32, 0x33, 0x37, 0x61, 
                    0x61, 0x37, 0x38, 0x63, 
                    0x61, 0x62, 0x39, 0x39, 
                    0x64, 0x35, 0x36, 0x65, 
                    0x65, 0x65, 0x36, 0x63, 
                    0x63, 0x63, 0x6c, 0x61, 
                    0x6e, 0x67, 0x20, 0x76, 
                    0x65, 0x72, 0x73, 0x69, 
                    0x6f, 0x6e, 0x20, 0x31, 
                    0x38, 0x2e, 0x31, 0x2e, 
                    0x36, 0x20, 0x28, 0x68, 
                    0x74, 0x74, 0x70, 0x73, 
                    0x3a, 0x2f, 0x2f, 0x67, 
                    0x69, 0x74, 0x68, 0x75, 
                    0x62, 0x2e, 0x63, 0x6f, 
                    0x6d, 0x2f, 0x6c, 0x6c, 
                    0x76, 0x6d, 0x2f, 0x6c, 
                    0x6c, 0x76, 0x6d, 0x2d, 
                    0x70, 0x72, 0x6f, 0x6a, 
                    0x65, 0x63, 0x74, 0x2e, 
                    0x67, 0x69, 0x74, 0x20, 
                    0x62, 0x63, 0x65, 0x39, 
                    0x33, 0x39, 0x33, 0x32, 
                    0x39, 0x31, 0x61, 0x32, 
                    0x64, 0x61, 0x61, 0x38, 
                    0x30, 0x30, 0x36, 0x64, 
                    0x31, 0x64, 0x61, 0x36, 
                    0x32, 0x39, 0x61, 0x61, 
                    0x32, 0x37, 0x36, 0x35, 
                    0x65, 0x30, 0x30, 0x66, 
                    0x34, 0x65, 0x37, 0x30, 
                    0x29, 0x44, 0x77, 0x61, 
                    0x72, 0x66, 0x20, 0x56, 
                    0x65, 0x72, 0x73, 0x69, 
                    0x6f, 0x6e, 0x44, 0x65, 
                    0x62, 0x75, 0x67, 0x20, 
                    0x49, 0x6e, 0x66, 0x6f, 
                    0x20, 0x56, 0x65, 0x72, 
                    0x73, 0x69, 0x6f, 0x6e, 
                    0x77, 0x63, 0x68, 0x61, 
                    0x72, 0x5f, 0x73, 0x69, 
                    0x7a, 0x65, 0x50, 0x49, 
                    0x43, 0x20, 0x4c, 0x65, 
                    0x76, 0x65, 0x6c, 0x50, 
                    0x49, 0x45, 0x20, 0x4c, 
                    0x65, 0x76, 0x65, 0x6c, 
                    0x75, 0x77, 0x74, 0x61, 
                    0x62, 0x6c, 0x65, 0x66, 
                    0x72, 0x61, 0x6d, 0x65, 
                    0x2d, 0x70, 0x6f, 0x69, 
                    0x6e, 0x74, 0x65, 0x72, 
                    0x23, 0x08, 0x81, 0x30, 
                    0x82, 0x10, 0x0c, 0x23, 
                    0x08, 0x01, 0x31, 0x82, 
                    0x10, 0x14, 0x23, 0x08, 
                    0x81, 0x31, 0x82, 0x10, 
                    0x1c, 0x23, 0x08, 0x01, 
                    0x32, 0x94, 0x15, 0x74, 
                    0x14, 0x01, 0x00, 0x00, 
                    0x10, 0x00, 0x00, 0x00, 
                    0x00, 0x00, 0x00, 0x00, 
                    0x02, 0x00, 0x00, 0x03, 
                    0x15, 0x40, 0x20, 0x04, 
                    0xc3, 0x0c, 0x03, 0x53, 
                    0x34, 0x33, 0x0c, 0x8e, 
                    0xf1, 0xcc, 0x30, 0x40, 
                    0x47, 0x34, 0xc3, 0x20, 
                    0x21, 0xce, 0x0c, 0x03, 
                    0x93, 0x38, 0x33, 0x0c, 
                    0x8c, 0xe2, 0xcc, 0x30, 
                    0x30, 0x8b, 0x33, 0x43, 
                    0x40, 0xc8, 0x48, 0x60, 
                    0x82, 0x72, 0x61, 0x63, 
                    0xb3, 0x6b, 0x73, 0x21, 
                    0x13, 0x3b, 0x73, 0x19, 
                    0xab, 0x1b, 0x25, 0x90, 
                    0x32, 0x62, 0x63, 0xb3, 
                    0x6b, 0x73, 0x69, 0x7b, 
                    0x23, 0xab, 0x63, 0x2b, 
                    0x73, 0x31, 0x63, 0x0b, 
                    0x3b, 0x9b, 0x1b, 0xe5, 
                    0xa0, 0x2a, 0xeb, 0xc2, 
                    0x32, 0x2d, 0x15, 0x36, 
                    0x36, 0xbb, 0x36, 0x97, 
                    0x34, 0xb2, 0x32, 0x37, 
                    0xba, 0x51, 0x82, 0x0d, 
                    0x00, 0x00, 0x00, 0x00, 
                    0xa9, 0x18, 0x00, 0x00, 
                    0x2d, 0x00, 0x00, 0x00, 
                    0x0b, 0x0a, 0x72, 0x28, 
                    0x87, 0x77, 0x80, 0x07, 
                    0x7a, 0x58, 0x70, 0x98, 
                    0x43, 0x3d, 0xb8, 0xc3, 
                    0x38, 0xb0, 0x43, 0x39, 
                    0xd0, 0xc3, 0x82, 0xe6, 
                    0x1c, 0xc6, 0xa1, 0x0d, 
                    0xe8, 0x41, 0x1e, 0xc2, 
                    0xc1, 0x1d, 0xe6, 0x21, 
                    0x1d, 0xe8, 0x21, 0x1d, 
                    0xde, 0xc1, 0x1d, 0x16, 
                    0x34, 0xe3, 0x60, 0x0e, 
                    0xe7, 0x50, 0x0f, 0xe1, 
                    0x20, 0x0f, 0xe4, 0x40, 
                    0x0f, 0xe1, 0x20, 0x0f, 
                    0xe7, 0x50, 0x0e, 0xf4, 
                    0xb0, 0x80, 0x81, 0x07, 
                    0x79, 0x28, 0x87, 0x70, 
                    0x60, 0x07, 0x76, 0x78, 
                    0x87, 0x71, 0x08, 0x07, 
                    0x7a, 0x28, 0x07, 0x72, 
                    0x58, 0x70, 0x9c, 0xc3, 
                    0x38, 0xb4, 0x01, 0x3b, 
                    0xa4, 0x83, 0x3d, 0x94, 
                    0xc3, 0x02, 0x6b, 0x1c, 
                    0xd8, 0x21, 0x1c, 0xdc, 
                    0xe1, 0x1c, 0xdc, 0x20, 
                    0x1c, 0xe4, 0x61, 0x1c, 
                    0xdc, 0x20, 0x1c, 0xe8, 
                    0x81, 0x1e, 0xc2, 0x61, 
                    0x1c, 0xd0, 0xa1, 0x1c, 
                    0xc8, 0x61, 0x1c, 0xc2, 
                    0x81, 0x1d, 0xd8, 0x61, 
                    0xc1, 0x01, 0x0f, 0xf4, 
                    0x20, 0x0f, 0xe1, 0x50, 
                    0x0f, 0xf4, 0x80, 0x0e, 
                    0x0b, 0x88, 0x75, 0x18, 
                    0x07, 0x73, 0x48, 0x87, 
                    0x05, 0xcf, 0x38, 0xbc, 
                    0x83, 0x3b, 0xd8, 0x43, 
                    0x39, 0xc8, 0xc3, 0x39, 
                    0x94, 0x83, 0x3b, 0x8c, 
                    0x43, 0x39, 0x8c, 0x03, 
                    0x3d, 0xc8, 0x03, 0x3b, 
                    0x00, 0x00, 0x00, 0x00, 
                    0xd1, 0x10, 0x00, 0x00, 
                    0x06, 0x00, 0x00, 0x00, 
                    0x07, 0xcc, 0x3c, 0xa4, 
                    0x83, 0x3b, 0x9c, 0x03, 
                    0x3b, 0x94, 0x03, 0x3d, 
                    0xa0, 0x83, 0x3c, 0x94, 
                    0x43, 0x38, 0x90, 0xc3, 
                    0x01, 0x00, 0x00, 0x00, 
                    0x61, 0x20, 0x00, 0x00, 
                    0x4d, 0x00, 0x00, 0x00, 
                    0x13, 0x04, 0x41, 0x2c, 
                    0x10, 0x00, 0x00, 0x00, 
                    0x01, 0x00, 0x00, 0x00, 
                    0x94, 0x11, 0x00, 0x00, 
                    0xf1, 0x30, 0x00, 0x00, 
                    0x24, 0x00, 0x00, 0x00, 
                    0x22, 0x47, 0xc8, 0x90, 
                    0x51, 0x16, 0xc4, 0x05, 
                    0xc4, 0x40, 0x10, 0x04, 
                    0x6d, 0x61, 0x69, 0x6e, 
                    0x69, 0x6e, 0x74, 0x63, 
                    0x68, 0x61, 0x72, 0x61, 
                    0x72, 0x67, 0x63, 0x61, 
                    0x72, 0x67, 0x76, 0x00, 
                    0xab, 0xa8, 0x83, 0xea, 
                    0x00, 0x2a, 0x40, 0x03, 
                    0x01, 0x40, 0x00, 0x10, 
                    0x99, 0x00, 0x20, 0x0d, 
                    0x00, 0x00, 0x00, 0xf6, 
                    0x1c, 0x00, 0x19, 0x78, 
                    0x60, 0x00, 0x14, 0xc0, 
                    0x9e, 0x03, 0x20, 0x83, 
                    0x0f, 0x01, 0x0c, 0x60, 
                    0x91, 0x03, 0x3c, 0x00, 
                    0x00, 0x00, 0x64, 0x00, 
                    0x0a, 0x00, 0x00, 0x00, 
                    0x00, 0xb0, 0xc8, 0x01, 
                    0x1e, 0x00, 0x00, 0x80, 
                    0x32, 0x00, 0x05, 0x00, 
                    0x00, 0x00, 0x00, 0xd8, 
                    0x30, 0x8c, 0xc1, 0x18, 
                    0x98, 0xc1, 0x26, 0x42, 
                    0x00, 0xce, 0x00, 0xd8, 
                    0x00, 0x8c, 0x53, 0x04, 
                    0x31, 0x00, 0x03, 0x2a, 
                    0x18, 0x83, 0x00, 0x00, 
                    0x80, 0x75, 0x81, 0x31, 
                    0x4e, 0x11, 0xc4, 0x20, 
                    0x0c, 0xa8, 0xc0, 0x0c, 
                    0x04, 0x00, 0x00, 0x26, 
                    0x08, 0x40, 0x33, 0x41, 
                    0x00, 0x1c, 0x00, 0x00, 
                    0x33, 0x11, 0x41, 0x60, 
                    0x8c, 0xc2, 0x4c, 0x44, 
                    0x10, 0x18, 0xa3, 0x30, 
                    0x13, 0x01, 0x04, 0x06, 
                    0x29, 0x0c, 0x1b, 0x10, 
                    0x03, 0x31, 0x00, 0xc3, 
                    0x06, 0x84, 0x60, 0x0c, 
                    0xc0, 0x88, 0xc1, 0x01, 
                    0x80, 0x20, 0x18, 0x14, 
                    0xce, 0xf8, 0xff, 0xff, 
                    0xff, 0x0f, 0xe6, 0xff, 
                    0xff, 0xff, 0x3f, 0x94, 
                    0xff, 0xff, 0xff, 0xff, 
                    0x30, 0x63, 0x50, 0x04, 
                    0x8e, 0x18, 0x00, 0xc0, 
                    0xb0, 0x01, 0x11, 0x14, 
                    0x04, 0x30, 0x62, 0x70, 
                    0x00, 0x20, 0x08, 0x06, 
                    0x85, 0x23, 0xfe, 0xff, 
                    0xff, 0xff, 0x03, 0xf9, 
                    0xff, 0xff, 0xff, 0x0f, 
                    0xe5, 0xff, 0xff, 0xff, 
                    0x3f, 0xcc, 0x18, 0x14, 
                    0xc1, 0x26, 0x06, 0x00, 
                    0xc0, 0xc4, 0x8c, 0x41, 
                    0x31, 0x14, 0x62, 0x00, 
                    0x00, 0x01, 0x31, 0x00, 
                    0x02, 0x00, 0x00, 0x00, 
                    0x5b, 0x04, 0x20, 0x0c, 
                    0x00, 0x00, 0x00, 0x00, 
                    0x21, 0x31, 0x00, 0x00, 
                    0x02, 0x00, 0x00, 0x00, 
                    0x0b, 0x86, 0x00, 0x08, 
                    0x00, 0x00, 0x00, 0x00, 
                    0x00, 0x00, 0x00, 0x00, 
                    0x71, 0x20, 0x00, 0x00, 
                    0x03, 0x00, 0x00, 0x00, 
                    0x32, 0x0e, 0x10, 0x22, 
                    0x84, 0x00, 0xac, 0x04, 
                    0x00, 0x00, 0x00, 0x00, 
                    0x00, 0x00, 0x00, 0x00, 
                };
                writer.append_bytes(&module_block);
            } else {
                const module_version_start = writer.buffer.length;
                _ = module_version_start; // autofix
                writer.enter_subblock(.identification, 3);
                const block_start_position = writer.get_byte_position();
                _ = block_start_position; // autofix

                writer.write_module_version();

                writer.write_block_info();

                writer.write_type_table();

                writer.write_attribute_group_table();

                writer.write_attribute_table();

                // TODO
                // writer.write_comdats();

                writer.write_module_info();

                writer.write_module_constants();

                writer.write_module_metadata_kinds();

                writer.write_module_metadata();

                // TODO:
                const should_preserve_use_list_order = false;
                if (should_preserve_use_list_order) {
                    writer.write_use_list_block(null);
                }

                writer.write_operand_bundle_tags();

                writer.write_sync_scope_names();

                // TODO: functions
                // for (functions) |function| {
                //     if (!function.is_declaration) {
                //         write.write_function(function);
                //     }
                // }
                //

                // TODO: module summary
                // if (index) {
                //     writer.write_per_module_global_value_summary();
                // }

                // TODO:
                // writer.write_global_value_symbol_table(map);

                // writer.write_module_hash(block_start_position);
                writer.exit_block();
            }
        }

        fn write_symtab(writer: *Writer) void {
            // TODO:
            const symtab_block align(4) = [_]u8{
                0x65, 0x0c, 0x00, 0x00, 
                0x25, 0x00, 0x00, 0x00, 
                0x12, 0x03, 0x94, 0x28, 
                0x01, 0x00, 0x00, 0x00, 
                0x03, 0x00, 0x00, 0x00, 
                0x14, 0x00, 0x00, 0x00, 
                0x2f, 0x00, 0x00, 0x00, 
                0x4c, 0x00, 0x00, 0x00, 
                0x01, 0x00, 0x00, 0x00, 
                0x58, 0x00, 0x00, 0x00, 
                0x00, 0x00, 0x00, 0x00, 
                0x58, 0x00, 0x00, 0x00, 
                0x02, 0x00, 0x00, 0x00, 
                0x88, 0x00, 0x00, 0x00, 
                0x00, 0x00, 0x00, 0x00, 
                0x43, 0x00, 0x00, 0x00, 
                0x18, 0x00, 0x00, 0x00, 
                0x5b, 0x00, 0x00, 0x00, 
                0x06, 0x00, 0x00, 0x00, 
                0x04, 0x00, 0x00, 0x00, 
                0x00, 0x00, 0x00, 0x00, 
                0x88, 0x00, 0x00, 0x00, 
                0x00, 0x00, 0x00, 0x00, 
                0x00, 0x00, 0x00, 0x00, 
                0x02, 0x00, 0x00, 0x00, 
                0x00, 0x00, 0x00, 0x00, 
                0x00, 0x00, 0x00, 0x00, 
                0x04, 0x00, 0x00, 0x00, 
                0x00, 0x00, 0x00, 0x00, 
                0x04, 0x00, 0x00, 0x00, 
                0xff, 0xff, 0xff, 0xff, 
                0x00, 0x24, 0x00, 0x00, 
                0x04, 0x00, 0x00, 0x00, 
                0x10, 0x00, 0x00, 0x00, 
                0x04, 0x00, 0x00, 0x00, 
                0x10, 0x00, 0x00, 0x00, 
                0xff, 0xff, 0xff, 0xff, 
                0x08, 0x2c, 0x00, 0x00, 
                0x00, 0x00, 0x00, 0x00, 
            };
            writer.append_bytes(&symtab_block);
        }

        fn write_strtab(writer: *Writer) void {
            // TODO:
            const strtab_block align(4) = .{
                0x5d, 0x0c, 0x00, 0x00, 
                0x1c, 0x00, 0x00, 0x00, 
                0x12, 0x03, 0x94, 0xe1, 
                0x00, 0x00, 0x00, 0x00, 
                0x6d, 0x61, 0x69, 0x6e, 
                0x6c, 0x6c, 0x76, 0x6d, 
                0x2e, 0x64, 0x62, 0x67, 
                0x2e, 0x64, 0x65, 0x63, 
                0x6c, 0x61, 0x72, 0x65, 
                0x31, 0x38, 0x2e, 0x31, 
                0x2e, 0x36, 0x20, 0x62, 
                0x63, 0x65, 0x39, 0x33, 
                0x39, 0x33, 0x32, 0x39, 
                0x31, 0x61, 0x32, 0x64, 
                0x61, 0x61, 0x38, 0x30, 
                0x30, 0x36, 0x64, 0x31, 
                0x64, 0x61, 0x36, 0x32, 
                0x39, 0x61, 0x61, 0x32, 
                0x37, 0x36, 0x35, 0x65, 
                0x30, 0x30, 0x66, 0x34, 
                0x65, 0x37, 0x30, 0x78, 
                0x38, 0x36, 0x5f, 0x36, 
                0x34, 0x2d, 0x75, 0x6e, 
                0x6b, 0x6e, 0x6f, 0x77, 
                0x6e, 0x2d, 0x6c, 0x69, 
                0x6e, 0x75, 0x78, 0x2d, 
                0x67, 0x6e, 0x75, 0x6d, 
                0x61, 0x69, 0x6e, 0x2e, 
                0x63, 0x00, 0x00, 0x00, 
                0x00, 0x00, 0x00, 0x00, 
            };
            writer.append_bytes(&strtab_block);
        }

        pub fn write(writer: *Writer) void {
            const magic align(4) = [_]u8{ 0x42, 0x43, 0xc0, 0xde };
            writer.append_bytes(&magic);

            writer.write_identification_block();

            writer.write_module_block();

            writer.write_symtab();

            writer.write_strtab();
        }

        fn write_module_version(writer: *Writer) void {
            writer.emit_record(u64, @intFromEnum(ModuleCode.version), &.{2}, 0);
        }

        fn enter_block_info_block(writer: *Writer) void {
            writer.enter_subblock(BlockId.block_info, 2);
            writer.block_info_current_block_id = ~@as(u32, 0);
            writer.block_info_records.clear();
        }

        fn write_block_info(writer: *Writer) void {
            writer.enter_block_info_block();

            const start = writer.buffer.length * 4;

            {
                const abbreviation = writer.abbreviation_buffer.append(.{});
                abbreviation.add_with_encoding(.{ .encoding = .fixed, .value = 3 });
                abbreviation.add_with_encoding(.{ .encoding = .vbr, .value = 8 });
                abbreviation.add_with_encoding(.{ .encoding = .array });
                abbreviation.add_with_encoding(.{ .encoding = .fixed, .value = 8 });

                const block_info_abbrev = writer.emit_block_info_abbrev(@intFromEnum(BlockId.value_symtab), abbreviation);
                if (block_info_abbrev != @intFromEnum(ValueSymtabAbbreviationId.entry8)) unreachable;
            }

            {
                const abbreviation = writer.abbreviation_buffer.append(.{});
                abbreviation.add_literal(@intFromEnum(ValueSymtabCode.entry));
                abbreviation.add_with_encoding(.{ .encoding = .vbr, .value = 8 });
                abbreviation.add_with_encoding(.{ .encoding = .array });
                abbreviation.add_with_encoding(.{ .encoding = .fixed, .value = 7 });

                const block_info_abbrev = writer.emit_block_info_abbrev(@intFromEnum(BlockId.value_symtab), abbreviation);
                if (block_info_abbrev != @intFromEnum(ValueSymtabAbbreviationId.entry7)) unreachable;
            }

            {
                const abbreviation = writer.abbreviation_buffer.append(.{});
                abbreviation.add_literal(@intFromEnum(ValueSymtabCode.entry));
                abbreviation.add_with_encoding(.{ .encoding = .vbr, .value = 8 });
                abbreviation.add_with_encoding(.{ .encoding = .array });
                abbreviation.add_with_encoding(.{ .encoding = .char6 });

                const block_info_abbrev = writer.emit_block_info_abbrev(@intFromEnum(BlockId.value_symtab), abbreviation);
                if (block_info_abbrev != @intFromEnum(ValueSymtabAbbreviationId.entry6)) unreachable;
            }

            {
                const abbreviation = writer.abbreviation_buffer.append(.{});
                abbreviation.add_literal(@intFromEnum(ValueSymtabCode.bb_entry));
                abbreviation.add_with_encoding(.{ .encoding = .vbr, .value = 8 });
                abbreviation.add_with_encoding(.{ .encoding = .array });
                abbreviation.add_with_encoding(.{ .encoding = .char6 });

                const block_info_abbrev = writer.emit_block_info_abbrev(@intFromEnum(BlockId.value_symtab), abbreviation);
                if (block_info_abbrev != @intFromEnum(ValueSymtabAbbreviationId.bb_entry6)) unreachable;
            }

            {
                const abbreviation = writer.abbreviation_buffer.append(.{});
                abbreviation.add_literal(@intFromEnum(ConstantCode.set_type));

                abbreviation.add_with_encoding(.{ .encoding = .fixed, .value = writer.compute_bits_required_for_type_indices() });

                const block_info_abbrev = writer.emit_block_info_abbrev(@intFromEnum(BlockId.constant), abbreviation);
                if (block_info_abbrev != @intFromEnum(ConstantAbbreviationId.set_type)) unreachable;
            }

            {
                const abbreviation = writer.abbreviation_buffer.append(.{});
                abbreviation.add_literal(@intFromEnum(ConstantCode.integer));
                abbreviation.add_with_encoding(.{ .encoding = .vbr, .value = 8 });

                const block_info_abbrev = writer.emit_block_info_abbrev(@intFromEnum(BlockId.constant), abbreviation);
                if (block_info_abbrev != @intFromEnum(ConstantAbbreviationId.integer)) unreachable;
            }

            {
                const abbreviation = writer.abbreviation_buffer.append(.{});
                abbreviation.add_literal(@intFromEnum(ConstantCode.cast));
                abbreviation.add_with_encoding(.{ .encoding = .fixed, .value = 4 });

                abbreviation.add_with_encoding(.{ .encoding = .fixed, .value = writer.compute_bits_required_for_type_indices() });

                abbreviation.add_with_encoding(.{ .encoding = .vbr, .value = 8 });

                const block_info_abbrev = writer.emit_block_info_abbrev(@intFromEnum(BlockId.constant), abbreviation);
                if (block_info_abbrev != @intFromEnum(ConstantAbbreviationId.cast)) unreachable;
            }

            {
                const abbreviation = writer.abbreviation_buffer.append(.{});
                abbreviation.add_literal(@intFromEnum(ConstantCode.null));

                const block_info_abbrev = writer.emit_block_info_abbrev(@intFromEnum(BlockId.constant), abbreviation);
                if (block_info_abbrev != @intFromEnum(ConstantAbbreviationId.null)) unreachable;
            }

            // TODO: check FIXME in LLVM code
            
            {
                const abbreviation = writer.abbreviation_buffer.append(.{});
                abbreviation.add_literal(@intFromEnum(FunctionCode.load));
                abbreviation.add_with_encoding(.{ .encoding = .vbr, .value = 6 });

                abbreviation.add_with_encoding(.{ .encoding = .fixed, .value = writer.compute_bits_required_for_type_indices() });

                abbreviation.add_with_encoding(.{ .encoding = .vbr, .value = 4 });
                abbreviation.add_with_encoding(.{ .encoding = .fixed, .value = 1 });

                const block_info_abbrev = writer.emit_block_info_abbrev(@intFromEnum(BlockId.function), abbreviation);
                if (block_info_abbrev != @intFromEnum(FunctionAbbreviationId.load)) unreachable;
            }

            {
                const abbreviation = writer.abbreviation_buffer.append(.{});
                abbreviation.add_literal(@intFromEnum(FunctionCode.unary_op));
                abbreviation.add_with_encoding(.{ .encoding = .vbr, .value = 6 });
                abbreviation.add_with_encoding(.{ .encoding = .fixed, .value = 4 });

                const block_info_abbrev = writer.emit_block_info_abbrev(@intFromEnum(BlockId.function), abbreviation);
                if (block_info_abbrev != @intFromEnum(FunctionAbbreviationId.unary_op)) unreachable;
            }

            {
                const abbreviation = writer.abbreviation_buffer.append(.{});
                abbreviation.add_literal(@intFromEnum(FunctionCode.unary_op));
                abbreviation.add_with_encoding(.{ .encoding = .vbr, .value = 6 });
                abbreviation.add_with_encoding(.{ .encoding = .fixed, .value = 4 });
                abbreviation.add_with_encoding(.{ .encoding = .fixed, .value = 8 });

                const block_info_abbrev = writer.emit_block_info_abbrev(@intFromEnum(BlockId.function), abbreviation);
                if (block_info_abbrev != @intFromEnum(FunctionAbbreviationId.unary_op_flags)) unreachable;
            }

            {
                const abbreviation = writer.abbreviation_buffer.append(.{});
                abbreviation.add_literal(@intFromEnum(FunctionCode.binary_op));
                abbreviation.add_with_encoding(.{ .encoding = .vbr, .value = 6 });
                abbreviation.add_with_encoding(.{ .encoding = .vbr, .value = 6 });
                abbreviation.add_with_encoding(.{ .encoding = .fixed, .value = 4 });

                const block_info_abbrev = writer.emit_block_info_abbrev(@intFromEnum(BlockId.function), abbreviation);
                if (block_info_abbrev != @intFromEnum(FunctionAbbreviationId.binary_op)) unreachable;
            }

            {
                const abbreviation = writer.abbreviation_buffer.append(.{});
                abbreviation.add_literal(@intFromEnum(FunctionCode.binary_op));
                abbreviation.add_with_encoding(.{ .encoding = .vbr, .value = 6 });
                abbreviation.add_with_encoding(.{ .encoding = .vbr, .value = 6 });
                abbreviation.add_with_encoding(.{ .encoding = .fixed, .value = 4 });
                abbreviation.add_with_encoding(.{ .encoding = .fixed, .value = 8 });

                const block_info_abbrev = writer.emit_block_info_abbrev(@intFromEnum(BlockId.function), abbreviation);
                if (block_info_abbrev != @intFromEnum(FunctionAbbreviationId.binary_op_flags)) unreachable;
            }

            {
                const abbreviation = writer.abbreviation_buffer.append(.{});
                abbreviation.add_literal(@intFromEnum(FunctionCode.cast));
                abbreviation.add_with_encoding(.{ .encoding = .vbr, .value = 6 });
                
                abbreviation.add_with_encoding(.{ .encoding = .fixed, .value = writer.compute_bits_required_for_type_indices() });
                abbreviation.add_with_encoding(.{ .encoding = .fixed, .value = 4 });

                const block_info_abbrev = writer.emit_block_info_abbrev(@intFromEnum(BlockId.function), abbreviation);
                if (block_info_abbrev != @intFromEnum(FunctionAbbreviationId.cast)) unreachable;
            }

            {
                const abbreviation = writer.abbreviation_buffer.append(.{});
                abbreviation.add_literal(@intFromEnum(FunctionCode.cast));
                abbreviation.add_with_encoding(.{ .encoding = .vbr, .value = 6 });
                
                abbreviation.add_with_encoding(.{ .encoding = .fixed, .value = writer.compute_bits_required_for_type_indices() });

                abbreviation.add_with_encoding(.{ .encoding = .fixed, .value = 4 });
                abbreviation.add_with_encoding(.{ .encoding = .fixed, .value = 8 });

                const block_info_abbrev = writer.emit_block_info_abbrev(@intFromEnum(BlockId.function), abbreviation);
                if (block_info_abbrev != @intFromEnum(FunctionAbbreviationId.cast_flags)) unreachable;
            }

            {
                const abbreviation = writer.abbreviation_buffer.append(.{});
                abbreviation.add_literal(@intFromEnum(FunctionCode.ret));

                const block_info_abbrev = writer.emit_block_info_abbrev(@intFromEnum(BlockId.function), abbreviation);
                if (block_info_abbrev != @intFromEnum(FunctionAbbreviationId.ret_void)) unreachable;
            }

            {
                const abbreviation = writer.abbreviation_buffer.append(.{});
                abbreviation.add_literal(@intFromEnum(FunctionCode.ret));
                abbreviation.add_with_encoding(.{ .encoding = .vbr, .value = 6 });

                const block_info_abbrev = writer.emit_block_info_abbrev(@intFromEnum(BlockId.function), abbreviation);
                if (block_info_abbrev != @intFromEnum(FunctionAbbreviationId.ret_val)) unreachable;
            }

            {
                const abbreviation = writer.abbreviation_buffer.append(.{});
                abbreviation.add_literal(@intFromEnum(FunctionCode.@"unreachable"));

                const block_info_abbrev = writer.emit_block_info_abbrev(@intFromEnum(BlockId.function), abbreviation);
                if (block_info_abbrev != @intFromEnum(FunctionAbbreviationId.@"unreachable")) unreachable;
            }

            {
                const abbreviation = writer.abbreviation_buffer.append(.{});
                abbreviation.add_literal(@intFromEnum(FunctionCode.gep));
                abbreviation.add_with_encoding(.{ .encoding = .fixed, .value = 1 });
                
                abbreviation.add_with_encoding(.{ .encoding = .fixed, .value = writer.compute_bits_required_for_type_indices() });

                abbreviation.add_with_encoding(.{ .encoding = .array });
                abbreviation.add_with_encoding(.{ .encoding = .vbr, .value = 6 });

                const block_info_abbrev = writer.emit_block_info_abbrev(@intFromEnum(BlockId.function), abbreviation);
                if (block_info_abbrev != @intFromEnum(FunctionAbbreviationId.gep)) unreachable;
            }

            writer.exit_block();

            const end = writer.buffer.length * 4;
            const expected = debug_main_bitcode[start..end];
            const have = writer.get_byte_slice()[start..end];
            std.testing.expectEqualSlices(u8, expected, have) catch unreachable;
        }

        const DummyType = union(enum){
            pointer,
            integer: u16,
            function: struct{
                varargs: bool,
                return_type: u64,
                parameter_types: []const u64,
            },
            metadata,
            void,
        };

        const dummy_types = [_]DummyType{.pointer, .{ .integer = 32 }, .{ .function = .{
            .varargs = false,
            .return_type = 1,
            .parameter_types = &.{ 1, 0 },
        } }, .void, .metadata, .{
            .function = .{
                .varargs = false,
                .return_type = 3,
                .parameter_types = &.{ 4, 4, 4 },
            },
        } };
        comptime {
            assert(dummy_types.len == 6);
        }

        fn write_type_table(writer: *Writer) void {
            writer.enter_subblock(.type, 4);

            const start = writer.buffer.length * 4;

            var type_values = std.BoundedArray(u64, 64){};

            // TODO: compute
            const opaque_pointer_abbreviation = blk: {
                const abbreviation = writer.abbreviation_buffer.append(.{});
                abbreviation.add_literal(@intFromEnum(TypeCode.opaque_pointer));
                abbreviation.add_literal(0);
                break :blk writer.emit_abbreviation(abbreviation);
            };
            const function_abbreviation = blk: {
                const abbreviation = writer.abbreviation_buffer.append(.{});
                abbreviation.add_literal(@intFromEnum(TypeCode.function));
                abbreviation.add_with_encoding(.{ .encoding = .fixed, .value = 1 });
                abbreviation.add_with_encoding(.{ .encoding = .array });
                abbreviation.add_with_encoding(.{ .encoding = .fixed, .value = writer.compute_bits_required_for_type_indices() });

                break :blk writer.emit_abbreviation(abbreviation);
            };

            const struct_anon_abbreviation = blk: {
                const abbreviation = writer.abbreviation_buffer.append(.{});
                abbreviation.add_literal(@intFromEnum(TypeCode.struct_anon));
                abbreviation.add_with_encoding(.{ .encoding = .fixed, .value = 1 });
                abbreviation.add_with_encoding(.{ .encoding = .array });
                abbreviation.add_with_encoding(.{ .encoding = .fixed, .value = writer.compute_bits_required_for_type_indices() });

                break :blk writer.emit_abbreviation(abbreviation);
            };
            _ = struct_anon_abbreviation; // autofix
            const struct_name_abbreviation = blk: {
                const abbreviation = writer.abbreviation_buffer.append(.{});
                abbreviation.add_literal(@intFromEnum(TypeCode.struct_name));
                abbreviation.add_with_encoding(.{ .encoding = .array });
                abbreviation.add_with_encoding(.{ .encoding = .char6 });

                break :blk writer.emit_abbreviation(abbreviation);
            };

            const struct_named_abbreviation = blk: {
                const abbreviation = writer.abbreviation_buffer.append(.{});
                abbreviation.add_literal(@intFromEnum(TypeCode.struct_named));
                abbreviation.add_with_encoding(.{ .encoding = .fixed, .value = 1 });
                abbreviation.add_with_encoding(.{ .encoding = .array });
                abbreviation.add_with_encoding(.{ .encoding = .fixed, .value = writer.compute_bits_required_for_type_indices() });

                break :blk writer.emit_abbreviation(abbreviation);
            };
            _ = struct_named_abbreviation; // autofix

            const array_abbreviation = blk: {
                const abbreviation = writer.abbreviation_buffer.append(.{});
                abbreviation.add_literal(@intFromEnum(TypeCode.array));
                abbreviation.add_with_encoding(.{ .encoding = .vbr, .value = 8 });
                abbreviation.add_with_encoding(.{ .encoding = .fixed, .value = writer.compute_bits_required_for_type_indices() });

                break :blk writer.emit_abbreviation(abbreviation);
            };
            _ = array_abbreviation; // autofix

            _ = struct_name_abbreviation; // autofix
                                       //
            type_values.appendAssumeCapacity(writer.get_type_count());
            writer.emit_record(u64, @intFromEnum(TypeCode.num_entry), type_values.constSlice(), 0);
            type_values.resize(0) catch unreachable;

            const EmissionInfo = struct{
                abbreviation: u32 = 0,
                code: u32 = 0,
            };

            for (dummy_types) |ty| {
                // std.debug.print("Ty: {s}\n", .{@tagName(ty)});
                const emission_info: EmissionInfo = switch (ty) {
                    .pointer => b: {
                        type_values.appendAssumeCapacity(address_space);
                        break :b .{
                            .abbreviation = opaque_pointer_abbreviation,
                            .code = @intFromEnum(TypeCode.opaque_pointer),
                        };
                    },
                    .integer => |bit_count| b: {
                        type_values.appendAssumeCapacity(bit_count);
                        break :b .{
                            .code = @intFromEnum(TypeCode.integer),
                        };
                    },
                    .function => |f| b: {
                        type_values.appendAssumeCapacity(@intFromBool(f.varargs));
                        type_values.appendAssumeCapacity(f.return_type);
                        for (f.parameter_types) |parameter_type_index| {
                            type_values.appendAssumeCapacity(parameter_type_index);
                        }
                        break :b .{
                            .code = @intFromEnum(TypeCode.function),
                            .abbreviation = function_abbreviation,
                        };
                    },
                    .metadata => .{
                        .code = @intFromEnum(TypeCode.metadata),
                    },
                    .void => .{
                        .code = @intFromEnum(TypeCode.void),
                    },
                };

                writer.emit_record(u64, emission_info.code, type_values.constSlice(), emission_info.abbreviation);
                type_values.resize(0) catch unreachable;
            }

            writer.exit_block();

            const end = writer.buffer.length * 4;
            const expected = debug_main_bitcode[start..end];
            const have = writer.get_byte_slice()[start..end];
            std.debug.print("Start: {}\n", .{start});
            std.testing.expectEqualSlices(u8, expected, have) catch unreachable;
        }

        const DummyAttribute = union(enum) {
            string: struct{
                key: []const u8,
                value: []const u8,
            },
            enumeration: AttributeKindCode,
            int: struct{
                value: u64,
                key: AttributeKindCode,
            },
            // TODO
            type: AttributeKindCode,
        };

        const AttributeGroup = struct{
            attributes: []const DummyAttribute,
            parameter_index: u32,
        };

        const attribute_groups = [_]AttributeGroup{
            .{
                .parameter_index = 0xffff_ffff,
                .attributes = &.{
                    .{ .enumeration = .no_inline },
                    .{ .enumeration = .no_unwind },
                    .{ .enumeration = .optimize_none },
                    .{
                        .int = .{
                            .key = .uw_table,
                            .value = 2,
                        },
                    },
                    .{
                        .string = .{
                            .key = "frame-pointer",
                            .value = "all",
                        },
                    },
                    .{
                        .string = .{
                            .key = "min-legal-vector-width",
                            .value = "0",
                        },
                    },
                    .{
                        .string = .{
                            .key = "no-trapping-math",
                            .value = "true",
                        },
                    },
                    .{
                        .string = .{
                            .key = "stack-protector-buffer-size",
                            .value = "8",
                        },
                    },
                    .{
                        .string = .{
                            .key = "target-cpu",
                            .value = "x86-64",
                        },
                    },
                    .{
                        .string = .{
                            .key = "target-features",
                            .value = "+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87",
                        },
                    },
                    .{
                        .string = .{
                            .key = "tune-cpu",
                            .value = "generic",
                        },
                    },
                },
            },
            .{
                .parameter_index = 1,
                .attributes = &.{
                    .{ .enumeration = .noundef },
                },
            },
            .{
                .parameter_index = 2,
                .attributes = &.{
                    .{ .enumeration = .noundef },
                },
            },
            .{
                .parameter_index = 0xffff_ffff,
                .attributes = &.{
                    .{ .enumeration = .no_callback },
                    .{ .enumeration = .nofree },
                    .{ .enumeration = .nosync },
                    .{ .enumeration = .no_unwind },
                    .{ .enumeration = .speculatable },
                    .{ .enumeration = .willreturn },
                    .{ 
                        .int = .{
                            .key = .memory,
                            .value = 0,
                        },
                    },
                },
            },
        };

        fn write_attribute_group_table(writer: *Writer) void {
            if (attribute_groups.len > 0) {
                writer.enter_subblock(.parameter_attribute_group, 3);
                const start = writer.buffer.length * 4;
                var records = std.BoundedArray(u64, 4096){};

                for (attribute_groups, 0..) |attribute_group, attribute_group_index| {
                    std.debug.print("====\nWriting attribute group #{}...\n====\n", .{attribute_group_index});
                    defer std.debug.print("====\nEnded attribute group #{}...\n====\n", .{attribute_group_index});
                    records.appendAssumeCapacity(attribute_group_index + 1);
                    records.appendAssumeCapacity(attribute_group.parameter_index);

                    for (attribute_group.attributes) |attribute| {
                        switch (attribute) {
                            .enumeration => |e| {
                                records.appendAssumeCapacity(0);
                                records.appendAssumeCapacity(@intFromEnum(e));
                            },
                            .int => |i| {
                                records.appendAssumeCapacity(1);
                                records.appendAssumeCapacity(@intFromEnum(i.key));
                                records.appendAssumeCapacity(i.value);
                            },
                            .string => |s| {
                                records.appendAssumeCapacity(@as(u64, 3) + @intFromBool(s.value.len > 0));
                                for (s.key) |b| {
                                    records.appendAssumeCapacity(b);
                                }
                                records.appendAssumeCapacity(0);

                                if (s.value.len > 0) {
                                    for (s.value) |b| {
                                        records.appendAssumeCapacity(b);
                                    }
                                    records.appendAssumeCapacity(0);
                                }
                            },
                            else => |t| @panic(@tagName(t)),
                        }
                    }

                    writer.emit_record(u64, @intFromEnum(AttributeCode.group_entry), records.constSlice(), 0);
                    records.resize(0) catch unreachable;
                }

                writer.exit_block();
                const end = writer.buffer.length * 4;
                const expected = debug_main_bitcode[start..end];
                const have = writer.get_byte_slice()[start..end];
                std.debug.print("Start: {}\n", .{start});
                std.testing.expectEqualSlices(u8, expected, have) catch unreachable;
            }
        }

        const AttributeList = struct{
            attribute_groups: []const u32,
        };

        const attribute_lists = [_]AttributeList{
            .{ .attribute_groups = &.{1, 2, 3} },
            .{ .attribute_groups = &.{4} },
        };

        fn write_attribute_table(writer: *Writer) void {
            if (attribute_groups.len > 0) {
                writer.enter_subblock(.parameter_attribute, 3);

                var records = std.BoundedArray(u64, 4096){};
                for (attribute_lists) |attribute_list| {
                    for (attribute_list.attribute_groups) |attribute_group_index| {
                        const attribute_group = attribute_groups[attribute_group_index - 1];
                        if (attribute_group.attributes.len > 0) {
                            records.appendAssumeCapacity(attribute_group_index);
                        }
                    }
                    
                    writer.emit_record(u64, @intFromEnum(AttributeCode.entry), records.constSlice(), 0);
                    records.resize(0) catch unreachable;
                }

                writer.exit_block();
            }
        }

        fn write_module_info(writer: *Writer) void {
            const target_triple = "x86_64-pc-linux-gnu";
            writer.write_string_record(@intFromEnum(ModuleCode.triple), target_triple,
                // TODO in LLVM code
                0);

            const data_layout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128";
            writer.write_string_record(@intFromEnum(ModuleCode.data_layout), data_layout,
                // TODO in LLVM code
                0);

            // TODO: global inline assembly
            // const global_inline_assembly = "";
            // write_string_record(@intFromEnum(ModuleCode.@"asm"), global_inline_assembly,
            //     // TODO in LLVM code
            //     0);
            //

            // TODO: section names
            
            // TODO: global abbreviation

            var values = std.BoundedArray(u32, 64){};
            {
                const source_filename = "llvm-link";
                const source_string_encoding = get_string_encoding(source_filename);
                const abbreviation = writer.abbreviation_buffer.append(.{});
                abbreviation.add_literal(@intFromEnum(ModuleCode.source_filename));
                abbreviation.add_with_encoding(.{ .encoding = .array });
                switch (source_string_encoding) {
                    .char6 => abbreviation.add_with_encoding(.{ .encoding = .char6 }),
                    .fixed7 => abbreviation.add_with_encoding(.{ .encoding = .fixed, .value = 7 }),
                    .fixed8 => abbreviation.add_with_encoding(.{ .encoding = .fixed, .value = 8 }),
                }

                const filename_abbreviation = writer.emit_abbreviation(abbreviation);
                for (source_filename) |ch| {
                    values.appendAssumeCapacity(ch);
                }

                writer.emit_record(u32, @intFromEnum(ModuleCode.source_filename), values.constSlice(), filename_abbreviation);
                values.resize(0) catch unreachable;
            }

            // TODO: global variables

            for (dummy_functions) |function| {
                const offset = writer.strtab_content.length;
                writer.strtab_content.append_slice(function.name);
                values.appendAssumeCapacity(offset);
                values.appendAssumeCapacity(@intCast(function.name.len));
                values.appendAssumeCapacity(function.type);
                values.appendAssumeCapacity(@intFromEnum(function.calling_convention));
                values.appendAssumeCapacity(@intFromBool(function.is_declaration));
                values.appendAssumeCapacity(@intFromEnum(function.linkage));
                values.appendAssumeCapacity(function.attribute_list_id);
                values.appendAssumeCapacity(function.alignment);
                values.appendAssumeCapacity(function.section);
                values.appendAssumeCapacity(@intFromEnum(function.visibility));
                values.appendAssumeCapacity(@intFromBool(function.gc));
                values.appendAssumeCapacity(@intFromEnum(function.unnamed_address));
                // TODO:
                values.appendAssumeCapacity(function.prologued_data);
                values.appendAssumeCapacity(function.comdat);
                values.appendAssumeCapacity(function.prefix_data);
                values.appendAssumeCapacity(function.personality);
                values.appendAssumeCapacity(@intFromBool(function.dso_local));
                values.appendAssumeCapacity(function.address_space);
                values.appendAssumeCapacity(function.partition_offset);
                values.appendAssumeCapacity(function.partition_len);

                writer.emit_record(@TypeOf(values.constSlice()[0]), @intFromEnum(ModuleCode.function), values.constSlice(), 0);
                values.resize(0) catch unreachable;
            }

            // TODO: global aliases

            // TODO: global ifunc

            writer.write_value_symbol_table_forward_declaration();
        }

        const DummyFunction = struct{
            name: []const u8,
            type: u32,
            calling_convention: LLVM.Value.Constant.Function.CallingConvention,
            is_declaration: bool,
            linkage: LLVM.BitcodeLinkage,
            attribute_list_id: u32,
            alignment: u32,
            section: u32,
            visibility: LLVM.GlobalVisibility,
            gc: bool = false,
            unnamed_address: LLVM.GlobalUnnamedAddress,
            prologued_data: u32,
            dll_storage_class: LLVM.DLLStorageClass,
            comdat: u32,
            prefix_data: u32,
            personality: u32,
            dso_local: bool,
            address_space: u32,
            partition_offset: u32,
            partition_len: u32,
        };

        const dummy_functions = [_]DummyFunction{
            .{
                .name = "main",
                .type = 2,
                .calling_convention = .C,
                .is_declaration = false,
                .linkage = .external,
                .attribute_list_id = 0,
                .alignment = 0,
                .section = 0,
                .visibility = .default,
                .unnamed_address = .none,
                .prologued_data = 0,
                .dll_storage_class = .default,
                .comdat = 0,
                .prefix_data = 0,
                .personality = 0,
                .dso_local = true,
                .address_space = 0,
                .partition_offset = 0,
                .partition_len = 0,
            },
            .{
                .name = "llvm.dbg.declare",
                .type = 5,
                .calling_convention = .C,
                .is_declaration = true,
                .linkage = .external,
                .attribute_list_id = 1,
                .alignment = 0,
                .section = 0,
                .visibility = .default,
                .unnamed_address = .none,
                .prologued_data = 0,
                .dll_storage_class = .default,
                .comdat = 0,
                .prefix_data = 0,
                .personality = 0,
                .dso_local = false,
                .address_space = 0,
                .partition_offset = 0,
                .partition_len = 0,
            },
        };

        fn write_module_constants(writer: *Writer) void {
            _ = writer; // autofix
            // TODO:
        }

        fn write_module_metadata_kinds(writer: *Writer) void {
            _ = writer; // autofix
            // TODO:
        }

        fn write_module_metadata(writer: *Writer) void {
            _ = writer; // autofix
            // TODO:
        }

        fn write_use_list_block(writer: *Writer, function: ?*u32) void {
            _ = function; // autofix
            _ = writer; // autofix
            // TODO:
        }

        fn write_operand_bundle_tags(writer: *Writer) void {
            _ = writer; // autofix
        }

        fn write_sync_scope_names(writer: *Writer) void {
            _ = writer; // autofix
        }

        fn write_value_symbol_table_forward_declaration(writer: *Writer) void {
            const abbreviation = writer.abbreviation_buffer.append(.{});
            abbreviation.add_literal(@intFromEnum(ModuleCode.vst_offset));
            abbreviation.add_with_encoding(.{ .encoding = .fixed, .value = 32 });

            const vst_offset_abbreviation = writer.emit_abbreviation(abbreviation);
            const values = [_]u64{@intFromEnum(ModuleCode.vst_offset), 0};
            writer.emit_record_with_abbrev(u64, vst_offset_abbreviation, &values);

            writer.vst_offset_placeholder = (writer.buffer.length * 32) - 32;
        }

        fn emit_record_with_abbrev(writer: *Writer, comptime T: type, abbreviation: u32, values: []const T) void {
            writer.emit_record_with_abbrev_impl(T, abbreviation, values, null, null);
        }

        fn switch_to_block_id(writer: *Writer, block_id: u32) void {
            if (block_id != writer.block_info_current_block_id) {
                const v = [1]u32{block_id};
                writer.emit_record(u32, @intFromEnum(BlockInfoCode.set_bid), &v, 0);
                writer.block_info_current_block_id = block_id;
            }
        }

        fn get_block_info(writer: *Writer, block_id: u32) ?*BlockInfo {
            if (writer.block_info_records.length > 0) {
                const last = &writer.block_info_records.slice()[writer.block_info_records.length - 1];
                if (last.id == block_id) {
                    return last;
                }

                for (writer.block_info_records.slice()) |*block_info| {
                    if (block_info.id == block_id) {
                        return block_info;
                    }
                }
            }

            return null;
        }

        fn get_or_create_block_info(writer: *Writer, block_id: u32) *BlockInfo {
            if (writer.get_block_info(block_id)) |block_info| return block_info else {
                const result = writer.block_info_records.append(.{
                    .id = block_id,
                });

                return result;
            }
        }

        fn emit_block_info_abbrev(writer: *Writer, block_id: u32, abbreviation: *Abbreviation) u32 {
            writer.switch_to_block_id(block_id);
            writer.encode_abbreviation(abbreviation);
            const block_info = writer.get_or_create_block_info(block_id);
            _ = block_info.abbreviations.append(abbreviation);
            return block_info.abbreviations.length - 1 + @intFromEnum(FixedAbbreviationId.first_application_abbrev);
        }

        fn write_raw(writer: *Writer, value: u32) void {
            std.debug.print("[{}-{}] Flushing buffer 0x{x}\n", .{writer.buffer.length, writer.buffer.length * 4, value});
            // if (writer.buffer.length == (220) / 4 - 1) @breakpoint();
            // if (writer.buffer.length == (152 + 32) / 4) @breakpoint();
            _ = writer.buffer.append(value);
        }

        pub fn append_bytes(writer: *Writer, bytes: []const u8) void {
            assert(bytes.len % 4 == 0);

            var slice: []const u32 = undefined;
            slice.ptr = @alignCast(@ptrCast(bytes.ptr));
            slice.len = @divExact(bytes.len, @sizeOf(u32));

            writer.buffer.append_slice(slice);
        }

        fn emit(writer: *Writer, value: u32, bit_count: u32) void {
            std.debug.print("ASK: [[32-B-IDX[0x{x}] 8-bit IDX[{}] - CVAL=0x{x} - CBIT={}]] Writing 0x{x} for {} bits\n", .{writer.buffer.length, writer.buffer.length * 4, writer.current_value, writer.current_bit, value, bit_count});
            assert(bit_count > 0 and bit_count <= 32);
            assert(value & ~(~@as(u32, 0) >> @as(u5, @intCast(32 - bit_count))) == 0);
            const shifted = value << @as(u5, @intCast(writer.current_bit));
            writer.current_value |= shifted;

            if (writer.current_bit + bit_count < 32) {
                writer.current_bit += bit_count;
            } else {
                writer.write_raw(writer.current_value);

                if (writer.current_bit != 0) {
                    writer.current_value = value >> @as(u5, @intCast(32 - writer.current_bit));
                } else {
                    writer.current_value = 0;
                }

                writer.current_bit = (writer.current_bit + bit_count) & 31;
            }
        }

        fn flush(writer: *Writer) void {
            if (writer.current_bit != 0) {
                writer.write_raw(writer.current_value);
                writer.current_bit = 0;
                writer.current_value = 0;
            }
        }

        fn encode_abbreviation(writer: *Writer, abbreviation: *Abbreviation) void {
            writer.emit_code(@intFromEnum(FixedAbbreviationId.define_abbrev));
            writer.emit_vbr(abbreviation.operands.length, 5);

            for (abbreviation.operands.const_slice()) |*operand| {
                writer.emit(@intFromBool(operand.is_literal), 1);
                if (operand.is_literal) {
                    writer.emit_vbr64(operand.value, 8);
                } else {
                    writer.emit(@intFromEnum(operand.encoding), 3);
                    if (operand.get_encoding_data()) |encoding_data| {
                        writer.emit_vbr64(encoding_data, 5);
                    }
                }
            }
        }

        fn emit_abbreviation(writer: *Writer, abbreviation: *Abbreviation) u32 {
            writer.encode_abbreviation(abbreviation);
            _ = writer.current_abbreviations.append(abbreviation);
            return writer.current_abbreviations.length - 1 + @intFromEnum(FixedAbbreviationId.first_application_abbrev);
        }

        fn emit_abbreviated_literal(writer: *Writer, comptime T: type, operand: *Abbreviation.Op, value: T) void {
            _ = writer; // autofix
            assert(operand.is_literal);
            assert(value == operand.value);
        }

        fn write_identification_block(writer: *Writer) void {
            writer.enter_subblock(.identification, 5);

            {
                const abbreviation = writer.abbreviation_buffer.append(.{});
                abbreviation.add_literal(@intFromEnum(IdentificationCode.string));
                abbreviation.add_with_encoding(.{ .encoding = .array });
                abbreviation.add_with_encoding(.{ .encoding = .char6 });
                const string_abbreviation = writer.emit_abbreviation(abbreviation);
                writer.write_string_record(@intFromEnum(IdentificationCode.string), "LLVM17.0.6", string_abbreviation);
            }

            {
                const abbreviation = writer.abbreviation_buffer.append(.{});
                abbreviation.add_literal(@intFromEnum(IdentificationCode.epoch));
                abbreviation.add_with_encoding_advanced(.{
                    .encoding = .vbr,
                    .value = 6,
                    .is_literal = false,
                });
                const epoch_abbreviation = writer.emit_abbreviation(abbreviation);
                const current_epoch = 0;
                const values = [1]u32{current_epoch};
                writer.emit_record(u32, @intFromEnum(IdentificationCode.epoch), &values, epoch_abbreviation);
                writer.exit_block();
            }
            
            const identification_block = [_]u8{
                0x35, 0x14, 0x00, 0x00, 
                0x05, 0x00, 0x00, 0x00, 
                0x62, 0x0c, 0x30, 0x24, 
                0x4a, 0x59, 0xbe, 0x66, 
                0xbd, 0xfb, 0xb4, 0xaf, 
                0x0b, 0x51, 0x80, 0x4c, 
                0x01, 0x00, 0x00, 0x00, 
            };
            std.testing.expectEqualSlices(u8, &identification_block, writer.get_byte_slice()[4..]) catch unreachable;
        }

        fn exit_block(writer: *Writer) void {
            assert(writer.block_scope.length != 0);

            const last = &writer.block_scope.slice()[writer.block_scope.length - 1];

            writer.emit_code(@intFromEnum(FixedAbbreviationId.end_block));
            writer.flush();

            const size32 = writer.buffer.length - last.start_size_index - 1;

            writer.buffer.slice()[last.start_size_index] = size32;

            writer.current_codesize = last.previous_code_size;
            writer.current_abbreviations = last.previous_abbreviations;
            writer.block_scope.length -= 1;
        }

        fn is_char6(ch: u8) bool {
            return (is_alphabetic(ch) or is_decimal_digit(ch)) or (ch == '.' or ch == '_');
        }

        fn write_string_record(writer: *Writer, code: u32, string: []const u8, abbreviation_to_use: u32) void {
            var values = std.BoundedArray(u32, 128){};
            var a = abbreviation_to_use;
            for (string) |ch| {
                if (a != 0 and !is_char6(ch)) {
                    a = 0;
                }
                values.appendAssumeCapacity(ch);
            }
            writer.emit_record(u32, code, values.constSlice(), a);
        }

        fn emit_record(writer: *Writer, comptime T: type, code: u32, values: []const T, abbreviation: u32) void {
            if (abbreviation == 0) {
                const count: u32 = @intCast(values.len);

                writer.emit_code(@intFromEnum(FixedAbbreviationId.unabbrev_record));
                writer.emit_vbr(code, 6);
                writer.emit_vbr(count, 6);

                for (values, 0..) |v, i| {
                    std.debug.print("Value #{} at [{}]: 0x{x}\n", .{i, writer.buffer.length * 4, v});
                    writer.emit_vbr64(v, 6);
                }
            } else {
                writer.emit_record_with_abbrev_impl(T, abbreviation, values, null, code);
            }
        }

        fn emit_record_with_abbrev_impl(writer: *Writer, comptime T: type, abbreviation_int: u32, values: []const T, string: ?[]const u8, code: ?u32) void {
            const abbreviation_number = abbreviation_int - @intFromEnum(FixedAbbreviationId.first_application_abbrev);
            assert(abbreviation_number < writer.current_abbreviations.length);
            const abbreviation = writer.current_abbreviations.slice()[abbreviation_number];

            writer.emit_code(abbreviation_int);

            const operand_count = abbreviation.operands.length;
            var operand_index: u32 = 0;
            if (code) |c| {
                assert(operand_count > 0);
                const operand = &abbreviation.operands.slice()[operand_index];
                operand_index += 1;

                if (operand.is_literal) {
                    writer.emit_abbreviated_literal(u32, operand, c);
                } else {
                    unreachable;
                }
            }

            var record_index: u32 = 0;
            while (operand_index < operand_count) : (operand_index += 1) {
                const operand = &abbreviation.operands.slice()[operand_index];

                if (operand.is_literal) {
                    assert(record_index < values.len);
                    writer.emit_abbreviated_literal(T, operand, values[record_index]);
                    record_index += 1;
                } else if (operand.encoding == .array) {
                    assert(operand_index + 2 == operand_count);
                    operand_index += 1;
                    const elt_enc = &abbreviation.operands.slice()[operand_index];
                    if (string) |s| {
                        _ = s; // autofix
                        unreachable;
                    } else {
                        writer.emit_vbr(@intCast(values.len - record_index), 6);
                        while (record_index < values.len) : (record_index += 1) {
                            writer.emit_abbreviated_field(T, elt_enc, values[record_index]);
                        }
                    }
                } else if (operand.encoding == .blob) {
                    unreachable;
                } else {
                    assert(record_index < values.len);
                    writer.emit_abbreviated_field(T, operand, values[record_index]);
                    record_index += 1;
                }
            }
            assert(record_index == values.len);
        }

        fn emit_abbreviated_field(writer: *Writer, comptime T: type, operand: *Abbreviation.Op, value: T) void {
            assert(!operand.is_literal);

            switch (operand.encoding) {
                else => unreachable,
                .fixed => {
                    if (operand.get_encoding_data()) |v| {
                        writer.emit(@intCast(value), @intCast(v));
                    }
                },
                .vbr => {
                    if (operand.get_encoding_data()) |v| {
                        writer.emit_vbr64(value, @intCast(v));
                    }
                },
                .char6 => {
                    const ch6 = encode_char6(@intCast(value));
                    writer.emit(ch6, 6);
                },
            }
        }

        fn encode_char6(ch: u8) u32 {
            if (is_lower(ch)) return ch - 'a';
            if (is_upper(ch)) return ch - 'A' + 26;
            if (is_decimal_digit(ch)) return ch - '0' + 26 + 26;
            if (ch == '.') return 62;
            if (ch == '_') return 63;
            unreachable;
        }

        const StringEncoding = enum{
            char6,
            fixed7,
            fixed8,
        };

        fn get_string_encoding(string: []const u8) StringEncoding{
            var char6 = true;
            for (string) |ch| {
                if (char6) {
                    char6 = is_char6(ch);
                }

                if (ch & 128 != 0) {
                    return .fixed8;
                }
            }

            return if (char6) .char6 else .fixed7;
        }

        fn enter_subblock(writer: *Writer, block_id: BlockId, code_length: u32) void {
            writer.emit_code(@intFromEnum(FixedAbbreviationId.enter_subblock));
            writer.emit_vbr(@intFromEnum(block_id), width.block_id);
            writer.emit_vbr(code_length, width.code_length);
            writer.flush();

            const block_size_index = writer.buffer.length;
            const old_code_size = writer.current_codesize;

            writer.write_raw(0);

            writer.current_codesize = code_length;

            const block = writer.block_scope.append(.{
                .start_size_index = block_size_index,
                .previous_code_size = old_code_size,
            });
            block.previous_abbreviations = writer.current_abbreviations;
            writer.current_abbreviations = .{};

            // getBlockInfo
            if (false) {
                unreachable;
            }
        }

        fn emit_code(writer: *Writer, value: u32) void {
            writer.emit(value, writer.current_codesize);
        }

        fn emit_vbr(writer: *Writer, value: u32, bit_count: u32) void {
            std.debug.print("Emitting VBR{}: 0x{x}...\n", .{bit_count, value});
            assert(bit_count <= 32);
            const shifter: u5 = @intCast(bit_count - 1);
            const threshold = @as(u32, 1) << shifter;
            var v = value;

            while (v >= threshold) : (v >>= shifter) {
                const value_to_emit = (v & (threshold - 1)) | threshold;
                writer.emit(value_to_emit, bit_count);
            }

            writer.emit(v, bit_count);
        }

        fn emit_vbr64(writer: *Writer, value: u64, bit_count: u32) void {
            std.debug.print("Emitting VBR{}: 0x{x}...\n", .{bit_count, value});
            assert(bit_count <= 32);
            if (@as(u32, @truncate(value)) == value) {
                writer.emit_vbr(@truncate(value), bit_count);
            } else {
                const shifter: u5 = @intCast(bit_count - 1);
                const threshold = @as(u32, 1) << shifter;

                var v = value;
                while (v >= threshold) : (v >>= shifter) {
                    const v32: u32 = @truncate(v);
                    const value_to_emit = (v32 & (threshold - 1)) | threshold;
                    writer.emit(value_to_emit, bit_count);
                }

                writer.emit(@truncate(v), bit_count);
            }
        }
    };
};

fn write_bitcode() void {
    var writer = Bitcode.Writer{};
    if (false) {
        // const file = std.fs.cwd().readFileAlloc(std.heap.page_allocator, "/home/david/clang18.ll", 0xfffffffff) catch unreachable;
        // Bitcode.print_hex_slice(file);
        // writer.append_bytes(file);
    } else {
        writer.write();
    }


    const context = LLVM.Context.create();
    const module = context.parse_bitcode(writer.get_byte_slice()) orelse exit(1);
    _ = module; // autofix

    exit(0);
}

const CallingConvention = enum {
    c,
    custom,
};

const Analyzer = struct {
    current_basic_block: *BasicBlock = undefined,
    current_function: *Function = undefined,
};

const bracket_open = 0x7b;
const bracket_close = 0x7d;

var cpu_count: u32 = 0;

const address_space = 0;

fn thread_callback(thread_index: u32) void {
    var created_thread_count: u32 = 0;
    while (true) {
        const local_cpu_count = cpu_count;
        if (local_cpu_count == 0) {
            break;
        }

        if (@cmpxchgWeak(u32, &cpu_count, local_cpu_count, local_cpu_count - 1, .seq_cst, .seq_cst) == null) {
            created_thread_count += 1;
            const t = std.Thread.spawn(.{}, thread_callback, .{local_cpu_count - 1}) catch unreachable;
            _ = t; // autofix
        }
    }

    const thread = &threads[thread_index];

    thread.arena = Arena.init(4 * 1024 * 1024) catch unreachable;

    while (true) {
        const to_do = thread.task_system.job.to_do;
        const completed = thread.task_system.job.completed;

        if (completed < to_do) {
            const jobs = thread.task_system.job.entries[completed..to_do];
            for (jobs) |job| {
                switch (job.id) {
                    .llvm_setup => {
                        for ([_]Type.Integer.Signedness{ .unsigned, .signed }) |signedness| {
                            for (0..64 + 1) |bit_count| {
                                const integer_type = Type.Integer{
                                    .bit_count = @intCast(bit_count),
                                    .signedness = signedness,
                                };
                                _ = thread.types.append(.{
                                    .sema = @bitCast(integer_type),
                                });
                            }
                        }
                    },
                    .analyze_file => {
                        const file_index = job.offset;
                        const file = &instance.files.slice()[file_index];
                        file.scope = .{
                            .id = .file,
                            .index = @intCast(thread.file_scopes.append_index(.{})),
                        };
                        file.state = .analyzing;
                        file.source_code = library.read_file(thread.arena, std.fs.cwd(), file.path);
                        file.thread = thread_index;
                        analyze_file(thread, file_index);

                        // if (do_codegen and codegen_backend == .llvm) {
                        // }

                        thread.analyzed_file_count += 1;

                        for (file.interested_threads.slice()) |ti| {
                            thread.add_control_work(.{
                                .id = .notify_file_resolved,
                                .offset = file_index,
                                .count = @intCast(ti),
                            });
                        }
                    },
                    .notify_file_resolved => {
                        const file_path_hash = job.offset;
                        const file_index = job.count;
                        const file = &instance.files.pointer[file_index];
                        const file_scope = threads[file.thread].file_scopes.get(@enumFromInt(file.scope.index));
                        if (&threads[file.thread] == thread) {
                            exit_with_error("Threads match!");
                        } else {
                            const pending_file_index = for (thread.pending_files.slice(), 0..) |pending_file_path_hash, i| {
                                if (file_path_hash == pending_file_path_hash) {
                                    break i;
                                }
                            } else {
                                exit(1);
                            };
                            // _ = pending_file_index; // autofix

                            const pending_file_values = thread.pending_file_values.get(@enumFromInt(pending_file_index));

                            for (pending_file_values.slice()) |value| {
                                assert(value.sema.thread == thread.get_index());
                                if (!value.sema.resolved) {
                                    switch (value.sema.id) {
                                        .instruction => {
                                            const instruction = thread.instructions.get(@enumFromInt(value.sema.index));
                                            switch (instruction.id) {
                                                .call => {
                                                    const call = thread.calls.get(@enumFromInt(instruction.index));
                                                    const callable = call.value;
                                                    assert(!callable.sema.resolved);
                                                    switch (callable.sema.id) {
                                                        .lazy_expression => {
                                                            const lazy_expression = thread.lazy_expressions.get(@enumFromInt(callable.sema.index));
                                                            assert(lazy_expression.* == .static);
                                                            const names = lazy_expression.names();
                                                            assert(names.len > 0);
                                                            const declaration = lazy_expression.static.outsider;
                                                            switch (declaration.id) {
                                                                .file => {},
                                                                // .unresolved_import => {
                                                                //     assert(declaration.index == pending_file_index);
                                                                //     declaration.id = .file;
                                                                //     declaration.index = file_index;
                                                                //     value.resolved = true;
                                                                //     unreachable;
                                                                // },
                                                                else => |t| @panic(@tagName(t)),
                                                            }

                                                            assert(names.len == 1);

                                                            if (file_scope.declarations.get(names[0])) |callable_declaration| switch (callable_declaration.id) {
                                                                .function_definition => {
                                                                    const function_definition = threads[file.thread].functions.get_unchecked(callable_declaration.index);
                                                                    const external_fn = thread.external_functions.append(function_definition.declaration);
                                                                    external_fn.global.attributes.@"export" = false;
                                                                    external_fn.global.attributes.@"extern" = true;

                                                                    const new_callable_declaration = GlobalSymbolReference{
                                                                        .id = .function_declaration,
                                                                        .index = @intCast(thread.external_functions.get_index(external_fn)),
                                                                    };

                                                                    const new_callable_value = thread.values.append(.{
                                                                        .sema = .{
                                                                            .id = .global_symbol,
                                                                            .index = @bitCast(new_callable_declaration),
                                                                            .thread = thread.get_index(),
                                                                            .resolved = true,
                                                                        },
                                                                    });
                                                                    call.value = new_callable_value;
                                                                    value.sema.resolved = true;
                                                                },
                                                                else => |t| @panic(@tagName(t)),
                                                                // unreachable;
                                                                // // const new_callable_value = thread.values.append(.{
                                                                // //     .id = .global_symbol,
                                                                // //     .index = @bitCast(callable_declaration),
                                                                // //     .thread = @intCast(file.thread),
                                                                // //     .resolved = true,
                                                                // // });
                                                                // // call.value = new_callable_value;
                                                                // // value.resolved = true;
                                                            } else exit(1);
                                                        },
                                                        else => |t| @panic(@tagName(t)),
                                                    }
                                                },
                                                else => |t| @panic(@tagName(t)),
                                            }
                                        },
                                        .lazy_expression => {
                                            const lazy_expression = thread.lazy_expressions.get(@enumFromInt(value.sema.index));
                                            assert(lazy_expression.* == .static);
                                            for (lazy_expression.static.names) |n| {
                                                assert(n == 0);
                                            }
                                            const declaration = lazy_expression.static.outsider;
                                            switch (declaration.id) {
                                                .unresolved_import => {
                                                    assert(declaration.index == pending_file_index);
                                                    declaration.id = .file;
                                                    declaration.index = file_index;
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
                    },
                    .resolve_thread_module => {
                        // exit(0);
                    },
                    .llvm_codegen_thread_module => {
                        if (thread.functions.length > 0) {
                            // const bytes = library.read_file(instance.arena, std.fs.cwd(), "/home/david/main.ll");
                            // for (bytes, 0..) |b, i| {
                            //     if (i % 4 == 0) {
                            //         std.debug.print("\n    ", .{});
                            //     }
                            //     std.debug.print("0x{x:0>2}, ", .{b});
                            // }
                            write_bitcode();
                            // _ = result; // autofix
                            exit(0);
                            // const bytes = library.read_file(instance.arena, std.fs.cwd(), "/home/david/mybitcode.ll");
                            // for (bytes, 0..) |*b, i| {
                            //     if (i % 4 == 0) {
                            //         std.debug.print("\n[{}] 0x{x:<8}: ", .{i, @as(*const u32, @alignCast(@ptrCast(b))).*});
                            //     }
                            //     std.debug.print("[{}] 0x{x:<2} ", .{i, b.*});
                            // }
                            // write("\n");
                            // const debug_info = true;
                            //
                            // const ExternalRef = struct{
                            //     gsr: GlobalSymbolReference,
                            //     thread: u16,
                            // };
                            // var external_hashmap = PinnedHashMap(ExternalRef, *LLVM.Value.Constant.Function){};
                            //
                            // for (thread.external_functions.slice()) |*nat_function| {
                            //     _ = llvm_get_function(thread, nat_function, true);
                            // }
                            //
                            // _ = &external_hashmap; // autofix
                            // for (thread.functions.slice()) |*nat_function| {
                            //     _ = llvm_get_function(thread, &nat_function.declaration, false);
                            // }
                            //
                            // for (thread.functions.slice()) |*nat_function| {
                            //     const function = nat_function.declaration.llvm.?;
                            //     const nat_entry_basic_block = thread.basic_blocks.get(nat_function.entry_block);
                            //     assert(nat_entry_basic_block.predecessors.length == 0);
                            //     const entry_block_name = "entry_block_name";
                            //     const entry_block = thread.llvm.context.createBasicBlock(entry_block_name, entry_block_name.len, function, null);
                            //     thread.llvm.builder.setInsertPoint(entry_block);
                            //
                            //     for (nat_entry_basic_block.instructions.slice()) |instruction| {
                            //         const value: *LLVM.Value = switch (instruction.id) {
                            //             .ret => block: {
                            //                 const return_instruction = thread.returns.get(@enumFromInt(instruction.index));
                            //                 const return_value = llvm_get_value(thread, return_instruction.value);
                            //                 const ret = thread.llvm.builder.createRet(return_value);
                            //                 break :block ret.toValue();
                            //             },
                            //             .call => block: {
                            //                 const call = thread.calls.get(@enumFromInt(instruction.index));
                            //                 const callee = if (call.value.sema.thread == thread.get_index()) switch (call.value.sema.id) {
                            //                     .global_symbol => blk: {
                            //                         const global_symbol: GlobalSymbolReference = @bitCast(call.value.sema.index);
                            //                         break :blk switch (global_symbol.id) {
                            //                             .function_declaration => b: {
                            //                                 const external_function = thread.external_functions.slice()[global_symbol.index];
                            //                                 break :b external_function.llvm.?;
                            //                             },
                            //                             else => |t| @panic(@tagName(t)),
                            //                         };
                            //                     },
                            //                     else => |t| @panic(@tagName(t)),
                            //                 } else exit(1);
                            //                 const function_type = callee.getType();
                            //
                            //                 const arguments: []const *LLVM.Value = &.{};
                            //                 const call_i = thread.llvm.builder.createCall(function_type, callee.toValue(), arguments.ptr, arguments.len, "", "".len, null);
                            //                 break :block call_i.toValue();
                            //             },
                            //             else => |t| @panic(@tagName(t)),
                            //         };
                            //
                            //         instruction.llvm = value;
                            //     }
                            //
                            //     if (debug_info) {
                            //         const file_index = nat_function.declaration.file;
                            //         const llvm_file = thread.debug_info_file_map.get_pointer(file_index).?;
                            //         const subprogram = function.getSubprogram();
                            //         llvm_file.builder.finalizeSubprogram(subprogram, function);
                            //     }
                            //
                            //     const verify_function = true;
                            //     if (verify_function) {
                            //         var message: []const u8 = undefined;
                            //         const verification_success = function.verify(&message.ptr, &message.len);
                            //         if (!verification_success) {
                            //             var function_msg: []const u8 = undefined;
                            //             function.toString(&function_msg.ptr, &function_msg.len);
                            //             write(function_msg);
                            //             write("\n");
                            //             exit_with_error(message);
                            //         }
                            //     }
                            // }
                            //
                            // if (debug_info) {
                            //     const file_index = thread.functions.slice()[0].declaration.file;
                            //     const llvm_file = thread.debug_info_file_map.get_pointer(file_index).?;
                            //     llvm_file.builder.finalize();
                            // }
                            //
                            // const verify_module = true;
                            // if (verify_module) {
                            //     var verification_message: []const u8 = undefined;
                            //     const verification_success = thread.llvm.module.verify(&verification_message.ptr, &verification_message.len);
                            //     if (!verification_success) {
                            //         const print_module = true;
                            //         if (print_module) {
                            //             var module_content: []const u8 = undefined;
                            //             thread.llvm.module.toString(&module_content.ptr, &module_content.len);
                            //             write(module_content);
                            //             write("\n");
                            //         }
                            //
                            //         exit_with_error(verification_message);
                            //     }
                            // }
                        }
                    },
                }

                thread.task_system.job.completed += 1;
            }
        }

        std.atomic.spinLoopHint();
    }
}

fn llvm_get_value(thread: *Thread, value: *Value) *LLVM.Value {
    if (value.llvm) |llvm| return llvm else {
        const value_id = value.sema.id;
        const llvm_value: *LLVM.Value = switch (value_id) {
            .constant_int => b: {
                const constant_int = thread.constant_ints.get(@enumFromInt(value.sema.index));
                const integer_value = constant_int.value;
                const bit_count = integer_bit_count(constant_int.type);
                const signedness = integer_signedness(constant_int.type);
                const result = thread.llvm.context.getConstantInt(bit_count, integer_value, @intFromEnum(signedness) != 0);
                break :b result.toValue();
            },
            .lazy_expression => {
                // const lazy_expression = thread.expressions.get(@enumFromInt(value.index));
                // switch (lazy_expression.kind) {
                //     .resolved => |resolved| switch (resolved) {
                //         .instruction => |instruction| switch (instruction.id) {
                //             else => |t| @panic(@tagName(t)),
                //         },
                //         else => |t| @panic(@tagName(t)),
                //     },
                //     else => |t| @panic(@tagName(t)),
                // }
                @trap();
            },
            .instruction => block: {
                const instruction = thread.instructions.get_unchecked(value.sema.index);
                break :block instruction.llvm.?;
            },
            else => |t| @panic(@tagName(t)),
        };

        value.llvm = llvm_value;

        return llvm_value;
    }
}

fn llvm_get_type(thread: *Thread, ty: *Type) *LLVM.Type {
    var store = true;
    if (ty.llvm) |llvm| {
        if (llvm.getContext() == thread.llvm.context) {
            return llvm;
        }
        store = false;
    }

    {
        const llvm_type: *LLVM.Type = switch (ty.sema.id) {
            .integer => b: {
                const bit_count = integer_bit_count(ty);
                const integer_type = thread.llvm.context.getIntegerType(bit_count);
                break :b integer_type.toType();
            },
            else => |t| @panic(@tagName(t)),
        };
        if (store) {
            ty.llvm = llvm_type;
        }
        return llvm_type;
    }
}

fn llvm_get_file(thread: *Thread, file_index: u32) *LLVMFile {
    if (thread.debug_info_file_map.get_pointer(file_index)) |llvm| return llvm else {
        const builder = thread.llvm.module.createDebugInfoBuilder();
        const file = &instance.files.slice()[file_index];
        const filename = std.fs.path.basename(file.path);
        const directory = file.path[0 .. file.path.len - filename.len];
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
    if (nat_function.llvm) |llvm| return llvm else {
        _ = override_extern; // autofix
        const function_name = thread.identifiers.get(nat_function.global.name) orelse unreachable;
        const return_type = llvm_get_type(thread, nat_function.return_type);
        var argument_types = PinnedArray(*LLVM.Type){};
        _ = &argument_types;
        for (nat_function.argument_types) |argument_type| {
            _ = argument_type; // autofix
            exit(1);
        }
        const is_var_args = false;
        const function_type = LLVM.getFunctionType(return_type, argument_types.pointer, argument_types.length, is_var_args);
        const is_extern_function = nat_function.global.attributes.@"extern";
        const export_or_extern = nat_function.global.attributes.@"export" or is_extern_function;
        const linkage: LLVM.Linkage = switch (export_or_extern) {
            true => .@"extern",
            false => .internal,
        };
        const function = thread.llvm.module.createFunction(function_type, linkage, address_space, function_name.ptr, function_name.len);

        const debug_info = true;
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

        nat_function.llvm = function;
        return function;
    }
}

pub fn analyze_file(thread: *Thread, file_index: u32) void {
    const file = instance.files.get(@enumFromInt(file_index));
    const src = file.source_code;
    if (src.len > std.math.maxInt(u32)) {
        exit(1);
    }

    file.functions.start = @intCast(thread.functions.length);

    var parser = Parser{};
    var analyzer = Analyzer{};

    while (true) {
        parser.skip_space(src);

        if (parser.i >= src.len) break;

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
                    const function_index = thread.functions.get_index(function);
                    const entry_block = thread.basic_blocks.append(.{});
                    const entry_block_index = thread.basic_blocks.get_typed_index(entry_block);

                    analyzer.current_function = function;
                    analyzer.current_basic_block = entry_block;

                    function.* = .{
                        .declaration = .{
                            .return_type = undefined,
                            .global = .{
                                .name = undefined,
                            },
                            .file = file_index,
                        },
                        .entry_block = entry_block_index,
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

                    function.declaration.global.name = parser.parse_identifier(thread, src);

                    parser.skip_space(src);

                    const has_symbol_attributes = src[parser.i] == '[';
                    parser.i += @intFromBool(has_symbol_attributes);

                    if (has_symbol_attributes) {
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

                                    const after_ch = src[parser.i];
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

                    const split_modules = true;
                    if (split_modules) {
                        function.declaration.global.attributes.@"export" = true;
                    }

                    parser.expect_character(src, '(');

                    while (true) {
                        parser.skip_space(src);

                        if (src[parser.i] == ')') break;

                        exit(1);
                    }

                    parser.expect_character(src, ')');

                    parser.skip_space(src);

                    function.declaration.return_type = parser.parse_type_expression(thread, src);

                    parser.skip_space(src);

                    const block_start = parser.i;
                    const block_line = parser.current_line + 1;
                    _ = block_line; // autofix
                    const block_column = block_start - parser.line_offset + 1;
                    _ = block_column; // autofix
                    //
                    parser.expect_character(src, bracket_open);
                    const file_scope = thread.file_scopes.get(@enumFromInt(file.scope.index));
                    file_scope.declarations.put_no_clobber(function.declaration.global.name, .{
                        .id = .function_definition,
                        .index = @intCast(function_index),
                    });

                    parser.skip_space(src);

                    while (true) {
                        parser.skip_space(src);

                        if (src[parser.i] == bracket_close) break;

                        if (src[parser.i] == 'r') {
                            const identifier = parser.parse_raw_identifier(src);

                            if (byte_equal(identifier, "return")) {
                                parser.skip_space(src);

                                if (function.declaration.return_type.sema.id != .unresolved) {
                                    const return_value = parser.parse_typed_expression(&analyzer, thread, file, function.declaration.return_type);
                                    parser.expect_character(src, ';');

                                    const return_expression = thread.returns.append_index(.{
                                        .value = return_value,
                                    });

                                    const return_instruction = thread.instructions.append(.{
                                        .id = .ret,
                                        .index = @intCast(return_expression),
                                    });

                                    _ = analyzer.current_basic_block.instructions.append(return_instruction);
                                    analyzer.current_basic_block.is_terminated = true;
                                } else {
                                    exit(1);
                                }
                            } else {
                                exit(1);
                            }
                        } else {
                            exit(1);
                        }
                    }

                    parser.expect_character(src, bracket_close);
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
                    const has_right_extension = filename.len > ".nat".len and byte_equal(filename[filename.len - ".nat".len ..], ".nat");
                    if (!has_right_extension) {
                        exit(1);
                    }
                    const filename_without_extension = filename[0 .. filename.len - ".nat".len];
                    const filename_without_extension_hash = hash_bytes(filename_without_extension);

                    const directory_path = file.get_directory_path();
                    const directory = std.fs.openDirAbsolute(directory_path, .{}) catch unreachable;
                    const file_path = library.realpath(thread.arena, directory, string_literal) catch unreachable;
                    const file_path_hash = intern_identifier(&thread.identifiers, file_path);

                    if (thread.local_files.get(file_path_hash)) |import_file_index| {
                        _ = import_file_index; // autofix
                        exit(1);
                    } else {
                        for (thread.pending_files.slice()) |pending_file| {
                            if (pending_file == file_path_hash) {
                                exit(1);
                            }
                        } else {
                            thread.add_control_work(.{
                                .id = .analyze_file,
                                .offset = file_path_hash,
                            });
                            const index = thread.pending_files.append_index(file_path_hash);
                            const file_scope = thread.file_scopes.get(@enumFromInt(file.scope.index));
                            file_scope.declarations.put_no_clobber(filename_without_extension_hash, .{
                                .id = .unresolved_import,
                                .index = @intCast(index),
                            });
                            const ptr = file_scope.declarations.get_pointer(filename_without_extension_hash) orelse unreachable;
                            const list = thread.pending_file_values.append(.{});
                            const lazy_expression = thread.lazy_expressions.append(LazyExpression.init(ptr));
                            const declaration = thread.values.append(.{
                                .sema = .{
                                    .id = .lazy_expression,
                                    .index = thread.lazy_expressions.get_index(lazy_expression),
                                    .thread = thread.get_index(),
                                    .resolved = false,
                                },
                            });
                            _ = list.append(declaration);
                        }
                    }
                } else {
                    exit(1);
                }
            },
            else => exit(1),
        }
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

    pub const BitcodeLinkage = enum(c_uint) {
        external = 0,
        appending = 2,
        internal = 3,
        external_weak = 7,
        common = 8,
        private = 9,
        available_external = 12,
        weak_any = 16,
        weak_odr = 17,
        link_once_any = 18,
        link_once_odr = 19,
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

        pub fn parse_bitcode(context: *LLVM.Context, bytes: []const u8) ?*LLVM.Module {
            const memory_buffer = bindings.LLVMCreateMemoryBufferWithMemoryRange(bytes.ptr, bytes.len, null, 0);
            var out_module: *LLVM.Module = undefined;

            if (bindings.LLVMParseBitcodeInContext2(context, memory_buffer, &out_module) == 0) {
                return out_module;
            } else {
                return null;
            }
        }
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

    pub const MemoryBuffer = opaque {};

    pub const GlobalVisibility = enum(u8) {
        default = 0,
        hidden = 1,
        protected = 2,
    };

    pub const GlobalUnnamedAddress = enum(u8) {
        none = 0,
        local = 1,
        global = 2,
    };

    pub const DLLStorageClass = enum(u8) {
        default = 0,
        import = 1,
        @"export" = 2,
    };

    pub const Value = opaque {
        const setName = bindings.NativityLLVMValueSetName;
        const getType = bindings.NativityLLVMValueGetType;
        const toConstant = bindings.NativityLLVMValueToConstant;
        const toFunction = bindings.NativityLLVMValueToFunction;
        const toAlloca = bindings.NativityLLVMValueToAlloca;
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

                    /// Used on AMDGPUs to give the middle-end more control over argument
                    /// placement.
                    AMDGPU_CS_Chain = 104,

                    /// Used on AMDGPUs to give the middle-end more control over argument
                    /// placement. Preserves active lane values for input VGPRs.
                    AMDGPU_CS_ChainPreserve = 105,

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
