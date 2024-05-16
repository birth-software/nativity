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

const GlobalSymbol = struct{
    attributes: Attributes = .{},
    name: u32,
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
    dynamic: struct{
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
            .static => |*s| s.names[0.. for (s.names, 0..) |n, i| {
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

const Expression = struct{
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
    const Id = enum(u8){
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

    const Id = enum(u8){
        unresolved,
        void,
        integer,
    };

    const Integer = packed struct(u32) {
        bit_count: u16,
        signedness: Signedness,
        reserved: u7 = 0,
        id: Id = .integer,

        const Signedness = enum(u1){
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

const IntegerType = struct{
};

const Keyword = enum{
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
const Range = struct{
    start: u32,
    end: u32,
};

const FileScope = struct{
    declarations: PinnedHashMap(u32, GlobalSymbolReference) = .{},
};

const GlobalSymbolReference = Descriptor(enum(u3) {
    function_definition,
    function_declaration,
    file,
    unresolved_import,
}, u32);

const BasicBlock = struct{
    instructions: PinnedArray(*Instruction) = .{},
    predecessors: PinnedArray(u32) = .{},
    is_terminated: bool = false,

    const Index = PinnedArray(BasicBlock).Index;
};

const Function = struct{
    declaration: Function.Declaration,
    entry_block: BasicBlock.Index,

    const Attributes = struct{
        calling_convention: CallingConvention = .custom,
    };

    const Attribute = enum{
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


const Instruction = struct{
    index: u24,
    id: Id,
    llvm: ?*LLVM.Value = null,

    const Id = enum{
        call,
        ret,
        ret_void,
    };
};

const ConstantInt = struct{
    value: u64,
    type: *Type,
};


const Call = struct{
    value: *Value,
    const Index = PinnedArray(Call).Index;
};

const Return = struct{
    value: *Value,
    const Index = PinnedArray(Call).Index;
};

const Thread = struct{
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

    const Id = enum(u8){
        analyze_file,
        llvm_setup,
        notify_file_resolved,
        resolve_module,
        llvm_generate_ir,
        llvm_optimize,
        llvm_emit_object,
    };
};

const TaskSystem = struct{
    job: JobQueue = .{},
    ask: JobQueue = .{},
};

const JobQueue = struct{
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

const Instance = struct{
    files: PinnedArray(File) = .{},
    file_paths: PinnedArray(u32) = .{},
    arena: *Arena = undefined,
};

const File = struct{
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

    const State = enum{
        queued,
        analyzing,
    };

    const Index = PinnedArray(File).Index;
};

var instance = Instance{};
const do_codegen = true;
const codegen_backend = CodegenBackend.llvm;

const CodegenBackend = enum{
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
                    const jobs_to_do = thread.task_system.ask.entries[thread.task_system.ask.completed .. thread.task_system.ask.to_do];

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
                .id = .resolve_module,
            });
        }
    }

    // TODO: Prune
    if (do_codegen) {
        for (threads) |*thread| {
            thread.add_thread_work(Job{
                .id = switch (codegen_backend) {
                    .llvm => .llvm_generate_ir,
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
            1 => unreachable,
            2 => {
                const first = modules_present.slice()[0];
                const second = modules_present.slice()[1];
                const destination = threads[first].llvm.module;
                {
                    var message: []const u8 = undefined;
                    destination.toString(&message.ptr, &message.len);
                    std.debug.print("{s}\n", .{message});
                }
                const source = threads[second].llvm.module;
                {
                    var message: []const u8 = undefined;
                    source.toString(&message.ptr, &message.len);
                    std.debug.print("{s}\n", .{message});
                }

                if (!destination.link(source, .{
                    .override_from_source = true,
                    .link_only_needed = false,
                })) {
                    exit(1);
                }

                var message: []const u8 = undefined;
                destination.toString(&message.ptr, &message.len);
                std.debug.print("============\n===========\n{s}\n", .{message});
            },
            else => unreachable,
        }
    }

    // while (true) {}
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

fn get_integer_type(thread: *Thread) void {
    _ = thread; // autofix
}

const CallingConvention = enum{
    c,
    custom,
};

const Analyzer = struct{
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
                        thread.llvm = .{
                            .context = context,
                            .module = module,
                            .builder = builder,
                            .attributes = attributes,
                        };

                        for ([_]Type.Integer.Signedness{.unsigned, .signed}) |signedness| {
                            for (0..64+1) |bit_count| {
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
                                            for ( lazy_expression.static.names) |n| {
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
                    .resolve_module => {
                        // exit(0);
                    },
                    .llvm_generate_ir => {
                        if (thread.functions.length > 0) {
                            const debug_info = true;

                            const ExternalRef = struct{
                                gsr: GlobalSymbolReference,
                                thread: u16,
                            };
                            var external_hashmap = PinnedHashMap(ExternalRef, *LLVM.Value.Constant.Function){};

                            for (thread.external_functions.slice()) |*nat_function| {
                                _ = llvm_get_function(thread, nat_function, true);
                            }

                            _ = &external_hashmap; // autofix
                            for (thread.functions.slice()) |*nat_function| {
                                _ = llvm_get_function(thread, &nat_function.declaration, false);
                            }

                            for (thread.functions.slice()) |*nat_function| {
                                const function = nat_function.declaration.llvm.?;
                                const nat_entry_basic_block = thread.basic_blocks.get(nat_function.entry_block);
                                assert(nat_entry_basic_block.predecessors.length == 0);
                                const entry_block_name = "entry_block_name";
                                const entry_block = thread.llvm.context.createBasicBlock(entry_block_name, entry_block_name.len, function, null);
                                thread.llvm.builder.setInsertPoint(entry_block);

                                for (nat_entry_basic_block.instructions.slice()) |instruction| {
                                    const value: *LLVM.Value = switch (instruction.id) {
                                        .ret => block: {
                                            const return_instruction = thread.returns.get(@enumFromInt(instruction.index));
                                            const return_value = llvm_get_value(thread, return_instruction.value);
                                            const ret = thread.llvm.builder.createRet(return_value);
                                            break :block ret.toValue();
                                        },
                                        .call => block: {
                                            const call = thread.calls.get(@enumFromInt(instruction.index));
                                            const callee = if (call.value.sema.thread == thread.get_index()) switch (call.value.sema.id) {
                                                .global_symbol => blk: {
                                                    const global_symbol: GlobalSymbolReference = @bitCast(call.value.sema.index);
                                                    break :blk switch (global_symbol.id) {
                                                        .function_declaration => b: {
                                                            const external_function = thread.external_functions.slice()[global_symbol.index];
                                                            break :b external_function.llvm.?;
                                                        },
                                                        else => |t| @panic(@tagName(t)),
                                                    };
                                                },
                                                else => |t| @panic(@tagName(t)),
                                            } else exit(1);
                                            const function_type = callee.getType();

                                            const arguments: []const *LLVM.Value = &.{};
                                            const call_i = thread.llvm.builder.createCall(function_type, callee.toValue(), arguments.ptr, arguments.len, "", "".len, null);
                                            break :block call_i.toValue();
                                        },
                                        else => |t| @panic(@tagName(t)),
                                    };

                                    instruction.llvm = value;
                                }

                                if (debug_info) {
                                    const file_index = nat_function.declaration.file;
                                    const llvm_file = thread.debug_info_file_map.get_pointer(file_index).?;
                                    const subprogram = function.getSubprogram();
                                    llvm_file.builder.finalizeSubprogram(subprogram, function);
                                }

                                const verify_function = true;
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
                                const file_index = thread.functions.slice()[0].declaration.file;
                                const llvm_file = thread.debug_info_file_map.get_pointer(file_index).?;
                                llvm_file.builder.finalize();
                            }

                            const verify_module = true;
                            if (verify_module) {
                                var verification_message: []const u8 = undefined;
                                const verification_success = thread.llvm.module.verify(&verification_message.ptr, &verification_message.len);
                                if (!verification_success) {
                                    const print_module = true;
                                    if (print_module) {
                                        var module_content: []const u8 = undefined;
                                        thread.llvm.module.toString(&module_content.ptr, &module_content.len);
                                        write(module_content);
                                        write("\n");
                                    }

                                    exit_with_error(verification_message);
                                }
                            }
                        }
                    },
                    else => |t| @panic(@tagName(t)),
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
                                } else  {
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
