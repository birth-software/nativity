const std = @import("std");
const assert = std.debug.assert;
const equal = std.mem.eql;

const Allocator = std.mem.Allocator;

const data_structures = @import("data_structures.zig");
const ArrayList = data_structures.ArrayList;
const AutoHashMap = data_structures.AutoHashMap;
const AutoArrayHashMap = data_structures.AutoArrayHashMap;
const BlockList = data_structures.BlockList;
const HashMap = data_structures.HashMap;
const SegmentedList = data_structures.SegmentedList;
const StringKeyMap = data_structures.StringKeyMap;
const StringHashMap = data_structures.StringHashMap;
const StringArrayHashMap = data_structures.StringArrayHashMap;

const lexer = @import("frontend/lexer.zig");
const parser = @import("frontend/parser.zig");
const Node = parser.Node;
const llvm = @import("backend/llvm.zig");

const cache_dir_name = "cache";
const installation_dir_name = "installation";

const ArgumentParsingError = error{
    main_package_path_not_specified,
    main_source_file_not_found,
};

fn reportUnterminatedArgumentError(string: []const u8) noreturn {
    std.debug.panic("Unterminated argument: {s}", .{string});
}

fn parseArguments(context: *const Context) !Descriptor {
    const allocator = context.allocator;
    const arguments = (try std.process.argsAlloc(allocator))[1..];

    var maybe_executable_path: ?[]const u8 = null;
    var maybe_main_package_path: ?[]const u8 = null;
    var target_triplet: []const u8 = "x86_64-linux-gnu";
    var should_transpile_to_c: ?bool = null;
    var maybe_only_parse: ?bool = null;
    var link_libc = false;
    var maybe_executable_name: ?[]const u8 = null;
    const generate_debug_information = true;
    var is_build = false;

    if (arguments.len == 0) {
        is_build = true;
    } else if (equal(u8, arguments[0], "init")) {
        if (arguments.len == 1) {
            unreachable;
        } else {
            @panic("Init does not take arguments");
        }
    } else {
        var i: usize = 0;
        while (i < arguments.len) : (i += 1) {
            const current_argument = arguments[i];
            if (equal(u8, current_argument, "-o")) {
                if (i + 1 != arguments.len) {
                    maybe_executable_path = arguments[i + 1];
                    assert(maybe_executable_path.?.len != 0);
                    i += 1;
                } else {
                    reportUnterminatedArgumentError(current_argument);
                }
            } else if (equal(u8, current_argument, "-target")) {
                if (i + 1 != arguments.len) {
                    target_triplet = arguments[i + 1];
                    i += 1;
                } else {
                    reportUnterminatedArgumentError(current_argument);
                }
            } else if (equal(u8, current_argument, "-log")) {
                if (i + 1 != arguments.len) {
                    i += 1;

                    var log_argument_iterator = std.mem.splitScalar(u8, arguments[i], ',');

                    while (log_argument_iterator.next()) |log_argument| {
                        var log_argument_splitter = std.mem.splitScalar(u8, log_argument, '.');
                        const log_scope_candidate = log_argument_splitter.next() orelse unreachable;
                        var recognized_scope = false;

                        inline for (@typeInfo(LoggerScope).Enum.fields) |logger_scope_enum_field| {
                            const log_scope = @field(LoggerScope, logger_scope_enum_field.name);

                            if (equal(u8, @tagName(log_scope), log_scope_candidate)) {
                                const LogScope = getLoggerScopeType(log_scope);

                                if (log_argument_splitter.next()) |particular_log_candidate| {
                                    var recognized_particular = false;
                                    inline for (@typeInfo(LogScope.Logger).Enum.fields) |particular_log_field| {
                                        const particular_log = @field(LogScope.Logger, particular_log_field.name);

                                        if (equal(u8, particular_log_candidate, @tagName(particular_log))) {
                                            LogScope.Logger.bitset.setPresent(particular_log, true);
                                            recognized_particular = true;
                                        }
                                    } else if (!recognized_particular) std.debug.panic("Unrecognized particular log \"{s}\" in scope {s}", .{ particular_log_candidate, @tagName(log_scope) });
                                } else {
                                    // LogScope.Logger.bitset = @TypeOf(LogScope.Logger.bitset).initFull();
                                }

                                logger_bitset.setPresent(log_scope, true);

                                recognized_scope = true;
                            }
                        } else if (!recognized_scope) std.debug.panic("Unrecognized log scope: {s}", .{log_scope_candidate});
                    }
                } else {
                    reportUnterminatedArgumentError(current_argument);
                }
            } else if (equal(u8, current_argument, "-transpile_to_c")) {
                if (i + 1 != arguments.len) {
                    i += 1;

                    const arg = arguments[i];
                    if (std.mem.eql(u8, arg, "true")) {
                        should_transpile_to_c = true;
                    } else if (std.mem.eql(u8, arg, "false")) {
                        should_transpile_to_c = false;
                    } else {
                        unreachable;
                    }
                } else {
                    reportUnterminatedArgumentError(current_argument);
                }
            } else if (equal(u8, current_argument, "-parse")) {
                if (i + 1 != arguments.len) {
                    i += 1;

                    const arg = arguments[i];
                    maybe_main_package_path = arg;
                    maybe_only_parse = true;
                } else {
                    reportUnterminatedArgumentError(current_argument);
                }
            } else if (equal(u8, current_argument, "-link_libc")) {
                if (i + 1 != arguments.len) {
                    i += 1;

                    const arg = arguments[i];
                    if (std.mem.eql(u8, arg, "true")) {
                        link_libc = true;
                    } else if (std.mem.eql(u8, arg, "false")) {
                        link_libc = false;
                    } else {
                        unreachable;
                    }
                } else {
                    reportUnterminatedArgumentError(current_argument);
                }
            } else if (equal(u8, current_argument, "-main_source_file")) {
                if (i + 1 != arguments.len) {
                    i += 1;

                    const arg = arguments[i];
                    maybe_main_package_path = arg;
                } else {
                    reportUnterminatedArgumentError(current_argument);
                }
            } else if (equal(u8, current_argument, "-name")) {
                if (i + 1 != arguments.len) {
                    i += 1;

                    const arg = arguments[i];
                    maybe_executable_name = arg;
                } else {
                    reportUnterminatedArgumentError(current_argument);
                }
            } else {
                std.debug.panic("Unrecognized argument: {s}", .{current_argument});
            }
        }
    }

    const cross_target = try std.zig.CrossTarget.parse(.{ .arch_os_abi = target_triplet });
    const target = try std.zig.system.resolveTargetQuery(cross_target);
    const transpile_to_c = should_transpile_to_c orelse false;
    const only_parse = maybe_only_parse orelse false;

    const main_package_path = if (maybe_main_package_path) |path| blk: {
        const file = std.fs.cwd().openFile(path, .{}) catch return error.main_source_file_not_found;
        file.close();

        break :blk path;
    } else blk: {
        const build_file = "build.nat";
        const file = std.fs.cwd().openFile(build_file, .{}) catch return error.main_package_path_not_specified;
        file.close();
        is_build = true;

        break :blk build_file;
    };

    const executable_name = if (is_build) b: {
        assert(maybe_executable_name == null);
        break :b "build";
    } else b: {
        break :b if (maybe_executable_name) |name| name else std.fs.path.basename(main_package_path[0 .. main_package_path.len - "/main.nat".len]);
    };

    const executable_path = maybe_executable_path orelse blk: {
        assert(executable_name.len > 0);
        const result = try std.mem.concat(allocator, u8, &.{ "nat/", executable_name });
        break :blk result;
    };

    return .{
        .main_package_path = main_package_path,
        .executable_path = executable_path,
        .target = target,
        .transpile_to_c = transpile_to_c,
        .is_build = is_build,
        .only_parse = only_parse,
        .link_libc = link_libc,
        .generate_debug_information = generate_debug_information,
        .name = executable_name,
    };
}

pub fn init(allocator: Allocator) !void {
    const context: *Context = try allocator.create(Context);

    const self_exe_path = try std.fs.selfExePathAlloc(allocator);
    const self_exe_dir_path = std.fs.path.dirname(self_exe_path).?;
    context.* = .{
        .allocator = allocator,
        .cwd_absolute_path = try realpathAlloc(allocator, "."),
        .executable_absolute_path = self_exe_path,
        .directory_absolute_path = self_exe_dir_path,
        .build_directory = try std.fs.cwd().makeOpenPath("nat", .{}),
    };

    try context.build_directory.makePath(cache_dir_name);
    try context.build_directory.makePath(installation_dir_name);

    const unit = try context.allocator.create(Unit);
    unit.* = .{
        .descriptor = try parseArguments(context),
    };
    try unit.compile(context);
}

pub const Intrinsic = struct{
    kind: Kind,
    type: Type.Index,

    pub const List = BlockList(@This(), enum{});
    pub usingnamespace @This().List.Index;

    // Each time an enum is added here, a corresponding insertion in the initialization must be made
    pub const Kind = union(Id) {
        @"asm", //this is processed separately as it need special parsing
        cast: Value.Index,
        enum_to_int: Value.Index,
        @"error",
        int_to_pointer: Value.Index,
        import,
        min,
        size,
        sign_extend: Value.Index,
        syscall: []const Value.Index,
        zero_extend: Value.Index,
    };

    pub const Id = enum{
        @"asm", //this is processed separately as it need special parsing
        cast,
        enum_to_int,
        @"error",
        int_to_pointer,
        import,
        min,
        size,
        sign_extend,
        syscall,
        zero_extend,
    };
};

pub const BinaryOperation = struct{
    left: Value.Index,
    right: Value.Index,
    type: Type.Index,
    id: Id,

    pub const Id = enum {
        add,
        sub,
        mul,
        div,
        mod,
        bit_and,
        bit_xor,
        bit_or,
        shift_left,
        shift_right,
        compare_equal,
        compare_not_equal,
        compare_greater,
        compare_greater_equal,
        compare_less,
        compare_less_equal,
    };

    pub const List = BlockList(@This(), enum{});
    pub usingnamespace List.Index;
};

pub const Assignment = struct {
    destination: Value.Index,
    source: Value.Index,
    operation: ?BinaryOperation.Id,

    pub const List = BlockList(@This(), enum{});
    pub usingnamespace List.Index;
};

pub const Call = struct {
    value: Value.Index,
    arguments: []const Value.Index,
    type: Type.Index,

    pub const List = BlockList(@This(), enum{});
    pub usingnamespace List.Index;
};

pub const Return = struct {
    value: Value.Index,

    pub const List = BlockList(@This(), enum{});
    pub usingnamespace List.Index;
};

pub const InlineAssembly = struct {
    instructions: []const InlineAssembly.Instruction.Index,

    pub const List = BlockList(@This(), enum{});
    pub usingnamespace List.Index;

    pub const Instruction = struct {
        id: u32,
        operands: []const Operand,

        pub const List = BlockList(@This(), enum{});
        pub usingnamespace @This().List.Index;
    };

    pub const Operand = union(enum) {
        register: u32,
        number_literal: u64,
        value_index: Value.Index,
    };

    pub const x86_64 = struct {
        pub const Instruction = enum {
            @"and",
            call,
            mov,
            xor,
        };

        pub const Register = enum {
            ebp,
            rsp,
            rdi,
        };
    };
};

fn realpathAlloc(allocator: Allocator, pathname: []const u8) ![]const u8 {
    var path_buffer: [std.fs.MAX_PATH_BYTES]u8 = undefined;
    const realpathInStack = try std.os.realpath(pathname, &path_buffer);
    return allocator.dupe(u8, realpathInStack);
}

pub const ContainerType = enum {
    @"struct",
    @"enum",
};

pub const Directory = struct {
    handle: std.fs.Dir,
    path: []const u8,
};

pub const Package = struct {
    directory: Directory,
    /// Relative to the package main directory
    source_path: []const u8,
    dependencies: StringHashMap(*Package) = .{},

    fn addDependency(package: *Package, allocator: Allocator, package_name: []const u8, new_dependency: *Package) !void {
        try package.dependencies.ensureUnusedCapacity(allocator, 1);
        package.dependencies.putAssumeCapacityNoClobber(package_name, new_dependency);
    }
};

const LoggerScope = enum {
    compilation,
    lexer,
    parser,
};

const Logger = enum {
    import,
    new_file,
    arguments,
    token_bytes,
    identifier,
    ir,

    var bitset = std.EnumSet(Logger).initMany(&.{
        .ir,
    });
};

fn getLoggerScopeType(comptime logger_scope: LoggerScope) type {
    comptime {
        return switch (logger_scope) {
            .compilation => @This(),
            .lexer => lexer,
            .parser => parser,
        };
    }
}

var logger_bitset = std.EnumSet(LoggerScope).initEmpty();

var writer = std.io.getStdOut().writer();

fn shouldLog(comptime logger_scope: LoggerScope, logger: getLoggerScopeType(logger_scope).Logger) bool {
    return logger_bitset.contains(logger_scope) and getLoggerScopeType(logger_scope).Logger.bitset.contains(logger);
}

pub fn logln(comptime logger_scope: LoggerScope, logger: getLoggerScopeType(logger_scope).Logger, comptime format: []const u8, arguments: anytype) void {
    if (shouldLog(logger_scope, logger)) {
        log(logger_scope, logger, format, arguments);
        writer.writeByte('\n') catch unreachable;
    }
}

pub fn log(comptime logger_scope: LoggerScope, logger: getLoggerScopeType(logger_scope).Logger, comptime format: []const u8, arguments: anytype) void {
    if (shouldLog(logger_scope, logger)) {
        std.fmt.format(writer, format, arguments) catch unreachable;
    }
}

pub fn panic(message: []const u8, stack_trace: ?*std.builtin.StackTrace, return_address: ?usize) noreturn {
    const print_stack_trace = false;
    switch (print_stack_trace) {
        true => @call(.always_inline, std.builtin.default_panic, .{ message, stack_trace, return_address }),
        false => {
            writer.writeAll("\nPANIC: ") catch {};
            writer.writeAll(message) catch {};
            writer.writeByte('\n') catch {};
            @breakpoint();
            std.os.abort();
        },
    }
}

const TypeCheckSwitchEnums = struct {
    switch_case_groups: ArrayList(ArrayList(Enum.Field.Index)),
    else_switch_case_group_index: ?usize = null,
};

const ImportFileResult = struct {
    index: File.Index,
    is_new: bool,
};

const ImportPackageResult = struct {
    file: ImportFileResult,
    is_package: bool,
};

pub const Value = union(enum) {
    undefined,
    @"unreachable",
    unresolved: Node.Index,
    copy: Value.Index,
    type: Type.Index,
    declaration: Declaration.Index,
    bool: bool,
    reference: Declaration.Index,
    intrinsic: Intrinsic.Index,
    unary_operation: UnaryOperation.Index,
    binary_operation: BinaryOperation.Index,
    assignment: Assignment.Index,
    integer: Integer,
    enum_field: Enum.Field.Index,
    block: Block.Index,
    function_definition: Function.Definition.Index,
    @"return": Return.Index,
    call: Call.Index,
    inline_assembly: InlineAssembly.Index,

    pub const List = BlockList(@This(), Common);
    pub usingnamespace List.Index;

    const Common = enum{
        undefined,
        @"unreachable",
        bool_false,
        bool_true,

        const map = std.EnumArray(@This(), Value).init(.{
            .undefined = .undefined,
            .@"unreachable" = .@"unreachable",
            .bool_false = .{
                .bool = false,
            },
            .bool_true = .{
                .bool = true,
            },
        });
    };

    pub const Integer = struct {
        value: u64,
        type: Type.Index,
    };

    pub fn isComptime(value: *const Value, unit: *Unit) bool {
        return Compilation.isComptime(value, unit);
    }

    pub fn getType(value: *const Value, unit: *Unit) Type.Index {
        return Compilation.getType(value, unit);
    }
};

fn isComptime(value: *const Value, unit: *Unit) bool {
    const result: bool = switch (value.*) {
        .type => true,
        .bool => true,
        .copy => true,
        .enum_field => true,
        .function_definition => true,
        .intrinsic => |intrinsic_index| switch (unit.intrinsics.get(intrinsic_index).kind) {
            .cast => |value_index| Compilation.isComptime(unit.values.get(value_index), unit),
            .int_to_pointer => false,
            else => |t| @panic(@tagName(t)),
        },
        .reference => false,
        .call => false,
        else => |t| @panic(@tagName(t)),
    };

    return result;
}

fn getType(value: *const Value, unit: *Unit) Type.Index{
    return switch (value.*) {
        .type => Type.Index.type,
        .bool => Type.Index.bool,
        .copy => |value_index| b: {
            const v = unit.values.get(value_index);
            break :b getType(v, unit);
        },
        .reference => |declaration_index| b: {
            const declaration = unit.declarations.get(declaration_index);
            assert(declaration.type != .null);
            const declaration_type = unit.unwrapTypeCopy(declaration.type);
            assert(unit.types.get(declaration_type).* != .unresolved);
            assert(unit.types.get(declaration_type).* != .copy);
            break :b declaration_type;
        },
        .integer => |integer| integer.type,
        .enum_field => |enum_field_index| unit.enum_fields.get(enum_field_index).parent,
        .function_definition => |function_index| unit.function_definitions.get(function_index).type,
        .call => |call_index| unit.calls.get(call_index).type,
        else => |t| @panic(@tagName(t)),
    };
}

pub const UnaryOperation = struct {
    value: Value.Index,
    type: Type.Index,
    id: Id,

    pub const List = BlockList(@This(), enum{});
    pub usingnamespace List.Index;

    pub const Id = enum {
        boolean_not,
        negation,
        address_of,
        pointer_dereference,
    };
};

pub const Block = struct{
    scope: Scope,
    pub const List = BlockList(@This(), enum{});
    pub usingnamespace List.Index;
};

const Compilation = @This();

pub const Type = union(enum) {
    void,
    noreturn,
    type,
    comptime_int,
    bool,
    unresolved: Node.Index,
    copy: Type.Index,
    @"struct": Struct.Index,
    @"enum": Enum.Index,
    function: Function.Prototype.Index,
    integer: Integer,
    pointer: Pointer,

    fn getByteSize(ty: *Type, unit: *Unit) u32 {
        _ = unit; // autofix
        return switch (ty.*) {
            .integer => |integer| integer.bit_count,
            else => |t| @panic(@tagName(t)),
        };
    }

    fn getScope(ty: *Type, unit: *Unit) *Scope {
        return switch (ty.*) {
            .@"struct" => |struct_index| &unit.structs.get(struct_index).scope,
            .@"enum" => |enum_index| &unit.enums.get(enum_index).scope,
            else => |t| @panic(@tagName(t)),
        };
    }

    const Expect = union(enum){
        none,
        type: Type.Index,
    };

    const Integer = struct {
        bit_count: u16,
        signedness: Signedness,

        pub const Signedness = enum(u1) {
            unsigned = 0,
            signed = 1,
        };
    };


    const Pointer = struct{
        type: Type.Index,
        termination: Termination,
        mutability: Mutability,
        many: bool,
        nullable: bool,
    };

    pub const Termination = enum {
        none,
        null,
        zero,
    };

    const Common = enum{
        void,
        noreturn,
        type,
        comptime_int,
        bool,
        u1,
        u8,
        u16,
        u32,
        u64,
        s8,
        s16,
        s32,
        s64,
        usize,
        ssize,

        const map = std.EnumArray(@This(), Type).init(.{
            .void = .void,
            .noreturn = .noreturn,
            .type = .type,
            .bool = .bool,
            .comptime_int = .comptime_int,
            .u1 = .{
                .integer = .{
                    .bit_count = 1,
                    .signedness = .unsigned,
                },
            },
            .u8 = .{
                .integer = .{
                    .bit_count = 8,
                    .signedness = .unsigned,
                },
            },
            .u16 = .{
                .integer = .{
                    .bit_count = 16,
                    .signedness = .unsigned,
                },
            },
            .u32 = .{
                .integer = .{
                    .bit_count = 32,
                    .signedness = .unsigned,
                },
            },
            .u64 = .{
                .integer = .{
                    .bit_count = 64,
                    .signedness = .unsigned,
                },
            },
            .s8 = .{
                .integer = .{
                    .bit_count = 8,
                    .signedness = .signed,
                },
            },
            .s16 = .{
                .integer = .{
                    .bit_count = 16,
                    .signedness = .signed,
                },
            },
            .s32 = .{
                .integer = .{
                    .bit_count = 32,
                    .signedness = .signed,
                },
            },
            .s64 = .{
                .integer = .{
                    .bit_count = 64,
                    .signedness = .signed,
                },
            },
            .ssize = .{
                .integer = .{
                    .bit_count = 64,
                    .signedness = .signed,
                },
            },
            .@"usize" = .{
                .integer = .{
                    .bit_count = 64,
                    .signedness = .unsigned,
                },
            },
        });
    };

    pub const List = BlockList(@This(), Common);
    pub usingnamespace List.Index;
};

pub const Instruction = union(enum) {
    argument_declaration: ArgumentDeclaration,
    // TODO
    call: Instruction.Call,
    cast: Cast,
    // TODO: remove?
    constant_int: Value.Integer,
    debug_checkpoint: DebugCheckPoint,
    global_variable: GlobalVariable.Index,
    inline_assembly: InlineAssembly.Index,
    integer_binary_operation: Instruction.IntegerBinaryOperation,
    // TODO: delete
    load: Load,
    load_instruction: LoadInstruction,
    load_global: LoadGlobal,
    pop_scope: Instruction.Scope,
    push_scope: Instruction.Scope,
    ret: Instruction.Index,
    ret_void,
    stack_slot: Instruction.StackSlot,
    store: Store,
    syscall: Syscall,
    @"unreachable",

    const Syscall = struct{
        arguments: []const Instruction.Index,
    };

    const Callable = union(enum) {
        function_definition: Function.Definition.Index,
    };

    const Call = struct{
        callable: Callable,
        function_type: Type.Index,
        arguments: []const Instruction.Index,
    };

    const IntegerBinaryOperation = struct{
        left: Instruction.Index,
        right: Instruction.Index,
        id: Id,
        signedness: Type.Integer.Signedness,

        const Id = enum{
            add,
            mul,
        };
    };

    const Scope = struct {
        old: *Compilation.Scope,
        new: *Compilation.Scope,
    };

    const ArgumentDeclaration = struct{
        name: u32,
        type: Type.Index,
    };

    const Cast = struct {
        id: Cast.Id,
        value: Value.Index,
        type: Type.Index,

        const Id = enum{
            enum_to_int,
            int_to_pointer,
            sign_extend,
            zero_extend,
        };
    };

    const DebugCheckPoint = struct{
        scope: *Compilation.Scope,
        line: u32,
        column: u32,
    };

    const Load = struct{
        value: Value.Index,
    };

    const LoadGlobal = struct{
        value: GlobalVariable.Index,
    };

    const LoadInstruction = struct{
        value: Instruction.Index,
    };

    const StackSlot = struct{
        type: Type.Index,
    };

    const Store = struct{
        // TODO:
        destination: Instruction.Index,
        source: Instruction.Index,
    };

    pub const List = BlockList(@This(), enum{});
    pub usingnamespace @This().List.Index;
};

pub const BasicBlock = struct{
    instructions: ArrayList(Instruction.Index) = .{},
    predecessor: BasicBlock.Index = .null,
    // TODO: not use a bool
    terminated: bool = false,

    pub const List = BlockList(@This(), enum{});
    pub usingnamespace @This().List.Index;
};

pub const Function = struct{
    pub const Attribute = enum{
        cc,
        naked,
        @"export",
        @"extern",
    };

    pub const Definition = struct{
        scope: Scope,
        symbol: GlobalSymbol,
        basic_blocks: ArrayList(BasicBlock.Index) = .{},
        // TODO: make this more efficient
        declarations: AutoArrayHashMap(Declaration.Index, Instruction.Index) = .{},
        argument_map: AutoArrayHashMap(Declaration.Index, Instruction.Index) = .{},
        type: Type.Index,
        body: Value.Index,

        pub const List = BlockList(@This(), enum{});
        pub usingnamespace @This().List.Index;
    };

    pub const Prototype = struct {
        argument_types: []const Type.Index,
        return_type: Type.Index,
        attributes: Attributes,

        const Attributes = struct{
            @"export": bool,
            naked: bool,
        };

        const List = BlockList(@This(), enum{});
        pub usingnamespace @This().List.Index;
    };

};

const Struct = struct{
    fields: ArrayList(Field) = .{},
    scope: Scope,
    backing_type: Type.Index,

    const Field = struct{
        name: u32,
        type: u32,
        value: Value.Index,
    };

    const List = BlockList(@This(), enum{});
    pub usingnamespace @This().List.Index;
};

pub const GlobalSymbol = struct{
    name: u32,
    type: Type.Index,
    kind: Kind,

    const Kind = enum{
        code,
        data,
    };
};

pub const GlobalVariable = struct{
    symbol: GlobalSymbol,
    mutability: Mutability,
    value: Value.Index,

    const List = BlockList(@This(), enum{});
    pub usingnamespace @This().List.Index;
};

pub const Context = struct {
    allocator: Allocator,
    cwd_absolute_path: []const u8,
    directory_absolute_path: []const u8,
    executable_absolute_path: []const u8,
    build_directory: std.fs.Dir,

    fn pathFromCwd(context: *const Context, relative_path: []const u8) ![]const u8 {
        return std.fs.path.join(context.allocator, &.{ context.cwd_absolute_path, relative_path });
    }

    fn pathFromCompiler(context: *const Context, relative_path: []const u8) ![]const u8 {
        return std.fs.path.join(context.allocator, &.{ context.directory_absolute_path, relative_path });
    }
};

pub const File = struct {
    relative_path: []const u8,
    package: *Package,
    source_code: []const u8 = &.{},
    status: Status = .not_loaded,
    lexer: lexer.Result = undefined,
    parser: parser.Result = undefined,
    value: Value.Index = .null,
    type: Type.Index = .null,
    scope: Scope,

    pub const List = BlockList(@This(), enum{});
    pub usingnamespace List.Index;

    pub const Status = enum {
        not_loaded,
        loaded_into_memory,
        lexed,
        parsed,
    };
};

pub const Scope = struct{
    declarations: AutoArrayHashMap(u32, Declaration.Index) =.{},
    parent: ?*Scope = null,
    file: File.Index,
    line: u32,
    column: u32,
    kind: Kind,
    local: bool,
    level: u8,

    const Lookup = struct{
        scope: *Scope,
        declaration: Declaration.Index,
    };

    fn lookupDeclaration(s: *Scope, name: u32, look_in_parent_scopes: bool) ?Lookup{
        var scope_it: ?*Scope = s;
        while (scope_it) |scope| : (scope_it = scope.parent) {
            if (scope.declarations.get(name)) |declaration| {
                return Lookup{
                    .declaration = declaration,
                    .scope = scope,
                };
            }

            if (!look_in_parent_scopes) break;
        } 

        return null;
    }

    fn getFile(scope: *Scope, unit: *Unit) File.Index {
        var scope_it: ?*Scope = scope;
        while (scope_it) |s| : (scope_it = s.parent) {
            if (s.kind == .file) {
                const file = @fieldParentPtr(File, "scope", s);
                const file_index = unit.files.indexOf(file);
                return file_index;
            }
        } else @panic("No parent file scope");

    }

    const Kind = enum{
        compilation_unit,
        file,
        file_container,
        container,
        function,// Arguments
        block,
    };
};

pub const Declaration = struct{
    scope: *Scope,
    value: Value.Index,
    type: Type.Index,
    line: u32,
    column: u32,
    name: u32,
    mutability: Mutability,

    pub const List = BlockList(@This(), enum{});
    pub usingnamespace List.Index;
};

pub const Mutability = enum(u1) {
    @"const",
    @"var",
};

pub const Builder = struct {
    current_scope: *Scope,
    current_file: File.Index = .null,
    current_function: Function.Definition.Index = .null,
    current_basic_block: BasicBlock.Index = .null,
    last_check_point: struct{
        line: u32 = 0,
        column: u32 = 0,
        scope: ?*Scope = null,
    } = .{},
    generate_debug_info: bool,
    emit_ir: bool,


    fn pushScope(builder: *Builder, unit: *Unit, context: *const Context, new_scope: *Scope) !void {
        const old_scope = builder.current_scope;

        if (builder.current_basic_block != .null) {
            const instruction = try unit.instructions.append(context.allocator, .{
                .push_scope = .{
                    .old = old_scope,
                    .new = new_scope,
                },
                });
            try builder.appendInstruction(unit, context, instruction);
        }

        new_scope.parent = old_scope;
        builder.current_scope = new_scope;
    }

    fn popScope(builder: *Builder, unit: *Unit, context: *const Context) !void {
        const old_scope = builder.current_scope;
        const new_scope = old_scope.parent.?;

        if (builder.current_basic_block != .null) {
            const instruction = try unit.instructions.append(context.allocator, .{
                .pop_scope = .{
                    .old = old_scope,
                    .new = new_scope,
                },
                });
            try builder.appendInstruction(unit, context, instruction);
        }

        builder.current_scope = new_scope;
    }

    fn analyzePackage(builder: *Builder, unit: *Unit, context: *const Context, package: *Package) !void {
        const package_import = try unit.importPackage(context, package);
        assert(!package_import.file.is_new);
        const file_index = package_import.file.index;

        _ = try builder.analyzeFile(unit, context, file_index);
    }

    fn analyzeFile(builder: *Builder, unit: *Unit, context: *const Context, file_index: File.Index) !void {
        const old_scope = builder.current_scope;
        builder.current_scope = &unit.scope;
        defer builder.current_scope = old_scope;

        const file = unit.files.get(file_index);
        assert(file.status == .parsed);
        assert(file.value == .null);

        const previous_file = builder.current_file;
        builder.current_file = file_index;
        defer builder.current_file = previous_file;

        try builder.pushScope(unit, context, &file.scope);
        defer builder.popScope(unit, context) catch unreachable;

        const main_node_index = file.parser.main_node_index;
        const main_node = unit.node_buffer.get(main_node_index);
        const main_node_list = unit.getNodeList(main_node.left);


        // Dummy
        file.type = try unit.types.append(context.allocator, .{
            .unresolved = main_node_index,
        });
        file.value = try unit.values.append(context.allocator, .{
            .type = file.type,
        });

        try builder.resolveContainerType(unit, context, main_node_list, main_node_index, .@"struct", file.type);
    }

    fn resolveValueAllocate(builder: *Builder, unit: *Unit, context: *const Context, type_expect: Type.Expect, node_index: Node.Index) !Value.Index {
        const value_index = try unit.values.append(context.allocator, .{
            .unresolved = node_index,
        });
        try builder.resolveValue(unit, context, type_expect, value_index);
        return value_index;
    }

    const TypeCheckResult = enum {
        success,
        zero_extend,
        sign_extend,
        take_source,
        take_expected,
        optional_wrap,
        array_coerce_to_slice,
    };

    const CastResult = enum{
        int_to_pointer,
        enum_to_int,
        sign_extend,
        zero_extend,
    };

    fn getCastType(builder: *Builder, unit: *Unit, context: *const Context, type_expect: Type.Expect, value_index: Value.Index) !CastResult {
        _ = builder; // autofix
        _ = context; // autofix
        const value_type_index = unit.values.get(value_index).getType(unit);
        const value_type = unit.types.get(value_type_index);

        return switch (type_expect) {
            .type => |type_index| {
                const destination_type = unit.types.get(type_index);
                switch (destination_type.*) {
                    .pointer => |destination_pointer| {
                        _ = destination_pointer; // autofix
                        switch (value_type.*) {
                            .integer => |source_integer| {
                                _ = source_integer; // autofix
                                // TODO:
                                return .int_to_pointer;
                            },
                            else => |t| @panic(@tagName(t)),
                        }
                    },
                    .integer => |destination_integer| {
                        switch (value_type.*) {
                            .@"enum" => {
                                return .enum_to_int;
                            },
                            .integer => |source_integer| {
                                if (destination_integer.bit_count < source_integer.bit_count) {
                                    unreachable;
                                } else if (destination_integer.bit_count > source_integer.bit_count) {
                                    assert(destination_integer.signedness != source_integer.signedness);
                                    return switch (destination_integer.signedness) {
                                        .signed => .sign_extend,
                                        .unsigned => .sign_extend,
                                    };
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
        };
    }

    const TokenDebugInfo = struct{
        line: u32,
        column: u32,
    };

    fn getTokenDebugInfo(builder: *Builder, unit: *Unit, token: Token.Index) TokenDebugInfo{
        const file = unit.files.get(builder.current_file);
        const line_offset_index = unit.token_buffer.tokens.items(.line)[Token.unwrap(token)];
        const line = line_offset_index - file.lexer.line_offset;
        const offset = unit.token_buffer.tokens.items(.offset)[Token.unwrap(token)];
        const line_offset = unit.token_buffer.line_offsets.items[line_offset_index];
        const column = offset - line_offset;

        return .{
            .line = line,
            .column = column,
        };
    }

    fn insertDebugCheckPoint(builder: *Builder, unit: *Unit, context: *const Context, token: Token.Index) !void {
        if (builder.generate_debug_info and builder.current_scope.local) {
            const basic_block = unit.basic_blocks.get(builder.current_basic_block);
            assert(!basic_block.terminated);

            const debug_info = builder.getTokenDebugInfo(unit, token);

            if (debug_info.line != builder.last_check_point.line or debug_info.column != builder.last_check_point.column or builder.current_scope != builder.last_check_point.scope) {
                const instruction = try unit.instructions.append(context.allocator, .{
                    .debug_checkpoint = .{
                        .scope = builder.current_scope,
                        .line = debug_info.line,
                        .column = debug_info.column,
                    },
                });
                try basic_block.instructions.append(context.allocator, instruction);

                builder.last_check_point = .{
                    .scope = builder.current_scope,
                    .line = debug_info.line,
                    .column = debug_info.column,
                };
            }
        }
    }

    fn appendInstruction(builder: *Builder, unit: *Unit, context: *const Context, instruction_index: Instruction.Index) !void {
        const basic_block = unit.basic_blocks.get(builder.current_basic_block);
        assert(!basic_block.terminated);
        try basic_block.instructions.append(context.allocator, instruction_index);
    }

    const If = struct{
        condition: Condition,
        const Condition = union(enum){
            true: Value.Index,
            false,
            runtime: Value.Index,
        };
    };

    fn resolveIf(builder: *Builder, unit: *Unit, context: *const Context, node_index: Node.Index) !If {
        const if_node = unit.getNode(node_index);
        assert(if_node.id == .@"if");

        const condition = try builder.resolveValueAllocate(unit, context, Type.Expect{
            .type = .bool,
        }, if_node.left);
        assert(condition != .null);

        if (unit.evaluateBooleanAtComptime(condition)) |comptime_condition| {
            if (comptime_condition == true) {
                unreachable;
            } else {
                return If{
                    .condition = .false,
                };
            }
        } else {
            try builder.insertDebugCheckPoint(unit, context, if_node.token);
            unreachable;
        }

        unreachable;
    }

    fn referenceDeclaration(builder: *Builder, unit: *Unit, context: *const Context, scope: *Scope, identifier: []const u8, declaration_index: Declaration.Index, value_index: Value.Index) !void {
        _ = identifier; // autofix
        const old_file = builder.current_file;
        builder.current_file = scope.getFile(unit);
        defer builder.current_file = old_file;

        const old_scope = builder.current_scope;
        builder.current_scope = scope;
        defer builder.current_scope = old_scope;

        const old_basic_block = builder.current_basic_block;
        defer builder.current_basic_block = old_basic_block;

        // We need to switch the current file so that the correct node pointers are picked by the indices into the file buffer
        const declaration = unit.declarations.get(declaration_index);
        const declaration_value_index = declaration.value;

        const is_comptime = if (declaration_value_index != .null) b: {
            const declaration_value = unit.values.get(declaration_value_index);

            switch (declaration_value.*) {
                .unresolved => {
                    switch (declaration.type) {
                        .null => {},
                        else => {
                            if (scope.kind == .function) {
                                @panic("arguments are not supposed to be here");
                            }

                            try builder.resolveType(unit, context, declaration.type);
                        },
                    }

                    const type_expect = switch (declaration.type) {
                        .null => .none,
                        else => Type.Expect{
                            .type = declaration.type,
                        },
                    };

                    try builder.resolveValue(unit, context, type_expect, declaration_value_index);

                    switch (declaration.type) {
                        .null => declaration.type = declaration_value.getType(unit),
                        else => {
                            const declaration_type = unit.types.get(declaration.type);
                            assert(declaration_type.* != .unresolved);
                        },
                    }

                    switch (unit.values.get(declaration_value_index).*) {
                        .unresolved => unreachable,
                        .function_definition => |function_definition_index| {
                            const function_definition = unit.function_definitions.get(function_definition_index);
                            function_definition.symbol = .{
                                .type = declaration.type,
                                .name = declaration.name,
                                .kind = .code,
                            };

                            try unit.function_declaration_map.putNoClobber(context.allocator, function_definition_index, declaration_index);
                        },
                        .type => |type_index| {
                            switch (unit.types.get(type_index).*) {
                                .unresolved, .copy => unreachable,
                                else => {},
                            }
                            try unit.type_declaration_map.putNoClobber(context.allocator, type_index, declaration_index);
                        },
                        else => {},
                    }
                },
                else => {},
            }

            assert(declaration_value.* != .declaration);
            assert(declaration_value.* != .unresolved);

            const result = if (declaration.mutability == .@"const" and declaration_value.isComptime(unit)) blk: {
                if (declaration_value_index != value_index) {
                    unit.copyValue(value_index, declaration.value);
                } else {
                    std.debug.print("Same value, not copying...\n", .{});
                }

                break :blk true;
            } else blk: {
                // Here we need to declare global variables that go into the executable
                switch (scope.kind) {
                    .block,
                    .function,
                    => {},
                    .file_container => {
                        if (unit.global_variable_map.get(declaration_index)) |_| {
                            //
                        } else {
                            switch (unit.values.get(declaration.value).*) {
                                .integer => {},
                                .undefined => {},
                                else => |t| @panic(@tagName(t)),
                            }
                            const global_variable = try unit.global_variables.append(context.allocator, .{
                                .symbol = .{
                                    .name = declaration.name,
                                    .type = declaration.type,
                                    .kind = .data,
                                },
                                .mutability = declaration.mutability,
                                .value = declaration.value,
                            });
                            try unit.global_variable_map.putNoClobber(context.allocator, declaration_index, global_variable);
                        }
                    },
                    else => |t| @panic(@tagName(t)),
                }

                break :blk false;
            };

            break :b result;
        } else false;

        if (!is_comptime) {
            if (declaration.value != value_index) {
                const value = unit.values.get(value_index);
                value.* = .{
                    .reference = declaration_index,
                };

                // Map the value to an instruction
                switch (declaration.scope.kind) {
                    .function => {
                        const function = unit.function_definitions.get( builder.current_function);
                        const declaration_instruction = function.argument_map.get(declaration_index).?;
                        const load = try unit.instructions.append(context.allocator, .{
                            .load_instruction = .{
                                .value = declaration_instruction,
                            },
                        });
                        try builder.appendInstruction(unit, context, load);

                        try unit.value_to_instruction_map.putNoClobber(context.allocator, value_index, load);
                    },
                    .block => {
                        const function = unit.function_definitions.get( builder.current_function);
                        const declaration_instruction = function.declarations.get(declaration_index).?;
                        const load = try unit.instructions.append(context.allocator, .{
                            .load_instruction = .{
                                .value = declaration_instruction,
                            },
                        });
                        try builder.appendInstruction(unit, context, load);

                        try unit.value_to_instruction_map.putNoClobber(context.allocator, value_index, load);
                    },
                    .file_container => {
                        const global_variable_index = unit.global_variable_map.get(declaration_index).?;
                        const load = try unit.instructions.append(context.allocator, .{
                            .load_global = .{
                                .value = global_variable_index,
                            },
                        });
                        try builder.appendInstruction(unit, context, load);
                        try unit.value_to_instruction_map.putNoClobber(context.allocator, value_index, load);
                    },
                    else => |t| @panic(@tagName(t)),
                }
            } else unreachable;
        }
    }

    fn resolveValue(builder: *Builder, unit: *Unit, context: *const Context, type_expect: Type.Expect, value_index: Value.Index) anyerror!void {
        const value = unit.values.get(value_index);
        const node_index = switch (value.*) {
            .unresolved => |ni| ni,
            else => |t| @panic(@tagName(t)),
        };

        const node = unit.getNode(node_index);

        switch (node.id) {
            .block => {
                const token_debug_info = builder.getTokenDebugInfo(unit, node.token);
                const block_index = try unit.blocks.append(context.allocator, .{
                    .scope = .{
                        .line = token_debug_info.line,
                        .column = token_debug_info.column,
                        .kind = .block,
                        .level = builder.current_scope.level + 1,
                        .local = builder.current_scope.local,
                        .file = builder.current_file,
                    },
                });

                value.* = .{
                    .block = block_index,
                };

                const block = unit.blocks.get(block_index);
                try builder.pushScope(unit, context, &block.scope);
                defer builder.popScope(unit, context) catch unreachable;

                const statement_node_list = unit.getNodeList(node.left);

                for (statement_node_list) |statement_node_index| {
                    const statement_node = unit.getNode(statement_node_index);

                    try builder.insertDebugCheckPoint(unit, context, statement_node.token);

                    switch (statement_node.id) {
                        .assign,
                        .add_assign,
                        .if_else,
                        .@"return",
                        .intrinsic,
                        .constant_symbol_declaration,
                        .variable_symbol_declaration,
                        .call,
                        .@"switch",
                        .@"unreachable",
                        => {
                            const statement_value_index = try builder.resolveValueAllocate(unit, context, Type.Expect { .type = .void }, statement_node_index);
                            assert(unit.values.get(statement_value_index).* != .unresolved);
                        },
                        else => |t| @panic(@tagName(t)),
                    }
                }
            },
            .assign, .add_assign => {
                switch (type_expect) {
                    .none => {},
                    .type => |original_type_index| {
                        const type_index = unit.unwrapTypeCopy(original_type_index);
                        assert(type_index == .void);
                    },
                }

                if (unit.getNode(node.left).id == .discard) {
                    value.* = .{
                        .unresolved = node.right,
                    };

                    try builder.resolveValue(unit, context, Type.Expect.none, value_index);
                } else {
                    const left = try builder.resolveValueAllocate(unit, context, Type.Expect.none, node.left);
                    const left_value = unit.values.get(left);
                    const is_left_comptime = left_value.isComptime(unit);
                    const left_type = left_value.getType(unit);

                    switch (is_left_comptime) {
                        true => unreachable,
                        false => {
                            const right = try builder.resolveValueAllocate(unit, context, Type.Expect{ .type = left_type }, node.right);
                            const right_value = unit.values.get(right);
                            _ = right_value; // autofix
                            const right_i = unit.value_to_instruction_map.get(right).?;

                            const assignment = Assignment{
                                .destination = left,
                                .source = right,
                                .operation = switch (node.id) {
                                    .assign => null,
                                    .add_assign => .add,
                                    else => |t| @panic(@tagName(t)),
                                },
                            };
                            const assignment_index = try unit.assignments.append(context.allocator, assignment);
                            value.* = .{
                                .assignment = assignment_index,
                            };
                            // TODO: get better at this
                            const store = try unit.instructions.append(context.allocator, .{
                                .store = .{
                                    // TODO: do this better in a more efficient way
                                    .destination = switch (left_value.*) {
                                        .reference => |declaration_index| b: {
                                            const declaration = unit.declarations.get(declaration_index);
                                            switch (declaration.scope.kind) {
                                                .file_container => {
                                                    const global_variable_index = unit.global_variable_map.get(declaration_index).?;
                                                    const instruction = try unit.instructions.append(context.allocator, .{
                                                        .global_variable = global_variable_index,
                                                    });
                                                    break :b instruction;
                                                },
                                                .block => {
                                                    const function_definition = unit.function_definitions.get(builder.current_function);
                                                    const stack_slot_instruction = function_definition.declarations.get(declaration_index).?;
                                                    break :b stack_slot_instruction;
                                                },
                                                else => |t| @panic(@tagName(t)),
                                            }
                                        },
                                        else => |t| @panic(@tagName(t)),
                                    },
                                    .source = right_i,
                                },
                            });

                            try builder.appendInstruction(unit, context, store);
                        },
                    }
                }
            },
            .identifier => {
                const identifier = unit.getExpectedTokenBytes(node.token, .identifier);

                const hash = try unit.processIdentifier(context, identifier);

                const look_in_parent_scopes = true;
                if (builder.current_scope.lookupDeclaration(hash, look_in_parent_scopes)) |lookup| {
                    const scope = lookup.scope;
                    const declaration_index = lookup.declaration;
                    try builder.referenceDeclaration(unit, context, scope, 
                        identifier, // Field inserted for debugging purposes
                        declaration_index, value_index);
                } else {
                    var scope_it: ?*Scope = builder.current_scope;
                    const indentation_size = 4;
                    var indentation: u32 = 0;

                    var file_path: []const u8 = "";
                    while (scope_it) |scope| : (scope_it = scope.parent) {
                        for (0..indentation * indentation_size) |_|{
                            std.debug.print(" ", .{});
                        }
                        std.debug.print("> Scope {s} ", .{@tagName(scope.kind)});
                        switch (scope.kind) {
                            .compilation_unit => {},
                            .file_container, .container => {},
                            .function => {},
                            .file => {
                                const file = @fieldParentPtr(File, "scope", scope);
                                std.debug.print("{s}", .{file.relative_path});
                                file_path = file.relative_path;
                            },
                            .block => {},
                        }

                        std.debug.print("\n", .{});
                        indentation += 1;
                    }

                    std.debug.panic("Identifier '{s}' not found in file {s}", .{identifier, file_path});
                }

                assert(value.* != .unresolved);
            },
            .intrinsic => {
                const intrinsic_id: Intrinsic.Id = @enumFromInt(Node.unwrap(node.right));
                const argument_node_list = unit.getNodeList(node.left);

                switch (intrinsic_id) {
                    .import => {
                        if (argument_node_list.len != 1) {
                            @panic("Import argument mismatch");
                        }

                        const argument_node_index = argument_node_list[0];
                        const argument_node = unit.getNode(argument_node_index);
                        if (argument_node.id != .string_literal) {
                            @panic("Import expected a string literal as an argument");
                        }

                        const string_literal_bytes = unit.tokenStringLiteral(argument_node.token);

                        const import_file = try unit.importFile(context, builder.current_file, string_literal_bytes);

                        if (import_file.file.is_new) {
                            const new_file_index = import_file.file.index;
                            try unit.generateAbstractSyntaxTreeForFile(context, new_file_index);
                            try builder.analyzeFile(unit, context, new_file_index);
                            logln(.compilation, .import, "Done analyzing {s}!", .{string_literal_bytes});
                        }

                        const file = unit.files.get(import_file.file.index);
                        const file_type = unit.types.get(file.type);
                        assert(file_type.* != .unresolved);
                        unit.copyValue(value_index, file.value);
                    },
                    .@"asm" => {
                        const architecture = InlineAssembly.x86_64;

                        var instructions = try ArrayList(InlineAssembly.Instruction.Index).initCapacity(context.allocator, argument_node_list.len);

                        for (argument_node_list) |assembly_statement_node_index| {
                            const assembly_statement_node = unit.getNode(assembly_statement_node_index);
                            const instruction_name = unit.getExpectedTokenBytes(assembly_statement_node.token, .identifier);
                            const instruction = inline for (@typeInfo(architecture.Instruction).Enum.fields) |instruction_enum_field| {
                                if (equal(u8, instruction_name, instruction_enum_field.name)) {
                                    break @field(architecture.Instruction, instruction_enum_field.name);
                                }
                            } else unreachable;
                            const operand_nodes = unit.getNodeList(assembly_statement_node.left);

                            var operands = try ArrayList(InlineAssembly.Operand).initCapacity(context.allocator, operand_nodes.len);

                            for (operand_nodes) |operand_node_index| {
                                const operand_node = unit.getNode(operand_node_index);
                                const operand: InlineAssembly.Operand = switch (operand_node.id) {
                                    .assembly_register => blk: {
                                        const register_name = unit.getExpectedTokenBytes(operand_node.token, .identifier);

                                        const register = inline for (@typeInfo(architecture.Register).Enum.fields) |register_enum_field| {
                                            if (equal(u8, register_name, register_enum_field.name)) {
                                                break @field(architecture.Register, register_enum_field.name);
                                            }
                                        } else unreachable;
                                        break :blk .{
                                            .register = @intFromEnum(register),
                                        };
                                    },
                                    .number_literal => switch (std.zig.parseNumberLiteral(unit.getExpectedTokenBytes(operand_node.token, .number_literal))) {
                                        .int => |integer| .{
                                            .number_literal = integer,
                                        },
                                        else => |t| @panic(@tagName(t)),
                                    },
                                    .identifier => .{
                                        .value_index = try builder.resolveValueAllocate(unit, context, Type.Expect.none, operand_node_index),
                                    },
                                    else => |t| @panic(@tagName(t)),
                                };

                                operands.appendAssumeCapacity(operand);
                            }

                            const instruction_index = try unit.assembly_instructions.append(context.allocator, .{
                                .id = @intFromEnum(instruction),
                                .operands = operands.items,
                            });

                            instructions.appendAssumeCapacity(instruction_index);
                        }

                        const inline_assembly = try unit.inline_assembly.append(context.allocator, .{
                            .instructions = instructions.items,
                        });

                        const inline_asm = try unit.instructions.append(context.allocator, .{
                            .inline_assembly = inline_assembly,
                        });
                        try builder.appendInstruction(unit, context, inline_asm);

                        try unit.value_to_instruction_map.putNoClobber(context.allocator, value_index, inline_asm);

                        value.* = .{
                            .inline_assembly = inline_assembly,
                        };
                    },
                    .cast => {
                        assert(argument_node_list.len == 1);
                        const value_to_cast_index = try builder.resolveValueAllocate(unit, context, Type.Expect.none, argument_node_list[0]);

                        const cast_type = try builder.getCastType(unit, context, type_expect, value_to_cast_index);
                        switch (cast_type) {
                            .int_to_pointer => {
                                const intrinsic = try unit.intrinsics.append(context.allocator, .{
                                    .kind = .{
                                        .int_to_pointer = value_to_cast_index,
                                    },
                                    .type = type_expect.type,
                                });

                                const instruction = try unit.instructions.append(context.allocator, .{
                                    .cast = .{
                                        .id = .int_to_pointer,
                                        .value = value_to_cast_index,
                                        .type = type_expect.type,
                                    },
                                });

                                try builder.appendInstruction(unit, context, instruction);

                                value.* = .{
                                    .intrinsic = intrinsic,
                                };

                                try unit.value_to_instruction_map.putNoClobber(context.allocator, value_index, instruction);
                            },
                            .enum_to_int => {
                                const intrinsic = try unit.intrinsics.append(context.allocator, .{
                                        .kind = .{
                                            .enum_to_int = value_to_cast_index,
                                        },
                                        .type = type_expect.type,
                                    });

                                const instruction = try unit.instructions.append(context.allocator, .{
                                    .cast = .{
                                        .id = .enum_to_int,
                                        .value = value_to_cast_index,
                                        .type = type_expect.type,
                                    },
                                });

                                try builder.appendInstruction(unit, context, instruction);
                                try unit.value_to_instruction_map.putNoClobber(context.allocator, value_index, instruction);

                                value.* = .{
                                    .intrinsic = intrinsic,
                                };
                            },
                            .sign_extend => {
                                const intrinsic = try unit.intrinsics.append(context.allocator, .{
                                        .kind = .{
                                            .sign_extend = value_to_cast_index,
                                        },
                                        .type = type_expect.type,
                                    });

                                const instruction = try unit.instructions.append(context.allocator, .{
                                    .cast = .{
                                        .id = .sign_extend,
                                        .value = value_to_cast_index,
                                        .type = type_expect.type,
                                    },
                                });

                                try builder.appendInstruction(unit, context, instruction);
                                try unit.value_to_instruction_map.putNoClobber(context.allocator, value_index, instruction);

                                value.* = .{
                                    .intrinsic = intrinsic,
                                };
                            },
                            else => |t| @panic(@tagName(t)),
                        }
                    },
                    .size => {
                        assert(argument_node_list.len == 1);
                        const argument_type_index = unit.unwrapTypeCopy(try builder.resolveTypeAllocate(unit, context, argument_node_list[0]));
                        const argument_type = unit.types.get(argument_type_index);
                        const argument_size = argument_type.getByteSize(unit);

                        const integer = Value.Integer{
                            .value = argument_size,
                            .type = switch (type_expect) {
                                .none => .comptime_int,
                                .type => |type_index| b: {
                                    const ty = unit.types.get(type_index);
                                    break :b switch (ty.*) {
                                        .integer => type_index,
                                        else => |t| @panic(@tagName(t)),
                                    };
                                },
                            },
                        };

                        value.* = .{
                            .integer = integer,
                        };

                        const const_int = try unit.getConstantInt(context, integer);

                        try builder.appendInstruction(unit, context, const_int);
                        // We dont mind clobbering the value
                        try unit.value_to_instruction_map.put(context.allocator, value_index, const_int);
                    },
                    .syscall => {
                        if (argument_node_list.len > 0 and argument_node_list.len <= 6 + 1) {
                            var argument_list = try ArrayList(Value.Index).initCapacity(context.allocator, argument_node_list.len);
                            var instruction_list = try ArrayList(Instruction.Index).initCapacity(context.allocator, argument_node_list.len);
                            // TODO
                            const arg_type_expect = Type.Expect{
                                .type = Type.Index.usize,
                            };

                            for (argument_node_list) |argument_node_index| {
                                const argument_value_index = try builder.resolveValueAllocate(unit, context, arg_type_expect, argument_node_index);

                                const argument_value = unit.values.get(argument_value_index);
                                _ = argument_value; // autofix
                                const instruction_index = unit.value_to_instruction_map.get(argument_value_index).?;

                                argument_list.appendAssumeCapacity(argument_value_index);
                                instruction_list.appendAssumeCapacity(instruction_index);
                            }

                            const intrinsic = try unit.intrinsics.append(context.allocator, .{
                                .kind = .{
                                    .syscall = argument_list.items,
                                },
                                .type = Type.Index.usize,
                            });

                            const syscall = try unit.instructions.append(context.allocator, .{
                                .syscall = .{
                                    .arguments = instruction_list.items,
                                },
                            });

                            try builder.appendInstruction(unit, context, syscall);

                            try unit.value_to_instruction_map.putNoClobber(context.allocator, value_index, syscall);

                            value.* = .{
                                .intrinsic = intrinsic,
                            };
                        } else {
                            @panic("Syscall argument mismatch");
                        }
                    },
                    else => |t| @panic(@tagName(t)),
                }

                assert(value.* != .unresolved);
            },
            .if_else => {
                assert(node.left != .null);
                assert(node.right != .null);

                const if_result = try builder.resolveIf(unit, context, node.left);
                switch (if_result.condition) {
                    .false => {
                        value.* = .{
                            .unresolved = node.right,
                        };
                        try builder.resolveValue(unit, context, Type.Expect{
                            .type = .void,
                        }, value_index);
                    },
                    else => |t| @panic(@tagName(t)),
                }
            },
            .field_access => {
                const right_node = unit.getNode(node.right);
                assert(right_node.id == .identifier);
                const identifier = unit.getExpectedTokenBytes(right_node.token,.identifier);

                const lvi = try builder.resolveValueAllocate(unit, context, Type.Expect.none, node.left);
                const left_value_index = unit.unwrapValueCopy(lvi);
                const left_value = unit.values.get(left_value_index);

                switch (left_value.*) {
                    .type => |type_index| {
                        const left_type = unit.types.get(type_index);
                        const scope = left_type.getScope(unit);
                        const identifier_hash = try unit.processIdentifier(context, identifier);
                        const look_in_parent_scopes = false;

                        if (scope.lookupDeclaration(identifier_hash, look_in_parent_scopes)) |lookup| {
                            try builder.referenceDeclaration(unit,context, lookup.scope, identifier, // Argument inserted for debugging
                                lookup.declaration, value_index);
                            if (value.isComptime(unit)) {
                                //
                            } else {
                                unreachable;
                            }
                        } else {
                            switch (left_type.*) {
                                .@"enum" => |enum_index| {
                                    const enum_type = unit.enums.get(enum_index);
                                    const field_index = for (enum_type.fields.items) |enum_field_index| {
                                        const enum_field = unit.enum_fields.get(enum_field_index);
                                        if (enum_field.name == identifier_hash) {
                                            break enum_field_index;
                                        }
                                    } else @panic("identifier not found");
                                    value.* = .{
                                        .enum_field = field_index,
                                    };
                                },
                                else => |t| @panic(@tagName(t)),
                            }
                        }
                    },
                    else => |t| @panic(@tagName(t)),
                }
            },
            .keyword_false => unit.copyValue(value_index, Value.Index.bool_false),
            .keyword_true => unit.copyValue(value_index, Value.Index.bool_true),
            .function_definition => {
                const current_basic_block = builder.current_basic_block;
                defer builder.current_basic_block = current_basic_block;
                builder.current_basic_block = .null;
                const function_prototype_node_index = node.left;
                const body_node_index = node.right;

                const function_prototype_index = try builder.resolveFunctionPrototype(unit, context, function_prototype_node_index);
                const function_prototype_type_index = try unit.types.append(context.allocator, .{
                    .function = function_prototype_index,
                });
                const body_value_index = try unit.values.append(context.allocator, .{
                    .unresolved = body_node_index,
                });

                const old_function = builder.current_function;
                const token_debug_info = builder.getTokenDebugInfo(unit, node.token);
                builder.current_function = try unit.function_definitions.append(context.allocator, .{
                    .type = function_prototype_type_index,
                    .body = body_value_index,
                    .scope = Scope{
                        .line = token_debug_info.line,
                        .column = token_debug_info.column,
                        .kind = .function,
                        .local = true,
                        .level = builder.current_scope.level + 1,
                        .file = builder.current_file,
                    },
                    // This data assignment when the symbol is resolved in an upper step in the callstack
                    .symbol = undefined,
                });
                defer builder.current_function = old_function;

                const function = unit.function_definitions.get(builder.current_function);
                value.* = .{
                    .function_definition = builder.current_function,
                };

                builder.last_check_point = .{};

                try builder.pushScope(unit, context, &function.scope);
                defer builder.popScope(unit, context) catch unreachable;

                const entry_basic_block = try builder.newBasicBlock(unit, context);
                builder.current_basic_block = entry_basic_block;
                defer builder.current_basic_block = .null;

                // Get argument declarations into scope
                const function_prototype_node = unit.getNode(function_prototype_node_index);
                if (function_prototype_node.left != .null) {
                    const argument_node_list = unit.getNodeList(function_prototype_node.left);
                    const function_prototype = unit.function_prototypes.get(function_prototype_index);
                    const argument_types = function_prototype.argument_types;

                    for (argument_node_list, argument_types) |argument_node_index, argument_type_index| {
                        const argument_node = unit.getNode(argument_node_index);
                        assert(argument_node.id == .argument_declaration);

                        const argument_name = unit.getExpectedTokenBytes(argument_node.token, .identifier);
                        const argument_name_hash = try unit.processIdentifier(context, argument_name);

                        const look_in_parent_scopes = true;
                        if (builder.current_scope.lookupDeclaration(argument_name_hash, look_in_parent_scopes)) |_| {
                            std.debug.panic("Symbol with name '{s}' already declarared on scope", .{argument_name});
                        }

                        const argument_token_debug_info = builder.getTokenDebugInfo(unit, argument_node.token);
                        const argument_declaration_index = try unit.declarations.append(context.allocator, .{
                            .scope = builder.current_scope,
                            .name = argument_name_hash,
                            .type = argument_type_index,
                            .value = .null,
                            .mutability = .@"const",
                            .line = argument_token_debug_info.line,
                            .column = argument_token_debug_info.column,
                        });

                        try builder.current_scope.declarations.putNoClobber(context.allocator, argument_name_hash, argument_declaration_index);
                    }

                    for (builder.current_scope.declarations.values()) |declaration_index| {
                        const argument_declaration = unit.declarations.get(declaration_index);

                        const argument_instruction = try unit.instructions.append(context.allocator, .{
                            .argument_declaration = .{
                                .name = argument_declaration.name,
                                .type = argument_declaration.type,
                            },
                        });

                        try builder.appendInstruction(unit, context, argument_instruction);

                        try function.argument_map.putNoClobber(context.allocator, declaration_index, argument_instruction);
                    }
                }

                const body_node = unit.getNode(body_node_index);

                if (body_node.id == .block) {
                    try builder.resolveValue(unit, context, Type.Expect{ .type = .void }, body_value_index);

                    logln(.compilation, .ir, "Function #{}", .{Function.Definition.unwrap(builder.current_function)});

                    for (function.basic_blocks.items) |basic_block_index| {
                        const basic_block = unit.basic_blocks.get(basic_block_index);
                        logln(.compilation, .ir, "[#{}]:", .{BasicBlock.unwrap(basic_block_index)});

                        for (basic_block.instructions.items) |instruction_index| {
                            const instruction = unit.instructions.get(instruction_index);
                            log(.compilation, .ir, "    %{}: {s} ", .{Instruction.unwrap(instruction_index), @tagName(instruction.*)});

                            switch (instruction.*) {
                                .debug_checkpoint => |checkpoint| {
                                    log(.compilation, .ir, "{}, {}", .{checkpoint.line, checkpoint.column});
                                },
                                .argument_declaration => |arg|{
                                    log(.compilation, .ir, "\"{s}\"", .{unit.getIdentifier(arg.name)});
                                },
                                .cast => |cast| {
                                    log(.compilation, .ir, "{s}", .{@tagName(cast.id)});
                                },
                                // .binary_operation => |binary_operation| {
                                //     log(.compilation, .ir, "{s}", .{@tagName(binary_operation.id)});
                                // },
                                else => {}
                            }
                            logln(.compilation, .ir, "",  .{});
                        }
                    }
                } else {
                    @panic("Function body is expected to be a block");
                }
            },
            .constant_symbol_declaration,
            .variable_symbol_declaration, => {
                // All variables here are local
                assert(builder.current_scope.local);
                const expected_identifier_token_index = Token.addInt(node.token, 1);
                const identifier = unit.getExpectedTokenBytes(expected_identifier_token_index, .identifier);
                logln(.compilation, .identifier, "Analyzing local declaration {s}", .{identifier});
                const identifier_hash = try unit.processIdentifier(context, identifier);

                const look_in_parent_scopes = true;
                if (builder.current_scope.lookupDeclaration(identifier_hash, look_in_parent_scopes)) |lookup| {
                    _ = lookup; // autofix
                    std.debug.panic("Identifier '{s}' already declarared on scope", .{identifier});
                }

                const type_node_index = node.left;
                const value_node_index = node.right;
                assert(value_node_index != .null);
                const init_value_index = try unit.values.append(context.allocator, .{
                    .unresolved = value_node_index,
                });

                const declaration_type_index: Type.Index = switch (type_node_index) {
                    .null => blk: {
                        try builder.resolveValue(unit, context, Type.Expect.none, init_value_index);
                        const init_value = unit.values.get(init_value_index);
                        const init_type_index = init_value.getType(unit);
                        break :blk init_type_index;
                    },
                    else => blk: {
                        const type_index = try builder.resolveTypeAllocate(unit, context, type_node_index);
                        try builder.resolveValue(unit, context, Type.Expect{
                            .type = type_index,
                        }, init_value_index);
                        break :blk type_index;
                    },
                };

                const token_debug_info = builder.getTokenDebugInfo(unit, node.token);

                const mutability: Mutability = switch (node.id) {
                    .constant_symbol_declaration => .@"const",
                    .variable_symbol_declaration => .@"var",
                    else => unreachable,
                };

                const declaration_index = try unit.declarations.append(context.allocator, .{
                    .scope = builder.current_scope,
                    .name = identifier_hash,
                    .type = declaration_type_index,
                    .value = init_value_index,
                    .mutability = mutability,
                    .line = token_debug_info.line,
                    .column = token_debug_info.column,
                });

                try builder.current_scope.declarations.putNoClobber(context.allocator, identifier_hash, declaration_index);

                if (!(mutability == .@"const" and unit.values.get(init_value_index).isComptime(unit))) {
                    const instruction = try unit.instructions.append(context.allocator, .{
                        .stack_slot = .{
                            .type = unit.unwrapTypeCopy(declaration_type_index),
                        },
                    });
                    try builder.appendInstruction(unit, context, instruction);

                    const current_function = unit.function_definitions.get(builder.current_function);
                    try current_function.declarations.putNoClobber(context.allocator, declaration_index, instruction);

                    const init_value = unit.values.get(init_value_index);
                    switch (init_value.*) {
                        .intrinsic => |intrinsic_index| {
                            const intrinsic = unit.intrinsics.get(intrinsic_index);
                            _ = intrinsic; // autofix
                            // @breakpoint();
                        },
                        else => {},
                    }
                    const init_value_instruction = unit.value_to_instruction_map.get(init_value_index).?;

                    // TODO: store initial value
                    const initialization = try unit.instructions.append(context.allocator, .{
                        .store = .{
                            .destination = instruction,
                            .source = init_value_instruction,
                        },
                    });
                    try builder.appendInstruction(unit, context, initialization);
                }

                value.* = .{
                    .declaration = declaration_index,
                };
            },
            .pointer_dereference => {
                // TODO: 
                const pointer_type_expect = switch (type_expect) {
                    .none => unreachable,//type_expect,
                    .type => |type_index| b: {
                        const pointer_type = try unit.types.append(context.allocator, .{
                            .unresolved = undefined,
                        });
                        try unit.getPointerType(context, .{
                            .type = type_index,
                            .mutability = .@"const",
                            .many = false, // TODO
                            .termination = .none, // TODO
                            .nullable = false,
                        }, pointer_type);
                        const result = Type.Expect{
                            .type = pointer_type,
                        };
                        break :b result;
                    }, 
                };
                const pointer_value_index = try builder.resolveValueAllocate(unit, context, pointer_type_expect, node.left);

                const load = try unit.instructions.append(context.allocator, .{
                    .load = .{
                        .value = pointer_value_index,
                    },
                });
                try builder.appendInstruction(unit, context, load);

                const unary_operation = try unit.unary_operations.append(context.allocator, .{
                    .value = pointer_value_index,
                    .type = switch (type_expect) {
                        .none => unreachable,
                        .type => |type_index| type_index,
                    },
                    .id = .pointer_dereference,
                });

                value.* = .{
                    .unary_operation = unary_operation,
                };

                try unit.value_to_instruction_map.putNoClobber(context.allocator, value_index, load);
            },
            .number_literal => switch (std.zig.parseNumberLiteral(unit.getExpectedTokenBytes(node.token, .number_literal))) {
                .int => |integer| {
                    const type_index = switch (type_expect) {
                        .type => |original_type_index| b: {
                            const type_index = unit.unwrapTypeCopy(original_type_index);
                            const ty = unit.types.get(type_index);
                            break :b switch (ty.*) {
                                .integer => type_index,
                                else => |t| @panic(@tagName(t)),
                            };
                        },
                        .none => Type.Index.comptime_int,
                        //else => |t| @panic(@tagName(t)),
                    };

                    const integer_value = Value.Integer{
                        .value = integer,
                        .type = type_index,
                    };
                    
                    const const_int = try unit.getConstantInt(context, integer_value);

                    if (builder.current_basic_block != .null) {
                        try builder.appendInstruction(unit, context, const_int);
                    }

                    value.* = .{
                        .integer = integer_value,
                    };

                    try unit.value_to_instruction_map.putNoClobber(context.allocator, value_index, const_int);
                },
                else => |t| @panic(@tagName(t)),
            },
            .undefined => {
                value.* = .undefined;
            },
            .add, .mul => {
                const binary_operation_id: BinaryOperation.Id = switch (node.id) {
                    .add => .add,
                    .sub => .sub,
                    .bit_and => .bit_and,
                    .bit_xor => .bit_xor,
                    .bit_or => .bit_or,
                    .mul => .mul,
                    .div => .div,
                    .mod => .mod,
                    .shift_left => .shift_left,
                    .shift_right => .shift_right,
                    .compare_equal => .compare_equal,
                    .compare_not_equal => .compare_not_equal,
                    .compare_greater => .compare_greater,
                    .compare_greater_equal => .compare_greater_equal,
                    .compare_less => .compare_less,
                    .compare_less_equal => .compare_less_equal,
                    else => |t| @panic(@tagName(t)),
                };
                const left_expect_type: Type.Expect = switch (binary_operation_id) {
                    .compare_equal,
                    .compare_not_equal,
                    .compare_less,
                    .compare_less_equal,
                    .compare_greater,
                    .compare_greater_equal,
                    => Type.Expect.none,
                    else => type_expect,
                };
                const left_value_index = try builder.resolveValueAllocate(unit, context, left_expect_type, node.left);
                const left_value = unit.values.get(left_value_index);
                const left_instruction = unit.value_to_instruction_map.get(left_value_index).?;
                const left_type = left_value.getType(unit);
                                         
                const right_expect_type: Type.Expect = switch (type_expect) {
                    .none => Type.Expect{
                        .type = left_type,
                    },
                    .type => switch (binary_operation_id) {
                        .add,
                        .sub,
                        .bit_and,
                        .bit_xor,
                        .bit_or,
                        .mul,
                        .div,
                        .mod,
                        .shift_left,
                        .shift_right,
                        => type_expect,
                        // .shift_left,
                        // .shift_right,
                        // => ExpectType{
                        //     .type_index = Type.u8,
                        // },
                        .compare_equal,
                        .compare_not_equal,
                        .compare_less,
                        .compare_greater,
                        .compare_greater_equal,
                        .compare_less_equal,
                        => Type.Expect{
                            .type = left_type,
                        },
                    },
                    // else => |t| @panic(@tagName(t)),
                };
                const right_value_index = try builder.resolveValueAllocate(unit, context, right_expect_type, node.right);
                const right_instruction = unit.value_to_instruction_map.get(right_value_index).?;

                const binary_operation = BinaryOperation{
                    .left = left_value_index,
                    .right = right_value_index,
                    .type = switch (type_expect) {
                        .none => switch (binary_operation_id) {
                            .bit_and,
                            .bit_or,
                            .shift_right,
                            .add,
                            .sub,
                            .mul,
                            .div,
                            .mod,
                            => left_type,
                            else => |t| @panic(@tagName(t)),
                        },
                        .type => |type_index| type_index,
                        // else => |t| @panic(@tagName(t)),
                    },
                    .id = binary_operation_id,
                };
                const binary_operation_index = try unit.binary_operations.append(context.allocator, binary_operation);

                {
                    const instruction = switch (unit.types.get(left_type).*) {
                        .integer => |integer| b: {
                            const id: Instruction.IntegerBinaryOperation.Id = switch (binary_operation_id) {
                                .add => .add,
                                .mul => .mul,
                                else => |t| @panic(@tagName(t)),
                            };

                            const i = try unit.instructions.append(context.allocator, .{
                                .integer_binary_operation = .{
                                    .left = left_instruction,
                                    .right = right_instruction,
                                    .id = id,
                                    .signedness = integer.signedness,
                                },
                            });
                            break :b i;
                        },
                        else => |t| @panic(@tagName(t)),
                    };

                    try builder.appendInstruction(unit, context, instruction);
                    try unit.value_to_instruction_map.putNoClobber(context.allocator, value_index, instruction);
                }
                
                value.* = .{
                    .binary_operation = binary_operation_index,
                };
            },
            .call => {
                assert(node.left != .null);
                assert(node.right != .null);
                const left_node = unit.getNode(node.left);
                const is_field_access = switch (left_node.id) {
                    .field_access => true,
                    else => false,
                };
                _ = is_field_access; // autofix
                const left_value_index = unit.unwrapValueCopy( try builder.resolveValueAllocate(unit, context, Type.Expect.none, node.left));
                const left_value = unit.values.get(left_value_index);

                switch (left_value.*) {
                    .function_definition => |function_definition_index| {
                        const function = unit.function_definitions.get(function_definition_index);
                        const function_type = unit.types.get( function.type);
                        const function_prototype = unit.function_prototypes.get(function_type.function);
                        const argument_nodes = unit.getNodeList(node.right);
                        const argument_declaration_count = function.scope.declarations.count();

                        if (argument_nodes.len != argument_declaration_count) {
                            @panic("Argument count mismatch");
                        }

                        var list = try ArrayList(Value.Index).initCapacity(context.allocator, argument_declaration_count);
                        var instruction_list = try ArrayList(Instruction.Index).initCapacity(context.allocator, argument_declaration_count);

                        for (argument_nodes, function.scope.declarations.values()) |arg_ni, argument_declaration_index| {
                            const argument_node = unit.getNode(arg_ni);
                            const argument_declaration = unit.declarations.get(argument_declaration_index);
                            const arg_type_expect = Type.Expect{
                                .type = argument_declaration.type,
                            };
                            const argument_node_index = switch (argument_node.id) {
                                .named_argument => argument_node.right,
                                else => arg_ni,
                            };
                            const argument_value_index = try builder.resolveValueAllocate(unit, context, arg_type_expect, argument_node_index);
                            list.appendAssumeCapacity(argument_value_index);
                            instruction_list.appendAssumeCapacity(unit.value_to_instruction_map.get(argument_value_index).?);
                        }

                        const call = Call{
                            .value = left_value_index,
                            .arguments = list.items,
                            .type = switch (type_expect) {
                                .none => function_prototype.return_type,
                                .type => |type_index| b: {
                                    const rt_index = unit.unwrapTypeCopy( function_prototype.return_type);
                                    const rt = unit.types.get(rt_index);
                                    _ = rt; // autofix
                                    if (rt_index != .noreturn) {
                                        assert(type_index == rt_index);
                                    }
                                    break :b rt_index;
                                },
                                // else => |t| @panic(@tagName(t)),
                            },
                        };

                        const instruction = try unit.instructions.append(context.allocator, .{
                            .call = .{
                                .callable = .{
                                    .function_definition = function_definition_index,
                                },
                                .function_type = function.type,
                                .arguments = instruction_list.items,
                            },
                        });
                        try builder.appendInstruction(unit, context, instruction);
                        
                        try unit.value_to_instruction_map.putNoClobber(context.allocator, value_index, instruction);

                        // TODO: type check return type
                        const call_index = try unit.calls.append(context.allocator, call);

                        value.* = .{
                            .call = call_index,
                        };
                    },
                    else => |t| @panic(@tagName(t)),
                }
            },
            .@"return" => {
                assert(node.left != .null);
                assert(node.right == .null);
                const return_value_node_index = node.left;
                const return_value_index = try builder.resolveValueAllocate(unit, context, Type.Expect{
                    .type = unit.getReturnType(builder.current_function),
                },return_value_node_index);
                const instruction_index = unit.value_to_instruction_map.get(return_value_index).?;
                const return_index = try unit.returns.append(context.allocator,.{
                    .value = return_value_index,
                });
                value.* = .{
                    .@"return" = return_index,
                };

                const ret = try unit.instructions.append(context.allocator, .{
                    .ret = instruction_index,
                });
                try builder.appendInstruction(unit, context, ret);
            },
            .@"switch" => {
                const switch_expression_value_index = try builder.resolveValueAllocate(unit, context, Type.Expect.none, node.left);
                const case_nodes = unit.getNodeList(node.right);

                const comptime_switch_expression = unit.evaluateAtComptime(switch_expression_value_index);
                if (comptime_switch_expression != .null) {
                    const switch_expression = unit.values.get(comptime_switch_expression);
                    switch (switch_expression.*) {
                        .enum_field => |enum_field_index| {
                            const enum_field = unit.enum_fields.get(enum_field_index);
                            const enum_type_general = unit.types.get(enum_field.parent);
                            const enum_type = unit.enums.get(enum_type_general.@"enum");
                            const typecheck_enum_result = try unit.typecheckSwitchEnums(context, enum_type.*, case_nodes);

                            const group_index = for (typecheck_enum_result.switch_case_groups.items, 0..) |switch_case_group, switch_case_group_index| {
                                break for (switch_case_group.items) |field_index| {
                                    if (enum_field_index == field_index) {
                                        break switch_case_group_index;
                                    }
                                } else {
                                    continue;
                                };
                            } else typecheck_enum_result.else_switch_case_group_index orelse unreachable;
                            const true_switch_case_node = unit.getNode(case_nodes[group_index]);
                            value.* = .{
                                .unresolved = true_switch_case_node.right,
                            };
                            try builder.resolveValue(unit, context, type_expect, value_index);
                        },
                        else => |t| @panic(@tagName(t)),
                    }
                } else {
                    unreachable;
                }
            },
            .enum_type => {
                const node_list = unit.getNodeList(node.left);

                const type_index = try unit.types.append(context.allocator,.{
                    .unresolved = node_index,
                });
                value.* = .{
                    .type = type_index,
                };

                try builder.resolveContainerType(unit, context, node_list, node_index, .@"enum", type_index);
            },
            .@"unreachable" => {
                unit.copyValue(value_index, .@"unreachable");
                const instruction = try unit.instructions.append(context.allocator, .@"unreachable");
                try builder.appendInstruction(unit, context, instruction);
            },
            else => |t| @panic(@tagName(t)),
        }

        assert(value.* != .unresolved);
    }

    fn newBasicBlock(builder: *Builder, unit: *Unit, context: *const Context) !BasicBlock.Index{
        const function = unit.function_definitions.get(builder.current_function);
        const entry_basic_block = try unit.basic_blocks.append(context.allocator, .{});
        try function.basic_blocks.append(context.allocator, entry_basic_block);

        return entry_basic_block;
    }

    fn resolveTypeAllocate(builder: *Builder, unit: *Unit, context: *const Context, node_index: Node.Index) !Type.Index {
        const type_index = try unit.types.append(context.allocator, .{
            .unresolved = node_index,
        });
        try builder.resolveType(unit, context, type_index);
        return type_index;
    }

    fn resolveType(builder: *Builder, unit: *Unit, context: *const Context, type_index: Type.Index) anyerror!void {
        const ty = unit.types.get(type_index);
        const node_index = switch (ty.*) {
            .unresolved => |ni| ni,
            else => |t| @panic(@tagName(t)),
        };
        const node = unit.getNode(node_index);

        switch (node.id) {
            .signed_integer_type, .unsigned_integer_type, => {
                const token_bytes = unit.getExpectedTokenBytes(node.token, switch (node.id) {
                    .signed_integer_type => .keyword_signed_integer,
                    .unsigned_integer_type => .keyword_unsigned_integer,
                    else => unreachable,
                });

                const number_chunk = token_bytes[1..];
                                       //
                try unit.getIntegerType(context, .{
                    .bit_count = try std.fmt.parseInt(u16, number_chunk, 10),
                    .signedness = switch (node.id) {
                        .signed_integer_type => .signed,
                        .unsigned_integer_type => .unsigned,
                        else => unreachable,
                    },
                }, type_index);
            },
            .pointer_type => {
                const attribute_node_list = unit.getNodeList(node.left);
                var mutability = Mutability.@"var";
                var element_type_index = Type.Index.null;
                var termination = Type.Termination.none;
                var many = false;

                for (attribute_node_list) |element_node_index| {
                    const element_node = unit.getNode(element_node_index);
                    switch (element_node.id) {
                        .function_prototype,
                        .identifier,
                        .unsigned_integer_type,
                        .signed_integer_type,
                        .optional_type,
                        .array_type,
                        .usize_type,
                        .pointer_type,
                        => {
                            if (element_type_index != .null) {
                                unreachable;
                            }

                            element_type_index = try builder.resolveTypeAllocate(unit, context, element_node_index);
                        },
                        .const_expression => mutability = .@"const",
                        .many_pointer_expression => many = true,
                        .zero_terminated => {
                            assert(many);
                            assert(termination == .none);
                            termination = .zero;
                        },
                        .null_terminated => {
                            assert(many);
                            assert(termination == .none);
                            termination = .null;
                        },
                        else => |t| @panic(@tagName(t)),
                    }
                }

                assert(element_type_index != .null);

                try unit.getPointerType(context, .{
                    .mutability = mutability,
                    .many = many,
                    .type = element_type_index,
                    .termination = termination,
                    .nullable = false,
                }, type_index);
            },
            .optional_type => {
                const element_type_index = try builder.resolveTypeAllocate(unit, context, node.left);
                const element_type = unit.types.get(element_type_index);
                switch (element_type.*) {
                    .pointer => |pointer| {
                        var nullable_pointer = pointer;
                        assert(!nullable_pointer.nullable);
                        nullable_pointer.nullable = true;
                        try unit.getPointerType(context, nullable_pointer, type_index);
                    },
                    else => unreachable,
                }
            },
            .keyword_noreturn => unit.copyType(type_index, Type.Index.noreturn),
            .usize_type => unit.copyType(type_index, Type.Index.usize),
            else => |t| @panic(@tagName(t)),
        }

        assert(unit.types.get(type_index).* != .unresolved);
    }

    fn resolveFunctionPrototype(builder: *Builder, unit: *Unit, context: *const Context, node_index: Node.Index) !Function.Prototype.Index {
        const node = unit.getNode(node_index);
        assert(node.id == .function_prototype);
        const attribute_and_return_type_node_list = unit.getNodeList(node.right);
        assert(attribute_and_return_type_node_list.len >= 1);
        const attribute_node_list = attribute_and_return_type_node_list[0..attribute_and_return_type_node_list.len - 1];
        const return_type_node_index = attribute_and_return_type_node_list[attribute_and_return_type_node_list.len - 1];

        const function_prototype_index = try unit.function_prototypes.append(context.allocator, .{
            .argument_types = &.{},
            .return_type = .null,
            .attributes = .{
                .@"export" = false,
                .naked = false,
            },
        });


        var is_export: bool = false;
        var is_naked: bool = false;

        // Resolve attributes
        for (attribute_node_list) |attribute_node_index| {
            const attribute_node = unit.getNode(attribute_node_index);
            switch (attribute_node.id) {
                .attribute_export => is_export = true,
                .attribute_naked => is_naked = true,
                else => |t| @panic(@tagName(t)),
            }
        }

        const function_prototype = unit.function_prototypes.get(function_prototype_index);

        if (node.left != .null) {
            const argument_node_list = unit.getNodeList(node.left);
            var argument_types = try ArrayList(Type.Index).initCapacity(context.allocator, argument_node_list.len);

            for (argument_node_list) |argument_node_index| {
                const argument_node = unit.getNode(argument_node_index);
                assert(argument_node.id == .argument_declaration);

                const argument_type_index = try builder.resolveTypeAllocate(unit, context, argument_node.left);
                assert(unit.types.get(argument_type_index).* != .unresolved);
                argument_types.appendAssumeCapacity(argument_type_index);
            }

            function_prototype.argument_types = argument_types.items;
        }

        function_prototype.attributes = .{
            .@"export" = is_export,
            .naked = is_naked,
        };

        function_prototype.return_type = try builder.resolveTypeAllocate(unit, context, return_type_node_index);

        return function_prototype_index;
    }

    fn resolveContainerType(builder: *Builder, unit: *Unit, context: *const Context, container_nodes: []const Node.Index, container_node_index: Node.Index, container_type: ContainerType, type_index: Type.Index) !void {
        const current_basic_block = builder.current_basic_block;
        defer builder.current_basic_block = current_basic_block;
        builder.current_basic_block = .null;

        const container_node = unit.getNode(container_node_index);

        const Data = struct{
            scope: *Scope,
            type: Type.Index,
        };

        const backing_type: Type.Index = switch (container_node.right) {
            .null => .null,
            else => |backing_type_node_index| b: {
                switch (builder.current_scope.kind) {
                    .file => unreachable,
                    else => {
                        const backing_type_index = try builder.resolveTypeAllocate(unit, context, backing_type_node_index);
                        const backing_type = unit.types.get(unit.unwrapTypeCopy(backing_type_index));
                        switch (backing_type.*) {
                            .integer => |integer| {
                                switch (integer.bit_count) {
                                    8, 16, 32, 64 => {},
                                    else => @panic("Invalid integer backing type bit count"),
                                }
                            },
                            else => |t| @panic(@tagName(t)),
                        }

                        break :b backing_type_index;
                    },
                }
            },
            // if (true) unreachable;
            // break :blk switch (container_type) {
            //     else => |t| @panic(@tagName(t)),
            // };
        };

        const token_debug_info = builder.getTokenDebugInfo(unit, container_node.token);
        const data: Data = switch (container_type) {
            .@"struct" => b: {
                assert(container_node.id == .struct_type);
                const struct_index = try unit.structs.append(context.allocator, .{
                    .scope = .{
                        .kind = switch (builder.current_scope.kind) {
                            .file => .file_container,
                            else => .container,
                        },
                        .line = token_debug_info.line,
                        .column = token_debug_info.column,
                        .level = builder.current_scope.level + 1,
                        .local = false,
                        .file = builder.current_file,
                    },
                    .backing_type = backing_type,
                });
                const struct_type = unit.structs.get(struct_index);

                const ty = unit.types.get(type_index);
                ty.* = .{
                    .@"struct" = struct_index,
                };

                try unit.struct_type_map.putNoClobber(context.allocator, struct_index, type_index);

                break :b .{
                    .scope = &struct_type.scope,
                    .type = type_index,
                };
            },
            .@"enum" => b: {
                assert(container_node.id == .enum_type);
                const enum_index = try unit.enums.append(context.allocator, .{
                    .scope = .{
                        .kind = .container,
                        .line = token_debug_info.line,
                        .column = token_debug_info.column,
                        .level = builder.current_scope.level + 1,
                        .local = false,
                        .file = builder.current_file,
                    },
                    .backing_type = backing_type,
                });

                const enum_type = unit.enums.get(enum_index);
                const ty = unit.types.get(type_index);
                ty.* = .{
                    .@"enum" = enum_index,
                };
                break :b .{
                    .scope = &enum_type.scope,
                    .type = type_index,
                };
            },
        };

        const scope = data.scope;
        try builder.pushScope(unit, context, scope);
        defer builder.popScope(unit, context) catch unreachable;

        const count = blk: {
            var result: struct {
                fields: u32 = 0,
                declarations: u32 = 0,
                comptime_blocks: u32 = 0,
            } = .{};

            for (container_nodes) |member_index| {
                const member = unit.getNode(member_index);
                switch (container_type) {
                    .@"struct" => assert(member.id != .enum_field),
                    .@"enum" => assert(member.id != .container_field),
                }
                // const token_offset = file.lexer.token_offsets.items[Token.unwrap(member.token)];
                // const slice = file.source_code[token_offset..@min(token_offset + 100, file.source_code.len)];
                // std.debug.print("Member: `{s}`\n", .{slice});
                const member_type = getContainerMemberType(member.id);

                switch (member_type) {
                    .declaration => result.declarations += 1,
                    .field => result.fields += 1,
                    .comptime_block => result.comptime_blocks += 1,
                }
            }

            break :blk result;
        };

        var declaration_nodes = try ArrayList(Node.Index).initCapacity(context.allocator, count.declarations);
        var field_nodes = try ArrayList(Node.Index).initCapacity(context.allocator, count.fields);
        var comptime_block_nodes = try ArrayList(Node.Index).initCapacity(context.allocator, count.comptime_blocks);

        for (container_nodes) |member_index| {
            const member_node = unit.getNode(member_index);
            const member_type = getContainerMemberType(member_node.id);
            const array_list = switch (member_type) {
                .comptime_block => &comptime_block_nodes,
                .declaration => &declaration_nodes,
                .field => &field_nodes,
            };
            array_list.appendAssumeCapacity(member_index);
        }

        if (count.declarations > 0) {
            for (declaration_nodes.items) |declaration_node_index| {
                const declaration_node = unit.getNode(declaration_node_index);

                switch (declaration_node.id) {
                    .constant_symbol_declaration,
                    .variable_symbol_declaration,
                    => {
                        const expected_identifier_token_index = Token.addInt(declaration_node.token, 1);
                        const identifier = unit.getExpectedTokenBytes(expected_identifier_token_index, .identifier);
                        logln(.compilation, .identifier, "Analyzing global declaration {s}", .{identifier});
                        const identifier_hash = try unit.processIdentifier(context, identifier);

                        const look_in_parent_scopes = true;
                        if (builder.current_scope.lookupDeclaration(identifier_hash, look_in_parent_scopes)) |lookup_result| {
                            _ = lookup_result; // autofix
                            std.debug.panic("Symbol {s} already on scope", .{identifier});
                        }

                        assert(declaration_node.right != .null);
                        const type_node_index = declaration_node.left;
                        const value_node_index = declaration_node.right;
                        const unresolved_initial_value = try unit.values.append(context.allocator, .{
                            .unresolved = value_node_index,
                        });

                        const declaration_type_index: Type.Index = switch (type_node_index) {
                            .null => .null,
                            else => try unit.types.append(context.allocator, .{
                                .unresolved = type_node_index,
                            }),
                        };

                        const declaration_token_debug_info = builder.getTokenDebugInfo(unit, declaration_node.token);

                        const declaration = try unit.declarations.append(context.allocator, .{
                            .scope = builder.current_scope,
                            .name = identifier_hash,
                            .type = declaration_type_index,
                            .value = unresolved_initial_value,
                            .mutability = switch (declaration_node.id) {
                                .constant_symbol_declaration => .@"const",
                                .variable_symbol_declaration => .@"var",
                                else => unreachable,
                            },
                            .line = declaration_token_debug_info.line,
                            .column = declaration_token_debug_info.column,
                        });

                        try builder.current_scope.declarations.putNoClobber(context.allocator, identifier_hash, declaration);
                    },
                    else => unreachable,
                }
            }
        }

        if (count.fields > 0) {
            switch (container_type) {
                .@"enum" => {
                    const ty = unit.types.get(type_index);
                    const enum_type = unit.enums.get(ty.@"enum");
                    const field_count = field_nodes.items.len;
                    try enum_type.fields.ensureTotalCapacity(context.allocator, field_count);

                    if (enum_type.backing_type == .null) {
                        const bit_count = @bitSizeOf(@TypeOf(field_nodes.items.len)) - @clz(field_nodes.items.len);
                        const real_bit_count: u16 = if (bit_count <= 8) 8 else if (bit_count <= 16) 16 else if (bit_count <= 32) 32 else if (bit_count <= 64) 64 else unreachable;
                        const backing_type_index = try unit.types.append(context.allocator, .{
                            .unresolved = undefined,
                        });

                        try unit.getIntegerType(context, .{
                            .bit_count = real_bit_count,
                            .signedness = .unsigned,
                        }, backing_type_index);

                        enum_type.backing_type = backing_type_index;
                    }
                },
                else => |t| @panic(@tagName(t)),
            }

            //    // TODO: bit-sized integers
            //    const expect_type = ExpectType{
            //        .type_index = switch (backing_type.invalid) {
            //            true => blk: {
            //                break :blk type_index;
            //            },
            //            false => backing_type,
            //        },
            //    };

            for (field_nodes.items, 0..) |field_node_index, index| {
                const field_node = unit.getNode(field_node_index);
                switch (container_type) {
                    .@"enum" => {
                        assert(field_node.id == .@"enum_field");
                        const ty = unit.types.get(type_index);
                        const enum_type = unit.enums.get(ty.@"enum");

                        const identifier = unit.getExpectedTokenBytes(field_node.token, .identifier);
                        const hash = try unit.processIdentifier(context, identifier);

                        const enum_value: usize = switch (field_node.left) {
                            .null => index,
                            else => b: {
                                const enum_value_index = try builder.resolveValueAllocate(unit, context, Type.Expect.none, field_node.left);
                                const comptime_enum_value_index = unit.evaluateAtComptime(enum_value_index);
                                if (comptime_enum_value_index == .null) @panic("Enum value must be known at compile time");
                                const enum_value = unit.values.get(comptime_enum_value_index);

                                break :b switch (enum_value.*) {
                                    .integer => |integer| integer.value,
                                    else => |t| @panic(@tagName(t)),
                                };
                            },
                        };
                       const enum_field_index = try unit.enum_fields.append(context.allocator, .{
                           .name = hash,
                           .value = enum_value,
                           .parent = type_index,
                       });
                       enum_type.fields.appendAssumeCapacity(enum_field_index);
                    },
                    else => |t| @panic(@tagName(t)),
                }
            }
        }

        if (count.comptime_blocks > 0) {
            const emit_ir = builder.emit_ir;
            builder.emit_ir = false;
            defer builder.emit_ir = emit_ir;

            for (comptime_block_nodes.items) |comptime_node_index| {
                const comptime_node = unit.getNode(comptime_node_index);
                assert(comptime_node.id == .@"comptime");

                const comptime_block_value = try unit.values.append(context.allocator, .{
                    .unresolved = comptime_node.left,
                });
                try builder.resolveValue(unit, context, Type.Expect{
                    .type = .void,
                }, comptime_block_value);
            }
        }
    }
};

pub const Enum = struct {
    scope: Scope,
    fields: ArrayList(Enum.Field.Index) = .{},
    backing_type: Type.Index,

    pub const Field = struct {
        value: usize,
        name: u32,
        parent: Type.Index,

        pub const List = BlockList(@This(), enum{});
        pub usingnamespace @This().List.Index;
    };

    pub const List = BlockList(@This(), enum{});
    pub usingnamespace @This().List.Index;
};

pub const Unit = struct {
    node_buffer: Node.List = .{},
    files: File.List = .{},
    values: Value.List = .{},
    types: Type.List = .{},
    structs: Struct.List = .{},
    enums: Enum.List = .{},
    enum_fields: Enum.Field.List = .{},
    function_definitions: Function.Definition.List = .{},
    blocks: Block.List = .{},
    declarations: Declaration.List = .{},
    assembly_instructions: InlineAssembly.Instruction.List = .{},
    function_prototypes: Function.Prototype.List = .{},
    intrinsics: Intrinsic.List = .{},
    unary_operations: UnaryOperation.List = .{},
    binary_operations: BinaryOperation.List = .{},
    assignments: Assignment.List = .{},
    returns: Return.List = .{},
    calls: Call.List = .{},
    inline_assembly: InlineAssembly.List = .{},
    instructions: Instruction.List = .{},
    basic_blocks: BasicBlock.List = .{},
    global_variables: GlobalVariable.List = .{},
    global_variable_map: AutoHashMap(Declaration.Index, GlobalVariable.Index) = .{},
    token_buffer: Token.Buffer = .{},
    node_lists: ArrayList(ArrayList(Node.Index)) = .{},
    file_token_offsets: AutoArrayHashMap(Token.Range, File.Index) = .{},
    file_map: StringArrayHashMap(File.Index) = .{},
    identifiers: StringKeyMap([]const u8) = .{},
    pointers: AutoHashMap(Type.Pointer, Type.Index) = .{},
    function_declaration_map: AutoHashMap(Function.Definition.Index, Declaration.Index) = .{},
    type_declaration_map: AutoHashMap(Type.Index, Declaration.Index) = .{},
    // TODO
    value_to_instruction_map: AutoHashMap(Value.Index, Instruction.Index) = .{},
    constant_int_map: AutoHashMap(Value.Integer, Instruction.Index) = .{},
    struct_type_map: AutoHashMap(Struct.Index, Type.Index) = .{},
    scope: Scope = .{
        .file = .null,
        .kind = .compilation_unit,
        .line = 0,
        .column = 0,
        .level = 0,
        .local = false,
    },
    main_package: *Package = undefined,
    descriptor: Descriptor,

    fn getReturnType(unit: *Unit, function_index: Function.Definition.Index) Type.Index{
        const function = unit.function_definitions.get(function_index);
        const function_type = unit.types.get(function.type);
        const function_prototype = unit.function_prototypes.get(function_type.function);
        return function_prototype.return_type;
    }

    fn typecheckSwitchEnums(unit: *Unit, context: *const Context, enum_type: Enum, switch_case_node_list: []const Node.Index) !TypeCheckSwitchEnums {
        var result = TypeCheckSwitchEnums{
            .switch_case_groups = try ArrayList(ArrayList(Enum.Field.Index)).initCapacity(context.allocator, switch_case_node_list.len),
        };

        var existing_enums = ArrayList(Enum.Field.Index){};

        for (switch_case_node_list, 0..) |switch_case_node_index, index| {
            const switch_case_node = unit.getNode(switch_case_node_index);

            switch (switch_case_node.left) {
                else => {
                    const switch_case_condition_node = unit.getNode(switch_case_node.left);
                    var switch_case_group = ArrayList(Enum.Field.Index){};

                    switch (switch_case_condition_node.id) {
                        .enum_literal => {
                            if (try unit.typeCheckEnumLiteral(context, Token.addInt(switch_case_condition_node.token, 1), enum_type)) |enum_field_index| {
                                for (existing_enums.items) |existing| {
                                    if (enum_field_index == existing) {
                                        // Duplicate case
                                        unreachable;
                                    }
                                }

                                try switch_case_group.append(context.allocator, enum_field_index);
                                try existing_enums.append(context.allocator, enum_field_index);
                            } else {
                                unreachable;
                            }
                        },
                        .node_list => {
                            const node_list = unit.getNodeListFromNode(switch_case_condition_node);
                            try switch_case_group.ensureTotalCapacity(context.allocator, node_list.len);

                            for (node_list) |case_condition_node_index| {
                                const case_condition_node = unit.getNode(case_condition_node_index);
                                switch (case_condition_node.id) {
                                    .enum_literal => {
                                        if (try unit.typeCheckEnumLiteral(context, Token.addInt(case_condition_node.token, 1), enum_type)) |enum_field_index| {
                                            for (existing_enums.items) |existing| {
                                                if (enum_field_index == existing) {
                                                    // Duplicate case
                                                    unreachable;
                                                }
                                            }

                                            try existing_enums.append(context.allocator, enum_field_index);
                                            switch_case_group.appendAssumeCapacity(enum_field_index);
                                        } else {
                                            unreachable;
                                        }
                                    },
                                    else => |t| @panic(@tagName(t)),
                                }
                            }
                        },
                        else => |t| @panic(@tagName(t)),
                    }

                    result.switch_case_groups.appendAssumeCapacity(switch_case_group);
                },
                .null => {
                    result.else_switch_case_group_index = index;
                },
            }
        }

        return result;
    }

    fn typeCheckEnumLiteral(unit: *Unit, context: *const Context, token_index: Token.Index, enum_type: Enum) !?Enum.Field.Index {
        const enum_name = unit.getExpectedTokenBytes(token_index, .identifier);
        const enum_name_hash = try unit.processIdentifier(context, enum_name);
        for (enum_type.fields.items) |enum_field_index| {
            const enum_field = unit.enum_fields.get(enum_field_index);
            if (enum_field.name == enum_name_hash) {
                return enum_field_index;
            }
        } else {
            return null;
        }
    }

    pub fn unwrapValueCopy(unit: *Unit, value_index: Value.Index) Value.Index{
        var i = value_index;
        while (true) {
            const value = unit.values.get(i);
            switch (value.*) {
                .copy => |new_value_index| {
                    i = new_value_index;
                },
                else => return i,
            }
        }
    }

    pub fn unwrapTypeCopy(unit: *Unit, type_index: Type.Index) Type.Index{
        var i = type_index;
        while (true) {
            const ty = unit.types.get(i);
            switch (ty.*) {
                .copy => |new_type_index| {
                    i = new_type_index;
                },
                else => return i,
            }
        }
    }

    fn getNode(unit: *Unit, node_index: Node.Index) *const Node {
        const node = unit.node_buffer.get(node_index);
        return node;
    }

    fn getNodeList(unit: *Unit, node_index: Node.Index) []const Node.Index {
        const node_list_node = unit.getNode(node_index);
        const list = unit.getNodeListFromNode(node_list_node);
        return list;
    }

    fn getNodeListFromNode(unit: *Unit, node: *const Node) []const Node.Index {
        assert(node.id == .node_list);
        const list_index = node.left;
        const node_list = unit.node_lists.items[Node.unwrap(list_index)];
        return node_list.items;
    }

    // TODO: make this fast
    fn findTokenFile(unit: *Unit, token_index: Token.Index) File.Index{
        const ti = @intFromEnum(token_index);
        for (unit.file_token_offsets.keys(), unit.file_token_offsets.values()) |range, file_index| {
            const i = @intFromEnum(range.start);
            if (ti >= i and ti < i + range.count) {
                return file_index;
            }
        }

        unreachable;
    }

    fn getExpectedTokenBytes(unit: *Unit, token_index: Token.Index, expected_id: Token.Id) []const u8 {
        const index = Token.unwrap(token_index);
        const id = unit.token_buffer.tokens.items(.id)[index];
        logln(.compilation, .token_bytes, "trying to get {s} from token of id {s}", .{ @tagName(expected_id), @tagName(id) });
        if (id != expected_id) @panic("Unexpected token");
        const offset = unit.token_buffer.tokens.items(.offset)[index];
        const len = unit.token_buffer.tokens.items(.length)[index];
        const file_index = unit.findTokenFile(token_index);
        const file = unit.files.get(file_index);
        const bytes = file.source_code[offset..][0..len];
        return bytes;
    }
   
    fn tokenStringLiteral(unit: *Unit, token_index: Token.Index) []const u8 {
        const bytes = unit.getExpectedTokenBytes(token_index, .string_literal);
        // Eat double quotes
        const string_literal_bytes = bytes[1..][0 .. bytes.len - 2];
        return string_literal_bytes;
    }

    fn evaluateAtComptime(unit: *Unit, original_value_index: Value.Index) Value.Index{
        const value_index = unit.unwrapValueCopy(original_value_index);
        const value = unit.values.get(value_index);
        return switch (value.*) {
            .bool => value_index,
            .enum_field => value_index,
            .integer => value_index,
            else => |t| @panic(@tagName(t)),
        };
    }

    fn evaluateBooleanAtComptime(unit: *Unit, value_index: Value.Index) ?bool {
        const comptime_condition = unit.evaluateAtComptime(value_index);
        if (comptime_condition != .null) {
            const value = unit.values.get(comptime_condition);
            return value.bool;
        } else {
            return null;
        }
    }

    fn getPointerType(unit: *Unit, context: *const Context, pointer: Type.Pointer, type_index: Type.Index) !void {
        if (unit.pointers.get(pointer)) |existing_type_index| {
            unit.copyType(type_index, existing_type_index);
        } else {
            assert(unit.types.get(type_index).* == .unresolved);
            unit.types.get(type_index).* = .{
                .pointer = pointer,
            };
            try unit.pointers.putNoClobber(context.allocator, pointer, type_index);
            assert(unit.types.get(type_index).* != .copy);
            assert(unit.types.get(type_index).* != .unresolved);
        }
    }

    fn getIntegerType(unit: *Unit, context: *const Context, integer: Type.Integer, type_index: Type.Index) !void {
        _ = context; // autofix
        const existing_type_index: Type.Index = switch (integer.bit_count) {
            8 => switch (integer.signedness) {
                .unsigned => .u8,
                .signed => .s8,
            },
            16 => switch (integer.signedness) {
                .unsigned => .u16,
                .signed => .s16,
            },
            32 => switch (integer.signedness) {
                .unsigned => .u32,
                .signed => .s32,
            },
            64 => switch (integer.signedness) {
                .unsigned => .u64,
                .signed => .s64,
            },
            else => unreachable,
        };

        unit.copyType(type_index, existing_type_index);
    }

    fn copyType(unit: *Unit, destination: Type.Index, source: Type.Index) void {
        if (destination != source) {
            unit.types.get(destination).* = .{
                .copy = source,
            };
        } else unreachable;
    }

    fn copyValue(unit: *Unit, destination: Value.Index, source: Value.Index) void {
        if (destination != source) {
            unit.values.get(destination).* = .{
                .copy = source,
            };
        }
    }

    fn processIdentifier(unit: *Unit, context: *const Context, string: []const u8) !u32 {
        const lookup_result = try unit.identifiers.getOrPut(context.allocator, string, string);
        return lookup_result.key;
    }

    pub fn getIdentifier(unit: *Unit, hash: u32) []const u8 {
        return unit.identifiers.getValue(hash).?;
    }

    pub fn analyze(unit: *Unit, context: *const Context, main_package: *Package) !void {
        const builder = try context.allocator.create(Builder);
        builder.* = .{
            .generate_debug_info = unit.descriptor.generate_debug_information,
            .emit_ir = true,
            .current_scope = &unit.scope,
        };

        inline for (@typeInfo(Type.Common).Enum.fields) |enum_field| {
            const e = @field(Type.Common, enum_field.name);
            const type_value = Type.Common.map.get(e);
            _ = try unit.types.append(context.allocator, type_value);
        }

        inline for (@typeInfo(Value.Common).Enum.fields) |enum_field| {
            const e = @field(Value.Common, enum_field.name);
            const value = Value.Common.map.get(e);
            _ = try unit.values.append(context.allocator, value);
        }


        try builder.analyzePackage(unit, context, main_package);
    }

    pub fn generateAbstractSyntaxTreeForFile(unit: *Unit, context: *const Context, file_index: File.Index) !void {
        const file = unit.files.get(file_index);
        const source_file = file.package.directory.handle.openFile(file.relative_path, .{}) catch |err| {
            std.debug.panic("Can't find file {s} in directory {s} for error {s}", .{ file.relative_path, file.package.directory.path, @errorName(err) });
        };
        
        const file_size = try source_file.getEndPos();
        var file_buffer = try context.allocator.alloc(u8, file_size);

        const read_byte_count = try source_file.readAll(file_buffer);
        assert(read_byte_count == file_size);
        source_file.close();

        //TODO: adjust file maximum size
        file.source_code = file_buffer[0..read_byte_count];
        file.status = .loaded_into_memory;

        assert(file.status == .loaded_into_memory);
        file.lexer = try lexer.analyze(context.allocator, file.source_code, &unit.token_buffer);
        assert(file.status == .loaded_into_memory);
        file.status = .lexed;
        try unit.file_token_offsets.putNoClobber(context.allocator, .{
            .start = file.lexer.offset,
            .count = file.lexer.count,
        }, file_index);

        logln(.parser, .file, "[START PARSING FILE #{} {s}]", .{ file_index, file.package.source_path });
        file.parser = try parser.analyze(context.allocator, file.lexer, file.source_code, file_index, &unit.token_buffer, &unit.node_buffer, &unit.node_lists);
        logln(.parser, .file, "[END PARSING FILE #{} {s}]", .{ file_index, file.package.source_path });
        assert(file.status == .lexed);
        file.status = .parsed;
    }

    fn importPackage(unit: *Unit, context: *const Context, package: *Package) !ImportPackageResult {
        const full_path = try std.fs.path.resolve(context.allocator, &.{ package.directory.path, package.source_path });
        logln(.compilation, .import, "Import full path: {s}\n", .{full_path});
        const import_file = try unit.getFile(context, full_path, package.source_path, package);

        return .{
            .file = import_file,
            .is_package = true,
        };
    }

    pub fn importFile(unit: *Unit, context:*const Context, current_file_index: File.Index, import_name: []const u8) !ImportPackageResult {
        logln(.compilation, .import, "import: '{s}'\n", .{import_name});

        if (equal(u8, import_name, "std")) {
            return unit.importPackage(context, unit.main_package.dependencies.get("std").?);
        }

        if (equal(u8, import_name, "builtin")) {
            return unit.importPackage(context, unit.main_package.dependencies.get("builtin").?);
        }

        if (equal(u8, import_name, "main")) {
            return unit.importPackage(context, unit.main_package);
        }

        const current_file = unit.files.get(current_file_index);
        if (current_file.package.dependencies.get(import_name)) |package| {
            return unit.importPackage(context, package);
        }

        if (!std.mem.endsWith(u8, import_name, ".nat")) {
            unreachable;
        }

        const current_file_relative_path_to_package_directory = std.fs.path.dirname(current_file.relative_path) orelse "";
        const import_file_relative_path = try std.fs.path.join(context.allocator, &.{ current_file_relative_path_to_package_directory, import_name });
        const full_path = try std.fs.path.join(context.allocator, &.{ current_file.package.directory.path, import_file_relative_path });
        const file_relative_path = import_file_relative_path;
        const package = current_file.package;
        const import_file = try unit.getFile(context, full_path, file_relative_path, package);
        _ = @intFromPtr(unit.files.get(import_file.index).package);

        // try unit.files.get(import_file.index).file_references.append(context.allocator, current_file);

        const result = ImportPackageResult{
            .file = import_file,
            .is_package = false,
        };

        return result;
    }

    fn getFile(unit: *Unit, context: *const Context, full_path: []const u8, relative_path: []const u8, package: *Package) !ImportFileResult {
        const path_lookup = try unit.file_map.getOrPut(context.allocator, full_path);
        const index = switch (path_lookup.found_existing) {
            true => path_lookup.value_ptr.*,
            false => blk: {
                const file_index = try unit.files.append(context.allocator, File{
                    .relative_path = relative_path,
                    .package = package,
                    .scope = .{
                        .file = .null,
                        .kind = .file,
                        .line = 0,
                        .column = 0,
                        .local = false,
                        .level = 1,
                    },
                });
                logln(.compilation, .new_file, "Adding file #{}: {s}\n", .{ file_index, full_path });
                path_lookup.value_ptr.* = file_index;
                // break :blk file;
                break :blk file_index;
            },
        };

        return .{
            .index = index,
            .is_new = !path_lookup.found_existing,
        };
    }

    fn compile(unit: *Unit, context: *const Context) !void {
        const builtin_file_name = "builtin.nat";
        var cache_dir = try context.build_directory.openDir("cache", .{});

        // Write the builtin file to the filesystem
        {
            const builtin_file = try cache_dir.createFile(builtin_file_name, .{});
            try builtin_file.writer().print(
                \\const builtin = #import("std").builtin;
                \\const cpu = builtin.Cpu.{s};
                \\const os = builtin.Os.{s};
                \\const abi = builtin.Abi.{s};
                \\const link_libc = {};
                \\
            , .{
                @tagName(unit.descriptor.target.cpu.arch),
                @tagName(unit.descriptor.target.os.tag),
                @tagName(unit.descriptor.target.abi),
                unit.descriptor.link_libc,
            });
            builtin_file.close();
        }

        unit.main_package = blk: {
            const result = try context.allocator.create(Package);
            const main_package_absolute_directory_path = b: {
                const relative_path = if (std.fs.path.dirname(unit.descriptor.main_package_path)) |dirname| dirname else ".";
                break :b try context.pathFromCwd(relative_path);
            };
            result.* = .{
                .directory = .{
                    .handle = try std.fs.openDirAbsolute(main_package_absolute_directory_path, .{}),
                    .path = main_package_absolute_directory_path,
                },
                .source_path = try context.allocator.dupe(u8, std.fs.path.basename(unit.descriptor.main_package_path)),
            };
            break :blk result;
        };
        const std_package_dir = "lib/std";

        const package_descriptors = [2]struct {
            name: []const u8,
            directory_path: []const u8,
        }{
            .{
                .name = "std",
                .directory_path = try context.pathFromCompiler(std_package_dir),
            },
            .{
                .name = "builtin",
                .directory_path = blk: {
                    const result = try cache_dir.realpathAlloc(context.allocator, ".");
                    cache_dir.close();
                    break :blk result;
                },
            },
        };

        var packages: [package_descriptors.len]*Package = undefined;
        for (package_descriptors, &packages) |package_descriptor, *package_ptr| {
            const package = try context.allocator.create(Package);
            package.* = .{
                .directory = .{
                    .path = package_descriptor.directory_path,
                    .handle = try std.fs.openDirAbsolute(package_descriptor.directory_path, .{}),
                },
                .source_path = try std.mem.concat(context.allocator, u8, &.{ package_descriptor.name, ".nat" }),
            };

            try unit.main_package.addDependency(context.allocator, package_descriptor.name, package);

            package_ptr.* = package;
        }

        assert(unit.main_package.dependencies.size == 2);

        if (!unit.descriptor.only_parse) {
            _ = try unit.importPackage(context, unit.main_package.dependencies.get("std").?);
        } else {
            _ = try unit.importPackage(context, unit.main_package);
        }

        for (unit.file_map.values()) |import| {
            try unit.generateAbstractSyntaxTreeForFile(context, import);
        }

        if (!unit.descriptor.only_parse) {
            try unit.analyze(context, packages[0]);

            try llvm.codegen(unit, context);
        }
    }

    fn getConstantInt(unit: *Unit, context: *const Context, integer: Value.Integer) !Instruction.Index{
        if (unit.constant_int_map.get(integer)) |r| return r else {
            const const_int = try unit.instructions.append(context.allocator, .{
                .constant_int = integer,
            });
            try unit.constant_int_map.putNoClobber(context.allocator, integer, const_int);
            return const_int;
        }
    }
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
    null,
    @"align",
    @"for",
    undefined,
    @"break",
};

pub const Descriptor = struct {
    main_package_path: []const u8,
    executable_path: []const u8,
    target: std.Target,
    transpile_to_c: bool,
    is_build: bool,
    only_parse: bool,
    link_libc: bool,
    generate_debug_information: bool,
    name: []const u8,
};

fn getContainerMemberType(member_id: Node.Id) MemberType {
    return switch (member_id) {
        .@"comptime" => .comptime_block,
        .constant_symbol_declaration,
        .variable_symbol_declaration,
        => .declaration,
        .enum_field,
        .container_field,
        => .field,
        else => |t| @panic(@tagName(t)),
    };
}

const MemberType = enum {
    declaration,
    field,
    comptime_block,
};

// TODO: switch to packed struct when speed is important
pub const Token = struct {
    line: u32,
    offset: u32,
    length: u32,
    id: Token.Id,

    pub const Buffer = struct{
        tokens: std.MultiArrayList(Token) = .{},
        line_offsets: ArrayList(u32) = .{},

        pub fn getOffset(buffer: *const Buffer) Token.Index {
            return @enumFromInt(buffer.tokens.len);
        }

        pub fn getLineOffset(buffer: *const Buffer) u32 {
            return @intCast(buffer.line_offsets.items.len);
        }
    };

    pub const Range = struct{
        start: Token.Index,
        count: u32,
    };

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
        operator_shift_left,
        operator_shift_right,
        operator_add_assign,
        operator_sub_assign,
        operator_mul_assign,
        operator_div_assign,
        operator_mod_assign,
        operator_or_assign,
        operator_and_assign,
        operator_xor_assign,
        operator_shift_left_assign,
        operator_shift_right_assign,
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
        fixed_keyword_null,
        fixed_keyword_align,
        fixed_keyword_for,
        fixed_keyword_undefined,
        fixed_keyword_break,
        unused0,
        unused1,
        unused2,
        unused3,
        unused4,
        unused5,
        unused6,
        unused7,
        unused8,
        unused9,
        unused20,
        unused21,
        unused22,
        unused23,
        unused24,
        unused25,
        unused26,
        unused27,
        unused28,
        unused29,
        unused30,
        unused31,
        unused32,
        unused33,
        unused34,
        unused35,
        unused36,
        unused37,
        unused38,
        unused39,
        unused40,
        unused41,
        unused42,
        unused43,
        unused44,
        unused45,
        unused46,
        unused47,
        unused48,
        unused49,
        unused50,
        unused51,
        unused52,
        unused53,
        unused54,
        unused55,
        unused56,
        unused57,
        unused58,
        unused59,
        unused60,
        unused61,
        unused62,
        unused63,
        unused64,
        unused65,
        unused66,
        unused67,
        unused68,
        unused69,

        comptime {
            assert(@bitSizeOf(@This()) == @bitSizeOf(u8));
        }
    };

    pub usingnamespace data_structures.getIndexForType(@This(), enum{});
};
