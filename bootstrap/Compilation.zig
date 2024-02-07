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

fn todo() noreturn {
    @panic("todo");
}

fn reportUnterminatedArgumentError(string: []const u8) noreturn {
    std.debug.panic("Unterminated argument: {s}", .{string});
}

pub fn buildExecutable(allocator: Allocator, arguments: [][:0]u8) !void {
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

    var maybe_executable_path: ?[]const u8 = null;
    var maybe_main_package_path: ?[]const u8 = null;
    var target_triplet: []const u8 = switch (@import("builtin").os.tag) {
        .linux => "x86_64-linux-gnu",
        .macos => "aarch64-macos-none",
        else => unreachable,
    };
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

    const unit = try context.allocator.create(Unit);
    unit.* = .{
        .descriptor = .{
            .main_package_path = main_package_path,
            .executable_path = executable_path,
            .target = target,
            .is_build = is_build,
            .only_parse = only_parse,
            .link_libc = switch (target.os.tag) {
                .linux => link_libc,
                .macos => true,
                .windows => link_libc,
                else => unreachable,
            },
            .generate_debug_information = generate_debug_information,
            .name = executable_name,
        },
    };

    try unit.compile(context);
}

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
    lexer,
    parser,
    compilation,
    llvm,
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
            .llvm => llvm,
        };
    }
}

var logger_bitset = std.EnumSet(LoggerScope).initEmpty();

fn getWriter() !std.fs.File.Writer{
    const stdout = std.io.getStdOut();
    return stdout.writer();
}

fn shouldLog(comptime logger_scope: LoggerScope, logger: getLoggerScopeType(logger_scope).Logger) bool {
    return logger_bitset.contains(logger_scope) and getLoggerScopeType(logger_scope).Logger.bitset.contains(logger);
}

pub fn logln(comptime logger_scope: LoggerScope, logger: getLoggerScopeType(logger_scope).Logger, comptime format: []const u8, arguments: anytype) void {
    if (shouldLog(logger_scope, logger)) {
        log(logger_scope, logger, format, arguments);
        const writer = try getWriter();
        writer.writeByte('\n') catch unreachable;
    }
}

pub fn log(comptime logger_scope: LoggerScope, logger: getLoggerScopeType(logger_scope).Logger, comptime format: []const u8, arguments: anytype) void {
    if (shouldLog(logger_scope, logger)) {
        std.fmt.format(try getWriter(), format, arguments) catch unreachable;
    }
}

pub fn panic(message: []const u8, stack_trace: ?*std.builtin.StackTrace, return_address: ?usize) noreturn {
    const print_stack_trace = @import("configuration").print_stack_trace;
    switch (print_stack_trace) {
        true => @call(.always_inline, std.builtin.default_panic, .{ message, stack_trace, return_address }),
        false => {
            const writer = try getWriter();
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
    index: Debug.File.Index,
    is_new: bool,
};

const ImportPackageResult = struct {
    file: ImportFileResult,
    is_package: bool,
};


pub const Type = union(enum) {
    void,
    noreturn,
    type,
    comptime_int,
    bool,
    @"struct": Struct.Index,
    @"enum": Enum.Index,
    function: Function.Prototype.Index,
    integer: Type.Integer,
    pointer: Type.Pointer,
    slice: Type.Slice,
    array: Type.Array,

    fn getByteSize(ty: *Type, unit: *Unit) u32 {
        _ = unit; // autofix
        return switch (ty.*) {
            .integer => |integer| integer.bit_count,
            else => |t| @panic(@tagName(t)),
        };
    }

    fn getScope(ty: *Type, unit: *Unit) *Debug.Scope {
        return switch (ty.*) {
            .@"struct" => |struct_index| &unit.structs.get(struct_index).scope.scope,
            .@"enum" => |enum_index| &unit.enums.get(enum_index).scope.scope,
            else => |t| @panic(@tagName(t)),
        };
    }

    const Expect = union(enum){
        none,
        type: Type.Index,
        optional,
        array: struct{
            count: ?usize,
            type: Type.Index,
            termination: Termination,
        },
    };

    const Integer = struct {
        bit_count: u16,
        signedness: Signedness,

        pub const Signedness = enum(u1) {
            unsigned = 0,
            signed = 1,
        };
    };

    pub const Pointer = struct{
        type: Type.Index,
        termination: Termination,
        mutability: Mutability,
        many: bool,
        nullable: bool,
    };

    const Slice = struct{
        child_pointer_type: Type.Index,
        child_type: Type.Index,
        termination: Termination,
        mutability: Mutability,
        nullable: bool,
    };

    const Array = struct{
        count: usize,
        type: Type.Index,
        termination: Termination,
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
    argument_declaration: *Debug.Declaration.Argument,
    branch: Branch,
    block: Debug.Block.Index,
    // TODO
    call: Instruction.Call,
    cast: Cast,
    // TODO: remove?
    constant_int: struct{
        value: u64,
        type: Type.Index,
    },
    debug_checkpoint: DebugCheckPoint,
    debug_declare_local_variable: DebugDeclareLocalVariable,
    extract_value: ExtractValue,
    insert_value: InsertValue,
    get_element_pointer: GEP,
    global: *Debug.Declaration.Global,
    inline_assembly: InlineAssembly.Index,
    integer_compare: IntegerCompare,
    integer_binary_operation: Instruction.IntegerBinaryOperation,
    jump: Jump,
    load: Load,
    umin: Min,
    smin: Min,
    // optional_wrap: V,
    // optional_unwrap_unchecked: Instruction.Index,
    // optional_unwrap_checked: V,
    // optional_check: Instruction.Index,
    phi: Phi,
    pop_scope: Instruction.Scope,
    push_scope: Instruction.Scope,
    ret: V,
    ret_void,
    stack_slot: Instruction.StackSlot,
    store: Store,
    syscall: Syscall,
    @"unreachable",

    const Phi = struct{
        values: ArrayList(V) = .{},
        basic_blocks: ArrayList(BasicBlock.Index) = .{},
        type: Type.Index,
    };

    const Min = struct{
        left: V,
        right: V,
        type: Type.Index,
    };

    const GEP = struct{
        pointer: Instruction.Index,
        base_type: Type.Index,
        index: V,
    };

    const ExtractValue = struct{
        expression: V,
        index: u32,
    };

    const InsertValue = struct{
        expression: V,
        index: u32,
        new_value: V,
    };

    const Branch = struct{
        condition: Instruction.Index,
        from: BasicBlock.Index,
        taken: BasicBlock.Index,
        not_taken: BasicBlock.Index,
    };
    const Jump = struct{
        from: BasicBlock.Index,
        to: BasicBlock.Index,
    };

    const DebugDeclareLocalVariable = struct{
        variable: *Debug.Declaration.Local,
        stack: Instruction.Index,
    };

    const Syscall = struct{
        arguments: []const V,
    };

    const Callable = union(enum) {
        function_definition: *Debug.Declaration.Global,
    };

    const Call = struct{
        callable: Callable,
        function_type: Type.Index,
        arguments: []const V,
    };

    const IntegerCompare = struct{
        left: V,
        right: V,
        type: Type.Index,
        id: Id,

        const Id = enum{
            equal,
            not_equal,
            unsigned_less,
            unsigned_less_equal,
            unsigned_greater,
            unsigned_greater_equal,
            signed_less,
            signed_less_equal,
            signed_greater,
            signed_greater_equal,
        };
    };

    const IntegerBinaryOperation = struct{
        left: V,
        right: V,
        id: Id,
        signedness: Type.Integer.Signedness,

        const Id = enum{
            add,
            div,
            mod,
            mul,
            sub,
            bit_and,
            bit_or,
            bit_xor,
            shift_left,
            shift_right,
        };
    };

    const Scope = struct {
        old: *Debug.Scope,
        new: *Debug.Scope,
    };

    const ArgumentDeclaration = struct{
        name: u32,
        type: Type.Index,
    };

    const Cast = struct {
        id: Cast.Id,
        value: V,
        type: Type.Index,

        const Id = enum{
            bitcast,
            enum_to_int,
            int_to_pointer,
            pointer_to_int,
            sign_extend,
            zero_extend,
            pointer_var_to_const,
            slice_var_to_const,
            truncate,
        };
    };

    const DebugCheckPoint = struct{
        scope: *Debug.Scope,
        line: u32,
        column: u32,
    };

    const Load = struct{
        value: V,
    };

    const StackSlot = struct{
        type: Type.Index,
    };

    const Store = struct{
        // TODO:
        destination: V,
        source: V,
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
        @"extern",
    };

    pub const Definition = struct{
        scope: Debug.Scope.Function,
        basic_blocks: ArrayList(BasicBlock.Index) = .{},
        // TODO: make this more efficient
        type: Type.Index,
        body: Debug.Block.Index,

        pub const List = BlockList(@This(), enum{});
        pub usingnamespace @This().List.Index;
    };

    const CallingConvention = enum{
        c,
        auto,
    };

    pub const Prototype = struct {
        argument_types: []const Type.Index,
        return_type: Type.Index,
        attributes: Attributes,
        calling_convention: CallingConvention,

        const Attributes = struct{
            naked: bool,
        };

        const List = BlockList(@This(), enum{});
        pub usingnamespace @This().List.Index;
    };

};

pub const Struct = struct{
    fields: ArrayList(Struct.Field.Index) = .{},
    scope: Debug.Scope.Global,
    backing_type: Type.Index,
    type: Type.Index,
    optional: bool,

    pub const Field = struct{
        name: u32,
        type: Type.Index,
        default_value: ?V.Comptime,
        
        const List = BlockList(@This(), enum{});
        pub usingnamespace @This().List.Index;
    };

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

pub const V = struct{
    value: union(enum) {
        unresolved: Node.Index,
        runtime: Instruction.Index,
        @"comptime": Comptime,
        function_reference: *Debug.Declaration.Global,
    },
    type: Type.Index,

    pub const Comptime = union(enum){
        unresolved: Node.Index,
        undefined,
        type: Type.Index,
        bool: bool,
        comptime_int: ComptimeInt,
        constant_int: ConstantInt,
        enum_value: Enum.Field.Index,
        function_definition: Function.Definition.Index,
        constant_struct: ConstantStruct.Index,
        constant_array: ConstantArray.Index,
        constant_slice: ConstantSlice.Index,
        string_literal: u32,

        pub const ConstantSlice = struct{
            ptr: *Debug.Declaration.Global,
            len: usize,
            type: Type.Index,
            
            pub const List = BlockList(@This(), enum{});
            pub usingnamespace List.Index;
        };

        pub const ConstantArray = struct{
            values: []const V.Comptime,
            type: Type.Index,
            
            pub const List = BlockList(@This(), enum{});
            pub usingnamespace List.Index;
        };

        pub const ConstantStruct = struct{
            fields: []const V.Comptime,
            type: Type.Index,
            
            pub const List = BlockList(@This(), enum{});
            pub usingnamespace List.Index;
        };

        pub const ComptimeInt = struct{
            value: u64,
            signedness: Type.Integer.Signedness,
        };

        pub const ConstantInt = struct{
            value: u64,
        };

        fn getType(v: Comptime, unit: *Unit) Type.Index{
            return switch (v) {
                .type => .type,
                .bool => .bool,
                .enum_value => |enum_field_index| unit.enum_fields.get(enum_field_index).parent,
                .function_definition => |function_definition_index| unit.function_definitions.get(function_definition_index).type,
                .comptime_int => .comptime_int,
                else => |t| @panic(@tagName(t)),
            };
        }
    };
};


pub const Debug = struct{
    pub const Declaration = struct{
        scope: *Scope,
        type: Type.Index,
        name: u32,
        line: u32,
        column: u32,
        mutability: Mutability,
        kind: Kind,

        const Kind = enum{
            global,
            local,
            argument,
        };

        pub const Global = struct{
            declaration: Declaration,
            initial_value: V.Comptime,
            type_node_index: Node.Index,
            attributes: Attributes,

            const Attributes = std.EnumSet(Attribute);

            pub const Attribute = enum{
                @"export",
            };

            pub const List = BlockList(@This(), enum{});
            pub usingnamespace List.Index;

            pub fn getFunctionDefinitionIndex(global: *Global) Function.Definition.Index{
                return global.initial_value.function_definition;
            }
        };

        pub const Local = struct{
            declaration: Declaration,
            init_value: V,
            pub const List = BlockList(@This(), enum{});
            pub usingnamespace List.Index;
        };
        pub const Argument = struct{
            declaration: Declaration,

            pub const List = BlockList(@This(), enum{});
            pub usingnamespace List.Index;
        };
    };

    pub const Scope = struct{
        declarations: AutoArrayHashMap(u32, *Declaration) =.{},
        parent: ?*Scope = null,
        file: File.Index,
        line: u32,
        column: u32,
        kind: Kind,
        local: bool,
        level: u8,

        const Lookup = struct{
            scope: *Scope,
            declaration: *Declaration,
        };

        pub const Local = struct{
            scope: Scope,
            local_declaration_map: AutoArrayHashMap(*Debug.Declaration.Local, Instruction.Index) = .{},
        };

        pub const Global = struct{
            scope: Scope,
        };

        pub const Function = struct{
            scope: Scope,
            argument_map: AutoArrayHashMap(*Debug.Declaration.Argument, Instruction.Index) = .{},
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

        pub const Kind = enum{
            compilation_unit,
            file,
            file_container,
            container,
            function,// Arguments
            block,
        };
    };

    pub const Block = struct{
        scope: Scope.Local,
        pub const List = BlockList(@This(), enum{});
        pub usingnamespace List.Index;
    };

    pub const File = struct {
        relative_path: []const u8,
        package: *Package,
        source_code: []const u8 = &.{},
        status: Status = .not_loaded,
        lexer: lexer.Result = undefined,
        parser: parser.Result = undefined,
        // value: Value.Index = .null,
        type: Type.Index = .null,
        scope: Scope.Global,

        pub const List = BlockList(@This(), enum{});
        pub usingnamespace List.Index;

        pub const Status = enum {
            not_loaded,
            loaded_into_memory,
            lexed,
            parsed,
        };
    };

};

pub const Mutability = enum(u1) {
    @"const",
    @"var",
};

pub const IntrinsicId = enum{
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

pub const ArithmeticLogicIntegerInstruction = enum {
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
};

pub const Builder = struct {
    current_scope: *Debug.Scope,
    current_file: Debug.File.Index = .null,
    current_function: Function.Definition.Index = .null,
    current_basic_block: BasicBlock.Index = .null,
    exit_blocks: ArrayList(BasicBlock.Index) = .{},
    loop_exit_block: BasicBlock.Index = .null,
    return_phi: Instruction.Index = .null,
    return_block: BasicBlock.Index = .null,
    last_check_point: struct{
        line: u32 = 0,
        column: u32 = 0,
        scope: ?*Debug.Scope = null,
    } = .{},
    generate_debug_info: bool,
    emit_ir: bool,

    fn processArrayLiteral(builder: *Builder, unit: *Unit, context: *const Context, constant_array_index: V.Comptime.ConstantArray.Index, token: Token.Index) !*Debug.Declaration.Global {
        if (unit.global_array_constants.get(constant_array_index)) |global| {
            return global;
        } else {
            const token_debug_info = builder.getTokenDebugInfo(unit, token);
            const array_literal_name = try std.fmt.allocPrint(context.allocator, "__anon_arr_{}", .{unit.global_array_constants.size});
            const identifier = try unit.processIdentifier(context, array_literal_name);
            const constant_array = unit.constant_arrays.get(constant_array_index);

            const global_declaration_index = try unit.global_declarations.append(context.allocator, .{
                .declaration = .{
                    .scope = builder.current_scope,
                    .name = identifier,
                    .type = constant_array.type,
                    .line = token_debug_info.line,
                    .column = token_debug_info.column,
                    .mutability = .@"const",
                    .kind = .global,
                },
                .initial_value = .{
                    .constant_array = constant_array_index,
                },
                .type_node_index = .null,
                .attributes = Debug.Declaration.Global.Attributes.initMany(&.{
                    .@"export",
                }),
            });
            const global_declaration = unit.global_declarations.get(global_declaration_index);
            try unit.data_to_emit.append(context.allocator, global_declaration);

            try unit.global_array_constants.putNoClobber(context.allocator, constant_array_index, global_declaration);

            return global_declaration;
        }
    }

    fn processStringLiteral(builder: *Builder, unit: *Unit, context: *const Context, token_index: Token.Index) !*Debug.Declaration.Global {
        const string = try unit.fixupStringLiteral(context, token_index);
        const possible_id = unit.string_literal_values.size;
        const hash = data_structures.hash(string);
        const gop = try unit.string_literal_globals.getOrPut(context.allocator, hash);

        if (gop.found_existing) {
            return gop.value_ptr.*;
        } else {
            const string_name = try std.fmt.allocPrint(context.allocator, "__anon_str_{}", .{possible_id});
            const identifier = try unit.processIdentifier(context, string_name);
            try unit.string_literal_values.putNoClobber(context.allocator, hash, string);
            const token_debug_info = builder.getTokenDebugInfo(unit, token_index);

            const string_global_index = try unit.global_declarations.append(context.allocator, .{
                .declaration = .{
                    .scope = builder.current_scope,
                    .name = identifier,
                    .type = blk: {
                        const length = string.len;
                        const array_type = try unit.getArrayType(context, .{
                            .type = .u8,
                            .count = length,
                            .termination = .zero,
                        });
                        const string_type = try unit.getPointerType(context, .{
                            .type = array_type,
                            .termination = .none,
                            .mutability = .@"const",
                            .many = true,
                            .nullable = false,
                        });
                        _ = string_type; // autofix

                        break :blk array_type;
                    },
                    .line = token_debug_info.line,
                    .column = token_debug_info.column,
                    .mutability = .@"const",
                    .kind = .global,
                },
                .initial_value = .{
                    .string_literal = hash,
                },
                .type_node_index = .null,
                .attributes = Debug.Declaration.Global.Attributes.initMany(&.{
                    .@"export",
                }),
            });

            const string_global = unit.global_declarations.get(string_global_index);

            gop.value_ptr.* = string_global;

            try unit.data_to_emit.append(context.allocator, string_global);

            return string_global;
        }
    }

    fn resolveIntrinsic(builder: *Builder, unit: *Unit, context: *const Context, type_expect: Type.Expect, node_index: Node.Index) anyerror!V {
        const node = unit.getNode(node_index);
        const intrinsic_id: IntrinsicId = @enumFromInt(Node.unwrap(node.right));
        const argument_node_list = unit.getNodeList(node.left);

        switch (intrinsic_id) {
            .import => {
                const file_index = try builder.resolveImport(unit, context, type_expect, argument_node_list);
                const file = unit.files.get(file_index);
                return .{
                    .value = .{
                        .@"comptime" = .{
                            .type = file.type,
                        },
                    },
                    .type = .type,
                };
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
                            .identifier => b: {
                                const identifier = unit.getExpectedTokenBytes(operand_node.token, .identifier);
                                const result = try builder.resolveIdentifier(unit, context, Type.Expect.none, identifier, .left);

                                break :b .{
                                    .value = result,
                                };
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

                return .{
                    .value = .{
                        .runtime = inline_asm,
                    },
                    // TODO: WARN fix
                    .type = .@"noreturn",
                };
            },
            .cast => {
                assert(argument_node_list.len == 1);
                const argument_node_index = argument_node_list[0];
                // TODO: depends? .right is not always the right choice
                const v = try builder.resolveRuntimeValue(unit, context, Type.Expect.none, argument_node_index, .right);

                const source_type = unit.types.get(v.type);
                                 //
                const cast_id: Instruction.Cast.Id = switch (type_expect) {
                    .type => |type_index| b: {
                        assert(type_index != v.type);
                        const destination_type = unit.types.get(type_index);
                        switch (destination_type.*) {
                            .pointer => |destination_pointer| {
                                _ = destination_pointer; // autofix
                                switch (source_type.*) {
                                    .integer => |source_integer| {
                                        _ = source_integer; // autofix
                                        // TODO:
                                        break :b .int_to_pointer;
                                    },
                                    else => |t| @panic(@tagName(t)),
                                }
                            },
                            .integer => |destination_integer| {
                                switch (source_type.*) {
                                    .@"enum" => |enum_index| {
                                        const enum_type = unit.enums.get(enum_index);
                                        if (enum_type.backing_type == type_index) {
                                            break :b .enum_to_int;
                                        } else {
                                            const source_integer = unit.types.get(enum_type.backing_type).integer;
                                            if (destination_integer.bit_count < source_integer.bit_count) {
                                                unreachable;
                                            } else if (destination_integer.bit_count > source_integer.bit_count) {
                                                assert(destination_integer.signedness != source_integer.signedness);
                                                break :b switch (destination_integer.signedness) {
                                                    .signed => .sign_extend,
                                                    .unsigned => .zero_extend,
                                                };
                                            } else {
                                                assert(destination_integer.signedness != source_integer.signedness);
                                                break :b .bitcast;
                                            }
                                        }
                                    },
                                    .integer => |source_integer| {
                                        if (destination_integer.bit_count < source_integer.bit_count) {
                                            assert(destination_integer.signedness == source_integer.signedness);
                                            break :b .truncate;
                                        } else if (destination_integer.bit_count > source_integer.bit_count) {
                                            assert(destination_integer.signedness != source_integer.signedness);
                                            break :b switch (destination_integer.signedness) {
                                                .signed => .sign_extend,
                                                .unsigned => .zero_extend,
                                            };
                                        } else {
                                            assert(destination_integer.signedness != source_integer.signedness);
                                            break :b .bitcast;
                                        }
                                    },
                                    .pointer => {
                                        if (destination_integer.signedness == .signed) {
                                            unreachable;
                                        }
                                        if (destination_integer.bit_count < 64) {
                                            unreachable;
                                        }

                                        break :b .pointer_to_int;
                                    },
                                    else => |t| @panic(@tagName(t)),
                                }
                            },
                            else => |t| @panic(@tagName(t)),
                        }
                    },
                    else => |t| @panic(@tagName(t)),
                };

                const instruction = try unit.instructions.append(context.allocator, .{
                    .cast = .{
                        .value = v,
                        .type = type_expect.type,
                        .id = cast_id,
                    },
                });
                
                try builder.appendInstruction(unit, context, instruction);

                return .{
                    .value = .{
                        .runtime = instruction,
                    },
                    .type = type_expect.type,
                };
            },
            .size => {
                assert(argument_node_list.len == 1);
                const argument_type_index = try builder.resolveType(unit, context, argument_node_list[0]);
                const argument_type = unit.types.get(argument_type_index);
                const argument_size = argument_type.getByteSize(unit);

                const integer_value = argument_size;
                const integer_type = switch (type_expect) {
                    .type => |type_index| b: {
                        const ty = unit.types.get(type_index);
                        break :b switch (ty.*) {
                            .integer => type_index,
                            else => |t| @panic(@tagName(t)),
                        };
                    },
                    else => |t| @panic(@tagName(t)),
                };

                return .{
                    .value = .{
                        .@"comptime" = .{
                            .comptime_int = .{
                                .value = integer_value,
                                .signedness = .unsigned,
                            },
                        },
                    },
                    .type = integer_type,
                };
            },
            .syscall => {
                if (argument_node_list.len > 0 and argument_node_list.len <= 6 + 1) {
                    var instruction_list = try ArrayList(V).initCapacity(context.allocator, argument_node_list.len);
                    // TODO
                    const arg_type_expect = Type.Expect{
                        .type = Type.Index.usize,
                    };

                    for (argument_node_list) |argument_node_index| {
                        const argument_value = try builder.resolveRuntimeValue(unit, context, arg_type_expect, argument_node_index, .right);
                        instruction_list.appendAssumeCapacity(argument_value);
                    }

                    const syscall = try unit.instructions.append(context.allocator, .{
                        .syscall = .{
                            .arguments = instruction_list.items,
                        },
                    });

                    try builder.appendInstruction(unit, context, syscall);

                    return .{
                        .value = .{
                            .runtime = syscall,
                        },
                        .type = Type.Index.usize,
                    };
                } else {
                    @panic("Syscall argument mismatch");
                }
            },
            .min => {
                assert(argument_node_list.len == 2);
                const expected_type = switch (type_expect) {
                    .type => |type_index| {
                        const left = try builder.resolveRuntimeValue(unit, context, type_expect, argument_node_list[0], .right);
                        const right = try builder.resolveRuntimeValue(unit, context, type_expect, argument_node_list[1], .right);
                        switch (unit.types.get(type_index).*) {
                            .integer => |integer| {
                                const min_descriptor = Instruction.Min{
                                    .left = left,
                                    .right = right,
                                    .type = type_index,
                                };
                                const instruction: Instruction = switch (integer.signedness) {
                                    .unsigned => .{
                                        .umin = min_descriptor,
                                    },
                                    .signed => .{
                                        .smin = min_descriptor,
                                    },
                                };
                                const min = try unit.instructions.append(context.allocator, instruction);
                                try builder.appendInstruction(unit, context, min);

                                return .{
                                    .value = .{
                                        .runtime = min,
                                    },
                                    .type = type_index,
                                };
                            },
                            else => |t| @panic(@tagName(t)),
                        }
                    },
                    else => |t| @panic(@tagName(t)),
                };
                _ = expected_type; // autofix
                unreachable;
            },
            else => |t| @panic(@tagName(t)),
        }
    }

    fn pushScope(builder: *Builder, unit: *Unit, context: *const Context, new_scope: *Debug.Scope) !void {
        const old_scope = builder.current_scope;

        assert(@intFromEnum(old_scope.kind) <= @intFromEnum(new_scope.kind));

        if (builder.current_basic_block != .null) {
            assert(@intFromEnum(old_scope.kind) >= @intFromEnum(Debug.Scope.Kind.function));
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

        assert(@intFromEnum(old_scope.kind) >= @intFromEnum(new_scope.kind));

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

    fn analyzeFile(builder: *Builder, unit: *Unit, context: *const Context, file_index: Debug.File.Index) !void {
        const old_function = builder.current_function;
        builder.current_function = .null;
        defer builder.current_function = old_function;

        const old_basic_block = builder.current_basic_block;
        defer builder.current_basic_block = old_basic_block;
        builder.current_basic_block = .null;

        const old_loop_exit_block = builder.loop_exit_block;
        defer builder.loop_exit_block = old_loop_exit_block;
        builder.loop_exit_block = .null;

        const old_scope = builder.current_scope;
        builder.current_scope = &unit.scope.scope;
        defer builder.current_scope = old_scope;

        const old_exit_blocks = builder.exit_blocks;
        builder.exit_blocks = .{};
        defer builder.exit_blocks = old_exit_blocks;

        const old_return_phi = builder.return_phi;
        builder.return_phi = .null;
        defer builder.return_phi = old_return_phi;

        const old_return_block = builder.return_block;
        builder.return_block = .null;
        defer builder.return_block = old_return_block;

        const file = unit.files.get(file_index);
        assert(file.status == .parsed);

        const previous_file = builder.current_file;
        builder.current_file = file_index;
        defer builder.current_file = previous_file;

        try builder.pushScope(unit, context, &file.scope.scope);
        defer builder.popScope(unit, context) catch unreachable;

        const main_node_index = file.parser.main_node_index;

        // File type already assigned
        _ = try builder.resolveContainerType(unit, context, main_node_index, .@"struct");
        assert(file.type != .null);
    }

    const CastResult = enum{
        int_to_pointer,
        enum_to_int,
        sign_extend,
        zero_extend,
    };

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
        if (!basic_block.terminated) {
            try basic_block.instructions.append(context.allocator, instruction_index);
        } else {
            const instruction = unit.instructions.get(instruction_index);
            assert(instruction.* == .pop_scope);
            try basic_block.instructions.insert(context.allocator, basic_block.instructions.items.len - 1, instruction_index);
        }
    }

    const If = struct{
        condition: Condition,
        const Condition = union(enum){
            true,
            false,
            runtime,
        };
    };

    fn referenceGlobalDeclaration(builder: *Builder, unit: *Unit, context: *const Context, scope: *Debug.Scope, declaration: *Debug.Declaration) !V{
        // TODO: implement this
        assert(declaration.kind == .global);
        const old_context = builder.startContextSwitch(.{
            .scope = scope,
            .file = scope.file,
            .basic_block = .null,
        });

        const global_declaration = @fieldParentPtr(Debug.Declaration.Global, "declaration", declaration);
        switch (global_declaration.initial_value) {
            .unresolved => |declaration_node_index| {
                assert(declaration.type == .null);
                switch (global_declaration.type_node_index) {
                    .null => {},
                    else => |type_node_index| {
                        declaration.type = try builder.resolveType(unit, context, type_node_index);
                    },
                }

                const type_expect = switch (declaration.type) {
                    .null => Type.Expect.none,
                    else => Type.Expect{
                        .type = declaration.type,
                    },
                };

                global_declaration.initial_value = try builder.resolveComptimeValue(unit, context, type_expect, global_declaration.attributes, declaration_node_index);

                switch (declaration.type) {
                    .null => {
                        assert(global_declaration.type_node_index == .null);
                        declaration.type = global_declaration.initial_value.getType(unit);
                    },
                    else => {},
                }

                switch (global_declaration.initial_value) {
                    .function_definition => {
                        try unit.code_to_emit.append(context.allocator, global_declaration);
                    },
                    .type => |type_index| {
                        assert(declaration.type == .type);
                        unit.type_declarations.put(context.allocator, type_index, global_declaration) catch {
                            assert(unit.type_declarations.get(type_index).? == global_declaration);
                        };
                    },
                    else => {
                        if (global_declaration.attributes.contains(.@"export") or declaration.mutability == .@"var") {
                            try unit.data_to_emit.append(context.allocator, global_declaration);
                        }
                    },
                }
            },
            else => {},
        }

        builder.endContextSwitch(old_context);

        switch (global_declaration.initial_value) {
            .function_definition => {
                return .{
                    .value = .{
                        .function_reference = global_declaration,
                    },
                    .type = global_declaration.declaration.type,
                };
            },
            else => {
                if (declaration.mutability == .@"const") {
                    return .{
                        .value = .{
                            .@"comptime" = global_declaration.initial_value,
                        },
                        .type = declaration.type,
                    };
                } else {
                    const instruction = try unit.instructions.append(context.allocator, .{
                        .global = global_declaration,
                    });
                    return .{
                        .value = .{
                            .runtime = instruction,
                        },
                        .type = declaration.type,// TODO: fetch proper type
                    };
                }
            },
        }
    }

    const ContextSwitch = struct{
        scope: *Debug.Scope,
        file: Debug.File.Index,
        basic_block: BasicBlock.Index,
    };

    fn startContextSwitch(builder: *Builder, new: ContextSwitch) ContextSwitch {
        const old = ContextSwitch{
            .scope = builder.current_scope,
            .file = builder.current_file,
            .basic_block = builder.current_basic_block,
        };

        builder.current_scope = new.scope;
        builder.current_basic_block = new.basic_block;
        builder.current_file = new.file;

        return old;
    }

    fn endContextSwitch(builder: *Builder, old: ContextSwitch) void {
        builder.current_scope = old.scope;
        builder.current_basic_block = old.basic_block;
        builder.current_file = old.file;
    }

    fn resolveImport(builder: *Builder, unit: *Unit, context: *const Context, type_expect: Type.Expect, arguments: []const Node.Index) !Debug.File.Index {
        switch (type_expect) {
            .none => {},
            .type => |type_index| if (type_index != .type) @panic("expected type"),
            else => unreachable,
        }
        if (arguments.len != 1) {
            @panic("Import argument mismatch");
        }

        const argument_node_index = arguments[0];
        const argument_node = unit.getNode(argument_node_index);
        if (argument_node.id != .string_literal) {
            @panic("Import expected a string literal as an argument");
        }

        const string_literal_bytes = try unit.fixupStringLiteral(context, argument_node.token);

        const import_file = try unit.importFile(context, builder.current_file, string_literal_bytes);

        if (import_file.file.is_new) {
            const new_file_index = import_file.file.index;
            try unit.generateAbstractSyntaxTreeForFile(context, new_file_index);
            try builder.analyzeFile(unit, context, new_file_index);
            logln(.compilation, .import, "Done analyzing {s}!", .{string_literal_bytes});
        }

        const file = unit.files.get(import_file.file.index);
        assert(file.type != .null);

        return import_file.file.index;
    }

    const ComptimeEvaluationError = error{
        cannot_evaluate,
    };

    fn resolveComptimeValue(builder: *Builder, unit: *Unit, context: *const Context, type_expect: Type.Expect, global_attributes: Debug.Declaration.Global.Attributes, node_index: Node.Index) anyerror!V.Comptime{
        const node = unit.getNode(node_index);
        switch (node.id) {
            .intrinsic => {
                const argument_node_list = unit.getNodeList(node.left);
                const intrinsic_id: IntrinsicId = @enumFromInt(Node.unwrap(node.right));
                switch (intrinsic_id) {
                    .import => {
                        const file_index = try builder.resolveImport(unit, context, type_expect, argument_node_list);
                        const file = unit.files.get(file_index);
                        return .{
                            .type = file.type,
                        };
                    },
                    else => |t| @panic(@tagName(t)),
                }
            },
            .field_access => {
                const result = try builder.resolveFieldAccess(unit, context, type_expect, node_index);
                return switch (result.value) {
                    .@"comptime" => |ct| ct,
                    else => @panic("Expected comptime value, found runtime value"),
                };
            },
            .keyword_false,
            .keyword_true, => return .{
                .@"bool" = node.id == .keyword_true,
            },
            .function_definition => {
                const current_basic_block = builder.current_basic_block;
                defer builder.current_basic_block = current_basic_block;
                builder.current_basic_block = .null;

                const old_exit_blocks = builder.exit_blocks;
                defer builder.exit_blocks = old_exit_blocks;
                builder.exit_blocks = .{};

                const old_phi_node = builder.return_phi;
                defer builder.return_phi = old_phi_node;
                builder.return_phi = .null;

                const old_return_block = builder.return_block;
                defer builder.return_block = old_return_block;
                builder.return_block = .null;

                const function_prototype_node_index = node.left;
                const body_node_index = node.right;

                const function_prototype_index = try builder.resolveFunctionPrototype(unit, context, function_prototype_node_index, global_attributes.contains(.@"export"));
                const function_prototype_type_index = try unit.types.append(context.allocator, .{
                    .function = function_prototype_index,
                });

                const old_function = builder.current_function;
                const token_debug_info = builder.getTokenDebugInfo(unit, node.token);
                builder.current_function = try unit.function_definitions.append(context.allocator, .{
                    .type = function_prototype_type_index,
                    .body = undefined,
                    .scope = .{
                        .scope = Debug.Scope{
                        .line = token_debug_info.line,
                        .column = token_debug_info.column,
                        .kind = .function,
                        .local = true,
                        .level = builder.current_scope.level + 1,
                        .file = builder.current_file,
                        },
                    },
                });

                defer builder.current_function = old_function;

                const function = unit.function_definitions.get(builder.current_function);

                builder.last_check_point = .{};
                assert(builder.current_scope.kind == .file_container or builder.current_scope.kind == .file or builder.current_scope.kind == .container);
                try builder.pushScope(unit, context, &function.scope.scope);
                defer builder.popScope(unit, context) catch unreachable;

                const entry_basic_block = try builder.newBasicBlock(unit, context);
                builder.current_basic_block = entry_basic_block;
                defer builder.current_basic_block = .null;

                const body_node = unit.getNode(body_node_index);
                try builder.insertDebugCheckPoint(unit, context, body_node.token);

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
                        const argument_declaration_index = try unit.argument_declarations.append(context.allocator, .{
                            .declaration = .{
                                .scope = builder.current_scope,
                                .name = argument_name_hash,
                                .type = argument_type_index,
                                .mutability = .@"const",
                                .line = argument_token_debug_info.line,
                                .column = argument_token_debug_info.column,
                                .kind = .argument,
                            },
                        });
                        comptime assert(@TypeOf(argument_declaration_index) == Debug.Declaration.Argument.Index);
                        const argument = unit.argument_declarations.get(argument_declaration_index);

                        try builder.current_scope.declarations.putNoClobber(context.allocator, argument_name_hash, &argument.declaration);

                        const argument_instruction = try unit.instructions.append(context.allocator, .{
                            .argument_declaration = argument,
                        });

                        try builder.appendInstruction(unit, context, argument_instruction);

                        try function.scope.argument_map.putNoClobber(context.allocator, argument, argument_instruction);
                    }
                }

                if (body_node.id == .block) {
                    function.body = try builder.resolveBlock(unit, context, body_node_index);

                    const function_definition_index = builder.current_function;

                    return .{
                        .function_definition = function_definition_index,
                    };
                } else {
                    @panic("Function body is expected to be a block");
                }
            },
            .number_literal => switch (std.zig.parseNumberLiteral(unit.getExpectedTokenBytes(node.token, .number_literal))) {
                .int => |integer| {
                    // const type_index = switch (type_expect) {
                    //     .type => |type_index| b: {
                    //         const ty = unit.types.get(type_index);
                    //         break :b switch (ty.*) {
                    //             .integer => type_index,
                    //             else => |t| @panic(@tagName(t)),
                    //         };
                    //     },
                    //     .none => Type.Index.comptime_int,
                    // };
                    // _ = type_index; // autofix

                    return .{
                        .comptime_int = .{
                            .value = integer,
                            .signedness = .unsigned,
                        },
                    };
                },
                else => |t| @panic(@tagName(t)),
            },
            .undefined => {
                return .undefined;
            },
            .enum_type => {
                const type_index = try builder.resolveContainerType(unit, context, node_index, .@"enum");
                return .{
                    .type = type_index,
                };
            },
            .struct_type => {
                const type_index = try builder.resolveContainerType(unit, context, node_index, .@"struct");
                return .{
                    .type = type_index,
                };
            },
            .@"switch" => {
                const result = try builder.resolveSwitch(unit, context, type_expect, node_index);
                switch (result.value) {
                    .@"comptime" => |ct| {
                        return ct;
                    },
                    .runtime => unreachable,
                    else => unreachable,
                }
            },
            .identifier => {
                const identifier = unit.getExpectedTokenBytes(node.token, .identifier);
                const resolved_value = try builder.resolveIdentifier(unit, context, type_expect, identifier, .left);
                return switch (resolved_value.value) {
                    .@"comptime" => |ct| ct,
                    .runtime => return error.cannot_evaluate,
                    else => unreachable,
                };
            },
            .signed_integer_type => {
                const result =  try builder.resolveIntegerType(unit, context, node_index);
                return .{
                    .type = result,
                };
            },
            .compare_greater_equal => {
                const left = try builder.resolveComptimeValue(unit, context, Type.Expect.none, .{}, node.left);
                const left_type = left.getType(unit);
                const right = try builder.resolveComptimeValue(unit, context, Type.Expect{ .type = left_type }, .{}, node.right);
                _ = right; // autofix
                unreachable;
            },
            else => |t| @panic(@tagName(t)),
        }
    }

    fn referenceArgumentDeclaration(builder: *Builder, unit: *Unit, context: *const Context, scope: *Debug.Scope, declaration: *Debug.Declaration) !V {
        _ = builder; // autofix
        _ = unit; // autofix
        _ = context; // autofix
        assert(declaration.kind == .argument);
        assert(scope.kind == .function);

        const argument_declaration = @fieldParentPtr(Debug.Declaration.Argument, "declaration", declaration);
        const function_scope = @fieldParentPtr(Debug.Scope.Function, "scope", scope);
        const instruction_index = function_scope.argument_map.get(argument_declaration).?;

        return .{
            .value = .{
                .runtime = instruction_index,
            },
            .type = declaration.type,
        };

    }

    fn referenceLocalDeclaration(builder: *Builder, unit:  *Unit, context: *const Context, scope: *Debug.Scope, declaration: *Debug.Declaration) !V {
        _ = builder; // autofix
        _ = unit; // autofix
        _ = context; // autofix
        assert(declaration.kind == .local);
        assert(scope.kind == .block);

        const local_declaration = @fieldParentPtr(Debug.Declaration.Local, "declaration", declaration);
        const local_scope = @fieldParentPtr(Debug.Scope.Local, "scope", scope);
        if (local_scope.local_declaration_map.get(local_declaration)) |instruction_index| {
            return .{
                .value = .{
                    .runtime = instruction_index,
                },
                .type = declaration.type,
            };
        } else {
            return local_declaration.init_value;
        }
    }

    const TypeCheckResult = enum{
        success,
        pointer_var_to_const,
        slice_var_to_const,
        materialize_int,
        optional_wrap,
        sign_extend,
        zero_extend,
    };

    const TypecheckError = error{
    };

    fn typecheck(builder: *Builder, unit: *Unit, context: *const Context, destination_type_index: Type.Index, source_type_index: Type.Index) TypecheckError!TypeCheckResult {
        _ = builder; // autofix
        _ = context; // autofix
        if (destination_type_index == source_type_index) {
            return .success;
        } else {
            const destination = unit.types.get(destination_type_index);
            const source = unit.types.get(source_type_index);
            switch (destination.*) {
                .pointer => |destination_pointer| {
                    switch (source.*) {
                        .pointer => |source_pointer| {
                            if (destination_pointer.type == source_pointer.type) {
                                if (destination_pointer.many == source_pointer.many) {
                                    if (destination_pointer.termination == source_pointer.termination) {
                                        if (destination_pointer.nullable == source_pointer.nullable) {
                                            assert(destination_pointer.mutability != source_pointer.mutability);
                                            assert(destination_pointer.mutability == .@"const");
                                            assert(source_pointer.mutability == .@"var");

                                            return .pointer_var_to_const;
                                        }
                                    }
                                }
                            }

                            unreachable;
                        },
                        else =>|t| @panic(@tagName(t)),
                    }
                },
                .integer => |destination_integer| {
                    switch (source.*) {
                        .integer => |source_integer| {
                            if (destination_integer.signedness == source_integer.signedness) {
                                if (destination_integer.bit_count == source_integer.bit_count) {
                                    unreachable;
                                } else if (destination_integer.bit_count > source_integer.bit_count) {
                                    return switch (destination_integer.signedness) {
                                        .signed => .sign_extend,
                                        .unsigned => .zero_extend,
                                    };
                                }
                            }

                            unreachable;
                        },
                        .comptime_int => {
                            return .materialize_int;
                        },
                        else => |t| @panic(@tagName(t)),
                    }
                },
                .@"struct" => |destination_struct_index| {
                    const destination_struct = unit.structs.get(destination_struct_index);
                    if (destination_struct.optional) {
                        if (unit.optionals.get(source_type_index)) |optional_type_index| {
                            _ = optional_type_index; // autofix
                            return .optional_wrap;
                        } else {
                            unreachable;
                        }
                    } else {
                        unreachable;
                    }

                },
                .slice => |destination_slice| {
                    switch (source.*) {
                        .slice => |source_slice| {
                            if (destination_slice.child_type == source_slice.child_type) {
                                if (destination_slice.termination == source_slice.termination) {
                                    if (destination_slice.nullable == source_slice.nullable) {
                                        assert(destination_slice.mutability != source_slice.mutability);
                                        if (destination_slice.mutability == .@"const" and source_slice.mutability == .@"var") {
                                            return .slice_var_to_const;
                                        }
                                    }
                                }
                                unreachable;
                            }
                            unreachable;
                        },
                        else => |t| @panic(@tagName(t)),
                    }
                },
                // .optional => |destination_optional_element_type_index| {
                //     if (destination_optional_element_type_index == source_type_index) {
                //         return .optional_wrap;
                //     } else {
                //         unreachable;
                //     }
                // },
                else => |t| @panic(@tagName(t)),
            }

            unreachable;
        }
    }

    const Side = enum{
        left,
        right,
    };

    fn resolveIdentifier(builder: *Builder, unit: *Unit, context: *const Context, type_expect: Type.Expect, identifier: []const u8, side: Side) !V {
        const hash = try unit.processIdentifier(context, identifier);

        const look_in_parent_scopes = true;
        if (builder.current_scope.lookupDeclaration(hash, look_in_parent_scopes)) |lookup| {
            // TODO: we could do this better
            // const scope = lookup.scope;
            const preliminary_result: V = switch (lookup.scope.kind) {
                .file_container, .file => try builder.referenceGlobalDeclaration(unit, context, lookup.scope, lookup.declaration),
                .function => try builder.referenceArgumentDeclaration(unit, context, lookup.scope, lookup.declaration),
                .block => try builder.referenceLocalDeclaration(unit, context, lookup.scope, lookup.declaration),
                else => |t| @panic(@tagName(t)),
            };

            const v: V = switch (preliminary_result.value) {
                .runtime => switch (side) {
                    .left => preliminary_result,
                    .right => b: {
                        const instruction = try unit.instructions.append(context.allocator, .{
                            .load = .{
                                .value = preliminary_result,
                            },
                            });

                        try builder.appendInstruction(unit, context, instruction);

                        break :b .{
                            .value = .{
                                .runtime = instruction,
                            },
                            .type = lookup.declaration.type,
                        };
                    },
                },
                .@"comptime", .function_reference => preliminary_result,
                else => |t| @panic(@tagName(t)),
            };

            switch (type_expect) {
                .none => return v,
                .type => |expected_type_index| {
                    const typecheck_result = try builder.typecheck(unit, context, expected_type_index, lookup.declaration.type);
                    switch (typecheck_result) {
                        .success => return v,
                        .zero_extend => {
                            const zero_extend = try unit.instructions.append(context.allocator, .{
                                .cast = .{
                                    .id = .zero_extend,
                                    .value = v,
                                    .type = expected_type_index,
                                },
                            });
                            try builder.appendInstruction(unit, context, zero_extend);

                            return .{
                                .value = .{
                                    .runtime = zero_extend,
                                },
                                .type = expected_type_index,
                            };
                        },
                        .sign_extend => {
                            const sign_extend = try unit.instructions.append(context.allocator, .{
                                .cast = .{
                                    .id = .sign_extend,
                                    .value = v,
                                    .type = expected_type_index,
                                },
                            });
                            try builder.appendInstruction(unit, context, sign_extend);
                            return .{
                                .value = .{
                                    .runtime = sign_extend,
                                },
                                .type = expected_type_index,
                            };
                        },
                        .pointer_var_to_const => {
                            const cast_to_const = try unit.instructions.append(context.allocator, .{
                                .cast = .{
                                    .id = .pointer_var_to_const,
                                    .value = v,
                                    .type = expected_type_index,
                                },
                            });

                            try builder.appendInstruction(unit, context, cast_to_const);
                            return .{
                                .value = .{
                                    .runtime = cast_to_const,
                                },
                                .type = expected_type_index,
                            };
                        },
                        .slice_var_to_const => {
                            const cast_to_const = try unit.instructions.append(context.allocator, .{
                                .cast = .{
                                    .id = .slice_var_to_const,
                                    .value = v,
                                    .type = expected_type_index,
                                },
                            });

                            try builder.appendInstruction(unit, context, cast_to_const);
                            return .{
                                .value = .{
                                    .runtime = cast_to_const,
                                },
                                .type = expected_type_index,
                            };
                        },
                        .materialize_int => {
                            const destination_integer_type = unit.types.get(expected_type_index).integer;
                            const ct_int = v.value.@"comptime".comptime_int;

                            switch (ct_int.signedness) {
                                .unsigned => {
                                    const number_bit_count = @bitSizeOf(@TypeOf(ct_int.value)) - @clz(ct_int.value);
                                    if (destination_integer_type.bit_count < number_bit_count) {
                                        unreachable;
                                    }
                                },
                                .signed => {
                                    if (destination_integer_type.signedness == .unsigned) {
                                        unreachable;
                                    }
                                    unreachable;
                                },
                            }

                            return .{
                                .value = .{
                                    .@"comptime" = .{
                                        .constant_int = .{
                                            .value = ct_int.value,
                                        },
                                    },
                                },
                                .type = expected_type_index,
                            };
                        },
                        .optional_wrap => {
                            const optional_type_index = expected_type_index;
                            switch (unit.types.get(optional_type_index).*) {
                                .@"struct" => |struct_index| {
                                    assert(unit.structs.get(struct_index).optional);
                                    const optional_undefined = V{
                                        .value = .{
                                            .@"comptime" = .undefined,
                                        },
                                        .type = optional_type_index,
                                    };

                                    const insert_value_to_optional = try unit.instructions.append(context.allocator, .{
                                        .insert_value = .{
                                            .expression = optional_undefined,
                                            .index = 0,
                                            .new_value = v,
                                        },
                                        });

                                    try builder.appendInstruction(unit, context, insert_value_to_optional);

                                    const final_insert = try unit.instructions.append(context.allocator, .{
                                        .insert_value = .{
                                            .expression = .{
                                                .value = .{
                                                    .runtime = insert_value_to_optional,
                                                },
                                                .type = optional_type_index,
                                            },
                                            .index = 1,
                                            // This tells the optional is valid (aka not null)
                                            .new_value = .{
                                                .value = .{
                                                    .@"comptime" = .{
                                                        .bool = true,
                                                    },
                                                    },
                                                .type = .bool,
                                            },
                                            },
                                        });

                                    try builder.appendInstruction(unit, context, final_insert);

                                    return .{
                                        .value = .{
                                            .runtime = final_insert,
                                        },
                                        .type = expected_type_index,
                                    };
                                },
                                else => |t| @panic(@tagName(t)),
                            }
                        },
                    }
                },
                .array => |expected_array_descriptor| {
                    const len = switch (unit.types.get(lookup.declaration.type).*) {
                        .array => |array| array.count,
                        else => |t| @panic(@tagName(t)),
                    };
                    const array_type = try unit.getArrayType(context, .{
                        .count = expected_array_descriptor.count orelse len,
                        .termination = expected_array_descriptor.termination,
                        .type = expected_array_descriptor.type,
                    });
                    if (array_type == lookup.declaration.type) {
                        assert(v.type == lookup.declaration.type);
                        return v;
                    } else {
                        unreachable;
                    }
                },
                else => |t| @panic(@tagName(t)),
            }
        } else {
            var scope_it: ?*Debug.Scope = builder.current_scope;
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
                        const global_scope = @fieldParentPtr(Debug.Scope.Global, "scope", scope);
                        const file = @fieldParentPtr(Debug.File, "scope", global_scope);
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
    }

    fn resolveAssignment(builder: *Builder, unit: *Unit, context: *const Context, node_index: Node.Index) !V {
        const node = unit.getNode(node_index);
        switch (node.id) {
            .assign, .add_assign, .sub_assign, .div_assign => {
                if (unit.getNode(node.left).id == .discard) {
                    const r =  try builder.resolveRuntimeValue(unit, context, Type.Expect.none, node.right, .right);
                    return r;
                } else {
                    const left = try builder.resolveRuntimeValue(unit, context, Type.Expect.none, node.left, .left);
                    const expected_right_type = switch (left.value) {
                        .runtime => |instr_index| switch (unit.instructions.get(instr_index).*) {
                            .global => |global| global.declaration.type,
                            .stack_slot => |stack_slot| stack_slot.type,
                            .get_element_pointer => |gep| gep.base_type,
                            else => |t| @panic(@tagName(t)),
                        },
                        else => |t| @panic(@tagName(t)),
                    };
                    const right = try builder.resolveRuntimeValue(unit, context, Type.Expect{ .type = expected_right_type }, node.right, .right);
                    const value_to_store = switch (node.id) {
                        .assign => right,
                        else => blk: {
                            const left_load = try unit.instructions.append(context.allocator, .{
                                .load = .{
                                    .value = left,
                                },
                            });

                            try builder.appendInstruction(unit, context, left_load);

                            const instruction = switch (unit.types.get(left.type).*) {
                                .integer => |integer| {
                                    const instruction = try unit.instructions.append(context.allocator, .{
                                        .integer_binary_operation = .{
                                            .left = .{
                                                .value = .{
                                                    .runtime = left_load,
                                                },
                                                .type = left.type,
                                            },
                                            .right = right,
                                            .signedness = integer.signedness,
                                            .id = switch (node.id) {
                                                .add_assign => .add,
                                                .sub_assign => .sub,
                                                .div_assign => .div,
                                                else => |t| @panic(@tagName(t)),
                                            },
                                        },
                                    });
                                    try builder.appendInstruction(unit, context, instruction);

                                    break :blk V{
                                        .value = .{
                                            .runtime = instruction,
                                        },
                                        .type = left.type,
                                    };
                                },
                                else => |t| @panic(@tagName(t)),
                            };
                            _ = instruction; // autofix
                            unreachable;
                        },
                    };
                    const store = try unit.instructions.append(context.allocator, .{
                        .store = .{
                            .destination = left,
                            .source = value_to_store,
                        },
                    });
                    try builder.appendInstruction(unit, context, store);

                    return .{
                        .value = .{
                            .runtime = store,
                        },
                        .type = .void,
                    };
                }
            },
            else => |t| @panic(@tagName(t)),
        }
    }

    fn newBasicBlock(builder: *Builder, unit: *Unit, context: *const Context) !BasicBlock.Index{
        const function = unit.function_definitions.get(builder.current_function);
        const entry_basic_block = try unit.basic_blocks.append(context.allocator, .{});
        try function.basic_blocks.append(context.allocator, entry_basic_block);

        return entry_basic_block;
    }

    fn resolveIntegerType(builder: *Builder, unit: *Unit, context: *const Context, node_index: Node.Index) anyerror!Type.Index {
        _ = builder; // autofix
        const node = unit.getNode(node_index);
        const result: Type.Index = switch (node.id) {
            .signed_integer_type, .unsigned_integer_type, => b: {
                const token_bytes = unit.getExpectedTokenBytes(node.token, switch (node.id) {
                    .signed_integer_type => .keyword_signed_integer,
                    .unsigned_integer_type => .keyword_unsigned_integer,
                    else => unreachable,
                });

                const number_chunk = token_bytes[1..];
                const type_index = try unit.getIntegerType(context, .{
                    .bit_count = try std.fmt.parseInt(u16, number_chunk, 10),
                    .signedness = switch (node.id) {
                        .signed_integer_type => .signed,
                        .unsigned_integer_type => .unsigned,
                        else => unreachable,
                    },
                });
                break :b type_index;
            },
            else => unreachable,
        };

        return result;
    }

    fn resolveArrayType(builder: *Builder, unit: *Unit, context: *const Context, node_index: Node.Index, size_hint: ?usize) !Type.Index{
        const node = unit.getNode(node_index);
        const attribute_node_list = unit.getNodeList(node.left);
        assert(attribute_node_list.len == 2);
        const termination = Type.Termination.none;
        const len_node = unit.getNode(attribute_node_list[0]);
        const len = switch (len_node.id) {
            else => switch (try builder.resolveComptimeValue(unit, context, Type.Expect{ .type = .usize }, .{}, attribute_node_list[0])) {
                .comptime_int => |ct_int| ct_int.value,
                else => |t| @panic(@tagName(t)),
            },
            .discard => size_hint orelse unreachable,
        };
        const element_type = try builder.resolveType(unit, context, attribute_node_list[1]);
        const array_type = try unit.getArrayType(context, .{
            .count = len,
            .type = element_type,
            .termination = termination,
        });
        return array_type;
    }

    fn resolveType(builder: *Builder, unit: *Unit, context: *const Context, node_index: Node.Index) anyerror!Type.Index {
        const node = unit.getNode(node_index);

        const result: Type.Index = switch (node.id) {
            .keyword_noreturn => .noreturn,
            .usize_type => .usize,
            .void_type => .void,
            .identifier, .field_access => {
                const resolved_type_value = try builder.resolveComptimeValue(unit, context, Type.Expect{ .type = .type }, .{}, node_index);
                return resolved_type_value.type;
            },
            .bool_type => .bool,
            .ssize_type => .ssize,
            .signed_integer_type, .unsigned_integer_type, => b: {
                break :b try builder.resolveIntegerType(unit, context, node_index);
            },
            .pointer_type => b: {
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

                            element_type_index = try builder.resolveType(unit, context, element_node_index);
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

                const pointer_type = try unit.getPointerType(context, .{
                    .mutability = mutability,
                    .many = many,
                    .type = element_type_index,
                    .termination = termination,
                    .nullable = false,
                });
                break :b pointer_type;
            },
            .slice_type => b: {
                const attribute_node_list = unit.getNodeList(node.left);
                var mutability = Mutability.@"var";
                var element_type_index = Type.Index.null;
                var termination = Type.Termination.none;

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
                        .slice_type,
                        => {
                            if (element_type_index != .null) {
                                unreachable;
                            }

                            element_type_index = try builder.resolveType(unit, context, element_node_index);
                        },
                        .const_expression => mutability = .@"const",
                        .zero_terminated => {
                            assert(termination == .none);
                            termination = .zero;
                        },
                        .null_terminated => {
                            assert(termination == .none);
                            termination = .null;
                        },
                        else => |t| @panic(@tagName(t)),
                    }
                }

                assert(element_type_index != .null);

                const nullable = false;

                const slice_type = try unit.getSliceType(context, .{
                    .mutability = mutability,
                    .child_type = element_type_index,
                    .child_pointer_type = try unit.getPointerType(context, .{
                        .type = element_type_index,
                        .termination = termination,
                        .mutability = mutability,
                        .many = true,
                        .nullable = nullable,
                    }),
                    .termination = termination,
                    .nullable = nullable,
                });
                break :b slice_type;
            },
            .array_type => try builder.resolveArrayType(unit, context, node_index, null),
            .optional_type => blk: {
                const element_type_index = try builder.resolveType(unit, context, node.left);
                const element_type = unit.types.get(element_type_index);
                const r = switch (element_type.*) {
                    .pointer => |pointer| b: {
                        var nullable_pointer = pointer;
                        assert(!nullable_pointer.nullable);
                        nullable_pointer.nullable = true;
                        break :b try unit.getPointerType(context, nullable_pointer);
                    },
                    .slice => |slice| b: {
                        var nullable_slice = slice;
                        assert(!nullable_slice.nullable);
                        nullable_slice.nullable = true;
                        break :b try unit.getSliceType(context, nullable_slice);
                    },
                    else => b: {
                        const optional_type = try unit.getOptionalType(context, element_type_index);
                        break :b optional_type;
                    },
                };
                break :blk r;
            },
            else => |t| @panic(@tagName(t)),
        };

        return result;
    }

    fn resolveFunctionPrototype(builder: *Builder, unit: *Unit, context: *const Context, node_index: Node.Index, is_export: bool) !Function.Prototype.Index {
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
                // .@"export" = false,
                .naked = false,
            },
            .calling_convention = switch (is_export) {
                true => .c,
                false => .auto,
            },
        });


        var is_naked: bool = false;

        // Resolve attributes
        for (attribute_node_list) |attribute_node_index| {
            const attribute_node = unit.getNode(attribute_node_index);
            switch (attribute_node.id) {
                .function_attribute_naked => is_naked = true,
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

                const argument_type_index = try builder.resolveType(unit, context, argument_node.left);
                argument_types.appendAssumeCapacity(argument_type_index);
            }

            function_prototype.argument_types = argument_types.items;
        }

        function_prototype.attributes = .{
            .naked = is_naked,
        };

        function_prototype.return_type = try builder.resolveType(unit, context, return_type_node_index);

        return function_prototype_index;
    }

    fn resolveContainerType(builder: *Builder, unit: *Unit, context: *const Context, container_node_index: Node.Index, container_type: ContainerType) !Type.Index {
        const current_basic_block = builder.current_basic_block;
        defer builder.current_basic_block = current_basic_block;
        builder.current_basic_block = .null;

        const container_node = unit.getNode(container_node_index);
        const container_nodes = unit.getNodeList(container_node.left);

        const Data = struct{
            scope: *Debug.Scope.Global,
            type: Type.Index,
        };

        const backing_type: Type.Index = switch (container_node.right) {
            .null => .null,
            else => |backing_type_node_index| b: {
                switch (builder.current_scope.kind) {
                    .file => unreachable,
                    else => {
                        const backing_type_index = try builder.resolveType(unit, context, backing_type_node_index);
                        const backing_type = unit.types.get(backing_type_index);
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
        };

        const token_debug_info = builder.getTokenDebugInfo(unit, container_node.token);
        const data: Data = switch (container_type) {
            .@"struct" => b: {
                assert(container_node.id == .struct_type);
                const struct_index = try unit.structs.append(context.allocator, .{
                    .scope = .{
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
                    },
                    .backing_type = backing_type,
                    .optional = false,
                    .type = .null,
                });
                const struct_type = unit.structs.get(struct_index);

                const type_index = try unit.types.append(context.allocator, .{
                    .@"struct" = struct_index,
                });

                struct_type.type = type_index;

                // Save file type
                switch (builder.current_scope.kind) {
                    .file => {
                        const global_scope = @fieldParentPtr(Debug.Scope.Global, "scope", builder.current_scope);
                        const file = @fieldParentPtr(Debug.File, "scope", global_scope);
                        file.type = type_index;
                    },
                    .file_container => {},
                    // .file_container => {
                    //     const global_scope = @fieldParentPtr(Debug.Scope.Global, "scope", builder.current_scope);
                    //     const file = @fieldParentPtr(Debug.File, "scope", global_scope);
                    //     file.type = type_index;
                    // },
                    else => |t| @panic(@tagName(t)),
                }

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
                        .scope = .{
                            .kind = .container,
                            .line = token_debug_info.line,
                            .column = token_debug_info.column,
                            .level = builder.current_scope.level + 1,
                            .local = false,
                            .file = builder.current_file,
                        }
                    },
                    .backing_type = backing_type,
                });

                const enum_type = unit.enums.get(enum_index);
                const type_index = try unit.types.append(context.allocator, .{
                    .@"enum" = enum_index,
                });
                break :b .{
                    .scope = &enum_type.scope,
                    .type = type_index,
                };
            },
        };

        const scope = data.scope;
        const type_index = data.type;
        try builder.pushScope(unit, context, &scope.scope);
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
                        const metadata_node_index = declaration_node.left;
                        const metadata_node_result: struct {
                            type_node_index: Node.Index,
                            attributes_node_index: Node.Index,
                        } = if (metadata_node_index != .null) b: {
                            const metadata_node = unit.getNode(metadata_node_index);

                            break :b .{
                                .type_node_index = metadata_node.left,
                                .attributes_node_index = metadata_node.right,
                            };
                        } else .{
                            .type_node_index = .null,
                            .attributes_node_index = .null,
                        };

                        const type_node_index = metadata_node_result.type_node_index;
                        const attributes_node_index = metadata_node_result.attributes_node_index;
                        const attributes: Debug.Declaration.Global.Attributes = switch (attributes_node_index) {
                            .null => Debug.Declaration.Global.Attributes.initEmpty(),
                            else => b: {
                                var res = Debug.Declaration.Global.Attributes.initEmpty();
                                const attribute_nodes = unit.getNodeList(attributes_node_index);
                                for (attribute_nodes) |attribute_node_index| {
                                    const attribute_node = unit.getNode(attribute_node_index);
                                    switch (attribute_node.id) {
                                        .symbol_attribute_export => res.setPresent(.@"export", true),
                                        else => |t| @panic(@tagName(t)),
                                    }
                                }

                                break :b res;
                            }
                        };

                        const value_node_index = declaration_node.right;

                        const declaration_token_debug_info = builder.getTokenDebugInfo(unit, declaration_node.token);
                        const mutability: Mutability = switch (declaration_node.id) {
                            .constant_symbol_declaration => .@"const",
                            .variable_symbol_declaration => .@"var",
                            else => unreachable,
                        };
                                                          //
                        const global_declaration_index = try unit.global_declarations.append(context.allocator, .{
                            .declaration = .{
                                .scope = &scope.scope,
                                .name = identifier_hash,
                                .type = .null,
                                .line = declaration_token_debug_info.line,
                                .column = declaration_token_debug_info.column,
                                .mutability = mutability,
                                .kind = .global,
                            },
                            .initial_value = .{
                                .unresolved = value_node_index,
                            },
                            .type_node_index = type_node_index,
                            .attributes = attributes,
                        });

                        const global_declaration = unit.global_declarations.get(global_declaration_index);
                        try builder.current_scope.declarations.putNoClobber(context.allocator, identifier_hash, &global_declaration.declaration);
                    },
                    else => unreachable,
                }
            }
        }

        if (count.fields > 0) {
            const ty = unit.types.get(type_index);
            switch (container_type) {
                .@"enum" => {
                    const enum_type = unit.enums.get(ty.@"enum");
                    const field_count = field_nodes.items.len;
                    try enum_type.fields.ensureTotalCapacity(context.allocator, field_count);

                    if (enum_type.backing_type == .null) {
                        const bit_count = @bitSizeOf(@TypeOf(field_nodes.items.len)) - @clz(field_nodes.items.len);

                        enum_type.backing_type = try unit.getIntegerType(context, .{
                            .bit_count = bit_count,
                            .signedness = .unsigned,
                        });
                    }
                },
                .@"struct" => {
                    const struct_type = unit.structs.get(ty.@"struct");
                    const field_count = field_nodes.items.len;
                    try struct_type.fields.ensureTotalCapacity(context.allocator, field_count);
                },
            }

            for (field_nodes.items, 0..) |field_node_index, index| {
                const field_node = unit.getNode(field_node_index);
                const identifier = unit.getExpectedTokenBytes(field_node.token, .identifier);
                const hash = try unit.processIdentifier(context, identifier);

                switch (container_type) {
                    .@"enum" => {
                        assert(field_node.id == .@"enum_field");
                        const enum_type = unit.enums.get(ty.@"enum");

                        const enum_value: usize = switch (field_node.left) {
                            .null => index,
                            else => b: {
                                const enum_value = try builder.resolveComptimeValue(unit, context, Type.Expect{
                                    .type = enum_type.backing_type,
                                }, .{},
                                //Debug.Declaration.Global.Attributes.initEmpty(),
                                field_node.left);
                                assert(enum_value.comptime_int.signedness == .unsigned);
                                break :b enum_value.comptime_int.value;
                            },
                        };

                       const enum_field_index = try unit.enum_fields.append(context.allocator, .{
                           .name = hash,
                           .value = enum_value,
                           .parent = type_index,
                       });
                       enum_type.fields.appendAssumeCapacity(enum_field_index);
                    },
                   .@"struct" => {
                        assert(field_node.id == .@"container_field");
                        const struct_type = unit.structs.get(ty.@"struct");
                        const field_name = unit.getExpectedTokenBytes(field_node.token, .identifier);
                        const field_name_hash  = try unit.processIdentifier(context, field_name);
                        const field_type = try builder.resolveType(unit, context, field_node.left);
                        const field_default_value: ?V.Comptime = switch (field_node.right) {
                            .null => null,
                            else => |default_value_node_index| try builder.resolveComptimeValue(unit, context, Type.Expect{ .type = field_type }, .{}, default_value_node_index),
                        };

                        const struct_field = try unit.struct_fields.append(context.allocator, .{
                            .name = field_name_hash,
                            .type = field_type,
                            .default_value = field_default_value,
                        });
                        struct_type.fields.appendAssumeCapacity(struct_field);
                   },
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

                assert(comptime_node.left != .null);
                assert(comptime_node.right == .null);

                const left_node = unit.getNode(comptime_node.left);
                switch (left_node.id) {
                    .block => {
                        const block = try builder.resolveBlock(unit, context, comptime_node.left);
                        _ = block; // autofix
                    },
                    else => |t| @panic(@tagName(t)),
                }
            }
        }

        return type_index;
    }

    fn resolveRuntimeValue(builder: *Builder, unit: *Unit, context: *const Context, type_expect: Type.Expect, node_index: Node.Index, side: Side) anyerror!V{
        const node = unit.getNode(node_index);

        const v : V = switch (node.id) {
            .identifier => block: {
                const identifier = unit.getExpectedTokenBytes(node.token, .identifier);
                const result = try builder.resolveIdentifier(unit, context, type_expect, identifier, side);
                break :block result;
            },
            .intrinsic => try builder.resolveIntrinsic(unit, context, type_expect, node_index),
            .pointer_dereference => block: {
                // TODO: 
                const pointer_type_expect = switch (type_expect) {
                    .none => unreachable,//type_expect,
                    .type => |type_index| b: {
                        const pointer_type = try unit.getPointerType(context, .{
                            .type = type_index,
                            .mutability = .@"const",
                            .many = false, // TODO
                            .termination = .none, // TODO
                            .nullable = false,
                        });
                        const result = Type.Expect{
                            .type = pointer_type,
                        };
                        break :b result;
                    }, 
                    else => unreachable,
                };

                // TODO: is this right? .right
                const pointer_value = try builder.resolveRuntimeValue(unit, context, pointer_type_expect, node.left, .right);

                const load = try unit.instructions.append(context.allocator, .{
                    .load = .{
                        .value = pointer_value,
                    },
                });
                try builder.appendInstruction(unit, context, load);

                const load_type = switch (type_expect) {
                    .none => unreachable,
                    .type => |type_index| type_index,
                    else => unreachable,
                };

                break :block .{
                    .value = .{
                        .runtime = load,
                    },
                    .type = load_type,
                };
            },
            .compare_equal, .compare_not_equal, .compare_greater, .compare_greater_equal, .compare_less, .compare_less_equal, => |cmp_node_id| block: {
                const left_node_index = node.left;
                const right_node_index = node.right;
                const left_expect_type = Type.Expect.none;
                const left_value = try builder.resolveRuntimeValue(unit, context, left_expect_type, left_node_index, .right);
                const left_type = left_value.type;
                const right_expect_type = Type.Expect{ .type = left_type };
                const right_value = try builder.resolveRuntimeValue(unit, context, right_expect_type, right_node_index, .right);

                switch (unit.types.get(left_type).*) {
                    .integer => |integer| {
                        const compare = try unit.instructions.append(context.allocator, .{
                            .integer_compare = .{
                                .left = left_value,
                                .right = right_value,
                                .type = left_type,
                                .id = switch (cmp_node_id) {
                                    .compare_equal => .equal,
                                    .compare_not_equal => .not_equal,
                                    else => switch (integer.signedness) {
                                        .unsigned => switch (cmp_node_id) {
                                            .compare_less => .unsigned_less,
                                            .compare_less_equal => .unsigned_less_equal,
                                            .compare_greater => .unsigned_greater,
                                            .compare_greater_equal => .unsigned_greater_equal,
                                            else => unreachable,
                                        },
                                        .signed => switch (cmp_node_id) {
                                            .compare_less => .signed_less,
                                            .compare_less_equal => .signed_less_equal,
                                            .compare_greater => .signed_greater,
                                            .compare_greater_equal => .signed_greater_equal,
                                            else => unreachable,
                                        },
                                    }
                                },
                            },
                        });
                        try builder.appendInstruction(unit, context, compare);

                        break :block .{
                            .value = .{
                                .runtime = compare,
                            },
                            .type = .bool,
                        };
                    },
                    else => |t| @panic(@tagName(t)),
                }
            },
            .add, .sub, .mul, .div, .mod, .bit_and, .bit_or, .bit_xor, .shift_left, .shift_right => block: {
                const left_node_index = node.left;
                const right_node_index = node.right;
                const binary_operation_id: ArithmeticLogicIntegerInstruction = switch (node.id) {
                    .add => .add,
                    .sub => .sub,
                    .mul => .mul,
                    .div => .div,
                    .mod => .mod,
                    .bit_and => .bit_and,
                    .bit_xor => .bit_xor,
                    .bit_or => .bit_or,
                    .shift_left => .shift_left,
                    .shift_right => .shift_right,
                    else => |t| @panic(@tagName(t)),
                };

                const left_expect_type = type_expect;

                const left_value = try builder.resolveRuntimeValue(unit, context, left_expect_type, left_node_index, .right);
                const left_type = left_value.type;
                switch (unit.types.get(left_type).*) {
                    .integer => {},
                    else => |t| @panic(@tagName(t)),
                }

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
                    },
                    else => unreachable,
                };
                const right_value = try builder.resolveRuntimeValue(unit, context, right_expect_type, right_node_index, .right);

                const type_index = switch (type_expect) {
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
                    else => unreachable,
                };

                assert(left_value.type == right_value.type);

                const instruction = switch (unit.types.get(left_type).*) {
                    .integer => |integer| b: {
                        const id: Instruction.IntegerBinaryOperation.Id = switch (binary_operation_id) {
                            .add => .add,
                            .div => .div,
                            .mod => .mod,
                            .mul => .mul,
                            .sub => .sub,
                            .bit_and => .bit_and,
                            .bit_or => .bit_or,
                            .bit_xor => .bit_xor,
                            .shift_left => .shift_left,
                            .shift_right => .shift_right,
                        };

                        const i = try unit.instructions.append(context.allocator, .{
                            .integer_binary_operation = .{
                                .left = left_value,
                                .right = right_value,
                                .id = id,
                                .signedness = integer.signedness,
                            },
                        });
                        break :b i;
                    },
                    else => |t| @panic(@tagName(t)),
                };

                try builder.appendInstruction(unit, context, instruction);

                break :block .{
                    .value = .{
                        .runtime = instruction,
                    },
                    .type = type_index,
                };
            },
            .call => try builder.resolveCall(unit, context, node_index),
            .field_access => try builder.resolveFieldAccess(unit, context, type_expect, node_index),
            .number_literal => switch (std.zig.parseNumberLiteral(unit.getExpectedTokenBytes(node.token, .number_literal))) {
                .int => |integer| switch (type_expect) {
                    .type => |type_index| switch (unit.types.get(type_index).*) {
                        .integer => V{
                            .value = .{
                                .@"comptime" = .{
                                    .constant_int = .{
                                        .value = integer,
                                    },
                                },
                            },
                            .type = type_index,
                        },
                        else => |t| @panic(@tagName(t)),
                    },
                    .none => V{
                        .value = .{
                            .@"comptime" = .{
                                .comptime_int = .{
                                    .value = integer,
                                    .signedness = .unsigned,
                                },
                            },
                        },
                        .type = .comptime_int,
                    },
                    else => unreachable,
                },
                else => |t| @panic(@tagName(t)),
            },
            .assign, .add_assign => block: {
                assert(type_expect == .none or type_expect.type == .void);
                const result = try builder.resolveAssignment(unit, context, node_index);
                break :block result;
            },
            .block => block: {
                assert(type_expect == .none or type_expect.type == .void);
                const block = try builder.resolveBlock(unit, context, node_index);
                const block_i = try unit.instructions.append(context.allocator, .{
                    .block = block,
                });

                // if (builder.current_basic_block != .null) {
                //     try builder.appendInstruction(unit, context, block_i);
                // }

                break :block .{
                    .value = .{
                        .runtime = block_i,
                    },
                    .type = .void,
                };
            },
            .container_literal => block: {
                assert(node.left != .null);
                assert(node.right != .null);

                const container_type_index = try builder.resolveType(unit, context, node.left);
                const container_type = unit.types.get(container_type_index);

                const initialization_nodes = unit.getNodeList(node.right);

                switch (container_type.*) {
                    .@"struct" => |struct_index| {
                        const struct_type = unit.structs.get( struct_index);
                        const fields = struct_type.fields.items;
                        var list = try ArrayList(V).initCapacity(context.allocator, fields.len);
                        var is_comptime = true;

                        for (fields) |field_index| {
                            const field = unit.struct_fields.get(field_index);

                            for (initialization_nodes) |initialization_node_index| {
                                const initialization_node = unit.getNode(initialization_node_index);
                                assert(initialization_node.id == .container_field_initialization);
                                assert(initialization_node.left != .null);
                                assert(initialization_node.right == .null);
                                const field_name = unit.getExpectedTokenBytes(Token.addInt(initialization_node.token, 1), .identifier);
                                const field_name_hash = try unit.processIdentifier(context, field_name);
                                if (field_name_hash == field.name) {
                                    const expected_type = field.type;
                                    const field_initialization = try builder.resolveRuntimeValue(unit, context, Type.Expect{ .type = expected_type }, initialization_node.left, .right);
                                    is_comptime = is_comptime and field_initialization.value == .@"comptime";
                                    list.appendAssumeCapacity(field_initialization);
                                    break;
                                }
                                unreachable;
                            } else if (field.default_value) |default_value| {
                                _ = default_value; // autofix
                                unreachable;
                            } else {
                                @panic("Missing field");
                            }
                        }

                        if (is_comptime) {
                            var comptime_list = try ArrayList(V.Comptime).initCapacity(context.allocator, fields.len);
                            for (list.items) |item| {
                                comptime_list.appendAssumeCapacity(item.value.@"comptime");
                            }

                            break :block .{
                                .value = .{
                                    .@"comptime" = .{
                                        .constant_struct = try unit.constant_structs.append(context.allocator, .{
                                            .fields = comptime_list.items,
                                            .type = container_type_index,
                                        }),
                                    },
                                },
                                .type = container_type_index,
                            };
                        } else {
                            var struct_initialization = V{
                                .value = .{
                                    .@"comptime" = .undefined,
                                },
                                .type = container_type_index,
                            };

                            for (list.items, 0..) |field, index| {
                                const struct_initialization_instruction = try unit.instructions.append(context.allocator, .{
                                    .insert_value = .{
                                        .expression = struct_initialization,
                                        .index = @intCast(index),
                                        .new_value = field,
                                    },
                                });

                                try builder.appendInstruction(unit, context, struct_initialization_instruction);

                                struct_initialization.value = .{
                                    .runtime = struct_initialization_instruction,
                                };

                            }

                            break :block struct_initialization;
                        }
                    },
                    else => |t| @panic(@tagName(t)),
                }
            },
            .enum_literal => block: {
                switch (type_expect) {
                    .type => |type_index| {
                        const expected_type = unit.types.get(type_index);
                        switch (expected_type.*) {
                            .@"enum" => |enum_index| {
                                const enum_type = unit.enums.get(enum_index);
                                const identifier = unit.getExpectedTokenBytes(Token.addInt( node.token, 1), .identifier);
                                const hash = try unit.processIdentifier(context, identifier);
                                for (enum_type.fields.items) |field_index| {
                                    const field = unit.enum_fields.get(field_index);
                                    if (field.name == hash) {
                                        break :block V{
                                            .value = .{
                                                .@"comptime" = .{
                                                    .enum_value = field_index,
                                                },
                                            },
                                            .type = type_index,
                                        };
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
            .null_literal => switch (type_expect) {
                .type => |type_index| switch (unit.types.get(type_index).*) {
                    .@"struct" => |struct_index| {
                        const struct_type = unit.structs.get(struct_index);
                        if (struct_type.optional) {
                            const optional_undefined = V{
                                .value = .{
                                    .@"comptime" = .undefined,
                                },
                                .type = type_index,
                            };

                            const final_insert = try unit.instructions.append(context.allocator, .{
                                .insert_value = .{
                                    .expression = optional_undefined,
                                    .index = 1,
                                    // This tells the optional is valid (aka not null)
                                    .new_value = .{
                                        .value = .{
                                            .@"comptime" = .{
                                                .bool = true,
                                            },
                                        },
                                        .type = .bool,
                                    },
                                },
                            });

                            try builder.appendInstruction(unit, context, final_insert);

                            return .{
                                .value = .{
                                    .runtime = final_insert,
                                },
                                .type = type_index,
                            };
                        } else {
                            unreachable;
                        }
                    },
                    // .optional => .{
                    //     .value = .{
                    //         .@"comptime" = .optional_null_literal,
                    //     },
                    //     .type = type_index,
                    // },
                    else => |t| @panic(@tagName(t)),
                },
                else => |t| @panic(@tagName(t)),
            },
            .slice => blk: {
                const expression_to_slice = try builder.resolveRuntimeValue(unit, context, Type.Expect.none, node.left, .right);
                const range_node = unit.getNode(node.right);
                assert(range_node.id == .range);
                const range_start: V = try builder.resolveRuntimeValue(unit, context, Type.Expect{ .type = .usize }, range_node.left, .right);
                const range_end: V = switch (range_node.right) {
                    .null => switch (unit.types.get(expression_to_slice.type).*) {
                        .slice => b: {
                            const extract_value = try unit.instructions.append(context.allocator, .{
                                .extract_value = .{
                                    .expression = expression_to_slice,
                                    .index = 1,
                                },
                            });
                            try builder.appendInstruction(unit, context, extract_value);

                            break :b .{
                                .value = .{
                                    .runtime = extract_value,
                                },
                                .type = .usize,
                            };
                        },
                        .pointer => |pointer| switch (unit.types.get( pointer.type).*) {
                            .array => |array| .{
                                .value = .{
                                    .@"comptime" = .{
                                        .constant_int = .{
                                            .value = array.count,
                                        },
                                    },
                                },
                                .type = .usize,
                            },
                            else => |t| @panic(@tagName(t)),
                        },
                        else => |t| @panic(@tagName(t)),
                    },
                    else => try builder.resolveRuntimeValue(unit, context, Type.Expect{ .type = .usize }, range_node.right, .right),
                };

                switch (unit.types.get(expression_to_slice.type).*) {
                    .slice => |slice| {
                        const extract_value = try unit.instructions.append(context.allocator, .{
                            .extract_value = .{
                                .expression = expression_to_slice,
                                .index = 0,
                            },
                        });
                        try builder.appendInstruction(unit, context, extract_value);

                        const pointer_type = slice.child_pointer_type;
                        const pointer_gep = try unit.instructions.append(context.allocator, .{
                            .get_element_pointer = .{
                                .pointer = extract_value,
                                .base_type = slice.child_type,
                                .index = range_start,
                            },
                        });
                        try builder.appendInstruction(unit, context, pointer_gep);

                        const slice_builder = try unit.instructions.append(context.allocator, .{
                            .insert_value = .{
                                .expression = V{
                                    .value = .{
                                        .@"comptime" = .undefined,
                                    },
                                    .type = expression_to_slice.type,
                                },
                                .index = 0,
                                .new_value = .{
                                    .value = .{
                                        .runtime = pointer_gep,
                                    },
                                    .type = pointer_type,
                                },
                            },
                        });
                        try builder.appendInstruction(unit, context, slice_builder);

                        const range_compute = try unit.instructions.append(context.allocator, .{
                            .integer_binary_operation = .{
                                .left = range_end,
                                .right = range_start,
                                .id = .sub,
                                .signedness = .unsigned,
                            },
                        });

                        try builder.appendInstruction(unit, context, range_compute);

                        const final_slice = try unit.instructions.append(context.allocator, .{
                            .insert_value = .{
                                .expression = V{
                                    .value = .{
                                        .runtime = slice_builder,
                                    },
                                    .type = expression_to_slice.type,
                                },
                                .index = 1,
                                .new_value = .{
                                    .value = .{
                                        .runtime = range_compute,
                                    },
                                    .type = .usize,
                                },
                            },
                        });

                        try builder.appendInstruction(unit, context, final_slice);

                        break :blk .{
                            .value = .{
                                .runtime = final_slice,
                            },
                            .type = expression_to_slice.type,
                        };
                    },
                    .pointer => |pointer| switch (pointer.many) {
                        true => unreachable,
                        false => switch (unit.types.get(pointer.type).*) {
                            .array => |array| {
                                const slice_builder = try unit.instructions.append(context.allocator, .{
                                    .insert_value = .{
                                        .expression = V{
                                            .value = .{
                                                .@"comptime" = .undefined,
                                            },
                                            .type = switch (type_expect) {
                                                .type => |type_index| type_index,
                                                else => |t| @panic(@tagName(t)),
                                            },
                                        },
                                        .index = 0,
                                        .new_value = expression_to_slice,
                                    },
                                });
                                try builder.appendInstruction(unit, context, slice_builder);

                                const final_slice = try unit.instructions.append(context.allocator, .{
                                    .insert_value = .{
                                        .expression = V{
                                            .value = .{
                                                .runtime = slice_builder,
                                            },
                                            .type = expression_to_slice.type,
                                        },
                                        .index = 1,
                                        .new_value = .{
                                            .value = .{
                                                .@"comptime" = .{
                                                    .constant_int = .{
                                                        .value = array.count,
                                                    },
                                                },
                                            },
                                            .type = .usize,
                                        },
                                    },
                                });
                                try builder.appendInstruction(unit, context, final_slice);

                                break :blk .{
                                    .value = .{
                                        .runtime = final_slice,
                                    },
                                    .type = switch (type_expect) {
                                        .type => |type_index| type_index,
                                        else => |t| @panic(@tagName(t)),
                                    },
                                };
                            },
                            else => |t| @panic(@tagName(t)),
                        },
                    },
                    else => |t| @panic(@tagName(t)),
                }
            },
            .keyword_false, .keyword_true => .{
                .value = .{
                    .@"comptime" = .{
                        .bool = node.id == .keyword_true,
                    },
                },
                .type = .bool,
            },
            .string_literal => switch (type_expect) {
                .type => |type_index| switch (unit.types.get(type_index).*) {
                    .slice => |slice| blk: {
                        assert(slice.child_type == .u8);
                        assert(!slice.nullable);
                        assert(slice.mutability == .@"const");

                        const string_global = try builder.processStringLiteral(unit, context, node.token);

                        const pointer_type = slice.child_pointer_type;
                        const instruction = try unit.instructions.append(context.allocator, .{
                            .global = string_global,
                        });
                        // try builder.appendInstruction(instruction);

                        const global_string_pointer = .{
                            .value = .{
                                .runtime = instruction,
                            },
                            .type = pointer_type,
                        };

                        const slice_builder = try unit.instructions.append(context.allocator, .{
                            .insert_value = .{
                                .expression = V{
                                    .value = .{
                                        .@"comptime" = .undefined,
                                    },
                                    .type = type_index,
                                },
                                .index = 0,
                                .new_value = global_string_pointer,
                            },
                        });
                        try builder.appendInstruction(unit, context, slice_builder);

                        const len = unit.types.get(string_global.declaration.type).array.count;

                        const final_slice = try unit.instructions.append(context.allocator, .{
                            .insert_value = .{
                                .expression = V{
                                    .value = .{
                                        .runtime = slice_builder,
                                    },
                                    .type = type_index,
                                },
                                .index = 1,
                                .new_value = .{
                                    .value = .{
                                        .@"comptime" = .{
                                            .constant_int = .{
                                                .value = len,
                                            },
                                        },
                                    },
                                    .type = .usize,
                                },
                            },
                        });

                        try builder.appendInstruction(unit, context, final_slice);

                        break :blk .{
                            .value = .{
                                .runtime = final_slice,
                            },
                            .type = type_index,
                        };
                    },
                    else => |t| @panic(@tagName(t)),
                },
                else => |t| @panic(@tagName(t)),
            },
            .if_else => try builder.resolveIfElse(unit, context, type_expect, node_index),
            .anonymous_array_literal => blk: {
                const array_type_expect = switch (type_expect) {
                    .type => type_expect,
                    .array => type_expect,
                    else => |t| @panic(@tagName(t)),
                };
                const array_literal = try builder.resolveArrayLiteral(unit, context, array_type_expect, unit.getNodeList(node.right), .null);
                break :blk array_literal;
            },
            .address_of => blk: {
                assert(node.left != .null);
                assert(node.right == .null);
                switch (type_expect) {
                    .type => |type_index| switch (unit.types.get(type_index).*) {
                        .slice => |slice| {
                            const value_pointer = try builder.resolveRuntimeValue(unit, context, Type.Expect{
                                .array = .{
                                    .count = null,
                                    .type = slice.child_type,
                                    .termination = slice.termination,
                                },
                            }, node.left, .left);

                            const array_type = unit.types.get(value_pointer.type).array;

                            switch (value_pointer.value) {
                                // TODO: hash identical constants
                                .runtime => |instruction_index| switch (unit.instructions.get(instruction_index).*) {
                                    .stack_slot => |stack_slot| {
                                        const slice_builder = try unit.instructions.append(context.allocator, .{
                                            .insert_value = .{
                                                .expression = .{
                                                    .value = .{
                                                        .@"comptime" = .undefined,
                                                    },
                                                    .type = type_index,
                                                },
                                                .index = 0,
                                                .new_value = value_pointer,
                                            },
                                        });
                                        try builder.appendInstruction(unit, context, slice_builder);

                                        const final_slice = try unit.instructions.append(context.allocator, .{
                                            .insert_value = .{
                                                .expression = .{
                                                    .value = .{
                                                        .runtime = slice_builder,
                                                    },
                                                    .type = type_index,
                                                },
                                                .index = 1,
                                                .new_value = .{
                                                    .value = .{
                                                        .@"comptime" = .{
                                                            .constant_int = .{
                                                                .value = unit.types.get(stack_slot.type).array.count,
                                                            },
                                                        },
                                                    },
                                                    .type = .usize,
                                                },
                                            },
                                        });
                                        try builder.appendInstruction(unit, context, final_slice);

                                        break :blk .{
                                            .value = .{
                                                .runtime = final_slice,
                                            },
                                            .type = type_index,
                                        };
                                    },
                                    .insert_value => {
                                        const name = try std.fmt.allocPrintZ(context.allocator, "__anon_local_arr_{}", .{unit.anon_arr});
                                        unit.anon_arr += 1;
                                        const emit = true;
                                        const stack_slot = try builder.emitLocalVariableDeclaration(unit, context, unit.getNode(node.left).token, .@"const", value_pointer.type, value_pointer, emit, name);
                                        const slice_builder = try unit.instructions.append(context.allocator, .{
                                            .insert_value = .{
                                                .expression = .{
                                                    .value = .{
                                                        .@"comptime" = .undefined,
                                                    },
                                                    .type = type_index,
                                                },
                                                .index = 0,
                                                .new_value = .{
                                                    .value = .{
                                                        .runtime = stack_slot,
                                                    },
                                                    .type = unit.instructions.get(stack_slot).stack_slot.type,
                                                },
                                            },
                                        });
                                        try builder.appendInstruction(unit, context, slice_builder);

                                        const final_slice = try unit.instructions.append(context.allocator, .{
                                            .insert_value = .{
                                                .expression = .{
                                                    .value = .{
                                                        .runtime = slice_builder,
                                                    },
                                                    .type = type_index,
                                                },
                                                .index = 1,
                                                .new_value = .{
                                                    .value = .{
                                                        .@"comptime" = .{
                                                            .constant_int = .{
                                                                .value = array_type.count,
                                                            },
                                                        },
                                                    },
                                                    .type = .usize,
                                                },
                                            },
                                        });
                                        try builder.appendInstruction(unit, context, final_slice);

                                        break :blk .{
                                            .value = .{
                                                .runtime = final_slice,
                                            },
                                            .type = type_index,
                                        };
                                    },
                                    else => |t| @panic(@tagName(t)),
                                },
                                .@"comptime" => |ct| switch (ct) {
                                    .constant_array => {
                                        const name = try std.fmt.allocPrintZ(context.allocator, "__anon_local_arr_{}", .{unit.anon_arr});
                                        unit.anon_arr += 1;
                                        const emit = true;
                                        const stack_slot = try builder.emitLocalVariableDeclaration(unit, context, unit.getNode(node.left).token, .@"const", value_pointer.type, value_pointer, emit, name);
                                        const slice_builder = try unit.instructions.append(context.allocator, .{
                                            .insert_value = .{
                                                .expression = .{
                                                    .value = .{
                                                        .@"comptime" = .undefined,
                                                    },
                                                    .type = type_index,
                                                },
                                                .index = 0,
                                                .new_value = .{
                                                    .value = .{
                                                        .runtime = stack_slot,
                                                    },
                                                    .type = unit.instructions.get(stack_slot).stack_slot.type,
                                                },
                                                },
                                            });
                                        try builder.appendInstruction(unit, context, slice_builder);

                                        const final_slice = try unit.instructions.append(context.allocator, .{
                                            .insert_value = .{
                                                .expression = .{
                                                    .value = .{
                                                        .runtime = slice_builder,
                                                    },
                                                    .type = type_index,
                                                },
                                                .index = 1,
                                                .new_value = .{
                                                    .value = .{
                                                        .@"comptime" = .{
                                                            .constant_int = .{
                                                                .value = array_type.count,
                                                            },
                                                        },
                                                    },
                                                    .type = .usize,
                                                },
                                            },
                                        });
                                        try builder.appendInstruction(unit, context, final_slice);

                                        break :blk .{
                                            .value = .{
                                                .runtime = final_slice,
                                            },
                                            .type = type_index,
                                        };
                                    },
                                    else => |t| @panic(@tagName(t)),
                                },
                                else => |t| @panic(@tagName(t)),
                            }
                        },
                        .pointer => |pointer| switch (pointer.many) {
                            true => unreachable,
                            false => {
                                const v = try builder.resolveRuntimeValue(unit, context, Type.Expect{
                                    .type = pointer.type,
                                }, node.left, .left);
                                break :blk switch (v.value) {
                                    .runtime => |instruction_index| switch (unit.instructions.get(instruction_index).*) {
                                        .stack_slot => v,
                                        else => |t| @panic(@tagName(t)),
                                    },
                                    else => |t| @panic(@tagName(t)),
                                };
                            },
                        },
                        else => |t| @panic(@tagName(t)),
                    },
                    else => |t| @panic(@tagName(t)),
                }
            },
            .undefined => .{
                .value = .{
                    .@"comptime" = .undefined,
                },
                .type = switch (type_expect) {
                    .type => |type_index| type_index,
                    else => |t| @panic(@tagName(t)),
                },
            },
            .array_literal => blk: {
                switch (type_expect) {
                    .none => {},
                    else => |t| @panic(@tagName(t)),
                }
                const array_literal = try builder.resolveArrayLiteral(unit, context, Type.Expect.none, unit.getNodeList(node.right), node.left);
                break :blk array_literal;
            },
            .indexed_access => blk: {
                assert(node.left != .null);
                assert(node.right != .null);

                const array_like_expression = try builder.resolveRuntimeValue(unit, context, Type.Expect.none, node.left, .left);
                const index = try builder.resolveRuntimeValue(unit, context, Type.Expect{ .type = .usize }, node.right, .right);

                const gep: V = switch (unit.types.get(array_like_expression.type).*) {
                    .pointer => |pointer| switch (pointer.many) {
                        true => unreachable,
                        false => switch (unit.types.get(pointer.type).*) {
                            .slice => |slice| b: {
                                const load = try unit.instructions.append(context.allocator, .{
                                    .load = .{
                                        .value = array_like_expression,
                                    },
                                });
                                try builder.appendInstruction(unit, context, load);

                                const pointer_extract_value = try unit.instructions.append(context.allocator, .{
                                    .extract_value = .{
                                        .expression = .{
                                            .value = .{
                                                .runtime = load,
                                            },
                                            .type = pointer.type,
                                        },
                                        .index = 0,
                                    },
                                });
                                try builder.appendInstruction(unit, context, pointer_extract_value);

                                const gep = try unit.instructions.append(context.allocator, .{
                                    .get_element_pointer = .{
                                        .pointer = pointer_extract_value, //pointer_extract_value,
                                        .base_type = slice.child_type,
                                        .index = index,
                                    },
                                });
                                try builder.appendInstruction(unit, context, gep);

                                const gep_type = try unit.getPointerType(context, .{
                                    .type = slice.child_type,
                                    .termination = .none,
                                    .mutability = pointer.mutability,
                                    .many = false,
                                    .nullable = false,
                                });

                                break :b .{
                                    .value = .{
                                        .runtime = gep,
                                    },
                                    .type = gep_type,
                                };
                            },
                            .array => |array| b: {
                                const gep = try unit.instructions.append(context.allocator, .{
                                    .get_element_pointer = .{
                                        .pointer = array_like_expression.value.runtime,
                                        .base_type = array.type,
                                        .index = index,
                                    },
                                });
                                try builder.appendInstruction(unit, context, gep);

                                const gep_type = try unit.getPointerType(context, .{
                                    .type = array.type,
                                    .termination = .none,
                                    .mutability = pointer.mutability,
                                    .many = false,
                                    .nullable = false,
                                });

                                break :b .{
                                    .value = .{
                                        .runtime = gep,
                                    },
                                    .type = gep_type,
                                };
                            },
                            else => |t| @panic(@tagName(t)),
                        },
                    },
                    .slice => |slice| b: {
                        const array_like_loaded = switch (array_like_expression.value) {
                            .runtime => |instruction_index| switch (unit.instructions.get(instruction_index).*) {
                                .stack_slot => stack_slot: {
                                    const load = try unit.instructions.append(context.allocator, .{
                                        .load = .{
                                            .value = array_like_expression,
                                        },
                                    });

                                    try builder.appendInstruction(unit, context, load);

                                    break :stack_slot V{
                                        .value = .{
                                            .runtime = load,
                                        },
                                        .type = array_like_expression.type,
                                    };
                                },
                                else => |t| @panic(@tagName(t)),
                            },
                            else => |t| @panic(@tagName(t)),
                        };

                        const pointer_extract_value = try unit.instructions.append(context.allocator, .{
                            .extract_value = .{
                                .expression = array_like_loaded,
                                .index = 0,
                            },
                        });
                        try builder.appendInstruction(unit, context, pointer_extract_value);

                        const instruction = try unit.instructions.append(context.allocator, .{
                            .get_element_pointer = .{
                                .pointer = pointer_extract_value,
                                .base_type = slice.child_type,
                                .index = index,
                            },
                        });
                        try builder.appendInstruction(unit, context, instruction);

                        const gep_type = try unit.getPointerType(context, .{
                            .type = slice.child_type,
                            .termination = .none,
                            .mutability = slice.mutability,
                            .many = false,
                            .nullable = false,
                        });

                        break :b .{
                            .value = .{
                                .runtime = instruction,
                            },
                            .type = gep_type,
                        };
                    },
                    else => |t| @panic(@tagName(t)),
                };

                switch (side) {
                    .left => break :blk gep,
                    .right => {
                        const load = try unit.instructions.append(context.allocator, .{
                            .load = .{
                                .value = gep,
                            },
                        });
                        try builder.appendInstruction(unit, context, load);

                        break :blk .{
                            .value = .{
                                .runtime = load,
                            },
                            .type = switch (type_expect) {
                                .type => |type_index| b: {
                                    const result = try builder.typecheck(unit, context, type_index, unit.instructions.get(gep.value.runtime).get_element_pointer.base_type);
                                    switch (result) {
                                        .success => {},
                                        else => |t| @panic(@tagName(t)),
                                    }
                                    const result2 = try builder.typecheck(unit, context, type_index, unit.types.get(gep.type).pointer.type);
                                    switch (result2) {
                                        .success => {},
                                        else => |t| @panic(@tagName(t)),
                                    }

                                    break :b unit.types.get(gep.type).pointer.type;
                                },
                                else => |t| @panic(@tagName(t)),
                            },
                        };
                    },
                }
            },
            .character_literal => blk: {
                const ch_literal = unit.getExpectedTokenBytes(node.token, .character_literal);
                assert(ch_literal.len == 3);
                const character = ch_literal[1];
                break :blk .{
                    .value = .{
                        .@"comptime" = .{
                            .constant_int = .{
                                .value = character,
                            },
                        },
                    },
                    .type = .u8,
                };
            },
            else => |t| @panic(@tagName(t)),
        };

        return v;
    }

    fn resolveArrayLiteral(builder: *Builder, unit: *Unit, context: *const Context, array_type_expect: Type.Expect, nodes: []const Node.Index, type_node_index: Node.Index) !V {
        const expression_element_count = nodes.len;
        const array_type_index = switch (array_type_expect) {
            .none => b: {
                assert(type_node_index != .null);
                const array_type = try builder.resolveArrayType(unit, context, type_node_index, expression_element_count);
                break :b array_type;
            },
            .type => |type_index| switch (unit.types.get(type_index).*) {
                .array => type_index,
                else => |t| @panic(@tagName(t)),
            },
            .array => |array| try unit.getArrayType(context, .{
                .count = expression_element_count,
                .type = array.type,
                .termination = array.termination,
            }),
            else => unreachable,
        };

        const array_type = unit.types.get(array_type_index).array;

        if (array_type.count != expression_element_count) @panic("Array element count mismatch");

        var is_comptime = true;
        var values = try ArrayList(V).initCapacity(context.allocator, nodes.len); 
        for (nodes) |node_index| {
            const value = try builder.resolveRuntimeValue(unit, context, Type.Expect { .type = array_type.type }, node_index, .right);
            // assert(value.value == .@"comptime");
            is_comptime = is_comptime and value.value == .@"comptime";
            values.appendAssumeCapacity(value);
        }

        if (is_comptime) {
            const constant_array = try unit.constant_arrays.append(context.allocator, .{
                .values = blk: {
                    var ct_values = try ArrayList(V.Comptime).initCapacity(context.allocator, values.items.len);

                    for (values.items) |v| {
                        ct_values.appendAssumeCapacity(v.value.@"comptime");
                    }

                    break :blk ct_values.items;
                },
                // TODO: avoid hash lookup
                .type = try unit.getArrayType(context, array_type),
            });
            const v = V{
                .value = .{
                    .@"comptime" = .{
                        .constant_array = constant_array,
                    },
                    },
                // TODO: avoid hash lookup
                .type = try unit.getArrayType(context, array_type),
            };
            return v;
        } else {
            var array_builder = V{
                .value = .{
                    .@"comptime" = .undefined,
                },
                .type = array_type_index,
            };

            for (values.items, 0..) |value, index| {
                const insert_value = try unit.instructions.append(context.allocator, .{
                    .insert_value = .{
                        .expression = array_builder,
                        .index = @intCast(index),
                        .new_value = value,
                    },
                });

                try builder.appendInstruction(unit, context, insert_value);

                array_builder.value = .{
                    .runtime = insert_value,
                };
            }

            return array_builder;
        }
    }

    fn resolveCall(builder: *Builder, unit: *Unit, context: *const Context, node_index: Node.Index) !V{
        const node = unit.getNode(node_index);

        assert(node.left != .null);
        assert(node.right != .null);
        const left_node = unit.getNode(node.left);

        var argument_list = ArrayList(V){};
        const callable = switch (left_node.id) {
            .field_access => b: {
                const field_access_left = try builder.resolveRuntimeValue(unit, context, Type.Expect.none, left_node.left, .right);
                const right_identifier_node = unit.getNode(left_node.right);
                assert(right_identifier_node.id == .identifier);
                const right_identifier = unit.getExpectedTokenBytes(right_identifier_node.token, .identifier);
                const right_identifier_hash = try unit.processIdentifier(context, right_identifier);

                switch (field_access_left.value) {
                    .@"comptime" => |ct| switch (ct) {
                        .type => |type_index| switch (unit.types.get(type_index).*) {
                            .@"struct", .@"enum" => {
                                const container_type = unit.types.get(type_index);
                                const container_scope = container_type.getScope(unit);
                                const look_in_parent_scopes = false;
                                if (container_scope.lookupDeclaration(right_identifier_hash, look_in_parent_scopes)) |lookup| {
                                    const global_decl_ref = try builder.referenceGlobalDeclaration(unit, context, lookup.scope, lookup.declaration);
                                    break :b global_decl_ref;
                                } else {
                                    unreachable;
                                }
                            },
                            else => |t| @panic(@tagName(t)),
                        },
                        .constant_struct => |constant_struct_index| {
                            _ = constant_struct_index; // autofix
                                                       // const constant_struct = unit.constant_structs.get(constant_struct_index);
                            const struct_type = unit.structs.get(unit.types.get(field_access_left.type).@"struct" );
                            for (struct_type.fields.items) |field_index| {
                                const field = unit.struct_fields.get(field_index);
                                if (field.name == right_identifier_hash) {
                                    unreachable;
                                }
                            } else {
                                const look_in_parent_scopes = false;
                                if (struct_type.scope.scope.lookupDeclaration(right_identifier_hash, look_in_parent_scopes)) |lookup| {
                                    const global_decl_ref = try builder.referenceGlobalDeclaration(unit, context, lookup.scope, lookup.declaration);
                                    switch (global_decl_ref.value) {
                                        .function_reference => |function_declaration| {
                                            const function_prototype_type = unit.types.get( function_declaration.declaration.type);
                                            const function_prototype = unit.function_prototypes.get(function_prototype_type.function);

                                            if (function_prototype.argument_types.len == 0) {
                                                unreachable;
                                            }

                                            const first_argument_type_index = function_prototype.argument_types[0];
                                            if (first_argument_type_index == field_access_left.type) {
                                                try argument_list.append(context.allocator, field_access_left);
                                                break :b global_decl_ref;
                                            } else {
                                                unreachable;
                                            }
                                        },
                                        else => |t| @panic(@tagName(t)),
                                    }
                                    unreachable;
                                    // break :b global_decl_ref;
                                } else {
                                    unreachable;
                                }
                            }
                        },
                        else => |t| @panic(@tagName(t)),
                    },
                    .runtime => |instruction_index| {
                        switch (unit.types.get(field_access_left.type).*) {
                            .@"struct" => |struct_index| {
                                const struct_type = unit.structs.get(struct_index);
                                for (struct_type.fields.items) |field_index| {
                                    const field = unit.struct_fields.get(field_index);
                                    if (field.name == right_identifier_hash) {
                                        unreachable;
                                    }
                                } else {
                                    const look_in_parent_scopes = false;
                                    if (struct_type.scope.scope.lookupDeclaration(right_identifier_hash, look_in_parent_scopes)) |lookup| {
                                        const global_decl_ref = try builder.referenceGlobalDeclaration(unit, context, lookup.scope, lookup.declaration);
                                        switch (global_decl_ref.value) {
                                            .function_reference => |function_declaration| {
                                                const function_prototype_type = unit.types.get( function_declaration.declaration.type);
                                                const function_prototype = unit.function_prototypes.get(function_prototype_type.function);

                                                if (function_prototype.argument_types.len == 0) {
                                                    unreachable;
                                                }

                                                const first_argument_type_index = function_prototype.argument_types[0];
                                                if (first_argument_type_index == field_access_left.type) {
                                                    try argument_list.append(context.allocator, field_access_left);
                                                    break :b global_decl_ref;
                                                } else {
                                                    unreachable;
                                                }
                                            },
                                            else => |t| @panic(@tagName(t)),
                                        }
                                        unreachable;
                                        // break :b global_decl_ref;
                                    } else {
                                        unreachable;
                                    }
                                }
                            },
                            else => |t| @panic(@tagName(t)),
                        }
                        _ = instruction_index; // autofix
                    },
                    else => |t| @panic(@tagName(t)),
                }
            },
            .identifier => blk: {
                const identifier = unit.getExpectedTokenBytes(left_node.token, .identifier);
                const result = try builder.resolveIdentifier(unit, context, Type.Expect.none, identifier, .left);
                break :blk result;
            },
            else => |t| @panic(@tagName(t)),
        };

        switch (callable.value) {
            .function_reference => |function_declaration| {
                const function_definition_index = function_declaration.getFunctionDefinitionIndex();
                const function = unit.function_definitions.get(function_definition_index);
                const function_type = unit.types.get( function.type);
                const function_prototype = unit.function_prototypes.get(function_type.function);
                const argument_nodes = unit.getNodeList(node.right);
                const argument_declaration_count = function.scope.scope.declarations.count();
                
                // Argument list holds already the value of the member value
                if (argument_nodes.len + argument_list.items.len != argument_declaration_count) {
                    @panic("Argument count mismatch");
                }

                try argument_list.ensureTotalCapacity(context.allocator, argument_declaration_count);

                const argument_offset = argument_list.items.len;
                for (argument_nodes, function.scope.scope.declarations.values()[argument_offset..]) |arg_ni, argument_declaration| {
                    const argument_node = unit.getNode(arg_ni);
                    const arg_type_expect = Type.Expect{
                        .type = argument_declaration.type,
                    };
                    const argument_node_index = switch (argument_node.id) {
                        .named_argument => argument_node.right,
                        else => arg_ni,
                    };
                    const argument_value = try builder.resolveRuntimeValue(unit, context, arg_type_expect, argument_node_index, .right);
                    argument_list.appendAssumeCapacity(argument_value);
                }

                const instruction = try unit.instructions.append(context.allocator, .{
                    .call = .{
                        .callable = .{
                            .function_definition = function_declaration,
                        },
                        .function_type = function.type,
                        .arguments = argument_list.items,
                    },
                });
                try builder.appendInstruction(unit, context, instruction);

                return .{
                    .value = .{
                        .runtime = instruction,
                    },
                    .type = function_prototype.return_type,
                };
            },
            .runtime => unreachable,
            else => unreachable,
        }
    }

    fn emitLocalVariableDeclaration(builder: *Builder, unit: *Unit, context: *const Context, token: Token.Index, mutability: Mutability, declaration_type: Type.Index, initialization: V, emit: bool, maybe_name: ?[]const u8) !Instruction.Index {
        assert(builder.current_scope.local);
        const index = Token.unwrap(token);
        const id = unit.token_buffer.tokens.items(.id)[index];
        const identifier = if (maybe_name) |name| name else switch (id) {
            .identifier => unit.getExpectedTokenBytes(token, .identifier),
            .discard => blk: {
                const name = try std.fmt.allocPrintZ(context.allocator, "_{}", .{unit.discard_identifiers});
                unit.discard_identifiers += 1;
                break :blk name;
            },
            else => |t| @panic(@tagName(t)),
        };
        logln(.compilation, .identifier, "Analyzing local declaration {s}", .{identifier});
        const identifier_hash = try unit.processIdentifier(context, identifier);
        const token_debug_info = builder.getTokenDebugInfo(unit, token);

        const look_in_parent_scopes = true;
        if (builder.current_scope.lookupDeclaration(identifier_hash, look_in_parent_scopes)) |lookup| {
            _ = lookup; // autofix
            std.debug.panic("Identifier '{s}' already declarared on scope", .{identifier});
        }

        const declaration_index = try unit.local_declarations.append(context.allocator, .{
            .declaration = .{
                .scope = builder.current_scope,
                .name = identifier_hash,
                .type = declaration_type,
                .mutability = mutability,
                .line = token_debug_info.line,
                .column = token_debug_info.column,
                .kind = .local,
            },
            .init_value = initialization,
        });

        const local_declaration = unit.local_declarations.get(declaration_index);
        assert(builder.current_scope.kind == .block);
        try builder.current_scope.declarations.putNoClobber(context.allocator, identifier_hash, &local_declaration.declaration);

        if (emit) {
            const stack = try unit.instructions.append(context.allocator, .{
                .stack_slot = .{
                    .type = declaration_type,
                },
            });

            try builder.appendInstruction(unit, context, stack);

            assert(builder.current_scope.kind == .block);
            const local_scope = @fieldParentPtr(Debug.Scope.Local, "scope", builder.current_scope);
            try local_scope.local_declaration_map.putNoClobber(context.allocator, local_declaration, stack);
            
            const debug_declare_local = try unit.instructions.append(context.allocator, .{
                .debug_declare_local_variable = .{
                    .variable = local_declaration,
                    .stack = stack,
                },
                });

            try builder.appendInstruction(unit, context, debug_declare_local);

            const store = try unit.instructions.append(context.allocator, .{
                .store = .{
                    .destination = .{
                        .value = .{
                            .runtime = stack,
                        },
                        .type = declaration_type,
                    },
                    .source = initialization,
                },
                });

            try builder.appendInstruction(unit, context, store);

            return stack;
        } else {
            return .null;
        }
    }

    fn resolveBlock(builder: *Builder, unit: *Unit, context: *const Context, node_index: Node.Index) anyerror!Debug.Block.Index {
        const block_node = unit.getNode(node_index);
        assert(block_node.id == .block);
        const token_debug_info = builder.getTokenDebugInfo(unit, block_node.token);
        const block_index = try unit.blocks.append(context.allocator, .{
            .scope = .{
                .scope = .{
                    .line = token_debug_info.line,
                    .column = token_debug_info.column,
                    .kind = .block,
                    .level = builder.current_scope.level + 1,
                    .local = builder.current_scope.local,
                    .file = builder.current_file,
                },
                },
            });

        const block = unit.blocks.get(block_index);
        if (builder.current_basic_block != .null) {
            assert(builder.current_scope.kind == .block or builder.current_scope.kind == .function);
        }

        try builder.pushScope(unit, context, &block.scope.scope);
        defer builder.popScope(unit, context) catch unreachable;

        const statement_node_list = unit.getNodeList(block_node.left);

        for (statement_node_list) |statement_node_index| {
            const statement_node = unit.getNode(statement_node_index);

            try builder.insertDebugCheckPoint(unit, context, statement_node.token);

            switch (statement_node.id) {
                .assign, .add_assign, .sub_assign, .div_assign => {
                    _ = try builder.resolveAssignment(unit, context, statement_node_index);
                },
                .if_else => {
                    // TODO: typecheck
                    _ = try builder.resolveIfElse(unit, context, Type.Expect{
                        .type = .void,
                    }, statement_node_index);
                },
                .intrinsic => {
                    _ = try builder.resolveIntrinsic(unit, context, Type.Expect{
                        .type = .void,
                    }, statement_node_index);
                },
                .constant_symbol_declaration,
                .variable_symbol_declaration, => {
                    // All variables here are local
                    assert(builder.current_scope.local);
                    const expected_identifier_token_index = Token.addInt(statement_node.token, 1);

                    const mutability: Mutability = switch (statement_node.id) {
                        .constant_symbol_declaration => .@"const",
                        .variable_symbol_declaration => .@"var",
                        else => unreachable,
                    };

                    const metadata_node_index = statement_node.left;
                    const value_node_index = statement_node.right;
                    assert(value_node_index != .null);

                    const type_expect = switch (metadata_node_index) {
                        .null => Type.Expect.none,
                        else => b: {
                            const metadata_node = unit.getNode(metadata_node_index);
                            const type_node_index = metadata_node.left;
                            assert(metadata_node.right == .null);
                            const type_expect = Type.Expect{
                                .type = try builder.resolveType(unit, context, type_node_index),
                            };
                            break :b type_expect;
                        },
                    };

                    const initialization = try builder.resolveRuntimeValue(unit, context, type_expect, value_node_index, .right);

                    const emit = !(mutability == .@"const" and initialization.value == .@"comptime" and initialization.value.@"comptime" != .constant_array);

                    const declaration_type = switch (type_expect) {
                        .none => initialization.type,
                        .type => |type_index| type_index,
                        else => unreachable,
                    };

                    _ = try builder.emitLocalVariableDeclaration(unit, context, expected_identifier_token_index, mutability, declaration_type, initialization, emit, null);
                },
                .@"return" => {
                    assert(statement_node.left != .null);
                    assert(statement_node.right == .null);
                    const return_value_node_index = statement_node.left;
                    const return_type = unit.getReturnType(builder.current_function);
                    const return_value = try builder.resolveRuntimeValue(unit, context, Type.Expect{
                        .type = return_type,
                    }, return_value_node_index, .right);

                    if (builder.return_block != .null) {
                        if (builder.return_phi != .null) {
                            const phi = &unit.instructions.get(builder.return_phi).phi;
                            try phi.values.append(context.allocator, return_value);
                            try phi.basic_blocks.append(context.allocator, builder.current_basic_block);
                        }

                        assert(builder.current_basic_block != builder.return_block);

                        try builder.jump(unit, context, builder.return_block); 
                    } else if (builder.exit_blocks.items.len > 0) {
                        builder.return_phi = try unit.instructions.append(context.allocator, .{
                            .phi = .{
                                .type = return_type,
                            },
                        });

                        builder.return_block = try builder.newBasicBlock(unit, context);
                        const current_basic_block = builder.current_basic_block;
                        builder.current_basic_block = builder.return_block;
                        
                        try builder.appendInstruction(unit, context, builder.return_phi);
                        
                        const phi = &unit.instructions.get(builder.return_phi).phi;
                        try phi.values.append(context.allocator, return_value);
                        try phi.basic_blocks.append(context.allocator, current_basic_block);
                        
                        const ret = try unit.instructions.append(context.allocator, .{
                            .ret = .{
                                .value = .{
                                    .runtime = builder.return_phi,
                                },
                                .type = return_type,
                            },
                        });
                        try builder.appendInstruction(unit, context, ret);
                        
                        builder.current_basic_block = current_basic_block;
                        try builder.jump(unit, context, builder.return_block);
                    } else {
                        const ret = try unit.instructions.append(context.allocator, .{
                            .ret = return_value,
                        });
                        try builder.appendInstruction(unit, context, ret);
                    }
                },
                .call =>  {
                    const result = try builder.resolveCall(unit, context, statement_node_index);
                    assert(result.type == .void or result.type == .@"noreturn");
                },
                .@"switch" => {
                    const expression_to_switch_on = try builder.resolveRuntimeValue(unit, context, Type.Expect.none, statement_node.left, .right);
                    const case_nodes = unit.getNodeList(statement_node.right);

                    switch (expression_to_switch_on.value) {
                        .@"comptime" => |ct| switch (ct) {
                            .enum_value => |enum_field_index| {
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
                                _ = try builder.resolveRuntimeValue(unit, context, Type.Expect { .type = .void }, true_switch_case_node.right, .right);
                            },
                            else => |t| @panic(@tagName(t)),
                        },
                        .runtime => todo(),
                        else => |t| @panic(@tagName(t)),
                    }
                },
                .@"unreachable" => {
                    const instruction = try unit.instructions.append(context.allocator, .@"unreachable");
                    try builder.appendInstruction(unit, context, instruction);
                },
                .@"while" => {
                    assert(statement_node.left != .null);
                    assert(statement_node.right != .null);

                    const loop_header_block = try builder.newBasicBlock(unit, context);
                    try builder.jump(unit, context, loop_header_block);
                    builder.current_basic_block = loop_header_block;

                    const condition = try builder.resolveRuntimeValue(unit, context, Type.Expect{ .type = .bool  }, statement_node.left, .right);
                    const body_block = try builder.newBasicBlock(unit, context); 
                    const exit_block = try builder.newBasicBlock(unit, context); 

                    const old_loop_exit_block = builder.loop_exit_block;
                    defer builder.loop_exit_block = old_loop_exit_block;

                    switch (condition.value) {
                        .runtime => |condition_instruction| {
                            try builder.branch(unit, context, condition_instruction, body_block, exit_block);

                            builder.current_basic_block = body_block;
                            builder.loop_exit_block = exit_block;

                            const body_value = try builder.resolveRuntimeValue(unit, context, Type.Expect{ .type = .void }, statement_node.right, .right);
                            _ = body_value; // autofix
                            // _ = body_value; // autofix
                            try builder.jump(unit, context, loop_header_block);
                            
                            builder.current_basic_block = exit_block;
                        },
                        .@"comptime" => |ct| switch (ct) {
                            .bool => |boolean| switch (boolean) {
                                true => {
                                    try builder.jump(unit, context, body_block);
                                    builder.current_basic_block = body_block;
                                    builder.loop_exit_block = exit_block;

                                    const body_value = try builder.resolveRuntimeValue(unit, context, Type.Expect{ .type = .void }, statement_node.right, .right);
                                    try builder.jump(unit, context, loop_header_block);
                                    _ = body_value; // autofix
                                    builder.current_basic_block = exit_block;
                                },
                                false => unreachable,
                            },
                            else => |t| @panic(@tagName(t)),
                        },
                        else => unreachable,
                    }
                },
                .if_else_payload => {
                    assert(statement_node.left != .null);
                    assert(statement_node.right != .null);
                    const payload_node = unit.getNode(statement_node.right);
                    assert(payload_node.id == .identifier);

                    const if_else_node = unit.getNode(statement_node.left);
                    assert(if_else_node.id == .if_else);
                    assert(if_else_node.left != .null);
                    assert(if_else_node.right != .null);

                    const if_node = unit.getNode(if_else_node.left);
                    assert(if_node.id == .@"if");
                    assert(if_node.left != .null);
                    assert(if_node.right != .null);

                    const optional_expression = try builder.resolveRuntimeValue(unit, context, Type.Expect.none, if_node.left, .right);

                    const taken_expression_node_index = if_node.right;
                    const not_taken_expression_node_index = if_else_node.right;

                    switch (optional_expression.value) {
                        .runtime => {
                            switch (unit.types.get(optional_expression.type).*) {
                                .@"struct" => |struct_index| {
                                    const struct_type = unit.structs.get(struct_index);
                                    if (struct_type.optional) {
                                        const condition = try unit.instructions.append(context.allocator, .{
                                            .extract_value = .{
                                                .expression = optional_expression,
                                                .index = 1,
                                            },
                                        });
                                        try builder.appendInstruction(unit, context, condition);

                                        try builder.resolveBranch(unit, context, Type.Expect{ .type = .void }, condition, taken_expression_node_index, not_taken_expression_node_index, payload_node.token);
                                    } else {
                                        unreachable;
                                    }
                                },
                                // .optional => |optional_element_type_index| {
                                // },
                                else => |t| @panic(@tagName(t)),
                            }
                        },
                        else => |t| @panic(@tagName(t)),
                    }
                },
                .@"if" => {
                    assert(statement_node.left != .null);
                    assert(statement_node.right != .null);
                    const condition = try builder.resolveRuntimeValue(unit, context, Type.Expect{ .type = .bool }, statement_node.left, .right);
                    const taken_expression_node_index = statement_node.right;
                    const not_taken_expression_node_index = .null;
                    switch (condition.value) {
                        .@"comptime" => unreachable,
                        .runtime => |condition_instruction| {
                            try builder.resolveBranch(unit, context, Type.Expect{ .type = .void }, condition_instruction, taken_expression_node_index, not_taken_expression_node_index, .null);
                        },
                        else => unreachable,
                    }
                },
                .for_loop => {
                    assert(statement_node.left != .null);
                    assert(statement_node.right != .null);

                    const conditions = unit.getNode(statement_node.left);
                    const slices_and_range_node = unit.getNodeList(conditions.left);
                    const payloads = unit.getNodeList(conditions.right);
                    assert(slices_and_range_node.len > 0);
                    assert(payloads.len > 0);

                    if (slices_and_range_node.len != payloads.len) {
                        @panic("Slice/range count does not match payload count");
                    }

                    const count = slices_and_range_node.len;
                    // var slice_init_instructions = ArrayList(Instruction.Index){};
                    // var slice_init_values = ArrayList(V){};
                    var slices = ArrayList(V){};

                    const last_element_node_index = slices_and_range_node[count - 1];
                    const last_element_node = unit.getNode(last_element_node_index);
                    const last_element_payload = unit.getNode(payloads[count - 1]);

                    const LoopCounter = struct{
                        stack_slot: Instruction.Index,
                        end: V,
                    };

                    for (slices_and_range_node[0..count - 1]) |slice_or_range_node_index| {
                        const slice = try builder.resolveRuntimeValue(unit, context, Type.Expect.none, slice_or_range_node_index, .right);
                        try slices.append(context.allocator, slice);
                    }

                    const loop_counter: LoopCounter = switch (last_element_node.id) {
                        .range => blk: {
                            assert(last_element_node.left != .null);

                            const range_start = try builder.resolveRuntimeValue(unit, context, Type.Expect{ .type = .usize }, last_element_node.left, .right);
                            const emit = true;
                            const stack_slot = try builder.emitLocalVariableDeclaration(unit, context, last_element_payload.token, .@"var", .usize, range_start, emit, null);
                            // This is put up here so that the length is constant throughout the loop and we dont have to load the variable unnecessarily


                            const range_end = switch (last_element_node.right) {
                                .null => switch (unit.types.get( slices.items[0].type).*) {
                                    .slice => b: {
                                        const len_extract_instruction = try unit.instructions.append(context.allocator, .{
                                            .extract_value = .{
                                                .expression = slices.items[0],
                                                .index = 1,
                                            },
                                        });
                                        try builder.appendInstruction(unit, context, len_extract_instruction);

                                        break :b V{
                                            .value = .{
                                                .runtime = len_extract_instruction,
                                            },
                                            .type = .usize,
                                        };
                                    },
                                    else => |t| @panic(@tagName(t)),
                                },
                                else => try builder.resolveRuntimeValue(unit, context, Type.Expect{ .type = .usize }, last_element_node.right, .right),
                            };

                            break :blk .{
                                .stack_slot = stack_slot,
                                .end = range_end,
                            };
                        },
                        else => blk: {
                            const for_loop_value = try builder.resolveRuntimeValue(unit, context, Type.Expect.none, last_element_node_index, .right);
                            try slices.append(context.allocator, for_loop_value);

                            switch (unit.types.get(for_loop_value.type).*) {
                                .slice => |slice| {
                                    _ = slice; // autofix
                                    const name = try std.fmt.allocPrintZ(context.allocator, "__anon_i_{}", .{unit.anon_i});
                                    unit.anon_i += 1;
                                    const emit = true;
                                    const stack_slot = try builder.emitLocalVariableDeclaration(unit, context, last_element_payload.token, .@"var", .usize, .{
                                        .value = .{
                                            .@"comptime" = .{
                                                .constant_int = .{
                                                    .value = 0,
                                                },
                                            },
                                        },
                                        .type = .usize,
                                    }, emit, name);

                                    const len_extract_value = try unit.instructions.append(context.allocator, .{
                                        .extract_value = .{
                                            .expression = for_loop_value,
                                            .index = 1,
                                        },
                                    });
                                    try builder.appendInstruction(unit, context, len_extract_value);

                                    break :blk .{
                                        .stack_slot = stack_slot,
                                        .end = .{
                                            .value = .{
                                                .runtime = len_extract_value,
                                            },
                                            .type = .usize,
                                        },
                                    };
                                },
                                else => |t| @panic(@tagName(t)),
                            }
                        },
                    };

                    const loop_header = try builder.newBasicBlock(unit, context);
                    try builder.jump(unit, context, loop_header);
                    builder.current_basic_block = loop_header;

                    const load = try unit.instructions.append(context.allocator, .{
                        .load = .{
                            .value = .{
                                .value = .{
                                    .runtime = loop_counter.stack_slot,
                                },
                                .type = .usize,
                            },
                        },
                    });

                    try builder.appendInstruction(unit, context, load);

                    const compare = try unit.instructions.append(context.allocator, .{
                        .integer_compare = .{
                            .left = .{
                                .value = .{
                                    .runtime = load,
                                },
                                .type = .usize,
                            },
                            .right = loop_counter.end,
                            .type = .usize,
                            .id = .unsigned_less,
                        },
                    });
                    try builder.appendInstruction(unit, context, compare);

                    const body_block = try builder.newBasicBlock(unit, context); 
                    const exit_block = try builder.newBasicBlock(unit, context); 
                    try builder.branch(unit, context, compare, body_block, exit_block);

                    builder.current_basic_block = body_block;
                    const old_loop_exit_block = builder.loop_exit_block;
                    defer builder.loop_exit_block = old_loop_exit_block;
                    builder.loop_exit_block = exit_block;

                    const is_last_element_range = last_element_node.id == .range;
                    const not_range_len = payloads.len - @intFromBool(is_last_element_range);
                    if (slices.items.len > 0) {
                        const load_i = try unit.instructions.append(context.allocator, .{
                            .load = .{
                                .value = .{
                                    .value = .{
                                        .runtime = loop_counter.stack_slot,
                                    },
                                    .type = .usize,
                                },
                                },
                            });
                        try builder.appendInstruction(unit, context, load_i);
                        
                        for (payloads[0..not_range_len], slices.items) |payload_node_index, slice| {
                            const pointer_extract_value = try unit.instructions.append(context.allocator, .{
                                .extract_value = .{
                                    .expression = slice,
                                    .index = 0,
                                },
                            });
                            try builder.appendInstruction(unit, context, pointer_extract_value);
                            
                            const slice_type = unit.types.get(slice.type).slice;

                            const gep = try unit.instructions.append(context.allocator, .{
                                .get_element_pointer = .{
                                    .pointer = pointer_extract_value,
                                    .base_type = slice_type.child_type,
                                    .index = .{
                                        .value = .{
                                            .runtime = load_i,
                                        },
                                        .type = .usize,
                                    },
                                },
                            });
                            try builder.appendInstruction(unit, context, gep);

                            const is_by_value = true;
                            const init_instruction = switch (is_by_value) {
                                true => vblk: {
                                    const load_gep = try unit.instructions.append(context.allocator, .{
                                        .load = .{
                                            .value = .{
                                                .value = .{
                                                    .runtime = gep,
                                                },
                                                .type = slice_type.child_pointer_type,
                                            },
                                            },
                                        });
                                    try builder.appendInstruction(unit, context, load_gep);
                                    break :vblk load_gep;
                                },
                                false => gep,
                            };

                            const slice_get_element_value = V{
                                .value = .{
                                    .runtime = init_instruction,
                                },
                                .type = switch (unit.instructions.get(init_instruction).*) {
                                    .load => |get_load| unit.types.get(get_load.value.type).pointer.type,
                                    else => |t| @panic(@tagName(t)),
                                },
                            };

                            const payload_node = unit.getNode(payload_node_index);
                            const emit = true;
                            _ = try builder.emitLocalVariableDeclaration(unit, context, payload_node.token, .@"const", unit.types.get(slice.type).slice.child_type, slice_get_element_value, emit, null);
                        }
                    }

                    const body_node_index = statement_node.right;
                    _ = try builder.resolveRuntimeValue(unit, context, Type.Expect{ .type = .void }, body_node_index, .right);

                    const load_iterator = try unit.instructions.append(context.allocator, .{
                        .load = .{
                            .value = .{
                                .value = .{
                                    .runtime = loop_counter.stack_slot,
                                },
                                .type = .usize,
                            },
                        },
                    });

                    try builder.appendInstruction(unit, context, load_iterator);

                    const increment = try unit.instructions.append(context.allocator, .{
                        .integer_binary_operation = .{
                            .left = .{
                                .value = .{
                                    .runtime = load_iterator,
                                },
                                .type = .usize,
                            },
                            .right = .{
                                .value = .{
                                    .@"comptime" = .{
                                        .constant_int = .{
                                            .value = 1,
                                        },
                                        },
                                    },
                                    .type = .usize,
                                },
                                .id = .add,
                                .signedness = .unsigned,
                            },
                            });

                    try builder.appendInstruction(unit, context, increment);

                    const increment_store = try unit.instructions.append(context.allocator, .{
                        .store = .{
                            .destination = .{
                                .value = .{
                                    .runtime = loop_counter.stack_slot,
                                },
                                .type = .usize,
                            },
                            .source = .{
                                .value = .{
                                    .runtime = increment,
                                },
                                .type = .usize,
                            },
                            },
                        });

                    try builder.appendInstruction(unit, context, increment_store);

                    try builder.jump(unit, context, loop_header);

                    builder.current_basic_block = exit_block;
                },
                .break_expression => {
                    try builder.jump(unit, context, builder.loop_exit_block);
                },
                else => |t| @panic(@tagName(t)),
            }
        }

        return block_index;
    }

    fn resolveBranch(builder: *Builder, unit: *Unit, context: *const Context, type_expect: Type.Expect, condition: Instruction.Index, taken_node_index: Node.Index, not_taken_node_index: Node.Index, optional_payload_token: Token.Index) !void {
        const taken_block = try builder.newBasicBlock(unit, context);
        const exit_block = try builder.newBasicBlock(unit, context);
        const not_taken_block = if (not_taken_node_index != .null) try builder.newBasicBlock(unit, context) else exit_block;
        try builder.exit_blocks.append(context.allocator, exit_block);
        try builder.branch(unit, context, condition, taken_block, not_taken_block);

        builder.current_basic_block = taken_block;

        if (optional_payload_token != .null) {
            const conditional_instruction = unit.instructions.get(condition);
            const optional_expression = conditional_instruction.extract_value.expression;
            // TODO: avoid local symbol name collisions
            const unwrap = try unit.instructions.append(context.allocator, .{
                .extract_value = .{
                    .expression = optional_expression,
                    .index = 0,
                },
                });
            try builder.appendInstruction(unit, context, unwrap);
            const emit = true;
            const optional_type_index = optional_expression.type;
            const optional_type = unit.types.get(optional_type_index);
            const optional_struct = unit.structs.get(optional_type.@"struct");
            const optional_payload = unit.struct_fields.get( optional_struct.fields.items[0]);
            _ = try builder.emitLocalVariableDeclaration(unit, context, optional_payload_token, .@"const", optional_payload.type, .{
                .value = .{
                    .runtime = unwrap,
                },
                .type = optional_payload.type,
            }, emit, null);
        }

        _ = try builder.resolveRuntimeValue(unit, context, type_expect, taken_node_index, .right);
        if (!unit.basic_blocks.get(builder.current_basic_block).terminated) {
            try builder.jump(unit, context, exit_block);
        }

        if (not_taken_node_index != .null) {
            builder.current_basic_block = not_taken_block;
            _ = try builder.resolveRuntimeValue(unit, context, type_expect, not_taken_node_index, .right);
            if (!unit.basic_blocks.get(builder.current_basic_block).terminated) {
                try builder.jump(unit, context, exit_block);
            }
        }


        builder.current_basic_block = exit_block;
    }

    fn branch(builder: *Builder, unit: *Unit, context: *const Context, condition: Instruction.Index, taken_block: BasicBlock.Index, non_taken_block: BasicBlock.Index) !void {
        const br = try unit.instructions.append(context.allocator, .{
            .branch = .{
                .condition = condition,
                .from = builder.current_basic_block,
                .taken = taken_block,
                .not_taken = non_taken_block,
            },
            });

        try builder.appendInstruction(unit, context, br);

        unit.basic_blocks.get(builder.current_basic_block).terminated = true;
        unit.basic_blocks.get(taken_block).predecessor = builder.current_basic_block;
        unit.basic_blocks.get(non_taken_block).predecessor = builder.current_basic_block;
    }

    fn jump(builder: *Builder, unit: *Unit, context: *const Context, new_basic_block: BasicBlock.Index) !void {
        const instruction = try unit.instructions.append(context.allocator, .{
            .jump = .{
                .from = builder.current_basic_block,
                .to = new_basic_block, 
            },
            });

        try builder.appendInstruction(unit, context, instruction);

        unit.basic_blocks.get(builder.current_basic_block).terminated = true;
        unit.basic_blocks.get(new_basic_block).predecessor = builder.current_basic_block;
    }

    fn resolveSwitch(builder: *Builder, unit: *Unit, context: *const Context, type_expect: Type.Expect, node_index: Node.Index) !V {
        const node = unit.getNode(node_index);
        assert(node.id == .@"switch");
        const expression_to_switch_on = try builder.resolveRuntimeValue(unit, context, Type.Expect.none, node.left, .right);
        const case_nodes = unit.getNodeList(node.right);

        switch (expression_to_switch_on.value) {
            .@"comptime" => |ct| switch (ct) {
                .enum_value => |enum_field_index| {
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
                    return try builder.resolveRuntimeValue(unit, context, type_expect, true_switch_case_node.right, .right);
                },
                else => |t| @panic(@tagName(t)),
            },
            .runtime => todo(),
            else => |t| @panic(@tagName(t)),
        }
    }

    fn resolveFieldAccess(builder: *Builder, unit: *Unit, context: *const Context, type_expect: Type.Expect, node_index: Node.Index) !V {
        const node = unit.getNode(node_index);
        const right_node = unit.getNode(node.right);
        assert(right_node.id == .identifier);
        const identifier = unit.getExpectedTokenBytes(right_node.token,.identifier);
        const identifier_hash = try unit.processIdentifier(context, identifier);

        const left_node_index = node.left;
        const left = try builder.resolveRuntimeValue(unit, context, Type.Expect.none, left_node_index, .right);

        const result: V = switch (left.value) {
            .@"comptime" => |ct| switch (ct) {
                .type => |type_index| b: {
                    const left_type = unit.types.get(type_index);
                    const scope = left_type.getScope(unit);
                    const look_in_parent_scopes = false;

                    const result = if (scope.lookupDeclaration(identifier_hash, look_in_parent_scopes)) |lookup| blk: {
                        const global_decl_ref = try builder.referenceGlobalDeclaration(unit, context, lookup.scope, lookup.declaration);
                        break :blk global_decl_ref;
                    } else switch (left_type.*) {
                        .@"enum" => |enum_index| blk: {
                            const enum_type = unit.enums.get(enum_index);
                            const field_index = for (enum_type.fields.items) |enum_field_index| {
                                const enum_field = unit.enum_fields.get(enum_field_index);
                                if (enum_field.name == identifier_hash) {
                                    break enum_field_index;
                                }
                            } else @panic("identifier not found");
                            break :blk V{
                                .value = .{
                                    .@"comptime" = .{
                                        .enum_value = field_index,
                                    },
                                    },
                                .type = type_index,
                            };
                        },
                        else => |t| @panic(@tagName(t)),
                    };

                    break :b result;
                },
                .constant_struct => |constant_struct_index| b: {
                    const constant_struct = unit.constant_structs.get(constant_struct_index);
                    const type_index = constant_struct.type;
                    const left_type = unit.types.get(type_index);
                    const scope = left_type.getScope(unit);
                    const look_in_parent_scopes = false;
                    const result = if (scope.lookupDeclaration(identifier_hash, look_in_parent_scopes)) |lookup| blk: {
                        const global_decl_ref = try builder.referenceGlobalDeclaration(unit, context, lookup.scope, lookup.declaration);
                        break :blk global_decl_ref;
                    } else unreachable;

                    break :b result;
                },
                .constant_array => |constant_array_index| b: {
                    assert(equal(u8, identifier, "len"));
                    const constant_array = unit.constant_arrays.get(constant_array_index);
                    // TODO: typecheck
                    break :b switch (type_expect) {
                        .type => |type_index| .{
                            .value = .{
                                .@"comptime" = .{
                                    .constant_int = .{
                                        .value = constant_array.values.len,
                                    },
                                },
                            },
                            .type = type_index,
                        },
                        else => |t| @panic(@tagName(t)),
                    };
                },
                else => |t| @panic(@tagName(t)),
            },
            .runtime => |instruction_index| b: {
                _ = instruction_index;
                const left_type = unit.types.get(left.type);
                switch (left_type.*) {
                    .@"struct" => |struct_index| {
                        const struct_type = unit.structs.get(struct_index);
                        const fields = struct_type.fields.items;

                        for (fields, 0..) |field_index, i| {
                            const field = unit.struct_fields.get(field_index);
                            if (field.name == identifier_hash) {
                                const extract_value = try unit.instructions.append(context.allocator, .{
                                    .extract_value = .{
                                        .expression = left,
                                        .index = @intCast(i),
                                    },
                                });

                                try builder.appendInstruction(unit, context, extract_value);
                                break :b V{
                                    .value = .{
                                        .runtime = extract_value,
                                    },
                                    .type = field.type,
                                };
                            }
                        } else {
                            const scope = left_type.getScope(unit);
                            const look_in_parent_scopes = false;
                            if (scope.lookupDeclaration(identifier_hash, look_in_parent_scopes)) |lookup| {
                                const global_decl_ref = try builder.referenceGlobalDeclaration(unit, context, lookup.scope, lookup.declaration);
                                break :b global_decl_ref;
                            } else {
                                unreachable;
                            }
                        }
                    },
                    .@"enum" => {
                        unreachable;
                    },
                    .slice => |slice| {
                        const slice_field : enum{
                            ptr,
                            len,
                        } = if (equal(u8, "ptr", identifier)) .ptr else if (equal(u8, "len", identifier)) .len else unreachable;
                        const field_type = switch (slice_field) {
                            .ptr => slice.child_pointer_type,
                            .len => Type.Index.usize,
                        };
                        const field_index = @intFromEnum(slice_field);

                        const extract_value = try unit.instructions.append(context.allocator, .{
                            .extract_value = .{
                                .expression = left,
                                .index = field_index,
                            },
                        });

                        try builder.appendInstruction(unit, context, extract_value);

                        break :b .{
                            .value = .{
                                .runtime = extract_value,
                            },
                            .type = field_type,
                        };
                    },
                    .pointer => |pointer| switch (unit.types.get(pointer.type).*) {
                        .array => |array| {
                            assert(equal(u8, identifier, "len"));

                            break :b switch (type_expect) {
                                .type => |type_index| V{
                                    .value = .{
                                        .@"comptime" = .{
                                            .constant_int = .{
                                                .value = array.count,
                                            },
                                        },
                                    },
                                    .type = type_index,
                                },
                                else => |t| @panic(@tagName(t)),
                            };
                        },
                        else => |t| @panic(@tagName(t)),
                    },
                    .array => |array| {
                        assert(equal(u8, identifier, "len"));
                        break :b switch (type_expect) {
                            .type => |type_index| V{
                                .value = .{
                                    .@"comptime" = .{
                                        .constant_int = .{
                                            .value = array.count,
                                        },
                                    },
                                },
                                .type = type_index,
                            },
                            else => |t| @panic(@tagName(t)),
                        };
                    },
                    else => |t| @panic(@tagName(t)),
                }
            },
            else => |t| @panic(@tagName(t)),
        };

        switch (type_expect) {
            .none => return result,
            .type => |ti| {
                const typecheck_result = try builder.typecheck(unit, context, ti, result.type);
                switch (typecheck_result) {
                    .success => return result,
                    else => |t| @panic(@tagName(t)),
                }
            },
            else => unreachable,
        }
    }

    fn resolveIfElse(builder: *Builder, unit: *Unit, context: *const Context, type_expect: Type.Expect, node_index: Node.Index) !V{
        const node = unit.getNode(node_index);
        assert(node.left != .null);
        assert(node.right != .null);

        const if_node_index = node.left;
        const if_node = unit.getNode(if_node_index);
        const condition_node_index = if_node.left;
        const taken_expression_node_index = if_node.right;
        const not_taken_expression_node_index = node.right;
        assert(if_node.id == .@"if");
        try builder.insertDebugCheckPoint(unit, context, if_node.token);

        const condition = try builder.resolveRuntimeValue(unit, context, Type.Expect{ .type = .bool }, condition_node_index, .right);
        const result: V = switch (condition.value) {
            .@"comptime" => |ct| switch (ct.bool) {
                true => try builder.resolveRuntimeValue(unit, context, type_expect, taken_expression_node_index, .right),
                false => try builder.resolveRuntimeValue(unit, context, type_expect, not_taken_expression_node_index, .right),
            },
            .runtime => |condition_instruction| {
                try builder.resolveBranch(unit, context, type_expect, condition_instruction, taken_expression_node_index, not_taken_expression_node_index, .null);
                // TODO WARN SAFETY:
                return undefined;
            },
            else => unreachable,
        };

        return result;
    }
};

pub const Enum = struct {
    scope: Debug.Scope.Global,
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
    files: Debug.File.List = .{},
    // values: Value.List = .{},
    types: Type.List = .{},
    structs: Struct.List = .{},
    struct_fields: Struct.Field.List = .{},
    enums: Enum.List = .{},
    enum_fields: Enum.Field.List = .{},
    function_definitions: Function.Definition.List = .{},
    blocks: Debug.Block.List = .{},
    global_declarations: Debug.Declaration.Global.List = .{},
    local_declarations: Debug.Declaration.Local.List = .{},
    argument_declarations: Debug.Declaration.Argument.List = .{},
    assembly_instructions: InlineAssembly.Instruction.List = .{},
    function_prototypes: Function.Prototype.List = .{},
    inline_assembly: InlineAssembly.List = .{},
    instructions: Instruction.List = .{},
    basic_blocks: BasicBlock.List = .{},
    constant_structs: V.Comptime.ConstantStruct.List = .{},
    constant_arrays: V.Comptime.ConstantArray.List = .{},
    constant_slices: V.Comptime.ConstantSlice.List = .{},
    token_buffer: Token.Buffer = .{},
    node_lists: ArrayList(ArrayList(Node.Index)) = .{},
    file_token_offsets: AutoArrayHashMap(Token.Range, Debug.File.Index) = .{},
    file_map: StringArrayHashMap(Debug.File.Index) = .{},
    identifiers: StringKeyMap([]const u8) = .{},
    string_literal_values: AutoHashMap(u32, [:0]const u8) = .{},
    string_literal_globals: AutoHashMap(u32, *Debug.Declaration.Global) = .{},

    optionals: AutoHashMap(Type.Index, Type.Index) = .{},
    pointers: AutoHashMap(Type.Pointer, Type.Index) = .{},
    slices: AutoHashMap(Type.Slice, Type.Index) = .{},
    arrays: AutoHashMap(Type.Array, Type.Index) = .{},
    integers: AutoHashMap(Type.Integer, Type.Index) = .{},
    global_array_constants: AutoHashMap(V.Comptime.ConstantArray.Index, *Debug.Declaration.Global) = .{},

    code_to_emit: ArrayList(*Debug.Declaration.Global) = .{},
    data_to_emit: ArrayList(*Debug.Declaration.Global) = .{},
    type_declarations: AutoHashMap(Type.Index, *Debug.Declaration.Global) = .{},
    // function_declaration_map: AutoHashMap(Function.Definition.Index, Declaration.Index) = .{},
    // type_declaration_map: AutoHashMap(Type.Index, Declaration.Index) = .{},
    // TODO
    struct_type_map: AutoHashMap(Struct.Index, Type.Index) = .{},
    scope: Debug.Scope.Global = .{
        .scope = .{
            .file = .null,
            .kind = .compilation_unit,
            .line = 0,
            .column = 0,
            .level = 0,
            .local = false,
        },
    },
    main_package: *Package = undefined,
    descriptor: Descriptor,
    discard_identifiers: usize = 0,
    anon_i: usize = 0,
    anon_arr: usize = 0,

    fn dumpFunctionDefinition(unit: *Unit, function_definition_index: Function.Definition.Index) void {
        const function_definition = unit.function_definitions.get(function_definition_index);

        for (function_definition.basic_blocks.items) |basic_block_index| {
            const basic_block = unit.basic_blocks.get(basic_block_index);
            logln(.compilation, .ir, "[#{}]:", .{BasicBlock.unwrap(basic_block_index)});

            for (basic_block.instructions.items) |instruction_index| {
                const instruction = unit.instructions.get(instruction_index);
                log(.compilation, .ir, "    %{}: {s} ", .{Instruction.unwrap(instruction_index), @tagName(instruction.*)});

                switch (instruction.*) {
                    .insert_value => |insert_value| {
                        log(.compilation, .ir, "aggregate ", .{});
                        switch (insert_value.expression.value) {
                            .@"comptime" => log(.compilation, .ir, "comptime", .{}),
                            .runtime => |ii| log(.compilation, .ir, "%{}", .{Instruction.unwrap(ii)}),
                            else => unreachable,
                        }
                        log(.compilation, .ir, ", {}, ", .{insert_value.index});
                        switch (insert_value.new_value.value) {
                            .@"comptime" => log(.compilation, .ir, "comptime", .{}),
                            .runtime => |ii| log(.compilation, .ir, "%{}", .{Instruction.unwrap(ii)}),
                            else => unreachable,
                        }
                    },
                    .extract_value => |extract_value| {
                        log(.compilation, .ir, "aggregate ", .{});
                        switch (extract_value.expression.value) {
                            .@"comptime" => log(.compilation, .ir, "comptime", .{}),
                            .runtime => |ii| log(.compilation, .ir, "%{}", .{Instruction.unwrap(ii)}),
                            else => unreachable,
                        }
                        log(.compilation, .ir, ", {}", .{extract_value.index});
                    },
                    .get_element_pointer => |gep| {
                        log(.compilation, .ir, "aggregate %{}, ", .{Instruction.unwrap(gep.pointer)});
                        switch (gep.index.value) {
                            .@"comptime" => log(.compilation, .ir, "comptime", .{}),
                            .runtime => |ii| log(.compilation, .ir, "%{}", .{Instruction.unwrap(ii)}),
                            else => unreachable,
                        }
                    },
                    .load => |load| {
                        switch (load.value.value) {
                            .@"comptime" => unreachable,
                            .runtime => |ii| {
                                log(.compilation, .ir, "%{}", .{@intFromEnum(ii)});
                            },
                            else => unreachable,
                        }
                    },
                    .push_scope => |push_scope| {
                        log(.compilation, .ir, "0x{x} -> 0x{x}", .{@as(u24, @truncate(@intFromPtr(push_scope.old))), @as(u24, @truncate(@intFromPtr(push_scope.new)))});
                    },
                    .pop_scope => |pop_scope| {
                        log(.compilation, .ir, "0x{x} <- 0x{x}", .{@as(u24, @truncate(@intFromPtr(pop_scope.new))), @as(u24, @truncate(@intFromPtr(pop_scope.old)))});
                    },
                    .debug_checkpoint => |checkpoint| {
                        log(.compilation, .ir, "{}, {}", .{checkpoint.line, checkpoint.column});
                    },
                    .argument_declaration => |arg|{
                        log(.compilation, .ir, "\"{s}\"", .{unit.getIdentifier(arg.declaration.name)});
                    },
                    .cast => |cast| {
                        log(.compilation, .ir, "{s}", .{@tagName(cast.id)});
                    },
                    .jump => |jump| {
                        log(.compilation, .ir, "[#{}]", .{BasicBlock.unwrap(jump.to)});
                    },
                    .branch => |branch| {
                        log(.compilation, .ir, "bool %{}, [#{}, #{}]", .{Instruction.unwrap(branch.condition), BasicBlock.unwrap(branch.taken), BasicBlock.unwrap(branch.not_taken)});
                    },
                    .phi => |phi| {
                        for (phi.values.items, phi.basic_blocks.items) |value, bb| {
                            log(.compilation, .ir, "(%{}, #{}), ", .{switch (value.value) {
                                .@"comptime" => 0xffff_ffff,
                                .runtime => |ii| @intFromEnum(ii),
                                else => unreachable,
                                }, @intFromEnum(bb)});
                        }
                    },
                    .integer_compare => |compare| {
                        log(.compilation, .ir, "{s} ", .{@tagName(compare.id)});
                        switch (compare.left.value) {
                            .@"comptime" => {
                                log(.compilation, .ir, "$comptime, ", .{});
                            },
                            .runtime => |ii| {
                                log(.compilation, .ir, "%{}, ", .{@intFromEnum(ii)});
                            },
                            else => unreachable,
                        }

                        switch (compare.right.value) {
                            .@"comptime" => {
                                log(.compilation, .ir, "$comptime", .{});
                            },
                            .runtime => |ii| {
                                log(.compilation, .ir, "%{}", .{@intFromEnum(ii)});
                            },
                            else => unreachable,
                        }
                    },
                    else => {}
                }
                logln(.compilation, .ir, "",  .{});
            }
        }
    }

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
    fn findTokenFile(unit: *Unit, token_index: Token.Index) Debug.File.Index{
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
   
    fn getOptionalType(unit: *Unit, context: *const Context, element_type: Type.Index) !Type.Index{
        if (unit.optionals.get(element_type)) |optional| {
            return optional;
        } else {
            const optional_struct_index = try unit.structs.append(context.allocator, .{
                // TODO: this is going to bite my ass
                .scope = .{
                    .scope = .{
                        .file = @enumFromInt(0),
                        .line = 0,
                        .column = 0,
                        // can this trick the compiler?
                        .kind = .block,
                        .local = true,
                        .level = 0,
                    },
                },
                .backing_type = .null,
                .optional = true,
                .type = .null,
            });
            const optional_struct = unit.structs.get(optional_struct_index);
            try optional_struct.fields.ensureTotalCapacity(context.allocator, 2);
            const types = [_]Type.Index{element_type, .bool};
            const names = [_][]const u8{"payload", "is_valid"};
            for (types, names) |t, name| {
                const field = try unit.struct_fields.append(context.allocator, .{
                    .name = try unit.processIdentifier(context, name),
                    .type = t,
                    .default_value = null,
                });

                optional_struct.fields.appendAssumeCapacity(field);
            }

            const optional_type_index = try unit.types.append(context.allocator, .{
                .@"struct" = optional_struct_index,
            });

            try unit.optionals.putNoClobber(context.allocator, element_type, optional_type_index);
            
            return optional_type_index;
        }
    }

    fn getPointerType(unit: *Unit, context: *const Context, pointer: Type.Pointer) !Type.Index {
        if (unit.pointers.get(pointer)) |existing_type_index| {
            return existing_type_index;
        } else {
            const type_index = try unit.types.append(context.allocator, .{
                .pointer = pointer,
            });
            try unit.pointers.putNoClobber(context.allocator, pointer, type_index);

            return type_index;
        }
    }

    fn getSliceType(unit: *Unit, context: *const Context, slice: Type.Slice) !Type.Index{
        if (unit.slices.get(slice)) |existing_type_index| {
            return existing_type_index;
        } else {
            const type_index = try unit.types.append(context.allocator, .{
                .slice = slice,
            });
            try unit.slices.putNoClobber(context.allocator, slice, type_index);

            return type_index;
        }
    }

    fn getArrayType(unit: *Unit, context: *const Context, array: Type.Array) !Type.Index {
        if (unit.arrays.get(array)) |array_type| {
            return array_type;
        } else {
            const array_type = try unit.types.append(context.allocator, .{
                .array = array,
            });
            try unit.arrays.putNoClobber(context.allocator, array, array_type);
            
            return array_type;
        }
    }

    fn getIntegerType(unit: *Unit, context: *const Context, integer: Type.Integer) !Type.Index {
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
            else => {
                if (unit.integers.get(integer)) |type_index| {
                    return type_index;
                } else {
                    const type_index = try unit.types.append(context.allocator, .{
                        .integer = integer,
                    });
                    try unit.integers.putNoClobber(context.allocator, integer, type_index);
                    return type_index;
                }
            },
        };

        return existing_type_index;
    }

    fn processIdentifier(unit: *Unit, context: *const Context, string: []const u8) !u32 {
        const lookup_result = try unit.identifiers.getOrPut(context.allocator, string, string);
        return lookup_result.key;
    }

    fn fixupStringLiteral(unit: *Unit, context: *const Context, token_index: Token.Index) ![:0]const u8 {
        const bytes = unit.getExpectedTokenBytes(token_index, .string_literal);
        // Eat double quotes
        const string_literal_bytes = bytes[1..][0 .. bytes.len - 2];
        var fixed_string = try ArrayList(u8).initCapacity(context.allocator, string_literal_bytes.len + 1);
        var i: usize = 0;

        while (i < string_literal_bytes.len) : (i += 1) {
            const ch = string_literal_bytes[i];
            switch (ch) {
                '\\' => {
                    i += 1;
                    const next_ch = string_literal_bytes[i];
                    switch (next_ch) {
                        'n' => fixed_string.appendAssumeCapacity('\n'),
                        else => unreachable,
                    }
                },
                else => fixed_string.appendAssumeCapacity(ch),
            }
        }

        fixed_string.appendAssumeCapacity(0);

        const string = fixed_string.items[0 .. fixed_string.items.len - 1 :0];

        return string;
    }

    pub fn getIdentifier(unit: *Unit, hash: u32) []const u8 {
        return unit.identifiers.getValue(hash).?;
    }

    pub fn analyze(unit: *Unit, context: *const Context, main_package: *Package) !void {
        const builder = try context.allocator.create(Builder);
        builder.* = .{
            .generate_debug_info = unit.descriptor.generate_debug_information,
            .emit_ir = true,
            .current_scope = &unit.scope.scope,
        };

        inline for (@typeInfo(Type.Common).Enum.fields) |enum_field| {
            const e = @field(Type.Common, enum_field.name);
            const type_value = Type.Common.map.get(e);
            _ = try unit.types.append(context.allocator, type_value);
        }

        try builder.analyzePackage(unit, context, main_package);

        for (unit.code_to_emit.items) |function_declaration| {
            const function_definition_index = function_declaration.initial_value.function_definition;
            logln(.compilation, .ir, "Function #{} {s}", .{Function.Definition.unwrap(function_definition_index), unit.getIdentifier(function_declaration.declaration.name) });

            unit.dumpFunctionDefinition(function_definition_index);
        }
    }

    pub fn generateAbstractSyntaxTreeForFile(unit: *Unit, context: *const Context, file_index: Debug.File.Index) !void {
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
        file.parser = try parser.analyze(context.allocator, file.lexer, file.source_code, &unit.token_buffer, &unit.node_buffer, &unit.node_lists);
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

    pub fn importFile(unit: *Unit, context:*const Context, current_file_index: Debug.File.Index, import_name: []const u8) !ImportPackageResult {
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
                const file_index = try unit.files.append(context.allocator, Debug.File{
                    .relative_path = relative_path,
                    .package = package,
                    .scope = .{
                        .scope = .{
                            .file = .null,
                            .kind = .file,
                            .line = 0,
                            .column = 0,
                            .local = false,
                            .level = 1,
                        }
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
        value: V,
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
