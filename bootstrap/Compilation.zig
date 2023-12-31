const Compilation = @This();

const std = @import("std");
const assert = std.debug.assert;
const equal = std.mem.eql;

const Allocator = std.mem.Allocator;

const data_structures = @import("data_structures.zig");
const ArrayList = data_structures.ArrayList;
const AutoHashMap = data_structures.AutoHashMap;
const BlockList = data_structures.BlockList;
const HashMap = data_structures.HashMap;
const SegmentedList = data_structures.SegmentedList;
const StringKeyMap = data_structures.StringKeyMap;
const StringHashMap = data_structures.StringHashMap;
const StringArrayHashMap = data_structures.StringArrayHashMap;

const lexical_analyzer = @import("frontend/lexical_analyzer.zig");
const Token = lexical_analyzer.Token;
const syntactic_analyzer = @import("frontend/syntactic_analyzer.zig");
const Node = syntactic_analyzer.Node;
const semantic_analyzer = @import("frontend/semantic_analyzer.zig");
const c_transpiler = @import("backend/c_transpiler.zig");

test {
    _ = lexical_analyzer;
    _ = syntactic_analyzer;
    _ = semantic_analyzer;
    _ = data_structures;
}

base_allocator: Allocator,
cwd_absolute_path: []const u8,
directory_absolute_path: []const u8,
executable_absolute_path: []const u8,
build_directory: std.fs.Dir,

const cache_dir_name = "cache";
const installation_dir_name = "installation";

const ArgumentParsingError = error{
    main_package_path_not_specified,
    main_source_file_not_found,
};

fn reportUnterminatedArgumentError(string: []const u8) noreturn {
    std.debug.panic("Unterminated argument: {s}", .{string});
}

fn parseArguments(compilation: *const Compilation) !Compilation.Module.Descriptor {
    const allocator = compilation.base_allocator;
    const arguments = (try std.process.argsAlloc(allocator))[1..];

    var maybe_executable_path: ?[]const u8 = null;
    var maybe_main_package_path: ?[]const u8 = null;
    var target_triplet: []const u8 = "x86_64-linux-gnu";
    var should_transpile_to_c: ?bool = null;
    var maybe_only_parse: ?bool = null;
    var link_libc = false;
    var maybe_executable_name: ?[]const u8 = null;

    if (arguments.len == 0) {
        // foo
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
    const target = cross_target.toTarget();
    const transpile_to_c = should_transpile_to_c orelse true;
    const only_parse = maybe_only_parse orelse false;

    var is_build = false;
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

    const executable_path = maybe_executable_path orelse blk: {
        const executable_name = if (is_build) b: {
            assert(maybe_executable_name == null);
            break :b "build";
        } else b: {
            break :b if (maybe_executable_name) |name| name else std.fs.path.basename(main_package_path[0 .. main_package_path.len - "/main.nat".len]);
        };
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
    };
}

pub fn init(allocator: Allocator) !void {
    const compilation: *Compilation = try allocator.create(Compilation);

    const self_exe_path = try std.fs.selfExePathAlloc(allocator);
    const self_exe_dir_path = std.fs.path.dirname(self_exe_path).?;
    compilation.* = .{
        .base_allocator = allocator,
        .cwd_absolute_path = try realpathAlloc(allocator, "."),
        .executable_absolute_path = self_exe_path,
        .directory_absolute_path = self_exe_dir_path,
        .build_directory = try std.fs.cwd().makeOpenPath("nat", .{}),
    };

    try compilation.build_directory.makePath(cache_dir_name);
    try compilation.build_directory.makePath(installation_dir_name);

    const compilation_descriptor = try parseArguments(compilation);

    try compilation.compileModule(compilation_descriptor);
}

pub const Struct = struct {
    scope: Scope.Index,
    fields: ArrayList(ContainerField.Index) = .{},
    backing_type: Type.Index,

    pub const List = BlockList(@This());
    pub const Index = List.Index;
};

pub const ContainerField = struct {
    name: u32,
    type: Type.Index,
    default_value: Value.Index,
    parent: Type.Index,

    pub const List = BlockList(@This());
    pub const Index = List.Index;
};

pub const ContainerInitialization = struct {
    field_initializations: ArrayList(Value.Index),
    type: Type.Index,

    pub const List = BlockList(@This());
    pub const Index = List.Index;
};

pub const Type = union(enum) {
    any,
    void,
    noreturn,
    bool,
    type,
    comptime_int,
    integer: Type.Integer,
    slice: Type.Slice,
    pointer: Pointer,
    @"struct": Struct.Index,
    @"enum": Enum.Index,
    function: Function.Prototype.Index,
    array: Array,
    optional: Optional,

    pub const Optional = struct {
        element_type: Type.Index,
    };

    pub const Termination = enum {
        none,
        null,
        zero,
    };

    pub const Array = struct {
        element_type: Type.Index,
        element_count: usize,
        termination: Termination,
    };

    pub const Slice = struct {
        element_type: Type.Index,
        @"const": bool,
        termination: Termination,
    };

    pub const Pointer = struct {
        element_type: Type.Index,
        many: bool,
        @"const": bool,
        termination: Termination,
    };

    pub const List = BlockList(@This());
    pub const Index = List.Index;

    pub const Enum = struct {
        scope: Scope.Index,
        fields: ArrayList(Enum.Field.Index) = .{},
        backing_type: Type.Index,

        pub const Field = struct {
            name: u32,
            value: Value.Index,
            parent: Type.Index,

            pub const List = BlockList(@This());
            pub const Index = Enum.Field.List.Index;
        };

        pub const List = BlockList(@This());
        pub const Index = Enum.List.Index;
    };

    pub const Integer = struct {
        bit_count: u16,
        signedness: Signedness,
        pub const Signedness = enum(u1) {
            unsigned = 0,
            signed = 1,
        };

        pub fn getSize(integer: Integer) u64 {
            return integer.bit_count / @bitSizeOf(u8) + @intFromBool(integer.bit_count % @bitSizeOf(u8) != 0);
        }

        pub fn getIndex(integer: Integer) Compilation.Type.Index {
            return .{
                .block = 0,
                .element = @ctz(integer.bit_count) - @ctz(@as(u8, 8)) + @as(u6, switch (integer.signedness) {
                    .signed => Compilation.HardwareSignedIntegerType.offset,
                    .unsigned => Compilation.HardwareUnsignedIntegerType.offset,
                }),
            };
        }

        // pub fn get(bit_count: u16, comptime signedness: Signedness) @This().Type(signedness) {
        //     _ = bit_count;
        // }

        fn Type(comptime signedness: Signedness) type {
            return switch (signedness) {
                .unsigned => HardwareUnsignedIntegerType,
                .signed => HardwareSignedIntegerType,
            };
        }
    };

    pub fn getSize(type_info: Type) u64 {
        return switch (type_info) {
            .integer => |integer| integer.getSize(),
            .pointer => 8,
            .comptime_int => @panic("This call should never happen"),
            else => |t| @panic(@tagName(t)),
        };
    }

    pub fn getBitSize(type_info: Type) u64 {
        return switch (type_info) {
            .integer => |integer| integer.bit_count,
            .pointer => 8,
            .bool => 1,
            .comptime_int => @panic("This call should never happen"),
            else => |t| @panic(@tagName(t)),
        };
    }

    pub fn getAlignment(type_info: Type) u64 {
        return switch (type_info) {
            .integer => |integer| @min(16, integer.getSize()),
            .pointer => 8,
            else => |t| @panic(@tagName(t)),
        };
    }

    pub const any = FixedTypeKeyword.any.toType();
    pub const @"void" = FixedTypeKeyword.void.toType();
    pub const boolean = FixedTypeKeyword.bool.toType();
    pub const ssize = FixedTypeKeyword.ssize.toType();
    pub const @"usize" = FixedTypeKeyword.usize.toType();
    pub const @"noreturn" = FixedTypeKeyword.noreturn.toType();
    pub const @"type" = FixedTypeKeyword.type.toType();
    pub const @"comptime_int" = FixedTypeKeyword.comptime_int.toType();
    pub const string_literal = ExtraCommonType.string_literal.toType();
    pub const @"u8" = Type.Integer.getIndex(.{
        .bit_count = 8,
        .signedness = .unsigned,
    });
    pub const @"u16" = Type.Integer.getIndex(.{
        .bit_count = 16,
        .signedness = .unsigned,
    });
    pub const @"u32" = Type.Integer.getIndex(.{
        .bit_count = 32,
        .signedness = .unsigned,
    });
    pub const @"u64" = Type.Integer.getIndex(.{
        .bit_count = 64,
        .signedness = .unsigned,
    });
};

pub const Intrinsic = struct {
    kind: Kind,
    type: Type.Index,

    pub const Kind = union(enum) {
        cast: Value.Index,
        array_coerce_to_slice: Value.Index,
        min: Binary,
        optional_wrap: Value.Index,
        optional_unwrap: Value.Index,
        optional_check: Value.Index,
        sign_extend: Value.Index,
        syscall: ArrayList(Value.Index),
        zero_extend: Value.Index,

        pub const Binary = struct {
            left: Value.Index,
            right: Value.Index,
        };
    };

    pub const List = BlockList(@This());
    pub const Index = @This().List.Index;
};

// Each time an enum is added here, a corresponding insertion in the initialization must be made
pub const ValidIntrinsic = enum {
    //@"asm", this is processed separately as it need special parsing
    cast,
    @"error",
    import,
    min,
    size,
    syscall,
};

pub const FixedTypeKeyword = enum {
    void,
    noreturn,
    bool,
    usize,
    ssize,
    type,
    comptime_int,
    any,

    const offset = 0;

    fn toType(fixed_type_keyword: FixedTypeKeyword) Type.Index {
        return Type.Index.fromInteger(offset + @intFromEnum(fixed_type_keyword));
    }
};

pub const HardwareUnsignedIntegerType = enum {
    u8,
    u16,
    u32,
    u64,

    pub const offset = @typeInfo(FixedTypeKeyword).Enum.fields.len;
};

pub const HardwareSignedIntegerType = enum {
    s8,
    s16,
    s32,
    s64,

    pub const offset = HardwareUnsignedIntegerType.offset + @typeInfo(HardwareUnsignedIntegerType).Enum.fields.len;
};

pub const ExtraCommonType = enum {
    string_literal,
    pub const offset = HardwareSignedIntegerType.offset + @typeInfo(HardwareSignedIntegerType).Enum.fields.len;

    fn toType(t: ExtraCommonType) Type.Index {
        return Type.Index.fromInteger(offset + @intFromEnum(t));
    }
};

pub const extra_common_type_data = blk: {
    var result: [@typeInfo(ExtraCommonType).Enum.fields.len]Type = undefined;
    result[@intFromEnum(ExtraCommonType.string_literal)] = .{
        .pointer = .{
            .many = true,
            .@"const" = true,
            .element_type = Type.u8,
            .termination = .null,
        },
    };

    break :blk result;
};

/// A scope contains a bunch of declarations
pub const Scope = struct {
    declarations: data_structures.AutoArrayHashMap(u32, Declaration.Index) = .{},
    parent: Scope.Index,
    file: File.Index,
    token: Token.Index,
    type: Type.Index = Type.Index.invalid,

    pub const List = BlockList(@This());
    pub const Index = List.Index;
};

pub const ScopeType = enum(u1) {
    local = 0,
    global = 1,
};

pub const Mutability = enum(u1) {
    @"const",
    @"var",
};

pub const Declaration = struct {
    scope_type: ScopeType,
    mutability: Mutability,
    init_value: Value.Index,
    name: u32,
    argument_index: ?u32,
    // A union is needed here because of global lazy declarations
    type: Declaration.Type,
    scope: Scope.Index,

    pub const Reference = struct {
        value: Declaration.Index,

        pub fn getType(reference: Reference, module: *Module) Compilation.Type.Index {
            return module.values.declarations.get(reference.value).getType();
        }
    };

    pub const Type = union(enum) {
        resolved: Compilation.Type.Index,
        inferred: Compilation.Type.Index,
        unresolved: Node.Index,
    };

    pub fn getType(declaration: *Declaration) Compilation.Type.Index {
        const type_index: Compilation.Type.Index = switch (declaration.type) {
            .resolved => |resolved| resolved,
            .inferred => |inferred| inferred,
            .unresolved => unreachable,
        };

        assert(!type_index.invalid);

        return type_index;
    }

    pub const List = BlockList(@This());
    pub const Index = List.Index;
};

pub const Function = struct {
    body: Block.Index,
    prototype: Type.Index,

    pub const Prototype = struct {
        arguments: ArrayList(Declaration.Index),
        return_type: Type.Index,
        attributes: Attributes = .{},
        scope: Scope.Index,

        pub const List = BlockList(@This());
        pub const Index = Prototype.List.Index;

        pub const Attributes = struct {
            @"extern": bool = false,
            @"export": bool = false,
            @"inline": Inline = .none,
            calling_convention: CallingConvention = .system_v,

            pub const Inline = enum {
                none,
                suggestion_optimizer,
                force_semantic,
                force_optimizer,
            };
        };
    };

    pub fn getBodyBlock(function: Function, module: *Module) *Block {
        return module.blocks.get(function.body);
    }

    pub const List = BlockList(@This());
    pub const Index = List.Index;
};

pub const Block = struct {
    statements: ArrayList(Value.Index) = .{},
    reaches_end: bool,
    pub const List = BlockList(@This());
    pub const Index = List.Index;
};

pub const Loop = struct {
    pre: Value.Index,
    condition: Value.Index,
    body: Value.Index,
    post: Value.Index,
    reaches_end: bool,

    pub const List = BlockList(@This());
    pub const Index = List.Index;
};

const Unresolved = struct {
    node_index: Node.Index,
};

pub const Assignment = struct {
    destination: Value.Index,
    source: Value.Index,
    operation: Operation,

    const Operation = enum {
        none,
        add,
    };

    pub const List = BlockList(@This());
    pub const Index = List.Index;
};

pub const Syscall = struct {
    number: Value.Index,
    arguments: [6]Value.Index,
    argument_count: u8,

    pub fn getArguments(syscall: *const Syscall) []const Value.Index {
        return syscall.arguments[0..syscall.argument_count];
    }

    pub const List = BlockList(@This());
    pub const Index = List.Index;
};

pub const Call = struct {
    value: Value.Index,
    arguments: ArgumentList.Index,
    type: Type.Index,

    pub const List = BlockList(@This());
    pub const Index = List.Index;
};

pub const ArgumentList = struct {
    array: ArrayList(Value.Index),
    pub const List = BlockList(@This());
    pub const Index = List.Index;
};

pub const Return = struct {
    value: Value.Index,
    pub const List = BlockList(@This());
    pub const Index = List.Index;
};

pub const Cast = struct {
    value: Value.Index,
    type: Type.Index,

    pub const List = BlockList(@This());
    pub const Index = List.Index;
};

pub const BinaryOperation = struct {
    left: Value.Index,
    right: Value.Index,
    type: Type.Index,
    id: Id,

    pub const List = BlockList(@This());
    pub const Index = List.Index;

    pub const Id = enum {
        add,
        sub,
        bit_and,
        bit_xor,
        bit_or,
        multiply,
        divide,
        shift_left,
        shift_right,
        compare_equal,
        compare_greater_than,
        compare_greater_or_equal,
        compare_less_than,
        compare_less_or_equal,
        compare_not_equal,
    };
};

pub const UnaryOperation = struct {
    value: Value.Index,
    type: Type.Index,
    id: Id,

    pub const List = BlockList(@This());
    pub const Index = List.Index;

    pub const Id = enum {
        boolean_not,
        negation,
        address_of,
        pointer_dereference,
    };
};

pub const CallingConvention = enum {
    system_v,
    naked,
};

pub const Branch = struct {
    expression: Value.Index,
    taken_expression: Value.Index,
    not_taken_expression: Value.Index,
    reaches_end: bool,

    pub const List = BlockList(@This());
    pub const Index = List.Index;
};

pub const Switch = struct {
    value: Value.Index,
    groups: ArrayList(Group),

    pub const Group = struct {
        conditions: ArrayList(Value.Index),
        expression: Value.Index,
    };

    pub const List = BlockList(@This());
    pub const Index = List.Index;
};

pub const FieldAccess = struct {
    declaration_reference: Value.Index,
    field: ContainerField.Index,

    pub const List = BlockList(@This());
    pub const Index = List.Index;
};

pub const Range = struct {
    start: Value.Index,
    end: Value.Index,
};

pub const Slice = struct {
    sliceable: Value.Index,
    range: Range,
    type: Type.Index,

    pub const Access = struct {
        value: Value.Index,
        field: Field,
        type: Type.Index,

        pub const List = BlockList(@This());
        pub const Index = Slice.Access.List.Index;
    };

    pub const Field = enum {
        ptr,
        len,
    };

    pub const List = BlockList(@This());
    pub const Index = List.Index;
};

pub const IndexedAccess = struct {
    indexed_expression: Value.Index,
    index_expression: Value.Index,

    pub const List = BlockList(@This());
    pub const Index = List.Index;
};

pub const OptionalCheck = struct {
    value: Value.Index,

    pub const List = BlockList(@This());
    pub const Index = List.Index;
};

pub const OptionalUnwrap = struct {
    value: Value.Index,

    pub const List = BlockList(@This());
    pub const Index = List.Index;
};

pub const Assembly = struct {
    pub const Instruction = struct {
        id: u32,
        operands: []const Operand,

        pub const List = BlockList(@This());
        pub const Index = List.Index;
    };

    pub const Operand = union(enum) {
        register: u32,
        number_literal: u64,
        value_index: Value.Index,
    };

    pub const Block = struct {
        instructions: []const Assembly.Instruction.Index,

        pub const List = BlockList(@This());
        pub const Index = List.Index;
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

pub const StringLiteral = struct {
    hash: u32,
    type: Type.Index,
};

pub const Value = union(enum) {
    void,
    @"break",
    undefined,
    @"unreachable",
    bool: bool,
    pointer_null_literal,
    optional_null_literal,
    unresolved: Unresolved,
    intrinsic: Intrinsic.Index,
    declaration: Declaration.Index,
    declaration_reference: Declaration.Reference,
    loop: Loop.Index,
    function_definition: Function.Index,
    function_declaration: Function.Index,
    block: Block.Index,
    assign: Assignment.Index,
    type: Type.Index,
    integer: Integer,
    call: Call.Index,
    argument_list: ArgumentList,
    @"return": Return.Index,
    argument: Declaration.Index,
    string_literal: StringLiteral,
    enum_field: Type.Enum.Field.Index,
    extern_function: Function.Prototype.Index,
    binary_operation: BinaryOperation.Index,
    unary_operation: UnaryOperation.Index,
    branch: Branch.Index,
    container_initialization: ContainerInitialization.Index,
    array_initialization: ContainerInitialization.Index,
    field_access: FieldAccess.Index,
    slice_access: Slice.Access.Index,
    indexed_access: IndexedAccess.Index,
    optional_check: OptionalCheck.Index,
    optional_unwrap: OptionalUnwrap.Index,
    array_coerce_to_slice: Cast.Index,
    slice: Slice.Index,
    assembly_block: Assembly.Block.Index,
    switch_expression: Switch.Index,

    pub const List = BlockList(@This());
    pub const Index = List.Index;

    pub const Integer = struct {
        value: u64,
        type: Type.Index,
        signedness: Type.Integer.Signedness,

        pub fn getBitCount(integer: Integer, module: *Module) u16 {
            return module.types.get(integer.type).integer.bit_count;
        }
    };

    pub fn isComptime(value: *Value, module: *Module) bool {
        _ = module;

        return switch (value.*) {
            .bool,
            .void,
            .function_definition,
            .function_declaration,
            .type,
            .enum_field,
            .string_literal,
            => true,
            .integer => |integer| integer.type.eq(Type.comptime_int),
            .declaration_reference => false,
            // TODO:
            .call,
            // .syscall,
            .binary_operation,
            .container_initialization,
            // .cast,
            .optional_unwrap,
            .pointer_null_literal,
            .indexed_access,
            .slice,
            .array_initialization,
            .undefined,
            .intrinsic,
            .field_access,
            => false,
            // TODO:
            else => |t| @panic(@tagName(t)),
        };
    }

    pub fn getType(value: Value, module: *Module) Type.Index {
        const result = switch (value) {
            .call => |call_index| module.values.calls.get(call_index).type,
            .integer => |integer| integer.type,
            .declaration_reference => |declaration_reference| declaration_reference.getType(module),
            .string_literal => |string_literal| string_literal.type,
            .type => Type.type,
            .enum_field => |enum_field_index| module.types.enum_fields.get(enum_field_index).parent,
            .function_definition => |function_index| module.types.function_definitions.get(function_index).prototype,
            .function_declaration => |function_index| module.types.function_declarations.get(function_index).prototype,
            .binary_operation => |binary_operation| module.values.binary_operations.get(binary_operation).type,
            .bool => Type.boolean,
            // .declaration => Type.void,
            .container_initialization,
            .array_initialization,
            => |initialization| module.values.container_initializations.get(initialization).type,
            .intrinsic => |intrinsic_index| module.values.intrinsics.get(intrinsic_index).type,
            .unary_operation => |unary_operation_index| module.values.unary_operations.get(unary_operation_index).type,
            .pointer_null_literal => semantic_analyzer.optional_pointer_to_any_type,
            .optional_null_literal => semantic_analyzer.optional_any,
            .field_access => |field_access_index| module.types.container_fields.get(module.values.field_accesses.get(field_access_index).field).type,
            // .cast,
            // .optional_cast,
            // .array_coerce_to_slice => |cast_index| module.values.casts.get(cast_index).type,
            .slice => |slice_index| module.values.slices.get(slice_index).type,
            .slice_access => |slice_access_index| module.values.slice_accesses.get(slice_access_index).type,
            .optional_check => Type.boolean,
            .indexed_access => |indexed_access_index| blk: {
                const indexed_expression = module.values.array.get(module.values.indexed_accesses.get(indexed_access_index).indexed_expression);
                const indexed_expression_type_index = indexed_expression.getType(module);
                const indexed_expression_type = module.types.array.get(indexed_expression_type_index);

                break :blk switch (indexed_expression_type.*) {
                    .slice => |slice| slice.element_type,
                    .array => |array| array.element_type,
                    .pointer => |pointer| switch (pointer.many) {
                        true => pointer.element_type,
                        false => unreachable,
                    },
                    else => |t| @panic(@tagName(t)),
                };
            },
            .undefined => Type.any,
            .optional_unwrap => |optional_unwrap_index| blk: {
                const optional_unwrap = module.values.optional_unwraps.get(optional_unwrap_index);
                const optional_value = module.values.array.get(optional_unwrap.value);
                const expected_optional_type_index = optional_value.getType(module);
                const expected_optional_type = module.types.array.get(expected_optional_type_index);

                break :blk switch (expected_optional_type.*) {
                    .optional => |optional| optional.element_type,
                    else => |t| @panic(@tagName(t)),
                };
            },
            .branch => |branch_index| {
                // TODO
                const branch = module.values.branches.get(branch_index);
                const taken = module.values.array.get(branch.taken_expression);
                const not_taken = module.values.array.get(branch.not_taken_expression);
                const taken_type = taken.getType(module);
                const not_taken_type = not_taken.getType(module);
                _ = not_taken_type;
                return taken_type;
            },
            else => |t| @panic(@tagName(t)),
        };

        return result;
    }

    const TypeCheckError = error{
        integer_size,
        pointer_many_differ,
        pointer_element_type_differ,
    };
};

pub const Module = struct {
    values: struct {
        field_accesses: BlockList(FieldAccess) = .{},
        array: BlockList(Value) = .{},
        declarations: BlockList(Declaration) = .{},
        scopes: BlockList(Scope) = .{},
        files: BlockList(File) = .{},
        blocks: BlockList(Block) = .{},
        loops: BlockList(Loop) = .{},
        assignments: BlockList(Assignment) = .{},
        intrinsics: BlockList(Intrinsic) = .{},
        // syscalls: BlockList(Syscall) = .{},
        calls: BlockList(Call) = .{},
        argument_lists: BlockList(ArgumentList) = .{},
        returns: BlockList(Return) = .{},
        container_initializations: BlockList(ContainerInitialization) = .{},
        // casts: BlockList(Cast) = .{},
        branches: BlockList(Branch) = .{},
        binary_operations: BlockList(BinaryOperation) = .{},
        unary_operations: BlockList(UnaryOperation) = .{},
        slices: BlockList(Slice) = .{},
        slice_accesses: BlockList(Slice.Access) = .{},
        indexed_accesses: BlockList(IndexedAccess) = .{},
        optional_checks: BlockList(OptionalCheck) = .{},
        optional_unwraps: BlockList(OptionalUnwrap) = .{},
        assembly_blocks: BlockList(Assembly.Block) = .{},
        assembly_instructions: BlockList(Assembly.Instruction) = .{},
        switches: BlockList(Switch) = .{},
    } = .{},
    types: struct {
        array: BlockList(Type) = .{},
        enums: BlockList(Type.Enum) = .{},
        structs: BlockList(Struct) = .{},
        container_fields: BlockList(ContainerField) = .{},
        enum_fields: BlockList(Type.Enum.Field) = .{},
        function_definitions: BlockList(Function) = .{},
        function_declarations: BlockList(Function) = .{},
        function_prototypes: BlockList(Function.Prototype) = .{},
    } = .{},
    map: struct {
        function_definitions: data_structures.AutoArrayHashMap(Function.Index, Declaration.Index) = .{},
        function_declarations: data_structures.AutoArrayHashMap(Function.Index, Declaration.Index) = .{},
        strings: StringKeyMap([]const u8) = .{},
        imports: StringArrayHashMap(File.Index) = .{},
        types: data_structures.AutoArrayHashMap(Type.Index, Declaration.Index) = .{},
        non_primitive_integer: data_structures.AutoArrayHashMap(Type.Integer, Type.Index) = .{},
        slices: data_structures.AutoArrayHashMap(Type.Slice, Type.Index) = .{},
        pointers: data_structures.AutoArrayHashMap(Type.Pointer, Type.Index) = .{},
        optionals: data_structures.AutoArrayHashMap(Type.Index, Type.Index) = .{},
        arrays: data_structures.AutoArrayHashMap(Type.Array, Type.Index) = .{},
        libraries: data_structures.StringArrayHashMap(void) = .{},
    } = .{},
    main_package: *Package,
    entry_point: Function.Index = Function.Index.invalid,
    descriptor: Descriptor,

    pub const Descriptor = struct {
        main_package_path: []const u8,
        executable_path: []const u8,
        target: std.Target,
        transpile_to_c: bool,
        is_build: bool,
        only_parse: bool,
        link_libc: bool,
    };

    const ImportFileResult = struct {
        index: File.Index,
        is_new: bool,
    };

    const ImportPackageResult = struct {
        file: ImportFileResult,
        is_package: bool,
    };

    pub fn importFile(module: *Module, allocator: Allocator, current_file_index: File.Index, import_name: []const u8) !ImportPackageResult {
        logln(.compilation, .import, "import: '{s}'\n", .{import_name});
        if (equal(u8, import_name, "std")) {
            return module.importPackage(allocator, module.main_package.dependencies.get("std").?);
        }

        if (equal(u8, import_name, "builtin")) {
            return module.importPackage(allocator, module.main_package.dependencies.get("builtin").?);
        }

        if (equal(u8, import_name, "main")) {
            return module.importPackage(allocator, module.main_package);
        }

        const current_file = module.values.files.get(current_file_index);
        if (current_file.package.dependencies.get(import_name)) |package| {
            return module.importPackage(allocator, package);
        }

        if (!std.mem.endsWith(u8, import_name, ".nat")) {
            unreachable;
        }

        const current_file_relative_path_to_package_directory = std.fs.path.dirname(current_file.relative_path) orelse "";
        const import_file_relative_path = try std.fs.path.join(allocator, &.{ current_file_relative_path_to_package_directory, import_name });
        const full_path = try std.fs.path.join(allocator, &.{ current_file.package.directory.path, import_file_relative_path });
        const file_relative_path = import_file_relative_path;
        const package = current_file.package;
        const import_file = try module.getFile(allocator, full_path, file_relative_path, package);

        try module.values.files.get(import_file.index).file_references.append(allocator, current_file);

        const result = ImportPackageResult{
            .file = import_file,
            .is_package = false,
        };

        return result;
    }

    fn getFile(module: *Module, allocator: Allocator, full_path: []const u8, relative_path: []const u8, package: *Package) !ImportFileResult {
        const path_lookup = try module.map.imports.getOrPut(allocator, full_path);
        const index = switch (path_lookup.found_existing) {
            true => path_lookup.value_ptr.*,
            false => blk: {
                const file_index = try module.values.files.append(allocator, File{
                    .relative_path = relative_path,
                    .package = package,
                });
                logln(.compilation, .new_file, "Adding file #{}: {s}\n", .{ file_index.uniqueInteger(), full_path });
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

    pub fn importPackage(module: *Module, allocator: Allocator, package: *Package) !ImportPackageResult {
        const full_path = try std.fs.path.resolve(allocator, &.{ package.directory.path, package.source_path });
        logln(.compilation, .import, "Import full path: {s}\n", .{full_path});
        const import_file = try module.getFile(allocator, full_path, package.source_path, package);
        const file = module.values.files.get(import_file.index);
        try file.addPackageReference(allocator, package);

        return .{
            .file = import_file,
            .is_package = true,
        };
    }

    pub fn generateAbstractSyntaxTreeForFile(module: *Module, allocator: Allocator, file_index: File.Index) !void {
        const file = module.values.files.get(file_index);
        const source_file = file.package.directory.handle.openFile(file.relative_path, .{}) catch |err| {
            std.debug.panic("Can't find file {s} in directory {s} for error {s}", .{ file.relative_path, file.package.directory.path, @errorName(err) });
        };

        const file_size = try source_file.getEndPos();
        var file_buffer = try allocator.alloc(u8, file_size);

        const read_byte_count = try source_file.readAll(file_buffer);
        assert(read_byte_count == file_size);
        source_file.close();

        //TODO: adjust file maximum size
        file.source_code = file_buffer[0..read_byte_count];
        file.status = .loaded_into_memory;

        try file.lex(allocator, file_index);
        try file.parse(allocator, file_index);
    }

    fn getString(map: *StringKeyMap([]const u8), key: u32) ?[]const u8 {
        return map.getValue(key);
    }

    pub fn addString(map: *StringKeyMap([]const u8), allocator: Allocator, string: []const u8) !u32 {
        const lookup_result = try map.getOrPut(allocator, string, string);
        return lookup_result.key;
    }

    pub fn getName(module: *Module, key: u32) ?[]const u8 {
        return getString(&module.map.strings, key);
    }

    pub fn addName(module: *Module, allocator: Allocator, name: []const u8) !u32 {
        return addString(&module.map.strings, allocator, name);
    }
};

fn pathFromCwd(compilation: *const Compilation, relative_path: []const u8) ![]const u8 {
    return std.fs.path.join(compilation.base_allocator, &.{ compilation.cwd_absolute_path, relative_path });
}

fn pathFromCompiler(compilation: *const Compilation, relative_path: []const u8) ![]const u8 {
    return std.fs.path.join(compilation.base_allocator, &.{ compilation.directory_absolute_path, relative_path });
}

fn realpathAlloc(allocator: Allocator, pathname: []const u8) ![]const u8 {
    var path_buffer: [std.fs.MAX_PATH_BYTES]u8 = undefined;
    const realpathInStack = try std.os.realpath(pathname, &path_buffer);
    return allocator.dupe(u8, realpathInStack);
}

pub fn compileModule(compilation: *Compilation, descriptor: Module.Descriptor) !void {
    const module: *Module = try compilation.base_allocator.create(Module);
    module.* = Module{
        .main_package = blk: {
            const result = try compilation.base_allocator.create(Package);
            const main_package_absolute_directory_path = b: {
                const relative_path = if (std.fs.path.dirname(descriptor.main_package_path)) |dirname| dirname else ".";
                break :b try compilation.pathFromCwd(relative_path);
            };
            result.* = .{
                .directory = .{
                    .handle = try std.fs.openDirAbsolute(main_package_absolute_directory_path, .{}),
                    .path = main_package_absolute_directory_path,
                },
                .source_path = try compilation.base_allocator.dupe(u8, std.fs.path.basename(descriptor.main_package_path)),
            };
            break :blk result;
        },
        .descriptor = descriptor,
    };

    const builtin_file_name = "builtin.nat";
    var cache_dir = try compilation.build_directory.openDir("cache", .{});
    const builtin_file = try cache_dir.createFile(builtin_file_name, .{});
    try builtin_file.writer().print(
        \\const builtin = #import("std").builtin;
        \\const cpu = builtin.Cpu.{s};
        \\const os = builtin.Os.{s};
        \\const abi = builtin.Abi.{s};
        \\const link_libc = {};
        \\
    , .{
        @tagName(module.descriptor.target.cpu.arch),
        @tagName(module.descriptor.target.os.tag),
        @tagName(module.descriptor.target.abi),
        module.descriptor.link_libc,
    });
    builtin_file.close();

    const std_package_dir = "lib/std";

    const package_descriptors = [2]struct {
        name: []const u8,
        directory_path: []const u8,
    }{
        .{
            .name = "std",
            .directory_path = try compilation.pathFromCompiler(std_package_dir),
        },
        .{
            .name = "builtin",
            .directory_path = blk: {
                const result = try cache_dir.realpathAlloc(compilation.base_allocator, ".");
                cache_dir.close();
                break :blk result;
            },
        },
    };

    var packages: [package_descriptors.len]*Package = undefined;
    for (package_descriptors, &packages) |package_descriptor, *package_ptr| {
        const package = try compilation.base_allocator.create(Package);
        package.* = .{
            .directory = .{
                .path = package_descriptor.directory_path,
                .handle = try std.fs.openDirAbsolute(package_descriptor.directory_path, .{}),
            },
            .source_path = try std.mem.concat(compilation.base_allocator, u8, &.{ package_descriptor.name, ".nat" }),
        };

        try module.main_package.addDependency(compilation.base_allocator, package_descriptor.name, package);

        package_ptr.* = package;
    }

    assert(module.main_package.dependencies.size == 2);

    if (!module.descriptor.only_parse) {
        _ = try module.importPackage(compilation.base_allocator, module.main_package.dependencies.get("std").?);
    } else {
        _ = try module.importPackage(compilation.base_allocator, module.main_package);
    }

    for (module.map.imports.values()) |import| {
        try module.generateAbstractSyntaxTreeForFile(compilation.base_allocator, import);
    }

    if (!module.descriptor.only_parse) {
        inline for (@typeInfo(FixedTypeKeyword).Enum.fields) |enum_field| {
            _ = try module.types.array.append(compilation.base_allocator, switch (@field(FixedTypeKeyword, enum_field.name)) {
                .usize => @unionInit(Type, "integer", .{
                    .bit_count = 64,
                    .signedness = .unsigned,
                }),
                .ssize => @unionInit(Type, "integer", .{
                    .bit_count = 64,
                    .signedness = .signed,
                }),
                else => @unionInit(Type, enum_field.name, {}),
            });
        }

        inline for (@typeInfo(HardwareUnsignedIntegerType).Enum.fields) |enum_field| {
            _ = try module.types.array.append(compilation.base_allocator, .{
                .integer = .{
                    .signedness = .unsigned,
                    .bit_count = switch (@field(HardwareUnsignedIntegerType, enum_field.name)) {
                        .u8 => 8,
                        .u16 => 16,
                        .u32 => 32,
                        .u64 => 64,
                    },
                },
            });
        }

        inline for (@typeInfo(HardwareSignedIntegerType).Enum.fields) |enum_field| {
            _ = try module.types.array.append(compilation.base_allocator, .{
                .integer = .{
                    .signedness = .signed,
                    .bit_count = switch (@field(HardwareSignedIntegerType, enum_field.name)) {
                        .s8 => 8,
                        .s16 => 16,
                        .s32 => 32,
                        .s64 => 64,
                    },
                },
            });
        }

        for (extra_common_type_data) |type_data| {
            _ = try module.types.array.append(compilation.base_allocator, type_data);
        }
        semantic_analyzer.pointer_to_any_type = try module.types.array.append(compilation.base_allocator, .{
            .pointer = .{
                .element_type = Type.any,
                .many = false,
                .@"const" = true,
                .termination = .none,
            },
        });
        semantic_analyzer.optional_pointer_to_any_type = try module.types.array.append(compilation.base_allocator, .{
            .optional = .{
                .element_type = semantic_analyzer.pointer_to_any_type,
            },
        });
        semantic_analyzer.optional_any = try module.types.array.append(compilation.base_allocator, .{
            .optional = .{
                .element_type = Type.any,
            },
        });

        semantic_analyzer.unreachable_index = try module.values.array.append(compilation.base_allocator, .@"unreachable");
        semantic_analyzer.pointer_null_index = try module.values.array.append(compilation.base_allocator, .pointer_null_literal);
        semantic_analyzer.optional_null_index = try module.values.array.append(compilation.base_allocator, .optional_null_literal);
        semantic_analyzer.undefined_index = try module.values.array.append(compilation.base_allocator, .undefined);
        semantic_analyzer.boolean_false = try module.values.array.append(compilation.base_allocator, .{
            .bool = false,
        });
        semantic_analyzer.boolean_true = try module.values.array.append(compilation.base_allocator, .{
            .bool = true,
        });

        const value_index = try module.values.array.append(compilation.base_allocator, .{
            .unresolved = .{
                .node_index = .{ .value = 0 },
            },
        });

        try semantic_analyzer.initialize(compilation, module, packages[0], value_index);

        if (module.descriptor.transpile_to_c) {
            try c_transpiler.initialize(compilation, module);
            if (module.descriptor.is_build) {
                const argv = [_][]const u8{ module.descriptor.executable_path, "--compiler", compilation.executable_absolute_path };
                const process_result = try std.ChildProcess.run(.{
                    .allocator = compilation.base_allocator,
                    .argv = &argv,
                });

                switch (process_result.term) {
                    .Exited => |exit_code| {
                        if (exit_code != 0) {
                            for (argv) |arg| {
                                std.debug.print("{s} ", .{arg});
                            }
                            std.debug.print("exited with failure: {}\n", .{exit_code});
                            std.debug.print("STDOUT:\n```\n{s}\n```\n", .{process_result.stdout});
                            std.debug.print("STDERR:\n```\n{s}\n```\n", .{process_result.stderr});
                            @panic("Internal error");
                        }
                    },
                    else => @panic("Unexpected program state"),
                }
            }
        } else {
            unreachable;
            // const ir = try intermediate_representation.initialize(compilation, module);
            //
            // switch (descriptor.target.cpu.arch) {
            //     inline else => |arch| try emit.get(arch).initialize(compilation.base_allocator, ir, descriptor),
            // }
        }
    }
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

pub const File = struct {
    status: Status = .not_loaded,
    source_code: []const u8 = &.{},
    lexical_analyzer_result: lexical_analyzer.Result = undefined,
    syntactic_analyzer_result: syntactic_analyzer.Result = undefined,
    package_references: ArrayList(*Package) = .{},
    file_references: ArrayList(*File) = .{},
    type: Type.Index = Type.Index.invalid,
    relative_path: []const u8,
    package: *Package,

    pub const List = BlockList(@This());
    pub const Index = List.Index;

    const Status = enum {
        not_loaded,
        loaded_into_memory,
        lexed,
        parsed,
    };

    fn addPackageReference(file: *File, allocator: Allocator, package: *Package) !void {
        for (file.package_references.items) |other| {
            if (other == package) return;
        }

        try file.package_references.insert(allocator, 0, package);
    }

    fn addFileReference(file: *File, allocator: Allocator, affected: *File) !void {
        try file.file_references.append(allocator, affected);
    }

    fn lex(file: *File, allocator: Allocator, file_index: File.Index) !void {
        assert(file.status == .loaded_into_memory);
        file.lexical_analyzer_result = try lexical_analyzer.analyze(allocator, file.source_code, file_index);
        // if (!@import("builtin").is_test) {
        // print("[LEXICAL ANALYSIS] {} ns\n", .{file.lexical_analyzer_result.time});
        // }
        file.status = .lexed;
    }

    fn parse(file: *File, allocator: Allocator, file_index: File.Index) !void {
        assert(file.status == .lexed);
        file.syntactic_analyzer_result = try syntactic_analyzer.analyze(allocator, file.lexical_analyzer_result.tokens.items, file.source_code, file_index);

        // if (file_index.uniqueInteger() == 5) {
        //     assert(file.syntactic_analyzer_result.nodes.items[1356].id != .node_list);
        // }
        // if (!@import("builtin").is_test) {
        //     print("[SYNTACTIC ANALYSIS] {} ns\n", .{file.syntactic_analyzer_result.time});
        // }
        file.status = .parsed;
    }
};

const LoggerScope = enum {
    compilation,
    lexer,
    parser,
    sema,
    c,
};

const Logger = enum {
    import,
    new_file,
    arguments,
    var bitset = std.EnumSet(Logger).initEmpty();
};

fn getLoggerScopeType(comptime logger_scope: LoggerScope) type {
    comptime {
        return switch (logger_scope) {
            .compilation => @This(),
            .lexer => lexical_analyzer,
            .parser => syntactic_analyzer,
            .sema => semantic_analyzer,
            .c => c_transpiler,
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
