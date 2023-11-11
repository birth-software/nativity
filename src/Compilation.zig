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
const syntactic_analyzer = @import("frontend/syntactic_analyzer.zig");
const Node = syntactic_analyzer.Node;
const semantic_analyzer = @import("frontend/semantic_analyzer.zig");
const intermediate_representation = @import("backend/intermediate_representation.zig");
const emit = @import("backend/emit.zig");

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
};

fn reportUnterminatedArgumentError(string: []const u8) noreturn {
    std.debug.panic("Unterminated argument: {s}", .{string});
}

fn parseArguments(allocator: Allocator) !Compilation.Module.Descriptor {
    const arguments = (try std.process.argsAlloc(allocator))[1..];

    var maybe_executable_path: ?[]const u8 = null;
    var maybe_main_package_path: ?[]const u8 = null;
    var target_triplet: []const u8 = "x86_64-linux-gnu";

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
        } else {
            maybe_main_package_path = current_argument;
        }
    }

    const main_package_path = maybe_main_package_path orelse return error.main_package_path_not_specified;

    const executable_path = maybe_executable_path orelse blk: {
        const executable_name = std.fs.path.basename(main_package_path[0 .. main_package_path.len - "/main.nat".len]);
        assert(executable_name.len > 0);
        const result = try std.mem.concat(allocator, u8, &.{ "nat/", executable_name });
        break :blk result;
    };

    const cross_target = try std.zig.CrossTarget.parse(.{ .arch_os_abi = target_triplet });
    const target = cross_target.toTarget();

    return .{
        .main_package_path = main_package_path,
        .executable_path = executable_path,
        .target = target,
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

    const compilation_descriptor = try parseArguments(allocator);

    try compilation.compileModule(compilation_descriptor);
}

pub const Struct = struct {
    scope: Scope.Index,
    fields: ArrayList(Field.Index) = .{},

    pub const List = BlockList(@This());
    pub const Index = List.Index;
    pub const Allocation = List.Allocation;
};

pub const Enum = struct {
    scope: Scope.Index,
    fields: ArrayList(Enum.Field.Index) = .{},
    type: Type.Index,

    pub const Field = struct {
        name: u32,
        value: Value.Index,
        parent: Enum.Index,

        pub const List = BlockList(@This());
        pub const Index = Enum.Field.List.Index;
        pub const Allocation = Enum.Field.List.Allocation;
    };

    pub const List = BlockList(@This());
    pub const Index = List.Index;
    pub const Allocation = List.Allocation;
};

pub const Array = struct {
    element_type: Type.Index,
    element_count: u32,

    pub const List = BlockList(@This());
    pub const Index = List.Index;
    pub const Allocation = List.Allocation;
};

pub const Type = union(enum) {
    void,
    noreturn,
    bool,
    type,
    comptime_int,
    integer: Type.Integer,
    slice: Slice,
    pointer: Pointer,
    @"struct": Struct.Index,
    @"enum": Enum.Index,
    function: Function.Prototype.Index,
    array: Array,

    const Slice = struct {
        element_type: Type.Index,
    };
    const Pointer = struct {
        element_type: Type.Index,
        many: bool,
        @"const": bool,
    };
    pub const List = BlockList(@This());
    pub const Index = List.Index;
    pub const Allocation = List.Allocation;

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
                .index = @ctz(integer.bit_count) - @ctz(@as(u8, 8)) + @as(u6, switch (integer.signedness) {
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

    pub fn getAlignment(type_info: Type) u64 {
        return switch (type_info) {
            .integer => |integer| @min(16, integer.getSize()),
            .pointer => 8,
            else => |t| @panic(@tagName(t)),
        };
    }

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
};

// Each time an enum is added here, a corresponding insertion in the initialization must be made
pub const Values = enum {
    bool_false,
    bool_true,
    @"unreachable",

    pub fn getIndex(value: Values) Value.Index {
        const absolute: u32 = @intFromEnum(value);
        const foo = @as(Value.Index, undefined);
        const ElementT = @TypeOf(@field(foo, "index"));
        const BlockT = @TypeOf(@field(foo, "block"));
        const divider = std.math.maxInt(ElementT);
        const element_index: ElementT = @intCast(absolute % divider);
        const block_index: BlockT = @intCast(absolute / divider);
        return .{
            .index = element_index,
            .block = block_index,
        };
    }
};

pub const Intrinsic = enum {
    @"error",
    import,
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
        },
    };

    break :blk result;
};

/// A scope contains a bunch of declarations
pub const Scope = struct {
    declarations: AutoHashMap(u32, Declaration.Index) = .{},
    parent: Scope.Index,
    file: File.Index,
    type: Type.Index = Type.Index.invalid,

    pub const List = BlockList(@This());
    pub const Index = List.Index;
    pub const Allocation = List.Allocation;
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
    type: Type.Index,

    pub const Reference = struct {
        value: Declaration.Index,
        type: Type.Index,
    };

    pub const List = BlockList(@This());
    pub const Index = List.Index;
    pub const Allocation = List.Allocation;
};

pub const Function = struct {
    scope: Scope.Index,
    body: Block.Index,
    prototype: Type.Index,

    pub const Prototype = struct {
        arguments: ?[]const Declaration.Index,
        return_type: Type.Index,
        attributes: Attributes = .{},

        pub const List = BlockList(@This());
        pub const Index = Prototype.List.Index;

        pub const Attributes = packed struct {
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
    pub const Allocation = List.Allocation;
};

pub const Block = struct {
    statements: ArrayList(Value.Index) = .{},
    reaches_end: bool,
    pub const List = BlockList(@This());
    pub const Index = List.Index;
    pub const Allocation = List.Allocation;
};

pub const Field = struct {
    name: u32,
    type: Type.Index,

    pub const List = BlockList(@This());
    pub const Index = List.Index;
    pub const Allocation = List.Allocation;
};

pub const Loop = struct {
    condition: Value.Index,
    body: Value.Index,
    breaks: bool,

    pub const List = BlockList(@This());
    pub const Index = List.Index;
    pub const Allocation = List.Allocation;
};

const Runtime = struct {
    foo: u32 = 0,
};

const Unresolved = struct {
    node_index: Node.Index,
};

pub const Assignment = struct {
    store: Value.Index,
    load: Value.Index,

    pub const List = BlockList(@This());
    pub const Index = List.Index;
    pub const Allocation = List.Allocation;
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
    pub const Allocation = List.Allocation;
};

pub const Call = struct {
    value: Value.Index,
    arguments: ArgumentList.Index,
    type: Type.Index,
    pub const List = BlockList(@This());
    pub const Index = List.Index;
    pub const Allocation = List.Allocation;
};

pub const ArgumentList = struct {
    array: ArrayList(Value.Index),
    pub const List = BlockList(@This());
    pub const Index = List.Index;
    pub const Allocation = List.Allocation;
};

pub const Return = struct {
    value: Value.Index,
    pub const List = BlockList(@This());
    pub const Index = List.Index;
    pub const Allocation = List.Allocation;
};

pub const Cast = struct {
    value: Value.Index,
    type: Type.Index,

    pub const List = BlockList(@This());
    pub const Index = List.Index;
    pub const Allocation = List.Allocation;
};

pub const BinaryOperation = struct {
    left: Value.Index,
    right: Value.Index,
    type: Type.Index,
    id: Id,

    pub const List = BlockList(@This());
    pub const Index = List.Index;
    pub const Allocation = List.Allocation;

    const Id = enum {
        add,
        sub,
    };
};

pub const CallingConvention = enum {
    system_v,
};

pub const Value = union(enum) {
    unresolved: Unresolved,
    declaration: Declaration.Index,
    declaration_reference: Declaration.Reference,
    void,
    bool: bool,
    undefined,
    @"unreachable",
    loop: Loop.Index,
    function: Function.Index,
    block: Block.Index,
    runtime: Runtime,
    assign: Assignment.Index,
    type: Type.Index,
    integer: Integer,
    syscall: Syscall.Index,
    call: Call.Index,
    argument_list: ArgumentList,
    @"return": Return.Index,
    argument: Declaration.Index,
    string_literal: u32,
    enum_field: Enum.Field.Index,
    extern_function: Function.Prototype.Index,
    sign_extend: Cast.Index,
    zero_extend: Cast.Index,
    binary_operation: BinaryOperation.Index,

    pub const List = BlockList(@This());
    pub const Index = List.Index;
    pub const Allocation = List.Allocation;

    pub const Integer = struct {
        value: u64,
        type: Type.Index,
        signedness: Type.Integer.Signedness,

        pub fn getBitCount(integer: Integer, module: *Module) u16 {
            return module.types.get(integer.type).integer.bit_count;
        }
    };

    pub fn isComptime(value: Value) bool {
        return switch (value) {
            .bool, .void, .undefined, .function, .type, .enum_field => true,
            .integer => |integer| integer.type.eq(Type.comptime_int),
            .call => false,
            .binary_operation => false,
            else => |t| @panic(@tagName(t)),
        };
    }

    pub fn getType(value: Value, module: *Module) Type.Index {
        const result = switch (value) {
            .call => |call_index| module.calls.get(call_index).type,
            .integer => |integer| integer.type,
            .declaration_reference => |declaration_reference| declaration_reference.type,
            .string_literal => |string_literal_hash| module.string_literal_types.get(@intCast(module.getStringLiteral(string_literal_hash).?.len)).?,
            .type => Type.type,
            .enum_field => |enum_field_index| module.enums.get(module.enum_fields.get(enum_field_index).parent).type,
            .function => |function_index| module.functions.get(function_index).prototype,
            .binary_operation => |binary_operation| module.binary_operations.get(binary_operation).type,
            else => |t| @panic(@tagName(t)),
        };

        return result;
    }

    // pub fn setType(value: *Value, new_type: Type.Index) void {
    //     switch (value.*) {
    //         .integer => value.integer.type = new_type,
    //         else => |t| @panic(@tagName(t)),
    //     }
    // }
    const TypeCheckError = error{
        integer_size,
        pointer_many_differ,
        pointer_element_type_differ,
    };

    pub fn typeCheck(value: *Value, module: *Module, type_to_check_index: Type.Index) TypeCheckError!void {
        const value_type_index = value.getType(module);

        if (!value_type_index.eq(type_to_check_index)) {
            const value_type = module.types.get(value_type_index);
            const check_type = module.types.get(type_to_check_index);
            if (std.meta.activeTag(value_type.*) == std.meta.activeTag(check_type.*)) {
                switch (value_type.*) {
                    .integer => |coercee_int| {
                        if (check_type.integer.getSize() < coercee_int.getSize()) {
                            return error.integer_size;
                        }
                    },
                    .pointer => |coercee_pointer| {
                        if (coercee_pointer.many != check_type.pointer.many) {
                            return error.pointer_many_differ;
                        }

                        if (!coercee_pointer.element_type.eq(check_type.pointer.element_type)) {
                            if (check_type.pointer.many) {
                                const coercee_element_type = module.types.get(coercee_pointer.element_type);
                                switch (coercee_element_type.*) {
                                    .array => |array| if (!array.element_type.eq(check_type.pointer.element_type)) {
                                        return error.pointer_element_type_differ;
                                    },
                                    else => |t| @panic(@tagName(t)),
                                }
                            }
                        }
                    },
                    else => |t| @panic(@tagName(t)),
                }
            } else {
                switch (check_type.*) {
                    .integer => {
                        switch (value_type.*) {
                            .comptime_int => switch (value.*) {
                                .integer => value.integer.type = type_to_check_index,
                                .declaration_reference => value.declaration_reference.type = type_to_check_index,
                                else => |t| @panic(@tagName(t)),
                            },
                            else => |t| @panic(@tagName(t)),
                        }
                    },
                    else => |t| @panic(@tagName(t)),
                }
            }
        }
    }
};

pub const Module = struct {
    main_package: *Package,
    import_table: StringArrayHashMap(*File) = .{},
    string_table: StringKeyMap([]const u8) = .{},
    declarations: BlockList(Declaration) = .{},
    structs: BlockList(Struct) = .{},
    scopes: BlockList(Scope) = .{},
    files: BlockList(File) = .{},
    values: BlockList(Value) = .{},
    functions: BlockList(Function) = .{},
    fields: BlockList(Field) = .{},
    function_prototypes: BlockList(Function.Prototype) = .{},
    types: BlockList(Type) = .{},
    blocks: BlockList(Block) = .{},
    loops: BlockList(Loop) = .{},
    assignments: BlockList(Assignment) = .{},
    syscalls: BlockList(Syscall) = .{},
    calls: BlockList(Call) = .{},
    argument_lists: BlockList(ArgumentList) = .{},
    returns: BlockList(Return) = .{},
    string_literals: StringKeyMap([]const u8) = .{},
    enums: BlockList(Enum) = .{},
    enum_fields: BlockList(Enum.Field) = .{},
    function_name_map: data_structures.AutoArrayHashMap(Function.Index, u32) = .{},
    arrays: BlockList(Array) = .{},
    casts: BlockList(Cast) = .{},
    binary_operations: BlockList(BinaryOperation) = .{},
    string_literal_types: data_structures.AutoArrayHashMap(u32, Type.Index) = .{},
    array_types: data_structures.AutoArrayHashMap(Array, Type.Index) = .{},
    entry_point: Function.Index = Function.Index.invalid,

    pub const Descriptor = struct {
        main_package_path: []const u8,
        executable_path: []const u8,
        target: std.Target,
    };

    const ImportFileResult = struct {
        ptr: *File,
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

        const current_file = module.files.get(current_file_index);
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

        try import_file.ptr.addFileReference(allocator, current_file);

        const result = ImportPackageResult{
            .file = import_file,
            .is_package = false,
        };

        return result;
    }

    fn getFile(module: *Module, allocator: Allocator, full_path: []const u8, relative_path: []const u8, package: *Package) !ImportFileResult {
        const path_lookup = try module.import_table.getOrPut(allocator, full_path);
        const file, const index = switch (path_lookup.found_existing) {
            true => blk: {
                const result = path_lookup.value_ptr.*;
                const index = module.files.indexOf(result);
                break :blk .{
                    result,
                    index,
                };
            },
            false => blk: {
                const file_allocation = try module.files.append(allocator, File{
                    .relative_path = relative_path,
                    .package = package,
                });
                logln(.compilation, .new_file, "Adding file #{}: {s}\n", .{ file_allocation.index.uniqueInteger(), full_path });
                path_lookup.value_ptr.* = file_allocation.ptr;
                // break :blk file;
                break :blk .{
                    file_allocation.ptr,
                    file_allocation.index,
                };
            },
        };

        return .{
            .ptr = file,
            .index = index,
            .is_new = !path_lookup.found_existing,
        };
    }

    pub fn importPackage(module: *Module, allocator: Allocator, package: *Package) !ImportPackageResult {
        const full_path = try std.fs.path.resolve(allocator, &.{ package.directory.path, package.source_path });
        logln(.compilation, .import, "Import full path: {s}\n", .{full_path});
        const import_file = try module.getFile(allocator, full_path, package.source_path, package);
        try import_file.ptr.addPackageReference(allocator, package);

        return .{
            .file = import_file,
            .is_package = true,
        };
    }

    pub fn generateAbstractSyntaxTreeForFile(module: *Module, allocator: Allocator, file_index: File.Index) !void {
        const file = module.files.get(file_index);
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

    fn addString(map: *StringKeyMap([]const u8), allocator: Allocator, string: []const u8) !u32 {
        const lookup_result = try map.getOrPut(allocator, string, string);

        {
            const lookup_name = map.getValue(lookup_result.key) orelse unreachable;
            assert(equal(u8, lookup_name, string));
        }

        return lookup_result.key;
    }

    pub fn getName(module: *Module, key: u32) ?[]const u8 {
        return getString(&module.string_table, key);
    }

    pub fn addName(module: *Module, allocator: Allocator, name: []const u8) !u32 {
        return addString(&module.string_table, allocator, name);
    }

    pub fn getStringLiteral(module: *Module, key: u32) ?[]const u8 {
        return getString(&module.string_literals, key);
    }

    pub fn addStringLiteral(module: *Module, allocator: Allocator, string_literal: []const u8) !u32 {
        const result = addString(&module.string_literals, allocator, string_literal);

        const len: u32 = @intCast(string_literal.len);
        // try analyzer.module.
        const string_literal_type_gop = try module.string_literal_types.getOrPut(allocator, len);
        if (!string_literal_type_gop.found_existing) {
            const array = Array{
                .element_type = Type.u8,
                .element_count = len,
            };
            const array_type_gop = try module.array_types.getOrPut(allocator, array);
            if (!array_type_gop.found_existing) {
                const array_type_allocation = try module.types.append(allocator, .{
                    .array = array,
                });
                array_type_gop.value_ptr.* = array_type_allocation.index;
            }

            const array_type_index = array_type_gop.value_ptr.*;
            const pointer_type_allocation = try module.types.append(allocator, .{
                .pointer = .{
                    .@"const" = true,
                    .many = true,
                    .element_type = array_type_index,
                },
            });
            string_literal_type_gop.value_ptr.* = pointer_type_allocation.index;
        }

        return result;
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
    // TODO: generate an actual file
    const builtin_file_name = "builtin.nat";
    var cache_dir = try compilation.build_directory.openDir("cache", .{});
    const builtin_file = try cache_dir.createFile(builtin_file_name, .{});
    try builtin_file.writer().print(
        \\const builtin = #import("std").builtin;
        \\const cpu = builtin.Cpu.{s};
        \\const os = builtin.Os.{s};
        \\const abi = builtin.Abi.{s};
        \\
    , .{
        @tagName(descriptor.target.cpu.arch),
        @tagName(descriptor.target.os.tag),
        @tagName(descriptor.target.abi),
    });
    builtin_file.close();

    const module: *Module = try compilation.base_allocator.create(Module);
    module.* = Module{
        .main_package = blk: {
            const result = try compilation.base_allocator.create(Package);
            const main_package_absolute_directory_path = try compilation.pathFromCwd(std.fs.path.dirname(descriptor.main_package_path).?);
            result.* = .{
                .directory = .{
                    .handle = try std.fs.openDirAbsolute(main_package_absolute_directory_path, .{}),
                    .path = main_package_absolute_directory_path,
                },
                .source_path = try compilation.base_allocator.dupe(u8, std.fs.path.basename(descriptor.main_package_path)),
            };
            break :blk result;
        },
    };

    const std_package_dir = "lib/std";

    const package_descriptors = [2]struct {
        name: []const u8,
        directory_path: []const u8,
    }{
        .{
            .name = "std",
            .directory_path = try compilation.pathFromCwd(std_package_dir),
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

    _ = try module.importPackage(compilation.base_allocator, module.main_package.dependencies.get("std").?);

    for (module.import_table.values()) |import| {
        try module.generateAbstractSyntaxTreeForFile(compilation.base_allocator, module.files.indexOf(import));
    }

    inline for (@typeInfo(FixedTypeKeyword).Enum.fields) |enum_field| {
        _ = try module.types.append(compilation.base_allocator, switch (@field(FixedTypeKeyword, enum_field.name)) {
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
        _ = try module.types.append(compilation.base_allocator, .{
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
        _ = try module.types.append(compilation.base_allocator, .{
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
        _ = try module.types.append(compilation.base_allocator, type_data);
    }

    _ = try module.values.append(compilation.base_allocator, .{
        .bool = false,
    });

    _ = try module.values.append(compilation.base_allocator, .{
        .bool = true,
    });

    _ = try module.values.append(compilation.base_allocator, .{
        .@"unreachable" = {},
    });

    const value_allocation = try module.values.append(compilation.base_allocator, .{
        .unresolved = .{
            .node_index = .{ .value = 0 },
        },
    });

    try semantic_analyzer.initialize(compilation, module, packages[0], value_allocation.ptr);

    const ir = try intermediate_representation.initialize(compilation, module);

    switch (descriptor.target.cpu.arch) {
        inline else => |arch| try emit.get(arch).initialize(compilation.base_allocator, ir, descriptor),
    }
}

fn generateAST() !void {}

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
    ir,
    codegen,
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
            .ir => intermediate_representation,
            .codegen => emit,
        };
    }
}

var logger_bitset = std.EnumSet(LoggerScope).initEmpty();

var writer = std.io.getStdErr().writer();

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
    const print_stack_trace = true;
    switch (print_stack_trace) {
        true => @call(.always_inline, std.builtin.default_panic, .{ message, stack_trace, return_address }),
        false => {
            writer.writeAll("\nPANIC: ") catch {};
            writer.writeAll(message) catch {};
            writer.writeByte('\n') catch {};
            std.os.abort();
        },
    }
}
