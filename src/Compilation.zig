const Compilation = @This();

const std = @import("std");
const assert = std.debug.assert;
const equal = std.mem.eql;
const print = std.debug.print;

const Allocator = std.mem.Allocator;

const data_structures = @import("data_structures.zig");
const ArrayList = data_structures.ArrayList;
const AutoHashMap = data_structures.AutoHashMap;
const BlockList = data_structures.BlockList;
const HashMap = data_structures.HashMap;
const SegmentedList = data_structures.SegmentedList;
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

pub fn init(allocator: Allocator) !*Compilation {
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

    return compilation;
}

pub const Struct = struct {
    scope: Scope.Index,
    fields: ArrayList(Field.Index) = .{},

    pub const List = BlockList(@This());
    pub const Index = List.Index;
    pub const Allocation = List.Allocation;
};

pub const Type = union(enum) {
    void,
    noreturn,
    bool,
    integer: Type.Integer,
    @"struct": Struct.Index,
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

        pub fn getSize(integer: Type.Integer) u64 {
            return integer.bit_count / @bitSizeOf(u8) + @intFromBool(integer.bit_count % @bitSizeOf(u8) != 0);
        }
    };

    pub fn getSize(type_info: Type) u64 {
        return switch (type_info) {
            .integer => |integer| integer.getSize(),
            else => |t| @panic(@tagName(t)),
        };
    }

    pub fn getAlignment(type_info: Type) u64 {
        return switch (type_info) {
            .integer => |integer| @min(16, integer.getSize()),
            else => |t| @panic(@tagName(t)),
        };
    }
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
    name: []const u8,

    pub const List = BlockList(@This());
    pub const Index = List.Index;
    pub const Allocation = List.Allocation;
};

pub const Function = struct {
    body: Block.Index,
    prototype: Prototype.Index,

    pub const Prototype = struct {
        arguments: ?[]const Field.Index,
        return_type: Type.Index,

        pub const List = BlockList(@This());
        pub const Index = Prototype.List.Index;
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
    foo: u32 = 0,

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

    pub fn getArguments(syscall: Syscall) []const Value.Index {
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

pub const Value = union(enum) {
    unresolved: Unresolved,
    declaration: Declaration.Index,
    declaration_reference: Declaration.Index,
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

    pub const List = BlockList(@This());
    pub const Index = List.Index;
    pub const Allocation = List.Allocation;

    pub fn isComptime(value: Value) bool {
        return switch (value) {
            .bool, .void, .undefined, .function => true,
            else => false,
        };
    }

    pub fn getType(value: *Value, module: *Module) Type.Index {
        return switch (value.*) {
            .call => |call_index| module.calls.get(call_index).type,
            else => |t| @panic(@tagName(t)),
        };
    }
};

pub const Integer = struct {
    value: u64,
    type: Type.Integer,
};

pub const Module = struct {
    main_package: *Package,
    import_table: StringArrayHashMap(*File) = .{},
    string_table: AutoHashMap(u32, []const u8) = .{},
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
    argument_list: BlockList(ArgumentList) = .{},
    returns: BlockList(Return) = .{},
    entry_point: ?u32 = null,

    pub const Descriptor = struct {
        main_package_path: []const u8,
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
        print("import: '{s}'\n", .{import_name});
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

        const full_path = try std.fs.path.join(allocator, &.{ current_file.package.directory.path, import_name });
        const file_relative_path = std.fs.path.basename(full_path);
        const package = current_file.package;
        const import_file = try module.getFile(allocator, full_path, file_relative_path, package);

        try import_file.ptr.addFileReference(allocator, current_file);

        const result = ImportPackageResult{
            .file = import_file,
            .is_package = false,
        };

        return result;
    }

    fn lookupDeclaration(module: *Module, hashed: u32) !noreturn {
        _ = hashed;
        _ = module;
        while (true) {}
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
                std.debug.print("Adding file #{}: {s}\n", .{ file_allocation.index.uniqueInteger(), full_path });
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
        const import_file = try module.getFile(allocator, full_path, package.source_path, package);
        try import_file.ptr.addPackageReference(allocator, package);

        return .{
            .file = import_file,
            .is_package = true,
        };
    }

    pub fn generateAbstractSyntaxTreeForFile(module: *Module, allocator: Allocator, file: *File) !void {
        _ = module;
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

        try file.lex(allocator);
        try file.parse(allocator);
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
    const builtin_file = try cache_dir.createFile(builtin_file_name, .{ .truncate = false });
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
        try module.generateAbstractSyntaxTreeForFile(compilation.base_allocator, import);
    }

    const main_declaration = try semantic_analyzer.initialize(compilation, module, packages[0], .{ .block = 0, .index = 0 });

    var ir = try intermediate_representation.initialize(compilation, module, packages[0], main_declaration);

    try emit.get(.x86_64).initialize(compilation.base_allocator, &ir);
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

    fn lex(file: *File, allocator: Allocator) !void {
        assert(file.status == .loaded_into_memory);
        file.lexical_analyzer_result = try lexical_analyzer.analyze(allocator, file.source_code);
        // if (!@import("builtin").is_test) {
        // print("[LEXICAL ANALYSIS] {} ns\n", .{file.lexical_analyzer_result.time});
        // }
        file.status = .lexed;
    }

    fn parse(file: *File, allocator: Allocator) !void {
        assert(file.status == .lexed);
        file.syntactic_analyzer_result = try syntactic_analyzer.analyze(allocator, file.lexical_analyzer_result.tokens.items, file.source_code);
        // if (!@import("builtin").is_test) {
        //     print("[SYNTACTIC ANALYSIS] {} ns\n", .{file.syntactic_analyzer_result.time});
        // }
        file.status = .parsed;
    }
};
