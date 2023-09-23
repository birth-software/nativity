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
};

pub const Type = union(enum) {
    void,
    noreturn,
    bool,
    integer: Integer,
    @"struct": Struct.Index,
    pub const List = BlockList(@This());
    pub const Index = List.Index;
};

pub const Integer = struct {
    bit_count: u16,
    signedness: Signedness,
    pub const Signedness = enum(u1) {
        unsigned = 0,
        signed = 1,
    };
};

/// A scope contains a bunch of declarations
pub const Scope = struct {
    parent: Scope.Index,
    type: Type.Index = Type.Index.invalid,
    declarations: AutoHashMap(u32, Declaration.Index) = .{},

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
    name: []const u8,

    pub const List = BlockList(@This());
    pub const Index = List.Index;
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
};

pub const Block = struct {
    statements: ArrayList(Value.Index) = .{},
    reaches_end: bool,
    pub const List = BlockList(@This());
    pub const Index = List.Index;
};

pub const Field = struct {
    foo: u32 = 0,

    pub const List = BlockList(@This());
    pub const Index = List.Index;
};

pub const Loop = struct {
    condition: Value.Index,
    body: Value.Index,
    breaks: bool,

    pub const List = BlockList(@This());
    pub const Index = List.Index;
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
};

pub const Value = union(enum) {
    unresolved: Unresolved,
    declaration: Declaration.Index,
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
    integer: u64,
    syscall: Syscall.Index,

    pub const List = BlockList(@This());
    pub const Index = List.Index;

    pub fn isComptime(value: Value) bool {
        return switch (value) {
            .bool, .void, .undefined, .function => true,
            else => false,
        };
    }

    pub fn getType(value: *Value) !void {
        switch (value.*) {
            else => |t| @panic(@tagName(t)),
        }
        unreachable;
    }
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

    pub const Descriptor = struct {
        main_package_path: []const u8,
    };

    const ImportFileResult = struct {
        file: *File,
        is_new: bool,
    };

    const ImportPackageResult = struct {
        file: *File,
        is_new: bool,
        is_package: bool,
    };

    pub fn importFile(module: *Module, allocator: Allocator, current_file: *File, import_name: []const u8) !ImportPackageResult {
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

        if (current_file.package.dependencies.get(import_name)) |package| {
            return module.importPackage(allocator, package);
        }

        if (!std.mem.endsWith(u8, import_name, ".nat")) {
            unreachable;
        }

        const full_path = try std.fs.path.join(allocator, &.{ current_file.package.directory.path, import_name });
        const file_relative_path = std.fs.path.basename(full_path);
        const package = current_file.package;
        const import = try module.getFile(allocator, full_path, file_relative_path, package);

        try import.file.addFileReference(allocator, current_file);

        const result = ImportPackageResult{
            .file = import.file,
            .is_new = import.is_new,
            .is_package = false,
        };

        return result;
    }

    fn getFile(module: *Module, allocator: Allocator, full_path: []const u8, relative_path: []const u8, package: *Package) !ImportFileResult {
        const path_lookup = try module.import_table.getOrPut(allocator, full_path);
        const file: *File = switch (path_lookup.found_existing) {
            true => path_lookup.value_ptr.*,
            false => blk: {
                const new_file_index = try module.files.append(allocator, File{
                    .relative_path = relative_path,
                    .package = package,
                });
                const file = module.files.get(new_file_index);
                path_lookup.value_ptr.* = file;
                break :blk file;
            },
        };

        return .{
            .file = file,
            .is_new = !path_lookup.found_existing,
        };
    }

    pub fn importPackage(module: *Module, allocator: Allocator, package: *Package) !ImportPackageResult {
        const full_path = try std.fs.path.resolve(allocator, &.{ package.directory.path, package.source_path });
        const import = try module.getFile(allocator, full_path, package.source_path, package);
        try import.file.addPackageReference(allocator, package);

        return .{
            .file = import.file,
            .is_new = import.is_new,
            .is_package = true,
        };
    }

    pub fn generateAbstractSyntaxTreeForFile(module: *Module, allocator: Allocator, file: *File) !void {
        _ = module;
        const source_file = try file.package.directory.handle.openFile(file.relative_path, .{});

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

    const main_declaration = try semantic_analyzer.initialize(compilation, module, packages[0]);

    var ir = try intermediate_representation.initialize(compilation, module, packages[0], main_declaration);

    switch (@import("builtin").cpu.arch) {
        .x86_64 => |arch| try emit.get(arch).initialize(compilation.base_allocator, &ir),
        else => {},
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
    relative_path: []const u8,
    package: *Package,

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

    pub fn fromRelativePath(allocator: Allocator, file_relative_path: []const u8) *File {
        const file_content = try std.fs.cwd().readFileAlloc(allocator, file_relative_path, std.math.maxInt(usize));
        _ = file_content;
        const file = try allocator.create(File);
        file.* = File{};

        return file;
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
