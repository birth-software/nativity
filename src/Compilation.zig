const Compilation = @This();

const std = @import("std");
const assert = std.debug.assert;
const print = std.debug.print;

const Allocator = std.mem.Allocator;

const data_structures = @import("data_structures.zig");
const ArrayList = data_structures.ArrayList;
const StringHashMap = data_structures.StringHashMap;
const StringArrayHashMap = data_structures.StringArrayHashMap;

const lexical_analyzer = @import("frontend/lexical_analyzer.zig");
const syntactic_analyzer = @import("frontend/syntactic_analyzer.zig");
const semantic_analyzer = @import("frontend/semantic_analyzer.zig");

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

pub fn deinit(compilation: *Compilation) void {
    const allocator = compilation.base_allocator;
    allocator.free(compilation.cwd_absolute_path);
    allocator.free(compilation.executable_absolute_path);
    allocator.destroy(compilation);
}

pub const Module = struct {
    main_package: *Package,
    import_table: StringArrayHashMap(*File) = .{},

    pub const Descriptor = struct {
        main_package_path: []const u8,
    };

    fn deinit(module: *Module, allocator: Allocator) void {
        defer allocator.destroy(module);

        for (module.import_table.values()) |file| {
            file.deinit(allocator);
        }

        var iterator = module.main_package.dependencies.valueIterator();
        while (iterator.next()) |it| {
            const package = it.*;
            package.deinit(allocator);
        }

        module.main_package.deinit(allocator);

        module.import_table.clearAndFree(allocator);
    }

    fn importPackage(module: *Module, compilation: *Compilation, package: *Package) !ImportPackageResult {
        const lookup_result = try module.import_table.getOrPut(compilation.base_allocator, package.directory.path);
        errdefer _ = module.import_table.pop();
        if (lookup_result.found_existing) {
            const file: *File = lookup_result.value_ptr.*;
            try file.addPackageReference(compilation.base_allocator, package);
            unreachable;
        }
        const file = try compilation.base_allocator.create(File);
        lookup_result.value_ptr.* = file;
        file.* = File{
            .relative_path = package.source_path,
            .package = package,
        };
        try file.addPackageReference(compilation.base_allocator, package);

        return .{
            .file = file,
            .is_new = true,
        };
    }

    fn generateAbstractSyntaxTreeForFile(module: *Module, allocator: Allocator, file: *File) !void {
        _ = module;
        const source_file = try file.package.directory.handle.openFile(file.relative_path, .{});
        defer source_file.close();

        const file_size = try source_file.getEndPos();
        var file_buffer = try allocator.alloc(u8, file_size);

        const read_byte_count = try source_file.readAll(file_buffer);
        assert(read_byte_count == file_size);

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
    defer module.deinit(compilation.base_allocator);
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
            .directory_path = try switch (@import("builtin").is_test) {
                true => compilation.pathFromCwd(std_package_dir),
                false => compilation.pathFromCompiler(std_package_dir),
            },
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

    for (package_descriptors) |package_descriptor| {
        const package = try compilation.base_allocator.create(Package);
        package.* = .{
            .directory = .{
                .path = package_descriptor.directory_path,
                .handle = try std.fs.openDirAbsolute(package_descriptor.directory_path, .{}),
            },
            .source_path = try std.mem.concat(compilation.base_allocator, u8, &.{ package_descriptor.name, ".nat" }),
        };

        try module.main_package.addDependency(compilation.base_allocator, package_descriptor.name, package);
    }

    assert(module.main_package.dependencies.size == 2);

    _ = try module.importPackage(compilation, module.main_package.dependencies.get("std").?);

    for (module.import_table.values()) |import| {
        try module.generateAbstractSyntaxTreeForFile(compilation.base_allocator, import);
    }
}

const ImportPackageResult = struct {
    file: *File,
    is_new: bool,
};

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

    fn deinit(package: *Package, allocator: Allocator) void {
        if (package.dependencies.size > 0) {
            assert(package.dependencies.size == 2);
        }
        package.dependencies.clearAndFree(allocator);
        allocator.free(package.source_path);
        allocator.free(package.directory.path);
        package.directory.handle.close();
        allocator.destroy(package);
    }
};

pub const File = struct {
    status: Status = .not_loaded,
    source_code: []const u8 = &.{},
    lexical_analyzer_result: lexical_analyzer.Result = undefined,
    syntactic_analyzer_result: syntactic_analyzer.Result = undefined,
    package_references: ArrayList(*Package) = .{},
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
        if (!@import("builtin").is_test) {
            print("[LEXICAL ANALYSIS] {} ns\n", .{file.lexical_analyzer_result.time});
        }
        file.status = .lexed;
    }

    fn parse(file: *File, allocator: Allocator) !void {
        assert(file.status == .lexed);
        file.syntactic_analyzer_result = try syntactic_analyzer.analyze(allocator, file.lexical_analyzer_result.tokens.items, file.source_code);
        if (!@import("builtin").is_test) {
            print("[SYNTACTIC ANALYSIS] {} ns\n", .{file.syntactic_analyzer_result.time});
        }
        file.status = .parsed;
    }

    fn deinit(file: *File, allocator: Allocator) void {
        defer allocator.destroy(file);
        if (file.status == .parsed) {
            file.syntactic_analyzer_result.free(allocator);
            file.lexical_analyzer_result.free(allocator);
            file.package_references.clearAndFree(allocator);
            allocator.free(file.source_code);
        } else {
            unreachable;
        }
    }
};
