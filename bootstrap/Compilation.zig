const std = @import("std");

const Allocator = std.mem.Allocator;

const library = @import("library.zig");
const assert = library.assert;
const align_forward = library.align_forward;
const Arena = library.Arena;
const BoundedArray = library.BoundedArray;
const byte_equal = library.byte_equal;
const enumFromString = library.enumFromString;
const byte_equal_terminated = library.byte_equal_terminated;
const DynamicBoundedArray = library.DynamicBoundedArray;
const last_byte = library.last_byte;
const first_byte = library.first_byte;
const first_slice = library.first_slice;
const starts_with_slice = library.starts_with_slice;
const PinnedArray = library.PinnedArray;
const PinnedArrayAdvanced = library.PinnedArrayAdvanced;
const MyAllocator = library.MyAllocator;
const PinnedHashMap = library.PinnedHashMap;
const span = library.span;
const format_int = library.format_int;
const my_hash = library.my_hash;

const lexer = @import("frontend/lexer.zig");
const parser = @import("frontend/parser.zig");
const Node = parser.Node;
const llvm = @import("backend/llvm.zig");
const linker = @import("linker/linker.zig");
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
    write(.panic, "Unterminated argument: ") catch {};
    @panic(string);
}

const Error = struct {
    message: []const u8,
    node: Node.Index,
};

const SliceField = enum {
    pointer,
    length,
};

const length_field_name = @tagName(SliceField.length);

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

pub fn createContext(allocator: Allocator) !*const Context {
    const context: *Context = try allocator.create(Context);

    const self_exe_path = try std.fs.selfExePathAlloc(allocator);
    const self_exe_dir_path = std.fs.path.dirname(self_exe_path).?;
    context.* = .{
        .allocator = allocator,
        .cwd_absolute_path = try realpathAlloc(allocator, "."),
        .executable_absolute_path = self_exe_path,
        .directory_absolute_path = self_exe_dir_path,
        .build_directory = try std.fs.cwd().makeOpenPath("nat", .{}),
        .arena = try Arena.init(4 * 1024 * 1024),
    };

    try context.build_directory.makePath(cache_dir_name);
    try context.build_directory.makePath(installation_dir_name);

    return context;
}

pub fn compileBuildExecutable(context: *const Context, arguments: []const []const u8) !void {
    _ = arguments; // autofix
    const unit = try createUnit(context, .{
        .main_package_path = "build.nat",
        .object_path = "nat/build.o",
        .executable_path = "nat/build",
        .only_parse = false,
        .arch = switch (@import("builtin").cpu.arch) {
            .x86_64 => .x86_64,
            .aarch64 => .aarch64,
            else => @compileError("Architecture not supported"),
        },
        .os = switch (@import("builtin").os.tag) {
            .linux => .linux,
            .macos => .macos,
            else => |t| @panic(@tagName(t)),
        },
        .abi = switch (@import("builtin").abi) {
            .none => .none,
            .gnu => .gnu,
            .musl => .musl,
            else => |t| @panic(@tagName(t)),
        },
        .optimization = .none,
        .link_libc = false,
        .generate_debug_information = true,
        .name = "build",
        .is_test = false,
        .c_source_files = &.{},
    });

    try unit.compile(context);
    const argv: []const []const u8 = &.{ "nat/build", "-compiler_path", context.executable_absolute_path };
    const result = try std.ChildProcess.run(.{
        .allocator = context.allocator,
        .argv = argv,
    });

    const success = switch (result.term) {
        .Exited => |exit_code| exit_code == 0,
        else => false,
    };
    if (!success) {
        try write(.panic, "The following command terminated with failure (");
        try write(.panic, @tagName(result.term));
        try write(.panic, "):\n");
        for (argv) |arg| {
            try write(.panic, arg);
            try write(.panic, ", ");
        }
        try write(.panic, "\n");
        try write(.panic, result.stdout);
        try write(.panic, "\n");
        try write(.panic, result.stderr);
        try write(.panic, "\n");
        std.posix.abort();
    }
}

fn clang_job(arguments: []const []const u8) !void {
    const exit_code = try clangMain(std.heap.page_allocator, arguments);
    if (exit_code != 0) unreachable;
}

const musl_lib_dir_relative_path = "lib/libc/musl/";

const MuslContext = struct {
    global_cache_dir: []const u8,
    arch_include_path: []const u8,
    arch_generic_include_path: []const u8,
    src_include_path: []const u8,
    src_internal_path: []const u8,
    include_path: []const u8,
    triple_include_path: []const u8,
    generic_include_path: []const u8,

    fn init(context: *const Context) !MuslContext {
        const home_dir = std.posix.getenv("HOME") orelse unreachable;
        return .{
            .global_cache_dir = try std.mem.concat(context.allocator, u8, &.{ home_dir, "/.cache/nat/musl/" }),
            .arch_include_path = try context.pathFromCompiler(musl_lib_dir_relative_path ++ "arch/x86_64"),
            .arch_generic_include_path = try context.pathFromCompiler(musl_lib_dir_relative_path ++ "arch/generic"),
            .src_include_path = try context.pathFromCompiler(musl_lib_dir_relative_path ++ "src/include"),
            .src_internal_path = try context.pathFromCompiler(musl_lib_dir_relative_path ++ "src/internal"),
            .include_path = try context.pathFromCompiler(musl_lib_dir_relative_path ++ "include"),
            .triple_include_path = try context.pathFromCompiler("lib/libc/include/x86_64-linux-musl"),
            .generic_include_path = try context.pathFromCompiler("lib/libc/include/generic-musl"),
        };
    }

    fn compileFileWithClang(musl: *const MuslContext, context: *const Context, src_file_relative_path: []const u8, target_path: []const u8) !void {
        if (std.mem.indexOf(u8, src_file_relative_path, "lib/libc")) |index| {
            if (std.mem.indexOf(u8, src_file_relative_path[index + 1 ..], "lib/libc")) |_| {
                unreachable;
            }
        }
        const src_file_path = try context.pathFromCompiler(src_file_relative_path);
        const args: []const []const u8 = &.{
            context.executable_absolute_path, "--no-default-config",  "-fno-caret-diagnostics", "-target",                      "x86_64-unknown-linux-musl", "-std=c99",            "-ffreestanding", "-mred-zone",           "-fno-omit-frame-pointer", "-fno-stack-protector", "-O2", "-fno-unwind-tables",     "-fno-asynchronous-unwind-tables", "-ffunction-sections",     "-fdata-sections", "-gdwarf-4",   "-gdwarf32", "-Wa,--noexecstack", "-D_XOPEN_SOURCE=700",
            "-I",                             musl.arch_include_path, "-I",                     musl.arch_generic_include_path, "-I",                        musl.src_include_path, "-I",             musl.src_internal_path, "-I",                      musl.include_path,      "-I",  musl.triple_include_path, "-I",                              musl.generic_include_path, "-c",              src_file_path, "-o",        target_path,
        };
        const exit_code = try clangMain(context.allocator, args);
        if (exit_code != 0) unreachable;
    }
};

const CSourceKind = enum {
    c,
    cpp,
};

fn compileMusl(context: *const Context) MuslContext {
    const musl = try MuslContext.init(context);
    var exists = true;
    var dir = std.fs.cwd().openDir(musl.global_cache_dir, .{}) catch b: {
        exists = false;
        break :b undefined;
    };

    if (exists) {
        dir.close();
    } else {
        try std.fs.cwd().makePath(musl.global_cache_dir);
    }

    if (!exists) {
        var buffer: [65]u8 = undefined;
        var ar_args = BoundedArray([]const u8, 4096){};
        ar_args.appendAssumeCapacity("ar");
        ar_args.appendAssumeCapacity("rcs");
        ar_args.appendAssumeCapacity(try std.mem.concat(context.allocator, u8, &.{ musl.global_cache_dir, "libc.a" }));

        for (generic_musl_source_files) |src_file_relative_path| {
            const basename = std.fs.path.basename(src_file_relative_path);
            const target = try context.allocator.dupe(u8, basename);
            target[target.len - 1] = 'o';
            const hash = my_hash(src_file_relative_path);
            const hash_string = format_int(&buffer, hash, 16, false);
            const target_path = try std.mem.concat(context.allocator, u8, &.{ musl.global_cache_dir, hash_string, target });
            try musl.compileFileWithClang(context, src_file_relative_path, target_path);

            ar_args.appendAssumeCapacity(target_path);
        }

        for (musl_x86_64_source_files) |src_file_relative_path| {
            const basename = std.fs.path.basename(src_file_relative_path);
            const target = try context.allocator.dupe(u8, basename);
            target[target.len - 1] = 'o';
            const hash = my_hash(src_file_relative_path);
            const hash_string = format_int(&buffer, hash, 16, false);
            const target_path = try std.mem.concat(context.allocator, u8, &.{ musl.global_cache_dir, hash_string, target });

            try musl.compileFileWithClang(context, src_file_relative_path, target_path);
            ar_args.appendAssumeCapacity(target_path);
        }

        if (try arMain(context.allocator, ar_args.slice()) != 0) {
            unreachable;
        }

        const crt1_output_path = try std.mem.concat(context.allocator, u8, &.{ musl.global_cache_dir, "crt1.o" });
        {
            const crt_path = try context.pathFromCompiler("lib/libc/musl/crt/crt1.c");
            const args: []const []const u8 = &.{
                context.executable_absolute_path, "--no-default-config",  "-fno-caret-diagnostics", "-target",                      "x86_64-unknown-linux-musl", "-std=c99",            "-ffreestanding", "-mred-zone",           "-fno-omit-frame-pointer", "-fno-stack-protector", "-O2", "-fno-unwind-tables",     "-fno-asynchronous-unwind-tables", "-ffunction-sections",     "-fdata-sections", "-gdwarf-4", "-gdwarf32", "-Wa,--noexecstack", "-D_XOPEN_SOURCE=700", "-DCRT",
                "-I",                             musl.arch_include_path, "-I",                     musl.arch_generic_include_path, "-I",                        musl.src_include_path, "-I",             musl.src_internal_path, "-I",                      musl.include_path,      "-I",  musl.triple_include_path, "-I",                              musl.generic_include_path, "-c",              crt_path,    "-o",        crt1_output_path,
            };
            const exit_code = try clangMain(context.allocator, args);
            if (exit_code != 0) {
                unreachable;
            }
        }

        const crti_output_path = try std.mem.concat(context.allocator, u8, &.{ musl.global_cache_dir, "crti.o" });
        {
            const crt_path = try context.pathFromCompiler("lib/libc/musl/crt/crti.c");
            const args: []const []const u8 = &.{
                context.executable_absolute_path, "--no-default-config",  "-fno-caret-diagnostics", "-target",                      "x86_64-unknown-linux-musl", "-std=c99",            "-ffreestanding", "-mred-zone",           "-fno-omit-frame-pointer", "-fno-stack-protector", "-O2", "-fno-unwind-tables",     "-fno-asynchronous-unwind-tables", "-ffunction-sections",     "-fdata-sections", "-gdwarf-4", "-gdwarf32", "-Wa,--noexecstack", "-D_XOPEN_SOURCE=700", "-DCRT",
                "-I",                             musl.arch_include_path, "-I",                     musl.arch_generic_include_path, "-I",                        musl.src_include_path, "-I",             musl.src_internal_path, "-I",                      musl.include_path,      "-I",  musl.triple_include_path, "-I",                              musl.generic_include_path, "-c",              crt_path,    "-o",        crti_output_path,
            };
            const exit_code = try clangMain(context.allocator, args);
            if (exit_code != 0) {
                unreachable;
            }
        }

        {
            const crt_path = try context.pathFromCompiler("lib/libc/musl/crt/x86_64/crtn.s");
            const crt_output_path = try std.mem.concat(context.allocator, u8, &.{ musl.global_cache_dir, "crtn.o" });
            const args: []const []const u8 = &.{
                context.executable_absolute_path, "--no-default-config",  "-fno-caret-diagnostics", "-target",                      "x86_64-unknown-linux-musl", "-std=c99",            "-ffreestanding", "-mred-zone",           "-fno-omit-frame-pointer", "-fno-stack-protector", "-O2", "-fno-unwind-tables",     "-fno-asynchronous-unwind-tables", "-ffunction-sections",     "-fdata-sections", "-gdwarf-4", "-gdwarf32", "-Wa,--noexecstack", "-D_XOPEN_SOURCE=700",
                "-I",                             musl.arch_include_path, "-I",                     musl.arch_generic_include_path, "-I",                        musl.src_include_path, "-I",             musl.src_internal_path, "-I",                      musl.include_path,      "-I",  musl.triple_include_path, "-I",                              musl.generic_include_path, "-c",              crt_path,    "-o",        crt_output_path,
            };
            const exit_code = try clangMain(context.allocator, args);
            if (exit_code != 0) {
                unreachable;
            }
        }
    }

    return musl;
}

pub fn compileCSourceFile(context: *const Context, arguments: []const []const u8, kind: CSourceKind) !void {
    _ = kind; // autofix
    var argument_index: usize = 0;
    _ = &argument_index;
    const Mode = enum {
        object,
        link,
    };
    var out_path: ?[]const u8 = null;
    var out_mode: ?Mode = null;
    const Extension = enum {
        c,
        cpp,
        assembly,
        object,
        static_library,
        shared_library,
    };
    const CSourceFile = struct {
        path: []const u8,
        extension: Extension,
    };
    const DebugInfo = enum {
        yes,
        no,
    };
    const LinkArch = enum {
        arm64,
    };
    var debug_info: ?DebugInfo = null;
    var stack_protector: ?bool = null;
    var link_arch: ?LinkArch = null;

    var cc_argv = BoundedArray([]const u8, 4096){};
    var ld_argv = BoundedArray([]const u8, 4096){};
    var c_source_files = BoundedArray(CSourceFile, 4096){};
    var link_objects = BoundedArray(linker.Object, 4096){};
    var link_libraries = BoundedArray(linker.Library, 4096){};

    while (argument_index < arguments.len) {
        const argument = arguments[argument_index];

        if (argument[0] != '-') {
            if (last_byte(argument, '.')) |dot_index| {
                const extension_string = argument[dot_index..];
                const extension: Extension =
                    if (byte_equal(extension_string, ".c")) .c else if (byte_equal(extension_string, ".cpp") or byte_equal(extension_string, ".cxx") or byte_equal(extension_string, ".cc")) .cpp else if (byte_equal(extension_string, ".S")) .assembly else if (byte_equal(extension_string, ".o")) .object else if (byte_equal(extension_string, ".a")) .static_library else if (byte_equal(extension_string, ".so") or
                    byte_equal(extension_string, ".dll") or
                    byte_equal(extension_string, ".dylib") or
                    byte_equal(extension_string, ".tbd")) .shared_library else {
                    try write(.panic, argument);
                    try write(.panic, "\n");
                    @panic("Unable to recognize extension for the file above");
                };
                switch (extension) {
                    .c, .cpp, .assembly => {
                        c_source_files.appendAssumeCapacity(.{
                            .path = argument,
                            .extension = extension,
                        });
                    },
                    .object, .static_library, .shared_library => {
                        link_objects.appendAssumeCapacity(.{
                            .path = argument,
                        });
                    },
                }
            } else {
                try write(.panic, argument);
                try write(.panic, "\n");
                @panic("Positional argument without extension");
            }
        } else if (byte_equal(argument, "-c")) {
            out_mode = .object;
        } else if (byte_equal(argument, "-o")) {
            argument_index += 1;
            out_path = arguments[argument_index];
        } else if (byte_equal(argument, "-g")) {
            debug_info = .yes;
        } else if (byte_equal(argument, "-fno-stack-protector")) {
            stack_protector = false;
        } else if (byte_equal(argument, "-arch")) {
            argument_index += 1;
            const arch_argument = arguments[argument_index];
            if (byte_equal(arch_argument, "arm64")) {
                link_arch = .arm64;
                cc_argv.appendAssumeCapacity("-arch");
                cc_argv.appendAssumeCapacity("arm64");
            } else {
                unreachable;
            }
        } else if (byte_equal(argument, "-bundle")) {
            ld_argv.appendAssumeCapacity(argument);
        } else if (byte_equal(argument, "-pthread")) {
            cc_argv.appendAssumeCapacity(argument);
        } else if (byte_equal(argument, "-fPIC")) {
            cc_argv.appendAssumeCapacity(argument);
        } else if (byte_equal(argument, "-MD")) {
            cc_argv.appendAssumeCapacity(argument);
        } else if (byte_equal(argument, "-MT")) {
            cc_argv.appendAssumeCapacity(argument);
            argument_index += 1;
            const arg = arguments[argument_index];
            cc_argv.appendAssumeCapacity(arg);
        } else if (byte_equal(argument, "-MF")) {
            cc_argv.appendAssumeCapacity(argument);
            argument_index += 1;
            const arg = arguments[argument_index];
            cc_argv.appendAssumeCapacity(arg);
        } else if (byte_equal(argument, "-isysroot")) {
            cc_argv.appendAssumeCapacity(argument);
            argument_index += 1;
            const arg = arguments[argument_index];
            cc_argv.appendAssumeCapacity(arg);
        } else if (byte_equal(argument, "-isystem")) {
            cc_argv.appendAssumeCapacity(argument);
            argument_index += 1;
            const arg = arguments[argument_index];
            cc_argv.appendAssumeCapacity(arg);
        } else if (byte_equal(argument, "-h")) {
            cc_argv.appendAssumeCapacity(argument);
        } else if (byte_equal(argument, "-framework")) {
            ld_argv.appendAssumeCapacity(argument);
            argument_index += 1;
            const framework = arguments[argument_index];
            ld_argv.appendAssumeCapacity(framework);
        } else if (byte_equal(argument, "--coverage")) {
            cc_argv.appendAssumeCapacity(argument);
        } else if (byte_equal(argument, "-pedantic")) {
            cc_argv.appendAssumeCapacity(argument);
        } else if (byte_equal(argument, "-pedantic-errors")) {
            cc_argv.appendAssumeCapacity(argument);
        } else if (byte_equal(argument, "-?")) {
            cc_argv.appendAssumeCapacity(argument);
        } else if (byte_equal(argument, "-v")) {
            cc_argv.appendAssumeCapacity(argument);
        } else if (byte_equal(argument, "-V")) {
            cc_argv.appendAssumeCapacity(argument);
        } else if (byte_equal(argument, "--version")) {
            cc_argv.appendAssumeCapacity(argument);
        } else if (byte_equal(argument, "-version")) {
            cc_argv.appendAssumeCapacity(argument);
        } else if (byte_equal(argument, "-qversion")) {
            cc_argv.appendAssumeCapacity(argument);
        } else if (byte_equal(argument, "-print-resource-dir")) {
            cc_argv.appendAssumeCapacity(argument);
        } else if (byte_equal(argument, "-shared")) {
            ld_argv.appendAssumeCapacity(argument);
        } else if (byte_equal(argument, "-compatibility_version")) {
            ld_argv.appendAssumeCapacity(argument);
            argument_index += 1;
            const arg = arguments[argument_index];
            ld_argv.appendAssumeCapacity(arg);
        } else if (byte_equal(argument, "-current_version")) {
            ld_argv.appendAssumeCapacity(argument);
            argument_index += 1;
            const arg = arguments[argument_index];
            ld_argv.appendAssumeCapacity(arg);
        } else if (byte_equal(argument, "-install_name")) {
            ld_argv.appendAssumeCapacity(argument);
            argument_index += 1;
            const arg = arguments[argument_index];
            ld_argv.appendAssumeCapacity(arg);
        } else if (starts_with_slice(argument, "-f")) {
            cc_argv.appendAssumeCapacity(argument);
        } else if (starts_with_slice(argument, "-wd")) {
            cc_argv.appendAssumeCapacity(argument);
        } else if (starts_with_slice(argument, "-D")) {
            cc_argv.appendAssumeCapacity(argument);
        } else if (starts_with_slice(argument, "-I")) {
            cc_argv.appendAssumeCapacity(argument);
        } else if (starts_with_slice(argument, "-W")) {
            cc_argv.appendAssumeCapacity(argument);
        } else if (starts_with_slice(argument, "-l")) {
            link_libraries.appendAssumeCapacity(.{
                .path = argument[2..],
            });
        } else if (starts_with_slice(argument, "-O")) {
            cc_argv.appendAssumeCapacity(argument);
        } else if (starts_with_slice(argument, "-std=")) {
            cc_argv.appendAssumeCapacity(argument);
        } else if (starts_with_slice(argument, "-rdynamic")) {
            ld_argv.appendAssumeCapacity("-export_dynamic");
        } else if (starts_with_slice(argument, "-dynamiclib")) {
            ld_argv.appendAssumeCapacity("-dylib");
        } else if (starts_with_slice(argument, "-Wl,")) {
            const wl_arg = argument["-Wl,".len..];
            if (first_byte(wl_arg, ',')) |comma_index| {
                const key = wl_arg[0..comma_index];
                const value = wl_arg[comma_index + 1 ..];
                ld_argv.appendAssumeCapacity(key);
                ld_argv.appendAssumeCapacity(value);
            } else {
                ld_argv.appendAssumeCapacity(wl_arg);
            }
        } else if (starts_with_slice(argument, "-m")) {
            cc_argv.appendAssumeCapacity(argument);
        } else {
            try write(.panic, "unhandled argument: '");
            try write(.panic, argument);
            try write(.panic, "'\n");
            @panic("Unhandled argument");
        }

        argument_index += 1;
    }

    const link_libcpp = true;
    const mode = out_mode orelse .link;

    var argv = BoundedArray([]const u8, 4096){};
    if (c_source_files.len > 0) {
        for (c_source_files.slice()) |c_source_file| {
            argv.appendAssumeCapacity(context.executable_absolute_path);
            argv.appendAssumeCapacity("clang");
            argv.appendAssumeCapacity("--no-default-config");

            argv.appendAssumeCapacity(c_source_file.path);

            if (c_source_file.extension == .cpp) {
                argv.appendAssumeCapacity("-nostdinc++");
            }

            const caret = true;
            if (!caret) {
                argv.appendAssumeCapacity("-fno-caret-diagnostics");
            }

            const function_sections = false;
            if (function_sections) {
                argv.appendAssumeCapacity("-ffunction-sections");
            }

            const data_sections = false;
            if (data_sections) {
                argv.appendAssumeCapacity("-fdata-sections");
            }

            const builtin = true;
            if (!builtin) {
                argv.appendAssumeCapacity("-fno-builtin");
            }

            if (link_libcpp) {
                // include paths

            }

            const link_libc = c_source_file.extension == .c;
            if (link_libc) {}

            const link_libunwind = false;
            if (link_libunwind) {
                unreachable;
            }

            var target_triple_buffer = BoundedArray(u8, 512){};
            const target_triple = blk: {
                // Emit target
                switch (@import("builtin").target.cpu.arch) {
                    .x86_64 => {
                        target_triple_buffer.appendSliceAssumeCapacity("x86_64-");
                    },
                    .aarch64 => {
                        target_triple_buffer.appendSliceAssumeCapacity("aarch64-");
                    },
                    else => @compileError("Architecture not supported"),
                }

                if (@import("builtin").target.cpu.arch == .aarch64 and @import("builtin").target.os.tag == .macos) {
                    target_triple_buffer.appendSliceAssumeCapacity("apple-");
                } else {
                    target_triple_buffer.appendSliceAssumeCapacity("pc-");
                }

                switch (@import("builtin").target.os.tag) {
                    .linux => {
                        target_triple_buffer.appendSliceAssumeCapacity("linux-");
                    },
                    .macos => {
                        target_triple_buffer.appendSliceAssumeCapacity("macos-");
                    },
                    .windows => {
                        target_triple_buffer.appendSliceAssumeCapacity("windows-");
                    },
                    else => @compileError("OS not supported"),
                }

                switch (@import("builtin").target.abi) {
                    .musl => {
                        target_triple_buffer.appendSliceAssumeCapacity("musl");
                    },
                    .gnu => {
                        target_triple_buffer.appendSliceAssumeCapacity("gnu");
                    },
                    .none => {
                        target_triple_buffer.appendSliceAssumeCapacity("unknown");
                    },
                    else => @compileError("OS not supported"),
                }

                break :blk target_triple_buffer.slice();
            };
            argv.appendSliceAssumeCapacity(&.{ "-target", target_triple });

            const object_path = switch (mode) {
                .object => out_path.?,
                .link => try std.mem.concat(context.allocator, u8, &.{ if (out_path) |op| op else "a.o", ".o" }),
            };

            link_objects.appendAssumeCapacity(.{
                .path = object_path,
            });

            switch (c_source_file.extension) {
                .c, .cpp => {
                    argv.appendAssumeCapacity("-nostdinc");
                    argv.appendAssumeCapacity("-fno-spell-checking");

                    const lto = false;
                    if (lto) {
                        argv.appendAssumeCapacity("-flto");
                    }

                    const mm = false;
                    if (mm) {
                        argv.appendAssumeCapacity("-ObjC++");
                    }

                    const libc_framework_dirs: []const []const u8 = switch (@import("builtin").os.tag) {
                        .macos => &.{"/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/System/Library/Frameworks"},
                        else => &.{},
                    };
                    for (libc_framework_dirs) |framework_dir| {
                        argv.appendSliceAssumeCapacity(&.{ "-iframework", framework_dir });
                    }

                    const framework_dirs = &[_][]const u8{};
                    for (framework_dirs) |framework_dir| {
                        argv.appendSliceAssumeCapacity(&.{ "-F", framework_dir });
                    }

                    // TODO: c headers dir

                    const libc_include_dirs: []const []const u8 = switch (@import("builtin").os.tag) {
                        .macos => &.{
                            "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/c++/v1",
                            "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/clang/15.0.0/include",
                            "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include",
                        },
                        .linux => switch (@import("builtin").abi) {
                            .gnu => if (@import("configuration").ci) &.{
                                "/usr/include/c++/11",
                                "/usr/include/x86_64-linux-gnu/c++/11",
                                "/usr/lib/clang/17/include",
                                "/usr/include",
                                "/usr/include/x86_64-linux-gnu",
                            } else switch (@import("builtin").cpu.arch) {
                                .x86_64 => &.{
                                    "/usr/include/c++/13.2.1",
                                    "/usr/include/c++/13.2.1/x86_64-pc-linux-gnu",
                                    "/usr/lib/clang/17/include",
                                    "/usr/include",
                                    "/usr/include/linux",
                                },
                                .aarch64 => &.{
                                    "/usr/include/c++/13",
                                    "/usr/include/c++/13/aarch64-redhat-linux",
                                    "/usr/lib/clang/17/include",
                                    "/usr/include",
                                    "/usr/include/linux",
                                },
                                else => unreachable,
                            },
                            else => unreachable, //@compileError("ABI not supported"),
                        },
                        .windows => &.{},
                        else => @compileError("OS not supported"),
                    };

                    for (libc_include_dirs) |include_dir| {
                        argv.appendSliceAssumeCapacity(&.{ "-isystem", include_dir });
                    }

                    // TODO: cpu model
                    // TODO: cpu features
                    // TODO: code model
                    // TODO: OS-specific flags
                    // TODO: sanitize flags
                    // const red_zone = true;
                    // if (red_zone) {
                    //     argv.appendAssumeCapacity("-mred-zone");
                    // } else {
                    //     unreachable;
                    // }

                    const omit_frame_pointer = false;
                    if (omit_frame_pointer) {
                        argv.appendAssumeCapacity("-fomit-frame-pointer");
                    } else {
                        argv.appendAssumeCapacity("-fno-omit-frame-pointer");
                    }

                    if (stack_protector orelse false) {
                        argv.appendAssumeCapacity("-fstack-protector-strong");
                    } else {
                        argv.appendAssumeCapacity("-fno-stack-protector");
                    }

                    const is_debug = true;
                    if (is_debug) {
                        argv.appendAssumeCapacity("-D_DEBUG");
                        argv.appendAssumeCapacity("-O0");
                    } else {
                        unreachable;
                    }

                    const pic = false;
                    if (pic) {
                        argv.appendAssumeCapacity("-fPIC");
                    }

                    const unwind_tables = false;
                    if (unwind_tables) {
                        argv.appendAssumeCapacity("-funwind-tables");
                    } else {
                        argv.appendAssumeCapacity("-fno-unwind-tables");
                    }
                },
                .assembly => {
                    // TODO:
                },
                .object, .static_library, .shared_library => unreachable,
            }

            const has_debug_info = true;
            if (has_debug_info) {
                argv.appendAssumeCapacity("-g");
            } else {
                unreachable;
            }

            // TODO: machine ABI
            const freestanding = false;
            if (freestanding) {
                argv.appendAssumeCapacity("-ffrestanding");
            }

            // TODO: native system include paths
            // TODO: global cc argv

            argv.appendSliceAssumeCapacity(cc_argv.slice());

            // TODO: extra flags
            // TODO: cache exempt flags
            argv.appendSliceAssumeCapacity(&.{ "-c", "-o", object_path });
            // TODO: emit ASM/LLVM IR

            const debug_clang_args = false;
            if (debug_clang_args) {
                std.debug.print("Argv: {s}\n", .{argv.slice()});
            }
            const result = try clangMain(context.allocator, argv.slice());
            if (result != 0) {
                unreachable;
            }
        }
    } else if (link_objects.len == 0) {
        argv.appendAssumeCapacity(context.executable_absolute_path);
        argv.appendAssumeCapacity("clang");
        argv.appendAssumeCapacity("--no-default-config");
        argv.appendSliceAssumeCapacity(cc_argv.slice());
        const result = try clangMain(context.allocator, argv.slice());
        if (result != 0) {
            unreachable;
        }
        return;
    }

    if (mode == .link) {
        assert(link_objects.len > 0);
        try linker.link(context, .{
            .backend = .lld,
            .output_file_path = out_path orelse "a.out",
            .objects = link_objects.slice(),
            .libraries = link_libraries.slice(),
            .extra_arguments = ld_argv.slice(),
            .link_libc = true,
            .link_libcpp = link_libcpp,
        });
    }

    // if (kind == .cpp) {
    //     try clang_args.appendAssumeCapacity("-nostdinc++");
    //
    //     switch (@import("builtin").os.tag) {
    //         .linux => {
    //             switch (@import("builtin").abi) {
    //                 .gnu => {
    //                     try clang_args.appendSliceAssumeCapacity(&.{
    //                         "-isystem", "/usr/include/c++/13.2.1",
    //                         "-isystem", "/usr/include/c++/13.2.1/x86_64-pc-linux-gnu",
    //                     });
    //                 },
    //                 .musl => {
    //                     try clang_args.appendSliceAssumeCapacity(&.{
    //                         "-isystem", try context.pathFromCompiler("lib/libcxx/include"),
    //                         "-isystem", try context.pathFromCompiler("lib/libcxxabi/include"),
    //                         "-D_LIBCPP_DISABLE_VISIBILITY_ANNOTATIONS",
    //                         "-D_LIBCXXABI_DISABLE_VISIBILITY_ANNOTATIONS",
    //                         "-D_LIBCPP_HAS_NO_VENDOR_AVAILABILITY_ANNOTATIONS",
    //                         "-D_LIBCPP_PSTL_CPU_BACKEND_SERIAL",
    //                         "-D_LIBCPP_ABI_VERSION=1",
    //                         "-D_LIBCPP_ABI_NAMESPACE=__1",
    //                     });
    //                 },
    //                 else => unreachable,
    //             }
    //         },
    //         .macos => {
    //             try clang_args.appendSliceAssumeCapacity(&.{
    //                 "-isystem", try context.pathFromCompiler("lib/libcxx/include"),
    //                 "-isystem", try context.pathFromCompiler("lib/libcxxabi/include"),
    //                 "-D_LIBCPP_DISABLE_VISIBILITY_ANNOTATIONS",
    //                 "-D_LIBCXXABI_DISABLE_VISIBILITY_ANNOTATIONS",
    //                 "-D_LIBCPP_HAS_NO_VENDOR_AVAILABILITY_ANNOTATIONS",
    //                 "-D_LIBCPP_PSTL_CPU_BACKEND_SERIAL",
    //                 "-D_LIBCPP_ABI_VERSION=1",
    //                 "-D_LIBCPP_ABI_NAMESPACE=__1",
    //             });
    //         },
    //         else => @compileError("Operating system not supported"),
    //     }
    // }
    //
    // if (kind == .c or kind == .cpp) {
    //     try clang_args.appendAssumeCapacity("-nostdinc");
    //
    //     switch (@import("builtin").os.tag) {
    //         .linux => {
    //             switch (@import("builtin").abi) {
    //                 .gnu => {
    //                     try clang_args.appendSliceAssumeCapacity(&.{
    //                         "-isystem", "/usr/lib/clang/17/include",
    //                         "-isystem", "/usr/include",
    //                         "-isystem", "/usr/include/linux",
    //                     });
    //                 },
    //                 .musl => {
    //                     try clang_args.appendSliceAssumeCapacity(&.{
    //                         "-isystem", try context.pathFromCompiler("lib/include"),
    //                         "-isystem", try context.pathFromCompiler("lib/libc/include/x86_64-linux-gnu"),
    //                         "-isystem", try context.pathFromCompiler("lib/libc/include/generic-glibc"),
    //                         "-isystem", try context.pathFromCompiler("lib/libc/include/x86-linux-any"),
    //                         "-isystem", try context.pathFromCompiler("lib/libc/include/any-linux-any"),
    //                     });
    //                 },
    //                 else => @compileError("Abi not supported"),
    //             }
    //         },
    //         .macos => {
    //             try clang_args.appendSliceAssumeCapacity(&.{
    //                 "-iframework", "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/System/Library/Frameworks",
    //                 "-isystem",    try context.pathFromCompiler("lib/include"),
    //                 "-isystem",    "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include",
    //             });
    //         },
    //         else => @compileError("Operating system not supported"),
    //     }
    // }
    //
    // if (kind == .cpp) {
    //     switch (@import("builtin").os.tag) {
    //         .linux => {
    //             switch (@import("builtin").abi) {
    //                 .gnu => {
    //                     try clang_args.appendAssumeCapacity("-lstdc++");
    //                 },
    //                 .musl => {
    //                     unreachable;
    //                 },
    //                 else => @compileError("Abi not supported"),
    //             }
    //         },
    //         .macos => unreachable,
    //         else => @compileError("OS not supported"),
    //     }
    // }
    //
    // for (arguments) |arg| {
    //     try clang_args.appendAssumeCapacity(span(arg));
    // }
    //
    // const result = try clangMain(context.allocator, clang_args.slice());
    // if (result != 0) {
    //     unreachable;
    // }

    // const output_object_file = "nat/main.o";
    // const exit_code = try clangMain(context.allocator, &.{ context.executable_absolute_path, "--no-default-config", "-target", "x86_64-unknown-linux-musl", "-nostdinc", "-fno-spell-checking", "-isystem", "lib/include", "-isystem", "lib/libc/include/x86_64-linux-musl", "-isystem", "lib/libc/include/generic-musl", "-isystem", "lib/libc/include/x86-linux-any", "-isystem", "lib/libc/include/any-linux-any", "-c", argument, "-o", output_object_file });
    // if (exit_code != 0) {
    //     unreachable;
    // }

    // const link = false;
    // if (link) {
    //     var lld_args = PinnedArray([*:0]const u8){};
    //     try lld_args.appendAssumeCapacity("ld.lld");
    //     try lld_args.appendAssumeCapacity("--error-limit=0");
    //     try lld_args.appendAssumeCapacity("--entry");
    //     try lld_args.appendAssumeCapacity("_start");
    //     try lld_args.appendAssumeCapacity("-z");
    //     try lld_args.appendAssumeCapacity("stack-size=16777216");
    //     try lld_args.appendAssumeCapacity("--image-base=16777216");
    //     try lld_args.appendAssumeCapacity("-m");
    //     try lld_args.appendAssumeCapacity("elf_x86_64");
    //     try lld_args.appendAssumeCapacity("-static");
    //     try lld_args.appendAssumeCapacity("-o");
    //     try lld_args.appendAssumeCapacity("nat/main");
    //     try lld_args.appendAssumeCapacity(try std.mem.joinZ(context.allocator, "", &.{ musl.global_cache_dir, "crt1.o" }));
    //     try lld_args.appendAssumeCapacity(try std.mem.joinZ(context.allocator, "", &.{ musl.global_cache_dir, "crti.o" }));
    //     try lld_args.appendAssumeCapacity(output_object_file);
    //     try lld_args.appendAssumeCapacity("--as-needed");
    //     try lld_args.appendAssumeCapacity(try std.mem.joinZ(context.allocator, "", &.{ musl.global_cache_dir, "libc.a" }));
    //     try lld_args.appendAssumeCapacity(try std.mem.joinZ(context.allocator, "", &.{ musl.global_cache_dir, "crtn.o" }));
    //
    //     var stdout_ptr: [*]const u8 = undefined;
    //     var stdout_len: usize = 0;
    //     var stderr_ptr: [*]const u8 = undefined;
    //     var stderr_len: usize = 0;
    //     const link_result = llvm.bindings.NativityLLDLinkELF(lld_args.pointer, lld_args.length, &stdout_ptr, &stdout_len, &stderr_ptr, &stderr_len);
    //     if (!link_result) {
    //         unreachable;
    //     }
    // }
    // const thread = try std.Thread.spawn(.{}, clang_job, .{args});
    // thread.join();
}

const generic_musl_source_files = [_][]const u8{
    musl_lib_dir_relative_path ++ "src/aio/aio.c",
    musl_lib_dir_relative_path ++ "src/aio/aio_suspend.c",
    musl_lib_dir_relative_path ++ "src/aio/lio_listio.c",
    musl_lib_dir_relative_path ++ "src/complex/__cexp.c",
    musl_lib_dir_relative_path ++ "src/complex/__cexpf.c",
    musl_lib_dir_relative_path ++ "src/complex/cabs.c",
    musl_lib_dir_relative_path ++ "src/complex/cabsf.c",
    musl_lib_dir_relative_path ++ "src/complex/cabsl.c",
    musl_lib_dir_relative_path ++ "src/complex/cacos.c",
    musl_lib_dir_relative_path ++ "src/complex/cacosf.c",
    musl_lib_dir_relative_path ++ "src/complex/cacosh.c",
    musl_lib_dir_relative_path ++ "src/complex/cacoshf.c",
    musl_lib_dir_relative_path ++ "src/complex/cacoshl.c",
    musl_lib_dir_relative_path ++ "src/complex/cacosl.c",
    musl_lib_dir_relative_path ++ "src/complex/carg.c",
    musl_lib_dir_relative_path ++ "src/complex/cargf.c",
    musl_lib_dir_relative_path ++ "src/complex/cargl.c",
    musl_lib_dir_relative_path ++ "src/complex/casin.c",
    musl_lib_dir_relative_path ++ "src/complex/casinf.c",
    musl_lib_dir_relative_path ++ "src/complex/casinh.c",
    musl_lib_dir_relative_path ++ "src/complex/casinhf.c",
    musl_lib_dir_relative_path ++ "src/complex/casinhl.c",
    musl_lib_dir_relative_path ++ "src/complex/casinl.c",
    musl_lib_dir_relative_path ++ "src/complex/catan.c",
    musl_lib_dir_relative_path ++ "src/complex/catanf.c",
    musl_lib_dir_relative_path ++ "src/complex/catanh.c",
    musl_lib_dir_relative_path ++ "src/complex/catanhf.c",
    musl_lib_dir_relative_path ++ "src/complex/catanhl.c",
    musl_lib_dir_relative_path ++ "src/complex/catanl.c",
    musl_lib_dir_relative_path ++ "src/complex/ccos.c",
    musl_lib_dir_relative_path ++ "src/complex/ccosf.c",
    musl_lib_dir_relative_path ++ "src/complex/ccosh.c",
    musl_lib_dir_relative_path ++ "src/complex/ccoshf.c",
    musl_lib_dir_relative_path ++ "src/complex/ccoshl.c",
    musl_lib_dir_relative_path ++ "src/complex/ccosl.c",
    musl_lib_dir_relative_path ++ "src/complex/cexp.c",
    musl_lib_dir_relative_path ++ "src/complex/cexpf.c",
    musl_lib_dir_relative_path ++ "src/complex/cexpl.c",
    musl_lib_dir_relative_path ++ "src/complex/cimag.c",
    musl_lib_dir_relative_path ++ "src/complex/cimagf.c",
    musl_lib_dir_relative_path ++ "src/complex/cimagl.c",
    musl_lib_dir_relative_path ++ "src/complex/clog.c",
    musl_lib_dir_relative_path ++ "src/complex/clogf.c",
    musl_lib_dir_relative_path ++ "src/complex/clogl.c",
    musl_lib_dir_relative_path ++ "src/complex/conj.c",
    musl_lib_dir_relative_path ++ "src/complex/conjf.c",
    musl_lib_dir_relative_path ++ "src/complex/conjl.c",
    musl_lib_dir_relative_path ++ "src/complex/cpow.c",
    musl_lib_dir_relative_path ++ "src/complex/cpowf.c",
    musl_lib_dir_relative_path ++ "src/complex/cpowl.c",
    musl_lib_dir_relative_path ++ "src/complex/cproj.c",
    musl_lib_dir_relative_path ++ "src/complex/cprojf.c",
    musl_lib_dir_relative_path ++ "src/complex/cprojl.c",
    musl_lib_dir_relative_path ++ "src/complex/creal.c",
    musl_lib_dir_relative_path ++ "src/complex/crealf.c",
    musl_lib_dir_relative_path ++ "src/complex/creall.c",
    musl_lib_dir_relative_path ++ "src/complex/csin.c",
    musl_lib_dir_relative_path ++ "src/complex/csinf.c",
    musl_lib_dir_relative_path ++ "src/complex/csinh.c",
    musl_lib_dir_relative_path ++ "src/complex/csinhf.c",
    musl_lib_dir_relative_path ++ "src/complex/csinhl.c",
    musl_lib_dir_relative_path ++ "src/complex/csinl.c",
    musl_lib_dir_relative_path ++ "src/complex/csqrt.c",
    musl_lib_dir_relative_path ++ "src/complex/csqrtf.c",
    musl_lib_dir_relative_path ++ "src/complex/csqrtl.c",
    musl_lib_dir_relative_path ++ "src/complex/ctan.c",
    musl_lib_dir_relative_path ++ "src/complex/ctanf.c",
    musl_lib_dir_relative_path ++ "src/complex/ctanh.c",
    musl_lib_dir_relative_path ++ "src/complex/ctanhf.c",
    musl_lib_dir_relative_path ++ "src/complex/ctanhl.c",
    musl_lib_dir_relative_path ++ "src/complex/ctanl.c",
    musl_lib_dir_relative_path ++ "src/conf/confstr.c",
    musl_lib_dir_relative_path ++ "src/conf/fpathconf.c",
    musl_lib_dir_relative_path ++ "src/conf/legacy.c",
    musl_lib_dir_relative_path ++ "src/conf/pathconf.c",
    musl_lib_dir_relative_path ++ "src/conf/sysconf.c",
    musl_lib_dir_relative_path ++ "src/crypt/crypt.c",
    musl_lib_dir_relative_path ++ "src/crypt/crypt_blowfish.c",
    musl_lib_dir_relative_path ++ "src/crypt/crypt_des.c",
    musl_lib_dir_relative_path ++ "src/crypt/crypt_md5.c",
    musl_lib_dir_relative_path ++ "src/crypt/crypt_r.c",
    musl_lib_dir_relative_path ++ "src/crypt/crypt_sha256.c",
    musl_lib_dir_relative_path ++ "src/crypt/crypt_sha512.c",
    musl_lib_dir_relative_path ++ "src/crypt/encrypt.c",
    musl_lib_dir_relative_path ++ "src/ctype/__ctype_b_loc.c",
    musl_lib_dir_relative_path ++ "src/ctype/__ctype_get_mb_cur_max.c",
    musl_lib_dir_relative_path ++ "src/ctype/__ctype_tolower_loc.c",
    musl_lib_dir_relative_path ++ "src/ctype/__ctype_toupper_loc.c",
    musl_lib_dir_relative_path ++ "src/ctype/isalnum.c",
    musl_lib_dir_relative_path ++ "src/ctype/isalpha.c",
    musl_lib_dir_relative_path ++ "src/ctype/isascii.c",
    musl_lib_dir_relative_path ++ "src/ctype/isblank.c",
    musl_lib_dir_relative_path ++ "src/ctype/iscntrl.c",
    musl_lib_dir_relative_path ++ "src/ctype/isdigit.c",
    musl_lib_dir_relative_path ++ "src/ctype/isgraph.c",
    musl_lib_dir_relative_path ++ "src/ctype/islower.c",
    musl_lib_dir_relative_path ++ "src/ctype/isprint.c",
    musl_lib_dir_relative_path ++ "src/ctype/ispunct.c",
    musl_lib_dir_relative_path ++ "src/ctype/isspace.c",
    musl_lib_dir_relative_path ++ "src/ctype/isupper.c",
    musl_lib_dir_relative_path ++ "src/ctype/iswalnum.c",
    musl_lib_dir_relative_path ++ "src/ctype/iswalpha.c",
    musl_lib_dir_relative_path ++ "src/ctype/iswblank.c",
    musl_lib_dir_relative_path ++ "src/ctype/iswcntrl.c",
    musl_lib_dir_relative_path ++ "src/ctype/iswctype.c",
    musl_lib_dir_relative_path ++ "src/ctype/iswdigit.c",
    musl_lib_dir_relative_path ++ "src/ctype/iswgraph.c",
    musl_lib_dir_relative_path ++ "src/ctype/iswlower.c",
    musl_lib_dir_relative_path ++ "src/ctype/iswprint.c",
    musl_lib_dir_relative_path ++ "src/ctype/iswpunct.c",
    musl_lib_dir_relative_path ++ "src/ctype/iswspace.c",
    musl_lib_dir_relative_path ++ "src/ctype/iswupper.c",
    musl_lib_dir_relative_path ++ "src/ctype/iswxdigit.c",
    musl_lib_dir_relative_path ++ "src/ctype/isxdigit.c",
    musl_lib_dir_relative_path ++ "src/ctype/toascii.c",
    musl_lib_dir_relative_path ++ "src/ctype/tolower.c",
    musl_lib_dir_relative_path ++ "src/ctype/toupper.c",
    musl_lib_dir_relative_path ++ "src/ctype/towctrans.c",
    musl_lib_dir_relative_path ++ "src/ctype/wcswidth.c",
    musl_lib_dir_relative_path ++ "src/ctype/wctrans.c",
    musl_lib_dir_relative_path ++ "src/ctype/wcwidth.c",
    musl_lib_dir_relative_path ++ "src/dirent/alphasort.c",
    musl_lib_dir_relative_path ++ "src/dirent/closedir.c",
    musl_lib_dir_relative_path ++ "src/dirent/dirfd.c",
    musl_lib_dir_relative_path ++ "src/dirent/fdopendir.c",
    musl_lib_dir_relative_path ++ "src/dirent/opendir.c",
    musl_lib_dir_relative_path ++ "src/dirent/readdir.c",
    musl_lib_dir_relative_path ++ "src/dirent/readdir_r.c",
    musl_lib_dir_relative_path ++ "src/dirent/rewinddir.c",
    musl_lib_dir_relative_path ++ "src/dirent/scandir.c",
    musl_lib_dir_relative_path ++ "src/dirent/seekdir.c",
    musl_lib_dir_relative_path ++ "src/dirent/telldir.c",
    musl_lib_dir_relative_path ++ "src/dirent/versionsort.c",
    musl_lib_dir_relative_path ++ "src/env/__environ.c",
    musl_lib_dir_relative_path ++ "src/env/__init_tls.c",
    musl_lib_dir_relative_path ++ "src/env/__libc_start_main.c",
    musl_lib_dir_relative_path ++ "src/env/__reset_tls.c",
    musl_lib_dir_relative_path ++ "src/env/__stack_chk_fail.c",
    musl_lib_dir_relative_path ++ "src/env/clearenv.c",
    musl_lib_dir_relative_path ++ "src/env/getenv.c",
    musl_lib_dir_relative_path ++ "src/env/putenv.c",
    musl_lib_dir_relative_path ++ "src/env/secure_getenv.c",
    musl_lib_dir_relative_path ++ "src/env/setenv.c",
    musl_lib_dir_relative_path ++ "src/env/unsetenv.c",
    musl_lib_dir_relative_path ++ "src/errno/__errno_location.c",
    musl_lib_dir_relative_path ++ "src/errno/strerror.c",
    musl_lib_dir_relative_path ++ "src/exit/_Exit.c",
    musl_lib_dir_relative_path ++ "src/exit/abort.c",
    musl_lib_dir_relative_path ++ "src/exit/abort_lock.c",
    musl_lib_dir_relative_path ++ "src/exit/arm/__aeabi_atexit.c",
    musl_lib_dir_relative_path ++ "src/exit/assert.c",
    musl_lib_dir_relative_path ++ "src/exit/at_quick_exit.c",
    musl_lib_dir_relative_path ++ "src/exit/atexit.c",
    musl_lib_dir_relative_path ++ "src/exit/exit.c",
    musl_lib_dir_relative_path ++ "src/exit/quick_exit.c",
    musl_lib_dir_relative_path ++ "src/fcntl/creat.c",
    musl_lib_dir_relative_path ++ "src/fcntl/fcntl.c",
    musl_lib_dir_relative_path ++ "src/fcntl/open.c",
    musl_lib_dir_relative_path ++ "src/fcntl/openat.c",
    musl_lib_dir_relative_path ++ "src/fcntl/posix_fadvise.c",
    musl_lib_dir_relative_path ++ "src/fcntl/posix_fallocate.c",
    musl_lib_dir_relative_path ++ "src/fenv/__flt_rounds.c",
    musl_lib_dir_relative_path ++ "src/fenv/fegetexceptflag.c",
    musl_lib_dir_relative_path ++ "src/fenv/feholdexcept.c",
    musl_lib_dir_relative_path ++ "src/fenv/fenv.c",
    musl_lib_dir_relative_path ++ "src/fenv/fesetexceptflag.c",
    musl_lib_dir_relative_path ++ "src/fenv/fesetround.c",
    musl_lib_dir_relative_path ++ "src/fenv/feupdateenv.c",
    musl_lib_dir_relative_path ++ "src/internal/defsysinfo.c",
    musl_lib_dir_relative_path ++ "src/internal/floatscan.c",
    musl_lib_dir_relative_path ++ "src/internal/intscan.c",
    musl_lib_dir_relative_path ++ "src/internal/libc.c",
    musl_lib_dir_relative_path ++ "src/internal/procfdname.c",
    musl_lib_dir_relative_path ++ "src/internal/shgetc.c",
    musl_lib_dir_relative_path ++ "src/internal/syscall_ret.c",
    musl_lib_dir_relative_path ++ "src/internal/vdso.c",
    musl_lib_dir_relative_path ++ "src/internal/version.c",
    musl_lib_dir_relative_path ++ "src/ipc/ftok.c",
    musl_lib_dir_relative_path ++ "src/ipc/msgctl.c",
    musl_lib_dir_relative_path ++ "src/ipc/msgget.c",
    musl_lib_dir_relative_path ++ "src/ipc/msgrcv.c",
    musl_lib_dir_relative_path ++ "src/ipc/msgsnd.c",
    musl_lib_dir_relative_path ++ "src/ipc/semctl.c",
    musl_lib_dir_relative_path ++ "src/ipc/semget.c",
    musl_lib_dir_relative_path ++ "src/ipc/semop.c",
    musl_lib_dir_relative_path ++ "src/ipc/semtimedop.c",
    musl_lib_dir_relative_path ++ "src/ipc/shmat.c",
    musl_lib_dir_relative_path ++ "src/ipc/shmctl.c",
    musl_lib_dir_relative_path ++ "src/ipc/shmdt.c",
    musl_lib_dir_relative_path ++ "src/ipc/shmget.c",
    musl_lib_dir_relative_path ++ "src/ldso/__dlsym.c",
    musl_lib_dir_relative_path ++ "src/ldso/dl_iterate_phdr.c",
    musl_lib_dir_relative_path ++ "src/ldso/dladdr.c",
    musl_lib_dir_relative_path ++ "src/ldso/dlclose.c",
    musl_lib_dir_relative_path ++ "src/ldso/dlerror.c",
    musl_lib_dir_relative_path ++ "src/ldso/dlinfo.c",
    musl_lib_dir_relative_path ++ "src/ldso/dlopen.c",
    musl_lib_dir_relative_path ++ "src/ldso/dlsym.c",
    musl_lib_dir_relative_path ++ "src/legacy/cuserid.c",
    musl_lib_dir_relative_path ++ "src/legacy/daemon.c",
    musl_lib_dir_relative_path ++ "src/legacy/err.c",
    musl_lib_dir_relative_path ++ "src/legacy/euidaccess.c",
    musl_lib_dir_relative_path ++ "src/legacy/ftw.c",
    musl_lib_dir_relative_path ++ "src/legacy/futimes.c",
    musl_lib_dir_relative_path ++ "src/legacy/getdtablesize.c",
    musl_lib_dir_relative_path ++ "src/legacy/getloadavg.c",
    musl_lib_dir_relative_path ++ "src/legacy/getpagesize.c",
    musl_lib_dir_relative_path ++ "src/legacy/getpass.c",
    musl_lib_dir_relative_path ++ "src/legacy/getusershell.c",
    musl_lib_dir_relative_path ++ "src/legacy/isastream.c",
    musl_lib_dir_relative_path ++ "src/legacy/lutimes.c",
    musl_lib_dir_relative_path ++ "src/legacy/ulimit.c",
    musl_lib_dir_relative_path ++ "src/legacy/utmpx.c",
    musl_lib_dir_relative_path ++ "src/legacy/valloc.c",
    musl_lib_dir_relative_path ++ "src/linux/adjtime.c",
    musl_lib_dir_relative_path ++ "src/linux/adjtimex.c",
    musl_lib_dir_relative_path ++ "src/linux/arch_prctl.c",
    musl_lib_dir_relative_path ++ "src/linux/brk.c",
    musl_lib_dir_relative_path ++ "src/linux/cache.c",
    musl_lib_dir_relative_path ++ "src/linux/cap.c",
    musl_lib_dir_relative_path ++ "src/linux/chroot.c",
    musl_lib_dir_relative_path ++ "src/linux/clock_adjtime.c",
    musl_lib_dir_relative_path ++ "src/linux/clone.c",
    musl_lib_dir_relative_path ++ "src/linux/copy_file_range.c",
    musl_lib_dir_relative_path ++ "src/linux/epoll.c",
    musl_lib_dir_relative_path ++ "src/linux/eventfd.c",
    musl_lib_dir_relative_path ++ "src/linux/fallocate.c",
    musl_lib_dir_relative_path ++ "src/linux/fanotify.c",
    musl_lib_dir_relative_path ++ "src/linux/flock.c",
    musl_lib_dir_relative_path ++ "src/linux/getdents.c",
    musl_lib_dir_relative_path ++ "src/linux/getrandom.c",
    musl_lib_dir_relative_path ++ "src/linux/gettid.c",
    musl_lib_dir_relative_path ++ "src/linux/inotify.c",
    musl_lib_dir_relative_path ++ "src/linux/ioperm.c",
    musl_lib_dir_relative_path ++ "src/linux/iopl.c",
    musl_lib_dir_relative_path ++ "src/linux/klogctl.c",
    musl_lib_dir_relative_path ++ "src/linux/membarrier.c",
    musl_lib_dir_relative_path ++ "src/linux/memfd_create.c",
    musl_lib_dir_relative_path ++ "src/linux/mlock2.c",
    musl_lib_dir_relative_path ++ "src/linux/module.c",
    musl_lib_dir_relative_path ++ "src/linux/mount.c",
    musl_lib_dir_relative_path ++ "src/linux/name_to_handle_at.c",
    musl_lib_dir_relative_path ++ "src/linux/open_by_handle_at.c",
    musl_lib_dir_relative_path ++ "src/linux/personality.c",
    musl_lib_dir_relative_path ++ "src/linux/pivot_root.c",
    musl_lib_dir_relative_path ++ "src/linux/ppoll.c",
    musl_lib_dir_relative_path ++ "src/linux/prctl.c",
    musl_lib_dir_relative_path ++ "src/linux/prlimit.c",
    musl_lib_dir_relative_path ++ "src/linux/process_vm.c",
    musl_lib_dir_relative_path ++ "src/linux/ptrace.c",
    musl_lib_dir_relative_path ++ "src/linux/quotactl.c",
    musl_lib_dir_relative_path ++ "src/linux/readahead.c",
    musl_lib_dir_relative_path ++ "src/linux/reboot.c",
    musl_lib_dir_relative_path ++ "src/linux/remap_file_pages.c",
    musl_lib_dir_relative_path ++ "src/linux/sbrk.c",
    musl_lib_dir_relative_path ++ "src/linux/sendfile.c",
    musl_lib_dir_relative_path ++ "src/linux/setfsgid.c",
    musl_lib_dir_relative_path ++ "src/linux/setfsuid.c",
    musl_lib_dir_relative_path ++ "src/linux/setgroups.c",
    musl_lib_dir_relative_path ++ "src/linux/sethostname.c",
    musl_lib_dir_relative_path ++ "src/linux/setns.c",
    musl_lib_dir_relative_path ++ "src/linux/settimeofday.c",
    musl_lib_dir_relative_path ++ "src/linux/signalfd.c",
    musl_lib_dir_relative_path ++ "src/linux/splice.c",
    musl_lib_dir_relative_path ++ "src/linux/stime.c",
    musl_lib_dir_relative_path ++ "src/linux/swap.c",
    musl_lib_dir_relative_path ++ "src/linux/sync_file_range.c",
    musl_lib_dir_relative_path ++ "src/linux/syncfs.c",
    musl_lib_dir_relative_path ++ "src/linux/sysinfo.c",
    musl_lib_dir_relative_path ++ "src/linux/tee.c",
    musl_lib_dir_relative_path ++ "src/linux/timerfd.c",
    musl_lib_dir_relative_path ++ "src/linux/unshare.c",
    musl_lib_dir_relative_path ++ "src/linux/utimes.c",
    musl_lib_dir_relative_path ++ "src/linux/vhangup.c",
    musl_lib_dir_relative_path ++ "src/linux/vmsplice.c",
    musl_lib_dir_relative_path ++ "src/linux/wait3.c",
    musl_lib_dir_relative_path ++ "src/linux/wait4.c",
    musl_lib_dir_relative_path ++ "src/linux/xattr.c",
    musl_lib_dir_relative_path ++ "src/locale/__lctrans.c",
    musl_lib_dir_relative_path ++ "src/locale/__mo_lookup.c",
    musl_lib_dir_relative_path ++ "src/locale/bind_textdomain_codeset.c",
    musl_lib_dir_relative_path ++ "src/locale/c_locale.c",
    musl_lib_dir_relative_path ++ "src/locale/catclose.c",
    musl_lib_dir_relative_path ++ "src/locale/catgets.c",
    musl_lib_dir_relative_path ++ "src/locale/catopen.c",
    musl_lib_dir_relative_path ++ "src/locale/dcngettext.c",
    musl_lib_dir_relative_path ++ "src/locale/duplocale.c",
    musl_lib_dir_relative_path ++ "src/locale/freelocale.c",
    musl_lib_dir_relative_path ++ "src/locale/iconv.c",
    musl_lib_dir_relative_path ++ "src/locale/iconv_close.c",
    musl_lib_dir_relative_path ++ "src/locale/langinfo.c",
    musl_lib_dir_relative_path ++ "src/locale/locale_map.c",
    musl_lib_dir_relative_path ++ "src/locale/localeconv.c",
    musl_lib_dir_relative_path ++ "src/locale/newlocale.c",
    musl_lib_dir_relative_path ++ "src/locale/pleval.c",
    musl_lib_dir_relative_path ++ "src/locale/setlocale.c",
    musl_lib_dir_relative_path ++ "src/locale/strcoll.c",
    musl_lib_dir_relative_path ++ "src/locale/strfmon.c",
    musl_lib_dir_relative_path ++ "src/locale/strtod_l.c",
    musl_lib_dir_relative_path ++ "src/locale/strxfrm.c",
    musl_lib_dir_relative_path ++ "src/locale/textdomain.c",
    musl_lib_dir_relative_path ++ "src/locale/uselocale.c",
    musl_lib_dir_relative_path ++ "src/locale/wcscoll.c",
    musl_lib_dir_relative_path ++ "src/locale/wcsxfrm.c",
    musl_lib_dir_relative_path ++ "src/malloc/calloc.c",
    musl_lib_dir_relative_path ++ "src/malloc/free.c",
    musl_lib_dir_relative_path ++ "src/malloc/libc_calloc.c",
    musl_lib_dir_relative_path ++ "src/malloc/lite_malloc.c",
    musl_lib_dir_relative_path ++ "src/malloc/mallocng/aligned_alloc.c",
    musl_lib_dir_relative_path ++ "src/malloc/mallocng/donate.c",
    musl_lib_dir_relative_path ++ "src/malloc/mallocng/free.c",
    musl_lib_dir_relative_path ++ "src/malloc/mallocng/malloc.c",
    musl_lib_dir_relative_path ++ "src/malloc/mallocng/malloc_usable_size.c",
    musl_lib_dir_relative_path ++ "src/malloc/mallocng/realloc.c",
    musl_lib_dir_relative_path ++ "src/malloc/memalign.c",
    musl_lib_dir_relative_path ++ "src/malloc/oldmalloc/aligned_alloc.c",
    musl_lib_dir_relative_path ++ "src/malloc/oldmalloc/malloc.c",
    musl_lib_dir_relative_path ++ "src/malloc/oldmalloc/malloc_usable_size.c",
    musl_lib_dir_relative_path ++ "src/malloc/posix_memalign.c",
    musl_lib_dir_relative_path ++ "src/malloc/realloc.c",
    musl_lib_dir_relative_path ++ "src/malloc/reallocarray.c",
    musl_lib_dir_relative_path ++ "src/malloc/replaced.c",
    musl_lib_dir_relative_path ++ "src/math/__cos.c",
    musl_lib_dir_relative_path ++ "src/math/__cosdf.c",
    musl_lib_dir_relative_path ++ "src/math/__cosl.c",
    musl_lib_dir_relative_path ++ "src/math/__expo2.c",
    musl_lib_dir_relative_path ++ "src/math/__expo2f.c",
    musl_lib_dir_relative_path ++ "src/math/__fpclassify.c",
    musl_lib_dir_relative_path ++ "src/math/__fpclassifyf.c",
    musl_lib_dir_relative_path ++ "src/math/__fpclassifyl.c",
    musl_lib_dir_relative_path ++ "src/math/__invtrigl.c",
    musl_lib_dir_relative_path ++ "src/math/__math_divzero.c",
    musl_lib_dir_relative_path ++ "src/math/__math_divzerof.c",
    musl_lib_dir_relative_path ++ "src/math/__math_invalid.c",
    musl_lib_dir_relative_path ++ "src/math/__math_invalidf.c",
    musl_lib_dir_relative_path ++ "src/math/__math_invalidl.c",
    musl_lib_dir_relative_path ++ "src/math/__math_oflow.c",
    musl_lib_dir_relative_path ++ "src/math/__math_oflowf.c",
    musl_lib_dir_relative_path ++ "src/math/__math_uflow.c",
    musl_lib_dir_relative_path ++ "src/math/__math_uflowf.c",
    musl_lib_dir_relative_path ++ "src/math/__math_xflow.c",
    musl_lib_dir_relative_path ++ "src/math/__math_xflowf.c",
    musl_lib_dir_relative_path ++ "src/math/__polevll.c",
    musl_lib_dir_relative_path ++ "src/math/__rem_pio2.c",
    musl_lib_dir_relative_path ++ "src/math/__rem_pio2_large.c",
    musl_lib_dir_relative_path ++ "src/math/__rem_pio2f.c",
    musl_lib_dir_relative_path ++ "src/math/__rem_pio2l.c",
    musl_lib_dir_relative_path ++ "src/math/__signbit.c",
    musl_lib_dir_relative_path ++ "src/math/__signbitf.c",
    musl_lib_dir_relative_path ++ "src/math/__signbitl.c",
    musl_lib_dir_relative_path ++ "src/math/__sin.c",
    musl_lib_dir_relative_path ++ "src/math/__sindf.c",
    musl_lib_dir_relative_path ++ "src/math/__sinl.c",
    musl_lib_dir_relative_path ++ "src/math/__tan.c",
    musl_lib_dir_relative_path ++ "src/math/__tandf.c",
    musl_lib_dir_relative_path ++ "src/math/__tanl.c",
    musl_lib_dir_relative_path ++ "src/math/acos.c",
    musl_lib_dir_relative_path ++ "src/math/acosf.c",
    musl_lib_dir_relative_path ++ "src/math/acosh.c",
    musl_lib_dir_relative_path ++ "src/math/acoshf.c",
    musl_lib_dir_relative_path ++ "src/math/acoshl.c",
    musl_lib_dir_relative_path ++ "src/math/acosl.c",
    musl_lib_dir_relative_path ++ "src/math/asin.c",
    musl_lib_dir_relative_path ++ "src/math/asinf.c",
    musl_lib_dir_relative_path ++ "src/math/asinh.c",
    musl_lib_dir_relative_path ++ "src/math/asinhf.c",
    musl_lib_dir_relative_path ++ "src/math/asinhl.c",
    musl_lib_dir_relative_path ++ "src/math/asinl.c",
    musl_lib_dir_relative_path ++ "src/math/atan.c",
    musl_lib_dir_relative_path ++ "src/math/atan2.c",
    musl_lib_dir_relative_path ++ "src/math/atan2f.c",
    musl_lib_dir_relative_path ++ "src/math/atan2l.c",
    musl_lib_dir_relative_path ++ "src/math/atanf.c",
    musl_lib_dir_relative_path ++ "src/math/atanh.c",
    musl_lib_dir_relative_path ++ "src/math/atanhf.c",
    musl_lib_dir_relative_path ++ "src/math/atanhl.c",
    musl_lib_dir_relative_path ++ "src/math/atanl.c",
    musl_lib_dir_relative_path ++ "src/math/cbrt.c",
    musl_lib_dir_relative_path ++ "src/math/cbrtf.c",
    musl_lib_dir_relative_path ++ "src/math/cbrtl.c",
    musl_lib_dir_relative_path ++ "src/math/ceil.c",
    musl_lib_dir_relative_path ++ "src/math/ceilf.c",
    musl_lib_dir_relative_path ++ "src/math/ceill.c",
    musl_lib_dir_relative_path ++ "src/math/copysign.c",
    musl_lib_dir_relative_path ++ "src/math/copysignf.c",
    musl_lib_dir_relative_path ++ "src/math/copysignl.c",
    musl_lib_dir_relative_path ++ "src/math/cos.c",
    musl_lib_dir_relative_path ++ "src/math/cosf.c",
    musl_lib_dir_relative_path ++ "src/math/cosh.c",
    musl_lib_dir_relative_path ++ "src/math/coshf.c",
    musl_lib_dir_relative_path ++ "src/math/coshl.c",
    musl_lib_dir_relative_path ++ "src/math/cosl.c",
    musl_lib_dir_relative_path ++ "src/math/erf.c",
    musl_lib_dir_relative_path ++ "src/math/erff.c",
    musl_lib_dir_relative_path ++ "src/math/erfl.c",
    musl_lib_dir_relative_path ++ "src/math/exp.c",
    musl_lib_dir_relative_path ++ "src/math/exp10.c",
    musl_lib_dir_relative_path ++ "src/math/exp10f.c",
    musl_lib_dir_relative_path ++ "src/math/exp10l.c",
    musl_lib_dir_relative_path ++ "src/math/exp2.c",
    musl_lib_dir_relative_path ++ "src/math/exp2f.c",
    musl_lib_dir_relative_path ++ "src/math/exp2f_data.c",
    musl_lib_dir_relative_path ++ "src/math/exp2l.c",
    musl_lib_dir_relative_path ++ "src/math/exp_data.c",
    musl_lib_dir_relative_path ++ "src/math/expf.c",
    musl_lib_dir_relative_path ++ "src/math/expl.c",
    musl_lib_dir_relative_path ++ "src/math/expm1.c",
    musl_lib_dir_relative_path ++ "src/math/expm1f.c",
    musl_lib_dir_relative_path ++ "src/math/expm1l.c",
    musl_lib_dir_relative_path ++ "src/math/fabs.c",
    musl_lib_dir_relative_path ++ "src/math/fabsf.c",
    musl_lib_dir_relative_path ++ "src/math/fabsl.c",
    musl_lib_dir_relative_path ++ "src/math/fdim.c",
    musl_lib_dir_relative_path ++ "src/math/fdimf.c",
    musl_lib_dir_relative_path ++ "src/math/fdiml.c",
    musl_lib_dir_relative_path ++ "src/math/finite.c",
    musl_lib_dir_relative_path ++ "src/math/finitef.c",
    musl_lib_dir_relative_path ++ "src/math/floor.c",
    musl_lib_dir_relative_path ++ "src/math/floorf.c",
    musl_lib_dir_relative_path ++ "src/math/floorl.c",
    musl_lib_dir_relative_path ++ "src/math/fma.c",
    musl_lib_dir_relative_path ++ "src/math/fmaf.c",
    musl_lib_dir_relative_path ++ "src/math/fmal.c",
    musl_lib_dir_relative_path ++ "src/math/fmax.c",
    musl_lib_dir_relative_path ++ "src/math/fmaxf.c",
    musl_lib_dir_relative_path ++ "src/math/fmaxl.c",
    musl_lib_dir_relative_path ++ "src/math/fmin.c",
    musl_lib_dir_relative_path ++ "src/math/fminf.c",
    musl_lib_dir_relative_path ++ "src/math/fminl.c",
    musl_lib_dir_relative_path ++ "src/math/fmod.c",
    musl_lib_dir_relative_path ++ "src/math/fmodf.c",
    musl_lib_dir_relative_path ++ "src/math/fmodl.c",
    musl_lib_dir_relative_path ++ "src/math/frexp.c",
    musl_lib_dir_relative_path ++ "src/math/frexpf.c",
    musl_lib_dir_relative_path ++ "src/math/frexpl.c",
    musl_lib_dir_relative_path ++ "src/math/hypot.c",
    musl_lib_dir_relative_path ++ "src/math/hypotf.c",
    musl_lib_dir_relative_path ++ "src/math/hypotl.c",
    musl_lib_dir_relative_path ++ "src/math/ilogb.c",
    musl_lib_dir_relative_path ++ "src/math/ilogbf.c",
    musl_lib_dir_relative_path ++ "src/math/ilogbl.c",
    musl_lib_dir_relative_path ++ "src/math/j0.c",
    musl_lib_dir_relative_path ++ "src/math/j0f.c",
    musl_lib_dir_relative_path ++ "src/math/j1.c",
    musl_lib_dir_relative_path ++ "src/math/j1f.c",
    musl_lib_dir_relative_path ++ "src/math/jn.c",
    musl_lib_dir_relative_path ++ "src/math/jnf.c",
    musl_lib_dir_relative_path ++ "src/math/ldexp.c",
    musl_lib_dir_relative_path ++ "src/math/ldexpf.c",
    musl_lib_dir_relative_path ++ "src/math/ldexpl.c",
    musl_lib_dir_relative_path ++ "src/math/lgamma.c",
    musl_lib_dir_relative_path ++ "src/math/lgamma_r.c",
    musl_lib_dir_relative_path ++ "src/math/lgammaf.c",
    musl_lib_dir_relative_path ++ "src/math/lgammaf_r.c",
    musl_lib_dir_relative_path ++ "src/math/lgammal.c",
    musl_lib_dir_relative_path ++ "src/math/llrint.c",
    musl_lib_dir_relative_path ++ "src/math/llrintf.c",
    musl_lib_dir_relative_path ++ "src/math/llrintl.c",
    musl_lib_dir_relative_path ++ "src/math/llround.c",
    musl_lib_dir_relative_path ++ "src/math/llroundf.c",
    musl_lib_dir_relative_path ++ "src/math/llroundl.c",
    musl_lib_dir_relative_path ++ "src/math/log.c",
    musl_lib_dir_relative_path ++ "src/math/log10.c",
    musl_lib_dir_relative_path ++ "src/math/log10f.c",
    musl_lib_dir_relative_path ++ "src/math/log10l.c",
    musl_lib_dir_relative_path ++ "src/math/log1p.c",
    musl_lib_dir_relative_path ++ "src/math/log1pf.c",
    musl_lib_dir_relative_path ++ "src/math/log1pl.c",
    musl_lib_dir_relative_path ++ "src/math/log2.c",
    musl_lib_dir_relative_path ++ "src/math/log2_data.c",
    musl_lib_dir_relative_path ++ "src/math/log2f.c",
    musl_lib_dir_relative_path ++ "src/math/log2f_data.c",
    musl_lib_dir_relative_path ++ "src/math/log2l.c",
    musl_lib_dir_relative_path ++ "src/math/log_data.c",
    musl_lib_dir_relative_path ++ "src/math/logb.c",
    musl_lib_dir_relative_path ++ "src/math/logbf.c",
    musl_lib_dir_relative_path ++ "src/math/logbl.c",
    musl_lib_dir_relative_path ++ "src/math/logf.c",
    musl_lib_dir_relative_path ++ "src/math/logf_data.c",
    musl_lib_dir_relative_path ++ "src/math/logl.c",
    musl_lib_dir_relative_path ++ "src/math/lrint.c",
    musl_lib_dir_relative_path ++ "src/math/lrintf.c",
    musl_lib_dir_relative_path ++ "src/math/lrintl.c",
    musl_lib_dir_relative_path ++ "src/math/lround.c",
    musl_lib_dir_relative_path ++ "src/math/lroundf.c",
    musl_lib_dir_relative_path ++ "src/math/lroundl.c",
    musl_lib_dir_relative_path ++ "src/math/modf.c",
    musl_lib_dir_relative_path ++ "src/math/modff.c",
    musl_lib_dir_relative_path ++ "src/math/modfl.c",
    musl_lib_dir_relative_path ++ "src/math/nan.c",
    musl_lib_dir_relative_path ++ "src/math/nanf.c",
    musl_lib_dir_relative_path ++ "src/math/nanl.c",
    musl_lib_dir_relative_path ++ "src/math/nearbyint.c",
    musl_lib_dir_relative_path ++ "src/math/nearbyintf.c",
    musl_lib_dir_relative_path ++ "src/math/nearbyintl.c",
    musl_lib_dir_relative_path ++ "src/math/nextafter.c",
    musl_lib_dir_relative_path ++ "src/math/nextafterf.c",
    musl_lib_dir_relative_path ++ "src/math/nextafterl.c",
    musl_lib_dir_relative_path ++ "src/math/nexttoward.c",
    musl_lib_dir_relative_path ++ "src/math/nexttowardf.c",
    musl_lib_dir_relative_path ++ "src/math/nexttowardl.c",
    musl_lib_dir_relative_path ++ "src/math/pow.c",
    musl_lib_dir_relative_path ++ "src/math/pow_data.c",
    musl_lib_dir_relative_path ++ "src/math/powf.c",
    musl_lib_dir_relative_path ++ "src/math/powf_data.c",
    musl_lib_dir_relative_path ++ "src/math/powl.c",
    musl_lib_dir_relative_path ++ "src/math/remainder.c",
    musl_lib_dir_relative_path ++ "src/math/remainderf.c",
    musl_lib_dir_relative_path ++ "src/math/remainderl.c",
    musl_lib_dir_relative_path ++ "src/math/remquo.c",
    musl_lib_dir_relative_path ++ "src/math/remquof.c",
    musl_lib_dir_relative_path ++ "src/math/remquol.c",
    musl_lib_dir_relative_path ++ "src/math/rint.c",
    musl_lib_dir_relative_path ++ "src/math/rintf.c",
    musl_lib_dir_relative_path ++ "src/math/rintl.c",
    musl_lib_dir_relative_path ++ "src/math/round.c",
    musl_lib_dir_relative_path ++ "src/math/roundf.c",
    musl_lib_dir_relative_path ++ "src/math/roundl.c",
    musl_lib_dir_relative_path ++ "src/math/scalb.c",
    musl_lib_dir_relative_path ++ "src/math/scalbf.c",
    musl_lib_dir_relative_path ++ "src/math/scalbln.c",
    musl_lib_dir_relative_path ++ "src/math/scalblnf.c",
    musl_lib_dir_relative_path ++ "src/math/scalblnl.c",
    musl_lib_dir_relative_path ++ "src/math/scalbn.c",
    musl_lib_dir_relative_path ++ "src/math/scalbnf.c",
    musl_lib_dir_relative_path ++ "src/math/scalbnl.c",
    musl_lib_dir_relative_path ++ "src/math/signgam.c",
    musl_lib_dir_relative_path ++ "src/math/significand.c",
    musl_lib_dir_relative_path ++ "src/math/significandf.c",
    musl_lib_dir_relative_path ++ "src/math/sin.c",
    musl_lib_dir_relative_path ++ "src/math/sincos.c",
    musl_lib_dir_relative_path ++ "src/math/sincosf.c",
    musl_lib_dir_relative_path ++ "src/math/sincosl.c",
    musl_lib_dir_relative_path ++ "src/math/sinf.c",
    musl_lib_dir_relative_path ++ "src/math/sinh.c",
    musl_lib_dir_relative_path ++ "src/math/sinhf.c",
    musl_lib_dir_relative_path ++ "src/math/sinhl.c",
    musl_lib_dir_relative_path ++ "src/math/sinl.c",
    musl_lib_dir_relative_path ++ "src/math/sqrt.c",
    musl_lib_dir_relative_path ++ "src/math/sqrt_data.c",
    musl_lib_dir_relative_path ++ "src/math/sqrtf.c",
    musl_lib_dir_relative_path ++ "src/math/sqrtl.c",
    musl_lib_dir_relative_path ++ "src/math/tan.c",
    musl_lib_dir_relative_path ++ "src/math/tanf.c",
    musl_lib_dir_relative_path ++ "src/math/tanh.c",
    musl_lib_dir_relative_path ++ "src/math/tanhf.c",
    musl_lib_dir_relative_path ++ "src/math/tanhl.c",
    musl_lib_dir_relative_path ++ "src/math/tanl.c",
    musl_lib_dir_relative_path ++ "src/math/tgamma.c",
    musl_lib_dir_relative_path ++ "src/math/tgammaf.c",
    musl_lib_dir_relative_path ++ "src/math/tgammal.c",
    musl_lib_dir_relative_path ++ "src/math/trunc.c",
    musl_lib_dir_relative_path ++ "src/math/truncf.c",
    musl_lib_dir_relative_path ++ "src/math/truncl.c",
    musl_lib_dir_relative_path ++ "src/misc/a64l.c",
    musl_lib_dir_relative_path ++ "src/misc/basename.c",
    musl_lib_dir_relative_path ++ "src/misc/dirname.c",
    musl_lib_dir_relative_path ++ "src/misc/ffs.c",
    musl_lib_dir_relative_path ++ "src/misc/ffsl.c",
    musl_lib_dir_relative_path ++ "src/misc/ffsll.c",
    musl_lib_dir_relative_path ++ "src/misc/fmtmsg.c",
    musl_lib_dir_relative_path ++ "src/misc/forkpty.c",
    musl_lib_dir_relative_path ++ "src/misc/get_current_dir_name.c",
    musl_lib_dir_relative_path ++ "src/misc/getauxval.c",
    musl_lib_dir_relative_path ++ "src/misc/getdomainname.c",
    musl_lib_dir_relative_path ++ "src/misc/getentropy.c",
    musl_lib_dir_relative_path ++ "src/misc/gethostid.c",
    musl_lib_dir_relative_path ++ "src/misc/getopt.c",
    musl_lib_dir_relative_path ++ "src/misc/getopt_long.c",
    musl_lib_dir_relative_path ++ "src/misc/getpriority.c",
    musl_lib_dir_relative_path ++ "src/misc/getresgid.c",
    musl_lib_dir_relative_path ++ "src/misc/getresuid.c",
    musl_lib_dir_relative_path ++ "src/misc/getrlimit.c",
    musl_lib_dir_relative_path ++ "src/misc/getrusage.c",
    musl_lib_dir_relative_path ++ "src/misc/getsubopt.c",
    musl_lib_dir_relative_path ++ "src/misc/initgroups.c",
    musl_lib_dir_relative_path ++ "src/misc/ioctl.c",
    musl_lib_dir_relative_path ++ "src/misc/issetugid.c",
    musl_lib_dir_relative_path ++ "src/misc/lockf.c",
    musl_lib_dir_relative_path ++ "src/misc/login_tty.c",
    musl_lib_dir_relative_path ++ "src/misc/mntent.c",
    musl_lib_dir_relative_path ++ "src/misc/nftw.c",
    musl_lib_dir_relative_path ++ "src/misc/openpty.c",
    musl_lib_dir_relative_path ++ "src/misc/ptsname.c",
    musl_lib_dir_relative_path ++ "src/misc/pty.c",
    musl_lib_dir_relative_path ++ "src/misc/realpath.c",
    musl_lib_dir_relative_path ++ "src/misc/setdomainname.c",
    musl_lib_dir_relative_path ++ "src/misc/setpriority.c",
    musl_lib_dir_relative_path ++ "src/misc/setrlimit.c",
    musl_lib_dir_relative_path ++ "src/misc/syscall.c",
    musl_lib_dir_relative_path ++ "src/misc/syslog.c",
    musl_lib_dir_relative_path ++ "src/misc/uname.c",
    musl_lib_dir_relative_path ++ "src/misc/wordexp.c",
    musl_lib_dir_relative_path ++ "src/mman/madvise.c",
    musl_lib_dir_relative_path ++ "src/mman/mincore.c",
    musl_lib_dir_relative_path ++ "src/mman/mlock.c",
    musl_lib_dir_relative_path ++ "src/mman/mlockall.c",
    musl_lib_dir_relative_path ++ "src/mman/mmap.c",
    musl_lib_dir_relative_path ++ "src/mman/mprotect.c",
    musl_lib_dir_relative_path ++ "src/mman/mremap.c",
    musl_lib_dir_relative_path ++ "src/mman/msync.c",
    musl_lib_dir_relative_path ++ "src/mman/munlock.c",
    musl_lib_dir_relative_path ++ "src/mman/munlockall.c",
    musl_lib_dir_relative_path ++ "src/mman/munmap.c",
    musl_lib_dir_relative_path ++ "src/mman/posix_madvise.c",
    musl_lib_dir_relative_path ++ "src/mman/shm_open.c",
    musl_lib_dir_relative_path ++ "src/mq/mq_close.c",
    musl_lib_dir_relative_path ++ "src/mq/mq_getattr.c",
    musl_lib_dir_relative_path ++ "src/mq/mq_notify.c",
    musl_lib_dir_relative_path ++ "src/mq/mq_open.c",
    musl_lib_dir_relative_path ++ "src/mq/mq_receive.c",
    musl_lib_dir_relative_path ++ "src/mq/mq_send.c",
    musl_lib_dir_relative_path ++ "src/mq/mq_setattr.c",
    musl_lib_dir_relative_path ++ "src/mq/mq_timedreceive.c",
    musl_lib_dir_relative_path ++ "src/mq/mq_timedsend.c",
    musl_lib_dir_relative_path ++ "src/mq/mq_unlink.c",
    musl_lib_dir_relative_path ++ "src/multibyte/btowc.c",
    musl_lib_dir_relative_path ++ "src/multibyte/c16rtomb.c",
    musl_lib_dir_relative_path ++ "src/multibyte/c32rtomb.c",
    musl_lib_dir_relative_path ++ "src/multibyte/internal.c",
    musl_lib_dir_relative_path ++ "src/multibyte/mblen.c",
    musl_lib_dir_relative_path ++ "src/multibyte/mbrlen.c",
    musl_lib_dir_relative_path ++ "src/multibyte/mbrtoc16.c",
    musl_lib_dir_relative_path ++ "src/multibyte/mbrtoc32.c",
    musl_lib_dir_relative_path ++ "src/multibyte/mbrtowc.c",
    musl_lib_dir_relative_path ++ "src/multibyte/mbsinit.c",
    musl_lib_dir_relative_path ++ "src/multibyte/mbsnrtowcs.c",
    musl_lib_dir_relative_path ++ "src/multibyte/mbsrtowcs.c",
    musl_lib_dir_relative_path ++ "src/multibyte/mbstowcs.c",
    musl_lib_dir_relative_path ++ "src/multibyte/mbtowc.c",
    musl_lib_dir_relative_path ++ "src/multibyte/wcrtomb.c",
    musl_lib_dir_relative_path ++ "src/multibyte/wcsnrtombs.c",
    musl_lib_dir_relative_path ++ "src/multibyte/wcsrtombs.c",
    musl_lib_dir_relative_path ++ "src/multibyte/wcstombs.c",
    musl_lib_dir_relative_path ++ "src/multibyte/wctob.c",
    musl_lib_dir_relative_path ++ "src/multibyte/wctomb.c",
    musl_lib_dir_relative_path ++ "src/network/accept.c",
    musl_lib_dir_relative_path ++ "src/network/accept4.c",
    musl_lib_dir_relative_path ++ "src/network/bind.c",
    musl_lib_dir_relative_path ++ "src/network/connect.c",
    musl_lib_dir_relative_path ++ "src/network/dn_comp.c",
    musl_lib_dir_relative_path ++ "src/network/dn_expand.c",
    musl_lib_dir_relative_path ++ "src/network/dn_skipname.c",
    musl_lib_dir_relative_path ++ "src/network/dns_parse.c",
    musl_lib_dir_relative_path ++ "src/network/ent.c",
    musl_lib_dir_relative_path ++ "src/network/ether.c",
    musl_lib_dir_relative_path ++ "src/network/freeaddrinfo.c",
    musl_lib_dir_relative_path ++ "src/network/gai_strerror.c",
    musl_lib_dir_relative_path ++ "src/network/getaddrinfo.c",
    musl_lib_dir_relative_path ++ "src/network/gethostbyaddr.c",
    musl_lib_dir_relative_path ++ "src/network/gethostbyaddr_r.c",
    musl_lib_dir_relative_path ++ "src/network/gethostbyname.c",
    musl_lib_dir_relative_path ++ "src/network/gethostbyname2.c",
    musl_lib_dir_relative_path ++ "src/network/gethostbyname2_r.c",
    musl_lib_dir_relative_path ++ "src/network/gethostbyname_r.c",
    musl_lib_dir_relative_path ++ "src/network/getifaddrs.c",
    musl_lib_dir_relative_path ++ "src/network/getnameinfo.c",
    musl_lib_dir_relative_path ++ "src/network/getpeername.c",
    musl_lib_dir_relative_path ++ "src/network/getservbyname.c",
    musl_lib_dir_relative_path ++ "src/network/getservbyname_r.c",
    musl_lib_dir_relative_path ++ "src/network/getservbyport.c",
    musl_lib_dir_relative_path ++ "src/network/getservbyport_r.c",
    musl_lib_dir_relative_path ++ "src/network/getsockname.c",
    musl_lib_dir_relative_path ++ "src/network/getsockopt.c",
    musl_lib_dir_relative_path ++ "src/network/h_errno.c",
    musl_lib_dir_relative_path ++ "src/network/herror.c",
    musl_lib_dir_relative_path ++ "src/network/hstrerror.c",
    musl_lib_dir_relative_path ++ "src/network/htonl.c",
    musl_lib_dir_relative_path ++ "src/network/htons.c",
    musl_lib_dir_relative_path ++ "src/network/if_freenameindex.c",
    musl_lib_dir_relative_path ++ "src/network/if_indextoname.c",
    musl_lib_dir_relative_path ++ "src/network/if_nameindex.c",
    musl_lib_dir_relative_path ++ "src/network/if_nametoindex.c",
    musl_lib_dir_relative_path ++ "src/network/in6addr_any.c",
    musl_lib_dir_relative_path ++ "src/network/in6addr_loopback.c",
    musl_lib_dir_relative_path ++ "src/network/inet_addr.c",
    musl_lib_dir_relative_path ++ "src/network/inet_aton.c",
    musl_lib_dir_relative_path ++ "src/network/inet_legacy.c",
    musl_lib_dir_relative_path ++ "src/network/inet_ntoa.c",
    musl_lib_dir_relative_path ++ "src/network/inet_ntop.c",
    musl_lib_dir_relative_path ++ "src/network/inet_pton.c",
    musl_lib_dir_relative_path ++ "src/network/listen.c",
    musl_lib_dir_relative_path ++ "src/network/lookup_ipliteral.c",
    musl_lib_dir_relative_path ++ "src/network/lookup_name.c",
    musl_lib_dir_relative_path ++ "src/network/lookup_serv.c",
    musl_lib_dir_relative_path ++ "src/network/netlink.c",
    musl_lib_dir_relative_path ++ "src/network/netname.c",
    musl_lib_dir_relative_path ++ "src/network/ns_parse.c",
    musl_lib_dir_relative_path ++ "src/network/ntohl.c",
    musl_lib_dir_relative_path ++ "src/network/ntohs.c",
    musl_lib_dir_relative_path ++ "src/network/proto.c",
    musl_lib_dir_relative_path ++ "src/network/recv.c",
    musl_lib_dir_relative_path ++ "src/network/recvfrom.c",
    musl_lib_dir_relative_path ++ "src/network/recvmmsg.c",
    musl_lib_dir_relative_path ++ "src/network/recvmsg.c",
    musl_lib_dir_relative_path ++ "src/network/res_init.c",
    musl_lib_dir_relative_path ++ "src/network/res_mkquery.c",
    musl_lib_dir_relative_path ++ "src/network/res_msend.c",
    musl_lib_dir_relative_path ++ "src/network/res_query.c",
    musl_lib_dir_relative_path ++ "src/network/res_querydomain.c",
    musl_lib_dir_relative_path ++ "src/network/res_send.c",
    musl_lib_dir_relative_path ++ "src/network/res_state.c",
    musl_lib_dir_relative_path ++ "src/network/resolvconf.c",
    musl_lib_dir_relative_path ++ "src/network/send.c",
    musl_lib_dir_relative_path ++ "src/network/sendmmsg.c",
    musl_lib_dir_relative_path ++ "src/network/sendmsg.c",
    musl_lib_dir_relative_path ++ "src/network/sendto.c",
    musl_lib_dir_relative_path ++ "src/network/serv.c",
    musl_lib_dir_relative_path ++ "src/network/setsockopt.c",
    musl_lib_dir_relative_path ++ "src/network/shutdown.c",
    musl_lib_dir_relative_path ++ "src/network/sockatmark.c",
    musl_lib_dir_relative_path ++ "src/network/socket.c",
    musl_lib_dir_relative_path ++ "src/network/socketpair.c",
    musl_lib_dir_relative_path ++ "src/passwd/fgetgrent.c",
    musl_lib_dir_relative_path ++ "src/passwd/fgetpwent.c",
    musl_lib_dir_relative_path ++ "src/passwd/fgetspent.c",
    musl_lib_dir_relative_path ++ "src/passwd/getgr_a.c",
    musl_lib_dir_relative_path ++ "src/passwd/getgr_r.c",
    musl_lib_dir_relative_path ++ "src/passwd/getgrent.c",
    musl_lib_dir_relative_path ++ "src/passwd/getgrent_a.c",
    musl_lib_dir_relative_path ++ "src/passwd/getgrouplist.c",
    musl_lib_dir_relative_path ++ "src/passwd/getpw_a.c",
    musl_lib_dir_relative_path ++ "src/passwd/getpw_r.c",
    musl_lib_dir_relative_path ++ "src/passwd/getpwent.c",
    musl_lib_dir_relative_path ++ "src/passwd/getpwent_a.c",
    musl_lib_dir_relative_path ++ "src/passwd/getspent.c",
    musl_lib_dir_relative_path ++ "src/passwd/getspnam.c",
    musl_lib_dir_relative_path ++ "src/passwd/getspnam_r.c",
    musl_lib_dir_relative_path ++ "src/passwd/lckpwdf.c",
    musl_lib_dir_relative_path ++ "src/passwd/nscd_query.c",
    musl_lib_dir_relative_path ++ "src/passwd/putgrent.c",
    musl_lib_dir_relative_path ++ "src/passwd/putpwent.c",
    musl_lib_dir_relative_path ++ "src/passwd/putspent.c",
    musl_lib_dir_relative_path ++ "src/prng/__rand48_step.c",
    musl_lib_dir_relative_path ++ "src/prng/__seed48.c",
    musl_lib_dir_relative_path ++ "src/prng/drand48.c",
    musl_lib_dir_relative_path ++ "src/prng/lcong48.c",
    musl_lib_dir_relative_path ++ "src/prng/lrand48.c",
    musl_lib_dir_relative_path ++ "src/prng/mrand48.c",
    musl_lib_dir_relative_path ++ "src/prng/rand.c",
    musl_lib_dir_relative_path ++ "src/prng/rand_r.c",
    musl_lib_dir_relative_path ++ "src/prng/random.c",
    musl_lib_dir_relative_path ++ "src/prng/seed48.c",
    musl_lib_dir_relative_path ++ "src/prng/srand48.c",
    musl_lib_dir_relative_path ++ "src/process/_Fork.c",
    musl_lib_dir_relative_path ++ "src/process/execl.c",
    musl_lib_dir_relative_path ++ "src/process/execle.c",
    musl_lib_dir_relative_path ++ "src/process/execlp.c",
    musl_lib_dir_relative_path ++ "src/process/execv.c",
    musl_lib_dir_relative_path ++ "src/process/execve.c",
    musl_lib_dir_relative_path ++ "src/process/execvp.c",
    musl_lib_dir_relative_path ++ "src/process/fexecve.c",
    musl_lib_dir_relative_path ++ "src/process/fork.c",
    musl_lib_dir_relative_path ++ "src/process/posix_spawn.c",
    musl_lib_dir_relative_path ++ "src/process/posix_spawn_file_actions_addchdir.c",
    musl_lib_dir_relative_path ++ "src/process/posix_spawn_file_actions_addclose.c",
    musl_lib_dir_relative_path ++ "src/process/posix_spawn_file_actions_adddup2.c",
    musl_lib_dir_relative_path ++ "src/process/posix_spawn_file_actions_addfchdir.c",
    musl_lib_dir_relative_path ++ "src/process/posix_spawn_file_actions_addopen.c",
    musl_lib_dir_relative_path ++ "src/process/posix_spawn_file_actions_destroy.c",
    musl_lib_dir_relative_path ++ "src/process/posix_spawn_file_actions_init.c",
    musl_lib_dir_relative_path ++ "src/process/posix_spawnattr_destroy.c",
    musl_lib_dir_relative_path ++ "src/process/posix_spawnattr_getflags.c",
    musl_lib_dir_relative_path ++ "src/process/posix_spawnattr_getpgroup.c",
    musl_lib_dir_relative_path ++ "src/process/posix_spawnattr_getsigdefault.c",
    musl_lib_dir_relative_path ++ "src/process/posix_spawnattr_getsigmask.c",
    musl_lib_dir_relative_path ++ "src/process/posix_spawnattr_init.c",
    musl_lib_dir_relative_path ++ "src/process/posix_spawnattr_sched.c",
    musl_lib_dir_relative_path ++ "src/process/posix_spawnattr_setflags.c",
    musl_lib_dir_relative_path ++ "src/process/posix_spawnattr_setpgroup.c",
    musl_lib_dir_relative_path ++ "src/process/posix_spawnattr_setsigdefault.c",
    musl_lib_dir_relative_path ++ "src/process/posix_spawnattr_setsigmask.c",
    musl_lib_dir_relative_path ++ "src/process/posix_spawnp.c",
    musl_lib_dir_relative_path ++ "src/regex/fnmatch.c",
    musl_lib_dir_relative_path ++ "src/regex/glob.c",
    musl_lib_dir_relative_path ++ "src/regex/regcomp.c",
    musl_lib_dir_relative_path ++ "src/regex/regerror.c",
    musl_lib_dir_relative_path ++ "src/regex/regexec.c",
    musl_lib_dir_relative_path ++ "src/regex/tre-mem.c",
    musl_lib_dir_relative_path ++ "src/sched/affinity.c",
    musl_lib_dir_relative_path ++ "src/sched/sched_cpucount.c",
    musl_lib_dir_relative_path ++ "src/sched/sched_get_priority_max.c",
    musl_lib_dir_relative_path ++ "src/sched/sched_getcpu.c",
    musl_lib_dir_relative_path ++ "src/sched/sched_getparam.c",
    musl_lib_dir_relative_path ++ "src/sched/sched_getscheduler.c",
    musl_lib_dir_relative_path ++ "src/sched/sched_rr_get_interval.c",
    musl_lib_dir_relative_path ++ "src/sched/sched_setparam.c",
    musl_lib_dir_relative_path ++ "src/sched/sched_setscheduler.c",
    musl_lib_dir_relative_path ++ "src/sched/sched_yield.c",
    musl_lib_dir_relative_path ++ "src/search/hsearch.c",
    musl_lib_dir_relative_path ++ "src/search/insque.c",
    musl_lib_dir_relative_path ++ "src/search/lsearch.c",
    musl_lib_dir_relative_path ++ "src/search/tdelete.c",
    musl_lib_dir_relative_path ++ "src/search/tdestroy.c",
    musl_lib_dir_relative_path ++ "src/search/tfind.c",
    musl_lib_dir_relative_path ++ "src/search/tsearch.c",
    musl_lib_dir_relative_path ++ "src/search/twalk.c",
    musl_lib_dir_relative_path ++ "src/select/poll.c",
    musl_lib_dir_relative_path ++ "src/select/pselect.c",
    musl_lib_dir_relative_path ++ "src/select/select.c",
    musl_lib_dir_relative_path ++ "src/setjmp/longjmp.c",
    musl_lib_dir_relative_path ++ "src/setjmp/setjmp.c",
    musl_lib_dir_relative_path ++ "src/signal/block.c",
    musl_lib_dir_relative_path ++ "src/signal/getitimer.c",
    musl_lib_dir_relative_path ++ "src/signal/kill.c",
    musl_lib_dir_relative_path ++ "src/signal/killpg.c",
    musl_lib_dir_relative_path ++ "src/signal/psiginfo.c",
    musl_lib_dir_relative_path ++ "src/signal/psignal.c",
    musl_lib_dir_relative_path ++ "src/signal/raise.c",
    musl_lib_dir_relative_path ++ "src/signal/restore.c",
    musl_lib_dir_relative_path ++ "src/signal/sigaction.c",
    musl_lib_dir_relative_path ++ "src/signal/sigaddset.c",
    musl_lib_dir_relative_path ++ "src/signal/sigaltstack.c",
    musl_lib_dir_relative_path ++ "src/signal/sigandset.c",
    musl_lib_dir_relative_path ++ "src/signal/sigdelset.c",
    musl_lib_dir_relative_path ++ "src/signal/sigemptyset.c",
    musl_lib_dir_relative_path ++ "src/signal/sigfillset.c",
    musl_lib_dir_relative_path ++ "src/signal/sighold.c",
    musl_lib_dir_relative_path ++ "src/signal/sigignore.c",
    musl_lib_dir_relative_path ++ "src/signal/siginterrupt.c",
    musl_lib_dir_relative_path ++ "src/signal/sigisemptyset.c",
    musl_lib_dir_relative_path ++ "src/signal/sigismember.c",
    musl_lib_dir_relative_path ++ "src/signal/siglongjmp.c",
    musl_lib_dir_relative_path ++ "src/signal/signal.c",
    musl_lib_dir_relative_path ++ "src/signal/sigorset.c",
    musl_lib_dir_relative_path ++ "src/signal/sigpause.c",
    musl_lib_dir_relative_path ++ "src/signal/sigpending.c",
    musl_lib_dir_relative_path ++ "src/signal/sigprocmask.c",
    musl_lib_dir_relative_path ++ "src/signal/sigqueue.c",
    musl_lib_dir_relative_path ++ "src/signal/sigrelse.c",
    musl_lib_dir_relative_path ++ "src/signal/sigrtmax.c",
    musl_lib_dir_relative_path ++ "src/signal/sigrtmin.c",
    musl_lib_dir_relative_path ++ "src/signal/sigset.c",
    musl_lib_dir_relative_path ++ "src/signal/sigsetjmp.c",
    musl_lib_dir_relative_path ++ "src/signal/sigsetjmp_tail.c",
    musl_lib_dir_relative_path ++ "src/signal/sigsuspend.c",
    musl_lib_dir_relative_path ++ "src/signal/sigtimedwait.c",
    musl_lib_dir_relative_path ++ "src/signal/sigwait.c",
    musl_lib_dir_relative_path ++ "src/signal/sigwaitinfo.c",
    musl_lib_dir_relative_path ++ "src/stat/__xstat.c",
    musl_lib_dir_relative_path ++ "src/stat/chmod.c",
    musl_lib_dir_relative_path ++ "src/stat/fchmod.c",
    musl_lib_dir_relative_path ++ "src/stat/fchmodat.c",
    musl_lib_dir_relative_path ++ "src/stat/fstat.c",
    musl_lib_dir_relative_path ++ "src/stat/fstatat.c",
    musl_lib_dir_relative_path ++ "src/stat/futimens.c",
    musl_lib_dir_relative_path ++ "src/stat/futimesat.c",
    musl_lib_dir_relative_path ++ "src/stat/lchmod.c",
    musl_lib_dir_relative_path ++ "src/stat/lstat.c",
    musl_lib_dir_relative_path ++ "src/stat/mkdir.c",
    musl_lib_dir_relative_path ++ "src/stat/mkdirat.c",
    musl_lib_dir_relative_path ++ "src/stat/mkfifo.c",
    musl_lib_dir_relative_path ++ "src/stat/mkfifoat.c",
    musl_lib_dir_relative_path ++ "src/stat/mknod.c",
    musl_lib_dir_relative_path ++ "src/stat/mknodat.c",
    musl_lib_dir_relative_path ++ "src/stat/stat.c",
    musl_lib_dir_relative_path ++ "src/stat/statvfs.c",
    musl_lib_dir_relative_path ++ "src/stat/umask.c",
    musl_lib_dir_relative_path ++ "src/stat/utimensat.c",
    musl_lib_dir_relative_path ++ "src/stdio/__fclose_ca.c",
    musl_lib_dir_relative_path ++ "src/stdio/__fdopen.c",
    musl_lib_dir_relative_path ++ "src/stdio/__fmodeflags.c",
    musl_lib_dir_relative_path ++ "src/stdio/__fopen_rb_ca.c",
    musl_lib_dir_relative_path ++ "src/stdio/__lockfile.c",
    musl_lib_dir_relative_path ++ "src/stdio/__overflow.c",
    musl_lib_dir_relative_path ++ "src/stdio/__stdio_close.c",
    musl_lib_dir_relative_path ++ "src/stdio/__stdio_exit.c",
    musl_lib_dir_relative_path ++ "src/stdio/__stdio_read.c",
    musl_lib_dir_relative_path ++ "src/stdio/__stdio_seek.c",
    musl_lib_dir_relative_path ++ "src/stdio/__stdio_write.c",
    musl_lib_dir_relative_path ++ "src/stdio/__stdout_write.c",
    musl_lib_dir_relative_path ++ "src/stdio/__toread.c",
    musl_lib_dir_relative_path ++ "src/stdio/__towrite.c",
    musl_lib_dir_relative_path ++ "src/stdio/__uflow.c",
    musl_lib_dir_relative_path ++ "src/stdio/asprintf.c",
    musl_lib_dir_relative_path ++ "src/stdio/clearerr.c",
    musl_lib_dir_relative_path ++ "src/stdio/dprintf.c",
    musl_lib_dir_relative_path ++ "src/stdio/ext.c",
    musl_lib_dir_relative_path ++ "src/stdio/ext2.c",
    musl_lib_dir_relative_path ++ "src/stdio/fclose.c",
    musl_lib_dir_relative_path ++ "src/stdio/feof.c",
    musl_lib_dir_relative_path ++ "src/stdio/ferror.c",
    musl_lib_dir_relative_path ++ "src/stdio/fflush.c",
    musl_lib_dir_relative_path ++ "src/stdio/fgetc.c",
    musl_lib_dir_relative_path ++ "src/stdio/fgetln.c",
    musl_lib_dir_relative_path ++ "src/stdio/fgetpos.c",
    musl_lib_dir_relative_path ++ "src/stdio/fgets.c",
    musl_lib_dir_relative_path ++ "src/stdio/fgetwc.c",
    musl_lib_dir_relative_path ++ "src/stdio/fgetws.c",
    musl_lib_dir_relative_path ++ "src/stdio/fileno.c",
    musl_lib_dir_relative_path ++ "src/stdio/flockfile.c",
    musl_lib_dir_relative_path ++ "src/stdio/fmemopen.c",
    musl_lib_dir_relative_path ++ "src/stdio/fopen.c",
    musl_lib_dir_relative_path ++ "src/stdio/fopencookie.c",
    musl_lib_dir_relative_path ++ "src/stdio/fprintf.c",
    musl_lib_dir_relative_path ++ "src/stdio/fputc.c",
    musl_lib_dir_relative_path ++ "src/stdio/fputs.c",
    musl_lib_dir_relative_path ++ "src/stdio/fputwc.c",
    musl_lib_dir_relative_path ++ "src/stdio/fputws.c",
    musl_lib_dir_relative_path ++ "src/stdio/fread.c",
    musl_lib_dir_relative_path ++ "src/stdio/freopen.c",
    musl_lib_dir_relative_path ++ "src/stdio/fscanf.c",
    musl_lib_dir_relative_path ++ "src/stdio/fseek.c",
    musl_lib_dir_relative_path ++ "src/stdio/fsetpos.c",
    musl_lib_dir_relative_path ++ "src/stdio/ftell.c",
    musl_lib_dir_relative_path ++ "src/stdio/ftrylockfile.c",
    musl_lib_dir_relative_path ++ "src/stdio/funlockfile.c",
    musl_lib_dir_relative_path ++ "src/stdio/fwide.c",
    musl_lib_dir_relative_path ++ "src/stdio/fwprintf.c",
    musl_lib_dir_relative_path ++ "src/stdio/fwrite.c",
    musl_lib_dir_relative_path ++ "src/stdio/fwscanf.c",
    musl_lib_dir_relative_path ++ "src/stdio/getc.c",
    musl_lib_dir_relative_path ++ "src/stdio/getc_unlocked.c",
    musl_lib_dir_relative_path ++ "src/stdio/getchar.c",
    musl_lib_dir_relative_path ++ "src/stdio/getchar_unlocked.c",
    musl_lib_dir_relative_path ++ "src/stdio/getdelim.c",
    musl_lib_dir_relative_path ++ "src/stdio/getline.c",
    musl_lib_dir_relative_path ++ "src/stdio/gets.c",
    musl_lib_dir_relative_path ++ "src/stdio/getw.c",
    musl_lib_dir_relative_path ++ "src/stdio/getwc.c",
    musl_lib_dir_relative_path ++ "src/stdio/getwchar.c",
    musl_lib_dir_relative_path ++ "src/stdio/ofl.c",
    musl_lib_dir_relative_path ++ "src/stdio/ofl_add.c",
    musl_lib_dir_relative_path ++ "src/stdio/open_memstream.c",
    musl_lib_dir_relative_path ++ "src/stdio/open_wmemstream.c",
    musl_lib_dir_relative_path ++ "src/stdio/pclose.c",
    musl_lib_dir_relative_path ++ "src/stdio/perror.c",
    musl_lib_dir_relative_path ++ "src/stdio/popen.c",
    musl_lib_dir_relative_path ++ "src/stdio/printf.c",
    musl_lib_dir_relative_path ++ "src/stdio/putc.c",
    musl_lib_dir_relative_path ++ "src/stdio/putc_unlocked.c",
    musl_lib_dir_relative_path ++ "src/stdio/putchar.c",
    musl_lib_dir_relative_path ++ "src/stdio/putchar_unlocked.c",
    musl_lib_dir_relative_path ++ "src/stdio/puts.c",
    musl_lib_dir_relative_path ++ "src/stdio/putw.c",
    musl_lib_dir_relative_path ++ "src/stdio/putwc.c",
    musl_lib_dir_relative_path ++ "src/stdio/putwchar.c",
    musl_lib_dir_relative_path ++ "src/stdio/remove.c",
    musl_lib_dir_relative_path ++ "src/stdio/rename.c",
    musl_lib_dir_relative_path ++ "src/stdio/rewind.c",
    musl_lib_dir_relative_path ++ "src/stdio/scanf.c",
    musl_lib_dir_relative_path ++ "src/stdio/setbuf.c",
    musl_lib_dir_relative_path ++ "src/stdio/setbuffer.c",
    musl_lib_dir_relative_path ++ "src/stdio/setlinebuf.c",
    musl_lib_dir_relative_path ++ "src/stdio/setvbuf.c",
    musl_lib_dir_relative_path ++ "src/stdio/snprintf.c",
    musl_lib_dir_relative_path ++ "src/stdio/sprintf.c",
    musl_lib_dir_relative_path ++ "src/stdio/sscanf.c",
    musl_lib_dir_relative_path ++ "src/stdio/stderr.c",
    musl_lib_dir_relative_path ++ "src/stdio/stdin.c",
    musl_lib_dir_relative_path ++ "src/stdio/stdout.c",
    musl_lib_dir_relative_path ++ "src/stdio/swprintf.c",
    musl_lib_dir_relative_path ++ "src/stdio/swscanf.c",
    musl_lib_dir_relative_path ++ "src/stdio/tempnam.c",
    musl_lib_dir_relative_path ++ "src/stdio/tmpfile.c",
    musl_lib_dir_relative_path ++ "src/stdio/tmpnam.c",
    musl_lib_dir_relative_path ++ "src/stdio/ungetc.c",
    musl_lib_dir_relative_path ++ "src/stdio/ungetwc.c",
    musl_lib_dir_relative_path ++ "src/stdio/vasprintf.c",
    musl_lib_dir_relative_path ++ "src/stdio/vdprintf.c",
    musl_lib_dir_relative_path ++ "src/stdio/vfprintf.c",
    musl_lib_dir_relative_path ++ "src/stdio/vfscanf.c",
    musl_lib_dir_relative_path ++ "src/stdio/vfwprintf.c",
    musl_lib_dir_relative_path ++ "src/stdio/vfwscanf.c",
    musl_lib_dir_relative_path ++ "src/stdio/vprintf.c",
    musl_lib_dir_relative_path ++ "src/stdio/vscanf.c",
    musl_lib_dir_relative_path ++ "src/stdio/vsnprintf.c",
    musl_lib_dir_relative_path ++ "src/stdio/vsprintf.c",
    musl_lib_dir_relative_path ++ "src/stdio/vsscanf.c",
    musl_lib_dir_relative_path ++ "src/stdio/vswprintf.c",
    musl_lib_dir_relative_path ++ "src/stdio/vswscanf.c",
    musl_lib_dir_relative_path ++ "src/stdio/vwprintf.c",
    musl_lib_dir_relative_path ++ "src/stdio/vwscanf.c",
    musl_lib_dir_relative_path ++ "src/stdio/wprintf.c",
    musl_lib_dir_relative_path ++ "src/stdio/wscanf.c",
    musl_lib_dir_relative_path ++ "src/stdlib/abs.c",
    musl_lib_dir_relative_path ++ "src/stdlib/atof.c",
    musl_lib_dir_relative_path ++ "src/stdlib/atoi.c",
    musl_lib_dir_relative_path ++ "src/stdlib/atol.c",
    musl_lib_dir_relative_path ++ "src/stdlib/atoll.c",
    musl_lib_dir_relative_path ++ "src/stdlib/bsearch.c",
    musl_lib_dir_relative_path ++ "src/stdlib/div.c",
    musl_lib_dir_relative_path ++ "src/stdlib/ecvt.c",
    musl_lib_dir_relative_path ++ "src/stdlib/fcvt.c",
    musl_lib_dir_relative_path ++ "src/stdlib/gcvt.c",
    musl_lib_dir_relative_path ++ "src/stdlib/imaxabs.c",
    musl_lib_dir_relative_path ++ "src/stdlib/imaxdiv.c",
    musl_lib_dir_relative_path ++ "src/stdlib/labs.c",
    musl_lib_dir_relative_path ++ "src/stdlib/ldiv.c",
    musl_lib_dir_relative_path ++ "src/stdlib/llabs.c",
    musl_lib_dir_relative_path ++ "src/stdlib/lldiv.c",
    musl_lib_dir_relative_path ++ "src/stdlib/qsort.c",
    musl_lib_dir_relative_path ++ "src/stdlib/qsort_nr.c",
    musl_lib_dir_relative_path ++ "src/stdlib/strtod.c",
    musl_lib_dir_relative_path ++ "src/stdlib/strtol.c",
    musl_lib_dir_relative_path ++ "src/stdlib/wcstod.c",
    musl_lib_dir_relative_path ++ "src/stdlib/wcstol.c",
    musl_lib_dir_relative_path ++ "src/string/bcmp.c",
    musl_lib_dir_relative_path ++ "src/string/bcopy.c",
    musl_lib_dir_relative_path ++ "src/string/bzero.c",
    musl_lib_dir_relative_path ++ "src/string/explicit_bzero.c",
    musl_lib_dir_relative_path ++ "src/string/index.c",
    musl_lib_dir_relative_path ++ "src/string/memccpy.c",
    musl_lib_dir_relative_path ++ "src/string/memchr.c",
    musl_lib_dir_relative_path ++ "src/string/memcmp.c",
    musl_lib_dir_relative_path ++ "src/string/memcpy.c",
    musl_lib_dir_relative_path ++ "src/string/memmem.c",
    musl_lib_dir_relative_path ++ "src/string/memmove.c",
    musl_lib_dir_relative_path ++ "src/string/mempcpy.c",
    musl_lib_dir_relative_path ++ "src/string/memrchr.c",
    musl_lib_dir_relative_path ++ "src/string/memset.c",
    musl_lib_dir_relative_path ++ "src/string/rindex.c",
    musl_lib_dir_relative_path ++ "src/string/stpcpy.c",
    musl_lib_dir_relative_path ++ "src/string/stpncpy.c",
    musl_lib_dir_relative_path ++ "src/string/strcasecmp.c",
    musl_lib_dir_relative_path ++ "src/string/strcasestr.c",
    musl_lib_dir_relative_path ++ "src/string/strcat.c",
    musl_lib_dir_relative_path ++ "src/string/strchr.c",
    musl_lib_dir_relative_path ++ "src/string/strchrnul.c",
    musl_lib_dir_relative_path ++ "src/string/strcmp.c",
    musl_lib_dir_relative_path ++ "src/string/strcpy.c",
    musl_lib_dir_relative_path ++ "src/string/strcspn.c",
    musl_lib_dir_relative_path ++ "src/string/strdup.c",
    musl_lib_dir_relative_path ++ "src/string/strerror_r.c",
    musl_lib_dir_relative_path ++ "src/string/strlcat.c",
    musl_lib_dir_relative_path ++ "src/string/strlcpy.c",
    musl_lib_dir_relative_path ++ "src/string/strlen.c",
    musl_lib_dir_relative_path ++ "src/string/strncasecmp.c",
    musl_lib_dir_relative_path ++ "src/string/strncat.c",
    musl_lib_dir_relative_path ++ "src/string/strncmp.c",
    musl_lib_dir_relative_path ++ "src/string/strncpy.c",
    musl_lib_dir_relative_path ++ "src/string/strndup.c",
    musl_lib_dir_relative_path ++ "src/string/strnlen.c",
    musl_lib_dir_relative_path ++ "src/string/strpbrk.c",
    musl_lib_dir_relative_path ++ "src/string/strrchr.c",
    musl_lib_dir_relative_path ++ "src/string/strsep.c",
    musl_lib_dir_relative_path ++ "src/string/strsignal.c",
    musl_lib_dir_relative_path ++ "src/string/strspn.c",
    musl_lib_dir_relative_path ++ "src/string/strstr.c",
    musl_lib_dir_relative_path ++ "src/string/strtok.c",
    musl_lib_dir_relative_path ++ "src/string/strtok_r.c",
    musl_lib_dir_relative_path ++ "src/string/strverscmp.c",
    musl_lib_dir_relative_path ++ "src/string/swab.c",
    musl_lib_dir_relative_path ++ "src/string/wcpcpy.c",
    musl_lib_dir_relative_path ++ "src/string/wcpncpy.c",
    musl_lib_dir_relative_path ++ "src/string/wcscasecmp.c",
    musl_lib_dir_relative_path ++ "src/string/wcscasecmp_l.c",
    musl_lib_dir_relative_path ++ "src/string/wcscat.c",
    musl_lib_dir_relative_path ++ "src/string/wcschr.c",
    musl_lib_dir_relative_path ++ "src/string/wcscmp.c",
    musl_lib_dir_relative_path ++ "src/string/wcscpy.c",
    musl_lib_dir_relative_path ++ "src/string/wcscspn.c",
    musl_lib_dir_relative_path ++ "src/string/wcsdup.c",
    musl_lib_dir_relative_path ++ "src/string/wcslen.c",
    musl_lib_dir_relative_path ++ "src/string/wcsncasecmp.c",
    musl_lib_dir_relative_path ++ "src/string/wcsncasecmp_l.c",
    musl_lib_dir_relative_path ++ "src/string/wcsncat.c",
    musl_lib_dir_relative_path ++ "src/string/wcsncmp.c",
    musl_lib_dir_relative_path ++ "src/string/wcsncpy.c",
    musl_lib_dir_relative_path ++ "src/string/wcsnlen.c",
    musl_lib_dir_relative_path ++ "src/string/wcspbrk.c",
    musl_lib_dir_relative_path ++ "src/string/wcsrchr.c",
    musl_lib_dir_relative_path ++ "src/string/wcsspn.c",
    musl_lib_dir_relative_path ++ "src/string/wcsstr.c",
    musl_lib_dir_relative_path ++ "src/string/wcstok.c",
    musl_lib_dir_relative_path ++ "src/string/wcswcs.c",
    musl_lib_dir_relative_path ++ "src/string/wmemchr.c",
    musl_lib_dir_relative_path ++ "src/string/wmemcmp.c",
    musl_lib_dir_relative_path ++ "src/string/wmemcpy.c",
    musl_lib_dir_relative_path ++ "src/string/wmemmove.c",
    musl_lib_dir_relative_path ++ "src/string/wmemset.c",
    musl_lib_dir_relative_path ++ "src/temp/__randname.c",
    musl_lib_dir_relative_path ++ "src/temp/mkdtemp.c",
    musl_lib_dir_relative_path ++ "src/temp/mkostemp.c",
    musl_lib_dir_relative_path ++ "src/temp/mkostemps.c",
    musl_lib_dir_relative_path ++ "src/temp/mkstemp.c",
    musl_lib_dir_relative_path ++ "src/temp/mkstemps.c",
    musl_lib_dir_relative_path ++ "src/temp/mktemp.c",
    musl_lib_dir_relative_path ++ "src/termios/cfgetospeed.c",
    musl_lib_dir_relative_path ++ "src/termios/cfmakeraw.c",
    musl_lib_dir_relative_path ++ "src/termios/cfsetospeed.c",
    musl_lib_dir_relative_path ++ "src/termios/tcdrain.c",
    musl_lib_dir_relative_path ++ "src/termios/tcflow.c",
    musl_lib_dir_relative_path ++ "src/termios/tcflush.c",
    musl_lib_dir_relative_path ++ "src/termios/tcgetattr.c",
    musl_lib_dir_relative_path ++ "src/termios/tcgetsid.c",
    musl_lib_dir_relative_path ++ "src/termios/tcgetwinsize.c",
    musl_lib_dir_relative_path ++ "src/termios/tcsendbreak.c",
    musl_lib_dir_relative_path ++ "src/termios/tcsetattr.c",
    musl_lib_dir_relative_path ++ "src/termios/tcsetwinsize.c",
    musl_lib_dir_relative_path ++ "src/thread/__lock.c",
    //musl_lib_dir_relative_path ++ "src/thread/__set_thread_area.c",
    musl_lib_dir_relative_path ++ "src/thread/__syscall_cp.c",
    musl_lib_dir_relative_path ++ "src/thread/__timedwait.c",
    musl_lib_dir_relative_path ++ "src/thread/__tls_get_addr.c",
    musl_lib_dir_relative_path ++ "src/thread/__unmapself.c",
    musl_lib_dir_relative_path ++ "src/thread/__wait.c",
    musl_lib_dir_relative_path ++ "src/thread/call_once.c",
    musl_lib_dir_relative_path ++ "src/thread/clone.c",
    musl_lib_dir_relative_path ++ "src/thread/cnd_broadcast.c",
    musl_lib_dir_relative_path ++ "src/thread/cnd_destroy.c",
    musl_lib_dir_relative_path ++ "src/thread/cnd_init.c",
    musl_lib_dir_relative_path ++ "src/thread/cnd_signal.c",
    musl_lib_dir_relative_path ++ "src/thread/cnd_timedwait.c",
    musl_lib_dir_relative_path ++ "src/thread/cnd_wait.c",
    musl_lib_dir_relative_path ++ "src/thread/default_attr.c",
    musl_lib_dir_relative_path ++ "src/thread/lock_ptc.c",
    musl_lib_dir_relative_path ++ "src/thread/mtx_destroy.c",
    musl_lib_dir_relative_path ++ "src/thread/mtx_init.c",
    musl_lib_dir_relative_path ++ "src/thread/mtx_lock.c",
    musl_lib_dir_relative_path ++ "src/thread/mtx_timedlock.c",
    musl_lib_dir_relative_path ++ "src/thread/mtx_trylock.c",
    musl_lib_dir_relative_path ++ "src/thread/mtx_unlock.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_atfork.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_attr_destroy.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_attr_get.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_attr_init.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_attr_setdetachstate.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_attr_setguardsize.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_attr_setinheritsched.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_attr_setschedparam.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_attr_setschedpolicy.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_attr_setscope.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_attr_setstack.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_attr_setstacksize.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_barrier_destroy.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_barrier_init.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_barrier_wait.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_barrierattr_destroy.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_barrierattr_init.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_barrierattr_setpshared.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_cancel.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_cleanup_push.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_cond_broadcast.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_cond_destroy.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_cond_init.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_cond_signal.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_cond_timedwait.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_cond_wait.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_condattr_destroy.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_condattr_init.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_condattr_setclock.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_condattr_setpshared.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_create.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_detach.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_equal.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_getattr_np.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_getconcurrency.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_getcpuclockid.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_getname_np.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_getschedparam.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_getspecific.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_join.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_key_create.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_kill.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_mutex_consistent.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_mutex_destroy.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_mutex_getprioceiling.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_mutex_init.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_mutex_lock.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_mutex_setprioceiling.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_mutex_timedlock.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_mutex_trylock.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_mutex_unlock.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_mutexattr_destroy.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_mutexattr_init.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_mutexattr_setprotocol.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_mutexattr_setpshared.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_mutexattr_setrobust.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_mutexattr_settype.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_once.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_rwlock_destroy.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_rwlock_init.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_rwlock_rdlock.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_rwlock_timedrdlock.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_rwlock_timedwrlock.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_rwlock_tryrdlock.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_rwlock_trywrlock.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_rwlock_unlock.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_rwlock_wrlock.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_rwlockattr_destroy.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_rwlockattr_init.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_rwlockattr_setpshared.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_self.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_setattr_default_np.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_setcancelstate.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_setcanceltype.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_setconcurrency.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_setname_np.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_setschedparam.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_setschedprio.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_setspecific.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_sigmask.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_spin_destroy.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_spin_init.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_spin_lock.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_spin_trylock.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_spin_unlock.c",
    musl_lib_dir_relative_path ++ "src/thread/pthread_testcancel.c",
    musl_lib_dir_relative_path ++ "src/thread/sem_destroy.c",
    musl_lib_dir_relative_path ++ "src/thread/sem_getvalue.c",
    musl_lib_dir_relative_path ++ "src/thread/sem_init.c",
    musl_lib_dir_relative_path ++ "src/thread/sem_open.c",
    musl_lib_dir_relative_path ++ "src/thread/sem_post.c",
    musl_lib_dir_relative_path ++ "src/thread/sem_timedwait.c",
    musl_lib_dir_relative_path ++ "src/thread/sem_trywait.c",
    musl_lib_dir_relative_path ++ "src/thread/sem_unlink.c",
    musl_lib_dir_relative_path ++ "src/thread/sem_wait.c",
    musl_lib_dir_relative_path ++ "src/thread/synccall.c",
    musl_lib_dir_relative_path ++ "src/thread/syscall_cp.c",
    musl_lib_dir_relative_path ++ "src/thread/thrd_create.c",
    musl_lib_dir_relative_path ++ "src/thread/thrd_exit.c",
    musl_lib_dir_relative_path ++ "src/thread/thrd_join.c",
    musl_lib_dir_relative_path ++ "src/thread/thrd_sleep.c",
    musl_lib_dir_relative_path ++ "src/thread/thrd_yield.c",
    musl_lib_dir_relative_path ++ "src/thread/tls.c",
    musl_lib_dir_relative_path ++ "src/thread/tss_create.c",
    musl_lib_dir_relative_path ++ "src/thread/tss_delete.c",
    musl_lib_dir_relative_path ++ "src/thread/tss_set.c",
    musl_lib_dir_relative_path ++ "src/thread/vmlock.c",
    musl_lib_dir_relative_path ++ "src/time/__map_file.c",
    musl_lib_dir_relative_path ++ "src/time/__month_to_secs.c",
    musl_lib_dir_relative_path ++ "src/time/__secs_to_tm.c",
    musl_lib_dir_relative_path ++ "src/time/__tm_to_secs.c",
    musl_lib_dir_relative_path ++ "src/time/__tz.c",
    musl_lib_dir_relative_path ++ "src/time/__year_to_secs.c",
    musl_lib_dir_relative_path ++ "src/time/asctime.c",
    musl_lib_dir_relative_path ++ "src/time/asctime_r.c",
    musl_lib_dir_relative_path ++ "src/time/clock.c",
    musl_lib_dir_relative_path ++ "src/time/clock_getcpuclockid.c",
    musl_lib_dir_relative_path ++ "src/time/clock_getres.c",
    musl_lib_dir_relative_path ++ "src/time/clock_gettime.c",
    musl_lib_dir_relative_path ++ "src/time/clock_nanosleep.c",
    musl_lib_dir_relative_path ++ "src/time/clock_settime.c",
    musl_lib_dir_relative_path ++ "src/time/ctime.c",
    musl_lib_dir_relative_path ++ "src/time/ctime_r.c",
    musl_lib_dir_relative_path ++ "src/time/difftime.c",
    musl_lib_dir_relative_path ++ "src/time/ftime.c",
    musl_lib_dir_relative_path ++ "src/time/getdate.c",
    musl_lib_dir_relative_path ++ "src/time/gettimeofday.c",
    musl_lib_dir_relative_path ++ "src/time/gmtime.c",
    musl_lib_dir_relative_path ++ "src/time/gmtime_r.c",
    musl_lib_dir_relative_path ++ "src/time/localtime.c",
    musl_lib_dir_relative_path ++ "src/time/localtime_r.c",
    musl_lib_dir_relative_path ++ "src/time/mktime.c",
    musl_lib_dir_relative_path ++ "src/time/nanosleep.c",
    musl_lib_dir_relative_path ++ "src/time/strftime.c",
    musl_lib_dir_relative_path ++ "src/time/strptime.c",
    musl_lib_dir_relative_path ++ "src/time/time.c",
    musl_lib_dir_relative_path ++ "src/time/timegm.c",
    musl_lib_dir_relative_path ++ "src/time/timer_create.c",
    musl_lib_dir_relative_path ++ "src/time/timer_delete.c",
    musl_lib_dir_relative_path ++ "src/time/timer_getoverrun.c",
    musl_lib_dir_relative_path ++ "src/time/timer_gettime.c",
    musl_lib_dir_relative_path ++ "src/time/timer_settime.c",
    musl_lib_dir_relative_path ++ "src/time/times.c",
    musl_lib_dir_relative_path ++ "src/time/timespec_get.c",
    musl_lib_dir_relative_path ++ "src/time/utime.c",
    musl_lib_dir_relative_path ++ "src/time/wcsftime.c",
    musl_lib_dir_relative_path ++ "src/unistd/_exit.c",
    musl_lib_dir_relative_path ++ "src/unistd/access.c",
    musl_lib_dir_relative_path ++ "src/unistd/acct.c",
    musl_lib_dir_relative_path ++ "src/unistd/alarm.c",
    musl_lib_dir_relative_path ++ "src/unistd/chdir.c",
    musl_lib_dir_relative_path ++ "src/unistd/chown.c",
    musl_lib_dir_relative_path ++ "src/unistd/close.c",
    musl_lib_dir_relative_path ++ "src/unistd/ctermid.c",
    musl_lib_dir_relative_path ++ "src/unistd/dup.c",
    musl_lib_dir_relative_path ++ "src/unistd/dup2.c",
    musl_lib_dir_relative_path ++ "src/unistd/dup3.c",
    musl_lib_dir_relative_path ++ "src/unistd/faccessat.c",
    musl_lib_dir_relative_path ++ "src/unistd/fchdir.c",
    musl_lib_dir_relative_path ++ "src/unistd/fchown.c",
    musl_lib_dir_relative_path ++ "src/unistd/fchownat.c",
    musl_lib_dir_relative_path ++ "src/unistd/fdatasync.c",
    musl_lib_dir_relative_path ++ "src/unistd/fsync.c",
    musl_lib_dir_relative_path ++ "src/unistd/ftruncate.c",
    musl_lib_dir_relative_path ++ "src/unistd/getcwd.c",
    musl_lib_dir_relative_path ++ "src/unistd/getegid.c",
    musl_lib_dir_relative_path ++ "src/unistd/geteuid.c",
    musl_lib_dir_relative_path ++ "src/unistd/getgid.c",
    musl_lib_dir_relative_path ++ "src/unistd/getgroups.c",
    musl_lib_dir_relative_path ++ "src/unistd/gethostname.c",
    musl_lib_dir_relative_path ++ "src/unistd/getlogin.c",
    musl_lib_dir_relative_path ++ "src/unistd/getlogin_r.c",
    musl_lib_dir_relative_path ++ "src/unistd/getpgid.c",
    musl_lib_dir_relative_path ++ "src/unistd/getpgrp.c",
    musl_lib_dir_relative_path ++ "src/unistd/getpid.c",
    musl_lib_dir_relative_path ++ "src/unistd/getppid.c",
    musl_lib_dir_relative_path ++ "src/unistd/getsid.c",
    musl_lib_dir_relative_path ++ "src/unistd/getuid.c",
    musl_lib_dir_relative_path ++ "src/unistd/isatty.c",
    musl_lib_dir_relative_path ++ "src/unistd/lchown.c",
    musl_lib_dir_relative_path ++ "src/unistd/link.c",
    musl_lib_dir_relative_path ++ "src/unistd/linkat.c",
    musl_lib_dir_relative_path ++ "src/unistd/lseek.c",
    musl_lib_dir_relative_path ++ "src/unistd/nice.c",
    musl_lib_dir_relative_path ++ "src/unistd/pause.c",
    musl_lib_dir_relative_path ++ "src/unistd/pipe.c",
    musl_lib_dir_relative_path ++ "src/unistd/pipe2.c",
    musl_lib_dir_relative_path ++ "src/unistd/posix_close.c",
    musl_lib_dir_relative_path ++ "src/unistd/pread.c",
    musl_lib_dir_relative_path ++ "src/unistd/preadv.c",
    musl_lib_dir_relative_path ++ "src/unistd/pwrite.c",
    musl_lib_dir_relative_path ++ "src/unistd/pwritev.c",
    musl_lib_dir_relative_path ++ "src/unistd/read.c",
    musl_lib_dir_relative_path ++ "src/unistd/readlink.c",
    musl_lib_dir_relative_path ++ "src/unistd/readlinkat.c",
    musl_lib_dir_relative_path ++ "src/unistd/readv.c",
    musl_lib_dir_relative_path ++ "src/unistd/renameat.c",
    musl_lib_dir_relative_path ++ "src/unistd/rmdir.c",
    musl_lib_dir_relative_path ++ "src/unistd/setegid.c",
    musl_lib_dir_relative_path ++ "src/unistd/seteuid.c",
    musl_lib_dir_relative_path ++ "src/unistd/setgid.c",
    musl_lib_dir_relative_path ++ "src/unistd/setpgid.c",
    musl_lib_dir_relative_path ++ "src/unistd/setpgrp.c",
    musl_lib_dir_relative_path ++ "src/unistd/setregid.c",
    musl_lib_dir_relative_path ++ "src/unistd/setresgid.c",
    musl_lib_dir_relative_path ++ "src/unistd/setresuid.c",
    musl_lib_dir_relative_path ++ "src/unistd/setreuid.c",
    musl_lib_dir_relative_path ++ "src/unistd/setsid.c",
    musl_lib_dir_relative_path ++ "src/unistd/setuid.c",
    musl_lib_dir_relative_path ++ "src/unistd/setxid.c",
    musl_lib_dir_relative_path ++ "src/unistd/sleep.c",
    musl_lib_dir_relative_path ++ "src/unistd/symlink.c",
    musl_lib_dir_relative_path ++ "src/unistd/symlinkat.c",
    musl_lib_dir_relative_path ++ "src/unistd/sync.c",
    musl_lib_dir_relative_path ++ "src/unistd/tcgetpgrp.c",
    musl_lib_dir_relative_path ++ "src/unistd/tcsetpgrp.c",
    musl_lib_dir_relative_path ++ "src/unistd/truncate.c",
    musl_lib_dir_relative_path ++ "src/unistd/ttyname.c",
    musl_lib_dir_relative_path ++ "src/unistd/ttyname_r.c",
    musl_lib_dir_relative_path ++ "src/unistd/ualarm.c",
    musl_lib_dir_relative_path ++ "src/unistd/unlink.c",
    musl_lib_dir_relative_path ++ "src/unistd/unlinkat.c",
    musl_lib_dir_relative_path ++ "src/unistd/usleep.c",
    musl_lib_dir_relative_path ++ "src/unistd/write.c",
    musl_lib_dir_relative_path ++ "src/unistd/writev.c",
};

const musl_x86_64_source_files = [_][]const u8{
    musl_lib_dir_relative_path ++ "src/fenv/x86_64/fenv.s",
    musl_lib_dir_relative_path ++ "src/ldso/x86_64/dlsym.s",
    musl_lib_dir_relative_path ++ "src/ldso/x86_64/tlsdesc.s",
    musl_lib_dir_relative_path ++ "src/math/x86_64/__invtrigl.s",
    musl_lib_dir_relative_path ++ "src/math/x86_64/acosl.s",
    musl_lib_dir_relative_path ++ "src/math/x86_64/asinl.s",
    musl_lib_dir_relative_path ++ "src/math/x86_64/atan2l.s",
    musl_lib_dir_relative_path ++ "src/math/x86_64/atanl.s",
    musl_lib_dir_relative_path ++ "src/math/x86_64/ceill.s",
    musl_lib_dir_relative_path ++ "src/math/x86_64/exp2l.s",
    musl_lib_dir_relative_path ++ "src/math/x86_64/expl.s",
    musl_lib_dir_relative_path ++ "src/math/x86_64/expm1l.s",
    musl_lib_dir_relative_path ++ "src/math/x86_64/fabs.c",
    musl_lib_dir_relative_path ++ "src/math/x86_64/fabsf.c",
    musl_lib_dir_relative_path ++ "src/math/x86_64/fabsl.c",
    musl_lib_dir_relative_path ++ "src/math/x86_64/floorl.s",
    musl_lib_dir_relative_path ++ "src/math/x86_64/fma.c",
    musl_lib_dir_relative_path ++ "src/math/x86_64/fmaf.c",
    musl_lib_dir_relative_path ++ "src/math/x86_64/fmodl.c",
    musl_lib_dir_relative_path ++ "src/math/x86_64/llrint.c",
    musl_lib_dir_relative_path ++ "src/math/x86_64/llrintf.c",
    musl_lib_dir_relative_path ++ "src/math/x86_64/llrintl.c",
    musl_lib_dir_relative_path ++ "src/math/x86_64/log10l.s",
    musl_lib_dir_relative_path ++ "src/math/x86_64/log1pl.s",
    musl_lib_dir_relative_path ++ "src/math/x86_64/log2l.s",
    musl_lib_dir_relative_path ++ "src/math/x86_64/logl.s",
    musl_lib_dir_relative_path ++ "src/math/x86_64/lrint.c",
    musl_lib_dir_relative_path ++ "src/math/x86_64/lrintf.c",
    musl_lib_dir_relative_path ++ "src/math/x86_64/lrintl.c",
    musl_lib_dir_relative_path ++ "src/math/x86_64/remainderl.c",
    musl_lib_dir_relative_path ++ "src/math/x86_64/remquol.c",
    musl_lib_dir_relative_path ++ "src/math/x86_64/rintl.c",
    musl_lib_dir_relative_path ++ "src/math/x86_64/sqrt.c",
    musl_lib_dir_relative_path ++ "src/math/x86_64/sqrtf.c",
    musl_lib_dir_relative_path ++ "src/math/x86_64/sqrtl.c",
    musl_lib_dir_relative_path ++ "src/math/x86_64/truncl.s",
    musl_lib_dir_relative_path ++ "src/process/x86_64/vfork.s",
    musl_lib_dir_relative_path ++ "src/setjmp/x86_64/longjmp.s",
    musl_lib_dir_relative_path ++ "src/setjmp/x86_64/setjmp.s",
    musl_lib_dir_relative_path ++ "src/signal/x86_64/restore.s",
    musl_lib_dir_relative_path ++ "src/signal/x86_64/sigsetjmp.s",
    musl_lib_dir_relative_path ++ "src/string/x86_64/memcpy.s",
    musl_lib_dir_relative_path ++ "src/string/x86_64/memmove.s",
    musl_lib_dir_relative_path ++ "src/string/x86_64/memset.s",
    musl_lib_dir_relative_path ++ "src/thread/x86_64/__set_thread_area.s",
    musl_lib_dir_relative_path ++ "src/thread/x86_64/__unmapself.s",
    musl_lib_dir_relative_path ++ "src/thread/x86_64/clone.s",
    musl_lib_dir_relative_path ++ "src/thread/x86_64/syscall_cp.s",
};

const musl_arch_files = [_][]const u8{
    musl_lib_dir_relative_path ++ "src/fenv/aarch64/fenv.s",
    musl_lib_dir_relative_path ++ "src/fenv/arm/fenv-hf.S",
    musl_lib_dir_relative_path ++ "src/fenv/arm/fenv.c",
    musl_lib_dir_relative_path ++ "src/fenv/i386/fenv.s",
    musl_lib_dir_relative_path ++ "src/fenv/m68k/fenv.c",
    musl_lib_dir_relative_path ++ "src/fenv/mips/fenv-sf.c",
    musl_lib_dir_relative_path ++ "src/fenv/mips/fenv.S",
    musl_lib_dir_relative_path ++ "src/fenv/mips64/fenv-sf.c",
    musl_lib_dir_relative_path ++ "src/fenv/mips64/fenv.S",
    musl_lib_dir_relative_path ++ "src/fenv/mipsn32/fenv-sf.c",
    musl_lib_dir_relative_path ++ "src/fenv/mipsn32/fenv.S",
    musl_lib_dir_relative_path ++ "src/fenv/powerpc/fenv-sf.c",
    musl_lib_dir_relative_path ++ "src/fenv/powerpc/fenv.S",
    musl_lib_dir_relative_path ++ "src/fenv/powerpc64/fenv.c",
    musl_lib_dir_relative_path ++ "src/fenv/riscv64/fenv-sf.c",
    musl_lib_dir_relative_path ++ "src/fenv/riscv64/fenv.S",
    musl_lib_dir_relative_path ++ "src/fenv/s390x/fenv.c",
    musl_lib_dir_relative_path ++ "src/fenv/sh/fenv-nofpu.c",
    musl_lib_dir_relative_path ++ "src/fenv/sh/fenv.S",
    musl_lib_dir_relative_path ++ "src/fenv/x32/fenv.s",
    musl_lib_dir_relative_path ++ "src/internal/i386/defsysinfo.s",
    musl_lib_dir_relative_path ++ "src/internal/sh/__shcall.c",
    musl_lib_dir_relative_path ++ "src/ldso/aarch64/dlsym.s",
    musl_lib_dir_relative_path ++ "src/ldso/aarch64/tlsdesc.s",
    musl_lib_dir_relative_path ++ "src/ldso/arm/dlsym.s",
    musl_lib_dir_relative_path ++ "src/ldso/arm/dlsym_time64.S",
    musl_lib_dir_relative_path ++ "src/ldso/arm/find_exidx.c",
    musl_lib_dir_relative_path ++ "src/ldso/arm/tlsdesc.S",
    musl_lib_dir_relative_path ++ "src/ldso/i386/dlsym.s",
    musl_lib_dir_relative_path ++ "src/ldso/i386/dlsym_time64.S",
    musl_lib_dir_relative_path ++ "src/ldso/i386/tlsdesc.s",
    musl_lib_dir_relative_path ++ "src/ldso/m68k/dlsym.s",
    musl_lib_dir_relative_path ++ "src/ldso/m68k/dlsym_time64.S",
    musl_lib_dir_relative_path ++ "src/ldso/microblaze/dlsym.s",
    musl_lib_dir_relative_path ++ "src/ldso/microblaze/dlsym_time64.S",
    musl_lib_dir_relative_path ++ "src/ldso/mips/dlsym.s",
    musl_lib_dir_relative_path ++ "src/ldso/mips/dlsym_time64.S",
    musl_lib_dir_relative_path ++ "src/ldso/mips64/dlsym.s",
    musl_lib_dir_relative_path ++ "src/ldso/mipsn32/dlsym.s",
    musl_lib_dir_relative_path ++ "src/ldso/mipsn32/dlsym_time64.S",
    musl_lib_dir_relative_path ++ "src/ldso/or1k/dlsym.s",
    musl_lib_dir_relative_path ++ "src/ldso/or1k/dlsym_time64.S",
    musl_lib_dir_relative_path ++ "src/ldso/powerpc/dlsym.s",
    musl_lib_dir_relative_path ++ "src/ldso/powerpc/dlsym_time64.S",
    musl_lib_dir_relative_path ++ "src/ldso/powerpc64/dlsym.s",
    musl_lib_dir_relative_path ++ "src/ldso/riscv64/dlsym.s",
    musl_lib_dir_relative_path ++ "src/ldso/s390x/dlsym.s",
    musl_lib_dir_relative_path ++ "src/ldso/sh/dlsym.s",
    musl_lib_dir_relative_path ++ "src/ldso/sh/dlsym_time64.S",
    musl_lib_dir_relative_path ++ "src/ldso/tlsdesc.c",
    musl_lib_dir_relative_path ++ "src/ldso/x32/dlsym.s",
    musl_lib_dir_relative_path ++ "src/linux/x32/sysinfo.c",
    musl_lib_dir_relative_path ++ "src/math/aarch64/ceil.c",
    musl_lib_dir_relative_path ++ "src/math/aarch64/ceilf.c",
    musl_lib_dir_relative_path ++ "src/math/aarch64/fabs.c",
    musl_lib_dir_relative_path ++ "src/math/aarch64/fabsf.c",
    musl_lib_dir_relative_path ++ "src/math/aarch64/floor.c",
    musl_lib_dir_relative_path ++ "src/math/aarch64/floorf.c",
    musl_lib_dir_relative_path ++ "src/math/aarch64/fma.c",
    musl_lib_dir_relative_path ++ "src/math/aarch64/fmaf.c",
    musl_lib_dir_relative_path ++ "src/math/aarch64/fmax.c",
    musl_lib_dir_relative_path ++ "src/math/aarch64/fmaxf.c",
    musl_lib_dir_relative_path ++ "src/math/aarch64/fmin.c",
    musl_lib_dir_relative_path ++ "src/math/aarch64/fminf.c",
    musl_lib_dir_relative_path ++ "src/math/aarch64/llrint.c",
    musl_lib_dir_relative_path ++ "src/math/aarch64/llrintf.c",
    musl_lib_dir_relative_path ++ "src/math/aarch64/llround.c",
    musl_lib_dir_relative_path ++ "src/math/aarch64/llroundf.c",
    musl_lib_dir_relative_path ++ "src/math/aarch64/lrint.c",
    musl_lib_dir_relative_path ++ "src/math/aarch64/lrintf.c",
    musl_lib_dir_relative_path ++ "src/math/aarch64/lround.c",
    musl_lib_dir_relative_path ++ "src/math/aarch64/lroundf.c",
    musl_lib_dir_relative_path ++ "src/math/aarch64/nearbyint.c",
    musl_lib_dir_relative_path ++ "src/math/aarch64/nearbyintf.c",
    musl_lib_dir_relative_path ++ "src/math/aarch64/rint.c",
    musl_lib_dir_relative_path ++ "src/math/aarch64/rintf.c",
    musl_lib_dir_relative_path ++ "src/math/aarch64/round.c",
    musl_lib_dir_relative_path ++ "src/math/aarch64/roundf.c",
    musl_lib_dir_relative_path ++ "src/math/aarch64/sqrt.c",
    musl_lib_dir_relative_path ++ "src/math/aarch64/sqrtf.c",
    musl_lib_dir_relative_path ++ "src/math/aarch64/trunc.c",
    musl_lib_dir_relative_path ++ "src/math/aarch64/truncf.c",
    musl_lib_dir_relative_path ++ "src/math/arm/fabs.c",
    musl_lib_dir_relative_path ++ "src/math/arm/fabsf.c",
    musl_lib_dir_relative_path ++ "src/math/arm/fma.c",
    musl_lib_dir_relative_path ++ "src/math/arm/fmaf.c",
    musl_lib_dir_relative_path ++ "src/math/arm/sqrt.c",
    musl_lib_dir_relative_path ++ "src/math/arm/sqrtf.c",
    musl_lib_dir_relative_path ++ "src/math/i386/__invtrigl.s",
    musl_lib_dir_relative_path ++ "src/math/i386/acos.s",
    musl_lib_dir_relative_path ++ "src/math/i386/acosf.s",
    musl_lib_dir_relative_path ++ "src/math/i386/acosl.s",
    musl_lib_dir_relative_path ++ "src/math/i386/asin.s",
    musl_lib_dir_relative_path ++ "src/math/i386/asinf.s",
    musl_lib_dir_relative_path ++ "src/math/i386/asinl.s",
    musl_lib_dir_relative_path ++ "src/math/i386/atan.s",
    musl_lib_dir_relative_path ++ "src/math/i386/atan2.s",
    musl_lib_dir_relative_path ++ "src/math/i386/atan2f.s",
    musl_lib_dir_relative_path ++ "src/math/i386/atan2l.s",
    musl_lib_dir_relative_path ++ "src/math/i386/atanf.s",
    musl_lib_dir_relative_path ++ "src/math/i386/atanl.s",
    musl_lib_dir_relative_path ++ "src/math/i386/ceil.s",
    musl_lib_dir_relative_path ++ "src/math/i386/ceilf.s",
    musl_lib_dir_relative_path ++ "src/math/i386/ceill.s",
    musl_lib_dir_relative_path ++ "src/math/i386/exp2l.s",
    musl_lib_dir_relative_path ++ "src/math/i386/exp_ld.s",
    musl_lib_dir_relative_path ++ "src/math/i386/expl.s",
    musl_lib_dir_relative_path ++ "src/math/i386/expm1l.s",
    musl_lib_dir_relative_path ++ "src/math/i386/fabs.c",
    musl_lib_dir_relative_path ++ "src/math/i386/fabsf.c",
    musl_lib_dir_relative_path ++ "src/math/i386/fabsl.c",
    musl_lib_dir_relative_path ++ "src/math/i386/floor.s",
    musl_lib_dir_relative_path ++ "src/math/i386/floorf.s",
    musl_lib_dir_relative_path ++ "src/math/i386/floorl.s",
    musl_lib_dir_relative_path ++ "src/math/i386/fmod.c",
    musl_lib_dir_relative_path ++ "src/math/i386/fmodf.c",
    musl_lib_dir_relative_path ++ "src/math/i386/fmodl.c",
    musl_lib_dir_relative_path ++ "src/math/i386/hypot.s",
    musl_lib_dir_relative_path ++ "src/math/i386/hypotf.s",
    musl_lib_dir_relative_path ++ "src/math/i386/ldexp.s",
    musl_lib_dir_relative_path ++ "src/math/i386/ldexpf.s",
    musl_lib_dir_relative_path ++ "src/math/i386/ldexpl.s",
    musl_lib_dir_relative_path ++ "src/math/i386/llrint.c",
    musl_lib_dir_relative_path ++ "src/math/i386/llrintf.c",
    musl_lib_dir_relative_path ++ "src/math/i386/llrintl.c",
    musl_lib_dir_relative_path ++ "src/math/i386/log.s",
    musl_lib_dir_relative_path ++ "src/math/i386/log10.s",
    musl_lib_dir_relative_path ++ "src/math/i386/log10f.s",
    musl_lib_dir_relative_path ++ "src/math/i386/log10l.s",
    musl_lib_dir_relative_path ++ "src/math/i386/log1p.s",
    musl_lib_dir_relative_path ++ "src/math/i386/log1pf.s",
    musl_lib_dir_relative_path ++ "src/math/i386/log1pl.s",
    musl_lib_dir_relative_path ++ "src/math/i386/log2.s",
    musl_lib_dir_relative_path ++ "src/math/i386/log2f.s",
    musl_lib_dir_relative_path ++ "src/math/i386/log2l.s",
    musl_lib_dir_relative_path ++ "src/math/i386/logf.s",
    musl_lib_dir_relative_path ++ "src/math/i386/logl.s",
    musl_lib_dir_relative_path ++ "src/math/i386/lrint.c",
    musl_lib_dir_relative_path ++ "src/math/i386/lrintf.c",
    musl_lib_dir_relative_path ++ "src/math/i386/lrintl.c",
    musl_lib_dir_relative_path ++ "src/math/i386/remainder.c",
    musl_lib_dir_relative_path ++ "src/math/i386/remainderf.c",
    musl_lib_dir_relative_path ++ "src/math/i386/remainderl.c",
    musl_lib_dir_relative_path ++ "src/math/i386/remquo.s",
    musl_lib_dir_relative_path ++ "src/math/i386/remquof.s",
    musl_lib_dir_relative_path ++ "src/math/i386/remquol.s",
    musl_lib_dir_relative_path ++ "src/math/i386/rint.c",
    musl_lib_dir_relative_path ++ "src/math/i386/rintf.c",
    musl_lib_dir_relative_path ++ "src/math/i386/rintl.c",
    musl_lib_dir_relative_path ++ "src/math/i386/scalbln.s",
    musl_lib_dir_relative_path ++ "src/math/i386/scalblnf.s",
    musl_lib_dir_relative_path ++ "src/math/i386/scalblnl.s",
    musl_lib_dir_relative_path ++ "src/math/i386/scalbn.s",
    musl_lib_dir_relative_path ++ "src/math/i386/scalbnf.s",
    musl_lib_dir_relative_path ++ "src/math/i386/scalbnl.s",
    musl_lib_dir_relative_path ++ "src/math/i386/sqrt.c",
    musl_lib_dir_relative_path ++ "src/math/i386/sqrtf.c",
    musl_lib_dir_relative_path ++ "src/math/i386/sqrtl.c",
    musl_lib_dir_relative_path ++ "src/math/i386/trunc.s",
    musl_lib_dir_relative_path ++ "src/math/i386/truncf.s",
    musl_lib_dir_relative_path ++ "src/math/i386/truncl.s",
    musl_lib_dir_relative_path ++ "src/math/m68k/sqrtl.c",
    musl_lib_dir_relative_path ++ "src/math/mips/fabs.c",
    musl_lib_dir_relative_path ++ "src/math/mips/fabsf.c",
    musl_lib_dir_relative_path ++ "src/math/mips/sqrt.c",
    musl_lib_dir_relative_path ++ "src/math/mips/sqrtf.c",
    musl_lib_dir_relative_path ++ "src/math/powerpc/fabs.c",
    musl_lib_dir_relative_path ++ "src/math/powerpc/fabsf.c",
    musl_lib_dir_relative_path ++ "src/math/powerpc/fma.c",
    musl_lib_dir_relative_path ++ "src/math/powerpc/fmaf.c",
    musl_lib_dir_relative_path ++ "src/math/powerpc/sqrt.c",
    musl_lib_dir_relative_path ++ "src/math/powerpc/sqrtf.c",
    musl_lib_dir_relative_path ++ "src/math/powerpc64/ceil.c",
    musl_lib_dir_relative_path ++ "src/math/powerpc64/ceilf.c",
    musl_lib_dir_relative_path ++ "src/math/powerpc64/fabs.c",
    musl_lib_dir_relative_path ++ "src/math/powerpc64/fabsf.c",
    musl_lib_dir_relative_path ++ "src/math/powerpc64/floor.c",
    musl_lib_dir_relative_path ++ "src/math/powerpc64/floorf.c",
    musl_lib_dir_relative_path ++ "src/math/powerpc64/fma.c",
    musl_lib_dir_relative_path ++ "src/math/powerpc64/fmaf.c",
    musl_lib_dir_relative_path ++ "src/math/powerpc64/fmax.c",
    musl_lib_dir_relative_path ++ "src/math/powerpc64/fmaxf.c",
    musl_lib_dir_relative_path ++ "src/math/powerpc64/fmin.c",
    musl_lib_dir_relative_path ++ "src/math/powerpc64/fminf.c",
    musl_lib_dir_relative_path ++ "src/math/powerpc64/lrint.c",
    musl_lib_dir_relative_path ++ "src/math/powerpc64/lrintf.c",
    musl_lib_dir_relative_path ++ "src/math/powerpc64/lround.c",
    musl_lib_dir_relative_path ++ "src/math/powerpc64/lroundf.c",
    musl_lib_dir_relative_path ++ "src/math/powerpc64/round.c",
    musl_lib_dir_relative_path ++ "src/math/powerpc64/roundf.c",
    musl_lib_dir_relative_path ++ "src/math/powerpc64/sqrt.c",
    musl_lib_dir_relative_path ++ "src/math/powerpc64/sqrtf.c",
    musl_lib_dir_relative_path ++ "src/math/powerpc64/trunc.c",
    musl_lib_dir_relative_path ++ "src/math/powerpc64/truncf.c",
    musl_lib_dir_relative_path ++ "src/math/riscv64/copysign.c",
    musl_lib_dir_relative_path ++ "src/math/riscv64/copysignf.c",
    musl_lib_dir_relative_path ++ "src/math/riscv64/fabs.c",
    musl_lib_dir_relative_path ++ "src/math/riscv64/fabsf.c",
    musl_lib_dir_relative_path ++ "src/math/riscv64/fma.c",
    musl_lib_dir_relative_path ++ "src/math/riscv64/fmaf.c",
    musl_lib_dir_relative_path ++ "src/math/riscv64/fmax.c",
    musl_lib_dir_relative_path ++ "src/math/riscv64/fmaxf.c",
    musl_lib_dir_relative_path ++ "src/math/riscv64/fmin.c",
    musl_lib_dir_relative_path ++ "src/math/riscv64/fminf.c",
    musl_lib_dir_relative_path ++ "src/math/riscv64/sqrt.c",
    musl_lib_dir_relative_path ++ "src/math/riscv64/sqrtf.c",
    musl_lib_dir_relative_path ++ "src/math/s390x/ceil.c",
    musl_lib_dir_relative_path ++ "src/math/s390x/ceilf.c",
    musl_lib_dir_relative_path ++ "src/math/s390x/ceill.c",
    musl_lib_dir_relative_path ++ "src/math/s390x/fabs.c",
    musl_lib_dir_relative_path ++ "src/math/s390x/fabsf.c",
    musl_lib_dir_relative_path ++ "src/math/s390x/fabsl.c",
    musl_lib_dir_relative_path ++ "src/math/s390x/floor.c",
    musl_lib_dir_relative_path ++ "src/math/s390x/floorf.c",
    musl_lib_dir_relative_path ++ "src/math/s390x/floorl.c",
    musl_lib_dir_relative_path ++ "src/math/s390x/fma.c",
    musl_lib_dir_relative_path ++ "src/math/s390x/fmaf.c",
    musl_lib_dir_relative_path ++ "src/math/s390x/nearbyint.c",
    musl_lib_dir_relative_path ++ "src/math/s390x/nearbyintf.c",
    musl_lib_dir_relative_path ++ "src/math/s390x/nearbyintl.c",
    musl_lib_dir_relative_path ++ "src/math/s390x/rint.c",
    musl_lib_dir_relative_path ++ "src/math/s390x/rintf.c",
    musl_lib_dir_relative_path ++ "src/math/s390x/rintl.c",
    musl_lib_dir_relative_path ++ "src/math/s390x/round.c",
    musl_lib_dir_relative_path ++ "src/math/s390x/roundf.c",
    musl_lib_dir_relative_path ++ "src/math/s390x/roundl.c",
    musl_lib_dir_relative_path ++ "src/math/s390x/sqrt.c",
    musl_lib_dir_relative_path ++ "src/math/s390x/sqrtf.c",
    musl_lib_dir_relative_path ++ "src/math/s390x/sqrtl.c",
    musl_lib_dir_relative_path ++ "src/math/s390x/trunc.c",
    musl_lib_dir_relative_path ++ "src/math/s390x/truncf.c",
    musl_lib_dir_relative_path ++ "src/math/s390x/truncl.c",
    musl_lib_dir_relative_path ++ "src/math/x32/__invtrigl.s",
    musl_lib_dir_relative_path ++ "src/math/x32/acosl.s",
    musl_lib_dir_relative_path ++ "src/math/x32/asinl.s",
    musl_lib_dir_relative_path ++ "src/math/x32/atan2l.s",
    musl_lib_dir_relative_path ++ "src/math/x32/atanl.s",
    musl_lib_dir_relative_path ++ "src/math/x32/ceill.s",
    musl_lib_dir_relative_path ++ "src/math/x32/exp2l.s",
    musl_lib_dir_relative_path ++ "src/math/x32/expl.s",
    musl_lib_dir_relative_path ++ "src/math/x32/expm1l.s",
    musl_lib_dir_relative_path ++ "src/math/x32/fabs.s",
    musl_lib_dir_relative_path ++ "src/math/x32/fabsf.s",
    musl_lib_dir_relative_path ++ "src/math/x32/fabsl.s",
    musl_lib_dir_relative_path ++ "src/math/x32/floorl.s",
    musl_lib_dir_relative_path ++ "src/math/x32/fma.c",
    musl_lib_dir_relative_path ++ "src/math/x32/fmaf.c",
    musl_lib_dir_relative_path ++ "src/math/x32/fmodl.s",
    musl_lib_dir_relative_path ++ "src/math/x32/llrint.s",
    musl_lib_dir_relative_path ++ "src/math/x32/llrintf.s",
    musl_lib_dir_relative_path ++ "src/math/x32/llrintl.s",
    musl_lib_dir_relative_path ++ "src/math/x32/log10l.s",
    musl_lib_dir_relative_path ++ "src/math/x32/log1pl.s",
    musl_lib_dir_relative_path ++ "src/math/x32/log2l.s",
    musl_lib_dir_relative_path ++ "src/math/x32/logl.s",
    musl_lib_dir_relative_path ++ "src/math/x32/lrint.s",
    musl_lib_dir_relative_path ++ "src/math/x32/lrintf.s",
    musl_lib_dir_relative_path ++ "src/math/x32/lrintl.s",
    musl_lib_dir_relative_path ++ "src/math/x32/remainderl.s",
    musl_lib_dir_relative_path ++ "src/math/x32/rintl.s",
    musl_lib_dir_relative_path ++ "src/math/x32/sqrt.s",
    musl_lib_dir_relative_path ++ "src/math/x32/sqrtf.s",
    musl_lib_dir_relative_path ++ "src/math/x32/sqrtl.s",
    musl_lib_dir_relative_path ++ "src/math/x32/truncl.s",
    musl_lib_dir_relative_path ++ "src/process/aarch64/vfork.s",
    musl_lib_dir_relative_path ++ "src/process/arm/vfork.s",
    musl_lib_dir_relative_path ++ "src/process/i386/vfork.s",
    musl_lib_dir_relative_path ++ "src/process/riscv64/vfork.s",
    musl_lib_dir_relative_path ++ "src/process/s390x/vfork.s",
    musl_lib_dir_relative_path ++ "src/process/sh/vfork.s",
    musl_lib_dir_relative_path ++ "src/process/system.c",
    musl_lib_dir_relative_path ++ "src/process/vfork.c",
    musl_lib_dir_relative_path ++ "src/process/wait.c",
    musl_lib_dir_relative_path ++ "src/process/waitid.c",
    musl_lib_dir_relative_path ++ "src/process/waitpid.c",
    musl_lib_dir_relative_path ++ "src/process/x32/vfork.s",
    musl_lib_dir_relative_path ++ "src/setjmp/aarch64/longjmp.s",
    musl_lib_dir_relative_path ++ "src/setjmp/aarch64/setjmp.s",
    musl_lib_dir_relative_path ++ "src/setjmp/arm/longjmp.S",
    musl_lib_dir_relative_path ++ "src/setjmp/arm/setjmp.S",
    musl_lib_dir_relative_path ++ "src/setjmp/i386/longjmp.s",
    musl_lib_dir_relative_path ++ "src/setjmp/i386/setjmp.s",
    musl_lib_dir_relative_path ++ "src/setjmp/m68k/longjmp.s",
    musl_lib_dir_relative_path ++ "src/setjmp/m68k/setjmp.s",
    musl_lib_dir_relative_path ++ "src/setjmp/microblaze/longjmp.s",
    musl_lib_dir_relative_path ++ "src/setjmp/microblaze/setjmp.s",
    musl_lib_dir_relative_path ++ "src/setjmp/mips/longjmp.S",
    musl_lib_dir_relative_path ++ "src/setjmp/mips/setjmp.S",
    musl_lib_dir_relative_path ++ "src/setjmp/mips64/longjmp.S",
    musl_lib_dir_relative_path ++ "src/setjmp/mips64/setjmp.S",
    musl_lib_dir_relative_path ++ "src/setjmp/mipsn32/longjmp.S",
    musl_lib_dir_relative_path ++ "src/setjmp/mipsn32/setjmp.S",
    musl_lib_dir_relative_path ++ "src/setjmp/or1k/longjmp.s",
    musl_lib_dir_relative_path ++ "src/setjmp/or1k/setjmp.s",
    musl_lib_dir_relative_path ++ "src/setjmp/powerpc/longjmp.S",
    musl_lib_dir_relative_path ++ "src/setjmp/powerpc/setjmp.S",
    musl_lib_dir_relative_path ++ "src/setjmp/powerpc64/longjmp.s",
    musl_lib_dir_relative_path ++ "src/setjmp/powerpc64/setjmp.s",
    musl_lib_dir_relative_path ++ "src/setjmp/riscv64/longjmp.S",
    musl_lib_dir_relative_path ++ "src/setjmp/riscv64/setjmp.S",
    musl_lib_dir_relative_path ++ "src/setjmp/s390x/longjmp.s",
    musl_lib_dir_relative_path ++ "src/setjmp/s390x/setjmp.s",
    musl_lib_dir_relative_path ++ "src/setjmp/sh/longjmp.S",
    musl_lib_dir_relative_path ++ "src/setjmp/sh/setjmp.S",
    musl_lib_dir_relative_path ++ "src/setjmp/x32/longjmp.s",
    musl_lib_dir_relative_path ++ "src/setjmp/x32/setjmp.s",
    musl_lib_dir_relative_path ++ "src/signal/aarch64/restore.s",
    musl_lib_dir_relative_path ++ "src/signal/aarch64/sigsetjmp.s",
    musl_lib_dir_relative_path ++ "src/signal/arm/restore.s",
    musl_lib_dir_relative_path ++ "src/signal/arm/sigsetjmp.s",
    musl_lib_dir_relative_path ++ "src/signal/i386/restore.s",
    musl_lib_dir_relative_path ++ "src/signal/i386/sigsetjmp.s",
    musl_lib_dir_relative_path ++ "src/signal/m68k/sigsetjmp.s",
    musl_lib_dir_relative_path ++ "src/signal/microblaze/restore.s",
    musl_lib_dir_relative_path ++ "src/signal/microblaze/sigsetjmp.s",
    musl_lib_dir_relative_path ++ "src/signal/mips/sigsetjmp.s",
    musl_lib_dir_relative_path ++ "src/signal/mips64/sigsetjmp.s",
    musl_lib_dir_relative_path ++ "src/signal/mipsn32/sigsetjmp.s",
    musl_lib_dir_relative_path ++ "src/signal/or1k/sigsetjmp.s",
    musl_lib_dir_relative_path ++ "src/signal/powerpc/restore.s",
    musl_lib_dir_relative_path ++ "src/signal/powerpc/sigsetjmp.s",
    musl_lib_dir_relative_path ++ "src/signal/powerpc64/restore.s",
    musl_lib_dir_relative_path ++ "src/signal/powerpc64/sigsetjmp.s",
    musl_lib_dir_relative_path ++ "src/signal/riscv64/restore.s",
    musl_lib_dir_relative_path ++ "src/signal/riscv64/sigsetjmp.s",
    musl_lib_dir_relative_path ++ "src/signal/s390x/restore.s",
    musl_lib_dir_relative_path ++ "src/signal/s390x/sigsetjmp.s",
    musl_lib_dir_relative_path ++ "src/signal/setitimer.c",
    musl_lib_dir_relative_path ++ "src/signal/sh/restore.s",
    musl_lib_dir_relative_path ++ "src/signal/sh/sigsetjmp.s",
    musl_lib_dir_relative_path ++ "src/signal/x32/getitimer.c",
    musl_lib_dir_relative_path ++ "src/signal/x32/restore.s",
    musl_lib_dir_relative_path ++ "src/signal/x32/setitimer.c",
    musl_lib_dir_relative_path ++ "src/signal/x32/sigsetjmp.s",
    musl_lib_dir_relative_path ++ "src/string/aarch64/memcpy.S",
    musl_lib_dir_relative_path ++ "src/string/aarch64/memset.S",
    musl_lib_dir_relative_path ++ "src/string/arm/__aeabi_memcpy.s",
    musl_lib_dir_relative_path ++ "src/string/arm/__aeabi_memset.s",
    musl_lib_dir_relative_path ++ "src/string/arm/memcpy.S",
    musl_lib_dir_relative_path ++ "src/string/i386/memcpy.s",
    musl_lib_dir_relative_path ++ "src/string/i386/memmove.s",
    musl_lib_dir_relative_path ++ "src/string/i386/memset.s",
    musl_lib_dir_relative_path ++ "src/thread/aarch64/__set_thread_area.s",
    musl_lib_dir_relative_path ++ "src/thread/aarch64/__unmapself.s",
    musl_lib_dir_relative_path ++ "src/thread/aarch64/clone.s",
    musl_lib_dir_relative_path ++ "src/thread/aarch64/syscall_cp.s",
    musl_lib_dir_relative_path ++ "src/thread/arm/__aeabi_read_tp.s",
    musl_lib_dir_relative_path ++ "src/thread/arm/__set_thread_area.c",
    musl_lib_dir_relative_path ++ "src/thread/arm/__unmapself.s",
    musl_lib_dir_relative_path ++ "src/thread/arm/atomics.s",
    musl_lib_dir_relative_path ++ "src/thread/arm/clone.s",
    musl_lib_dir_relative_path ++ "src/thread/arm/syscall_cp.s",
    musl_lib_dir_relative_path ++ "src/thread/i386/__set_thread_area.s",
    musl_lib_dir_relative_path ++ "src/thread/i386/__unmapself.s",
    musl_lib_dir_relative_path ++ "src/thread/i386/clone.s",
    musl_lib_dir_relative_path ++ "src/thread/i386/syscall_cp.s",
    musl_lib_dir_relative_path ++ "src/thread/i386/tls.s",
    musl_lib_dir_relative_path ++ "src/thread/m68k/__m68k_read_tp.s",
    musl_lib_dir_relative_path ++ "src/thread/m68k/clone.s",
    musl_lib_dir_relative_path ++ "src/thread/m68k/syscall_cp.s",
    musl_lib_dir_relative_path ++ "src/thread/microblaze/__set_thread_area.s",
    musl_lib_dir_relative_path ++ "src/thread/microblaze/__unmapself.s",
    musl_lib_dir_relative_path ++ "src/thread/microblaze/clone.s",
    musl_lib_dir_relative_path ++ "src/thread/microblaze/syscall_cp.s",
    musl_lib_dir_relative_path ++ "src/thread/mips/__unmapself.s",
    musl_lib_dir_relative_path ++ "src/thread/mips/clone.s",
    musl_lib_dir_relative_path ++ "src/thread/mips/syscall_cp.s",
    musl_lib_dir_relative_path ++ "src/thread/mips64/__unmapself.s",
    musl_lib_dir_relative_path ++ "src/thread/mips64/clone.s",
    musl_lib_dir_relative_path ++ "src/thread/mips64/syscall_cp.s",
    musl_lib_dir_relative_path ++ "src/thread/mipsn32/__unmapself.s",
    musl_lib_dir_relative_path ++ "src/thread/mipsn32/clone.s",
    musl_lib_dir_relative_path ++ "src/thread/mipsn32/syscall_cp.s",
    musl_lib_dir_relative_path ++ "src/thread/or1k/__set_thread_area.s",
    musl_lib_dir_relative_path ++ "src/thread/or1k/__unmapself.s",
    musl_lib_dir_relative_path ++ "src/thread/or1k/clone.s",
    musl_lib_dir_relative_path ++ "src/thread/or1k/syscall_cp.s",
    musl_lib_dir_relative_path ++ "src/thread/powerpc/__set_thread_area.s",
    musl_lib_dir_relative_path ++ "src/thread/powerpc/__unmapself.s",
    musl_lib_dir_relative_path ++ "src/thread/powerpc/clone.s",
    musl_lib_dir_relative_path ++ "src/thread/powerpc/syscall_cp.s",
    musl_lib_dir_relative_path ++ "src/thread/powerpc64/__set_thread_area.s",
    musl_lib_dir_relative_path ++ "src/thread/powerpc64/__unmapself.s",
    musl_lib_dir_relative_path ++ "src/thread/powerpc64/clone.s",
    musl_lib_dir_relative_path ++ "src/thread/powerpc64/syscall_cp.s",
    musl_lib_dir_relative_path ++ "src/thread/riscv64/__set_thread_area.s",
    musl_lib_dir_relative_path ++ "src/thread/riscv64/__unmapself.s",
    musl_lib_dir_relative_path ++ "src/thread/riscv64/clone.s",
    musl_lib_dir_relative_path ++ "src/thread/riscv64/syscall_cp.s",
    musl_lib_dir_relative_path ++ "src/thread/s390x/__set_thread_area.s",
    musl_lib_dir_relative_path ++ "src/thread/s390x/__tls_get_offset.s",
    musl_lib_dir_relative_path ++ "src/thread/s390x/__unmapself.s",
    musl_lib_dir_relative_path ++ "src/thread/s390x/clone.s",
    musl_lib_dir_relative_path ++ "src/thread/s390x/syscall_cp.s",
    musl_lib_dir_relative_path ++ "src/thread/sh/__set_thread_area.c",
    musl_lib_dir_relative_path ++ "src/thread/sh/__unmapself.c",
    musl_lib_dir_relative_path ++ "src/thread/sh/__unmapself_mmu.s",
    musl_lib_dir_relative_path ++ "src/thread/sh/atomics.s",
    musl_lib_dir_relative_path ++ "src/thread/sh/clone.s",
    musl_lib_dir_relative_path ++ "src/thread/sh/syscall_cp.s",
    musl_lib_dir_relative_path ++ "src/thread/x32/__set_thread_area.s",
    musl_lib_dir_relative_path ++ "src/thread/x32/__unmapself.s",
    musl_lib_dir_relative_path ++ "src/thread/x32/clone.s",
    musl_lib_dir_relative_path ++ "src/thread/x32/syscall_cp.s",
    musl_lib_dir_relative_path ++ "src/unistd/mips/pipe.s",
    musl_lib_dir_relative_path ++ "src/unistd/mips64/pipe.s",
    musl_lib_dir_relative_path ++ "src/unistd/mipsn32/lseek.c",
    musl_lib_dir_relative_path ++ "src/unistd/mipsn32/pipe.s",
    musl_lib_dir_relative_path ++ "src/unistd/sh/pipe.s",
    musl_lib_dir_relative_path ++ "src/unistd/x32/lseek.c",
};

pub fn argsCopyZ(alloc: Allocator, args: []const []const u8) ![:null]?[*:0]u8 {
    var argv = try alloc.allocSentinel(?[*:0]u8, args.len, null);
    for (args, 0..) |arg, i| {
        argv[i] = try alloc.dupeZ(u8, arg); // TODO If there was an argsAllocZ we could avoid this allocation.
    }
    return argv;
}

extern "c" fn NativityLLVMArchiverMain(argc: c_int, argv: [*:null]?[*:0]u8) c_int;
fn arMain(allocator: Allocator, arguments: []const []const u8) !u8 {
    const argv = try argsCopyZ(allocator, arguments);
    const exit_code = NativityLLVMArchiverMain(@as(c_int, @intCast(arguments.len)), argv.ptr);
    return @as(u8, @bitCast(@as(i8, @truncate(exit_code))));
}

extern "c" fn NativityClangMain(argc: c_int, argv: [*:null]?[*:0]u8) c_int;
pub fn clangMain(allocator: Allocator, arguments: []const []const u8) !u8 {
    const argv = try argsCopyZ(allocator, arguments);
    const exit_code = NativityClangMain(@as(c_int, @intCast(arguments.len)), argv.ptr);
    return @as(u8, @bitCast(@as(i8, @truncate(exit_code))));
}

const ExecutableOptions = struct {
    is_test: bool,
};

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

pub fn buildExecutable(context: *const Context, arguments: []const []const u8, options: ExecutableOptions) !void {
    var maybe_executable_path: ?[]const u8 = null;
    var maybe_main_package_path: ?[]const u8 = null;

    // TODO: make these mutable
    const arch: Arch = switch (@import("builtin").cpu.arch) {
        .aarch64 => .aarch64,
        .x86_64 => .x86_64,
        else => unreachable,
    };
    const os: Os = switch (@import("builtin").os.tag) {
        .linux => .linux,
        .macos => .macos,
        .windows => .windows,
        else => unreachable,
    };
    const abi: Abi = switch (@import("builtin").os.tag) {
        .linux => .gnu,
        .macos => .none,
        .windows => .gnu,
        else => unreachable,
    };

    var maybe_only_parse: ?bool = null;
    var link_libc = false;
    var maybe_executable_name: ?[]const u8 = null;
    var c_source_files = BoundedArray([]const u8, 4096){};
    var optimization = Optimization.none;
    var generate_debug_information = true;

    if (arguments.len == 0) return error.InvalidInput;

    var i: usize = 0;
    while (i < arguments.len) : (i += 1) {
        const current_argument = arguments[i];
        if (byte_equal(current_argument, "-o")) {
            if (i + 1 != arguments.len) {
                maybe_executable_path = arguments[i + 1];
                assert(maybe_executable_path.?.len != 0);
                i += 1;
            } else {
                reportUnterminatedArgumentError(current_argument);
            }
        } else if (byte_equal(current_argument, "-target")) {
            if (i + 1 != arguments.len) {
                // target_triplet = span(arguments[i + 1]);
                i += 1;
                unreachable;
            } else {
                reportUnterminatedArgumentError(current_argument);
            }
        } else if (byte_equal(current_argument, "-log")) {
            if (i + 1 != arguments.len) {
                i += 1;

                // var log_argument_iterator = std.mem.splitScalar(u8, span(arguments[i]), ',');
                //
                // while (log_argument_iterator.next()) |log_argument| {
                //     var log_argument_splitter = std.mem.splitScalar(u8, log_argument, '.');
                //     const log_scope_candidate = log_argument_splitter.next() orelse unreachable;
                //     var recognized_scope = false;
                //
                //     inline for (@typeInfo(LoggerScope).Enum.fields) |logger_scope_enum_field| {
                //         const log_scope = @field(LoggerScope, logger_scope_enum_field.name);
                //
                //         if (byte_equal(@tagName(log_scope), log_scope_candidate)) {
                //             const LogScope = getLoggerScopeType(log_scope);
                //
                //             if (log_argument_splitter.next()) |particular_log_candidate| {
                //                 var recognized_particular = false;
                //                 inline for (@typeInfo(LogScope.Logger).Enum.fields) |particular_log_field| {
                //                     const particular_log = @field(LogScope.Logger, particular_log_field.name);
                //
                //                     if (byte_equal(particular_log_candidate, @tagName(particular_log))) {
                //                         LogScope.Logger.bitset.setPresent(particular_log, true);
                //                         recognized_particular = true;
                //                     }
                //                 } else if (!recognized_particular) @panic("Unrecognized particular log"); //std.debug.panic("Unrecognized particular log \"{s}\" in scope {s}", .{ particular_log_candidate, @tagName(log_scope) });
                //             } else {
                //                 // LogScope.Logger.bitset = @TypeOf(LogScope.Logger.bitset).initFull();
                //             }
                //
                //             logger_bitset.setPresent(log_scope, true);
                //
                //             recognized_scope = true;
                //         }
                //     } else if (!recognized_scope) @panic("Unrecognized particular log"); //std.debug.panic("Unrecognized log scope: {s}", .{log_scope_candidate});
                // }
            } else {
                reportUnterminatedArgumentError(current_argument);
            }
        } else if (byte_equal(current_argument, "-parse")) {
            if (i + 1 != arguments.len) {
                i += 1;

                const arg = arguments[i];
                maybe_main_package_path = arg;
                maybe_only_parse = true;
            } else {
                reportUnterminatedArgumentError(current_argument);
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
                reportUnterminatedArgumentError(current_argument);
            }
        } else if (byte_equal(current_argument, "-main_source_file")) {
            if (i + 1 != arguments.len) {
                i += 1;

                const arg = arguments[i];
                maybe_main_package_path = arg;
            } else {
                reportUnterminatedArgumentError(current_argument);
            }
        } else if (byte_equal(current_argument, "-name")) {
            if (i + 1 != arguments.len) {
                i += 1;

                const arg = arguments[i];
                maybe_executable_name = arg;
            } else {
                reportUnterminatedArgumentError(current_argument);
            }
        } else if (byte_equal(current_argument, "-c_source_files")) {
            if (i + 1 != arguments.len) {
                i += 1;

                c_source_files.appendSliceAssumeCapacity(arguments[i..]);
                i = arguments.len;
            } else {
                reportUnterminatedArgumentError(current_argument);
            }
        } else if (byte_equal(current_argument, "-optimize")) {
            if (i + 1 != arguments.len) {
                i += 1;

                const optimize_string = arguments[i];
                optimization = enumFromString(Optimization, optimize_string) orelse unreachable;
            } else {
                reportUnterminatedArgumentError(current_argument);
            }
        } else if (byte_equal(current_argument, "-debug")) {
            if (i + 1 != arguments.len) {
                i += 1;

                const debug_string = arguments[i];
                generate_debug_information = if (byte_equal(debug_string, "true")) true else if (byte_equal(debug_string, "false")) false else unreachable;
            } else {
                reportUnterminatedArgumentError(current_argument);
            }
        } else {
            @panic(current_argument);
            // std.debug.panic("Unrecognized argument: {s}", .{current_argument});
        }
    }

    const only_parse = maybe_only_parse orelse false;

    const main_package_path = if (maybe_main_package_path) |path| blk: {
        const file = std.fs.cwd().openFile(path, .{}) catch return error.main_source_file_not_found;
        file.close();

        break :blk path;
    } else unreachable;

    const executable_name = if (maybe_executable_name) |name| name else std.fs.path.basename(main_package_path[0 .. main_package_path.len - "/main.nat".len]);

    const executable_path = maybe_executable_path orelse blk: {
        assert(executable_name.len > 0);
        const result = try std.mem.concat(context.allocator, u8, &.{ "nat/", executable_name });
        break :blk result;
    };

    const object_file_path = blk: {
        const slice = try context.allocator.alloc(u8, executable_path.len + 2);
        @memcpy(slice[0..executable_path.len], executable_path);
        slice[executable_path.len] = '.';
        slice[executable_path.len + 1] = 'o';
        break :blk slice;
    };

    const unit = try createUnit(context, .{
        .main_package_path = main_package_path,
        .object_path = object_file_path,
        .executable_path = executable_path,
        .only_parse = only_parse,
        .arch = arch,
        .os = os,
        .abi = abi,
        .optimization = optimization,
        .link_libc = link_libc,
        .generate_debug_information = generate_debug_information,
        .name = executable_name,
        .is_test = options.is_test,
        .c_source_files = c_source_files.slice(),
    });

    try unit.compile(context);
}

fn createUnit(context: *const Context, arguments: struct {
    main_package_path: []const u8,
    executable_path: []const u8,
    object_path: []const u8,
    only_parse: bool,
    arch: Arch,
    os: Os,
    abi: Abi,
    optimization: Optimization,
    link_libc: bool,
    generate_debug_information: bool,
    name: []const u8,
    is_test: bool,
    c_source_files: []const []const u8,
}) !*Unit {
    const unit = try context.allocator.create(Unit);
    unit.* = .{
        .descriptor = .{
            .main_package_path = arguments.main_package_path,
            .executable_path = arguments.executable_path,
            .object_path = arguments.object_path,
            .only_parse = arguments.only_parse,
            .arch = arguments.arch,
            .os = arguments.os,
            .abi = arguments.abi,
            .optimization = arguments.optimization,
            .link_libc = switch (arguments.os) {
                .linux => arguments.link_libc,
                .macos => true,
                .windows => arguments.link_libc,
                // .windows => link_libc,
                // else => unreachable,
            },
            .link_libcpp = false,
            .generate_debug_information = arguments.generate_debug_information,
            .name = arguments.name,
            .is_test = arguments.is_test,
            .c_source_files = arguments.c_source_files,
        },
        .token_buffer = Token.Buffer{
            .tokens = try PinnedArray(Token).init_with_default_granularity(),
            .line_offsets = try PinnedArray(u32).init_with_default_granularity(),
        },
        // pinned hashmaps
        .file_token_offsets = try PinnedHashMap(Token.Range, Debug.File.Index).init(std.mem.page_size),
        .file_map = try PinnedHashMap([]const u8, Debug.File.Index).init(std.mem.page_size),
        .identifiers = try PinnedHashMap(u32, []const u8).init(std.mem.page_size),
        .string_literal_values = try PinnedHashMap(u32, [:0]const u8).init(std.mem.page_size),
        .string_literal_globals = try PinnedHashMap(u32, *Debug.Declaration.Global).init(std.mem.page_size),
        .optionals = try PinnedHashMap(Type.Index, Type.Index).init(std.mem.page_size),
        .pointers = try PinnedHashMap(Type.Pointer, Type.Index).init(std.mem.page_size),
        .slices = try PinnedHashMap(Type.Slice, Type.Index).init(std.mem.page_size),
        .arrays = try PinnedHashMap(Type.Array, Type.Index).init(std.mem.page_size),
        .integers = try PinnedHashMap(Type.Integer, Type.Index).init(std.mem.page_size),
        .error_unions = try PinnedHashMap(Type.Error.Union.Descriptor, Type.Index).init(std.mem.page_size),
        .two_structs = try PinnedHashMap([2]Type.Index, Type.Index).init(std.mem.page_size),
        .fields_array = try PinnedHashMap(Type.Index, *Debug.Declaration.Global).init(std.mem.page_size),
        .name_functions = try PinnedHashMap(Type.Index, *Debug.Declaration.Global).init(std.mem.page_size),
        .external_functions = try PinnedHashMap(Type.Index, *Debug.Declaration.Global).init(std.mem.page_size),
        .type_declarations = try PinnedHashMap(Type.Index, *Debug.Declaration.Global).init(std.mem.page_size),
        .test_functions = try PinnedHashMap(*Debug.Declaration.Global, *Debug.Declaration.Global).init(std.mem.page_size),
        .code_to_emit = try PinnedHashMap(Function.Definition.Index, *Debug.Declaration.Global).init(std.mem.page_size),
        // special pinned arrays
        .types = try Type.List.init_with_default_granularity(),
        // pinned arrays
        .node_buffer = try PinnedArray(Node).init_with_default_granularity(),
        .node_lists = try PinnedArray([]const Node.Index).init_with_default_granularity(),
        .data_to_emit = try PinnedArray(*Debug.Declaration.Global).init_with_default_granularity(),
        .files = try PinnedArray(Debug.File).init_with_default_granularity(),
        .structs = try PinnedArray(Struct).init_with_default_granularity(),
        .struct_fields = try PinnedArray(Struct.Field).init_with_default_granularity(),
        .enum_fields = try PinnedArray(Enum.Field).init_with_default_granularity(),
        .function_definitions = try PinnedArray(Function.Definition).init_with_default_granularity(),
        .blocks = try PinnedArray(Debug.Block).init_with_default_granularity(),
        .global_declarations = try PinnedArray(Debug.Declaration.Global).init_with_default_granularity(),
        .local_declarations = try PinnedArray(Debug.Declaration.Local).init_with_default_granularity(),
        .argument_declarations = try PinnedArray(Debug.Declaration.Argument).init_with_default_granularity(),
        .assembly_instructions = try PinnedArray(InlineAssembly.Instruction).init_with_default_granularity(),
        .function_prototypes = try PinnedArray(Function.Prototype).init_with_default_granularity(),
        .inline_assembly = try PinnedArray(InlineAssembly).init_with_default_granularity(),
        .instructions = try PinnedArray(Instruction).init_with_default_granularity(),
        .basic_blocks = try PinnedArray(BasicBlock).init_with_default_granularity(),
        .constant_structs = try PinnedArray(V.Comptime.ConstantStruct).init_with_default_granularity(),
        .constant_arrays = try PinnedArray(V.Comptime.ConstantArray).init_with_default_granularity(),
        .constant_slices = try PinnedArray(V.Comptime.ConstantSlice).init_with_default_granularity(),
        .error_fields = try PinnedArray(Type.Error.Field).init_with_default_granularity(),
    };

    return unit;
}

fn realpathAlloc(allocator: Allocator, pathname: []const u8) ![]const u8 {
    var path_buffer: [std.fs.MAX_PATH_BYTES]u8 = undefined;
    const realpathInStack = try std.posix.realpath(pathname, &path_buffer);
    return allocator.dupe(u8, realpathInStack);
}

pub const ContainerType = enum {
    @"struct",
    @"enum",
    bitfield,
};

pub const Directory = struct {
    handle: std.fs.Dir,
    path: []const u8,
};

pub const Package = struct {
    directory: Directory,
    /// Relative to the package main directory
    source_path: []const u8,
    dependencies: PinnedHashMap([]const u8, *Package),

    fn addDependency(package: *Package, package_name: []const u8, new_dependency: *Package) !void {
        try package.dependencies.put_no_clobber(package_name, new_dependency);
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

pub fn panic(message: []const u8, stack_trace: ?*std.builtin.StackTrace, return_address: ?usize) noreturn {
    const print_stack_trace = @import("configuration").print_stack_trace;
    switch (print_stack_trace) {
        true => @call(.always_inline, std.builtin.default_panic, .{ message, stack_trace, return_address }),
        false => {
            write(.panic, "\nPANIC: ") catch {};
            write(.panic, message) catch {};
            write(.panic, "\n") catch {};
            @breakpoint();
            std.posix.abort();
        },
    }
}

const TypeCheckSwitchEnums = struct {
    switch_case_groups: []const []const Enum.Field.Index,
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

fn getTypeBitSize(ty: *Type, unit: *Unit) u32 {
    return switch (ty.*) {
        .integer => |integer| integer.bit_count,
        .@"struct" => |struct_index| switch (unit.structs.get(struct_index).kind) {
            .@"struct" => |*struct_type| {
                var bit_size: u32 = 0;
                for (struct_type.fields) |field_index| {
                    const field = unit.struct_fields.get(field_index);
                    const field_type = unit.types.get(field.type);
                    const field_bit_size = field_type.getBitSize(unit);
                    bit_size += field_bit_size;
                }
                return bit_size;
            },
            else => |t| @panic(@tagName(t)),
        },
        .pointer => 64,
        .slice => 2 * @bitSizeOf(usize),
        .void, .noreturn => 0,
        .array => |array| {
            const array_element_type = unit.types.get(array.type);
            return @intCast(getTypeBitSize(array_element_type, unit) * array.count);
        },
        else => |t| @panic(@tagName(t)),
    };
}

fn getTypeAbiSize(ty: *Type, unit: *Unit) u32 {
    return switch (ty.*) {
        .integer => |integer| std.math.divExact(u16, integer.bit_count, @bitSizeOf(u8)) catch switch (integer.kind) {
            .bool => 1,
            else => |t| @panic(@tagName(t)),
        },
        .pointer => 8,
        .@"struct" => |struct_index| switch (unit.structs.get(struct_index).kind) {
            .@"struct" => |*struct_type| b: {
                const struct_alignment = ty.getAbiAlignment(unit);
                var total_byte_size: u32 = 0;
                for (struct_type.fields) |field_index| {
                    const field = unit.struct_fields.get(field_index);
                    const field_type = unit.types.get(field.type);
                    const field_size = getTypeAbiSize(field_type, unit);
                    const field_alignment = getTypeAbiAlignment(field_type, unit);
                    total_byte_size = @intCast(align_forward(total_byte_size, field_alignment));
                    total_byte_size += field_size;
                }

                total_byte_size = @intCast(align_forward(total_byte_size, struct_alignment));

                break :b total_byte_size;
            },
            .two_struct => |pair| b: {
                const struct_alignment = ty.getAbiAlignment(unit);
                var total_byte_size: u32 = 0;
                for (pair) |type_index| {
                    const field_type = unit.types.get(type_index);
                    const field_size = getTypeAbiSize(field_type, unit);
                    const field_alignment = getTypeAbiAlignment(field_type, unit);
                    total_byte_size = @intCast(align_forward(total_byte_size, field_alignment));
                    total_byte_size += field_size;
                }

                total_byte_size = @intCast(align_forward(total_byte_size, struct_alignment));

                break :b total_byte_size;
            },
            else => |t| @panic(@tagName(t)),
        },
        .array => |array| b: {
            const element_type = unit.types.get(array.type);
            const element_size = element_type.getAbiSize(unit);
            const array_size: u32 = @intCast(element_size * array.count);
            break :b array_size;
        },
        else => |t| @panic(@tagName(t)),
    };
}

fn getTypeAbiAlignment(ty: *Type, unit: *Unit) u32 {
    return switch (ty.*) {
        .@"struct" => |struct_index| switch (unit.structs.get(struct_index).kind) {
            .@"struct" => |*struct_type| b: {
                var alignment: u32 = 1;
                for (struct_type.fields) |field_index| {
                    const field = unit.struct_fields.get(field_index);
                    const field_ty = unit.types.get(field.type);
                    const field_alignment = field_ty.getAbiAlignment(unit);
                    alignment = @max(alignment, field_alignment);
                }

                break :b alignment;
            },
            // TODO: is this correct?
            .two_struct => |pair| {
                const low = unit.types.get(pair[0]).getAbiAlignment(unit);
                const high = unit.types.get(pair[1]).getAbiAlignment(unit);
                return @max(low, high);
            },
            // TODO: is this correct?
            .error_union => |error_union| {
                return unit.types.get(error_union.abi).getAbiAlignment(unit);
            },
            // TODO: is this correct?
            .raw_error_union => |error_union_type| {
                const type_alignment = unit.types.get(error_union_type).getAbiAlignment(unit);
                return @max(type_alignment, 1);
            },
            // TODO: is this correct?
            .abi_compatible_error_union => |error_union| {
                const t = unit.types.get(error_union.type).getAbiAlignment(unit);
                if (error_union.padding != .null) {
                    const padding = unit.types.get(error_union.padding).getAbiAlignment(unit);
                    return @max(t, padding);
                } else return t;
            },
            else => |t| @panic(@tagName(t)),
        },
        .integer => |integer| switch (integer.bit_count) {
            8 => 1,
            16 => 2,
            32 => 4,
            64 => 8,
            else => if (integer.bit_count < 8) 1 else if (integer.bit_count < 16) 2 else if (integer.bit_count < 32) 4 else if (integer.bit_count < 64) 8 else unreachable,
        },
        .pointer => 8,
        .slice => 8,
        .array => |array| {
            const element_type = unit.types.get(array.type);
            const alignment = element_type.getAbiAlignment(unit);
            return alignment;
        },
        else => |t| @panic(@tagName(t)),
    };
}

const HomogeneousAggregate = struct {
    type: Type.Index,
    count: u32,
};

fn getTypeHomogeneousAggregate(ty: *Type, unit: *Unit) ?HomogeneousAggregate {
    return switch (ty.*) {
        .@"struct" => |struct_index| switch (unit.structs.get(struct_index).kind) {
            .@"struct" => |*struct_type| {
                for (struct_type.fields) |field_index| {
                    const field = unit.struct_fields.get(field_index);
                    const field_type = unit.types.get(field.type);
                    while (field_type.* == .array) {
                        unreachable;
                    }

                    if (getTypeHomogeneousAggregate(field_type, unit)) |homogeneous_aggregate| {
                        _ = homogeneous_aggregate;
                        unreachable;
                    } else {
                        return null;
                    }
                }
                unreachable;
            },
            else => |t| @panic(@tagName(t)),
        },
        .integer => |_| {
            if (ty.is_homogeneous_base_type(unit)) {
                unreachable;
            } else {
                return null;
            }
        },
        else => |t| @panic(@tagName(t)),
    };
}

const _usize: Type.Index = .u64;
const _ssize: Type.Index = .s64;

fn serialize_comptime_parameters(unit: *Unit, context: *const Context, original_declaration: *Debug.Declaration, parameters: []const V.Comptime) !u32 {
    _ = context; // autofix
    var name = BoundedArray(u8, 4096){};
    const original_name = unit.getIdentifier(original_declaration.name);
    name.appendSliceAssumeCapacity(original_name);
    assert(parameters.len > 0);
    name.appendAssumeCapacity('(');

    for (parameters) |parameter| {
        switch (parameter) {
            .type => |parameter_type_index| if (unit.type_declarations.get(parameter_type_index)) |foo| {
                _ = foo; // autofix
                unreachable;
            } else switch (unit.types.get(parameter_type_index).*) {
                .integer => |integer| switch (integer.kind) {
                    .materialized_int => {
                        const char: u8 = switch (integer.signedness) {
                            .signed => 's',
                            .unsigned => 'u',
                        };
                        name.appendAssumeCapacity(char);
                        var bit_buffer: [32]u8 = undefined;
                        const formatted_int = format_int(&bit_buffer, integer.bit_count, 10, false);
                        name.appendSliceAssumeCapacity(formatted_int);
                    },
                    else => |t| @panic(@tagName(t)),
                },
                else => |t| @panic(@tagName(t)),
            },
            else => |t| @panic(@tagName(t)),
        }

        name.appendAssumeCapacity(',');
        name.appendAssumeCapacity(' ');
    }

    name.len -= 2;
    name.buffer[name.len] = ')';
    name.len += 1;

    const hash = my_hash(name.slice());
    // Don't allocate memory if not necessary
    if (unit.identifiers.get(hash) == null) {
        try unit.identifiers.put_no_clobber(hash, name.slice());
    }

    return hash;
}

pub const Type = union(enum) {
    void,
    noreturn,
    type,
    any,
    @"struct": Struct.Index,
    function: Function.Prototype.Index,
    integer: Type.Integer,
    pointer: Type.Pointer,
    slice: Type.Slice,
    array: Type.Array,
    polymorphic: Type.Polymorphic,
    polymorphic_function: void,

    pub const @"usize" = _usize;
    pub const ssize = _ssize;

    pub const Polymorphic = struct {
        parameters: []const Token.Index,
        instantiations: PinnedHashMap(u32, *Debug.Declaration.Global),
        node: Node.Index,

        pub fn get_instantiation(polymorphic: *Polymorphic, types: []const V.Comptime) ?*Debug.Declaration.Global {
            const parameter_hash = hash(types);
            const result = polymorphic.instantiations.get(parameter_hash);
            return result;
        }

        pub fn add_instantiation(polymorphic: *Polymorphic, unit: *Unit, context: *const Context, parameters: []const V.Comptime, original_declaration: *Debug.Declaration.Global, type_index: Type.Index) !void {
            const name_hash = try serialize_comptime_parameters(unit, context, &original_declaration.declaration, parameters);

            const new_declaration = unit.global_declarations.append(.{
                .declaration = .{
                    .scope = original_declaration.declaration.scope,
                    .type = .type,
                    .name = name_hash,
                    .line = original_declaration.declaration.line,
                    .column = original_declaration.declaration.column,
                    .mutability = original_declaration.declaration.mutability,
                    .kind = original_declaration.declaration.kind,
                },
                .initial_value = .{
                    .type = type_index,
                },
                .type_node_index = original_declaration.type_node_index,
                .attributes = original_declaration.attributes,
            });

            const parameter_hash = hash(parameters);
            try polymorphic.instantiations.put_no_clobber(parameter_hash, new_declaration);
        }

        fn hash(types: []const V.Comptime) u32 {
            const result = my_hash(std.mem.sliceAsBytes(types));
            return result;
        }
    };

    pub fn getBitSize(ty: *Type, unit: *Unit) u32 {
        return getTypeBitSize(ty, unit);
    }

    pub fn getAbiSize(ty: *Type, unit: *Unit) u32 {
        return getTypeAbiSize(ty, unit);
    }

    pub fn getAbiAlignment(ty: *Type, unit: *Unit) u32 {
        return getTypeAbiAlignment(ty, unit);
    }

    fn is_homogeneous_base_type(ty: *Type, unit: *Unit) bool {
        _ = unit;
        return switch (ty.*) {
            .integer => false,
            else => |t| @panic(@tagName(t)),
        };
    }

    fn get_homogeneous_aggregate(ty: *Type, unit: *Unit) ?HomogeneousAggregate {
        return getTypeHomogeneousAggregate(ty, unit);
    }

    fn getScope(ty: *Type, unit: *Unit) *Debug.Scope {
        return switch (ty.*) {
            .@"struct" => |struct_index| &unit.structs.get(struct_index).kind.@"struct".scope.scope,
            .integer => |*integer| switch (integer.kind) {
                .@"enum" => |*enum_type| &enum_type.scope.scope,
                .@"error" => |*err| &err.scope.scope,
                else => |t| @panic(@tagName(t)),
            },
            else => |t| @panic(@tagName(t)),
        };
    }

    fn is_aggregate(ty: *Type) bool {
        return switch (ty.*) {
            .integer, .pointer => false,
            .@"struct" => true,
            else => |t| @panic(@tagName(t)),
        };
    }

    const Expect = union(enum) {
        none,
        type: Type.Index,
        optional,
        array: struct {
            count: ?usize,
            type: Type.Index,
            termination: Termination,
        },
        cast: Type.Index,
    };

    pub const Error = struct {
        fields: DynamicBoundedArray(Type.Error.Field.Index),
        scope: Debug.Scope.Global,
        id: u32,

        pub const Index = PinnedArray(Type.Error).Index;

        pub const Field = struct {
            name: u32,
            type: Type.Index,
            value: usize,

            pub const Index = PinnedArray(Type.Error.Field).Index;
        };

        pub const Union = struct {
            @"error": Type.Index,
            type: Type.Index,
            alternate_type: Type.Index,
            alternate_index: bool,

            pub const Index = PinnedArray(Type.Error.Union).Index;

            const Descriptor = struct {
                @"error": Type.Index,
                type: Type.Index,
            };
        };
    };

    const Integer = struct {
        kind: Kind,
        bit_count: u16,
        signedness: Signedness,

        const Kind = union(enum) {
            bool,
            comptime_int,
            @"enum": Enum,
            materialized_int,
            disguised_pointer,
            @"error": Type.Error,
            bitfield: Bitfield,
        };

        pub const Signedness = enum(u1) {
            unsigned = 0,
            signed = 1,
        };
    };

    pub const Bitfield = struct {
        fields: []const Struct.Field.Index = &.{},
        scope: Debug.Scope.Global,
    };

    pub const Pointer = struct {
        type: Type.Index,
        termination: Termination,
        mutability: Mutability,
        many: bool,
        nullable: bool,
    };

    const Slice = struct {
        child_pointer_type: Type.Index,
        child_type: Type.Index,
        termination: Termination,
        mutability: Mutability,
        nullable: bool,
    };

    const Array = struct {
        count: usize,
        type: Type.Index,
        termination: Termination,
    };

    pub const Termination = enum {
        none,
        null,
        zero,
    };

    const Common = enum {
        void,
        noreturn,
        type,
        comptime_int,
        any,
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
        polymorphic_function,
        // usize,
        // ssize,

        const bool_type = Type.u1;

        const map = std.EnumArray(@This(), Type).init(.{
            .void = .void,
            .noreturn = .noreturn,
            .type = .type,
            .bool = .{
                .integer = .{
                    .bit_count = 1,
                    .signedness = .unsigned,
                    .kind = .bool,
                },
            },
            .comptime_int = .{
                .integer = .{
                    .bit_count = 0,
                    .signedness = .unsigned,
                    .kind = .comptime_int,
                },
            },
            .any = .any,
            .u1 = .{
                .integer = .{
                    .bit_count = 1,
                    .signedness = .unsigned,
                    .kind = .materialized_int,
                },
            },
            .u8 = .{
                .integer = .{
                    .bit_count = 8,
                    .signedness = .unsigned,
                    .kind = .materialized_int,
                },
            },
            .u16 = .{
                .integer = .{
                    .bit_count = 16,
                    .signedness = .unsigned,
                    .kind = .materialized_int,
                },
            },
            .u32 = .{
                .integer = .{
                    .bit_count = 32,
                    .signedness = .unsigned,
                    .kind = .materialized_int,
                },
            },
            .u64 = .{
                .integer = .{
                    .bit_count = 64,
                    .signedness = .unsigned,
                    .kind = .materialized_int,
                },
            },
            .s8 = .{
                .integer = .{
                    .bit_count = 8,
                    .signedness = .signed,
                    .kind = .materialized_int,
                },
            },
            .s16 = .{
                .integer = .{
                    .bit_count = 16,
                    .signedness = .signed,
                    .kind = .materialized_int,
                },
            },
            .s32 = .{
                .integer = .{
                    .bit_count = 32,
                    .signedness = .signed,
                    .kind = .materialized_int,
                },
            },
            .s64 = .{
                .integer = .{
                    .bit_count = 64,
                    .signedness = .signed,
                    .kind = .materialized_int,
                },
            },
            .polymorphic_function = .polymorphic_function,
            // .ssize = .{
            //     .integer = .{
            //         .bit_count = 64,
            //         .signedness = .signed,
            //         .kind = .materialized_int,
            //     },
            // },
            // .usize = .{
            //     .integer = .{
            //         .bit_count = 64,
            //         .signedness = .unsigned,
            //         .kind = .materialized_int,
            //     },
            // },
        });
    };

    pub const List = PinnedArrayAdvanced(Type, Common);
    pub const Index = List.Index;
};

pub const Instruction = union(enum) {
    add_overflow: AddOverflow,
    abi_argument: u32,
    branch: Branch,
    block: Debug.Block.Index,
    // TODO
    call: Instruction.Call,
    cast: Cast,
    debug_checkpoint: DebugCheckPoint,
    debug_declare_local_variable: DebugDeclareLocalVariable,
    debug_declare_argument: DebugDeclareArgument,
    extract_value: ExtractValue,
    insert_value: InsertValue,
    get_element_pointer: GEP,
    inline_assembly: InlineAssembly.Index,
    integer_compare: IntegerCompare,
    integer_binary_operation: Instruction.IntegerBinaryOperation,
    jump: Jump,
    leading_zeroes: V,
    load: Load,
    memcpy: Memcpy,
    umin: Min,
    smin: Min,
    phi: Phi,
    pop_scope: Instruction.Scope,
    push_scope: Instruction.Scope,
    ret: V,
    ret_void,
    stack_slot: Instruction.StackSlot,
    store: Store,
    syscall: Syscall,
    @"switch": Switch,
    trailing_zeroes: V,
    trap,
    @"unreachable",

    const Memcpy = struct {
        destination: V,
        source: V,
        destination_alignment: ?u32,
        source_alignment: ?u32,
        size: u32,
        is_volatile: bool,
    };

    const Switch = struct {
        condition: V,
        cases: []const Case = &.{},
        else_block: BasicBlock.Index = .null,
        block_type: Type.Index,

        const Case = struct {
            condition: V.Comptime,
            basic_block: BasicBlock.Index,
        };
    };

    const Phi = struct {
        values: *BoundedArray(Phi.Value, max_value_count),
        type: Type.Index,

        pub const max_value_count = 32;

        const Value = struct {
            value: V,
            basic_block: BasicBlock.Index,
        };

        pub fn addIncoming(phi: *Phi, value: V, basic_block: BasicBlock.Index) void {
            assert(phi.type == value.type);
            assert(basic_block != .null);
            phi.values.appendAssumeCapacity(.{
                .value = value,
                .basic_block = basic_block,
            });
        }
    };

    const Min = struct {
        left: V,
        right: V,
        type: Type.Index,
    };

    pub const GEP = struct {
        index: V,
        pointer: Instruction.Index,
        base_type: Type.Index,
        name: u32,
        is_struct: bool,
    };

    const ExtractValue = struct {
        expression: V,
        index: u32,
    };

    const InsertValue = struct {
        expression: V,
        index: u32,
        new_value: V,
    };

    const Branch = struct {
        condition: Instruction.Index,
        from: BasicBlock.Index,
        taken: BasicBlock.Index,
        not_taken: BasicBlock.Index,
    };

    const Jump = struct {
        from: BasicBlock.Index,
        to: BasicBlock.Index,
    };

    const DebugDeclareLocalVariable = struct {
        variable: *Debug.Declaration.Local,
        stack: Instruction.Index,
    };

    const DebugDeclareArgument = struct {
        argument: *Debug.Declaration.Argument,
        stack: Instruction.Index,
    };

    const Syscall = struct {
        arguments: []const V,
    };

    const Call = struct {
        callable: V,
        function_type: Type.Index,
        arguments: []const V,
    };

    const IntegerCompare = struct {
        left: V,
        right: V,
        type: Type.Index,
        id: Id,

        const Id = enum {
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

    const IntegerBinaryOperation = struct {
        left: V,
        right: V,
        id: Id,
        signedness: Type.Integer.Signedness,

        const Id = enum {
            add,
            wrapping_add,
            saturated_add,
            sub,
            wrapping_sub,
            saturated_sub,
            mul,
            wrapping_mul,
            saturated_mul,
            div,
            mod,
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

    const ArgumentDeclaration = struct {
        name: u32,
        type: Type.Index,
    };

    const Cast = struct {
        id: Cast.Id,
        value: V,
        type: Type.Index,

        const Id = enum {
            bitcast,
            enum_to_int,
            int_to_pointer,
            pointer_to_int,
            sign_extend,
            zero_extend,
            pointer_var_to_const,
            pointer_const_to_var,
            pointer_to_nullable,
            pointer_source_type_to_destination_type,
            pointer_to_not_nullable,
            pointer_none_terminated_to_zero,
            slice_var_to_const,
            slice_to_nullable,
            slice_to_not_null,
            slice_coerce_to_zero_termination,
            slice_zero_to_no_termination,
            truncate,
            pointer_to_array_to_pointer_to_many,
            error_union_type_int_to_pointer,
            error_union_type_upcast,
            error_union_type_downcast,
            array_bitcast_to_integer,
        };
    };

    const DebugCheckPoint = struct {
        scope: *Debug.Scope,
        line: u32,
        column: u32,
    };

    const Load = struct {
        value: V,
        type: Type.Index,
        alignment: ?u32 = null,
    };

    const StackSlot = struct {
        type: Type.Index,
        alignment: ?u32,
    };

    const Store = struct {
        // TODO:
        destination: V,
        source: V,
    };

    const AddOverflow = struct {
        left: V,
        right: V,
        type: Type.Index,
    };

    pub const Index = PinnedArray(Instruction).Index;
};

pub const BasicBlock = struct {
    instructions: PinnedArray(Instruction.Index),
    predecessors: PinnedArray(BasicBlock.Index) = .{
        .pointer = undefined,
        .length = 0,
        .granularity = 0,
    },
    // TODO: not use a bool
    terminated: bool = false,

    fn add_predecessor(basic_block: *BasicBlock, predecessor: BasicBlock.Index) !void {
        if (basic_block.predecessors.length == 0) {
            basic_block.predecessors = try PinnedArray(BasicBlock.Index).init(std.mem.page_size);
        }
        _ = basic_block.predecessors.append(predecessor);
    }

    pub const Index = PinnedArray(BasicBlock).Index;
};

pub const ComptimeParameterDeclaration = struct {
    type: Type.Index,
    name_token: Token.Index,
    index: u32,
};

pub const Function = struct {
    pub const Attribute = enum {
        cc,
        naked,
        @"extern",
    };

    pub const Definition = struct {
        scope: Debug.Scope.Function,
        basic_blocks: PinnedArray(BasicBlock.Index),
        // TODO: make this more efficient
        type: Type.Index,
        body: Debug.Block.Index,
        return_pointer: Instruction.Index = .null,
        alloca_index: u32 = 1,
        has_debug_info: bool,

        pub const Index = PinnedArray(Definition).Index;
    };

    pub const CallingConvention = enum {
        c,
        auto,
    };

    pub const Prototype = struct {
        argument_types: []const Type.Index = &.{},
        return_type: Type.Index = .null,
        abi: Prototype.Abi = .{},
        attributes: Attributes = .{},
        calling_convention: CallingConvention = .auto,
        has_polymorphic_parameters: bool = false,

        const Attributes = struct {
            naked: bool = false,
        };

        const Index = PinnedArray(Prototype).Index;

        const Abi = struct {
            return_type: Type.Index = .null,
            parameter_types: []const Type.Index = &.{},
            return_type_abi: Function.AbiInfo = .{},
            parameter_types_abi: []const Function.AbiInfo = &.{},
        };
    };

    pub const AbiInfo = struct {
        indices: [2]u16 = .{ 0, 0 },
        kind: AbiKind = .direct,
        attributes: AbiAttributes = .{},
    };

    const AbiKind = union(enum) {
        ignore,
        direct,
        direct_pair: [2]Type.Index,
        direct_coerce: Type.Index,
        direct_coerce_int,
        direct_split_struct_i32,
        expand_coerce,
        indirect: struct {
            type: Type.Index,
            pointer: Type.Index,
            alignment: u32,
        },
        expand,
    };

    const AbiAttributes = struct {
        by_reg: bool = false,
        zero_extend: bool = false,
        sign_extend: bool = false,
        realign: bool = false,
        by_value: bool = false,
    };
};

pub const Struct = struct {
    kind: Kind,

    pub const Kind = union(enum) {
        @"struct": Struct.Descriptor,
        error_union: struct {
            @"error": Type.Index,
            type: Type.Index,
            union_for_type: Type.Index,
            union_for_error: Type.Index,
            abi: Type.Index,
        },
        optional: Type.Index,
        raw_error_union: Type.Index,
        abi_compatible_error_union: struct {
            type: Type.Index,
            padding: Type.Index,
        },
        two_struct: [2]Type.Index,
    };

    pub const Descriptor = struct {
        scope: Debug.Scope.Global,
        fields: []const Struct.Field.Index = &.{},
        options: Options,
    };

    pub const Options = struct {
        sliceable: ?Sliceable = null,
        pub const Id = enum {
            sliceable,
        };
    };

    pub const Sliceable = struct {
        pointer: u32,
        length: u32,
    };

    pub const Field = struct {
        name: u32,
        type: Type.Index,
        default_value: ?V.Comptime,

        pub const Index = PinnedArray(Struct.Field).Index;
    };

    pub const Index = PinnedArray(Struct).Index;
};

pub const Context = struct {
    allocator: Allocator,
    arena: *Arena,
    cwd_absolute_path: []const u8,
    directory_absolute_path: []const u8,
    executable_absolute_path: []const u8,
    build_directory: std.fs.Dir,

    fn pathFromCwd(context: *const Context, relative_path: []const u8) ![]const u8 {
        return try joinPath(context, context.cwd_absolute_path, relative_path);
    }

    fn pathFromCompiler(context: *const Context, relative_path: []const u8) ![]const u8 {
        return try joinPath(context, context.directory_absolute_path, relative_path);
    }
};

pub fn joinPath(context: *const Context, a: []const u8, b: []const u8) ![]const u8 {
    return if (a.len != 0 and b.len != 0) try std.mem.concat(context.allocator, u8, &.{ a, "/", b }) else b;
}

pub const PolymorphicFunction = struct {
    parameters: []const ComptimeParameterDeclaration,
    instantiations: PinnedHashMap(u32, *Debug.Declaration.Global),
    node: Node.Index,
    is_member_call: bool,

    pub fn get_instantiation(polymorphic_function: *PolymorphicFunction, types: []const V.Comptime) ?*Debug.Declaration.Global {
        const param_hash = hash(types);
        const result = polymorphic_function.instantiations.get(param_hash);
        return result;
    }

    pub fn add_instantiation(polymorphic_function: *PolymorphicFunction, unit: *Unit, context: *const Context, parameters: []const V.Comptime, original_declaration: *Debug.Declaration.Global, function_definition_index: Function.Definition.Index) !*Debug.Declaration.Global {
        const name_hash = try serialize_comptime_parameters(unit, context, &original_declaration.declaration, parameters);

        if (original_declaration.declaration.type != .null) {
            assert(original_declaration.declaration.type == .polymorphic_function);
        }

        const function_definition = unit.function_definitions.get(function_definition_index);
        const type_index = function_definition.type;

        const new_declaration = unit.global_declarations.append(.{
            .declaration = .{
                .scope = original_declaration.declaration.scope,
                .type = type_index,
                .name = name_hash,
                .line = original_declaration.declaration.line,
                .column = original_declaration.declaration.column,
                .mutability = original_declaration.declaration.mutability,
                .kind = original_declaration.declaration.kind,
            },
            .initial_value = .{
                .function_definition = function_definition_index,
            },
            .type_node_index = original_declaration.type_node_index,
            .attributes = original_declaration.attributes,
        });

        const parameter_hash = hash(parameters);
        try polymorphic_function.instantiations.put_no_clobber(parameter_hash, new_declaration);

        return new_declaration;
    }

    fn hash(parameters: []const V.Comptime) u32 {
        const result = my_hash(std.mem.sliceAsBytes(parameters));
        return result;
    }
};

pub const V = struct {
    value: union(enum) {
        unresolved: Node.Index,
        runtime: Instruction.Index,
        @"comptime": Comptime,
    },
    type: Type.Index,

    pub const Comptime = union(enum) {
        unresolved: Node.Index,
        undefined,
        void,
        noreturn,
        type: Type.Index,
        bool: bool,
        comptime_int: ComptimeInt,
        constant_int: ConstantInt,
        function_declaration: Type.Index,
        enum_value: Enum.Field.Index,
        enum_fields: []const Enum.Field.Index,
        error_value: Type.Error.Field.Index,
        function_definition: Function.Definition.Index,
        global: *Debug.Declaration.Global,
        constant_bitfield: u64,
        constant_struct: ConstantStruct.Index,
        constant_array: ConstantArray.Index,
        constant_slice: ConstantSlice.Index,
        polymorphic_function: PolymorphicFunction,
        string_literal: u32,
        null_pointer,
        @"unreachable",

        pub const ConstantSlice = struct {
            array: ?*Debug.Declaration.Global,
            start: usize,
            end: usize,
            type: Type.Index,

            pub const Index = PinnedArray(ConstantSlice).Index;
        };

        pub const ConstantArray = struct {
            values: []const V.Comptime,
            type: Type.Index,

            pub const Index = PinnedArray(@This()).Index;
        };

        pub const ConstantStruct = struct {
            fields: []const V.Comptime,
            type: Type.Index,

            pub const Index = PinnedArray(@This()).Index;
        };

        pub const ComptimeInt = struct {
            value: u64,
            signedness: Type.Integer.Signedness,
        };

        pub const ConstantInt = struct {
            value: u64,
        };

        fn getType(v: Comptime, unit: *Unit) Type.Index {
            return switch (v) {
                .type => .type,
                .bool => .bool,
                .enum_value => |enum_field_index| unit.enum_fields.get(enum_field_index).parent,
                .function_definition => |function_definition_index| unit.function_definitions.get(function_definition_index).type,
                .comptime_int => .comptime_int,
                .constant_struct => |constant_struct| unit.constant_structs.get(constant_struct).type,
                .function_declaration => |function_type| function_type,
                .polymorphic_function => .polymorphic_function,
                else => |t| @panic(@tagName(t)),
            };
        }
    };
};

pub const Debug = struct {
    pub const Declaration = struct {
        scope: *Scope,
        type: Type.Index,
        name: u32,
        line: u32,
        column: u32,
        mutability: Mutability,
        kind: Kind,

        const Kind = enum {
            global,
            local,
            argument,
            @"comptime",
        };

        pub const Global = struct {
            declaration: Declaration,
            initial_value: V.Comptime,
            type_node_index: Node.Index,
            attributes: Attributes,

            const Attributes = std.EnumSet(Attribute);

            pub const Attribute = enum {
                @"export",
                @"extern",
            };

            pub const Index = PinnedArray(@This()).Index;

            pub fn getFunctionDefinitionIndex(global: *Global) Function.Definition.Index {
                return global.initial_value.function_definition;
            }
        };

        pub const Local = struct {
            declaration: Declaration,
            init_value: V,
            pub const Index = PinnedArray(@This()).Index;
        };
        pub const Argument = struct {
            declaration: Declaration,
            index: u32,

            pub const Index = PinnedArray(@This()).Index;
        };
    };

    pub const Scope = struct {
        declarations: PinnedHashMap(u32, *Declaration),
        parent: ?*Scope = null,
        file: File.Index,
        line: u32,
        column: u32,
        kind: Kind,
        local: bool,
        level: u8,

        const Lookup = struct {
            scope: *Scope,
            declaration: *Declaration,
        };

        pub const Local = struct {
            scope: Scope,
            local_declaration_map: PinnedHashMap(*Debug.Declaration.Local, Instruction.Index),
        };

        pub const Global = struct {
            scope: Scope,
            type: Type.Index = .null,
        };

        pub const Function = struct {
            scope: Scope,
            argument_map: PinnedHashMap(*Debug.Declaration.Argument, Instruction.Index),
            // comptime_parameters: PinnedArray(*Debug.Declaration.Argument,
        };

        fn lookupDeclaration(s: *Scope, name: u32, look_in_parent_scopes: bool) ?Lookup {
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
                    const file: *File = @fieldParentPtr("scope", s);
                    const file_index = unit.files.indexOf(file);
                    return file_index;
                }
            } else @panic("No parent file scope");
        }

        pub const Kind = enum {
            compilation_unit,
            file,
            file_container,
            struct_type,
            enum_type,
            bitfield,
            error_type,
            function, // Arguments
            block,
        };
    };

    pub const Block = struct {
        scope: Scope.Local,
        pub const Index = PinnedArray(@This()).Index;
    };

    pub const File = struct {
        relative_path: []const u8,
        package: *Package,
        source_code: []const u8 = &.{},
        status: Status = .not_loaded,
        lexer: lexer.Result = undefined,
        parser: parser.Result = undefined,
        // value: Value.Index = .null,
        scope: Scope.Global,

        pub const Index = PinnedArray(File).Index;

        pub const Status = enum {
            not_loaded,
            loaded_into_memory,
            lexed,
            parsed,
            analyzing,
            analyzed,
        };

        pub fn getPath(file: *File, allocator: Allocator) ![]const u8 {
            return try std.mem.concat(allocator, u8, &.{ file.package.directory.path, "/", file.relative_path });
        }
    };
};

pub const Mutability = enum(u1) {
    @"const",
    @"var",
};

pub const IntrinsicId = enum {
    add_overflow,
    assert,
    @"asm", //this is processed separately as it need special parsing
    cast,
    enum_to_int,
    fields,
    @"export",
    @"error",
    int_to_pointer,
    import,
    leading_zeroes,
    min,
    name,
    size,
    sign_extend,
    syscall,
    trailing_zeroes,
    trap,
    zero_extend,
};

pub const ArithmeticLogicIntegerInstruction = enum {
    add,
    wrapping_add,
    saturated_add,
    sub,
    wrapping_sub,
    saturated_sub,
    mul,
    wrapping_mul,
    saturated_mul,
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
    exit_blocks: BoundedArray(BasicBlock.Index, 16) = .{},
    loop_exit_block: BasicBlock.Index = .null,
    loop_header_block: BasicBlock.Index = .null,
    return_phi: Instruction.Index = .null,
    return_block: BasicBlock.Index = .null,
    last_check_point: struct {
        line: u32 = 0,
        column: u32 = 0,
        scope: ?*Debug.Scope = null,
    } = .{},
    generate_debug_info: bool,
    emit_ir: bool,

    fn setCurrentScope(builder: *Builder, scope: *Debug.Scope) void {
        builder.current_scope = scope;
    }

    fn getErrorUnionType(builder: *Builder, unit: *Unit, context: *const Context, error_union: Type.Error.Union.Descriptor) !Type.Index {
        _ = context; // autofix
        _ = builder; // autofix
        if (unit.error_unions.get(error_union)) |type_index| {
            return type_index;
        } else {
            const t = unit.types.get(error_union.type);
            const e = unit.types.get(error_union.@"error");
            const t_bitsize = t.getBitSize(unit);
            const e_bitsize = e.getBitSize(unit);
            const types = [2]Type.Index{ error_union.type, error_union.@"error" };
            const is_type_smaller_or_equal = t_bitsize < e_bitsize;
            const biggest_index = @intFromBool(is_type_smaller_or_equal);
            const biggest_type_index = types[biggest_index];

            const abi_struct_index = unit.structs.append_index(.{
                .kind = .{
                    .raw_error_union = biggest_type_index,
                },
            });

            const abi_type_index = unit.types.append_index(.{
                .@"struct" = abi_struct_index,
            });

            var error_union_for_type = Type.Index.null;
            var error_union_for_error = Type.Index.null;

            if (biggest_type_index == error_union.type) {
                error_union_for_type = abi_type_index;

                const padding_bit_count = t_bitsize - e_bitsize;
                assert(padding_bit_count != t_bitsize);
                if (padding_bit_count == 0 and t.* == .integer) {
                    error_union_for_error = abi_type_index;
                } else {
                    const padding_type = if (padding_bit_count != 0) try unit.getArrayType(.{
                        .count = padding_bit_count,
                        .type = .u1,
                        .termination = .none,
                    }) else .null;

                    const error_union_for_error_struct_index = unit.structs.append_index(.{
                        .kind = .{
                            .abi_compatible_error_union = .{
                                .type = error_union.@"error",
                                .padding = padding_type,
                            },
                        },
                    });
                    error_union_for_error = unit.types.append_index(.{
                        .@"struct" = error_union_for_error_struct_index,
                    });
                }
            } else {
                error_union_for_error = abi_type_index;

                const padding_bit_count = e_bitsize - t_bitsize;
                assert(padding_bit_count != 0);
                if (padding_bit_count != e_bitsize) {
                    const padding_type = try unit.getArrayType(.{
                        .count = padding_bit_count,
                        .type = .u1,
                        .termination = .none,
                    });

                    const error_union_for_error_struct_index = unit.structs.append_index(.{
                        .kind = .{
                            .abi_compatible_error_union = .{
                                .type = error_union.@"error",
                                .padding = padding_type,
                            },
                        },
                    });
                    _ = error_union_for_error_struct_index; // autofix
                    unreachable;
                } else {
                    error_union_for_type = abi_type_index;
                }
            }

            const error_union_struct_index = unit.structs.append_index(.{
                .kind = .{
                    .error_union = .{
                        .@"error" = error_union.@"error",
                        .type = error_union.type,
                        .union_for_type = error_union_for_type,
                        .union_for_error = error_union_for_error,
                        .abi = abi_type_index,
                    },
                },
            });

            const error_union_type_index = unit.types.append_index(.{
                .@"struct" = error_union_struct_index,
            });
            try unit.error_unions.put_no_clobber(error_union, error_union_type_index);

            return error_union_type_index;
        }
    }

    fn processStringLiteralFromToken(builder: *Builder, unit: *Unit, context: *const Context, token_index: Token.Index) !*Debug.Declaration.Global {
        const string = try unit.fixupStringLiteral(context, token_index);
        const token_debug_info = builder.getTokenDebugInfo(unit, token_index);

        return try builder.processStringLiteralFromStringAndDebugInfo(unit, context, string, token_debug_info);
    }

    fn join_name(context: *const Context, name: []const u8, number: usize, base: u8) ![:0]const u8 {
        const len = 65;
        var buffer: [len + 1]u8 = undefined;
        const slice = format_int(buffer[0..len], number, base, false);
        const ptr = slice.ptr - name.len;
        const new_slice = ptr[0 .. slice.len + name.len];
        @memcpy(new_slice[0..name.len], name);
        buffer[len] = 0;
        return @ptrCast(try context.arena.duplicate_bytes(new_slice));
    }

    fn processStringLiteralFromStringAndDebugInfo(builder: *Builder, unit: *Unit, context: *const Context, string: [:0]const u8, debug_info: TokenDebugInfo) !*Debug.Declaration.Global {
        const possible_id = unit.string_literal_values.length;
        const hash = try unit.processIdentifier(context, string);
        if (unit.string_literal_globals.get(hash)) |v| {
            return v;
        } else {
            const string_name = try join_name(context, "__anon_str_", possible_id, 10);
            const identifier = try unit.processIdentifier(context, string_name);
            try unit.string_literal_values.put_no_clobber(hash, string);

            const string_global = unit.global_declarations.append(.{
                .declaration = .{
                    .scope = builder.current_scope,
                    .name = identifier,
                    .type = blk: {
                        const length = string.len;
                        const array_type = try unit.getArrayType(.{
                            .type = .u8,
                            .count = length,
                            .termination = .zero,
                        });
                        const string_type = try unit.getPointerType(.{
                            .type = array_type,
                            .termination = .none,
                            .mutability = .@"const",
                            .many = true,
                            .nullable = false,
                        });
                        _ = string_type; // autofix

                        break :blk array_type;
                    },
                    .line = debug_info.line,
                    .column = debug_info.column,
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

            try unit.string_literal_globals.put_no_clobber(hash, string_global);

            _ = unit.data_to_emit.append(string_global);

            return string_global;
        }
    }

    fn resolveIntrinsic(builder: *Builder, unit: *Unit, context: *const Context, type_expect: Type.Expect, node_index: Node.Index, side: Side) anyerror!V {
        const node = unit.getNode(node_index);
        const intrinsic_id: IntrinsicId = @enumFromInt(@intFromEnum(node.right));
        const argument_node_list = unit.getNodeList(node.left);

        switch (intrinsic_id) {
            .import => {
                const file_index = try builder.resolveImport(unit, context, type_expect, argument_node_list);
                const file = unit.files.get(file_index);
                return .{
                    .value = .{
                        .@"comptime" = .{
                            .type = file.scope.type,
                        },
                    },
                    .type = .type,
                };
            },
            .@"asm" => {
                switch (unit.descriptor.arch) {
                    inline else => |arch| {
                        const architecture = @field(InlineAssembly, @tagName(arch));
                        assert(argument_node_list.len == 1);
                        const assembly_block_node = unit.getNode(argument_node_list[0]);
                        const instruction_node_list = unit.getNodeList(assembly_block_node.left);
                        var instructions = try context.arena.new_array(InlineAssembly.Instruction.Index, instruction_node_list.len);
                        instructions.len = 0;

                        for (instruction_node_list) |assembly_statement_node_index| {
                            const assembly_instruction_node = unit.getNode(assembly_statement_node_index);
                            const assembly_instruction_name_node = unit.getNode(assembly_instruction_node.left);
                            const instruction_name = unit.getExpectedTokenBytes(assembly_instruction_name_node.token, .identifier);
                            const instruction = inline for (@typeInfo(architecture.Instruction).Enum.fields) |instruction_enum_field| {
                                if (byte_equal(instruction_name, instruction_enum_field.name)) {
                                    break @field(architecture.Instruction, instruction_enum_field.name);
                                }
                            } else unreachable;
                            const operand_nodes = unit.getNodeList(assembly_instruction_node.right);

                            var operands = try context.arena.new_array(InlineAssembly.Operand, operand_nodes.len);
                            operands.len = 0;

                            for (operand_nodes) |operand_node_index| {
                                const operand_node = unit.getNode(operand_node_index);
                                const operand: InlineAssembly.Operand = switch (operand_node.id) {
                                    .assembly_register => blk: {
                                        const register_name = unit.getExpectedTokenBytes(operand_node.token, .identifier);

                                        const register = inline for (@typeInfo(architecture.Register).Enum.fields) |register_enum_field| {
                                            if (byte_equal(register_name, register_enum_field.name)) {
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
                                    .assembly_code_expression => .{
                                        .value = try builder.resolveRuntimeValue(unit, context, Type.Expect.none, operand_node.left, .left),
                                    },
                                    else => |t| @panic(@tagName(t)),
                                };

                                const index = operands.len;
                                operands.len += 1;
                                operands[index] = operand;
                            }

                            const instruction_index = unit.assembly_instructions.append_index(.{
                                .id = @intFromEnum(instruction),
                                .operands = operands,
                            });

                            const index = instructions.len;
                            instructions.len += 1;
                            instructions[index] = instruction_index;
                        }

                        const inline_assembly = unit.inline_assembly.append_index(.{
                            .instructions = instructions,
                        });

                        const inline_asm = unit.instructions.append_index(.{
                            .inline_assembly = inline_assembly,
                        });
                        try builder.appendInstruction(unit, inline_asm);

                        return .{
                            .value = .{
                                .runtime = inline_asm,
                            },
                            // TODO: WARN fix
                            .type = .noreturn,
                        };
                    },
                }
            },
            .cast => {
                assert(argument_node_list.len == 1);
                const argument_node_index = argument_node_list[0];
                const cast_type_expect = Type.Expect{
                    .cast = switch (type_expect) {
                        .type => |type_index| type_index,
                        else => |t| @panic(@tagName(t)),
                    },
                };
                // TODO: depends? .right is not always the right choice
                const v = try builder.resolveRuntimeValue(unit, context, cast_type_expect, argument_node_index, side);

                switch (type_expect) {
                    .type => |type_index| {
                        const cast_id = try builder.resolveCast(unit, context, type_index, v, side);
                        switch (cast_id) {
                            .array_bitcast_to_integer => switch (v.value) {
                                .@"comptime" => |ct| switch (ct) {
                                    .constant_array => |constant_array_index| {
                                        const constant_array = unit.constant_arrays.get(constant_array_index);
                                        const array_type = unit.types.get(constant_array.type).array;
                                        switch (array_type.type) {
                                            .u8 => {
                                                var value: u64 = 0;
                                                for (constant_array.values, 0..) |array_value, i| {
                                                    value |= array_value.constant_int.value << @as(u6, @intCast(i * 8));
                                                }
                                                return V{
                                                    .value = .{
                                                        .@"comptime" = .{
                                                            .constant_int = .{
                                                                .value = value,
                                                            },
                                                        },
                                                    },
                                                    .type = type_index,
                                                };
                                            },
                                            else => unreachable,
                                        }
                                    },
                                    .string_literal => |hash| {
                                        const string_literal = unit.getIdentifier(hash);
                                        var value: u64 = 0;
                                        for (string_literal, 0..) |byte, i| {
                                            value |= @as(u64, byte) << @as(u6, @intCast(i * 8));
                                        }
                                        return V{
                                            .value = .{
                                                .@"comptime" = .{
                                                    .constant_int = .{
                                                        .value = value,
                                                    },
                                                },
                                            },
                                            .type = switch (unit.types.get(type_index).*) {
                                                .pointer => |pointer| pointer.type,
                                                else => |t| @panic(@tagName(t)),
                                            },
                                        };
                                    },
                                    else => |t| @panic(@tagName(t)),
                                },
                                .runtime => {
                                    const stack = try builder.createStackVariable(unit, context, type_index, null);
                                    const destination = V{
                                        .value = .{ .runtime = stack },
                                        .type = try unit.getPointerType(.{
                                            .type = type_index,
                                            .many = false,
                                            .termination = .none,
                                            .mutability = .@"var",
                                            .nullable = false,
                                        }),
                                    };
                                    const store = unit.instructions.append_index(.{
                                        .store = .{
                                            .destination = destination,
                                            .source = v,
                                        },
                                    });
                                    try builder.appendInstruction(unit, store);

                                    const load = unit.instructions.append_index(.{
                                        .load = .{
                                            .value = destination,
                                            .type = type_index,
                                        },
                                    });
                                    try builder.appendInstruction(unit, load);

                                    return V{
                                        .value = .{ .runtime = load },
                                        .type = type_index,
                                    };
                                },
                                else => |t| @panic(@tagName(t)),
                            },
                            else => {
                                const instruction = unit.instructions.append_index(.{
                                    .cast = .{
                                        .value = v,
                                        .type = type_expect.type,
                                        .id = cast_id,
                                    },
                                });

                                try builder.appendInstruction(unit, instruction);

                                return .{
                                    .value = .{
                                        .runtime = instruction,
                                    },
                                    .type = type_expect.type,
                                };
                            },
                        }
                    },
                    else => |t| @panic(@tagName(t)),
                }
            },
            .size => {
                assert(argument_node_list.len == 1);
                const argument_type_index = try builder.resolveType(unit, context, argument_node_list[0], &.{});
                const argument_type = unit.types.get(argument_type_index);
                const argument_size = argument_type.getAbiSize(unit);

                const integer_value = argument_size;
                const integer_type = switch (type_expect) {
                    .type => |type_index| b: {
                        const ty = unit.types.get(type_index);
                        break :b switch (ty.*) {
                            .integer => type_index,
                            else => |t| @panic(@tagName(t)),
                        };
                    },
                    .none => Type.usize,
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
                    var instruction_list = try context.arena.new_array(V, argument_node_list.len);
                    // TODO
                    const arg_type_expect = Type.Expect{
                        .type = Type.usize,
                    };

                    for (argument_node_list, 0..) |argument_node_index, i| {
                        const argument_value = try builder.resolveRuntimeValue(unit, context, arg_type_expect, argument_node_index, .right);
                        instruction_list[i] = argument_value;
                    }

                    const syscall = unit.instructions.append_index(.{
                        .syscall = .{
                            .arguments = instruction_list,
                        },
                    });

                    try builder.appendInstruction(unit, syscall);

                    return .{
                        .value = .{
                            .runtime = syscall,
                        },
                        .type = Type.usize,
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
                            .integer => |integer| switch (integer.kind) {
                                .materialized_int => {
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
                                    const min = unit.instructions.append_index(instruction);
                                    try builder.appendInstruction(unit, min);

                                    return .{
                                        .value = .{
                                            .runtime = min,
                                        },
                                        .type = type_index,
                                    };
                                },
                                else => |t| @panic(@tagName(t)),
                            },
                            else => |t| @panic(@tagName(t)),
                        }
                    },
                    else => |t| @panic(@tagName(t)),
                };
                _ = expected_type; // autofix
                unreachable;
            },
            .@"error" => {
                assert(argument_node_list.len == 1);
                // TODO: type
                const argument_node = unit.getNode(argument_node_list[0]);
                switch (argument_node.id) {
                    .string_literal => {
                        const error_message = try unit.fixupStringLiteral(context, argument_node.token);
                        builder.reportCompileError(unit, context, .{
                            .message = error_message,
                            .node = node_index,
                        });
                    },
                    else => |t| @panic(@tagName(t)),
                }
            },
            .@"export" => {
                assert(argument_node_list.len == 1);
                const expression = try builder.resolveComptimeValue(unit, context, Type.Expect.none, Debug.Declaration.Global.Attributes.initMany(&.{.@"export"}), argument_node_list[0], null, .left, &.{}, null, &.{});
                switch (expression) {
                    .global => {},
                    else => |t| @panic(@tagName(t)),
                }

                return .{
                    .value = .{
                        .@"comptime" = .void,
                    },
                    .type = .void,
                };
            },
            .trap => {
                assert(argument_node_list.len == 0);
                try builder.buildTrap(unit, context);
                return .{
                    .value = .{
                        .@"comptime" = .noreturn,
                    },
                    .type = .noreturn,
                };
            },
            .fields => {
                assert(argument_node_list.len == 1);
                const container_type_index = try builder.resolveType(unit, context, argument_node_list[0], &.{});
                const fields = try builder.get_fields_array(unit, context, container_type_index, unit.getNode(argument_node_list[0]).token);
                return .{
                    .value = .{
                        .@"comptime" = .{
                            .global = fields,
                        },
                    },
                    .type = try unit.getPointerType(.{
                        .type = fields.declaration.type,
                        .termination = .none,
                        .mutability = .@"const",
                        .many = false,
                        .nullable = false,
                    }),
                };
            },
            .name => {
                assert(argument_node_list.len == 1);
                const v = try builder.resolveRuntimeValue(unit, context, Type.Expect.none, argument_node_list[0], .right);
                switch (v.value) {
                    .runtime => switch (unit.types.get(v.type).*) {
                        .integer => |*integer| switch (integer.kind) {
                            .@"enum" => {
                                const name_function = try builder.get_name_function(unit, context, v.type);
                                var args = try context.arena.new_array(V, 1);
                                args[0] = v;
                                const call = unit.instructions.append_index(.{
                                    .call = .{
                                        .callable = .{
                                            .value = .{
                                                .@"comptime" = .{
                                                    .global = name_function,
                                                },
                                            },
                                            .type = name_function.declaration.type,
                                        },
                                        .function_type = name_function.declaration.type,
                                        .arguments = args,
                                    },
                                });
                                try builder.appendInstruction(unit, call);

                                return V{
                                    .value = .{
                                        .runtime = call,
                                    },
                                    .type = unit.function_prototypes.get(unit.types.get(name_function.declaration.type).function).return_type,
                                };
                            },
                            else => |t| @panic(@tagName(t)),
                        },
                        else => |t| @panic(@tagName(t)),
                    },
                    .@"comptime" => |ct| switch (ct) {
                        .enum_value => |enum_field_index| {
                            const enum_field = unit.enum_fields.get(enum_field_index);
                            const enum_name = unit.getIdentifier(enum_field.name);
                            const enum_name_z = try context.allocator.dupeZ(u8, enum_name);
                            const string_literal = try builder.processStringLiteralFromStringAndDebugInfo(unit, context, enum_name_z, .{
                                .line = 0,
                                .column = 0,
                            });
                            switch (type_expect) {
                                .type => |type_index| switch (unit.types.get(type_index).*) {
                                    .slice => |slice| {
                                        assert(slice.child_type == .u8);
                                        const constant_slice = unit.constant_slices.append_index(.{
                                            .array = string_literal,
                                            .start = 0,
                                            .end = enum_name.len,
                                            .type = type_index,
                                        });
                                        return V{
                                            .type = type_index,
                                            .value = .{
                                                .@"comptime" = .{
                                                    .constant_slice = constant_slice,
                                                },
                                            },
                                        };
                                    },
                                    else => |t| @panic(@tagName(t)),
                                },
                                else => |t| @panic(@tagName(t)),
                            }
                        },
                        else => |t| @panic(@tagName(t)),
                    },
                    else => |t| @panic(@tagName(t)),
                }
            },
            .trailing_zeroes => {
                assert(argument_node_list.len == 1);
                const argument = try builder.resolveRuntimeValue(unit, context, Type.Expect.none, argument_node_list[0], .right);
                const trailing_zeroes = unit.instructions.append_index(.{
                    .trailing_zeroes = argument,
                });
                try builder.appendInstruction(unit, trailing_zeroes);

                return V{
                    .type = argument.type,
                    .value = .{
                        .runtime = trailing_zeroes,
                    },
                };
            },
            .leading_zeroes => {
                assert(argument_node_list.len == 1);
                const argument = try builder.resolveRuntimeValue(unit, context, Type.Expect.none, argument_node_list[0], .right);
                const leading_zeroes = unit.instructions.append_index(.{
                    .leading_zeroes = argument,
                });
                try builder.appendInstruction(unit, leading_zeroes);

                return V{
                    .type = argument.type,
                    .value = .{
                        .runtime = leading_zeroes,
                    },
                };
            },
            else => |t| @panic(@tagName(t)),
        }
    }

    fn get_name_function(builder: *Builder, unit: *Unit, context: *const Context, type_index: Type.Index) !*Debug.Declaration.Global {
        if (unit.name_functions.get(type_index)) |result| return result else {
            var argument_types = try context.arena.new_array(Type.Index, 1);
            argument_types[0] = type_index;
            const return_type_index = try unit.getSliceType(.{
                .child_pointer_type = try unit.getPointerType(.{
                    .type = .u8,
                    // TODO: zero-terminate?
                    .termination = .none,
                    .mutability = .@"const",
                    .many = true,
                    .nullable = false,
                }),
                .child_type = .u8,
                // TODO: zero-terminate?
                .termination = .none,
                .mutability = .@"const",
                .nullable = false,
            });
            const function_prototype_index = unit.function_prototypes.append_index(.{
                .argument_types = argument_types,
                .return_type = return_type_index,
                .abi = .{
                    .return_type = return_type_index,
                    .parameter_types = argument_types,
                },
            });
            const function_type_index = unit.types.append_index(.{
                .function = function_prototype_index,
            });
            const function_definition_index = unit.function_definitions.append_index(.{
                .scope = .{
                    .scope = .{
                        .file = builder.current_file,
                        .line = 0,
                        .column = 0,
                        .kind = .function,
                        .local = true,
                        .level = builder.current_scope.level + 1,
                        .declarations = try PinnedHashMap(u32, *Debug.Declaration).init(std.mem.page_size),
                    },
                    .argument_map = try PinnedHashMap(*Debug.Declaration.Argument, Instruction.Index).init(std.mem.page_size),
                },
                .type = function_type_index,
                .body = .null,
                .has_debug_info = false,
                .basic_blocks = try PinnedArray(BasicBlock.Index).init(std.mem.page_size),
            });

            const function_definition = unit.function_definitions.get(function_definition_index);
            const old_scope = builder.current_scope;
            builder.current_scope = &function_definition.scope.scope;
            defer builder.current_scope = old_scope;

            const old_function = builder.current_function;
            builder.current_function = function_definition_index;
            defer builder.current_function = old_function;

            const old_basic_block = builder.current_basic_block;
            defer builder.current_basic_block = old_basic_block;

            const argument_name_hash = try unit.processIdentifier(context, "_enum_value_");
            const argument_declaration = unit.argument_declarations.append(.{
                .declaration = .{
                    .scope = builder.current_scope,
                    .name = argument_name_hash,
                    .type = type_index,
                    .mutability = .@"const",
                    .line = 0,
                    .column = 0,
                    .kind = .argument,
                },
                .index = 0,
            });

            try builder.current_scope.declarations.put_no_clobber(argument_name_hash, &argument_declaration.declaration);

            const entry_block = try builder.newBasicBlock(unit);
            const exit_block = try builder.newBasicBlock(unit);
            builder.current_basic_block = entry_block;

            const argument_instruction = unit.instructions.append_index(.{
                .abi_argument = 0,
            });
            try builder.appendInstruction(unit, argument_instruction);
            const switch_instruction_index = unit.instructions.append_index(.{
                .@"switch" = .{
                    .condition = .{
                        .value = .{
                            .runtime = argument_instruction,
                        },
                        .type = type_index,
                    },
                    .block_type = return_type_index,
                },
            });
            try builder.appendInstruction(unit, switch_instruction_index);
            const switch_instruction = &unit.instructions.get(switch_instruction_index).@"switch";

            const phi_instruction_index = unit.instructions.append_index(.{
                .phi = .{
                    .type = return_type_index,
                    .values = try context.arena.new(BoundedArray(Instruction.Phi.Value, Instruction.Phi.max_value_count)),
                },
            });
            const phi = &unit.instructions.get(phi_instruction_index).phi;

            const cases = switch (unit.types.get(type_index).*) {
                .integer => |*integer| switch (integer.kind) {
                    .@"enum" => |*enum_type| b: {
                        var cases = try context.arena.new_array(Instruction.Switch.Case, enum_type.fields.len);
                        for (enum_type.fields, 0..) |enum_field_index, i| {
                            builder.current_basic_block = entry_block;
                            const enum_field = unit.enum_fields.get(enum_field_index);
                            const case_block = try builder.newBasicBlock(unit);
                            builder.current_basic_block = case_block;
                            const identifier = unit.getIdentifier(enum_field.name);
                            const identifier_z = try context.allocator.dupeZ(u8, identifier);
                            const string_literal = try builder.processStringLiteralFromStringAndDebugInfo(unit, context, identifier_z, .{
                                .line = 0,
                                .column = 0,
                            });
                            const slice = unit.constant_slices.append_index(.{
                                .array = string_literal,
                                .start = 0,
                                .end = identifier_z.len,
                                .type = return_type_index,
                            });
                            const v = V{
                                .value = .{
                                    .@"comptime" = .{
                                        .constant_slice = slice,
                                    },
                                },
                                .type = return_type_index,
                            };
                            phi.addIncoming(v, builder.current_basic_block);
                            try builder.jump(unit, exit_block);

                            const case = Instruction.Switch.Case{
                                .condition = .{
                                    .enum_value = enum_field_index,
                                },
                                .basic_block = case_block,
                            };
                            cases[i] = case;
                        }

                        break :b cases;
                    },
                    else => |t| @panic(@tagName(t)),
                },
                else => |t| @panic(@tagName(t)),
            };

            switch_instruction.cases = cases;
            switch_instruction.else_block = try builder.create_unreachable_block(unit, context);

            builder.current_basic_block = exit_block;
            try builder.appendInstruction(unit, phi_instruction_index);

            const ret = unit.instructions.append_index(.{
                .ret = .{
                    .type = return_type_index,
                    .value = .{
                        .runtime = phi_instruction_index,
                    },
                },
            });
            try builder.appendInstruction(unit, ret);

            const global = unit.global_declarations.append(.{
                .declaration = .{
                    .scope = builder.current_scope,
                    .name = try unit.processIdentifier(context, try std.fmt.allocPrint(context.allocator, "get_enum_name_{}", .{@intFromEnum(type_index)})),
                    .type = function_type_index,
                    .line = 0,
                    .column = 0,
                    .mutability = .@"const",
                    .kind = .global,
                },
                .initial_value = .{
                    .function_definition = function_definition_index,
                },
                .type_node_index = .null,
                .attributes = .{},
            });

            try unit.code_to_emit.put_no_clobber(function_definition_index, global);
            try unit.name_functions.put_no_clobber(type_index, global);

            return global;
        }
    }

    fn get_fields_array(builder: *Builder, unit: *Unit, context: *const Context, container_type_index: Type.Index, token: Token.Index) !*Debug.Declaration.Global {
        if (unit.fields_array.get(container_type_index)) |result| return result else {
            const container_type = unit.types.get(container_type_index);

            switch (container_type.*) {
                .integer => |*integer| switch (integer.kind) {
                    .@"enum" => |*enum_type| {
                        const enum_count = enum_type.fields.len;
                        const array_type = try unit.getArrayType(.{
                            .type = container_type_index,
                            .count = enum_count,
                            .termination = .none,
                        });
                        var fields = try context.arena.new_array(V.Comptime, enum_count);
                        for (enum_type.fields, 0..) |enum_field_index, i| {
                            fields[i] = V.Comptime{
                                .enum_value = enum_field_index,
                            };
                        }
                        const constant_array = unit.constant_arrays.append_index(.{
                            .values = fields,
                            .type = array_type,
                        });

                        const token_debug_info = builder.getTokenDebugInfo(unit, token);
                        const name = try join_name(context, "_field_array_", unit.fields_array.length, 10);
                        const identifier = try unit.processIdentifier(context, name);

                        const global_declaration = unit.global_declarations.append(.{
                            .declaration = .{
                                .scope = builder.current_scope,
                                .name = identifier,
                                .type = array_type,
                                .line = token_debug_info.line,
                                .column = token_debug_info.column,
                                .mutability = .@"const",
                                .kind = .global,
                            },
                            .initial_value = .{
                                .constant_array = constant_array,
                            },
                            .type_node_index = .null,
                            .attributes = Debug.Declaration.Global.Attributes.initMany(&.{
                                .@"export",
                            }),
                        });
                        _ = unit.data_to_emit.append(global_declaration);

                        try unit.fields_array.put_no_clobber(container_type_index, global_declaration);

                        return global_declaration;
                    },
                    else => |t| @panic(@tagName(t)),
                },
                else => |t| @panic(@tagName(t)),
            }
        }
    }

    fn resolveCast(builder: *Builder, unit: *Unit, context: *const Context, type_index: Type.Index, value: V, side: Side) !Instruction.Cast.Id {
        _ = builder; // autofix
        _ = context; // autofix
        assert(type_index != value.type);
        const source_type = unit.types.get(value.type);
        const destination_type = unit.types.get(type_index);

        switch (destination_type.*) {
            .pointer => |destination_pointer| {
                switch (source_type.*) {
                    .integer => |source_integer| switch (source_integer.kind) {
                        // TODO:
                        .materialized_int => return .int_to_pointer,
                        else => |t| @panic(@tagName(t)),
                    },
                    .pointer => |source_pointer| {
                        if (destination_pointer.type == source_pointer.type) {
                            if (destination_pointer.mutability == source_pointer.mutability) {
                                if (destination_pointer.nullable != source_pointer.nullable) {
                                    // std.debug.print("Dst: {} Src: {}\n", .{ destination_pointer.nullable, source_pointer.nullable });
                                    if (destination_pointer.nullable) {
                                        assert(destination_pointer.termination != source_pointer.termination);
                                        unreachable;
                                    } else {
                                        unreachable;
                                    }
                                }
                                if (destination_pointer.termination != source_pointer.termination) return switch (destination_pointer.termination) {
                                    .zero => switch (source_pointer.termination) {
                                        .none => .pointer_none_terminated_to_zero,
                                        else => |t| @panic(@tagName(t)),
                                    },
                                    else => |t| @panic(@tagName(t)),
                                };
                                unreachable;
                            } else {
                                return .pointer_const_to_var;
                            }
                        } else {
                            return .pointer_source_type_to_destination_type;
                        }
                    },
                    .array => |array| {
                        const array_size = array.count * unit.types.get(array.type).getAbiSize(unit);
                        switch (side) {
                            .right => {
                                const destination_type_size = unit.types.get(destination_pointer.type).getAbiSize(unit);
                                if (array_size == destination_type_size) {
                                    return .array_bitcast_to_integer;
                                } else {
                                    unreachable;
                                }
                            },
                            .left => unreachable,
                        }
                    },
                    else => |t| @panic(@tagName(t)),
                }
            },
            .integer => |destination_integer| switch (destination_integer.kind) {
                .materialized_int => switch (source_type.*) {
                    .integer => |source_integer| switch (source_integer.kind) {
                        .@"enum" => {
                            if (destination_integer.signedness == source_integer.signedness and destination_integer.bit_count == source_integer.bit_count) {
                                return .enum_to_int;
                            } else {
                                // TODO: is this correct?
                                if (destination_integer.bit_count < source_integer.bit_count) {
                                    unreachable;
                                } else if (destination_integer.bit_count > source_integer.bit_count) {
                                    assert(destination_integer.signedness != source_integer.signedness);
                                    return switch (destination_integer.signedness) {
                                        .signed => .sign_extend,
                                        .unsigned => .zero_extend,
                                    };
                                } else {
                                    assert(destination_integer.signedness != source_integer.signedness);
                                    return .bitcast;
                                }
                            }
                        },
                        .materialized_int => {
                            if (destination_integer.bit_count < source_integer.bit_count) {
                                assert(destination_integer.signedness == source_integer.signedness);
                                return .truncate;
                            } else if (destination_integer.bit_count > source_integer.bit_count) {
                                assert(destination_integer.signedness != source_integer.signedness);
                                return switch (destination_integer.signedness) {
                                    .signed => .sign_extend,
                                    .unsigned => .zero_extend,
                                };
                            } else {
                                assert(destination_integer.signedness != source_integer.signedness);
                                return .bitcast;
                            }
                        },
                        .bitfield => {
                            if (destination_integer.bit_count == source_integer.bit_count and destination_integer.signedness == source_integer.signedness) {
                                return .bitcast;
                            } else {
                                unreachable;
                            }
                        },
                        .bool => return .zero_extend,
                        else => |t| @panic(@tagName(t)),
                    },
                    .pointer => {
                        if (destination_integer.signedness == .signed) {
                            unreachable;
                        }
                        if (destination_integer.bit_count < 64) {
                            unreachable;
                        }

                        return .pointer_to_int;
                    },
                    .array => |source_array| {
                        const array_size = source_array.count * unit.types.get(source_array.type).getAbiSize(unit);
                        if (destination_integer.bit_count % 8 != 0) {
                            unreachable;
                        }
                        const destination_byte_count = @divExact(destination_integer.bit_count, 8);
                        if (destination_byte_count == array_size) {
                            return .array_bitcast_to_integer;
                        } else {
                            unreachable;
                        }
                    },
                    else => |t| @panic(@tagName(t)),
                },
                .@"error" => |_| switch (source_type.*) {
                    .integer => |source_integer| switch (source_integer.kind) {
                        .materialized_int => {
                            if (destination_integer.signedness == source_integer.signedness and destination_integer.bit_count == source_integer.bit_count) {
                                return .bitcast;
                            } else {
                                unreachable;
                            }
                        },
                        else => |t| @panic(@tagName(t)),
                    },
                    else => |t| @panic(@tagName(t)),
                },
                else => |t| @panic(@tagName(t)),
            },
            .@"struct" => |destination_struct_index| switch (unit.structs.get(destination_struct_index).kind) {
                .error_union => |_| switch (source_type.*) {
                    .integer => |source_integer| switch (source_integer.kind) {
                        else => |t| @panic(@tagName(t)),
                    },
                    else => |t| @panic(@tagName(t)),
                },
                else => |t| @panic(@tagName(t)),
            },
            else => |t| @panic(@tagName(t)),
        }
    }

    fn pushScope(builder: *Builder, unit: *Unit, new_scope: *Debug.Scope) !void {
        const old_scope = builder.current_scope;

        assert(@intFromEnum(old_scope.kind) <= @intFromEnum(new_scope.kind));

        if (builder.current_basic_block != .null) {
            const current_function = unit.function_definitions.get(builder.current_function);
            const current_basic_block = unit.basic_blocks.get(builder.current_basic_block);

            if (current_function.basic_blocks.length <= 1 or current_basic_block.instructions.length > 0 or current_basic_block.predecessors.length > 0) {
                assert(@intFromEnum(old_scope.kind) >= @intFromEnum(Debug.Scope.Kind.function));
                const instruction = unit.instructions.append_index(.{
                    .push_scope = .{
                        .old = old_scope,
                        .new = new_scope,
                    },
                });
                try builder.appendInstruction(unit, instruction);
            }
        }

        new_scope.parent = old_scope;
        builder.setCurrentScope(new_scope);
    }

    fn popScope(builder: *Builder, unit: *Unit) !void {
        const old_scope = builder.current_scope;
        const new_scope = old_scope.parent.?;

        assert(@intFromEnum(old_scope.kind) >= @intFromEnum(new_scope.kind));

        if (builder.current_basic_block != .null and (unit.function_definitions.get(builder.current_function).basic_blocks.length <= 1 or (unit.basic_blocks.get(builder.current_basic_block).instructions.length > 0 or unit.basic_blocks.get(builder.current_basic_block).predecessors.length > 0))) {
            const instruction = unit.instructions.append_index(.{
                .pop_scope = .{
                    .old = old_scope,
                    .new = new_scope,
                },
            });
            try builder.appendInstruction(unit, instruction);
        }

        builder.setCurrentScope(new_scope);
    }

    fn analyzePackage(builder: *Builder, unit: *Unit, context: *const Context, package: *Package) !void {
        const package_import = try unit.importPackage(context, package);
        assert(!package_import.file.is_new);
        const file_index = package_import.file.index;

        _ = try builder.analyzeFile(unit, context, file_index);
    }

    fn analyzeFile(builder: *Builder, unit: *Unit, context: *const Context, file_index: Debug.File.Index) anyerror!void {
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
        builder.setCurrentScope(&unit.scope.scope);
        defer builder.setCurrentScope(old_scope);

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
        file.status = .analyzing;

        const previous_file = builder.current_file;
        builder.current_file = file_index;
        defer builder.current_file = previous_file;

        try builder.pushScope(unit, &file.scope.scope);
        defer builder.popScope(unit) catch unreachable;

        const main_node_index = file.parser.main_node_index;

        // File type already assigned
        _ = try builder.resolveContainerType(unit, context, main_node_index, .@"struct", null, &.{});
        file.status = .analyzed;
        assert(file.scope.type != .null);
    }

    const CastResult = enum {
        int_to_pointer,
        enum_to_int,
        sign_extend,
        zero_extend,
    };

    const TokenDebugInfo = struct {
        line: u32,
        column: u32,
    };

    fn getTokenDebugInfo(builder: *Builder, unit: *Unit, token_index: Token.Index) TokenDebugInfo {
        const file = unit.files.get(builder.current_file);
        const token = unit.token_buffer.tokens.get(token_index);
        const line = token.line - file.lexer.line_offset;
        const line_offset = unit.token_buffer.line_offsets.get_unchecked(token.line).*;
        const column = token.offset - line_offset;

        return .{
            .line = line,
            .column = column,
        };
    }

    fn insertDebugCheckPoint(builder: *Builder, unit: *Unit, token: Token.Index) !void {
        if (builder.generate_debug_info and builder.current_scope.local) {
            const basic_block = unit.basic_blocks.get(builder.current_basic_block);
            assert(!basic_block.terminated);

            const debug_info = builder.getTokenDebugInfo(unit, token);

            if (debug_info.line != builder.last_check_point.line or debug_info.column != builder.last_check_point.column or builder.current_scope != builder.last_check_point.scope) {
                const instruction = unit.instructions.append_index(.{
                    .debug_checkpoint = .{
                        .scope = builder.current_scope,
                        .line = debug_info.line,
                        .column = debug_info.column,
                    },
                });

                _ = basic_block.instructions.append(instruction);

                builder.last_check_point = .{
                    .scope = builder.current_scope,
                    .line = debug_info.line,
                    .column = debug_info.column,
                };
            }
        }
    }

    fn createStackVariable(builder: *Builder, unit: *Unit, context: *const Context, type_index: Type.Index, alignment: ?u32) !Instruction.Index {
        _ = context; // autofix
        const stack = unit.instructions.append_index(.{
            .stack_slot = .{
                .type = type_index,
                .alignment = alignment,
            },
        });
        const function_definition = unit.function_definitions.get(builder.current_function);

        const basic_block_index = function_definition.basic_blocks.slice()[0];
        const basic_block = unit.basic_blocks.get(basic_block_index);
        basic_block.instructions.insert(function_definition.alloca_index, stack);

        function_definition.alloca_index += 1;

        return stack;
    }

    fn appendInstruction(builder: *Builder, unit: *Unit, instruction_index: Instruction.Index) !void {
        switch (unit.instructions.get(instruction_index).*) {
            .extract_value => |extract_value| switch (unit.types.get(extract_value.expression.type).*) {
                .pointer => unreachable,
                else => {},
            },
            .store => |store| {
                if (store.source.value == .runtime and @intFromEnum(store.source.value.runtime) == 0xaaaa_aaaa) @breakpoint();
            },
            else => {},
        }
        const basic_block = unit.basic_blocks.get(builder.current_basic_block);
        if (!basic_block.terminated) {
            _ = basic_block.instructions.append(instruction_index);
        } else {
            const instruction = unit.instructions.get(instruction_index);
            assert(instruction.* == .pop_scope);
            basic_block.instructions.insert(basic_block.instructions.length - 1, instruction_index);
        }
    }

    const If = struct {
        condition: Condition,
        const Condition = union(enum) {
            true,
            false,
            runtime,
        };
    };

    fn referenceGlobalDeclaration(builder: *Builder, unit: *Unit, context: *const Context, scope: *Debug.Scope, declaration: *Debug.Declaration, global_attribute_override: Debug.Declaration.Global.Attributes, new_parameters: []const V.Comptime, maybe_member_value: ?V, polymorphic_argument_nodes: []const Node.Index) !*Debug.Declaration.Global {
        // TODO: implement this
        assert(declaration.kind == .global);
        const old_context = builder.startContextSwitch(.{
            .scope = scope,
            .file = scope.file,
            .basic_block = .null,
        });
        defer builder.endContextSwitch(old_context);

        const global_declaration: *Debug.Declaration.Global = @fieldParentPtr("declaration", declaration);
        switch (global_declaration.initial_value) {
            .unresolved => |declaration_node_index| {
                assert(declaration.type == .null);
                switch (global_declaration.type_node_index) {
                    .null => {},
                    else => |type_node_index| {
                        declaration.type = try builder.resolveType(unit, context, type_node_index, &.{});
                    },
                }

                const type_expect = switch (declaration.type) {
                    .null => Type.Expect.none,
                    else => Type.Expect{
                        .type = declaration.type,
                    },
                };

                inline for (@typeInfo(Debug.Declaration.Global.Attribute).Enum.fields) |attribute_enum_field| {
                    const attribute = @field(Debug.Declaration.Global.Attribute, attribute_enum_field.name);
                    if (global_attribute_override.contains(attribute)) {
                        global_declaration.attributes.insert(attribute);
                    }
                }

                global_declaration.initial_value = try builder.resolveComptimeValue(unit, context, type_expect, global_declaration.attributes, declaration_node_index, global_declaration, .right, new_parameters, maybe_member_value, polymorphic_argument_nodes);

                switch (declaration.type) {
                    .null => {
                        assert(global_declaration.type_node_index == .null);
                        declaration.type = global_declaration.initial_value.getType(unit);

                        if (global_declaration.initial_value == .function_definition) {
                            const function_definition = unit.function_definitions.get(global_declaration.initial_value.function_definition);
                            assert(declaration.type == function_definition.type);
                        }
                    },
                    else => {},
                }

                switch (global_declaration.initial_value) {
                    .polymorphic_function => |*polymorphic_function| {
                        assert(polymorphic_function.instantiations.length == 1);
                        const function_definition_global = polymorphic_function.instantiations.values()[0];
                        assert(function_definition_global.initial_value == .function_definition);

                        try unit.code_to_emit.put_no_clobber(function_definition_global.initial_value.function_definition, function_definition_global);

                        return function_definition_global;
                    },
                    .function_definition => |function_definition_index| {
                        switch (unit.getNode(declaration_node_index).id) {
                            .function_definition => try unit.code_to_emit.put_no_clobber(function_definition_index, global_declaration),
                            else => {
                                const actual_function_declaration = unit.code_to_emit.get(function_definition_index).?;
                                global_declaration.initial_value = .{
                                    .global = actual_function_declaration,
                                };
                            },
                        }
                    },
                    .function_declaration => |function_type| {
                        switch (unit.getNode(declaration_node_index).id) {
                            .function_prototype => try unit.external_functions.put_no_clobber(function_type, global_declaration),
                            else => {
                                const actual_function_declaration = unit.external_functions.get(function_type).?;
                                global_declaration.initial_value = .{
                                    .global = actual_function_declaration,
                                };
                            },
                        }
                    },
                    .type => |type_index| {
                        assert(declaration.type == .type);
                        switch (unit.types.get(type_index).*) {
                            .polymorphic => |*poly| if (new_parameters.len > 0) {
                                if (poly.get_instantiation(new_parameters)) |result| return result else {
                                    unreachable;
                                }
                            },
                            else => unit.type_declarations.put(type_index, global_declaration) catch {
                                assert(unit.type_declarations.get(type_index).? == global_declaration);
                            },
                        }
                    },
                    else => {
                        if (global_declaration.attributes.contains(.@"export") or declaration.mutability == .@"var") {
                            _ = unit.data_to_emit.append(global_declaration);
                        }
                    },
                }
            },
            .polymorphic_function => |*polymorphic_function| {
                const instantiation_value = try builder.resolveComptimeValue(unit, context, Type.Expect.none, global_declaration.attributes, polymorphic_function.node, global_declaration, .right, new_parameters, maybe_member_value, polymorphic_argument_nodes);
                const instantiation_global = instantiation_value.global;
                try unit.code_to_emit.put(instantiation_global.initial_value.function_definition, instantiation_global);

                return instantiation_global;
            },
            else => {},
        }

        inline for (@typeInfo(Debug.Declaration.Global.Attribute).Enum.fields) |attribute_enum_field| {
            const attribute = @field(Debug.Declaration.Global.Attribute, attribute_enum_field.name);
            if (global_attribute_override.contains(attribute)) {
                assert(global_declaration.attributes.contains(attribute));
            }
        }

        return global_declaration;
    }

    const ContextSwitch = struct {
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

        builder.setCurrentScope(new.scope);
        builder.current_basic_block = new.basic_block;
        builder.current_file = new.file;

        return old;
    }

    fn endContextSwitch(builder: *Builder, old: ContextSwitch) void {
        builder.setCurrentScope(old.scope);
        builder.current_basic_block = old.basic_block;
        builder.current_file = old.file;
    }

    fn resolveImport(builder: *Builder, unit: *Unit, context: *const Context, type_expect: Type.Expect, arguments: []const Node.Index) !Debug.File.Index {
        if (arguments.len != 1) {
            @panic("Import argument mismatch");
        }

        const argument_node_index = arguments[0];
        const argument_node = unit.getNode(argument_node_index);
        if (argument_node.id != .string_literal) {
            @panic("Import expected a string literal as an argument");
        }

        const string_literal_bytes = try unit.fixupStringLiteral(context, argument_node.token);

        return try builder.resolveImportStringLiteral(unit, context, type_expect, string_literal_bytes);
    }

    fn resolveImportStringLiteral(builder: *Builder, unit: *Unit, context: *const Context, type_expect: Type.Expect, import_path: []const u8) !Debug.File.Index {
        switch (type_expect) {
            .none => {},
            .type => |type_index| if (type_index != .type) @panic("expected type"),
            else => unreachable,
        }

        const import_file = try unit.importFile(context, builder.current_file, import_path);
        const file_index = import_file.file.index;
        const file = unit.files.get(file_index);

        if (file.status == .not_loaded) {
            try unit.generateAbstractSyntaxTreeForFile(context, file_index);
        }

        if (file.status == .parsed) {
            try builder.analyzeFile(unit, context, file_index);
        }

        assert(file.scope.type != .null);

        return file_index;
    }

    const ComptimeEvaluationError = error{
        cannot_evaluate,
    };

    fn referenceArgumentDeclaration(builder: *Builder, unit: *Unit, context: *const Context, scope: *Debug.Scope, declaration: *Debug.Declaration) !V {
        _ = context; // autofix
        _ = builder; // autofix
        assert(declaration.kind == .argument);
        assert(scope.kind == .function);

        const argument_declaration: *Debug.Declaration.Argument = @fieldParentPtr("declaration", declaration);
        const function_scope: *Debug.Scope.Function = @fieldParentPtr("scope", scope);
        const instruction_index = function_scope.argument_map.get(argument_declaration).?;

        return .{
            .value = .{
                .runtime = instruction_index,
            },
            .type = try unit.getPointerType(.{
                .type = declaration.type,
                .termination = .none,
                .mutability = .@"const",
                .many = false,
                .nullable = false,
            }),
        };
    }

    fn referenceLocalDeclaration(builder: *Builder, unit: *Unit, context: *const Context, scope: *Debug.Scope, declaration: *Debug.Declaration) !V {
        _ = context; // autofix
        _ = builder; // autofix
        assert(declaration.kind == .local);
        assert(scope.kind == .block);

        const local_declaration: *Debug.Declaration.Local = @fieldParentPtr("declaration", declaration);
        const local_scope: *Debug.Scope.Local = @fieldParentPtr("scope", scope);
        if (local_scope.local_declaration_map.get(local_declaration)) |instruction_index| {
            return .{
                .value = .{
                    .runtime = instruction_index,
                },
                .type = try unit.getPointerType(.{
                    .type = declaration.type,
                    .termination = .none,
                    .mutability = declaration.mutability,
                    .many = false,
                    .nullable = false,
                }),
            };
        } else {
            return local_declaration.init_value;
        }
    }

    const TypeCheckResult = enum {
        success,
        pointer_var_to_const,
        pointer_to_nullable,
        slice_var_to_const,
        slice_to_nullable,
        slice_coerce_to_zero_termination,
        slice_zero_to_no_termination,
        pointer_to_array_coerce_to_slice,
        materialize_int,
        optional_wrap,
        sign_extend,
        zero_extend,
        error_to_error_union,
        type_to_error_union,
        error_union_to_all_error_union,
        error_union_same_error,
        error_to_all_errors,
        error_to_all_errors_error_union,
    };

    const TypecheckError = error{};

    fn typecheck(builder: *Builder, unit: *Unit, context: *const Context, destination_type_index: Type.Index, source_type_index: Type.Index) TypecheckError!TypeCheckResult {
        if (destination_type_index == source_type_index) {
            return .success;
        } else {
            const destination = unit.types.get(destination_type_index);
            const source = unit.types.get(source_type_index);
            switch (destination.*) {
                .pointer => |destination_pointer| {
                    switch (source.*) {
                        .pointer => |source_pointer| {
                            const result = try builder.typecheck(unit, context, destination_pointer.type, source_pointer.type);
                            switch (result) {
                                .success => {
                                    if (destination_pointer.many == source_pointer.many) {
                                        if (destination_pointer.termination == source_pointer.termination) {
                                            if (destination_pointer.nullable == source_pointer.nullable) {
                                                if (destination_pointer.mutability == source_pointer.mutability) {
                                                    return .success;
                                                } else {
                                                    assert(destination_pointer.mutability == .@"const");
                                                    assert(source_pointer.mutability == .@"var");

                                                    return .pointer_var_to_const;
                                                }
                                            } else {
                                                assert(destination_pointer.mutability == source_pointer.mutability);

                                                if (!destination_pointer.nullable) {
                                                    unreachable;
                                                }

                                                return .pointer_to_nullable;
                                            }
                                        } else {
                                            if (destination_pointer.termination != .none) {
                                                unreachable;
                                            } else {
                                                unreachable;
                                            }
                                        }
                                    }

                                    @panic("Pointer unknown typecheck");

                                    // std.debug.panic("Pointer unknown typecheck:\nDst: {}\n Src: {}", .{ destination_pointer, source_pointer });
                                },
                                else => |t| @panic(@tagName(t)),
                            }
                        },
                        .slice => |source_slice| {
                            switch (destination_pointer.many) {
                                true => unreachable,
                                false => unreachable,
                            }
                            _ = source_slice; // autofix
                        },
                        else => |t| @panic(@tagName(t)),
                    }
                },
                .integer => |destination_integer| switch (destination_integer.kind) {
                    .materialized_int => switch (source.*) {
                        .integer => |source_integer| switch (source_integer.kind) {
                            .materialized_int => {
                                if (destination_integer.signedness == source_integer.signedness) {
                                    if (destination_integer.bit_count > source_integer.bit_count) {
                                        return switch (destination_integer.signedness) {
                                            .signed => .sign_extend,
                                            .unsigned => .zero_extend,
                                        };
                                    } else if (destination_integer.bit_count == source_integer.bit_count) {
                                        unreachable;
                                    } else {
                                        unreachable;
                                    }
                                } else {
                                    @panic("Signedness mismatch");
                                }
                            },
                            .comptime_int => {
                                return .materialize_int;
                            },
                            else => |t| @panic(@tagName(t)),
                        },
                        else => |t| @panic(@tagName(t)),
                    },
                    .@"error" => switch (source.*) {
                        .integer => |source_integer| switch (source_integer.kind) {
                            .@"error" => {
                                if (destination_type_index == unit.all_errors) {
                                    return .error_to_all_errors;
                                } else {
                                    unreachable;
                                }
                            },
                            else => |t| @panic(@tagName(t)),
                        },
                        else => |t| @panic(@tagName(t)),
                    },
                    else => |t| @panic(@tagName(t)),
                },
                .@"struct" => |destination_struct_index| switch (unit.structs.get(destination_struct_index).kind) {
                    .optional => {
                        if (unit.optionals.get(source_type_index)) |optional_type_index| {
                            _ = optional_type_index; // autofix
                            return .optional_wrap;
                        } else {
                            unreachable;
                        }
                    },
                    .error_union => |destination_error_union| {
                        if (destination_error_union.@"error" == source_type_index) {
                            return .error_to_error_union;
                        } else if (destination_error_union.type == source_type_index) {
                            return .type_to_error_union;
                        } else switch (unit.types.get(source_type_index).*) {
                            .integer => |integer| switch (integer.kind) {
                                .@"error" => {
                                    if (destination_error_union.@"error" == unit.all_errors) {
                                        return .error_to_all_errors_error_union;
                                    } else {
                                        unreachable;
                                    }
                                },
                                else => |t| @panic(@tagName(t)),
                            },
                            else => |t| @panic(@tagName(t)),
                        }
                    },
                    else => |t| @panic(@tagName(t)),
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
                                    } else {
                                        if (destination_slice.nullable and !source_slice.nullable) {
                                            assert(destination_slice.mutability == source_slice.mutability);
                                            return .slice_to_nullable;
                                        }
                                    }
                                } else {
                                    if (destination_slice.termination == .none) {
                                        return .slice_zero_to_no_termination;
                                    } else {
                                        unreachable;
                                    }
                                }
                            } else {
                                unreachable;
                            }

                            unreachable;
                        },
                        .pointer => |source_pointer| if (source_pointer.type == destination_slice.child_type) {
                            unreachable;
                        } else switch (unit.types.get(source_pointer.type).*) {
                            .array => |array| if (array.type == destination_slice.child_type) {
                                return .pointer_to_array_coerce_to_slice;
                            } else unreachable,
                            else => |t| @panic(@tagName(t)),
                        },
                        else => |t| @panic(@tagName(t)),
                    }
                },
                .function => |destination_function_prototype_index| {
                    const destination_function_prototype = unit.function_prototypes.get(destination_function_prototype_index);
                    switch (source.*) {
                        .function => |source_function_prototype_index| {
                            // We are not that good yet
                            assert(destination_function_prototype_index != source_function_prototype_index);
                            const source_function_prototype = unit.function_prototypes.get(source_function_prototype_index);
                            if (destination_function_prototype.calling_convention != source_function_prototype.calling_convention) {
                                unreachable;
                            }

                            if (!std.meta.eql(destination_function_prototype.attributes, source_function_prototype.attributes)) {
                                unreachable;
                            }

                            if (destination_function_prototype.return_type != source_function_prototype.return_type) {
                                unreachable;
                            }

                            if (destination_function_prototype.argument_types.len != source_function_prototype.argument_types.len) {
                                unreachable;
                            }

                            for (destination_function_prototype.argument_types, source_function_prototype.argument_types) |dst_arg_type, src_arg_type| {
                                if (dst_arg_type != src_arg_type) {
                                    unreachable;
                                }
                            }

                            return .success;
                        },
                        else => |t| @panic(@tagName(t)),
                    }
                },
                .array => |destination_array| {
                    switch (source.*) {
                        .array => |source_array| {
                            assert(destination_array.type == source_array.type);
                            assert(destination_array.count == source_array.count);
                            if (destination_array.termination != source_array.termination) {
                                if (destination_array.termination == .none) {
                                    unreachable;
                                } else {
                                    @panic("Expected array termination");
                                }
                            } else unreachable;
                        },
                        else => |t| @panic(@tagName(t)),
                    }
                },
                .void => switch (source.*) {
                    .noreturn => return .success,
                    else => |t| @panic(@tagName(t)),
                },
                else => |t| @panic(@tagName(t)),
            }
        }
    }

    const Side = enum {
        left,
        right,
    };

    fn resolveIdentifier(builder: *Builder, unit: *Unit, context: *const Context, type_expect: Type.Expect, identifier: []const u8, global_attributes: Debug.Declaration.Global.Attributes, side: Side, new_parameters: []const V.Comptime) !V {
        const hash = try unit.processIdentifier(context, identifier);

        const look_in_parent_scopes = true;
        if (builder.current_scope.lookupDeclaration(hash, look_in_parent_scopes)) |lookup| {
            // TODO: we could do this better
            // const scope = lookup.scope;
            const v: V = switch (lookup.scope.kind) {
                .file_container,
                .file,
                .struct_type,
                => b: {
                    const global = try builder.referenceGlobalDeclaration(unit, context, lookup.scope, lookup.declaration, global_attributes, new_parameters, null, &.{});
                    const pointer_to_global = try unit.getPointerType(.{
                        .type = global.declaration.type,
                        .termination = switch (type_expect) {
                            .none, .cast => .none,
                            .type => |type_index| switch (unit.types.get(type_index).*) {
                                .pointer => |pointer| pointer.termination,
                                else => .none,
                            },
                            else => unreachable,
                        },
                        .mutability = switch (type_expect) {
                            .none, .cast => .@"var",
                            .type => |type_index| switch (unit.types.get(type_index).*) {
                                .pointer => |pointer| pointer.mutability,
                                else => .@"var",
                            },
                            else => unreachable,
                        },
                        .many = false,
                        .nullable = false,
                    });

                    break :b switch (side) {
                        .left => switch (global.declaration.type) {
                            .type => .{
                                .value = .{
                                    .@"comptime" = .{
                                        .type = global.initial_value.type,
                                    },
                                },
                                .type = .type,
                            },
                            else => .{
                                .value = .{
                                    .@"comptime" = .{
                                        .global = global,
                                    },
                                },
                                .type = switch (type_expect) {
                                    .none => pointer_to_global,
                                    .type => |type_index| switch (try builder.typecheck(unit, context, type_index, pointer_to_global)) {
                                        .success => type_index,
                                        else => |t| @panic(@tagName(t)),
                                    },
                                    else => |t| @panic(@tagName(t)),
                                },
                            },
                        },
                        .right => switch (global.declaration.mutability) {
                            .@"const" => .{
                                .value = .{
                                    .@"comptime" = global.initial_value,
                                },
                                .type = global.declaration.type,
                            },
                            .@"var" => blk: {
                                const load = unit.instructions.append_index(.{
                                    .load = .{
                                        .value = .{
                                            .value = .{
                                                .@"comptime" = .{
                                                    .global = global,
                                                },
                                            },
                                            .type = pointer_to_global,
                                        },
                                        .type = global.declaration.type,
                                    },
                                });

                                try builder.appendInstruction(unit, load);

                                break :blk .{
                                    .value = .{
                                        .runtime = load,
                                    },
                                    .type = global.declaration.type,
                                };
                            },
                        },
                    };
                },
                .function, .block => |kind| blk: {
                    const preliminary_result: V = switch (kind) {
                        .function => switch (lookup.declaration.kind) {
                            .global => {
                                const comptime_parameter = try builder.referenceGlobalDeclaration(unit, context, lookup.scope, lookup.declaration, global_attributes, new_parameters, null, &.{});
                                assert(comptime_parameter.declaration.mutability == .@"const");
                                break :blk V{
                                    .value = .{
                                        .@"comptime" = comptime_parameter.initial_value,
                                    },
                                    .type = comptime_parameter.declaration.type,
                                };
                            },
                            .argument => try builder.referenceArgumentDeclaration(unit, context, lookup.scope, lookup.declaration),
                            // These are comptime parameters
                            else => unreachable,
                        },
                        .block => try builder.referenceLocalDeclaration(unit, context, lookup.scope, lookup.declaration),
                        else => unreachable,
                    };
                    const v: V = switch (preliminary_result.value) {
                        .runtime => switch (side) {
                            .left => preliminary_result,
                            .right => b: {
                                const instruction = unit.instructions.append_index(.{
                                    .load = .{
                                        .value = preliminary_result,
                                        .type = lookup.declaration.type,
                                    },
                                });

                                try builder.appendInstruction(unit, instruction);

                                break :b .{
                                    .value = .{
                                        .runtime = instruction,
                                    },
                                    .type = lookup.declaration.type,
                                };
                            },
                        },
                        .@"comptime" => preliminary_result,
                        else => |t| @panic(@tagName(t)),
                    };

                    break :blk v;
                },
                else => |t| @panic(@tagName(t)),
            };

            switch (type_expect) {
                .none => return v,
                .type => |expected_type_index| {
                    const typecheck_result = try builder.typecheck(unit, context, expected_type_index, v.type);
                    switch (typecheck_result) {
                        .success => return v,
                        .zero_extend => {
                            const zero_extend = unit.instructions.append_index(.{
                                .cast = .{
                                    .id = .zero_extend,
                                    .value = v,
                                    .type = expected_type_index,
                                },
                            });
                            try builder.appendInstruction(unit, zero_extend);

                            return .{
                                .value = .{
                                    .runtime = zero_extend,
                                },
                                .type = expected_type_index,
                            };
                        },
                        .sign_extend => {
                            const sign_extend = unit.instructions.append_index(.{
                                .cast = .{
                                    .id = .sign_extend,
                                    .value = v,
                                    .type = expected_type_index,
                                },
                            });
                            try builder.appendInstruction(unit, sign_extend);
                            return .{
                                .value = .{
                                    .runtime = sign_extend,
                                },
                                .type = expected_type_index,
                            };
                        },
                        .pointer_var_to_const => {
                            const cast_to_const = unit.instructions.append_index(.{
                                .cast = .{
                                    .id = .pointer_var_to_const,
                                    .value = v,
                                    .type = expected_type_index,
                                },
                            });

                            try builder.appendInstruction(unit, cast_to_const);
                            return .{
                                .value = .{
                                    .runtime = cast_to_const,
                                },
                                .type = expected_type_index,
                            };
                        },
                        .slice_coerce_to_zero_termination => {
                            const cast_to_zero_termination = unit.instructions.append_index(.{
                                .cast = .{
                                    .id = .slice_coerce_to_zero_termination,
                                    .value = v,
                                    .type = expected_type_index,
                                },
                            });
                            try builder.appendInstruction(unit, cast_to_zero_termination);

                            return .{
                                .value = .{
                                    .runtime = cast_to_zero_termination,
                                },
                                .type = expected_type_index,
                            };
                        },
                        .slice_var_to_const => {
                            const cast_to_const = unit.instructions.append_index(.{
                                .cast = .{
                                    .id = .slice_var_to_const,
                                    .value = v,
                                    .type = expected_type_index,
                                },
                            });

                            try builder.appendInstruction(unit, cast_to_const);
                            return .{
                                .value = .{
                                    .runtime = cast_to_const,
                                },
                                .type = expected_type_index,
                            };
                        },
                        .slice_to_nullable => {
                            const cast = unit.instructions.append_index(.{
                                .cast = .{
                                    .id = .slice_to_nullable,
                                    .value = v,
                                    .type = expected_type_index,
                                },
                            });

                            try builder.appendInstruction(unit, cast);
                            return .{
                                .value = .{
                                    .runtime = cast,
                                },
                                .type = expected_type_index,
                            };
                        },
                        .pointer_to_nullable => {
                            const cast = unit.instructions.append_index(.{
                                .cast = .{
                                    .id = .pointer_to_nullable,
                                    .value = v,
                                    .type = expected_type_index,
                                },
                            });

                            try builder.appendInstruction(unit, cast);
                            return .{
                                .value = .{
                                    .runtime = cast,
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
                                .signed => {
                                    if (destination_integer_type.signedness == .unsigned) {
                                        unreachable;
                                    } else {
                                        const value = -@as(i64, @intCast(ct_int.value));
                                        return .{
                                            .value = .{
                                                .@"comptime" = .{
                                                    .constant_int = .{
                                                        .value = @bitCast(value),
                                                    },
                                                },
                                            },
                                            .type = expected_type_index,
                                        };
                                    }
                                },
                            }
                        },
                        .optional_wrap => {
                            const optional_type_index = expected_type_index;
                            switch (unit.types.get(optional_type_index).*) {
                                else => |t| @panic(@tagName(t)),
                            }
                        },
                        .error_to_error_union => {
                            const error_union_struct_index = unit.types.get(expected_type_index).@"struct";
                            const error_union_struct = unit.structs.get(error_union_struct_index);
                            const error_union = error_union_struct.kind.error_union;

                            if (error_union.union_for_error == error_union.abi) {
                                const undef = V{
                                    .value = .{
                                        .@"comptime" = .undefined,
                                    },
                                    .type = expected_type_index,
                                };
                                const error_union_builder = unit.instructions.append_index(.{
                                    .insert_value = .{
                                        .expression = undef,
                                        .index = 0,
                                        .new_value = v,
                                    },
                                });
                                try builder.appendInstruction(unit, error_union_builder);

                                const final_error_union = unit.instructions.append_index(.{
                                    .insert_value = .{
                                        .expression = .{
                                            .value = .{
                                                .runtime = error_union_builder,
                                            },
                                            .type = expected_type_index,
                                        },
                                        .index = 1,
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
                                try builder.appendInstruction(unit, final_error_union);

                                const value = V{
                                    .value = .{
                                        .runtime = final_error_union,
                                    },
                                    .type = expected_type_index,
                                };
                                return value;
                            } else {
                                const has_padding = switch (unit.types.get(error_union.union_for_error).*) {
                                    .@"struct" => |struct_index| switch (unit.structs.get(struct_index).kind) {
                                        .abi_compatible_error_union => |eu| eu.padding != .null,
                                        else => |t| @panic(@tagName(t)),
                                    },
                                    else => |t| @panic(@tagName(t)),
                                };
                                const undef = V{
                                    .value = .{
                                        .@"comptime" = .undefined,
                                    },
                                    .type = error_union.union_for_error,
                                };

                                const error_union_builder = unit.instructions.append_index(.{
                                    .insert_value = .{
                                        .expression = undef,
                                        .index = 0,
                                        .new_value = v,
                                    },
                                });
                                try builder.appendInstruction(unit, error_union_builder);

                                const final_error_union = unit.instructions.append_index(.{
                                    .insert_value = .{
                                        .expression = .{
                                            .value = .{
                                                .runtime = error_union_builder,
                                            },
                                            .type = error_union.union_for_error,
                                        },
                                        .index = @as(u32, 1) + @intFromBool(has_padding),
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
                                try builder.appendInstruction(unit, final_error_union);

                                const support_alloca = try builder.createStackVariable(unit, context, error_union.union_for_error, null);

                                const pointer_type = try unit.getPointerType(.{
                                    .type = error_union.union_for_error,
                                    .termination = .none,
                                    .mutability = .@"var",
                                    .many = false,
                                    .nullable = false,
                                });

                                const support_store = unit.instructions.append_index(.{
                                    .store = .{
                                        .destination = .{
                                            .value = .{
                                                .runtime = support_alloca,
                                            },
                                            .type = pointer_type,
                                        },
                                        .source = .{
                                            .value = .{
                                                .runtime = final_error_union,
                                            },
                                            .type = error_union.union_for_error,
                                        },
                                    },
                                });
                                try builder.appendInstruction(unit, support_store);

                                const support_load = unit.instructions.append_index(.{
                                    .load = .{
                                        .value = .{
                                            .value = .{
                                                .runtime = support_alloca,
                                            },
                                            .type = pointer_type,
                                        },
                                        .type = expected_type_index,
                                    },
                                });
                                try builder.appendInstruction(unit, support_load);
                                return .{
                                    .value = .{
                                        .runtime = support_load,
                                    },
                                    .type = expected_type_index,
                                };
                            }
                        },
                        .type_to_error_union => return try builder.resolveTypeToErrorUnion(unit, context, expected_type_index, v),
                        .slice_zero_to_no_termination => {
                            const cast = unit.instructions.append_index(.{
                                .cast = .{
                                    .id = .slice_zero_to_no_termination,
                                    .value = v,
                                    .type = expected_type_index,
                                },
                            });

                            try builder.appendInstruction(unit, cast);
                            return .{
                                .value = .{
                                    .runtime = cast,
                                },
                                .type = expected_type_index,
                            };
                        },
                        .pointer_to_array_coerce_to_slice => unreachable,
                        .error_to_all_errors_error_union => unreachable,
                        .error_union_to_all_error_union => unreachable,
                        .error_union_same_error => unreachable,
                        .error_to_all_errors => unreachable,
                    }
                },
                .array => |expected_array_descriptor| {
                    const len = switch (unit.types.get(lookup.declaration.type).*) {
                        .array => |array| array.count,
                        else => |t| @panic(@tagName(t)),
                    };
                    const array_type = try unit.getArrayType(.{
                        .count = expected_array_descriptor.count orelse len,
                        .termination = expected_array_descriptor.termination,
                        .type = expected_array_descriptor.type,
                    });

                    const typecheck_result = try builder.typecheck(unit, context, array_type, lookup.declaration.type);
                    switch (typecheck_result) {
                        .success => return v,
                        else => |t| @panic(@tagName(t)),
                    }
                },
                .cast => return v,
                else => |t| @panic(@tagName(t)),
            }
        } else {
            try write(.panic, "identifier '");
            try write(.panic, identifier);
            try write(.panic, "' not found\n");
            @panic("identifier not found");
            //std.debug.panic("Identifier '{s}' not found in file {s}", .{ identifier, file_path });
        }
    }

    fn resolveTypeToErrorUnion(builder: *Builder, unit: *Unit, context: *const Context, error_union_type_index: Type.Index, value: V) !V {
        _ = context; // autofix
        const error_union_struct_index = unit.types.get(error_union_type_index).@"struct";
        const error_union_struct = unit.structs.get(error_union_struct_index);
        const error_union = error_union_struct.kind.error_union;

        assert(error_union.type != .void);
        assert(error_union.type != .noreturn);

        if (error_union.union_for_type == error_union.abi) {
            const undef = V{
                .value = .{
                    .@"comptime" = .undefined,
                },
                .type = error_union_type_index,
            };
            const error_union_builder = unit.instructions.append_index(.{
                .insert_value = .{
                    .expression = undef,
                    .index = 0,
                    .new_value = value,
                },
            });
            try builder.appendInstruction(unit, error_union_builder);

            const final_error_union = unit.instructions.append_index(.{
                .insert_value = .{
                    .expression = .{
                        .value = .{
                            .runtime = error_union_builder,
                        },
                        .type = error_union_type_index,
                    },
                    .index = 1,
                    .new_value = .{
                        .value = .{
                            .@"comptime" = .{
                                .bool = false,
                            },
                        },
                        .type = .bool,
                    },
                },
            });
            try builder.appendInstruction(unit, final_error_union);

            const result = V{
                .value = .{
                    .runtime = final_error_union,
                },
                .type = error_union_type_index,
            };
            return result;
        } else {
            unreachable;
        }
    }

    fn resolveErrorToAllErrorUnion(builder: *Builder, unit: *Unit, context: *const Context, destination_type_index: Type.Index, error_value: V) !V {
        _ = context; // autofix
        const error_value_type = unit.types.get(error_value.type);
        const error_type = error_value_type.integer.kind.@"error";
        const destination_error_union_type = unit.types.get(destination_type_index);
        const destination_error_union_struct_index = destination_error_union_type.@"struct";
        const destination_error_union = unit.structs.get(destination_error_union_struct_index).kind.error_union;

        const error_id = error_type.id;
        const constant_shifted = @as(u64, error_id) << 32;

        const zero_extend = unit.instructions.append_index(.{
            .cast = .{
                .id = .zero_extend,
                .value = error_value,
                .type = .u64,
            },
        });
        try builder.appendInstruction(unit, zero_extend);

        const or_value = unit.instructions.append_index(.{
            .integer_binary_operation = .{
                .left = .{
                    .value = .{
                        .runtime = zero_extend,
                    },
                    .type = .u64,
                },
                .right = .{
                    .value = .{
                        .@"comptime" = .{
                            .constant_int = .{
                                .value = constant_shifted,
                            },
                        },
                    },
                    .type = .u64,
                },
                .id = .bit_or,
                .signedness = .unsigned,
            },
        });
        try builder.appendInstruction(unit, or_value);

        if (destination_error_union.union_for_error == destination_error_union.abi) {
            const error_union_builder = unit.instructions.append_index(.{
                .insert_value = .{
                    .expression = .{
                        .value = .{
                            .@"comptime" = .undefined,
                        },
                        .type = destination_type_index,
                    },
                    .index = 0,
                    .new_value = .{
                        .value = .{
                            .runtime = or_value,
                        },
                        .type = destination_error_union.@"error",
                    },
                },
            });
            try builder.appendInstruction(unit, error_union_builder);

            const final_error_union = unit.instructions.append_index(.{
                .insert_value = .{
                    .expression = .{
                        .value = .{
                            .runtime = error_union_builder,
                        },
                        .type = destination_type_index,
                    },
                    .index = 1,
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
            try builder.appendInstruction(unit, final_error_union);

            return V{
                .value = .{
                    .runtime = final_error_union,
                },
                .type = destination_type_index,
            };
        } else {
            unreachable;
        }
    }

    fn resolveAssignment(builder: *Builder, unit: *Unit, context: *const Context, node_index: Node.Index) !V {
        const node = unit.getNode(node_index);
        switch (node.id) {
            .assign, .add_assign, .sub_assign, .div_assign, .or_assign => {
                if (unit.getNode(node.left).id == .discard) {
                    _ = try builder.resolveRuntimeValue(unit, context, Type.Expect.none, node.right, .right);
                    return .{
                        .value = .{
                            .@"comptime" = .void,
                        },
                        .type = .void,
                    };
                } else {
                    const left = try builder.resolveRuntimeValue(unit, context, Type.Expect.none, node.left, .left);
                    const expected_right_type = switch (left.value) {
                        .runtime => unit.types.get(left.type).pointer.type,
                        .@"comptime" => |ct| switch (ct) {
                            .global => |global| global.declaration.type,
                            else => |t| @panic(@tagName(t)),
                        },
                        else => |t| @panic(@tagName(t)),
                    };
                    assert(expected_right_type != .null);
                    const right = try builder.resolveRuntimeValue(unit, context, Type.Expect{ .type = expected_right_type }, node.right, .right);
                    const value_to_store = switch (node.id) {
                        .assign => right,
                        else => blk: {
                            const left_load = unit.instructions.append_index(.{
                                .load = .{
                                    .value = left,
                                    .type = expected_right_type,
                                },
                            });

                            try builder.appendInstruction(unit, left_load);

                            switch (unit.types.get(expected_right_type).*) {
                                .integer => |integer| switch (integer.kind) {
                                    .materialized_int => {
                                        const instruction = unit.instructions.append_index(.{
                                            .integer_binary_operation = .{
                                                .left = .{
                                                    .value = .{
                                                        .runtime = left_load,
                                                    },
                                                    .type = expected_right_type,
                                                },
                                                .right = right,
                                                .signedness = integer.signedness,
                                                .id = switch (node.id) {
                                                    .add_assign => .add,
                                                    .sub_assign => .sub,
                                                    .div_assign => .div,
                                                    .or_assign => .bit_or,
                                                    else => |t| @panic(@tagName(t)),
                                                },
                                            },
                                        });
                                        try builder.appendInstruction(unit, instruction);

                                        break :blk V{
                                            .value = .{
                                                .runtime = instruction,
                                            },
                                            .type = expected_right_type,
                                        };
                                    },
                                    else => |t| @panic(@tagName(t)),
                                },
                                else => |t| @panic(@tagName(t)),
                            }
                        },
                    };
                    const store = unit.instructions.append_index(.{
                        .store = .{
                            .destination = left,
                            .source = value_to_store,
                        },
                    });
                    try builder.appendInstruction(unit, store);

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

    fn newBasicBlock(builder: *Builder, unit: *Unit) !BasicBlock.Index {
        const function = unit.function_definitions.get(builder.current_function);
        const basic_block = unit.basic_blocks.append_index(.{
            .instructions = try PinnedArray(Instruction.Index).init(std.mem.page_size),
        });
        _ = function.basic_blocks.append(basic_block);

        return basic_block;
    }

    fn resolveIntegerType(unit: *Unit, node_index: Node.Index) anyerror!Type.Index {
        const node = unit.getNode(node_index);
        const result: Type.Index = switch (node.id) {
            .signed_integer_type,
            .unsigned_integer_type,
            => b: {
                const token_bytes = unit.getExpectedTokenBytes(node.token, switch (node.id) {
                    .signed_integer_type => .keyword_signed_integer,
                    .unsigned_integer_type => .keyword_unsigned_integer,
                    else => unreachable,
                });

                const number_chunk = token_bytes[1..];
                const type_index = try unit.getIntegerType(.{
                    .bit_count = try std.fmt.parseInt(u16, number_chunk, 10),
                    .signedness = switch (node.id) {
                        .signed_integer_type => .signed,
                        .unsigned_integer_type => .unsigned,
                        else => unreachable,
                    },
                    .kind = .materialized_int,
                });
                break :b type_index;
            },
            else => unreachable,
        };

        return result;
    }

    fn resolveArrayType(builder: *Builder, unit: *Unit, context: *const Context, node_index: Node.Index, size_hint: ?usize) !Type.Index {
        const node = unit.getNode(node_index);
        const attribute_node_list = unit.getNodeList(node.left);
        var termination = Type.Termination.none;
        const len_node = unit.getNode(attribute_node_list[0]);
        const len = switch (len_node.id) {
            else => switch (try builder.resolveComptimeValue(unit, context, Type.Expect{ .type = Type.usize }, .{}, attribute_node_list[0], null, .right, &.{}, null, &.{})) {
                .comptime_int => |ct_int| ct_int.value,
                .constant_int => |constant_int| constant_int.value,
                else => |t| @panic(@tagName(t)),
            },
            .discard => size_hint orelse unreachable,
        };

        if (attribute_node_list.len == 3) {
            switch (unit.getNode(attribute_node_list[1]).id) {
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

        const element_type_index = @as(usize, 1) + @intFromBool(attribute_node_list.len == 3);
        const element_type = try builder.resolveType(unit, context, attribute_node_list[element_type_index], &.{});
        const array_type = try unit.getArrayType(.{
            .count = len,
            .type = element_type,
            .termination = termination,
        });
        return array_type;
    }

    fn resolveType(builder: *Builder, unit: *Unit, context: *const Context, node_index: Node.Index, new_parameters: []const V.Comptime) anyerror!Type.Index {
        const node = unit.getNode(node_index);

        const result: Type.Index = switch (node.id) {
            .keyword_noreturn => .noreturn,
            .usize_type => Type.usize,
            .void_type => .void,
            .identifier, .field_access => {
                const resolved_type_value = try builder.resolveComptimeValue(unit, context, Type.Expect{ .type = .type }, .{}, node_index, null, .right, new_parameters, null, &.{});
                return resolved_type_value.type;
            },
            .bool_type => .bool,
            .ssize_type => Type.ssize,
            .signed_integer_type,
            .unsigned_integer_type,
            => b: {
                break :b try resolveIntegerType(unit, node_index);
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
                        .self,
                        .any,
                        => {
                            if (element_type_index != .null) {
                                unreachable;
                            }

                            element_type_index = try builder.resolveType(unit, context, element_node_index, &.{});
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

                const pointer_type = try unit.getPointerType(.{
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
                        .field_access,
                        => {
                            if (element_type_index != .null) {
                                unreachable;
                            }

                            element_type_index = try builder.resolveType(unit, context, element_node_index, &.{});
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

                const slice_type = try unit.getSliceType(.{
                    .mutability = mutability,
                    .child_type = element_type_index,
                    .child_pointer_type = try unit.getPointerType(.{
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
                const element_type_index = try builder.resolveType(unit, context, node.left, &.{});
                const element_type = unit.types.get(element_type_index);
                const r = switch (element_type.*) {
                    .pointer => |pointer| b: {
                        var nullable_pointer = pointer;
                        assert(!nullable_pointer.nullable);
                        nullable_pointer.nullable = true;
                        break :b try unit.getPointerType(nullable_pointer);
                    },
                    .slice => |slice| b: {
                        var nullable_slice = slice;
                        assert(!nullable_slice.nullable);
                        nullable_slice.nullable = true;
                        break :b try unit.getSliceType(nullable_slice);
                    },
                    else => b: {
                        const optional_type = try unit.getOptionalType(element_type_index);
                        break :b optional_type;
                    },
                };
                break :blk r;
            },
            .function_prototype => block: {
                var b = false;
                const fp = try builder.resolveFunctionPrototype(unit, context, node_index, .{}, null, &.{}, null, null, null, &b, null);
                break :block fp;
            },
            .error_union => blk: {
                assert(node.left != .null);
                assert(node.right != .null);

                const err = try builder.resolveType(unit, context, node.left, &.{});
                const ty = try builder.resolveType(unit, context, node.right, &.{});

                const error_union = try builder.getErrorUnionType(unit, context, .{
                    .@"error" = err,
                    .type = ty,
                });

                break :blk error_union;
            },
            .all_errors => blk: {
                if (unit.all_errors != .null) {
                    break :blk unit.all_errors;
                } else {
                    const token_debug_info = builder.getTokenDebugInfo(unit, node.token);
                    unit.all_errors = unit.types.append_index(.{
                        .integer = .{
                            .bit_count = 64,
                            .signedness = .unsigned,
                            .kind = .{
                                .@"error" = .{
                                    .scope = .{
                                        .scope = .{
                                            .file = builder.current_file,
                                            .line = token_debug_info.line,
                                            .column = token_debug_info.column,
                                            .kind = .error_type,
                                            .local = false,
                                            .level = builder.current_scope.level + 1,
                                            .parent = &unit.scope.scope,
                                            .declarations = try PinnedHashMap(u32, *Debug.Declaration).init(std.mem.page_size),
                                        },
                                    },
                                    .id = std.math.maxInt(u32),
                                    .fields = .{
                                        .pointer = undefined,
                                        .length = 0,
                                        .capacity = 0,
                                    },
                                },
                            },
                        },
                    });
                    break :blk unit.all_errors;
                }
            },
            // This is a data structures with parameters
            .call => {
                // const parameterized_type_index = try builder.resolveType(unit, context, node.left);
                const parameter_nodes = unit.getNodeList(node.right);
                var parameters = try context.arena.new_array(V.Comptime, parameter_nodes.len);

                for (parameter_nodes, 0..) |parameter_node_index, i| {
                    const parameter = try builder.resolveComptimeValue(unit, context, Type.Expect.none, .{}, parameter_node_index, null, .right, &.{}, null, &.{});
                    parameters[i] = parameter;
                }

                const instantiated_type = try builder.resolveType(unit, context, node.left, parameters);
                const instantiated_ty = unit.types.get(instantiated_type);
                assert(instantiated_ty.* != .polymorphic);

                return instantiated_type;
            },
            .self => {
                var scope = builder.current_scope;
                while (true) {
                    const global_scope: *Debug.Scope.Global = switch (scope.kind) {
                        .struct_type => @fieldParentPtr("scope", scope),
                        .function => {
                            scope = scope.parent.?;
                            continue;
                        },
                        else => |t| @panic(@tagName(t)),
                    };
                    _ = &scope;
                    const type_index = global_scope.type;
                    assert(type_index != .null);
                    const ty = unit.types.get(type_index);
                    assert(ty.* != .polymorphic);
                    return type_index;
                }
            },
            .any => .any,
            .type => .type,
            else => |t| @panic(@tagName(t)),
        };

        return result;
    }

    fn get_builtin_declaration(builder: *Builder, unit: *Unit, context: *const Context, name: []const u8) !*Debug.Declaration.Global {
        const std_file_index = try builder.resolveImportStringLiteral(unit, context, Type.Expect{ .type = .type }, "std");
        const std_file = unit.files.get(std_file_index);
        const std_file_struct_index = unit.types.get(std_file.scope.type).@"struct";
        const std_file_struct = unit.structs.get(std_file_struct_index);
        const builtin_hash = try unit.processIdentifier(context, "builtin");

        const look_in_parent_scopes = false;
        if (std_file_struct.kind.@"struct".scope.scope.lookupDeclaration(builtin_hash, look_in_parent_scopes)) |lookup| {
            const builtin_declaration = try builder.referenceGlobalDeclaration(unit, context, &std_file_struct.kind.@"struct".scope.scope, lookup.declaration, .{}, &.{}, null, &.{});
            switch (builtin_declaration.initial_value) {
                .type => |builtin_type_index| {
                    const builtin_type_struct_index = unit.types.get(builtin_type_index).@"struct";
                    const builtin_type_struct = &unit.structs.get(builtin_type_struct_index).kind.@"struct";
                    const hash = try unit.processIdentifier(context, name);
                    if (builtin_type_struct.scope.scope.lookupDeclaration(hash, look_in_parent_scopes)) |declaration_lookup| {
                        const declaration_global = try builder.referenceGlobalDeclaration(unit, context, declaration_lookup.scope, declaration_lookup.declaration, .{}, &.{}, null, &.{});
                        return declaration_global;
                    } else {
                        unreachable;
                    }
                },
                else => |t| @panic(@tagName(t)),
            }
        } else {
            @panic("Internal compiler error");
        }
    }

    fn resolveFunctionPrototype(builder: *Builder, unit: *Unit, context: *const Context, node_index: Node.Index, global_attributes: Debug.Declaration.Global.Attributes, member: ?V, polymorphic_argument_nodes: []const Node.Index, maybe_scope: ?*Debug.Scope.Function, maybe_comptime_argument_declarations: ?*[]const ComptimeParameterDeclaration, maybe_comptime_argument_instantiations: ?*[]const V.Comptime, is_member: *bool, maybe_global: ?*Debug.Declaration.Global) !Type.Index {
        _ = maybe_global; // autofix
        const node = unit.getNode(node_index);
        assert(node.id == .function_prototype);
        const attribute_and_return_type_node_list = unit.getNodeList(node.right);
        assert(attribute_and_return_type_node_list.len >= 1);
        const attribute_node_list = attribute_and_return_type_node_list[0 .. attribute_and_return_type_node_list.len - 1];
        const return_type_node_index = attribute_and_return_type_node_list[attribute_and_return_type_node_list.len - 1];

        const function_prototype_index = unit.function_prototypes.append_index(.{});
        const function_prototype = unit.function_prototypes.get(function_prototype_index);

        var is_naked: bool = false;

        // Resolve attributes
        for (attribute_node_list) |attribute_node_index| {
            const attribute_node = unit.getNode(attribute_node_index);
            switch (attribute_node.id) {
                .function_attribute_naked => is_naked = true,
                .function_attribute_cc => {
                    if (unit.cc_type == .null) {
                        const calling_convention_declaration = try builder.get_builtin_declaration(unit, context, "CallingConvention");
                        unit.cc_type = calling_convention_declaration.initial_value.type;
                    }

                    assert(unit.cc_type != .null);
                    const cc = try builder.resolveComptimeValue(unit, context, Type.Expect{ .type = unit.cc_type }, .{}, attribute_node.left, null, .right, &.{}, null, &.{});
                    switch (cc) {
                        .enum_value => |enum_field_index| {
                            const enum_field = unit.enum_fields.get(enum_field_index);
                            const enum_name = unit.getIdentifier(enum_field.name);

                            function_prototype.calling_convention = enumFromString(Function.CallingConvention, enum_name) orelse unreachable;
                        },
                        else => |t| @panic(@tagName(t)),
                    }
                },
                else => |t| @panic(@tagName(t)),
            }
        }

        if (global_attributes.contains(.@"export") or global_attributes.contains(.@"extern")) {
            if (function_prototype.calling_convention == .auto) {
                @panic("Function prototype must have a non-automatic calling calling convention");
            }
        }

        function_prototype.attributes = .{
            .naked = is_naked,
        };

        if (node.left != .null) {
            const argument_node_list = unit.getNodeList(node.left);
            var argument_types = try context.arena.new_array(Type.Index, argument_node_list.len);
            argument_types.len = 0;

            if (polymorphic_argument_nodes.len > 0) {
                var comptime_parameter_instantiations = BoundedArray(V.Comptime, 512){};
                var comptime_parameter_declarations = BoundedArray(ComptimeParameterDeclaration, 512){};
                is_member.* = polymorphic_argument_nodes.len + 1 == argument_node_list.len;
                const scope = maybe_scope orelse unreachable;
                assert(&scope.scope == builder.current_scope);

                if (is_member.*) {
                    const member_node = unit.getNode(argument_node_list[0]);
                    const member_type = try builder.resolveType(unit, context, member_node.left, &.{});
                    const member_value = member orelse unreachable;

                    if (member_value.type != member_type) {
                        unreachable;
                    }

                    try builder.put_argument_in_scope(unit, context, member_node, 0, member_type);
                    const index = argument_types.len;
                    argument_types.len += 1;
                    argument_types[index] = member_type;
                }

                for (argument_node_list[@intFromBool(is_member.*)..], polymorphic_argument_nodes, 0..) |argument_declaration_node_index, polymorphic_call_argument_node_index, index| {
                    const argument_declaration_node = unit.getNode(argument_declaration_node_index);
                    const argument_type = try builder.resolveType(unit, context, argument_declaration_node.left, &.{});

                    const polymorphic_call_argument_node = unit.getNode(polymorphic_call_argument_node_index);
                    switch (argument_declaration_node.id) {
                        .comptime_argument_declaration => switch (polymorphic_call_argument_node.id) {
                            .comptime_expression => {
                                const comptime_argument = try builder.resolveComptimeValue(unit, context, Type.Expect{ .type = argument_type }, .{}, polymorphic_call_argument_node.left, null, .right, &.{}, null, &.{});
                                const name = unit.getExpectedTokenBytes(@enumFromInt(@intFromEnum(argument_declaration_node.token) + 1), .identifier);
                                const name_hash = try unit.processIdentifier(context, name);
                                const debug_info = builder.getTokenDebugInfo(unit, argument_declaration_node.token);
                                comptime_parameter_declarations.appendAssumeCapacity(.{
                                    .type = argument_type,
                                    .name_token = argument_declaration_node.token,
                                    .index = @intCast(index),
                                });

                                comptime_parameter_instantiations.appendAssumeCapacity(comptime_argument);

                                const look_in_parent_scopes = true;
                                if (builder.current_scope.lookupDeclaration(name_hash, look_in_parent_scopes)) |_| {
                                    @panic("Symbol already in scope");
                                    // std.debug.panic("Symbol with name '{s}' already declarared on scope", .{argument_name});
                                }

                                const comptime_parameter = unit.global_declarations.append(.{
                                    .declaration = .{
                                        .scope = builder.current_scope,
                                        .name = name_hash,
                                        .type = argument_type,
                                        .line = debug_info.line,
                                        .column = debug_info.column,
                                        .mutability = .@"const",
                                        .kind = .global,
                                    },
                                    .initial_value = comptime_argument,
                                    .type_node_index = argument_declaration_node.left,
                                    .attributes = .{},
                                });
                                try builder.current_scope.declarations.put_no_clobber(name_hash, &comptime_parameter.declaration);
                            },
                            else => |t| @panic(@tagName(t)),
                        },
                        .argument_declaration => {
                            const argument_type_index = try builder.resolveType(unit, context, argument_declaration_node.left, &.{});
                            const i = argument_types.len;
                            argument_types.len += 1;
                            argument_types[i] = argument_type_index;
                            try builder.put_argument_in_scope(unit, context, argument_declaration_node, index, argument_type_index);
                        },
                        else => unreachable,
                    }
                }

                function_prototype.has_polymorphic_parameters = true;

                assert(comptime_parameter_declarations.len > 0);
                assert(comptime_parameter_instantiations.len > 0);

                const heap_comptime_parameter_declarations = try context.arena.new_array(ComptimeParameterDeclaration, comptime_parameter_declarations.len);
                const heap_comptime_parameter_instantiations = try context.arena.new_array(V.Comptime, comptime_parameter_instantiations.len);
                @memcpy(heap_comptime_parameter_declarations, comptime_parameter_declarations.slice());
                @memcpy(heap_comptime_parameter_instantiations, comptime_parameter_instantiations.slice());

                maybe_comptime_argument_declarations.?.* = heap_comptime_parameter_declarations;
                maybe_comptime_argument_instantiations.?.* = heap_comptime_parameter_instantiations;
            } else {
                if (maybe_comptime_argument_instantiations) |p| {
                    p.* = &.{};
                }
                if (maybe_comptime_argument_declarations) |p| {
                    p.* = &.{};
                }
                for (argument_node_list, 0..) |argument_node_index, i| {
                    const argument_node = unit.getNode(argument_node_index);
                    assert(argument_node.id == .argument_declaration);

                    const argument_type_index = try builder.resolveType(unit, context, argument_node.left, &.{});

                    const index = argument_types.len;
                    argument_types.len += 1;
                    argument_types[index] = argument_type_index;

                    if (maybe_scope) |scope| {
                        assert(&scope.scope == builder.current_scope);
                        try builder.put_argument_in_scope(unit, context, argument_node, i, argument_type_index);
                    }
                }
            }

            function_prototype.argument_types = argument_types;
        } else {
            if (maybe_comptime_argument_instantiations) |p| {
                p.* = &.{};
            }
            if (maybe_comptime_argument_declarations) |p| {
                p.* = &.{};
            }
        }

        function_prototype.return_type = try builder.resolveType(unit, context, return_type_node_index, &.{});

        try builder.resolveFunctionPrototypeAbi(unit, context, function_prototype);

        const function_prototype_type_index = unit.types.append_index(.{
            .function = function_prototype_index,
        });

        return function_prototype_type_index;
    }

    fn put_argument_in_scope(builder: *Builder, unit: *Unit, context: *const Context, argument_node: *const Node, argument_index: usize, argument_type_index: Type.Index) !void {
        const argument_name = switch (unit.token_buffer.tokens.get(argument_node.token).id) {
            .identifier => b: {
                const argument_name = unit.getExpectedTokenBytes(argument_node.token, .identifier);

                break :b argument_name;
            },
            .discard => b: {
                var buffer: [65]u8 = undefined;
                const formatted_int = format_int(&buffer, argument_index, 10, false);
                break :b try std.mem.concat(context.allocator, u8, &.{ "_anon_arg_", formatted_int });
            },
            else => |t| @panic(@tagName(t)),
        };
        const argument_name_hash = try unit.processIdentifier(context, argument_name);
        const look_in_parent_scopes = true;
        if (builder.current_scope.lookupDeclaration(argument_name_hash, look_in_parent_scopes)) |_| {
            @panic("Symbol already in scope");
            // std.debug.panic("Symbol with name '{s}' already declarared on scope", .{argument_name});
        }

        const argument_token_debug_info = builder.getTokenDebugInfo(unit, argument_node.token);
        const argument_declaration = unit.argument_declarations.append(.{
            .declaration = .{
                .scope = builder.current_scope,
                .name = argument_name_hash,
                .type = argument_type_index,
                .mutability = .@"const",
                .line = argument_token_debug_info.line,
                .column = argument_token_debug_info.column,
                .kind = .argument,
            },
            .index = @intCast(argument_index),
        });

        try builder.current_scope.declarations.put_no_clobber(argument_name_hash, &argument_declaration.declaration);
    }

    fn classify_argument_type_aarch64(unit: *Unit, type_index: Type.Index) Function.AbiInfo {
        if (type_index == .void or type_index == .noreturn) return Function.AbiInfo{
            .kind = .ignore,
        };

        // TODO:
        const is_illegal_vector = false;
        if (is_illegal_vector) {
            unreachable;
        }

        const ty = unit.types.get(type_index);
        const size = ty.getAbiSize(unit);

        if (!ty.is_aggregate()) {
            const extend = switch (ty.*) {
                else => |t| @panic(@tagName(t)),
                .integer => |integer| integer.bit_count < 32,
                .pointer => false,
            };

            if (extend) {
                const signed = switch (ty.*) {
                    else => |t| @panic(@tagName(t)),
                    .integer => |integer| integer.signedness == .signed,
                    .pointer => false,
                };

                return Function.AbiInfo{
                    .kind = .direct,
                    .attributes = .{
                        .zero_extend = !signed,
                        .sign_extend = signed,
                    },
                };
            } else {
                return Function.AbiInfo{
                    .kind = .direct,
                };
            }
        } else {
            assert(size > 0);

            if (ty.get_homogeneous_aggregate(unit)) |homogeneous_aggregate| {
                _ = homogeneous_aggregate;
                unreachable;
            } else if (size <= 16) {
                const base_alignment = ty.getAbiAlignment(unit);
                const is_appcs = false;
                const alignment: u32 = switch (is_appcs) {
                    true => if (base_alignment < 16) 8 else 16,
                    false => @max(base_alignment, 8),
                };
                assert(alignment == 8 or alignment == 16);

                const aligned_size = align_forward(size, alignment);
                if (alignment == 16) {
                    unreachable;
                } else {
                    const m = aligned_size / alignment;
                    if (m > 1) {
                        const array_type = unit.getArrayType(.{
                            .type = .u64,
                            .count = m,
                            .termination = .none,
                        }) catch unreachable;
                        return .{
                            .kind = .{
                                .direct_coerce = array_type,
                            },
                        };
                    } else {
                        return .{
                            .kind = .{
                                .direct_coerce = .u64,
                            },
                        };
                    }
                }
            } else {
                const alignment = ty.getAbiAlignment(unit);
                assert(alignment > 0);
                const pointer_type = unit.getPointerType(.{
                    .type = type_index,
                    .termination = .none,
                    .mutability = .@"var",
                    .many = false,
                    .nullable = false,
                }) catch unreachable;
                return .{
                    .kind = .{
                        .indirect = .{
                            .type = type_index,
                            .pointer = pointer_type,
                            .alignment = alignment,
                        },
                    },
                };
            }
        }
    }

    fn classify_return_type_aarch64(builder: *Builder, unit: *Unit, context: *const Context, type_index: Type.Index) Function.AbiInfo {
        _ = context; // autofix
        _ = builder;
        if (type_index == .void or type_index == .noreturn) return Function.AbiInfo{
            .kind = .ignore,
        };
        const ty = unit.types.get(type_index);
        const size = ty.getAbiSize(unit);

        const is_vector = false;
        if (is_vector and size > 16) {
            unreachable;
        }

        if (!ty.is_aggregate()) {
            const extend = switch (ty.*) {
                else => |t| @panic(@tagName(t)),
                .integer => |integer| integer.bit_count < 32,
                .pointer => false,
            };

            if (extend) {
                const signed = switch (ty.*) {
                    else => |t| @panic(@tagName(t)),
                    .integer => |integer| integer.signedness == .signed,
                    .pointer => false,
                };

                return Function.AbiInfo{
                    .kind = .direct,
                    .attributes = .{
                        .zero_extend = !signed,
                        .sign_extend = signed,
                    },
                };
            } else {
                return Function.AbiInfo{
                    .kind = .direct,
                };
            }
        } else {
            assert(size > 0);
            const is_variadic = false;
            const is_aarch64_32 = false;
            const maybe_homogeneous_aggregate = ty.get_homogeneous_aggregate(unit);

            if (maybe_homogeneous_aggregate != null and !(is_aarch64_32 and is_variadic)) {
                unreachable;
            } else if (size <= 16) {
                if (size <= 8 and @import("builtin").cpu.arch.endian() == .little) {
                    return .{
                        .kind = .{
                            .direct_coerce = unit.getIntegerType(.{
                                .bit_count = @intCast(size * 8),
                                .signedness = .unsigned,
                                .kind = .materialized_int,
                            }) catch unreachable,
                        },
                    };
                } else {
                    const alignment = ty.getAbiAlignment(unit);
                    const aligned_size: u16 = @intCast(align_forward(size, 8));
                    if (alignment < 16 and aligned_size == 16) {
                        const array_type = unit.getArrayType(.{
                            .count = 2,
                            .type = .u64,
                            .termination = .none,
                        }) catch unreachable;
                        return .{
                            .kind = .{
                                .direct_coerce = array_type,
                            },
                        };
                    } else {
                        const integer_t = unit.getIntegerType(.{
                            .kind = .materialized_int,
                            .bit_count = aligned_size * 8,
                            .signedness = .unsigned,
                        }) catch unreachable;
                        return .{
                            .kind = .{
                                .direct_coerce = integer_t,
                            },
                        };
                    }
                }
            } else {
                const alignment = ty.getAbiAlignment(unit);
                assert(alignment > 0);
                const pointer_type = unit.getPointerType(.{
                    .type = type_index,
                    .termination = .none,
                    .mutability = .@"var",
                    .many = false,
                    .nullable = false,
                }) catch unreachable;
                return .{
                    .kind = .{
                        .indirect = .{
                            .type = type_index,
                            .pointer = pointer_type,
                            .alignment = alignment,
                        },
                    },
                    .attributes = .{
                        .by_value = true,
                    },
                };
            }
        }
    }

    fn resolveFunctionPrototypeAbiAarch64(builder: *Builder, unit: *Unit, context: *const Context, function_prototype: *Function.Prototype) !void {
        var parameter_types_abi = BoundedArray(Function.AbiInfo, 512){};
        const return_type_abi = builder.classify_return_type_aarch64(unit, context, function_prototype.return_type);
        for (function_prototype.argument_types) |argument_type_index| {
            const abi_arg = classify_argument_type_aarch64(unit, argument_type_index);
            parameter_types_abi.appendAssumeCapacity(abi_arg);
        }

        function_prototype.abi.return_type_abi = return_type_abi;

        const parameter_abis = try context.arena.new_array(Function.AbiInfo, parameter_types_abi.len);
        @memcpy(parameter_abis, parameter_types_abi.slice());
        function_prototype.abi.parameter_types_abi = parameter_abis;
    }

    fn resolveFunctionPrototypeAbi(builder: *Builder, unit: *Unit, context: *const Context, function_prototype: *Function.Prototype) !void {
        switch (function_prototype.calling_convention) {
            .auto => {
                function_prototype.abi.return_type = function_prototype.return_type;
                function_prototype.abi.parameter_types = function_prototype.argument_types;
                function_prototype.abi.return_type_abi = .{
                    .kind = if (function_prototype.return_type == .void or function_prototype.return_type == .noreturn) .ignore else .direct,
                };

                var parameter_abis = try context.arena.new_array(Function.AbiInfo, function_prototype.argument_types.len);

                for (0..function_prototype.argument_types.len) |i| {
                    const index: u16 = @intCast(i);
                    parameter_abis[i] = .{
                        .kind = .direct,
                        .indices = .{ index, index + 1 },
                    };
                }

                function_prototype.abi.parameter_types_abi = parameter_abis;
            },
            .c => {
                switch (unit.descriptor.arch) {
                    .x86_64 => switch (unit.descriptor.os) {
                        .linux => try builder.resolveFunctionPrototypeAbiSystemVx86_64(unit, context, function_prototype),
                        else => |t| @panic(@tagName(t)),
                    },
                    .aarch64 => try builder.resolveFunctionPrototypeAbiAarch64(unit, context, function_prototype),
                }

                var abi_parameter_types = BoundedArray(Type.Index, 512){};
                const abi_return_type = switch (function_prototype.abi.return_type_abi.kind) {
                    .ignore => function_prototype.return_type,
                    .direct_pair => |direct_pair| try unit.getTwoStruct(direct_pair),
                    .direct => function_prototype.return_type,
                    .indirect => |indirect| b: {
                        abi_parameter_types.appendAssumeCapacity(indirect.pointer);
                        break :b .void;
                    },
                    .direct_coerce => |coerced_type| coerced_type,
                    else => |t| @panic(@tagName(t)),
                };

                for (function_prototype.abi.parameter_types_abi, function_prototype.argument_types) |*const_parameter_abi, parameter_type_index| {
                    const start: u16 = @intCast(abi_parameter_types.len);
                    switch (const_parameter_abi.kind) {
                        .direct => abi_parameter_types.appendAssumeCapacity(parameter_type_index),
                        .direct_coerce => |coerced_type| abi_parameter_types.appendAssumeCapacity(coerced_type),
                        .indirect => |indirect| abi_parameter_types.appendAssumeCapacity(indirect.pointer),
                        .direct_pair => |direct_pair| {
                            abi_parameter_types.appendAssumeCapacity(direct_pair[0]);
                            abi_parameter_types.appendAssumeCapacity(direct_pair[1]);
                        },
                        else => |t| @panic(@tagName(t)),
                    }

                    const parameter_abi: *Function.AbiInfo = @constCast(const_parameter_abi);
                    const end: u16 = @intCast(abi_parameter_types.len);
                    parameter_abi.indices = .{ start, end };
                }

                const heap_abi_parameter_types = try context.arena.new_array(Type.Index, abi_parameter_types.len);
                @memcpy(heap_abi_parameter_types, abi_parameter_types.slice());

                function_prototype.abi.return_type = abi_return_type;
                function_prototype.abi.parameter_types = heap_abi_parameter_types;
            },
        }

        assert(function_prototype.return_type != .null);
        assert(function_prototype.abi.return_type != .null);
    }

    fn resolveFunctionPrototypeAbiSystemVx86_64(builder: *Builder, unit: *Unit, context: *const Context, function_prototype: *Function.Prototype) !void {
        var parameter_types_abi = BoundedArray(Function.AbiInfo, 512){};
        const return_abi = builder.classify_return_type_systemv_x86_64(unit, context, function_prototype.return_type);
        var available_registers = SystemV_x86_64_Registers{
            .gp_registers = 6,
            .sse_registers = 8,
        };
        if (return_abi.kind == .indirect) {
            available_registers.gp_registers -= 1;
        }

        const return_by_reference = false;
        if (return_by_reference) {
            unreachable;
        }

        for (function_prototype.argument_types) |parameter_type_index| {
            const parameter_classification = builder.classify_argument_type_systemv_x86_64(unit, context, parameter_type_index, available_registers.gp_registers);

            const parameter_abi = if (available_registers.sse_registers < parameter_classification.needed_registers.sse_registers or available_registers.gp_registers < parameter_classification.needed_registers.gp_registers) b: {
                break :b indirect_result(unit, parameter_type_index, available_registers.gp_registers);
            } else b: {
                available_registers.gp_registers -= parameter_classification.needed_registers.gp_registers;
                available_registers.sse_registers -= parameter_classification.needed_registers.sse_registers;
                break :b parameter_classification.abi;
            };
            parameter_types_abi.appendAssumeCapacity(parameter_abi);
        }

        function_prototype.abi.return_type_abi = return_abi;
        const abi_infos = try context.arena.new_array(Function.AbiInfo, parameter_types_abi.len);
        @memcpy(abi_infos, parameter_types_abi.slice());
        function_prototype.abi.parameter_types_abi = abi_infos;
    }

    const Class_SystemVx86_64 = enum {
        no_class,
        memory,
        integer,
        sse,
        sseup,

        fn merge(accumulator: Class_SystemVx86_64, field: Class_SystemVx86_64) Class_SystemVx86_64 {
            assert(accumulator != .memory);
            if (accumulator == field) {
                return accumulator;
            } else {
                var a = accumulator;
                var f = field;
                if (@intFromEnum(accumulator) > @intFromEnum(field)) {
                    a = field;
                    f = accumulator;
                }

                return switch (a) {
                    .no_class => f,
                    .memory => .memory,
                    .integer => .integer,
                    .sse, .sseup => .sse,
                };
            }
        }
    };

    fn classify_systemv_x86_64(builder: *Builder, unit: *Unit, context: *const Context, type_index: Type.Index, base_offset: u64) [2]Class_SystemVx86_64 {
        var result: [2]Class_SystemVx86_64 = undefined;
        const is_memory = base_offset >= 8;
        const current_index = @intFromBool(is_memory);
        const not_current_index = @intFromBool(!is_memory);
        assert(current_index != not_current_index);
        result[current_index] = .memory;
        result[not_current_index] = .no_class;

        const ty = unit.types.get(type_index);
        switch (ty.*) {
            .void, .noreturn => result[current_index] = .no_class,
            .pointer => result[current_index] = .integer,
            .integer => |*integer| switch (type_index) {
                .u8,
                .u16,
                .u32,
                .u64,
                .s8,
                .s16,
                .s32,
                .s64,
                .bool,
                => result[current_index] = .integer,
                else => switch (integer.kind) {
                    .comptime_int => unreachable,
                    else => return builder.classify_systemv_x86_64(unit, context, unit.getIntegerType(.{
                        .bit_count = integer.bit_count,
                        .signedness = integer.signedness,
                        .kind = .materialized_int,
                    }) catch unreachable, base_offset),
                },
            },
            .@"struct" => |struct_index| switch (unit.structs.get(struct_index).kind) {
                .@"struct" => |*struct_type| {
                    const size = unit.types.get(type_index).getAbiSize(unit);
                    const alignment = unit.types.get(type_index).getAbiAlignment(unit);
                    if (size <= 64) {
                        const has_variable_array = false;
                        if (!has_variable_array) {
                            result[current_index] = .no_class;
                            const is_union = false;

                            var member_offset: u32 = 0;
                            for (struct_type.fields) |field_index| {
                                const field = unit.struct_fields.get(field_index);
                                const field_type = unit.types.get(field.type);
                                const offset = base_offset + member_offset;
                                const member_size = field_type.getAbiSize(unit);
                                const member_alignment = field_type.getAbiAlignment(unit);
                                member_offset = @intCast(align_forward(member_offset + member_size, alignment));
                                // TODO:
                                const native_vector_size = 16;
                                if (size > 16 and ((!is_union and size != member_size) or size > native_vector_size)) {
                                    result[0] = .memory;
                                    const r = classify_post_merge(size, result);
                                    return r;
                                }

                                if (offset % member_alignment != 0) {
                                    result[0] = .memory;
                                    const r = classify_post_merge(size, result);
                                    return r;
                                }

                                const member_classes = builder.classify_systemv_x86_64(unit, context, field.type, offset);
                                for (&result, member_classes) |*r, m| {
                                    const merge_result = r.merge(m);
                                    r.* = merge_result;
                                }

                                if (result[0] == .memory or result[1] == .memory) break;
                            }

                            result = classify_post_merge(size, result);
                        }
                    }
                },
                else => |t| @panic(@tagName(t)),
            },
            .array => |array| {
                const element_type = unit.types.get(array.type);
                const element_size = element_type.getAbiSize(unit);
                const element_alignment = element_type.getAbiAlignment(unit);
                const array_size = ty.getAbiSize(unit);

                if (array_size <= 64) {
                    if (base_offset % element_alignment == 0) {
                        result[current_index] = .no_class;

                        const vector_size = 16;
                        if (array_size > 16 and (array_size != element_size or array_size > vector_size)) {
                            unreachable;
                        } else {
                            var offset = base_offset;

                            for (0..array.count) |_| {
                                const element_classes = builder.classify_systemv_x86_64(unit, context, array.type, offset);
                                offset += element_size;
                                const merge_result = [2]Class_SystemVx86_64{ Class_SystemVx86_64.merge(result[0], element_classes[0]), Class_SystemVx86_64.merge(result[1], element_classes[1]) };
                                result = merge_result;
                                if (result[0] == .memory or result[1] == .memory) {
                                    break;
                                }
                            }

                            const final_result = classify_post_merge(array_size, result);
                            assert(final_result[1] != .sseup or final_result[0] != .sse);
                            result = final_result;
                        }
                    } else {
                        unreachable;
                    }
                } else {
                    unreachable;
                }
            },
            else => |t| @panic(@tagName(t)),
        }

        return result;
    }

    fn classify_post_merge(size: u64, classes: [2]Class_SystemVx86_64) [2]Class_SystemVx86_64 {
        if (classes[1] == .memory) {
            return .{ .memory, .memory };
        } else if (size > 16 and (classes[0] != .sse or classes[1] != .sseup)) {
            return .{ .memory, classes[1] };
        } else if (classes[1] == .sseup and classes[0] != .sse and classes[0] != .sseup) {
            return .{ classes[0], .sse };
        } else {
            return classes;
        }
    }

    const Member = struct {
        type: Type.Index,
        offset: u32,
    };

    fn get_member_at_offset(unit: *Unit, struct_type_index: Type.Index, struct_type_descriptor: *Struct.Descriptor, offset: u32) ?Member {
        const struct_type = unit.types.get(struct_type_index);
        const struct_size = struct_type.getAbiSize(unit);
        const struct_alignment = struct_type.getAbiAlignment(unit);
        if (struct_size <= offset) return null;
        var offset_it: u32 = 0;
        var last_match: ?Member = null;

        for (struct_type_descriptor.fields) |field_index| {
            const field = unit.struct_fields.get(field_index);
            if (offset_it > offset) break;
            last_match = .{
                .type = field.type,
                .offset = offset_it,
            };
            offset_it = @intCast(align_forward(offset_it + unit.types.get(field.type).getAbiSize(unit), struct_alignment));
        }

        assert(last_match != null);
        return last_match;
    }

    fn contains_no_user_data(builder: *Builder, unit: *Unit, context: *const Context, type_index: Type.Index, start: u32, end: u32) bool {
        const ty = unit.types.get(type_index);
        const size = ty.getAbiSize(unit);
        return if (size <= start) true else switch (ty.*) {
            .@"struct" => |struct_index| switch (unit.structs.get(struct_index).kind) {
                .@"struct" => |*struct_type| {
                    var offset: u32 = 0;

                    for (struct_type.fields) |field_index| {
                        const field = unit.struct_fields.get(field_index);
                        if (offset >= end) break;
                        const field_type = unit.types.get(field.type);
                        const field_start = if (offset < start) start - offset else 0;
                        if (!builder.contains_no_user_data(unit, context, field.type, field_start, end - offset)) return false;
                        offset += field_type.getAbiSize(unit);
                    }

                    return true;
                },
                else => |t| @panic(@tagName(t)),
            },
            .array => |array| {
                const element_type = unit.types.get(array.type);
                const element_size = element_type.getAbiSize(unit);

                for (0..array.count) |i| {
                    const offset: u32 = @intCast(i * element_size);
                    if (offset >= end) break;
                    const element_start = if (offset < start) start - offset else 0;
                    if (!builder.contains_no_user_data(unit, context, array.type, element_start, end - offset)) return false;
                }

                return true;
            },
            else => false,
        };
    }

    fn get_int_type_at_offset_system_v_x86_64(builder: *Builder, unit: *Unit, context: *const Context, type_index: Type.Index, offset: u32, source_type_index: Type.Index, source_offset: u32) Type.Index {
        const ty = unit.types.get(type_index);
        switch (ty.*) {
            .pointer => return if (offset == 0) type_index else unreachable,
            .integer => |integer| switch (type_index) {
                .u64, .s64 => return type_index,
                .bool, .u8, .u16, .u32, .s8, .s16, .s32 => {
                    if (offset != 0) unreachable;
                    const start = source_offset + ty.getAbiSize(unit);
                    const end = source_offset + 8;
                    if (builder.contains_no_user_data(unit, context, source_type_index, start, end)) {
                        return type_index;
                    }
                },
                else => return builder.get_int_type_at_offset_system_v_x86_64(unit, context, unit.getIntegerType(.{
                    .bit_count = integer.bit_count,
                    .signedness = integer.signedness,
                    .kind = .materialized_int,
                }) catch unreachable, offset, source_type_index, source_offset),
            },
            .@"struct" => |struct_index| switch (unit.structs.get(struct_index).kind) {
                .@"struct" => |*struct_type| {
                    if (get_member_at_offset(unit, type_index, struct_type, offset)) |member| {
                        return builder.get_int_type_at_offset_system_v_x86_64(unit, context, member.type, offset - member.offset, source_type_index, source_offset);
                    }
                    unreachable;
                },
                else => |t| @panic(@tagName(t)),
            },
            .array => |array| {
                const element_type = unit.types.get(array.type);
                const element_size = element_type.getAbiSize(unit);
                const element_offset = (offset / element_size) * element_size;
                return builder.get_int_type_at_offset_system_v_x86_64(unit, context, array.type, offset - element_offset, source_type_index, source_offset);
            },
            else => |t| @panic(@tagName(t)),
        }

        const source_type = unit.types.get(source_type_index);
        const source_size = source_type.getAbiSize(unit);
        if (source_size - source_offset > 8) {
            return .u64;
        } else {
            const byte_count: u16 = @intCast(source_size - source_offset);
            const bit_count = byte_count * 8;
            const integer_type = unit.getIntegerType(.{
                .bit_count = bit_count,
                .kind = .materialized_int,
                .signedness = .unsigned, // TODO
            }) catch unreachable;
            return integer_type;
        }
    }

    const RegisterAbiX86_64 = struct {
        abi: Function.AbiInfo,
        needed_registers: SystemV_x86_64_Registers,
    };

    fn classify_argument_type_systemv_x86_64(builder: *Builder, unit: *Unit, context: *const Context, type_index: Type.Index, free_gp_registers: u32) RegisterAbiX86_64 {
        const type_classes = builder.classify_systemv_x86_64(unit, context, type_index, 0);
        assert(type_classes[1] != .memory or type_classes[0] == .memory);
        assert(type_classes[1] != .sseup or type_classes[0] == .sse);

        var needed_registers = SystemV_x86_64_Registers{
            .gp_registers = 0,
            .sse_registers = 0,
        };

        const result_type = switch (type_classes[0]) {
            .integer => b: {
                needed_registers.gp_registers += 1;
                const result_type = builder.get_int_type_at_offset_system_v_x86_64(unit, context, type_index, 0, type_index, 0);
                if (type_classes[1] == .no_class and unit.types.get(type_index).getBitSize(unit) < 32) {
                    const signed = unit.types.get(type_index).integer.signedness == .unsigned;
                    return .{
                        .abi = .{
                            .kind = .{
                                .direct_coerce = type_index,
                            },
                            .attributes = .{
                                .sign_extend = signed,
                                .zero_extend = !signed,
                            },
                        },
                        .needed_registers = needed_registers,
                    };
                } else {
                    break :b result_type;
                }
            },
            .memory => return .{
                .abi = indirect_result(unit, type_index, free_gp_registers),
                .needed_registers = needed_registers,
            },
            else => |t| @panic(@tagName(t)),
        };

        const high_part: Type.Index = switch (type_classes[1]) {
            .no_class, .memory => .null,
            .integer => b: {
                assert(type_classes[0] != .no_class);
                needed_registers.gp_registers += 1;
                const high_part = builder.get_int_type_at_offset_system_v_x86_64(unit, context, type_index, 8, type_index, 8);
                break :b high_part;
            },
            else => |t| @panic(@tagName(t)),
        };

        if (high_part != .null) {
            return .{
                .abi = get_argument_pair(unit, .{ result_type, high_part }),
                .needed_registers = needed_registers,
            };
        } else {
            if (result_type != .null) {
                if (type_index == result_type) {
                    return .{
                        .abi = .{
                            .kind = .direct,
                        },
                        .needed_registers = needed_registers,
                    };
                } else {
                    return .{
                        .abi = .{
                            .kind = .{
                                .direct_coerce = result_type,
                            },
                        },
                        .needed_registers = needed_registers,
                    };
                }
            } else {
                unreachable;
            }
            unreachable;
        }
    }

    fn classify_return_type_systemv_x86_64(builder: *Builder, unit: *Unit, context: *const Context, type_index: Type.Index) Function.AbiInfo {
        const type_classes = builder.classify_systemv_x86_64(unit, context, type_index, 0);
        assert(type_classes[1] != .memory or type_classes[0] == .memory);
        assert(type_classes[1] != .sseup or type_classes[0] == .sse);

        const result_type: Type.Index = switch (type_classes[0]) {
            .no_class => switch (type_classes[1]) {
                .no_class => return .{
                    .kind = .ignore,
                },
                else => |t| @panic(@tagName(t)),
            },
            .integer => b: {
                const result_type = builder.get_int_type_at_offset_system_v_x86_64(unit, context, type_index, 0, type_index, 0);
                if (type_classes[1] == .no_class and unit.types.get(type_index).getAbiSize(unit) < 32) {
                    const ty = unit.types.get(result_type);
                    const signed = ty.integer.signedness == .signed;
                    return .{
                        .kind = .{
                            .direct_coerce = result_type,
                        },
                        .attributes = .{
                            .sign_extend = signed,
                            .zero_extend = !signed,
                        },
                    };
                }
                break :b result_type;
            },
            .memory => return indirect_return_result(unit, type_index),
            else => |t| @panic(@tagName(t)),
        };

        const high_part: Type.Index = switch (type_classes[1]) {
            .integer => b: {
                assert(type_classes[0] != .no_class);
                const high_part = builder.get_int_type_at_offset_system_v_x86_64(unit, context, type_index, 8, type_index, 8);
                break :b high_part;
            },
            else => |t| @panic(@tagName(t)),
        };

        if (high_part != .null) {
            return get_argument_pair(unit, .{ result_type, high_part });
        } else {
            unreachable;
        }
    }

    fn get_argument_pair(unit: *Unit, types: [2]Type.Index) Function.AbiInfo {
        const low_size = unit.types.get(types[0]).getAbiSize(unit);
        const high_alignment = unit.types.get(types[1]).getAbiAlignment(unit);
        const high_start = align_forward(low_size, high_alignment);
        assert(high_start == 8);
        return .{
            .kind = .{
                .direct_pair = types,
            },
        };
    }

    const SystemV_x86_64_Registers = struct {
        gp_registers: u32,
        sse_registers: u32,
    };

    fn indirect_result(unit: *Unit, type_index: Type.Index, free_gp_registers: u32) Function.AbiInfo {
        const ty = unit.types.get(type_index);
        const is_illegal_vector = false;
        if (!ty.is_aggregate() and !is_illegal_vector) {
            if (ty.* == .integer and ty.integer.bit_count < 32) {
                unreachable;
            } else {
                return .{
                    .kind = .direct,
                };
            }
        } else {
            const alignment = ty.getAbiAlignment(unit);
            if (free_gp_registers == 0) {
                const size = ty.getAbiSize(unit);
                if (alignment <= 8 and size <= 8) {
                    unreachable;
                }
            }

            const pointer_type = unit.getPointerType(.{
                .type = type_index,
                .termination = .none,
                .mutability = .@"var",
                .many = false,
                .nullable = false,
            }) catch unreachable;

            if (alignment < 8) {
                return .{
                    .kind = .{
                        .indirect = .{
                            .type = type_index,
                            .pointer = pointer_type,
                            .alignment = 8,
                        },
                    },
                    .attributes = .{
                        .realign = true,
                        .by_value = true,
                    },
                };
            } else {
                return .{
                    .kind = .{
                        .indirect = .{
                            .type = type_index,
                            .pointer = pointer_type,
                            .alignment = alignment,
                        },
                    },
                    .attributes = .{
                        .by_value = true,
                    },
                };
            }
        }
    }

    fn indirect_return_result(unit: *Unit, type_index: Type.Index) Function.AbiInfo {
        const ty = unit.types.get(type_index);
        if (ty.is_aggregate()) {
            const pointer_type = unit.getPointerType(.{
                .type = type_index,
                .termination = .none,
                .mutability = .@"var",
                .many = false,
                .nullable = false,
            }) catch unreachable;
            return .{
                .kind = .{
                    .indirect = .{
                        .type = type_index,
                        .pointer = pointer_type,
                        .alignment = ty.getAbiAlignment(unit),
                    },
                },
            };
        } else {
            unreachable;
        }
    }

    fn resolveContainerType(builder: *Builder, unit: *Unit, context: *const Context, container_node_index: Node.Index, container_type: ContainerType, maybe_global: ?*Debug.Declaration.Global, new_parameters: []const V.Comptime) !Type.Index {
        const current_basic_block = builder.current_basic_block;
        defer builder.current_basic_block = current_basic_block;
        builder.current_basic_block = .null;

        const container_node = unit.getNode(container_node_index);
        const container_nodes = unit.getNodeList(container_node.left);

        const Data = struct {
            scope: *Debug.Scope.Global,
            plain: Type.Index,
            polymorphic: Type.Index,
        };

        const token_debug_info = builder.getTokenDebugInfo(unit, container_node.token);
        const data: Data = switch (container_type) {
            .@"struct" => b: {
                assert(container_node.id == .struct_type);

                const struct_index = unit.structs.append_index(.{
                    .kind = .{
                        .@"struct" = .{
                            .scope = .{
                                .scope = .{
                                    .kind = switch (builder.current_scope.kind) {
                                        .file => .file_container,
                                        else => .struct_type,
                                    },
                                    .line = token_debug_info.line,
                                    .column = token_debug_info.column,
                                    .level = builder.current_scope.level + 1,
                                    .local = false,
                                    .file = builder.current_file,
                                    .declarations = try PinnedHashMap(u32, *Debug.Declaration).init(std.mem.page_size),
                                },
                            },
                            .options = .{},
                        },
                    },
                });

                const struct_type = unit.structs.get(struct_index);
                const struct_options = &struct_type.kind.@"struct".options;

                var parameter_types = BoundedArray(Token.Index, 64){};

                if (container_node.right != .null) {
                    const struct_option_nodes = unit.getNodeList(container_node.right);
                    var struct_options_value = false;

                    for (struct_option_nodes) |struct_option_node_index| {
                        const struct_option_node = unit.getNode(struct_option_node_index);
                        switch (struct_option_node.id) {
                            .anonymous_container_literal => {
                                if (struct_options_value) unreachable;
                                struct_options_value = true;
                                assert(struct_option_node.left == .null);
                                const nodes = unit.getNodeList(struct_option_node.right);
                                const struct_options_declaration = try builder.get_builtin_declaration(unit, context, "StructOptions");
                                const struct_options_declaration_type_index = struct_options_declaration.initial_value.type;
                                const struct_options_literal = try builder.resolveContainerLiteral(unit, context, nodes, struct_options_declaration_type_index);
                                const constant_struct_index = struct_options_literal.value.@"comptime".constant_struct;
                                const constant_struct = unit.constant_structs.get(constant_struct_index);
                                const struct_options_struct_index = unit.types.get(struct_options_declaration_type_index).@"struct";
                                const struct_options_struct = unit.structs.get(struct_options_struct_index);

                                for (struct_options_struct.kind.@"struct".fields, constant_struct.fields) |field_index, field_value| {
                                    const field = unit.struct_fields.get(field_index);
                                    const name = unit.getIdentifier(field.name);
                                    const option_id = enumFromString(Struct.Options.Id, name) orelse unreachable;
                                    switch (option_id) {
                                        .sliceable => switch (field_value.bool) {
                                            true => struct_options.sliceable = .{
                                                .pointer = 0,
                                                .length = 1,
                                            },
                                            false => unreachable,
                                        },
                                    }
                                }
                            },
                            .comptime_expression => {
                                assert(struct_option_node.left != .null);
                                assert(struct_option_node.right == .null);
                                const left = unit.getNode(struct_option_node.left);
                                assert(left.id == .identifier);
                                parameter_types.appendAssumeCapacity(left.token);
                            },
                            else => |t| @panic(@tagName(t)),
                        }
                    }
                }

                const plain_type_index = unit.types.append_index(.{
                    .@"struct" = struct_index,
                });

                assert(new_parameters.len == parameter_types.len);

                for (parameter_types.slice(), new_parameters) |parameter_type_token, parameter_value| {
                    const parameter_type = switch (parameter_value) {
                        .type => |type_index| type_index,
                        else => |t| @panic(@tagName(t)),
                    };
                    const declaration_token_debug_info = builder.getTokenDebugInfo(unit, parameter_type_token);
                    const identifier = unit.getExpectedTokenBytes(parameter_type_token, .identifier);
                    const hash = try unit.processIdentifier(context, identifier);
                    const global_declaration = unit.global_declarations.append(.{
                        .declaration = .{
                            .scope = &struct_type.kind.@"struct".scope.scope,
                            .name = hash,
                            .type = .type,
                            .line = declaration_token_debug_info.line,
                            .column = declaration_token_debug_info.column,
                            .mutability = .@"const",
                            .kind = .global,
                        },
                        .initial_value = .{
                            .type = parameter_type,
                        },
                        .type_node_index = .null,
                        .attributes = .{},
                    });
                    try struct_type.kind.@"struct".scope.scope.declarations.put_no_clobber(hash, &global_declaration.declaration);
                }

                const polymorphic_type_index = switch (parameter_types.len > 0) {
                    true => blk: {
                        const polymorphic_type_index = unit.types.append_index(.{
                            .polymorphic = .{
                                .parameters = param: {
                                    const heap_parameter_types = try context.arena.new_array(Token.Index, parameter_types.len);
                                    @memcpy(heap_parameter_types, parameter_types.slice());
                                    break :param heap_parameter_types;
                                },
                                .node = container_node_index,
                                .instantiations = try PinnedHashMap(u32, *Debug.Declaration.Global).init(std.mem.page_size),
                            },
                        });
                        const polymorphic_type = &unit.types.get(polymorphic_type_index).polymorphic;
                        try polymorphic_type.add_instantiation(unit, context, new_parameters, maybe_global.?, plain_type_index);
                        break :blk polymorphic_type_index;
                    },
                    false => .null,
                };

                // Assign the struct type to the upper file scope
                switch (builder.current_scope.kind) {
                    .file => {
                        const global_scope: *Debug.Scope.Global = @fieldParentPtr("scope", builder.current_scope);
                        const file: *Debug.File = @fieldParentPtr("scope", global_scope);
                        file.scope.type = plain_type_index;
                    },
                    .file_container => {},
                    else => |t| @panic(@tagName(t)),
                }

                break :b .{
                    .scope = &struct_type.kind.@"struct".scope,
                    .plain = plain_type_index,
                    .polymorphic = polymorphic_type_index,
                };
            },
            .@"enum" => b: {
                assert(container_node.id == .enum_type);
                const integer = switch (container_node.right) {
                    .null => Type.Integer{
                        .bit_count = 0,
                        .signedness = .unsigned,
                        .kind = .comptime_int,
                    },
                    else => e: {
                        const node_list = unit.getNodeList(container_node.right);
                        assert(node_list.len == 1);
                        const backing_type_index = try builder.resolveType(unit, context, node_list[0], &.{});
                        const backing_type = unit.types.get(backing_type_index);
                        break :e switch (backing_type.*) {
                            .integer => |integer| switch (integer.kind) {
                                .materialized_int => integer,
                                else => |t| @panic(@tagName(t)),
                            },
                            else => |t| @panic(@tagName(t)),
                        };
                    },
                };

                const type_index = unit.types.append_index(.{
                    .integer = .{
                        .bit_count = integer.bit_count,
                        .signedness = integer.signedness,
                        .kind = .{
                            .@"enum" = .{
                                .scope = .{
                                    .scope = .{
                                        .kind = .enum_type,
                                        .line = token_debug_info.line,
                                        .column = token_debug_info.column,
                                        .level = builder.current_scope.level + 1,
                                        .local = false,
                                        .file = builder.current_file,
                                        .declarations = try PinnedHashMap(u32, *Debug.Declaration).init(std.mem.page_size),
                                    },
                                },
                            },
                        },
                    },
                });
                const e_type = unit.types.get(type_index);
                break :b .{
                    .scope = &e_type.integer.kind.@"enum".scope,
                    .plain = type_index,
                    .polymorphic = .null,
                };
            },
            .bitfield => b: {
                assert(container_node.id == .bitfield_type);
                const integer = switch (container_node.right) {
                    .null => unreachable,
                    else => e: {
                        const argument_nodes = unit.getNodeList(container_node.right);
                        assert(argument_nodes.len == 1);
                        const backing_type_index = try builder.resolveType(unit, context, argument_nodes[0], &.{});
                        const backing_type = unit.types.get(backing_type_index);
                        break :e switch (backing_type.*) {
                            .integer => |integer| switch (integer.kind) {
                                .materialized_int => integer,
                                else => |t| @panic(@tagName(t)),
                            },
                            else => |t| @panic(@tagName(t)),
                        };
                    },
                };

                const bitfield_type_index = unit.types.append_index(.{
                    .integer = .{
                        .bit_count = integer.bit_count,
                        .signedness = integer.signedness,
                        .kind = .{
                            .bitfield = .{
                                .scope = .{
                                    .scope = .{
                                        .kind = .bitfield,
                                        .line = token_debug_info.line,
                                        .column = token_debug_info.column,
                                        .level = builder.current_scope.level + 1,
                                        .local = false,
                                        .file = builder.current_file,
                                        .declarations = try PinnedHashMap(u32, *Debug.Declaration).init(std.mem.page_size),
                                    },
                                },
                            },
                        },
                    },
                });

                break :b .{
                    .plain = bitfield_type_index,
                    .polymorphic = .null,
                    .scope = &unit.types.get(bitfield_type_index).integer.kind.bitfield.scope,
                };
            },
        };

        const scope = data.scope;
        scope.type = data.plain;

        if (maybe_global) |global| {
            global.declaration.type = .type;
            global.initial_value = .{
                .type = if (data.polymorphic != .null) data.polymorphic else data.plain,
            };
        }

        try builder.pushScope(unit, &scope.scope);
        defer builder.popScope(unit) catch unreachable;

        const count = blk: {
            var result: struct {
                fields: u32 = 0,
                declarations: u32 = 0,
                comptime_blocks: u32 = 0,
                test_declarations: u32 = 0,
            } = .{};

            for (container_nodes) |member_index| {
                const member = unit.getNode(member_index);

                const member_type = getContainerMemberType(member.id);

                switch (member_type) {
                    .declaration => result.declarations += 1,
                    .field => result.fields += 1,
                    .comptime_block => result.comptime_blocks += 1,
                    .test_declaration => result.test_declarations += 1,
                }
            }

            break :blk result;
        };

        var declaration_nodes = try context.arena.new_array(Node.Index, count.declarations);
        var field_nodes = try context.arena.new_array(Node.Index, count.fields);
        var comptime_block_nodes = try context.arena.new_array(Node.Index, count.comptime_blocks);
        var test_declarations = try context.arena.new_array(Node.Index, count.test_declarations);
        declaration_nodes.len = 0;
        field_nodes.len = 0;
        comptime_block_nodes.len = 0;
        test_declarations.len = 0;

        for (container_nodes) |member_index| {
            const member_node = unit.getNode(member_index);
            const member_type = getContainerMemberType(member_node.id);
            const array_list = switch (member_type) {
                .comptime_block => &comptime_block_nodes,
                .declaration => &declaration_nodes,
                .field => &field_nodes,
                .test_declaration => &test_declarations,
            };
            const index = array_list.len;
            array_list.len += 1;
            array_list.*[index] = member_index;
        }

        if (count.declarations > 0) {
            for (declaration_nodes) |declaration_node_index| {
                const declaration_node = unit.getNode(declaration_node_index);

                switch (declaration_node.id) {
                    .constant_symbol_declaration,
                    .variable_symbol_declaration,
                    => {
                        const expected_identifier_token_index: Token.Index = @enumFromInt(@intFromEnum(declaration_node.token) + 1);
                        const identifier = unit.getExpectedTokenBytes(expected_identifier_token_index, .identifier);
                        // logln(.compilation, .identifier, "Analyzing global declaration {s}", .{identifier});
                        const identifier_hash = try unit.processIdentifier(context, identifier);

                        const look_in_parent_scopes = true;
                        if (builder.current_scope.lookupDeclaration(identifier_hash, look_in_parent_scopes)) |lookup_result| {
                            _ = lookup_result; // autofix
                            @panic("Symbol already on scope");
                            //std.debug.panic("Symbol {s} already on scope", .{identifier});
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
                                        .symbol_attribute_extern => res.setPresent(.@"extern", true),
                                        else => |t| @panic(@tagName(t)),
                                    }
                                }

                                break :b res;
                            },
                        };

                        const value_node_index = declaration_node.right;

                        const declaration_token_debug_info = builder.getTokenDebugInfo(unit, declaration_node.token);
                        const mutability: Mutability = switch (declaration_node.id) {
                            .constant_symbol_declaration => .@"const",
                            .variable_symbol_declaration => .@"var",
                            else => unreachable,
                        };

                        const global_declaration = unit.global_declarations.append(.{
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

                        try builder.current_scope.declarations.put_no_clobber(identifier_hash, &global_declaration.declaration);
                    },
                    else => unreachable,
                }
            }
        }

        if (count.fields > 0) {
            const ty = unit.types.get(data.plain);
            const field_count: u32 = @intCast(field_nodes.len);
            var enum_fields: []Enum.Field.Index = undefined;
            var struct_fields: []Struct.Field.Index = undefined;
            switch (container_type) {
                .@"enum" => {
                    const integer_type = &ty.integer;
                    enum_fields = try context.arena.new_array(Enum.Field.Index, field_count);

                    if (integer_type.bit_count == 0) {
                        integer_type.bit_count = @bitSizeOf(@TypeOf(field_nodes.len)) - @clz(field_nodes.len);
                    }
                    assert(integer_type.bit_count > 0);
                },
                .@"struct", .bitfield => {
                    struct_fields = try context.arena.new_array(Struct.Field.Index, field_count);
                },
            }

            var sliceable_pointer_index: ?u32 = null;
            var sliceable_length_index: ?u32 = null;
            var ignore_field_count: u8 = 0;

            for (field_nodes, 0..) |field_node_index, index| {
                const field_node = unit.getNode(field_node_index);
                const identifier = switch (unit.token_buffer.tokens.get(field_node.token).id) {
                    .identifier => unit.getExpectedTokenBytes(field_node.token, .identifier),
                    .string_literal => try unit.fixupStringLiteral(context, field_node.token),
                    .discard => try std.mem.concat(context.allocator, u8, &.{ "_", &.{'0' + b: {
                        const ch = '0' + ignore_field_count;
                        ignore_field_count += 1;
                        break :b ch;
                    }} }),
                    else => unreachable,
                };
                const hash = try unit.processIdentifier(context, identifier);

                switch (container_type) {
                    .@"enum" => {
                        assert(field_node.id == .enum_field);

                        const integer_type = try unit.getIntegerType(.{
                            .bit_count = ty.integer.bit_count,
                            .signedness = ty.integer.signedness,
                            .kind = .materialized_int,
                        });

                        const enum_value: usize = switch (field_node.left) {
                            .null => index,
                            else => b: {
                                const enum_value = try builder.resolveComptimeValue(unit, context, Type.Expect{ .type = integer_type }, .{}, field_node.left, null, .right, &.{}, null, &.{});
                                assert(enum_value.comptime_int.signedness == .unsigned);
                                break :b enum_value.comptime_int.value;
                            },
                        };

                        const enum_field_index = unit.enum_fields.append_index(.{
                            .name = hash,
                            .value = enum_value,
                            .parent = data.plain,
                        });
                        enum_fields[index] = enum_field_index;
                    },
                    .@"struct" => {
                        assert(field_node.id == .container_field);
                        const struct_type = unit.structs.get(ty.@"struct");
                        if (struct_type.kind.@"struct".options.sliceable != null) {
                            inline for (@typeInfo(SliceField).Enum.fields) |field| {
                                if (byte_equal(field.name, identifier)) {
                                    const v = @field(SliceField, field.name);
                                    switch (v) {
                                        .pointer => {
                                            assert(sliceable_pointer_index == null);
                                            sliceable_pointer_index = @intCast(index);
                                        },
                                        .length => {
                                            assert(sliceable_length_index == null);
                                            sliceable_length_index = @intCast(index);
                                        },
                                    }
                                }
                            }
                        }
                        const field_type = try builder.resolveType(unit, context, field_node.left, &.{});
                        const field_default_value: ?V.Comptime = switch (field_node.right) {
                            .null => null,
                            else => |default_value_node_index| try builder.resolveComptimeValue(unit, context, Type.Expect{ .type = field_type }, .{}, default_value_node_index, null, .right, &.{}, null, &.{}),
                        };

                        const struct_field = unit.struct_fields.append_index(.{
                            .name = hash,
                            .type = field_type,
                            .default_value = field_default_value,
                        });
                        struct_fields[index] = struct_field;
                    },
                    .bitfield => {
                        assert(field_node.id == .container_field);
                        const field_type = try builder.resolveType(unit, context, field_node.left, &.{});
                        const field_default_value: ?V.Comptime = switch (field_node.right) {
                            .null => null,
                            else => |default_value_node_index| try builder.resolveComptimeValue(unit, context, Type.Expect{ .type = field_type }, .{}, default_value_node_index, null, .right, &.{}, null, &.{}),
                        };

                        const struct_field = unit.struct_fields.append_index(.{
                            .name = hash,
                            .type = field_type,
                            .default_value = field_default_value,
                        });
                        struct_fields[index] = struct_field;
                    },
                }
            }

            switch (container_type) {
                .@"struct" => {
                    const struct_type = unit.structs.get(ty.@"struct");
                    struct_type.kind.@"struct".fields = struct_fields;
                    if (struct_type.kind.@"struct".options.sliceable) |*sliceable| {
                        sliceable.pointer = sliceable_pointer_index orelse unreachable;
                        sliceable.length = sliceable_length_index orelse unreachable;
                    }
                },
                .bitfield => {
                    ty.integer.kind.bitfield.fields = struct_fields;
                },
                .@"enum" => {
                    ty.integer.kind.@"enum".fields = enum_fields;
                },
            }
        }

        if (count.comptime_blocks > 0) {
            const emit_ir = builder.emit_ir;
            builder.emit_ir = false;
            defer builder.emit_ir = emit_ir;

            for (comptime_block_nodes) |comptime_node_index| {
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

        if (unit.descriptor.is_test and count.test_declarations > 0 and unit.main_package.? == unit.files.get(builder.current_file).package) {
            const function_type = if (unit.test_function_type != .null) unit.test_function_type else b: {
                const return_type = try builder.getErrorUnionType(unit, context, .{
                    .@"error" = unit.all_errors,
                    .type = .void,
                });

                // TODO: make test function prototypes unique
                const function_prototype_index = unit.function_prototypes.append_index(.{
                    .argument_types = &.{},
                    .return_type = return_type,
                    .abi = .{
                        .return_type = return_type,
                    },
                    .attributes = .{
                        .naked = false,
                    },
                    .calling_convention = .auto,
                });
                const function_type = unit.types.append_index(.{
                    .function = function_prototype_index,
                });
                unit.test_function_type = function_type;

                break :b function_type;
            };

            for (test_declarations) |test_declaration_node_index| {
                const test_node = unit.getNode(test_declaration_node_index);
                assert(test_node.id == .test_declaration);

                const comptime_value = try builder.resolveFunctionDefinition(unit, context, function_type, test_declaration_node_index, test_node.left, .null, .{}, null, &.{}, null);

                const test_name_global = if (test_node.right != .null) b: {
                    const test_name_node = unit.getNode(test_node.right);
                    const named_global = try builder.processStringLiteralFromToken(unit, context, test_name_node.token);
                    break :b named_global;
                } else b: {
                    const name = try join_name(context, "_anon_test_", unit.test_functions.length, 10);
                    const anon_global = try builder.processStringLiteralFromStringAndDebugInfo(unit, context, name, token_debug_info);
                    break :b anon_global;
                };

                const name_hash = test_name_global.initial_value.string_literal;

                const test_global = unit.global_declarations.append(.{
                    .declaration = .{
                        .scope = &scope.scope,
                        .type = function_type,
                        .name = name_hash,
                        .line = token_debug_info.line,
                        .column = token_debug_info.column,
                        .mutability = .@"const",
                        .kind = .global,
                    },
                    .initial_value = comptime_value,
                    .type_node_index = .null,
                    .attributes = .{},
                });

                try scope.scope.declarations.put_no_clobber(name_hash, &test_global.declaration);
                try unit.test_functions.put_no_clobber(test_name_global, test_global);
                try unit.code_to_emit.put_no_clobber(comptime_value.function_definition, test_global);
            }
        }

        for (builder.current_scope.declarations.values()) |declaration| {
            const global_declaration: *Debug.Declaration.Global = @fieldParentPtr("declaration", declaration);
            if (global_declaration.attributes.contains(.@"export")) {
                const result = try builder.referenceGlobalDeclaration(unit, context, &scope.scope, declaration, .{}, &.{}, null, &.{});
                assert(result == global_declaration);
            }
        }

        return if (data.polymorphic != .null) data.polymorphic else data.plain;
    }

    fn emitMemcpy(builder: *Builder, unit: *Unit, context: *const Context, arguments: Instruction.Memcpy) !void {
        _ = context; // autofix
        const memcpy = unit.instructions.append_index(.{
            .memcpy = arguments,
        });
        try builder.appendInstruction(unit, memcpy);
    }

    fn emitIntegerCompare(builder: *Builder, unit: *Unit, context: *const Context, left_value: V, right_value: V, integer: Type.Integer, compare_node_id: Node.Id) anyerror!V {
        _ = context; // autofix
        assert(left_value.type == right_value.type);
        const compare = unit.instructions.append_index(.{
            .integer_compare = .{
                .left = left_value,
                .right = right_value,
                .type = left_value.type,
                .id = switch (compare_node_id) {
                    .compare_equal => .equal,
                    .compare_not_equal => .not_equal,
                    else => switch (integer.signedness) {
                        .unsigned => switch (compare_node_id) {
                            .compare_less => .unsigned_less,
                            .compare_less_equal => .unsigned_less_equal,
                            .compare_greater => .unsigned_greater,
                            .compare_greater_equal => .unsigned_greater_equal,
                            else => unreachable,
                        },
                        .signed => switch (compare_node_id) {
                            .compare_less => .signed_less,
                            .compare_less_equal => .signed_less_equal,
                            .compare_greater => .signed_greater,
                            .compare_greater_equal => .signed_greater_equal,
                            else => unreachable,
                        },
                    },
                },
            },
        });
        try builder.appendInstruction(unit, compare);

        return .{
            .value = .{
                .runtime = compare,
            },
            .type = .bool,
        };
    }

    fn resolveFunctionDefinition(builder: *Builder, unit: *Unit, context: *const Context, maybe_function_type_index: Type.Index, function_node_index: Node.Index, body_node_index: Node.Index, argument_list_node_index: Node.Index, global_attributes: Debug.Declaration.Global.Attributes, maybe_member_value: ?V, polymorphic_argument_nodes: []const Node.Index, maybe_global: ?*Debug.Declaration.Global) !V.Comptime {
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

        const function_node = unit.getNode(function_node_index);
        const token_debug_info = builder.getTokenDebugInfo(unit, function_node.token);
        const old_function = builder.current_function;

        builder.current_function = unit.function_definitions.append_index(.{
            .type = maybe_function_type_index,
            .body = .null,
            .scope = .{
                .scope = Debug.Scope{
                    .line = token_debug_info.line,
                    .column = token_debug_info.column,
                    .kind = .function,
                    .local = true,
                    .level = builder.current_scope.level + 1,
                    .file = builder.current_file,
                    .declarations = try PinnedHashMap(u32, *Debug.Declaration).init(std.mem.page_size),
                },
                .argument_map = try PinnedHashMap(*Debug.Declaration.Argument, Instruction.Index).init(std.mem.page_size),
            },
            .has_debug_info = true,
            .basic_blocks = try PinnedArray(BasicBlock.Index).init(std.mem.page_size),
        });

        defer builder.current_function = old_function;

        const function = unit.function_definitions.get(builder.current_function);

        builder.last_check_point = .{};
        try builder.pushScope(unit, &function.scope.scope);
        defer builder.popScope(unit) catch unreachable;

        var comptime_parameter_declarations: []const ComptimeParameterDeclaration = &.{};
        var comptime_parameter_instantiations: []const V.Comptime = &.{};
        var is_member_call = false;
        function.type = if (maybe_function_type_index == .null) b: {
            const function_prototype_node_index = function_node.left;
            const function_prototype_index = try builder.resolveFunctionPrototype(unit, context, function_prototype_node_index, global_attributes, maybe_member_value, polymorphic_argument_nodes, &function.scope, &comptime_parameter_declarations, &comptime_parameter_instantiations, &is_member_call, maybe_global);
            if (maybe_global) |g| {
                switch (g.initial_value) {
                    .polymorphic_function => |*pf| if (pf.get_instantiation(comptime_parameter_instantiations)) |_| unreachable else {},
                    else => {},
                }
            }
            break :b function_prototype_index;
        } else maybe_function_type_index;

        const entry_basic_block = try builder.newBasicBlock(unit);
        builder.current_basic_block = entry_basic_block;
        defer builder.current_basic_block = .null;

        const body_node = unit.getNode(body_node_index);
        try builder.insertDebugCheckPoint(unit, body_node.token);

        const function_prototype_index = unit.types.get(function.type).function;
        const function_prototype = unit.function_prototypes.get(function_prototype_index);

        //function.has_polymorphic_parameters = function_prototype.comptime_parameter_instantiations.len > 0;

        if (function_prototype.abi.return_type_abi.kind == .indirect) {
            const return_pointer_argument = unit.instructions.append_index(.{
                .abi_argument = 0,
            });
            try builder.appendInstruction(unit, return_pointer_argument);
            function.return_pointer = return_pointer_argument;
        }

        // Get argument declarations into scope
        if (argument_list_node_index != .null) {
            const argument_types = function_prototype.argument_types;
            var runtime_parameter_count: usize = 0;

            for (builder.current_scope.declarations.values()) |declaration| {
                switch (declaration.kind) {
                    .argument => {
                        const argument_declaration: *Debug.Declaration.Argument = @fieldParentPtr("declaration", declaration);
                        var argument_abi_instructions: [12]Instruction.Index = undefined;
                        const argument_abi = function_prototype.abi.parameter_types_abi[runtime_parameter_count];
                        const argument_type_index = argument_types[runtime_parameter_count];
                        const argument_abi_count = argument_abi.indices[1] - argument_abi.indices[0];
                        for (0..argument_abi_count) |argument_index| {
                            const argument_instruction = unit.instructions.append_index(.{
                                .abi_argument = @intCast(argument_abi.indices[0] + argument_index),
                            });

                            try builder.appendInstruction(unit, argument_instruction);

                            argument_abi_instructions[argument_index] = argument_instruction;
                        }

                        const argument_type = unit.types.get(argument_type_index);

                        const LowerKind = union(enum) {
                            direct,
                            direct_pair: [2]Type.Index,
                            direct_coerce: Type.Index,
                            indirect,
                        };

                        const lower_kind: LowerKind = switch (argument_abi.kind) {
                            .direct => .direct,
                            .direct_coerce => |coerced_type_index| if (argument_type_index == coerced_type_index) .direct else .{
                                .direct_coerce = coerced_type_index,
                            },
                            .direct_pair => |pair| .{
                                .direct_pair = pair,
                            },
                            .indirect => .indirect,
                            else => |t| @panic(@tagName(t)),
                        };

                        const stack = switch (lower_kind) {
                            .direct => b: {
                                assert(argument_abi_count == 1);
                                const stack = try builder.createStackVariable(unit, context, argument_type_index, null);

                                const pointer_type = try unit.getPointerType(.{
                                    .type = argument_type_index,
                                    .termination = .none,
                                    .mutability = .@"var",
                                    .many = false,
                                    .nullable = false,
                                });

                                const store = unit.instructions.append_index(.{
                                    .store = .{
                                        .destination = .{
                                            .value = .{
                                                .runtime = stack,
                                            },
                                            .type = pointer_type,
                                        },
                                        .source = .{
                                            .value = .{
                                                .runtime = argument_abi_instructions[0],
                                            },
                                            .type = argument_type_index,
                                        },
                                    },
                                });

                                try builder.appendInstruction(unit, store);

                                break :b stack;
                            },
                            .direct_pair => |pair| b: {
                                assert(argument_abi_count == 2);
                                const types = [2]*Type{ unit.types.get(pair[0]), unit.types.get(pair[1]) };
                                assert(types[0].* == .integer);
                                assert(types[1].* == .integer);
                                const alignments = [2]u32{ types[0].getAbiAlignment(unit), types[1].getAbiAlignment(unit) };
                                const sizes = [2]u32{ types[0].getAbiSize(unit), types[1].getAbiSize(unit) };
                                const alignment = @max(alignments[0], alignments[1]);
                                _ = alignment; // autofix
                                const high_aligned_size: u32 = @intCast(align_forward(sizes[1], alignments[1]));
                                _ = high_aligned_size; // autofix
                                const high_offset: u32 = @intCast(align_forward(sizes[0], alignments[1]));
                                assert(high_offset + sizes[1] <= argument_type.getAbiSize(unit));
                                const stack = try builder.createStackVariable(unit, context, argument_type_index, null);

                                const pointer_types = [2]Type.Index{
                                    try unit.getPointerType(.{
                                        .type = pair[0],
                                        .termination = .none,
                                        .mutability = .@"var",
                                        .many = false,
                                        .nullable = false,
                                    }),
                                    try unit.getPointerType(.{
                                        .type = pair[0],
                                        .termination = .none,
                                        .mutability = .@"var",
                                        .many = false,
                                        .nullable = false,
                                    }),
                                };

                                var destination = V{
                                    .type = pointer_types[0],
                                    .value = .{
                                        .runtime = stack,
                                    },
                                };

                                var source = V{
                                    .value = .{
                                        .runtime = argument_abi_instructions[0],
                                    },
                                    .type = pair[0],
                                };
                                const first_store = unit.instructions.append_index(.{
                                    .store = .{
                                        .destination = destination,
                                        .source = source,
                                    },
                                });
                                try builder.appendInstruction(unit, first_store);

                                const gep = unit.instructions.append_index(.{
                                    .get_element_pointer = .{
                                        .pointer = stack,
                                        .base_type = pair[0],
                                        .is_struct = false,
                                        .index = .{
                                            .value = .{
                                                .@"comptime" = .{
                                                    .constant_int = .{
                                                        .value = 1,
                                                    },
                                                },
                                            },
                                            .type = Type.usize,
                                        },
                                        .name = try unit.processIdentifier(context, "direct_pair"),
                                    },
                                });
                                try builder.appendInstruction(unit, gep);

                                destination = .{
                                    .value = .{
                                        .runtime = gep,
                                    },
                                    .type = pointer_types[1],
                                };

                                source = .{
                                    .value = .{
                                        .runtime = argument_abi_instructions[1],
                                    },
                                    .type = pair[1],
                                };

                                const second_store = unit.instructions.append_index(.{
                                    .store = .{
                                        .destination = destination,
                                        .source = source,
                                    },
                                });
                                try builder.appendInstruction(unit, second_store);

                                break :b stack;
                            },
                            .indirect => b: {
                                assert(argument_abi_count == 1);
                                break :b argument_abi_instructions[0];
                            },
                            .direct_coerce => |coerced_type_index| b: {
                                assert(coerced_type_index != argument_type_index);
                                assert(argument_abi_count == 1);

                                const argument_size = argument_type.getAbiSize(unit);
                                const argument_alloca = try builder.createStackVariable(unit, context, argument_type_index, null);
                                const coerced_type = unit.types.get(coerced_type_index);
                                const coerced_size = coerced_type.getAbiSize(unit);
                                const argument_pointer_type = try unit.getPointerType(.{
                                    .type = argument_type_index,
                                    .termination = .none,
                                    .mutability = .@"var",
                                    .many = false,
                                    .nullable = false,
                                });

                                switch (argument_type.*) {
                                    .@"struct" => {
                                        // TODO:
                                        const is_vector = false;

                                        if (coerced_size <= argument_size and !is_vector) {
                                            const store = unit.instructions.append_index(.{
                                                .store = .{
                                                    .destination = .{
                                                        .value = .{
                                                            .runtime = argument_alloca,
                                                        },
                                                        .type = argument_pointer_type,
                                                    },
                                                    .source = .{
                                                        .value = .{
                                                            .runtime = argument_abi_instructions[0],
                                                        },
                                                        .type = coerced_type_index,
                                                    },
                                                },
                                            });

                                            try builder.appendInstruction(unit, store);
                                        } else {
                                            const coerced_alloca = try builder.createStackVariable(unit, context, coerced_type_index, null);
                                            const coerced_pointer_type = try unit.getPointerType(.{
                                                .type = coerced_type_index,
                                                .termination = .none,
                                                .mutability = .@"var",
                                                .many = false,
                                                .nullable = false,
                                            });

                                            const store = unit.instructions.append_index(.{
                                                .store = .{
                                                    .destination = .{
                                                        .value = .{
                                                            .runtime = coerced_alloca,
                                                        },
                                                        .type = coerced_pointer_type,
                                                    },
                                                    .source = .{
                                                        .value = .{
                                                            .runtime = argument_abi_instructions[0],
                                                        },
                                                        .type = coerced_type_index,
                                                    },
                                                },
                                            });
                                            try builder.appendInstruction(unit, store);

                                            try builder.emitMemcpy(unit, context, .{
                                                .destination = .{
                                                    .value = .{
                                                        .runtime = argument_alloca,
                                                    },
                                                    .type = argument_pointer_type,
                                                },
                                                .source = .{
                                                    .value = .{
                                                        .runtime = coerced_alloca,
                                                    },
                                                    .type = coerced_pointer_type,
                                                },
                                                .destination_alignment = null,
                                                .source_alignment = null,
                                                .size = argument_size,
                                                .is_volatile = false,
                                            });
                                        }

                                        break :b argument_alloca;
                                    },
                                    else => |t| @panic(@tagName(t)),
                                }
                            },
                            // else => |t| @panic(@tagName(t)),
                        };

                        try function.scope.argument_map.put_no_clobber(argument_declaration, stack);

                        const debug_declare_argument = unit.instructions.append_index(.{
                            .debug_declare_argument = .{
                                .argument = argument_declaration,
                                .stack = stack,
                            },
                        });

                        try builder.appendInstruction(unit, debug_declare_argument);

                        runtime_parameter_count += 1;
                    },
                    // Comptime parameters are already processed
                    .global => {},
                    else => |t| @panic(@tagName(t)),
                }
            }

            assert(runtime_parameter_count
            // + @intFromBool(function_prototype.is_member)
            == argument_types.len);
            assert(runtime_parameter_count
            //+ @intFromBool(function_prototype.is_member)
            == function_prototype.abi.parameter_types_abi.len);
        }

        if (body_node.id == .block) {
            function.body = try builder.resolveBlock(unit, context, body_node_index);

            if (builder.return_phi != .null) {
                const old_block = builder.current_basic_block;
                builder.current_basic_block = builder.return_block;

                try builder.appendInstruction(unit, builder.return_phi);
                try builder.buildRet(unit, context, .{
                    .value = .{
                        .runtime = builder.return_phi,
                    },
                    .type = function_prototype.return_type,
                });

                builder.current_basic_block = old_block;
            }

            const cbb = unit.basic_blocks.get(builder.current_basic_block);
            const return_type_index = function_prototype.return_type;
            const return_type = unit.types.get(return_type_index);

            if (!cbb.terminated and (cbb.instructions.length > 0 or cbb.predecessors.length > 0)) {
                if (builder.return_block == .null) {
                    switch (return_type.*) {
                        .void => try builder.buildRet(unit, context, .{
                            .value = .{
                                .@"comptime" = .void,
                            },
                            .type = .void,
                        }),
                        .noreturn => try builder.buildTrap(unit, context),
                        .@"struct" => |struct_index| switch (unit.structs.get(struct_index).kind) {
                            .error_union => |error_union| {
                                assert(function_prototype.calling_convention == .auto);
                                switch (error_union.type) {
                                    .void => {
                                        assert(error_union.abi == error_union.union_for_type);
                                        const undefined_value = V{
                                            .value = .{
                                                .@"comptime" = .undefined,
                                            },
                                            .type = return_type_index,
                                        };
                                        const insert = unit.instructions.append_index(.{
                                            .insert_value = .{
                                                .expression = undefined_value,
                                                .index = 1,
                                                .new_value = .{
                                                    .value = .{
                                                        .@"comptime" = .{
                                                            .bool = false,
                                                        },
                                                    },
                                                    .type = .bool,
                                                },
                                            },
                                        });
                                        try builder.appendInstruction(unit, insert);

                                        try builder.buildRet(unit, context, .{
                                            .value = .{
                                                .runtime = insert,
                                            },
                                            .type = return_type_index,
                                        });
                                    },
                                    else => unreachable,
                                }
                            },
                            else => |t| @panic(@tagName(t)),
                        },
                        else => unreachable,
                    }
                } else {
                    assert(function_prototype.calling_convention == .auto);
                    assert(builder.return_phi != .null);
                    assert(builder.return_block != builder.current_basic_block);

                    const phi = &unit.instructions.get(builder.return_phi).phi;

                    switch (return_type.*) {
                        .void => unreachable,
                        .noreturn => unreachable,
                        .@"struct" => |struct_index| switch (unit.structs.get(struct_index).kind) {
                            .error_union => |error_union| {
                                if (error_union.type == .void or
                                    // TODO: is this correct?
                                    error_union.type == .noreturn)
                                {
                                    const return_value = unit.instructions.append_index(.{
                                        .insert_value = .{
                                            .expression = .{
                                                .value = .{
                                                    .@"comptime" = .undefined,
                                                },
                                                .type = return_type_index,
                                            },
                                            .index = 1,
                                            .new_value = .{
                                                .value = .{
                                                    .@"comptime" = .{
                                                        .bool = false,
                                                    },
                                                },
                                                .type = .bool,
                                            },
                                        },
                                    });
                                    try builder.appendInstruction(unit, return_value);

                                    phi.addIncoming(.{
                                        .value = .{
                                            .runtime = return_value,
                                        },
                                        .type = return_type_index,
                                    }, builder.current_basic_block);

                                    try builder.jump(unit, builder.return_block);
                                } else {
                                    try unit.dumpFunctionDefinition(builder.current_function);
                                    unreachable;
                                }
                            },
                            else => |t| @panic(@tagName(t)),
                        },
                        else => {
                            try unit.dumpFunctionDefinition(builder.current_function);
                            unreachable;
                        },
                    }
                }
            }

            const current_function = builder.current_function;

            if (maybe_global != null and maybe_global.?.initial_value == .polymorphic_function) {
                const polymorphic_function = &maybe_global.?.initial_value.polymorphic_function;
                const instantiation = try polymorphic_function.add_instantiation(unit, context, comptime_parameter_instantiations, maybe_global orelse unreachable, current_function);
                return .{
                    .global = instantiation,
                };
            } else if (comptime_parameter_declarations.len > 0) {
                var polymorphic_function = PolymorphicFunction{
                    .node = function_node_index,
                    .parameters = comptime_parameter_declarations,
                    .is_member_call = is_member_call,
                    .instantiations = try PinnedHashMap(u32, *Debug.Declaration.Global).init(std.mem.page_size),
                };
                _ = try polymorphic_function.add_instantiation(unit, context, comptime_parameter_instantiations, maybe_global orelse unreachable, current_function);
                return V.Comptime{
                    .polymorphic_function = polymorphic_function,
                };
            } else return .{
                .function_definition = current_function,
            };
        } else {
            @panic("Function body is expected to be a block");
        }
    }

    /// Last value is used to cache types being analyzed so we dont hit stack overflow
    fn resolveComptimeValue(builder: *Builder, unit: *Unit, context: *const Context, type_expect: Type.Expect, global_attributes: Debug.Declaration.Global.Attributes, node_index: Node.Index, maybe_global: ?*Debug.Declaration.Global, side: Side, new_parameters: []const V.Comptime, maybe_member_value: ?V, polymorphic_argument_nodes: []const Node.Index) anyerror!V.Comptime {
        const node = unit.getNode(node_index);
        switch (node.id) {
            .intrinsic => {
                const argument_node_list = unit.getNodeList(node.left);
                const intrinsic_id: IntrinsicId = @enumFromInt(@intFromEnum(node.right));
                switch (intrinsic_id) {
                    .import => {
                        assert(argument_node_list.len == 1);
                        const file_index = try builder.resolveImport(unit, context, type_expect, argument_node_list);
                        const file = unit.files.get(file_index);
                        return .{
                            .type = file.scope.type,
                        };
                    },
                    .@"error" => {
                        assert(argument_node_list.len == 1);
                        // TODO: type
                        const argument_node = unit.getNode(argument_node_list[0]);
                        switch (argument_node.id) {
                            .string_literal => {
                                const error_message = try unit.fixupStringLiteral(context, argument_node.token);
                                builder.reportCompileError(unit, context, .{
                                    .message = error_message,
                                    .node = node_index,
                                });
                            },
                            else => |t| @panic(@tagName(t)),
                        }
                    },
                    .cast => {
                        assert(argument_node_list.len == 1);
                        switch (type_expect) {
                            .type => |type_index| {
                                const value = try builder.resolveComptimeValue(unit, context, Type.Expect.none, .{}, argument_node_list[0], null, .right, &.{}, null, &.{});
                                const ty = unit.types.get(type_index);
                                switch (ty.*) {
                                    .pointer => |_| switch (value) {
                                        .comptime_int => |ct_int| switch (ct_int.value) {
                                            0 => return .null_pointer,
                                            else => unreachable,
                                        },
                                        else => |t| @panic(@tagName(t)),
                                    },
                                    else => |t| @panic(@tagName(t)),
                                }
                            },
                            else => |t| @panic(@tagName(t)),
                        }
                    },
                    .fields => {
                        assert(argument_node_list.len == 1);
                        const container_type_index = try builder.resolveType(unit, context, argument_node_list[0], &.{});
                        const container_type = unit.types.get(container_type_index);
                        switch (container_type.*) {
                            .integer => |*integer| switch (integer.kind) {
                                .@"enum" => |*enum_type| {
                                    return V.Comptime{
                                        .enum_fields = enum_type.fields,
                                    };
                                },
                                else => |t| @panic(@tagName(t)),
                            },
                            else => |t| @panic(@tagName(t)),
                        }
                    },
                    else => |t| @panic(@tagName(t)),
                }
            },
            .field_access => {
                const result = try builder.resolveFieldAccess(unit, context, type_expect, node_index, .right, new_parameters);
                return switch (result.value) {
                    .@"comptime" => |ct| ct,
                    else => @panic("Expected comptime value, found runtime value"),
                };
            },
            .keyword_false,
            .keyword_true,
            => return .{
                .bool = node.id == .keyword_true,
            },
            .function_definition => {
                // if (@intFromEnum(node_index) == 2183) @breakpoint();
                const function_prototype_node_index = node.left;
                const function_prototype_node = unit.getNode(function_prototype_node_index);
                const argument_list_node_index = function_prototype_node.left;
                const body_node_index = node.right;

                // const function_type_index = try builder.resolveFunctionPrototype(unit, context, function_prototype_node_index, global_attributes, maybe_member_value, polymorphic_argument_nodes);

                const function_definition = try builder.resolveFunctionDefinition(unit, context, .null, node_index, body_node_index, argument_list_node_index, global_attributes, maybe_member_value, polymorphic_argument_nodes, maybe_global);

                return function_definition;
            },
            .number_literal => switch (std.zig.parseNumberLiteral(unit.getExpectedTokenBytes(node.token, .number_literal))) {
                .int => |integer| {
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
            .enum_type, .struct_type, .bitfield_type => {
                const type_index = try builder.resolveContainerType(unit, context, node_index, switch (node.id) {
                    .enum_type => .@"enum",
                    .struct_type => .@"struct",
                    .bitfield_type => .bitfield,
                    else => unreachable,
                }, maybe_global, new_parameters);
                return .{
                    .type = type_index,
                };
            },
            .unsigned_integer_type, .signed_integer_type => return .{
                .type = try builder.resolveType(unit, context, node_index, new_parameters),
            },
            .@"switch" => return try builder.resolveComptimeSwitch(unit, context, type_expect, global_attributes, node_index, maybe_global),
            .identifier => {
                const identifier = unit.getExpectedTokenBytes(node.token, .identifier);
                const resolved_value = try builder.resolveIdentifier(unit, context, type_expect, identifier, global_attributes, side, new_parameters);
                return switch (resolved_value.value) {
                    .@"comptime" => |ct| ct,
                    .runtime => return error.cannot_evaluate,
                    else => unreachable,
                };
            },
            .add, .mul => {
                const left = try builder.resolveComptimeValue(unit, context, Type.Expect.none, .{}, node.left, null, .right, &.{}, null, &.{});
                const left_type = left.getType(unit);
                const right = try builder.resolveComptimeValue(unit, context, Type.Expect{ .type = left_type }, .{}, node.right, null, .right, &.{}, null, &.{});
                switch (left) {
                    .comptime_int => |left_ct_int| {
                        assert(left_ct_int.signedness == .unsigned);
                        const left_value = left_ct_int.value;
                        switch (right) {
                            .comptime_int => |right_ct_int| {
                                assert(right_ct_int.signedness == .unsigned);
                                const right_value = right_ct_int.value;
                                const result = switch (node.id) {
                                    .add => left_value + right_value,
                                    .mul => left_value * right_value,
                                    else => unreachable,
                                };
                                return .{
                                    .comptime_int = .{
                                        .value = result,
                                        .signedness = .unsigned,
                                    },
                                };
                            },
                            else => |t| @panic(@tagName(t)),
                        }
                    },
                    else => |t| @panic(@tagName(t)),
                }
            },
            .empty_container_literal_guess => {
                assert(node.left != .null);
                assert(node.right != .null);
                const container_type = try builder.resolveType(unit, context, node.left, &.{});
                const node_list = unit.getNodeList(node.right);
                assert(node_list.len == 0);
                const result = try builder.resolveContainerLiteral(unit, context, node_list, container_type);
                return switch (result.value) {
                    .@"comptime" => |ct| ct,
                    else => |t| @panic(@tagName(t)),
                };
            },
            .anonymous_container_literal => {
                assert(node.left == .null);
                assert(node.right != .null);
                switch (type_expect) {
                    .type => |type_index| {
                        const node_list = unit.getNodeList(node.right);
                        const result = try builder.resolveContainerLiteral(unit, context, node_list, type_index);
                        return switch (result.value) {
                            .@"comptime" => |ct| ct,
                            else => |t| @panic(@tagName(t)),
                        };
                    },
                    else => |t| @panic(@tagName(t)),
                }
            },
            .function_prototype => {
                var b = false;
                const function_prototype = try builder.resolveFunctionPrototype(unit, context, node_index, global_attributes, null, &.{}, null, null, null, &b, null);
                if (global_attributes.contains(.@"extern")) {
                    return .{
                        .function_declaration = function_prototype,
                    };
                } else {
                    unreachable;
                }
            },
            .error_type => {
                assert(node.left != .null);
                const nodes = unit.getNodeList(node.left);
                if (nodes.len == 0) {
                    unreachable;
                }

                const token_debug_info = builder.getTokenDebugInfo(unit, node.token);
                const error_type_index = unit.types.append_index(.{
                    .integer = .{
                        .signedness = .unsigned,
                        .bit_count = 32,
                        .kind = .{
                            .@"error" = .{
                                .scope = .{
                                    .scope = .{
                                        .file = builder.current_file,
                                        .line = token_debug_info.line,
                                        .column = token_debug_info.column,
                                        .kind = .error_type,
                                        .local = false,
                                        .level = builder.current_scope.level + 1,
                                        .parent = builder.current_scope,
                                        .declarations = try PinnedHashMap(u32, *Debug.Declaration).init(std.mem.page_size),
                                    },
                                },
                                .fields = try DynamicBoundedArray(Type.Error.Field.Index).init(context.arena, @intCast(nodes.len)),
                                .id = unit.error_count,
                            },
                        },
                    },
                });
                unit.error_count += 1;

                const error_type = &unit.types.get(error_type_index).integer.kind.@"error";
                for (nodes, 0..) |field_node_index, index| {
                    const field_node = unit.getNode(field_node_index);
                    const identifier = unit.getExpectedTokenBytes(field_node.token, .identifier);
                    const hash = try unit.processIdentifier(context, identifier);
                    const error_field_index = unit.error_fields.append_index(.{
                        .name = hash,
                        .type = error_type_index,
                        .value = index,
                    });
                    error_type.fields.append(error_field_index);
                }

                return .{
                    .type = error_type_index,
                };
            },
            .dot_literal => {
                switch (type_expect) {
                    .type => |type_index| {
                        const expected_type = unit.types.get(type_index);
                        const identifier = unit.getExpectedTokenBytes(@enumFromInt(@intFromEnum(node.token) + 1), .identifier);
                        const hash = try unit.processIdentifier(context, identifier);
                        switch (expected_type.*) {
                            .integer => |*integer| switch (integer.kind) {
                                .@"enum" => |*enum_type| {
                                    for (enum_type.fields) |field_index| {
                                        const field = unit.enum_fields.get(field_index);
                                        if (field.name == hash) {
                                            return .{
                                                .enum_value = field_index,
                                            };
                                        }
                                    } else {
                                        unreachable;
                                    }
                                },
                                .@"error" => |*error_type| {
                                    for (error_type.fields.slice()) |field_index| {
                                        const field = unit.error_fields.get(field_index);
                                        if (field.name == hash) {
                                            return .{
                                                .error_value = field_index,
                                            };
                                        }
                                    } else {
                                        unreachable;
                                    }
                                },
                                else => |t| @panic(@tagName(t)),
                            },
                            else => |t| @panic(@tagName(t)),
                        }
                    },
                    else => |t| @panic(@tagName(t)),
                }
            },
            .address_of => {
                assert(node.left != .null);
                assert(node.right == .null);

                const appointee = unit.getNode(node.left);
                switch (appointee.id) {
                    .anonymous_empty_literal => switch (type_expect) {
                        .type => |type_index| switch (unit.types.get(type_index).*) {
                            .slice => {
                                const constant_slice = unit.constant_slices.append_index(.{
                                    .array = null,
                                    .start = 0,
                                    .end = 0,
                                    .type = type_index,
                                });

                                return .{
                                    .constant_slice = constant_slice,
                                };
                            },
                            else => |t| @panic(@tagName(t)),
                        },
                        else => |t| @panic(@tagName(t)),
                    },
                    else => |t| @panic(@tagName(t)),
                }
            },
            .character_literal => return try unit.resolve_character_literal(node_index),
            .negation => {
                assert(node.left != .null);
                assert(node.right == .null);

                const value = try builder.resolveComptimeValue(unit, context, type_expect, .{}, node.left, null, .right, &.{}, null, &.{});
                switch (value) {
                    .constant_int => |constant_int| switch (type_expect) {
                        .type => |type_index| {
                            assert(type_index == value.type);
                            const expected_type = unit.types.get(type_index);
                            switch (expected_type.*) {
                                .integer => |integer| switch (integer.kind) {
                                    .materialized_int => {
                                        assert(integer.signedness == .signed);
                                        var v: i64 = @intCast(constant_int.value);
                                        v = 0 - v;

                                        return .{
                                            .constant_int = .{
                                                .value = @bitCast(v),
                                            },
                                        };
                                    },
                                    else => |t| @panic(@tagName(t)),
                                },
                                else => |t| @panic(@tagName(t)),
                            }
                        },
                        else => |t| @panic(@tagName(t)),
                    },
                    .comptime_int => |ct_int| switch (type_expect) {
                        .type => |type_index| switch (unit.types.get(type_index).*) {
                            .integer => |integer| switch (integer.kind) {
                                .materialized_int => {
                                    assert(integer.signedness == .signed);
                                    var v = switch (ct_int.signedness) {
                                        .signed => 0 - @as(i64, @intCast(ct_int.value)),
                                        .unsigned => @as(i64, @intCast(ct_int.value)),
                                    };
                                    v = 0 - v;

                                    return .{
                                        .constant_int = .{
                                            .value = @bitCast(v),
                                        },
                                    };
                                },
                                else => |t| @panic(@tagName(t)),
                            },
                            else => |t| @panic(@tagName(t)),
                        },
                        .none => {
                            return .{
                                .comptime_int = .{
                                    .value = ct_int.value,
                                    .signedness = switch (ct_int.signedness) {
                                        .unsigned => .signed,
                                        .signed => .unsigned,
                                    },
                                },
                            };
                        },
                        else => |t| @panic(@tagName(t)),
                    },
                    else => |t| @panic(@tagName(t)),
                }
            },
            else => |t| @panic(@tagName(t)),
        }
    }

    fn resolveRuntimeValue(builder: *Builder, unit: *Unit, context: *const Context, type_expect: Type.Expect, node_index: Node.Index, side: Side) anyerror!V {
        const node = unit.getNode(node_index);

        const v: V = switch (node.id) {
            .identifier => block: {
                const identifier = unit.getExpectedTokenBytes(node.token, .identifier);
                const result = try builder.resolveIdentifier(unit, context, type_expect, identifier, .{}, side, &.{});
                break :block result;
            },
            .intrinsic => try builder.resolveIntrinsic(unit, context, type_expect, node_index, side),
            .pointer_dereference => block: {
                // TODO:
                const pointer_type_expect = switch (type_expect) {
                    .none => type_expect,
                    .type => |type_index| b: {
                        const pointer_type = try unit.getPointerType(.{
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
                    .cast => Type.Expect.none,
                    else => unreachable,
                };

                const left_node = unit.getNode(node.left);
                switch (left_node.id) {
                    .string_literal => {
                        const string_literal = try unit.fixupStringLiteral(context, left_node.token);
                        var values = try context.arena.new_array(V.Comptime, string_literal.len);

                        for (string_literal, 0..) |b, i| {
                            values[i] = V.Comptime{
                                .constant_int = .{
                                    .value = b,
                                },
                            };
                        }

                        const array_type = try unit.getArrayType(.{
                            .count = string_literal.len,
                            .type = .u8,
                            .termination = .none,
                        });

                        return V{
                            .value = .{
                                .@"comptime" = .{
                                    .constant_array = unit.constant_arrays.append_index(.{
                                        .values = values,
                                        .type = array_type,
                                    }),
                                },
                            },
                            .type = array_type,
                        };
                    },
                    else => {
                        const pointer_like_value = try builder.resolveRuntimeValue(unit, context, pointer_type_expect, node.left, .right);

                        break :block switch (side) {
                            .left => pointer_like_value,
                            .right => switch (unit.types.get(pointer_like_value.type).*) {
                                .pointer => |pointer| right: {
                                    const load_type = switch (type_expect) {
                                        .none, .cast => b: {
                                            const pointer_element_type = pointer.type;
                                            break :b pointer_element_type;
                                        },
                                        .type => |type_index| type_index,
                                        else => unreachable,
                                    };

                                    const load = unit.instructions.append_index(.{
                                        .load = .{
                                            .value = pointer_like_value,
                                            .type = load_type,
                                        },
                                    });
                                    try builder.appendInstruction(unit, load);

                                    break :right .{
                                        .value = .{
                                            .runtime = load,
                                        },
                                        .type = load_type,
                                    };
                                },
                                .integer => switch (type_expect) {
                                    .type => |type_index| if (type_index == pointer_like_value.type) pointer_like_value else unreachable,
                                    else => |t| @panic(@tagName(t)),
                                },
                                else => |t| @panic(@tagName(t)),
                            },
                        };
                    },
                }
            },
            .compare_equal,
            .compare_not_equal,
            .compare_greater,
            .compare_greater_equal,
            .compare_less,
            .compare_less_equal,
            => |cmp_node_id| block: {
                const left_node_index = node.left;
                const right_node_index = node.right;
                const left_expect_type = Type.Expect.none;
                var left_value = try builder.resolveRuntimeValue(unit, context, left_expect_type, left_node_index, .right);
                const right_expect_type = switch (left_value.type) {
                    .comptime_int => Type.Expect.none,
                    else => Type.Expect{ .type = left_value.type },
                };
                var right_value = try builder.resolveRuntimeValue(unit, context, right_expect_type, right_node_index, .right);

                if (left_value.value == .@"comptime" and right_value.value == .@"comptime") {
                    const left = switch (left_value.value.@"comptime") {
                        .comptime_int => |ct_int| b: {
                            assert(ct_int.signedness == .unsigned);
                            break :b ct_int.value;
                        },
                        .constant_int => |constant_int| constant_int.value,
                        else => |t| @panic(@tagName(t)),
                    };

                    const right = switch (right_value.value.@"comptime") {
                        .comptime_int => |ct_int| b: {
                            assert(ct_int.signedness == .unsigned);
                            break :b ct_int.value;
                        },
                        .constant_int => |constant_int| constant_int.value,
                        else => |t| @panic(@tagName(t)),
                    };

                    const result = switch (cmp_node_id) {
                        .compare_equal => left == right,
                        .compare_not_equal => left != right,
                        .compare_greater => left > right,
                        .compare_greater_equal => left >= right,
                        .compare_less => left < right,
                        .compare_less_equal => left <= right,
                        else => |t| @panic(@tagName(t)),
                    };

                    break :block V{
                        .value = .{
                            .@"comptime" = .{
                                .bool = result,
                            },
                        },
                        .type = .bool,
                    };
                } else {
                    if (left_value.type != .comptime_int and right_value.type == .comptime_int) {
                        const ct_int = right_value.value.@"comptime".comptime_int;
                        right_value = .{
                            .value = .{
                                .@"comptime" = .{
                                    .constant_int = .{
                                        .value = switch (ct_int.signedness) {
                                            .unsigned => ct_int.value,
                                            .signed => unreachable,
                                        },
                                    },
                                },
                            },
                            .type = left_value.type,
                        };
                    } else if (left_value.type == .comptime_int and right_value.type != .comptime_int) {
                        const ct_int = left_value.value.@"comptime".comptime_int;
                        left_value = .{
                            .value = .{
                                .@"comptime" = .{
                                    .constant_int = .{
                                        .value = switch (ct_int.signedness) {
                                            .unsigned => ct_int.value,
                                            .signed => unreachable,
                                        },
                                    },
                                },
                            },
                            .type = right_value.type,
                        };
                    }

                    break :block switch (unit.types.get(left_value.type).*) {
                        .integer => |integer| switch (integer.kind) {
                            .materialized_int, .bool => try builder.emitIntegerCompare(unit, context, left_value, right_value, integer, cmp_node_id),
                            else => |t| @panic(@tagName(t)),
                        },
                        .pointer => |pointer| b: {
                            const Pair = struct {
                                left: V,
                                right: V,
                            };

                            const pair: Pair = if (left_value.type == right_value.type) .{ .left = left_value, .right = right_value } else switch (unit.types.get(right_value.type).*) {
                                .pointer => |right_pointer| blk: {
                                    assert(pointer.type == right_pointer.type);
                                    assert(pointer.mutability == right_pointer.mutability);
                                    assert(pointer.termination == right_pointer.termination);
                                    assert(pointer.many == right_pointer.many);
                                    assert(pointer.nullable != right_pointer.nullable);

                                    if (pointer.nullable) {
                                        // Left nullable
                                        unreachable;
                                    } else {
                                        // Right nullable, then we cast the left side to optional
                                        const cast = unit.instructions.append_index(.{
                                            .cast = .{
                                                .id = .pointer_to_nullable,
                                                .value = left_value,
                                                .type = right_value.type,
                                            },
                                        });
                                        try builder.appendInstruction(unit, cast);

                                        const new_left_value = V{
                                            .value = .{
                                                .runtime = cast,
                                            },
                                            .type = right_value.type,
                                        };

                                        break :blk .{
                                            .left = new_left_value,
                                            .right = right_value,
                                        };
                                    }
                                },
                                else => |t| @panic(@tagName(t)),
                            };

                            const compare = try builder.emitIntegerCompare(unit, context, pair.left, pair.right, .{
                                .bit_count = 64,
                                .signedness = .unsigned,
                                .kind = .disguised_pointer,
                            }, cmp_node_id);

                            break :b compare;
                        },
                        else => |t| @panic(@tagName(t)),
                    };
                }
            },
            .add, .wrapping_add, .saturated_add, .sub, .wrapping_sub, .saturated_sub, .mul, .wrapping_mul, .saturated_mul, .div, .mod, .bit_and, .bit_or, .bit_xor, .shift_left, .shift_right, .bool_and, .bool_or => block: {
                const left_node_index = node.left;
                const right_node_index = node.right;
                const binary_operation_id: ArithmeticLogicIntegerInstruction = switch (node.id) {
                    .add => .add,
                    .wrapping_add => .wrapping_add,
                    .saturated_add => .saturated_add,
                    .sub => .sub,
                    .wrapping_sub => .wrapping_sub,
                    .saturated_sub => .saturated_sub,
                    .mul => .mul,
                    .wrapping_mul => .wrapping_mul,
                    .saturated_mul => .saturated_mul,
                    .div => .div,
                    .mod => .mod,
                    .bit_and => .bit_and,
                    .bit_xor => .bit_xor,
                    .bit_or => .bit_or,
                    .shift_left => .shift_left,
                    .shift_right => .shift_right,
                    .bool_and => .bit_and,
                    .bool_or => .bit_or,
                    else => |t| @panic(@tagName(t)),
                };

                const left_expect_type = type_expect;

                var left_value = try builder.resolveRuntimeValue(unit, context, left_expect_type, left_node_index, .right);
                switch (unit.types.get(left_value.type).*) {
                    .integer => |int| switch (int.kind) {
                        .materialized_int, .comptime_int, .bool => {
                            const right_expect_type: Type.Expect = switch (type_expect) {
                                .none, .cast => switch (left_value.type) {
                                    .comptime_int => type_expect,
                                    else => Type.Expect{
                                        .type = left_value.type,
                                    },
                                },
                                .type => switch (binary_operation_id) {
                                    .add,
                                    .wrapping_add,
                                    .saturated_add,
                                    .sub,
                                    .wrapping_sub,
                                    .saturated_sub,
                                    .bit_and,
                                    .bit_xor,
                                    .bit_or,
                                    .mul,
                                    .wrapping_mul,
                                    .saturated_mul,
                                    .div,
                                    .mod,
                                    .shift_left,
                                    .shift_right,
                                    => type_expect,
                                },
                                else => unreachable,
                            };
                            var right_value = try builder.resolveRuntimeValue(unit, context, right_expect_type, right_node_index, .right);

                            if (left_value.value == .@"comptime" and right_value.value == .@"comptime") {
                                const left = switch (left_value.value.@"comptime") {
                                    .comptime_int => |ct_int| b: {
                                        assert(ct_int.signedness == .unsigned);
                                        break :b ct_int.value;
                                    },
                                    .constant_int => |constant_int| constant_int.value,
                                    else => |t| @panic(@tagName(t)),
                                };
                                const right = switch (right_value.value.@"comptime") {
                                    .comptime_int => |ct_int| b: {
                                        assert(ct_int.signedness == .unsigned);
                                        break :b ct_int.value;
                                    },
                                    .constant_int => |constant_int| constant_int.value,
                                    else => |t| @panic(@tagName(t)),
                                };

                                const result = switch (binary_operation_id) {
                                    .add => left + right,
                                    .sub => left - right,
                                    .mul => left * right,
                                    .div => left / right,
                                    .mod => left % right,
                                    .bit_and => left & right,
                                    .bit_or => left | right,
                                    .bit_xor => left ^ right,
                                    .shift_left => left << @as(u6, @intCast(right)),
                                    .shift_right => left >> @as(u6, @intCast(right)),
                                    else => unreachable,
                                };

                                break :block switch (type_expect) {
                                    .type => |type_index| .{
                                        .value = .{
                                            .@"comptime" = .{
                                                .constant_int = .{
                                                    .value = result,
                                                },
                                            },
                                        },
                                        .type = type_index,
                                    },
                                    .none => .{
                                        .value = .{
                                            .@"comptime" = .{
                                                .comptime_int = .{
                                                    .value = result,
                                                    .signedness = .unsigned,
                                                },
                                            },
                                        },
                                        .type = .comptime_int,
                                    },
                                    else => |t| @panic(@tagName(t)),
                                };
                            } else {
                                if (left_value.type != .comptime_int and right_value.type == .comptime_int) {
                                    const r_comptime_int = right_value.value.@"comptime".comptime_int;
                                    right_value = .{
                                        .value = .{
                                            .@"comptime" = .{
                                                .constant_int = .{
                                                    .value = switch (r_comptime_int.signedness) {
                                                        .unsigned => r_comptime_int.value,
                                                        .signed => unreachable,
                                                    },
                                                },
                                            },
                                        },
                                        .type = left_value.type,
                                    };
                                } else if (left_value.type == .comptime_int and right_value.type != .comptime_int) {
                                    const l_comptime_int = left_value.value.@"comptime".comptime_int;
                                    left_value = .{
                                        .value = .{
                                            .@"comptime" = .{
                                                .constant_int = .{
                                                    .value = switch (l_comptime_int.signedness) {
                                                        .unsigned => l_comptime_int.value,
                                                        .signed => unreachable,
                                                    },
                                                },
                                            },
                                        },
                                        .type = right_value.type,
                                    };
                                }

                                const result = try builder.typecheck(unit, context, left_value.type, right_value.type);
                                break :block switch (result) {
                                    .success => {
                                        assert(left_value.type == right_value.type);

                                        const type_index = switch (type_expect) {
                                            .none, .cast => switch (binary_operation_id) {
                                                .bit_and,
                                                .bit_or,
                                                .bit_xor,
                                                .shift_right,
                                                .add,
                                                .wrapping_add,
                                                .saturated_add,
                                                .sub,
                                                .wrapping_sub,
                                                .saturated_sub,
                                                .mul,
                                                .wrapping_mul,
                                                .saturated_mul,
                                                .div,
                                                .mod,
                                                => left_value.type,
                                                else => |t| @panic(@tagName(t)),
                                            },
                                            .type => |type_index| type_index,
                                            else => unreachable,
                                        };

                                        const instruction = switch (unit.types.get(left_value.type).*) {
                                            .integer => |integer| switch (integer.kind) {
                                                .materialized_int => b: {
                                                    const id: Instruction.IntegerBinaryOperation.Id = switch (binary_operation_id) {
                                                        .add => .add,
                                                        .wrapping_add => .wrapping_add,
                                                        .saturated_add => .saturated_add,
                                                        .sub => .sub,
                                                        .wrapping_sub => .wrapping_sub,
                                                        .saturated_sub => .saturated_sub,
                                                        .mul => .mul,
                                                        .wrapping_mul => .wrapping_mul,
                                                        .saturated_mul => .saturated_mul,
                                                        .div => .div,
                                                        .mod => .mod,
                                                        .bit_and => .bit_and,
                                                        .bit_or => .bit_or,
                                                        .bit_xor => .bit_xor,
                                                        .shift_left => .shift_left,
                                                        .shift_right => .shift_right,
                                                    };

                                                    const i = unit.instructions.append_index(.{
                                                        .integer_binary_operation = .{
                                                            .left = left_value,
                                                            .right = right_value,
                                                            .id = id,
                                                            .signedness = integer.signedness,
                                                        },
                                                    });
                                                    break :b i;
                                                },
                                                .bool => b: {
                                                    const id: Instruction.IntegerBinaryOperation.Id = switch (binary_operation_id) {
                                                        .bit_and => .bit_and,
                                                        .bit_or => .bit_or,
                                                        else => |t| @panic(@tagName(t)),
                                                    };
                                                    const i = unit.instructions.append_index(.{
                                                        .integer_binary_operation = .{
                                                            .left = left_value,
                                                            .right = right_value,
                                                            .id = id,
                                                            .signedness = .unsigned,
                                                        },
                                                    });
                                                    break :b i;
                                                },
                                                else => |t| @panic(@tagName(t)),
                                            },
                                            else => |t| @panic(@tagName(t)),
                                        };

                                        try builder.appendInstruction(unit, instruction);

                                        break :block .{
                                            .value = .{
                                                .runtime = instruction,
                                            },
                                            .type = type_index,
                                        };
                                    },
                                    else => |t| @panic(@tagName(t)),
                                };
                            }
                        },
                        else => |t| @panic(@tagName(t)),
                    },
                    .pointer => |pointer| {
                        const right_value = try builder.resolveRuntimeValue(unit, context, Type.Expect.none, right_node_index, .right);
                        switch (binary_operation_id) {
                            .add => switch (unit.types.get(right_value.type).*) {
                                .integer => {
                                    const gep = unit.instructions.append_index(.{
                                        .get_element_pointer = .{
                                            .index = right_value,
                                            .pointer = left_value.value.runtime,
                                            .base_type = pointer.type,
                                            .name = try unit.processIdentifier(context, "pointer_add"),
                                            .is_struct = false,
                                        },
                                    });
                                    try builder.appendInstruction(unit, gep);

                                    const v = V{
                                        .value = .{ .runtime = gep },
                                        .type = left_value.type,
                                    };

                                    break :block switch (type_expect) {
                                        .type => |destination_type_index| switch (try builder.typecheck(unit, context, destination_type_index, left_value.type)) {
                                            .success => v,
                                            else => |t| @panic(@tagName(t)),
                                        },
                                        .none => v,
                                        else => |t| @panic(@tagName(t)),
                                    };
                                },
                                else => |t| @panic(@tagName(t)),
                            },
                            else => |t| @panic(@tagName(t)),
                        }
                        // switch (right_value.value) {
                        //     .runtime => |_| switch (unit.types.get(right_value.type).*) {
                        //         .integer => |integer| {
                        //             _ = integer; // autofix
                        //         },
                        //         else => |t| @panic(@tagName(t)),
                        //     },
                        //     else => |t| @panic(@tagName(t)),
                        // }
                        unreachable;
                    },
                    else => |t| @panic(@tagName(t)),
                }
            },
            .call => try builder.resolveCall(unit, context, node_index),
            .field_access => try builder.resolveFieldAccess(unit, context, type_expect, node_index, side, &.{}),
            .number_literal => switch (std.zig.parseNumberLiteral(unit.getExpectedTokenBytes(node.token, .number_literal))) {
                .int => |integer_value| switch (type_expect) {
                    .type => |type_index| switch (unit.types.get(type_index).*) {
                        .integer => |integer| switch (integer.kind) {
                            .materialized_int => V{
                                .value = .{
                                    .@"comptime" = .{
                                        .constant_int = .{
                                            .value = integer_value,
                                        },
                                    },
                                },
                                .type = type_index,
                            },
                            else => |t| @panic(@tagName(t)),
                        },
                        else => |t| @panic(@tagName(t)),
                    },
                    .none => V{
                        .value = .{
                            .@"comptime" = .{
                                .comptime_int = .{
                                    .value = integer_value,
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
                const block = try builder.resolveBlock(unit, context, node_index);
                const block_i = unit.instructions.append_index(.{
                    .block = block,
                });
                break :block .{
                    .value = .{
                        .runtime = block_i,
                    },
                    .type = if (builder.current_basic_block != .null and unit.basic_blocks.get(builder.current_basic_block).terminated) .noreturn else switch (type_expect) {
                        .type => |type_index| switch (unit.types.get(type_index).*) {
                            .void => type_index,
                            else => |t| @panic(@tagName(t)),
                        },
                        else => |t| @panic(@tagName(t)),
                    },
                };
            },
            .container_literal => block: {
                assert(node.left != .null);
                assert(node.right != .null);
                const initialization_nodes = unit.getNodeList(node.right);
                const container_type_index = try builder.resolveType(unit, context, node.left, &.{});

                const result = try builder.resolveContainerLiteral(unit, context, initialization_nodes, container_type_index);
                break :block result;
            },
            .anonymous_container_literal => block: {
                switch (type_expect) {
                    .type => |type_index| {
                        assert(node.left == .null);
                        assert(node.right != .null);
                        const initialization_nodes = unit.getNodeList(node.right);
                        const result = try builder.resolveContainerLiteral(unit, context, initialization_nodes, type_index);
                        break :block result;
                    },
                    else => |t| @panic(@tagName(t)),
                }
                unreachable;
            },
            .dot_literal => block: {
                switch (type_expect) {
                    .type => |type_index| {
                        const expected_type = unit.types.get(type_index);
                        switch (expected_type.*) {
                            .integer => |*integer| switch (integer.kind) {
                                .@"enum" => |*enum_type| {
                                    const identifier = unit.getExpectedTokenBytes(@enumFromInt(@intFromEnum(node.token) + 1), .identifier);
                                    const hash = try unit.processIdentifier(context, identifier);
                                    for (enum_type.fields) |field_index| {
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
                            },
                            else => |t| @panic(@tagName(t)),
                        }
                    },
                    else => |t| @panic(@tagName(t)),
                }
            },
            .null_literal => switch (type_expect) {
                .type => |type_index| switch (unit.types.get(type_index).*) {
                    .pointer => |pointer| .{
                        .value = .{
                            .@"comptime" = .null_pointer,
                        },
                        .type = if (pointer.nullable) type_index else blk: {
                            var p = pointer;
                            p.nullable = true;
                            const nullable_pointer = try unit.getPointerType(p);
                            break :blk nullable_pointer;
                        },
                    },
                    .slice => |slice| if (slice.nullable) b: {
                        const constant_slice = unit.constant_slices.append_index(.{
                            .array = null,
                            .start = 0,
                            .end = 0,
                            .type = type_index,
                        });
                        break :b V{
                            .value = .{
                                .@"comptime" = .{
                                    .constant_slice = constant_slice,
                                },
                            },
                            .type = type_index,
                        };
                    } else {
                        unreachable;
                    },
                    else => |t| @panic(@tagName(t)),
                },
                else => |t| @panic(@tagName(t)),
            },
            .slice => block: {
                const expression_to_slice = try builder.resolveRuntimeValue(unit, context, Type.Expect.none, node.left, .left);

                const slice_metadata_node = unit.getNode(node.right);
                const range_node = unit.getNode(slice_metadata_node.left);
                assert(range_node.id == .range);
                const range_start: V = try builder.resolveRuntimeValue(unit, context, Type.Expect{ .type = Type.usize }, range_node.left, .right);
                const range_end: V = switch (range_node.right) {
                    .null => switch (unit.types.get(expression_to_slice.type).*) {
                        .slice => b: {
                            const extract_value = unit.instructions.append_index(.{
                                .extract_value = .{
                                    .expression = expression_to_slice,
                                    .index = 1,
                                },
                            });
                            try builder.appendInstruction(unit, extract_value);

                            break :b .{
                                .value = .{
                                    .runtime = extract_value,
                                },
                                .type = Type.usize,
                            };
                        },
                        .pointer => |pointer| switch (pointer.many) {
                            true => unreachable,
                            false => switch (unit.types.get(pointer.type).*) {
                                .array => |array| .{
                                    .value = .{
                                        .@"comptime" = .{
                                            .constant_int = .{
                                                .value = array.count,
                                            },
                                        },
                                    },
                                    .type = Type.usize,
                                },
                                .slice => |slice| b: {
                                    _ = slice; // autofix
                                    assert(!pointer.many);
                                    const gep = unit.instructions.append_index(.{
                                        .get_element_pointer = .{
                                            .pointer = expression_to_slice.value.runtime,
                                            .is_struct = true,
                                            .base_type = pointer.type,
                                            .index = .{
                                                .value = .{
                                                    .@"comptime" = .{
                                                        .constant_int = .{
                                                            .value = 1,
                                                        },
                                                    },
                                                },
                                                .type = .u32,
                                            },
                                            .name = try unit.processIdentifier(context, "slice_end_gep"),
                                        },
                                    });
                                    try builder.appendInstruction(unit, gep);

                                    const load = unit.instructions.append_index(.{
                                        .load = .{
                                            .value = .{
                                                .value = .{
                                                    .runtime = gep,
                                                },
                                                .type = try unit.getPointerType(.{
                                                    .type = Type.usize,
                                                    .termination = .none,
                                                    .many = false,
                                                    .nullable = false,
                                                    .mutability = .@"const",
                                                }),
                                            },
                                            .type = Type.usize,
                                        },
                                    });
                                    try builder.appendInstruction(unit, load);

                                    break :b V{
                                        .value = .{
                                            .runtime = load,
                                        },
                                        .type = Type.usize,
                                    };
                                },
                                .pointer => |child_pointer| b: {
                                    assert(!child_pointer.many);
                                    switch (unit.types.get(child_pointer.type).*) {
                                        .array => |array| {
                                            break :b V{
                                                .value = .{
                                                    .@"comptime" = .{
                                                        .constant_int = .{
                                                            .value = array.count,
                                                        },
                                                    },
                                                },
                                                .type = Type.usize,
                                            };
                                        },
                                        else => |t| @panic(@tagName(t)),
                                    }
                                    @panic("Range end of many-item pointer is unknown");
                                },
                                else => |t| @panic(@tagName(t)),
                            },
                        },
                        else => |t| @panic(@tagName(t)),
                    },
                    else => try builder.resolveRuntimeValue(unit, context, Type.Expect{ .type = Type.usize }, range_node.right, .right),
                };

                const len_expression: V = b: {
                    if (range_start.value == .@"comptime" and range_end.value == .@"comptime") {
                        const end = switch (range_end.value.@"comptime") {
                            .constant_int => |constant_int| constant_int.value,
                            else => |t| @panic(@tagName(t)),
                        };
                        const start = switch (range_start.value.@"comptime") {
                            .constant_int => |constant_int| constant_int.value,
                            else => |t| @panic(@tagName(t)),
                        };
                        const len = end - start;
                        break :b V{
                            .value = .{
                                .@"comptime" = .{
                                    .constant_int = .{
                                        .value = len,
                                    },
                                },
                            },
                            .type = Type.usize,
                        };
                    } else {
                        const range_compute = unit.instructions.append_index(.{
                            .integer_binary_operation = .{
                                .left = range_end,
                                .right = range_start,
                                .id = .sub,
                                .signedness = .unsigned,
                            },
                        });

                        try builder.appendInstruction(unit, range_compute);

                        break :b .{
                            .value = .{
                                .runtime = range_compute,
                            },
                            .type = Type.usize,
                        };
                    }
                };

                switch (len_expression.value) {
                    .@"comptime" => {
                        const pointer_value = switch (unit.types.get(expression_to_slice.type).*) {
                            .slice => |slice| slice: {
                                const extract_pointer = unit.instructions.append_index(.{
                                    .extract_value = .{
                                        .expression = expression_to_slice,
                                        .index = 0,
                                    },
                                });
                                try builder.appendInstruction(unit, extract_pointer);

                                const gep = unit.instructions.append_index(.{
                                    .get_element_pointer = .{
                                        .pointer = extract_pointer,
                                        .index = range_start,
                                        .base_type = slice.child_type,
                                        .name = try unit.processIdentifier(context, "slice_comptime_expression_slice"),
                                        .is_struct = false,
                                    },
                                });
                                try builder.appendInstruction(unit, gep);

                                break :slice V{
                                    .value = .{
                                        .runtime = gep,
                                    },
                                    .type = try unit.getPointerType(.{
                                        .type = try unit.getArrayType(.{
                                            .type = slice.child_type,
                                            .count = len_expression.value.@"comptime".constant_int.value,
                                            .termination = slice.termination,
                                        }),
                                        .termination = .none,
                                        .mutability = slice.mutability,
                                        .many = true,
                                        .nullable = false,
                                    }),
                                };
                            },
                            .pointer => |pointer| switch (pointer.many) {
                                true => unreachable,
                                false => switch (unit.types.get(pointer.type).*) {
                                    .slice => |slice| slice: {
                                        const load = unit.instructions.append_index(.{
                                            .load = .{
                                                .value = expression_to_slice,
                                                .type = slice.child_pointer_type,
                                            },
                                        });
                                        try builder.appendInstruction(unit, load);

                                        const gep = unit.instructions.append_index(.{
                                            .get_element_pointer = .{
                                                .pointer = load,
                                                .index = range_start,
                                                .base_type = slice.child_type,
                                                .name = try unit.processIdentifier(context, "slice_comptime_expression_slice"),
                                                .is_struct = false,
                                            },
                                        });
                                        try builder.appendInstruction(unit, gep);

                                        break :slice V{
                                            .value = .{
                                                .runtime = gep,
                                            },
                                            .type = try unit.getPointerType(.{
                                                .type = try unit.getArrayType(.{
                                                    .type = slice.child_type,
                                                    .count = len_expression.value.@"comptime".constant_int.value,
                                                    .termination = slice.termination,
                                                }),
                                                .termination = .none,
                                                .mutability = slice.mutability,
                                                .many = true,
                                                .nullable = false,
                                            }),
                                        };
                                    },
                                    .pointer => |child_pointer| switch (type_expect) {
                                        .type => |destination_type_index| switch (unit.types.get(destination_type_index).*) {
                                            .slice => |slice| if (slice.child_type == child_pointer.type) {
                                                unreachable;
                                            } else switch (unit.types.get(child_pointer.type).*) {
                                                .array => |array| if (array.type == slice.child_type) pointer: {
                                                    const load = unit.instructions.append_index(.{
                                                        .load = .{
                                                            .value = expression_to_slice,
                                                            .type = pointer.type,
                                                        },
                                                    });
                                                    try builder.appendInstruction(unit, load);
                                                    const gep = unit.instructions.append_index(.{
                                                        .get_element_pointer = .{
                                                            .pointer = load,
                                                            .index = range_start,
                                                            .base_type = slice.child_type,
                                                            .name = try unit.processIdentifier(context, "slice_comptime_expression_pointer"),
                                                            .is_struct = false,
                                                        },
                                                    });
                                                    try builder.appendInstruction(unit, gep);
                                                    break :pointer V{
                                                        .value = .{
                                                            .runtime = gep,
                                                        },
                                                        .type = pointer.type,
                                                    };
                                                } else unreachable,
                                                else => |t| @panic(@tagName(t)),
                                            },
                                            else => |t| @panic(@tagName(t)),
                                        },
                                        else => |t| @panic(@tagName(t)),
                                    },
                                    else => |t| @panic(@tagName(t)),
                                },
                            },
                            else => |t| @panic(@tagName(t)),
                        };

                        switch (type_expect) {
                            .type => |destination_type_index| switch (try builder.typecheck(unit, context, destination_type_index, pointer_value.type)) {
                                .pointer_to_array_coerce_to_slice => switch (pointer_value.value) {
                                    .runtime => {
                                        const insert_pointer = unit.instructions.append_index(.{
                                            .insert_value = .{
                                                .expression = .{
                                                    .value = .{
                                                        .@"comptime" = .undefined,
                                                    },
                                                    .type = destination_type_index,
                                                },
                                                .index = 0,
                                                .new_value = pointer_value,
                                            },
                                        });
                                        try builder.appendInstruction(unit, insert_pointer);

                                        const insert_length = unit.instructions.append_index(.{
                                            .insert_value = .{
                                                .expression = .{
                                                    .value = .{
                                                        .runtime = insert_pointer,
                                                    },
                                                    .type = destination_type_index,
                                                },
                                                .index = 1,
                                                .new_value = len_expression,
                                            },
                                        });
                                        try builder.appendInstruction(unit, insert_length);

                                        break :block V{
                                            .value = .{
                                                .runtime = insert_length,
                                            },
                                            .type = destination_type_index,
                                        };
                                    },
                                    else => |t| @panic(@tagName(t)),
                                },
                                else => |t| @panic(@tagName(t)),
                            },
                            .none => break :block pointer_value,
                            else => |t| @panic(@tagName(t)),
                        }
                    },
                    .runtime => {
                        const slice_value: V = switch (unit.types.get(expression_to_slice.type).*) {
                            .slice => |slice| blk: {
                                const extract_value = unit.instructions.append_index(.{
                                    .extract_value = .{
                                        .expression = expression_to_slice,
                                        .index = 0,
                                    },
                                });
                                try builder.appendInstruction(unit, extract_value);

                                const pointer_type = slice.child_pointer_type;
                                const pointer_gep = unit.instructions.append_index(.{
                                    .get_element_pointer = .{
                                        .pointer = extract_value,
                                        .is_struct = false,
                                        .base_type = slice.child_type,
                                        .index = range_start,
                                        .name = try unit.processIdentifier(context, "slice_pointer_gep"),
                                    },
                                });
                                try builder.appendInstruction(unit, pointer_gep);

                                const slice_builder = unit.instructions.append_index(.{
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
                                try builder.appendInstruction(unit, slice_builder);

                                const final_slice = unit.instructions.append_index(.{
                                    .insert_value = .{
                                        .expression = V{
                                            .value = .{
                                                .runtime = slice_builder,
                                            },
                                            .type = expression_to_slice.type,
                                        },
                                        .index = 1,
                                        .new_value = len_expression,
                                    },
                                });

                                try builder.appendInstruction(unit, final_slice);

                                break :blk .{
                                    .value = .{
                                        .runtime = final_slice,
                                    },
                                    .type = expression_to_slice.type,
                                };
                            },
                            .pointer => |pointer| switch (pointer.many) {
                                true => blk: {
                                    const pointer_gep = unit.instructions.append_index(.{
                                        .get_element_pointer = .{
                                            .pointer = expression_to_slice.value.runtime,
                                            .is_struct = false,
                                            .base_type = pointer.type,
                                            .index = range_start,
                                            .name = try unit.processIdentifier(context, "pointer_many_slice"),
                                        },
                                    });
                                    try builder.appendInstruction(unit, pointer_gep);

                                    const pointer_type = try unit.getPointerType(.{
                                        .type = pointer.type,
                                        .termination = pointer.termination,
                                        .mutability = pointer.mutability,
                                        .many = true,
                                        .nullable = false,
                                    });

                                    const slice_type = try unit.getSliceType(.{
                                        .child_type = pointer.type,
                                        .child_pointer_type = pointer_type,
                                        .mutability = pointer.mutability,
                                        .termination = pointer.termination,
                                        .nullable = false,
                                    });

                                    const slice_builder = unit.instructions.append_index(.{
                                        .insert_value = .{
                                            .expression = V{
                                                .value = .{
                                                    .@"comptime" = .undefined,
                                                },
                                                .type = slice_type,
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
                                    try builder.appendInstruction(unit, slice_builder);

                                    const final_slice = unit.instructions.append_index(.{
                                        .insert_value = .{
                                            .expression = V{
                                                .value = .{
                                                    .runtime = slice_builder,
                                                },
                                                .type = slice_type,
                                            },
                                            .index = 1,
                                            .new_value = len_expression,
                                        },
                                    });
                                    try builder.appendInstruction(unit, final_slice);

                                    break :blk .{
                                        .value = .{
                                            .runtime = final_slice,
                                        },
                                        .type = slice_type,
                                    };
                                },
                                false => switch (unit.types.get(pointer.type).*) {
                                    .array => |array| blk: {
                                        assert(!pointer.nullable);
                                        const pointer_gep = unit.instructions.append_index(.{
                                            .get_element_pointer = .{
                                                .pointer = expression_to_slice.value.runtime,
                                                .base_type = array.type,
                                                .is_struct = false,
                                                .index = range_start,
                                                .name = try unit.processIdentifier(context, "array_slice"),
                                            },
                                        });
                                        try builder.appendInstruction(unit, pointer_gep);

                                        const pointer_type = try unit.getPointerType(.{
                                            .type = array.type,
                                            .termination = array.termination,
                                            .mutability = pointer.mutability,
                                            .many = true,
                                            .nullable = false,
                                        });

                                        const slice_type = try unit.getSliceType(.{
                                            .child_type = array.type,
                                            .child_pointer_type = pointer_type,
                                            .termination = array.termination,
                                            .mutability = pointer.mutability,
                                            .nullable = pointer.nullable,
                                        });

                                        const slice_builder = unit.instructions.append_index(.{
                                            .insert_value = .{
                                                .expression = V{
                                                    .value = .{
                                                        .@"comptime" = .undefined,
                                                    },
                                                    .type = slice_type,
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
                                        try builder.appendInstruction(unit, slice_builder);

                                        const final_slice = unit.instructions.append_index(.{
                                            .insert_value = .{
                                                .expression = V{
                                                    .value = .{
                                                        .runtime = slice_builder,
                                                    },
                                                    .type = slice_type,
                                                },
                                                .index = 1,
                                                .new_value = len_expression,
                                            },
                                        });
                                        try builder.appendInstruction(unit, final_slice);

                                        break :blk .{
                                            .value = .{
                                                .runtime = final_slice,
                                            },
                                            .type = slice_type,
                                        };
                                    },
                                    .pointer => |child_pointer| switch (child_pointer.many) {
                                        true => blk: {
                                            assert(!child_pointer.nullable);
                                            const load = unit.instructions.append_index(.{
                                                .load = .{
                                                    .value = expression_to_slice,
                                                    .type = pointer.type,
                                                },
                                            });
                                            try builder.appendInstruction(unit, load);

                                            const pointer_gep = unit.instructions.append_index(.{
                                                .get_element_pointer = .{
                                                    .pointer = load,
                                                    .base_type = child_pointer.type,
                                                    .is_struct = false,
                                                    .index = range_start,
                                                    .name = try unit.processIdentifier(context, "double_many_pointer_slice"),
                                                },
                                            });
                                            try builder.appendInstruction(unit, pointer_gep);

                                            const pointer_type = try unit.getPointerType(.{
                                                .type = child_pointer.type,
                                                .termination = child_pointer.termination,
                                                .mutability = child_pointer.mutability,
                                                .many = true,
                                                .nullable = false,
                                            });

                                            const slice_type = try unit.getSliceType(.{
                                                .child_type = child_pointer.type,
                                                .child_pointer_type = pointer_type,
                                                .termination = child_pointer.termination,
                                                .mutability = child_pointer.mutability,
                                                .nullable = false,
                                            });

                                            const slice_builder = unit.instructions.append_index(.{
                                                .insert_value = .{
                                                    .expression = V{
                                                        .value = .{
                                                            .@"comptime" = .undefined,
                                                        },
                                                        .type = slice_type,
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
                                            try builder.appendInstruction(unit, slice_builder);

                                            const final_slice = unit.instructions.append_index(.{
                                                .insert_value = .{
                                                    .expression = V{
                                                        .value = .{
                                                            .runtime = slice_builder,
                                                        },
                                                        .type = slice_type,
                                                    },
                                                    .index = 1,
                                                    .new_value = len_expression,
                                                },
                                            });
                                            try builder.appendInstruction(unit, final_slice);

                                            break :blk .{
                                                .value = .{
                                                    .runtime = final_slice,
                                                },
                                                .type = slice_type,
                                            };
                                        },
                                        false => switch (unit.types.get(child_pointer.type).*) {
                                            .array => |array| blk: {
                                                const load = unit.instructions.append_index(.{
                                                    .load = .{
                                                        .value = expression_to_slice,
                                                        .type = pointer.type,
                                                    },
                                                });
                                                try builder.appendInstruction(unit, load);

                                                const pointer_gep = unit.instructions.append_index(.{
                                                    .get_element_pointer = .{
                                                        .pointer = load,
                                                        .base_type = array.type,
                                                        .is_struct = false,
                                                        .index = range_start,
                                                        .name = try unit.processIdentifier(context, "double_array_slice"),
                                                    },
                                                });
                                                try builder.appendInstruction(unit, pointer_gep);

                                                const pointer_type = try unit.getPointerType(.{
                                                    .type = array.type,
                                                    .termination = array.termination,
                                                    .mutability = child_pointer.mutability,
                                                    .many = true,
                                                    .nullable = false,
                                                });

                                                const slice_type = try unit.getSliceType(.{
                                                    .child_type = array.type,
                                                    .child_pointer_type = pointer_type,
                                                    .termination = array.termination,
                                                    .mutability = child_pointer.mutability,
                                                    .nullable = false,
                                                });

                                                const slice_builder = unit.instructions.append_index(.{
                                                    .insert_value = .{
                                                        .expression = V{
                                                            .value = .{
                                                                .@"comptime" = .undefined,
                                                            },
                                                            .type = slice_type,
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
                                                try builder.appendInstruction(unit, slice_builder);

                                                const final_slice = unit.instructions.append_index(.{
                                                    .insert_value = .{
                                                        .expression = V{
                                                            .value = .{
                                                                .runtime = slice_builder,
                                                            },
                                                            .type = slice_type,
                                                        },
                                                        .index = 1,
                                                        .new_value = len_expression,
                                                    },
                                                });
                                                try builder.appendInstruction(unit, final_slice);

                                                break :blk .{
                                                    .value = .{
                                                        .runtime = final_slice,
                                                    },
                                                    .type = slice_type,
                                                };
                                            },
                                            else => |t| @panic(@tagName(t)),
                                        },
                                    },
                                    .slice => |slice| blk: {
                                        const load = unit.instructions.append_index(.{
                                            .load = .{
                                                .value = expression_to_slice,
                                                .type = pointer.type,
                                            },
                                        });
                                        try builder.appendInstruction(unit, load);

                                        const extract_pointer = unit.instructions.append_index(.{
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
                                        try builder.appendInstruction(unit, extract_pointer);

                                        const pointer_gep = unit.instructions.append_index(.{
                                            .get_element_pointer = .{
                                                .pointer = extract_pointer,
                                                .base_type = slice.child_type,
                                                .is_struct = false,
                                                .index = range_start,
                                                .name = try unit.processIdentifier(context, "slice_ptr_gep"),
                                            },
                                        });
                                        try builder.appendInstruction(unit, pointer_gep);

                                        const slice_type = pointer.type;

                                        const slice_builder = unit.instructions.append_index(.{
                                            .insert_value = .{
                                                .expression = V{
                                                    .value = .{
                                                        .@"comptime" = .undefined,
                                                    },
                                                    .type = slice_type,
                                                },
                                                .index = 0,
                                                .new_value = .{
                                                    .value = .{
                                                        .runtime = pointer_gep,
                                                    },
                                                    .type = slice.child_pointer_type,
                                                },
                                            },
                                        });
                                        try builder.appendInstruction(unit, slice_builder);

                                        const final_slice = unit.instructions.append_index(.{
                                            .insert_value = .{
                                                .expression = V{
                                                    .value = .{
                                                        .runtime = slice_builder,
                                                    },
                                                    .type = slice_type,
                                                },
                                                .index = 1,
                                                .new_value = len_expression,
                                            },
                                        });
                                        try builder.appendInstruction(unit, final_slice);

                                        break :blk .{
                                            .value = .{
                                                .runtime = final_slice,
                                            },
                                            .type = slice_type,
                                        };
                                    },
                                    else => |t| @panic(@tagName(t)),
                                },
                            },
                            else => |t| @panic(@tagName(t)),
                        };

                        break :block switch (type_expect) {
                            .none => slice_value,
                            .type => |type_index| switch (try builder.typecheck(unit, context, type_index, slice_value.type)) {
                                .success => slice_value,
                                .type_to_error_union => try builder.resolveTypeToErrorUnion(unit, context, type_index, slice_value),
                                .slice_to_nullable => b: {
                                    const cast = unit.instructions.append_index(.{
                                        .cast = .{
                                            .id = .slice_to_nullable,
                                            .value = slice_value,
                                            .type = type_index,
                                        },
                                    });

                                    try builder.appendInstruction(unit, cast);
                                    break :b .{
                                        .value = .{
                                            .runtime = cast,
                                        },
                                        .type = type_index,
                                    };
                                },
                                .slice_zero_to_no_termination => b: {
                                    const cast = unit.instructions.append_index(.{
                                        .cast = .{
                                            .id = .slice_zero_to_no_termination,
                                            .value = slice_value,
                                            .type = type_index,
                                        },
                                    });

                                    try builder.appendInstruction(unit, cast);
                                    break :b V{
                                        .value = .{
                                            .runtime = cast,
                                        },
                                        .type = type_index,
                                    };
                                },
                                else => |t| @panic(@tagName(t)),
                            },
                            else => |t| @panic(@tagName(t)),
                        };
                    },
                    else => unreachable,
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

                        const string_global = try builder.processStringLiteralFromToken(unit, context, node.token);

                        const pointer_type = slice.child_pointer_type;

                        const global_string_pointer = .{
                            .value = .{
                                .@"comptime" = .{
                                    .global = string_global,
                                },
                            },
                            .type = pointer_type,
                        };

                        const slice_builder = unit.instructions.append_index(.{
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
                        try builder.appendInstruction(unit, slice_builder);

                        const len = unit.types.get(string_global.declaration.type).array.count;

                        const final_slice = unit.instructions.append_index(.{
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
                                    .type = Type.usize,
                                },
                            },
                        });

                        try builder.appendInstruction(unit, final_slice);

                        break :blk .{
                            .value = .{
                                .runtime = final_slice,
                            },
                            .type = type_index,
                        };
                    },
                    .pointer => |pointer| blk: {
                        const string_global = try builder.processStringLiteralFromToken(unit, context, node.token);
                        switch (pointer.many) {
                            true => {
                                const pointer_type = try unit.getPointerType(.{
                                    .type = string_global.declaration.type,
                                    .termination = .none,
                                    .mutability = pointer.mutability,
                                    .many = false,
                                    .nullable = false,
                                });
                                const cast = unit.instructions.append_index(.{
                                    .cast = .{
                                        .id = .pointer_to_array_to_pointer_to_many,
                                        .value = .{
                                            .value = .{
                                                .@"comptime" = .{
                                                    .global = string_global,
                                                },
                                            },
                                            .type = pointer_type,
                                        },
                                        .type = type_index,
                                    },
                                });
                                try builder.appendInstruction(unit, cast);

                                break :blk .{
                                    .value = .{
                                        .runtime = cast,
                                    },
                                    .type = type_index,
                                };
                            },
                            false => unreachable,
                        }
                    },
                    else => |t| @panic(@tagName(t)),
                },
                .cast => |type_index| switch (unit.types.get(type_index).*) {
                    .pointer => switch (side) {
                        .left => unreachable,
                        .right => blk: {
                            const string_literal = try unit.fixupStringLiteral(context, node.token);
                            const hash = try unit.processIdentifier(context, string_literal);
                            const ty = try unit.getArrayType(.{
                                .type = .u8,
                                .count = string_literal.len,
                                .termination = .none,
                            });
                            break :blk V{
                                .value = .{
                                    .@"comptime" = .{
                                        .string_literal = hash,
                                    },
                                },
                                .type = ty,
                            };
                        },
                    },
                    else => |t| @panic(@tagName(t)),
                },
                .none => none: {
                    const string_literal = try unit.fixupStringLiteral(context, node.token);
                    const hash = try unit.processIdentifier(context, string_literal);
                    const ty = try unit.getArrayType(.{
                        .type = .u8,
                        .count = string_literal.len,
                        .termination = .none,
                    });
                    break :none V{
                        .value = .{
                            .@"comptime" = .{
                                .string_literal = hash,
                            },
                        },
                        .type = ty,
                    };
                },
                else => |t| @panic(@tagName(t)),
            },
            .if_else => try builder.resolveIfElse(unit, context, type_expect, node_index),
            .anonymous_array_literal => blk: {
                const array_type_expect = switch (type_expect) {
                    .type => type_expect,
                    .array => type_expect,
                    .none => @panic("Anonymous array literal requires type specification"),
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

                            switch (unit.types.get(value_pointer.type).*) {
                                .array => |array| switch (value_pointer.value) {
                                    .runtime => |ii| switch (unit.instructions.get(ii).*) {
                                        .insert_value => {
                                            const name = try join_name(context, "__anon_local_arr_", unit.anon_arr, 10);
                                            unit.anon_arr += 1;
                                            const emit = true;
                                            const stack_slot = try builder.emitLocalVariableDeclaration(unit, context, unit.getNode(node.left).token, .@"const", value_pointer.type, value_pointer, emit, name);

                                            const pointer_type = try unit.getPointerType(.{
                                                .type = value_pointer.type,
                                                .many = false,
                                                .nullable = false,
                                                .mutability = .@"const",
                                                .termination = .none,
                                            });

                                            const cast = unit.instructions.append_index(.{
                                                .cast = .{
                                                    .id = .pointer_to_array_to_pointer_to_many,
                                                    .value = .{
                                                        .value = .{
                                                            .runtime = stack_slot,
                                                        },
                                                        .type = pointer_type,
                                                    },
                                                    .type = slice.child_pointer_type,
                                                },
                                            });
                                            try builder.appendInstruction(unit, cast);
                                            const slice_builder = unit.instructions.append_index(.{
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
                                                            .runtime = cast,
                                                        },
                                                        .type = slice.child_pointer_type,
                                                    },
                                                },
                                            });
                                            try builder.appendInstruction(unit, slice_builder);

                                            const final_slice = unit.instructions.append_index(.{
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
                                                                    .value = array.count,
                                                                },
                                                            },
                                                        },
                                                        .type = Type.usize,
                                                    },
                                                },
                                            });
                                            try builder.appendInstruction(unit, final_slice);

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
                                            const name = try join_name(context, "__anon_local_arr_{}", unit.anon_arr, 10);
                                            unit.anon_arr += 1;
                                            const emit = true;
                                            const stack_slot = try builder.emitLocalVariableDeclaration(unit, context, unit.getNode(node.left).token, .@"const", value_pointer.type, value_pointer, emit, name);
                                            const slice_builder = unit.instructions.append_index(.{
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
                                            try builder.appendInstruction(unit, slice_builder);

                                            const final_slice = unit.instructions.append_index(.{
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
                                                                    .value = array.count,
                                                                },
                                                            },
                                                        },
                                                        .type = Type.usize,
                                                    },
                                                },
                                            });
                                            try builder.appendInstruction(unit, final_slice);

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
                                .pointer => |pointer| {
                                    switch (unit.types.get(pointer.type).*) {
                                        .array => |array| {
                                            const cast = unit.instructions.append_index(.{
                                                .cast = .{
                                                    .id = .pointer_to_array_to_pointer_to_many,
                                                    .value = value_pointer,
                                                    .type = slice.child_pointer_type,
                                                },
                                            });
                                            try builder.appendInstruction(unit, cast);

                                            const slice_builder = unit.instructions.append_index(.{
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
                                                            .runtime = cast,
                                                        },
                                                        .type = slice.child_pointer_type,
                                                    },
                                                },
                                            });
                                            try builder.appendInstruction(unit, slice_builder);

                                            const final_slice = unit.instructions.append_index(.{
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
                                                                    .value = array.count,
                                                                },
                                                            },
                                                        },
                                                        .type = Type.usize,
                                                    },
                                                },
                                            });
                                            try builder.appendInstruction(unit, final_slice);

                                            break :blk .{
                                                .value = .{
                                                    .runtime = final_slice,
                                                },
                                                .type = type_index,
                                            };
                                        },
                                        else => |t| @panic(@tagName(t)),
                                    }
                                },
                                else => |t| @panic(@tagName(t)),
                            }
                        },
                        .pointer => |pointer| switch (pointer.many) {
                            true => {
                                const v = try builder.resolveRuntimeValue(unit, context, Type.Expect.none, node.left, .left);
                                switch (unit.types.get(v.type).*) {
                                    .pointer => |left_pointer| switch (unit.types.get(left_pointer.type).*) {
                                        .array => |array| {
                                            assert(array.type == pointer.type);
                                            const cast = unit.instructions.append_index(.{
                                                .cast = .{
                                                    .id = .pointer_to_array_to_pointer_to_many, //.array_to_pointer,
                                                    .type = type_index,
                                                    .value = v,
                                                },
                                            });
                                            try builder.appendInstruction(unit, cast);
                                            break :blk .{
                                                .value = .{
                                                    .runtime = cast,
                                                },
                                                .type = type_index,
                                            };
                                        },
                                        else => |t| @panic(@tagName(t)),
                                    },
                                    else => |t| @panic(@tagName(t)),
                                }
                            },
                            false => {
                                const v = try builder.resolveRuntimeValue(unit, context, type_expect, node.left, .left);
                                break :blk v;
                            },
                        },
                        .integer => |integer| switch (integer.kind) {
                            .materialized_int => {
                                const v = try builder.resolveRuntimeValue(unit, context, Type.Expect.none, node.left, .left);
                                _ = v;
                                unreachable;
                            },
                            else => |t| @panic(@tagName(t)),
                        },
                        else => |t| @panic(@tagName(t)),
                    },
                    .none => {
                        const value_pointer = try builder.resolveRuntimeValue(unit, context, Type.Expect.none, node.left, .left);
                        break :blk value_pointer;
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
                const original_index_value = try builder.resolveRuntimeValue(unit, context, Type.Expect.none, node.right, .right);
                const index = switch (original_index_value.type) {
                    .comptime_int => V{
                        .value = .{
                            .@"comptime" = .{
                                .constant_int = .{
                                    .value = original_index_value.value.@"comptime".comptime_int.value,
                                },
                            },
                        },
                        .type = Type.usize,
                    },
                    else => original_index_value,
                };

                const gep: V = switch (unit.types.get(array_like_expression.type).*) {
                    .pointer => |pointer| switch (pointer.many) {
                        true => unreachable,
                        false => switch (unit.types.get(pointer.type).*) {
                            .slice => |slice| try builder.build_slice_indexed_access(unit, context, array_like_expression, pointer.type, slice.child_pointer_type, slice.child_type, slice.mutability, .{ .pointer = 0, .length = 1 }, index),
                            .array => |array| b: {
                                const gep = unit.instructions.append_index(.{
                                    .get_element_pointer = .{
                                        .pointer = array_like_expression.value.runtime,
                                        .base_type = array.type,
                                        .is_struct = false,
                                        .index = index,
                                        .name = try unit.processIdentifier(context, "indexed_array_gep"),
                                    },
                                });
                                try builder.appendInstruction(unit, gep);

                                const gep_type = try unit.getPointerType(.{
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
                            .pointer => |child_pointer| switch (child_pointer.many) {
                                true => b: {
                                    const load = unit.instructions.append_index(.{
                                        .load = .{
                                            .value = array_like_expression,
                                            .type = pointer.type,
                                        },
                                    });
                                    try builder.appendInstruction(unit, load);
                                    const gep = unit.instructions.append_index(.{
                                        .get_element_pointer = .{
                                            .pointer = load,
                                            .base_type = child_pointer.type,
                                            .is_struct = false,
                                            .index = index,
                                            .name = try unit.processIdentifier(context, "indexed_many_pointer"),
                                        },
                                    });
                                    try builder.appendInstruction(unit, gep);

                                    const gep_type = try unit.getPointerType(.{
                                        .type = child_pointer.type,
                                        .termination = child_pointer.termination,
                                        .mutability = child_pointer.mutability,
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
                                false => switch (unit.types.get(child_pointer.type).*) {
                                    .array => |array| b: {
                                        const load = unit.instructions.append_index(.{
                                            .load = .{
                                                .value = array_like_expression,
                                                .type = pointer.type,
                                            },
                                        });
                                        try builder.appendInstruction(unit, load);

                                        const gep = unit.instructions.append_index(.{
                                            .get_element_pointer = .{
                                                .pointer = load,
                                                .base_type = array.type,
                                                .is_struct = false,
                                                .index = index,
                                                .name = try unit.processIdentifier(context, "indexed_pointer_array"),
                                            },
                                        });
                                        try builder.appendInstruction(unit, gep);

                                        const gep_type = try unit.getPointerType(.{
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
                                    .integer => |integer| switch (integer.kind) {
                                        .materialized_int => b: {
                                            assert(child_pointer.many);

                                            const load = unit.instructions.append_index(.{
                                                .load = .{
                                                    .value = array_like_expression,
                                                    .type = pointer.type,
                                                },
                                            });
                                            try builder.appendInstruction(unit, load);

                                            const gep = unit.instructions.append_index(.{
                                                .get_element_pointer = .{
                                                    .pointer = load,
                                                    .base_type = child_pointer.type,
                                                    .is_struct = false,
                                                    .index = index,
                                                    .name = try unit.processIdentifier(context, "many_pointer_integer"),
                                                },
                                            });
                                            try builder.appendInstruction(unit, gep);

                                            const gep_type = try unit.getPointerType(.{
                                                .type = child_pointer.type,
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
                                    .@"struct" => |struct_index| switch (unit.structs.get(struct_index).kind) {
                                        .@"struct" => |*struct_type| b: {
                                            if (struct_type.options.sliceable) |sliceable| {
                                                const load = unit.instructions.append_index(.{
                                                    .load = .{
                                                        .value = array_like_expression,
                                                        .type = pointer.type,
                                                    },
                                                });
                                                try builder.appendInstruction(unit, load);

                                                const pointer_field_index = struct_type.fields[sliceable.pointer];
                                                const pointer_field = unit.struct_fields.get(pointer_field_index);
                                                const pointer_type = unit.types.get(pointer_field.type).pointer;
                                                const child_type_index = pointer_type.type;

                                                const load_value = V{
                                                    .value = .{
                                                        .runtime = load,
                                                    },
                                                    .type = pointer.type,
                                                };
                                                const v = try builder.build_slice_indexed_access(unit, context, load_value, child_pointer.type, pointer_field.type, child_type_index, pointer_type.mutability, sliceable, index);
                                                break :b v;
                                            } else {
                                                unreachable;
                                            }
                                        },
                                        else => |t| @panic(@tagName(t)),
                                    },
                                    else => |t| @panic(@tagName(t)),
                                },
                            },
                            .@"struct" => |struct_index| switch (unit.structs.get(struct_index).kind) {
                                .@"struct" => |*struct_type| if (struct_type.options.sliceable) |sliceable| b: {
                                    const field_index = struct_type.fields[sliceable.pointer];
                                    const field = unit.struct_fields.get(field_index);
                                    const child_pointer_type = field.type;
                                    const pointer_type = unit.types.get(field.type).pointer;
                                    const child_base_type = pointer_type.type;
                                    const v = try builder.build_slice_indexed_access(unit, context, array_like_expression, pointer.type, child_pointer_type, child_base_type, pointer_type.mutability, sliceable, index);
                                    break :b v;
                                } else {
                                    unreachable;
                                },
                                else => |t| @panic(@tagName(t)),
                            },
                            else => |t| @panic(@tagName(t)),
                        },
                    },
                    else => |t| @panic(@tagName(t)),
                };

                switch (side) {
                    .left => break :blk gep,
                    .right => {
                        const load = unit.instructions.append_index(.{
                            .load = .{
                                .value = gep,
                                .type = unit.types.get(gep.type).pointer.type,
                            },
                        });
                        try builder.appendInstruction(unit, load);

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
                                .none => unit.types.get(gep.type).pointer.type,
                                else => |t| @panic(@tagName(t)),
                            },
                        };
                    },
                }
            },
            .character_literal => V{
                .type = .u8,
                .value = .{
                    .@"comptime" = try unit.resolve_character_literal(node_index),
                },
            },
            .boolean_not => blk: {
                switch (type_expect) {
                    .none => {},
                    .type => |type_index| assert(type_index == .bool),
                    else => |t| @panic(@tagName(t)),
                }
                const boolean = try builder.resolveRuntimeValue(unit, context, Type.Expect{ .type = .bool }, node.left, .right);
                switch (boolean.value) {
                    .runtime => {
                        const xor = unit.instructions.append_index(.{
                            .integer_binary_operation = .{
                                .id = .bit_xor,
                                .signedness = .unsigned,
                                .left = boolean,
                                .right = .{
                                    .value = .{
                                        .@"comptime" = .{
                                            .bool = true,
                                        },
                                    },
                                    .type = .bool,
                                },
                            },
                        });
                        try builder.appendInstruction(unit, xor);

                        break :blk .{
                            .value = .{
                                .runtime = xor,
                            },
                            .type = .bool,
                        };
                    },
                    else => |t| @panic(@tagName(t)),
                }
            },
            .negation => block: {
                assert(node.left != .null);
                assert(node.right == .null);

                const value = try builder.resolveRuntimeValue(unit, context, type_expect, node.left, .right);

                switch (value.value) {
                    .@"comptime" => |ct| switch (ct) {
                        .constant_int => |constant_int| switch (type_expect) {
                            .type => |type_index| {
                                assert(type_index == value.type);
                                const expected_type = unit.types.get(type_index);
                                switch (expected_type.*) {
                                    .integer => |integer| switch (integer.kind) {
                                        .materialized_int => {
                                            assert(integer.signedness == .signed);
                                            var v: i64 = @intCast(constant_int.value);
                                            v = 0 - v;

                                            break :block .{
                                                .value = .{
                                                    .@"comptime" = .{
                                                        .constant_int = .{
                                                            .value = @bitCast(v),
                                                        },
                                                    },
                                                },
                                                .type = type_index,
                                            };
                                        },
                                        else => |t| @panic(@tagName(t)),
                                    },
                                    else => |t| @panic(@tagName(t)),
                                }
                            },
                            else => |t| @panic(@tagName(t)),
                        },
                        .comptime_int => |ct_int| switch (type_expect) {
                            .type => |type_index| switch (unit.types.get(type_index).*) {
                                .integer => |integer| switch (integer.kind) {
                                    .materialized_int => assert(integer.signedness == .signed),
                                    else => |t| @panic(@tagName(t)),
                                },
                                else => |t| @panic(@tagName(t)),
                            },
                            .none => {
                                break :block .{
                                    .value = .{
                                        .@"comptime" = .{
                                            .comptime_int = .{
                                                .value = ct_int.value,
                                                .signedness = switch (ct_int.signedness) {
                                                    .unsigned => .signed,
                                                    .signed => .unsigned,
                                                },
                                            },
                                        },
                                    },
                                    .type = .comptime_int,
                                };
                            },
                            else => |t| @panic(@tagName(t)),
                        },
                        else => |t| @panic(@tagName(t)),
                    },
                    .runtime => {
                        const sub = unit.instructions.append_index(.{
                            .integer_binary_operation = .{
                                .id = .sub,
                                .left = .{
                                    .value = .{
                                        .@"comptime" = .{
                                            .constant_int = .{
                                                .value = 0,
                                            },
                                        },
                                    },
                                    .type = value.type,
                                },
                                .right = value,
                                .signedness = switch (unit.types.get(value.type).*) {
                                    .integer => |integer| switch (integer.kind) {
                                        .materialized_int => integer.signedness,
                                        else => |t| @panic(@tagName(t)),
                                    },
                                    else => |t| @panic(@tagName(t)),
                                },
                            },
                        });
                        try builder.appendInstruction(unit, sub);
                        break :block .{
                            .value = .{
                                .runtime = sub,
                            },
                            .type = value.type,
                        };
                    },
                    else => |t| @panic(@tagName(t)),
                }
            },
            .@"return" => block: {
                try builder.emitReturn(unit, context, node_index);
                // TODO: warning
                break :block V{
                    .value = .{
                        .@"comptime" = .void,
                    },
                    .type = .void,
                };
            },
            .@"switch" => try builder.resolveSwitch(unit, context, type_expect, node_index, side, null),
            .catch_expression => try builder.resolveCatchExpression(unit, context, type_expect, node_index, side),
            .@"unreachable" => block: {
                try builder.buildTrap(unit, context);
                break :block .{
                    .value = .{
                        .@"comptime" = .@"unreachable",
                    },
                    .type = .noreturn,
                };
            },
            .try_expression => try builder.resolveTryExpression(unit, context, type_expect, node_index, side),
            .bitfield_type => .{
                .type = try builder.resolveContainerType(unit, context, node_index, switch (node.id) {
                    .enum_type => .@"enum",
                    .struct_type => .@"struct",
                    .bitfield_type => .bitfield,
                    else => unreachable,
                }, unreachable, &.{}),
            },
            .empty_container_literal_guess => block: {
                assert(node.left != .null);
                assert(node.right != .null);
                const container_type = try builder.resolveType(unit, context, node.left, &.{});
                const node_list = unit.getNodeList(node.right);
                assert(node_list.len == 0);
                const result = try builder.resolveContainerLiteral(unit, context, node_list, container_type);
                break :block result;
            },
            .if_else_payload => block: {
                assert(node.left != .null);
                assert(node.right != .null);

                const if_else_node = unit.getNode(node.left);
                assert(if_else_node.id == .if_else);
                assert(if_else_node.left != .null);
                assert(if_else_node.right != .null);

                const if_node = unit.getNode(if_else_node.left);
                assert(if_node.id == .@"if");
                assert(if_node.left != .null);
                assert(if_node.right != .null);

                try builder.resolveBranchPayload(unit, context, .{
                    .payload_node_index = node.right,
                    .optional_node_index = if_node.left,
                    .taken_expression_node_index = if_node.right,
                    .not_taken_expression_node_index = if_else_node.right,
                });

                break :block .{
                    .value = .{
                        .@"comptime" = .void,
                    },
                    .type = .void,
                };
            },
            .orelse_expression => block: {
                const v = try builder.resolveRuntimeValue(unit, context, Type.Expect.none, node.left, .right);
                switch (unit.types.get(v.type).*) {
                    .pointer => |pointer| if (pointer.nullable) {
                        const type_to_expect = switch (type_expect) {
                            .none => b: {
                                var p = pointer;
                                p.nullable = false;
                                const non_null_pointer = try unit.getPointerType(p);
                                break :b non_null_pointer;
                            },
                            else => |t| @panic(@tagName(t)),
                        };
                        const new_type_expect = Type.Expect{ .type = type_to_expect };
                        const null_pointer = V{
                            .type = v.type,
                            .value = .{
                                .@"comptime" = .null_pointer,
                            },
                        };
                        const cmp = unit.instructions.append_index(.{
                            .integer_compare = .{
                                .left = v,
                                .right = null_pointer,
                                .type = v.type,
                                .id = .equal,
                            },
                        });
                        try builder.appendInstruction(unit, cmp);
                        const is_null_block = try builder.newBasicBlock(unit);
                        const is_not_null_block = try builder.newBasicBlock(unit);
                        try builder.branch(unit, cmp, is_null_block, is_not_null_block);

                        builder.current_basic_block = is_null_block;

                        const else_expr = try builder.resolveRuntimeValue(unit, context, new_type_expect, node.right, .right);
                        _ = else_expr; // autofix
                        const is_block_terminated = unit.basic_blocks.get(builder.current_basic_block).terminated;
                        if (!is_block_terminated) {
                            unreachable;
                        } else {
                            builder.current_basic_block = is_not_null_block;
                            const cast = unit.instructions.append_index(.{
                                .cast = .{
                                    .id = .pointer_to_not_nullable,
                                    .value = v,
                                    .type = type_to_expect,
                                },
                            });
                            try builder.appendInstruction(unit, cast);

                            break :block .{
                                .value = .{
                                    .runtime = cast,
                                },
                                .type = type_to_expect,
                            };
                        }
                    } else unreachable,
                    .slice => |slice| if (slice.nullable) {
                        const type_to_expect = switch (type_expect) {
                            .none => b: {
                                var s = slice;
                                s.nullable = false;
                                const non_null_slice = try unit.getSliceType(s);
                                break :b non_null_slice;
                            },
                            .type => |type_index| b: {
                                var s = slice;
                                s.nullable = false;
                                const non_null_slice = try unit.getSliceType(s);
                                assert(non_null_slice == type_index);
                                break :b non_null_slice;
                            },
                            else => |t| @panic(@tagName(t)),
                        };
                        const new_type_expect = Type.Expect{ .type = type_to_expect };
                        const null_pointer = V{
                            .type = slice.child_pointer_type,
                            .value = .{
                                .@"comptime" = .null_pointer,
                            },
                        };

                        const get_pointer = unit.instructions.append_index(.{
                            .extract_value = .{
                                .expression = v,
                                .index = 0,
                            },
                        });
                        try builder.appendInstruction(unit, get_pointer);
                        const cmp = unit.instructions.append_index(.{
                            .integer_compare = .{
                                .left = .{
                                    .value = .{
                                        .runtime = get_pointer,
                                    },
                                    .type = slice.child_pointer_type,
                                },
                                .right = null_pointer,
                                .type = v.type,
                                .id = .equal,
                            },
                        });
                        try builder.appendInstruction(unit, cmp);
                        const is_null_block = try builder.newBasicBlock(unit);
                        const is_not_null_block = try builder.newBasicBlock(unit);
                        try builder.branch(unit, cmp, is_null_block, is_not_null_block);

                        builder.current_basic_block = is_null_block;

                        const else_expr = try builder.resolveRuntimeValue(unit, context, new_type_expect, node.right, .right);
                        const is_block_terminated = unit.basic_blocks.get(builder.current_basic_block).terminated;
                        if (!is_block_terminated) {
                            assert(else_expr.type == type_to_expect);
                            const phi_index = unit.instructions.append_index(.{
                                .phi = .{
                                    .type = type_to_expect,
                                    .values = try context.arena.new(BoundedArray(Instruction.Phi.Value, Instruction.Phi.max_value_count)),
                                },
                            });
                            const phi = &unit.instructions.get(phi_index).phi;
                            phi.addIncoming(else_expr, builder.current_basic_block);

                            const phi_block = try builder.newBasicBlock(unit);
                            try builder.jump(unit, phi_block);

                            builder.current_basic_block = is_not_null_block;

                            const cast = unit.instructions.append_index(.{
                                .cast = .{
                                    .id = .slice_to_not_null,
                                    .value = v,
                                    .type = type_to_expect,
                                },
                            });
                            try builder.appendInstruction(unit, cast);

                            const unwrap = V{
                                .value = .{
                                    .runtime = cast,
                                },
                                .type = type_to_expect,
                            };
                            phi.addIncoming(unwrap, builder.current_basic_block);
                            try builder.jump(unit, phi_block);

                            builder.current_basic_block = phi_block;

                            try builder.appendInstruction(unit, phi_index);

                            break :block V{
                                .value = .{ .runtime = phi_index },
                                .type = type_to_expect,
                            };
                        } else {
                            builder.current_basic_block = is_not_null_block;
                            const cast = unit.instructions.append_index(.{
                                .cast = .{
                                    .id = .slice_to_not_null,
                                    .value = v,
                                    .type = type_to_expect,
                                },
                            });
                            try builder.appendInstruction(unit, cast);

                            break :block .{
                                .value = .{
                                    .runtime = cast,
                                },
                                .type = type_to_expect,
                            };
                        }
                    } else unreachable,
                    else => |t| @panic(@tagName(t)),
                }
            },
            .anonymous_empty_literal => switch (type_expect) {
                .type => |type_index| try builder.resolveContainerLiteral(unit, context, &.{}, type_index),
                else => |t| @panic(@tagName(t)),
            },
            .one_complement => block: {
                const value = try builder.resolveRuntimeValue(unit, context, type_expect, node.left, .right);
                const not = unit.instructions.append_index(.{
                    .integer_binary_operation = .{
                        .id = .bit_xor,
                        .left = value,
                        .right = .{
                            .value = .{
                                .@"comptime" = .{
                                    .constant_int = .{
                                        .value = @bitCast(@as(i64, -1)),
                                    },
                                },
                            },
                            .type = value.type,
                        },
                        .signedness = .unsigned,
                    },
                });
                try builder.appendInstruction(unit, not);

                break :block V{
                    .type = value.type,
                    .value = .{
                        .runtime = not,
                    },
                };
            },
            .break_expression => b: {
                try builder.jump(unit, builder.loop_exit_block);
                break :b V{
                    .type = .noreturn,
                    .value = .{
                        .@"comptime" = .noreturn,
                    },
                };
            },
            else => |t| @panic(@tagName(t)),
        };

        return v;
    }

    fn resolveTryExpression(builder: *Builder, unit: *Unit, context: *const Context, type_expect: Type.Expect, node_index: Node.Index, side: Side) !V {
        _ = side; // autofix
        const node = unit.getNode(node_index);
        assert(node.left != .null);
        assert(node.right == .null);
        const value = try builder.resolveRuntimeValue(unit, context, Type.Expect.none, node.left, .right);

        const function_type = unit.function_definitions.get(builder.current_function).type;
        const function_prototype_index = unit.types.get(function_type).function;
        const function_prototype = unit.function_prototypes.get(function_prototype_index);
        const return_type_index = function_prototype.return_type;
        const return_type = unit.types.get(return_type_index);

        switch (unit.types.get(value.type).*) {
            .@"struct" => |struct_index| switch (unit.structs.get(struct_index).kind) {
                .error_union => |error_union| {
                    switch (type_expect) {
                        .none, .cast => {},
                        .type => |type_index| {
                            switch (try builder.typecheck(unit, context, type_index, error_union.type)) {
                                .success => {},
                                else => |t| @panic(@tagName(t)),
                            }
                        },
                        else => |t| @panic(@tagName(t)),
                    }

                    const is_error = unit.instructions.append_index(.{
                        .extract_value = .{
                            .expression = value,
                            .index = 1,
                        },
                    });
                    try builder.appendInstruction(unit, is_error);
                    const error_block = try builder.newBasicBlock(unit);
                    const clean_block = try builder.newBasicBlock(unit);

                    try builder.branch(unit, is_error, error_block, clean_block);

                    builder.current_basic_block = error_block;

                    const final_error_union = if (return_type_index == value.type) value else final: {
                        switch (return_type.*) {
                            .@"struct" => |return_struct_index| switch (unit.structs.get(return_struct_index).kind) {
                                .error_union => |return_error_union| {
                                    switch (try builder.typecheck(unit, context, return_error_union.@"error", error_union.@"error")) {
                                        .success => {
                                            const error_value = if (error_union.union_for_error == error_union.abi) blk: {
                                                const extract_value = unit.instructions.append_index(.{
                                                    .extract_value = .{
                                                        .expression = value,
                                                        .index = 0,
                                                    },
                                                });
                                                try builder.appendInstruction(unit, extract_value);

                                                break :blk V{
                                                    .type = error_union.abi,
                                                    .value = .{
                                                        .runtime = extract_value,
                                                    },
                                                };
                                            } else err: {
                                                const try_alloca = try builder.createStackVariable(unit, context, value.type, null);

                                                const try_store = unit.instructions.append_index(.{
                                                    .store = .{
                                                        .destination = .{
                                                            .value = .{
                                                                .runtime = try_alloca,
                                                            },
                                                            .type = try unit.getPointerType(.{
                                                                .type = value.type,
                                                                .termination = .none,
                                                                .mutability = .@"var",
                                                                .many = false,
                                                                .nullable = false,
                                                            }),
                                                        },
                                                        .source = value,
                                                    },
                                                });
                                                try builder.appendInstruction(unit, try_store);

                                                const union_for_error_gep = unit.instructions.append_index(.{
                                                    .get_element_pointer = .{
                                                        .pointer = try_alloca,
                                                        .base_type = error_union.union_for_error,
                                                        .is_struct = true,
                                                        .index = .{
                                                            .value = .{
                                                                .@"comptime" = .{
                                                                    .constant_int = .{
                                                                        .value = 0,
                                                                    },
                                                                },
                                                            },
                                                            .type = .u32,
                                                        },
                                                        .name = try unit.processIdentifier(context, "union_for_error_gep"),
                                                    },
                                                });
                                                try builder.appendInstruction(unit, union_for_error_gep);

                                                const error_load = unit.instructions.append_index(.{
                                                    .load = .{
                                                        .value = .{
                                                            .value = .{
                                                                .runtime = union_for_error_gep,
                                                            },
                                                            .type = try unit.getPointerType(.{
                                                                .type = error_union.@"error",
                                                                .termination = .none,
                                                                .mutability = .@"const",
                                                                .many = false,
                                                                .nullable = false,
                                                            }),
                                                        },
                                                        .type = error_union.@"error",
                                                    },
                                                });
                                                try builder.appendInstruction(unit, error_load);
                                                break :err V{
                                                    .value = .{
                                                        .runtime = error_load,
                                                    },
                                                    .type = error_union.@"error",
                                                };
                                            };

                                            if (return_error_union.union_for_error == return_error_union.abi) {
                                                const error_union_builder = unit.instructions.append_index(.{
                                                    .insert_value = .{
                                                        .expression = .{
                                                            .value = .{
                                                                .@"comptime" = .undefined,
                                                            },
                                                            .type = return_type_index,
                                                        },
                                                        .index = 0,
                                                        .new_value = error_value,
                                                    },
                                                });
                                                try builder.appendInstruction(unit, error_union_builder);

                                                const final_error_union = unit.instructions.append_index(.{
                                                    .insert_value = .{
                                                        .expression = .{
                                                            .value = .{
                                                                .runtime = error_union_builder,
                                                            },
                                                            .type = return_type_index,
                                                        },
                                                        .index = 1,
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
                                                try builder.appendInstruction(unit, final_error_union);

                                                break :final V{
                                                    .value = .{
                                                        .runtime = final_error_union,
                                                    },
                                                    .type = return_type_index,
                                                };
                                            } else {
                                                const has_padding = switch (unit.types.get(error_union.union_for_error).*) {
                                                    .@"struct" => |si| switch (unit.structs.get(si).kind) {
                                                        .abi_compatible_error_union => |eu| eu.padding != .null,
                                                        .raw_error_union => false,
                                                        else => |t| @panic(@tagName(t)),
                                                    },
                                                    else => |t| @panic(@tagName(t)),
                                                };
                                                const v = V{
                                                    .value = .{
                                                        .@"comptime" = .undefined,
                                                    },
                                                    .type = error_union.union_for_error,
                                                };

                                                const error_union_builder = unit.instructions.append_index(.{
                                                    .insert_value = .{
                                                        .expression = v,
                                                        .index = 0,
                                                        .new_value = error_value,
                                                    },
                                                });
                                                try builder.appendInstruction(unit, error_union_builder);

                                                const final_error_union = unit.instructions.append_index(.{
                                                    .insert_value = .{
                                                        .expression = .{
                                                            .value = .{
                                                                .runtime = error_union_builder,
                                                            },
                                                            .type = error_union.union_for_error,
                                                        },
                                                        .index = @as(u32, 1) + @intFromBool(has_padding),
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
                                                try builder.appendInstruction(unit, final_error_union);

                                                const support_alloca = try builder.createStackVariable(unit, context, error_union.union_for_error, null);

                                                const pointer_type = try unit.getPointerType(.{
                                                    .type = error_union.union_for_error,
                                                    .termination = .none,
                                                    .mutability = .@"var",
                                                    .many = false,
                                                    .nullable = false,
                                                });

                                                const support_store = unit.instructions.append_index(.{
                                                    .store = .{
                                                        .destination = .{
                                                            .value = .{
                                                                .runtime = support_alloca,
                                                            },
                                                            .type = pointer_type,
                                                        },
                                                        .source = .{
                                                            .value = .{
                                                                .runtime = final_error_union,
                                                            },
                                                            .type = error_union.union_for_error,
                                                        },
                                                    },
                                                });
                                                try builder.appendInstruction(unit, support_store);

                                                const support_load = unit.instructions.append_index(.{
                                                    .load = .{
                                                        .value = .{
                                                            .value = .{
                                                                .runtime = support_alloca,
                                                            },
                                                            .type = pointer_type,
                                                        },
                                                        .type = return_type_index,
                                                    },
                                                });
                                                try builder.appendInstruction(unit, support_load);

                                                break :final V{
                                                    .value = .{
                                                        .runtime = support_load,
                                                    },
                                                    .type = return_type_index,
                                                };
                                            }
                                        },
                                        .error_to_all_errors => {
                                            // Prepare error composed id
                                            const error_type = unit.types.get(error_union.@"error").integer.kind.@"error";
                                            const error_id = error_type.id;
                                            const constant_shifted = @as(u64, error_id) << 32;
                                            _ = constant_shifted; // autofix

                                            const error_value = if (error_union.union_for_error == error_union.abi) b: {
                                                const get_error = unit.instructions.append_index(.{
                                                    .extract_value = .{
                                                        .expression = value,
                                                        .index = 0,
                                                    },
                                                });
                                                try builder.appendInstruction(unit, get_error);
                                                break :b V{
                                                    .value = .{
                                                        .runtime = get_error,
                                                    },
                                                    .type = error_union.@"error",
                                                };
                                            } else err: {
                                                const try_alloca = try builder.createStackVariable(unit, context, value.type, null);

                                                const try_store = unit.instructions.append_index(.{
                                                    .store = .{
                                                        .destination = .{
                                                            .value = .{
                                                                .runtime = try_alloca,
                                                            },
                                                            .type = try unit.getPointerType(.{
                                                                .type = value.type,
                                                                .termination = .none,
                                                                .mutability = .@"var",
                                                                .many = false,
                                                                .nullable = false,
                                                            }),
                                                        },
                                                        .source = value,
                                                    },
                                                });
                                                try builder.appendInstruction(unit, try_store);

                                                const union_for_error_gep = unit.instructions.append_index(.{
                                                    .get_element_pointer = .{
                                                        .pointer = try_alloca,
                                                        .base_type = error_union.union_for_error,
                                                        .is_struct = true,
                                                        .index = .{
                                                            .value = .{
                                                                .@"comptime" = .{
                                                                    .constant_int = .{
                                                                        .value = 0,
                                                                    },
                                                                },
                                                            },
                                                            .type = .u32,
                                                        },
                                                        .name = try unit.processIdentifier(context, "union_for_error_gep"),
                                                    },
                                                });
                                                try builder.appendInstruction(unit, union_for_error_gep);

                                                const error_load = unit.instructions.append_index(.{
                                                    .load = .{
                                                        .value = .{
                                                            .value = .{
                                                                .runtime = union_for_error_gep,
                                                            },
                                                            .type = try unit.getPointerType(.{
                                                                .type = error_union.@"error",
                                                                .termination = .none,
                                                                .mutability = .@"const",
                                                                .many = false,
                                                                .nullable = false,
                                                            }),
                                                        },
                                                        .type = error_union.@"error",
                                                    },
                                                });
                                                try builder.appendInstruction(unit, error_load);
                                                break :err V{
                                                    .value = .{
                                                        .runtime = error_load,
                                                    },
                                                    .type = error_union.@"error",
                                                };
                                            };

                                            break :final try builder.resolveErrorToAllErrorUnion(unit, context, return_type_index, error_value);
                                        },
                                        else => |t| @panic(@tagName(t)),
                                    }
                                },
                                else => |t| @panic(@tagName(t)),
                            },
                            else => |t| @panic(@tagName(t)),
                        }
                    };

                    if (builder.return_block != .null) {
                        assert(builder.return_phi != .null);
                        const phi = &unit.instructions.get(builder.return_phi).phi;
                        phi.addIncoming(final_error_union, builder.current_basic_block);
                    } else if (builder.return_phi != .null) {
                        unreachable;
                    } else {
                        assert(builder.return_phi == .null);
                        assert(builder.return_block == .null);
                        const phi_index = unit.instructions.append_index(.{
                            .phi = .{
                                .type = return_type_index,
                                .values = try context.arena.new(BoundedArray(Instruction.Phi.Value, Instruction.Phi.max_value_count)),
                            },
                        });
                        const phi = &unit.instructions.get(phi_index).phi;
                        const phi_block = try builder.newBasicBlock(unit);
                        phi.addIncoming(final_error_union, builder.current_basic_block);

                        // const old_block = builder.current_basic_block;

                        builder.return_phi = phi_index;
                        builder.return_block = phi_block;
                    }

                    assert(builder.return_block != .null);
                    try builder.jump(unit, builder.return_block);

                    builder.current_basic_block = clean_block;

                    const result = unit.instructions.append_index(.{
                        .extract_value = .{
                            .expression = value,
                            .index = 0,
                        },
                    });
                    try builder.appendInstruction(unit, result);

                    const v = V{
                        .value = .{
                            .runtime = result,
                        },
                        .type = error_union.type,
                    };

                    return v;
                },
                else => |t| @panic(@tagName(t)),
            },
            else => |t| @panic(@tagName(t)),
        }
    }

    fn resolveContainerLiteral(builder: *Builder, unit: *Unit, context: *const Context, nodes: []const Node.Index, type_index: Type.Index) !V {
        const container_type = unit.types.get(type_index);

        const fields = switch (container_type.*) {
            .integer => |*integer| switch (integer.kind) {
                .bitfield => |*bitfield| bitfield.fields,
                else => |t| @panic(@tagName(t)),
            },
            .@"struct" => |struct_index| switch (unit.structs.get(struct_index).kind) {
                .@"struct" => |*struct_type| struct_type.fields,
                else => |t| @panic(@tagName(t)),
            },
            else => |t| @panic(@tagName(t)),
        };

        var list = try DynamicBoundedArray(V).init(context.arena, @intCast(fields.len));
        var is_comptime = true;

        for (fields) |field_index| {
            const field = unit.struct_fields.get(field_index);

            for (nodes) |initialization_node_index| {
                const initialization_node = unit.getNode(initialization_node_index);
                assert(initialization_node.id == .container_field_initialization);
                assert(initialization_node.left != .null);
                assert(initialization_node.right == .null);
                const field_name = unit.getExpectedTokenBytes(@enumFromInt(@intFromEnum(initialization_node.token) + 1), .identifier);
                const field_name_hash = try unit.processIdentifier(context, field_name);

                if (field_name_hash == field.name) {
                    const expected_type = field.type;
                    const field_initialization = try builder.resolveRuntimeValue(unit, context, Type.Expect{ .type = expected_type }, initialization_node.left, .right);
                    is_comptime = is_comptime and field_initialization.value == .@"comptime";
                    list.append(field_initialization);
                    break;
                }
            } else if (field.default_value) |default_value| {
                list.append(.{
                    .value = .{
                        .@"comptime" = default_value,
                    },
                    .type = field.type,
                });
            } else {
                const identifier = unit.getIdentifier(field.name);
                try write(.panic, "Missing field: ");
                try write(.panic, identifier);
                try write(.panic, "\n");
                @panic("Missing field");
            }
        }

        switch (container_type.*) {
            .integer => |integer| switch (integer.kind) {
                .bitfield => {
                    assert(integer.signedness == .unsigned);
                    if (is_comptime) {
                        var bit_offset: u32 = 0;
                        var value: u64 = 0;
                        for (list.slice()) |field| {
                            const field_type = unit.types.get(field.type);
                            const bit_size = field_type.getBitSize(unit);
                            const field_value: u64 = switch (field.value.@"comptime") {
                                .constant_int => |constant_int| constant_int.value,
                                .bool => |boolean| @intFromBool(boolean),
                                .comptime_int => |ct_int| switch (ct_int.signedness) {
                                    .unsigned => ct_int.value,
                                    .signed => unreachable,
                                },
                                .enum_value => |enum_field_index| unit.enum_fields.get(enum_field_index).value,
                                else => |t| @panic(@tagName(t)),
                            };
                            const value_with_offset = field_value << @as(u6, @intCast(bit_offset));
                            value |= value_with_offset;
                            bit_offset += bit_size;
                        }

                        return .{
                            .value = .{
                                .@"comptime" = .{
                                    .constant_bitfield = value,
                                },
                            },
                            .type = type_index,
                        };
                    } else {
                        const zero_extend = unit.instructions.append_index(.{
                            .cast = .{
                                .id = .zero_extend,
                                .value = list.pointer[0],
                                .type = type_index,
                            },
                        });
                        try builder.appendInstruction(unit, zero_extend);
                        var value = V{
                            .value = .{
                                .runtime = zero_extend,
                            },
                            .type = type_index,
                        };

                        const first_field_type = unit.types.get(list.pointer[0].type);
                        var bit_offset = first_field_type.getBitSize(unit);

                        for (list.slice()[1..]) |field| {
                            const field_type = unit.types.get(field.type);
                            const field_bit_size = field_type.getBitSize(unit);
                            defer bit_offset += field_bit_size;

                            const field_zero_extend = unit.instructions.append_index(.{
                                .cast = .{
                                    .id = .zero_extend,
                                    .value = field,
                                    .type = type_index,
                                },
                            });
                            try builder.appendInstruction(unit, field_zero_extend);

                            const shift_left = unit.instructions.append_index(.{
                                .integer_binary_operation = .{
                                    .id = .shift_left,
                                    .left = .{
                                        .value = .{
                                            .runtime = field_zero_extend,
                                        },
                                        .type = type_index,
                                    },
                                    .right = .{
                                        .value = .{
                                            .@"comptime" = .{
                                                .constant_int = .{
                                                    .value = bit_offset,
                                                },
                                            },
                                        },
                                        .type = type_index,
                                    },
                                    .signedness = integer.signedness,
                                },
                            });

                            try builder.appendInstruction(unit, shift_left);

                            const merge_or = unit.instructions.append_index(.{
                                .integer_binary_operation = .{
                                    .id = .bit_or,
                                    .signedness = integer.signedness,
                                    .left = .{
                                        .value = .{
                                            .runtime = shift_left,
                                        },
                                        .type = type_index,
                                    },
                                    .right = value,
                                },
                            });
                            try builder.appendInstruction(unit, merge_or);

                            value = .{
                                .value = .{
                                    .runtime = merge_or,
                                },
                                .type = type_index,
                            };
                        }

                        return value;
                    }
                },
                else => |t| @panic(@tagName(t)),
            },
            .@"struct" => |struct_index| switch (unit.structs.get(struct_index).kind) {
                .@"struct" => {
                    if (is_comptime) {
                        var comptime_list = try context.arena.new_array(V.Comptime, fields.len);
                        for (list.slice(), 0..) |item, i| {
                            comptime_list[i] = item.value.@"comptime";
                        }

                        return .{
                            .value = .{
                                .@"comptime" = .{
                                    .constant_struct = unit.constant_structs.append_index(.{
                                        .fields = comptime_list,
                                        .type = type_index,
                                    }),
                                },
                            },
                            .type = type_index,
                        };
                    } else {
                        var struct_initialization = V{
                            .value = .{
                                .@"comptime" = .undefined,
                            },
                            .type = type_index,
                        };

                        for (list.slice(), 0..) |field, index| {
                            const struct_initialization_instruction = unit.instructions.append_index(.{
                                .insert_value = .{
                                    .expression = struct_initialization,
                                    .index = @intCast(index),
                                    .new_value = field,
                                },
                            });

                            try builder.appendInstruction(unit, struct_initialization_instruction);

                            struct_initialization.value = .{
                                .runtime = struct_initialization_instruction,
                            };
                        }

                        return struct_initialization;
                    }
                },
                else => |t| @panic(@tagName(t)),
            },
            else => |t| @panic(@tagName(t)),
        }
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
            .array => |array| try unit.getArrayType(.{
                .count = expression_element_count,
                .type = array.type,
                .termination = array.termination,
            }),
            else => unreachable,
        };

        const array_type = unit.types.get(array_type_index).array;

        if (array_type.count != expression_element_count) @panic("Array element count mismatch");

        var is_comptime = true;
        const is_terminated = switch (array_type.termination) {
            .none => false,
            else => true,
        };
        var values = try DynamicBoundedArray(V).init(context.arena, @intCast(nodes.len + @intFromBool(is_terminated)));
        for (nodes) |node_index| {
            const value = try builder.resolveRuntimeValue(unit, context, Type.Expect{ .type = array_type.type }, node_index, .right);
            // assert(value.value == .@"comptime");
            is_comptime = is_comptime and value.value == .@"comptime";
            values.append(value);
        }

        switch (array_type.termination) {
            .none => {},
            .zero => values.append(.{
                .value = .{
                    .@"comptime" = .{
                        .constant_int = .{
                            .value = 0,
                        },
                    },
                },
                .type = array_type.type,
            }),
            .null => values.append(.{
                .value = .{
                    .@"comptime" = .null_pointer,
                },
                .type = array_type.type,
            }),
        }

        if (is_comptime) {
            const constant_array = unit.constant_arrays.append_index(.{
                .values = blk: {
                    var ct_values = try context.arena.new_array(V.Comptime, values.length);

                    for (values.slice(), 0..) |v, i| {
                        ct_values[i] = v.value.@"comptime";
                    }

                    break :blk ct_values;
                },
                // TODO: avoid hash lookup
                .type = try unit.getArrayType(array_type),
            });
            const v = V{
                .value = .{
                    .@"comptime" = .{
                        .constant_array = constant_array,
                    },
                },
                // TODO: avoid hash lookup
                .type = try unit.getArrayType(array_type),
            };
            return v;
        } else {
            var array_builder = V{
                .value = .{
                    .@"comptime" = .undefined,
                },
                .type = array_type_index,
            };

            for (values.slice(), 0..) |value, index| {
                const insert_value = unit.instructions.append_index(.{
                    .insert_value = .{
                        .expression = array_builder,
                        .index = @intCast(index),
                        .new_value = value,
                    },
                });

                try builder.appendInstruction(unit, insert_value);

                array_builder.value = .{
                    .runtime = insert_value,
                };
            }

            return array_builder;
        }
    }

    const MemberResolution = struct {
        callable: V,
        member: ?V,
    };

    fn end_up_resolving_member_call(builder: *Builder, unit: *Unit, context: *const Context, type_index: Type.Index, value: V, right_identifier_hash: u32, argument_nodes: []const Node.Index) !MemberResolution {
        const ty = unit.types.get(type_index);
        switch (ty.*) {
            .@"struct" => |struct_index| switch (unit.structs.get(struct_index).kind) {
                .@"struct" => |*struct_type| {
                    for (struct_type.fields, 0..) |field_index, index| {
                        const field = unit.struct_fields.get(field_index);

                        if (field.name == right_identifier_hash) {
                            switch (unit.types.get(field.type).*) {
                                .pointer => |field_pointer_type| switch (unit.types.get(field_pointer_type.type).*) {
                                    .function => {
                                        assert(field_pointer_type.mutability == .@"const");
                                        assert(!field_pointer_type.nullable);

                                        const gep = unit.instructions.append_index(.{
                                            .get_element_pointer = .{
                                                .pointer = value.value.runtime,
                                                .base_type = type_index,
                                                .is_struct = true,
                                                .index = .{
                                                    .value = .{
                                                        .@"comptime" = .{
                                                            .constant_int = .{
                                                                .value = index,
                                                            },
                                                        },
                                                    },
                                                    .type = .u32,
                                                },
                                                .name = field.name,
                                            },
                                        });
                                        try builder.appendInstruction(unit, gep);

                                        const second_load = unit.instructions.append_index(.{
                                            .load = .{
                                                .value = .{
                                                    .value = .{
                                                        .runtime = gep,
                                                    },
                                                    .type = try unit.getPointerType(.{
                                                        .type = field.type,
                                                        .many = false,
                                                        .nullable = false,
                                                        .mutability = .@"const",
                                                        .termination = .none,
                                                    }),
                                                },
                                                .type = field.type,
                                            },
                                        });
                                        try builder.appendInstruction(unit, second_load);

                                        return .{
                                            .callable = .{
                                                .value = .{
                                                    .runtime = second_load,
                                                },
                                                .type = field.type,
                                            },
                                            .member = null,
                                        };
                                    },
                                    else => |t| @panic(@tagName(t)),
                                },
                                else => |t| @panic(@tagName(t)),
                            }
                        }
                    } else if (struct_type.scope.scope.lookupDeclaration(right_identifier_hash, false)) |lookup| {
                        const right_symbol = try builder.referenceGlobalDeclaration(unit, context, lookup.scope, lookup.declaration, .{}, &.{}, value, argument_nodes);
                        assert(right_symbol.initial_value != .polymorphic_function);
                        switch (right_symbol.initial_value) {
                            .function_definition => {
                                const function_type_index = right_symbol.declaration.type;
                                const function_prototype_index = unit.types.get(function_type_index).function;
                                const function_prototype = unit.function_prototypes.get(function_prototype_index);

                                if (function_prototype.argument_types.len == 0) {
                                    unreachable;
                                }

                                const first_argument_type_index = function_prototype.argument_types[0];

                                if (first_argument_type_index == value.type) {
                                    return .{
                                        .callable = .{
                                            .value = .{
                                                .@"comptime" = .{
                                                    .global = right_symbol,
                                                },
                                            },
                                            .type = function_type_index,
                                        },
                                        .member = value,
                                    };
                                } else if (first_argument_type_index == type_index) {
                                    const load = unit.instructions.append_index(.{
                                        .load = .{
                                            .value = value,
                                            .type = first_argument_type_index,
                                        },
                                    });
                                    try builder.appendInstruction(unit, load);

                                    return .{
                                        .member = .{
                                            .value = .{
                                                .runtime = load,
                                            },
                                            .type = first_argument_type_index,
                                        },
                                        .callable = .{
                                            .value = .{
                                                .@"comptime" = .{
                                                    .global = right_symbol,
                                                },
                                            },
                                            .type = function_type_index,
                                        },
                                    };
                                } else {
                                    const symbol_name = unit.getIdentifier(right_symbol.declaration.name);
                                    _ = symbol_name; // autofix
                                    const decl_arg_type_index = first_argument_type_index;
                                    const field_access_left_type_index = value.type;
                                    const result = try builder.typecheck(unit, context, decl_arg_type_index, field_access_left_type_index);
                                    switch (result) {
                                        else => |t| @panic(@tagName(t)),
                                    }
                                }
                            },
                            else => |t| @panic(@tagName(t)),
                        }
                        unreachable;
                    } else {
                        unreachable;
                    }
                },
                else => |t| @panic(@tagName(t)),
            },
            else => |t| @panic(@tagName(t)),
        }
    }

    fn resolveCall(builder: *Builder, unit: *Unit, context: *const Context, node_index: Node.Index) !V {
        const node = unit.getNode(node_index);

        assert(node.left != .null);
        assert(node.right != .null);
        const left_node = unit.getNode(node.left);
        const argument_nodes = unit.getNodeList(node.right);

        var comptime_argument_count: u32 = 0;
        for (argument_nodes) |argument_node_index| {
            const argument_node = unit.getNode(argument_node_index);
            comptime_argument_count += @intFromBool(argument_node.id == .comptime_expression);
        }

        const polymorphic_argument_nodes: []const Node.Index = if (comptime_argument_count > 0) argument_nodes else &.{};

        const member_resolution: MemberResolution = switch (left_node.id) {
            .field_access => field_access: {
                const right_identifier_node = unit.getNode(left_node.right);
                assert(right_identifier_node.id == .identifier);
                const right_identifier = unit.getExpectedTokenBytes(right_identifier_node.token, .identifier);
                const right_identifier_hash = try unit.processIdentifier(context, right_identifier);

                const field_access_left = try builder.resolveRuntimeValue(unit, context, Type.Expect.none, left_node.left, .left);

                const member_resolution = switch (field_access_left.value) {
                    .@"comptime" => |ct| switch (ct) {
                        .type => |type_index| blk: {
                            const container_type = unit.types.get(type_index);
                            const container_scope = container_type.getScope(unit);
                            const look_in_parent_scopes = false;

                            if (container_scope.lookupDeclaration(right_identifier_hash, look_in_parent_scopes)) |lookup| {
                                const global = try builder.referenceGlobalDeclaration(unit, context, lookup.scope, lookup.declaration, .{}, &.{}, null, &.{});
                                switch (global.initial_value) {
                                    .function_definition, .function_declaration => {
                                        const value = V{
                                            .value = .{
                                                .@"comptime" = .{
                                                    .global = global,
                                                },
                                            },
                                            .type = global.declaration.type,
                                        };
                                        break :blk MemberResolution{
                                            .callable = value,
                                            .member = null,
                                        };
                                    },
                                    else => |t| @panic(@tagName(t)),
                                }
                            } else {
                                try write(.panic, "Right identifier in field access like call expression: ");
                                try write(.panic, right_identifier);
                                @panic("Right identifier in field access like call expression");
                            }
                        },
                        else => |t| @panic(@tagName(t)),
                    },
                    .runtime => switch (unit.types.get(field_access_left.type).*) {
                        .pointer => |pointer| switch (unit.types.get(pointer.type).*) {
                            .@"struct" => |struct_index| switch (unit.structs.get(struct_index).kind) {
                                .@"struct" => try builder.end_up_resolving_member_call(unit, context, pointer.type, field_access_left, right_identifier_hash, polymorphic_argument_nodes),
                                else => |t| @panic(@tagName(t)),
                            },
                            .pointer => |child_pointer| blk: {
                                const load = unit.instructions.append_index(.{
                                    .load = .{
                                        .value = field_access_left,
                                        .type = pointer.type,
                                    },
                                });
                                try builder.appendInstruction(unit, load);

                                const member_resolution = try builder.end_up_resolving_member_call(unit, context, child_pointer.type, .{
                                    .value = .{
                                        .runtime = load,
                                    },
                                    .type = pointer.type,
                                }, right_identifier_hash, polymorphic_argument_nodes);
                                break :blk member_resolution;
                            },
                            else => |t| @panic(@tagName(t)),
                        },
                        else => |t| @panic(@tagName(t)),
                    },
                    else => unreachable,
                };

                break :field_access member_resolution;
            },
            .identifier => blk: {
                const identifier = unit.getExpectedTokenBytes(left_node.token, .identifier);
                const result = try builder.resolveIdentifier(unit, context, Type.Expect.none, identifier, .{}, .left, &.{});

                break :blk switch (result.value) {
                    .@"comptime" => |ct| switch (ct) {
                        .global => |global| switch (global.initial_value) {
                            .function_definition, .function_declaration => MemberResolution{
                                .callable = .{
                                    .value = .{
                                        .@"comptime" = .{
                                            .global = global,
                                        },
                                    },
                                    .type = global.declaration.type,
                                },
                                .member = null,
                            },
                            // This is a comptime alias
                            .global => |function_declaration| switch (function_declaration.initial_value) {
                                .function_definition => MemberResolution{
                                    .callable = .{
                                        .value = .{
                                            .@"comptime" = .{
                                                .global = function_declaration,
                                            },
                                        },
                                        .type = function_declaration.declaration.type,
                                    },
                                    .member = null,
                                },
                                else => |t| @panic(@tagName(t)),
                            },
                            else => |t| @panic(@tagName(t)),
                        },
                        else => |t| @panic(@tagName(t)),
                    },
                    .runtime => switch (unit.types.get(result.type).*) {
                        .pointer => |pointer| switch (unit.types.get(pointer.type).*) {
                            .pointer => |child_pointer| switch (unit.types.get(child_pointer.type).*) {
                                .function => b: {
                                    const load = unit.instructions.append_index(.{
                                        .load = .{
                                            .value = result,
                                            .type = pointer.type,
                                        },
                                    });
                                    try builder.appendInstruction(unit, load);

                                    break :b .{
                                        .callable = .{
                                            .value = .{
                                                .runtime = load,
                                            },
                                            .type = pointer.type,
                                        },
                                        .member = null,
                                    };
                                },
                                else => |t| @panic(@tagName(t)),
                            },
                            else => |t| @panic(@tagName(t)),
                        },
                        else => |t| @panic(@tagName(t)),
                    },
                    else => |t| @panic(@tagName(t)),
                };
            },
            else => |t| @panic(@tagName(t)),
        };

        const function_type_index = switch (unit.types.get(member_resolution.callable.type).*) {
            .function => member_resolution.callable.type,
            .pointer => |pointer| switch (unit.types.get(pointer.type).*) {
                .function => pointer.type,
                else => |t| @panic(@tagName(t)),
            },
            else => |t| @panic(@tagName(t)),
        };

        const function_prototype = unit.function_prototypes.get(unit.types.get(function_type_index).function);

        const argument_declaration_count = function_prototype.argument_types.len;
        _ = argument_declaration_count; // autofix

        // // Argument list holds already the value of the member value
        // if (argument_nodes.len + @intFromBool(member_resolution.member != null) != argument_declaration_count) {
        //     @panic("Argument count mismatch");
        // }

        const is_indirect = function_prototype.abi.return_type_abi.kind == .indirect;
        const extra_member_count = @as(usize, @intFromBool(is_indirect)) + @intFromBool(member_resolution.member != null);
        _ = extra_member_count; // autofix

        var argument_list = BoundedArray(V, 512){};

        const indirect_return: ?V = switch (function_prototype.abi.return_type_abi.kind) {
            .indirect => |indirect| b: {
                const indirect_type = unit.types.get(indirect.type);
                const indirect_alignment = indirect_type.getAbiAlignment(unit);
                if (indirect.alignment <= indirect_alignment) {
                    const stack = try builder.createStackVariable(unit, context, indirect.type, null);
                    const v = V{
                        .value = .{
                            .runtime = stack,
                        },
                        .type = indirect.pointer,
                    };
                    argument_list.appendAssumeCapacity(v);

                    break :b v;
                } else {
                    unreachable;
                }
            },
            else => null,
        };

        if (member_resolution.member) |m| {
            const member_argument_index = @intFromBool(is_indirect);
            const abi = function_prototype.abi.parameter_types_abi[member_argument_index];
            switch (abi.kind) {
                .direct => argument_list.appendAssumeCapacity(m),
                else => |t| @panic(@tagName(t)),
            }
        }

        const argument_offset = @intFromBool(member_resolution.member != null);
        //extra_memmber_count
        //
        var index: usize = argument_offset;
        _ = &index;

        for (argument_nodes) |argument_ni| {
            const argument_node = unit.getNode(argument_ni);

            switch (argument_node.id) {
                .comptime_expression => {},
                else => {
                    const argument_type_index = function_prototype.argument_types[index];
                    const argument_abi = function_prototype.abi.parameter_types_abi[index];
                    index += 1;
                    const argument_node_index = switch (argument_node.id) {
                        .named_argument => argument_node.right,
                        else => argument_ni,
                    };
                    const arg_type_expect = Type.Expect{
                        .type = argument_type_index,
                    };
                    const argument_value = try builder.resolveRuntimeValue(unit, context, arg_type_expect, argument_node_index, .right);

                    switch (argument_abi.kind) {
                        .direct => {
                            assert(argument_value.type == argument_type_index);
                            argument_list.appendAssumeCapacity(argument_value);
                        },
                        .direct_coerce => |coerced_type_index| if (coerced_type_index == argument_value.type) argument_list.appendAssumeCapacity(argument_value) else {
                            const stack = try builder.createStackVariable(unit, context, argument_value.type, null);

                            const pointer_type = try unit.getPointerType(.{
                                .type = argument_value.type,
                                .termination = .none,
                                .mutability = .@"var",
                                .many = false,
                                .nullable = false,
                            });

                            const argument_alloca = V{
                                .value = .{
                                    .runtime = stack,
                                },
                                .type = pointer_type,
                            };

                            const store = unit.instructions.append_index(.{
                                .store = .{
                                    .destination = argument_alloca,
                                    .source = argument_value,
                                },
                            });
                            try builder.appendInstruction(unit, store);

                            const target_type = unit.types.get(coerced_type_index);
                            const target_alignment = target_type.getAbiAlignment(unit);
                            const target_size = target_type.getAbiSize(unit);
                            // const types = [2]*Type{unit.types.get(pair[0]), unit.types.get(pair[1])};
                            const source_type = unit.types.get(argument_value.type);
                            const source_alignment = source_type.getAbiAlignment(unit);
                            const source_size = source_type.getAbiSize(unit);
                            const target_is_scalable_vector_type = false;
                            const source_is_scalable_vector_type = false;

                            if (source_size >= target_size and !source_is_scalable_vector_type and !target_is_scalable_vector_type) {
                                const load = unit.instructions.append_index(.{
                                    .load = .{
                                        .value = argument_alloca,
                                        .type = coerced_type_index,
                                    },
                                });
                                try builder.appendInstruction(unit, load);

                                argument_list.appendAssumeCapacity(V{
                                    .value = .{
                                        .runtime = load,
                                    },
                                    .type = coerced_type_index,
                                });
                            } else {
                                const alignment = @max(target_alignment, source_alignment);
                                const temporal = try builder.createStackVariable(unit, context, coerced_type_index, alignment);
                                const coerced_pointer_type = try unit.getPointerType(.{
                                    .type = coerced_type_index,
                                    .termination = .none,
                                    .mutability = .@"var",
                                    .many = false,
                                    .nullable = false,
                                });
                                const destination = V{
                                    .value = .{
                                        .runtime = temporal,
                                    },
                                    .type = coerced_pointer_type,
                                };
                                try builder.emitMemcpy(unit, context, .{
                                    .destination = destination,
                                    .source = argument_alloca,
                                    .destination_alignment = alignment,
                                    .source_alignment = source_alignment,
                                    .size = source_size,
                                    .is_volatile = false,
                                });
                                const load = unit.instructions.append_index(.{
                                    .load = .{
                                        .value = destination,
                                        .type = coerced_type_index,
                                        .alignment = alignment,
                                    },
                                });
                                try builder.appendInstruction(unit, load);

                                argument_list.appendAssumeCapacity(V{
                                    .value = .{
                                        .runtime = load,
                                    },
                                    .type = coerced_type_index,
                                });
                            }
                        },
                        .direct_pair => |pair| {
                            const struct_type_index = try unit.getTwoStruct(pair);
                            const pair_struct_type = unit.types.get(struct_type_index);
                            const are_similar = b: {
                                if (struct_type_index == argument_type_index) {
                                    break :b true;
                                } else {
                                    const original_type = unit.types.get(argument_type_index);
                                    switch (original_type.*) {
                                        .@"struct" => |struct_index| switch (unit.structs.get(struct_index).kind) {
                                            .@"struct" => |*original_struct| {
                                                if (original_struct.fields.len == 2) {
                                                    for (original_struct.fields, pair) |field_index, pair_type_index| {
                                                        const field = unit.struct_fields.get(field_index);
                                                        if (field.type != pair_type_index) break :b false;
                                                    }

                                                    break :b true;
                                                } else {
                                                    break :b false;
                                                }
                                            },
                                            else => |t| @panic(@tagName(t)),
                                        },
                                        else => |t| @panic(@tagName(t)),
                                    }
                                }
                            };

                            if (are_similar) {
                                const extract_0 = unit.instructions.append_index(.{
                                    .extract_value = .{
                                        .expression = argument_value,
                                        .index = 0,
                                    },
                                });
                                try builder.appendInstruction(unit, extract_0);

                                argument_list.appendAssumeCapacity(.{
                                    .value = .{
                                        .runtime = extract_0,
                                    },
                                    .type = pair[0],
                                });

                                const extract_1 = unit.instructions.append_index(.{
                                    .extract_value = .{
                                        .expression = argument_value,
                                        .index = 1,
                                    },
                                });
                                try builder.appendInstruction(unit, extract_1);

                                argument_list.appendAssumeCapacity(.{
                                    .value = .{
                                        .runtime = extract_1,
                                    },
                                    .type = pair[1],
                                });
                            } else {
                                const argument_type = unit.types.get(argument_type_index);
                                const argument_alignment = argument_type.getAbiAlignment(unit);
                                const target_type = pair_struct_type;
                                const target_alignment = target_type.getAbiAlignment(unit);

                                const alloca_value = if (argument_alignment < target_alignment) b: {
                                    const coerced_alloca = try builder.createStackVariable(unit, context, struct_type_index, null);
                                    const coerced_pointer_type = try unit.getPointerType(.{
                                        .type = struct_type_index,
                                        .termination = .none,
                                        .mutability = .@"var",
                                        .many = false,
                                        .nullable = false,
                                    });
                                    const coerced_pointer = V{
                                        .value = .{
                                            .runtime = coerced_alloca,
                                        },
                                        .type = coerced_pointer_type,
                                    };
                                    const coerced_store = unit.instructions.append_index(.{
                                        .store = .{
                                            .destination = coerced_pointer,
                                            .source = argument_value,
                                        },
                                    });
                                    try builder.appendInstruction(unit, coerced_store);

                                    break :b coerced_pointer;
                                } else b: {
                                    const pointer_type = try unit.getPointerType(.{
                                        .type = argument_type_index,
                                        .termination = .none,
                                        .mutability = .@"var",
                                        .many = false,
                                        .nullable = false,
                                    });
                                    const alloca = try builder.createStackVariable(unit, context, argument_type_index, null);

                                    const argument_alloca = V{
                                        .value = .{
                                            .runtime = alloca,
                                        },
                                        .type = pointer_type,
                                    };
                                    const store = unit.instructions.append_index(.{
                                        .store = .{
                                            .destination = argument_alloca,
                                            .source = argument_value,
                                        },
                                    });
                                    try builder.appendInstruction(unit, store);

                                    break :b argument_alloca;
                                };
                                const gep0 = unit.instructions.append_index(.{
                                    .get_element_pointer = .{
                                        .pointer = alloca_value.value.runtime,
                                        .base_type = struct_type_index,
                                        .is_struct = true,
                                        .index = .{
                                            .value = .{
                                                .@"comptime" = .{
                                                    .constant_int = .{
                                                        .value = 0,
                                                    },
                                                },
                                            },
                                            .type = .u32,
                                        },
                                        .name = try unit.processIdentifier(context, "direct_pair_gep0"),
                                    },
                                });
                                try builder.appendInstruction(unit, gep0);

                                const load0 = unit.instructions.append_index(.{
                                    .load = .{
                                        .value = .{
                                            .value = .{
                                                .runtime = gep0,
                                            },
                                            .type = try unit.getPointerType(.{
                                                .type = pair[0],
                                                .termination = .none,
                                                .mutability = .@"var",
                                                .many = false,
                                                .nullable = false,
                                            }),
                                        },
                                        .type = pair[0],
                                    },
                                });
                                try builder.appendInstruction(unit, load0);

                                const gep1 = unit.instructions.append_index(.{
                                    .get_element_pointer = .{
                                        .pointer = alloca_value.value.runtime,
                                        .base_type = struct_type_index,
                                        .is_struct = true,
                                        .index = .{
                                            .value = .{
                                                .@"comptime" = .{
                                                    .constant_int = .{
                                                        .value = 1,
                                                    },
                                                },
                                            },
                                            .type = .u32,
                                        },
                                        .name = try unit.processIdentifier(context, "direct_pair_gep1"),
                                    },
                                });
                                try builder.appendInstruction(unit, gep1);

                                const load1 = unit.instructions.append_index(.{
                                    .load = .{
                                        .value = .{
                                            .value = .{
                                                .runtime = gep1,
                                            },
                                            .type = try unit.getPointerType(.{
                                                .type = pair[1],
                                                .termination = .none,
                                                .mutability = .@"var",
                                                .many = false,
                                                .nullable = false,
                                            }),
                                        },
                                        .type = pair[1],
                                    },
                                });
                                try builder.appendInstruction(unit, load1);

                                argument_list.appendAssumeCapacity(V{
                                    .value = .{
                                        .runtime = load0,
                                    },
                                    .type = pair[0],
                                });
                                argument_list.appendAssumeCapacity(V{
                                    .value = .{
                                        .runtime = load1,
                                    },
                                    .type = pair[1],
                                });
                            }
                        },
                        .indirect => |indirect| {
                            const argument_type = unit.types.get(argument_type_index);
                            const indirect_pointer_type = unit.types.get(indirect.pointer);
                            assert(argument_type_index == indirect_pointer_type.pointer.type);
                            assert(indirect.type == argument_type_index);

                            const direct = b: {
                                if (!argument_abi.attributes.by_value) break :b false;
                                switch (argument_type.*) {
                                    .pointer => unreachable,
                                    else => break :b false,
                                }
                            };

                            if (direct) {
                                unreachable;
                            } else {
                                const stack = try builder.createStackVariable(unit, context, argument_type_index, indirect.alignment);
                                const indirect_value = V{
                                    .value = .{
                                        .runtime = stack,
                                    },
                                    .type = indirect.pointer,
                                };
                                const store = unit.instructions.append_index(.{
                                    .store = .{
                                        .destination = indirect_value,
                                        .source = argument_value,
                                    },
                                });
                                try builder.appendInstruction(unit, store);

                                argument_list.appendAssumeCapacity(indirect_value);
                            }
                        },
                        else => |t| @panic(@tagName(t)),
                    }
                },
            }
        }

        const instruction = unit.instructions.append_index(.{
            .call = .{
                .callable = member_resolution.callable,
                .function_type = function_type_index,
                .arguments = b: {
                    const array = try context.arena.new_array(V, argument_list.len);
                    @memcpy(array, argument_list.slice());
                    break :b array;
                },
            },
        });
        try builder.appendInstruction(unit, instruction);

        if (function_prototype.return_type == .noreturn) {
            try builder.buildTrap(unit, context);
        }

        if (indirect_return) |v| {
            const load = unit.instructions.append_index(.{
                .load = .{
                    .value = v,
                    .type = function_prototype.return_type,
                },
            });

            try builder.appendInstruction(unit, load);
            return .{
                .value = .{
                    .runtime = load,
                },
                .type = function_prototype.return_type,
            };
        } else {
            return .{
                .value = .{
                    .runtime = instruction,
                },
                .type = function_prototype.return_type,
            };
        }
    }

    fn emitLocalVariableDeclaration(builder: *Builder, unit: *Unit, context: *const Context, token_index: Token.Index, mutability: Mutability, declaration_type: Type.Index, initialization: V, emit: bool, maybe_name: ?[]const u8) !Instruction.Index {
        assert(builder.current_scope.local);
        const token = unit.token_buffer.tokens.get(token_index);
        const identifier = if (maybe_name) |name| name else switch (token.id) {
            .identifier => unit.getExpectedTokenBytes(token_index, .identifier),
            .discard => blk: {
                const name = try join_name(context, "_", unit.discard_identifiers, 10);
                unit.discard_identifiers += 1;
                break :blk name;
            },
            else => |t| @panic(@tagName(t)),
        };
        // logln(.compilation, .identifier, "Analyzing local declaration {s}", .{identifier});
        const identifier_hash = try unit.processIdentifier(context, identifier);
        const token_debug_info = builder.getTokenDebugInfo(unit, token_index);

        const look_in_parent_scopes = true;
        if (builder.current_scope.lookupDeclaration(identifier_hash, look_in_parent_scopes)) |lookup| {
            _ = lookup; // autofix
            @panic("identifier already declared on scope");
            //std.debug.panic("Identifier '{s}' already declarared on scope", .{identifier});
        }

        const local_declaration = unit.local_declarations.append(.{
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

        assert(builder.current_scope.kind == .block);
        try builder.current_scope.declarations.put_no_clobber(identifier_hash, &local_declaration.declaration);

        if (emit) {
            const stack = try builder.createStackVariable(unit, context, declaration_type, null);

            assert(builder.current_scope.kind == .block);
            const local_scope: *Debug.Scope.Local = @fieldParentPtr("scope", builder.current_scope);
            try local_scope.local_declaration_map.put_no_clobber(local_declaration, stack);

            const debug_declare_local = unit.instructions.append_index(.{
                .debug_declare_local_variable = .{
                    .variable = local_declaration,
                    .stack = stack,
                },
            });

            try builder.appendInstruction(unit, debug_declare_local);

            const store = unit.instructions.append_index(.{
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

            try builder.appendInstruction(unit, store);

            return stack;
        } else {
            return .null;
        }
    }

    fn resolveBlock(builder: *Builder, unit: *Unit, context: *const Context, node_index: Node.Index) anyerror!Debug.Block.Index {
        const block_node = unit.getNode(node_index);
        assert(block_node.id == .block);
        const token_debug_info = builder.getTokenDebugInfo(unit, block_node.token);
        const block_index = unit.blocks.append_index(.{
            .scope = .{
                .scope = .{
                    .line = token_debug_info.line,
                    .column = token_debug_info.column,
                    .kind = .block,
                    .level = builder.current_scope.level + 1,
                    .local = builder.current_scope.local,
                    .file = builder.current_file,
                    .declarations = try PinnedHashMap(u32, *Debug.Declaration).init(std.mem.page_size),
                },
                .local_declaration_map = try PinnedHashMap(*Debug.Declaration.Local, Instruction.Index).init(std.mem.page_size),
            },
        });

        const block = unit.blocks.get(block_index);
        if (builder.current_basic_block != .null) {
            assert(builder.current_scope.kind == .block or builder.current_scope.kind == .function);
        }

        try builder.pushScope(unit, &block.scope.scope);
        defer {
            builder.popScope(unit) catch unreachable;
        }

        const statement_node_list = unit.getNodeList(block_node.left);

        for (statement_node_list) |statement_node_index| {
            const statement_node = unit.getNode(statement_node_index);

            try builder.insertDebugCheckPoint(unit, statement_node.token);

            switch (statement_node.id) {
                .assign, .add_assign, .sub_assign, .div_assign, .or_assign => {
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
                    }, statement_node_index, .right);
                },
                .constant_symbol_declaration,
                .variable_symbol_declaration,
                => {
                    // All variables here are local
                    assert(builder.current_scope.local);
                    const expected_identifier_token_index: Token.Index = @enumFromInt(@intFromEnum(statement_node.token) + 1);

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
                                .type = try builder.resolveType(unit, context, type_node_index, &.{}),
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
                    try builder.emitReturn(unit, context, statement_node_index);
                },
                .call => {
                    const result = try builder.resolveCall(unit, context, statement_node_index);
                    switch (unit.types.get(result.type).*) {
                        .void, .noreturn => {},
                        .@"struct" => |struct_index| switch (unit.structs.get(struct_index).kind) {
                            .error_union => {},
                            else => |t| @panic(@tagName(t)),
                        },
                        else => |t| @panic(@tagName(t)),
                    }
                },
                .@"switch" => _ = try builder.resolveSwitch(unit, context, Type.Expect{ .type = .void }, statement_node_index, .right, null),
                .@"unreachable" => {
                    try builder.buildTrap(unit, context);
                },
                .@"while" => {
                    assert(statement_node.left != .null);
                    assert(statement_node.right != .null);

                    const old_loop_header_block = builder.loop_header_block;
                    defer builder.loop_header_block = old_loop_header_block;

                    builder.loop_header_block = try builder.newBasicBlock(unit);
                    try builder.jump(unit, builder.loop_header_block);
                    builder.current_basic_block = builder.loop_header_block;

                    const condition = try builder.resolveRuntimeValue(unit, context, Type.Expect{ .type = .bool }, statement_node.left, .right);
                    const body_block = try builder.newBasicBlock(unit);
                    const exit_block = try builder.newBasicBlock(unit);

                    const old_loop_exit_block = builder.loop_exit_block;
                    defer builder.loop_exit_block = old_loop_exit_block;

                    switch (condition.value) {
                        .runtime => |condition_instruction| {
                            try builder.branch(unit, condition_instruction, body_block, exit_block);
                        },
                        .@"comptime" => |ct| switch (ct) {
                            .bool => |boolean| switch (boolean) {
                                true => {
                                    try builder.jump(unit, body_block);
                                },
                                false => unreachable,
                            },
                            else => |t| @panic(@tagName(t)),
                        },
                        else => unreachable,
                    }

                    builder.current_basic_block = body_block;
                    builder.loop_exit_block = exit_block;

                    const body_value = try builder.resolveRuntimeValue(unit, context, Type.Expect{ .type = .void }, statement_node.right, .right);
                    switch (unit.types.get(body_value.type).*) {
                        .void => {
                            try builder.jump(unit, builder.loop_header_block);
                        },
                        .noreturn => {},
                        else => |t| @panic(@tagName(t)),
                    }

                    builder.current_basic_block = exit_block;
                },
                .for_loop => {
                    assert(statement_node.left != .null);
                    assert(statement_node.right != .null);

                    const conditions = unit.getNode(statement_node.left);
                    const slices_and_range_node = unit.getNodeList(conditions.left);
                    const payloads = unit.getNodeList(conditions.right);
                    assert(slices_and_range_node.len > 0);
                    assert(payloads.len > 0);

                    const for_expressions = unit.getNode(statement_node.right);
                    assert(for_expressions.id == .for_expressions);
                    const body_node_index = for_expressions.left;

                    if (slices_and_range_node.len != payloads.len) {
                        @panic("Slice/range count does not match payload count");
                    }

                    if (slices_and_range_node.len == 1 and unit.getNode(slices_and_range_node[0]).id == .comptime_expression) {
                        const node = unit.getNode(slices_and_range_node[0]);
                        assert(slices_and_range_node.len == 1);
                        const comptime_value = try builder.resolveComptimeValue(unit, context, Type.Expect.none, .{}, node.left, null, .right, &.{}, null, &.{});
                        switch (comptime_value) {
                            .enum_fields => |enum_fields| {
                                const first_enum_field = unit.enum_fields.get(enum_fields[0]);
                                const payload_node = unit.getNode(payloads[0]);
                                const emit = false;
                                const comptime_payload = try builder.emitLocalVariableDeclaration(unit, context, payload_node.token, .@"const", first_enum_field.parent, V{
                                    .type = first_enum_field.parent,
                                    .value = .{
                                        .@"comptime" = .{
                                            .enum_value = enum_fields[0],
                                        },
                                    },
                                }, emit, null);
                                _ = comptime_payload; // autofix
                                const identifier = unit.getExpectedTokenBytes(payload_node.token, .identifier);
                                const hash = try unit.processIdentifier(context, identifier);
                                const symbol_lookup = builder.current_scope.lookupDeclaration(hash, false) orelse unreachable;
                                const local_symbol: *Debug.Declaration.Local = @fieldParentPtr("declaration", symbol_lookup.declaration);

                                for (enum_fields) |enum_field_index| {
                                    local_symbol.init_value.value.@"comptime".enum_value = enum_field_index; // autofix
                                    _ = try builder.resolveRuntimeValue(unit, context, Type.Expect{ .type = .void }, body_node_index, .right);
                                    // const enum_field = unit.enum_fields.get(enum_field_index);
                                }
                            },
                            else => |t| @panic(@tagName(t)),
                        }
                    } else {
                        const count = slices_and_range_node.len;
                        var slices = try context.arena.new_array(V, slices_and_range_node.len);
                        slices.len = count - 1;

                        const last_element_node_index = slices_and_range_node[count - 1];
                        const last_element_node = unit.getNode(last_element_node_index);
                        const last_element_payload = unit.getNode(payloads[count - 1]);

                        const LoopCounter = struct {
                            stack_slot: Instruction.Index,
                            end: V,
                        };

                        for (slices_and_range_node[0 .. count - 1], 0..) |slice_or_range_node_index, i| {
                            const slice = try builder.resolveRuntimeValue(unit, context, Type.Expect.none, slice_or_range_node_index, .right);
                            slices[i] = slice;
                        }

                        const loop_counter: LoopCounter = switch (last_element_node.id) {
                            .range => blk: {
                                assert(last_element_node.left != .null);

                                const range_start = try builder.resolveRuntimeValue(unit, context, Type.Expect{ .type = Type.usize }, last_element_node.left, .right);
                                const emit = true;
                                const stack_slot = try builder.emitLocalVariableDeclaration(unit, context, last_element_payload.token, .@"var", Type.usize, range_start, emit, null);
                                // This is put up here so that the length is constant throughout the loop and we dont have to load the variable unnecessarily
                                const range_end = switch (last_element_node.right) {
                                    .null => switch (unit.types.get(slices[0].type).*) {
                                        .slice => b: {
                                            const len_extract_instruction = unit.instructions.append_index(.{
                                                .extract_value = .{
                                                    .expression = slices[0],
                                                    .index = 1,
                                                },
                                            });
                                            try builder.appendInstruction(unit, len_extract_instruction);

                                            break :b V{
                                                .value = .{
                                                    .runtime = len_extract_instruction,
                                                },
                                                .type = Type.usize,
                                            };
                                        },
                                        else => |t| @panic(@tagName(t)),
                                    },
                                    else => try builder.resolveRuntimeValue(unit, context, Type.Expect{ .type = Type.usize }, last_element_node.right, .right),
                                };

                                break :blk .{
                                    .stack_slot = stack_slot,
                                    .end = range_end,
                                };
                            },
                            else => blk: {
                                const for_loop_value = try builder.resolveRuntimeValue(unit, context, Type.Expect.none, last_element_node_index, .right);

                                const name = try join_name(context, "__anon_i_", unit.anon_i, 10);
                                unit.anon_i += 1;
                                const emit = true;
                                const stack_slot = try builder.emitLocalVariableDeclaration(unit, context, last_element_payload.token, .@"var", Type.usize, .{
                                    .value = .{
                                        .@"comptime" = .{
                                            .constant_int = .{
                                                .value = 0,
                                            },
                                        },
                                    },
                                    .type = Type.usize,
                                }, emit, name);

                                switch (unit.types.get(for_loop_value.type).*) {
                                    .slice => {
                                        const index = slices.len;
                                        slices.len += 1;
                                        slices[index] = for_loop_value;

                                        const len_extract_value = unit.instructions.append_index(.{
                                            .extract_value = .{
                                                .expression = for_loop_value,
                                                .index = 1,
                                            },
                                        });
                                        try builder.appendInstruction(unit, len_extract_value);

                                        break :blk .{
                                            .stack_slot = stack_slot,
                                            .end = .{
                                                .value = .{
                                                    .runtime = len_extract_value,
                                                },
                                                .type = Type.usize,
                                            },
                                        };
                                    },
                                    .pointer => |pointer| switch (unit.types.get(pointer.type).*) {
                                        .array => |array| {
                                            const slice_type = try unit.getSliceType(.{
                                                .child_pointer_type = try unit.getPointerType(.{
                                                    .type = array.type,
                                                    .termination = pointer.termination,
                                                    .mutability = pointer.mutability,
                                                    .many = true,
                                                    .nullable = pointer.nullable,
                                                }),
                                                .child_type = array.type,
                                                .termination = pointer.termination,
                                                .mutability = pointer.mutability,
                                                .nullable = pointer.nullable,
                                            });
                                            const slice = unit.constant_slices.append_index(.{
                                                .array = switch (for_loop_value.value) {
                                                    .@"comptime" => |ct| switch (ct) {
                                                        .global => |global| global,
                                                        else => |t| @panic(@tagName(t)),
                                                    },
                                                    else => |t| @panic(@tagName(t)),
                                                },
                                                .start = 0,
                                                .end = array.count,
                                                .type = slice_type,
                                            });
                                            const slice_value = V{
                                                .value = .{
                                                    .@"comptime" = .{
                                                        .constant_slice = slice,
                                                    },
                                                },
                                                .type = slice_type,
                                            };

                                            const index = slices.len;
                                            slices.len += 1;
                                            slices[index] = slice_value;

                                            break :blk .{
                                                .stack_slot = stack_slot,
                                                .end = .{
                                                    .value = .{
                                                        .@"comptime" = .{
                                                            .constant_int = .{
                                                                .value = array.count,
                                                            },
                                                        },
                                                    },
                                                    .type = Type.usize,
                                                },
                                            };
                                            // TODO: fix this
                                        },
                                        else => |t| @panic(@tagName(t)),
                                    },
                                    else => |t| @panic(@tagName(t)),
                                }
                            },
                        };

                        const old_loop_header_block = builder.loop_header_block;
                        defer builder.loop_header_block = old_loop_header_block;

                        builder.loop_header_block = try builder.newBasicBlock(unit);
                        try builder.jump(unit, builder.loop_header_block);
                        builder.current_basic_block = builder.loop_header_block;

                        const pointer_to_usize = try unit.getPointerType(.{
                            .type = Type.usize,
                            .mutability = .@"const",
                            .nullable = false,
                            .many = false,
                            .termination = .none,
                        });

                        const load = unit.instructions.append_index(.{
                            .load = .{
                                .value = .{
                                    .value = .{
                                        .runtime = loop_counter.stack_slot,
                                    },
                                    .type = pointer_to_usize,
                                },
                                .type = Type.usize,
                            },
                        });

                        try builder.appendInstruction(unit, load);

                        const compare = unit.instructions.append_index(.{
                            .integer_compare = .{
                                .left = .{
                                    .value = .{
                                        .runtime = load,
                                    },
                                    .type = Type.usize,
                                },
                                .right = loop_counter.end,
                                .type = Type.usize,
                                .id = .unsigned_less,
                            },
                        });
                        try builder.appendInstruction(unit, compare);

                        const body_block = try builder.newBasicBlock(unit);
                        const exit_block = try builder.newBasicBlock(unit);
                        try builder.branch(unit, compare, body_block, exit_block);

                        builder.current_basic_block = body_block;
                        const old_loop_exit_block = builder.loop_exit_block;
                        defer builder.loop_exit_block = old_loop_exit_block;
                        builder.loop_exit_block = exit_block;

                        const is_last_element_range = last_element_node.id == .range;
                        const not_range_len = payloads.len - @intFromBool(is_last_element_range);

                        if (slices.len > 0) {
                            const load_i = unit.instructions.append_index(.{
                                .load = .{
                                    .value = .{
                                        .value = .{
                                            .runtime = loop_counter.stack_slot,
                                        },
                                        .type = pointer_to_usize,
                                    },
                                    .type = Type.usize,
                                },
                            });
                            try builder.appendInstruction(unit, load_i);

                            for (payloads[0..not_range_len], slices) |payload_node_index, slice| {
                                const pointer_extract_value = unit.instructions.append_index(.{
                                    .extract_value = .{
                                        .expression = slice,
                                        .index = 0,
                                    },
                                });
                                try builder.appendInstruction(unit, pointer_extract_value);

                                const slice_type = unit.types.get(slice.type).slice;

                                const gep = unit.instructions.append_index(.{
                                    .get_element_pointer = .{
                                        .pointer = pointer_extract_value,
                                        .base_type = slice_type.child_type,
                                        .is_struct = false,
                                        .index = .{
                                            .value = .{
                                                .runtime = load_i,
                                            },
                                            .type = .u32,
                                        },
                                        .name = try unit.processIdentifier(context, "slice_for_payload"),
                                    },
                                });
                                try builder.appendInstruction(unit, gep);

                                const is_by_value = true;
                                const init_instruction = switch (is_by_value) {
                                    true => vblk: {
                                        const load_gep = unit.instructions.append_index(.{
                                            .load = .{
                                                .value = .{
                                                    .value = .{
                                                        .runtime = gep,
                                                    },
                                                    .type = slice_type.child_pointer_type,
                                                },
                                                .type = slice_type.child_type,
                                            },
                                        });
                                        try builder.appendInstruction(unit, load_gep);
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

                        _ = try builder.resolveRuntimeValue(unit, context, Type.Expect{ .type = .void }, body_node_index, .right);

                        const else_node_index = for_expressions.right;
                        if (else_node_index != .null) {
                            unreachable;
                        }

                        const load_iterator = unit.instructions.append_index(.{
                            .load = .{
                                .value = .{
                                    .value = .{
                                        .runtime = loop_counter.stack_slot,
                                    },
                                    .type = pointer_to_usize,
                                },
                                .type = Type.usize,
                            },
                        });

                        try builder.appendInstruction(unit, load_iterator);

                        const increment = unit.instructions.append_index(.{
                            .integer_binary_operation = .{
                                .left = .{
                                    .value = .{
                                        .runtime = load_iterator,
                                    },
                                    .type = Type.usize,
                                },
                                .right = .{
                                    .value = .{
                                        .@"comptime" = .{
                                            .constant_int = .{
                                                .value = 1,
                                            },
                                        },
                                    },
                                    .type = Type.usize,
                                },
                                .id = .add,
                                .signedness = .unsigned,
                            },
                        });

                        try builder.appendInstruction(unit, increment);

                        const increment_store = unit.instructions.append_index(.{
                            .store = .{
                                .destination = .{
                                    .value = .{
                                        .runtime = loop_counter.stack_slot,
                                    },
                                    .type = Type.usize,
                                },
                                .source = .{
                                    .value = .{
                                        .runtime = increment,
                                    },
                                    .type = Type.usize,
                                },
                            },
                        });

                        try builder.appendInstruction(unit, increment_store);

                        try builder.jump(unit, builder.loop_header_block);

                        builder.current_basic_block = exit_block;
                    }
                },
                .break_expression => {
                    try builder.jump(unit, builder.loop_exit_block);
                },
                .continue_expression => {
                    try builder.jump(unit, builder.loop_header_block);
                },
                .@"if" => {
                    assert(statement_node.left != .null);
                    assert(statement_node.right != .null);
                    const condition = try builder.resolveRuntimeValue(unit, context, Type.Expect{ .type = .bool }, statement_node.left, .right);
                    const taken_expression_node_index = statement_node.right;
                    const not_taken_expression_node_index = .null;
                    switch (condition.value) {
                        .@"comptime" => |ct| switch (ct) {
                            .bool => |boolean| switch (boolean) {
                                true => _ = try builder.resolveRuntimeValue(unit, context, Type.Expect{ .type = .void }, taken_expression_node_index, .right),
                                false => {},
                            },
                            else => |t| @panic(@tagName(t)),
                        },
                        .runtime => |condition_instruction| {
                            try builder.resolveBranch(unit, context, Type.Expect{ .type = .void }, condition_instruction, taken_expression_node_index, not_taken_expression_node_index, .null, null);
                        },
                        else => unreachable,
                    }
                },
                .if_else_payload => {
                    assert(statement_node.left != .null);
                    assert(statement_node.right != .null);

                    const if_else_node = unit.getNode(statement_node.left);
                    assert(if_else_node.id == .if_else);
                    assert(if_else_node.left != .null);
                    assert(if_else_node.right != .null);

                    const if_node = unit.getNode(if_else_node.left);
                    assert(if_node.id == .@"if");
                    assert(if_node.left != .null);
                    assert(if_node.right != .null);

                    try builder.resolveBranchPayload(unit, context, .{
                        .payload_node_index = statement_node.right,
                        .optional_node_index = if_node.left,
                        .taken_expression_node_index = if_node.right,
                        .not_taken_expression_node_index = if_else_node.right,
                    });
                },
                .if_payload => {
                    assert(statement_node.left != .null);
                    assert(statement_node.right != .null);
                    const if_node = unit.getNode(statement_node.left);
                    assert(if_node.id == .@"if");
                    assert(if_node.left != .null);
                    assert(if_node.right != .null);

                    try builder.resolveBranchPayload(unit, context, .{
                        .payload_node_index = statement_node.right,
                        .optional_node_index = if_node.left,
                        .taken_expression_node_index = if_node.right,
                        .not_taken_expression_node_index = .null,
                    });
                },
                .catch_expression => _ = try builder.resolveCatchExpression(unit, context, Type.Expect{ .type = .void }, statement_node_index, .left),
                .try_expression => _ = try builder.resolveTryExpression(unit, context, Type.Expect{ .type = .void }, statement_node_index, .left),
                else => |t| @panic(@tagName(t)),
            }
        }

        return block_index;
    }

    fn resolveCatchExpression(builder: *Builder, unit: *Unit, context: *const Context, type_expect: Type.Expect, node_index: Node.Index, side: Side) !V {
        const node = unit.getNode(node_index);
        assert(node.left != .null);
        assert(node.right != .null);

        const expression = try builder.resolveRuntimeValue(unit, context, Type.Expect.none, node.left, .left);
        const expression_type = unit.types.get(expression.type);
        switch (expression_type.*) {
            .@"struct" => |struct_index| switch (unit.structs.get(struct_index).kind) {
                .error_union => |error_union| {
                    switch (type_expect) {
                        .none => {},
                        .type => |type_index| switch (try builder.typecheck(unit, context, type_index, error_union.type)) {
                            .success => {},
                            else => |t| @panic(@tagName(t)),
                        },
                        else => |t| @panic(@tagName(t)),
                    }

                    const catch_type_expect = Type.Expect{ .type = error_union.type };
                    const is_error = unit.instructions.append_index(.{
                        .extract_value = .{
                            .expression = expression,
                            .index = 1,
                        },
                    });
                    try builder.appendInstruction(unit, is_error);
                    const error_block = try builder.newBasicBlock(unit);
                    const clean_block = try builder.newBasicBlock(unit);
                    try builder.branch(unit, is_error, error_block, clean_block);

                    builder.current_basic_block = error_block;

                    const right_node = unit.getNode(node.right);
                    const catch_expression_node_index = switch (right_node.id) {
                        .catch_payload => b: {
                            const payload_node = unit.getNode(right_node.left);
                            const emit = true;

                            const error_extract_value = unit.instructions.append_index(.{
                                .extract_value = .{
                                    .expression = expression,
                                    .index = 0,
                                },
                            });
                            try builder.appendInstruction(unit, error_extract_value);
                            const error_value = V{
                                .value = .{
                                    .runtime = error_extract_value,
                                },
                                .type = error_union.@"error",
                            };
                            _ = try builder.emitLocalVariableDeclaration(unit, context, payload_node.token, .@"const", error_union.@"error", error_value, emit, null);
                            break :b right_node.right;
                        },
                        else => node.right,
                    };

                    const v = try builder.resolveRuntimeValue(unit, context, catch_type_expect, catch_expression_node_index, side);

                    switch (error_union.type) {
                        .void, .noreturn => {
                            assert(unit.basic_blocks.get(builder.current_basic_block).terminated);
                            builder.current_basic_block = clean_block;
                            return v;
                        },
                        else => {
                            const is_block_terminated = unit.basic_blocks.get(builder.current_basic_block).terminated;
                            const CatchInfo = struct {
                                phi: Instruction.Index,
                                exit_block: BasicBlock.Index,
                            };
                            const maybe_catch_info: ?CatchInfo = if (!is_block_terminated) blk: {
                                const expected_type = error_union.type;
                                assert(v.type == expected_type);
                                const phi_index = unit.instructions.append_index(.{
                                    .phi = .{
                                        .type = expected_type,
                                        .values = try context.arena.new(BoundedArray(Instruction.Phi.Value, Instruction.Phi.max_value_count)),
                                    },
                                });
                                const phi = &unit.instructions.get(phi_index).phi;
                                phi.addIncoming(v, builder.current_basic_block);

                                const phi_block = try builder.newBasicBlock(unit);
                                try builder.jump(unit, phi_block);
                                break :blk .{
                                    .phi = phi_index,
                                    .exit_block = phi_block,
                                };
                            } else null;

                            assert(unit.basic_blocks.get(builder.current_basic_block).terminated);
                            builder.current_basic_block = clean_block;

                            const no_error_extract_value = unit.instructions.append_index(.{
                                .extract_value = .{
                                    .expression = expression,
                                    .index = 0,
                                },
                            });
                            try builder.appendInstruction(unit, no_error_extract_value);

                            const value = V{
                                .value = .{
                                    .runtime = no_error_extract_value,
                                },
                                .type = error_union.type,
                            };

                            if (maybe_catch_info) |catch_info| {
                                assert(!is_block_terminated);
                                const phi_index = catch_info.phi;
                                const phi = &unit.instructions.get(phi_index).phi;
                                const exit_block = catch_info.exit_block;

                                phi.addIncoming(value, builder.current_basic_block);

                                try builder.jump(unit, exit_block);
                                builder.current_basic_block = exit_block;

                                try builder.appendInstruction(unit, phi_index);

                                return .{
                                    .value = .{
                                        .runtime = phi_index,
                                    },
                                    .type = error_union.type,
                                };
                            } else {
                                assert(is_block_terminated);
                                return value;
                            }
                        },
                    }
                },
                else => {},
            },
            else => {},
        }

        builder.reportCompileError(unit, context, .{
            .message = "expected error union expression",
            .node = node.left,
        });
    }

    fn resolveBranchPayload(builder: *Builder, unit: *Unit, context: *const Context, arguments: struct {
        payload_node_index: Node.Index,
        optional_node_index: Node.Index,
        taken_expression_node_index: Node.Index,
        not_taken_expression_node_index: Node.Index,
    }) !void {
        const optional_expression = try builder.resolveRuntimeValue(unit, context, Type.Expect.none, arguments.optional_node_index, .right);
        const payload_node = unit.getNode(arguments.payload_node_index);

        switch (optional_expression.value) {
            .runtime => {
                switch (unit.types.get(optional_expression.type).*) {
                    .slice => |slice| {
                        if (slice.nullable) {
                            const pointer_value = unit.instructions.append_index(.{
                                .extract_value = .{
                                    .expression = optional_expression,
                                    .index = 0,
                                },
                            });

                            try builder.appendInstruction(unit, pointer_value);

                            const condition = unit.instructions.append_index(.{
                                .integer_compare = .{
                                    .id = .not_equal,
                                    .left = .{
                                        .value = .{
                                            .runtime = pointer_value,
                                        },
                                        .type = slice.child_pointer_type,
                                    },
                                    .right = .{
                                        .value = .{
                                            .@"comptime" = .null_pointer,
                                        },
                                        .type = slice.child_pointer_type,
                                    },
                                    .type = slice.child_pointer_type,
                                },
                            });
                            try builder.appendInstruction(unit, condition);
                            try builder.resolveBranch(unit, context, Type.Expect{ .type = .void }, condition, arguments.taken_expression_node_index, arguments.not_taken_expression_node_index, payload_node.token, optional_expression);
                        } else {
                            unreachable;
                        }
                    },
                    .pointer => |pointer| {
                        if (pointer.nullable) {
                            const condition = unit.instructions.append_index(.{
                                .integer_compare = .{
                                    .id = .not_equal,
                                    .left = optional_expression,
                                    .right = .{
                                        .value = .{
                                            .@"comptime" = .null_pointer,
                                        },
                                        .type = optional_expression.type,
                                    },
                                    .type = optional_expression.type,
                                },
                            });
                            try builder.appendInstruction(unit, condition);
                            try builder.resolveBranch(unit, context, Type.Expect{ .type = .void }, condition, arguments.taken_expression_node_index, arguments.not_taken_expression_node_index, payload_node.token, optional_expression);
                        } else {
                            unreachable;
                        }
                    },
                    else => |t| @panic(@tagName(t)),
                }
            },
            else => |t| @panic(@tagName(t)),
        }
    }

    fn resolveBranch(builder: *Builder, unit: *Unit, context: *const Context, type_expect: Type.Expect, condition: Instruction.Index, taken_node_index: Node.Index, not_taken_node_index: Node.Index, optional_payload_token: Token.Index, maybe_optional_value: ?V) !void {
        const taken_block = try builder.newBasicBlock(unit);
        const exit_block = try builder.newBasicBlock(unit);
        const not_taken_block = if (not_taken_node_index != .null) try builder.newBasicBlock(unit) else exit_block;
        builder.exit_blocks.appendAssumeCapacity(exit_block);
        try builder.branch(unit, condition, taken_block, not_taken_block);

        builder.current_basic_block = taken_block;

        if (maybe_optional_value) |optional_value| {
            assert(optional_payload_token != .null);
            switch (unit.types.get(optional_value.type).*) {
                .slice => |slice| {
                    const not_null_slice = try unit.getSliceType(.{
                        .child_pointer_type = blk: {
                            const child_pointer_type = unit.types.get(slice.child_pointer_type).pointer;

                            break :blk try unit.getPointerType(.{
                                .type = child_pointer_type.type,
                                .termination = child_pointer_type.termination,
                                .mutability = child_pointer_type.mutability,
                                .many = child_pointer_type.many,
                                .nullable = false,
                            });
                        },
                        .child_type = slice.child_type,
                        .termination = slice.termination,
                        .mutability = slice.mutability,
                        .nullable = false,
                    });

                    const unwrap = unit.instructions.append_index(.{
                        .cast = .{
                            .id = .slice_to_not_null,
                            .value = optional_value,
                            .type = not_null_slice,
                        },
                    });
                    try builder.appendInstruction(unit, unwrap);

                    const emit = true;
                    _ = try builder.emitLocalVariableDeclaration(unit, context, optional_payload_token, .@"const", not_null_slice, .{
                        .value = .{
                            .runtime = unwrap,
                        },
                        .type = not_null_slice,
                    }, emit, null);
                },
                .pointer => |pointer| {
                    const pointer_type = try unit.getPointerType(.{
                        .type = pointer.type,
                        .termination = pointer.termination,
                        .mutability = pointer.mutability,
                        .many = pointer.many,
                        .nullable = false,
                    });

                    const unwrap = unit.instructions.append_index(.{
                        .cast = .{
                            .id = .slice_to_not_null,
                            .value = optional_value,
                            .type = pointer_type,
                        },
                    });
                    try builder.appendInstruction(unit, unwrap);

                    const emit = true;
                    _ = try builder.emitLocalVariableDeclaration(unit, context, optional_payload_token, .@"const", pointer_type, .{
                        .value = .{
                            .runtime = unwrap,
                        },
                        .type = pointer_type,
                    }, emit, null);
                },
                else => |t| @panic(@tagName(t)),
            }
        }

        _ = try builder.resolveRuntimeValue(unit, context, type_expect, taken_node_index, .right);
        if (!unit.basic_blocks.get(builder.current_basic_block).terminated) {
            try builder.jump(unit, exit_block);
        }

        if (not_taken_node_index != .null) {
            builder.current_basic_block = not_taken_block;
            _ = try builder.resolveRuntimeValue(unit, context, type_expect, not_taken_node_index, .right);
            if (!unit.basic_blocks.get(builder.current_basic_block).terminated) {
                try builder.jump(unit, exit_block);
            }
        }

        if (unit.basic_blocks.get(exit_block).predecessors.length > 0) {
            builder.current_basic_block = exit_block;
        }
    }

    fn branch(builder: *Builder, unit: *Unit, condition: Instruction.Index, taken_block: BasicBlock.Index, non_taken_block: BasicBlock.Index) !void {
        const br = unit.instructions.append_index(.{
            .branch = .{
                .condition = condition,
                .from = builder.current_basic_block,
                .taken = taken_block,
                .not_taken = non_taken_block,
            },
        });

        try builder.appendInstruction(unit, br);

        unit.basic_blocks.get(builder.current_basic_block).terminated = true;
        const taken_bb = unit.basic_blocks.get(taken_block);
        const non_taken_bb = unit.basic_blocks.get(non_taken_block);
        try taken_bb.add_predecessor(builder.current_basic_block);
        try non_taken_bb.add_predecessor(builder.current_basic_block);
    }

    fn jump(builder: *Builder, unit: *Unit, new_basic_block: BasicBlock.Index) !void {
        const instruction = unit.instructions.append_index(.{
            .jump = .{
                .from = builder.current_basic_block,
                .to = new_basic_block,
            },
        });

        try builder.appendInstruction(unit, instruction);

        unit.basic_blocks.get(builder.current_basic_block).terminated = true;
        const new_bb = unit.basic_blocks.get(new_basic_block);
        try new_bb.add_predecessor(builder.current_basic_block);
    }

    fn resolveComptimeSwitch(builder: *Builder, unit: *Unit, context: *const Context, type_expect: Type.Expect, global_attributes: Debug.Declaration.Global.Attributes, node_index: Node.Index, maybe_global: ?*Debug.Declaration.Global) !V.Comptime {
        const node = unit.getNode(node_index);
        assert(node.id == .@"switch");
        const expression_to_switch_on = try builder.resolveComptimeValue(unit, context, Type.Expect.none, .{}, node.left, null, .right, &.{}, null, &.{});
        const case_nodes = unit.getNodeList(node.right);
        switch (expression_to_switch_on) {
            .enum_value => |enum_field_index| {
                const enum_field = unit.enum_fields.get(enum_field_index);
                const enum_type = &unit.types.get(enum_field.parent).integer.kind.@"enum";
                const typecheck_enum_result = try unit.typecheckSwitchEnums(context, enum_type, case_nodes);

                const group_index = for (typecheck_enum_result.switch_case_groups, 0..) |switch_case_group, switch_case_group_index| {
                    break for (switch_case_group) |field_index| {
                        if (enum_field_index == field_index) {
                            break switch_case_group_index;
                        }
                    } else {
                        continue;
                    };
                } else typecheck_enum_result.else_switch_case_group_index orelse unreachable;
                const true_switch_case_node = unit.getNode(case_nodes[group_index]);
                return try builder.resolveComptimeValue(unit, context, type_expect, global_attributes, true_switch_case_node.right, maybe_global, .right, &.{}, null, &.{});
            },
            .bool => |boolean| {
                assert(case_nodes.len == 2);
                for (case_nodes) |case_node_index| {
                    const case_node = unit.getNode(case_node_index);
                    assert(case_node.left != .null);
                    assert(case_node.right != .null);
                    const boolean_value = try builder.resolveComptimeValue(unit, context, Type.Expect{ .type = .bool }, .{}, case_node.left, null, .right, &.{}, null, &.{});
                    switch (boolean_value) {
                        .bool => |case_boolean| {
                            if (case_boolean == boolean) {
                                return try builder.resolveComptimeValue(unit, context, type_expect, global_attributes, case_node.right, maybe_global, .right, &.{}, null, &.{});
                            }
                        },
                        else => |t| @panic(@tagName(t)),
                    }
                } else {
                    unreachable;
                }
            },
            else => |t| @panic(@tagName(t)),
        }
    }

    fn resolveSwitch(builder: *Builder, unit: *Unit, context: *const Context, type_expect: Type.Expect, node_index: Node.Index, side: Side, maybe_global: ?*Debug.Declaration.Global) !V {
        _ = maybe_global;
        const node = unit.getNode(node_index);
        assert(node.id == .@"switch");
        const expression_to_switch_on = try builder.resolveRuntimeValue(unit, context, Type.Expect.none, node.left, .right);
        const case_nodes = unit.getNodeList(node.right);

        switch (expression_to_switch_on.value) {
            .@"comptime" => |ct| switch (ct) {
                .enum_value => |enum_field_index| {
                    const enum_field = unit.enum_fields.get(enum_field_index);
                    const enum_type = &unit.types.get(enum_field.parent).integer.kind.@"enum";
                    const typecheck_enum_result = try unit.typecheckSwitchEnums(context, enum_type, case_nodes);

                    const group_index = for (typecheck_enum_result.switch_case_groups, 0..) |switch_case_group, switch_case_group_index| {
                        break for (switch_case_group) |field_index| {
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
                .bool => |boolean| {
                    assert(case_nodes.len == 2);
                    for (case_nodes) |case_node_index| {
                        const case_node = unit.getNode(case_node_index);
                        assert(case_node.left != .null);
                        assert(case_node.right != .null);
                        const boolean_value = try builder.resolveComptimeValue(unit, context, Type.Expect{ .type = .bool }, .{}, case_node.left, null, .right, &.{}, null, &.{});
                        switch (boolean_value) {
                            .bool => |case_boolean| {
                                if (case_boolean == boolean) {
                                    return try builder.resolveRuntimeValue(unit, context, type_expect, case_node.right, side);
                                }
                            },
                            else => |t| @panic(@tagName(t)),
                        }
                    } else {
                        unreachable;
                    }
                },
                else => |t| @panic(@tagName(t)),
            },
            .runtime => {
                const condition_type = expression_to_switch_on.type;
                switch (condition_type) {
                    .comptime_int => unreachable,
                    else => {},
                }

                const PhiInfo = struct {
                    block: BasicBlock.Index,
                    instruction: Instruction.Index,
                };
                const type_index = switch (type_expect) {
                    .type => |type_index| type_index,
                    else => |t| @panic(@tagName(t)),
                };

                const switch_instruction_index = unit.instructions.append_index(.{
                    .@"switch" = .{
                        .condition = expression_to_switch_on,
                        .block_type = type_index,
                    },
                });
                try builder.appendInstruction(unit, switch_instruction_index);

                const switch_instruction = &unit.instructions.get(switch_instruction_index).@"switch";
                const phi_info: ?PhiInfo = switch (unit.types.get(type_index).*) {
                    .void, .noreturn => null,
                    else => PhiInfo{
                        .instruction = unit.instructions.append_index(.{
                            .phi = .{
                                .type = type_index,
                                .values = try context.arena.new(BoundedArray(Instruction.Phi.Value, Instruction.Phi.max_value_count)),
                            },
                        }),
                        .block = try builder.newBasicBlock(unit),
                    },
                };

                const before_switch_bb = builder.current_basic_block;
                const switch_exit_block = try builder.newBasicBlock(unit);

                var stack_switch_cases = BoundedArray(Instruction.Switch.Case, 512){};

                for (case_nodes) |case_node_index| {
                    builder.current_basic_block = before_switch_bb;
                    const case_node = unit.getNode(case_node_index);
                    assert(case_node.right != .null);
                    var conditions = BoundedArray(V.Comptime, 512){};

                    switch (case_node.left) {
                        .null => {},
                        else => {
                            const condition_node = unit.getNode(case_node.left);
                            switch (condition_node.id) {
                                .node_list => {
                                    const condition_nodes = unit.getNodeListFromNode(condition_node);

                                    for (condition_nodes) |condition_node_index| {
                                        const cn = unit.getNode(condition_node_index);
                                        switch (cn.id) {
                                            .range => {
                                                const left = try builder.resolveComptimeValue(unit, context, Type.Expect{ .type = condition_type }, .{}, cn.left, null, .right, &.{}, null, &.{});
                                                const right = try builder.resolveComptimeValue(unit, context, Type.Expect{ .type = condition_type }, .{}, cn.right, null, .right, &.{}, null, &.{});

                                                switch (condition_type) {
                                                    .u8 => {
                                                        var left_ch: u8 = switch (left) {
                                                            .constant_int => |ci| @intCast(ci.value),
                                                            else => |t| @panic(@tagName(t)),
                                                        };
                                                        const right_ch: u8 = switch (right) {
                                                            .constant_int => |ci| @intCast(ci.value),
                                                            else => |t| @panic(@tagName(t)),
                                                        };

                                                        if (left_ch < right_ch) {
                                                            while (left_ch <= right_ch) : (left_ch += 1) {
                                                                conditions.appendAssumeCapacity(.{
                                                                    .constant_int = .{
                                                                        .value = left_ch,
                                                                    },
                                                                });
                                                            }
                                                        } else {
                                                            unreachable;
                                                        }
                                                    },
                                                    else => unreachable,
                                                }
                                            },
                                            else => conditions.appendAssumeCapacity(try builder.resolveComptimeValue(unit, context, Type.Expect{ .type = condition_type }, .{}, condition_node_index, null, .right, &.{}, null, &.{})),
                                        }
                                    }
                                },
                                else => {
                                    const v = try builder.resolveComptimeValue(unit, context, Type.Expect{ .type = condition_type }, .{}, case_node.left, null, .right, &.{}, null, &.{});
                                    conditions.appendAssumeCapacity(v);
                                },
                            }
                        },
                    }

                    const case_block = try builder.newBasicBlock(unit);
                    const case_bb = unit.basic_blocks.get(case_block);
                    try case_bb.add_predecessor(before_switch_bb);

                    builder.current_basic_block = case_block;

                    const v = try builder.resolveRuntimeValue(unit, context, type_expect, case_node.right, .right);

                    if (phi_info) |phi| {
                        if (!unit.basic_blocks.get(builder.current_basic_block).terminated) {
                            const phi_instruction = &unit.instructions.get(phi.instruction).phi;
                            phi_instruction.addIncoming(v, case_block);
                            try builder.jump(unit, phi.block);
                        }
                    } else if (builder.current_basic_block != .null) {
                        const current_block = unit.basic_blocks.get(builder.current_basic_block);
                        const v_ty = unit.types.get(v.type);
                        switch (v_ty.*) {
                            .void => {
                                assert(!current_block.terminated);
                                try builder.jump(unit, switch_exit_block);
                            },
                            .noreturn => {},
                            else => |t| @panic(@tagName(t)),
                        }
                    }

                    if (conditions.len > 0) {
                        for (conditions.slice()) |condition| {
                            const case = Instruction.Switch.Case{
                                .condition = condition,
                                .basic_block = case_block,
                            };
                            stack_switch_cases.appendAssumeCapacity(case);
                        }
                    } else {
                        assert(switch_instruction.else_block == .null);
                        switch_instruction.else_block = case_block;
                    }
                }

                const switch_cases = try context.arena.new_array(Instruction.Switch.Case, stack_switch_cases.len);
                @memcpy(switch_cases, stack_switch_cases.slice());

                switch_instruction.cases = switch_cases;

                if (switch_instruction.else_block == .null) {
                    switch_instruction.else_block = try builder.create_unreachable_block(unit, context);
                }

                if (phi_info) |phi| {
                    const phi_instruction = &unit.instructions.get(phi.instruction).phi;
                    if (phi_instruction.values.len > 0) {
                        builder.current_basic_block = phi.block;
                        try builder.appendInstruction(unit, phi.instruction);

                        return V{
                            .value = .{
                                .runtime = phi.instruction,
                            },
                            .type = type_index,
                        };
                    }
                }

                if (builder.current_basic_block != .null) {
                    const current_block = unit.basic_blocks.get(builder.current_basic_block);
                    assert(current_block.terminated);
                    const sw_exit_block = unit.basic_blocks.get(switch_exit_block);
                    assert(current_block.terminated);
                    if (sw_exit_block.predecessors.length > 0) {
                        builder.current_basic_block = switch_exit_block;

                        switch (type_expect) {
                            .type => |ti| switch (ti) {
                                .void => return V{
                                    .value = .{
                                        .@"comptime" = .void,
                                    },
                                    .type = .void,
                                },
                                else => unreachable,
                            },
                            else => |t| @panic(@tagName(t)),
                        }
                    } else {
                        return V{
                            .value = .{
                                .@"comptime" = .@"unreachable",
                            },
                            .type = .noreturn,
                        };
                    }
                } else {
                    unreachable;
                }
            },
            else => |t| @panic(@tagName(t)),
        }
    }

    fn create_unreachable_block(builder: *Builder, unit: *Unit, context: *const Context) !BasicBlock.Index {
        const block = try builder.newBasicBlock(unit);
        const old_block = builder.current_basic_block;
        builder.current_basic_block = block;
        try builder.buildUnreachable(unit, context);
        builder.current_basic_block = old_block;

        return block;
    }

    fn resolveFieldAccess(builder: *Builder, unit: *Unit, context: *const Context, type_expect: Type.Expect, node_index: Node.Index, side: Side, new_parameters: []const V.Comptime) !V {
        const node = unit.getNode(node_index);
        const right_node = unit.getNode(node.right);
        const identifier = switch (right_node.id) {
            .identifier => unit.getExpectedTokenBytes(right_node.token, .identifier),
            .string_literal => try unit.fixupStringLiteral(context, right_node.token),
            else => |t| @panic(@tagName(t)),
        };
        const identifier_hash = try unit.processIdentifier(context, identifier);

        const left_node_index = node.left;
        const left = try builder.resolveRuntimeValue(unit, context, Type.Expect.none, left_node_index, .left);

        const result: V = switch (left.value) {
            .@"comptime" => |ct| switch (ct) {
                .type => |type_index| b: {
                    const left_type = unit.types.get(type_index);
                    const scope = left_type.getScope(unit);
                    const look_in_parent_scopes = false;

                    const result: V = if (scope.lookupDeclaration(identifier_hash, look_in_parent_scopes)) |lookup| blk: {
                        const global = try builder.referenceGlobalDeclaration(unit, context, lookup.scope, lookup.declaration, .{}, new_parameters, null, &.{});
                        const pointer_type = try unit.getPointerType(.{
                            .type = global.declaration.type,
                            .termination = .none,
                            .mutability = .@"var",
                            .many = false,
                            .nullable = false,
                        });

                        break :blk switch (side) {
                            .left => switch (global.initial_value) {
                                .type => |ti| .{
                                    .value = .{
                                        .@"comptime" = .{
                                            .type = ti,
                                        },
                                    },
                                    .type = .type,
                                },
                                else => .{
                                    .value = .{
                                        .@"comptime" = .{
                                            .global = global,
                                        },
                                    },
                                    .type = pointer_type,
                                },
                            },
                            .right => switch (global.declaration.mutability) {
                                .@"const" => .{
                                    .value = .{
                                        .@"comptime" = global.initial_value,
                                    },
                                    .type = global.declaration.type,
                                },
                                .@"var" => v: {
                                    const load = unit.instructions.append_index(.{
                                        .load = .{
                                            .value = .{
                                                .value = .{
                                                    .@"comptime" = .{
                                                        .global = global,
                                                    },
                                                },
                                                .type = pointer_type,
                                            },
                                            .type = global.declaration.type,
                                        },
                                    });

                                    try builder.appendInstruction(unit, load);
                                    break :v .{
                                        .value = .{
                                            .runtime = load,
                                        },
                                        .type = global.declaration.type,
                                    };
                                },
                            },
                        };
                    } else switch (left_type.*) {
                        .integer => |*integer| switch (integer.kind) {
                            .@"enum" => |*enum_type| blk: {
                                const field_index = for (enum_type.fields) |enum_field_index| {
                                    const enum_field = unit.enum_fields.get(enum_field_index);
                                    if (enum_field.name == identifier_hash) {
                                        break enum_field_index;
                                    }
                                } else @panic("Right identifier not found"); //std.debug.panic("Right identifier '{s}' not found", .{identifier});
                                break :blk V{
                                    .value = .{
                                        .@"comptime" = .{
                                            .enum_value = field_index,
                                        },
                                    },
                                    .type = type_index,
                                };
                            },
                            .@"error" => |*error_type| blk: {
                                const field_index = for (error_type.fields.slice()) |error_field_index| {
                                    const enum_field = unit.error_fields.get(error_field_index);
                                    if (enum_field.name == identifier_hash) {
                                        break error_field_index;
                                    }
                                } else @panic("Right identifier not found"); //std.debug.panic("Right identifier '{s}' not found", .{identifier});
                                break :blk V{
                                    .value = .{
                                        .@"comptime" = .{
                                            .error_value = field_index,
                                        },
                                    },
                                    .type = type_index,
                                };
                            },
                            else => |t| @panic(@tagName(t)),
                        },
                        else => |t| @panic(@tagName(t)),
                    };

                    break :b result;
                },
                .global => |global| switch (unit.types.get(global.declaration.type).*) {
                    .array => |array| if (byte_equal(identifier, length_field_name)) switch (type_expect) {
                        .none => V{
                            .value = .{
                                .@"comptime" = .{
                                    .comptime_int = .{
                                        .value = array.count,
                                        .signedness = .unsigned,
                                    },
                                },
                            },
                            .type = .comptime_int,
                        },
                        else => |t| @panic(@tagName(t)),
                    } else unreachable,
                    else => |t| @panic(@tagName(t)),
                },
                .string_literal => |hash| if (byte_equal(identifier, length_field_name)) switch (type_expect) {
                    .type => |type_index| switch (unit.types.get(type_index).*) {
                        .integer => |*integer| switch (integer.kind) {
                            .materialized_int => V{
                                .value = .{
                                    .@"comptime" = .{
                                        .constant_int = .{
                                            .value = unit.getIdentifier(hash).len,
                                        },
                                    },
                                },
                                .type = type_index,
                            },
                            else => |t| @panic(@tagName(t)),
                        },
                        else => |t| @panic(@tagName(t)),
                    },
                    else => |t| @panic(@tagName(t)),
                } else unreachable,
                else => |t| @panic(@tagName(t)),
            },
            .runtime => |_| b: {
                const left_type = unit.types.get(left.type);
                switch (left_type.*) {
                    .pointer => |pointer| switch (unit.types.get(pointer.type).*) {
                        .array => |array| {
                            assert(side == .right);
                            assert(byte_equal(identifier, length_field_name));
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
                                .none => V{
                                    .value = .{
                                        .@"comptime" = .{
                                            .comptime_int = .{
                                                .value = array.count,
                                                .signedness = .unsigned,
                                            },
                                        },
                                    },
                                    .type = .comptime_int,
                                },
                                else => |t| @panic(@tagName(t)),
                            };
                        },
                        .slice => |slice| {
                            const slice_field: SliceField = inline for (@typeInfo(SliceField).Enum.fields) |field| {
                                if (byte_equal(field.name, identifier)) break @enumFromInt(field.value);
                            } else unreachable;
                            const field_type = switch (slice_field) {
                                .pointer => slice.child_pointer_type,
                                .length => Type.usize,
                            };
                            const field_index = @intFromEnum(slice_field);

                            const gep = unit.instructions.append_index(.{
                                .get_element_pointer = .{
                                    .pointer = left.value.runtime,
                                    .base_type = pointer.type,
                                    .is_struct = true,
                                    .index = .{
                                        .value = .{
                                            .@"comptime" = .{
                                                .constant_int = .{
                                                    .value = field_index,
                                                },
                                            },
                                        },
                                        .type = .u32,
                                    },
                                    .name = try unit.processIdentifier(context, switch (slice_field) {
                                        .pointer => "slice_pointer",
                                        .length => "slice_length",
                                    }),
                                },
                            });
                            try builder.appendInstruction(unit, gep);

                            const gep_value = V{
                                .value = .{
                                    .runtime = gep,
                                },
                                .type = try unit.getPointerType(.{
                                    .type = Type.usize,
                                    .many = false,
                                    .nullable = false,
                                    .termination = .none,
                                    .mutability = .@"const",
                                }),
                            };

                            switch (side) {
                                .left => break :b gep_value,
                                .right => {
                                    const load = unit.instructions.append_index(.{
                                        .load = .{
                                            .value = gep_value,
                                            .type = field_type,
                                        },
                                    });
                                    try builder.appendInstruction(unit, load);

                                    break :b .{
                                        .value = .{
                                            .runtime = load,
                                        },
                                        .type = field_type,
                                    };
                                },
                            }
                        },
                        .pointer => |child_pointer| switch (unit.types.get(child_pointer.type).*) {
                            .array => |array| {
                                assert(byte_equal(identifier, length_field_name));

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
                            .@"struct" => |struct_index| switch (unit.structs.get(struct_index).kind) {
                                .@"struct" => |*struct_type| {
                                    const fields = struct_type.fields;

                                    for (fields, 0..) |field_index, i| {
                                        const field = unit.struct_fields.get(field_index);
                                        if (field.name == identifier_hash) {
                                            const load = unit.instructions.append_index(.{
                                                .load = .{
                                                    .value = left,
                                                    .type = pointer.type,
                                                },
                                            });
                                            try builder.appendInstruction(unit, load);

                                            // GEP because this is still a pointer
                                            const gep = unit.instructions.append_index(.{
                                                .get_element_pointer = .{
                                                    .pointer = load,
                                                    .base_type = child_pointer.type,
                                                    .is_struct = true,
                                                    .index = .{
                                                        .value = .{
                                                            .@"comptime" = .{
                                                                .constant_int = .{
                                                                    .value = i,
                                                                },
                                                            },
                                                        },
                                                        .type = .u32,
                                                    },
                                                    .name = field.name,
                                                },
                                            });
                                            try builder.appendInstruction(unit, gep);

                                            const mutability = child_pointer.mutability;
                                            const gep_pointer_type = try unit.getPointerType(.{
                                                .type = field.type,
                                                .termination = .none,
                                                .mutability = mutability,
                                                .many = false,
                                                .nullable = false,
                                            });
                                            const gep_value = V{
                                                .value = .{
                                                    .runtime = gep,
                                                },
                                                .type = gep_pointer_type,
                                            };

                                            break :b switch (side) {
                                                .left => gep_value,
                                                .right => right: {
                                                    const field_load = unit.instructions.append_index(.{
                                                        .load = .{
                                                            .value = gep_value,
                                                            .type = field.type,
                                                        },
                                                    });
                                                    try builder.appendInstruction(unit, field_load);

                                                    break :right .{
                                                        .value = .{
                                                            .runtime = field_load,
                                                        },
                                                        .type = field.type,
                                                    };
                                                },
                                            };
                                        }
                                    } else {
                                        const scope = left_type.getScope(unit);
                                        _ = scope; // autofix
                                        unreachable;
                                    }
                                },
                                else => |t| @panic(@tagName(t)),
                            },
                            else => |t| @panic(@tagName(t)),
                        },
                        .@"struct" => |struct_index| switch (unit.structs.get(struct_index).kind) {
                            .@"struct" => |*struct_type| {
                                const fields = struct_type.fields;

                                for (fields, 0..) |field_index, i| {
                                    const field = unit.struct_fields.get(field_index);
                                    if (field.name == identifier_hash) {
                                        const gep = unit.instructions.append_index(.{
                                            .get_element_pointer = .{
                                                .pointer = left.value.runtime,
                                                .base_type = pointer.type,
                                                .is_struct = true,
                                                .index = .{
                                                    .value = .{
                                                        .@"comptime" = .{
                                                            .constant_int = .{
                                                                .value = i,
                                                            },
                                                        },
                                                    },
                                                    .type = .u32,
                                                },
                                                .name = field.name,
                                            },
                                        });
                                        try builder.appendInstruction(unit, gep);

                                        const gep_value = V{
                                            .value = .{
                                                .runtime = gep,
                                            },
                                            .type = try unit.getPointerType(.{
                                                .type = field.type,
                                                .mutability = .@"const",
                                                .nullable = false,
                                                .many = false,
                                                .termination = .none,
                                            }),
                                        };
                                        switch (side) {
                                            .left => break :b gep_value,
                                            .right => {
                                                const load = unit.instructions.append_index(.{
                                                    .load = .{
                                                        .value = gep_value,
                                                        .type = field.type,
                                                    },
                                                });

                                                try builder.appendInstruction(unit, load);

                                                break :b V{
                                                    .value = .{
                                                        .runtime = load,
                                                    },
                                                    .type = field.type,
                                                };
                                            },
                                        }
                                    }
                                } else {
                                    const scope = left_type.getScope(unit);
                                    _ = scope; // autofix
                                    unreachable;
                                }
                            },
                            else => |t| @panic(@tagName(t)),
                        },
                        .integer => |*integer| switch (integer.kind) {
                            .bitfield => |*bitfield| {
                                const fields = bitfield.fields;

                                for (fields, 0..) |field_index, i| {
                                    const field = unit.struct_fields.get(field_index);
                                    if (field.name == identifier_hash) {
                                        assert(side == .right);

                                        const load = unit.instructions.append_index(.{
                                            .load = .{
                                                .value = left,
                                                .type = pointer.type,
                                            },
                                        });
                                        try builder.appendInstruction(unit, load);

                                        var bit_offset: u32 = 0;
                                        for (fields[0..i]) |fi| {
                                            const f = unit.struct_fields.get(fi);
                                            const f_type = unit.types.get(f.type);
                                            const bit_size = f_type.getBitSize(unit);
                                            bit_offset += bit_size;
                                        }

                                        const instruction_to_truncate = switch (bit_offset) {
                                            0 => load,
                                            else => shl: {
                                                const shl = unit.instructions.append_index(.{
                                                    .integer_binary_operation = .{
                                                        .id = .shift_right,
                                                        .left = .{
                                                            .value = .{
                                                                .runtime = load,
                                                            },
                                                            .type = pointer.type,
                                                        },
                                                        .right = .{
                                                            .value = .{
                                                                .@"comptime" = .{
                                                                    .constant_int = .{
                                                                        .value = bit_offset,
                                                                    },
                                                                },
                                                            },
                                                            .type = pointer.type,
                                                        },
                                                        .signedness = integer.signedness,
                                                    },
                                                });
                                                try builder.appendInstruction(unit, shl);

                                                break :shl shl;
                                            },
                                        };

                                        const f_type = unit.types.get(field.type);
                                        const f_bit_size = f_type.getBitSize(unit);

                                        switch (f_bit_size == integer.bit_count) {
                                            true => {
                                                //instruction_to_truncate,
                                                unreachable;
                                            },
                                            false => {
                                                const truncate = unit.instructions.append_index(.{
                                                    .cast = .{
                                                        .id = .truncate,
                                                        .value = .{
                                                            .value = .{
                                                                .runtime = instruction_to_truncate,
                                                            },
                                                            .type = left.type,
                                                        },
                                                        .type = field.type,
                                                    },
                                                });
                                                try builder.appendInstruction(unit, truncate);
                                                break :b V{
                                                    .value = .{
                                                        .runtime = truncate,
                                                    },
                                                    .type = field.type,
                                                };
                                            },
                                        }
                                        unreachable;
                                    }
                                } else unreachable;
                            },
                            else => |t| @panic(@tagName(t)),
                        },
                        else => |t| @panic(@tagName(t)),
                    },
                    else => |t| @panic(@tagName(t)),
                }
            },
            else => |t| @panic(@tagName(t)),
        };

        switch (type_expect) {
            .none => return result,
            .cast => return result,
            .type => |ti| {
                const typecheck_result = try builder.typecheck(unit, context, ti, result.type);
                switch (typecheck_result) {
                    .success => return result,
                    .pointer_var_to_const => {
                        const cast = unit.instructions.append_index(.{
                            .cast = .{
                                .id = .pointer_var_to_const,
                                .value = result,
                                .type = ti,
                            },
                        });
                        try builder.appendInstruction(unit, cast);

                        return .{
                            .value = .{
                                .runtime = cast,
                            },
                            .type = ti,
                        };
                    },
                    .materialize_int => {
                        const destination_integer_type = unit.types.get(ti).integer;
                        const ct_int = result.value.@"comptime".comptime_int;

                        switch (ct_int.signedness) {
                            .unsigned => {
                                const number_bit_count = @bitSizeOf(@TypeOf(ct_int.value)) - @clz(ct_int.value);
                                if (destination_integer_type.bit_count < number_bit_count) {
                                    unreachable;
                                }
                                return .{
                                    .value = .{
                                        .@"comptime" = .{
                                            .constant_int = .{
                                                .value = ct_int.value,
                                            },
                                        },
                                    },
                                    .type = ti,
                                };
                            },
                            .signed => {
                                if (destination_integer_type.signedness == .unsigned) {
                                    unreachable;
                                } else {
                                    const value = -@as(i64, @intCast(ct_int.value));
                                    return .{
                                        .value = .{
                                            .@"comptime" = .{
                                                .constant_int = .{
                                                    .value = @bitCast(value),
                                                },
                                            },
                                        },
                                        .type = ti,
                                    };
                                }
                            },
                        }
                    },
                    .pointer_to_nullable => {
                        const cast = unit.instructions.append_index(.{
                            .cast = .{
                                .id = .pointer_to_nullable,
                                .value = result,
                                .type = ti,
                            },
                        });
                        try builder.appendInstruction(unit, cast);

                        return .{
                            .value = .{
                                .runtime = cast,
                            },
                            .type = ti,
                        };
                    },
                    .error_to_error_union => {
                        switch (result.value) {
                            .@"comptime" => |ct| switch (ct) {
                                .error_value => {
                                    const struct_index = unit.types.get(ti).@"struct";
                                    const error_union = unit.structs.get(struct_index).kind.error_union;

                                    if (error_union.union_for_error == error_union.abi) {
                                        const v = V{
                                            .value = .{
                                                .@"comptime" = .undefined,
                                            },
                                            .type = ti,
                                        };

                                        const error_union_builder = unit.instructions.append_index(.{
                                            .insert_value = .{
                                                .expression = v,
                                                .index = 0,
                                                .new_value = result,
                                            },
                                        });
                                        try builder.appendInstruction(unit, error_union_builder);

                                        const final_error_union = unit.instructions.append_index(.{
                                            .insert_value = .{
                                                .expression = .{
                                                    .value = .{
                                                        .runtime = error_union_builder,
                                                    },
                                                    .type = ti,
                                                },
                                                .index = 1,
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
                                        try builder.appendInstruction(unit, final_error_union);

                                        return .{
                                            .value = .{
                                                .runtime = final_error_union,
                                            },
                                            .type = ti,
                                        };
                                    } else {
                                        const has_padding = switch (unit.types.get(error_union.union_for_error).*) {
                                            .@"struct" => |si| switch (unit.structs.get(si).kind) {
                                                .abi_compatible_error_union => |eu| eu.padding != .null,
                                                else => |t| @panic(@tagName(t)),
                                            },
                                            else => |t| @panic(@tagName(t)),
                                        };
                                        const v = V{
                                            .value = .{
                                                .@"comptime" = .undefined,
                                            },
                                            .type = error_union.union_for_error,
                                        };

                                        const error_union_builder = unit.instructions.append_index(.{
                                            .insert_value = .{
                                                .expression = v,
                                                .index = 0,
                                                .new_value = result,
                                            },
                                        });
                                        try builder.appendInstruction(unit, error_union_builder);

                                        const final_error_union = unit.instructions.append_index(.{
                                            .insert_value = .{
                                                .expression = .{
                                                    .value = .{
                                                        .runtime = error_union_builder,
                                                    },
                                                    .type = error_union.union_for_error,
                                                },
                                                .index = @as(u32, 1) + @intFromBool(has_padding),
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
                                        try builder.appendInstruction(unit, final_error_union);

                                        const support_alloca = try builder.createStackVariable(unit, context, error_union.union_for_error, null);

                                        const pointer_type = try unit.getPointerType(.{
                                            .type = error_union.union_for_error,
                                            .termination = .none,
                                            .mutability = .@"var",
                                            .many = false,
                                            .nullable = false,
                                        });

                                        const support_store = unit.instructions.append_index(.{
                                            .store = .{
                                                .destination = .{
                                                    .value = .{
                                                        .runtime = support_alloca,
                                                    },
                                                    .type = pointer_type,
                                                },
                                                .source = .{
                                                    .value = .{
                                                        .runtime = final_error_union,
                                                    },
                                                    .type = error_union.union_for_error,
                                                },
                                            },
                                        });
                                        try builder.appendInstruction(unit, support_store);

                                        const support_load = unit.instructions.append_index(.{
                                            .load = .{
                                                .value = .{
                                                    .value = .{
                                                        .runtime = support_alloca,
                                                    },
                                                    .type = pointer_type,
                                                },
                                                .type = ti,
                                            },
                                        });
                                        try builder.appendInstruction(unit, support_load);
                                        return .{
                                            .value = .{
                                                .runtime = support_load,
                                            },
                                            .type = ti,
                                        };
                                    }
                                },
                                else => |t| @panic(@tagName(t)),
                            },
                            else => |t| @panic(@tagName(t)),
                        }
                    },
                    .error_to_all_errors_error_union => return try builder.resolveErrorToAllErrorUnion(unit, context, ti, result),
                    .type_to_error_union => return try builder.resolveTypeToErrorUnion(unit, context, ti, result),
                    .zero_extend => {
                        const zero_extend = unit.instructions.append_index(.{
                            .cast = .{
                                .id = .zero_extend,
                                .value = result,
                                .type = ti,
                            },
                        });
                        try builder.appendInstruction(unit, zero_extend);

                        return .{
                            .value = .{
                                .runtime = zero_extend,
                            },
                            .type = ti,
                        };
                    },
                    else => |t| @panic(@tagName(t)),
                }
            },
            else => unreachable,
        }
    }

    fn resolveIfElse(builder: *Builder, unit: *Unit, context: *const Context, type_expect: Type.Expect, node_index: Node.Index) !V {
        const node = unit.getNode(node_index);
        assert(node.left != .null);
        assert(node.right != .null);

        const if_node_index = node.left;
        const if_node = unit.getNode(if_node_index);
        const condition_node_index = if_node.left;
        const taken_expression_node_index = if_node.right;
        const not_taken_expression_node_index = node.right;
        assert(if_node.id == .@"if");
        try builder.insertDebugCheckPoint(unit, if_node.token);

        const condition = try builder.resolveRuntimeValue(unit, context, Type.Expect{ .type = .bool }, condition_node_index, .right);
        const result: V = switch (condition.value) {
            .@"comptime" => |ct| switch (ct.bool) {
                true => try builder.resolveRuntimeValue(unit, context, type_expect, taken_expression_node_index, .right),
                false => try builder.resolveRuntimeValue(unit, context, type_expect, not_taken_expression_node_index, .right),
            },
            .runtime => |condition_instruction| {
                try builder.resolveBranch(unit, context, type_expect, condition_instruction, taken_expression_node_index, not_taken_expression_node_index, .null, null);
                // TODO WARN SAFETY:
                return V{
                    .value = .{
                        .@"comptime" = .void,
                    },
                    .type = .void,
                };
            },
            else => unreachable,
        };

        return result;
    }

    fn isCurrentFunction(builder: *Builder, unit: *Unit, name: []const u8) bool {
        const hash = unit.code_to_emit.get(builder.current_function).?.declaration.name;
        const identifier = unit.getIdentifier(hash);
        return byte_equal(identifier, name);
    }

    fn emitReturn(builder: *Builder, unit: *Unit, context: *const Context, return_node_index: Node.Index) !void {
        const return_type_index = unit.getReturnType(builder.current_function);
        const return_node = unit.getNode(return_node_index);
        assert(return_node.id == .@"return");
        assert(return_node.right == .null);

        const return_value = if (return_node.left != .null) b: {
            const return_value_node_index = return_node.left;
            const return_value = try builder.resolveRuntimeValue(unit, context, Type.Expect{
                .type = return_type_index,
            }, return_value_node_index, .right);
            break :b return_value;
        } else switch (unit.types.get(return_type_index).*) {
            .@"struct" => |struct_index| switch (unit.structs.get(struct_index).kind) {
                .error_union => |error_union| if (error_union.type == .void) b: {
                    const fields = &[_]V.Comptime{
                        .undefined,
                        .{
                            .bool = false,
                        },
                    };
                    const constant_struct = unit.constant_structs.append_index(.{
                        .fields = fields,
                        .type = return_type_index,
                    });

                    break :b V{
                        .type = return_type_index,
                        .value = .{
                            .@"comptime" = .{
                                .constant_struct = constant_struct,
                            },
                        },
                    };
                } else unreachable,
                else => |t| @panic(@tagName(t)),
            },
            else => |t| @panic(@tagName(t)),
        };

        if (builder.return_block != .null) {
            if (builder.return_phi != .null) {
                const phi = &unit.instructions.get(builder.return_phi).phi;
                phi.addIncoming(return_value, builder.current_basic_block);
            }

            assert(builder.current_basic_block != builder.return_block);

            try builder.jump(unit, builder.return_block);
        } else if (builder.exit_blocks.len > 0) {
            builder.return_phi = unit.instructions.append_index(.{
                .phi = .{
                    .type = return_type_index,
                    .values = try context.arena.new(BoundedArray(Instruction.Phi.Value, Instruction.Phi.max_value_count)),
                },
            });

            builder.return_block = try builder.newBasicBlock(unit);

            const phi = &unit.instructions.get(builder.return_phi).phi;
            phi.addIncoming(return_value, builder.current_basic_block);

            try builder.jump(unit, builder.return_block);
        } else {
            try builder.buildRet(unit, context, return_value);
        }
    }

    fn buildUnreachable(builder: *Builder, unit: *Unit, context: *const Context) !void {
        _ = context; // autofix
        const instruction = unit.instructions.append_index(.@"unreachable");
        try builder.appendInstruction(unit, instruction);
        unit.basic_blocks.get(builder.current_basic_block).terminated = true;
    }

    fn buildTrap(builder: *Builder, unit: *Unit, context: *const Context) !void {
        const instruction = unit.instructions.append_index(.trap);
        try builder.appendInstruction(unit, instruction);

        try builder.buildUnreachable(unit, context);
    }

    fn buildRet(builder: *Builder, unit: *Unit, context: *const Context, value: V) !void {
        const function_definition = unit.function_definitions.get(builder.current_function);
        const function_prototype_index = unit.types.get(function_definition.type).function;
        const function_prototype = unit.function_prototypes.get(function_prototype_index);
        const abi_value = switch (function_prototype.abi.return_type_abi.kind) {
            .direct, .ignore => value,
            .direct_pair => |pair| b: {
                const struct_type_index = try unit.getTwoStruct(pair);
                assert(struct_type_index == function_prototype.abi.return_type);

                if (struct_type_index == value.type) {
                    unreachable;
                } else {
                    const stack = try builder.createStackVariable(unit, context, value.type, null);
                    const pointer_type = try unit.getPointerType(.{
                        .type = value.type,
                        .termination = .none,
                        .mutability = .@"var",
                        .many = false,
                        .nullable = false,
                    });

                    const argument_alloca = V{
                        .value = .{
                            .runtime = stack,
                        },
                        .type = pointer_type,
                    };

                    const store = unit.instructions.append_index(.{
                        .store = .{
                            .destination = .{
                                .value = .{
                                    .runtime = stack,
                                },
                                .type = pointer_type,
                            },
                            .source = value,
                        },
                    });
                    try builder.appendInstruction(unit, store);

                    const target_type = unit.types.get(struct_type_index);
                    const target_size = target_type.getAbiSize(unit);
                    const target_alignment = target_type.getAbiAlignment(unit);
                    // const types = [2]*Type{unit.types.get(pair[0]), unit.types.get(pair[1])};
                    const source_type = unit.types.get(value.type);
                    const source_size = source_type.getAbiSize(unit);
                    const source_alignment = target_type.getAbiAlignment(unit);
                    const target_is_scalable_vector_type = false;
                    const source_is_scalable_vector_type = false;

                    if (source_size >= target_size and !source_is_scalable_vector_type and !target_is_scalable_vector_type) {
                        const load = unit.instructions.append_index(.{
                            .load = .{
                                .value = .{
                                    .value = .{
                                        .runtime = stack,
                                    },
                                    .type = pointer_type,
                                },
                                .type = struct_type_index,
                            },
                        });
                        try builder.appendInstruction(unit, load);

                        break :b V{
                            .value = .{
                                .runtime = load,
                            },
                            .type = struct_type_index,
                        };
                    } else {
                        const alignment = @max(target_alignment, source_alignment);
                        const temporal = try builder.createStackVariable(unit, context, struct_type_index, alignment);
                        const coerced_pointer_type = try unit.getPointerType(.{
                            .type = struct_type_index,
                            .termination = .none,
                            .mutability = .@"var",
                            .many = false,
                            .nullable = false,
                        });
                        const destination = V{
                            .value = .{
                                .runtime = temporal,
                            },
                            .type = coerced_pointer_type,
                        };
                        try builder.emitMemcpy(unit, context, .{
                            .destination = destination,
                            .source = argument_alloca,
                            .destination_alignment = alignment,
                            .source_alignment = source_alignment,
                            .size = source_size,
                            .is_volatile = false,
                        });
                        const load = unit.instructions.append_index(.{
                            .load = .{
                                .value = destination,
                                .type = struct_type_index,
                                .alignment = alignment,
                            },
                        });
                        try builder.appendInstruction(unit, load);

                        break :b V{
                            .value = .{
                                .runtime = load,
                            },
                            .type = struct_type_index,
                        };
                    }
                }
            },
            .indirect => b: {
                assert(function_definition.return_pointer != .null);
                const store = unit.instructions.append_index(.{
                    .store = .{
                        .destination = .{
                            .value = .{
                                .runtime = function_definition.return_pointer,
                            },
                            .type = function_prototype.abi.parameter_types[0],
                        },
                        .source = value,
                    },
                });
                try builder.appendInstruction(unit, store);
                const void_value = V{
                    .value = .{
                        .@"comptime" = .void,
                    },
                    .type = .void,
                };
                break :b void_value;
            },
            .direct_coerce => |coerced_type_index| if (coerced_type_index == value.type) value else b: {
                const stack = try builder.createStackVariable(unit, context, value.type, null);

                const pointer_type = try unit.getPointerType(.{
                    .type = value.type,
                    .termination = .none,
                    .mutability = .@"var",
                    .many = false,
                    .nullable = false,
                });

                const argument_alloca = V{
                    .value = .{
                        .runtime = stack,
                    },
                    .type = pointer_type,
                };

                const store = unit.instructions.append_index(.{
                    .store = .{
                        .destination = argument_alloca,
                        .source = value,
                    },
                });
                try builder.appendInstruction(unit, store);

                const target_type = unit.types.get(coerced_type_index);
                const target_alignment = target_type.getAbiAlignment(unit);
                const target_size = target_type.getAbiSize(unit);
                // const types = [2]*Type{unit.types.get(pair[0]), unit.types.get(pair[1])};
                const source_type = unit.types.get(value.type);
                const source_alignment = source_type.getAbiAlignment(unit);
                const source_size = source_type.getAbiSize(unit);
                const target_is_scalable_vector_type = false;
                const source_is_scalable_vector_type = false;

                if (source_size >= target_size and !source_is_scalable_vector_type and !target_is_scalable_vector_type) {
                    const load = unit.instructions.append_index(.{
                        .load = .{
                            .value = argument_alloca,
                            .type = coerced_type_index,
                        },
                    });
                    try builder.appendInstruction(unit, load);

                    break :b V{
                        .value = .{
                            .runtime = load,
                        },
                        .type = coerced_type_index,
                    };
                } else {
                    const alignment = @max(target_alignment, source_alignment);
                    const temporal = try builder.createStackVariable(unit, context, coerced_type_index, alignment);
                    const coerced_pointer_type = try unit.getPointerType(.{
                        .type = coerced_type_index,
                        .termination = .none,
                        .mutability = .@"var",
                        .many = false,
                        .nullable = false,
                    });
                    const destination = V{
                        .value = .{
                            .runtime = temporal,
                        },
                        .type = coerced_pointer_type,
                    };
                    try builder.emitMemcpy(unit, context, .{
                        .destination = destination,
                        .source = argument_alloca,
                        .destination_alignment = alignment,
                        .source_alignment = source_alignment,
                        .size = source_size,
                        .is_volatile = false,
                    });
                    const load = unit.instructions.append_index(.{
                        .load = .{
                            .value = destination,
                            .type = coerced_type_index,
                            .alignment = alignment,
                        },
                    });
                    try builder.appendInstruction(unit, load);

                    break :b V{
                        .value = .{
                            .runtime = load,
                        },
                        .type = coerced_type_index,
                    };
                }
            },
            else => |t| @panic(@tagName(t)),
        };
        const ret = unit.instructions.append_index(.{
            .ret = abi_value,
        });
        try builder.appendInstruction(unit, ret);
        unit.basic_blocks.get(builder.current_basic_block).terminated = true;
    }

    fn reportCompileError(builder: *Builder, unit: *Unit, context: *const Context, err: Error) noreturn {
        const err_node = unit.getNode(err.node);
        const file = unit.files.get(builder.current_file);
        const token_debug_info = builder.getTokenDebugInfo(unit, err_node.token);
        const line = token_debug_info.line + 1;
        const column = token_debug_info.column + 1;
        const file_path = file.getPath(context.allocator) catch unreachable;
        write(.panic, file_path) catch unreachable;
        write(.panic, ":") catch unreachable;
        Unit.dumpInt(line, 10, false) catch unreachable;
        write(.panic, ":") catch unreachable;
        Unit.dumpInt(column, 10, false) catch unreachable;
        write(.panic, ":\x1b[0m ") catch unreachable;
        write(.panic, err.message) catch unreachable;
        write(.panic, "\n") catch unreachable;
        std.posix.abort();
    }

    fn reportFormattedCompileError(builder: *Builder, unit: *Unit, context: *const Context, node_index: Node.Index, comptime format: []const u8, args: anytype) noreturn {
        _ = context; // autofix
        _ = format; // autofix
        _ = args; // autofix
        const err_node = unit.getNode(node_index);
        const file = unit.files.get(builder.current_file);
        _ = file; // autofix
        const token_debug_info = builder.getTokenDebugInfo(unit, err_node.token);
        _ = token_debug_info; // autofix
        // std.io.getStdOut().writer().print("{s}:{}:{}: \x1b[31merror:\x1b[0m ", .{ file.getPath(context.allocator) catch unreachable, token_debug_info.line + 1, token_debug_info.column + 1 }) catch unreachable;
        // std.io.getStdOut().writer().print(format, args) catch unreachable;
        // std.io.getStdOut().writer().writeByte('\n') catch unreachable;
        std.os.abort();
    }

    fn populateTestFunctions(builder: *Builder, unit: *Unit, context: *const Context) !void {
        _ = builder;
        const builtin_package = try unit.importPackage(context, unit.root_package.dependencies.get("builtin").?);
        const builtin_file_index = builtin_package.file.index;
        const builtin_file = unit.files.get(builtin_file_index);
        const builtin_file_struct_index = unit.types.get(builtin_file.scope.type).@"struct";
        const builtin_file_struct = unit.structs.get(builtin_file_struct_index);
        const test_functions_name = "test_functions";
        const test_functions_name_hash = try unit.processIdentifier(context, test_functions_name);
        const test_functions = builtin_file_struct.kind.@"struct".scope.scope.declarations.get(test_functions_name_hash).?;
        const test_slice_type = test_functions.type;
        const test_type = unit.types.get(test_slice_type).slice.child_type;
        assert(test_functions.kind == .global);
        const test_functions_global: *Debug.Declaration.Global = @fieldParentPtr("declaration", test_functions);
        assert(test_functions_global.declaration.mutability == .@"var");
        const array_type = try unit.getArrayType(.{
            .type = test_type,
            .count = unit.test_functions.values().len,
            .termination = .none,
        });

        const struct_test_type = unit.types.get(test_type);
        const test_type_struct = unit.structs.get(struct_test_type.@"struct");
        const struct_fields = test_type_struct.kind.@"struct".fields;
        assert(struct_fields.len == 2);
        const first_field = unit.struct_fields.get(struct_fields[0]);
        // const second_field = unit.struct_fields.get(test_type_struct.fields.items[1]);

        var list = try context.arena.new_array(V.Comptime, unit.test_functions.length);
        for (unit.test_functions.keys(), unit.test_functions.values(), 0..) |test_function_name_global, test_function_global, i| {
            var fields = try context.arena.new_array(V.Comptime, 2);
            const name = unit.getIdentifier(test_function_name_global.initial_value.string_literal);
            const name_slice = unit.constant_slices.append_index(.{
                .array = test_function_name_global,
                .start = 0,
                .end = name.len,
                .type = first_field.type,
            });
            fields[0] = .{
                .constant_slice = name_slice,
            };
            fields[1] = .{
                .global = test_function_global,
            };
            const constant_struct = unit.constant_structs.append_index(.{
                .fields = fields,
                .type = test_type,
            });

            list[i] = .{
                .constant_struct = constant_struct,
            };
        }

        const constant_array = unit.constant_arrays.append_index(.{
            .type = array_type,
            .values = list,
        });

        const array_name = "_anon_test_function_array";
        const array_name_hash = try unit.processIdentifier(context, array_name);
        const test_function_array_global = unit.global_declarations.append(.{
            .declaration = .{
                .scope = test_functions_global.declaration.scope,
                .type = array_type,
                .name = array_name_hash,
                .line = test_functions_global.declaration.line,
                .column = test_functions_global.declaration.column,
                .mutability = .@"const",
                .kind = .global,
            },
            .initial_value = .{
                .constant_array = constant_array,
            },
            .type_node_index = .null,
            .attributes = .{},
        });
        _ = unit.data_to_emit.append(test_function_array_global);
        const constant_slice = unit.constant_slices.append_index(.{
            .array = test_function_array_global,
            .start = 0,
            .end = list.len,
            .type = test_functions_global.declaration.type,
        });

        test_functions_global.initial_value = .{
            .constant_slice = constant_slice,
        };
    }

    fn build_slice_indexed_access(builder: *Builder, unit: *Unit, context: *const Context, array_like_expression: V, sliceable_type_index: Type.Index, sliceable_pointer_type_index: Type.Index, sliceable_child_type_index: Type.Index, mutability: Mutability, sliceable: Struct.Sliceable, index: V) !V {
        const gep = unit.instructions.append_index(.{
            .get_element_pointer = .{
                .pointer = array_like_expression.value.runtime,
                .base_type = sliceable_type_index,
                .is_struct = true,
                .index = .{
                    .value = .{
                        .@"comptime" = .{
                            .constant_int = .{
                                .value = sliceable.pointer,
                            },
                        },
                    },
                    .type = .u32,
                },
                .name = try unit.processIdentifier(context, "slice_pointer_access"),
            },
        });
        try builder.appendInstruction(unit, gep);

        const pointer_to_slice_pointer = try unit.getPointerType(.{
            .type = sliceable_pointer_type_index,
            .mutability = mutability,
            .termination = .none,
            .many = false,
            .nullable = false,
        });

        const pointer_load = unit.instructions.append_index(.{
            .load = .{
                .value = .{
                    .value = .{
                        .runtime = gep,
                    },
                    .type = pointer_to_slice_pointer,
                },
                .type = sliceable_pointer_type_index,
            },
        });
        try builder.appendInstruction(unit, pointer_load);

        const slice_pointer_gep = unit.instructions.append_index(.{
            .get_element_pointer = .{
                .pointer = pointer_load,
                .base_type = sliceable_child_type_index,
                .is_struct = false,
                .index = index,
                .name = try unit.processIdentifier(context, "indexed_slice_gep"),
            },
        });
        try builder.appendInstruction(unit, slice_pointer_gep);

        return .{
            .value = .{
                .runtime = slice_pointer_gep,
            },
            .type = try unit.getPointerType(.{
                .type = sliceable_child_type_index,
                .mutability = mutability,
                .many = false,
                .nullable = false,
                .termination = .none,
            }),
        };
    }
};

pub const Enum = struct {
    scope: Debug.Scope.Global,
    fields: []const Enum.Field.Index = &.{},

    pub const Field = struct {
        value: usize,
        name: u32,
        parent: Type.Index,

        pub const Index = PinnedArray(@This()).Index;
    };

    pub const Index = PinnedArray(@This()).Index;
};

pub const Unit = struct {
    node_buffer: PinnedArray(Node),
    token_buffer: Token.Buffer,
    node_lists: PinnedArray([]const Node.Index),
    files: PinnedArray(Debug.File),
    types: Type.List,
    structs: PinnedArray(Struct),
    struct_fields: PinnedArray(Struct.Field),
    enum_fields: PinnedArray(Enum.Field),
    function_definitions: PinnedArray(Function.Definition),
    blocks: PinnedArray(Debug.Block),
    global_declarations: PinnedArray(Debug.Declaration.Global),
    local_declarations: PinnedArray(Debug.Declaration.Local),
    argument_declarations: PinnedArray(Debug.Declaration.Argument),
    assembly_instructions: PinnedArray(InlineAssembly.Instruction),
    function_prototypes: PinnedArray(Function.Prototype),
    inline_assembly: PinnedArray(InlineAssembly),
    instructions: PinnedArray(Instruction),
    basic_blocks: PinnedArray(BasicBlock),
    constant_structs: PinnedArray(V.Comptime.ConstantStruct),
    constant_arrays: PinnedArray(V.Comptime.ConstantArray),
    constant_slices: PinnedArray(V.Comptime.ConstantSlice),
    error_fields: PinnedArray(Type.Error.Field),
    file_token_offsets: PinnedHashMap(Token.Range, Debug.File.Index),
    file_map: PinnedHashMap([]const u8, Debug.File.Index),
    identifiers: PinnedHashMap(u32, []const u8),
    string_literal_values: PinnedHashMap(u32, [:0]const u8),
    string_literal_globals: PinnedHashMap(u32, *Debug.Declaration.Global),

    optionals: PinnedHashMap(Type.Index, Type.Index),
    pointers: PinnedHashMap(Type.Pointer, Type.Index),
    slices: PinnedHashMap(Type.Slice, Type.Index),
    arrays: PinnedHashMap(Type.Array, Type.Index),
    integers: PinnedHashMap(Type.Integer, Type.Index),
    error_unions: PinnedHashMap(Type.Error.Union.Descriptor, Type.Index),
    two_structs: PinnedHashMap([2]Type.Index, Type.Index),
    fields_array: PinnedHashMap(Type.Index, *Debug.Declaration.Global),
    name_functions: PinnedHashMap(Type.Index, *Debug.Declaration.Global),

    external_functions: PinnedHashMap(Type.Index, *Debug.Declaration.Global),
    type_declarations: PinnedHashMap(Type.Index, *Debug.Declaration.Global),
    test_functions: PinnedHashMap(*Debug.Declaration.Global, *Debug.Declaration.Global),
    code_to_emit: PinnedHashMap(Function.Definition.Index, *Debug.Declaration.Global),
    data_to_emit: PinnedArray(*Debug.Declaration.Global),
    scope: Debug.Scope.Global = .{
        .scope = .{
            .file = .null,
            .kind = .compilation_unit,
            .line = 0,
            .column = 0,
            .level = 0,
            .local = false,
            .declarations = .{
                .key_pointer = undefined,
                .value_pointer = undefined,
                .length = 0,
                .granularity = 0,
                .committed = 0,
            },
        },
    },
    root_package: *Package = undefined,
    main_package: ?*Package = null,
    all_errors: Type.Index = .null,
    cc_type: Type.Index = .null,
    test_function_type: Type.Index = .null,
    descriptor: Descriptor,
    // object_files: []const linker.Object,
    discard_identifiers: usize = 0,
    anon_i: usize = 0,
    anon_arr: usize = 0,
    error_count: u32 = 0,

    fn dumpInstruction(instruction_index: Instruction.Index) !void {
        try write(.ir, "%");
        try dumpInt(@intFromEnum(instruction_index), 10, false);
    }

    fn dumpInt(value: u64, base: u8, signed: bool) !void {
        var buffer: [65]u8 = undefined;
        const formatted_int = format_int(&buffer, value, base, signed);
        try write(.ir, formatted_int);
    }

    fn dumpBasicBlock(basic_block: BasicBlock.Index) !void {
        try write(.ir, "#");
        try dumpInt(@intFromEnum(basic_block), 10, false);
    }

    fn dumpFunctionDefinition(unit: *Unit, function_definition_index: Function.Definition.Index) !void {
        const function_definition = unit.function_definitions.get(function_definition_index);

        for (function_definition.basic_blocks.slice()) |basic_block_index| {
            const basic_block = unit.basic_blocks.get(basic_block_index);
            try write(.ir, "[");
            try dumpBasicBlock(basic_block_index);
            try write(.ir, "]:\n");

            for (basic_block.instructions.slice()) |instruction_index| {
                const instruction = unit.instructions.get(instruction_index);
                try write(.ir, "    ");
                try dumpInstruction(instruction_index);
                try write(.ir, ": ");
                try write(.ir, @tagName(instruction.*));
                try write(.ir, " ");

                switch (instruction.*) {
                    .call => |call| {
                        switch (call.callable.value) {
                            .@"comptime" => |ct| switch (ct) {
                                .global => |global| {
                                    _ = global; // autofix
                                }, //log(.compilation, .ir, "{s}(", .{unit.getIdentifier(global.declaration.name)}),
                                else => unreachable,
                            },
                            .runtime => |ii| try dumpInstruction(ii),
                            else => |t| @panic(@tagName(t)),
                        }

                        for (call.arguments) |arg| {
                            switch (arg.value) {
                                .@"comptime" => try write(.ir, "comptime"),
                                .runtime => |ii| try dumpInstruction(ii),
                                else => |t| @panic(@tagName(t)),
                            }
                        }

                        try write(.ir, ")");
                    },
                    .insert_value => |insert_value| {
                        try write(.ir, "aggregate ");
                        switch (insert_value.expression.value) {
                            .@"comptime" => try write(.ir, "comptime"),
                            .runtime => |ii| try dumpInstruction(ii),
                            else => unreachable,
                        }

                        try write(.ir, ", ");
                        try dumpInt(insert_value.index, 10, false);
                        try write(.ir, ", ");
                        switch (insert_value.new_value.value) {
                            .@"comptime" => try write(.ir, "comptime"),
                            .runtime => |ii| try dumpInstruction(ii),
                            else => unreachable,
                        }
                    },
                    .extract_value => |extract_value| {
                        try write(.ir, "aggregate ");
                        switch (extract_value.expression.value) {
                            .@"comptime" => try write(.ir, "$comptime"),
                            .runtime => |ii| try dumpInstruction(ii),
                            else => unreachable,
                        }
                        try write(.ir, ", ");
                        try dumpInt(extract_value.index, 10, false);
                    },
                    .get_element_pointer => |gep| {
                        try write(.ir, "aggregate ");
                        try dumpInstruction(gep.pointer);
                        try write(.ir, ", ");
                        switch (gep.index.value) {
                            .@"comptime" => try write(.ir, "$comptime"),
                            .runtime => |ii| try dumpInstruction(ii),
                            else => unreachable,
                        }
                    },
                    .load => |load| {
                        switch (load.value.value) {
                            .@"comptime" => |ct| switch (ct) {
                                .global => |global| try write(.ir, unit.getIdentifier(global.declaration.name)),
                                else => |t| @panic(@tagName(t)),
                            },
                            .runtime => |ii| try dumpInstruction(ii),
                            else => unreachable,
                        }
                    },
                    .push_scope => |push_scope| {
                        try dumpInt(@as(u24, @truncate(@intFromPtr(push_scope.old))), 16, false);
                        try write(.ir, " -> ");
                        try dumpInt(@as(u24, @truncate(@intFromPtr(push_scope.new))), 16, false);
                    },
                    .pop_scope => |pop_scope| {
                        try dumpInt(@as(u24, @truncate(@intFromPtr(pop_scope.new))), 16, false);
                        try write(.ir, " <- ");
                        try dumpInt(@as(u24, @truncate(@intFromPtr(pop_scope.old))), 16, false);
                    },
                    .debug_checkpoint => |checkpoint| {
                        try dumpInt(checkpoint.line, 10, false);
                        try write(.ir, ", ");
                        try dumpInt(checkpoint.column, 10, false);
                    },
                    .debug_declare_argument => |debug_declare| {
                        try write(.ir, "\"");
                        try write(.ir, unit.getIdentifier(debug_declare.argument.declaration.name));
                        try write(.ir, "\"");
                    },
                    .cast => |cast| {
                        try write(.ir, @tagName(cast.id));
                    },
                    .jump => |jump| {
                        try write(.ir, "[#");
                        try dumpInt(@intFromEnum(jump.to), 10, false);
                        try write(.ir, "]");
                    },
                    .branch => |branch| {
                        try dumpInstruction(branch.condition);
                        try write(.ir, ", [");
                        try dumpInt(@intFromEnum(branch.taken), 10, false);
                        try write(.ir, ", ");
                        try dumpInt(@intFromEnum(branch.not_taken), 10, false);
                        try write(.ir, "]");
                    },
                    .phi => |*phi| {
                        for (phi.values.slice()) |v| {
                            const value = v.value;
                            const bb = v.basic_block;
                            try write(.ir, "(");
                            switch (value.value) {
                                .@"comptime" => try write(.ir, "$comptime"),
                                .runtime => |ii| try dumpInstruction(ii),
                                else => |t| @panic(@tagName(t)),
                            }
                            try write(.ir, "#");
                            try dumpInt(@intFromEnum(bb), 10, false);
                            try write(.ir, ")");
                        }
                    },
                    .integer_compare => |compare| {
                        try write(.ir, @tagName(compare.id));
                        try write(.ir, " ");
                        switch (compare.left.value) {
                            .@"comptime" => try write(.ir, "$comptime "),
                            .runtime => |ii| {
                                try dumpInstruction(ii);
                                try write(.ir, ", ");
                            },
                            else => unreachable,
                        }

                        switch (compare.right.value) {
                            .@"comptime" => try write(.ir, "$comptime"),
                            .runtime => |ii| try dumpInstruction(ii),
                            else => unreachable,
                        }
                    },
                    else => {},
                }
                try write(.ir, "\n");
                // logln(.compilation, .ir, "", .{});
            }
        }
    }

    fn getReturnType(unit: *Unit, function_index: Function.Definition.Index) Type.Index {
        const function = unit.function_definitions.get(function_index);
        const function_type = unit.types.get(function.type);
        const function_prototype = unit.function_prototypes.get(function_type.function);
        return function_prototype.return_type;
    }

    fn typecheckSwitchEnums(unit: *Unit, context: *const Context, enum_type: *Enum, switch_case_node_list: []const Node.Index) !TypeCheckSwitchEnums {
        var else_switch_case_group_index: ?usize = null;
        var switch_case_groups = try context.arena.new_array([]const Enum.Field.Index, switch_case_node_list.len);
        switch_case_groups.len = 0;

        var existing_enums = BoundedArray(Enum.Field.Index, 512){};

        for (switch_case_node_list, 0..) |switch_case_node_index, index| {
            const switch_case_node = unit.getNode(switch_case_node_index);

            switch (switch_case_node.left) {
                .null => else_switch_case_group_index = index,
                else => {
                    const switch_case_condition_node = unit.getNode(switch_case_node.left);

                    const switch_case_group = switch (switch_case_condition_node.id) {
                        .dot_literal => b: {
                            if (try unit.typeCheckEnumLiteral(context, @enumFromInt(@intFromEnum(switch_case_condition_node.token) + 1), enum_type)) |enum_field_index| {
                                for (existing_enums.slice()) |existing| {
                                    if (enum_field_index == existing) {
                                        // Duplicate case
                                        unreachable;
                                    }
                                }

                                var switch_case_group = try context.arena.new_array(Enum.Field.Index, 1);
                                switch_case_group[0] = enum_field_index;
                                existing_enums.appendAssumeCapacity(enum_field_index);
                                break :b switch_case_group;
                            } else {
                                unreachable;
                            }
                        },
                        .node_list => b: {
                            const node_list = unit.getNodeListFromNode(switch_case_condition_node);
                            var switch_case_group = try context.arena.new_array(Enum.Field.Index, node_list.len);

                            for (node_list, 0..) |case_condition_node_index, i| {
                                const case_condition_node = unit.getNode(case_condition_node_index);
                                switch (case_condition_node.id) {
                                    .dot_literal => {
                                        if (try unit.typeCheckEnumLiteral(context, @enumFromInt(@intFromEnum(case_condition_node.token) + 1), enum_type)) |enum_field_index| {
                                            for (existing_enums.slice()) |existing| {
                                                if (enum_field_index == existing) {
                                                    // Duplicate case
                                                    unreachable;
                                                }
                                            }

                                            existing_enums.appendAssumeCapacity(enum_field_index);
                                            switch_case_group[i] = enum_field_index;
                                        } else {
                                            unreachable;
                                        }
                                    },
                                    else => |t| @panic(@tagName(t)),
                                }
                            }

                            break :b switch_case_group;
                        },
                        else => |t| @panic(@tagName(t)),
                    };

                    const i = switch_case_groups.len;
                    switch_case_groups.len += 1;
                    switch_case_groups[i] = switch_case_group;
                },
            }
        }

        assert(switch_case_groups.len + @intFromBool(else_switch_case_group_index != null) == switch_case_node_list.len);

        return TypeCheckSwitchEnums{
            .switch_case_groups = switch_case_groups,
            .else_switch_case_group_index = else_switch_case_group_index,
        };
    }

    fn typeCheckEnumLiteral(unit: *Unit, context: *const Context, token_index: Token.Index, enum_type: *Enum) !?Enum.Field.Index {
        const enum_name = unit.getExpectedTokenBytes(token_index, .identifier);
        const enum_name_hash = try unit.processIdentifier(context, enum_name);
        for (enum_type.fields) |enum_field_index| {
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
        const node_list = unit.node_lists.get_unchecked(@intFromEnum(list_index)).*;
        return node_list;
    }

    // TODO: make this fast
    fn findTokenFile(unit: *Unit, token_index: Token.Index) Debug.File.Index {
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
        const token = unit.token_buffer.tokens.get(token_index);
        const file_index = unit.findTokenFile(token_index);
        const file = unit.files.get(file_index);
        if (token.id != expected_id) @panic("Unexpected token");
        const bytes = file.source_code[token.offset..][0..token.length];
        return bytes;
    }

    fn getOptionalType(unit: *Unit, element_type: Type.Index) !Type.Index {
        if (unit.optionals.get(element_type)) |optional| {
            return optional;
        } else {
            const optional_struct_index = unit.structs.append_index(.{
                .kind = .{
                    .optional = element_type,
                },
            });

            const optional_type_index = unit.types.append_index(.{
                .@"struct" = optional_struct_index,
            });

            try unit.optionals.put_no_clobber(element_type, optional_type_index);

            return optional_type_index;
        }
    }

    fn getPointerType(unit: *Unit, pointer: Type.Pointer) !Type.Index {
        if (unit.pointers.get(pointer)) |existing_type_index| {
            return existing_type_index;
        } else {
            const type_index = unit.types.append_index(.{
                .pointer = pointer,
            });
            try unit.pointers.put_no_clobber(pointer, type_index);

            return type_index;
        }
    }

    fn getSliceType(unit: *Unit, slice: Type.Slice) !Type.Index {
        if (unit.slices.get(slice)) |existing_type_index| {
            return existing_type_index;
        } else {
            const type_index = unit.types.append_index(.{
                .slice = slice,
            });
            try unit.slices.put_no_clobber(slice, type_index);

            return type_index;
        }
    }

    fn getArrayType(unit: *Unit, array: Type.Array) !Type.Index {
        if (unit.arrays.get(array)) |array_type| {
            return array_type;
        } else {
            assert(array.count != 0);
            const array_type = unit.types.append_index(.{
                .array = array,
            });
            try unit.arrays.put_no_clobber(array, array_type);

            return array_type;
        }
    }

    pub fn getIntegerType(unit: *Unit, integer: Type.Integer) !Type.Index {
        // if (integer.bit_count > 64) unreachable;
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
                    const type_index = unit.types.append_index(.{
                        .integer = integer,
                    });
                    try unit.integers.put_no_clobber(integer, type_index);
                    return type_index;
                }
            },
        };

        return existing_type_index;
    }

    fn processIdentifier(unit: *Unit, context: *const Context, string: []const u8) !u32 {
        _ = context; // autofix
        const hash = my_hash(string);
        if (unit.identifiers.get_pointer(hash) == null) {
            try unit.identifiers.put_no_clobber(hash, string);
        }
        return hash;
    }

    fn fixupStringLiteral(unit: *Unit, context: *const Context, token_index: Token.Index) ![:0]const u8 {
        const bytes = unit.getExpectedTokenBytes(token_index, .string_literal);
        // Eat double quotes
        const string_literal_bytes = bytes[1..][0 .. bytes.len - 2];
        var i: usize = 0;

        var fixed_string = try context.arena.new_array(u8, string_literal_bytes.len + 1);
        fixed_string.len = 0;

        while (i < string_literal_bytes.len) : (i += 1) {
            const ch = string_literal_bytes[i];
            switch (ch) {
                '\\' => {
                    i += 1;
                    const next_ch = string_literal_bytes[i];
                    switch (next_ch) {
                        'n' => {
                            const index = fixed_string.len;
                            fixed_string.len += 1;
                            fixed_string[index] = '\n';
                        },
                        else => unreachable,
                    }
                },
                else => {
                    const index = fixed_string.len;
                    fixed_string.len += 1;
                    fixed_string[index] = ch;
                },
            }
        }

        const zero_index = fixed_string.len;
        fixed_string.len += 1;
        fixed_string[zero_index] = 0;

        const string = fixed_string[0..zero_index :0];

        return string;
    }

    pub fn getIdentifier(unit: *Unit, hash: u32) []const u8 {
        return unit.identifiers.get(hash).?;
    }

    pub fn analyze(unit: *Unit, context: *const Context) !void {
        const builder = try context.arena.new(Builder);
        builder.* = .{
            .generate_debug_info = unit.descriptor.generate_debug_information,
            .emit_ir = true,
            .current_scope = &unit.scope.scope,
        };

        inline for (@typeInfo(Type.Common).Enum.fields) |enum_field| {
            const e = @field(Type.Common, enum_field.name);
            const type_value = Type.Common.map.get(e);
            _ = unit.types.append(type_value);
        }

        try builder.analyzePackage(unit, context, unit.root_package.dependencies.get("std").?);
        if (unit.descriptor.is_test) {
            try builder.analyzePackage(unit, context, unit.main_package.?);
            const test_function_count = unit.test_functions.keys().len;
            if (test_function_count > 0) {
                try builder.populateTestFunctions(unit, context);
            }
        }

        for (unit.code_to_emit.values()) |function_declaration| {
            const function_definition_index = function_declaration.initial_value.function_definition;
            try write(.ir, "\nFunction #");
            try dumpInt(@intFromEnum(function_definition_index), 16, false);
            try write(.ir, ": ");
            const function_name = unit.getIdentifier(function_declaration.declaration.name);
            try write(.ir, function_name);
            try write(.ir, "\n\n");
            // logln(.compilation, .ir, "Function #{} {s}", .{ Function.Definition.unwrap(function_definition_index),  });

            try unit.dumpFunctionDefinition(function_definition_index);
        }
    }

    pub fn generateAbstractSyntaxTreeForFile(unit: *Unit, context: *const Context, file_index: Debug.File.Index) !void {
        const file = unit.files.get(file_index);
        const source_file = file.package.directory.handle.openFile(file.relative_path, .{}) catch |err| {
            const stdout = std.io.getStdOut();
            try stdout.writeAll("Can't find file ");
            try stdout.writeAll(file.relative_path);
            try stdout.writeAll(" in directory ");
            try stdout.writeAll(file.package.directory.path);
            try stdout.writeAll(" for error ");
            try stdout.writeAll(@errorName(err));
            @panic("Unrecoverable error");
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
        file.lexer = try lexer.analyze(file.source_code, &unit.token_buffer);
        assert(file.status == .loaded_into_memory);
        file.status = .lexed;
        try unit.file_token_offsets.put_no_clobber(.{
            .start = file.lexer.offset,
            .count = file.lexer.count,
        }, file_index);

        file.parser = try parser.analyze(context.arena, file.lexer, file.source_code, &unit.token_buffer, &unit.node_buffer, &unit.node_lists);
        assert(file.status == .lexed);
        file.status = .parsed;
    }

    fn importPackage(unit: *Unit, context: *const Context, package: *Package) !ImportPackageResult {
        const full_path = try package.directory.handle.realpathAlloc(context.allocator, package.source_path); //try std.fs.path.resolve(context.allocator, &.{ package.directory.path, package.source_path });
        // logln(.compilation, .import, "Import full path: {s}\n", .{full_path});
        const import_file = try unit.getFile(full_path, package.source_path, package);

        return .{
            .file = import_file,
            .is_package = true,
        };
    }

    pub fn importFile(unit: *Unit, context: *const Context, current_file_index: Debug.File.Index, import_name: []const u8) !ImportPackageResult {
        // logln(.compilation, .import, "import: '{s}'\n", .{import_name});

        if (byte_equal(import_name, "std")) {
            return unit.importPackage(context, unit.root_package.dependencies.get("std").?);
        }

        if (byte_equal(import_name, "builtin")) {
            return unit.importPackage(context, unit.root_package.dependencies.get("builtin").?);
        }

        if (byte_equal(import_name, "root")) {
            return unit.importPackage(context, unit.root_package);
        }

        const current_file = unit.files.get(current_file_index);
        if (current_file.package.dependencies.get(import_name)) |package| {
            return unit.importPackage(context, package);
        }

        const ends_with_nat = import_name.len >= 4 and @as(u32, @bitCast(import_name[import_name.len - 4 ..][0..4].*)) == @as(u32, @bitCast(@as([*]const u8, ".nat")[0..4].*));
        if (!ends_with_nat) {
            unreachable;
        }

        const current_file_relative_path_to_package_directory = std.fs.path.dirname(current_file.relative_path) orelse "";
        const import_file_relative_path = try joinPath(context, current_file_relative_path_to_package_directory, import_name);
        const full_path = try joinPath(context, current_file.package.directory.path, import_file_relative_path);
        const file_relative_path = import_file_relative_path;
        const package = current_file.package;
        const import_file = try unit.getFile(full_path, file_relative_path, package);
        _ = @intFromPtr(unit.files.get(import_file.index).package);

        const result = ImportPackageResult{
            .file = import_file,
            .is_package = false,
        };

        return result;
    }

    fn getFile(unit: *Unit, full_path: []const u8, relative_path: []const u8, package: *Package) !ImportFileResult {
        if (unit.file_map.get(full_path)) |file_index| {
            return .{
                .index = file_index,
                .is_new = false,
            };
        } else {
            const file_index = unit.files.append_index(Debug.File{
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
                        .declarations = try PinnedHashMap(u32, *Debug.Declaration).init(std.mem.page_size),
                    },
                },
            });
            // logln(.compilation, .new_file, "Adding file #{}: {s}\n", .{ file_index, full_path });

            try unit.file_map.put_no_clobber(full_path, file_index);

            return .{
                .index = file_index,
                .is_new = true,
            };
        }
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
            , .{
                @tagName(unit.descriptor.arch),
                @tagName(unit.descriptor.os),
                @tagName(unit.descriptor.abi),
                unit.descriptor.link_libc,
            });
            if (unit.descriptor.is_test) {
                try builtin_file.writer().writeAll(
                    \\var test_functions: []const builtin.TestFunction = undefined;
                );
            }
            try builtin_file.writer().writeByte('\n');
            builtin_file.close();
        }

        const main_package = blk: {
            const result = try context.arena.new(Package);
            const main_package_absolute_directory_path = b: {
                const relative_path = if (std.fs.path.dirname(unit.descriptor.main_package_path)) |dirname| dirname else ".";
                break :b try context.pathFromCwd(relative_path);
            };
            result.* = .{
                .directory = .{
                    .handle = try std.fs.openDirAbsolute(main_package_absolute_directory_path, .{}),
                    .path = main_package_absolute_directory_path,
                },
                .source_path = try context.arena.duplicate_bytes(std.fs.path.basename(unit.descriptor.main_package_path)),
                .dependencies = try PinnedHashMap([]const u8, *Package).init(std.mem.page_size),
            };
            break :blk result;
        };

        unit.root_package = if (unit.descriptor.is_test) blk: {
            const package = try context.allocator.create(Package);
            const directory_path = try context.pathFromCompiler("lib");
            package.* = .{
                .directory = .{
                    .handle = try std.fs.openDirAbsolute(directory_path, .{}),
                    .path = directory_path,
                },
                .source_path = "test_runner.nat",
                .dependencies = try PinnedHashMap([]const u8, *Package).init(std.mem.page_size),
            };
            unit.main_package = main_package;

            break :blk package;
        } else main_package;
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
                .dependencies = try PinnedHashMap([]const u8, *Package).init(std.mem.page_size),
            };

            try unit.root_package.addDependency(package_descriptor.name, package);

            package_ptr.* = package;
        }

        assert(unit.root_package.dependencies.length == 2);

        if (!unit.descriptor.only_parse) {
            _ = try unit.importPackage(context, unit.root_package.dependencies.get("std").?);
            if (unit.descriptor.is_test) {
                _ = try unit.importPackage(context, unit.main_package.?);
            }
        } else {
            _ = try unit.importPackage(context, unit.root_package);
        }

        for (unit.file_map.values()) |import| {
            try unit.generateAbstractSyntaxTreeForFile(context, import);
        }

        if (!unit.descriptor.only_parse) {
            var object_files = try context.arena.new_array(linker.Object, unit.descriptor.c_source_files.len + 1);
            object_files[0] = .{
                .path = unit.descriptor.object_path,
            };
            object_files.len = 1;

            for (unit.descriptor.c_source_files) |c_source_file| {
                const dot_index = last_byte(c_source_file, '.') orelse unreachable;
                const path_without_extension = c_source_file[0..dot_index];
                const basename = std.fs.path.basename(path_without_extension);
                const o_file = try std.mem.concat(context.allocator, u8, &.{ basename, ".o" });
                const object_path = try std.mem.concat(context.allocator, u8, &.{
                    "nat/",
                    o_file,
                });

                var arguments = [_][]const u8{ "-c", c_source_file, "-o", object_path, "-g", "-fno-stack-protector" };
                try compileCSourceFile(context, &arguments, .c);
                const index = object_files.len;
                object_files.len += 1;
                object_files[index] = .{
                    .path = object_path,
                };
            }

            try unit.analyze(context);

            try llvm.codegen(unit, context);

            try linker.link(context, .{
                .output_file_path = unit.descriptor.executable_path,
                .objects = object_files,
                .libraries = &.{},
                .link_libc = unit.descriptor.link_libc,
                .link_libcpp = false,
                .extra_arguments = &.{},
            });
        }
    }

    fn getTwoStruct(unit: *Unit, types: [2]Type.Index) !Type.Index {
        if (unit.two_structs.get(types)) |result| return result else {
            const two_struct = unit.structs.append_index(.{
                .kind = .{
                    .two_struct = types,
                },
            });
            const type_index = unit.types.append_index(.{
                .@"struct" = two_struct,
            });

            try unit.two_structs.put_no_clobber(types, type_index);

            return type_index;
        }
    }

    fn resolve_character_literal(unit: *Unit, node_index: Node.Index) !V.Comptime {
        const node = unit.getNode(node_index);
        const ch_literal = unit.getExpectedTokenBytes(node.token, .character_literal);
        const character: u8 = switch (ch_literal.len) {
            3 => ch_literal[1],
            // This has a escape character
            4 => switch (ch_literal[2]) {
                'n' => '\n',
                'r' => '\r',
                't' => '\t',
                else => unreachable,
            },
            else => unreachable,
        };

        return V.Comptime{
            .constant_int = .{
                .value = character,
            },
        };
    }
};

pub const FixedKeyword = enum { @"comptime", @"const", @"var", void, noreturn, @"while", bool, true, false, @"fn", @"unreachable", @"return", ssize, usize, @"switch", @"if", @"else", @"struct", @"enum", null, @"align", @"for", undefined, @"break", @"test", @"catch", @"try", @"orelse", @"error", @"and", @"or", bitfield, Self, any, type, @"continue" };

pub const Descriptor = struct {
    main_package_path: []const u8,
    executable_path: []const u8,
    object_path: []const u8,
    arch: Arch,
    os: Os,
    abi: Abi,
    optimization: Optimization,
    only_parse: bool,
    link_libc: bool,
    link_libcpp: bool,
    is_test: bool,
    generate_debug_information: bool,
    c_source_files: []const []const u8,
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
        .test_declaration => .test_declaration,
        else => |t| @panic(@tagName(t)),
    };
}

const MemberType = enum {
    declaration,
    field,
    comptime_block,
    test_declaration,
};

pub const Token = struct {
    line: u32,
    offset: u32,
    length: u32,
    id: Token.Id,

    pub const Buffer = struct {
        line_offsets: PinnedArray(u32) = .{},
        tokens: PinnedArray(Token) = .{},
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
        operator_double_dot,
        operator_triple_dot,
        operator_colon,
        operator_bang,
        operator_optional,
        operator_dollar,
        operator_switch_case,
        operator_backtick,
        operator_tilde,
        // Binary
        operator_assign,
        operator_add,
        operator_saturated_add,
        operator_wrapping_add,
        operator_minus,
        operator_saturated_sub,
        operator_wrapping_sub,
        operator_asterisk,
        operator_saturated_mul,
        operator_wrapping_mul,
        operator_div,
        operator_mod,
        operator_bar,
        operator_ampersand,
        operator_xor,
        operator_shift_left,
        operator_shift_right,
        operator_add_assign,
        operator_wrapping_add_assign,
        operator_saturated_add_assign,
        operator_sub_assign,
        operator_wrapping_sub_assign,
        operator_saturated_sub_assign,
        operator_mul_assign,
        operator_wrapping_mul_assign,
        operator_saturated_mul_assign,
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
        fixed_keyword_test,
        fixed_keyword_try,
        fixed_keyword_catch,
        fixed_keyword_orelse,
        fixed_keyword_error,
        fixed_keyword_and,
        fixed_keyword_or,
        fixed_keyword_bitfield,
        fixed_keyword_Self,
        fixed_keyword_any,
        fixed_keyword_type,
        fixed_keyword_continue,

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

    pub const Index = PinnedArray(Token).Index;

    pub const Range = struct {
        start: Token.Index,
        count: u32,
    };
};

pub const InlineAssembly = struct {
    instructions: []const InlineAssembly.Instruction.Index,

    pub const Index = PinnedArray(@This()).Index;

    pub const Instruction = struct {
        id: u32,
        operands: []const Operand,

        pub const Index = PinnedArray(@This()).Index;
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

    pub const aarch64 = struct {
        pub const Instruction = enum {
            b,
            mov,
        };

        pub const Register = enum {
            fp,
            lr,
            sp,
            x0,
            x1,
            x2,
            x3,
            x4,
            x5,
            x6,
            x7,
            x8,
            x9,
            x10,
            x11,
            x12,
            x13,
            x14,
            x15,
            x16,
            x17,
            x18,
            x19,
            x20,
            x21,
            x22,
            x23,
            x24,
            x25,
            x26,
            x27,
            x28,
            x29,
            x30,
            x31,
        };
    };
};

const LogKind = enum {
    parser,
    ir,
    llvm,
    panic,
};

const should_log_map = std.EnumSet(LogKind).initMany(&.{
    // .parser,
    //.ir,
    //.llvm,
    .panic,
});

pub fn write(kind: LogKind, string: []const u8) !void {
    if (should_log_map.contains(kind)) {
        try std.io.getStdOut().writeAll(string);
    }
}
