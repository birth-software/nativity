const std = @import("std");
const assert = std.debug.assert;
const linker = @import("linker.zig");

const library = @import("../library.zig");
const PinnedArray = library.PinnedArray;

const Compilation = @import("../Compilation.zig");
const write = Compilation.write;

pub fn link(context: *const Compilation.Context, options: linker.Options) !void {
    assert(options.backend == .lld);
    var argv = try PinnedArray([]const u8).init_with_default_granularity();
    const driver_program = switch (@import("builtin").os.tag) {
        .windows => "lld-link",
        .linux => "ld.lld",
        .macos => "ld64.lld",
        else => @compileError("OS not supported"),
    };
    _ = argv.append(driver_program);
    _ = argv.append("--error-limit=0");

    switch (@import("builtin").cpu.arch) {
        .aarch64 => switch (@import("builtin").os.tag) {
            .linux => {
                _ = argv.append("-znow");
                _ = argv.append_slice(&.{ "-m", "aarch64linux" });
            },
            else => {},
        },
        else => {},
    }

    // const output_path = out_path orelse "a.out";
    _ = argv.append("-o");
    _ = argv.append(options.output_file_path);

    argv.append_slice(options.extra_arguments);

    for (options.objects) |object| {
        _ = argv.append(object.path);
    }

    const ci = @import("configuration").ci;
    switch (@import("builtin").os.tag) {
        .macos => {
            _ = argv.append("-dynamic");
            argv.append_slice(&.{ "-platform_version", "macos", "13.4.1", "13.3" });
            _ = argv.append("-arch");
            _ = argv.append(switch (@import("builtin").cpu.arch) {
                .aarch64 => "arm64",
                else => |t| @panic(@tagName(t)),
            });

            argv.append_slice(&.{ "-syslibroot", "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk" });

            if (!library.ends_with_slice(options.output_file_path, ".dylib")) {
                argv.append_slice(&.{ "-e", "_main" });
            }

            _ = argv.append("-lSystem");

            if (options.link_libcpp) {
                _ = argv.append("-L/Library/Developer/CommandLineTools/SDKs/MacOSX13.3.sdk/usr/lib");
                _ = argv.append("-lc++");
            }
        },
        .linux => {
            if (ci) {
                if (options.link_libcpp) {
                    assert(options.link_libc);
                    _ = argv.append("/lib/x86_64-linux-gnu/libstdc++.so.6");
                }

                if (options.link_libc) {
                    _ = argv.append("/lib/x86_64-linux-gnu/crt1.o");
                    _ = argv.append("/lib/x86_64-linux-gnu/crti.o");
                    argv.append_slice(&.{ "-L", "/lib/x86_64-linux-gnu" });
                    argv.append_slice(&.{ "-dynamic-linker", "/lib64/ld-linux-x86-64.so.2" });
                    _ = argv.append("--as-needed");
                    _ = argv.append("-lm");
                    _ = argv.append("-lpthread");
                    _ = argv.append("-lc");
                    _ = argv.append("-ldl");
                    _ = argv.append("-lrt");
                    _ = argv.append("-lutil");
                    _ = argv.append("/lib/x86_64-linux-gnu/crtn.o");
                }
            } else {
                if (options.link_libcpp) {
                    assert(options.link_libc);
                    _ = argv.append("/usr/lib64/libstdc++.so.6");
                }

                if (options.link_libc) {
                    _ = argv.append("/usr/lib64/crt1.o");
                    _ = argv.append("/usr/lib64/crti.o");
                    argv.append_slice(&.{ "-L", "/usr/lib64" });

                    _ = argv.append("-dynamic-linker");
                    switch (@import("builtin").cpu.arch) {
                        .x86_64 => _ = argv.append("/lib64/ld-linux-x86-64.so.2"),
                        .aarch64 => _ = argv.append("/lib/ld-linux-aarch64.so.1"),
                        else => unreachable,
                    }

                    _ = argv.append("--as-needed");
                    _ = argv.append("-lm");
                    _ = argv.append("-lpthread");
                    _ = argv.append("-lc");
                    _ = argv.append("-ldl");
                    _ = argv.append("-lrt");
                    _ = argv.append("-lutil");

                    _ = argv.append("/usr/lib64/crtn.o");
                }
            }
        },
        .windows => {},
        else => @compileError("OS not supported"),
    }

    for (options.libraries) |lib| {
        _ = argv.append(try context.arena.join(&.{ "-l", lib.path }));
    }

    const argv_zero_terminated = try Compilation.argsCopyZ(context.arena, argv.const_slice());

    var stdout_ptr: [*]const u8 = undefined;
    var stdout_len: usize = 0;
    var stderr_ptr: [*]const u8 = undefined;
    var stderr_len: usize = 0;
    const result = switch (@import("builtin").os.tag) {
        .linux => NativityLLDLinkELF(argv_zero_terminated.ptr, argv_zero_terminated.len, &stdout_ptr, &stdout_len, &stderr_ptr, &stderr_len),
        .macos => NativityLLDLinkMachO(argv_zero_terminated.ptr, argv_zero_terminated.len, &stdout_ptr, &stdout_len, &stderr_ptr, &stderr_len),
        .windows => NativityLLDLinkCOFF(argv_zero_terminated.ptr, argv_zero_terminated.len, &stdout_ptr, &stdout_len, &stderr_ptr, &stderr_len),
        else => @compileError("OS not supported"),
    };

    if (!result) {
        const stdout = stdout_ptr[0..stdout_len];
        const stderr = stderr_ptr[0..stderr_len];
        for (argv.const_slice()) |arg| {
            try write(.panic, arg);
            try write(.panic, " ");
        }
        try write(.panic, "\n");
        if (stdout.len > 0) {
            try write(.panic, stdout);
            try write(.panic, "\n");
        }

        if (stderr.len > 0) {
            try write(.panic, stderr);
            try write(.panic, "\n");
        }

        @panic("Linking with LLD failed");
    }
}

extern fn NativityLLDLinkELF(argument_ptr: [*:null]?[*:0]u8, argument_count: usize, stdout_ptr: *[*]const u8, stdout_len: *usize, stderr_ptr: *[*]const u8, stderr_len: *usize) bool;
extern fn NativityLLDLinkCOFF(argument_ptr: [*:null]?[*:0]u8, argument_count: usize, stdout_ptr: *[*]const u8, stdout_len: *usize, stderr_ptr: *[*]const u8, stderr_len: *usize) bool;
extern fn NativityLLDLinkMachO(argument_ptr: [*:null]?[*:0]u8, argument_count: usize, stdout_ptr: *[*]const u8, stdout_len: *usize, stderr_ptr: *[*]const u8, stderr_len: *usize) bool;
extern fn NativityLLDLinkWasm(argument_ptr: [*:null]?[*:0]u8, argument_count: usize, stdout_ptr: *[*]const u8, stdout_len: *usize, stderr_ptr: *[*]const u8, stderr_len: *usize) bool;
