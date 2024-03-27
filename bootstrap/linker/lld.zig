const std = @import("std");
const assert = std.debug.assert;
const linker = @import("linker.zig");

const library = @import("../library.zig");
const UnpinnedArray = library.UnpinnedArray;

const Compilation = @import("../Compilation.zig");
const write = Compilation.write;

pub fn link(context: *const Compilation.Context, options: linker.Options) !void {
    assert(options.backend == .lld);
    var argv = UnpinnedArray([]const u8){};
    const driver_program = switch (@import("builtin").os.tag) {
        .windows => "lld-link",
        .linux => "ld.lld",
        .macos => "ld64.lld",
        else => @compileError("OS not supported"),
    };
    try argv.append(context.my_allocator, driver_program);
    try argv.append(context.my_allocator, "--error-limit=0");

    // const output_path = out_path orelse "a.out";
    try argv.append(context.my_allocator, "-o");
    const is_dylib = library.ends_with_slice(options.output_file_path, ".dylib");
    try argv.append(context.my_allocator, options.output_file_path);
    if (library.byte_equal(options.output_file_path, "lib/LLVMHello.dylib")) {
        assert(is_dylib);
    }

    try argv.append_slice(context.my_allocator, options.extra_arguments);

    for (options.objects) |object| {
        try argv.append(context.my_allocator, object.path);
    }

    switch (@import("builtin").os.tag) {
        .macos => {
            try argv.append(context.my_allocator, "-dynamic");
            try argv.append_slice(context.my_allocator, &.{ "-platform_version", "macos", "13.4.1", "13.3" });
            try argv.append(context.my_allocator, "-arch");
            try argv.append(context.my_allocator, switch (@import("builtin").cpu.arch) {
                .aarch64 => "arm64",
                else => |t| @panic(@tagName(t)),
            });
            try argv.append_slice(context.my_allocator, &.{ "-syslibroot", "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk" });

            if (!library.ends_with_slice(options.output_file_path, ".dylib")) {
                try argv.append_slice(context.my_allocator, &.{ "-e", "_main" });
            }

            try argv.append(context.my_allocator, "-lSystem");

            if (options.link_libcpp) {
                try argv.append(context.my_allocator, "-L/Library/Developer/CommandLineTools/SDKs/MacOSX13.3.sdk/usr/lib");
                try argv.append(context.my_allocator, "-lc++");
            }
        },
        .linux => {
            if (options.link_libcpp) {
                assert(options.link_libc);
                try argv.append(context.my_allocator, "/usr/lib/libstdc++.so" );
            }

            if (options.link_libc) {
                try argv.append(context.my_allocator, "/usr/lib/crt1.o");
                try argv.append(context.my_allocator, "/usr/lib/crti.o");
                try argv.append_slice(context.my_allocator, &.{ "-L", "/usr/lib" });
                try argv.append_slice(context.my_allocator, &.{ "-dynamic-linker", "/lib64/ld-linux-x86-64.so.2" });
                try argv.append(context.my_allocator, "--as-needed");
                try argv.append(context.my_allocator, "-lm");
                try argv.append(context.my_allocator, "-lpthread");
                try argv.append(context.my_allocator, "-lc");
                try argv.append(context.my_allocator, "-ldl");
                try argv.append(context.my_allocator, "-lrt");
                try argv.append(context.my_allocator, "-lutil");
                try argv.append(context.my_allocator, "/usr/lib/crtn.o");
            }
        },
        else => @compileError("OS not supported"),
    }


    for (options.libraries) |lib| {
        try argv.append(context.my_allocator, try std.mem.concat(context.allocator, u8, &.{"-l", lib.path}));
    }

    const argv_zero_terminated = try Compilation.argsCopyZ(context.allocator, argv.slice());

    var stdout_ptr: [*]const u8 = undefined;
    var stdout_len: usize = 0;
    var stderr_ptr: [*]const u8 = undefined;
    var stderr_len: usize = 0;
    const result = switch (@import("builtin").os.tag) {
        .linux => NativityLLDLinkELF   (argv_zero_terminated.ptr, argv_zero_terminated.len, &stdout_ptr, &stdout_len, &stderr_ptr, &stderr_len),
        .macos => NativityLLDLinkMachO (argv_zero_terminated.ptr, argv_zero_terminated.len, &stdout_ptr, &stdout_len, &stderr_ptr, &stderr_len),
        .windows => NativityLLDLinkCOFF(argv_zero_terminated.ptr, argv_zero_terminated.len, &stdout_ptr, &stdout_len, &stderr_ptr, &stderr_len),
        else => @compileError("OS not supported"),
    };

    if (!result) {
        const stdout = stdout_ptr[0..stdout_len];
        const stderr = stderr_ptr[0..stderr_len];
        for (argv.slice()) |arg| {
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
