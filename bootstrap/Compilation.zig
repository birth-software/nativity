const std = @import("std");

const Allocator = std.mem.Allocator;

const data_structures = @import("library.zig");
const assert = data_structures.assert;
const byte_equal = data_structures.byte_equal;
const byte_equal_terminated = data_structures.byte_equal_terminated;
const UnpinnedArray = data_structures.UnpinnedArray;
const BlockList = data_structures.BlockList;
const MyAllocator = data_structures.MyAllocator;
const MyHashMap = data_structures.MyHashMap;
const span = data_structures.span;

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
    std.io.getStdOut().writeAll("Unterminated argument: ") catch {};
    @panic(string);
}

const Error = struct {
    message: []const u8,
    node: Node.Index,
};

pub fn createContext(allocator: Allocator, my_allocator: *MyAllocator) !*const Context {
    const context: *Context = try allocator.create(Context);

    const self_exe_path = try std.fs.selfExePathAlloc(allocator);
    const self_exe_dir_path = std.fs.path.dirname(self_exe_path).?;
    context.* = .{
        .allocator = allocator,
        .my_allocator = my_allocator,
        .cwd_absolute_path = try realpathAlloc(allocator, "."),
        .executable_absolute_path = self_exe_path,
        .directory_absolute_path = self_exe_dir_path,
        .build_directory = try std.fs.cwd().makeOpenPath("nat", .{}),
    };

    try context.build_directory.makePath(cache_dir_name);
    try context.build_directory.makePath(installation_dir_name);

    return context;
}

pub fn compileBuildExecutable(context: *const Context, arguments: [][*:0]u8) !void {
    _ = arguments; // autofix
    const unit = try context.my_allocator.allocate_one(Unit);
    // const target_query = try std.Target.Query.parse(.{});
    // const target = try std.zig.system.resolveTargetQuery(target_query);
    unit.* = .{
        .descriptor = .{
            .main_package_path = "build.nat",
            .arch = switch (@import("builtin").cpu.arch) {
                .x86_64 => .x86_64,
                .aarch64 => .aarch64,
                else => |t| @panic(@tagName(t)),
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
            .only_parse = false,
            .executable_path = "nat/build",
            .link_libc = @import("builtin").os.tag == .macos,
            .generate_debug_information = true,
            .name = "build",
            .is_test = false,
        },
    };

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
        // std.debug.print("The following command terminated with failure ({s}): {s}\n", .{ @tagName(result.term), argv });
        // if (result.stdout.len > 0) {
        //     std.debug.print("STDOUT:\n{s}\n", .{result.stdout});
        // }
        // if (result.stderr.len > 0) {
        //     std.debug.print("STDOUT:\n{s}\n", .{result.stderr});
        // }
        std.os.abort();
    }
}

fn clang_job(arguments: []const []const u8) !void {
    const exit_code = try clangMain(std.heap.page_allocator, arguments);
    if (exit_code != 0) unreachable;
}

pub fn compileCSourceFile(context: *const Context, arguments: [][*:0]u8) !void {
    assert(arguments.len > 0);
    if (byte_equal_terminated(arguments[0], "-c")) {
        unreachable;
    } else {
        const arch_include_path = "lib/libc/musl/arch/x86_64";
        const arch_generic_include_path = "lib/libc/musl/arch/generic";
        const src_include_path = "lib/libc/musl/src/include";
        const src_internal_path = "lib/libc/musl/src/internal";
        const include_path = "lib/libc/musl/include";
        const triple_include_path = "lib/libc/include/x86_64-linux-musl";
        const generic_include_path = "lib/libc/include/generic-musl";

        if (std.fs.cwd().makeDir("nat/musl")) {
            var buffer: [65]u8 = undefined;
            const out_dir = "nat/musl/";
            var ar_args = try UnpinnedArray([]const u8).initialize_with_capacity(context.my_allocator, @intCast(generic_musl_source_files.len + musl_x86_64_source_files.len + 3));
            ar_args.append_with_capacity("ar");
            ar_args.append_with_capacity("rcs");
            ar_args.append_with_capacity(out_dir ++ "libc.a");

            for (generic_musl_source_files) |src_file| {
                const src_file_path = try std.mem.concat(context.allocator, u8, &.{"lib/libc/musl/", src_file});
                const basename = std.fs.path.basename(src_file);
                const target = try context.allocator.dupe(u8, basename);
                target[target.len - 1] = 'o';
                const hash = data_structures.my_hash(src_file);
                const hash_string = data_structures.format_int(&buffer, hash, 16, false);
                const target_path = try std.mem.concat(context.allocator, u8, &.{out_dir, hash_string, target});
                const args: []const []const u8 = &.{ context.executable_absolute_path, "--no-default-config", "-fno-caret-diagnostics", "-target", "x86_64-unknown-linux-musl",  "-std=c99", "-ffreestanding", "-mred-zone", "-fno-omit-frame-pointer", "-fno-stack-protector", "-O2", "-fno-unwind-tables", "-fno-asynchronous-unwind-tables", "-ffunction-sections", "-fdata-sections", "-gdwarf-4", "-gdwarf32", "-Wa,--noexecstack", "-D_XOPEN_SOURCE=700",
                    "-I", arch_include_path,
                    "-I", arch_generic_include_path,
                    "-I", src_include_path,
                    "-I", src_internal_path,
                    "-I", include_path,
                    "-I", triple_include_path,
                    "-I", generic_include_path,
                    "-c", src_file_path,
                    "-o", target_path,
                };
                const exit_code = try clangMain(context.allocator, args);
                if (exit_code != 0) unreachable;

                ar_args.append_with_capacity(target_path);
            }

            for (musl_x86_64_source_files) |src_file| {
                const src_file_path = try std.mem.concat(context.allocator, u8, &.{"lib/libc/musl/", src_file});
                const basename = std.fs.path.basename(src_file);
                const target = try context.allocator.dupe(u8, basename);
                target[target.len - 1] = 'o';
                const hash = data_structures.my_hash(src_file);
                const hash_string = data_structures.format_int(&buffer, hash, 16, false);
                const target_path = try std.mem.concat(context.allocator, u8, &.{out_dir, hash_string, target});
                const args: []const []const u8 = &.{ context.executable_absolute_path, "--no-default-config", "-fno-caret-diagnostics", "-target", "x86_64-unknown-linux-musl",  "-std=c99", "-ffreestanding", "-mred-zone", "-fno-omit-frame-pointer", "-fno-stack-protector", "-O2", "-fno-unwind-tables", "-fno-asynchronous-unwind-tables", "-ffunction-sections", "-fdata-sections", "-gdwarf-4", "-gdwarf32", "-Wa,--noexecstack", "-D_XOPEN_SOURCE=700",
                    "-I", arch_include_path,
                    "-I", arch_generic_include_path,
                    "-I", src_include_path,
                    "-I", src_internal_path,
                    "-I", include_path,
                    "-I", triple_include_path,
                    "-I", generic_include_path,
                    "-c", src_file_path,
                    "-o", target_path,
                };
                const exit_code = try clangMain(context.allocator, args);
                if (exit_code != 0) unreachable;
                ar_args.append_with_capacity(target_path);
            }

            if (try arMain(context.allocator, ar_args.slice()) != 0) {
                unreachable;
            }
        } else |e| {
            e catch {};
        }

        const crt1_output_path = "nat/musl/crt1.o";
        {
            const crt_path = "lib/libc/musl/crt/crt1.c";
            const args: []const []const u8 = &.{ context.executable_absolute_path, "--no-default-config", "-fno-caret-diagnostics", "-target", "x86_64-unknown-linux-musl",  "-std=c99", "-ffreestanding", "-mred-zone", "-fno-omit-frame-pointer", "-fno-stack-protector", "-O2", "-fno-unwind-tables", "-fno-asynchronous-unwind-tables", "-ffunction-sections", "-fdata-sections", "-gdwarf-4", "-gdwarf32", "-Wa,--noexecstack", "-D_XOPEN_SOURCE=700", "-DCRT",
                "-I", arch_include_path,
                "-I", arch_generic_include_path,
                "-I", src_include_path,
                "-I", src_internal_path,
                "-I", include_path,
                "-I", triple_include_path,
                "-I", generic_include_path,
                "-c", crt_path,
                "-o", crt1_output_path,
            };
            const exit_code = try clangMain(context.allocator, args);
            if (exit_code != 0) {
                unreachable;
            }
        }

        const crti_output_path = "nat/musl/crti.o";
        {
            const crt_path = "lib/libc/musl/crt/x86_64/crti.s";
            const args: []const []const u8 = &.{ context.executable_absolute_path, "--no-default-config", "-fno-caret-diagnostics", "-target", "x86_64-unknown-linux-musl",  "-std=c99", "-ffreestanding", "-mred-zone", "-fno-omit-frame-pointer", "-fno-stack-protector", "-O2", "-fno-unwind-tables", "-fno-asynchronous-unwind-tables", "-ffunction-sections", "-fdata-sections", "-gdwarf-4", "-gdwarf32", "-Wa,--noexecstack", "-D_XOPEN_SOURCE=700",
                "-I", arch_include_path,
                "-I", arch_generic_include_path,
                "-I", src_include_path,
                "-I", src_internal_path,
                "-I", include_path,
                "-I", triple_include_path,
                "-I", generic_include_path,
                "-c", crt_path,
                "-o", crti_output_path,
            };
            const exit_code = try clangMain(context.allocator, args);
            if (exit_code != 0) {
                unreachable;
            }
        }

        const crtn_output_path = "nat/musl/crtn.o";
        {
            const crt_path = "lib/libc/musl/crt/x86_64/crtn.s";
            const args: []const []const u8 = &.{ context.executable_absolute_path, "--no-default-config", "-fno-caret-diagnostics", "-target", "x86_64-unknown-linux-musl",  "-std=c99", "-ffreestanding", "-mred-zone", "-fno-omit-frame-pointer", "-fno-stack-protector", "-O2", "-fno-unwind-tables", "-fno-asynchronous-unwind-tables", "-ffunction-sections", "-fdata-sections", "-gdwarf-4", "-gdwarf32", "-Wa,--noexecstack", "-D_XOPEN_SOURCE=700", 
                "-I", arch_include_path,
                "-I", arch_generic_include_path,
                "-I", src_include_path,
                "-I", src_internal_path,
                "-I", include_path,
                "-I", triple_include_path,
                "-I", generic_include_path,
                "-c", crt_path,
                "-o", crtn_output_path,
            };
            const exit_code = try clangMain(context.allocator, args);
            if (exit_code != 0) {
                unreachable;
            }
        }

        assert(arguments.len == 1);
        const argument = span(arguments[0]);

        const output_object_file = "nat/main.o";
        const exit_code = try clangMain(context.allocator, &.{ context.executable_absolute_path, "--no-default-config", "-target", "x86_64-unknown-linux-musl", "-nostdinc", "-fno-spell-checking", 
            "-isystem", "lib/include",
            "-isystem", "lib/libc/include/x86_64-linux-musl",
            "-isystem", "lib/libc/include/generic-musl",
            "-isystem", "lib/libc/include/x86-linux-any",
            "-isystem", "lib/libc/include/any-linux-any",
            "-c", argument, "-o", output_object_file});
        if (exit_code != 0) {
            unreachable;
        }

        var lld_args = UnpinnedArray([*:0]const u8){};
        try lld_args.append(context.my_allocator, "ld.lld");
        try lld_args.append(context.my_allocator, "--error-limit=0");
        try lld_args.append(context.my_allocator, "--entry");
        try lld_args.append(context.my_allocator, "_start");
        try lld_args.append(context.my_allocator, "-z");
        try lld_args.append(context.my_allocator, "stack-size=16777216");
        try lld_args.append(context.my_allocator, "--image-base=16777216");
        try lld_args.append(context.my_allocator, "-m");
        try lld_args.append(context.my_allocator, "elf_x86_64");
        try lld_args.append(context.my_allocator, "-static");
        try lld_args.append(context.my_allocator, "-o");
        try lld_args.append(context.my_allocator, "nat/main");
        try lld_args.append(context.my_allocator, crt1_output_path);
        try lld_args.append(context.my_allocator, crti_output_path);
        try lld_args.append(context.my_allocator, output_object_file);
        try lld_args.append(context.my_allocator, "--as-needed");
        try lld_args.append(context.my_allocator, "nat/musl/libc.a");
        try lld_args.append(context.my_allocator, crtn_output_path);

        var stdout_ptr: [*]const u8 = undefined;
        var stdout_len: usize = 0;
        var stderr_ptr: [*]const u8 = undefined;
        var stderr_len: usize = 0;
        const result = llvm.bindings.NativityLLDLinkELF(lld_args.pointer, lld_args.length, &stdout_ptr, &stdout_len, &stderr_ptr, &stderr_len);
        if (!result) {
            unreachable;
        }
        // const thread = try std.Thread.spawn(.{}, clang_job, .{args});
        // thread.join();
    }
}

const generic_musl_source_files = [_][]const u8{
    "src/aio/aio.c",
    "src/aio/aio_suspend.c",
    "src/aio/lio_listio.c",
    "src/complex/__cexp.c",
    "src/complex/__cexpf.c",
    "src/complex/cabs.c",
    "src/complex/cabsf.c",
    "src/complex/cabsl.c",
    "src/complex/cacos.c",
    "src/complex/cacosf.c",
    "src/complex/cacosh.c",
    "src/complex/cacoshf.c",
    "src/complex/cacoshl.c",
    "src/complex/cacosl.c",
    "src/complex/carg.c",
    "src/complex/cargf.c",
    "src/complex/cargl.c",
    "src/complex/casin.c",
    "src/complex/casinf.c",
    "src/complex/casinh.c",
    "src/complex/casinhf.c",
    "src/complex/casinhl.c",
    "src/complex/casinl.c",
    "src/complex/catan.c",
    "src/complex/catanf.c",
    "src/complex/catanh.c",
    "src/complex/catanhf.c",
    "src/complex/catanhl.c",
    "src/complex/catanl.c",
    "src/complex/ccos.c",
    "src/complex/ccosf.c",
    "src/complex/ccosh.c",
    "src/complex/ccoshf.c",
    "src/complex/ccoshl.c",
    "src/complex/ccosl.c",
    "src/complex/cexp.c",
    "src/complex/cexpf.c",
    "src/complex/cexpl.c",
    "src/complex/cimag.c",
    "src/complex/cimagf.c",
    "src/complex/cimagl.c",
    "src/complex/clog.c",
    "src/complex/clogf.c",
    "src/complex/clogl.c",
    "src/complex/conj.c",
    "src/complex/conjf.c",
    "src/complex/conjl.c",
    "src/complex/cpow.c",
    "src/complex/cpowf.c",
    "src/complex/cpowl.c",
    "src/complex/cproj.c",
    "src/complex/cprojf.c",
    "src/complex/cprojl.c",
    "src/complex/creal.c",
    "src/complex/crealf.c",
    "src/complex/creall.c",
    "src/complex/csin.c",
    "src/complex/csinf.c",
    "src/complex/csinh.c",
    "src/complex/csinhf.c",
    "src/complex/csinhl.c",
    "src/complex/csinl.c",
    "src/complex/csqrt.c",
    "src/complex/csqrtf.c",
    "src/complex/csqrtl.c",
    "src/complex/ctan.c",
    "src/complex/ctanf.c",
    "src/complex/ctanh.c",
    "src/complex/ctanhf.c",
    "src/complex/ctanhl.c",
    "src/complex/ctanl.c",
    "src/conf/confstr.c",
    "src/conf/fpathconf.c",
    "src/conf/legacy.c",
    "src/conf/pathconf.c",
    "src/conf/sysconf.c",
    "src/crypt/crypt.c",
    "src/crypt/crypt_blowfish.c",
    "src/crypt/crypt_des.c",
    "src/crypt/crypt_md5.c",
    "src/crypt/crypt_r.c",
    "src/crypt/crypt_sha256.c",
    "src/crypt/crypt_sha512.c",
    "src/crypt/encrypt.c",
    "src/ctype/__ctype_b_loc.c",
    "src/ctype/__ctype_get_mb_cur_max.c",
    "src/ctype/__ctype_tolower_loc.c",
    "src/ctype/__ctype_toupper_loc.c",
    "src/ctype/isalnum.c",
    "src/ctype/isalpha.c",
    "src/ctype/isascii.c",
    "src/ctype/isblank.c",
    "src/ctype/iscntrl.c",
    "src/ctype/isdigit.c",
    "src/ctype/isgraph.c",
    "src/ctype/islower.c",
    "src/ctype/isprint.c",
    "src/ctype/ispunct.c",
    "src/ctype/isspace.c",
    "src/ctype/isupper.c",
    "src/ctype/iswalnum.c",
    "src/ctype/iswalpha.c",
    "src/ctype/iswblank.c",
    "src/ctype/iswcntrl.c",
    "src/ctype/iswctype.c",
    "src/ctype/iswdigit.c",
    "src/ctype/iswgraph.c",
    "src/ctype/iswlower.c",
    "src/ctype/iswprint.c",
    "src/ctype/iswpunct.c",
    "src/ctype/iswspace.c",
    "src/ctype/iswupper.c",
    "src/ctype/iswxdigit.c",
    "src/ctype/isxdigit.c",
    "src/ctype/toascii.c",
    "src/ctype/tolower.c",
    "src/ctype/toupper.c",
    "src/ctype/towctrans.c",
    "src/ctype/wcswidth.c",
    "src/ctype/wctrans.c",
    "src/ctype/wcwidth.c",
    "src/dirent/alphasort.c",
    "src/dirent/closedir.c",
    "src/dirent/dirfd.c",
    "src/dirent/fdopendir.c",
    "src/dirent/opendir.c",
    "src/dirent/readdir.c",
    "src/dirent/readdir_r.c",
    "src/dirent/rewinddir.c",
    "src/dirent/scandir.c",
    "src/dirent/seekdir.c",
    "src/dirent/telldir.c",
    "src/dirent/versionsort.c",
    "src/env/__environ.c",
    "src/env/__init_tls.c",
    "src/env/__libc_start_main.c",
    "src/env/__reset_tls.c",
    "src/env/__stack_chk_fail.c",
    "src/env/clearenv.c",
    "src/env/getenv.c",
    "src/env/putenv.c",
    "src/env/secure_getenv.c",
    "src/env/setenv.c",
    "src/env/unsetenv.c",
    "src/errno/__errno_location.c",
    "src/errno/strerror.c",
    "src/exit/_Exit.c",
    "src/exit/abort.c",
    "src/exit/abort_lock.c",
    "src/exit/arm/__aeabi_atexit.c",
    "src/exit/assert.c",
    "src/exit/at_quick_exit.c",
    "src/exit/atexit.c",
    "src/exit/exit.c",
    "src/exit/quick_exit.c",
    "src/fcntl/creat.c",
    "src/fcntl/fcntl.c",
    "src/fcntl/open.c",
    "src/fcntl/openat.c",
    "src/fcntl/posix_fadvise.c",
    "src/fcntl/posix_fallocate.c",
    "src/fenv/__flt_rounds.c",
    "src/fenv/fegetexceptflag.c",
    "src/fenv/feholdexcept.c",
    "src/fenv/fenv.c",
    "src/fenv/fesetexceptflag.c",
    "src/fenv/fesetround.c",
    "src/fenv/feupdateenv.c",
    "src/internal/defsysinfo.c",
    "src/internal/floatscan.c",
    "src/internal/intscan.c",
    "src/internal/libc.c",
    "src/internal/procfdname.c",
    "src/internal/shgetc.c",
    "src/internal/syscall_ret.c",
    "src/internal/vdso.c",
    "src/internal/version.c",
    "src/ipc/ftok.c",
    "src/ipc/msgctl.c",
    "src/ipc/msgget.c",
    "src/ipc/msgrcv.c",
    "src/ipc/msgsnd.c",
    "src/ipc/semctl.c",
    "src/ipc/semget.c",
    "src/ipc/semop.c",
    "src/ipc/semtimedop.c",
    "src/ipc/shmat.c",
    "src/ipc/shmctl.c",
    "src/ipc/shmdt.c",
    "src/ipc/shmget.c",
    "src/ldso/__dlsym.c",
    "src/ldso/dl_iterate_phdr.c",
    "src/ldso/dladdr.c",
    "src/ldso/dlclose.c",
    "src/ldso/dlerror.c",
    "src/ldso/dlinfo.c",
    "src/ldso/dlopen.c",
    "src/ldso/dlsym.c",
    "src/legacy/cuserid.c",
    "src/legacy/daemon.c",
    "src/legacy/err.c",
    "src/legacy/euidaccess.c",
    "src/legacy/ftw.c",
    "src/legacy/futimes.c",
    "src/legacy/getdtablesize.c",
    "src/legacy/getloadavg.c",
    "src/legacy/getpagesize.c",
    "src/legacy/getpass.c",
    "src/legacy/getusershell.c",
    "src/legacy/isastream.c",
    "src/legacy/lutimes.c",
    "src/legacy/ulimit.c",
    "src/legacy/utmpx.c",
    "src/legacy/valloc.c",
    "src/linux/adjtime.c",
    "src/linux/adjtimex.c",
    "src/linux/arch_prctl.c",
    "src/linux/brk.c",
    "src/linux/cache.c",
    "src/linux/cap.c",
    "src/linux/chroot.c",
    "src/linux/clock_adjtime.c",
    "src/linux/clone.c",
    "src/linux/copy_file_range.c",
    "src/linux/epoll.c",
    "src/linux/eventfd.c",
    "src/linux/fallocate.c",
    "src/linux/fanotify.c",
    "src/linux/flock.c",
    "src/linux/getdents.c",
    "src/linux/getrandom.c",
    "src/linux/gettid.c",
    "src/linux/inotify.c",
    "src/linux/ioperm.c",
    "src/linux/iopl.c",
    "src/linux/klogctl.c",
    "src/linux/membarrier.c",
    "src/linux/memfd_create.c",
    "src/linux/mlock2.c",
    "src/linux/module.c",
    "src/linux/mount.c",
    "src/linux/name_to_handle_at.c",
    "src/linux/open_by_handle_at.c",
    "src/linux/personality.c",
    "src/linux/pivot_root.c",
    "src/linux/ppoll.c",
    "src/linux/prctl.c",
    "src/linux/prlimit.c",
    "src/linux/process_vm.c",
    "src/linux/ptrace.c",
    "src/linux/quotactl.c",
    "src/linux/readahead.c",
    "src/linux/reboot.c",
    "src/linux/remap_file_pages.c",
    "src/linux/sbrk.c",
    "src/linux/sendfile.c",
    "src/linux/setfsgid.c",
    "src/linux/setfsuid.c",
    "src/linux/setgroups.c",
    "src/linux/sethostname.c",
    "src/linux/setns.c",
    "src/linux/settimeofday.c",
    "src/linux/signalfd.c",
    "src/linux/splice.c",
    "src/linux/stime.c",
    "src/linux/swap.c",
    "src/linux/sync_file_range.c",
    "src/linux/syncfs.c",
    "src/linux/sysinfo.c",
    "src/linux/tee.c",
    "src/linux/timerfd.c",
    "src/linux/unshare.c",
    "src/linux/utimes.c",
    "src/linux/vhangup.c",
    "src/linux/vmsplice.c",
    "src/linux/wait3.c",
    "src/linux/wait4.c",
    "src/linux/xattr.c",
    "src/locale/__lctrans.c",
    "src/locale/__mo_lookup.c",
    "src/locale/bind_textdomain_codeset.c",
    "src/locale/c_locale.c",
    "src/locale/catclose.c",
    "src/locale/catgets.c",
    "src/locale/catopen.c",
    "src/locale/dcngettext.c",
    "src/locale/duplocale.c",
    "src/locale/freelocale.c",
    "src/locale/iconv.c",
    "src/locale/iconv_close.c",
    "src/locale/langinfo.c",
    "src/locale/locale_map.c",
    "src/locale/localeconv.c",
    "src/locale/newlocale.c",
    "src/locale/pleval.c",
    "src/locale/setlocale.c",
    "src/locale/strcoll.c",
    "src/locale/strfmon.c",
    "src/locale/strtod_l.c",
    "src/locale/strxfrm.c",
    "src/locale/textdomain.c",
    "src/locale/uselocale.c",
    "src/locale/wcscoll.c",
    "src/locale/wcsxfrm.c",
    "src/malloc/calloc.c",
    "src/malloc/free.c",
    "src/malloc/libc_calloc.c",
    "src/malloc/lite_malloc.c",
    "src/malloc/mallocng/aligned_alloc.c",
    "src/malloc/mallocng/donate.c",
    "src/malloc/mallocng/free.c",
    "src/malloc/mallocng/malloc.c",
    "src/malloc/mallocng/malloc_usable_size.c",
    "src/malloc/mallocng/realloc.c",
    "src/malloc/memalign.c",
    "src/malloc/oldmalloc/aligned_alloc.c",
    "src/malloc/oldmalloc/malloc.c",
    "src/malloc/oldmalloc/malloc_usable_size.c",
    "src/malloc/posix_memalign.c",
    "src/malloc/realloc.c",
    "src/malloc/reallocarray.c",
    "src/malloc/replaced.c",
    "src/math/__cos.c",
    "src/math/__cosdf.c",
    "src/math/__cosl.c",
    "src/math/__expo2.c",
    "src/math/__expo2f.c",
    "src/math/__fpclassify.c",
    "src/math/__fpclassifyf.c",
    "src/math/__fpclassifyl.c",
    "src/math/__invtrigl.c",
    "src/math/__math_divzero.c",
    "src/math/__math_divzerof.c",
    "src/math/__math_invalid.c",
    "src/math/__math_invalidf.c",
    "src/math/__math_invalidl.c",
    "src/math/__math_oflow.c",
    "src/math/__math_oflowf.c",
    "src/math/__math_uflow.c",
    "src/math/__math_uflowf.c",
    "src/math/__math_xflow.c",
    "src/math/__math_xflowf.c",
    "src/math/__polevll.c",
    "src/math/__rem_pio2.c",
    "src/math/__rem_pio2_large.c",
    "src/math/__rem_pio2f.c",
    "src/math/__rem_pio2l.c",
    "src/math/__signbit.c",
    "src/math/__signbitf.c",
    "src/math/__signbitl.c",
    "src/math/__sin.c",
    "src/math/__sindf.c",
    "src/math/__sinl.c",
    "src/math/__tan.c",
    "src/math/__tandf.c",
    "src/math/__tanl.c",
    "src/math/acos.c",
    "src/math/acosf.c",
    "src/math/acosh.c",
    "src/math/acoshf.c",
    "src/math/acoshl.c",
    "src/math/acosl.c",
    "src/math/asin.c",
    "src/math/asinf.c",
    "src/math/asinh.c",
    "src/math/asinhf.c",
    "src/math/asinhl.c",
    "src/math/asinl.c",
    "src/math/atan.c",
    "src/math/atan2.c",
    "src/math/atan2f.c",
    "src/math/atan2l.c",
    "src/math/atanf.c",
    "src/math/atanh.c",
    "src/math/atanhf.c",
    "src/math/atanhl.c",
    "src/math/atanl.c",
    "src/math/cbrt.c",
    "src/math/cbrtf.c",
    "src/math/cbrtl.c",
    "src/math/ceil.c",
    "src/math/ceilf.c",
    "src/math/ceill.c",
    "src/math/copysign.c",
    "src/math/copysignf.c",
    "src/math/copysignl.c",
    "src/math/cos.c",
    "src/math/cosf.c",
    "src/math/cosh.c",
    "src/math/coshf.c",
    "src/math/coshl.c",
    "src/math/cosl.c",
    "src/math/erf.c",
    "src/math/erff.c",
    "src/math/erfl.c",
    "src/math/exp.c",
    "src/math/exp10.c",
    "src/math/exp10f.c",
    "src/math/exp10l.c",
    "src/math/exp2.c",
    "src/math/exp2f.c",
    "src/math/exp2f_data.c",
    "src/math/exp2l.c",
    "src/math/exp_data.c",
    "src/math/expf.c",
    "src/math/expl.c",
    "src/math/expm1.c",
    "src/math/expm1f.c",
    "src/math/expm1l.c",
    "src/math/fabs.c",
    "src/math/fabsf.c",
    "src/math/fabsl.c",
    "src/math/fdim.c",
    "src/math/fdimf.c",
    "src/math/fdiml.c",
    "src/math/finite.c",
    "src/math/finitef.c",
    "src/math/floor.c",
    "src/math/floorf.c",
    "src/math/floorl.c",
    "src/math/fma.c",
    "src/math/fmaf.c",
    "src/math/fmal.c",
    "src/math/fmax.c",
    "src/math/fmaxf.c",
    "src/math/fmaxl.c",
    "src/math/fmin.c",
    "src/math/fminf.c",
    "src/math/fminl.c",
    "src/math/fmod.c",
    "src/math/fmodf.c",
    "src/math/fmodl.c",
    "src/math/frexp.c",
    "src/math/frexpf.c",
    "src/math/frexpl.c",
    "src/math/hypot.c",
    "src/math/hypotf.c",
    "src/math/hypotl.c",
    "src/math/ilogb.c",
    "src/math/ilogbf.c",
    "src/math/ilogbl.c",
    "src/math/j0.c",
    "src/math/j0f.c",
    "src/math/j1.c",
    "src/math/j1f.c",
    "src/math/jn.c",
    "src/math/jnf.c",
    "src/math/ldexp.c",
    "src/math/ldexpf.c",
    "src/math/ldexpl.c",
    "src/math/lgamma.c",
    "src/math/lgamma_r.c",
    "src/math/lgammaf.c",
    "src/math/lgammaf_r.c",
    "src/math/lgammal.c",
    "src/math/llrint.c",
    "src/math/llrintf.c",
    "src/math/llrintl.c",
    "src/math/llround.c",
    "src/math/llroundf.c",
    "src/math/llroundl.c",
    "src/math/log.c",
    "src/math/log10.c",
    "src/math/log10f.c",
    "src/math/log10l.c",
    "src/math/log1p.c",
    "src/math/log1pf.c",
    "src/math/log1pl.c",
    "src/math/log2.c",
    "src/math/log2_data.c",
    "src/math/log2f.c",
    "src/math/log2f_data.c",
    "src/math/log2l.c",
    "src/math/log_data.c",
    "src/math/logb.c",
    "src/math/logbf.c",
    "src/math/logbl.c",
    "src/math/logf.c",
    "src/math/logf_data.c",
    "src/math/logl.c",
    "src/math/lrint.c",
    "src/math/lrintf.c",
    "src/math/lrintl.c",
    "src/math/lround.c",
    "src/math/lroundf.c",
    "src/math/lroundl.c",
    "src/math/modf.c",
    "src/math/modff.c",
    "src/math/modfl.c",
    "src/math/nan.c",
    "src/math/nanf.c",
    "src/math/nanl.c",
    "src/math/nearbyint.c",
    "src/math/nearbyintf.c",
    "src/math/nearbyintl.c",
    "src/math/nextafter.c",
    "src/math/nextafterf.c",
    "src/math/nextafterl.c",
    "src/math/nexttoward.c",
    "src/math/nexttowardf.c",
    "src/math/nexttowardl.c",
    "src/math/pow.c",
    "src/math/pow_data.c",
    "src/math/powf.c",
    "src/math/powf_data.c",
    "src/math/powl.c",
    "src/math/remainder.c",
    "src/math/remainderf.c",
    "src/math/remainderl.c",
    "src/math/remquo.c",
    "src/math/remquof.c",
    "src/math/remquol.c",
    "src/math/rint.c",
    "src/math/rintf.c",
    "src/math/rintl.c",
    "src/math/round.c",
    "src/math/roundf.c",
    "src/math/roundl.c",
    "src/math/scalb.c",
    "src/math/scalbf.c",
    "src/math/scalbln.c",
    "src/math/scalblnf.c",
    "src/math/scalblnl.c",
    "src/math/scalbn.c",
    "src/math/scalbnf.c",
    "src/math/scalbnl.c",
    "src/math/signgam.c",
    "src/math/significand.c",
    "src/math/significandf.c",
    "src/math/sin.c",
    "src/math/sincos.c",
    "src/math/sincosf.c",
    "src/math/sincosl.c",
    "src/math/sinf.c",
    "src/math/sinh.c",
    "src/math/sinhf.c",
    "src/math/sinhl.c",
    "src/math/sinl.c",
    "src/math/sqrt.c",
    "src/math/sqrt_data.c",
    "src/math/sqrtf.c",
    "src/math/sqrtl.c",
    "src/math/tan.c",
    "src/math/tanf.c",
    "src/math/tanh.c",
    "src/math/tanhf.c",
    "src/math/tanhl.c",
    "src/math/tanl.c",
    "src/math/tgamma.c",
    "src/math/tgammaf.c",
    "src/math/tgammal.c",
    "src/math/trunc.c",
    "src/math/truncf.c",
    "src/math/truncl.c",
    "src/misc/a64l.c",
    "src/misc/basename.c",
    "src/misc/dirname.c",
    "src/misc/ffs.c",
    "src/misc/ffsl.c",
    "src/misc/ffsll.c",
    "src/misc/fmtmsg.c",
    "src/misc/forkpty.c",
    "src/misc/get_current_dir_name.c",
    "src/misc/getauxval.c",
    "src/misc/getdomainname.c",
    "src/misc/getentropy.c",
    "src/misc/gethostid.c",
    "src/misc/getopt.c",
    "src/misc/getopt_long.c",
    "src/misc/getpriority.c",
    "src/misc/getresgid.c",
    "src/misc/getresuid.c",
    "src/misc/getrlimit.c",
    "src/misc/getrusage.c",
    "src/misc/getsubopt.c",
    "src/misc/initgroups.c",
    "src/misc/ioctl.c",
    "src/misc/issetugid.c",
    "src/misc/lockf.c",
    "src/misc/login_tty.c",
    "src/misc/mntent.c",
    "src/misc/nftw.c",
    "src/misc/openpty.c",
    "src/misc/ptsname.c",
    "src/misc/pty.c",
    "src/misc/realpath.c",
    "src/misc/setdomainname.c",
    "src/misc/setpriority.c",
    "src/misc/setrlimit.c",
    "src/misc/syscall.c",
    "src/misc/syslog.c",
    "src/misc/uname.c",
    "src/misc/wordexp.c",
    "src/mman/madvise.c",
    "src/mman/mincore.c",
    "src/mman/mlock.c",
    "src/mman/mlockall.c",
    "src/mman/mmap.c",
    "src/mman/mprotect.c",
    "src/mman/mremap.c",
    "src/mman/msync.c",
    "src/mman/munlock.c",
    "src/mman/munlockall.c",
    "src/mman/munmap.c",
    "src/mman/posix_madvise.c",
    "src/mman/shm_open.c",
    "src/mq/mq_close.c",
    "src/mq/mq_getattr.c",
    "src/mq/mq_notify.c",
    "src/mq/mq_open.c",
    "src/mq/mq_receive.c",
    "src/mq/mq_send.c",
    "src/mq/mq_setattr.c",
    "src/mq/mq_timedreceive.c",
    "src/mq/mq_timedsend.c",
    "src/mq/mq_unlink.c",
    "src/multibyte/btowc.c",
    "src/multibyte/c16rtomb.c",
    "src/multibyte/c32rtomb.c",
    "src/multibyte/internal.c",
    "src/multibyte/mblen.c",
    "src/multibyte/mbrlen.c",
    "src/multibyte/mbrtoc16.c",
    "src/multibyte/mbrtoc32.c",
    "src/multibyte/mbrtowc.c",
    "src/multibyte/mbsinit.c",
    "src/multibyte/mbsnrtowcs.c",
    "src/multibyte/mbsrtowcs.c",
    "src/multibyte/mbstowcs.c",
    "src/multibyte/mbtowc.c",
    "src/multibyte/wcrtomb.c",
    "src/multibyte/wcsnrtombs.c",
    "src/multibyte/wcsrtombs.c",
    "src/multibyte/wcstombs.c",
    "src/multibyte/wctob.c",
    "src/multibyte/wctomb.c",
    "src/network/accept.c",
    "src/network/accept4.c",
    "src/network/bind.c",
    "src/network/connect.c",
    "src/network/dn_comp.c",
    "src/network/dn_expand.c",
    "src/network/dn_skipname.c",
    "src/network/dns_parse.c",
    "src/network/ent.c",
    "src/network/ether.c",
    "src/network/freeaddrinfo.c",
    "src/network/gai_strerror.c",
    "src/network/getaddrinfo.c",
    "src/network/gethostbyaddr.c",
    "src/network/gethostbyaddr_r.c",
    "src/network/gethostbyname.c",
    "src/network/gethostbyname2.c",
    "src/network/gethostbyname2_r.c",
    "src/network/gethostbyname_r.c",
    "src/network/getifaddrs.c",
    "src/network/getnameinfo.c",
    "src/network/getpeername.c",
    "src/network/getservbyname.c",
    "src/network/getservbyname_r.c",
    "src/network/getservbyport.c",
    "src/network/getservbyport_r.c",
    "src/network/getsockname.c",
    "src/network/getsockopt.c",
    "src/network/h_errno.c",
    "src/network/herror.c",
    "src/network/hstrerror.c",
    "src/network/htonl.c",
    "src/network/htons.c",
    "src/network/if_freenameindex.c",
    "src/network/if_indextoname.c",
    "src/network/if_nameindex.c",
    "src/network/if_nametoindex.c",
    "src/network/in6addr_any.c",
    "src/network/in6addr_loopback.c",
    "src/network/inet_addr.c",
    "src/network/inet_aton.c",
    "src/network/inet_legacy.c",
    "src/network/inet_ntoa.c",
    "src/network/inet_ntop.c",
    "src/network/inet_pton.c",
    "src/network/listen.c",
    "src/network/lookup_ipliteral.c",
    "src/network/lookup_name.c",
    "src/network/lookup_serv.c",
    "src/network/netlink.c",
    "src/network/netname.c",
    "src/network/ns_parse.c",
    "src/network/ntohl.c",
    "src/network/ntohs.c",
    "src/network/proto.c",
    "src/network/recv.c",
    "src/network/recvfrom.c",
    "src/network/recvmmsg.c",
    "src/network/recvmsg.c",
    "src/network/res_init.c",
    "src/network/res_mkquery.c",
    "src/network/res_msend.c",
    "src/network/res_query.c",
    "src/network/res_querydomain.c",
    "src/network/res_send.c",
    "src/network/res_state.c",
    "src/network/resolvconf.c",
    "src/network/send.c",
    "src/network/sendmmsg.c",
    "src/network/sendmsg.c",
    "src/network/sendto.c",
    "src/network/serv.c",
    "src/network/setsockopt.c",
    "src/network/shutdown.c",
    "src/network/sockatmark.c",
    "src/network/socket.c",
    "src/network/socketpair.c",
    "src/passwd/fgetgrent.c",
    "src/passwd/fgetpwent.c",
    "src/passwd/fgetspent.c",
    "src/passwd/getgr_a.c",
    "src/passwd/getgr_r.c",
    "src/passwd/getgrent.c",
    "src/passwd/getgrent_a.c",
    "src/passwd/getgrouplist.c",
    "src/passwd/getpw_a.c",
    "src/passwd/getpw_r.c",
    "src/passwd/getpwent.c",
    "src/passwd/getpwent_a.c",
    "src/passwd/getspent.c",
    "src/passwd/getspnam.c",
    "src/passwd/getspnam_r.c",
    "src/passwd/lckpwdf.c",
    "src/passwd/nscd_query.c",
    "src/passwd/putgrent.c",
    "src/passwd/putpwent.c",
    "src/passwd/putspent.c",
    "src/prng/__rand48_step.c",
    "src/prng/__seed48.c",
    "src/prng/drand48.c",
    "src/prng/lcong48.c",
    "src/prng/lrand48.c",
    "src/prng/mrand48.c",
    "src/prng/rand.c",
    "src/prng/rand_r.c",
    "src/prng/random.c",
    "src/prng/seed48.c",
    "src/prng/srand48.c",
    "src/process/_Fork.c",
    "src/process/execl.c",
    "src/process/execle.c",
    "src/process/execlp.c",
    "src/process/execv.c",
    "src/process/execve.c",
    "src/process/execvp.c",
    "src/process/fexecve.c",
    "src/process/fork.c",
    "src/process/posix_spawn.c",
    "src/process/posix_spawn_file_actions_addchdir.c",
    "src/process/posix_spawn_file_actions_addclose.c",
    "src/process/posix_spawn_file_actions_adddup2.c",
    "src/process/posix_spawn_file_actions_addfchdir.c",
    "src/process/posix_spawn_file_actions_addopen.c",
    "src/process/posix_spawn_file_actions_destroy.c",
    "src/process/posix_spawn_file_actions_init.c",
    "src/process/posix_spawnattr_destroy.c",
    "src/process/posix_spawnattr_getflags.c",
    "src/process/posix_spawnattr_getpgroup.c",
    "src/process/posix_spawnattr_getsigdefault.c",
    "src/process/posix_spawnattr_getsigmask.c",
    "src/process/posix_spawnattr_init.c",
    "src/process/posix_spawnattr_sched.c",
    "src/process/posix_spawnattr_setflags.c",
    "src/process/posix_spawnattr_setpgroup.c",
    "src/process/posix_spawnattr_setsigdefault.c",
    "src/process/posix_spawnattr_setsigmask.c",
    "src/process/posix_spawnp.c",
    "src/regex/fnmatch.c",
    "src/regex/glob.c",
    "src/regex/regcomp.c",
    "src/regex/regerror.c",
    "src/regex/regexec.c",
    "src/regex/tre-mem.c",
    "src/sched/affinity.c",
    "src/sched/sched_cpucount.c",
    "src/sched/sched_get_priority_max.c",
    "src/sched/sched_getcpu.c",
    "src/sched/sched_getparam.c",
    "src/sched/sched_getscheduler.c",
    "src/sched/sched_rr_get_interval.c",
    "src/sched/sched_setparam.c",
    "src/sched/sched_setscheduler.c",
    "src/sched/sched_yield.c",
    "src/search/hsearch.c",
    "src/search/insque.c",
    "src/search/lsearch.c",
    "src/search/tdelete.c",
    "src/search/tdestroy.c",
    "src/search/tfind.c",
    "src/search/tsearch.c",
    "src/search/twalk.c",
    "src/select/poll.c",
    "src/select/pselect.c",
    "src/select/select.c",
    "src/setjmp/longjmp.c",
    "src/setjmp/setjmp.c",
    "src/signal/block.c",
    "src/signal/getitimer.c",
    "src/signal/kill.c",
    "src/signal/killpg.c",
    "src/signal/psiginfo.c",
    "src/signal/psignal.c",
    "src/signal/raise.c",
    "src/signal/restore.c",
    "src/signal/sigaction.c",
    "src/signal/sigaddset.c",
    "src/signal/sigaltstack.c",
    "src/signal/sigandset.c",
    "src/signal/sigdelset.c",
    "src/signal/sigemptyset.c",
    "src/signal/sigfillset.c",
    "src/signal/sighold.c",
    "src/signal/sigignore.c",
    "src/signal/siginterrupt.c",
    "src/signal/sigisemptyset.c",
    "src/signal/sigismember.c",
    "src/signal/siglongjmp.c",
    "src/signal/signal.c",
    "src/signal/sigorset.c",
    "src/signal/sigpause.c",
    "src/signal/sigpending.c",
    "src/signal/sigprocmask.c",
    "src/signal/sigqueue.c",
    "src/signal/sigrelse.c",
    "src/signal/sigrtmax.c",
    "src/signal/sigrtmin.c",
    "src/signal/sigset.c",
    "src/signal/sigsetjmp.c",
    "src/signal/sigsetjmp_tail.c",
    "src/signal/sigsuspend.c",
    "src/signal/sigtimedwait.c",
    "src/signal/sigwait.c",
    "src/signal/sigwaitinfo.c",
    "src/stat/__xstat.c",
    "src/stat/chmod.c",
    "src/stat/fchmod.c",
    "src/stat/fchmodat.c",
    "src/stat/fstat.c",
    "src/stat/fstatat.c",
    "src/stat/futimens.c",
    "src/stat/futimesat.c",
    "src/stat/lchmod.c",
    "src/stat/lstat.c",
    "src/stat/mkdir.c",
    "src/stat/mkdirat.c",
    "src/stat/mkfifo.c",
    "src/stat/mkfifoat.c",
    "src/stat/mknod.c",
    "src/stat/mknodat.c",
    "src/stat/stat.c",
    "src/stat/statvfs.c",
    "src/stat/umask.c",
    "src/stat/utimensat.c",
    "src/stdio/__fclose_ca.c",
    "src/stdio/__fdopen.c",
    "src/stdio/__fmodeflags.c",
    "src/stdio/__fopen_rb_ca.c",
    "src/stdio/__lockfile.c",
    "src/stdio/__overflow.c",
    "src/stdio/__stdio_close.c",
    "src/stdio/__stdio_exit.c",
    "src/stdio/__stdio_read.c",
    "src/stdio/__stdio_seek.c",
    "src/stdio/__stdio_write.c",
    "src/stdio/__stdout_write.c",
    "src/stdio/__toread.c",
    "src/stdio/__towrite.c",
    "src/stdio/__uflow.c",
    "src/stdio/asprintf.c",
    "src/stdio/clearerr.c",
    "src/stdio/dprintf.c",
    "src/stdio/ext.c",
    "src/stdio/ext2.c",
    "src/stdio/fclose.c",
    "src/stdio/feof.c",
    "src/stdio/ferror.c",
    "src/stdio/fflush.c",
    "src/stdio/fgetc.c",
    "src/stdio/fgetln.c",
    "src/stdio/fgetpos.c",
    "src/stdio/fgets.c",
    "src/stdio/fgetwc.c",
    "src/stdio/fgetws.c",
    "src/stdio/fileno.c",
    "src/stdio/flockfile.c",
    "src/stdio/fmemopen.c",
    "src/stdio/fopen.c",
    "src/stdio/fopencookie.c",
    "src/stdio/fprintf.c",
    "src/stdio/fputc.c",
    "src/stdio/fputs.c",
    "src/stdio/fputwc.c",
    "src/stdio/fputws.c",
    "src/stdio/fread.c",
    "src/stdio/freopen.c",
    "src/stdio/fscanf.c",
    "src/stdio/fseek.c",
    "src/stdio/fsetpos.c",
    "src/stdio/ftell.c",
    "src/stdio/ftrylockfile.c",
    "src/stdio/funlockfile.c",
    "src/stdio/fwide.c",
    "src/stdio/fwprintf.c",
    "src/stdio/fwrite.c",
    "src/stdio/fwscanf.c",
    "src/stdio/getc.c",
    "src/stdio/getc_unlocked.c",
    "src/stdio/getchar.c",
    "src/stdio/getchar_unlocked.c",
    "src/stdio/getdelim.c",
    "src/stdio/getline.c",
    "src/stdio/gets.c",
    "src/stdio/getw.c",
    "src/stdio/getwc.c",
    "src/stdio/getwchar.c",
    "src/stdio/ofl.c",
    "src/stdio/ofl_add.c",
    "src/stdio/open_memstream.c",
    "src/stdio/open_wmemstream.c",
    "src/stdio/pclose.c",
    "src/stdio/perror.c",
    "src/stdio/popen.c",
    "src/stdio/printf.c",
    "src/stdio/putc.c",
    "src/stdio/putc_unlocked.c",
    "src/stdio/putchar.c",
    "src/stdio/putchar_unlocked.c",
    "src/stdio/puts.c",
    "src/stdio/putw.c",
    "src/stdio/putwc.c",
    "src/stdio/putwchar.c",
    "src/stdio/remove.c",
    "src/stdio/rename.c",
    "src/stdio/rewind.c",
    "src/stdio/scanf.c",
    "src/stdio/setbuf.c",
    "src/stdio/setbuffer.c",
    "src/stdio/setlinebuf.c",
    "src/stdio/setvbuf.c",
    "src/stdio/snprintf.c",
    "src/stdio/sprintf.c",
    "src/stdio/sscanf.c",
    "src/stdio/stderr.c",
    "src/stdio/stdin.c",
    "src/stdio/stdout.c",
    "src/stdio/swprintf.c",
    "src/stdio/swscanf.c",
    "src/stdio/tempnam.c",
    "src/stdio/tmpfile.c",
    "src/stdio/tmpnam.c",
    "src/stdio/ungetc.c",
    "src/stdio/ungetwc.c",
    "src/stdio/vasprintf.c",
    "src/stdio/vdprintf.c",
    "src/stdio/vfprintf.c",
    "src/stdio/vfscanf.c",
    "src/stdio/vfwprintf.c",
    "src/stdio/vfwscanf.c",
    "src/stdio/vprintf.c",
    "src/stdio/vscanf.c",
    "src/stdio/vsnprintf.c",
    "src/stdio/vsprintf.c",
    "src/stdio/vsscanf.c",
    "src/stdio/vswprintf.c",
    "src/stdio/vswscanf.c",
    "src/stdio/vwprintf.c",
    "src/stdio/vwscanf.c",
    "src/stdio/wprintf.c",
    "src/stdio/wscanf.c",
    "src/stdlib/abs.c",
    "src/stdlib/atof.c",
    "src/stdlib/atoi.c",
    "src/stdlib/atol.c",
    "src/stdlib/atoll.c",
    "src/stdlib/bsearch.c",
    "src/stdlib/div.c",
    "src/stdlib/ecvt.c",
    "src/stdlib/fcvt.c",
    "src/stdlib/gcvt.c",
    "src/stdlib/imaxabs.c",
    "src/stdlib/imaxdiv.c",
    "src/stdlib/labs.c",
    "src/stdlib/ldiv.c",
    "src/stdlib/llabs.c",
    "src/stdlib/lldiv.c",
    "src/stdlib/qsort.c",
    "src/stdlib/qsort_nr.c",
    "src/stdlib/strtod.c",
    "src/stdlib/strtol.c",
    "src/stdlib/wcstod.c",
    "src/stdlib/wcstol.c",
    "src/string/bcmp.c",
    "src/string/bcopy.c",
    "src/string/bzero.c",
    "src/string/explicit_bzero.c",
    "src/string/index.c",
    "src/string/memccpy.c",
    "src/string/memchr.c",
    "src/string/memcmp.c",
    "src/string/memcpy.c",
    "src/string/memmem.c",
    "src/string/memmove.c",
    "src/string/mempcpy.c",
    "src/string/memrchr.c",
    "src/string/memset.c",
    "src/string/rindex.c",
    "src/string/stpcpy.c",
    "src/string/stpncpy.c",
    "src/string/strcasecmp.c",
    "src/string/strcasestr.c",
    "src/string/strcat.c",
    "src/string/strchr.c",
    "src/string/strchrnul.c",
    "src/string/strcmp.c",
    "src/string/strcpy.c",
    "src/string/strcspn.c",
    "src/string/strdup.c",
    "src/string/strerror_r.c",
    "src/string/strlcat.c",
    "src/string/strlcpy.c",
    "src/string/strlen.c",
    "src/string/strncasecmp.c",
    "src/string/strncat.c",
    "src/string/strncmp.c",
    "src/string/strncpy.c",
    "src/string/strndup.c",
    "src/string/strnlen.c",
    "src/string/strpbrk.c",
    "src/string/strrchr.c",
    "src/string/strsep.c",
    "src/string/strsignal.c",
    "src/string/strspn.c",
    "src/string/strstr.c",
    "src/string/strtok.c",
    "src/string/strtok_r.c",
    "src/string/strverscmp.c",
    "src/string/swab.c",
    "src/string/wcpcpy.c",
    "src/string/wcpncpy.c",
    "src/string/wcscasecmp.c",
    "src/string/wcscasecmp_l.c",
    "src/string/wcscat.c",
    "src/string/wcschr.c",
    "src/string/wcscmp.c",
    "src/string/wcscpy.c",
    "src/string/wcscspn.c",
    "src/string/wcsdup.c",
    "src/string/wcslen.c",
    "src/string/wcsncasecmp.c",
    "src/string/wcsncasecmp_l.c",
    "src/string/wcsncat.c",
    "src/string/wcsncmp.c",
    "src/string/wcsncpy.c",
    "src/string/wcsnlen.c",
    "src/string/wcspbrk.c",
    "src/string/wcsrchr.c",
    "src/string/wcsspn.c",
    "src/string/wcsstr.c",
    "src/string/wcstok.c",
    "src/string/wcswcs.c",
    "src/string/wmemchr.c",
    "src/string/wmemcmp.c",
    "src/string/wmemcpy.c",
    "src/string/wmemmove.c",
    "src/string/wmemset.c",
    "src/temp/__randname.c",
    "src/temp/mkdtemp.c",
    "src/temp/mkostemp.c",
    "src/temp/mkostemps.c",
    "src/temp/mkstemp.c",
    "src/temp/mkstemps.c",
    "src/temp/mktemp.c",
    "src/termios/cfgetospeed.c",
    "src/termios/cfmakeraw.c",
    "src/termios/cfsetospeed.c",
    "src/termios/tcdrain.c",
    "src/termios/tcflow.c",
    "src/termios/tcflush.c",
    "src/termios/tcgetattr.c",
    "src/termios/tcgetsid.c",
    "src/termios/tcgetwinsize.c",
    "src/termios/tcsendbreak.c",
    "src/termios/tcsetattr.c",
    "src/termios/tcsetwinsize.c",
    "src/thread/__lock.c",
    // "src/thread/__set_thread_area.c",
    "src/thread/__syscall_cp.c",
    "src/thread/__timedwait.c",
    "src/thread/__tls_get_addr.c",
    "src/thread/__unmapself.c",
    "src/thread/__wait.c",
    "src/thread/call_once.c",
    "src/thread/clone.c",
    "src/thread/cnd_broadcast.c",
    "src/thread/cnd_destroy.c",
    "src/thread/cnd_init.c",
    "src/thread/cnd_signal.c",
    "src/thread/cnd_timedwait.c",
    "src/thread/cnd_wait.c",
    "src/thread/default_attr.c",
    "src/thread/lock_ptc.c",
    "src/thread/mtx_destroy.c",
    "src/thread/mtx_init.c",
    "src/thread/mtx_lock.c",
    "src/thread/mtx_timedlock.c",
    "src/thread/mtx_trylock.c",
    "src/thread/mtx_unlock.c",
    "src/thread/pthread_atfork.c",
    "src/thread/pthread_attr_destroy.c",
    "src/thread/pthread_attr_get.c",
    "src/thread/pthread_attr_init.c",
    "src/thread/pthread_attr_setdetachstate.c",
    "src/thread/pthread_attr_setguardsize.c",
    "src/thread/pthread_attr_setinheritsched.c",
    "src/thread/pthread_attr_setschedparam.c",
    "src/thread/pthread_attr_setschedpolicy.c",
    "src/thread/pthread_attr_setscope.c",
    "src/thread/pthread_attr_setstack.c",
    "src/thread/pthread_attr_setstacksize.c",
    "src/thread/pthread_barrier_destroy.c",
    "src/thread/pthread_barrier_init.c",
    "src/thread/pthread_barrier_wait.c",
    "src/thread/pthread_barrierattr_destroy.c",
    "src/thread/pthread_barrierattr_init.c",
    "src/thread/pthread_barrierattr_setpshared.c",
    "src/thread/pthread_cancel.c",
    "src/thread/pthread_cleanup_push.c",
    "src/thread/pthread_cond_broadcast.c",
    "src/thread/pthread_cond_destroy.c",
    "src/thread/pthread_cond_init.c",
    "src/thread/pthread_cond_signal.c",
    "src/thread/pthread_cond_timedwait.c",
    "src/thread/pthread_cond_wait.c",
    "src/thread/pthread_condattr_destroy.c",
    "src/thread/pthread_condattr_init.c",
    "src/thread/pthread_condattr_setclock.c",
    "src/thread/pthread_condattr_setpshared.c",
    "src/thread/pthread_create.c",
    "src/thread/pthread_detach.c",
    "src/thread/pthread_equal.c",
    "src/thread/pthread_getattr_np.c",
    "src/thread/pthread_getconcurrency.c",
    "src/thread/pthread_getcpuclockid.c",
    "src/thread/pthread_getname_np.c",
    "src/thread/pthread_getschedparam.c",
    "src/thread/pthread_getspecific.c",
    "src/thread/pthread_join.c",
    "src/thread/pthread_key_create.c",
    "src/thread/pthread_kill.c",
    "src/thread/pthread_mutex_consistent.c",
    "src/thread/pthread_mutex_destroy.c",
    "src/thread/pthread_mutex_getprioceiling.c",
    "src/thread/pthread_mutex_init.c",
    "src/thread/pthread_mutex_lock.c",
    "src/thread/pthread_mutex_setprioceiling.c",
    "src/thread/pthread_mutex_timedlock.c",
    "src/thread/pthread_mutex_trylock.c",
    "src/thread/pthread_mutex_unlock.c",
    "src/thread/pthread_mutexattr_destroy.c",
    "src/thread/pthread_mutexattr_init.c",
    "src/thread/pthread_mutexattr_setprotocol.c",
    "src/thread/pthread_mutexattr_setpshared.c",
    "src/thread/pthread_mutexattr_setrobust.c",
    "src/thread/pthread_mutexattr_settype.c",
    "src/thread/pthread_once.c",
    "src/thread/pthread_rwlock_destroy.c",
    "src/thread/pthread_rwlock_init.c",
    "src/thread/pthread_rwlock_rdlock.c",
    "src/thread/pthread_rwlock_timedrdlock.c",
    "src/thread/pthread_rwlock_timedwrlock.c",
    "src/thread/pthread_rwlock_tryrdlock.c",
    "src/thread/pthread_rwlock_trywrlock.c",
    "src/thread/pthread_rwlock_unlock.c",
    "src/thread/pthread_rwlock_wrlock.c",
    "src/thread/pthread_rwlockattr_destroy.c",
    "src/thread/pthread_rwlockattr_init.c",
    "src/thread/pthread_rwlockattr_setpshared.c",
    "src/thread/pthread_self.c",
    "src/thread/pthread_setattr_default_np.c",
    "src/thread/pthread_setcancelstate.c",
    "src/thread/pthread_setcanceltype.c",
    "src/thread/pthread_setconcurrency.c",
    "src/thread/pthread_setname_np.c",
    "src/thread/pthread_setschedparam.c",
    "src/thread/pthread_setschedprio.c",
    "src/thread/pthread_setspecific.c",
    "src/thread/pthread_sigmask.c",
    "src/thread/pthread_spin_destroy.c",
    "src/thread/pthread_spin_init.c",
    "src/thread/pthread_spin_lock.c",
    "src/thread/pthread_spin_trylock.c",
    "src/thread/pthread_spin_unlock.c",
    "src/thread/pthread_testcancel.c",
    "src/thread/sem_destroy.c",
    "src/thread/sem_getvalue.c",
    "src/thread/sem_init.c",
    "src/thread/sem_open.c",
    "src/thread/sem_post.c",
    "src/thread/sem_timedwait.c",
    "src/thread/sem_trywait.c",
    "src/thread/sem_unlink.c",
    "src/thread/sem_wait.c",
    "src/thread/synccall.c",
    "src/thread/syscall_cp.c",
    "src/thread/thrd_create.c",
    "src/thread/thrd_exit.c",
    "src/thread/thrd_join.c",
    "src/thread/thrd_sleep.c",
    "src/thread/thrd_yield.c",
    "src/thread/tls.c",
    "src/thread/tss_create.c",
    "src/thread/tss_delete.c",
    "src/thread/tss_set.c",
    "src/thread/vmlock.c",
    "src/time/__map_file.c",
    "src/time/__month_to_secs.c",
    "src/time/__secs_to_tm.c",
    "src/time/__tm_to_secs.c",
    "src/time/__tz.c",
    "src/time/__year_to_secs.c",
    "src/time/asctime.c",
    "src/time/asctime_r.c",
    "src/time/clock.c",
    "src/time/clock_getcpuclockid.c",
    "src/time/clock_getres.c",
    "src/time/clock_gettime.c",
    "src/time/clock_nanosleep.c",
    "src/time/clock_settime.c",
    "src/time/ctime.c",
    "src/time/ctime_r.c",
    "src/time/difftime.c",
    "src/time/ftime.c",
    "src/time/getdate.c",
    "src/time/gettimeofday.c",
    "src/time/gmtime.c",
    "src/time/gmtime_r.c",
    "src/time/localtime.c",
    "src/time/localtime_r.c",
    "src/time/mktime.c",
    "src/time/nanosleep.c",
    "src/time/strftime.c",
    "src/time/strptime.c",
    "src/time/time.c",
    "src/time/timegm.c",
    "src/time/timer_create.c",
    "src/time/timer_delete.c",
    "src/time/timer_getoverrun.c",
    "src/time/timer_gettime.c",
    "src/time/timer_settime.c",
    "src/time/times.c",
    "src/time/timespec_get.c",
    "src/time/utime.c",
    "src/time/wcsftime.c",
    "src/unistd/_exit.c",
    "src/unistd/access.c",
    "src/unistd/acct.c",
    "src/unistd/alarm.c",
    "src/unistd/chdir.c",
    "src/unistd/chown.c",
    "src/unistd/close.c",
    "src/unistd/ctermid.c",
    "src/unistd/dup.c",
    "src/unistd/dup2.c",
    "src/unistd/dup3.c",
    "src/unistd/faccessat.c",
    "src/unistd/fchdir.c",
    "src/unistd/fchown.c",
    "src/unistd/fchownat.c",
    "src/unistd/fdatasync.c",
    "src/unistd/fsync.c",
    "src/unistd/ftruncate.c",
    "src/unistd/getcwd.c",
    "src/unistd/getegid.c",
    "src/unistd/geteuid.c",
    "src/unistd/getgid.c",
    "src/unistd/getgroups.c",
    "src/unistd/gethostname.c",
    "src/unistd/getlogin.c",
    "src/unistd/getlogin_r.c",
    "src/unistd/getpgid.c",
    "src/unistd/getpgrp.c",
    "src/unistd/getpid.c",
    "src/unistd/getppid.c",
    "src/unistd/getsid.c",
    "src/unistd/getuid.c",
    "src/unistd/isatty.c",
    "src/unistd/lchown.c",
    "src/unistd/link.c",
    "src/unistd/linkat.c",
    "src/unistd/lseek.c",
    "src/unistd/nice.c",
    "src/unistd/pause.c",
    "src/unistd/pipe.c",
    "src/unistd/pipe2.c",
    "src/unistd/posix_close.c",
    "src/unistd/pread.c",
    "src/unistd/preadv.c",
    "src/unistd/pwrite.c",
    "src/unistd/pwritev.c",
    "src/unistd/read.c",
    "src/unistd/readlink.c",
    "src/unistd/readlinkat.c",
    "src/unistd/readv.c",
    "src/unistd/renameat.c",
    "src/unistd/rmdir.c",
    "src/unistd/setegid.c",
    "src/unistd/seteuid.c",
    "src/unistd/setgid.c",
    "src/unistd/setpgid.c",
    "src/unistd/setpgrp.c",
    "src/unistd/setregid.c",
    "src/unistd/setresgid.c",
    "src/unistd/setresuid.c",
    "src/unistd/setreuid.c",
    "src/unistd/setsid.c",
    "src/unistd/setuid.c",
    "src/unistd/setxid.c",
    "src/unistd/sleep.c",
    "src/unistd/symlink.c",
    "src/unistd/symlinkat.c",
    "src/unistd/sync.c",
    "src/unistd/tcgetpgrp.c",
    "src/unistd/tcsetpgrp.c",
    "src/unistd/truncate.c",
    "src/unistd/ttyname.c",
    "src/unistd/ttyname_r.c",
    "src/unistd/ualarm.c",
    "src/unistd/unlink.c",
    "src/unistd/unlinkat.c",
    "src/unistd/usleep.c",
    "src/unistd/write.c",
    "src/unistd/writev.c",
};

const musl_x86_64_source_files = [_][]const u8{
    "src/fenv/x86_64/fenv.s",
    "src/ldso/x86_64/dlsym.s",
    "src/ldso/x86_64/tlsdesc.s",
    "src/math/x86_64/__invtrigl.s",
    "src/math/x86_64/acosl.s",
    "src/math/x86_64/asinl.s",
    "src/math/x86_64/atan2l.s",
    "src/math/x86_64/atanl.s",
    "src/math/x86_64/ceill.s",
    "src/math/x86_64/exp2l.s",
    "src/math/x86_64/expl.s",
    "src/math/x86_64/expm1l.s",
    "src/math/x86_64/fabs.c",
    "src/math/x86_64/fabsf.c",
    "src/math/x86_64/fabsl.c",
    "src/math/x86_64/floorl.s",
    "src/math/x86_64/fma.c",
    "src/math/x86_64/fmaf.c",
    "src/math/x86_64/fmodl.c",
    "src/math/x86_64/llrint.c",
    "src/math/x86_64/llrintf.c",
    "src/math/x86_64/llrintl.c",
    "src/math/x86_64/log10l.s",
    "src/math/x86_64/log1pl.s",
    "src/math/x86_64/log2l.s",
    "src/math/x86_64/logl.s",
    "src/math/x86_64/lrint.c",
    "src/math/x86_64/lrintf.c",
    "src/math/x86_64/lrintl.c",
    "src/math/x86_64/remainderl.c",
    "src/math/x86_64/remquol.c",
    "src/math/x86_64/rintl.c",
    "src/math/x86_64/sqrt.c",
    "src/math/x86_64/sqrtf.c",
    "src/math/x86_64/sqrtl.c",
    "src/math/x86_64/truncl.s",
    "src/process/x86_64/vfork.s",
    "src/setjmp/x86_64/longjmp.s",
    "src/setjmp/x86_64/setjmp.s",
    "src/signal/x86_64/restore.s",
    "src/signal/x86_64/sigsetjmp.s",
    "src/string/x86_64/memcpy.s",
    "src/string/x86_64/memmove.s",
    "src/string/x86_64/memset.s",
    "src/thread/x86_64/__set_thread_area.s",
    "src/thread/x86_64/__unmapself.s",
    "src/thread/x86_64/clone.s",
    "src/thread/x86_64/syscall_cp.s",
};

const musl_arch_files = [_][]const u8{
    "src/fenv/aarch64/fenv.s",
    "src/fenv/arm/fenv-hf.S",
    "src/fenv/arm/fenv.c",
    "src/fenv/i386/fenv.s",
    "src/fenv/m68k/fenv.c",
    "src/fenv/mips/fenv-sf.c",
    "src/fenv/mips/fenv.S",
    "src/fenv/mips64/fenv-sf.c",
    "src/fenv/mips64/fenv.S",
    "src/fenv/mipsn32/fenv-sf.c",
    "src/fenv/mipsn32/fenv.S",
    "src/fenv/powerpc/fenv-sf.c",
    "src/fenv/powerpc/fenv.S",
    "src/fenv/powerpc64/fenv.c",
    "src/fenv/riscv64/fenv-sf.c",
    "src/fenv/riscv64/fenv.S",
    "src/fenv/s390x/fenv.c",
    "src/fenv/sh/fenv-nofpu.c",
    "src/fenv/sh/fenv.S",
    "src/fenv/x32/fenv.s",
    "src/internal/i386/defsysinfo.s",
    "src/internal/sh/__shcall.c",
    "src/ldso/aarch64/dlsym.s",
    "src/ldso/aarch64/tlsdesc.s",
    "src/ldso/arm/dlsym.s",
    "src/ldso/arm/dlsym_time64.S",
    "src/ldso/arm/find_exidx.c",
    "src/ldso/arm/tlsdesc.S",
    "src/ldso/i386/dlsym.s",
    "src/ldso/i386/dlsym_time64.S",
    "src/ldso/i386/tlsdesc.s",
    "src/ldso/m68k/dlsym.s",
    "src/ldso/m68k/dlsym_time64.S",
    "src/ldso/microblaze/dlsym.s",
    "src/ldso/microblaze/dlsym_time64.S",
    "src/ldso/mips/dlsym.s",
    "src/ldso/mips/dlsym_time64.S",
    "src/ldso/mips64/dlsym.s",
    "src/ldso/mipsn32/dlsym.s",
    "src/ldso/mipsn32/dlsym_time64.S",
    "src/ldso/or1k/dlsym.s",
    "src/ldso/or1k/dlsym_time64.S",
    "src/ldso/powerpc/dlsym.s",
    "src/ldso/powerpc/dlsym_time64.S",
    "src/ldso/powerpc64/dlsym.s",
    "src/ldso/riscv64/dlsym.s",
    "src/ldso/s390x/dlsym.s",
    "src/ldso/sh/dlsym.s",
    "src/ldso/sh/dlsym_time64.S",
    "src/ldso/tlsdesc.c",
    "src/ldso/x32/dlsym.s",
    "src/linux/x32/sysinfo.c",
    "src/math/aarch64/ceil.c",
    "src/math/aarch64/ceilf.c",
    "src/math/aarch64/fabs.c",
    "src/math/aarch64/fabsf.c",
    "src/math/aarch64/floor.c",
    "src/math/aarch64/floorf.c",
    "src/math/aarch64/fma.c",
    "src/math/aarch64/fmaf.c",
    "src/math/aarch64/fmax.c",
    "src/math/aarch64/fmaxf.c",
    "src/math/aarch64/fmin.c",
    "src/math/aarch64/fminf.c",
    "src/math/aarch64/llrint.c",
    "src/math/aarch64/llrintf.c",
    "src/math/aarch64/llround.c",
    "src/math/aarch64/llroundf.c",
    "src/math/aarch64/lrint.c",
    "src/math/aarch64/lrintf.c",
    "src/math/aarch64/lround.c",
    "src/math/aarch64/lroundf.c",
    "src/math/aarch64/nearbyint.c",
    "src/math/aarch64/nearbyintf.c",
    "src/math/aarch64/rint.c",
    "src/math/aarch64/rintf.c",
    "src/math/aarch64/round.c",
    "src/math/aarch64/roundf.c",
    "src/math/aarch64/sqrt.c",
    "src/math/aarch64/sqrtf.c",
    "src/math/aarch64/trunc.c",
    "src/math/aarch64/truncf.c",
    "src/math/arm/fabs.c",
    "src/math/arm/fabsf.c",
    "src/math/arm/fma.c",
    "src/math/arm/fmaf.c",
    "src/math/arm/sqrt.c",
    "src/math/arm/sqrtf.c",
    "src/math/i386/__invtrigl.s",
    "src/math/i386/acos.s",
    "src/math/i386/acosf.s",
    "src/math/i386/acosl.s",
    "src/math/i386/asin.s",
    "src/math/i386/asinf.s",
    "src/math/i386/asinl.s",
    "src/math/i386/atan.s",
    "src/math/i386/atan2.s",
    "src/math/i386/atan2f.s",
    "src/math/i386/atan2l.s",
    "src/math/i386/atanf.s",
    "src/math/i386/atanl.s",
    "src/math/i386/ceil.s",
    "src/math/i386/ceilf.s",
    "src/math/i386/ceill.s",
    "src/math/i386/exp2l.s",
    "src/math/i386/exp_ld.s",
    "src/math/i386/expl.s",
    "src/math/i386/expm1l.s",
    "src/math/i386/fabs.c",
    "src/math/i386/fabsf.c",
    "src/math/i386/fabsl.c",
    "src/math/i386/floor.s",
    "src/math/i386/floorf.s",
    "src/math/i386/floorl.s",
    "src/math/i386/fmod.c",
    "src/math/i386/fmodf.c",
    "src/math/i386/fmodl.c",
    "src/math/i386/hypot.s",
    "src/math/i386/hypotf.s",
    "src/math/i386/ldexp.s",
    "src/math/i386/ldexpf.s",
    "src/math/i386/ldexpl.s",
    "src/math/i386/llrint.c",
    "src/math/i386/llrintf.c",
    "src/math/i386/llrintl.c",
    "src/math/i386/log.s",
    "src/math/i386/log10.s",
    "src/math/i386/log10f.s",
    "src/math/i386/log10l.s",
    "src/math/i386/log1p.s",
    "src/math/i386/log1pf.s",
    "src/math/i386/log1pl.s",
    "src/math/i386/log2.s",
    "src/math/i386/log2f.s",
    "src/math/i386/log2l.s",
    "src/math/i386/logf.s",
    "src/math/i386/logl.s",
    "src/math/i386/lrint.c",
    "src/math/i386/lrintf.c",
    "src/math/i386/lrintl.c",
    "src/math/i386/remainder.c",
    "src/math/i386/remainderf.c",
    "src/math/i386/remainderl.c",
    "src/math/i386/remquo.s",
    "src/math/i386/remquof.s",
    "src/math/i386/remquol.s",
    "src/math/i386/rint.c",
    "src/math/i386/rintf.c",
    "src/math/i386/rintl.c",
    "src/math/i386/scalbln.s",
    "src/math/i386/scalblnf.s",
    "src/math/i386/scalblnl.s",
    "src/math/i386/scalbn.s",
    "src/math/i386/scalbnf.s",
    "src/math/i386/scalbnl.s",
    "src/math/i386/sqrt.c",
    "src/math/i386/sqrtf.c",
    "src/math/i386/sqrtl.c",
    "src/math/i386/trunc.s",
    "src/math/i386/truncf.s",
    "src/math/i386/truncl.s",
    "src/math/m68k/sqrtl.c",
    "src/math/mips/fabs.c",
    "src/math/mips/fabsf.c",
    "src/math/mips/sqrt.c",
    "src/math/mips/sqrtf.c",
    "src/math/powerpc/fabs.c",
    "src/math/powerpc/fabsf.c",
    "src/math/powerpc/fma.c",
    "src/math/powerpc/fmaf.c",
    "src/math/powerpc/sqrt.c",
    "src/math/powerpc/sqrtf.c",
    "src/math/powerpc64/ceil.c",
    "src/math/powerpc64/ceilf.c",
    "src/math/powerpc64/fabs.c",
    "src/math/powerpc64/fabsf.c",
    "src/math/powerpc64/floor.c",
    "src/math/powerpc64/floorf.c",
    "src/math/powerpc64/fma.c",
    "src/math/powerpc64/fmaf.c",
    "src/math/powerpc64/fmax.c",
    "src/math/powerpc64/fmaxf.c",
    "src/math/powerpc64/fmin.c",
    "src/math/powerpc64/fminf.c",
    "src/math/powerpc64/lrint.c",
    "src/math/powerpc64/lrintf.c",
    "src/math/powerpc64/lround.c",
    "src/math/powerpc64/lroundf.c",
    "src/math/powerpc64/round.c",
    "src/math/powerpc64/roundf.c",
    "src/math/powerpc64/sqrt.c",
    "src/math/powerpc64/sqrtf.c",
    "src/math/powerpc64/trunc.c",
    "src/math/powerpc64/truncf.c",
    "src/math/riscv64/copysign.c",
    "src/math/riscv64/copysignf.c",
    "src/math/riscv64/fabs.c",
    "src/math/riscv64/fabsf.c",
    "src/math/riscv64/fma.c",
    "src/math/riscv64/fmaf.c",
    "src/math/riscv64/fmax.c",
    "src/math/riscv64/fmaxf.c",
    "src/math/riscv64/fmin.c",
    "src/math/riscv64/fminf.c",
    "src/math/riscv64/sqrt.c",
    "src/math/riscv64/sqrtf.c",
    "src/math/s390x/ceil.c",
    "src/math/s390x/ceilf.c",
    "src/math/s390x/ceill.c",
    "src/math/s390x/fabs.c",
    "src/math/s390x/fabsf.c",
    "src/math/s390x/fabsl.c",
    "src/math/s390x/floor.c",
    "src/math/s390x/floorf.c",
    "src/math/s390x/floorl.c",
    "src/math/s390x/fma.c",
    "src/math/s390x/fmaf.c",
    "src/math/s390x/nearbyint.c",
    "src/math/s390x/nearbyintf.c",
    "src/math/s390x/nearbyintl.c",
    "src/math/s390x/rint.c",
    "src/math/s390x/rintf.c",
    "src/math/s390x/rintl.c",
    "src/math/s390x/round.c",
    "src/math/s390x/roundf.c",
    "src/math/s390x/roundl.c",
    "src/math/s390x/sqrt.c",
    "src/math/s390x/sqrtf.c",
    "src/math/s390x/sqrtl.c",
    "src/math/s390x/trunc.c",
    "src/math/s390x/truncf.c",
    "src/math/s390x/truncl.c",
    "src/math/x32/__invtrigl.s",
    "src/math/x32/acosl.s",
    "src/math/x32/asinl.s",
    "src/math/x32/atan2l.s",
    "src/math/x32/atanl.s",
    "src/math/x32/ceill.s",
    "src/math/x32/exp2l.s",
    "src/math/x32/expl.s",
    "src/math/x32/expm1l.s",
    "src/math/x32/fabs.s",
    "src/math/x32/fabsf.s",
    "src/math/x32/fabsl.s",
    "src/math/x32/floorl.s",
    "src/math/x32/fma.c",
    "src/math/x32/fmaf.c",
    "src/math/x32/fmodl.s",
    "src/math/x32/llrint.s",
    "src/math/x32/llrintf.s",
    "src/math/x32/llrintl.s",
    "src/math/x32/log10l.s",
    "src/math/x32/log1pl.s",
    "src/math/x32/log2l.s",
    "src/math/x32/logl.s",
    "src/math/x32/lrint.s",
    "src/math/x32/lrintf.s",
    "src/math/x32/lrintl.s",
    "src/math/x32/remainderl.s",
    "src/math/x32/rintl.s",
    "src/math/x32/sqrt.s",
    "src/math/x32/sqrtf.s",
    "src/math/x32/sqrtl.s",
    "src/math/x32/truncl.s",
    "src/process/aarch64/vfork.s",
    "src/process/arm/vfork.s",
    "src/process/i386/vfork.s",
    "src/process/riscv64/vfork.s",
    "src/process/s390x/vfork.s",
    "src/process/sh/vfork.s",
    "src/process/system.c",
    "src/process/vfork.c",
    "src/process/wait.c",
    "src/process/waitid.c",
    "src/process/waitpid.c",
    "src/process/x32/vfork.s",
    "src/setjmp/aarch64/longjmp.s",
    "src/setjmp/aarch64/setjmp.s",
    "src/setjmp/arm/longjmp.S",
    "src/setjmp/arm/setjmp.S",
    "src/setjmp/i386/longjmp.s",
    "src/setjmp/i386/setjmp.s",
    "src/setjmp/m68k/longjmp.s",
    "src/setjmp/m68k/setjmp.s",
    "src/setjmp/microblaze/longjmp.s",
    "src/setjmp/microblaze/setjmp.s",
    "src/setjmp/mips/longjmp.S",
    "src/setjmp/mips/setjmp.S",
    "src/setjmp/mips64/longjmp.S",
    "src/setjmp/mips64/setjmp.S",
    "src/setjmp/mipsn32/longjmp.S",
    "src/setjmp/mipsn32/setjmp.S",
    "src/setjmp/or1k/longjmp.s",
    "src/setjmp/or1k/setjmp.s",
    "src/setjmp/powerpc/longjmp.S",
    "src/setjmp/powerpc/setjmp.S",
    "src/setjmp/powerpc64/longjmp.s",
    "src/setjmp/powerpc64/setjmp.s",
    "src/setjmp/riscv64/longjmp.S",
    "src/setjmp/riscv64/setjmp.S",
    "src/setjmp/s390x/longjmp.s",
    "src/setjmp/s390x/setjmp.s",
    "src/setjmp/sh/longjmp.S",
    "src/setjmp/sh/setjmp.S",
    "src/setjmp/x32/longjmp.s",
    "src/setjmp/x32/setjmp.s",
    "src/signal/aarch64/restore.s",
    "src/signal/aarch64/sigsetjmp.s",
    "src/signal/arm/restore.s",
    "src/signal/arm/sigsetjmp.s",
    "src/signal/i386/restore.s",
    "src/signal/i386/sigsetjmp.s",
    "src/signal/m68k/sigsetjmp.s",
    "src/signal/microblaze/restore.s",
    "src/signal/microblaze/sigsetjmp.s",
    "src/signal/mips/sigsetjmp.s",
    "src/signal/mips64/sigsetjmp.s",
    "src/signal/mipsn32/sigsetjmp.s",
    "src/signal/or1k/sigsetjmp.s",
    "src/signal/powerpc/restore.s",
    "src/signal/powerpc/sigsetjmp.s",
    "src/signal/powerpc64/restore.s",
    "src/signal/powerpc64/sigsetjmp.s",
    "src/signal/riscv64/restore.s",
    "src/signal/riscv64/sigsetjmp.s",
    "src/signal/s390x/restore.s",
    "src/signal/s390x/sigsetjmp.s",
    "src/signal/setitimer.c",
    "src/signal/sh/restore.s",
    "src/signal/sh/sigsetjmp.s",
    "src/signal/x32/getitimer.c",
    "src/signal/x32/restore.s",
    "src/signal/x32/setitimer.c",
    "src/signal/x32/sigsetjmp.s",
    "src/string/aarch64/memcpy.S",
    "src/string/aarch64/memset.S",
    "src/string/arm/__aeabi_memcpy.s",
    "src/string/arm/__aeabi_memset.s",
    "src/string/arm/memcpy.S",
    "src/string/i386/memcpy.s",
    "src/string/i386/memmove.s",
    "src/string/i386/memset.s",
    "src/thread/aarch64/__set_thread_area.s",
    "src/thread/aarch64/__unmapself.s",
    "src/thread/aarch64/clone.s",
    "src/thread/aarch64/syscall_cp.s",
    "src/thread/arm/__aeabi_read_tp.s",
    "src/thread/arm/__set_thread_area.c",
    "src/thread/arm/__unmapself.s",
    "src/thread/arm/atomics.s",
    "src/thread/arm/clone.s",
    "src/thread/arm/syscall_cp.s",
    "src/thread/i386/__set_thread_area.s",
    "src/thread/i386/__unmapself.s",
    "src/thread/i386/clone.s",
    "src/thread/i386/syscall_cp.s",
    "src/thread/i386/tls.s",
    "src/thread/m68k/__m68k_read_tp.s",
    "src/thread/m68k/clone.s",
    "src/thread/m68k/syscall_cp.s",
    "src/thread/microblaze/__set_thread_area.s",
    "src/thread/microblaze/__unmapself.s",
    "src/thread/microblaze/clone.s",
    "src/thread/microblaze/syscall_cp.s",
    "src/thread/mips/__unmapself.s",
    "src/thread/mips/clone.s",
    "src/thread/mips/syscall_cp.s",
    "src/thread/mips64/__unmapself.s",
    "src/thread/mips64/clone.s",
    "src/thread/mips64/syscall_cp.s",
    "src/thread/mipsn32/__unmapself.s",
    "src/thread/mipsn32/clone.s",
    "src/thread/mipsn32/syscall_cp.s",
    "src/thread/or1k/__set_thread_area.s",
    "src/thread/or1k/__unmapself.s",
    "src/thread/or1k/clone.s",
    "src/thread/or1k/syscall_cp.s",
    "src/thread/powerpc/__set_thread_area.s",
    "src/thread/powerpc/__unmapself.s",
    "src/thread/powerpc/clone.s",
    "src/thread/powerpc/syscall_cp.s",
    "src/thread/powerpc64/__set_thread_area.s",
    "src/thread/powerpc64/__unmapself.s",
    "src/thread/powerpc64/clone.s",
    "src/thread/powerpc64/syscall_cp.s",
    "src/thread/riscv64/__set_thread_area.s",
    "src/thread/riscv64/__unmapself.s",
    "src/thread/riscv64/clone.s",
    "src/thread/riscv64/syscall_cp.s",
    "src/thread/s390x/__set_thread_area.s",
    "src/thread/s390x/__tls_get_offset.s",
    "src/thread/s390x/__unmapself.s",
    "src/thread/s390x/clone.s",
    "src/thread/s390x/syscall_cp.s",
    "src/thread/sh/__set_thread_area.c",
    "src/thread/sh/__unmapself.c",
    "src/thread/sh/__unmapself_mmu.s",
    "src/thread/sh/atomics.s",
    "src/thread/sh/clone.s",
    "src/thread/sh/syscall_cp.s",
    "src/thread/x32/__set_thread_area.s",
    "src/thread/x32/__unmapself.s",
    "src/thread/x32/clone.s",
    "src/thread/x32/syscall_cp.s",
    "src/unistd/mips/pipe.s",
    "src/unistd/mips64/pipe.s",
    "src/unistd/mipsn32/lseek.c",
    "src/unistd/mipsn32/pipe.s",
    "src/unistd/sh/pipe.s",
    "src/unistd/x32/lseek.c",
};


fn argsCopyZ(alloc: Allocator, args: []const []const u8) ![:null]?[*:0]u8 {
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
fn clangMain(allocator: Allocator, arguments: []const []const u8) !u8 {
    const argv = try argsCopyZ(allocator, arguments);
    const exit_code = NativityClangMain(@as(c_int, @intCast(arguments.len)), argv.ptr);
    return @as(u8, @bitCast(@as(i8, @truncate(exit_code))));
}

const ExecutableOptions = struct {
    is_test: bool,
};

const Arch = enum{
    x86_64,
    aarch64,
};

const Os = enum{
    linux,
    macos,
};

const Abi = enum{
    none,
    gnu,
    musl,
};

pub fn buildExecutable(context: *const Context, arguments: [][*:0]u8, options: ExecutableOptions) !void {
    var maybe_executable_path: ?[]const u8 = null;
    var maybe_main_package_path: ?[]const u8 = null;
    var arch: Arch = undefined;
    var os: Os = undefined;
    var abi: Abi = undefined;

    switch (@import("builtin").os.tag) {
        .linux => {
            arch = .x86_64;
            os = .linux;
            abi = .gnu;
        },
        .macos => {
            arch = .aarch64;
            os = .macos;
            abi = .none;
        },
        else => unreachable,
    }

    var maybe_only_parse: ?bool = null;
    var link_libc = false;
    var maybe_executable_name: ?[]const u8 = null;
    const generate_debug_information = true;

    if (arguments.len == 0) return error.InvalidInput;

    var i: usize = 0;
    while (i < arguments.len) : (i += 1) {
        const current_argument = span(arguments[i]);
        if (byte_equal(current_argument, "-o")) {
            if (i + 1 != arguments.len) {
                maybe_executable_path = span(arguments[i + 1]);
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

                const arg = span(arguments[i]);
                maybe_main_package_path = arg;
                maybe_only_parse = true;
            } else {
                reportUnterminatedArgumentError(current_argument);
            }
        } else if (byte_equal(current_argument, "-link_libc")) {
            if (i + 1 != arguments.len) {
                i += 1;

                const arg = span(arguments[i]);
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

                const arg = span(arguments[i]);
                maybe_main_package_path = arg;
            } else {
                reportUnterminatedArgumentError(current_argument);
            }
        } else if (byte_equal(current_argument, "-name")) {
            if (i + 1 != arguments.len) {
                i += 1;

                const arg = span(arguments[i]);
                maybe_executable_name = arg;
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

    const unit = try context.allocator.create(Unit);
    unit.* = .{
        .descriptor = .{
            .main_package_path = main_package_path,
            .executable_path = executable_path,
            .only_parse = only_parse,
            .arch = arch,
            .os = os,
            .abi = abi,
            .link_libc = switch (os) {
                .linux => link_libc,
                .macos => true,
                // .windows => link_libc,
                // else => unreachable,
            },
            .generate_debug_information = generate_debug_information,
            .name = executable_name,
            .is_test = options.is_test,
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
    dependencies: MyHashMap([]const u8, *Package) = .{},

    fn addDependency(package: *Package, allocator: *MyAllocator, package_name: []const u8, new_dependency: *Package) !void {
        try package.dependencies.put_no_clobber(allocator, package_name, new_dependency);
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

// fn getWriter() !std.fs.File.Writer {
//     const stdout = std.io.getStdOut();
//     return stdout.writer();
// }

// fn shouldLog(comptime logger_scope: LoggerScope, logger: getLoggerScopeType(logger_scope).Logger) bool {
//     return logger_bitset.contains(logger_scope) and getLoggerScopeType(logger_scope).Logger.bitset.contains(logger);
// }

// pub fn logln(comptime logger_scope: LoggerScope, logger: getLoggerScopeType(logger_scope).Logger, comptime format: []const u8, arguments: anytype) void {
//     if (shouldLog(logger_scope, logger)) {
//         log(logger_scope, logger, format, arguments);
//         const writer = try getWriter();
//         writer.writeByte('\n') catch unreachable;
//     }
// }

// pub fn log(comptime logger_scope: LoggerScope, logger: getLoggerScopeType(logger_scope).Logger, comptime format: []const u8, arguments: anytype) void {
//     if (shouldLog(logger_scope, logger)) {
//         std.fmt.format(try getWriter(), format, arguments) catch unreachable;
//     }
// }

pub fn panic(message: []const u8, stack_trace: ?*std.builtin.StackTrace, return_address: ?usize) noreturn {
    const print_stack_trace = @import("configuration").print_stack_trace;
    switch (print_stack_trace) {
        true => @call(.always_inline, std.builtin.default_panic, .{ message, stack_trace, return_address }),
        false => {
            // const writer = try getWriter();
            // writer.writeAll("\nPANIC: ") catch {};
            // writer.writeAll(message) catch {};
            // writer.writeByte('\n') catch {};
            @breakpoint();
            std.os.abort();
        },
    }
}

const TypeCheckSwitchEnums = struct {
    switch_case_groups: UnpinnedArray(UnpinnedArray(Enum.Field.Index)),
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
        .bool => 1,
        .integer => |integer| integer.bit_count,
        .@"struct" => |struct_index| {
            const struct_type = unit.structs.get(struct_index);
            switch (struct_type.optional) {
                false => switch (struct_type.backing_type) {
                    .null => {
                        var bit_size: u32 = 0;
                        for (struct_type.fields.slice()) |field_index| {
                            const field = unit.struct_fields.get(field_index);
                            const field_type = unit.types.get(field.type);
                            const field_bit_size = field_type.getBitSize(unit);
                            bit_size += field_bit_size;
                        }
                        return bit_size;
                    },
                    else => unreachable,
                },
                true => unreachable,
            }
        },
        .pointer => 64,
        .@"enum" => |enum_index| b: {
            const enum_type = unit.enums.get(enum_index);
            const backing_type = unit.types.get(enum_type.backing_type);
            break :b getTypeBitSize(backing_type, unit);
        },
        .slice => 2 * @bitSizeOf(usize),
        .void => 0,
        else => |t| @panic(@tagName(t)),
    };
}

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
    @"union": Type.Union.Index,
    @"error": Type.Error.Index,
    error_union: Type.Error.Union,
    error_set: Type.Error.Set.Index,

    pub fn getBitSize(ty: *Type, unit: *Unit) u32 {
        return getTypeBitSize(ty, unit);
    }

    fn getByteSize(ty: *Type, unit: *Unit) u32 {
        _ = unit; // autofix
        return switch (ty.*) {
            .integer => |integer| @divExact(integer.bit_count, @bitSizeOf(u8)),
            else => |t| @panic(@tagName(t)),
        };
    }

    fn getScope(ty: *Type, unit: *Unit) *Debug.Scope {
        return switch (ty.*) {
            .@"struct" => |struct_index| &unit.structs.get(struct_index).scope.scope,
            .@"enum" => |enum_index| &unit.enums.get(enum_index).scope.scope,
            .@"error" => |error_index| &unit.errors.get(error_index).scope.scope,
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
    };

    const Error = struct {
        fields: UnpinnedArray(Type.Error.Field.Index) = .{},
        scope: Debug.Scope.Global,
        backing_type: Type.Index,

        pub const List = BlockList(@This(), enum {});
        pub usingnamespace @This().List.Index;

        const Field = struct {
            name: u32,
            type: Type.Index,
            value: usize,

            pub const List = BlockList(@This(), enum {});
            pub usingnamespace @This().List.Index;
        };

        const Set = struct {
            values: UnpinnedArray(Type.Index) = .{}, // Empty means all errors
            pub const List = BlockList(@This(), enum {});
            pub usingnamespace @This().List.Index;
        };

        const Union = struct {
            @"error": Type.Index,
            type: Type.Index,
            pub const List = BlockList(@This(), enum {});
            pub usingnamespace @This().List.Index;
        };
    };

    const Union = struct {
        fields: UnpinnedArray(Struct.Field.Index) = .{},
        scope: Debug.Scope.Global,
        is_tagged: bool,
        pub const List = BlockList(@This(), enum {});
        pub usingnamespace @This().List.Index;
    };

    const Integer = struct {
        bit_count: u16,
        signedness: Signedness,

        pub const Signedness = enum(u1) {
            unsigned = 0,
            signed = 1,
        };
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
            .usize = .{
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
    add_overflow: AddOverflow,
    argument_declaration: *Debug.Declaration.Argument,
    branch: Branch,
    block: Debug.Block.Index,
    // TODO
    call: Instruction.Call,
    cast: Cast,
    debug_checkpoint: DebugCheckPoint,
    debug_declare_local_variable: DebugDeclareLocalVariable,
    extract_value: ExtractValue,
    insert_value: InsertValue,
    get_element_pointer: GEP,
    inline_assembly: InlineAssembly.Index,
    integer_compare: IntegerCompare,
    integer_binary_operation: Instruction.IntegerBinaryOperation,
    jump: Jump,
    load: Load,
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
    trap,
    @"unreachable",

    const Phi = struct {
        values: UnpinnedArray(V) = .{},
        basic_blocks: UnpinnedArray(BasicBlock.Index) = .{},
        type: Type.Index,
    };

    const Min = struct {
        left: V,
        right: V,
        type: Type.Index,
    };

    pub const GEP = struct {
        pointer: Instruction.Index,
        base_type: Type.Index,
        is_struct: bool,
        index: V,
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
            slice_var_to_const,
            slice_to_nullable,
            slice_to_not_null,
            slice_coerce_to_zero_termination,
            truncate,
            pointer_to_array_to_pointer_to_many,
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
    };

    const StackSlot = struct {
        type: Type.Index,
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

    pub const List = BlockList(@This(), enum {});
    pub usingnamespace @This().List.Index;
};

pub const BasicBlock = struct {
    instructions: UnpinnedArray(Instruction.Index) = .{},
    predecessor: BasicBlock.Index = .null,
    // TODO: not use a bool
    terminated: bool = false,

    pub const List = BlockList(@This(), enum {});
    pub usingnamespace @This().List.Index;
};

pub const Function = struct {
    pub const Attribute = enum {
        cc,
        naked,
        @"extern",
    };

    pub const Definition = struct {
        scope: Debug.Scope.Function,
        basic_blocks: UnpinnedArray(BasicBlock.Index) = .{},
        // TODO: make this more efficient
        type: Type.Index,
        body: Debug.Block.Index,

        pub const List = BlockList(@This(), enum {});
        pub usingnamespace @This().List.Index;
    };

    pub const CallingConvention = enum {
        c,
        auto,
    };

    pub const Prototype = struct {
        argument_types: []const Type.Index,
        return_type: Type.Index,
        attributes: Attributes,
        calling_convention: CallingConvention,

        const Attributes = struct {
            naked: bool,
        };

        const List = BlockList(@This(), enum {});
        pub usingnamespace @This().List.Index;
    };
};

pub const Struct = struct {
    fields: UnpinnedArray(Struct.Field.Index) = .{},
    scope: Debug.Scope.Global,
    backing_type: Type.Index,
    type: Type.Index,
    optional: bool,

    pub const Field = struct {
        name: u32,
        type: Type.Index,
        default_value: ?V.Comptime,

        const List = BlockList(@This(), enum {});
        pub usingnamespace @This().List.Index;
    };

    const List = BlockList(@This(), enum {});
    pub usingnamespace @This().List.Index;
};

pub const Context = struct {
    allocator: Allocator,
    my_allocator: *MyAllocator,
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
    return if (a.len != 0 and b.len != 0) try std.mem.concat(context.allocator, u8, &.{a, "/", b}) else b;
}

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
        type: Type.Index,
        bool: bool,
        comptime_int: ComptimeInt,
        constant_int: ConstantInt,
        function_declaration: Type.Index,
        enum_value: Enum.Field.Index,
        error_value: Type.Error.Field.Index,
        function_definition: Function.Definition.Index,
        global: *Debug.Declaration.Global,
        constant_backed_struct: u64,
        constant_struct: ConstantStruct.Index,
        constant_array: ConstantArray.Index,
        constant_slice: ConstantSlice.Index,
        string_literal: u32,
        null_pointer,

        pub const ConstantSlice = struct {
            array: *Debug.Declaration.Global,
            start: usize,
            end: usize,
            type: Type.Index,

            pub const List = BlockList(@This(), enum {});
            pub usingnamespace List.Index;
        };

        pub const ConstantArray = struct {
            values: []const V.Comptime,
            type: Type.Index,

            pub const List = BlockList(@This(), enum {});
            pub usingnamespace List.Index;
        };

        pub const ConstantStruct = struct {
            fields: []const V.Comptime,
            type: Type.Index,

            pub const List = BlockList(@This(), enum {});
            pub usingnamespace List.Index;
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

            pub const List = BlockList(@This(), enum {});
            pub usingnamespace List.Index;

            pub fn getFunctionDefinitionIndex(global: *Global) Function.Definition.Index {
                return global.initial_value.function_definition;
            }
        };

        pub const Local = struct {
            declaration: Declaration,
            init_value: V,
            pub const List = BlockList(@This(), enum {});
            pub usingnamespace List.Index;
        };
        pub const Argument = struct {
            declaration: Declaration,

            pub const List = BlockList(@This(), enum {});
            pub usingnamespace List.Index;
        };
    };

    pub const Scope = struct {
        declarations: MyHashMap(u32, *Declaration) = .{},
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
            local_declaration_map: MyHashMap(*Debug.Declaration.Local, Instruction.Index) = .{},
        };

        pub const Global = struct {
            scope: Scope,
        };

        pub const Function = struct {
            scope: Scope,
            argument_map: MyHashMap(*Debug.Declaration.Argument, Instruction.Index) = .{},
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
                    const file = @fieldParentPtr(File, "scope", s);
                    const file_index = unit.files.indexOf(file);
                    return file_index;
                }
            } else @panic("No parent file scope");
        }

        pub const Kind = enum {
            compilation_unit,
            file,
            file_container,
            container,
            function, // Arguments
            block,
        };
    };

    pub const Block = struct {
        scope: Scope.Local,
        pub const List = BlockList(@This(), enum {});
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

        pub const List = BlockList(@This(), enum {});
        pub usingnamespace List.Index;

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
    @"error",
    int_to_pointer,
    import,
    min,
    size,
    sign_extend,
    syscall,
    trap,
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
    exit_blocks: UnpinnedArray(BasicBlock.Index) = .{},
    loop_exit_block: BasicBlock.Index = .null,
    return_phi: Instruction.Index = .null,
    return_block: BasicBlock.Index = .null,
    last_check_point: struct {
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
            const name = try join_name(context, "_anon_arr_", unit.global_array_constants.length, 10);
            const identifier = try unit.processIdentifier(context, name);
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

            try unit.global_array_constants.put_no_clobber(context.my_allocator, constant_array_index, global_declaration);

            return global_declaration;
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
        const slice = data_structures.format_int(buffer[0..len], number, base, false);
        const ptr = slice.ptr - name.len;
        const new_slice = ptr[0..slice.len + name.len];
        @memcpy(new_slice[0..name.len], name);
        buffer[len] = 0;
        return @ptrCast(try context.my_allocator.duplicate_bytes(new_slice));
    }

    fn processStringLiteralFromStringAndDebugInfo(builder: *Builder, unit: *Unit, context: *const Context, string: [:0]const u8, debug_info: TokenDebugInfo) !*Debug.Declaration.Global {
        const possible_id = unit.string_literal_values.length;
        const hash = try unit.processIdentifier(context, string);
        if (unit.string_literal_globals.get(hash)) |v| {
            return v;
        } else {
            const string_name = try join_name(context, "__anon_str_", possible_id, 10);
            const identifier = try unit.processIdentifier(context, string_name);
            try unit.string_literal_values.put_no_clobber(context.my_allocator, hash, string);

            const string_global_index = try unit.global_declarations.append(context.my_allocator, .{
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

            const string_global = unit.global_declarations.get(string_global_index);

            try unit.string_literal_globals.put_no_clobber(context.my_allocator, hash, string_global);

            try unit.data_to_emit.append(context.my_allocator, string_global);

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

                var instructions = try UnpinnedArray(InlineAssembly.Instruction.Index).initialize_with_capacity(context.my_allocator, @intCast(argument_node_list.len));

                for (argument_node_list) |assembly_statement_node_index| {
                    const assembly_statement_node = unit.getNode(assembly_statement_node_index);
                    const instruction_name = unit.getExpectedTokenBytes(assembly_statement_node.token, .identifier);
                    const instruction = inline for (@typeInfo(architecture.Instruction).Enum.fields) |instruction_enum_field| {
                        if (byte_equal(instruction_name, instruction_enum_field.name)) {
                            break @field(architecture.Instruction, instruction_enum_field.name);
                        }
                    } else unreachable;
                    const operand_nodes = unit.getNodeList(assembly_statement_node.left);

                    var operands = try UnpinnedArray(InlineAssembly.Operand).initialize_with_capacity(context.my_allocator, @intCast(operand_nodes.len));

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
                            .identifier => b: {
                                const identifier = unit.getExpectedTokenBytes(operand_node.token, .identifier);
                                const result = try builder.resolveIdentifier(unit, context, Type.Expect.none, identifier, .left);

                                break :b .{
                                    .value = result,
                                };
                            },
                            else => |t| @panic(@tagName(t)),
                        };

                        operands.append_with_capacity(operand);
                    }

                    const instruction_index = try unit.assembly_instructions.append(context.my_allocator, .{
                        .id = @intFromEnum(instruction),
                        .operands = operands.slice(),
                    });

                    instructions.append_with_capacity(instruction_index);
                }

                const inline_assembly = try unit.inline_assembly.append(context.my_allocator, .{
                    .instructions = instructions.slice(),
                });

                const inline_asm = try unit.instructions.append(context.my_allocator, .{
                    .inline_assembly = inline_assembly,
                });
                try builder.appendInstruction(unit, context, inline_asm);

                return .{
                    .value = .{
                        .runtime = inline_asm,
                    },
                    // TODO: WARN fix
                    .type = .noreturn,
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
                                switch (source_type.*) {
                                    .integer => |source_integer| {
                                        _ = source_integer; // autofix
                                        // TODO:
                                        break :b .int_to_pointer;
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
                                                if (destination_pointer.termination != source_pointer.termination) {
                                                    unreachable;
                                                }
                                                unreachable;
                                            } else {
                                                break :b .pointer_const_to_var;
                                            }
                                        } else {
                                            unreachable;
                                        }
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
                                    .@"struct" => |struct_index| {
                                        const struct_type = unit.structs.get(struct_index);
                                        if (struct_type.backing_type != .null) {
                                            if (struct_type.backing_type == type_index) {
                                                break :b .bitcast;
                                            } else {
                                                unreachable;
                                            }
                                        } else {
                                            unreachable;
                                        }
                                    },
                                    else => |t| @panic(@tagName(t)),
                                }
                            },
                            .@"struct" => |struct_index| {
                                const struct_type = unit.structs.get(struct_index);
                                if (struct_type.optional) {
                                    assert(struct_type.backing_type == .null);
                                    unreachable;
                                } else {
                                    switch (struct_type.backing_type) {
                                        .null => unreachable,
                                        else => unreachable,
                                    }
                                }
                            },
                            else => |t| @panic(@tagName(t)),
                        }
                    },
                    else => |t| @panic(@tagName(t)),
                };

                const instruction = try unit.instructions.append(context.my_allocator, .{
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
                    .none => .usize,
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
                    var instruction_list = try UnpinnedArray(V).initialize_with_capacity(context.my_allocator, @intCast(argument_node_list.len));
                    // TODO
                    const arg_type_expect = Type.Expect{
                        .type = Type.Index.usize,
                    };

                    for (argument_node_list) |argument_node_index| {
                        const argument_value = try builder.resolveRuntimeValue(unit, context, arg_type_expect, argument_node_index, .right);
                        instruction_list.append_with_capacity(argument_value);
                    }

                    const syscall = try unit.instructions.append(context.my_allocator, .{
                        .syscall = .{
                            .arguments = instruction_list.slice(),
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
                                const min = try unit.instructions.append(context.my_allocator, instruction);
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
            .@"error" => {
                assert(argument_node_list.len == 1);
                // TODO: type
                // const value = try builder.resolveComptimeValue(unit, context, Type.Expect.none, .{}, argument_node_list[0], null);
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
            .add_overflow => {
                assert(argument_node_list.len == 2);
                const left = try builder.resolveRuntimeValue(unit, context, type_expect, argument_node_list[0], .right);
                const right_type_expect = switch (type_expect) {
                    .none => Type.Expect{ .type = left.type },
                    else => type_expect,
                };
                const right = try builder.resolveRuntimeValue(unit, context, right_type_expect, argument_node_list[1], .right);

                const add_overflow = try unit.instructions.append(context.my_allocator, .{
                    .add_overflow = .{
                        .left = left,
                        .right = right,
                        .type = left.type,
                    },
                });
                try builder.appendInstruction(unit, context, add_overflow);

                const result_type = try unit.getOptionalType(context, left.type);

                const extract_value = try unit.instructions.append(context.my_allocator, .{
                    .extract_value = .{
                        .expression = .{
                            .value = .{
                                .runtime = add_overflow,
                            },
                            .type = result_type,
                        },
                        .index = 1,
                    },
                });
                try builder.appendInstruction(unit, context, extract_value);

                const carry = try builder.newBasicBlock(unit, context);
                const normal = try builder.newBasicBlock(unit, context);

                try builder.branch(unit, context, extract_value, carry, normal);
                builder.current_basic_block = carry;

                try builder.buildRet(unit, context, .{
                    .value = .{
                        .@"comptime" = .{
                            .constant_int = .{
                                .value = 1,
                            },
                        },
                    },
                    .type = left.type,
                });

                builder.current_basic_block = normal;

                const result_extract_value = try unit.instructions.append(context.my_allocator, .{
                    .extract_value = .{
                        .expression = .{
                            .value = .{
                                .runtime = add_overflow,
                            },
                            .type = result_type,
                        },
                        .index = 0,
                    },
                });
                try builder.appendInstruction(unit, context, result_extract_value);

                return V{
                    .value = .{
                        .runtime = result_extract_value,
                    },
                    .type = left.type,
                };
            },
            else => |t| @panic(@tagName(t)),
        }
    }

    fn pushScope(builder: *Builder, unit: *Unit, context: *const Context, new_scope: *Debug.Scope) !void {
        const old_scope = builder.current_scope;

        assert(@intFromEnum(old_scope.kind) <= @intFromEnum(new_scope.kind));

        if (builder.current_basic_block != .null) {
            assert(@intFromEnum(old_scope.kind) >= @intFromEnum(Debug.Scope.Kind.function));
            const instruction = try unit.instructions.append(context.my_allocator, .{
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
            const instruction = try unit.instructions.append(context.my_allocator, .{
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
        file.status = .analyzing;

        const previous_file = builder.current_file;
        builder.current_file = file_index;
        defer builder.current_file = previous_file;

        try builder.pushScope(unit, context, &file.scope.scope);
        defer builder.popScope(unit, context) catch unreachable;

        const main_node_index = file.parser.main_node_index;

        // File type already assigned
        _ = try builder.resolveContainerType(unit, context, main_node_index, .@"struct", null);
        file.status = .analyzed;
        assert(file.type != .null);
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

    fn getTokenDebugInfo(builder: *Builder, unit: *Unit, token: Token.Index) TokenDebugInfo {
        const file = unit.files.get(builder.current_file);
        const index = Token.unwrap(token);
        assert(index < unit.token_buffer.length);
        const line_offset_index = unit.token_buffer.lines[index];
        const line = line_offset_index - file.lexer.line_offset;
        const offset = unit.token_buffer.offsets[index];
        assert(line_offset_index < unit.token_buffer.line_offsets.length);
        const line_offset = unit.token_buffer.line_offsets.pointer[line_offset_index];
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
                const instruction = try unit.instructions.append(context.my_allocator, .{
                    .debug_checkpoint = .{
                        .scope = builder.current_scope,
                        .line = debug_info.line,
                        .column = debug_info.column,
                    },
                });
                try basic_block.instructions.append(context.my_allocator, instruction);

                builder.last_check_point = .{
                    .scope = builder.current_scope,
                    .line = debug_info.line,
                    .column = debug_info.column,
                };
            }
        }
    }

    fn appendInstruction(builder: *Builder, unit: *Unit, context: *const Context, instruction_index: Instruction.Index) !void {
        // if (@intFromEnum(instruction_index) == 366) @breakpoint();
        switch (unit.instructions.get(instruction_index).*) {
            .extract_value => |extract_value| switch (unit.types.get(extract_value.expression.type).*) {
                .pointer => unreachable,
                else => {},
            },
            else => {},
        }
        const basic_block = unit.basic_blocks.get(builder.current_basic_block);
        if (!basic_block.terminated) {
            try basic_block.instructions.append(context.my_allocator, instruction_index);
        } else {
            const instruction = unit.instructions.get(instruction_index);
            assert(instruction.* == .pop_scope);
            try basic_block.instructions.insert(context.my_allocator, basic_block.instructions.length - 1, instruction_index);
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

    fn referenceGlobalDeclaration(builder: *Builder, unit: *Unit, context: *const Context, scope: *Debug.Scope, declaration: *Debug.Declaration) !*Debug.Declaration.Global {
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

                global_declaration.initial_value = try builder.resolveComptimeValue(unit, context, type_expect, global_declaration.attributes, declaration_node_index, global_declaration);

                switch (declaration.type) {
                    .null => {
                        assert(global_declaration.type_node_index == .null);
                        declaration.type = global_declaration.initial_value.getType(unit);
                    },
                    else => {},
                }

                switch (global_declaration.initial_value) {
                    .function_definition => |function_definition_index| {
                        switch (unit.getNode(declaration_node_index).id) {
                            .function_definition => try unit.code_to_emit.put_no_clobber(context.my_allocator, function_definition_index, global_declaration),
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
                            .function_prototype => try unit.external_functions.put_no_clobber(context.my_allocator, function_type, global_declaration),
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
                        unit.type_declarations.put(context.my_allocator, type_index, global_declaration) catch {
                            assert(unit.type_declarations.get(type_index).? == global_declaration);
                        };
                    },
                    else => {
                        if (global_declaration.attributes.contains(.@"export") or declaration.mutability == .@"var") {
                            try unit.data_to_emit.append(context.my_allocator, global_declaration);
                        }
                    },
                }
            },
            else => {},
        }

        builder.endContextSwitch(old_context);

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
        const file_index = import_file.file.index;
        const file = unit.files.get(file_index);

        if (file.status == .not_loaded) {
            try unit.generateAbstractSyntaxTreeForFile(context, file_index);
        }

        if (file.status == .parsed) {
            try builder.analyzeFile(unit, context, file_index);
        }

        assert(file.type != .null);

        return file_index;
    }

    const ComptimeEvaluationError = error{
        cannot_evaluate,
    };

    /// Last value is used to cache types being analyzed so we dont hit stack overflow
    fn resolveComptimeValue(builder: *Builder, unit: *Unit, context: *const Context, type_expect: Type.Expect, global_attributes: Debug.Declaration.Global.Attributes, node_index: Node.Index, maybe_global: ?*Debug.Declaration.Global) anyerror!V.Comptime {
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
                const result = try builder.resolveFieldAccess(unit, context, type_expect, node_index, .right);
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

                const function_type_index = try builder.resolveFunctionPrototype(unit, context, function_prototype_node_index, global_attributes);

                const old_function = builder.current_function;
                const token_debug_info = builder.getTokenDebugInfo(unit, node.token);
                builder.current_function = try unit.function_definitions.append(context.my_allocator, .{
                    .type = function_type_index,
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

                const function_prototype_index = unit.types.get(function_type_index).function;
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
                            @panic("Symbol already in scope");
                            // std.debug.panic("Symbol with name '{s}' already declarared on scope", .{argument_name});
                        }

                        const argument_token_debug_info = builder.getTokenDebugInfo(unit, argument_node.token);
                        const argument_declaration_index = try unit.argument_declarations.append(context.my_allocator, .{
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

                        try builder.current_scope.declarations.put_no_clobber(context.my_allocator, argument_name_hash, &argument.declaration);

                        const argument_instruction = try unit.instructions.append(context.my_allocator, .{
                            .argument_declaration = argument,
                        });

                        try builder.appendInstruction(unit, context, argument_instruction);

                        try function.scope.argument_map.put_no_clobber(context.my_allocator, argument, argument_instruction);
                    }
                }

                if (body_node.id == .block) {
                    function.body = try builder.resolveBlock(unit, context, body_node_index);

                    const cbb = unit.basic_blocks.get(builder.current_basic_block);
                    const function_prototype = unit.function_prototypes.get(function_prototype_index);
                    const return_type = function_prototype.return_type;

                    if (!cbb.terminated) {
                        if (builder.return_block == .null) {
                            switch (function_prototype.attributes.naked) {
                                true => {
                                    assert(return_type == .noreturn);
                                    try builder.buildTrap(unit, context);
                                },
                                false => switch (return_type) {
                                    .void => {
                                        try builder.buildRet(unit, context, .{
                                            .value = .{
                                                .@"comptime" = .void,
                                            },
                                            .type = .void,
                                        });
                                    },
                                    .noreturn => {
                                        try builder.buildTrap(unit, context);
                                    },
                                    else => switch (unit.types.get(return_type).*) {
                                        .error_union => |error_union| switch (error_union.type) {
                                            .void => {
                                                const undefined_value = V{
                                                    .value = .{
                                                        .@"comptime" = .undefined,
                                                    },
                                                    .type = return_type,
                                                };
                                                const insert = try unit.instructions.append(context.my_allocator, .{
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
                                                try builder.appendInstruction(unit, context, insert);

                                                try builder.buildRet(unit, context, .{
                                                    .value = .{
                                                        .runtime = insert,
                                                    },
                                                    .type = return_type,
                                                });
                                            },
                                            else => unreachable,
                                        },
                                        else => |t| @panic(@tagName(t)),
                                    },
                                },
                            }
                        } else {
                            assert(builder.return_phi != .null);
                            assert(builder.return_block != builder.current_basic_block);

                            const phi = &unit.instructions.get(builder.return_phi).phi;

                            switch (return_type) {
                                .void => unreachable,
                                .noreturn => unreachable,
                                else => switch (unit.types.get(return_type).*) {
                                    .error_union => |error_union| {
                                        if (error_union.type == .void) {
                                            const return_value = try unit.instructions.append(context.my_allocator, .{
                                                .insert_value = .{
                                                    .expression = .{
                                                        .value = .{
                                                            .@"comptime" = .undefined,
                                                        },
                                                        .type = return_type,
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
                                            try builder.appendInstruction(unit, context, return_value);

                                            try phi.values.append(context.my_allocator, .{
                                                .value = .{
                                                    .runtime = return_value,
                                                },
                                                .type = return_type,
                                            });
                                            try phi.basic_blocks.append(context.my_allocator, builder.current_basic_block);

                                            try builder.jump(unit, context, builder.return_block);
                                        } else if (error_union.type == .noreturn) {
                                            unreachable;
                                        } else {
                                            unreachable;
                                        }
                                    },
                                    else => {},
                                },
                            }
                        }
                    }

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
                const type_index = try builder.resolveContainerType(unit, context, node_index, .@"enum", maybe_global);
                return .{
                    .type = type_index,
                };
            },
            .struct_type => {
                const type_index = try builder.resolveContainerType(unit, context, node_index, .@"struct", maybe_global);
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
                const side: Side = switch (type_expect) {
                    .none => unreachable,
                    .type => |type_index| switch (unit.types.get(type_index).*) {
                        .type => .right,
                        .integer => .right,
                        else => |t| @panic(@tagName(t)),
                    },
                    else => unreachable,
                };
                const resolved_value = try builder.resolveIdentifier(unit, context, type_expect, identifier, side);
                return switch (resolved_value.value) {
                    .@"comptime" => |ct| ct,
                    .runtime => return error.cannot_evaluate,
                    else => unreachable,
                };
            },
            .signed_integer_type => {
                const result = try builder.resolveIntegerType(unit, context, node_index);
                return .{
                    .type = result,
                };
            },
            .compare_greater_equal => {
                const left = try builder.resolveComptimeValue(unit, context, Type.Expect.none, .{}, node.left, null);
                const left_type = left.getType(unit);
                const right = try builder.resolveComptimeValue(unit, context, Type.Expect{ .type = left_type }, .{}, node.right, null);
                _ = right; // autofix
                unreachable;
            },
            .add => {
                const left = try builder.resolveComptimeValue(unit, context, Type.Expect.none, .{}, node.left, null);
                const left_type = left.getType(unit);
                const right = try builder.resolveComptimeValue(unit, context, Type.Expect{ .type = left_type }, .{}, node.right, null);
                switch (left) {
                    .comptime_int => |left_ct_int| {
                        assert(left_ct_int.signedness == .unsigned);
                        const left_value = left_ct_int.value;
                        switch (right) {
                            .comptime_int => |right_ct_int| {
                                assert(right_ct_int.signedness == .unsigned);
                                const right_value = right_ct_int.value;
                                const result = left_value + right_value;
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
                const container_type = try builder.resolveType(unit, context, node.left);
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
                const function_prototype = try builder.resolveFunctionPrototype(unit, context, node_index, global_attributes);
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
                assert(node.right == .null);
                const nodes = unit.getNodeList(node.left);
                if (nodes.len == 0) {
                    unreachable;
                }

                const token_debug_info = builder.getTokenDebugInfo(unit, node.token);

                const error_index = try unit.errors.append(context.my_allocator, .{
                    .fields = try UnpinnedArray(Type.Error.Field.Index).initialize_with_capacity(context.my_allocator, @intCast(nodes.len)),
                    .scope = .{
                        .scope = .{
                            .file = builder.current_file,
                            .line = token_debug_info.line,
                            .column = token_debug_info.column,
                            .kind = .container,
                            .local = false,
                            .level = builder.current_scope.level + 1,
                        },
                    },
                    .backing_type = .u32,
                });
                const new_error = unit.errors.get(error_index);
                const error_type_index = try unit.types.append(context.my_allocator, .{
                    .@"error" = error_index,
                });

                for (nodes, 0..) |field_node_index, index| {
                    const field_node = unit.getNode(field_node_index);
                    const identifier = unit.getExpectedTokenBytes(field_node.token, .identifier);
                    const hash = try unit.processIdentifier(context, identifier);
                    const error_field_index = try unit.error_fields.append(context.my_allocator, .{
                        .name = hash,
                        .type = error_type_index,
                        .value = index,
                    });
                    new_error.fields.append_with_capacity(error_field_index);
                }

                return .{
                    .type = error_type_index,
                };
            },
            else => |t| @panic(@tagName(t)),
        }
    }

    fn referenceArgumentDeclaration(builder: *Builder, unit: *Unit, context: *const Context, scope: *Debug.Scope, declaration: *Debug.Declaration) !V {
        _ = builder; // autofix
        assert(declaration.kind == .argument);
        assert(scope.kind == .function);

        const argument_declaration = @fieldParentPtr(Debug.Declaration.Argument, "declaration", declaration);
        const function_scope = @fieldParentPtr(Debug.Scope.Function, "scope", scope);
        const instruction_index = function_scope.argument_map.get(argument_declaration).?;

        return .{
            .value = .{
                .runtime = instruction_index,
            },
            .type = try unit.getPointerType(context, .{
                .type = declaration.type,
                .termination = .none,
                .mutability = .@"const",
                .many = false,
                .nullable = false,
            }),
        };
    }

    fn referenceLocalDeclaration(builder: *Builder, unit: *Unit, context: *const Context, scope: *Debug.Scope, declaration: *Debug.Declaration) !V {
        _ = builder; // autofix
        assert(declaration.kind == .local);
        assert(scope.kind == .block);

        const local_declaration = @fieldParentPtr(Debug.Declaration.Local, "declaration", declaration);
        const local_scope = @fieldParentPtr(Debug.Scope.Local, "scope", scope);
        if (local_scope.local_declaration_map.get(local_declaration)) |instruction_index| {
            return .{
                .value = .{
                    .runtime = instruction_index,
                },
                .type = try unit.getPointerType(context, .{
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
        materialize_int,
        optional_wrap,
        sign_extend,
        zero_extend,
        error_to_error_union,
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
                .integer => |destination_integer| {
                    switch (source.*) {
                        .integer => |source_integer| {
                            if (destination_integer.signedness == source_integer.signedness) {
                                if (destination_integer.bit_count == source_integer.bit_count) {
                                    if (destination_type_index == .usize and source_type_index == .u64) {
                                        return .success;
                                    } else if (destination_type_index == .u64 and source_type_index == .usize) {
                                        return .success;
                                    } else if (destination_type_index == .ssize and source_type_index == .s64) {
                                        return .success;
                                    } else if (destination_type_index == .s64 and source_type_index == .ssize) {
                                        return .success;
                                    } else {
                                        unreachable;
                                    }
                                } else if (destination_integer.bit_count > source_integer.bit_count) {
                                    return switch (destination_integer.signedness) {
                                        .signed => .sign_extend,
                                        .unsigned => .zero_extend,
                                    };
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
                                    } else {
                                        if (destination_slice.nullable and !source_slice.nullable) {
                                            assert(destination_slice.mutability == source_slice.mutability);
                                            return .slice_to_nullable;
                                        }
                                    }
                                } else {
                                    if (destination_slice.termination == .none) {
                                        return .slice_coerce_to_zero_termination;
                                    } else {
                                        unreachable;
                                    }
                                }
                            } else {
                                unreachable;
                            }

                            unreachable;
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
                                    // std.debug.panic("Expected {s} array termination, got {s}", .{ @tagName(destination_array.termination), @tagName(source_array.termination) });
                                }
                            } else unreachable;
                        },
                        else => |t| @panic(@tagName(t)),
                    }
                },
                .error_union => |error_union| {
                    if (error_union.@"error" == source_type_index) {
                        return .error_to_error_union;
                    } else {
                        unreachable;
                    }
                },
                .bool => {
                    switch (source.*) {
                        else => |t| @panic(@tagName(t)),
                    }
                },
                .comptime_int => {
                    switch (source.*) {
                        .integer => |integer| {
                            _ = integer; // autofix
                            @panic("WTF");
                        },
                        else => |t| @panic(@tagName(t)),
                    }
                },
                else => |t| @panic(@tagName(t)),
            }
        }
    }

    const Side = enum {
        left,
        right,
    };

    fn resolveIdentifier(builder: *Builder, unit: *Unit, context: *const Context, type_expect: Type.Expect, identifier: []const u8, side: Side) !V {
        const hash = try unit.processIdentifier(context, identifier);

        const look_in_parent_scopes = true;
        if (builder.current_scope.lookupDeclaration(hash, look_in_parent_scopes)) |lookup| {
            // TODO: we could do this better
            // const scope = lookup.scope;
            const v: V = switch (lookup.scope.kind) {
                .file_container,
                .file,
                .container,
                => b: {
                    const global = try builder.referenceGlobalDeclaration(unit, context, lookup.scope, lookup.declaration);
                    const pointer_to_global = try unit.getPointerType(context, .{
                        .type = global.declaration.type,
                        .termination = switch (type_expect) {
                            .none => .none,
                            .type => |type_index| switch (unit.types.get(type_index).*) {
                                .pointer => |pointer| pointer.termination,
                                else => .none,
                            },
                            else => unreachable,
                        },
                        .mutability = switch (type_expect) {
                            .none => .@"var",
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
                                const load = try unit.instructions.append(context.my_allocator, .{
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

                                try builder.appendInstruction(unit, context, load);

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
                        .function => try builder.referenceArgumentDeclaration(unit, context, lookup.scope, lookup.declaration),
                        .block => try builder.referenceLocalDeclaration(unit, context, lookup.scope, lookup.declaration),
                        else => unreachable,
                    };
                    const v: V = switch (preliminary_result.value) {
                        .runtime => switch (side) {
                            .left => preliminary_result,
                            .right => b: {
                                const instruction = try unit.instructions.append(context.my_allocator, .{
                                    .load = .{
                                        .value = preliminary_result,
                                        .type = lookup.declaration.type,
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
                            const zero_extend = try unit.instructions.append(context.my_allocator, .{
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
                            const sign_extend = try unit.instructions.append(context.my_allocator, .{
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
                            const cast_to_const = try unit.instructions.append(context.my_allocator, .{
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
                        .slice_coerce_to_zero_termination => {
                            const cast_to_zero_termination = try unit.instructions.append(context.my_allocator, .{
                                .cast = .{
                                    .id = .slice_coerce_to_zero_termination,
                                    .value = v,
                                    .type = expected_type_index,
                                },
                            });
                            try builder.appendInstruction(unit, context, cast_to_zero_termination);

                            return .{
                                .value = .{
                                    .runtime = cast_to_zero_termination,
                                },
                                .type = expected_type_index,
                            };
                        },
                        .slice_var_to_const => {
                            const cast_to_const = try unit.instructions.append(context.my_allocator, .{
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
                        .slice_to_nullable => {
                            const cast = try unit.instructions.append(context.my_allocator, .{
                                .cast = .{
                                    .id = .slice_to_nullable,
                                    .value = v,
                                    .type = expected_type_index,
                                },
                            });

                            try builder.appendInstruction(unit, context, cast);
                            return .{
                                .value = .{
                                    .runtime = cast,
                                },
                                .type = expected_type_index,
                            };
                        },
                        .pointer_to_nullable => {
                            const cast = try unit.instructions.append(context.my_allocator, .{
                                .cast = .{
                                    .id = .pointer_to_nullable,
                                    .value = v,
                                    .type = expected_type_index,
                                },
                            });

                            try builder.appendInstruction(unit, context, cast);
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
                                .@"struct" => |struct_index| {
                                    assert(unit.structs.get(struct_index).optional);
                                    const optional_undefined = V{
                                        .value = .{
                                            .@"comptime" = .undefined,
                                        },
                                        .type = optional_type_index,
                                    };

                                    const insert_value_to_optional = try unit.instructions.append(context.my_allocator, .{
                                        .insert_value = .{
                                            .expression = optional_undefined,
                                            .index = 0,
                                            .new_value = v,
                                        },
                                    });

                                    try builder.appendInstruction(unit, context, insert_value_to_optional);

                                    const final_insert = try unit.instructions.append(context.my_allocator, .{
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
                        .error_to_error_union => {
                            unreachable;
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

                    const typecheck_result = try builder.typecheck(unit, context, array_type, lookup.declaration.type);
                    switch (typecheck_result) {
                        .success => return v,
                        else => |t| @panic(@tagName(t)),
                    }
                },
                else => |t| @panic(@tagName(t)),
            }
        } else {
            // var scope_it: ?*Debug.Scope = builder.current_scope;
            // const indentation_size = 4;
            // var indentation: u32 = 0;
            //
            // var file_path: []const u8 = "";
            // while (scope_it) |scope| : (scope_it = scope.parent) {
            //     for (0..indentation * indentation_size) |_| {
            //         std.debug.print(" ", .{});
            //     }
            //     std.debug.print("> Scope {s} ", .{@tagName(scope.kind)});
            //     switch (scope.kind) {
            //         .compilation_unit => {},
            //         .file_container, .container => {},
            //         .function => {},
            //         .file => {
            //             const global_scope = @fieldParentPtr(Debug.Scope.Global, "scope", scope);
            //             const file = @fieldParentPtr(Debug.File, "scope", global_scope);
            //             std.debug.print("{s}", .{file.relative_path});
            //             file_path = file.relative_path;
            //         },
            //         .block => {},
            //     }
            //
            //     std.debug.print("\n", .{});
            //     indentation += 1;
            // }


            @panic("identifier not found");
            //std.debug.panic("Identifier '{s}' not found in file {s}", .{ identifier, file_path });
        }
    }

    fn resolveAssignment(builder: *Builder, unit: *Unit, context: *const Context, node_index: Node.Index) !V {
        const node = unit.getNode(node_index);
        switch (node.id) {
            .assign, .add_assign, .sub_assign, .div_assign => {
                if (unit.getNode(node.left).id == .discard) {
                    const r = try builder.resolveRuntimeValue(unit, context, Type.Expect.none, node.right, .right);
                    return r;
                } else {
                    const left = try builder.resolveRuntimeValue(unit, context, Type.Expect.none, node.left, .left);
                    const expected_right_type = switch (left.value) {
                        .runtime => |instr_index| switch (unit.instructions.get(instr_index).*) {
                            // .global => |global| global.declaration.type,
                            .stack_slot => |stack_slot| stack_slot.type,
                            .get_element_pointer => |gep| gep.base_type,
                            else => |t| @panic(@tagName(t)),
                        },
                        .@"comptime" => |ct| switch (ct) {
                            .global => |global| global.declaration.type,
                            else => |t| @panic(@tagName(t)),
                        },
                        else => |t| @panic(@tagName(t)),
                    };
                    const right = try builder.resolveRuntimeValue(unit, context, Type.Expect{ .type = expected_right_type }, node.right, .right);
                    const value_to_store = switch (node.id) {
                        .assign => right,
                        else => blk: {
                            const left_load = try unit.instructions.append(context.my_allocator, .{
                                .load = .{
                                    .value = left,
                                    .type = expected_right_type,
                                },
                            });

                            try builder.appendInstruction(unit, context, left_load);

                            switch (unit.types.get(expected_right_type).*) {
                                .integer => |integer| {
                                    const instruction = try unit.instructions.append(context.my_allocator, .{
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
                                                else => |t| @panic(@tagName(t)),
                                            },
                                        },
                                    });
                                    try builder.appendInstruction(unit, context, instruction);

                                    break :blk V{
                                        .value = .{
                                            .runtime = instruction,
                                        },
                                        .type = expected_right_type,
                                    };
                                },
                                else => |t| @panic(@tagName(t)),
                            }
                        },
                    };
                    const store = try unit.instructions.append(context.my_allocator, .{
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

    fn newBasicBlock(builder: *Builder, unit: *Unit, context: *const Context) !BasicBlock.Index {
        const function = unit.function_definitions.get(builder.current_function);
        const entry_basic_block = try unit.basic_blocks.append(context.my_allocator, .{});
        try function.basic_blocks.append(context.my_allocator, entry_basic_block);

        return entry_basic_block;
    }

    fn resolveIntegerType(builder: *Builder, unit: *Unit, context: *const Context, node_index: Node.Index) anyerror!Type.Index {
        _ = builder; // autofix
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

    fn resolveArrayType(builder: *Builder, unit: *Unit, context: *const Context, node_index: Node.Index, size_hint: ?usize) !Type.Index {
        const node = unit.getNode(node_index);
        const attribute_node_list = unit.getNodeList(node.left);
        var termination = Type.Termination.none;
        const len_node = unit.getNode(attribute_node_list[0]);
        const len = switch (len_node.id) {
            else => switch (try builder.resolveComptimeValue(unit, context, Type.Expect{ .type = .usize }, .{}, attribute_node_list[0], null)) {
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
        const element_type = try builder.resolveType(unit, context, attribute_node_list[element_type_index]);
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
                const resolved_type_value = try builder.resolveComptimeValue(unit, context, Type.Expect{ .type = .type }, .{}, node_index, null);
                return resolved_type_value.type;
            },
            .bool_type => .bool,
            .ssize_type => .ssize,
            .signed_integer_type,
            .unsigned_integer_type,
            => b: {
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
                        .field_access,
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
            .function_prototype => try builder.resolveFunctionPrototype(unit, context, node_index, .{}),
            .error_union => blk: {
                assert(node.left != .null);
                assert(node.right != .null);

                const err = try builder.resolveType(unit, context, node.left);
                const ty = try builder.resolveType(unit, context, node.right);

                const error_union = try unit.types.append(context.my_allocator, .{
                    .error_union = .{
                        .@"error" = err,
                        .type = ty,
                    },
                });
                break :blk error_union;
            },
            .all_errors => blk: {
                const all_error_index = try unit.error_sets.append(context.my_allocator, .{});
                const all_errors = try unit.types.append(context.my_allocator, .{
                    .error_set = all_error_index,
                });
                break :blk all_errors;
            },
            else => |t| @panic(@tagName(t)),
        };

        return result;
    }

    fn resolveFunctionPrototype(builder: *Builder, unit: *Unit, context: *const Context, node_index: Node.Index, global_attributes: Debug.Declaration.Global.Attributes) !Type.Index {
        const node = unit.getNode(node_index);
        assert(node.id == .function_prototype);
        const attribute_and_return_type_node_list = unit.getNodeList(node.right);
        assert(attribute_and_return_type_node_list.len >= 1);
        const attribute_node_list = attribute_and_return_type_node_list[0 .. attribute_and_return_type_node_list.len - 1];
        const return_type_node_index = attribute_and_return_type_node_list[attribute_and_return_type_node_list.len - 1];

        const function_prototype_index = try unit.function_prototypes.append(context.my_allocator, .{
            .argument_types = &.{},
            .return_type = .null,
            .attributes = .{
                // .@"export" = false,
                .naked = false,
            },
            .calling_convention = switch (global_attributes.contains(.@"export") or global_attributes.contains(.@"extern")) {
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
            var argument_types = try UnpinnedArray(Type.Index).initialize_with_capacity(context.my_allocator, @intCast(argument_node_list.len));

            for (argument_node_list) |argument_node_index| {
                const argument_node = unit.getNode(argument_node_index);
                assert(argument_node.id == .argument_declaration);

                const argument_type_index = try builder.resolveType(unit, context, argument_node.left);
                argument_types.append_with_capacity(argument_type_index);
            }

            function_prototype.argument_types = argument_types.slice();
        }

        function_prototype.attributes = .{
            .naked = is_naked,
        };

        function_prototype.return_type = try builder.resolveType(unit, context, return_type_node_index);

        const function_prototype_type_index = try unit.types.append(context.my_allocator, .{
            .function = function_prototype_index,
        });

        return function_prototype_type_index;
    }

    fn resolveContainerType(builder: *Builder, unit: *Unit, context: *const Context, container_node_index: Node.Index, container_type: ContainerType, maybe_global: ?*Debug.Declaration.Global) !Type.Index {
        const current_basic_block = builder.current_basic_block;
        defer builder.current_basic_block = current_basic_block;
        builder.current_basic_block = .null;

        const container_node = unit.getNode(container_node_index);
        const container_nodes = unit.getNodeList(container_node.left);

        const Data = struct {
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
                const struct_index = try unit.structs.append(context.my_allocator, .{
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

                const type_index = try unit.types.append(context.my_allocator, .{
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
                    else => |t| @panic(@tagName(t)),
                }

                try unit.struct_type_map.put_no_clobber(context.my_allocator, struct_index, type_index);

                break :b .{
                    .scope = &struct_type.scope,
                    .type = type_index,
                };
            },
            .@"enum" => b: {
                assert(container_node.id == .enum_type);
                const enum_index = try unit.enums.append(context.my_allocator, .{
                    .scope = .{ .scope = .{
                        .kind = .container,
                        .line = token_debug_info.line,
                        .column = token_debug_info.column,
                        .level = builder.current_scope.level + 1,
                        .local = false,
                        .file = builder.current_file,
                    } },
                    .backing_type = backing_type,
                });

                const enum_type = unit.enums.get(enum_index);
                const type_index = try unit.types.append(context.my_allocator, .{
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
        if (maybe_global) |global| {
            global.declaration.type = .type;
            global.initial_value = .{
                .type = type_index,
            };
        }
        try builder.pushScope(unit, context, &scope.scope);
        defer builder.popScope(unit, context) catch unreachable;

        const count = blk: {
            var result: struct {
                fields: u32 = 0,
                declarations: u32 = 0,
                comptime_blocks: u32 = 0,
                test_declarations: u32 = 0,
            } = .{};

            for (container_nodes) |member_index| {
                const member = unit.getNode(member_index);
                switch (container_type) {
                    .@"struct" => assert(member.id != .enum_field),
                    .@"enum" => assert(member.id != .container_field),
                }

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

        var declaration_nodes = try UnpinnedArray(Node.Index).initialize_with_capacity(context.my_allocator, count.declarations);
        var field_nodes = try UnpinnedArray(Node.Index).initialize_with_capacity(context.my_allocator, count.fields);
        var comptime_block_nodes = try UnpinnedArray(Node.Index).initialize_with_capacity(context.my_allocator, count.comptime_blocks);
        var test_declarations = try UnpinnedArray(Node.Index).initialize_with_capacity(context.my_allocator, count.test_declarations);

        for (container_nodes) |member_index| {
            const member_node = unit.getNode(member_index);
            const member_type = getContainerMemberType(member_node.id);
            const array_list = switch (member_type) {
                .comptime_block => &comptime_block_nodes,
                .declaration => &declaration_nodes,
                .field => &field_nodes,
                .test_declaration => &test_declarations,
            };
            array_list.append_with_capacity(member_index);
        }

        if (count.declarations > 0) {
            for (declaration_nodes.slice()) |declaration_node_index| {
                const declaration_node = unit.getNode(declaration_node_index);

                switch (declaration_node.id) {
                    .constant_symbol_declaration,
                    .variable_symbol_declaration,
                    => {
                        const expected_identifier_token_index = Token.addInt(declaration_node.token, 1);
                        const identifier = unit.getExpectedTokenBytes(expected_identifier_token_index, .identifier);
                        // logln(.compilation, .identifier, "Analyzing global declaration {s}", .{identifier});
                        const identifier_hash = try unit.processIdentifier(context, identifier);

                        const look_in_parent_scopes = true;
                        if (builder.current_scope.lookupDeclaration(identifier_hash, look_in_parent_scopes)) |lookup_result| {
                            _ = lookup_result; // autofix
                            _ = UnpinnedArray; // autofix
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

                        const global_declaration_index = try unit.global_declarations.append(context.my_allocator, .{
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
                        try builder.current_scope.declarations.put_no_clobber(context.my_allocator, identifier_hash, &global_declaration.declaration);
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
                    const field_count = field_nodes.length;
                    try enum_type.fields.ensure_capacity(context.my_allocator, field_count);

                    if (enum_type.backing_type == .null) {
                        const bit_count = @bitSizeOf(@TypeOf(field_nodes.length)) - @clz(field_nodes.length);

                        enum_type.backing_type = try unit.getIntegerType(context, .{
                            .bit_count = bit_count,
                            .signedness = .unsigned,
                        });
                    }
                },
                .@"struct" => {
                    const struct_type = unit.structs.get(ty.@"struct");
                    const field_count = field_nodes.length;
                    try struct_type.fields.ensure_capacity(context.my_allocator, field_count);
                },
            }

            for (field_nodes.slice(), 0..) |field_node_index, index| {
                const field_node = unit.getNode(field_node_index);
                const identifier = unit.getExpectedTokenBytes(field_node.token, .identifier);
                const hash = try unit.processIdentifier(context, identifier);

                switch (container_type) {
                    .@"enum" => {
                        assert(field_node.id == .enum_field);
                        const enum_type = unit.enums.get(ty.@"enum");

                        const enum_value: usize = switch (field_node.left) {
                            .null => index,
                            else => b: {
                                const enum_value = try builder.resolveComptimeValue(unit, context, Type.Expect{
                                    .type = enum_type.backing_type,
                                }, .{}, field_node.left, null);
                                assert(enum_value.comptime_int.signedness == .unsigned);
                                break :b enum_value.comptime_int.value;
                            },
                        };

                        const enum_field_index = try unit.enum_fields.append(context.my_allocator, .{
                            .name = hash,
                            .value = enum_value,
                            .parent = type_index,
                        });
                        enum_type.fields.append_with_capacity(enum_field_index);
                    },
                    .@"struct" => {
                        assert(field_node.id == .container_field);
                        const struct_type = unit.structs.get(ty.@"struct");
                        const field_name = unit.getExpectedTokenBytes(field_node.token, .identifier);
                        const field_name_hash = try unit.processIdentifier(context, field_name);
                        const field_type = try builder.resolveType(unit, context, field_node.left);
                        const field_default_value: ?V.Comptime = switch (field_node.right) {
                            .null => null,
                            else => |default_value_node_index| try builder.resolveComptimeValue(unit, context, Type.Expect{ .type = field_type }, .{}, default_value_node_index, null),
                        };

                        const struct_field = try unit.struct_fields.append(context.my_allocator, .{
                            .name = field_name_hash,
                            .type = field_type,
                            .default_value = field_default_value,
                        });
                        struct_type.fields.append_with_capacity(struct_field);
                    },
                }
            }
        }

        if (count.comptime_blocks > 0) {
            const emit_ir = builder.emit_ir;
            builder.emit_ir = false;
            defer builder.emit_ir = emit_ir;

            for (comptime_block_nodes.slice()) |comptime_node_index| {
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
            for (test_declarations.slice()) |test_declaration_node_index| {
                const test_node = unit.getNode(test_declaration_node_index);
                assert(test_node.id == .test_declaration);

                const test_block = unit.getNode(test_node.left);
                assert(test_block.id == .block);

                const new_current_basic_block = builder.current_basic_block;
                defer builder.current_basic_block = new_current_basic_block;
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

                const test_name_global = if (test_node.right != .null) b: {
                    const test_name_node = unit.getNode(test_node.right);
                    const named_global = try builder.processStringLiteralFromToken(unit, context, test_name_node.token);
                    break :b named_global;
                } else b: {
                    const name = try join_name(context, "_anon_test_", unit.test_functions.length, 10);
                    const anon_global = try builder.processStringLiteralFromStringAndDebugInfo(unit, context, name, token_debug_info);
                    break :b anon_global;
                };

                const return_type = try unit.types.append(context.my_allocator, .{
                    .error_union = .{
                        .@"error" = try unit.types.append(context.my_allocator, .{
                            // This means all errors
                            .error_set = try unit.error_sets.append(context.my_allocator, .{}),
                        }),
                        .type = .void,
                    },
                });

                // TODO: make test function prototypes unique
                const function_prototype_index = try unit.function_prototypes.append(context.my_allocator, .{
                    .argument_types = &.{},
                    .return_type = return_type,
                    .attributes = .{
                        .naked = false,
                    },
                    .calling_convention = .auto,
                });
                const function_prototype = unit.function_prototypes.get(function_prototype_index);
                const function_type = try unit.types.append(context.my_allocator, .{
                    .function = function_prototype_index,
                });
                builder.current_function = try unit.function_definitions.append(context.my_allocator, .{
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
                    .type = function_type,
                    .body = undefined,
                });
                const function = unit.function_definitions.get(builder.current_function);

                builder.last_check_point = .{};
                assert(builder.current_scope.kind == .file_container or builder.current_scope.kind == .file or builder.current_scope.kind == .container);
                try builder.pushScope(unit, context, &function.scope.scope);
                defer builder.popScope(unit, context) catch unreachable;

                const entry_basic_block = try builder.newBasicBlock(unit, context);
                builder.current_basic_block = entry_basic_block;
                defer builder.current_basic_block = .null;

                try builder.insertDebugCheckPoint(unit, context, test_block.token);
                function.body = try builder.resolveBlock(unit, context, test_node.left);

                if (builder.return_block == .null) {
                    const cbb = unit.basic_blocks.get(builder.current_basic_block);

                    if (!cbb.terminated) {
                        switch (function_prototype.attributes.naked) {
                            true => {
                                assert(return_type == .noreturn);
                                unreachable;
                                //try builder.buildTrap(unit, context);
                            },
                            false => switch (return_type) {
                                .void => {
                                    try builder.buildRet(unit, context, .{
                                        .value = .{
                                            .@"comptime" = .void,
                                        },
                                        .type = .void,
                                    });
                                },
                                .noreturn => {
                                    try builder.buildTrap(unit, context);
                                },
                                else => switch (unit.types.get(return_type).*) {
                                    .error_union => |error_union| {
                                        if (error_union.type == .void) {
                                            const undef = V{
                                                .value = .{ .@"comptime" = .undefined },
                                                .type = return_type,
                                            };
                                            const insert_value = try unit.instructions.append(context.my_allocator, .{
                                                .insert_value = .{
                                                    .expression = undef,
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
                                            try builder.appendInstruction(unit, context, insert_value);

                                            try builder.buildRet(unit, context, .{
                                                .value = .{
                                                    .runtime = insert_value,
                                                },
                                                .type = return_type,
                                            });
                                        } else if (error_union.type == .noreturn) {
                                            unreachable;
                                            // try builder.buildTrap(unit, context);
                                        } else {
                                            unreachable;
                                        }
                                    },
                                    else => |t| @panic(@tagName(t)),
                                },
                            },
                        }
                    }
                }

                const name_hash = test_name_global.initial_value.string_literal;

                const test_global_index = try unit.global_declarations.append(context.my_allocator, .{
                    .declaration = .{
                        .scope = &scope.scope,
                        .type = function_type,
                        .name = name_hash,
                        .line = token_debug_info.line,
                        .column = token_debug_info.column,
                        .mutability = .@"const",
                        .kind = .global,
                    },
                    .initial_value = .{
                        .function_definition = builder.current_function,
                    },
                    .type_node_index = .null,
                    .attributes = .{},
                });
                const test_global = unit.global_declarations.get(test_global_index);
                try scope.scope.declarations.put_no_clobber(context.my_allocator, name_hash, &test_global.declaration);

                try unit.test_functions.put_no_clobber(context.my_allocator, test_name_global, test_global);

                try unit.code_to_emit.put_no_clobber(context.my_allocator, builder.current_function, test_global);
            }
        }

        return type_index;
    }

    fn emitIntegerCompare(builder: *Builder, unit: *Unit, context: *const Context, left_value: V, right_value: V, integer: Type.Integer, compare_node_id: Node.Id) anyerror!V {
        assert(left_value.type == right_value.type);
        const compare = try unit.instructions.append(context.my_allocator, .{
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
        try builder.appendInstruction(unit, context, compare);

        return .{
            .value = .{
                .runtime = compare,
            },
            .type = .bool,
        };
    }

    fn resolveRuntimeValue(builder: *Builder, unit: *Unit, context: *const Context, type_expect: Type.Expect, node_index: Node.Index, side: Side) anyerror!V {
        const node = unit.getNode(node_index);

        const v: V = switch (node.id) {
            .identifier => block: {
                const identifier = unit.getExpectedTokenBytes(node.token, .identifier);
                const result = try builder.resolveIdentifier(unit, context, type_expect, identifier, side);
                break :block result;
            },
            .intrinsic => try builder.resolveIntrinsic(unit, context, type_expect, node_index),
            .pointer_dereference => block: {
                // TODO:
                const pointer_type_expect = switch (type_expect) {
                    .none => unreachable, //type_expect,
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

                const load_type = switch (type_expect) {
                    .none => unreachable,
                    .type => |type_index| type_index,
                    else => unreachable,
                };

                const load = try unit.instructions.append(context.my_allocator, .{
                    .load = .{
                        .value = pointer_value,
                        .type = load_type,
                    },
                });
                try builder.appendInstruction(unit, context, load);

                break :block .{
                    .value = .{
                        .runtime = load,
                    },
                    .type = load_type,
                };
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
                        .integer => |integer| try builder.emitIntegerCompare(unit, context, left_value, right_value, integer, cmp_node_id),
                        .bool => try builder.emitIntegerCompare(unit, context, left_value, right_value, .{
                            .bit_count = 1,
                            .signedness = .unsigned,
                        }, cmp_node_id),
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
                                        const cast = try unit.instructions.append(context.my_allocator, .{
                                            .cast = .{
                                                .id = .pointer_to_nullable,
                                                .value = left_value,
                                                .type = right_value.type,
                                            },
                                        });
                                        try builder.appendInstruction(unit, context, cast);

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
                            }, cmp_node_id);

                            break :b compare;
                        },
                        else => |t| @panic(@tagName(t)),
                    };
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

                var left_value = try builder.resolveRuntimeValue(unit, context, left_expect_type, left_node_index, .right);
                switch (unit.types.get(left_value.type).*) {
                    .integer => {},
                    .comptime_int => {},
                    else => |t| @panic(@tagName(t)),
                }

                const right_expect_type: Type.Expect = switch (type_expect) {
                    .none => switch (unit.types.get(left_value.type).*) {
                        .comptime_int => type_expect,
                        else => Type.Expect{
                            .type = left_value.type,
                        },
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
                                .none => switch (binary_operation_id) {
                                    .bit_and,
                                    .bit_or,
                                    .bit_xor,
                                    .shift_right,
                                    .add,
                                    .sub,
                                    .mul,
                                    .div,
                                    .mod,
                                    => left_value.type,
                                    else => |t| @panic(@tagName(t)),
                                },
                                .type => |type_index| type_index,
                                else => unreachable,
                            };

                            const instruction = switch (unit.types.get(left_value.type).*) {
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

                                    const i = try unit.instructions.append(context.my_allocator, .{
                                        .integer_binary_operation = .{
                                            .left = left_value,
                                            .right = right_value,
                                            .id = id,
                                            .signedness = integer.signedness,
                                        },
                                    });
                                    break :b i;
                                },
                                .comptime_int => {
                                    const left = left_value.value.@"comptime".comptime_int;
                                    const right = right_value.value.@"comptime".comptime_int;
                                    switch (binary_operation_id) {
                                        .add => {
                                            assert(left.signedness == right.signedness);
                                            assert(left.signedness == .unsigned);
                                            if (true) unreachable;
                                            const value = left.value + right.value;
                                            break :block switch (type_expect) {
                                                .none => V{
                                                    .value = .{
                                                        .@"comptime" = .{
                                                            .comptime_int = .{
                                                                .value = value,
                                                                .signedness = left.signedness,
                                                            },
                                                        },
                                                    },
                                                    .type = .comptime_int,
                                                },
                                                else => |t| @panic(@tagName(t)),
                                            };
                                        },
                                        else => |t| @panic(@tagName(t)),
                                    }
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
                        else => |t| @panic(@tagName(t)),
                    };
                }
            },
            .call => try builder.resolveCall(unit, context, node_index),
            .field_access => try builder.resolveFieldAccess(unit, context, type_expect, node_index, side),
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
                        .comptime_int => V{
                            .value = .{
                                .@"comptime" = .{
                                    .comptime_int = .{
                                        .value = integer,
                                        .signedness = .unsigned,
                                    },
                                },
                            },
                            .type = type_index,
                        },
                        .error_union => |error_union| {
                            _ = error_union; // autofix
                            unreachable;
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
                const block_i = try unit.instructions.append(context.my_allocator, .{
                    .block = block,
                });

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
                const initialization_nodes = unit.getNodeList(node.right);
                const container_type_index = try builder.resolveType(unit, context, node.left);

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
            .enum_literal => block: {
                switch (type_expect) {
                    .type => |type_index| {
                        const expected_type = unit.types.get(type_index);
                        switch (expected_type.*) {
                            .@"enum" => |enum_index| {
                                const enum_type = unit.enums.get(enum_index);
                                const identifier = unit.getExpectedTokenBytes(Token.addInt(node.token, 1), .identifier);
                                const hash = try unit.processIdentifier(context, identifier);
                                for (enum_type.fields.slice()) |field_index| {
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
                    .@"struct" => |struct_index| blk: {
                        const struct_type = unit.structs.get(struct_index);

                        if (struct_type.optional) {
                            const optional_undefined = V{
                                .value = .{
                                    .@"comptime" = .undefined,
                                },
                                .type = type_index,
                            };

                            const final_insert = try unit.instructions.append(context.my_allocator, .{
                                .insert_value = .{
                                    .expression = optional_undefined,
                                    .index = 1,
                                    // This tells the optional is valid (aka not null)
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

                            try builder.appendInstruction(unit, context, final_insert);

                            break :blk .{
                                .value = .{
                                    .runtime = final_insert,
                                },
                                .type = type_index,
                            };
                        } else {
                            unreachable;
                        }
                    },
                    .slice => |slice| blk: {
                        const optional_undefined = V{
                            .value = .{
                                .@"comptime" = .undefined,
                            },
                            .type = type_index,
                        };

                        const slice_builder = try unit.instructions.append(context.my_allocator, .{
                            .insert_value = .{
                                .expression = optional_undefined,
                                .index = 0,
                                .new_value = .{
                                    .value = .{
                                        .@"comptime" = .null_pointer,
                                    },
                                    .type = slice.child_pointer_type,
                                },
                            },
                        });

                        try builder.appendInstruction(unit, context, slice_builder);

                        const final_slice = try unit.instructions.append(context.my_allocator, .{
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
                                                .value = 0,
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
                    .pointer => |pointer| .{
                        .value = .{
                            .@"comptime" = .null_pointer,
                        },
                        .type = if (pointer.nullable) type_index else blk: {
                            var p = pointer;
                            p.nullable = true;
                            const nullable_pointer = try unit.getPointerType(context, p);
                            break :blk nullable_pointer;
                        },
                    },
                    else => |t| @panic(@tagName(t)),
                },
                else => |t| @panic(@tagName(t)),
            },
            .slice => blk: {
                const expression_to_slice = try builder.resolveRuntimeValue(unit, context, Type.Expect.none, node.left, .left);

                const range_node = unit.getNode(node.right);
                assert(range_node.id == .range);
                const range_start: V = try builder.resolveRuntimeValue(unit, context, Type.Expect{ .type = .usize }, range_node.left, .right);
                const range_end: V = switch (range_node.right) {
                    .null => switch (unit.types.get(expression_to_slice.type).*) {
                        .slice => b: {
                            const extract_value = try unit.instructions.append(context.my_allocator, .{
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
                                    .type = .usize,
                                },
                                .slice => |slice| b: {
                                    _ = slice; // autofix
                                    assert(!pointer.many);
                                    const gep = try unit.instructions.append(context.my_allocator, .{
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
                                        },
                                    });
                                    try builder.appendInstruction(unit, context, gep);

                                    const load = try unit.instructions.append(context.my_allocator, .{
                                        .load = .{
                                            .value = .{
                                                .value = .{
                                                    .runtime = gep,
                                                },
                                                .type = try unit.getPointerType(context, .{
                                                    .type = .usize,
                                                    .termination = .none,
                                                    .many = false,
                                                    .nullable = false,
                                                    .mutability = .@"const",
                                                }),
                                            },
                                            .type = .usize,
                                        },
                                    });
                                    try builder.appendInstruction(unit, context, load);

                                    break :b V{
                                        .value = .{
                                            .runtime = load,
                                        },
                                        .type = .usize,
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
                                                .type = .usize,
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
                    else => try builder.resolveRuntimeValue(unit, context, Type.Expect{ .type = .usize }, range_node.right, .right),
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
                            .type = .usize,
                        };
                    } else {
                        const range_compute = try unit.instructions.append(context.my_allocator, .{
                            .integer_binary_operation = .{
                                .left = range_end,
                                .right = range_start,
                                .id = .sub,
                                .signedness = .unsigned,
                            },
                        });

                        try builder.appendInstruction(unit, context, range_compute);

                        break :b .{
                            .value = .{
                                .runtime = range_compute,
                            },
                            .type = .usize,
                        };
                    }
                };

                switch (unit.types.get(expression_to_slice.type).*) {
                    .slice => |slice| {
                        const extract_value = try unit.instructions.append(context.my_allocator, .{
                            .extract_value = .{
                                .expression = expression_to_slice,
                                .index = 0,
                            },
                        });
                        try builder.appendInstruction(unit, context, extract_value);

                        const pointer_type = slice.child_pointer_type;
                        const pointer_gep = try unit.instructions.append(context.my_allocator, .{
                            .get_element_pointer = .{
                                .pointer = extract_value,
                                .is_struct = false,
                                .base_type = slice.child_type,
                                .index = range_start,
                            },
                        });
                        try builder.appendInstruction(unit, context, pointer_gep);

                        const slice_builder = try unit.instructions.append(context.my_allocator, .{
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

                        const final_slice = try unit.instructions.append(context.my_allocator, .{
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

                        try builder.appendInstruction(unit, context, final_slice);

                        break :blk .{
                            .value = .{
                                .runtime = final_slice,
                            },
                            .type = expression_to_slice.type,
                        };
                    },
                    .pointer => |pointer| switch (pointer.many) {
                        true => {
                            const pointer_gep = try unit.instructions.append(context.my_allocator, .{
                                .get_element_pointer = .{
                                    .pointer = expression_to_slice.value.runtime,
                                    .is_struct = false,
                                    .base_type = pointer.type,
                                    .index = range_start,
                                },
                            });
                            try builder.appendInstruction(unit, context, pointer_gep);

                            const pointer_type = try unit.getPointerType(context, .{
                                .type = pointer.type,
                                .termination = pointer.termination,
                                .mutability = pointer.mutability,
                                .many = true,
                                .nullable = false,
                            });
                            const slice_builder = try unit.instructions.append(context.my_allocator, .{
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
                                    .new_value = .{
                                        .value = .{
                                            .runtime = pointer_gep,
                                        },
                                        .type = pointer_type,
                                    },
                                },
                            });
                            try builder.appendInstruction(unit, context, slice_builder);

                            const final_slice = try unit.instructions.append(context.my_allocator, .{
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
                        false => switch (unit.types.get(pointer.type).*) {
                            .array => |array| {
                                const pointer_gep = try unit.instructions.append(context.my_allocator, .{
                                    .get_element_pointer = .{
                                        .pointer = expression_to_slice.value.runtime,
                                        .base_type = array.type,
                                        .is_struct = false,
                                        .index = range_start,
                                    },
                                });
                                try builder.appendInstruction(unit, context, pointer_gep);

                                const pointer_type = try unit.getPointerType(context, .{
                                    .type = array.type,
                                    .termination = array.termination,
                                    .mutability = pointer.mutability,
                                    .many = true,
                                    .nullable = false,
                                });

                                const slice_type = try unit.getSliceType(context, .{
                                    .child_type = array.type,
                                    .child_pointer_type = pointer_type,
                                    .termination = array.termination,
                                    .mutability = pointer.mutability,
                                    .nullable = false,
                                });

                                const slice_builder = try unit.instructions.append(context.my_allocator, .{
                                    .insert_value = .{
                                        .expression = V{
                                            .value = .{
                                                .@"comptime" = .undefined,
                                            },
                                            .type = switch (type_expect) {
                                                .type => |type_index| type_index,
                                                .none => slice_type,
                                                else => |t| @panic(@tagName(t)),
                                            },
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

                                const final_slice = try unit.instructions.append(context.my_allocator, .{
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
                                try builder.appendInstruction(unit, context, final_slice);

                                break :blk .{
                                    .value = .{
                                        .runtime = final_slice,
                                    },
                                    .type = switch (type_expect) {
                                        .type => |type_index| type_index,
                                        .none => slice_type,
                                        else => |t| @panic(@tagName(t)),
                                    },
                                };
                            },
                            .pointer => |child_pointer| switch (child_pointer.many) {
                                true => {
                                    assert(!child_pointer.nullable);
                                    const load = try unit.instructions.append(context.my_allocator, .{
                                        .load = .{
                                            .value = expression_to_slice,
                                            .type = pointer.type,
                                        },
                                    });
                                    try builder.appendInstruction(unit, context, load);

                                    const pointer_gep = try unit.instructions.append(context.my_allocator, .{
                                        .get_element_pointer = .{
                                            .pointer = load,
                                            .base_type = child_pointer.type,
                                            .is_struct = false,
                                            .index = range_start,
                                        },
                                    });
                                    try builder.appendInstruction(unit, context, pointer_gep);

                                    const pointer_type = try unit.getPointerType(context, .{
                                        .type = child_pointer.type,
                                        .termination = child_pointer.termination,
                                        .mutability = child_pointer.mutability,
                                        .many = true,
                                        .nullable = false,
                                    });

                                    const slice_type = try unit.getSliceType(context, .{
                                        .child_type = child_pointer.type,
                                        .child_pointer_type = pointer_type,
                                        .termination = child_pointer.termination,
                                        .mutability = child_pointer.mutability,
                                        .nullable = false,
                                    });

                                    const slice_builder = try unit.instructions.append(context.my_allocator, .{
                                        .insert_value = .{
                                            .expression = V{
                                                .value = .{
                                                    .@"comptime" = .undefined,
                                                },
                                                .type = switch (type_expect) {
                                                    .type => |type_index| type_index,
                                                    .none => slice_type,
                                                    else => |t| @panic(@tagName(t)),
                                                },
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

                                    const final_slice = try unit.instructions.append(context.my_allocator, .{
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
                                    try builder.appendInstruction(unit, context, final_slice);

                                    break :blk .{
                                        .value = .{
                                            .runtime = final_slice,
                                        },
                                        .type = switch (type_expect) {
                                            .type => |type_index| type_index,
                                            .none => slice_type,
                                            else => |t| @panic(@tagName(t)),
                                        },
                                    };
                                },
                                false => switch (unit.types.get(child_pointer.type).*) {
                                    .array => |array| {
                                        const load = try unit.instructions.append(context.my_allocator, .{
                                            .load = .{
                                                .value = expression_to_slice,
                                                .type = pointer.type,
                                            },
                                        });
                                        try builder.appendInstruction(unit, context, load);

                                        const pointer_gep = try unit.instructions.append(context.my_allocator, .{
                                            .get_element_pointer = .{
                                                .pointer = load,
                                                .base_type = array.type,
                                                .is_struct = false,
                                                .index = range_start,
                                            },
                                        });
                                        try builder.appendInstruction(unit, context, pointer_gep);

                                        const pointer_type = try unit.getPointerType(context, .{
                                            .type = array.type,
                                            .termination = array.termination,
                                            .mutability = child_pointer.mutability,
                                            .many = true,
                                            .nullable = false,
                                        });

                                        const slice_type = try unit.getSliceType(context, .{
                                            .child_type = array.type,
                                            .child_pointer_type = pointer_type,
                                            .termination = array.termination,
                                            .mutability = child_pointer.mutability,
                                            .nullable = false,
                                        });

                                        const slice_builder = try unit.instructions.append(context.my_allocator, .{
                                            .insert_value = .{
                                                .expression = V{
                                                    .value = .{
                                                        .@"comptime" = .undefined,
                                                    },
                                                    .type = switch (type_expect) {
                                                        .type => |type_index| type_index,
                                                        .none => slice_type,
                                                        else => |t| @panic(@tagName(t)),
                                                    },
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

                                        const final_slice = try unit.instructions.append(context.my_allocator, .{
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
                                        try builder.appendInstruction(unit, context, final_slice);

                                        break :blk .{
                                            .value = .{
                                                .runtime = final_slice,
                                            },
                                            .type = switch (type_expect) {
                                                .type => |type_index| type_index,
                                                .none => slice_type,
                                                else => |t| @panic(@tagName(t)),
                                            },
                                        };
                                    },
                                    else => |t| @panic(@tagName(t)),
                                },
                            },
                            .slice => |slice| {
                                const load = try unit.instructions.append(context.my_allocator, .{
                                    .load = .{
                                        .value = expression_to_slice,
                                        .type = pointer.type,
                                    },
                                });
                                try builder.appendInstruction(unit, context, load);

                                const extract_pointer = try unit.instructions.append(context.my_allocator, .{
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
                                try builder.appendInstruction(unit, context, extract_pointer);

                                const pointer_gep = try unit.instructions.append(context.my_allocator, .{
                                    .get_element_pointer = .{
                                        .pointer = extract_pointer,
                                        .base_type = slice.child_type,
                                        .is_struct = false,
                                        .index = range_start,
                                    },
                                });
                                try builder.appendInstruction(unit, context, pointer_gep);

                                const slice_builder = try unit.instructions.append(context.my_allocator, .{
                                    .insert_value = .{
                                        .expression = V{
                                            .value = .{
                                                .@"comptime" = .undefined,
                                            },
                                            .type = switch (type_expect) {
                                                .type => |type_index| type_index,
                                                .none => pointer.type,
                                                else => |t| @panic(@tagName(t)),
                                            },
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
                                try builder.appendInstruction(unit, context, slice_builder);

                                const final_slice = try unit.instructions.append(context.my_allocator, .{
                                    .insert_value = .{
                                        .expression = V{
                                            .value = .{
                                                .runtime = slice_builder,
                                            },
                                            .type = pointer.type,
                                        },
                                        .index = 1,
                                        .new_value = len_expression,
                                    },
                                });
                                try builder.appendInstruction(unit, context, final_slice);

                                break :blk .{
                                    .value = .{
                                        .runtime = final_slice,
                                    },
                                    .type = switch (type_expect) {
                                        .type => |type_index| type_index,
                                        .none => pointer.type,
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

                        const slice_builder = try unit.instructions.append(context.my_allocator, .{
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

                        const final_slice = try unit.instructions.append(context.my_allocator, .{
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
                    .pointer => |pointer| blk: {
                        const string_global = try builder.processStringLiteralFromToken(unit, context, node.token);
                        switch (pointer.many) {
                            true => {
                                const pointer_type = try unit.getPointerType(context, .{
                                    .type = string_global.declaration.type,
                                    .termination = .none,
                                    .mutability = pointer.mutability,
                                    .many = false,
                                    .nullable = false,
                                });
                                const cast = try unit.instructions.append(context.my_allocator, .{
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
                                try builder.appendInstruction(unit, context, cast);

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

                                            const pointer_type = try unit.getPointerType(context, .{
                                                .type = value_pointer.type,
                                                .many = false,
                                                .nullable = false,
                                                .mutability = .@"const",
                                                .termination = .none,
                                            });

                                            const cast = try unit.instructions.append(context.my_allocator, .{
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
                                            try builder.appendInstruction(unit, context, cast);
                                            const slice_builder = try unit.instructions.append(context.my_allocator, .{
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
                                            try builder.appendInstruction(unit, context, slice_builder);

                                            const final_slice = try unit.instructions.append(context.my_allocator, .{
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
                                            const name = try join_name(context, "__anon_local_arr_{}", unit.anon_arr, 10);
                                            unit.anon_arr += 1;
                                            const emit = true;
                                            const stack_slot = try builder.emitLocalVariableDeclaration(unit, context, unit.getNode(node.left).token, .@"const", value_pointer.type, value_pointer, emit, name);
                                            const slice_builder = try unit.instructions.append(context.my_allocator, .{
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

                                            const final_slice = try unit.instructions.append(context.my_allocator, .{
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
                                .pointer => |pointer| {
                                    switch (unit.types.get(pointer.type).*) {
                                        .array => |array| {
                                            const cast = try unit.instructions.append(context.my_allocator, .{
                                                .cast = .{
                                                    .id = .pointer_to_array_to_pointer_to_many,
                                                    .value = value_pointer,
                                                    .type = slice.child_pointer_type,
                                                },
                                            });
                                            try builder.appendInstruction(unit, context, cast);

                                            const slice_builder = try unit.instructions.append(context.my_allocator, .{
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
                                            try builder.appendInstruction(unit, context, slice_builder);

                                            const final_slice = try unit.instructions.append(context.my_allocator, .{
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
                                            const cast = try unit.instructions.append(context.my_allocator, .{
                                                .cast = .{
                                                    .id = .pointer_to_array_to_pointer_to_many, //.array_to_pointer,
                                                    .type = type_index,
                                                    .value = v,
                                                },
                                            });
                                            try builder.appendInstruction(unit, context, cast);
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
                        .integer => {
                            const v = try builder.resolveRuntimeValue(unit, context, Type.Expect.none, node.left, .left);
                            _ = v;
                            unreachable;
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
                const index = try builder.resolveRuntimeValue(unit, context, Type.Expect{ .type = .usize }, node.right, .right);

                const gep: V = switch (unit.types.get(array_like_expression.type).*) {
                    .pointer => |pointer| switch (pointer.many) {
                        true => unreachable,
                        false => switch (unit.types.get(pointer.type).*) {
                            .slice => |slice| b: {
                                const gep = try unit.instructions.append(context.my_allocator, .{
                                    .get_element_pointer = .{
                                        .pointer = array_like_expression.value.runtime,
                                        .base_type = pointer.type,
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
                                    },
                                });
                                try builder.appendInstruction(unit, context, gep);

                                const pointer_to_slice_pointer = try unit.getPointerType(context, .{
                                    .type = slice.child_pointer_type,
                                    .mutability = pointer.mutability,
                                    .termination = .none,
                                    .many = false,
                                    .nullable = false,
                                });

                                const pointer_load = try unit.instructions.append(context.my_allocator, .{
                                    .load = .{
                                        .value = .{
                                            .value = .{
                                                .runtime = gep,
                                            },
                                            .type = pointer_to_slice_pointer,
                                        },
                                        .type = slice.child_pointer_type,
                                    },
                                });
                                try builder.appendInstruction(unit, context, pointer_load);

                                const slice_pointer_gep = try unit.instructions.append(context.my_allocator, .{
                                    .get_element_pointer = .{
                                        .pointer = pointer_load,
                                        .base_type = slice.child_type,
                                        .is_struct = false,
                                        .index = index,
                                    },
                                });
                                try builder.appendInstruction(unit, context, slice_pointer_gep);

                                break :b .{
                                    .value = .{
                                        .runtime = slice_pointer_gep,
                                    },
                                    .type = try unit.getPointerType(context, .{
                                        .type = slice.child_type,
                                        .mutability = slice.mutability,
                                        .many = false,
                                        .nullable = false,
                                        .termination = .none,
                                    }),
                                };
                            },
                            .array => |array| b: {
                                const gep = try unit.instructions.append(context.my_allocator, .{
                                    .get_element_pointer = .{
                                        .pointer = array_like_expression.value.runtime,
                                        .base_type = array.type,
                                        .is_struct = false,
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
                            .pointer => |child_pointer| switch (child_pointer.many) {
                                true => b: {
                                    const load = try unit.instructions.append(context.my_allocator, .{
                                        .load = .{
                                            .value = array_like_expression,
                                            .type = pointer.type,
                                        },
                                    });
                                    try builder.appendInstruction(unit, context, load);
                                    const gep = try unit.instructions.append(context.my_allocator, .{
                                        .get_element_pointer = .{
                                            .pointer = load,
                                            .base_type = child_pointer.type,
                                            .is_struct = false,
                                            .index = index,
                                        },
                                    });
                                    try builder.appendInstruction(unit, context, gep);

                                    const gep_type = try unit.getPointerType(context, .{
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
                                        const load = try unit.instructions.append(context.my_allocator, .{
                                            .load = .{
                                                .value = array_like_expression,
                                                .type = pointer.type,
                                            },
                                        });
                                        try builder.appendInstruction(unit, context, load);

                                        const gep = try unit.instructions.append(context.my_allocator, .{
                                            .get_element_pointer = .{
                                                .pointer = load,
                                                .base_type = array.type,
                                                .is_struct = false,
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
                                    .integer => b: {
                                        assert(child_pointer.many);

                                        const load = try unit.instructions.append(context.my_allocator, .{
                                            .load = .{
                                                .value = array_like_expression,
                                                .type = pointer.type,
                                            },
                                        });
                                        try builder.appendInstruction(unit, context, load);

                                        const gep = try unit.instructions.append(context.my_allocator, .{
                                            .get_element_pointer = .{
                                                .pointer = load,
                                                .base_type = child_pointer.type,
                                                .is_struct = false,
                                                .index = index,
                                            },
                                        });
                                        try builder.appendInstruction(unit, context, gep);

                                        const gep_type = try unit.getPointerType(context, .{
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
                            },
                            else => |t| @panic(@tagName(t)),
                        },
                    },
                    else => |t| @panic(@tagName(t)),
                };

                switch (side) {
                    .left => break :blk gep,
                    .right => {
                        const load = try unit.instructions.append(context.my_allocator, .{
                            .load = .{
                                .value = gep,
                                .type = unit.types.get(gep.type).pointer.type,
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
                                .none => unit.types.get(gep.type).pointer.type,
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
            .boolean_not => blk: {
                switch (type_expect) {
                    .none => {},
                    .type => |type_index| assert(type_index == .bool),
                    else => |t| @panic(@tagName(t)),
                }
                const boolean = try builder.resolveRuntimeValue(unit, context, Type.Expect{ .type = .bool }, node.left, .right);
                switch (boolean.value) {
                    .runtime => {
                        const xor = try unit.instructions.append(context.my_allocator, .{
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
                        try builder.appendInstruction(unit, context, xor);

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
                const value = try builder.resolveRuntimeValue(unit, context, Type.Expect.none, node.left, .right);
                switch (value.value) {
                    .@"comptime" => |ct| switch (ct) {
                        .comptime_int => |ct_int| switch (type_expect) {
                            .type => |type_index| switch (unit.types.get(type_index).*) {
                                .integer => |integer| {
                                    assert(integer.signedness == .signed);

                                    var v: i64 = @bitCast(ct_int.value);
                                    if (ct_int.signedness == .signed) {
                                        v = -v;
                                    }

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
                    else => |t| @panic(@tagName(t)),
                }
            },
            .@"return" => block: {
                try builder.emitReturn(unit, context, node_index);
                // TODO: warning
                break :block undefined;
            },
            else => |t| @panic(@tagName(t)),
        };

        return v;
    }

    fn resolveContainerLiteral(builder: *Builder, unit: *Unit, context: *const Context, nodes: []const Node.Index, type_index: Type.Index) !V {
        const container_type = unit.types.get(type_index);

        switch (container_type.*) {
            .@"struct" => |struct_index| {
                const struct_type = unit.structs.get(struct_index);
                const fields = struct_type.fields.slice();
                var list = try UnpinnedArray(V).initialize_with_capacity(context.my_allocator, @intCast(fields.len));
                var is_comptime = true;

                for (fields) |field_index| {
                    const field = unit.struct_fields.get(field_index);

                    for (nodes) |initialization_node_index| {
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
                            list.append_with_capacity(field_initialization);
                            break;
                        }
                    } else if (field.default_value) |default_value| {
                        list.append_with_capacity(.{
                            .value = .{
                                .@"comptime" = default_value,
                            },
                            .type = field.type,
                        });
                    } else {
                        @panic("Missing field");
                    }
                }

                switch (struct_type.backing_type) {
                    .null => {
                        if (is_comptime) {
                            var comptime_list = try UnpinnedArray(V.Comptime).initialize_with_capacity(context.my_allocator, @intCast(fields.len));
                            for (list.slice()) |item| {
                                comptime_list.append_with_capacity(item.value.@"comptime");
                            }

                            return .{
                                .value = .{
                                    .@"comptime" = .{
                                        .constant_struct = try unit.constant_structs.append(context.my_allocator, .{
                                            .fields = comptime_list.slice(),
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
                                const struct_initialization_instruction = try unit.instructions.append(context.my_allocator, .{
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

                            return struct_initialization;
                        }
                    },
                    else => {
                        const backing_integer_type = unit.types.get(struct_type.backing_type).integer;
                        assert(backing_integer_type.signedness == .unsigned);
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
                                    else => |t| @panic(@tagName(t)),
                                };
                                const value_with_offset = field_value << @as(u6, @intCast(bit_offset));
                                value |= value_with_offset;
                                bit_offset += bit_size;
                            }

                            return .{
                                .value = .{
                                    .@"comptime" = .{
                                        .constant_backed_struct = value,
                                    },
                                },
                                .type = type_index,
                            };
                        } else {
                            const zero_extend = try unit.instructions.append(context.my_allocator, .{
                                .cast = .{
                                    .id = .zero_extend,
                                    .value = list.pointer[0],
                                    .type = struct_type.backing_type,
                                },
                            });
                            try builder.appendInstruction(unit, context, zero_extend);
                            var value = V{
                                .value = .{
                                    .runtime = zero_extend,
                                },
                                .type = struct_type.backing_type,
                            };

                            const first_field_type = unit.types.get(list.pointer[0].type);
                            var bit_offset = first_field_type.getBitSize(unit);

                            for (list.slice()[1..]) |field| {
                                const field_type = unit.types.get(field.type);
                                const field_bit_size = field_type.getBitSize(unit);
                                defer bit_offset += field_bit_size;

                                switch (field.value) {
                                    .@"comptime" => |ct| {
                                        _ = ct; // autofix
                                        unreachable;
                                    },
                                    .runtime => {
                                        const field_zero_extend = try unit.instructions.append(context.my_allocator, .{
                                            .cast = .{
                                                .id = .zero_extend,
                                                .value = field,
                                                .type = struct_type.backing_type,
                                            },
                                        });
                                        try builder.appendInstruction(unit, context, field_zero_extend);

                                        const shift_left = try unit.instructions.append(context.my_allocator, .{
                                            .integer_binary_operation = .{
                                                .id = .shift_left,
                                                .left = .{
                                                    .value = .{
                                                        .runtime = field_zero_extend,
                                                    },
                                                    .type = struct_type.backing_type,
                                                },
                                                .right = .{
                                                    .value = .{
                                                        .@"comptime" = .{
                                                            .constant_int = .{
                                                                .value = bit_offset,
                                                            },
                                                        },
                                                    },
                                                    .type = struct_type.backing_type,
                                                },
                                                .signedness = backing_integer_type.signedness,
                                            },
                                        });

                                        try builder.appendInstruction(unit, context, shift_left);

                                        const merge_or = try unit.instructions.append(context.my_allocator, .{
                                            .integer_binary_operation = .{
                                                .id = .bit_or,
                                                .signedness = backing_integer_type.signedness,
                                                .left = .{
                                                    .value = .{
                                                        .runtime = shift_left,
                                                    },
                                                    .type = struct_type.backing_type,
                                                },
                                                .right = value,
                                            },
                                        });
                                        try builder.appendInstruction(unit, context, merge_or);

                                        value = .{
                                            .value = .{
                                                .runtime = merge_or,
                                            },
                                            .type = struct_type.backing_type,
                                        };
                                    },
                                    else => |t| @panic(@tagName(t)),
                                }
                            }

                            return value;
                        }
                    },
                }
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
        const is_terminated = switch (array_type.termination) {
            .none => false,
            else => true,
        };
        var values = try UnpinnedArray(V).initialize_with_capacity(context.my_allocator, @intCast(nodes.len + @intFromBool(is_terminated)));
        for (nodes) |node_index| {
            const value = try builder.resolveRuntimeValue(unit, context, Type.Expect{ .type = array_type.type }, node_index, .right);
            // assert(value.value == .@"comptime");
            is_comptime = is_comptime and value.value == .@"comptime";
            values.append_with_capacity(value);
        }

        switch (array_type.termination) {
            .none => {},
            .zero => values.append_with_capacity(.{
                .value = .{
                    .@"comptime" = .{
                        .constant_int = .{
                            .value = 0,
                        },
                    },
                },
                .type = array_type.type,
            }),
            .null => values.append_with_capacity(.{
                .value = .{
                    .@"comptime" = .null_pointer,
                },
                .type = array_type.type,
            }),
        }

        if (is_comptime) {
            const constant_array = try unit.constant_arrays.append(context.my_allocator, .{
                .values = blk: {
                    var ct_values = try UnpinnedArray(V.Comptime).initialize_with_capacity(context.my_allocator, values.length);

                    for (values.slice()) |v| {
                        ct_values.append_with_capacity(v.value.@"comptime");
                    }

                    break :blk ct_values.slice();
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

            for (values.slice(), 0..) |value, index| {
                const insert_value = try unit.instructions.append(context.my_allocator, .{
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

    fn resolveCall(builder: *Builder, unit: *Unit, context: *const Context, node_index: Node.Index) !V {
        const node = unit.getNode(node_index);

        assert(node.left != .null);
        assert(node.right != .null);
        const left_node = unit.getNode(node.left);

        var argument_list = UnpinnedArray(V){};
        const callable: V = switch (left_node.id) {
            .field_access => blk: {
                const right_identifier_node = unit.getNode(left_node.right);
                assert(right_identifier_node.id == .identifier);
                const right_identifier = unit.getExpectedTokenBytes(right_identifier_node.token, .identifier);
                const right_identifier_hash = try unit.processIdentifier(context, right_identifier);

                const field_access_left = try builder.resolveRuntimeValue(unit, context, Type.Expect.none, left_node.left, .left);

                switch (field_access_left.value) {
                    .@"comptime" => |ct| switch (ct) {
                        .type => |type_index| switch (unit.types.get(type_index).*) {
                            .@"struct", .@"enum" => {
                                const container_type = unit.types.get(type_index);
                                const container_scope = container_type.getScope(unit);
                                const look_in_parent_scopes = false;

                                if (container_scope.lookupDeclaration(right_identifier_hash, look_in_parent_scopes)) |lookup| {
                                    const global = try builder.referenceGlobalDeclaration(unit, context, lookup.scope, lookup.declaration);
                                    switch (global.initial_value) {
                                        .function_definition, .function_declaration => break :blk .{
                                            .value = .{
                                                .@"comptime" = .{
                                                    .global = global,
                                                },
                                            },
                                            .type = global.declaration.type,
                                        },
                                        else => |t| @panic(@tagName(t)),
                                    }
                                } else {
                                    @panic("Right identifier in field access like call expression");
                                    //std.debug.panic("Right identifier in field-access-like call expression not found: '{s}'", .{right_identifier});
                                }
                            },
                            else => |t| @panic(@tagName(t)),
                        },
                        .global => |global| {
                            switch (unit.types.get(global.declaration.type).*) {
                                .@"struct" => |struct_index| {
                                    const struct_type = unit.structs.get(struct_index);
                                    for (struct_type.fields.slice()) |field_index| {
                                        const field = unit.struct_fields.get(field_index);
                                        if (field.name == right_identifier_hash) {
                                            unreachable;
                                        }
                                    } else {
                                        const look_in_parent_scopes = false;
                                        if (struct_type.scope.scope.lookupDeclaration(right_identifier_hash, look_in_parent_scopes)) |lookup| {
                                            const right_symbol = try builder.referenceGlobalDeclaration(unit, context, lookup.scope, lookup.declaration);
                                            switch (right_symbol.initial_value) {
                                                .function_definition => {
                                                    const function_type_index = right_symbol.declaration.type;
                                                    const function_prototype_index = unit.types.get(function_type_index).function;
                                                    const function_prototype = unit.function_prototypes.get(function_prototype_index);
                                                    if (function_prototype.argument_types.len == 0) {
                                                        unreachable;
                                                    }

                                                    const first_argument_type_index = function_prototype.argument_types[0];
                                                    if (first_argument_type_index == field_access_left.type) {
                                                        try argument_list.append(context.my_allocator, field_access_left);
                                                        break :blk V{
                                                            .value = .{
                                                                .@"comptime" = .{
                                                                    .global = right_symbol,
                                                                },
                                                            },
                                                            .type = function_type_index,
                                                        };
                                                    } else {
                                                        unreachable;
                                                    }
                                                },
                                                else => |t| @panic(@tagName(t)),
                                            }
                                        } else {
                                            unreachable;
                                        }
                                    }
                                },
                                else => |t| @panic(@tagName(t)),
                            }
                        },
                        else => |t| @panic(@tagName(t)),
                    },
                    .runtime => |instruction_index| {
                        switch (unit.types.get(field_access_left.type).*) {
                            .pointer => |pointer| switch (unit.types.get(pointer.type).*) {
                                .@"struct" => |struct_index| {
                                    const struct_type = unit.structs.get(struct_index);

                                    for (struct_type.fields.slice(), 0..) |field_index, index| {
                                        const field = unit.struct_fields.get(field_index);
                                        if (field.name == right_identifier_hash) {
                                            switch (unit.types.get(field.type).*) {
                                                .pointer => |field_pointer_type| switch (unit.types.get(field_pointer_type.type).*) {
                                                    .function => {
                                                        assert(field_pointer_type.mutability == .@"const");
                                                        assert(!field_pointer_type.nullable);
                                                        const gep = try unit.instructions.append(context.my_allocator, .{
                                                            .get_element_pointer = .{
                                                                .pointer = instruction_index,
                                                                .base_type = pointer.type,
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
                                                            },
                                                        });
                                                        try builder.appendInstruction(unit, context, gep);

                                                        const load = try unit.instructions.append(context.my_allocator, .{
                                                            .load = .{
                                                                .value = .{
                                                                    .value = .{
                                                                        .runtime = gep,
                                                                    },
                                                                    .type = try unit.getPointerType(context, .{
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

                                                        try builder.appendInstruction(unit, context, load);
                                                        break :blk .{
                                                            .value = .{
                                                                .runtime = load,
                                                            },
                                                            .type = field.type,
                                                        };
                                                    },
                                                    else => |t| @panic(@tagName(t)),
                                                },
                                                else => |t| @panic(@tagName(t)),
                                            }
                                            unreachable;
                                        }
                                    } else {
                                        const look_in_parent_scopes = false;
                                        if (struct_type.scope.scope.lookupDeclaration(right_identifier_hash, look_in_parent_scopes)) |lookup| {
                                            const right_symbol = try builder.referenceGlobalDeclaration(unit, context, lookup.scope, lookup.declaration);
                                            switch (right_symbol.initial_value) {
                                                .function_definition => {
                                                    const function_type_index = right_symbol.declaration.type;
                                                    const function_prototype_index = unit.types.get(function_type_index).function;
                                                    const function_prototype = unit.function_prototypes.get(function_prototype_index);
                                                    if (function_prototype.argument_types.len == 0) {
                                                        unreachable;
                                                    }

                                                    const first_argument_type_index = function_prototype.argument_types[0];
                                                    if (first_argument_type_index == field_access_left.type) {
                                                        try argument_list.append(context.my_allocator, field_access_left);
                                                        break :blk V{
                                                            .value = .{
                                                                .@"comptime" = .{
                                                                    .global = right_symbol,
                                                                },
                                                            },
                                                            .type = function_type_index,
                                                        };
                                                    } else if (first_argument_type_index == pointer.type) {
                                                        const load = try unit.instructions.append(context.my_allocator, .{
                                                            .load = .{
                                                                .value = field_access_left,
                                                                .type = first_argument_type_index,
                                                            },
                                                        });
                                                        try builder.appendInstruction(unit, context, load);

                                                        try argument_list.append(context.my_allocator, .{
                                                            .value = .{
                                                                .runtime = load,
                                                            },
                                                            .type = first_argument_type_index,
                                                        });

                                                        break :blk V{
                                                            .value = .{
                                                                .@"comptime" = .{
                                                                    .global = right_symbol,
                                                                },
                                                            },
                                                            .type = function_type_index,
                                                        };
                                                    } else {
                                                        const symbol_name = unit.getIdentifier(right_symbol.declaration.name);
                                                        _ = symbol_name; // autofix
                                                        const decl_arg_type_index = first_argument_type_index;
                                                        const field_access_left_type_index = field_access_left.type;
                                                        const result = try builder.typecheck(unit, context, decl_arg_type_index, field_access_left_type_index);
                                                        switch (result) {
                                                            else => |t| @panic(@tagName(t)),
                                                        }
                                                    }
                                                },
                                                else => |t| @panic(@tagName(t)),
                                            }
                                        } else {
                                            unreachable;
                                        }
                                    }
                                },
                                .pointer => |child_pointer| switch (unit.types.get(child_pointer.type).*) {
                                    .@"struct" => |struct_index| {
                                        const struct_type = unit.structs.get(struct_index);
                                        for (struct_type.fields.slice(), 0..) |field_index, index| {
                                            const field = unit.struct_fields.get(field_index);
                                            if (field.name == right_identifier_hash) {
                                                switch (unit.types.get(field.type).*) {
                                                    .pointer => |field_pointer_type| switch (unit.types.get(field_pointer_type.type).*) {
                                                        .function => {
                                                            const first_load = try unit.instructions.append(context.my_allocator, .{
                                                                .load = .{
                                                                    .value = field_access_left,
                                                                    .type = pointer.type,
                                                                },
                                                            });
                                                            try builder.appendInstruction(unit, context, first_load);

                                                            assert(field_pointer_type.mutability == .@"const");
                                                            assert(!field_pointer_type.nullable);

                                                            const gep = try unit.instructions.append(context.my_allocator, .{
                                                                .get_element_pointer = .{
                                                                    .pointer = first_load,
                                                                    .base_type = child_pointer.type,
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
                                                                },
                                                            });
                                                            try builder.appendInstruction(unit, context, gep);

                                                            const load = try unit.instructions.append(context.my_allocator, .{
                                                                .load = .{
                                                                    .value = .{
                                                                        .value = .{
                                                                            .runtime = gep,
                                                                        },
                                                                        .type = try unit.getPointerType(context, .{
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
                                                            try builder.appendInstruction(unit, context, load);

                                                            break :blk .{
                                                                .value = .{
                                                                    .runtime = load,
                                                                },
                                                                .type = field.type,
                                                            };
                                                        },
                                                        else => |t| @panic(@tagName(t)),
                                                    },
                                                    else => |t| @panic(@tagName(t)),
                                                }
                                            }
                                        } else {
                                            const look_in_parent_scopes = false;
                                            if (struct_type.scope.scope.lookupDeclaration(right_identifier_hash, look_in_parent_scopes)) |lookup| {
                                                _ = lookup; // autofix
                                                unreachable;
                                            } else {
                                                unreachable;
                                            }
                                        }
                                    },
                                    else => |t| @panic(@tagName(t)),
                                },
                                else => |t| @panic(@tagName(t)),
                            },
                            .@"struct" => |struct_index| {
                                const struct_type = unit.structs.get(struct_index);
                                for (struct_type.fields.slice()) |field_index| {
                                    const field = unit.struct_fields.get(field_index);
                                    if (field.name == right_identifier_hash) {
                                        unreachable;
                                    }
                                } else {
                                    const look_in_parent_scopes = false;
                                    if (struct_type.scope.scope.lookupDeclaration(right_identifier_hash, look_in_parent_scopes)) |lookup| {
                                        const right_symbol = try builder.referenceGlobalDeclaration(unit, context, lookup.scope, lookup.declaration);
                                        switch (right_symbol.initial_value) {
                                            .function_definition => {
                                                const function_type_index = right_symbol.declaration.type;
                                                const function_prototype_index = unit.types.get(function_type_index).function;
                                                const function_prototype = unit.function_prototypes.get(function_prototype_index);
                                                if (function_prototype.argument_types.len == 0) {
                                                    unreachable;
                                                }

                                                const first_argument_type_index = function_prototype.argument_types[0];
                                                if (first_argument_type_index == field_access_left.type) {
                                                    try argument_list.append(context.my_allocator, field_access_left);
                                                    break :blk V{
                                                        .value = .{
                                                            .@"comptime" = .{
                                                                .global = right_symbol,
                                                            },
                                                        },
                                                        .type = function_type_index,
                                                    };
                                                } else {
                                                    unreachable;
                                                }
                                            },
                                            else => |t| @panic(@tagName(t)),
                                        }
                                    } else {
                                        unreachable;
                                    }
                                }
                            },
                            else => |t| @panic(@tagName(t)),
                        }
                    },
                    else => |t| @panic(@tagName(t)),
                }
            },
            .identifier => blk: {
                const identifier = unit.getExpectedTokenBytes(left_node.token, .identifier);
                const result = try builder.resolveIdentifier(unit, context, Type.Expect.none, identifier, .left);
                break :blk switch (result.value) {
                    .@"comptime" => |ct| switch (ct) {
                        .global => |global| switch (global.initial_value) {
                            .function_definition => .{
                                .value = .{
                                    .@"comptime" = .{
                                        .global = global,
                                    },
                                },
                                .type = global.declaration.type,
                            },
                            // This is a comptime alias
                            .global => |function_declaration| switch (function_declaration.initial_value) {
                                .function_definition => .{
                                    .value = .{
                                        .@"comptime" = .{
                                            .global = function_declaration,
                                        },
                                    },
                                    .type = function_declaration.declaration.type,
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
                                    const load = try unit.instructions.append(context.my_allocator, .{
                                        .load = .{
                                            .value = result,
                                            .type = pointer.type,
                                        },
                                    });
                                    try builder.appendInstruction(unit, context, load);

                                    break :b .{
                                        .value = .{
                                            .runtime = load,
                                        },
                                        .type = pointer.type,
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

        const function_type_index = switch (unit.types.get(callable.type).*) {
            .function => callable.type,
            .pointer => |pointer| switch (unit.types.get(pointer.type).*) {
                .function => pointer.type,
                else => |t| @panic(@tagName(t)),
            },
            else => |t| @panic(@tagName(t)),
        };

        const function_prototype = unit.function_prototypes.get(unit.types.get(function_type_index).function);

        const argument_nodes = unit.getNodeList(node.right);
        const argument_declaration_count = function_prototype.argument_types.len;

        // Argument list holds already the value of the member value
        if (argument_nodes.len + argument_list.length != argument_declaration_count) {
            @panic("Argument count mismatch");
        }

        try argument_list.ensure_capacity(context.my_allocator, @intCast(argument_declaration_count));

        const argument_offset = argument_list.length;
        for (argument_nodes, function_prototype.argument_types[argument_offset..]) |arg_ni, argument_type_index| {
            const argument_node = unit.getNode(arg_ni);
            const arg_type_expect = Type.Expect{
                .type = argument_type_index,
            };
            const argument_node_index = switch (argument_node.id) {
                .named_argument => argument_node.right,
                else => arg_ni,
            };
            const argument_value = try builder.resolveRuntimeValue(unit, context, arg_type_expect, argument_node_index, .right);
            argument_list.append_with_capacity(argument_value);
        }

        for (function_prototype.argument_types, argument_list.slice(), 0..) |argument_type, argument_value, i| {
            _ = i; // autofix
            if (argument_type != argument_value.type) {
                // switch (unit.types.get(argument_type).*) {
                //     .pointer => |dst_ptr| switch (unit.types.get(argument_value.type).*) {
                //         .pointer => |src_ptr| {
                //             _ = dst_ptr;
                //             _ = src_ptr; // autofix
                //             // std.debug.print("Declaration: {}\nCall: {}\n", .{ dst_ptr, src_ptr });
                //         },
                //         else => |t| @panic(@tagName(t)),
                //     },
                //     else => |t| @panic(@tagName(t)),
                // }

                @panic("Type mismatch");
            }
        }

        const instruction = try unit.instructions.append(context.my_allocator, .{
            .call = .{
                .callable = callable,
                .function_type = function_type_index,
                .arguments = argument_list.slice(),
            },
        });
        try builder.appendInstruction(unit, context, instruction);

        if (function_prototype.return_type == .noreturn) {
            try builder.buildTrap(unit, context);
        }

        return .{
            .value = .{
                .runtime = instruction,
            },
            .type = function_prototype.return_type,
        };
    }

    fn emitLocalVariableDeclaration(builder: *Builder, unit: *Unit, context: *const Context, token: Token.Index, mutability: Mutability, declaration_type: Type.Index, initialization: V, emit: bool, maybe_name: ?[]const u8) !Instruction.Index {
        assert(builder.current_scope.local);
        const index = Token.unwrap(token);
        const id = unit.token_buffer.ids[index];
        const identifier = if (maybe_name) |name| name else switch (id) {
            .identifier => unit.getExpectedTokenBytes(token, .identifier),
            .discard => blk: {
                const name = try join_name(context, "_", unit.discard_identifiers, 10);
                unit.discard_identifiers += 1;
                break :blk name;
            },
            else => |t| @panic(@tagName(t)),
        };
        // logln(.compilation, .identifier, "Analyzing local declaration {s}", .{identifier});
        const identifier_hash = try unit.processIdentifier(context, identifier);
        const token_debug_info = builder.getTokenDebugInfo(unit, token);

        const look_in_parent_scopes = true;
        if (builder.current_scope.lookupDeclaration(identifier_hash, look_in_parent_scopes)) |lookup| {
            _ = lookup; // autofix
            @panic("identifier already declared on scope");
            //std.debug.panic("Identifier '{s}' already declarared on scope", .{identifier});
        }

        const declaration_index = try unit.local_declarations.append(context.my_allocator, .{
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
        try builder.current_scope.declarations.put_no_clobber(context.my_allocator, identifier_hash, &local_declaration.declaration);

        if (emit) {
            const stack = try unit.instructions.append(context.my_allocator, .{
                .stack_slot = .{
                    .type = declaration_type,
                },
            });

            try builder.appendInstruction(unit, context, stack);

            assert(builder.current_scope.kind == .block);
            const local_scope = @fieldParentPtr(Debug.Scope.Local, "scope", builder.current_scope);
            try local_scope.local_declaration_map.put_no_clobber(context.my_allocator, local_declaration, stack);

            const debug_declare_local = try unit.instructions.append(context.my_allocator, .{
                .debug_declare_local_variable = .{
                    .variable = local_declaration,
                    .stack = stack,
                },
            });

            try builder.appendInstruction(unit, context, debug_declare_local);

            const store = try unit.instructions.append(context.my_allocator, .{
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
        const block_index = try unit.blocks.append(context.my_allocator, .{
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
                .variable_symbol_declaration,
                => {
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
                    try builder.emitReturn(unit, context, statement_node_index);
                },
                .call => {
                    const result = try builder.resolveCall(unit, context, statement_node_index);
                    assert(result.type == .void or result.type == .noreturn);
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
                                const typecheck_enum_result = try unit.typecheckSwitchEnums(context, enum_type, case_nodes);

                                const group_index = for (typecheck_enum_result.switch_case_groups.pointer[0..typecheck_enum_result.switch_case_groups.length], 0..) |switch_case_group, switch_case_group_index| {
                                    break for (switch_case_group.pointer[0..switch_case_group.length]) |field_index| {
                                        if (enum_field_index == field_index) {
                                            break switch_case_group_index;
                                        }
                                    } else {
                                        continue;
                                    };
                                } else typecheck_enum_result.else_switch_case_group_index orelse unreachable;
                                const true_switch_case_node = unit.getNode(case_nodes[group_index]);
                                _ = try builder.resolveRuntimeValue(unit, context, Type.Expect{ .type = .void }, true_switch_case_node.right, .right);
                            },
                            else => |t| @panic(@tagName(t)),
                        },
                        .runtime => todo(),
                        else => |t| @panic(@tagName(t)),
                    }
                },
                .@"unreachable" => {
                    try builder.buildTrap(unit, context);
                },
                .@"while" => {
                    assert(statement_node.left != .null);
                    assert(statement_node.right != .null);

                    const loop_header_block = try builder.newBasicBlock(unit, context);
                    try builder.jump(unit, context, loop_header_block);
                    builder.current_basic_block = loop_header_block;

                    const condition = try builder.resolveRuntimeValue(unit, context, Type.Expect{ .type = .bool }, statement_node.left, .right);
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
                    var slices = UnpinnedArray(V){};

                    const last_element_node_index = slices_and_range_node[count - 1];
                    const last_element_node = unit.getNode(last_element_node_index);
                    const last_element_payload = unit.getNode(payloads[count - 1]);

                    const LoopCounter = struct {
                        stack_slot: Instruction.Index,
                        end: V,
                    };

                    for (slices_and_range_node[0 .. count - 1]) |slice_or_range_node_index| {
                        const slice = try builder.resolveRuntimeValue(unit, context, Type.Expect.none, slice_or_range_node_index, .right);
                        try slices.append(context.my_allocator, slice);
                    }

                    const loop_counter: LoopCounter = switch (last_element_node.id) {
                        .range => blk: {
                            assert(last_element_node.left != .null);

                            const range_start = try builder.resolveRuntimeValue(unit, context, Type.Expect{ .type = .usize }, last_element_node.left, .right);
                            const emit = true;
                            const stack_slot = try builder.emitLocalVariableDeclaration(unit, context, last_element_payload.token, .@"var", .usize, range_start, emit, null);
                            // This is put up here so that the length is constant throughout the loop and we dont have to load the variable unnecessarily
                            const range_end = switch (last_element_node.right) {
                                .null => switch (unit.types.get(slices.pointer[0].type).*) {
                                    .slice => b: {
                                        const len_extract_instruction = try unit.instructions.append(context.my_allocator, .{
                                            .extract_value = .{
                                                .expression = slices.pointer[0],
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
                            try slices.append(context.my_allocator, for_loop_value);

                            switch (unit.types.get(for_loop_value.type).*) {
                                .slice => |slice| {
                                    _ = slice; // autofix
                                    const name = try join_name(context, "__anon_i_", unit.anon_i, 10);
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

                                    const len_extract_value = try unit.instructions.append(context.my_allocator, .{
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

                    const pointer_to_usize = try unit.getPointerType(context, .{
                        .type = .usize,
                        .mutability = .@"const",
                        .nullable = false,
                        .many = false,
                        .termination = .none,
                    });

                    const load = try unit.instructions.append(context.my_allocator, .{
                        .load = .{
                            .value = .{
                                .value = .{
                                    .runtime = loop_counter.stack_slot,
                                },
                                .type = pointer_to_usize,
                            },
                            .type = .usize,
                        },
                    });

                    try builder.appendInstruction(unit, context, load);

                    const compare = try unit.instructions.append(context.my_allocator, .{
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
                    if (slices.length > 0) {
                        const load_i = try unit.instructions.append(context.my_allocator, .{
                            .load = .{
                                .value = .{
                                    .value = .{
                                        .runtime = loop_counter.stack_slot,
                                    },
                                    .type = pointer_to_usize,
                                },
                                .type = .usize,
                            },
                        });
                        try builder.appendInstruction(unit, context, load_i);

                        for (payloads[0..not_range_len], slices.slice()) |payload_node_index, slice| {
                            const pointer_extract_value = try unit.instructions.append(context.my_allocator, .{
                                .extract_value = .{
                                    .expression = slice,
                                    .index = 0,
                                },
                            });
                            try builder.appendInstruction(unit, context, pointer_extract_value);

                            const slice_type = unit.types.get(slice.type).slice;

                            const gep = try unit.instructions.append(context.my_allocator, .{
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
                                },
                            });
                            try builder.appendInstruction(unit, context, gep);

                            const is_by_value = true;
                            const init_instruction = switch (is_by_value) {
                                true => vblk: {
                                    const load_gep = try unit.instructions.append(context.my_allocator, .{
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

                    const load_iterator = try unit.instructions.append(context.my_allocator, .{
                        .load = .{
                            .value = .{
                                .value = .{
                                    .runtime = loop_counter.stack_slot,
                                },
                                .type = pointer_to_usize,
                            },
                            .type = .usize,
                        },
                    });

                    try builder.appendInstruction(unit, context, load_iterator);

                    const increment = try unit.instructions.append(context.my_allocator, .{
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

                    const increment_store = try unit.instructions.append(context.my_allocator, .{
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
                .catch_expression => {
                    assert(statement_node.left != .null);
                    assert(statement_node.right != .null);

                    const expression = try builder.resolveRuntimeValue(unit, context, Type.Expect.none, statement_node.left, .left);
                    const expression_type = unit.types.get(expression.type);
                    switch (expression_type.*) {
                        .error_union => |error_union| switch (unit.types.get(error_union.type).*) {
                            .void => {
                                const extract_value = try unit.instructions.append(context.my_allocator, .{
                                    .extract_value = .{
                                        .expression = expression,
                                        .index = 1,
                                    },
                                });
                                try builder.appendInstruction(unit, context, extract_value);

                                const error_block = try builder.newBasicBlock(unit, context);
                                const clean_block = try builder.newBasicBlock(unit, context);
                                try builder.branch(unit, context, extract_value, error_block, clean_block);
                                builder.current_basic_block = error_block;

                                const v = try builder.resolveRuntimeValue(unit, context, Type.Expect{ .type = .void }, statement_node.right, .left);
                                _ = v; // autofix
                                assert(unit.basic_blocks.get(builder.current_basic_block).terminated);

                                builder.current_basic_block = clean_block;
                                // // try unit.instructions.append(context.my_allocator, .{
                                // //     .branch = .{
                                // //         .condition = extract_value,
                                // //         .from = builder.current_basic_block,
                                // //     },
                                // // });
                                // unreachable;
                            },
                            else => |t| @panic(@tagName(t)),
                        },
                        else => builder.reportCompileError(unit, context, .{
                            .message = "expected error union expression",
                            .node = statement_node.left,
                        }),
                    }
                },
                .try_expression => {
                    assert(statement_node.left != .null);
                    assert(statement_node.right == .null);

                    const expression = try builder.resolveRuntimeValue(unit, context, Type.Expect.none, statement_node.left, .left);
                    const expression_type = unit.types.get(expression.type);
                    switch (expression_type.*) {
                        .error_union => |error_union| switch (unit.types.get(error_union.type).*) {
                            .void => {
                                const extract_value = try unit.instructions.append(context.my_allocator, .{
                                    .extract_value = .{
                                        .expression = expression,
                                        .index = 1,
                                    },
                                });
                                try builder.appendInstruction(unit, context, extract_value);
                                const error_block = try builder.newBasicBlock(unit, context);
                                const clean_block = try builder.newBasicBlock(unit, context);
                                try builder.branch(unit, context, extract_value, error_block, clean_block);
                                builder.current_basic_block = error_block;

                                try builder.buildRet(unit, context, expression);
                                assert(unit.basic_blocks.get(builder.current_basic_block).terminated);

                                builder.current_basic_block = clean_block;
                            },
                            else => |t| @panic(@tagName(t)),
                        },
                        else => |t| @panic(@tagName(t)),
                    }
                },
                else => |t| @panic(@tagName(t)),
            }
        }

        return block_index;
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
                    .@"struct" => |struct_index| {
                        const struct_type = unit.structs.get(struct_index);
                        if (struct_type.optional) {
                            assert(struct_type.backing_type == .null);
                            const condition = try unit.instructions.append(context.my_allocator, .{
                                .extract_value = .{
                                    .expression = optional_expression,
                                    .index = 1,
                                },
                            });
                            try builder.appendInstruction(unit, context, condition);

                            try builder.resolveBranch(unit, context, Type.Expect{ .type = .void }, condition, arguments.taken_expression_node_index, arguments.not_taken_expression_node_index, payload_node.token, optional_expression);
                        } else {
                            unreachable;
                        }
                    },
                    .slice => |slice| {
                        if (slice.nullable) {
                            const pointer_value = try unit.instructions.append(context.my_allocator, .{
                                .extract_value = .{
                                    .expression = optional_expression,
                                    .index = 0,
                                },
                            });

                            try builder.appendInstruction(unit, context, pointer_value);

                            const condition = try unit.instructions.append(context.my_allocator, .{
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
                            try builder.appendInstruction(unit, context, condition);
                            try builder.resolveBranch(unit, context, Type.Expect{ .type = .void }, condition, arguments.taken_expression_node_index, arguments.not_taken_expression_node_index, payload_node.token, optional_expression);
                        } else {
                            unreachable;
                        }
                    },
                    .pointer => |pointer| {
                        if (pointer.nullable) {
                            const condition = try unit.instructions.append(context.my_allocator, .{
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
                            try builder.appendInstruction(unit, context, condition);
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
        const taken_block = try builder.newBasicBlock(unit, context);
        const exit_block = try builder.newBasicBlock(unit, context);
        const not_taken_block = if (not_taken_node_index != .null) try builder.newBasicBlock(unit, context) else exit_block;
        try builder.exit_blocks.append(context.my_allocator, exit_block);
        try builder.branch(unit, context, condition, taken_block, not_taken_block);

        builder.current_basic_block = taken_block;

        if (maybe_optional_value) |optional_value| {
            assert(optional_payload_token != .null);
            switch (unit.types.get(optional_value.type).*) {
                .@"struct" => |struct_index| {
                    const optional_struct = unit.structs.get(struct_index);
                    assert(optional_struct.optional);
                    assert(optional_struct.backing_type == .null);
                    // TODO: avoid local symbol name collisions
                    const unwrap = try unit.instructions.append(context.my_allocator, .{
                        .extract_value = .{
                            .expression = optional_value,
                            .index = 0,
                        },
                    });
                    try builder.appendInstruction(unit, context, unwrap);
                    const emit = true;
                    const optional_payload = unit.struct_fields.get(optional_struct.fields.pointer[0]);
                    _ = try builder.emitLocalVariableDeclaration(unit, context, optional_payload_token, .@"const", optional_payload.type, .{
                        .value = .{
                            .runtime = unwrap,
                        },
                        .type = optional_payload.type,
                    }, emit, null);
                },
                .slice => |slice| {
                    const not_null_slice = try unit.getSliceType(context, .{
                        .child_pointer_type = blk: {
                            const child_pointer_type = unit.types.get(slice.child_pointer_type).pointer;

                            break :blk try unit.getPointerType(context, .{
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

                    const unwrap = try unit.instructions.append(context.my_allocator, .{
                        .cast = .{
                            .id = .slice_to_not_null,
                            .value = optional_value,
                            .type = not_null_slice,
                        },
                    });
                    try builder.appendInstruction(unit, context, unwrap);

                    const emit = true;
                    _ = try builder.emitLocalVariableDeclaration(unit, context, optional_payload_token, .@"const", not_null_slice, .{
                        .value = .{
                            .runtime = unwrap,
                        },
                        .type = not_null_slice,
                    }, emit, null);
                },
                .pointer => |pointer| {
                    const pointer_type = try unit.getPointerType(context, .{
                        .type = pointer.type,
                        .termination = pointer.termination,
                        .mutability = pointer.mutability,
                        .many = pointer.many,
                        .nullable = false,
                    });

                    const unwrap = try unit.instructions.append(context.my_allocator, .{
                        .cast = .{
                            .id = .slice_to_not_null,
                            .value = optional_value,
                            .type = pointer_type,
                        },
                    });
                    try builder.appendInstruction(unit, context, unwrap);

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
        const br = try unit.instructions.append(context.my_allocator, .{
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
        const instruction = try unit.instructions.append(context.my_allocator, .{
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
                    const typecheck_enum_result = try unit.typecheckSwitchEnums(context, enum_type, case_nodes);

                    const group_index = for (typecheck_enum_result.switch_case_groups.pointer[0..typecheck_enum_result.switch_case_groups.length], 0..) |switch_case_group, switch_case_group_index| {
                        break for (switch_case_group.pointer[0..switch_case_group.length]) |field_index| {
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

    fn resolveFieldAccess(builder: *Builder, unit: *Unit, context: *const Context, type_expect: Type.Expect, node_index: Node.Index, side: Side) !V {
        const node = unit.getNode(node_index);
        const right_node = unit.getNode(node.right);
        assert(right_node.id == .identifier);
        const identifier = unit.getExpectedTokenBytes(right_node.token, .identifier);
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
                        const global = try builder.referenceGlobalDeclaration(unit, context, lookup.scope, lookup.declaration);
                        const pointer_type = try unit.getPointerType(context, .{
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
                                    const load = try unit.instructions.append(context.my_allocator, .{
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

                                    try builder.appendInstruction(unit, context, load);
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
                        .@"enum" => |enum_index| blk: {
                            const enum_type = unit.enums.get(enum_index);
                            const field_index = for (enum_type.fields.slice()) |enum_field_index| {
                                const enum_field = unit.enum_fields.get(enum_field_index);
                                if (enum_field.name == identifier_hash) {
                                    break enum_field_index;
                                }
                            } else @panic("Right identifier not found");//std.debug.panic("Right identifier '{s}' not found", .{identifier});
                            break :blk V{
                                .value = .{
                                    .@"comptime" = .{
                                        .enum_value = field_index,
                                    },
                                },
                                .type = type_index,
                            };
                        },
                        .@"struct" => |struct_index| {
                            const struct_type = unit.structs.get(struct_index);
                            const field_index = for (struct_type.fields.slice()) |enum_field_index| {
                                const enum_field = unit.struct_fields.get(enum_field_index);
                                if (enum_field.name == identifier_hash) {
                                    break enum_field_index;
                                }
                            } else @panic("Right identifier not found");//std.debug.panic("Right identifier '{s}' not found", .{identifier});
                            _ = field_index;
                            unreachable;
                            // break :blk V{
                            //     .value = .{
                            //         .@"comptime" = .{
                            //             .enum_value = field_index,
                            //         },
                            //     },
                            //     .type = type_index,
                            // };
                        },
                        .@"error" => |error_index| blk: {
                            const error_type = unit.errors.get(error_index);
                            const field_index = for (error_type.fields.slice()) |error_field_index| {
                                const error_field = unit.error_fields.get(error_field_index);
                                if (error_field.name == identifier_hash) {
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
                    };

                    break :b result;
                },
                else => |t| @panic(@tagName(t)),
            },
            .runtime => |_| b: {
                const left_type = unit.types.get(left.type);
                switch (left_type.*) {
                    .pointer => |pointer| switch (unit.types.get(pointer.type).*) {
                        .array => |array| {
                            assert(side == .right);
                            assert(byte_equal(identifier, "len"));
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
                            const slice_field: enum {
                                ptr,
                                len,
                            } = if (byte_equal("ptr", identifier)) .ptr else if (byte_equal("len", identifier)) .len else unreachable;
                            const field_type = switch (slice_field) {
                                .ptr => slice.child_pointer_type,
                                .len => Type.Index.usize,
                            };
                            const field_index = @intFromEnum(slice_field);

                            const gep = try unit.instructions.append(context.my_allocator, .{
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
                                },
                            });
                            try builder.appendInstruction(unit, context, gep);

                            const gep_value = V{
                                .value = .{
                                    .runtime = gep,
                                },
                                .type = try unit.getPointerType(context, .{
                                    .type = .usize,
                                    .many = false,
                                    .nullable = false,
                                    .termination = .none,
                                    .mutability = .@"const",
                                }),
                            };

                            switch (side) {
                                .left => break :b gep_value,
                                .right => {
                                    const load = try unit.instructions.append(context.my_allocator, .{
                                        .load = .{
                                            .value = gep_value,
                                            .type = field_type,
                                        },
                                    });
                                    try builder.appendInstruction(unit, context, load);

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
                                assert(byte_equal(identifier, "len"));

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
                            .@"struct" => |struct_index| {
                                const struct_type = unit.structs.get(struct_index);
                                const fields = struct_type.fields.slice();

                                for (fields, 0..) |field_index, i| {
                                    const field = unit.struct_fields.get(field_index);
                                    if (field.name == identifier_hash) {
                                        assert(struct_type.backing_type == .null);

                                        const load = try unit.instructions.append(context.my_allocator, .{
                                            .load = .{
                                                .value = left,
                                                .type = pointer.type,
                                            },
                                        });
                                        try builder.appendInstruction(unit, context, load);

                                        // GEP because this is still a pointer
                                        const gep = try unit.instructions.append(context.my_allocator, .{
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
                                            },
                                        });
                                        try builder.appendInstruction(unit, context, gep);

                                        const mutability = child_pointer.mutability;
                                        const gep_pointer_type = try unit.getPointerType(context, .{
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
                                                const field_load = try unit.instructions.append(context.my_allocator, .{
                                                    .load = .{
                                                        .value = gep_value,
                                                        .type = field.type,
                                                    },
                                                });
                                                try builder.appendInstruction(unit, context, field_load);

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
                        .@"struct" => |struct_index| {
                            const struct_type = unit.structs.get(struct_index);
                            const fields = struct_type.fields.slice();

                            for (fields, 0..) |field_index, i| {
                                const field = unit.struct_fields.get(field_index);
                                if (field.name == identifier_hash) {
                                    switch (struct_type.backing_type) {
                                        .null => {
                                            const gep = try unit.instructions.append(context.my_allocator, .{
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
                                                },
                                            });
                                            try builder.appendInstruction(unit, context, gep);

                                            const gep_value = V{
                                                .value = .{
                                                    .runtime = gep,
                                                },
                                                .type = try unit.getPointerType(context, .{
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
                                                    const load = try unit.instructions.append(context.my_allocator, .{
                                                        .load = .{
                                                            .value = gep_value,
                                                            .type = field.type,
                                                        },
                                                    });

                                                    try builder.appendInstruction(unit, context, load);

                                                    break :b V{
                                                        .value = .{
                                                            .runtime = load,
                                                        },
                                                        .type = field.type,
                                                    };
                                                },
                                            }
                                        },
                                        else => {
                                            assert(side == .right);

                                            const load = try unit.instructions.append(context.my_allocator, .{
                                                .load = .{
                                                    .value = left,
                                                    .type = struct_type.backing_type,
                                                },
                                            });
                                            try builder.appendInstruction(unit, context, load);

                                            var bit_offset: u32 = 0;
                                            for (fields[0..i]) |fi| {
                                                const f = unit.struct_fields.get(fi);
                                                const f_type = unit.types.get(f.type);
                                                const bit_size = f_type.getBitSize(unit);
                                                bit_offset += bit_size;
                                            }

                                            const backing_type = unit.types.get(struct_type.backing_type);
                                            const instruction_to_truncate = switch (bit_offset) {
                                                0 => load,
                                                else => shl: {
                                                    const shl = try unit.instructions.append(context.my_allocator, .{
                                                        .integer_binary_operation = .{
                                                            .id = .shift_right,
                                                            .left = .{
                                                                .value = .{
                                                                    .runtime = load,
                                                                },
                                                                .type = struct_type.backing_type,
                                                            },
                                                            .right = .{
                                                                .value = .{
                                                                    .@"comptime" = .{
                                                                        .constant_int = .{
                                                                            .value = bit_offset,
                                                                        },
                                                                    },
                                                                },
                                                                .type = struct_type.backing_type,
                                                            },
                                                            .signedness = backing_type.integer.signedness,
                                                        },
                                                    });
                                                    try builder.appendInstruction(unit, context, shl);

                                                    break :shl shl;
                                                },
                                            };

                                            const f_type = unit.types.get(field.type);
                                            const f_bit_size = f_type.getBitSize(unit);

                                            const backing_type_size = backing_type.getBitSize(unit);

                                            switch (f_bit_size == backing_type_size) {
                                                true => {
                                                    //instruction_to_truncate,
                                                    unreachable;
                                                },
                                                false => {
                                                    const truncate = try unit.instructions.append(context.my_allocator, .{
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
                                                    try builder.appendInstruction(unit, context, truncate);
                                                    break :b V{
                                                        .value = .{
                                                            .runtime = truncate,
                                                        },
                                                        .type = field.type,
                                                    };
                                                },
                                            }
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
                    .pointer_var_to_const => {
                        const cast = try unit.instructions.append(context.my_allocator, .{
                            .cast = .{
                                .id = .pointer_var_to_const,
                                .value = result,
                                .type = ti,
                            },
                        });
                        try builder.appendInstruction(unit, context, cast);

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
                        const cast = try unit.instructions.append(context.my_allocator, .{
                            .cast = .{
                                .id = .pointer_to_nullable,
                                .value = result,
                                .type = ti,
                            },
                        });
                        try builder.appendInstruction(unit, context, cast);

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
                                    const v = V{
                                        .value = .{
                                            .@"comptime" = .undefined,
                                        },
                                        .type = ti,
                                    };
                                    const error_union_builder = try unit.instructions.append(context.my_allocator, .{
                                        .insert_value = .{
                                            .expression = v,
                                            .index = 0,
                                            .new_value = result,
                                        },
                                    });
                                    try builder.appendInstruction(unit, context, error_union_builder);

                                    const final_error_union = try unit.instructions.append(context.my_allocator, .{
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
                                    try builder.appendInstruction(unit, context, final_error_union);

                                    return .{
                                        .value = .{
                                            .runtime = final_error_union,
                                        },
                                        .type = ti,
                                    };
                                },
                                else => |t| @panic(@tagName(t)),
                            },
                            else => |t| @panic(@tagName(t)),
                        }
                        unreachable;
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
        try builder.insertDebugCheckPoint(unit, context, if_node.token);

        const condition = try builder.resolveRuntimeValue(unit, context, Type.Expect{ .type = .bool }, condition_node_index, .right);
        const result: V = switch (condition.value) {
            .@"comptime" => |ct| switch (ct.bool) {
                true => try builder.resolveRuntimeValue(unit, context, type_expect, taken_expression_node_index, .right),
                false => try builder.resolveRuntimeValue(unit, context, type_expect, not_taken_expression_node_index, .right),
            },
            .runtime => |condition_instruction| {
                try builder.resolveBranch(unit, context, type_expect, condition_instruction, taken_expression_node_index, not_taken_expression_node_index, .null, null);
                // TODO WARN SAFETY:
                return undefined;
            },
            else => unreachable,
        };

        return result;
    }

    fn emitReturn(builder: *Builder, unit: *Unit, context: *const Context, return_node_index: Node.Index) !void {
        const return_node = unit.getNode(return_node_index);
        assert(return_node.id == .@"return");
        assert(return_node.left != .null);
        assert(return_node.right == .null);
        const return_value_node_index = return_node.left;
        const return_type = unit.getReturnType(builder.current_function);
        const return_value = try builder.resolveRuntimeValue(unit, context, Type.Expect{
            .type = return_type,
        }, return_value_node_index, .right);

        if (builder.return_block != .null) {
            if (builder.return_phi != .null) {
                const phi = &unit.instructions.get(builder.return_phi).phi;
                try phi.values.append(context.my_allocator, return_value);
                try phi.basic_blocks.append(context.my_allocator, builder.current_basic_block);
            }

            assert(builder.current_basic_block != builder.return_block);

            try builder.jump(unit, context, builder.return_block);
        } else if (builder.exit_blocks.length > 0) {
            builder.return_phi = try unit.instructions.append(context.my_allocator, .{
                .phi = .{
                    .type = return_type,
                },
            });

            builder.return_block = try builder.newBasicBlock(unit, context);
            const current_basic_block = builder.current_basic_block;
            builder.current_basic_block = builder.return_block;

            try builder.appendInstruction(unit, context, builder.return_phi);

            const phi = &unit.instructions.get(builder.return_phi).phi;
            try phi.values.append(context.my_allocator, return_value);
            try phi.basic_blocks.append(context.my_allocator, current_basic_block);

            try builder.buildRet(unit, context, .{
                .value = .{
                    .runtime = builder.return_phi,
                },
                .type = return_type,
            });

            builder.current_basic_block = current_basic_block;
            try builder.jump(unit, context, builder.return_block);
        } else {
            try builder.buildRet(unit, context, return_value);
        }
    }

    fn buildUnreachable(builder: *Builder, unit: *Unit, context: *const Context) !void {
        const instruction = try unit.instructions.append(context.my_allocator, .@"unreachable");
        try builder.appendInstruction(unit, context, instruction);
        unit.basic_blocks.get(builder.current_basic_block).terminated = true;
    }

    fn buildTrap(builder: *Builder, unit: *Unit, context: *const Context) !void {
        const instruction = try unit.instructions.append(context.my_allocator, .trap);
        try builder.appendInstruction(unit, context, instruction);

        try builder.buildUnreachable(unit, context);
    }

    fn buildRet(builder: *Builder, unit: *Unit, context: *const Context, value: V) !void {
        const ret = try unit.instructions.append(context.my_allocator, .{
            .ret = value,
        });
        try builder.appendInstruction(unit, context, ret);
        unit.basic_blocks.get(builder.current_basic_block).terminated = true;
    }

    fn reportCompileError(builder: *Builder, unit: *Unit, context: *const Context, err: Error) noreturn {
        const err_node = unit.getNode(err.node);
        const file = unit.files.get(builder.current_file);
        const token_debug_info = builder.getTokenDebugInfo(unit, err_node.token);
        std.io.getStdOut().writer().print("{s}:{}:{}: \x1b[31merror:\x1b[0m ", .{ file.getPath(context.allocator) catch unreachable, token_debug_info.line + 1, token_debug_info.column + 1 }) catch unreachable;
        std.io.getStdOut().writer().writeAll(err.message) catch unreachable;
        std.io.getStdOut().writer().writeByte('\n') catch unreachable;
        std.os.abort();
    }

    fn reportFormattedCompileError(builder: *Builder, unit: *Unit, context: *const Context, node_index: Node.Index, comptime format: []const u8, args: anytype) noreturn {
        const err_node = unit.getNode(node_index);
        const file = unit.files.get(builder.current_file);
        const token_debug_info = builder.getTokenDebugInfo(unit, err_node.token);
        std.io.getStdOut().writer().print("{s}:{}:{}: \x1b[31merror:\x1b[0m ", .{ file.getPath(context.allocator) catch unreachable, token_debug_info.line + 1, token_debug_info.column + 1 }) catch unreachable;
        std.io.getStdOut().writer().print(format, args) catch unreachable;
        std.io.getStdOut().writer().writeByte('\n') catch unreachable;
        std.os.abort();
    }

    fn populateTestFunctions(builder: *Builder, unit: *Unit, context: *const Context) !void {
        _ = builder;
        const builtin_package = try unit.importPackage(context, unit.root_package.dependencies.get("builtin").?);
        const builtin_file_index = builtin_package.file.index;
        const builtin_file = unit.files.get(builtin_file_index);
        const builtin_file_struct_index = unit.types.get(builtin_file.type).@"struct";
        const builtin_file_struct = unit.structs.get(builtin_file_struct_index);
        const test_functions_name = "test_functions";
        const test_functions_name_hash = try unit.processIdentifier(context, test_functions_name);
        const test_functions = builtin_file_struct.scope.scope.declarations.get(test_functions_name_hash).?;
        const test_slice_type = test_functions.type;
        const test_type = unit.types.get(test_slice_type).slice.child_type;
        assert(test_functions.kind == .global);
        const test_functions_global = @fieldParentPtr(Debug.Declaration.Global, "declaration", test_functions);
        assert(test_functions_global.declaration.mutability == .@"var");
        const array_type = try unit.getArrayType(context, .{
            .type = test_type,
            .count = unit.test_functions.values().len,
            .termination = .none,
        });

        const struct_test_type = unit.types.get(test_type);
        const test_type_struct = unit.structs.get(struct_test_type.@"struct");
        assert(test_type_struct.fields.length == 2);
        const first_field = unit.struct_fields.get(test_type_struct.fields.pointer[0]);
        // const second_field = unit.struct_fields.get(test_type_struct.fields.items[1]);

        var list = try UnpinnedArray(V.Comptime).initialize_with_capacity(context.my_allocator, unit.test_functions.length);
        for (unit.test_functions.keys(), unit.test_functions.values()) |test_function_name_global, test_function_global| {
            var fields = try UnpinnedArray(V.Comptime).initialize_with_capacity(context.my_allocator, 2);
            const name = unit.getIdentifier(test_function_name_global.initial_value.string_literal);
            const name_slice = try unit.constant_slices.append(context.my_allocator, .{
                .array = test_function_name_global,
                .start = 0,
                .end = name.len,
                .type = first_field.type,
            });
            fields.append_with_capacity(.{
                .constant_slice = name_slice,
            });
            fields.append_with_capacity(.{
                .global = test_function_global,
            });
            const constant_struct = try unit.constant_structs.append(context.my_allocator, .{
                .fields = fields.slice(),
                .type = test_type,
            });

            list.append_with_capacity(.{
                .constant_struct = constant_struct,
            });
        }

        const constant_array = try unit.constant_arrays.append(context.my_allocator, .{
            .type = array_type,
            .values = list.slice(),
        });

        const array_name = "_anon_test_function_array";
        const array_name_hash = try unit.processIdentifier(context, array_name);
        const test_function_array_global_index = try unit.global_declarations.append(context.my_allocator, .{
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
        const test_function_array_global = unit.global_declarations.get(test_function_array_global_index);
        try unit.data_to_emit.append(context.my_allocator, test_function_array_global);
        const constant_slice = try unit.constant_slices.append(context.my_allocator, .{
            .array = test_function_array_global,
            .start = 0,
            .end = list.length,
            .type = test_functions_global.declaration.type,
        });

        test_functions_global.initial_value = .{
            .constant_slice = constant_slice,
        };
    }
};

pub const Enum = struct {
    scope: Debug.Scope.Global,
    fields: UnpinnedArray(Enum.Field.Index) = .{},
    backing_type: Type.Index,

    pub const Field = struct {
        value: usize,
        name: u32,
        parent: Type.Index,

        pub const List = BlockList(@This(), enum {});
        pub usingnamespace @This().List.Index;
    };

    pub const List = BlockList(@This(), enum {});
    pub usingnamespace @This().List.Index;
};

pub const Unit = struct {
    node_buffer: Node.List = .{},
    files: Debug.File.List = .{},
    types: Type.List = .{},
    structs: Struct.List = .{},
    unions: Type.Union.List = .{},
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
    errors: Type.Error.List = .{},
    error_sets: Type.Error.Set.List = .{},
    error_fields: Type.Error.Field.List = .{},
    token_buffer: Token.Buffer = .{},
    node_lists: UnpinnedArray(UnpinnedArray(Node.Index)) = .{},
    file_token_offsets: MyHashMap(Token.Range, Debug.File.Index) = .{},
    file_map: MyHashMap([]const u8, Debug.File.Index) = .{},
    identifiers: MyHashMap(u32, []const u8) = .{},
    string_literal_values: MyHashMap(u32, [:0]const u8) = .{},
    string_literal_globals: MyHashMap(u32, *Debug.Declaration.Global) = .{},

    optionals: MyHashMap(Type.Index, Type.Index) = .{},
    pointers: MyHashMap(Type.Pointer, Type.Index) = .{},
    slices: MyHashMap(Type.Slice, Type.Index) = .{},
    arrays: MyHashMap(Type.Array, Type.Index) = .{},
    integers: MyHashMap(Type.Integer, Type.Index) = .{},
    global_array_constants: MyHashMap(V.Comptime.ConstantArray.Index, *Debug.Declaration.Global) = .{},

    code_to_emit: MyHashMap(Function.Definition.Index, *Debug.Declaration.Global) = .{},
    data_to_emit: UnpinnedArray(*Debug.Declaration.Global) = .{},
    external_functions: MyHashMap(Type.Index, *Debug.Declaration.Global) = .{},
    type_declarations: MyHashMap(Type.Index, *Debug.Declaration.Global) = .{},
    struct_type_map: MyHashMap(Struct.Index, Type.Index) = .{},
    test_functions: MyHashMap(*Debug.Declaration.Global, *Debug.Declaration.Global) = .{},
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
    root_package: *Package = undefined,
    main_package: ?*Package = null,
    descriptor: Descriptor,
    discard_identifiers: usize = 0,
    anon_i: usize = 0,
    anon_arr: usize = 0,

    fn dumpFunctionDefinition(unit: *Unit, function_definition_index: Function.Definition.Index) void {
        const function_definition = unit.function_definitions.get(function_definition_index);
        _ = function_definition; // autofix

        // for (function_definition.basic_blocks.slice()) |basic_block_index| {
        //     const basic_block = unit.basic_blocks.get(basic_block_index);
        //     // logln(.compilation, .ir, "[#{}]:", .{BasicBlock.unwrap(basic_block_index)});
        //
        //     for (basic_block.instructions.slice()) |instruction_index| {
        //         const instruction = unit.instructions.get(instruction_index);
        //         // log(.compilation, .ir, "    %{}: {s} ", .{ Instruction.unwrap(instruction_index), @tagName(instruction.*) });
        //
        //         switch (instruction.*) {
        //             .call => |call| {
        //                 switch (call.callable.value) {
        //                     .@"comptime" => |ct| switch (ct) {
        //                         .global => |global| {},//log(.compilation, .ir, "{s}(", .{unit.getIdentifier(global.declaration.name)}),
        //                         else => unreachable,
        //                     },
        //                     .runtime => |ii| log(.compilation, .ir, "%{}(", .{Instruction.unwrap(ii)}),
        //                     else => |t| @panic(@tagName(t)),
        //                 }
        //
        //                 for (call.arguments) |arg| {
        //                     switch (arg.value) {
        //                         .@"comptime" => log(.compilation, .ir, "comptime", .{}),
        //                         .runtime => |ii| log(.compilation, .ir, "%{}, ", .{Instruction.unwrap(ii)}),
        //                         else => |t| @panic(@tagName(t)),
        //                     }
        //                 }
        //
        //                 log(.compilation, .ir, ")", .{});
        //             },
        //             .insert_value => |insert_value| {
        //                 log(.compilation, .ir, "aggregate ", .{});
        //                 switch (insert_value.expression.value) {
        //                     .@"comptime" => log(.compilation, .ir, "comptime", .{}),
        //                     .runtime => |ii| log(.compilation, .ir, "%{}", .{Instruction.unwrap(ii)}),
        //                     else => unreachable,
        //                 }
        //                 log(.compilation, .ir, ", {}, ", .{insert_value.index});
        //                 switch (insert_value.new_value.value) {
        //                     .@"comptime" => log(.compilation, .ir, "comptime", .{}),
        //                     .runtime => |ii| log(.compilation, .ir, "%{}", .{Instruction.unwrap(ii)}),
        //                     else => unreachable,
        //                 }
        //             },
        //             .extract_value => |extract_value| {
        //                 log(.compilation, .ir, "aggregate ", .{});
        //                 switch (extract_value.expression.value) {
        //                     .@"comptime" => log(.compilation, .ir, "comptime", .{}),
        //                     .runtime => |ii| log(.compilation, .ir, "%{}", .{Instruction.unwrap(ii)}),
        //                     else => unreachable,
        //                 }
        //                 log(.compilation, .ir, ", {}", .{extract_value.index});
        //             },
        //             .get_element_pointer => |gep| {
        //                 log(.compilation, .ir, "aggregate %{}, ", .{Instruction.unwrap(gep.pointer)});
        //                 switch (gep.index.value) {
        //                     .@"comptime" => log(.compilation, .ir, "comptime", .{}),
        //                     .runtime => |ii| log(.compilation, .ir, "%{}", .{Instruction.unwrap(ii)}),
        //                     else => unreachable,
        //                 }
        //             },
        //             .load => |load| {
        //                 switch (load.value.value) {
        //                     .@"comptime" => |ct| switch (ct) {
        //                         .global => |global| log(.compilation, .ir, "{s}", .{unit.getIdentifier(global.declaration.name)}),
        //                         else => |t| @panic(@tagName(t)),
        //                     },
        //                     .runtime => |ii| {
        //                         log(.compilation, .ir, "%{}", .{@intFromEnum(ii)});
        //                     },
        //                     else => unreachable,
        //                 }
        //             },
        //             .push_scope => |push_scope| {
        //                 log(.compilation, .ir, "0x{x} -> 0x{x}", .{ @as(u24, @truncate(@intFromPtr(push_scope.old))), @as(u24, @truncate(@intFromPtr(push_scope.new))) });
        //             },
        //             .pop_scope => |pop_scope| {
        //                 log(.compilation, .ir, "0x{x} <- 0x{x}", .{ @as(u24, @truncate(@intFromPtr(pop_scope.new))), @as(u24, @truncate(@intFromPtr(pop_scope.old))) });
        //             },
        //             .debug_checkpoint => |checkpoint| {
        //                 log(.compilation, .ir, "{}, {}", .{ checkpoint.line, checkpoint.column });
        //             },
        //             .argument_declaration => |arg| {
        //                 log(.compilation, .ir, "\"{s}\"", .{unit.getIdentifier(arg.declaration.name)});
        //             },
        //             .cast => |cast| {
        //                 log(.compilation, .ir, "{s}", .{@tagName(cast.id)});
        //             },
        //             .jump => |jump| {
        //                 log(.compilation, .ir, "[#{}]", .{BasicBlock.unwrap(jump.to)});
        //             },
        //             .branch => |branch| {
        //                 log(.compilation, .ir, "bool %{}, [#{}, #{}]", .{ Instruction.unwrap(branch.condition), BasicBlock.unwrap(branch.taken), BasicBlock.unwrap(branch.not_taken) });
        //             },
        //             .phi => |phi| {
        //                 for (phi.values.pointer[0..phi.values.length], phi.basic_blocks.pointer[0..phi.basic_blocks.length]) |value, bb| {
        //                     log(.compilation, .ir, "(%{}, #{}), ", .{ switch (value.value) {
        //                         .@"comptime" => 0xffff_ffff,
        //                         .runtime => |ii| @intFromEnum(ii),
        //                         else => unreachable,
        //                     }, @intFromEnum(bb) });
        //                 }
        //             },
        //             .integer_compare => |compare| {
        //                 log(.compilation, .ir, "{s} ", .{@tagName(compare.id)});
        //                 switch (compare.left.value) {
        //                     .@"comptime" => {
        //                         log(.compilation, .ir, "$comptime, ", .{});
        //                     },
        //                     .runtime => |ii| {
        //                         log(.compilation, .ir, "%{}, ", .{@intFromEnum(ii)});
        //                     },
        //                     else => unreachable,
        //                 }
        //
        //                 switch (compare.right.value) {
        //                     .@"comptime" => {
        //                         log(.compilation, .ir, "$comptime", .{});
        //                     },
        //                     .runtime => |ii| {
        //                         log(.compilation, .ir, "%{}", .{@intFromEnum(ii)});
        //                     },
        //                     else => unreachable,
        //                 }
        //             },
        //             else => {},
        //         }
        //         // logln(.compilation, .ir, "", .{});
        //     }
        // }
    }

    fn getReturnType(unit: *Unit, function_index: Function.Definition.Index) Type.Index {
        const function = unit.function_definitions.get(function_index);
        const function_type = unit.types.get(function.type);
        const function_prototype = unit.function_prototypes.get(function_type.function);
        return function_prototype.return_type;
    }

    fn typecheckSwitchEnums(unit: *Unit, context: *const Context, enum_type: *Enum, switch_case_node_list: []const Node.Index) !TypeCheckSwitchEnums {
        var result = TypeCheckSwitchEnums{
            .switch_case_groups = try UnpinnedArray(UnpinnedArray(Enum.Field.Index)).initialize_with_capacity(context.my_allocator, @intCast(switch_case_node_list.len)),
        };

        var existing_enums = UnpinnedArray(Enum.Field.Index){};

        for (switch_case_node_list, 0..) |switch_case_node_index, index| {
            const switch_case_node = unit.getNode(switch_case_node_index);

            switch (switch_case_node.left) {
                else => {
                    const switch_case_condition_node = unit.getNode(switch_case_node.left);
                    var switch_case_group = UnpinnedArray(Enum.Field.Index){};

                    switch (switch_case_condition_node.id) {
                        .enum_literal => {
                            if (try unit.typeCheckEnumLiteral(context, Token.addInt(switch_case_condition_node.token, 1), enum_type)) |enum_field_index| {
                                for (existing_enums.slice()) |existing| {
                                    if (enum_field_index == existing) {
                                        // Duplicate case
                                        unreachable;
                                    }
                                }

                                try switch_case_group.append(context.my_allocator, enum_field_index);
                                try existing_enums.append(context.my_allocator, enum_field_index);
                            } else {
                                unreachable;
                            }
                        },
                        .node_list => {
                            const node_list = unit.getNodeListFromNode(switch_case_condition_node);
                            try switch_case_group.ensure_capacity(context.my_allocator, @intCast(node_list.len));

                            for (node_list) |case_condition_node_index| {
                                const case_condition_node = unit.getNode(case_condition_node_index);
                                switch (case_condition_node.id) {
                                    .enum_literal => {
                                        if (try unit.typeCheckEnumLiteral(context, Token.addInt(case_condition_node.token, 1), enum_type)) |enum_field_index| {
                                            for (existing_enums.slice()) |existing| {
                                                if (enum_field_index == existing) {
                                                    // Duplicate case
                                                    unreachable;
                                                }
                                            }

                                            try existing_enums.append(context.my_allocator, enum_field_index);
                                            switch_case_group.append_with_capacity(enum_field_index);
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

                    result.switch_case_groups.append_with_capacity(switch_case_group);
                },
                .null => {
                    result.else_switch_case_group_index = index;
                },
            }
        }

        return result;
    }

    fn typeCheckEnumLiteral(unit: *Unit, context: *const Context, token_index: Token.Index, enum_type: *Enum) !?Enum.Field.Index {
        const enum_name = unit.getExpectedTokenBytes(token_index, .identifier);
        const enum_name_hash = try unit.processIdentifier(context, enum_name);
        for (enum_type.fields.slice()) |enum_field_index| {
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
        const node_list = unit.node_lists.slice()[Node.unwrap(list_index)];
        return node_list.pointer[0..node_list.length];
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
        const index = Token.unwrap(token_index);
        assert(index < unit.token_buffer.length);
        const id = unit.token_buffer.ids[index];
        // logln(.compilation, .token_bytes, "trying to get {s} from token of id {s}", .{ @tagName(expected_id), @tagName(id) });
        if (id != expected_id) @panic("Unexpected token");
        const offset = unit.token_buffer.offsets[index];
        const len = unit.token_buffer.lengths[index];
        const file_index = unit.findTokenFile(token_index);
        const file = unit.files.get(file_index);
        const bytes = file.source_code[offset..][0..len];
        return bytes;
    }

    fn getOptionalType(unit: *Unit, context: *const Context, element_type: Type.Index) !Type.Index {
        if (unit.optionals.get(element_type)) |optional| {
            return optional;
        } else {
            const optional_struct_index = try unit.structs.append(context.my_allocator, .{
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
            try optional_struct.fields.ensure_capacity(context.my_allocator, 2);
            const types = [_]Type.Index{ element_type, .bool };
            const names = [_][]const u8{ "payload", "is_valid" };
            for (types, names) |t, name| {
                const field = try unit.struct_fields.append(context.my_allocator, .{
                    .name = try unit.processIdentifier(context, name),
                    .type = t,
                    .default_value = null,
                });

                optional_struct.fields.append_with_capacity(field);
            }

            const optional_type_index = try unit.types.append(context.my_allocator, .{
                .@"struct" = optional_struct_index,
            });

            try unit.optionals.put_no_clobber(context.my_allocator, element_type, optional_type_index);

            return optional_type_index;
        }
    }

    fn getPointerType(unit: *Unit, context: *const Context, pointer: Type.Pointer) !Type.Index {
        if (unit.pointers.get(pointer)) |existing_type_index| {
            return existing_type_index;
        } else {
            const type_index = try unit.types.append(context.my_allocator, .{
                .pointer = pointer,
            });
            try unit.pointers.put_no_clobber(context.my_allocator, pointer, type_index);

            return type_index;
        }
    }

    fn getSliceType(unit: *Unit, context: *const Context, slice: Type.Slice) !Type.Index {
        if (unit.slices.get(slice)) |existing_type_index| {
            return existing_type_index;
        } else {
            const type_index = try unit.types.append(context.my_allocator, .{
                .slice = slice,
            });
            try unit.slices.put_no_clobber(context.my_allocator, slice, type_index);

            return type_index;
        }
    }

    fn getArrayType(unit: *Unit, context: *const Context, array: Type.Array) !Type.Index {
        if (unit.arrays.get(array)) |array_type| {
            return array_type;
        } else {
            const array_type = try unit.types.append(context.my_allocator, .{
                .array = array,
            });
            try unit.arrays.put_no_clobber(context.my_allocator, array, array_type);

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
                    const type_index = try unit.types.append(context.my_allocator, .{
                        .integer = integer,
                    });
                    try unit.integers.put_no_clobber(context.my_allocator, integer, type_index);
                    return type_index;
                }
            },
        };

        return existing_type_index;
    }

    fn processIdentifier(unit: *Unit, context: *const Context, string: []const u8) !u32 {
        const hash = data_structures.my_hash(string);
        if (unit.identifiers.get_pointer(hash) == null) {
            try unit.identifiers.put_no_clobber(context.my_allocator, hash, string);
        }
        return hash;
    }

    fn fixupStringLiteral(unit: *Unit, context: *const Context, token_index: Token.Index) ![:0]const u8 {
        const bytes = unit.getExpectedTokenBytes(token_index, .string_literal);
        // Eat double quotes
        const string_literal_bytes = bytes[1..][0 .. bytes.len - 2];
        var fixed_string = try UnpinnedArray(u8).initialize_with_capacity(context.my_allocator, @intCast(string_literal_bytes.len + 1));
        var i: usize = 0;

        while (i < string_literal_bytes.len) : (i += 1) {
            const ch = string_literal_bytes[i];
            switch (ch) {
                '\\' => {
                    i += 1;
                    const next_ch = string_literal_bytes[i];
                    switch (next_ch) {
                        'n' => fixed_string.append_with_capacity('\n'),
                        else => unreachable,
                    }
                },
                else => fixed_string.append_with_capacity(ch),
            }
        }

        fixed_string.append_with_capacity(0);

        const string = fixed_string.slice()[0 .. fixed_string.length - 1 :0];

        return string;
    }

    pub fn getIdentifier(unit: *Unit, hash: u32) []const u8 {
        return unit.identifiers.get(hash).?;
    }

    pub fn analyze(unit: *Unit, context: *const Context) !void {
        const builder = try context.my_allocator.allocate_one(Builder);
        builder.* = .{
            .generate_debug_info = unit.descriptor.generate_debug_information,
            .emit_ir = true,
            .current_scope = &unit.scope.scope,
        };

        inline for (@typeInfo(Type.Common).Enum.fields) |enum_field| {
            const e = @field(Type.Common, enum_field.name);
            const type_value = Type.Common.map.get(e);
            _ = try unit.types.append(context.my_allocator, type_value);
        }

        try builder.analyzePackage(unit, context, unit.root_package.dependencies.get("std").?);
        if (unit.descriptor.is_test) {
            try builder.analyzePackage(unit, context, unit.main_package.?);
            const test_function_count = unit.test_functions.keys().len;
            if (test_function_count > 0) {
                try builder.populateTestFunctions(unit, context);
            }
        }

        // for (unit.external_functions.values()) |function_declaration| {
            // logln(.compilation, .ir, "External function: {s}", .{unit.getIdentifier(function_declaration.declaration.name)});
        // }

        for (unit.code_to_emit.values()) |function_declaration| {
            const function_definition_index = function_declaration.initial_value.function_definition;
            // logln(.compilation, .ir, "Function #{} {s}", .{ Function.Definition.unwrap(function_definition_index), unit.getIdentifier(function_declaration.declaration.name) });

            unit.dumpFunctionDefinition(function_definition_index);
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
        file.lexer = try lexer.analyze(context.my_allocator, file.source_code, &unit.token_buffer);
        assert(file.status == .loaded_into_memory);
        file.status = .lexed;
        try unit.file_token_offsets.put_no_clobber(context.my_allocator, .{
            .start = file.lexer.offset,
            .count = file.lexer.count,
        }, file_index);

        // logln(.parser, .file, "[START PARSING FILE #{} {s}]", .{ file_index, file.package.source_path });
        file.parser = try parser.analyze(context.allocator, context.my_allocator, file.lexer, file.source_code, &unit.token_buffer, &unit.node_buffer, &unit.node_lists);
        // logln(.parser, .file, "[END PARSING FILE #{} {s}]", .{ file_index, file.package.source_path });
        assert(file.status == .lexed);
        file.status = .parsed;
    }

    fn importPackage(unit: *Unit, context: *const Context, package: *Package) !ImportPackageResult {
        const full_path = try package.directory.handle.realpathAlloc(context.allocator, package.source_path); //try std.fs.path.resolve(context.allocator, &.{ package.directory.path, package.source_path });
        // logln(.compilation, .import, "Import full path: {s}\n", .{full_path});
        const import_file = try unit.getFile(context, full_path, package.source_path, package);

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
        const import_file = try unit.getFile(context, full_path, file_relative_path, package);
        _ = @intFromPtr(unit.files.get(import_file.index).package);

        const result = ImportPackageResult{
            .file = import_file,
            .is_package = false,
        };

        return result;
    }

    fn getFile(unit: *Unit, context: *const Context, full_path: []const u8, relative_path: []const u8, package: *Package) !ImportFileResult {
        if (unit.file_map.get(full_path)) |file_index| {
            return .{
                .index = file_index,
                .is_new = false,
            };
        } else {
            const file_index = try unit.files.append(context.my_allocator, Debug.File{
                .relative_path = relative_path,
                .package = package,
                .scope = .{ .scope = .{
                    .file = .null,
                    .kind = .file,
                    .line = 0,
                    .column = 0,
                    .local = false,
                    .level = 1,
                } },
            });
            // logln(.compilation, .new_file, "Adding file #{}: {s}\n", .{ file_index, full_path });

            try unit.file_map.put_no_clobber(context.my_allocator, full_path, file_index);

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
            const result = try context.my_allocator.allocate_one(Package);
            const main_package_absolute_directory_path = b: {
                const relative_path = if (std.fs.path.dirname(unit.descriptor.main_package_path)) |dirname| dirname else ".";
                break :b try context.pathFromCwd(relative_path);
            };
            result.* = .{
                .directory = .{
                    .handle = try std.fs.openDirAbsolute(main_package_absolute_directory_path, .{}),
                    .path = main_package_absolute_directory_path,
                },
                .source_path = try context.my_allocator.duplicate_bytes(std.fs.path.basename(unit.descriptor.main_package_path)),
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
            };

            try unit.root_package.addDependency(context.my_allocator, package_descriptor.name, package);

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
            try unit.analyze(context);

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
    @"test",
    @"catch",
    @"try",
    @"orelse",
    @"error",
};

pub const Descriptor = struct {
    main_package_path: []const u8,
    executable_path: []const u8,
    arch: Arch,
    os: Os,
    abi: Abi,
    only_parse: bool,
    link_libc: bool,
    is_test: bool,
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
        lines: [*]u32 = undefined,
        offsets: [*]u32 = undefined,
        lengths: [*]u32 = undefined,
        ids: [*]Token.Id = undefined,
        line_offsets: UnpinnedArray(u32) = .{},
        length: data_structures.IndexType = 0,
        capacity: data_structures.IndexType = 0,

        const factor = 2;
        const initial_item_count = 16;

        pub fn append_with_capacity(buffer: *Buffer, token: Token) void {
            const index = buffer.length;
            assert(index < buffer.capacity);

            buffer.lines[index] = token.line;
            buffer.offsets[index] = token.offset;
            buffer.lengths[index] = token.length;
            buffer.ids[index] = token.id;

            buffer.length += 1;
        }

        pub fn ensure_with_capacity(buffer: *Buffer, allocator: *MyAllocator, unused_capacity: data_structures.IndexType) !void {
            const desired_capacity = buffer.length + unused_capacity;
            var new_capacity = @max(buffer.capacity, initial_item_count);
            while (new_capacity < desired_capacity) {
                new_capacity *= factor;
            }

            if (new_capacity > buffer.capacity) {
                {
                    const line_byte_ptr: [*]u8 = @ptrCast(buffer.lines);
                    const line_bytes = line_byte_ptr[0..buffer.length * @sizeOf(u32)];
                    const new_line_bytes = try allocator.reallocate(line_bytes, new_capacity * @sizeOf(u32), @alignOf(u32));
                    buffer.lines = @ptrCast(@alignCast(new_line_bytes));
                }

                {
                    const offset_byte_ptr: [*]u8 = @ptrCast(buffer.offsets);
                    const offset_bytes = offset_byte_ptr[0..buffer.length * @sizeOf(u32)];
                    const new_offset_bytes = try allocator.reallocate(offset_bytes, new_capacity * @sizeOf(u32), @alignOf(u32));
                    buffer.offsets = @ptrCast(@alignCast(new_offset_bytes));
                }

                {
                    const length_byte_ptr: [*]u8 = @ptrCast(buffer.lengths);
                    const length_bytes = length_byte_ptr[0..buffer.length * @sizeOf(u32)];
                    const new_length_bytes = try allocator.reallocate(length_bytes, new_capacity * @sizeOf(u32), @alignOf(u32));
                    buffer.lengths = @ptrCast(@alignCast(new_length_bytes));
                }

                {
                    const id_byte_ptr: [*]u8 = @ptrCast(buffer.ids);
                    const id_bytes = id_byte_ptr[0..buffer.length * @sizeOf(Token.Id)];
                    const new_id_bytes = try allocator.reallocate(id_bytes, new_capacity * @sizeOf(Token.Id), @alignOf(Token.Id));
                    buffer.ids = @ptrCast(@alignCast(new_id_bytes));
                }

                buffer.capacity = new_capacity;
            }

        }

        pub fn getOffset(buffer: *const Buffer) Token.Index {
            return @enumFromInt(buffer.length);
        }

        pub fn getLineOffset(buffer: *const Buffer) u32 {
            return @intCast(buffer.line_offsets.length);
        }
    };

    pub const Range = struct {
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

    pub usingnamespace data_structures.getIndexForType(@This(), enum {});
};

pub const InlineAssembly = struct {
    instructions: []const InlineAssembly.Instruction.Index,

    pub const List = BlockList(@This(), enum {});
    pub usingnamespace List.Index;

    pub const Instruction = struct {
        id: u32,
        operands: []const Operand,

        pub const List = BlockList(@This(), enum {});
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
