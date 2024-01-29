const std = @import("std");
const Allocator = std.mem.Allocator;
const equal = std.mem.eql;

const Compilation = @import("Compilation.zig");
pub const panic = Compilation.panic;

const env_detecting_libc_paths = "NATIVITY_IS_DETECTING_LIBC_PATHS";

fn todo() noreturn {
    @setCold(true);
    @panic("TODO");
}

pub fn main() !void {
    var arena_allocator = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const allocator = arena_allocator.allocator();
    const arguments = try std.process.argsAlloc(allocator);

    if (arguments.len <= 1) {
        return error.InvalidInput;
    }

    if (std.process.can_execv and std.os.getenvZ(env_detecting_libc_paths) != null) {
        todo();
    }

    const command = arguments[1];
    const command_arguments = arguments[2..];

    if (equal(u8, command, "build")) {
        todo();
    } else if (equal(u8, command, "clang") or equal(u8, command, "-cc1") or equal(u8, command, "-cc1as")) {
        const exit_code = try clangMain(allocator, arguments);
        std.process.exit(exit_code);
    } else if (equal(u8, command, "cc")) {
        // TODO: transform our arguments to Clang and invoke it
        todo();
    } else if (equal(u8, command, "c++")) {
        // TODO: transform our arguments to Clang and invoke it
        todo();
    } else if (equal(u8, command, "exe")) {
        try Compilation.buildExecutable(allocator, command_arguments);
    } else if (equal(u8, command, "lib")) {
        todo();
    } else if (equal(u8, command, "obj")) {
        todo();
    } else {
        todo();
    }
}

fn argsCopyZ(alloc: Allocator, args: []const []const u8) ![:null]?[*:0]u8 {
    var argv = try alloc.allocSentinel(?[*:0]u8, args.len, null);
    for (args, 0..) |arg, i| {
        argv[i] = try alloc.dupeZ(u8, arg); // TODO If there was an argsAllocZ we could avoid this allocation.
    }
    return argv;
}

extern "c" fn NativityClangMain(argc: c_int, argv: [*:null]?[*:0]u8) c_int;
fn clangMain(allocator: Allocator, arguments: []const []const u8) !u8 {
    const argv = try argsCopyZ(allocator, arguments);
    const exit_code = NativityClangMain(@as(c_int, @intCast(arguments.len)), argv.ptr);
    return @as(u8, @bitCast(@as(i8, @truncate(exit_code))));
}
