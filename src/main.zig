const std = @import("std");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;
const equal = std.mem.eql;

const Compilation = @import("Compilation.zig");

pub const seed = std.math.maxInt(u64);
const default_src_file = "src/test/main.nat";

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    const compilation_descriptor = try parseArguments(allocator);
    const compilation = try Compilation.init(allocator);

    try compilation.compileModule(compilation_descriptor);
}

const ArgumentParsingError = error{
    main_package_path_not_specified,
};

fn parseArguments(allocator: Allocator) !Compilation.Module.Descriptor {
    const arguments = (try std.process.argsAlloc(allocator))[1..];

    var maybe_executable_path: ?[]const u8 = null;
    var maybe_main_package_path: ?[]const u8 = null;
    var target_triplet: []const u8 = "x86_64-linux-gnu";

    var i: usize = 0;
    while (i < arguments.len) : (i += 1) {
        const current_argument = arguments[i];
        if (equal(u8, current_argument, "-o")) {
            if (i <= arguments.len) {
                maybe_executable_path = arguments[i + 1];
                assert(maybe_executable_path.?.len != 0);
                i += 1;
            } else {
                unreachable;
            }
        } else if (equal(u8, current_argument, "-target")) {
            if (i <= arguments.len) {
                target_triplet = arguments[i + 1];
                i += 1;
            } else {
                unreachable;
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
    std.debug.print("Target: {}\n", .{target});

    return .{
        .main_package_path = main_package_path,
        .executable_path = executable_path,
        .target = target,
    };
}

test {
    _ = Compilation;
}
