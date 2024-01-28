const std = @import("std");
const equal = std.mem.eql;

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const allocator = arena.allocator();
    const arguments = try std.process.argsAlloc(allocator);
    var arch_arg: ?std.Target.Cpu.Arch = null;
    var os_arg: ?std.Target.Os.Tag = null;
    var abi_arg: ?std.Target.Abi = null;
    var cpu_arg: [:0]const u8 = "baseline";
    var version_arg: ?[]const u8 = null;
    var prefix_arg: [:0]const u8 = "nat";

    const State = enum{
        none,
        prefix,
        version,
        arch,
        os,
        abi,
        cpu,
    };

    var state = State.none;

    for (arguments[1..]) |argument| {
        switch (state) {
            .none => {
                if (equal(u8, argument, "-prefix")) {
                    state = .prefix;
                } else if (equal(u8, argument, "-version")) {
                    state = .version;
                } else if (equal(u8, argument, "-arch")) {
                    state = .arch;
                } else if (equal(u8, argument, "-os")) {
                    state = .os;
                } else if (equal(u8, argument, "-abi")) {
                    state = .abi;
                } else if (equal(u8, argument, "-cpu")) {
                    state = .cpu;
                } else return error.InvalidInput;
            },
            .prefix => {
                prefix_arg = argument;
                state = .none;
            },
            .version => {
                version_arg = argument;
                state = .none;
            },
            .arch => {
                arch_arg = std.meta.stringToEnum(std.Target.Cpu.Arch, argument) orelse return error.InvalidInput;
                state = .none;
            },
            .os => {
                os_arg = std.meta.stringToEnum(std.Target.Os.Tag, argument) orelse return error.InvalidInput;
                state = .none;
            },
            .abi => {
                abi_arg = std.meta.stringToEnum(std.Target.Abi, argument) orelse return error.InvalidInput;
                state = .none;
            },
            .cpu => {
                cpu_arg = argument;
                state = .none;
            },
        }
    }

    const version = version_arg orelse return error.InvalidInput;
    const arch = arch_arg orelse return error.InvalidInput;
    const os = os_arg orelse return error.InvalidInput;
    const abi = abi_arg orelse return error.InvalidInput;
    const cpu = cpu_arg;
    const prefix = prefix_arg;

    if (state != .none) return error.InvalidInput;

    const url = try std.mem.concat(allocator, u8, &.{"https://github.com/birth-software/fetch-llvm/releases/download/v", version, "/llvm-", version, "-", @tagName(arch), "-", @tagName(os), "-", @tagName(abi), "-", cpu, ".tar.xz"});
    const uri = try std.Uri.parse(url);
    var http_client = std.http.Client{
        .allocator = allocator,
    };
    defer http_client.deinit();

    var headers = std.http.Headers{
        .allocator = allocator,
    };
    defer headers.deinit();

    var request = try http_client.open(.GET, uri, headers, .{});
    defer request.deinit();
    try request.send(.{});
    try request.wait();

    if (request.response.status != .ok) {
        std.debug.panic("Status: {s} when fetching TAR {s}", .{@tagName(request.response.status), url});
    }

    var decompression = try std.compress.xz.decompress(allocator, request.reader());
    defer decompression.deinit();

    var decompressed_buffer = std.ArrayList(u8).init(allocator);
    try decompression.reader().readAllArrayList(&decompressed_buffer, std.math.maxInt(u32));

    var memory_stream = std.io.fixedBufferStream(decompressed_buffer.items);
    const directory = try std.fs.cwd().makeOpenPath(prefix, .{});
    try std.tar.pipeToFileSystem(directory, memory_stream.reader(), .{
        .mode_mode = .ignore,
    });
}
