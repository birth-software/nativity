const std = @import("std");
const equal = std.mem.eql;

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const allocator = arena.allocator();
    const arguments = try std.process.argsAlloc(allocator);
    var url_arg: ?[:0]const u8 = null;
    var prefix_arg: [:0]const u8 = "nat";

    const State = enum {
        none,
        prefix,
        url,
    };

    var state = State.none;

    for (arguments[1..]) |argument| {
        switch (state) {
            .none => {
                if (equal(u8, argument, "-prefix")) {
                    state = .prefix;
                } else if (equal(u8, argument, "-url")) {
                    state = .url;
                } else return error.InvalidInput;
            },
            .prefix => {
                prefix_arg = argument;
                state = .none;
            },
            .url => {
                url_arg = argument;
                state = .none;
            },
        }
    }

    const url = url_arg orelse return error.InvalidInput;
    const prefix = prefix_arg;

    if (state != .none) return error.InvalidInput;

    const dot_index = std.mem.lastIndexOfScalar(u8, url, '.') orelse return error.InvalidInput;
    const extension_string = url[dot_index + 1 ..];
    const Extension = enum {
        xz,
        gz,
        zip,
    };
    const extension: Extension = inline for (@typeInfo(Extension).Enum.fields) |field| {
        if (std.mem.eql(u8, field.name, extension_string)) {
            break @enumFromInt(field.value);
        }
    } else return error.InvalidInput;

    const uri = try std.Uri.parse(url);
    var http_client = std.http.Client{
        .allocator = allocator,
    };
    defer http_client.deinit();

    var buffer: [16 * 1024]u8 = undefined;
    var request = try http_client.open(.GET, uri, .{
        .server_header_buffer = &buffer,
    });
    defer request.deinit();
    try request.send(.{});
    try request.wait();

    if (request.response.status != .ok) {
        @panic("Failure when fetching TAR");
        //std.debug.panic("Status: {s} when fetching TAR {s}", .{@tagName(request.response.status), url});
    }

    var decompressed_buffer = std.ArrayList(u8).init(allocator);

    switch (extension) {
        .xz => {
            var decompression = try std.compress.xz.decompress(allocator, request.reader());
            defer decompression.deinit();
            try decompression.reader().readAllArrayList(&decompressed_buffer, std.math.maxInt(u32));
        },
        .gz => {
            var decompression = std.compress.gzip.decompressor(request.reader());
            try decompression.reader().readAllArrayList(&decompressed_buffer, std.math.maxInt(u32));
        },
        else => |t| @panic(@tagName(t)),
    }

    var memory_stream = std.io.fixedBufferStream(decompressed_buffer.items);
    const directory = try std.fs.cwd().makeOpenPath(prefix, .{});
    try std.tar.pipeToFileSystem(directory, memory_stream.reader(), .{
        .mode_mode = .ignore,
    });
}
