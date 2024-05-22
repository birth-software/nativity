const std = @import("std");
const builtin = @import("builtin");
const os = builtin.os.tag;
const arch = builtin.cpu.arch;
const page_size = std.mem.page_size;

pub fn assert(ok: bool) void {
    if (!ok) unreachable;
}

pub const BoundedArray = std.BoundedArray;

pub const Arena = struct {
    position: u64,
    commit_position: u64,
    alignment: u64,
    size: u64,

    pub const Temporary = struct {
        arena: *Arena,
        position: u64,
    };

    pub const commit_granularity = 2 * 1024 * 1024;

    pub fn init(requested_size: u64) !*Arena {
        var size = requested_size;
        const size_roundup_granularity = commit_granularity;
        size += size_roundup_granularity - 1;
        size -= size % size_roundup_granularity;
        const initial_commit_size = commit_granularity;
        assert(initial_commit_size >= @sizeOf(Arena));

        const reserved_memory = try reserve(size);
        try commit(reserved_memory, initial_commit_size);

        const arena: *Arena = @alignCast(@ptrCast(reserved_memory));
        arena.* = .{
            .position = @sizeOf(Arena),
            .commit_position = initial_commit_size,
            .alignment = 8,
            .size = size,
        };

        return arena;
    }

    pub fn allocate(arena: *Arena, size: u64) ![*]u8 {
        if (arena.position + size <= arena.size) {
            const base: [*]u8 = @ptrCast(arena);
            var post_alignment_position = arena.position + arena.alignment - 1;
            post_alignment_position -= post_alignment_position % arena.alignment;
            const alignment = post_alignment_position - arena.position;
            const result = base + arena.position + alignment;
            arena.position += size + alignment;

            if (arena.commit_position < arena.position) {
                var size_to_commit = arena.position - arena.commit_position;
                size_to_commit += commit_granularity - 1;
                size_to_commit -= size_to_commit % commit_granularity;

                try commit(base + arena.commit_position, size_to_commit);

                arena.commit_position += size_to_commit;
            }

            return result;
        } else {
            unreachable;
        }
    }

    pub fn align_forward(arena: *Arena, alignment: u64) void {
        arena.position = std.mem.alignForward(u64, arena.position, alignment);
    }

    pub fn new(arena: *Arena, comptime T: type) !*T {
        const result: *T = @ptrCast(@alignCast(try arena.allocate(@sizeOf(T))));
        return result;
    }

    pub fn new_array(arena: *Arena, comptime T: type, count: usize) ![]T {
        const result: [*]T = @ptrCast(@alignCast(try arena.allocate(@sizeOf(T) * count)));
        return result[0..count];
    }

    pub fn duplicate_bytes(arena: *Arena, bytes: []const u8) ![]u8 {
        const slice = try arena.new_array(u8, bytes.len);
        @memcpy(slice, bytes);
        return slice;
    }

    pub fn duplicate_bytes_zero_terminated(arena: *Arena, bytes: []const u8) ![:0]u8 {
        const slice = try arena.new_array(u8, bytes.len + 1);
        slice[bytes.len] = 0;
        @memcpy(slice[0..bytes.len], bytes);
        return slice[0..bytes.len :0];
    }

    pub fn join(arena: *Arena, slices: []const []const u8) ![]u8 {
        var byte_count: usize = 0;

        for (slices) |slice| {
            byte_count += slice.len;
        }

        const result = try arena.new_array(u8, byte_count);

        byte_count = 0;

        for (slices) |slice| {
            @memcpy(result[byte_count..][0..slice.len], slice);
            byte_count += slice.len;
        }

        return result;
    }
};

pub fn DynamicBoundedArray(comptime T: type) type {
    return struct {
        pointer: [*]T = @constCast((&[_]T{}).ptr),
        length: u32 = 0,
        capacity: u32 = 0,

        const Array = @This();

        pub fn init(arena: *Arena, count: u32) !Array {
            const array = try arena.new_array(T, count);
            return Array{
                .pointer = array.ptr,
                .length = 0,
                .capacity = count,
            };
        }

        pub fn append(array: *Array, item: T) void {
            const index = array.length;
            assert(index < array.capacity);
            array.pointer[index] = item;
            array.length += 1;
        }

        pub fn append_slice(array: *Array, items: []const T) void {
            const count: u32 = @intCast(items.len);
            const index = array.length;
            assert(index + count <= array.capacity);
            @memcpy(array.pointer[index..][0..count], items);
            array.length += count;
        }

        pub fn slice(array: *Array) []T {
            return array.pointer[0..array.length];
        }
    };
}

const pinned_array_page_size = 2 * 1024 * 1024;
const pinned_array_max_size = std.math.maxInt(u32) - pinned_array_page_size;
const pinned_array_default_granularity = pinned_array_page_size;

const small_granularity = std.mem.page_size;
const large_granularity = 2 * 1024 * 1024;
// This must be used with big arrays, which are not resizeable (can't be cleared)
pub fn PinnedArray(comptime T: type) type {
    return PinnedArrayAdvanced(T, null, small_granularity);
}

// This must be used with big arrays, which are not resizeable (can't be cleared)
pub fn PinnedArrayAdvanced(comptime T: type, comptime MaybeIndex: ?type, comptime granularity: comptime_int) type {
    return struct {
        pointer: [*]T = undefined,
        length: u32 = 0,
        committed: u32 = 0,

        pub const Index = if (MaybeIndex) |I| getIndexForType(T, I) else enum(u32) {
            null = 0xffff_ffff,
            _,
        };

        const Array = @This();

        pub fn const_slice(array: *const Array) []const T {
            return array.pointer[0..array.length];
        }

        pub fn slice(array: *Array) []T {
            return array.pointer[0..array.length];
        }

        pub fn get_unchecked(array: *Array, index: u32) *T {
            const array_slice = array.slice();
            return &array_slice[index];
        }

        pub fn get(array: *Array, index: Index) *T {
            assert(index != .null);
            const i = @intFromEnum(index);
            return array.get_unchecked(i);
        }

        pub fn get_index(array: *Array, item: *T) u32 {
            const many_item: [*]T = @ptrCast(item);
            const result: u32 = @intCast(@intFromPtr(many_item) - @intFromPtr(array.pointer));
            assert(result < pinned_array_max_size);
            return @divExact(result, @sizeOf(T));
        }

        pub fn get_typed_index(array: *Array, item: *T) Index {
            return @enumFromInt(array.get_index(item));
        }

        pub fn ensure_capacity(array: *Array, additional: u32) void {
            if (array.committed == 0) {
                assert(array.length == 0);
                array.pointer = @alignCast(@ptrCast(reserve(pinned_array_max_size) catch unreachable));
            }

            const length = array.length;
            const size = length * @sizeOf(T);
            const granularity_aligned_size = align_forward(size, granularity);
            const new_size = size + additional * @sizeOf(T);

            if (granularity_aligned_size < new_size) {
                assert((length + additional) * @sizeOf(T) <= pinned_array_max_size);
                const new_granularity_aligned_size = align_forward(new_size, granularity);
                const pointer: [*]u8 = @ptrCast(array.pointer);
                const commit_pointer = pointer + granularity_aligned_size;
                const commit_size = new_granularity_aligned_size - granularity_aligned_size;
                commit(commit_pointer, commit_size) catch unreachable;
                array.committed += @intCast(@divExact(commit_size, granularity));
            }
        }

        pub fn append(array: *Array, item: T) *T {
            array.ensure_capacity(1);
            return array.append_with_capacity(item);
        }

        pub fn append_index(array: *Array, item: T) u32 {
            return array.get_index(array.append(item));
        }

        pub fn append_typed_index(array: *Array, item: T) Index {
            return array.get_typed_index(array.append(item));
        }

        pub fn append_slice(array: *Array, items: []const T) void {
            array.ensure_capacity(@intCast(items.len));
            array.append_slice_with_capacity(items);
        }

        pub fn add_one_with_capacity(array: *Array) *T {
            const index = array.length;
            assert(index * @sizeOf(T) < pinned_array_max_size);
            array.length += 1;
            const ptr = &array.pointer[index];
            return ptr;
        }

        pub fn add_one(array: *Array) *T{
            array.ensure_capacity(1);
            return array.add_one_with_capacity();
        }

        pub fn append_with_capacity(array: *Array, item: T) *T {
            const ptr = array.add_one_with_capacity();
            ptr.* = item;
            return ptr;
        }

        pub fn append_slice_with_capacity(array: *Array, items: []const T) void {
            if (items.len > 0) {
                const index = array.length;
                const count: u32 = @intCast(items.len);
                assert((index + count - 1) * @sizeOf(T) < pinned_array_max_size);
                array.length += count;
                @memcpy(array.pointer[index..][0..count], items);
            }
        }

        pub fn insert(array: *@This(), index: u32, item: T) void {
            assert(index < array.length);
            array.ensure_capacity(1);
            const src = array.slice()[index..];
            array.length += 1;
            const dst = array.slice()[index + 1 ..];
            copy_backwards(T, dst, src);
            array.slice()[index] = item;
        }

        pub fn in_range(array: *@This(), item: *T) bool {
            if (array.committed == 0) return false;
            if (@intFromPtr(item) < @intFromPtr(array.pointer)) return false;
            const top = @intFromPtr(array.pointer) + array.committed * granularity;
            if (@intFromPtr(item) >= top) return false;
            return true;
        }
    };
}

pub fn reserve(size: u64) ![*]u8 {
    return switch (os) {
        .linux, .macos => (try std.posix.mmap(null, size, std.posix.PROT.NONE, .{
            .ANONYMOUS = true,
            .TYPE = .PRIVATE,
        }, -1, 0)).ptr,
        .windows => @ptrCast(try std.os.windows.VirtualAlloc(null, size, std.os.windows.MEM_RESERVE, std.os.windows.PAGE_READWRITE)),
        else => @compileError("OS not supported"),
    };
}

pub fn commit(bytes: [*]u8, size: u64) !void {
    const slice = bytes[0..size];
    return switch (os) {
        .linux, .macos => try std.posix.mprotect(@alignCast(slice), std.posix.PROT.WRITE | std.posix.PROT.READ),
        .windows => _ = try std.os.windows.VirtualAlloc(bytes, size, std.os.windows.MEM_COMMIT, std.os.windows.PAGE_READWRITE),
        else => @compileError("OS not supported"),
    };
}

pub fn getIndexForType(comptime T: type, comptime E: type) type {
    assert(@typeInfo(E) == .Enum);
    _ = T;
    const MAX = std.math.maxInt(u32);

    const EnumField = std.builtin.Type.EnumField;
    comptime var fields: []const EnumField = &.{};
    // comptime var enum_value: comptime_int = 0;
    fields = fields ++ @typeInfo(E).Enum.fields;

    fields = fields ++ [1]EnumField{.{
        .name = "null",
        .value = MAX,
    }};

    const Result = @Type(.{
        .Enum = .{
            .tag_type = u32,
            .fields = fields,
            .decls = &.{},
            .is_exhaustive = false,
        },
    });

    return Result;
}

fn JointEnum(comptime enums: []const type, comptime backing_type: ?type) type {
    _ = backing_type; // autofix
    _ = enums; // autofix
    return @Type(.{
        .Enum = .{
        },
    });
}

pub fn my_hash(bytes: []const u8) u32 {
    const fnv_offset = 14695981039346656037;
    const fnv_prime = 1099511628211;
    var result: u64 = fnv_offset;

    for (bytes) |byte| {
        result ^= byte;
        result *%= fnv_prime;
    }

    return @truncate(result);
}

fn CopyPtrAttrs(
    comptime source: type,
    comptime size: std.builtin.Type.Pointer.Size,
    comptime child: type,
) type {
    const info = @typeInfo(source).Pointer;
    return @Type(.{
        .Pointer = .{
            .size = size,
            .is_const = info.is_const,
            .is_volatile = info.is_volatile,
            .is_allowzero = info.is_allowzero,
            .alignment = info.alignment,
            .address_space = info.address_space,
            .child = child,
            .sentinel = null,
        },
    });
}

fn AsBytesReturnType(comptime P: type) type {
    const size = @sizeOf(std.meta.Child(P));
    return CopyPtrAttrs(P, .One, [size]u8);
}

/// Given a pointer to a single item, returns a slice of the underlying bytes, preserving pointer attributes.
pub fn asBytes(ptr: anytype) AsBytesReturnType(@TypeOf(ptr)) {
    return @ptrCast(@alignCast(ptr));
}

pub fn byte_equal(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;

    if (a.len != b.len) return false;
    if (a.len == 0 or a.ptr == b.ptr) return true;

    for (a, b) |byte_a, byte_b| {
        if (byte_a != byte_b) return false;
    }

    return true;
}

pub fn byte_equal_terminated(a: [*:0]const u8, b: [*:0]const u8) bool {
    const a_slice = span(a);
    const b_slice = span(b);
    return byte_equal(a_slice, b_slice);
}

const pinned_hash_map_page_size = 2 * 1024 * 1024;
const pinned_hash_map_max_size = std.math.maxInt(u32) - pinned_hash_map_page_size;
const pinned_hash_map_default_granularity = pinned_hash_map_page_size;

pub fn PinnedHashMap(comptime K: type, comptime V: type) type {
    return PinnedHashMapAdvanced(K, V, small_granularity);
}

pub fn PinnedHashMapAdvanced(comptime K: type, comptime V: type, comptime granularity: comptime_int) type {
    return struct {
        key_pointer: [*]K = undefined,
        value_pointer: [*]V = undefined,
        length: u64 = 0,
        committed_key: u32 = 0,
        committed_value: u32 = 0,

        const Map = @This();

        pub fn get_pointer(map: *Map, key: K) ?*V {
            for (map.keys(), 0..) |k, i| {
                const is_equal = switch (@typeInfo(K)) {
                    .Pointer => |pointer| switch (pointer.size) {
                        .Slice => byte_equal(k, key),
                        else => k == key,
                    },
                    .Struct, .Array => equal(k, key),
                    else => k == key,
                };

                if (is_equal) {
                    return &map.value_pointer[i];
                }
            }

            return null;
        }

        pub fn get(map: *@This(), key: K) ?V {
            if (map.get_pointer(key)) |p| {
                return p.*;
            } else {
                return null;
            }
        }

        pub fn put(map: *@This(), key: K, value: V) void {
            if (map.get_pointer(key)) |value_pointer| {
                value_pointer.* = value;
            } else {
                const len = map.length;
                map.ensure_capacity(len + 1);
                map.put_at_with_capacity(len, key, value);
            }
        }

        pub fn put_no_clobber(map: *@This(), key: K, value: V) void {
            assert(map.get_pointer(key) == null);
            const len = map.length;
            map.ensure_capacity(len + 1);
            map.put_at_with_capacity(len, key, value);
        }

        fn put_at_with_capacity(map: *@This(), index: u64, key: K, value: V) void {
            map.length += 1;
            assert(index < map.length);
            map.key_pointer[index] = key;
            map.value_pointer[index] = value;
        }

        fn ensure_capacity(map: *Map, additional: u64) void {
            if (map.committed_key == 0) {
                map.key_pointer = @alignCast(@ptrCast(reserve(pinned_hash_map_max_size) catch unreachable));
                map.value_pointer = @alignCast(@ptrCast(reserve(pinned_hash_map_max_size) catch unreachable));
            }

            const length = map.length;
            assert((length + additional) * @sizeOf(K) <= pinned_array_max_size);

            {
                const key_size = length * @sizeOf(K);
                const key_granularity_aligned_size = align_forward(key_size, granularity);
                const key_new_size = key_size + additional * @sizeOf(K);

                if (key_granularity_aligned_size < key_new_size) {
                    const new_key_granularity_aligned_size = align_forward(key_new_size, granularity);
                    const key_pointer: [*]u8 = @ptrCast(map.key_pointer);
                    const commit_pointer = key_pointer + key_granularity_aligned_size;
                    const commit_size = new_key_granularity_aligned_size - key_granularity_aligned_size;
                    commit(commit_pointer, commit_size) catch unreachable;
                    map.committed_key += @intCast(@divExact(commit_size, granularity));
                }
            }

            {
                const value_size = length * @sizeOf(V);
                const value_granularity_aligned_size = align_forward(value_size, granularity);
                const value_new_size = value_size + additional * @sizeOf(K);

                if (value_granularity_aligned_size < value_new_size) {
                    const new_value_granularity_aligned_size = align_forward(value_new_size, granularity);
                    const value_pointer: [*]u8 = @ptrCast(map.value_pointer);
                    commit(value_pointer + value_granularity_aligned_size, new_value_granularity_aligned_size - value_granularity_aligned_size) catch unreachable;
                    const commit_pointer = value_pointer + value_granularity_aligned_size;
                    const commit_size = new_value_granularity_aligned_size - value_granularity_aligned_size;
                    commit(commit_pointer, commit_size) catch unreachable;
                    map.committed_value += @intCast(@divExact(commit_size, granularity));
                }
            }
        }

        pub fn keys(map: *@This()) []K {
            return map.key_pointer[0..map.length];
        }

        pub fn values(map: *@This()) []V {
            return map.value_pointer[0..map.length];
        }

        pub fn clear(map: *Map) void {
            map.length = 0;
        }
    };
}

pub const ListType = enum {
    index,
    pointer,
};

pub fn enumFromString(comptime E: type, string: []const u8) ?E {
    return inline for (@typeInfo(E).Enum.fields) |enum_field| {
        if (byte_equal(string, enum_field.name)) {
            break @field(E, enum_field.name);
        }
    } else null;
}

extern fn pthread_jit_write_protect_np(enabled: bool) void;

fn copy_backwards(comptime T: type, destination: []T, source: []const T) void {
    @setRuntimeSafety(false);
    assert(destination.len >= source.len);
    var i = source.len;
    while (i > 0) {
        i -= 1;
        destination[i] = source[i];
    }
}

pub fn equal(a: anytype, b: @TypeOf(a)) bool {
    const T = @TypeOf(a);

    switch (@typeInfo(T)) {
        .Struct => |info| {
            inline for (info.fields) |field_info| {
                if (!equal(@field(a, field_info.name), @field(b, field_info.name))) return false;
            }
            return true;
        },
        .ErrorUnion => {
            if (a) |a_p| {
                if (b) |b_p| return equal(a_p, b_p) else |_| return false;
            } else |a_e| {
                if (b) |_| return false else |b_e| return a_e == b_e;
            }
        },
        .Union => |info| {
            if (info.tag_type) |UnionTag| {
                const tag_a = activeTag(a);
                const tag_b = activeTag(b);
                if (tag_a != tag_b) return false;

                inline for (info.fields) |field_info| {
                    if (@field(UnionTag, field_info.name) == tag_a) {
                        return equal(@field(a, field_info.name), @field(b, field_info.name));
                    }
                }
                return false;
            }

            @compileError("cannot compare untagged union type " ++ @typeName(T));
        },
        .Array => {
            if (a.len != b.len) return false;
            for (a, 0..) |e, i|
                if (!equal(e, b[i])) return false;
            return true;
        },
        .Vector => |info| {
            var i: usize = 0;
            while (i < info.len) : (i += 1) {
                if (!equal(a[i], b[i])) return false;
            }
            return true;
        },
        .Pointer => |info| {
            return switch (info.size) {
                .One, .Many, .C => a == b,
                .Slice => a.ptr == b.ptr and a.len == b.len,
            };
        },
        .Optional => {
            if (a == null and b == null) return true;
            if (a == null or b == null) return false;
            return equal(a.?, b.?);
        },
        else => return a == b,
    }
}

pub fn Tag(comptime T: type) type {
    return switch (@typeInfo(T)) {
        .Enum => |info| info.tag_type,
        .Union => |info| info.tag_type orelse @compileError(@typeName(T) ++ " has no tag type"),
        else => @compileError("expected enum or union type, found '" ++ @typeName(T) ++ "'"),
    };
}

///Returns the active tag of a tagged union
pub fn activeTag(u: anytype) Tag(@TypeOf(u)) {
    const T = @TypeOf(u);
    return @as(Tag(T), u);
}

pub fn missingCase(e: anytype) noreturn {
    @panic(@tagName(e));
}
// Converts values in the range [0, 100) to a string.
fn digits2(value: usize) [2]u8 {
    return ("0001020304050607080910111213141516171819" ++
        "2021222324252627282930313233343536373839" ++
        "4041424344454647484950515253545556575859" ++
        "6061626364656667686970717273747576777879" ++
        "8081828384858687888990919293949596979899")[value * 2 ..][0..2].*;
}

pub fn digit_to_char(digit: u8) u8 {
    return switch (digit) {
        0...9 => digit + '0',
        10...35 => digit + ((@as(u8, 'a')) - 10),
        else => unreachable,
    };
}

pub fn format_int(buffer: []u8, value: u64, base: u8, signed: bool) []u8 {
    assert(base >= 2);

    var a: u64 = value;
    var index: usize = buffer.len;

    if (base == 10) {
        while (a >= 100) : (a = @divTrunc(a, 100)) {
            index -= 2;
            buffer[index..][0..2].* = digits2(@as(usize, @intCast(a % 100)));
        }

        if (a < 10) {
            index -= 1;
            buffer[index] = '0' + @as(u8, @intCast(a));
        } else {
            index -= 2;
            buffer[index..][0..2].* = digits2(@as(usize, @intCast(a)));
        }
    } else {
        while (true) {
            const digit = a % base;
            index -= 1;
            buffer[index] = digit_to_char(@as(u8, @intCast(digit)));
            a /= base;
            if (a == 0) break;
        }
    }

    if (signed) {
        index -= 1;
        buffer[index] = '-';
    }

    return buffer[index..];
}

pub fn span(ptr: [*:0]const u8) [:0]const u8 {
    var len: usize = 0;
    while (ptr[len] != 0) {
        len += 1;
    }
    return ptr[0..len :0];
}

pub fn starts_with_slice(bytes: []const u8, slice: []const u8) bool {
    if (slice.len <= bytes.len) {
        if (byte_equal(bytes[0..slice.len], slice)) {
            return true;
        }
    }

    return false;
}

pub fn ends_with_slice(bytes: []const u8, slice: []const u8) bool {
    if (slice.len <= bytes.len) {
        if (byte_equal(bytes[bytes.len - slice.len ..], slice)) {
            return true;
        }
    }

    return false;
}

pub fn first_byte(bytes: []const u8, byte: u8) ?usize {
    for (bytes, 0..) |b, i| {
        if (b == byte) {
            return i;
        }
    }

    return null;
}

pub fn first_slice(bytes: []const u8, slice: []const u8) ?usize {
    if (slice.len <= bytes.len) {
        const top = bytes.len - slice.len;
        var i: usize = 0;

        while (i < top) : (i += 1) {
            const chunk = bytes[i..][0..slice.len];
            if (byte_equal(chunk, slice)) {
                return i;
            }
        }
    }

    return null;
}

pub fn last_byte(bytes: []const u8, byte: u8) ?usize {
    var i = bytes.len;
    while (i > 0) {
        i -= 1;

        if (bytes[i] == byte) {
            return i;
        }
    }

    return null;
}

pub fn align_forward(value: u64, alignment: u64) u64 {
    const mask = alignment - 1;
    return (value + mask) & ~mask;
}

pub fn exit_with_error() noreturn {
    @breakpoint();
    std.posix.exit(1);
}

pub fn read_file(arena: *Arena, directory: std.fs.Dir, file_relative_path: []const u8) []const u8 {
    const source_file = directory.openFile(file_relative_path, .{}) catch |err| {
        const stdout = std.io.getStdOut();
        stdout.writeAll("Can't find file '") catch {};
        stdout.writeAll(file_relative_path) catch {};
        // stdout.writeAll(" in directory ") catch {};
        // stdout.writeAll(file.package.directory.path) catch {};
        stdout.writeAll("' for error ") catch {};
        stdout.writeAll(@errorName(err)) catch {};
        @panic("Unrecoverable error");
    };

    const file_size = source_file.getEndPos() catch unreachable;
    var file_buffer = arena.new_array(u8, file_size) catch unreachable;

    const read_byte_count = source_file.readAll(file_buffer) catch unreachable;
    assert(read_byte_count == file_size);
    source_file.close();

    //TODO: adjust file maximum size
    return file_buffer[0..read_byte_count];
}

pub fn self_exe_path(arena: *Arena) ![]const u8 {
    var buffer: [std.fs.MAX_PATH_BYTES]u8 = undefined;
    return try arena.duplicate_bytes(try std.fs.selfExePath(&buffer));
}

pub fn realpath(arena: *Arena, dir: std.fs.Dir, relative_path: []const u8) ![]const u8 {
    var buffer: [std.fs.MAX_PATH_BYTES]u8 = undefined;
    const stack_realpath = try dir.realpath(relative_path, &buffer);
    const heap_realpath = try arena.new_array(u8, stack_realpath.len);
    @memcpy(heap_realpath, stack_realpath);
    return heap_realpath;
}

pub fn argument_copy_zero_terminated(arena: *Arena, args: []const []const u8) ![:null]?[*:0]u8 {
    var result = try arena.new_array(?[*:0]u8, args.len + 1);
    result[args.len] = null;

    for (args, 0..) |argument, i| {
        result[i] = try arena.duplicate_bytes_zero_terminated(argument);
    }

    return result[0..args.len :null];
}
