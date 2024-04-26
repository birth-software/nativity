const std = @import("std");
const builtin = @import("builtin");
const os = builtin.os.tag;
const arch = builtin.cpu.arch;
const page_size = std.mem.page_size;

pub fn assert(ok: bool) void {
    if (!ok) unreachable;
}

pub const Allocator = std.mem.Allocator;
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

    pub inline fn new(arena: *Arena, comptime T: type) !*T {
        const result: *T = @ptrCast(@alignCast(try arena.allocate(@sizeOf(T))));
        return result;
    }

    pub inline fn new_array(arena: *Arena, comptime T: type, count: usize) ![]T {
        const result: [*]T = @ptrCast(@alignCast(try arena.allocate(@sizeOf(T) * count)));
        return result[0..count];
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

// This must be used with big arrays, which are not resizeable (can't be cleared)
pub fn PinnedArray(comptime T: type) type {
    return PinnedArrayAdvanced(T, null);
}

// This must be used with big arrays, which are not resizeable (can't be cleared)
pub fn PinnedArrayAdvanced(comptime T: type, comptime MaybeIndex: ?type) type {
    return struct {
        pointer: [*]T = @constCast((&[_]T{}).ptr),
        length: u32 = 0,
        granularity: u32 = 0,

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

        pub fn get_index(array: *Array, item: *T) Index {
            const many_item: [*]T = @ptrCast(item);
            const result = @intFromPtr(many_item) - @intFromPtr(array.pointer);
            assert(result < pinned_array_max_size);
            return @enumFromInt(@divExact(result, @sizeOf(T)));
        }

        pub fn init(granularity: u32) !Array {
            assert(granularity & 0xfff == 0);
            const raw_ptr = try reserve(pinned_array_max_size);
            try commit(raw_ptr, granularity);
            return Array{
                .pointer = @alignCast(@ptrCast(raw_ptr)),
                .length = 0,
                .granularity = granularity,
            };
        }

        pub fn init_with_default_granularity() !Array {
            return try Array.init(pinned_array_default_granularity);
        }

        pub fn ensure_capacity(array: *Array, additional: u32) void {
            const length = array.length;
            const size = length * @sizeOf(T);
            const granularity_aligned_size = align_forward(size, array.granularity);
            const new_size = size + additional * @sizeOf(T);
            if (granularity_aligned_size < new_size) {
                assert((length + additional) * @sizeOf(T) <= pinned_array_max_size);
                const new_granularity_aligned_size = align_forward(new_size, array.granularity);
                const ptr: [*]u8 = @ptrCast(array.pointer);
                commit(ptr + granularity_aligned_size, new_granularity_aligned_size - granularity_aligned_size) catch unreachable;
            }
        }

        pub fn append(array: *Array, item: T) *T {
            array.ensure_capacity(1);
            return array.append_with_capacity(item);
        }

        pub fn append_index(array: *Array, item: T) Index {
            return array.get_index(array.append(item));
        }

        pub fn append_slice(array: *Array, items: []const T) void {
            array.ensure_capacity(@intCast(items.len));
            array.append_slice_with_capacity(items);
        }

        pub fn append_with_capacity(array: *Array, item: T) *T {
            const index = array.length;
            assert(index * @sizeOf(T) < pinned_array_max_size);
            array.length += 1;
            const ptr = &array.pointer[index];
            ptr.* = item;
            return ptr;
        }

        pub fn append_slice_with_capacity(array: *Array, items: []const T) void {
            const index = array.length;
            const count: u32 = @intCast(items.len);
            assert((index + count - 1) * @sizeOf(T) < pinned_array_max_size);
            array.length += count;
            @memcpy(array.pointer[index..][0..count], items);
        }

        pub fn insert(array: *@This(), index: u32, item: T) void {
            assert(index < array.length);
            array.ensure_capacity(1);
            const src = array.slice()[index..];
            array.length += 1;
            const dst = array.slice()[index + 1..];
            copy_backwards(T, dst, src);
            array.slice()[index] = item;
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
    return struct {
        key_pointer: [*]K,
        value_pointer: [*]V,
        length: u32,
        granularity: u32,
        committed: u32,

        const Map = @This();

        pub fn init(granularity: u32) !Map {
            assert(granularity & 0xfff == 0);
            const key_raw_pointer = try reserve(pinned_hash_map_max_size);
            try commit(key_raw_pointer, granularity);
            const value_raw_pointer = try reserve(pinned_hash_map_max_size);
            try commit(value_raw_pointer, granularity);

            return Map{
                .key_pointer = @alignCast(@ptrCast(key_raw_pointer)),
                .value_pointer = @alignCast(@ptrCast(value_raw_pointer)),
                .length = 0,
                .granularity = granularity,
                .committed = 1,
            };
        }

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

        pub fn put(map: *@This(), key: K, value: V) !void {
            if (map.get_pointer(key)) |value_pointer| {
                value_pointer.* = value;
            } else {
                const len = map.length;
                map.ensure_capacity(len + 1);
                map.put_at_with_capacity(len, key, value);
            }
        }

        pub fn put_no_clobber(map: *@This(), key: K, value: V) !void {
            assert(map.get_pointer(key) == null);
            const len = map.length;
            map.ensure_capacity(len + 1);
            map.put_at_with_capacity(len, key, value);
        }

        fn put_at_with_capacity(map: *@This(), index: u32, key: K, value: V) void {
            map.length += 1;
            assert(index < map.length);
            map.key_pointer[index] = key;
            map.value_pointer[index] = value;
        }

        fn ensure_capacity(map: *Map, additional: u32) void {
            const length = map.length;
            assert((length + additional) * @sizeOf(K) <= pinned_array_max_size);

            {
                const key_size = length * @sizeOf(K);
                const key_granularity_aligned_size = align_forward(key_size, map.granularity);
                const key_new_size = key_size + additional * @sizeOf(K);

                if (key_granularity_aligned_size < key_new_size) {
                    const new_key_granularity_aligned_size = align_forward(key_new_size, map.granularity);
                    const key_pointer: [*]u8 = @ptrCast(map.key_pointer);
                    commit(key_pointer + key_granularity_aligned_size, new_key_granularity_aligned_size - key_granularity_aligned_size) catch unreachable;
                }
            }

            {
                const value_size = length * @sizeOf(V);
                const value_granularity_aligned_size = align_forward(value_size, map.granularity);
                const value_new_size = value_size + additional * @sizeOf(K);

                if (value_granularity_aligned_size < value_new_size) {
                    const new_value_granularity_aligned_size = align_forward(value_new_size, map.granularity);
                    const value_pointer: [*]u8 = @ptrCast(map.value_pointer);
                    commit(value_pointer + value_granularity_aligned_size, new_value_granularity_aligned_size - value_granularity_aligned_size) catch unreachable;
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

pub fn allocate_virtual_memory(size: usize, flags: packed struct {
    executable: bool = false,
}) ![]align(page_size) u8 {
    return switch (os) {
        .windows => blk: {
            const windows = std.os.windows;
            break :blk @as([*]align(page_size) u8, @ptrCast(@alignCast(try windows.VirtualAlloc(null, size, windows.MEM_COMMIT | windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE))))[0..size];
        },
        .linux, .macos => |os_tag| blk: {
            const jit = switch (os_tag) {
                .macos => 0x800,
                .linux => 0,
                else => @compileError("OS not supported"),
            };
            _ = jit; // autofix
            const execute_flag: switch (os_tag) {
                .linux => u32,
                .macos => c_int,
                else => @compileError("OS not supported"),
            } = if (flags.executable) std.posix.PROT.EXEC else 0;
            const protection_flags: u32 = @intCast(std.posix.PROT.READ | std.posix.PROT.WRITE | execute_flag);

            const result = try std.posix.mmap(null, size, protection_flags, .{
                .TYPE = .PRIVATE,
                .ANONYMOUS = true,
            }, -1, 0);
            if (arch == .aarch64 and os == .macos) {
                if (flags.executable) {
                    pthread_jit_write_protect_np(false);
                }
            }

            break :blk result;
        },
        else => @compileError("OS not supported"),
    };
}

pub fn free_virtual_memory(slice: []align(page_size) const u8) void {
    switch (os) {
        .windows => {
            std.os.windows.VirtualFree(@constCast(@ptrCast(slice.ptr)), slice.len, std.os.windows.MEM_RELEASE);
        },
        else => {
            std.posix.munmap(slice);
        },
    }
}

pub const MyAllocator = struct {
    handler: *const fn (allocator: *MyAllocator, old_ptr: ?[*]u8, old_size: usize, new_size: usize, alignment: u16) Error![*]u8,

    pub fn allocate_one(allocator: *MyAllocator, comptime T: type) !*T {
        const slice = try allocator.allocate(@sizeOf(T), @alignOf(T));
        assert(slice.len == @sizeOf(T));
        return @ptrCast(@alignCast(&slice.ptr[0]));
    }

    pub fn allocate(allocator: *MyAllocator, size: usize, alignment: u16) ![]u8 {
        const ptr = try allocator.handler(allocator, null, 0, size, alignment);
        return ptr[0..size];
    }

    pub fn free(allocator: *MyAllocator, bytes: []u8) !void {
        _ = try allocator.handler(allocator, bytes.ptr, bytes.len, 0, 0);
    }

    pub fn reallocate(allocator: *MyAllocator, bytes: []u8, size: usize, alignment: u16) ![]u8 {
        const new_ptr = try allocator.handler(allocator, bytes.ptr, bytes.len, size, alignment);
        return new_ptr[0..size];
    }

    pub fn duplicate_bytes(allocator: *MyAllocator, bytes: []const u8) ![]u8 {
        const slice = try allocator.allocate(bytes.len, 0);
        @memcpy(slice, bytes);
        return slice;
    }

    const Error = error{
        allocation_failed,
    };
};

pub const PageAllocator = struct {
    allocator: MyAllocator = .{ .handler = handler },

    fn handler(allocator: *MyAllocator, maybe_old_ptr: ?[*]u8, old_size: usize, new_size: usize, alignment: u16) MyAllocator.Error![*]u8 {
        _ = allocator; // autofix
        _ = alignment; // autofix
        const maybe_new_slice: ?[]u8 = if (new_size > 0) allocate_virtual_memory(new_size, .{}) catch return MyAllocator.Error.allocation_failed else null;

        if (maybe_old_ptr) |old_ptr| {
            const old_slice = old_ptr[0..old_size];
            if (maybe_new_slice) |new_slice| {
                @memcpy(new_slice[0..old_size], old_slice);
                free_virtual_memory(@ptrCast(@alignCast(old_slice)));
                return new_slice.ptr;
            } else {
                return old_slice.ptr;
            }
        } else {
            return (maybe_new_slice orelse unreachable).ptr;
        }
    }
};

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
