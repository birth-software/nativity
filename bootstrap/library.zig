const std = @import("std");
const builtin = @import("builtin");
const os = builtin.os.tag;
const arch = builtin.cpu.arch;

pub fn assert(ok: bool) void {
    if (!ok) unreachable;
}

pub const Allocator = std.mem.Allocator;
pub const BoundedArray = std.BoundedArray;

pub fn BlockList(comptime T: type, comptime E: type) type {
    const item_count = 64;

    return struct {
        blocks: UnpinnedArray(*Block) = .{},
        len: usize = 0,

        const Block = BoundedArray(T, item_count);
        const List = @This();

        pub const Index = getIndexForType(T, E);
        pub const ElementIndex = Index.Index;

        pub fn wrapSplit(block: usize, element: usize) ElementIndex {
            return @enumFromInt(block * item_count + element);
        }

        pub fn get(list: *List, index: ElementIndex) *T {
            assert(index != .null);
            const i: u32 = @intFromEnum(index);
            const block_index = i / item_count;
            const element_index = i % item_count;
            assert(block_index < list.blocks.length);
            const block = list.blocks.pointer[block_index];
            const block_slice = block.buffer[0..block.len];
            const element = &block_slice[element_index];
            return element;
        }

        pub fn append(list: *List, allocator: *MyAllocator, element: T) !ElementIndex {
            const result = try list.addOne(allocator);
            list.get(result).* = element;
            return result;
        }

        pub fn addOne(list: *List, allocator: *MyAllocator) !ElementIndex {
            const block_index = try list.getFreeBlock(allocator);
            assert(block_index < list.blocks.length);
            const block = list.blocks.pointer[block_index];
            const index = block.len;
            _ = try block.addOne();
            return @enumFromInt(block_index * item_count + index);
        }

        fn getFreeBlock(list: *List, allocator: *MyAllocator) !usize {
            for (list.blocks.slice(), 0..) |block, i| {
                block.ensureUnusedCapacity(1) catch continue;
                return i;
            } else {
                const new_block = try allocator.allocate_one(Block);
                new_block.* = .{};
                const block_index = list.blocks.length;
                try list.blocks.append(allocator, new_block);
                return block_index;
            }
        }

        pub fn indexOf(list: *List, elem: *const T) ElementIndex {
            const address = @intFromPtr(elem);
            for (list.blocks.items, 0..) |block, block_index| {
                const base = @intFromPtr(&block.buffer[0]);
                const top = base + @sizeOf(T) * item_count;
                if (address >= base and address < top) {
                    const result: u32 = @intCast(block_index * item_count + @divExact(address - base, @sizeOf(T)));
                    return Index.wrap(result);
                }
            }

            @panic("not found");
        }
    };
}

pub fn getIndexForType(comptime T: type, comptime E: type) type {
    assert(@typeInfo(E) == .Enum);
    _ = T;
    const MAX = std.math.maxInt(IndexType);

    const EnumField = std.builtin.Type.EnumField;
    comptime var fields: []const EnumField = &.{};
    // comptime var enum_value: comptime_int = 0;
    fields = fields ++ @typeInfo(E).Enum.fields;

    // for (names) |name| {
    //     fields = fields ++ [1]EnumField{.{
    //         .name = name,
    //         .value = enum_value,
    //     }};
    //     enum_value += 1;
    // }

    fields = fields ++ [1]EnumField{.{
        .name = "null",
        .value = MAX,
    }};

    const Result = @Type(.{
        .Enum = .{
            .tag_type = IndexType,
            .fields = fields,
            .decls = &.{},
            .is_exhaustive = false,
        },
    });

    return struct {
        pub const Index = Result;

        pub fn unwrap(this: Index) IndexType {
            assert(this != .null);
            return @intFromEnum(this);
        }

        pub fn wrap(value: IndexType) Index {
            assert(value < MAX);
            return @enumFromInt(value);
        }

        pub fn addInt(this: Index, value: IndexType) Index {
            const this_int = @intFromEnum(this);
            return @enumFromInt(this_int + value);
        }

        pub fn subInt(this: Index, value: IndexType) IndexType {
            const this_int = @intFromEnum(this);
            return this_int - value;
        }

        pub fn add(a: Index, b: Index) Index {
            return @enumFromInt(@intFromEnum(a) + @intFromEnum(b));
        }

        pub fn sub(a: Index, b: Index) IndexType {
            return @intFromEnum(a) - @intFromEnum(b);
        }
    };
}

pub fn my_hash(bytes: []const u8) IndexType {
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

const MapResult = struct {
    key_pointer: *anyopaque,
    value_pointer: *anyopaque,
    capacity: IndexType,
};

fn ensure_capacity_hashmap(allocator: *MyAllocator, current_capacity: IndexType, desired_capacity: IndexType, key_pointer: [*]u8, value_pointer: [*]u8, length: IndexType, key_size: IndexType, key_alignment: u16, value_size: IndexType, value_alignment: u16) !MapResult {
    var new_capacity = @max(current_capacity, initial_item_count);
    while (new_capacity < desired_capacity) {
        new_capacity *= factor;
    }

    if (new_capacity > current_capacity) {
        const old_key_slice = key_pointer[0 .. length * key_size];
        const old_value_slice = value_pointer[0 .. length * value_size];
        const new_key_slice = try allocator.reallocate(old_key_slice, new_capacity * key_size, key_alignment);
        const new_value_slice = try allocator.reallocate(old_value_slice, new_capacity * value_size, value_alignment);

        return .{
            .key_pointer = new_key_slice.ptr,
            .value_pointer = new_value_slice.ptr,
            .capacity = new_capacity,
        };
    } else {
        return .{
            .capacity = current_capacity,
            .key_pointer = key_pointer,
            .value_pointer = value_pointer,
        };
    }
}

pub fn MyHashMap(comptime K: type, comptime V: type) type {
    // const K = []const u8;
    return struct {
        key_pointer: [*]K = undefined,
        value_pointer: [*]V = undefined,
        length: IndexType = 0,
        capacity: IndexType = 0,

        pub fn get_pointer(map: *@This(), key: K) ?*V {
            for (map.keys(), 0..) |k, i| {
                const is_equal = switch (@typeInfo(K)) {
                    .Pointer => |pointer| switch (pointer.size) {
                        .Slice => byte_equal(k, key),
                        else => k == key,
                    },
                    .Struct => equal(k, key),
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

        pub fn put(map: *@This(), allocator: *MyAllocator, key: K, value: V) !void {
            if (map.get_pointer(key)) |value_ptr| {
                value_ptr.* = value;
            } else {
                const len = map.length;
                try map.ensure_capacity(allocator, len + 1);
                map.put_at_with_capacity(len, key, value);
            }
        }

        pub fn put_no_clobber(map: *@This(), allocator: *MyAllocator, key: K, value: V) !void {
            assert(map.get_pointer(key) == null);
            const len = map.length;
            try map.ensure_capacity(allocator, len + 1);
            map.put_at_with_capacity(len, key, value);
        }

        fn put_at_with_capacity(map: *@This(), index: IndexType, key: K, value: V) void {
            map.length += 1;
            assert(index < map.length);
            map.key_pointer[index] = key;
            map.value_pointer[index] = value;
        }

        pub fn ensure_capacity(map: *@This(), allocator: *MyAllocator, desired_capacity: IndexType) !void {
            const result = try ensure_capacity_hashmap(allocator, map.capacity, desired_capacity, @ptrCast(map.key_pointer), @ptrCast(map.value_pointer), map.length, @sizeOf(K), @alignOf(K), @sizeOf(V), @alignOf(V));
            map.capacity = result.capacity;
            map.key_pointer = @ptrCast(@alignCast(result.key_pointer));
            map.value_pointer = @ptrCast(@alignCast(result.value_pointer));
        }

        pub fn keys(map: *@This()) []K {
            return map.key_pointer[0..map.length];
        }

        pub fn values(map: *@This()) []V {
            return map.value_pointer[0..map.length];
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

const page_size = std.mem.page_size;
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
            } = if (flags.executable) std.os.PROT.EXEC else 0;
            const protection_flags: u32 = @intCast(std.os.PROT.READ | std.os.PROT.WRITE | execute_flag);

            const result = try std.os.mmap(null, size, protection_flags, .{
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

pub fn free_virtual_memory(slice: []align(0x1000) const u8) void {
    switch (os) {
        .windows => {
            std.os.windows.VirtualFree(slice.ptr, slice.len, std.os.windows.MEM_RELEASE);
        },
        else => {
            std.os.munmap(slice);
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

pub const IndexType = if (@sizeOf(usize) >= 8) u32 else usize;

const ArrayCapacity = struct {
    pointer: *anyopaque,
    capacity: IndexType,
};

fn ensure_capacity_array(allocator: *MyAllocator, current_capacity: IndexType, desired_capacity: IndexType, pointer: [*]u8, length: IndexType, element_size: IndexType, element_alignment: u16) !ArrayCapacity {
    var new_capacity = @max(current_capacity, initial_item_count);
    while (new_capacity < desired_capacity) {
        new_capacity *= factor;
    }
    if (new_capacity > current_capacity) {
        const old_byte_slice = pointer[0 .. length * element_size];
        const new_byte_capacity = new_capacity * element_size;
        const new_slice = try allocator.reallocate(old_byte_slice, new_byte_capacity, element_alignment);
        return .{
            .pointer = new_slice.ptr,
            .capacity = new_capacity,
        };
    } else {
        return .{
            .pointer = pointer,
            .capacity = current_capacity,
        };
    }
}

const initial_item_count = 16;
const factor = 2;

pub fn UnpinnedArray(comptime T: type) type {
    return struct {
        pointer: [*]T = undefined,
        length: IndexType = 0,
        capacity: IndexType = 0,

        pub fn initialize_with_capacity(allocator: *MyAllocator, item_count: IndexType) !@This() {
            var array = @This(){};
            try array.ensure_capacity(allocator, item_count);
            return array;
        }

        pub fn ensure_capacity(array: *@This(), allocator: *MyAllocator, desired_capacity: IndexType) !void {
            const result = try ensure_capacity_array(allocator, array.capacity, desired_capacity, @ptrCast(array.pointer), array.length, @sizeOf(T), @alignOf(T));
            array.pointer = @ptrCast(@alignCast(result.pointer));
            array.capacity = result.capacity;
        }

        pub fn append(array: *@This(), allocator: *MyAllocator, item: T) !void {
            try array.ensure_capacity(allocator, array.length + 1);
            array.append_with_capacity(item);
        }

        pub fn append_slice(array: *@This(), allocator: *MyAllocator, items: []const T) !void {
            try array.ensure_capacity(allocator, @intCast(array.length + items.len));
            @memcpy(array.pointer[array.length..][0..items.len], items);
            array.length += @intCast(items.len);
        }

        pub fn append_with_capacity(array: *@This(), item: T) void {
            assert(array.length < array.capacity);
            array.pointer[array.length] = item;
            array.length += 1;
        }

        pub fn slice(array: *@This()) []T {
            return array.pointer[0..array.length];
        }

        pub fn insert(array: *@This(), allocator: *MyAllocator, index: IndexType, item: T) !void {
            assert(index < array.length);
            if (array.length + 1 >= array.capacity) {
                const after_count = array.length - index;
                copy_backwards(T, array.pointer[index + 1 ..][0..after_count], array.pointer[index..][0..after_count]);
            } else {
                const new_capacity = array.capacity * 2;
                const new_slice = try allocator.allocate(new_capacity * @sizeOf(T), @alignOf(T));
                const new_typed_slice: []T = @as([*]T, @ptrCast(@alignCast(new_slice.ptr)))[0..new_capacity];
                @memcpy(new_typed_slice[0..index], array.pointer[0..index]);
                const after_count = array.length - index;
                @memcpy(new_typed_slice[index + 1 ..][0..after_count], array.pointer[index..][0..after_count]);
                try allocator.free(@as([*]u8, @ptrCast(@alignCast(array.slice().ptr)))[0 .. array.capacity * @sizeOf(T)]);
                array.pointer = new_typed_slice.ptr;
                array.capacity = new_capacity;
            }

            array.pointer[index] = item;
            array.length += 1;
        }

        pub fn pop(array: *@This()) T {
            assert(array.length > 0);
            array.length -= 1;
            return array.pointer[array.length];
        }
    };
}

fn copy_backwards(comptime T: type, destination: []T, source: []const T) void {
    @setRuntimeSafety(false);
    assert(destination.len >= source.len);
    var i = source.len;
    while (i > 0) {
        i -= 1;
        destination[i] = source[i];
    }
}

test {
    var page_allocator = PageAllocator{};
    const allocator = &page_allocator.allocator;
    var foo = UnpinnedArray(u32){};
    try foo.append(allocator, 1);
    try foo.append(allocator, 1);
    try foo.append(allocator, 1);
    try foo.append(allocator, 1);
    try foo.append(allocator, 1);
    try foo.append(allocator, 1);
    try foo.append(allocator, 1);
    try foo.append(allocator, 1);
    try foo.append(allocator, 1);
    try foo.append(allocator, 1);
    try foo.append(allocator, 1);
    try foo.append(allocator, 1);
    try foo.append(allocator, 1);
    try foo.append(allocator, 1);
    try foo.append(allocator, 1);
    try foo.append(allocator, 1);
    try foo.append(allocator, 1);
    try foo.append(allocator, 1);
    try foo.append(allocator, 1);
    try foo.append(allocator, 1);
    try foo.append(allocator, 1);
    try foo.append(allocator, 1);
    try foo.append(allocator, 1);
    try foo.append(allocator, 1);
    try foo.append(allocator, 1);
    try foo.append(allocator, 1);
    try foo.append(allocator, 1);
    try foo.append(allocator, 1);
    try foo.append(allocator, 1);
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
