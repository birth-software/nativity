const std = @import("std");
const assert = std.debug.assert;

pub const Allocator = std.mem.Allocator;
pub const AutoArrayHashMap = std.AutoArrayHashMapUnmanaged;
pub const ArrayList = std.ArrayListUnmanaged;
pub const ArrayListAligned = std.ArrayListAlignedUnmanaged;
pub const AutoHashMap = std.AutoHashMapUnmanaged;
pub const BoundedArray = std.BoundedArray;
pub const HashMap = std.HashMapUnmanaged;
pub const StringHashMap = std.StringHashMapUnmanaged;
pub const StringArrayHashMap = std.StringArrayHashMapUnmanaged;

pub fn BlockList(comptime T: type, comptime E: type) type {
    const item_count = 64;

    return struct {
        blocks: ArrayList(*Block) = .{},
        len: usize = 0,

        const Block = BoundedArray(T, item_count);
        const List = @This();

        pub const Index = getIndexForType(T, E);
        pub const ElementIndex = Index.Index;

        // pub const append = switch (list_type) {
        //     .index => appendIndexed,
        //     .pointer => appendPointer,
        // };
        // pub const addOne = switch (list_type) {
        //     .index => addOneIndexed,
        //     .pointer => addOnePointer,
        // };

        pub fn wrapSplit(block: usize, element: usize) ElementIndex {
            return @enumFromInt(block * item_count + element);
        }

        pub fn get(list: *List, index: ElementIndex) *T {
            assert(index != .null);
            const i: u32 = @intFromEnum(index);
            const block_index = i / item_count;
            const element_index = i % item_count;
            const block = list.blocks.items[block_index];
            const block_slice = block.buffer[0..block.len];
            const element = &block_slice[element_index];
            return element;
        }

        pub fn append(list: *List, allocator: Allocator, element: T) !ElementIndex {
            const result = try list.addOne(allocator);
            list.get(result).* = element;
            return result;
        }

        pub fn addOne(list: *List, allocator: Allocator) !ElementIndex {
            const block_index = try list.getFreeBlock(allocator);
            const block = list.blocks.items[block_index];
            const index = block.len;
            _ = try block.addOne();
            return @enumFromInt(block_index * item_count + index);
        }

        fn getFreeBlock(list: *List, allocator: Allocator) !usize {
            for (list.blocks.items, 0..) |block, i| {
                block.ensureUnusedCapacity(1) catch continue;
                return i;
            } else {
                const new_block = try allocator.create(Block);
                new_block.* = .{};
                const block_index = list.blocks.items.len;
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
    const IndexType = u32;
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

        pub fn addInt(this: Index, value: IndexType) Index{
            const this_int = @intFromEnum(this);
            return @enumFromInt(this_int + value);
        }

        pub fn subInt(this: Index, value: IndexType) IndexType{
            const this_int = @intFromEnum(this);
            return this_int - value;
        }

        pub fn add(a: Index, b: Index) Index{
            return @enumFromInt(@intFromEnum(a) + @intFromEnum(b));
        }

        pub fn sub(a: Index, b: Index) IndexType{
            return @intFromEnum(a) - @intFromEnum(b);
        }
    };
}

pub const ListType = enum{
    index,
    pointer,
};


pub fn enumFromString(comptime E: type, string: []const u8) ?E {
    return inline for (@typeInfo(E).Enum.fields) |enum_field| {
        if (std.mem.eql(u8, string, enum_field.name)) {
            break @field(E, enum_field.name);
        }
    } else null;
}

pub fn hash(string: []const u8) u32 {
    const string_key: u32 = @truncate(std.hash.Wyhash.hash(0, string));
    return string_key;
}

pub fn StringKeyMap(comptime Value: type) type {
    return struct {
        list: std.MultiArrayList(Data) = .{},
        const Key = u32;
        const Data = struct {
            key: Key,
            value: Value,
        };

        pub fn length(string_map: *@This()) usize {
            return string_map.list.len;
        }

        fn hash(string: []const u8) Key {
            const string_key: Key = @truncate(std.hash.Wyhash.hash(0, string));
            return string_key;
        }

        pub fn getKey(string_map: *const @This(), string: []const u8) ?Key {
            return if (string_map.getKeyPtr(string)) |key_ptr| key_ptr.* else null;
        }

        pub fn getKeyPtr(string_map: *const @This(), string_key: Key) ?*const Key {
            for (string_map.list.items(.key)) |*key_ptr| {
                if (key_ptr.* == string_key) {
                    return key_ptr;
                }
            } else {
                return null;
            }
        }

        pub fn getValue(string_map: *const @This(), key: Key) ?Value {
            if (string_map.getKeyPtr(key)) |key_ptr| {
                const index = string_map.indexOfKey(key_ptr);
                return string_map.list.items(.value)[index];
            } else {
                return null;
            }
        }

        pub fn indexOfKey(string_map: *const @This(), key_ptr: *const Key) usize {
            return @divExact(@intFromPtr(key_ptr) - @intFromPtr(string_map.list.items(.key).ptr), @sizeOf(Key));
        }

        const GOP = struct {
            key: Key,
            found_existing: bool,
        };

        pub fn getOrPut(string_map: *@This(), allocator: Allocator, string: []const u8, value: Value) !GOP {
            const string_key: Key = @truncate(std.hash.Wyhash.hash(0, string));
            for (string_map.list.items(.key)) |key| {
                if (key == string_key) return .{
                    .key = string_key,
                    .found_existing = true,
                };
            } else {
                try string_map.list.append(allocator, .{
                    .key = string_key,
                    .value = value,
                });

                return .{
                    .key = string_key,
                    .found_existing = false,
                };
            }
        }
    };
}

const page_size = std.mem.page_size;
extern fn pthread_jit_write_protect_np(enabled: bool) void;

pub fn mmap(size: usize, flags: packed struct {
    executable: bool = false,
}) ![]align(page_size) u8 {
    return switch (@import("builtin").os.tag) {
        .windows => blk: {
            const windows = std.os.windows;
            break :blk @as([*]align(page_size) u8, @ptrCast(@alignCast(try windows.VirtualAlloc(null, size, windows.MEM_COMMIT | windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE))))[0..size];
        },
        .linux, .macos => |os_tag| blk: {
            const jit = switch (os_tag) {
                .macos => 0x800,
                .linux => 0,
                else => unreachable,
            };
            const execute_flag: switch (os_tag) {
                .linux => u32,
                .macos => c_int,
                else => unreachable,
            } = if (flags.executable) std.os.PROT.EXEC else 0;
            const protection_flags: u32 = @intCast(std.os.PROT.READ | std.os.PROT.WRITE | execute_flag);
            const mmap_flags = std.os.MAP.ANONYMOUS | std.os.MAP.PRIVATE | jit;

            const result = try std.os.mmap(null, size, protection_flags, mmap_flags, -1, 0);
            if (@import("builtin").cpu.arch == .aarch64 and @import("builtin").os.tag == .macos) {
                if (flags.executable) {
                    pthread_jit_write_protect_np(false);
                }
            }

            break :blk result;
        },
        else => @compileError("OS not supported"),
    };
}
