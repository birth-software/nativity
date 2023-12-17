const std = @import("std");
const assert = std.debug.assert;

pub const Allocator = std.mem.Allocator;
pub const AutoArrayHashMap = std.AutoArrayHashMapUnmanaged;
pub const ArrayList = std.ArrayListUnmanaged;
pub const ArrayListAligned = std.ArrayListAlignedUnmanaged;
pub const AutoHashMap = std.AutoHashMapUnmanaged;
pub const HashMap = std.HashMapUnmanaged;
pub const SegmentedList = std.SegmentedList;
pub const StringHashMap = std.StringHashMapUnmanaged;
pub const StringArrayHashMap = std.StringArrayHashMapUnmanaged;

pub fn BlockList(comptime T: type) type {
    const item_count = 64;
    const Block = struct {
        items: [item_count]T = undefined,
        bitset: Bitset = Bitset.initEmpty(),

        const Bitset = std.StaticBitSet(item_count);

        fn allocateIndex(block: *@This()) !u6 {
            if (block.bitset.mask != std.math.maxInt(@TypeOf(block.bitset.mask))) {
                const index = @ctz(~block.bitset.mask);
                block.bitset.set(index);
                return @intCast(index);
            } else {
                return error.OutOfMemory;
            }
        }
    };

    return struct {
        // TODO: make this not reallocate the whole block. Instead, use a pointer to the block as the ArrayList item
        blocks: ArrayList(*Block) = .{},
        len: usize = 0,
        first_block: u32 = 0,

        const List = @This();

        pub const Index = packed struct(u32) {
            element: u6,
            block: u24,
            _reserved: bool = false,
            invalid: bool = false,

            pub const invalid = Index{
                .invalid = true,
                .element = 0,
                .block = 0,
            };

            pub fn eq(index: Index, other: Index) bool {
                return @as(u32, @bitCast(index)) == @as(u32, @bitCast(other));
            }

            pub fn uniqueInteger(index: Index) u32 {
                assert(!index.invalid);
                return @as(u30, @truncate(@as(u32, @bitCast(index))));
            }

            pub fn fromInteger(usize_index: usize) Index {
                const index: u32 = @intCast(usize_index);
                const block: u24 = @intCast(index / item_count);
                const i: u6 = @intCast(index % item_count);
                return .{
                    .element = i,
                    .block = block,
                };
            }
        };

        pub const Iterator = struct {
            index: Index,
            list: *List,

            pub const Pair = struct {
                index: Index,
            };

            pub fn nextIndex(i: *Iterator) ?Index {
                // TODO: optimize with ctz and masking out already iterated indices in the bitmask
                for (i.index.block..i.list.blocks.items.len) |block_index| {
                    for (@as(u8, i.index.element)..item_count) |element_index| {
                        if (i.list.blocks.items[block_index].bitset.isSet(element_index)) {
                            const index = Index{
                                .element = @intCast(element_index),
                                .block = @intCast(block_index),
                            };

                            i.index = index;
                            i.index.element +%= 1;
                            i.index.block = @as(u24, @intCast(block_index)) + @intFromBool(i.index.element < element_index);

                            return index;
                        }
                    }
                }

                return null;
            }

            pub fn nextPointer(i: *Iterator) ?*T {
                if (i.nextIndex()) |index| {
                    const result = i.list.get(index);
                    return result;
                } else {
                    return null;
                }
            }
        };

        pub fn iterator(list: *List) Iterator {
            return .{
                .index = Index{
                    .element = 0,
                    .block = 0,
                },
                .list = list,
            };
        }

        pub fn get(list: *List, index: Index) *T {
            assert(!index.invalid);
            return &list.blocks.items[index.block].items[index.element];
        }

        pub fn append(list: *List, allocator: Allocator, element: T) !Index {
            const result = try list.addOne(allocator);
            list.get(result).* = element;
            return result;
        }

        pub fn addOne(list: *List, allocator: Allocator) !Index {
            try list.ensureCapacity(allocator, list.len + 1);
            const max_allocation = list.blocks.items.len * item_count;
            const result = switch (list.len < max_allocation) {
                true => blk: {
                    const block = list.blocks.items[list.first_block];
                    if (block.allocateIndex()) |element_index| {
                        break :blk Index{
                            .element = element_index,
                            .block = @intCast(list.first_block),
                        };
                    } else |_| {
                        @panic("TODO");
                    }
                },
                false => blk: {
                    const block_index = list.blocks.items.len;
                    const new_block = try allocator.create(Block);
                    new_block.* = .{};
                    list.blocks.appendAssumeCapacity(new_block);
                    const element_index = new_block.allocateIndex() catch unreachable;
                    list.first_block += @intFromBool(block_index != 0);
                    break :blk Index{
                        .element = element_index,
                        .block = @intCast(block_index),
                    };
                },
            };

            list.len += 1;

            return result;
        }

        pub fn ensureCapacity(list: *List, allocator: Allocator, new_capacity: usize) !void {
            const max_allocation = list.blocks.items.len * item_count;
            if (max_allocation < new_capacity) {
                const block_count = new_capacity / item_count + @intFromBool(new_capacity % item_count != 0);
                try list.blocks.ensureTotalCapacity(allocator, block_count);
            }
        }

        pub fn indexOf(list: *List, elem: *const T) Index {
            const address = @intFromPtr(elem);
            for (list.blocks.items, 0..) |*block, block_index| {
                const base = @intFromPtr(&block.items[0]);
                const top = base + @sizeOf(T) * item_count;
                if (address >= base and address < top) {
                    return .{
                        .block = @intCast(block_index),
                        .element = @intCast(@divExact(address - base, @sizeOf(T))),
                    };
                }
            }

            @panic("not found");
        }

        test "Bitset index allocation" {
            const expect = std.testing.expect;
            var block = Block{};
            for (0..item_count) |expected_index| {
                const new_index = try block.allocateIndex();
                try expect(new_index == expected_index);
            }

            _ = block.allocateIndex() catch return;

            return error.TestUnexpectedResult;
        }
    };
}

pub fn enumFromString(comptime E: type, string: []const u8) ?E {
    return inline for (@typeInfo(E).Enum.fields) |enum_field| {
        if (std.mem.eql(u8, string, enum_field.name)) {
            break @field(E, enum_field.name);
        }
    } else null;
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
