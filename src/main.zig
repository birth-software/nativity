const std = @import("std");
const page_size = std.mem.page_size;
const assert = std.debug.assert;
const expectEqual = std.testing.expectEqual;

const Section = struct {
    content: []align(page_size) u8,
    index: usize = 0,
};

const Image = struct {
    text: Section,
    rodata: Section,
    data: Section,
    entry_point: u32 = 0,

    fn create() !Image {
        return Image{
            .text = .{ .content = try mmap(page_size, .{ .executable = true }) },
            .rodata = .{ .content = try mmap(page_size, .{ .executable = false }) },
            .data = .{ .content = try mmap(page_size, .{ .executable = false }) },
        };
    }

    inline fn mmap(size: usize, flags: packed struct {
        executable: bool,
    }) ![]align(page_size) u8 {
        const protection_flags = std.os.PROT.READ | std.os.PROT.WRITE | if (flags.executable) std.os.PROT.EXEC else 0;
        const mmap_flags = std.os.MAP.ANONYMOUS | std.os.MAP.PRIVATE;

        return std.os.mmap(null, size, protection_flags, mmap_flags, -1, 0);
    }

    fn appendCode(image: *Image, code: []const u8) void {
        const destination = image.text.content[image.text.index..][0..code.len];
        @memcpy(destination, code);
        image.text.index += code.len;
    }

    fn getEntryPoint(image: *const Image, comptime Function: type) *const Function {
        comptime {
            assert(@typeInfo(Function) == .Fn);
        }

        assert(image.text.content.len > 0);
        return @as(*const Function, @ptrCast(&image.text.content[image.entry_point]));
    }
};

const Rex = enum(u8) {
    b = upper_4_bits | (1 << 0),
    x = upper_4_bits | (1 << 1),
    r = upper_4_bits | (1 << 2),
    w = upper_4_bits | (1 << 3),

    const upper_4_bits = 0b100_0000;
};

const prefix_rex_w = [1]u8{@intFromEnum(Rex.w)};
const prefix_16_bit_operand = [1]u8{0x66};

const ret = [1]u8{0xc3};
const movabs_to_register_a = [1]u8{0xb8};

inline fn intToArrayOfBytes(integer: anytype) [@sizeOf(@TypeOf(integer))]u8 {
    comptime {
        assert(@typeInfo(@TypeOf(integer)) == .Int);
    }

    return @as([@sizeOf(@TypeOf(integer))]u8, @bitCast(integer));
}

inline fn movU16ToA(integer: u16) [4]u8 {
    return prefix_16_bit_operand ++ movabs_to_register_a ++ intToArrayOfBytes(integer);
}

inline fn movU32ToA(integer: u32) [5]u8 {
    return movabs_to_register_a ++ intToArrayOfBytes(integer);
}

inline fn movU64ToA(integer: u64) [10]u8 {
    return prefix_rex_w ++ movabs_to_register_a ++ intToArrayOfBytes(integer);
}

test "ret void" {
    var image = try Image.create();
    image.appendCode(&ret);

    const function_pointer = image.getEntryPoint(fn () callconv(.C) void);
    function_pointer();
}

test "ret unsigned integer 16-bit" {
    var image = try Image.create();
    const expected_number = 0xffff;
    image.appendCode(&movU16ToA(expected_number));
    image.appendCode(&ret);

    const function_pointer = image.getEntryPoint(fn () callconv(.C) u16);
    const result = function_pointer();
    try expectEqual(result, expected_number);
}

test "ret unsigned integer 32-bit" {
    var image = try Image.create();
    const expected_number = 0xffff_ffff;
    image.appendCode(&movU32ToA(expected_number));
    image.appendCode(&ret);

    const function_pointer = image.getEntryPoint(fn () callconv(.C) u32);
    const result = function_pointer();
    try expectEqual(result, expected_number);
}

test "ret unsigned integer 64-bit" {
    var image = try Image.create();
    const expected_number = 0xffff_ffff_ffff_ffff;
    image.appendCode(&movU64ToA(expected_number));
    image.appendCode(&ret);

    const function_pointer = image.getEntryPoint(fn () callconv(.C) u64);
    const result = function_pointer();
    try expectEqual(result, expected_number);
}
