const std = @import("std");
const log = std.log;
const page_size = std.mem.page_size;
const assert = std.debug.assert;
const expect = std.testing.expect;
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

const GPRegister = enum(u4) {
    a = 0,
    c = 1,
    d = 2,
    b = 3,
    sp = 4,
    bp = 5,
    si = 6,
    di = 7,
    r8 = 8,
    r9 = 9,
    r10 = 10,
    r11 = 11,
    r12 = 12,
    r13 = 13,
    r14 = 14,
    r15 = 15,
};

const prefix_lock = 0xf0;
const prefix_repne_nz = 0xf2;
const prefix_rep = 0xf3;
const prefix_rex_w = [1]u8{@intFromEnum(Rex.w)};
const prefix_16_bit_operand = [1]u8{0x66};

const ret = [1]u8{0xc3};
const mov_a_imm = [1]u8{0xb8};
const mov_reg_imm8: u8 = 0xb0;

inline fn intToArrayOfBytes(integer: anytype) [@sizeOf(@TypeOf(integer))]u8 {
    comptime {
        assert(@typeInfo(@TypeOf(integer)) == .Int);
    }

    return @as([@sizeOf(@TypeOf(integer))]u8, @bitCast(integer));
}

fn movToAInstructionByteCount(comptime bit_count: u16) type {
    return [
        switch (bit_count) {
            8 => 2,
            16 => 4,
            32 => 5,
            64 => 10,
            else => @compileError("Not supported"),
        }
    ]u8;
}

inline fn movAImm(comptime signedness: std.builtin.Signedness, comptime bit_count: u16, integer: @Type(.{
    .Int = .{
        .signedness = signedness,
        .bits = bit_count,
    },
})) movToAInstructionByteCount(bit_count) {
    return switch (@TypeOf(integer)) {
        u8, i8 => .{mov_reg_imm8 | @intFromEnum(GPRegister.a)},
        u16, i16 => prefix_16_bit_operand ++ mov_a_imm,
        u32, i32 => mov_a_imm,
        u64, i64 => prefix_rex_w ++ mov_a_imm,
        else => @compileError("Unsupported"),
    } ++ intToArrayOfBytes(integer);
}

test "ret void" {
    var image = try Image.create();
    image.appendCode(&ret);

    const function_pointer = image.getEntryPoint(fn () callconv(.C) void);
    function_pointer();
}

const integer_types_to_test = [_]type{ u8, u16, u32, u64, i8, i16, i32, i64 };

fn testRetInteger(comptime T: type) !void {
    comptime {
        assert(@typeInfo(T) == .Int);
        assert((T == u8 or T == u16 or T == u32 or T == u64) or (T == i8 or T == i16 or T == i32 or T == i64));
    }

    var image = try Image.create();
    const signedness = @typeInfo(T).Int.signedness;
    const expected_number = getMaxInteger(T);

    image.appendCode(&movAImm(signedness, @bitSizeOf(T), expected_number));
    image.appendCode(&ret);

    const function_pointer = image.getEntryPoint(fn () callconv(.C) T);
    const result = function_pointer();
    try expect(result == expected_number);
}

fn getMaxInteger(comptime T: type) T {
    comptime {
        assert(@typeInfo(T) == .Int);
    }

    return switch (@typeInfo(T).Int.signedness) {
        .unsigned => std.math.maxInt(T),
        .signed => std.math.minInt(T),
    };
}

test "ret integer" {
    inline for (integer_types_to_test) |Int| {
        try testRetInteger(Int);
    }
}

const mov_rm_r = 0x89;

test "ret integer argument" {
    inline for (integer_types_to_test) |Int| {
        var image = try Image.create();
        const number = getMaxInteger(Int);
        const mov_a_di = switch (Int) {
            u8, i8 => .{ 0x40, 0x88, 0xf8 },
            u16, i16 => prefix_16_bit_operand ++ .{ mov_rm_r, 0xf8 },
            u32, i32 => .{ mov_rm_r, 0xf8 },
            u64, i64 => prefix_rex_w ++ .{ mov_rm_r, 0xf8 },
            else => @compileError("Not supported"),
        };

        image.appendCode(&mov_a_di);
        image.appendCode(&ret);

        const functionPointer = image.getEntryPoint(fn (Int) callconv(.C) Int);
        const result = functionPointer(number);
        try expectEqual(number, result);
    }
}
var r = std.rand.Pcg.init(0xffffffffffffffff);

fn getRandomNumberRange(comptime T: type, min: T, max: T) T {
    const random = r.random();
    return switch (@typeInfo(T).Int.signedness) {
        .signed => random.intRangeAtMost(T, min, max),
        .unsigned => random.uintAtMost(T, max),
    };
}

const sub_rm_r = 0x29;

test "ret sub arguments" {
    inline for (integer_types_to_test) |Int| {
        var image = try Image.create();
        const a = getRandomNumberRange(Int, std.math.minInt(Int) / 2, std.math.maxInt(Int) / 2);
        const b = getRandomNumberRange(Int, std.math.minInt(Int) / 2, a);

        const mov_a_di = switch (Int) {
            u8, i8 => .{ 0x40, 0x88, 0xf8 },
            u16, i16 => prefix_16_bit_operand ++ .{ mov_rm_r, 0xf8 },
            u32, i32 => .{ mov_rm_r, 0xf8 },
            u64, i64 => prefix_rex_w ++ .{ mov_rm_r, 0xf8 },
            else => @compileError("Not supported"),
        };
        image.appendCode(&mov_a_di);

        const sub_a_si = switch (Int) {
            u8, i8 => .{ 0x40, 0x28, 0xf0 },
            u16, i16 => prefix_16_bit_operand ++ .{ sub_rm_r, 0xf0 },
            u32, i32 => .{ sub_rm_r, 0xf0 },
            u64, i64 => prefix_rex_w ++ .{ sub_rm_r, 0xf0 },
            else => @compileError("Not supported"),
        };
        image.appendCode(&sub_a_si);
        image.appendCode(&ret);

        const functionPointer = image.getEntryPoint(fn (Int, Int) callconv(.C) Int);
        const result = functionPointer(a, b);
        try expectEqual(a - b, result);
    }
}
