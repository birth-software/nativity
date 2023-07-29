const std = @import("std");
const Allocator = std.mem.Allocator;
const log = std.log;
const page_size = std.mem.page_size;
const assert = std.debug.assert;
const expect = std.testing.expect;
const expectEqual = std.testing.expectEqual;

const ir = @import("ir.zig");

pub const Result = struct {
    pub fn free(result: *Result, allocator: Allocator) void {
        _ = allocator;
        _ = result;
    }
};

const Section = struct {
    content: []align(page_size) u8,
    index: usize = 0,
};

const Image = struct {
    sections: struct {
        text: Section,
        rodata: Section,
        data: Section,
    },
    entry_point: u32 = 0,

    fn create() !Image {
        return Image{
            .sections = .{
                .text = .{ .content = try mmap(page_size, .{ .executable = true }) },
                .rodata = .{ .content = try mmap(page_size, .{ .executable = false }) },
                .data = .{ .content = try mmap(page_size, .{ .executable = false }) },
            },
        };
    }

    fn destroy(image: *Image) void {
        inline for (comptime std.meta.fieldNames(@TypeOf(image.sections))) |field_name| {
            std.os.munmap(@field(image.sections, field_name).content);
        }
    }

    inline fn mmap(size: usize, flags: packed struct {
        executable: bool,
    }) ![]align(page_size) u8 {
        const protection_flags = std.os.PROT.READ | std.os.PROT.WRITE | if (flags.executable) std.os.PROT.EXEC else 0;
        const mmap_flags = std.os.MAP.ANONYMOUS | std.os.MAP.PRIVATE;

        return std.os.mmap(null, size, protection_flags, mmap_flags, -1, 0);
    }

    fn appendCode(image: *Image, code: []const u8) void {
        const destination = image.sections.text.content[image.sections.text.index..][0..code.len];
        @memcpy(destination, code);
        image.sections.text.index += code.len;
    }

    fn appendCodeByte(image: *Image, code_byte: u8) void {
        image.sections.text.content[image.sections.text.index] = code_byte;
        image.sections.text.index += 1;
    }

    fn getEntryPoint(image: *const Image, comptime Function: type) *const Function {
        comptime {
            assert(@typeInfo(Function) == .Fn);
        }

        assert(image.sections.text.content.len > 0);
        return @as(*const Function, @ptrCast(&image.sections.text.content[image.entry_point]));
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

pub const BasicGPRegister = enum(u3) {
    a = 0,
    c = 1,
    d = 2,
    b = 3,
    sp = 4,
    bp = 5,
    si = 6,
    di = 7,
};

const prefix_lock = 0xf0;
const prefix_repne_nz = 0xf2;
const prefix_rep = 0xf3;
const prefix_rex_w = [1]u8{@intFromEnum(Rex.w)};
const prefix_16_bit_operand = [1]u8{0x66};

const ret = 0xc3;
const mov_a_imm = [1]u8{0xb8};
const mov_reg_imm8: u8 = 0xb0;

inline fn intToArrayOfBytes(integer: anytype) [@sizeOf(@TypeOf(integer))]u8 {
    comptime {
        assert(@typeInfo(@TypeOf(integer)) == .Int);
    }

    return @as([@sizeOf(@TypeOf(integer))]u8, @bitCast(integer));
}

inline fn movAImm(image: *Image, integer: anytype) void {
    const T = @TypeOf(integer);
    image.appendCode(&(switch (T) {
        u8, i8 => .{mov_reg_imm8 | @intFromEnum(GPRegister.a)},
        u16, i16 => prefix_16_bit_operand ++ mov_a_imm,
        u32, i32 => mov_a_imm,
        u64, i64 => prefix_rex_w ++ mov_a_imm,
        else => @compileError("Unsupported"),
    } ++ intToArrayOfBytes(integer)));
}

test "ret void" {
    var image = try Image.create();
    defer image.destroy();
    image.appendCodeByte(ret);

    const function_pointer = image.getEntryPoint(fn () callconv(.C) void);
    function_pointer();
}

const integer_types_to_test = [_]type{ u8, u16, u32, u64, i8, i16, i32, i64 };

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
        var image = try Image.create();
        defer image.destroy();
        const expected_number = getMaxInteger(Int);

        movAImm(&image, expected_number);
        image.appendCodeByte(ret);

        const function_pointer = image.getEntryPoint(fn () callconv(.C) Int);
        const result = function_pointer();
        try expect(result == expected_number);
    }
}

const LastByte = packed struct(u8) {
    dst: BasicGPRegister,
    src: BasicGPRegister,
    always_on: u2 = 0b11,
};

fn movRmR(image: *Image, comptime T: type, dst: BasicGPRegister, src: BasicGPRegister) void {
    dstRmSrcR(image, T, .mov, dst, src);
}

fn dstRmSrcR(image: *Image, comptime T: type, opcode: OpcodeRmR, dst: BasicGPRegister, src: BasicGPRegister) void {
    const last_byte: u8 = @bitCast(LastByte{
        .dst = dst,
        .src = src,
    });
    const opcode_byte = @intFromEnum(opcode);

    const bytes = switch (T) {
        u8, i8 => blk: {
            const base = [_]u8{ opcode_byte - 1, last_byte };
            if (@intFromEnum(dst) >= @intFromEnum(BasicGPRegister.sp) or @intFromEnum(src) >= @intFromEnum(BasicGPRegister.sp)) {
                image.appendCodeByte(0x40);
            }

            break :blk base;
        },
        u16, i16 => prefix_16_bit_operand ++ .{ opcode_byte, last_byte },
        u32, i32 => .{ opcode_byte, last_byte },
        u64, i64 => prefix_rex_w ++ .{ opcode_byte, last_byte },
        else => @compileError("Not supported"),
    };

    image.appendCode(&bytes);
}

test "ret integer argument" {
    inline for (integer_types_to_test) |Int| {
        var image = try Image.create();
        defer image.destroy();
        const number = getMaxInteger(Int);

        movRmR(&image, Int, .a, .di);
        image.appendCodeByte(ret);

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

fn subRmR(image: *Image, comptime T: type, dst: BasicGPRegister, src: BasicGPRegister) void {
    dstRmSrcR(image, T, .sub, dst, src);
}

test "ret sub arguments" {
    inline for (integer_types_to_test) |Int| {
        var image = try Image.create();
        defer image.destroy();
        const a = getRandomNumberRange(Int, std.math.minInt(Int) / 2, std.math.maxInt(Int) / 2);
        const b = getRandomNumberRange(Int, std.math.minInt(Int) / 2, a);

        movRmR(&image, Int, .a, .di);
        subRmR(&image, Int, .a, .si);
        image.appendCodeByte(ret);

        const functionPointer = image.getEntryPoint(fn (Int, Int) callconv(.C) Int);
        const result = functionPointer(a, b);
        try expectEqual(a - b, result);
    }
}

const OpcodeRmR = enum(u8) {
    add = 0x01,
    @"or" = 0x09,
    @"and" = 0x21,
    sub = 0x29,
    xor = 0x31,
    @"test" = 0x85,
    mov = 0x89,
};

test "test binary operations" {
    inline for (integer_types_to_test) |T| {
        const test_cases = [_]TestIntegerBinaryOperation(T){
            .{
                .opcode = .add,
                .callback = struct {
                    fn callback(a: T, b: T) T {
                        return @addWithOverflow(a, b)[0];
                    }
                }.callback,
            },
            .{
                .opcode = .sub,
                .callback = struct {
                    fn callback(a: T, b: T) T {
                        return @subWithOverflow(a, b)[0];
                    }
                }.callback,
            },
            .{
                .opcode = .@"or",
                .callback = struct {
                    fn callback(a: T, b: T) T {
                        return a | b;
                    }
                }.callback,
            },
            .{
                .opcode = .@"and",
                .callback = struct {
                    fn callback(a: T, b: T) T {
                        return a & b;
                    }
                }.callback,
            },
            .{
                .opcode = .xor,
                .callback = struct {
                    fn callback(a: T, b: T) T {
                        return a ^ b;
                    }
                }.callback,
            },
        };

        for (test_cases) |test_case| {
            try test_case.runTest();
        }
    }
}

fn TestIntegerBinaryOperation(comptime T: type) type {
    const should_log = false;
    return struct {
        callback: *const fn (a: T, b: T) T,
        opcode: OpcodeRmR,

        pub fn runTest(test_case: @This()) !void {
            for (0..10) |_| {
                var image = try Image.create();
                defer image.destroy();
                errdefer image.destroy();
                const a = getRandomNumberRange(T, std.math.minInt(T) / 2, std.math.maxInt(T) / 2);
                const b = getRandomNumberRange(T, std.math.minInt(T) / 2, a);
                movRmR(&image, T, .a, .di);
                dstRmSrcR(&image, T, test_case.opcode, .a, .si);
                image.appendCodeByte(ret);

                const functionPointer = image.getEntryPoint(fn (T, T) callconv(.C) T);
                const expected = test_case.callback(a, b);
                const result = functionPointer(a, b);
                if (should_log) {
                    log.err("{s} {}, {} ({})", .{ @tagName(test_case.opcode), a, b, T });
                }
                try expectEqual(expected, result);
            }
        }
    };
}

test "call after" {
    var image = try Image.create();
    defer image.destroy();
    errdefer image.destroy();
    const jump_patch_offset = image.sections.text.index + 1;
    image.appendCode(&.{ 0xe8, 0x00, 0x00, 0x00, 0x00 });
    const jump_source = image.sections.text.index;
    image.appendCodeByte(ret);
    const jump_target = image.sections.text.index;
    @as(*align(1) u32, @ptrCast(&image.sections.text.content[jump_patch_offset])).* = @intCast(jump_target - jump_source);
    image.appendCodeByte(ret);

    const functionPointer = image.getEntryPoint(fn () callconv(.C) void);
    functionPointer();
}

test "call before" {
    var image = try Image.create();
    defer image.destroy();
    errdefer image.destroy();
    const first_jump_patch_offset = image.sections.text.index + 1;
    const first_call = .{0xe8} ++ .{ 0x00, 0x00, 0x00, 0x00 };
    image.appendCode(&first_call);
    const first_jump_source = image.sections.text.index;
    image.appendCodeByte(ret);
    const second_jump_target = image.sections.text.index;
    image.appendCodeByte(ret);
    const first_jump_target = image.sections.text.index;
    @as(*align(1) i32, @ptrCast(&image.sections.text.content[first_jump_patch_offset])).* = @intCast(first_jump_target - first_jump_source);
    const second_call = .{0xe8} ++ @as([4]u8, @bitCast(@as(i32, @intCast(@as(i64, @intCast(second_jump_target)) - @as(i64, @intCast(image.sections.text.index + 5))))));
    image.appendCode(&second_call);
    image.appendCodeByte(ret);

    const functionPointer = image.getEntryPoint(fn () callconv(.C) void);
    functionPointer();
}

pub fn runTest(allocator: Allocator, ir_result: *const ir.Result) !Result {
    _ = allocator;

    for (ir_result.functions.items) |*function| {
        _ = function;
    }

    return Result{};
}
