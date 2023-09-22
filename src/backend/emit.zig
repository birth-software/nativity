const std = @import("std");
const Allocator = std.mem.Allocator;
const log = std.log;
const page_size = std.mem.page_size;
const assert = std.debug.assert;
const expect = std.testing.expect;
const expectEqual = std.testing.expectEqual;

const ir = @import("intermediate_representation.zig");

const data_structures = @import("../data_structures.zig");
const ArrayList = data_structures.ArrayList;
const AutoHashMap = data_structures.AutoHashMap;

const jit_callconv = .SysV;

const Section = struct {
    content: []align(page_size) u8,
    index: usize = 0,
};

const Result = struct {
    sections: struct {
        text: Section,
        rodata: Section,
        data: Section,
    },
    entry_point: u32 = 0,

    fn create() !Result {
        return Result{
            .sections = .{
                .text = .{ .content = try mmap(page_size, .{ .executable = true }) },
                .rodata = .{ .content = try mmap(page_size, .{ .executable = false }) },
                .data = .{ .content = try mmap(page_size, .{ .executable = false }) },
            },
        };
    }

    fn mmap(size: usize, flags: packed struct {
        executable: bool,
    }) ![]align(page_size) u8 {
        return switch (@import("builtin").os.tag) {
            .windows => blk: {
                const windows = std.os.windows;
                break :blk @as([*]align(0x1000) u8, @ptrCast(@alignCast(try windows.VirtualAlloc(null, size, windows.MEM_COMMIT | windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE))))[0..size];
            },
            .linux, .macos => |os_tag| blk: {
                const execute_flag: switch (os_tag) {
                    .linux => u32,
                    .macos => c_int,
                    else => unreachable,
                } = if (flags.executable) std.os.PROT.EXEC else 0;
                const protection_flags: u32 = @intCast(std.os.PROT.READ | std.os.PROT.WRITE | execute_flag);
                const mmap_flags = std.os.MAP.ANONYMOUS | std.os.MAP.PRIVATE;

                break :blk std.os.mmap(null, size, protection_flags, mmap_flags, -1, 0);
            },
            else => @compileError("OS not supported"),
        };
    }

    fn appendCode(image: *Result, code: []const u8) void {
        const destination = image.sections.text.content[image.sections.text.index..][0..code.len];
        @memcpy(destination, code);
        image.sections.text.index += code.len;
    }

    fn appendCodeByte(image: *Result, code_byte: u8) void {
        image.sections.text.content[image.sections.text.index] = code_byte;
        image.sections.text.index += 1;
    }

    fn appendOnlyOpcodeSkipInstructionBytes(image: *Result, instruction: Instruction) void {
        const instruction_descriptor = instruction_descriptors.get(instruction);
        assert(instruction_descriptor.opcode_byte_count == instruction_descriptor.operand_offset);
        image.appendCode(instruction_descriptor.getOpcode());

        image.sections.text.index += instruction_descriptor.size - instruction_descriptor.opcode_byte_count;
    }

    fn getEntryPoint(image: *const Result, comptime FunctionType: type) *const FunctionType {
        comptime {
            assert(@typeInfo(FunctionType) == .Fn);
        }

        assert(image.sections.text.content.len > 0);
        return @as(*const FunctionType, @ptrCast(&image.sections.text.content[image.entry_point]));
    }
};

const Instruction = enum {
    jmp_rel_8,

    const Descriptor = struct {
        operands: [4]Operand,
        operand_count: u3,
        operand_offset: u5,
        size: u8,
        opcode: [2]u8,
        opcode_byte_count: u8,

        fn getOperands(descriptor: Descriptor) []const Operand {
            return descriptor.operands[0..descriptor.operand_count];
        }

        fn getOpcode(descriptor: Descriptor) []const u8 {
            return descriptor.opcode[0..descriptor.opcode_byte_count];
        }

        fn new(opcode_bytes: []const u8, operands: []const Operand) Descriptor {
            // TODO: prefixes
            var result = Descriptor{
                .operands = undefined,
                .operand_count = @intCast(operands.len),
                .operand_offset = opcode_bytes.len,
                .size = opcode_bytes.len,
                .opcode = undefined,
                .opcode_byte_count = opcode_bytes.len,
            };

            for (opcode_bytes, result.opcode[0..opcode_bytes.len]) |opcode_byte, *out_opcode| {
                out_opcode.* = opcode_byte;
            }

            for (operands, result.operands[0..operands.len]) |operand, *out_operand| {
                out_operand.* = operand;
                result.size += operand.size;
            }

            return result;
        }
    };

    const Operand = struct {
        type: Type,
        size: u8,

        const Type = enum {
            rel,
        };
    };
};

const rel8 = Instruction.Operand{
    .type = .rel,
    .size = @sizeOf(u8),
};

const instruction_descriptors = blk: {
    var result = std.EnumArray(Instruction, Instruction.Descriptor).initUndefined();
    result.getPtr(.jmp_rel_8).* = Instruction.Descriptor.new(&.{0xeb}, &[_]Instruction.Operand{rel8});
    break :blk result;
};

const InstructionSelector = struct {
    functions: ArrayList(Function),
    const Function = struct {
        instructions: ArrayList(Instruction) = .{},
        block_byte_counts: ArrayList(u16),
        block_offsets: ArrayList(u32),
        byte_count: u32 = 0,
        relocations: ArrayList(Relocation) = .{},
        block_map: AutoHashMap(ir.BasicBlock.Index, u32) = .{},
        const Relocation = struct {
            instruction: Instruction,
            source: u16,
            destination: u16,
            block_offset: u16,
        };
    };
};

pub fn get(comptime arch: std.Target.Cpu.Arch) type {
    const backend = switch (arch) {
        .x86_64 => @import("x86_64.zig"),
        else => @compileError("Architecture not supported"),
    };
    _ = backend;

    return struct {
        pub fn initialize(allocator: Allocator, intermediate: *ir.Result) !void {
            var result = try Result.create();
            var function_iterator = intermediate.functions.iterator();
            var instruction_selector = InstructionSelector{
                .functions = try ArrayList(InstructionSelector.Function).initCapacity(allocator, intermediate.functions.len),
            };

            while (function_iterator.next()) |ir_function| {
                const function = instruction_selector.functions.addOneAssumeCapacity();
                function.* = .{
                    .block_byte_counts = try ArrayList(u16).initCapacity(allocator, ir_function.blocks.items.len),
                    .block_offsets = try ArrayList(u32).initCapacity(allocator, ir_function.blocks.items.len),
                };
                try function.block_map.ensureTotalCapacity(allocator, @intCast(ir_function.blocks.items.len));
                for (ir_function.blocks.items, 0..) |block_index, index| {
                    function.block_map.putAssumeCapacity(block_index, @intCast(index));
                }

                for (ir_function.blocks.items) |block_index| {
                    const block = intermediate.blocks.get(block_index);
                    function.block_offsets.appendAssumeCapacity(function.byte_count);
                    var block_byte_count: u16 = 0;
                    for (block.instructions.items) |instruction_index| {
                        const instruction = intermediate.instructions.get(instruction_index).*;
                        switch (instruction) {
                            .phi => unreachable,
                            .ret => unreachable,
                            .jump => |jump_index| {
                                const jump = intermediate.jumps.get(jump_index);
                                const relocation = InstructionSelector.Function.Relocation{
                                    .instruction = .jmp_rel_8,
                                    .source = @intCast(function.block_map.get(jump.source) orelse unreachable),
                                    .destination = @intCast(function.block_map.get(jump.destination) orelse unreachable),
                                    .block_offset = block_byte_count,
                                };
                                try function.relocations.append(allocator, relocation);
                                block_byte_count += instruction_descriptors.get(.jmp_rel_8).size;
                                try function.instructions.append(allocator, .jmp_rel_8);
                            },
                        }
                    }
                    function.block_byte_counts.appendAssumeCapacity(block_byte_count);
                    function.byte_count += block_byte_count;
                }
            }

            for (instruction_selector.functions.items) |function| {
                for (function.instructions.items) |instruction| switch (instruction) {
                    .jmp_rel_8 => result.appendOnlyOpcodeSkipInstructionBytes(instruction),

                    // else => unreachable,
                };
            }

            for (instruction_selector.functions.items) |function| {
                var fix_size: bool = false;
                _ = fix_size;
                for (function.relocations.items) |relocation| {
                    std.debug.print("RELOC: {}\n", .{relocation});
                    const source_block = relocation.source;
                    const destination_block = relocation.destination;
                    const source_offset = function.block_offsets.items[source_block];
                    const destination_offset = function.block_offsets.items[destination_block];
                    std.debug.print("Source offset: {}. Destination: {}\n", .{ source_offset, destination_offset });
                    const instruction_descriptor = instruction_descriptors.get(relocation.instruction);
                    const instruction_offset = source_offset + relocation.block_offset;
                    const really_source_offset = instruction_offset + instruction_descriptor.size;
                    const displacement = @as(i64, destination_offset) - @as(i64, really_source_offset);

                    const operands = instruction_descriptor.getOperands();
                    switch (operands.len) {
                        1 => switch (operands[0].size) {
                            @sizeOf(u8) => {
                                if (displacement >= std.math.minInt(i8) and displacement <= std.math.maxInt(i8)) {
                                    const writer_index = instruction_offset + instruction_descriptor.operand_offset;
                                    std.debug.print("Instruction offset: {}. Operand offset: {}. Writer index: {}. displacement: {}\n", .{ instruction_offset, instruction_descriptor.operand_offset, writer_index, displacement });
                                    result.sections.text.content[writer_index] = @bitCast(@as(i8, @intCast(displacement)));
                                } else {
                                    unreachable;
                                }
                            },
                            else => unreachable,
                        },
                        else => unreachable,
                    }
                }
            }

            const text_section = result.sections.text.content[0..result.sections.text.index];
            for (text_section) |byte| {
                std.debug.print("0x{x}\n", .{byte});
            }
        }
    };
}

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

const jmp_rel_32 = 0xe9;
const ret = 0xc3;
const mov_a_imm = [1]u8{0xb8};
const mov_reg_imm8: u8 = 0xb0;

fn intToArrayOfBytes(integer: anytype) [@sizeOf(@TypeOf(integer))]u8 {
    comptime {
        assert(@typeInfo(@TypeOf(integer)) == .Int);
    }

    return @as([@sizeOf(@TypeOf(integer))]u8, @bitCast(integer));
}

fn movAImm(image: *Result, integer: anytype) void {
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
    var image = try Result.create();
    image.appendCodeByte(ret);

    const function_pointer = image.getEntryPoint(fn () callconv(jit_callconv) void);
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
        var image = try Result.create();
        const expected_number = getMaxInteger(Int);

        movAImm(&image, expected_number);
        image.appendCodeByte(ret);

        const function_pointer = image.getEntryPoint(fn () callconv(jit_callconv) Int);
        const result = function_pointer();
        try expect(result == expected_number);
    }
}

const LastByte = packed struct(u8) {
    dst: BasicGPRegister,
    src: BasicGPRegister,
    always_on: u2 = 0b11,
};

fn movRmR(image: *Result, comptime T: type, dst: BasicGPRegister, src: BasicGPRegister) void {
    dstRmSrcR(image, T, .mov, dst, src);
}

fn dstRmSrcR(image: *Result, comptime T: type, opcode: OpcodeRmR, dst: BasicGPRegister, src: BasicGPRegister) void {
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
        var image = try Result.create();
        const number = getMaxInteger(Int);

        movRmR(&image, Int, .a, .di);
        image.appendCodeByte(ret);

        const functionPointer = image.getEntryPoint(fn (Int) callconv(jit_callconv) Int);
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

fn subRmR(image: *Result, comptime T: type, dst: BasicGPRegister, src: BasicGPRegister) void {
    dstRmSrcR(image, T, .sub, dst, src);
}

test "ret sub arguments" {
    inline for (integer_types_to_test) |Int| {
        var image = try Result.create();
        const a = getRandomNumberRange(Int, std.math.minInt(Int) / 2, std.math.maxInt(Int) / 2);
        const b = getRandomNumberRange(Int, std.math.minInt(Int) / 2, a);

        movRmR(&image, Int, .a, .di);
        subRmR(&image, Int, .a, .si);
        image.appendCodeByte(ret);

        const functionPointer = image.getEntryPoint(fn (Int, Int) callconv(jit_callconv) Int);
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
                var image = try Result.create();
                const a = getRandomNumberRange(T, std.math.minInt(T) / 2, std.math.maxInt(T) / 2);
                const b = getRandomNumberRange(T, std.math.minInt(T) / 2, a);
                movRmR(&image, T, .a, .di);
                dstRmSrcR(&image, T, test_case.opcode, .a, .si);
                image.appendCodeByte(ret);

                const functionPointer = image.getEntryPoint(fn (T, T) callconv(jit_callconv) T);
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
    var image = try Result.create();
    const jump_patch_offset = image.sections.text.index + 1;
    image.appendCode(&.{ 0xe8, 0x00, 0x00, 0x00, 0x00 });
    const jump_source = image.sections.text.index;
    image.appendCodeByte(ret);
    const jump_target = image.sections.text.index;
    @as(*align(1) u32, @ptrCast(&image.sections.text.content[jump_patch_offset])).* = @intCast(jump_target - jump_source);
    image.appendCodeByte(ret);

    const functionPointer = image.getEntryPoint(fn () callconv(jit_callconv) void);
    functionPointer();
}

test "call before" {
    var image = try Result.create();
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

    const functionPointer = image.getEntryPoint(fn () callconv(jit_callconv) void);
    functionPointer();
}

pub fn runTest(allocator: Allocator, ir_result: *const ir.Result) !Result {
    _ = allocator;

    var image = try Result.create();

    var entry_point: u32 = 0;
    _ = entry_point;

    for (ir_result.functions.items) |*function| {
        for (function.instructions.items) |instruction| {
            switch (instruction.id) {
                .ret_void => {
                    image.appendCodeByte(ret);
                },
            }
        }
    }

    return image;
}
