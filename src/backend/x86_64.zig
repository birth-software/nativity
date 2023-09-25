const std = @import("std");
const assert = std.debug.assert;
const print = std.debug.print;
const emit = @import("emit.zig");
const ir = @import("./intermediate_representation.zig");

const InstructionSelector = emit.InstructionSelector(Instruction);

const Size = enum(u2) {
    one = 0,
    two = 1,
    four = 2,
    eight = 3,
};

pub fn selectInstruction(instruction_selector: *InstructionSelector, function: *InstructionSelector.Function, intermediate: *ir.Result, instruction: ir.Instruction) !void {
    switch (instruction) {
        .@"unreachable" => try function.instructions.append(instruction_selector.allocator, .{ .ud2 = {} }),
        .load => |load_index| {
            const load = intermediate.loads.get(load_index).*;
            const load_value = intermediate.values.get(load.value).*;
            switch (load_value) {
                .integer => |integer| {
                    _ = integer;
                    unreachable;
                },
                else => |t| @panic(@tagName(t)),
            }
            unreachable;
        },
        .syscall => |syscall_index| {
            const syscall = intermediate.syscalls.get(syscall_index);
            for (syscall.arguments.items, syscall_registers[0..syscall.arguments.items.len]) |argument_index, syscall_register| {
                const argument = intermediate.values.get(argument_index).*;
                switch (argument) {
                    .integer => |integer| {
                        if (integer.value == 0) {
                            try function.instructions.append(instruction_selector.allocator, .{
                                .xor_rm_r = .{
                                    .destination = @enumFromInt(@intFromEnum(syscall_register)),
                                    .source = @enumFromInt(@intFromEnum(syscall_register)),
                                    .size = .four,
                                    .direct = true,
                                },
                            });
                        } else if (integer.value <= std.math.maxInt(u32)) {
                            try function.instructions.append(instruction_selector.allocator, .{
                                .mov_r_imm = .{
                                    .register_size = .four,
                                    .register = @enumFromInt(@intFromEnum(syscall_register)),
                                    .immediate = argument_index,
                                    .immediate_size = .four,
                                },
                            });
                            // TODO
                        } else unreachable;
                        // if (integer.value == 0) {
                        //     try function.instructions.append(instruction_selector.allocator, .{
                        //         .xor_reg32_reg32 = .{
                        //             .destination = syscall_register,
                        //             .source = syscall_register,
                        //         },
                        //     });
                        // } else if (integer.value < std.math.maxInt(u32)) {
                        //     try function.instructions.append(instruction_selector.allocator, .{
                        //         .mov_reg_imm32 = .{
                        //             .destination = syscall_register,
                        //             .source = @intCast(integer.value),
                        //         },
                        //     });
                        // } else {
                        //     unreachable;
                        // }
                    },
                    else => |t| @panic(@tagName(t)),
                }
            }

            try function.instructions.append(instruction_selector.allocator, .{
                .syscall = {},
            });
        },
        .phi => unreachable,
        .ret => unreachable,
        .jump => |jump_index| {
            _ = jump_index;
            // const jump = intermediate.jumps.get(jump_index);
            // const relocation = LocalRelative{
            //     .instruction = .jmp_rel_8,
            //     .source = @intCast(function.block_map.get(jump.source) orelse unreachable),
            //     .destination = @intCast(function.block_map.get(jump.destination) orelse unreachable),
            //     .offset_in_block = function.block_byte_count,
            // };
            // const index = function.instructions.items.len;
            // try function.relocations.append(instruction_selector.allocator, @intCast(index));
            // try function.instructions.append(instruction_selector.allocator, .{
            //     .jmp_rel_8 = relocation,
            // });
            unreachable;
        },
    }
}

const RegisterImmediate = struct {
    immediate: ir.Value.Index,
    register: GPRegister,
    register_size: Size,
    immediate_size: Size,
};

const RegisterMemoryRegister = struct {
    destination: GPRegister,
    source: GPRegister,
    size: Size,
    direct: bool,
};

const RmResult = struct {
    rex: Rex,
    mod_rm: ModRm,
};

const RmAndRexArguments = packed struct {
    rm: GPRegister,
    reg: GPRegister,
    direct: bool,
    bit64: bool,
    sib: bool,
};

// fn computeRmAndRex(args: RmAndRexArguments) RmResult {
//     _ = register_memory_register;
//     const rex_byte = Rex{
// .b = @intFromEnum(args.rm) > std.math.maxInt(u3),
// .x = args.sib,
// .r = @intFromEnum(args.reg) > std.math.maxInt(u3),
// .w = args.bit64,
//     };
//     var rex_byte = std.mem.zeroes(Rex);
//     if (@intFromEnum(rm) > std.math.maxInt(u3))
// }
fn emitImmediate(result: *emit.Result, intermediate: *ir.Result, value_index: ir.Value.Index, size: Size) void {
    const value = intermediate.values.get(value_index);
    const integer = value.integer.value;
    const integer_bytes = switch (size) {
        .one => std.mem.asBytes(&@as(u8, @intCast(integer))),
        .two => std.mem.asBytes(&@as(u16, @intCast(integer))),
        .four => std.mem.asBytes(&@as(u32, @intCast(integer))),
        .eight => std.mem.asBytes(&@as(u64, @intCast(integer))),
    };
    result.appendCode(integer_bytes);
}

const ModRm = packed struct(u8) {
    rm: u3,
    reg: u3,
    mod: u2,
};

pub fn emitInstruction(result: *emit.Result, instruction: Instruction, intermediate: *ir.Result) void {
    switch (instruction) {
        inline .xor_rm_r => |register_memory_register, tag| {
            const rm = register_memory_register.destination;
            const reg = register_memory_register.source;
            const rex_byte = Rex{
                .b = @intFromEnum(rm) > std.math.maxInt(u3),
                .x = false, //args.sib,
                .r = @intFromEnum(reg) > std.math.maxInt(u3),
                .w = register_memory_register.size == .eight,
            };

            if (@as(u4, @truncate(@as(u8, @bitCast(rex_byte)))) != 0) {
                result.appendCodeByte(@bitCast(rex_byte));
            }

            const modrm = ModRm{
                .rm = @truncate(@intFromEnum(rm)),
                .reg = @truncate(@intFromEnum(reg)),
                .mod = @as(u2, @intFromBool(register_memory_register.direct)) << 1 | @intFromBool(register_memory_register.direct),
            };
            // _ = modrm;
            const opcode = tag.getOpcode(&.{
                .{
                    .register_memory = .{
                        .value = register_memory_register.destination,
                        .size = register_memory_register.size,
                        .direct = register_memory_register.direct,
                    },
                },
                .{
                    .register = .{
                        .value = register_memory_register.source,
                        .size = register_memory_register.size,
                    },
                },
            });

            result.appendCode(opcode);
            result.appendCodeByte(@bitCast(modrm));
        },
        inline .mov_r_imm => |register_immediate, tag| {
            const opcode = tag.getOpcode(&.{
                .{
                    .register = .{
                        .value = register_immediate.register,
                        .size = register_immediate.register_size,
                    },
                },
                .{
                    .immediate = register_immediate.immediate_size,
                },
            });
            assert(opcode.len == 1);
            const opcode_byte = opcode[0] | @intFromEnum(register_immediate.register);
            result.appendCodeByte(opcode_byte);
            emitImmediate(result, intermediate, register_immediate.immediate, register_immediate.immediate_size);
        },
        // .jmp_rel_8 => unreachable, //result.appendOnlyOpcodeSkipInstructionBytes(instruction),
        // inline .mov_reg_imm32 => |content, tag| {
        //     _ = tag;
        //     _ = content;
        //     // const descriptor = instruction_descriptors.get(tag);
        //     // result.writeOpcode(descriptor.opcode);
        //     // result.appendCodeByte(descriptor.getOpcode()[0] | @intFromEnum(content.destination));
        //     // result.appendCode(std.mem.asBytes(&content.source));
        //     unreachable;
        // },
        // inline .xor_reg32_reg32 => |content, tag| {
        //     _ = tag;
        //     _ = content;
        //     // const descriptor = instruction_descriptors.get(tag);
        //     // result.appendCodeByte(descriptor.getOpcode()[0]);
        //     // result.appendCodeByte(0xc0 | @as(u8, @intFromEnum(content.source)) << 4 | @intFromEnum(content.destination));
        //     unreachable;
        // },
        inline .syscall, .ud2 => |_, tag| {
            const opcode = tag.getOpcode(&.{});
            result.appendCode(opcode);
        },
        // else => unreachable,
    }
}

pub const Instruction = union(Id) {
    xor_rm_r: RegisterMemoryRegister,
    mov_r_imm: RegisterImmediate,
    // jmp_rel_8: LocalRelative,
    // mov_reg_imm32: struct {
    //     destination: GPRegister,
    //     source: u32,
    // },
    // xor_reg32_reg32: struct {
    //     destination: GPRegister,
    //     source: GPRegister,
    // },
    syscall,
    ud2,

    const Id = enum {
        xor_rm_r,
        mov_r_imm,
        // jmp_rel_8,
        // mov_reg_imm32,
        // xor_reg32_reg32,
        syscall,
        ud2,

        fn getOpcode(comptime instruction: Instruction.Id, operands: []const Operand) []const u8 {
            return switch (instruction) {
                .mov_r_imm => switch (operands[0].register.size) {
                    .one => &.{0xb0},
                    .two, .four, .eight => &.{0xb8},
                },
                .syscall => &.{ 0x0f, 0x05 },
                .ud2 => &.{ 0x0f, 0x0b },
                .xor_rm_r => switch (operands[0].register_memory.size) {
                    .one => &.{0x30},
                    .two, .four, .eight => &.{0x31},
                },
            };
        }
    };

    const Operand = union(enum) {
        displacement,
        register: struct {
            value: GPRegister,
            size: Size,
        },
        // TODO
        register_memory: struct {
            value: GPRegister,
            size: Size,
            direct: bool,
        },
        immediate: Size,

        const Id = enum {
            displacement,
            register,
            register_memory,
            immediate,
        };
    };

    pub const descriptors = blk: {
        var result = std.EnumArray(Instruction.Id, Instruction.Descriptor).initUndefined();
        result.getPtr(.jmp_rel_8).* = Instruction.Descriptor.new(&.{0xeb}, &[_]Instruction.Operand{rel8});
        result.getPtr(.mov_reg_imm32).* = Instruction.Descriptor.new(&.{0xb8}, &[_]Instruction.Operand{ reg32, imm32 });
        result.getPtr(.xor_reg_reg).* = Instruction.Descriptor.new(&.{0x31}, &[_]Instruction.Operand{ reg32, reg32 });
        result.getPtr(.syscall).* = Instruction.Descriptor.new(&.{ 0x0f, 0x05 }, &.{});
        result.getPtr(.ud2).* = Instruction.Descriptor.new(&.{ 0x0f, 0x0b }, &.{});
        break :blk result;
    };

    const Descriptor = struct {
        operands: [4]Operand,
        operand_count: u3,
        operand_offset: u5,
        size: u8,
        opcode: [3]u8,
        opcode_byte_count: u8,

        fn getOperands(descriptor: Descriptor) []const Operand {
            return descriptor.operands[0..descriptor.operand_count];
        }

        fn new(opcode_bytes: []const u8, operands: []const Operand) Descriptor {
            // TODO: prefixes
            var result = Descriptor{
                .operands = undefined,
                .operand_count = @intCast(operands.len),
                .operand_offset = opcode_bytes.len,
                .size = opcode_bytes.len,
                .opcode = .{ 0, 0 },
                .opcode_byte_count = opcode_bytes.len,
            };

            if (opcode_bytes.len == 1) {
                result.opcode[1] = opcode_bytes[0];
            } else for (opcode_bytes, result.opcode[0..opcode_bytes.len]) |opcode_byte, *out_opcode| {
                out_opcode.* = opcode_byte;
            }

            for (operands, result.operands[0..operands.len]) |operand, *out_operand| {
                out_operand.* = operand;
                result.size += operand.size;
            }

            return result;
        }
    };
};
const LocalRelative = struct {
    instruction: Instruction.Id,
    source: u16,
    destination: u16,
    offset_in_block: u16,
};

const rel8 = Instruction.Operand{
    .type = .relative,
    .size = @sizeOf(u8),
};

const reg32 = Instruction.Operand{
    .type = .register,
    .size = @sizeOf(u32),
};

const imm32 = Instruction.Operand{
    .type = .immediate,
    .size = @sizeOf(u32),
};

const Rex = packed struct(u8) {
    b: bool,
    x: bool,
    r: bool,
    w: bool,
    fixed: u4 = 0b0100,
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

// pub const BasicGPRegister = enum(u3) {
//     a = 0,
//     c = 1,
//     d = 2,
//     b = 3,
//     sp = 4,
//     bp = 5,
//     si = 6,
//     di = 7,
// };

const syscall_registers = [7]GPRegister{ .a, .di, .si, .d, .r10, .r8, .r9 };
