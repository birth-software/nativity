const std = @import("std");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;
const print = std.debug.print;
const emit = @import("emit.zig");
const ir = @import("./intermediate_representation.zig");

const Compilation = @import("../Compilation.zig");

const data_structures = @import("../data_structures.zig");
const ArrayList = data_structures.ArrayList;
const AutoArrayHashMap = data_structures.AutoArrayHashMap;

const InstructionSelector = emit.InstructionSelector(Instruction);
const x86_64 = @This();

const Size = enum(u2) {
    one = 0,
    two = 1,
    four = 2,
    eight = 3,
};

pub const MIR = struct {
    functions: ArrayList(Function) = .{},
    const GPRegister = struct {
        value: ?x86_64.GPRegister = null,
        can_omit_if_present: bool = true,
    };
    const Stack = struct {
        offset: u64,
    };
    const Function = struct {
        instructions: ArrayList(MIR.Instruction) = .{},
        blocks: AutoArrayHashMap(ir.BasicBlock.Index, u32) = .{},
    };
    const Instruction = struct {
        operands: [4]Operand,
        ir: ir.Instruction.Index,
        id: Id,
        operand_count: u8 = 0,

        pub fn getOperands(instruction: *MIR.Instruction) []Operand {
            return instruction.operands[0..instruction.operand_count];
        }

        const Id = enum(u16) {
            call,
            jmp,
            mov,
            push,
            ret,
            sub,
            syscall,
            ud2,
        };

        fn new(id: Id, reference: ir.Instruction.Index, operands: []const Operand) MIR.Instruction {
            var out_operands: [4]Operand = undefined;
            @memset(std.mem.asBytes(&out_operands), 0);
            @memcpy(out_operands[0..operands.len], operands);

            return .{
                .operands = out_operands,
                .ir = reference,
                .id = id,
                .operand_count = @intCast(operands.len),
            };
        }

        const Operand = union(enum) {
            gp_register: MIR.GPRegister,
            fp_register,
            memory,
            relative: union(enum) {
                block: ir.BasicBlock.Index,
                function: ir.Function.Index,
            },
            immediate: Compilation.Integer,
            stack: Stack,
        };
    };

    const RegisterUse = union(enum) {
        general,
        ret,
        param: x86_64.GPRegister,
        syscall_param: x86_64.GPRegister,
    };

    fn movRegImm(function: *Function, allocator: Allocator, integer: Compilation.Integer, instruction_index: ir.Instruction.Index, use: RegisterUse) !void {
        if (integer.type.bit_count <= @bitSizeOf(u64)) {
            switch (integer.type.signedness) {
                .signed, .unsigned => {
                    if (integer.value <= std.math.maxInt(u32)) {
                        try function.instructions.append(allocator, MIR.Instruction.new(.mov, instruction_index, &.{
                            .{
                                .gp_register = .{
                                    .value = switch (use) {
                                        .general => null,
                                        .ret => .a,
                                        .param => unreachable,
                                        .syscall_param => |register| register,
                                    },
                                },
                            },
                            .{ .immediate = integer },
                        }));
                    } else {
                        unreachable;
                    }
                },
            }
        } else {
            unreachable;
        }
    }

    fn movRegStack(function: *Function, allocator: Allocator, use: RegisterUse, stack_reference: ir.StackReference, instruction_index: ir.Instruction.Index) !void {
        if (stack_reference.size <= @sizeOf(u64)) {
            switch (stack_reference.size) {
                @sizeOf(u8) => unreachable,
                @sizeOf(u16) => unreachable,
                @sizeOf(u32) => {
                    try function.instructions.append(allocator, MIR.Instruction.new(.mov, instruction_index, &.{
                        .{
                            .gp_register = .{
                                .value = switch (use) {
                                    .general => null,
                                    .ret => unreachable,
                                    .param => unreachable,
                                    .syscall_param => |syscall_register| syscall_register,
                                },
                            },
                        },
                        .{
                            .stack = .{
                                .offset = stack_reference.offset,
                            },
                        },
                    }));
                },
                @sizeOf(u64) => unreachable,
                else => unreachable,
            }
        } else {
            unreachable;
        }
    }

    pub fn generate(allocator: Allocator, intermediate: *ir.Result) !MIR {
        var mir = MIR{};
        try mir.functions.ensureTotalCapacity(allocator, intermediate.functions.len);
        var ir_function_it = intermediate.functions.iterator();

        while (ir_function_it.nextPointer()) |ir_function| {
            const function = mir.functions.addOneAssumeCapacity();
            function.* = .{};
            try function.blocks.ensureTotalCapacity(allocator, ir_function.blocks.items.len);
            for (ir_function.blocks.items) |block_index| {
                function.blocks.putAssumeCapacity(block_index, @intCast(function.instructions.items.len));
                const basic_block = intermediate.blocks.get(block_index);

                if (ir_function.current_stack_offset > 0) {
                    // TODO: switch on ABI
                    try function.instructions.append(allocator, MIR.Instruction.new(.push, ir.Instruction.Index.invalid, &.{
                        .{ .gp_register = .{ .value = .bp } },
                    }));

                    try function.instructions.append(allocator, MIR.Instruction.new(.mov, ir.Instruction.Index.invalid, &.{
                        .{ .gp_register = .{ .value = .bp } },
                        .{ .gp_register = .{ .value = .sp } },
                    }));

                    try function.instructions.append(allocator, MIR.Instruction.new(.sub, ir.Instruction.Index.invalid, &.{
                        .{ .gp_register = .{ .value = .sp } },
                        .{
                            .immediate = Compilation.Integer{
                                .value = ir_function.current_stack_offset,
                                .type = .{
                                    .bit_count = 8,
                                    .signedness = .unsigned,
                                },
                            },
                        },
                    }));
                }

                for (basic_block.instructions.items) |instruction_index| {
                    const instruction = intermediate.instructions.get(instruction_index);
                    switch (instruction.*) {
                        .jump => |jump_index| {
                            const jump = intermediate.jumps.get(jump_index);
                            try function.instructions.append(allocator, MIR.Instruction.new(.jmp, instruction_index, &.{
                                .{ .relative = .{ .block = jump.destination } },
                            }));
                        },
                        .copy => |copy_value_index| {
                            const copy_value = intermediate.values.get(copy_value_index);
                            switch (copy_value.*) {
                                .integer => |integer| try movRegImm(function, allocator, integer, instruction_index, .general),
                                else => |t| @panic(@tagName(t)),
                            }
                        },
                        .ret => |ret_value_index| {
                            const ret_value = intermediate.values.get(ret_value_index);
                            switch (ret_value.*) {
                                .integer => |integer| try movRegImm(function, allocator, integer, instruction_index, .ret),
                                else => |t| @panic(@tagName(t)),
                            }

                            if (ir_function.current_stack_offset > 0) {
                                unreachable;
                            }

                            try function.instructions.append(allocator, MIR.Instruction.new(.ret, instruction_index, &.{}));
                        },
                        .call => |call_value_index| {
                            // TODO: args
                            const call = intermediate.calls.get(call_value_index);
                            try function.instructions.append(allocator, MIR.Instruction.new(.call, instruction_index, &.{
                                .{ .relative = .{ .function = call.function } },
                            }));
                        },
                        .store => |store_index| {
                            const store = intermediate.stores.get(store_index);
                            const source_value = intermediate.values.get(store.source);
                            const destination_value = intermediate.values.get(store.destination);
                            switch (destination_value.*) {
                                .stack_reference => |stack_reference_index| {
                                    const stack_reference = intermediate.stack_references.get(stack_reference_index);
                                    print("stack ref: {}\n", .{stack_reference});
                                    switch (source_value.*) {
                                        .call => |call_index| {
                                            try storeFunctionCallResult(allocator, function, intermediate, instruction_index, stack_reference.*, call_index);
                                        },
                                        else => |t| @panic(@tagName(t)),
                                    }
                                },
                                else => |t| @panic(@tagName(t)),
                            }
                        },
                        .syscall => |syscall_value_index| {
                            const syscall_value = intermediate.values.get(syscall_value_index);
                            const syscall = intermediate.syscalls.get(syscall_value.syscall);
                            for (syscall.arguments.items, syscall_registers[0..syscall.arguments.items.len]) |argument_index, syscall_register| {
                                const argument = intermediate.values.get(argument_index).*;
                                switch (argument) {
                                    .integer => |integer| try movRegImm(function, allocator, integer, instruction_index, .{ .syscall_param = syscall_register }),
                                    .stack_reference => |stack_reference_index| {
                                        const stack_reference = intermediate.stack_references.get(stack_reference_index);
                                        try movRegStack(function, allocator, .{ .syscall_param = syscall_register }, stack_reference.*, instruction_index);
                                    },
                                    else => |t| @panic(@tagName(t)),
                                }
                            }

                            try function.instructions.append(allocator, MIR.Instruction.new(.syscall, instruction_index, &.{}));
                        },
                        .@"unreachable" => try function.instructions.append(allocator, MIR.Instruction.new(.ud2, instruction_index, &.{})),
                        else => |t| @panic(@tagName(t)),
                    }
                }
            }
        }

        return mir;
    }

    const RegisterAllocator = struct {
        gp_registers: RegisterSet(x86_64.GPRegister) = .{},

        fn init(allocator: Allocator) !RegisterAllocator {
            var register_allocator = RegisterAllocator{};
            try register_allocator.gp_registers.free.ensureTotalCapacity(allocator, @typeInfo(x86_64.GPRegister).Enum.fields.len);
            inline for (@typeInfo(x86_64.GPRegister).Enum.fields) |enum_field| {
                register_allocator.gp_registers.free.putAssumeCapacity(@field(x86_64.GPRegister, enum_field.name), {});
            }

            return register_allocator;
        }
    };

    fn RegisterSet(comptime RegisterEnum: type) type {
        return struct {
            used: AutoArrayHashMap(RegisterEnum, ir.Value.Index) = .{},
            free: AutoArrayHashMap(RegisterEnum, void) = .{},

            fn allocate(register_set: *@This(), allocator: Allocator, register: RegisterEnum, intermediate: *ir.Result, instruction: MIR.Instruction, value_index: ir.Value.Index) !void {
                switch (intermediate.instructions.get(instruction.ir).*) {
                    .store => {},
                    else => {
                        switch (register_set.free.orderedRemove(register)) {
                            true => try register_set.used.put(allocator, register, value_index),
                            false => unreachable,
                        }
                    },
                }
            }
        };
    }

    fn getValueFromInstruction(intermediate: *ir.Result, instruction_index: ir.Instruction.Index) ir.Value.Index {
        const instruction = intermediate.instructions.get(instruction_index);
        const value_index: ir.Value.Index = switch (instruction.*) {
            .copy, .ret, .syscall => |value_index| value_index,
            .store => |store_index| blk: {
                const store = intermediate.stores.get(store_index);
                break :blk store.source;
            },
            else => |t| @panic(@tagName(t)),
        };

        return value_index;
    }

    pub fn allocateRegisters(mir: *MIR, allocator: Allocator, intermediate: *ir.Result) !void {
        for (mir.functions.items) |*function| {
            var register_allocator = try RegisterAllocator.init(allocator);
            for (function.instructions.items) |*instruction| {
                for (instruction.getOperands()) |*operand| {
                    switch (operand.*) {
                        .relative, .immediate, .stack => {},
                        .gp_register => |gp_register| switch (instruction.ir.valid) {
                            true => operand.gp_register.value = blk: {
                                const value_index = getValueFromInstruction(intermediate, instruction.ir);

                                if (gp_register.value) |expected_register| {
                                    if (register_allocator.gp_registers.used.get(expected_register)) |allocated_value| {
                                        const allocated = intermediate.values.get(allocated_value);
                                        const value = intermediate.values.get(value_index);
                                        print("\nAllocated: {}.\nValue: {}\n", .{ allocated.*, value.* });
                                        switch (value_index.eq(allocated_value)) {
                                            true => {},
                                            false => unreachable,
                                        }
                                    } else {
                                        if (register_allocator.gp_registers.free.get(expected_register)) |_| {
                                            try register_allocator.gp_registers.allocate(allocator, expected_register, intermediate, instruction.*, value_index);
                                        } else {
                                            unreachable;
                                        }
                                    }

                                    break :blk expected_register;
                                } else {
                                    for (register_allocator.gp_registers.free.keys()) |register| {
                                        try register_allocator.gp_registers.allocate(allocator, register, intermediate, instruction.*, value_index);
                                        break :blk register;
                                    } else {
                                        unreachable;
                                    }
                                }
                            },
                            false => {},
                        },
                        else => |t| @panic(@tagName(t)),
                    }
                }
            }
        }
    }

    fn storeFunctionCallResult(allocator: Allocator, function: *MIR.Function, intermediate: *ir.Result, instruction: ir.Instruction.Index, stack_reference: ir.StackReference, call_index: ir.Call.Index) !void {
        _ = call_index;
        _ = intermediate;
        if (stack_reference.size <= @sizeOf(u64)) {
            switch (stack_reference.size) {
                @sizeOf(u8) => unreachable,
                @sizeOf(u16) => unreachable,
                @sizeOf(u32) => try function.instructions.append(allocator, MIR.Instruction.new(.mov, instruction, &.{
                    .{ .stack = .{ .offset = stack_reference.offset } }, .{ .gp_register = .{ .value = .a } },
                })),
                @sizeOf(u64) => unreachable,
                else => unreachable,
            }
        } else {
            unreachable;
        }
    }
};

pub fn selectInstruction(instruction_selector: *InstructionSelector, function: *InstructionSelector.Function, intermediate: *ir.Result, instruction: ir.Instruction) !void {
    switch (instruction) {
        .copy => |copy_value| {
            _ = copy_value;
            unreachable;
        },
        .@"unreachable" => _ = try function.addInstruction(instruction_selector.allocator, .{ .ud2 = {} }),
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
                            _ = try function.addInstruction(instruction_selector.allocator, .{
                                .xor_rm_r = .{
                                    .destination = @enumFromInt(@intFromEnum(syscall_register)),
                                    .source = @enumFromInt(@intFromEnum(syscall_register)),
                                    .size = .four,
                                    .direct = true,
                                },
                            });
                        } else if (integer.value <= std.math.maxInt(u32)) {
                            _ = try function.addInstruction(instruction_selector.allocator, .{
                                .mov_r_imm = .{
                                    .register_size = .four,
                                    .register = @enumFromInt(@intFromEnum(syscall_register)),
                                    .immediate = argument_index,
                                    .immediate_size = .four,
                                },
                            });
                            // TODO
                        } else unreachable;
                    },
                    else => |t| @panic(@tagName(t)),
                }
            }

            _ = try function.addInstruction(instruction_selector.allocator, .{
                .syscall = {},
            });
        },
        .phi => unreachable,
        .ret => unreachable,
        .jump => |jump_index| {
            const jump = intermediate.jumps.get(jump_index);
            const instruction_index = try function.addInstruction(instruction_selector.allocator, .{
                .jmp_rel = Displacement{
                    .size = .one,
                    .source = @intCast(function.block_map.get(jump.source) orelse unreachable),
                    .destination = @intCast(function.block_map.get(jump.destination) orelse unreachable),
                    .instruction_index = @intCast(function.instructions.items.len),
                },
            });
            try function.relocations.append(instruction_selector.allocator, instruction_index);
        },
        .call => unreachable,
        .store => unreachable,
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

const Displacement = struct {
    instruction_index: u16,
    size: Size,
    source: u16,
    destination: u16,
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
        .jmp_rel => unreachable,
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
    jmp_rel: Displacement,
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
        jmp_rel,
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
                .jmp_rel => switch (operands[0].displacement.size) {
                    .one => unreachable,
                    .four => unreachable,
                    else => unreachable,
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
