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

const x86_64 = @This();

const Size = enum(u2) {
    one = 0,
    two = 1,
    four = 2,
    eight = 3,

    fn fromByteCount(byte_count: u8) Size {
        return @enumFromInt(@as(u2, @intCast(std.math.log2(byte_count))));
    }

    fn fromBitCount(bit_count: u16) Size {
        assert(bit_count % @bitSizeOf(u8) == 0);
        const byte_count: u8 = @intCast(bit_count >> 3);
        return fromByteCount(byte_count);
    }

    fn toInteger(comptime size: Size) type {
        return switch (size) {
            .one => u8,
            .two => u16,
            .four => u32,
            .eight => u64,
        };
    }
};

fn Relocation(comptime Target: type) type {
    return struct {
        target: Target,
        instruction_byte_offset: u32,
        instruction_length: u8,
        source_address_writer_offset: u8,
        size: Size,
    };
}

const LocalRelocation = Relocation(ir.BasicBlock.Index);
const GlobalRelocation = Relocation(u32);

fn RelocationIndex(comptime relocation_type: RelocationType) type {
    return switch (relocation_type) {
        .local => ir.BasicBlock.Index,
        .global => u32,
    };
}
const RelocationType = enum {
    local,
    global,
};

pub const MIR = struct {
    functions: ArrayList(Function) = .{},
    allocator: Allocator,
    const GPRegister = struct {
        value: ?x86_64.GPRegister = null,
        size: Size,
        can_omit_if_present: bool = true,
    };
    const Stack = struct {
        offset: u64,
    };
    const Function = struct {
        instructions: ArrayList(MIR.Instruction) = .{},
        blocks: AutoArrayHashMap(ir.BasicBlock.Index, u32) = .{},
        instruction_byte_offset: u32 = 0,
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
            xor,
        };
    };
    const Operand = union(enum) {
        gp_register: MIR.GPRegister,
        fp_register,
        memory,
        displacement: struct {
            source: ir.BasicBlock.Index,
            destination: union(enum) {
                block: ir.BasicBlock.Index,
                function: ir.Function.Index,
            },
        },
        immediate: Compilation.Integer,
        stack: Stack,
    };

    const RegisterUse = union(enum) {
        general,
        ret,
        param: x86_64.GPRegister,
        syscall_param: x86_64.GPRegister,
    };

    fn addInstruction(mir: *MIR, function: *Function, instruction_id: Instruction.Id, ir_instruction: ir.Instruction.Index, operands: []const Operand) !void {
        var out_operands: [4]Operand = undefined;
        @memset(std.mem.asBytes(&out_operands), 0);
        @memcpy(out_operands[0..operands.len], operands);

        const instruction = MIR.Instruction{
            .operands = out_operands,
            .ir = ir_instruction,
            .id = instruction_id,
            .operand_count = @intCast(operands.len),
        };
        print("Adding instruction {s}\n", .{@tagName(instruction_id)});
        try function.instructions.append(mir.allocator, instruction);
    }

    fn emitMovRegImm(mir: *MIR, function: *Function, integer: Compilation.Integer, instruction_index: ir.Instruction.Index, use: RegisterUse, register_size: Size) !void {
        if (integer.type.bit_count <= @bitSizeOf(u64)) {
            if (integer.value == 0) {
                const operand = .{
                    .gp_register = .{
                        .value = switch (use) {
                            .general => null,
                            .ret => .a,
                            .param => unreachable,
                            .syscall_param => |register| register,
                        },
                        .size = register_size,
                    },
                };

                try mir.addInstruction(function, .xor, instruction_index, &.{
                    operand,
                    operand,
                });
            } else if (integer.value <= std.math.maxInt(u32)) {
                try mir.addInstruction(function, .mov, instruction_index, &.{
                    .{
                        .gp_register = .{
                            .value = switch (use) {
                                .general => null,
                                .ret => .a,
                                .param => unreachable,
                                .syscall_param => |register| register,
                            },
                            .size = .four,
                        },
                    },
                    .{
                        .immediate = .{
                            .value = integer.value,
                            .type = .{
                                .signedness = integer.type.signedness,
                                .bit_count = 32,
                            },
                        },
                    },
                });
            } else {
                unreachable;
            }
        } else {
            unreachable;
        }
    }

    fn emitMovRegStack(mir: *MIR, function: *Function, use: RegisterUse, stack_reference: ir.StackReference, instruction_index: ir.Instruction.Index) !void {
        if (stack_reference.size <= @sizeOf(u64)) {
            switch (stack_reference.size) {
                @sizeOf(u8) => unreachable,
                @sizeOf(u16) => unreachable,
                @sizeOf(u32) => {
                    try mir.addInstruction(function, .mov, instruction_index, &.{
                        .{
                            .gp_register = .{
                                .value = switch (use) {
                                    .general => null,
                                    .ret => unreachable,
                                    .param => unreachable,
                                    .syscall_param => |syscall_register| syscall_register,
                                },
                                .size = Size.fromByteCount(@intCast(stack_reference.size)),
                            },
                        },
                        .{
                            .stack = .{
                                .offset = stack_reference.offset,
                            },
                        },
                    });
                },
                @sizeOf(u64) => unreachable,
                else => unreachable,
            }
        } else {
            unreachable;
        }
    }

    pub fn generate(allocator: Allocator, intermediate: *ir.Result) !MIR {
        var mir = MIR{
            .allocator = allocator,
        };
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
                    try mir.addInstruction(function, .push, ir.Instruction.Index.invalid, &.{.{ .gp_register = .{ .value = .bp, .size = .eight } }});

                    try mir.addInstruction(function, .mov, ir.Instruction.Index.invalid, &.{
                        .{ .gp_register = .{ .value = .bp, .size = .eight } },
                        .{ .gp_register = .{ .value = .sp, .size = .eight } },
                    });

                    try mir.addInstruction(function, .sub, ir.Instruction.Index.invalid, &.{
                        .{ .gp_register = .{ .value = .sp, .size = .eight } },
                        .{
                            .immediate = Compilation.Integer{
                                .value = ir_function.current_stack_offset,
                                .type = .{
                                    .bit_count = 8,
                                    .signedness = .unsigned,
                                },
                            },
                        },
                    });
                }

                for (basic_block.instructions.items) |instruction_index| {
                    const instruction = intermediate.instructions.get(instruction_index);
                    switch (instruction.*) {
                        .jump => |jump_index| {
                            const jump = intermediate.jumps.get(jump_index);
                            try mir.addInstruction(function, .jmp, instruction_index, &.{
                                .{ .displacement = .{
                                    .source = jump.source,
                                    .destination = .{ .block = jump.destination },
                                } },
                            });
                        },
                        .copy => |copy_value_index| {
                            const copy_value = intermediate.values.get(copy_value_index);
                            switch (copy_value.*) {
                                .integer => |integer| try mir.emitMovRegImm(function, integer, instruction_index, .general, Size.fromBitCount(integer.type.bit_count)),
                                else => |t| @panic(@tagName(t)),
                            }
                        },
                        .ret => |ret_value_index| {
                            const ret_value = intermediate.values.get(ret_value_index);
                            switch (ret_value.*) {
                                .integer => |integer| try mir.emitMovRegImm(function, integer, instruction_index, .ret, Size.fromBitCount(integer.type.bit_count)),
                                else => |t| @panic(@tagName(t)),
                            }

                            if (ir_function.current_stack_offset > 0) {
                                unreachable;
                            }

                            try mir.addInstruction(function, .ret, instruction_index, &.{});
                        },
                        .call => |call_value_index| {
                            // TODO: args
                            const call = intermediate.calls.get(call_value_index);
                            try mir.addInstruction(function, .call, instruction_index, &.{
                                .{
                                    .displacement = .{
                                        .source = block_index,
                                        .destination = .{
                                            .function = call.function,
                                        },
                                    },
                                },
                            });
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
                                        .call => |call_index| try mir.emitStoreForFunctionCallResult(function, intermediate, instruction_index, stack_reference.*, call_index),
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
                                    .integer => |integer| try mir.emitMovRegImm(function, integer, instruction_index, .{ .syscall_param = syscall_register }, Size.eight),
                                    .stack_reference => |stack_reference_index| {
                                        const stack_reference = intermediate.stack_references.get(stack_reference_index);
                                        try mir.emitMovRegStack(function, .{ .syscall_param = syscall_register }, stack_reference.*, instruction_index);
                                    },
                                    else => |t| @panic(@tagName(t)),
                                }
                            }

                            try mir.addInstruction(function, .syscall, instruction_index, &.{});
                        },
                        .@"unreachable" => try mir.addInstruction(function, .ud2, instruction_index, &.{}),
                        else => |t| @panic(@tagName(t)),
                    }
                }
            }
        }

        return mir;
    }

    pub fn allocateRegisters(mir: *MIR, allocator: Allocator, intermediate: *ir.Result) !void {
        for (mir.functions.items) |*function| {
            var register_allocator = try RegisterAllocator.init(allocator);
            var instructions_to_delete = AutoArrayHashMap(u32, void){};
            for (function.instructions.items, 0..) |*instruction, instruction_index| {
                print("#{} {s}\n", .{ instruction_index, @tagName(instruction.id) });
                var allocated_gp_register: ?x86_64.GPRegister = null;
                for (instruction.getOperands()) |*operand| {
                    switch (operand.*) {
                        .displacement, .immediate, .stack => {},
                        .gp_register => |gp_register| switch (instruction.ir.valid) {
                            true => operand.gp_register.value = blk: {
                                const value_index = getValueFromInstruction(intermediate, instruction.ir);

                                if (gp_register.value) |expected_register| {
                                    if (register_allocator.gp_registers.used.get(expected_register)) |allocated_value| {
                                        switch (value_index.eq(allocated_value)) {
                                            // TODO delete the instruction
                                            true => if (allocated_gp_register == null) unreachable else {
                                                assert(allocated_gp_register.? == expected_register);
                                            },
                                            // _ = try instructions_to_delete.getOrPut(allocator, @intCast(instruction_index)), //.append(allocator, @intCast(instruction_index)),
                                            false => unreachable,
                                        }
                                    } else {
                                        if (register_allocator.gp_registers.free.get(expected_register)) |_| {
                                            try register_allocator.gp_registers.allocate(allocator, expected_register, intermediate, instruction.*, value_index);
                                            allocated_gp_register = expected_register;
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

            if (instructions_to_delete.keys().len > 0) {
                var next_instruction_to_delete_index: usize = 0;
                print("Instructions to delete: ", .{});
                for (instructions_to_delete.keys()) |instruction| {
                    print("#{}, ", .{instruction});
                }
                print("\n", .{});
                for (function.blocks.keys(), function.blocks.values()) |*block_index, *instruction_offset| {
                    _ = block_index;
                    while (instructions_to_delete.keys()[next_instruction_to_delete_index] <= instruction_offset.*) : (next_instruction_to_delete_index += 1) {
                        unreachable;
                    }
                }

                var removed_instruction_count: usize = 0;
                for (instructions_to_delete.keys()) |instruction_to_delete_index| {
                    _ = function.instructions.orderedRemove(instruction_to_delete_index - removed_instruction_count);
                    removed_instruction_count += 1;
                }

                print("Instructions after deletion\n", .{});
                for (function.instructions.items, 0..) |instruction, index| {
                    print("#{} {s}\n", .{ index, @tagName(instruction.id) });
                }
                print("\n", .{});
            }
        }
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

    fn emitStoreForFunctionCallResult(mir: *MIR, function: *MIR.Function, intermediate: *ir.Result, instruction: ir.Instruction.Index, stack_reference: ir.StackReference, call_index: ir.Call.Index) !void {
        _ = call_index;
        _ = intermediate;
        if (stack_reference.size <= @sizeOf(u64)) {
            switch (stack_reference.size) {
                @sizeOf(u8) => unreachable,
                @sizeOf(u16) => unreachable,
                @sizeOf(u32) => try mir.addInstruction(function, .mov, instruction, &.{
                    .{ .stack = .{ .offset = stack_reference.offset } }, .{ .gp_register = .{ .value = .a, .size = Size.fromByteCount(@intCast(stack_reference.size)) } },
                }),
                @sizeOf(u64) => unreachable,
                else => unreachable,
            }
        } else {
            unreachable;
        }
    }

    pub fn encode(mir: *const MIR, intermediate: *const ir.Result) !emit.Result {
        var local_relocations = ArrayList(LocalRelocation){};
        var global_relocations = ArrayList(GlobalRelocation){};
        var block_index: usize = 0;

        var image = try emit.Result.create();

        for (mir.functions.items) |*function| {
            local_relocations.clearRetainingCapacity();
            function.instruction_byte_offset = @intCast(image.sections.text.index);
            for (function.instructions.items, 0..) |*instruction, instruction_index| {
                if (block_index < function.blocks.values().len) {
                    if (instruction_index == function.blocks.values()[block_index]) {
                        function.blocks.values()[block_index] = @intCast(image.sections.text.index);
                        block_index += 1;
                    }
                }

                const operands = instruction.getOperands();
                switch (operands.len) {
                    0 => switch (instruction.id) {
                        .ret => image.appendCodeByte(0xc3),
                        .syscall => image.appendCode(&.{ 0x0f, 0x05 }),
                        .ud2 => image.appendCode(&.{ 0x0f, 0x0b }),
                        else => |t| @panic(@tagName(t)),
                    },
                    1 => switch (instruction.id) {
                        .call => {
                            const operand = operands[0];
                            assert(operand == .displacement);
                            switch (operand.displacement.destination) {
                                .function => |ir_function_index| {
                                    const function_index = ir_function_index.uniqueInteger();
                                    const current_function_index = @divExact(@intFromPtr(function) - @intFromPtr(mir.functions.items.ptr), @sizeOf(MIR.Function));

                                    if (current_function_index < function_index) {
                                        try mir.encodeRel32InstructionWithRelocation(&image, RelocationType.global, .{
                                            .relocations = &global_relocations,
                                            .target = function_index,
                                            .opcode = 0xe8,
                                        });
                                    } else {
                                        try encodeRel32Instruction(&image, .{
                                            .target = mir.functions.items[function_index].instruction_byte_offset,
                                            .opcode = 0xe8,
                                        });
                                    }
                                },
                                else => |t| @panic(@tagName(t)),
                            }
                        },
                        .jmp => {
                            const operand = operands[0];
                            assert(operand == .displacement);
                            if (operand.displacement.source.uniqueInteger() < operand.displacement.destination.block.uniqueInteger()) {
                                try mir.encodeRel32InstructionWithRelocation(&image, RelocationType.local, .{
                                    .relocations = &local_relocations,
                                    .target = operand.displacement.destination.block,
                                    .opcode = 0xe9,
                                });
                            } else if (operand.displacement.source.uniqueInteger() == operand.displacement.destination.block.uniqueInteger()) {
                                unreachable;
                            } else {
                                unreachable;
                            }
                        },
                        .push => {
                            const operand = operands[0];
                            switch (operand) {
                                .gp_register => |gp_register| {
                                    assert(gp_register.size == .eight);
                                    if (Rex.create(.{ .rm = gp_register.value.? })) |rex_byte| {
                                        image.appendCodeByte(@bitCast(rex_byte));
                                    }
                                    const opcode = @as(u8, 0x50) | @as(u3, @truncate(@intFromEnum(gp_register.value.?)));
                                    image.appendCodeByte(opcode);
                                },
                                else => |t| @panic(@tagName(t)),
                            }
                        },
                        else => |t| @panic(@tagName(t)),
                    },
                    2 => switch (operands[0]) {
                        .gp_register => |dst_gp_register| switch (operands[1]) {
                            .gp_register => |src_gp_register| {
                                assert(dst_gp_register.size == src_gp_register.size);
                                const direct = true;
                                const rm = dst_gp_register.value.?;
                                const reg = src_gp_register.value.?;

                                if (Rex.create(.{
                                    .rm = rm,
                                    .reg = reg,
                                    .rm_size = dst_gp_register.size,
                                })) |rex_byte| {
                                    image.appendCodeByte(@bitCast(rex_byte));
                                }

                                const opcode_option: [2]u8 = switch (instruction.id) {
                                    .mov => .{ 0x88, 0x89 },
                                    .xor => .{ 0x30, 0x31 },
                                    else => |t| @panic(@tagName(t)),
                                };

                                image.appendCodeByte(switch (dst_gp_register.size) {
                                    .one => opcode_option[0],
                                    else => opcode_option[1],
                                });

                                const modrm = ModRm{
                                    .rm = @truncate(@intFromEnum(rm)),
                                    .reg = @truncate(@intFromEnum(reg)),
                                    .mod = @as(u2, @intFromBool(direct)) << 1 | @intFromBool(direct),
                                };
                                image.appendCodeByte(@bitCast(modrm));
                            },
                            .immediate => |src_immediate| {
                                assert(src_immediate.type.bit_count % @bitSizeOf(u8) == 0);
                                print("DST GP register: {}. SRC immediate: {}\n", .{ dst_gp_register, src_immediate });
                                switch (instruction.id) {
                                    .mov => switch (@intFromEnum(dst_gp_register.value.?) > std.math.maxInt(u3)) {
                                        true => unreachable, // Use RM encoding
                                        false => {
                                            const opcode: u8 = switch (dst_gp_register.size) {
                                                .one => 0xb0,
                                                else => 0xb8,
                                            };
                                            const opcode_byte = opcode | @intFromEnum(dst_gp_register.value.?);
                                            image.appendCodeByte(opcode_byte);
                                            const immediate_byte_count = @as(usize, 1) << @intFromEnum(dst_gp_register.size);
                                            print("Immediate byte count: {}\n", .{immediate_byte_count});
                                            for (std.mem.asBytes(&src_immediate.value)[0..immediate_byte_count]) |immediate_byte| {
                                                image.appendCodeByte(immediate_byte);
                                            }
                                        },
                                    },
                                    else => {
                                        const immediate8_different_than_register = src_immediate.type.bit_count == 8 and dst_gp_register.size != .one;
                                        switch (dst_gp_register.value.? == .a and !immediate8_different_than_register) {
                                            true => unreachable,
                                            false => {
                                                const reg: x86_64.GPRegister = @enumFromInt(@as(u3, switch (instruction.id) {
                                                    .sub => 5,
                                                    else => |t| @panic(@tagName(t)),
                                                }));
                                                if (Rex.create(.{ .reg = reg, .rm = dst_gp_register.value.?, .rm_size = dst_gp_register.size })) |rex_byte| {
                                                    image.appendCodeByte(@bitCast(rex_byte));
                                                }
                                                const opcode: u8 = switch (immediate8_different_than_register) {
                                                    true => switch (instruction.id) {
                                                        .sub => 0x83,
                                                        else => |t| @panic(@tagName(t)),
                                                    },
                                                    false => unreachable,
                                                };
                                                image.appendCodeByte(opcode);

                                                const rm = dst_gp_register.value.?;
                                                const direct = true;
                                                const modrm = ModRm{
                                                    .rm = @truncate(@intFromEnum(rm)),
                                                    .reg = @truncate(@intFromEnum(reg)),
                                                    .mod = @as(u2, @intFromBool(direct)) << 1 | @intFromBool(direct),
                                                };
                                                image.appendCodeByte(@bitCast(modrm));

                                                switch (Size.fromBitCount(src_immediate.type.bit_count)) {
                                                    inline else => |size| image.appendCode(std.mem.asBytes(&@as(size.toInteger(), @intCast(src_immediate.value)))),
                                                }
                                            },
                                        }
                                    },
                                }
                            },
                            .stack => |src_stack| {
                                const stack_offset = -@as(i64, @intCast(src_stack.offset));
                                for (std.mem.asBytes(&stack_offset)) |stack_byte| {
                                    print("0x{x} ", .{stack_byte});
                                }
                                print("\n", .{});
                                const displacement_bytes: u3 = if (std.math.cast(i8, stack_offset)) |_| @sizeOf(i8) else if (std.math.cast(i32, stack_offset)) |_| @sizeOf(i32) else unreachable;

                                const reg = dst_gp_register.value.?;
                                if (Rex.create(.{ .reg = reg, .rm_size = dst_gp_register.size })) |rex_byte| {
                                    image.appendCodeByte(@bitCast(rex_byte));
                                }
                                const opcode_option: [2]u8 = switch (instruction.id) {
                                    .mov => .{ 0x8a, 0x8b },
                                    else => |t| @panic(@tagName(t)),
                                };

                                image.appendCodeByte(switch (dst_gp_register.size) {
                                    .one => opcode_option[0],
                                    else => opcode_option[1],
                                });

                                const rm = x86_64.GPRegister.bp;
                                const modrm = ModRm{
                                    .rm = @truncate(@intFromEnum(rm)),
                                    .reg = @truncate(@intFromEnum(reg)),
                                    .mod = 0b01,
                                };
                                image.appendCodeByte(@bitCast(modrm));

                                image.appendCode(std.mem.asBytes(&stack_offset)[0..displacement_bytes]);
                            },
                            else => |t| @panic(@tagName(t)),
                        },
                        .stack => |dst_stack| switch (operands[1]) {
                            .gp_register => |src_gp_register| switch (instruction.id) {
                                .mov => {
                                    const stack_offset = -@as(i64, @intCast(dst_stack.offset));
                                    for (std.mem.asBytes(&stack_offset)) |stack_byte| {
                                        print("0x{x} ", .{stack_byte});
                                    }
                                    print("\n", .{});
                                    const displacement_bytes: u3 = if (std.math.cast(i8, stack_offset)) |_| @sizeOf(i8) else if (std.math.cast(i32, stack_offset)) |_| @sizeOf(i32) else unreachable;

                                    const reg = src_gp_register.value.?;
                                    if (Rex.create(.{ .reg = reg, .rm_size = src_gp_register.size })) |rex_byte| {
                                        image.appendCodeByte(@bitCast(rex_byte));
                                    }
                                    const opcode_option: [2]u8 = switch (instruction.id) {
                                        .mov => .{ 0x88, 0x89 },
                                        else => |t| @panic(@tagName(t)),
                                    };

                                    image.appendCodeByte(switch (src_gp_register.size) {
                                        .one => opcode_option[0],
                                        else => opcode_option[1],
                                    });

                                    const rm = x86_64.GPRegister.bp;
                                    const modrm = ModRm{
                                        .rm = @truncate(@intFromEnum(rm)),
                                        .reg = @truncate(@intFromEnum(reg)),
                                        .mod = 0b01,
                                    };
                                    image.appendCodeByte(@bitCast(modrm));

                                    image.appendCode(std.mem.asBytes(&stack_offset)[0..displacement_bytes]);
                                },
                                else => |t| @panic(@tagName(t)),
                            },
                            else => |t| @panic(@tagName(t)),
                        },
                        else => |t| @panic(@tagName(t)),
                    },
                    3 => switch (instruction.id) {
                        else => |t| @panic(@tagName(t)),
                    },
                    4 => switch (instruction.id) {
                        else => |t| @panic(@tagName(t)),
                    },
                    else => unreachable,
                }
            }

            for (local_relocations.items) |relocation| {
                const source_offset: i64 = relocation.instruction_byte_offset + relocation.instruction_length;
                const destination_offset: i64 = function.blocks.get(relocation.target).?;
                print("Source: {}. Destination: {}\n", .{ source_offset, destination_offset });
                const displacement_offset = destination_offset - source_offset;
                const address_to_address = @intFromPtr(&image.sections.text.content[relocation.instruction_byte_offset + relocation.source_address_writer_offset]);
                switch (relocation.size) {
                    inline .one, .four => |relocation_size| {
                        const RelocationInteger = switch (relocation_size) {
                            .one => i8,
                            .four => i32,
                            else => @compileError("Unreachable"),
                        };
                        const ptr: *align(1) RelocationInteger = @ptrFromInt(address_to_address);
                        ptr.* = @intCast(displacement_offset);
                    },
                    else => unreachable,
                }
            }

            print("Function code:\n", .{});
            for (image.sections.text.content[function.instruction_byte_offset..][0..image.sections.text.index]) |code_byte| {
                print("0x{x:0>2} ", .{code_byte});
            }
            print("\n", .{});
        }

        for (global_relocations.items) |global_relocation| {
            _ = global_relocation;
            unreachable;
        }

        image.entry_point = mir.functions.items[intermediate.entry_point].instruction_byte_offset;

        return image;
    }

    fn encodeRel32Instruction(image: *emit.Result, arguments: struct {
        target: u32,
        opcode: u8,
    }) !void {
        const instruction_byte_offset: u32 = @intCast(image.sections.text.index);
        const instruction_length = 5;

        const source_offset: i64 = instruction_byte_offset + instruction_length;
        const destination_offset: i64 = arguments.target;
        const offset: i32 = @intCast(destination_offset - source_offset);

        image.appendCodeByte(arguments.opcode);
        image.appendCode(std.mem.asBytes(&offset));
    }

    fn encodeRel32InstructionWithRelocation(mir: *const MIR, image: *emit.Result, comptime relocation_type: RelocationType, arguments: struct {
        relocations: *ArrayList(Relocation(RelocationIndex(relocation_type))),
        target: RelocationIndex(relocation_type),
        opcode: u8,
    }) !void {
        const instruction_byte_offset = image.sections.text.index;
        const source_address_writer_offset = 1;
        const instruction_length = 5;
        const size = .four;

        image.appendCodeByte(arguments.opcode);
        image.appendCode(&(.{0} ** 4));

        try arguments.relocations.append(mir.allocator, .{
            .instruction_byte_offset = @intCast(instruction_byte_offset),
            .source_address_writer_offset = source_address_writer_offset,
            .instruction_length = instruction_length,
            .target = arguments.target,
            .size = size,
        });
    }
};

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
const ModRm = packed struct(u8) {
    rm: u3,
    reg: u3,
    mod: u2,
};

const Rex = packed struct(u8) {
    b: bool,
    x: bool,
    r: bool,
    w: bool,
    fixed: u4 = 0b0100,

    fn create(args: struct {
        rm: ?GPRegister = null,
        reg: ?GPRegister = null,
        sib: bool = false,
        rm_size: ?Size = null,
    }) ?Rex {
        const rex_byte = Rex{
            .b = if (args.rm) |rm| @intFromEnum(rm) > std.math.maxInt(u3) else false,
            .x = args.sib,
            .r = if (args.reg) |reg| @intFromEnum(reg) > std.math.maxInt(u3) else false,
            .w = if (args.rm_size) |rm_size| rm_size == .eight else false,
        };

        if (@as(u4, @truncate(@as(u8, @bitCast(rex_byte)))) != 0) {
            return rex_byte;
        } else {
            return null;
        }
    }
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

const syscall_registers = [7]GPRegister{ .a, .di, .si, .d, .r10, .r8, .r9 };
