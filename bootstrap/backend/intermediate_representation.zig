const std = @import("std");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;

const Compilation = @import("../Compilation.zig");
const log = Compilation.log;
const logln = Compilation.logln;
const Module = Compilation.Module;
const Package = Compilation.Package;

const data_structures = @import("../data_structures.zig");
const ArrayList = data_structures.ArrayList;
const BlockList = data_structures.BlockList;
const AutoArrayHashMap = data_structures.AutoArrayHashMap;
const AutoHashMap = data_structures.AutoHashMap;
const StringKeyMap = data_structures.StringKeyMap;

const emit = @import("emit.zig");
const SectionManager = emit.SectionManager;

pub const Logger = enum {
    function,
    function_name,
    phi_removal,
    weird_bug,

    pub var bitset = std.EnumSet(Logger).initMany(&.{
        .function,
        .weird_bug,
        .function_name,
    });
};

pub const IR = struct {
    arguments: BlockList(Argument) = .{},
    basic_blocks: BlockList(BasicBlock) = .{},
    binary_operations: BlockList(BinaryOperation) = .{},
    branches: BlockList(Branch) = .{},
    calls: BlockList(Call) = .{},
    casts: BlockList(Cast) = .{},
    function_definitions: BlockList(FunctionDefinition) = .{},
    instructions: BlockList(Instruction) = .{},
    jumps: BlockList(Jump) = .{},
    loads: BlockList(Load) = .{},
    phis: BlockList(Phi) = .{},
    returns: BlockList(Return) = .{},
    stack_slots: BlockList(StackSlot) = .{},
    string_literals: BlockList(StringLiteral) = .{},
    stores: BlockList(Store) = .{},
    syscalls: BlockList(Syscall) = .{},

    section_manager: SectionManager,
    module: *Module,
    entry_point: FunctionDefinition.Index,

    pub fn getFunctionName(ir: *IR, function_index: FunctionDefinition.Index) []const u8 {
        return ir.module.getName(ir.module.function_name_map.get(@bitCast(function_index)).?).?;
    }
};

pub const StringLiteral = struct {
    offset: u32,

    pub const List = BlockList(@This());
    pub const Index = List.Index;
    pub const Allocation = List.Allocation;
};

pub const BinaryOperation = struct {
    left: Instruction.Index,
    right: Instruction.Index,
    id: Id,
    type: Type,

    const Id = enum {
        add,
        sub,
        logical_and,
        logical_xor,
        logical_or,
        signed_multiply,
        signed_divide,
        shift_left,
        shift_right,
        integer_compare_equal,
    };

    pub const List = BlockList(@This());
    pub const Index = List.Index;
    pub const Allocation = List.Allocation;
};

const Cast = struct {
    value: Instruction.Index,
    type: Type,

    pub const List = BlockList(@This());
    pub const Index = List.Index;
    pub const Allocation = List.Allocation;
};
const Syscall = struct {
    arguments: ArrayList(Instruction.Index),

    pub const List = BlockList(@This());
    pub const Index = List.Index;
    pub const Allocation = List.Allocation;
};

pub const Jump = struct {
    target: BasicBlock.Index,

    pub const List = BlockList(@This());
    pub const Index = List.Index;
    pub const Allocation = List.Allocation;
};

pub const Branch = struct {
    condition: Instruction.Index,
    true_jump: Jump.Index,
    false_jump: Jump.Index,

    pub const List = BlockList(@This());
    pub const Index = List.Index;
    pub const Allocation = List.Allocation;
};

pub const Load = struct {
    value: Instruction.Index,
    ordering: ?AtomicOrder = null,
    @"volatile": bool = false,

    pub fn isUnordered(load: *const Load) bool {
        return (load.ordering == null or load.ordering == .unordered) and !load.@"volatile";
    }

    pub const List = BlockList(@This());
    pub const Index = List.Index;
    pub const Allocation = List.Allocation;
};

const ConstantInteger = struct {
    value: extern union {
        signed: i64,
        unsigned: u64,
    },
    type: Type.Scalar,

    pub const List = BlockList(@This());
    pub const Index = List.Index;
    pub const Allocation = List.Allocation;
};

pub const AtomicOrder = enum {
    unordered,
    monotonic,
    acquire,
    release,
    acquire_release,
    sequentially_consistent,
};

pub const Store = struct {
    source: Instruction.Index,
    destination: Instruction.Index,
    ordering: ?AtomicOrder = null,
    @"volatile": bool = false,

    pub const List = BlockList(@This());
    pub const Index = List.Index;
    pub const Allocation = List.Allocation;
};
pub const StackSlot = struct {
    type: Type,

    pub const List = BlockList(@This());
    pub const Index = List.Index;
    pub const Allocation = List.Allocation;
};

pub const Return = struct {
    value: Instruction.Index,
    pub const List = BlockList(@This());
    pub const Index = List.Index;
    pub const Allocation = List.Allocation;
};

pub const Argument = struct {
    type: Type,

    pub const List = BlockList(@This());
    pub const Index = List.Index;
    pub const Allocation = List.Allocation;

    pub const Map = AutoArrayHashMap(Compilation.Declaration.Index, Instruction.Index);
};

pub const BasicBlock = struct {
    instructions: ArrayList(Instruction.Index) = .{},
    parent: FunctionDefinition.Index = FunctionDefinition.Index.invalid,
    /// This variable `filled` is set to true when local value numbering is finished for a basic block,
    /// that is, whenever the block is not going to receive more instructions
    filled: bool = false,
    sealed: bool = false,
    predecessors: ArrayList(BasicBlock.Index) = .{},
    incomplete_phis: ArrayList(Instruction.Index) = .{},

    pub const List = BlockList(@This());
    pub const Index = List.Index;
    pub const Allocation = List.Allocation;
};

const Builder = struct {
    allocator: Allocator,
    ir: IR,
    current_function_index: FunctionDefinition.Index = FunctionDefinition.Index.invalid,
    current_basic_block_index: BasicBlock.Index = BasicBlock.Index.invalid,
    return_phi_index: Instruction.Index = Instruction.Index.invalid,
    return_basic_block_index: BasicBlock.Index = BasicBlock.Index.invalid,

    fn translateType(builder: *Builder, type_index: Compilation.Type.Index) !?Type {
        const sema_type = builder.ir.module.types.get(type_index);
        return switch (sema_type.*) {
            .integer => |integer| switch (integer.bit_count) {
                8 => Type.i8,
                16 => Type.i16,
                32 => Type.i32,
                64 => Type.i64,
                else => unreachable,
            },
            // TODO
            .pointer => Type.i64,
            .bool => Type.i1,
            .void,
            .noreturn,
            => null,
            else => |t| @panic(@tagName(t)),
        };
    }

    fn allocateBlock(builder: *Builder) !BasicBlock.Allocation {
        const current_function_index = builder.current_function_index;
        assert(!current_function_index.invalid);
        const basic_block = try builder.ir.basic_blocks.append(builder.allocator, .{});
        basic_block.ptr.parent = current_function_index;

        return basic_block;
    }

    fn appendAndSetCurrentBlock(builder: *Builder) !BasicBlock.Allocation {
        const basic_block = try builder.allocateBlock();
        builder.current_basic_block_index = basic_block.index;
        return basic_block;
    }

    fn createStackSlot(builder: *Builder, arguments: struct {
        type: Type,
        sema: Compilation.Declaration.Index,
    }) !Instruction.Index {
        const current_function = builder.ir.function_definitions.get(builder.current_function_index);
        const stack_reference_allocation = try builder.ir.stack_slots.append(builder.allocator, .{
            .type = arguments.type,
        });

        const instruction_index = try builder.createInstructionAndAppendToCurrentBlock(.{
            .stack_slot = stack_reference_allocation.index,
        });

        try current_function.stack_map.put(builder.allocator, arguments.sema, instruction_index);

        return instruction_index;
    }

    fn createInstructionAndAppendToCurrentBlock(builder: *Builder, instruction_union: Instruction.U) !Instruction.Index {
        const current_function_index = builder.current_function_index;
        assert(!current_function_index.invalid);
        const current_basic_block_index = builder.current_basic_block_index;
        assert(!current_basic_block_index.invalid);
        const current_basic_block = builder.ir.basic_blocks.get(current_basic_block_index);
        assert(current_basic_block.parent.eq(current_function_index));
        const instruction = try builder.ir.instructions.append(builder.allocator, .{
            .u = instruction_union,
        });

        try builder.appendToBlock(current_basic_block_index, instruction.index);

        return instruction.index;
    }

    fn appendToBlock(builder: *Builder, basic_block_index: BasicBlock.Index, instruction_index: Instruction.Index) !void {
        const basic_block = builder.ir.basic_blocks.get(basic_block_index);
        const instruction = builder.ir.instructions.get(instruction_index);
        assert(instruction.parent.invalid);
        instruction.parent = basic_block_index;
        try basic_block.instructions.append(builder.allocator, instruction_index);
    }

    fn emitConstantInteger(builder: *Builder, constant_integer: ConstantInteger) !Instruction.Index {
        // TODO: should we emit integer constants to the block?
        assert(constant_integer.type.getKind() == .integer);
        const load_integer = try builder.createInstructionAndAppendToCurrentBlock(.{
            .constant_integer = constant_integer,
        });
        return load_integer;
    }

    fn emitValue(builder: *Builder, sema_value_index: Compilation.Value.Index) !Instruction.Index {
        const sema_value = builder.ir.module.values.get(sema_value_index);
        const result = switch (sema_value.*) {
            .bool => |boolean| try builder.emitConstantInteger(ConstantInteger{
                .value = .{
                    .unsigned = @intFromBool(boolean),
                },
                .type = .i8,
            }),
            .integer => |integer| try builder.emitConstantInteger(ConstantInteger{
                .value = .{
                    .unsigned = integer.value,
                },
                .type = (builder.translateType(integer.type) catch unreachable orelse unreachable).scalar,
            }),
            .declaration_reference => |sema_declaration_reference| blk: {
                const sema_declaration_index = sema_declaration_reference.value;
                const sema_declaration = builder.ir.module.declarations.get(sema_declaration_index);
                // TODO: substitute stack slot with a precise name
                const stack_slot = switch (sema_declaration.scope_type) {
                    .local => local: {
                        const current_function = builder.ir.function_definitions.get(builder.current_function_index);
                        const stack = current_function.stack_map.get(sema_declaration_index).?;
                        break :local stack;
                    },
                    .global => unreachable,
                };
                const load = try builder.ir.loads.append(builder.allocator, .{
                    .value = stack_slot,
                });
                const instruction = try builder.createInstructionAndAppendToCurrentBlock(.{
                    .load = load.index,
                });

                break :blk instruction;
            },
            .sign_extend => |sema_cast_index| blk: {
                const cast_type: CastType = switch (sema_value.*) {
                    .sign_extend => .sign_extend,
                    else => unreachable,
                };
                const sema_cast = builder.ir.module.casts.get(sema_cast_index);
                const source_value = try builder.emitValue(sema_cast.value);

                const cast_allocation = try builder.ir.casts.append(builder.allocator, .{
                    .value = source_value,
                    .type = try builder.translateType(sema_cast.type) orelse unreachable,
                });

                break :blk try builder.createInstructionAndAppendToCurrentBlock(switch (cast_type) {
                    inline else => |ct| @unionInit(Instruction.U, @tagName(ct), cast_allocation.index),
                });
            },
            .call => |sema_call_index| try builder.emitCall(sema_call_index),
            .binary_operation => |sema_binary_operation_index| try builder.emitBinaryOperation(sema_binary_operation_index),
            .syscall => |sema_syscall_index| try builder.emitSyscall(sema_syscall_index),
            .string_literal => |sema_string_literal_index| blk: {
                const string_literal = builder.ir.module.string_literals.getValue(sema_string_literal_index).?;

                if (builder.ir.section_manager.rodata == null) {
                    const rodata_index = try builder.ir.section_manager.addSection(.{
                        .name = ".rodata",
                        .size_guess = 0,
                        .alignment = 0x1000,
                        .flags = .{
                            .read = true,
                            .write = false,
                            .execute = false,
                        },
                        .type = .loadable_program,
                    });

                    builder.ir.section_manager.rodata = @intCast(rodata_index);
                }

                const rodata_index = builder.ir.section_manager.rodata orelse unreachable;
                const rodata_section_offset = builder.ir.section_manager.getSectionOffset(rodata_index);

                try builder.ir.section_manager.appendToSection(rodata_index, string_literal);
                try builder.ir.section_manager.appendByteToSection(rodata_index, 0);

                const string_literal_allocation = try builder.ir.string_literals.append(builder.allocator, .{
                    .offset = @intCast(rodata_section_offset),
                });

                break :blk try builder.createInstructionAndAppendToCurrentBlock(.{
                    .constant_string_literal = string_literal_allocation.index,
                });
            },
            else => |t| @panic(@tagName(t)),
        };

        return result;
    }

    fn emitCall(builder: *Builder, sema_call_index: Compilation.Call.Index) anyerror!Instruction.Index {
        const sema_call = builder.ir.module.calls.get(sema_call_index);
        const sema_argument_list_index = sema_call.arguments;

        const argument_list: []const Instruction.Index = switch (sema_argument_list_index.invalid) {
            false => blk: {
                var argument_list = ArrayList(Instruction.Index){};
                const sema_argument_list = builder.ir.module.argument_lists.get(sema_argument_list_index);
                try argument_list.ensureTotalCapacity(builder.allocator, sema_argument_list.array.items.len);
                for (sema_argument_list.array.items) |sema_argument_value_index| {
                    const argument_value_index = try builder.emitValue(sema_argument_value_index);
                    argument_list.appendAssumeCapacity(argument_value_index);
                }
                break :blk argument_list.items;
            },
            true => &.{},
        };

        const call = try builder.ir.calls.append(builder.allocator, .{
            .callable = switch (builder.ir.module.values.get(sema_call.value).*) {
                .function_definition => |sema_function_definition_index| .{
                    .function_definition = .{
                        .element = sema_function_definition_index.element,
                        .block = sema_function_definition_index.block,
                    },
                },
                // .function => |function_index| .{
                //     .index = function_index.index,
                //     .block = function_index.block,
                // },
                else => |t| @panic(@tagName(t)),
            },
            .arguments = argument_list,
        });

        const instruction_index = try builder.createInstructionAndAppendToCurrentBlock(.{
            .call = call.index,
        });

        return instruction_index;
    }

    fn emitBinaryOperation(builder: *Builder, sema_binary_operation_index: Compilation.BinaryOperation.Index) anyerror!Instruction.Index {
        const sema_binary_operation = builder.ir.module.binary_operations.get(sema_binary_operation_index);

        const left = try builder.emitValue(sema_binary_operation.left);
        const right = try builder.emitValue(sema_binary_operation.right);

        const sema_type = builder.ir.module.types.get(sema_binary_operation.type).*;
        const binary_operation_type = try builder.translateType(sema_binary_operation.type);

        const binary_operation = try builder.ir.binary_operations.append(builder.allocator, .{
            .left = left,
            .right = right,
            .id = switch (sema_binary_operation.id) {
                .add => .add,
                .sub => .sub,
                .logical_and => .logical_and,
                .logical_xor => .logical_xor,
                .logical_or => .logical_or,
                .multiply => switch (sema_type) {
                    .integer => |integer| switch (integer.signedness) {
                        .signed => .signed_multiply,
                        else => |t| @panic(@tagName(t)),
                    },
                    else => |t| @panic(@tagName(t)),
                },
                .divide => switch (sema_type) {
                    .integer => |integer| switch (integer.signedness) {
                        .signed => .signed_divide,
                        else => |t| @panic(@tagName(t)),
                    },
                    else => |t| @panic(@tagName(t)),
                },
                .shift_left => .shift_left,
                .shift_right => .shift_right,
                .compare_equal => switch (sema_type) {
                    .integer => .integer_compare_equal,
                    else => unreachable,
                },
            },
            .type = binary_operation_type orelse unreachable,
        });

        const instruction = try builder.createInstructionAndAppendToCurrentBlock(.{
            .binary_operation = binary_operation.index,
        });

        return instruction;
    }

    fn emitBlock(builder: *Builder, sema_block_index: Compilation.Block.Index) anyerror!void {
        const sema_block = builder.ir.module.blocks.get(sema_block_index);

        for (sema_block.statements.items) |sema_statement_index| {
            const sema_statement = builder.ir.module.values.get(sema_statement_index);
            switch (sema_statement.*) {
                .declaration => |sema_declaration_index| {
                    const sema_declaration = builder.ir.module.declarations.get(sema_declaration_index);
                    //logln("Name: {s}\n", .{builder.module.getName(sema_declaration.name).?});
                    assert(sema_declaration.scope_type == .local);
                    const declaration_type = builder.ir.module.types.get(sema_declaration.type);
                    switch (declaration_type.*) {
                        .comptime_int => unreachable,
                        else => {
                            const ir_type = try builder.translateType(sema_declaration.type);
                            const stack_slot = try builder.createStackSlot(.{
                                .type = ir_type orelse unreachable,
                                .sema = sema_declaration_index,
                            });

                            _ = try builder.emitAssignment(.{
                                .destination = stack_slot,
                                .sema_source = sema_declaration.init_value,
                            });
                        },
                    }
                },
                .branch => |sema_branch_index| {
                    const sema_branch = builder.ir.module.branches.get(sema_branch_index);
                    const condition = try builder.emitValue(sema_branch.condition);
                    const true_expression = builder.ir.module.values.get(sema_branch.true_expression);
                    const false_expression = builder.ir.module.values.get(sema_branch.false_expression);

                    const true_block = try builder.allocateBlock();
                    const false_block = try builder.allocateBlock();

                    const current_basic_block_index = builder.current_basic_block_index;
                    assert(!current_basic_block_index.invalid);

                    const branch = try builder.ir.branches.append(builder.allocator, .{
                        .condition = condition,
                        .true_jump = try builder.createJump(.{
                            .source = current_basic_block_index,
                            .target = true_block.index,
                        }),
                        .false_jump = try builder.createJump(.{
                            .source = current_basic_block_index,
                            .target = false_block.index,
                        }),
                    });

                    _ = try builder.createInstructionAndAppendToCurrentBlock(.{
                        .branch = branch.index,
                    });
                    builder.ir.basic_blocks.get(current_basic_block_index).filled = true;
                    try builder.sealBlock(true_block.index);
                    try builder.sealBlock(false_block.index);

                    const exit_block = try builder.allocateBlock();

                    const sema_true_block = builder.ir.module.blocks.get(true_expression.block);
                    try builder.pushBlockAndEmit(true_block.index, true_expression.block);
                    if (sema_true_block.reaches_end) {
                        const jump_index = try builder.createJump(.{
                            .source = builder.current_basic_block_index,
                            .target = exit_block.index,
                        });
                        _ = try builder.createInstructionAndAppendToCurrentBlock(.{
                            .jump = jump_index,
                        });
                    }
                    builder.ir.basic_blocks.get(builder.current_basic_block_index).filled = true;

                    const sema_false_block = builder.ir.module.blocks.get(false_expression.block);
                    try builder.pushBlockAndEmit(false_block.index, false_expression.block);
                    if (sema_false_block.reaches_end) {
                        const jump_index = try builder.createJump(.{
                            .source = builder.current_basic_block_index,
                            .target = exit_block.index,
                        });
                        _ = try builder.createInstructionAndAppendToCurrentBlock(.{
                            .jump = jump_index,
                        });
                    }
                    builder.ir.basic_blocks.get(builder.current_basic_block_index).filled = true;

                    try builder.sealBlock(exit_block.index);

                    builder.current_basic_block_index = exit_block.index;
                },
                .@"return" => |sema_return_index| {
                    const sema_return = builder.ir.module.returns.get(sema_return_index);
                    assert(!builder.return_basic_block_index.invalid);
                    const jump_index = try builder.createJump(.{
                        .source = builder.current_basic_block_index,
                        .target = builder.return_basic_block_index,
                    });

                    if (!sema_return.value.invalid) {
                        const return_value = try builder.emitValue(sema_return.value);
                        const return_phi_instruction = builder.ir.instructions.get(builder.return_phi_index);
                        assert(return_phi_instruction.parent.eq(builder.return_basic_block_index));
                        const return_phi = builder.ir.phis.get(return_phi_instruction.u.phi);
                        try return_phi.operands.append(builder.allocator, .{
                            .jump = jump_index,
                            .value = return_value,
                        });
                    }

                    _ = try builder.createInstructionAndAppendToCurrentBlock(.{
                        .jump = jump_index,
                    });
                },
                .syscall => |sema_syscall_index| _ = try builder.emitSyscall(sema_syscall_index),
                .@"unreachable" => _ = try builder.createInstructionAndAppendToCurrentBlock(.@"unreachable"),
                .call => |sema_call_index| _ = try builder.emitCall(sema_call_index),
                .assign => |sema_assignment_index| {
                    const sema_assignment = builder.ir.module.assignments.get(sema_assignment_index);
                    const current_function = builder.ir.function_definitions.get(builder.current_function_index);
                    const sema_declaration = builder.ir.module.values.get(sema_assignment.destination).declaration_reference.value;
                    const destination = current_function.stack_map.get(sema_declaration).?;
                    _ = try builder.emitAssignment(.{
                        .destination = destination,
                        .sema_source = sema_assignment.source,
                    });
                },
                else => |t| @panic(@tagName(t)),
            }
        }
    }

    fn emitAssignment(builder: *Builder, arguments: struct {
        destination: Instruction.Index,
        sema_source: Compilation.Value.Index,
    }) !Instruction.Index {
        const value_index = try builder.emitValue(arguments.sema_source);

        const store = try builder.ir.stores.append(builder.allocator, .{
            .destination = arguments.destination,
            .source = value_index,
        });

        return try builder.createInstructionAndAppendToCurrentBlock(.{
            .store = store.index,
        });
    }

    fn emitSyscall(builder: *Builder, sema_syscall_index: Compilation.Syscall.Index) anyerror!Instruction.Index {
        const sema_syscall = builder.ir.module.syscalls.get(sema_syscall_index);
        var arguments = try ArrayList(Instruction.Index).initCapacity(builder.allocator, sema_syscall.argument_count + 1);

        const sema_syscall_number = sema_syscall.number;
        assert(!sema_syscall_number.invalid);
        const number_value_index = try builder.emitValue(sema_syscall_number);

        arguments.appendAssumeCapacity(number_value_index);

        for (sema_syscall.getArguments()) |sema_syscall_argument| {
            assert(!sema_syscall_argument.invalid);
            const argument_value_index = try builder.emitValue(sema_syscall_argument);
            arguments.appendAssumeCapacity(argument_value_index);
        }

        const syscall = try builder.ir.syscalls.append(builder.allocator, .{
            .arguments = arguments,
        });

        return try builder.createInstructionAndAppendToCurrentBlock(.{
            .syscall = syscall.index,
        });
    }

    fn createJump(builder: *Builder, arguments: struct {
        source: BasicBlock.Index,
        target: BasicBlock.Index,
    }) !Jump.Index {
        assert(!arguments.source.invalid);
        assert(!arguments.target.invalid);

        const target_block = builder.ir.basic_blocks.get(arguments.target);
        assert(!target_block.sealed);
        const jump = try builder.ir.jumps.append(builder.allocator, .{
            .target = arguments.target,
        });
        try target_block.predecessors.append(builder.allocator, arguments.source);
        // TODO: predecessors
        return jump.index;
    }

    fn sealBlock(builder: *Builder, basic_block_index: BasicBlock.Index) !void {
        const block = builder.ir.basic_blocks.get(basic_block_index);
        for (block.incomplete_phis.items) |_| {
            unreachable;
        }
        block.sealed = true;
    }

    fn pushBlockAndEmit(builder: *Builder, basic_block_index: BasicBlock.Index, sema_block_index: Compilation.Block.Index) !void {
        builder.current_basic_block_index = basic_block_index;
        try builder.emitBlock(sema_block_index);
    }
};
pub const CastType = enum {
    sign_extend,
};

pub fn findReachableBlocks(arguments: struct {
    allocator: Allocator,
    ir: *IR,
    first: BasicBlock.Index,
    traverse_functions: bool,
}) !ArrayList(BasicBlock.Index) {
    const allocator = arguments.allocator;
    const ir = arguments.ir;
    const first = arguments.first;
    const traverse_functions = arguments.traverse_functions;

    const BlockSearcher = struct {
        to_visit: ArrayList(BasicBlock.Index) = .{},
        visited: AutoArrayHashMap(BasicBlock.Index, void) = .{},

        fn visit(searcher: *@This(), a: Allocator, basic_block: BasicBlock.Index) !void {
            if (searcher.visited.get(basic_block) == null) {
                try searcher.to_visit.append(a, basic_block);
                try searcher.visited.put(a, basic_block, {});
            }
        }
    };

    var searcher = BlockSearcher{};
    try searcher.to_visit.append(allocator, first);
    try searcher.visited.put(allocator, first, {});

    while (searcher.to_visit.items.len > 0) {
        const block_index = searcher.to_visit.swapRemove(0);
        const block_to_visit = ir.basic_blocks.get(block_index);
        const last_instruction_index = block_to_visit.instructions.items[block_to_visit.instructions.items.len - 1];
        const last_instruction = ir.instructions.get(last_instruction_index);
        switch (last_instruction.u) {
            .jump => |jump_index| {
                const ir_jump = ir.jumps.get(jump_index);
                const new_block = ir_jump.target;
                try searcher.visit(allocator, new_block);
            },
            .call => |call_index| {
                if (traverse_functions) {
                    const ir_call = ir.calls.get(call_index);
                    switch (ir_call.callable) {
                        .function_definition => |definition_index| {
                            switch (definition_index.invalid) {
                                false => {
                                    const function = ir.function_definitions.get(definition_index);
                                    try searcher.visit(allocator, function.entry_block);
                                },
                                true => {},
                            }
                        },
                        // else => unreachable,
                    }
                }
            },
            .branch => |branch_index| {
                const branch = ir.branches.get(branch_index);
                const true_jump = ir.jumps.get(branch.true_jump);
                const false_jump = ir.jumps.get(branch.false_jump);
                try searcher.visit(allocator, true_jump.target);
                try searcher.visit(allocator, false_jump.target);
            },
            .@"unreachable",
            .ret,
            .store,
            => {},
            else => |t| @panic(@tagName(t)),
        }
    }

    var list = try ArrayList(BasicBlock.Index).initCapacity(allocator, searcher.visited.keys().len);
    list.appendSliceAssumeCapacity(searcher.visited.keys());

    return list;
}

const Callable = struct {
    argument_map: AutoArrayHashMap(Compilation.Declaration.Index, Instruction.Index),
    calling_convention: Compilation.CallingConvention,
    return_type: ?Type,
    attributes: Attributes,

    const Attributes = struct {
        returns: bool,
    };

    pub const Index = union(enum) {
        function_definition: FunctionDefinition.Index,
    };
};

pub const Type = union(enum) {
    scalar: Scalar,
    vector: Vector,
    aggregate: Aggregate.Index,

    pub const Vector = struct {
        count: u16,
        scalar: Scalar,
        alignment: u16 = Vector.default_alignment,

        const default_alignment = std.math.log2_int(u16, 16);
    };

    pub const Scalar = enum {
        i1,
        i8,
        i16,
        i32,
        i64,

        pub const Kind = enum {
            integer,
            float,
        };

        pub fn getKind(scalar: Type.Scalar) Kind {
            return switch (scalar) {
                .i1,
                .i8,
                .i16,
                .i32,
                .i64,
                => .integer,
            };
        }
    };

    const Aggregate = struct {
        kind: Kind,
        const Kind = enum {
            @"struct",
            @"union",
        };
        pub const List = BlockList(@This());
        pub const Index = List.Index;
        pub const Allocation = List.Allocation;
    };

    pub const @"i1" = Type{
        .scalar = .i1,
    };
    pub const @"i8" = Type{
        .scalar = .i8,
    };
    pub const @"i16" = Type{
        .scalar = .i16,
    };
    pub const @"i32" = Type{
        .scalar = .i32,
    };
    pub const @"i64" = Type{
        .scalar = .i64,
    };

    pub fn getSize(t: Type) usize {
        const result: usize = switch (t) {
            .scalar => switch (t.scalar) {
                .i1 => @sizeOf(i1),
                .i8 => @sizeOf(i8),
                .i16 => @sizeOf(i16),
                .i32 => @sizeOf(i32),
                .i64 => @sizeOf(i64),
            },
            else => |tg| @panic(@tagName(tg)),
        };

        return result;
    }

    pub fn getAlignment(t: Type) u16 {
        const result: u16 = switch (t) {
            .scalar => switch (t.scalar) {
                .i1 => @alignOf(i1),
                .i8 => @alignOf(i8),
                .i16 => @alignOf(i16),
                .i32 => @alignOf(i32),
                .i64 => @alignOf(i64),
            },
            else => |tag| @panic(@tagName(tag)),
        };
        return result;
    }
};

pub const FunctionDefinition = struct {
    callable: Callable,
    entry_block: BasicBlock.Index = BasicBlock.Index.invalid,
    stack_map: AutoHashMap(Compilation.Declaration.Index, Instruction.Index) = .{},

    fn formatter(allocator: Allocator, function_definition: FunctionDefinition.Index, ir: *IR) FunctionDefinition.Formatter {
        return .{
            .function = function_definition,
            .ir = ir,
            .allocator = allocator,
        };
    }

    pub const Formatter = struct {
        function: FunctionDefinition.Index,
        ir: *IR,
        allocator: Allocator,

        pub fn format(function_formatter: *const Formatter, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
            const function_index = function_formatter.function;
            const ir = function_formatter.ir;
            const function = ir.function_definitions.get(function_index);
            const sema_function_index: Compilation.Function.Index = @bitCast(function_index);
            const function_name_hash = ir.module.function_name_map.get(sema_function_index).?;
            const function_name = ir.module.getName(function_name_hash).?;
            try writer.print("Function #{} \"{s}\"\n", .{ function_index.uniqueInteger(), function_name });

            const reachable_blocks = findReachableBlocks(.{
                .allocator = function_formatter.allocator,
                .ir = ir,
                .first = function.entry_block,
                .traverse_functions = false,
            }) catch unreachable;

            for (reachable_blocks.items, 0..) |basic_block_index, function_block_index| {
                const basic_block = ir.basic_blocks.get(basic_block_index);
                try writer.print("\nBLOCK #{} (${}):\n", .{ function_block_index, basic_block_index.uniqueInteger() });

                for (basic_block.instructions.items, 0..) |instruction_index, block_instruction_index| {
                    try writer.print("%{} (${}): ", .{ block_instruction_index, instruction_index.uniqueInteger() });

                    const instruction = ir.instructions.get(instruction_index);
                    switch (instruction.u) {
                        // .binary_operation => {}, @tagName(binary_operation.type)
                        else => try writer.writeAll(@tagName(instruction.u)),
                    }

                    try writer.writeByte(' ');

                    switch (instruction.u) {
                        .syscall => |syscall_index| {
                            const syscall = ir.syscalls.get(syscall_index);
                            try writer.writeAll(" (");
                            for (syscall.arguments.items, 0..) |arg_index, i| {
                                const arg_value = ir.instructions.get(arg_index);

                                try writer.print("${}: {s}", .{ i, @tagName(arg_value.u) });

                                if (i < syscall.arguments.items.len - 1) {
                                    try writer.writeAll(", ");
                                }
                            }
                            try writer.writeAll(")");
                        },
                        .jump => |jump_index| {
                            const jump = ir.jumps.get(jump_index);
                            try writer.print("${}", .{jump.target.uniqueInteger()});
                        },
                        .phi => |phi_index| {
                            const phi = ir.phis.get(phi_index);
                            for (phi.operands.items, 0..) |phi_operand, i| {
                                const arg_value = ir.instructions.get(phi_operand.value);

                                try writer.print("%{} (#{}): {s}", .{ i, phi_operand.value.uniqueInteger(), @tagName(arg_value.u) });

                                if (i < phi.operands.items.len - 1) {
                                    try writer.writeAll(", ");
                                }
                            }
                            try writer.writeAll(")");
                        },
                        .ret => |ret_index| {
                            const ret = ir.returns.get(ret_index);
                            switch (ret.value.invalid) {
                                false => {
                                    const ret_value = ir.instructions.get(ret.value);
                                    try writer.print("{s}", .{@tagName(ret_value.u)});
                                },
                                true => try writer.writeAll("void"),
                            }
                        },
                        // .load => |load_index| {
                        //     const load = ir.loads.get(load_index);
                        //     try writer.print("{s}", .{@tagName(ir.values.get(load.value).*)});
                        // },
                        .store => |store_index| {
                            const store = ir.stores.get(store_index);
                            const source = ir.instructions.get(store.source);
                            const destination = ir.instructions.get(store.destination);
                            try writer.print("{s}, {s}", .{ @tagName(destination.u), @tagName(source.u) });
                        },
                        .call => |call_index| {
                            const call = ir.calls.get(call_index);

                            switch (call.callable) {
                                .function_definition => |definition_index| try writer.print("${} {s}(", .{ definition_index.uniqueInteger(), ir.getFunctionName(definition_index) }),
                            }

                            for (call.arguments, 0..) |arg_index, i| {
                                const arg_value = ir.instructions.get(arg_index);

                                try writer.print("${}: {s}", .{ i, @tagName(arg_value.u) });

                                if (i < call.arguments.len - 1) {
                                    try writer.writeAll(", ");
                                }
                            }
                            try writer.writeAll(")");
                        },
                        .constant_integer => |integer| {
                            try writer.print("{s} (unsigned: 0x{x}, signed {})", .{ @tagName(integer.type), integer.value.unsigned, integer.value.signed });
                        },
                        .@"unreachable" => {},
                        .constant_string_literal => |string_literal_index| {
                            const string_literal = ir.string_literals.get(string_literal_index);
                            try writer.print("at 0x{x}", .{string_literal.offset});
                        },
                        .stack_slot => |stack_index| {
                            const stack = ir.stack_slots.get(stack_index);
                            try writer.print("size: {}. alignment: {}", .{ stack.type.getSize(), stack.type.getAlignment() });
                        },
                        .argument => |argument_index| {
                            const argument = ir.arguments.get(argument_index);
                            try writer.print("${}, size: {}. alignment: {}", .{ argument_index, argument.type.getSize(), argument.type.getAlignment() });
                        },
                        .sign_extend => |cast_index| {
                            const cast = ir.casts.get(cast_index);
                            try writer.print("{s} ${}", .{ @tagName(cast.type), cast.value.uniqueInteger() });
                        },
                        .load => |load_index| {
                            const load = ir.loads.get(load_index);
                            try writer.print("${}", .{load.value.uniqueInteger()});
                        },
                        .binary_operation => |binary_operation_index| {
                            const binary_operation = ir.binary_operations.get(binary_operation_index);
                            try writer.writeAll(@tagName(binary_operation.id));
                            try writer.print("${}, ${}", .{ binary_operation.left.uniqueInteger(), binary_operation.right.uniqueInteger() });
                        },
                        .branch => |branch_index| {
                            const branch = ir.branches.get(branch_index);
                            try writer.print("${}, #{}, #{}", .{ branch.condition.uniqueInteger(), branch.true_jump.uniqueInteger(), branch.false_jump.uniqueInteger() });
                        },
                        // else => |t| @panic(@tagName(t)),
                    }

                    try writer.writeByte('\n');
                }
            }
            _ = options;
            _ = fmt;
        }
    };

    pub const List = BlockList(@This());
    pub const Index = List.Index;
    pub const Allocation = List.Allocation;
};

const Phi = struct {
    operands: ArrayList(Phi.Operand) = .{},

    const Operand = struct {
        jump: Jump.Index,
        value: Instruction.Index,
    };

    pub const List = BlockList(@This());
    pub const Index = List.Index;
    pub const Allocation = List.Allocation;
};

pub const Call = struct {
    callable: Callable.Index,
    arguments: []const Instruction.Index,

    pub const List = BlockList(@This());
    pub const Index = List.Index;
    pub const Allocation = List.Allocation;
};

pub const Instruction = struct {
    u: U,
    parent: BasicBlock.Index = BasicBlock.Index.invalid,

    pub const U = union(enum) {
        argument: Argument.Index,
        binary_operation: BinaryOperation.Index,
        branch: Branch.Index,
        call: Call.Index,
        constant_integer: ConstantInteger,
        constant_string_literal: StringLiteral.Index,
        jump: Jump.Index,
        load: Load.Index,
        phi: Phi.Index,
        ret: Return.Index,
        sign_extend: Cast.Index,
        stack_slot: StackSlot.Index,
        store: Store.Index,
        syscall: Syscall.Index,
        @"unreachable": void,
    };
    pub const List = BlockList(@This());
    pub const Index = List.Index;
    pub const Allocation = List.Allocation;
};

const ArgumentMap = AutoArrayHashMap(Compilation.Declaration.Index, Instruction.Index);

pub fn initialize(compilation: *Compilation, module: *Module) !*IR {
    const builder = try compilation.base_allocator.create(Builder);
    const allocator = compilation.base_allocator;
    builder.* = .{
        .allocator = allocator,
        .ir = .{
            .module = module,
            .section_manager = SectionManager{
                .allocator = allocator,
            },
            .entry_point = @bitCast(module.entry_point),
        },
    };

    _ = try builder.ir.section_manager.addSection(.{
        .name = ".text",
        .size_guess = 0,
        .alignment = 0x1000,
        .flags = .{
            .execute = true,
            .read = true,
            .write = false,
        },
        .type = .loadable_program,
    });

    var sema_function_definition_iterator = module.function_definitions.iterator();

    while (sema_function_definition_iterator.nextIndex()) |sema_function_definition_index| {
        builder.return_basic_block_index = BasicBlock.Index.invalid;
        builder.current_function_index = FunctionDefinition.Index.invalid;
        builder.current_basic_block_index = BasicBlock.Index.invalid;
        builder.return_phi_index = Instruction.Index.invalid;
        // const function_decl_name = builder.ir.getFunctionName(function_declaration_allocation.index);

        const function_name = module.getName(module.function_name_map.get(sema_function_definition_index).?).?;
        const sema_function_definition = module.function_definitions.get(sema_function_definition_index);
        const sema_prototype = builder.ir.module.function_prototypes.get(builder.ir.module.types.get(sema_function_definition.prototype).function);
        const function_calling_convention = sema_prototype.attributes.calling_convention;
        const returns = !sema_prototype.return_type.eq(Compilation.Type.noreturn);
        const function_return_type = try builder.translateType(sema_prototype.return_type);
        //         arguments:
        const function_argument_map = if (sema_prototype.arguments) |sema_arguments| blk: {
            var arg_map = ArgumentMap{};
            try arg_map.ensureTotalCapacity(builder.allocator, @intCast(sema_arguments.len));

            for (sema_arguments) |sema_argument_declaration_index| {
                const sema_argument_declaration = builder.ir.module.declarations.get(sema_argument_declaration_index);
                const argument_allocation = try builder.ir.arguments.append(builder.allocator, .{
                    .type = try builder.translateType(sema_argument_declaration.type) orelse unreachable,
                });
                const value_allocation = try builder.ir.instructions.append(builder.allocator, .{
                    .u = .{
                        .argument = argument_allocation.index,
                    },
                });
                arg_map.putAssumeCapacity(sema_argument_declaration_index, value_allocation.index);
            }

            break :blk arg_map;
        } else ArgumentMap{};

        const function_definition_allocation = try builder.ir.function_definitions.addOne(builder.allocator);
        function_definition_allocation.ptr.* = .{
            .callable = .{
                .argument_map = function_argument_map,
                .calling_convention = function_calling_convention,
                .return_type = function_return_type,
                .attributes = .{
                    .returns = returns,
                },
            },
        };
        const function_definition = function_definition_allocation.ptr;
        builder.current_function_index = function_definition_allocation.index;

        builder.return_basic_block_index = if (returns) blk: {
            const exit_block = try builder.ir.basic_blocks.append(builder.allocator, .{});
            const is_void = false;
            builder.return_phi_index = if (is_void) ret_value: {
                break :ret_value Instruction.Index.invalid;
            } else ret_value: {
                const phi = try builder.ir.phis.append(builder.allocator, .{});
                const phi_instruction = try builder.ir.instructions.append(builder.allocator, .{
                    .u = .{
                        .phi = phi.index,
                    },
                });

                try builder.appendToBlock(exit_block.index, phi_instruction.index);

                break :ret_value phi_instruction.index;
            };
            const ret = try builder.ir.returns.append(builder.allocator, .{
                .value = builder.return_phi_index,
            });
            const ret_instruction = try builder.ir.instructions.append(builder.allocator, .{
                .u = .{
                    .ret = ret.index,
                },
            });

            try builder.appendToBlock(exit_block.index, ret_instruction.index);

            break :blk exit_block.index;
        } else BasicBlock.Index.invalid;

        const function_body = module.blocks.get(sema_function_definition.body);

        if (function_body.statements.items.len > 0) {
            // Create the entry block and assign it to the function
            const entry_block = try builder.appendAndSetCurrentBlock();
            function_definition.entry_block = entry_block.index;

            // Process arguments. TODO: Currently we spill them to the stack just like LLVM, but surely there must be a better way
            try function_definition.stack_map.ensureUnusedCapacity(builder.allocator, @intCast(function_definition.callable.argument_map.keys().len));

            for (function_definition.callable.argument_map.keys(), function_definition.callable.argument_map.values()) |sema_argument_index, ir_argument_instruction_index| {
                const ir_argument_instruction = builder.ir.instructions.get(ir_argument_instruction_index);
                const ir_argument = builder.ir.arguments.get(ir_argument_instruction.u.argument);

                _ = try builder.createStackSlot(.{
                    .type = ir_argument.type,
                    .sema = sema_argument_index,
                });
            }

            for (function_definition.callable.argument_map.keys(), function_definition.callable.argument_map.values()) |sema_argument_index, ir_argument_instruction_index| {
                const stack_slot = function_definition.stack_map.get(sema_argument_index).?;

                const store = try builder.ir.stores.append(builder.allocator, .{
                    .destination = stack_slot,
                    .source = ir_argument_instruction_index,
                });

                _ = try builder.createInstructionAndAppendToCurrentBlock(.{
                    .store = store.index,
                });
            }
            // End processing arguments

            try builder.emitBlock(sema_function_definition.body);
        }

        if (function_body.reaches_end) {
            assert(returns);
            if (!function_definition.entry_block.invalid) {
                const jump_index = try builder.createJump(.{
                    .source = builder.current_basic_block_index,
                    .target = builder.return_basic_block_index,
                });
                _ = try builder.createInstructionAndAppendToCurrentBlock(.{
                    .jump = jump_index,
                });
            } else {
                function_definition.entry_block = builder.return_basic_block_index;
            }
        }

        assert(!function_definition.entry_block.invalid);

        if (std.mem.eql(u8, function_name, "main")) {
            logln(.ir, .function, "{}", .{FunctionDefinition.formatter(builder.allocator, function_definition_allocation.index, &builder.ir)});
        }
    }

    //unreachable;
    return &builder.ir;
}
