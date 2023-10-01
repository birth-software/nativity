const std = @import("std");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;
const print = std.debug.print;

const Compilation = @import("../Compilation.zig");
const Module = Compilation.Module;
const Package = Compilation.Package;

const data_structures = @import("../data_structures.zig");
const ArrayList = data_structures.ArrayList;
const BlockList = data_structures.BlockList;
const AutoArrayHashMap = data_structures.AutoArrayHashMap;
const AutoHashMap = data_structures.AutoHashMap;

pub const Result = struct {
    blocks: BlockList(BasicBlock) = .{},
    calls: BlockList(Call) = .{},
    functions: BlockList(Function) = .{},
    instructions: BlockList(Instruction) = .{},
    jumps: BlockList(Jump) = .{},
    loads: BlockList(Load) = .{},
    phis: BlockList(Phi) = .{},
    stores: BlockList(Store) = .{},
    syscalls: BlockList(Syscall) = .{},
    values: BlockList(Value) = .{},
    stack_references: BlockList(StackReference) = .{},
};

pub fn initialize(compilation: *Compilation, module: *Module, package: *Package, main_file: Compilation.Type.Index) !Result {
    _ = main_file;
    _ = package;
    print("\nFunction count: {}\n", .{module.functions.len});

    var function_iterator = module.functions.iterator();
    var builder = Builder{
        .allocator = compilation.base_allocator,
        .module = module,
    };

    while (function_iterator.next()) |sema_function| {
        const function_index = try builder.buildFunction(sema_function);
        try builder.optimizeFunction(function_index);
    }

    var ir_function_iterator = builder.ir.functions.iterator();
    while (ir_function_iterator.nextPointer()) |function| {
        print("\n{}\n", .{function});
    }

    return builder.ir;
}

pub const BasicBlock = struct {
    instructions: ArrayList(Instruction.Index) = .{},
    incomplete_phis: ArrayList(Instruction.Index) = .{},
    filled: bool = false,
    sealed: bool = false,

    pub const List = BlockList(@This());
    pub const Index = List.Index;

    fn seal(basic_block: *BasicBlock) void {
        for (basic_block.incomplete_phis.items) |incomplete_phi| {
            _ = incomplete_phi;
            unreachable;
        }

        basic_block.sealed = true;
    }
};

pub const Instruction = union(enum) {
    call: Call.Index,
    jump: Jump.Index,
    load: Load.Index,
    phi: Phi.Index,
    ret: Value.Index,
    store: Store.Index,
    syscall: Value.Index,
    copy: Value.Index,
    @"unreachable",

    pub const List = BlockList(@This());
    pub const Index = List.Index;
};

const Phi = struct {
    value: Value.Index,
    jump: Jump.Index,
    block: BasicBlock.Index,
    next: Phi.Index,
    pub const List = BlockList(@This());
    pub const Index = List.Index;
};

pub const Jump = struct {
    source: BasicBlock.Index,
    destination: BasicBlock.Index,
    pub const List = BlockList(@This());
    pub const Index = List.Index;
};

const Syscall = struct {
    arguments: ArrayList(Value.Index),
    pub const List = BlockList(@This());
    pub const Index = List.Index;
};

const Load = struct {
    value: Value.Index,

    pub const List = BlockList(@This());
    pub const Index = List.Index;
};

const Store = struct {
    source: Value.Index,
    destination: Value.Index,
    pub const List = BlockList(@This());
    pub const Index = List.Index;
};

pub const StackReference = struct {
    size: u64,
    alignment: u64,
    offset: u64,
    pub const List = BlockList(@This());
    pub const Index = List.Index;
};

pub const Call = struct {
    function: Function.Index,

    pub const List = BlockList(@This());
    pub const Index = List.Index;
    pub const Allocation = List.Allocation;
};

pub const Value = union(enum) {
    integer: Compilation.Integer,
    load: Load.Index,
    call: Call.Index,
    stack_reference: StackReference.Index,
    phi: Phi.Index,
    instruction: Instruction.Index,
    syscall: Syscall.Index,
    pub const List = BlockList(@This());
    pub const Index = List.Index;

    pub fn isInMemory(value: Value) bool {
        return switch (value) {
            .integer => false,
            .load => true,
            .call => true,
            .stack_reference => true,
            .phi => unreachable,
            .instruction => unreachable,
            .syscall => unreachable,
        };
    }
};

pub const Function = struct {
    blocks: ArrayList(BasicBlock.Index) = .{},
    stack_map: AutoHashMap(Compilation.Declaration.Index, Value.Index) = .{},
    current_basic_block: BasicBlock.Index = BasicBlock.Index.invalid,
    return_phi_node: Instruction.Index = Instruction.Index.invalid,
    return_phi_block: BasicBlock.Index = BasicBlock.Index.invalid,
    ir: *Result,
    current_stack_offset: usize = 0,
    pub const List = BlockList(@This());
    pub const Index = List.Index;

    pub fn format(function: *const Function, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        try writer.writeAll("Function:\n");
        for (function.blocks.items, 0..) |block_index, function_block_index| {
            try writer.print("#{}:\n", .{function_block_index});
            const block = function.ir.blocks.get(block_index);
            for (block.instructions.items, 0..) |instruction_index, block_instruction_index| {
                try writer.print("%{}: ", .{block_instruction_index});
                const instruction = function.ir.instructions.get(instruction_index).*;
                try writer.print("{s}", .{@tagName(instruction)});
                try writer.writeByte('\n');
            }
            try writer.writeByte('\n');
        }
        _ = options;
        _ = fmt;
    }
};

pub const Builder = struct {
    allocator: Allocator,
    ir: Result = .{},
    module: *Module,
    current_function_index: Function.Index = Function.Index.invalid,

    fn currentFunction(builder: *Builder) *Function {
        return builder.ir.functions.get(builder.current_function_index);
    }

    fn buildFunction(builder: *Builder, sema_function: Compilation.Function) !Function.Index {
        const function_allocation = try builder.ir.functions.append(builder.allocator, .{
            .ir = &builder.ir,
        });
        builder.current_function_index = function_allocation.index;
        const function = function_allocation.ptr;
        // TODO: arguments
        function.current_basic_block = try builder.newBlock();

        const return_type = builder.module.types.get(builder.module.function_prototypes.get(sema_function.prototype).return_type);
        const is_noreturn = return_type.* == .noreturn;
        if (!is_noreturn) {
            const exit_block = try builder.newBlock();
            const phi_instruction = try builder.appendToBlock(exit_block, .{
                .phi = Phi.Index.invalid,
            });
            // phi.ptr.* = .{
            //     .value = Value.Index.invalid,
            //     .jump = Jump.Index.invalid,
            //     .block = exit_block,
            //     .next = Phi.Index.invalid,
            // };
            const ret = try builder.appendToBlock(exit_block, .{
                .ret = (try builder.ir.values.append(builder.allocator, .{
                    .instruction = phi_instruction,
                })).index,
            });
            _ = ret;
            function.return_phi_node = phi_instruction;
            function.return_phi_block = exit_block;
        }
        const sema_block = sema_function.getBodyBlock(builder.module);
        try builder.block(sema_block, .{ .emit_exit_block = !is_noreturn });

        builder.currentFunction().current_stack_offset = std.mem.alignForward(usize, builder.currentFunction().current_stack_offset, 0x10);

        return builder.current_function_index;
    }

    const BlockSearcher = struct {
        to_visit: ArrayList(BasicBlock.Index) = .{},
        visited: AutoArrayHashMap(BasicBlock.Index, void) = .{},
    };

    fn findReachableBlocks(builder: *Builder, first: BasicBlock.Index) ![]const BasicBlock.Index {
        var searcher = BlockSearcher{};
        try searcher.to_visit.append(builder.allocator, first);
        try searcher.visited.put(builder.allocator, first, {});

        while (searcher.to_visit.items.len > 0) {
            const block_index = searcher.to_visit.swapRemove(0);
            const block_to_visit = builder.ir.blocks.get(block_index);
            const last_instruction_index = block_to_visit.instructions.items[block_to_visit.instructions.items.len - 1];
            const last_instruction = builder.ir.instructions.get(last_instruction_index);
            switch (last_instruction.*) {
                .jump => |jump_index| {
                    const ir_jump = builder.ir.jumps.get(jump_index);
                    assert(ir_jump.source.eq(block_index));
                    const new_block = ir_jump.destination;
                    if (searcher.visited.get(new_block) == null) {
                        try searcher.to_visit.append(builder.allocator, new_block);
                        try searcher.visited.put(builder.allocator, new_block, {});
                    }
                },
                .@"unreachable", .ret => {},
                else => |t| @panic(@tagName(t)),
            }
        }

        return searcher.visited.keys();
    }

    fn optimizeFunction(builder: *Builder, function_index: Function.Index) !void {
        const function = builder.ir.functions.get(function_index);
        const reachable_blocks = try builder.findReachableBlocks(function.blocks.items[0]);
        var did_something = true;

        while (did_something) {
            did_something = false;
            for (reachable_blocks) |basic_block_index| {
                const basic_block = builder.ir.blocks.get(basic_block_index);
                for (basic_block.instructions.items) |instruction_index| {
                    did_something = did_something or try builder.removeUnreachablePhis(reachable_blocks, instruction_index);
                    did_something = did_something or try builder.removeTrivialPhis(instruction_index);
                    did_something = did_something or try builder.removeCopies(instruction_index);
                }
            }
        }
    }

    fn removeUnreachablePhis(builder: *Builder, reachable_blocks: []const BasicBlock.Index, instruction_index: Instruction.Index) !bool {
        const instruction = builder.ir.instructions.get(instruction_index);
        return switch (instruction.*) {
            .phi => blk: {
                var did_something = false;
                var head = &instruction.phi;
                next: while (head.valid) {
                    const phi = builder.ir.phis.get(head.*);
                    const phi_jump = builder.ir.jumps.get(phi.jump);
                    assert(phi_jump.source.valid);

                    for (reachable_blocks) |block_index| {
                        if (phi_jump.source.eq(block_index)) {
                            head = &phi.next;
                            continue :next;
                        }
                    }

                    head.* = phi.next;
                    did_something = true;
                }

                break :blk did_something;
            },
            else => false,
        };
    }

    fn removeTrivialPhis(builder: *Builder, instruction_index: Instruction.Index) !bool {
        const instruction = builder.ir.instructions.get(instruction_index);
        return switch (instruction.*) {
            .phi => |phi_index| blk: {
                const trivial_phi: ?Value.Index = trivial_blk: {
                    var only_value = Value.Index.invalid;
                    var it = phi_index;

                    while (it.valid) {
                        const phi = builder.ir.phis.get(it);
                        const phi_value = builder.ir.values.get(phi.value);
                        if (phi_value.* == .phi) unreachable;
                        // TODO: undefined
                        if (only_value.valid) {
                            if (!only_value.eq(phi.value)) {
                                break :trivial_blk null;
                            }
                        } else {
                            only_value = phi.value;
                        }

                        it = phi.next;
                    }

                    break :trivial_blk only_value;
                };

                if (trivial_phi) |trivial_value| {
                    if (trivial_value.valid) {
                        // Option to delete
                        const delete = false;
                        if (delete) {
                            unreachable;
                        } else {
                            instruction.* = .{
                                .copy = trivial_value,
                            };
                        }
                    } else {
                        unreachable;
                    }
                }

                break :blk instruction.* != .phi;
            },
            else => false,
        };
    }

    fn removeCopies(builder: *Builder, instruction_index: Instruction.Index) !bool {
        const instruction = builder.ir.instructions.get(instruction_index);
        return switch (instruction.*) {
            .copy => false,
            else => {
                var did_something = false;

                const operands: []const *Value.Index = switch (instruction.*) {
                    .jump, .@"unreachable" => &.{},
                    .ret => &.{&instruction.ret},
                    // TODO: arguments
                    .call => blk: {
                        var list = ArrayList(*Value.Index){};
                        break :blk list.items;
                    },
                    .store => |store_index| blk: {
                        const store_instr = builder.ir.stores.get(store_index);
                        break :blk &.{ &store_instr.source, &store_instr.destination };
                    },
                    .syscall => |syscall_value_index| blk: {
                        const syscall_value = builder.ir.values.get(syscall_value_index);
                        const syscall = builder.ir.syscalls.get(syscall_value.syscall);
                        var list = ArrayList(*Value.Index){};
                        try list.ensureTotalCapacity(builder.allocator, syscall.arguments.items.len);
                        for (syscall.arguments.items) |*arg| {
                            list.appendAssumeCapacity(arg);
                        }

                        break :blk list.items;
                    },
                    else => |t| @panic(@tagName(t)),
                };

                for (operands) |operand_value_index| {
                    const operand_value = builder.ir.values.get(operand_value_index.*);
                    switch (operand_value.*) {
                        .instruction => |operand_instruction_index| {
                            const operand_instruction = builder.ir.instructions.get(operand_instruction_index);
                            switch (operand_instruction.*) {
                                .copy => |copy_value| {
                                    operand_value_index.* = copy_value;
                                    did_something = true;
                                },
                                else => |t| @panic(@tagName(t)),
                            }
                        },
                        .integer, .stack_reference, .call => {},
                        else => |t| @panic(@tagName(t)),
                    }
                }

                return did_something;
            },
        };
    }

    fn blockInsideBasicBlock(builder: *Builder, sema_block: *Compilation.Block, block_index: BasicBlock.Index) !BasicBlock.Index {
        const current_function = builder.currentFunction();
        current_function.current_basic_block = block_index;
        try builder.block(sema_block, .{});
        return current_function.current_basic_block;
    }

    const BlockOptions = packed struct {
        emit_exit_block: bool = true,
    };

    fn block(builder: *Builder, sema_block: *Compilation.Block, options: BlockOptions) error{OutOfMemory}!void {
        for (sema_block.statements.items) |sema_statement_index| {
            const sema_statement = builder.module.values.get(sema_statement_index);
            switch (sema_statement.*) {
                .loop => |loop_index| {
                    const sema_loop = builder.module.loops.get(loop_index);
                    const sema_loop_condition = builder.module.values.get(sema_loop.condition);
                    const sema_loop_body = builder.module.values.get(sema_loop.body);
                    const condition: Compilation.Value.Index = switch (sema_loop_condition.*) {
                        .bool => |bool_value| switch (bool_value) {
                            true => Compilation.Value.Index.invalid,
                            false => unreachable,
                        },
                        else => |t| @panic(@tagName(t)),
                    };

                    const original_block = builder.currentFunction().current_basic_block;
                    const jump_to_loop = try builder.append(.{
                        .jump = undefined,
                    });
                    const loop_body_block = try builder.newBlock();
                    const loop_prologue_block = if (options.emit_exit_block) try builder.newBlock() else BasicBlock.Index.invalid;

                    const loop_head_block = switch (condition.valid) {
                        false => loop_body_block,
                        true => unreachable,
                    };

                    builder.ir.instructions.get(jump_to_loop).jump = try builder.jump(.{
                        .source = original_block,
                        .destination = loop_head_block,
                    });

                    const sema_body_block = builder.module.blocks.get(sema_loop_body.block);
                    builder.currentFunction().current_basic_block = try builder.blockInsideBasicBlock(sema_body_block, loop_body_block);
                    if (loop_prologue_block.valid) {
                        builder.ir.blocks.get(loop_prologue_block).seal();
                    }

                    if (sema_body_block.reaches_end) {
                        _ = try builder.append(.{
                            .jump = try builder.jump(.{
                                .source = builder.currentFunction().current_basic_block,
                                .destination = loop_head_block,
                            }),
                        });
                    }

                    builder.ir.blocks.get(builder.currentFunction().current_basic_block).filled = true;
                    builder.ir.blocks.get(loop_body_block).seal();
                    if (!loop_head_block.eq(loop_body_block)) {
                        unreachable;
                    }

                    if (loop_prologue_block.valid) {
                        builder.currentFunction().current_basic_block = loop_prologue_block;
                    }
                },
                .syscall => |syscall_index| {
                    const sema_syscall = builder.module.syscalls.get(syscall_index);
                    var arguments = try ArrayList(Value.Index).initCapacity(builder.allocator, sema_syscall.argument_count + 1);

                    const sema_syscall_number = sema_syscall.number;
                    assert(sema_syscall_number.valid);
                    const number_value_index = try builder.emitValue(sema_syscall_number);

                    arguments.appendAssumeCapacity(number_value_index);

                    for (sema_syscall.getArguments()) |sema_syscall_argument| {
                        assert(sema_syscall_argument.valid);
                        var argument_value_index = try builder.emitValue(sema_syscall_argument);
                        arguments.appendAssumeCapacity(argument_value_index);
                    }

                    // TODO: undo this mess
                    _ = try builder.append(.{
                        .syscall = (try builder.ir.values.append(builder.allocator, .{
                            .syscall = (try builder.ir.syscalls.append(builder.allocator, .{
                                .arguments = arguments,
                            })).index,
                        })).index,
                    });
                },
                .@"unreachable" => _ = try builder.append(.{
                    .@"unreachable" = {},
                }),
                .@"return" => |sema_ret_index| {
                    const sema_ret = builder.module.returns.get(sema_ret_index);
                    const return_value = try builder.emitValue(sema_ret.value);
                    const phi_instruction = builder.ir.instructions.get(builder.currentFunction().return_phi_node);
                    const phi = switch (phi_instruction.phi.valid) {
                        true => unreachable,
                        false => (try builder.ir.phis.append(builder.allocator, std.mem.zeroes(Phi))).ptr,
                    }; //builder.ir.phis.get(phi_instruction.phi);
                    const exit_jump = try builder.jump(.{
                        .source = builder.currentFunction().current_basic_block,
                        .destination = switch (phi_instruction.phi.valid) {
                            true => phi.block,
                            false => builder.currentFunction().return_phi_block,
                        },
                    });
                    print("Previous phi: {}\n", .{phi_instruction.phi});
                    phi_instruction.phi = (try builder.ir.phis.append(builder.allocator, .{
                        .value = return_value,
                        .jump = exit_jump,
                        .next = phi_instruction.phi,
                        .block = phi.block,
                    })).index;

                    _ = try builder.append(.{
                        .jump = exit_jump,
                    });
                },
                .declaration => |sema_declaration_index| {
                    const sema_declaration = builder.module.declarations.get(sema_declaration_index);
                    assert(sema_declaration.scope_type == .local);
                    const sema_init_value = builder.module.values.get(sema_declaration.init_value);
                    const declaration_type = builder.module.types.get(sema_init_value.getType(builder.module));
                    const size = declaration_type.getSize();
                    const alignment = declaration_type.getAlignment();
                    const stack_offset = switch (size > 0) {
                        true => builder.allocateStack(size, alignment),
                        false => 0,
                    };
                    var value_index = try builder.emitValue(sema_declaration.init_value);
                    const value = builder.ir.values.get(value_index);
                    print("Value: {}\n", .{value.*});
                    value_index = switch (value.isInMemory()) {
                        false => try builder.load(value_index),
                        true => value_index,
                    };

                    if (stack_offset > 0) {
                        _ = try builder.store(.{
                            .source = value_index,
                            .destination = try builder.stackReference(stack_offset, declaration_type.*, sema_declaration_index),
                        });
                    }
                },
                else => |t| @panic(@tagName(t)),
            }
        }
    }

    fn stackReference(builder: *Builder, stack_offset: u64, t: Compilation.Type, sema_declaration: Compilation.Declaration.Index) !Value.Index {
        const stack_reference_allocation = try builder.ir.stack_references.append(builder.allocator, .{
            .offset = stack_offset,
            .size = t.getSize(),
            .alignment = t.getAlignment(),
        });

        const value_allocation = try builder.ir.values.append(builder.allocator, .{
            .stack_reference = stack_reference_allocation.index,
        });

        try builder.currentFunction().stack_map.put(builder.allocator, sema_declaration, value_allocation.index);

        return value_allocation.index;
    }

    fn store(builder: *Builder, descriptor: Store) !void {
        const store_allocation = try builder.ir.stores.append(builder.allocator, descriptor);
        _ = try builder.append(.{
            .store = store_allocation.index,
        });
    }

    fn allocateStack(builder: *Builder, size: u64, alignment: u64) u64 {
        builder.currentFunction().current_stack_offset = std.mem.alignForward(u64, builder.currentFunction().current_stack_offset, alignment);
        builder.currentFunction().current_stack_offset += size;
        return builder.currentFunction().current_stack_offset;
    }

    fn load(builder: *Builder, value_index: Value.Index) !Value.Index {
        print("Doing load!\n", .{});

        const load_allocation = try builder.ir.loads.append(builder.allocator, .{
            .value = value_index,
        });
        const instruction_index = try builder.append(.{
            .load = load_allocation.index,
        });
        _ = instruction_index;
        const result = try builder.ir.values.append(builder.allocator, .{
            .load = load_allocation.index,
        });
        return result.index;
    }

    fn emitValue(builder: *Builder, sema_value_index: Compilation.Value.Index) !Value.Index {
        const sema_value = builder.module.values.get(sema_value_index).*;
        return switch (sema_value) {
            // TODO
            .integer => |integer| (try builder.ir.values.append(builder.allocator, .{
                .integer = integer,
            })).index,
            .call => |sema_call_index| {
                const sema_call = builder.module.calls.get(sema_call_index);
                const argument_list_index = sema_call.arguments;
                if (argument_list_index.valid) {
                    unreachable;
                }

                const call_index = try builder.call(.{
                    .function = switch (builder.module.values.get(sema_call.value).*) {
                        .function => |function_index| .{
                            .index = function_index.index,
                            .block = function_index.block,
                        },
                        else => |t| @panic(@tagName(t)),
                    },
                });

                _ = try builder.append(.{
                    .call = call_index,
                });

                const value_allocation = try builder.ir.values.append(builder.allocator, .{
                    .call = call_index,
                });

                return value_allocation.index;
            },
            .declaration_reference => |sema_declaration_index| {
                const sema_declaration = builder.module.declarations.get(sema_declaration_index);
                const sema_init_value = builder.module.values.get(sema_declaration.init_value);
                const init_type = sema_init_value.getType(builder.module);
                _ = init_type;
                switch (sema_declaration.scope_type) {
                    .local => {
                        const stack_reference = builder.currentFunction().stack_map.get(sema_declaration_index).?;
                        return stack_reference;
                    },
                    .global => unreachable,
                }
                // switch (sema_declaration.*) {
                //     else => |t| @panic(@tagName(t)),
                // }
            },
            else => |t| @panic(@tagName(t)),
        };
    }

    fn call(builder: *Builder, descriptor: Call) !Call.Index {
        const call_allocation = try builder.ir.calls.append(builder.allocator, descriptor);
        return call_allocation.index;
    }

    fn jump(builder: *Builder, descriptor: Jump) !Jump.Index {
        const destination_block = builder.ir.blocks.get(descriptor.destination);
        assert(!destination_block.sealed);
        const jump_allocation = try builder.ir.jumps.append(builder.allocator, descriptor);
        return jump_allocation.index;
    }

    fn append(builder: *Builder, instruction: Instruction) !Instruction.Index {
        assert(builder.current_function_index.valid);
        const current_function = builder.currentFunction();
        assert(current_function.current_basic_block.valid);
        return builder.appendToBlock(current_function.current_basic_block, instruction);
    }

    fn appendToBlock(builder: *Builder, block_index: BasicBlock.Index, instruction: Instruction) !Instruction.Index {
        if (instruction == .phi) {
            print("Adding phi: {}\n", .{instruction});
        }
        const instruction_allocation = try builder.ir.instructions.append(builder.allocator, instruction);
        try builder.ir.blocks.get(block_index).instructions.append(builder.allocator, instruction_allocation.index);

        return instruction_allocation.index;
    }

    fn newBlock(builder: *Builder) !BasicBlock.Index {
        const new_block_allocation = try builder.ir.blocks.append(builder.allocator, .{});
        const current_function = builder.ir.functions.get(builder.current_function_index);
        const function_block_index = current_function.blocks.items.len;
        try current_function.blocks.append(builder.allocator, new_block_allocation.index);

        print("Adding block: {}\n", .{function_block_index});

        return new_block_allocation.index;
    }
};
