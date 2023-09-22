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

pub const Result = struct {
    functions: BlockList(Function) = .{},
    blocks: BlockList(BasicBlock) = .{},
    instructions: BlockList(Instruction) = .{},
    jumps: BlockList(Jump) = .{},
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
        print("\nFunction: {}\n", .{sema_function});

        try builder.function(sema_function);
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

const Instruction = union(enum) {
    jump: Jump.Index,
    phi: Phi.Index,
    ret: Ret,

    pub const List = BlockList(@This());
    pub const Index = List.Index;
};

const Phi = struct {
    foo: u32 = 0,
    pub const List = BlockList(@This());
    pub const Index = List.Index;
};

const Ret = struct {
    value: Instruction.Index,
};

pub const Jump = struct {
    source: BasicBlock.Index,
    destination: BasicBlock.Index,
    pub const List = BlockList(@This());
    pub const Index = List.Index;
};

const Function = struct {
    blocks: ArrayList(BasicBlock.Index) = .{},
    pub const List = BlockList(@This());
    pub const Index = List.Index;
};

pub const Builder = struct {
    allocator: Allocator,
    ir: Result = .{},
    module: *Module,
    current_basic_block: BasicBlock.Index = BasicBlock.Index.invalid,
    current_function_index: Function.Index = Function.Index.invalid,

    fn function(builder: *Builder, sema_function: Compilation.Function) !void {
        builder.current_function_index = try builder.ir.functions.append(builder.allocator, .{});
        // TODO: arguments
        builder.current_basic_block = try builder.newBlock();

        const return_type = builder.module.types.get(builder.module.function_prototypes.get(sema_function.prototype).return_type);
        const is_noreturn = return_type.* == .noreturn;
        if (!is_noreturn) {
            const exit_block = try builder.newBlock();
            const phi = try builder.appendToBlock(exit_block, .{
                .phi = Phi.Index.invalid,
            });
            const ret = try builder.appendToBlock(exit_block, .{
                .ret = .{
                    .value = phi,
                },
            });
            _ = ret;
        }
        const sema_block = sema_function.getBodyBlock(builder.module);
        try builder.block(sema_block, .{ .emit_exit_block = !is_noreturn });

        try builder.dumpFunction(std.io.getStdErr().writer(), builder.current_function_index);
    }

    fn dumpFunction(builder: *Builder, writer: anytype, index: Function.Index) !void {
        const f = builder.ir.functions.get(index);
        try writer.writeAll("Hello world!\n");
        print("Function blocks: {}\n", .{f.blocks.items.len});
        var function_instruction_index: usize = 0;
        for (f.blocks.items, 0..) |block_index, function_block_index| {
            print("#{}:\n", .{function_block_index});
            const function_block = builder.ir.blocks.get(block_index);
            for (function_block.instructions.items) |instruction_index| {
                const instruction = builder.ir.instructions.get(instruction_index);
                print("%{}: {}\n", .{ function_instruction_index, instruction });
                function_instruction_index += 1;
            }

            print("\n", .{});
        }
    }

    fn blockInsideBasicBlock(builder: *Builder, sema_block: *Compilation.Block, block_index: BasicBlock.Index) !BasicBlock.Index {
        builder.current_basic_block = block_index;
        try builder.block(sema_block, .{});
        return builder.current_basic_block;
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

                    const original_block = builder.current_basic_block;
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
                    builder.current_basic_block = try builder.blockInsideBasicBlock(sema_body_block, loop_body_block);
                    if (loop_prologue_block.valid) {
                        builder.ir.blocks.get(loop_prologue_block).seal();
                    }

                    if (sema_body_block.reaches_end) {
                        _ = try builder.append(.{
                            .jump = try builder.jump(.{
                                .source = builder.current_basic_block,
                                .destination = loop_head_block,
                            }),
                        });
                    }

                    builder.ir.blocks.get(builder.current_basic_block).filled = true;
                    builder.ir.blocks.get(loop_body_block).seal();
                    if (!loop_head_block.eq(loop_body_block)) {
                        unreachable;
                    }

                    if (loop_prologue_block.valid) {
                        builder.current_basic_block = loop_prologue_block;
                    }
                },
                else => |t| @panic(@tagName(t)),
            }
        }
    }

    fn jump(builder: *Builder, jump_descriptor: Jump) !Jump.Index {
        const destination_block = builder.ir.blocks.get(jump_descriptor.destination);
        assert(!destination_block.sealed);
        return try builder.ir.jumps.append(builder.allocator, jump_descriptor);
    }

    fn append(builder: *Builder, instruction: Instruction) !Instruction.Index {
        assert(builder.current_basic_block.valid);
        return builder.appendToBlock(builder.current_basic_block, instruction);
    }

    fn appendToBlock(builder: *Builder, block_index: BasicBlock.Index, instruction: Instruction) !Instruction.Index {
        const instruction_index = try builder.ir.instructions.append(builder.allocator, instruction);
        try builder.ir.blocks.get(block_index).instructions.append(builder.allocator, instruction_index);

        return instruction_index;
    }

    fn newBlock(builder: *Builder) !BasicBlock.Index {
        const new_block_index = try builder.ir.blocks.append(builder.allocator, .{});
        const current_function = builder.ir.functions.get(builder.current_function_index);
        const function_block_index = current_function.blocks.items.len;
        try current_function.blocks.append(builder.allocator, new_block_index);

        print("Adding block: {}\n", .{function_block_index});

        return new_block_index;
    }
};
