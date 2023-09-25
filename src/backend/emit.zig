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

pub const Result = struct {
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

    pub fn appendCode(image: *Result, code: []const u8) void {
        std.debug.print("New code: ", .{});
        for (code) |byte| {
            std.debug.print("0x{x} ", .{byte});
        }
        std.debug.print("\n", .{});
        const destination = image.sections.text.content[image.sections.text.index..][0..code.len];
        @memcpy(destination, code);
        image.sections.text.index += code.len;
    }

    pub fn appendCodeByte(image: *Result, code_byte: u8) void {
        std.debug.print("New code: 0x{x}\n", .{code_byte});
        image.sections.text.content[image.sections.text.index] = code_byte;
        image.sections.text.index += 1;
    }

    // fn appendOnlyOpcodeSkipInstructionBytes(image: *Result, instruction: Instruction) void {
    //     const instruction_descriptor = instruction_descriptors.get(instruction);
    //     assert(instruction_descriptor.opcode_byte_count == instruction_descriptor.operand_offset);
    //     image.appendCode(instruction_descriptor.getOpcode());
    //
    //     image.sections.text.index += instruction_descriptor.size - instruction_descriptor.opcode_byte_count;
    // }

    fn getEntryPoint(image: *const Result, comptime FunctionType: type) *const FunctionType {
        comptime {
            assert(@typeInfo(FunctionType) == .Fn);
        }

        assert(image.sections.text.content.len > 0);
        return @as(*const FunctionType, @ptrCast(&image.sections.text.content[image.entry_point]));
    }
};

pub fn InstructionSelector(comptime Instruction: type) type {
    return struct {
        functions: ArrayList(Function),
        allocator: Allocator,

        pub const Function = struct {
            instructions: ArrayList(Instruction) = .{},
            block_byte_counts: ArrayList(u16),
            block_offsets: ArrayList(u32),
            relocations: ArrayList(u32) = .{},
            block_map: AutoHashMap(ir.BasicBlock.Index, u32) = .{},
            byte_count: u32 = 0,
            block_byte_count: u16 = 0,

            pub fn selectInstruction(function: *Function, allocator: Allocator, instruction: Instruction) !void {
                try function.instructions.append(allocator, instruction);
                function.block_byte_count += Instruction.descriptors.get(instruction).size;
            }
        };

        const Selector = @This();
    };
}

pub fn get(comptime arch: std.Target.Cpu.Arch) type {
    const backend = switch (arch) {
        .x86_64 => @import("x86_64.zig"),
        else => @compileError("Architecture not supported"),
    };
    const Instruction = backend.Instruction;

    return struct {
        pub fn initialize(allocator: Allocator, intermediate: *ir.Result) !void {
            var result = try Result.create();
            var function_iterator = intermediate.functions.iterator();
            const IS = InstructionSelector(Instruction);
            var instruction_selector = IS{
                .functions = try ArrayList(IS.Function).initCapacity(allocator, intermediate.functions.len),
                .allocator = allocator,
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
                    function.block_byte_count = 0;
                    for (block.instructions.items) |instruction_index| {
                        const instruction = intermediate.instructions.get(instruction_index).*;
                        try backend.selectInstruction(&instruction_selector, function, intermediate, instruction);
                    }

                    function.block_byte_counts.appendAssumeCapacity(function.block_byte_count);
                    function.byte_count += function.block_byte_count;
                }
            }

            for (instruction_selector.functions.items) |function| {
                for (function.instructions.items) |instruction| backend.emitInstruction(&result, instruction, intermediate);
            }

            // for (instruction_selector.functions.items) |function| {
            //     var fix_size: bool = false;
            //     _ = fix_size;
            //     for (function.relocations.items) |instruction_index| {
            //         const instruction = function.instructions.items[instruction_index];
            //         const relative = instruction.jmp_rel_8;
            //         const source_block = relative.source;
            //         const destination_block = relative.destination;
            //         const source_offset = function.block_offsets.items[source_block];
            //         const destination_offset = function.block_offsets.items[destination_block];
            //         std.debug.print("Source offset: {}. Destination: {}\n", .{ source_offset, destination_offset });
            //         const instruction_descriptor = instruction_descriptors.get(relative.instruction);
            //         const instruction_offset = source_offset + relative.block_offset;
            //         const really_source_offset = instruction_offset + instruction_descriptor.size;
            //         const displacement = @as(i64, destination_offset) - @as(i64, really_source_offset);
            //
            //         const operands = instruction_descriptor.getOperands();
            //         switch (operands.len) {
            //             1 => switch (operands[0].size) {
            //                 @sizeOf(u8) => {
            //                     if (displacement >= std.math.minInt(i8) and displacement <= std.math.maxInt(i8)) {
            //                         const writer_index = instruction_offset + instruction_descriptor.operand_offset;
            //                         std.debug.print("Instruction offset: {}. Operand offset: {}. Writer index: {}. displacement: {}\n", .{ instruction_offset, instruction_descriptor.operand_offset, writer_index, displacement });
            //                         result.sections.text.content[writer_index] = @bitCast(@as(i8, @intCast(displacement)));
            //                     } else {
            //                         unreachable;
            //                     }
            //                 },
            //                 else => unreachable,
            //             },
            //             else => unreachable,
            //         }
            //     }
            // }

            const text_section = result.sections.text.content[0..result.sections.text.index];
            for (text_section) |byte| {
                std.debug.print("0x{x}\n", .{byte});
            }
        }
    };
}
