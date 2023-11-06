const std = @import("std");
const Allocator = std.mem.Allocator;
const log = std.log;
const page_size = std.mem.page_size;
const assert = std.debug.assert;
const expect = std.testing.expect;
const expectEqual = std.testing.expectEqual;

const Compilation = @import("../Compilation.zig");

const ir = @import("intermediate_representation.zig");

const data_structures = @import("../data_structures.zig");
const ArrayList = data_structures.ArrayList;
const AutoHashMap = data_structures.AutoHashMap;
const mmap = data_structures.mmap;

const elf = @import("elf.zig");
const pe = @import("pe.zig");
const macho = @import("macho.zig");

const jit_callconv = .SysV;

const Section = struct {
    content: []align(page_size) u8,
    index: usize = 0,
    alignment: u32 = 0x10,
};

pub const Result = struct {
    sections: struct {
        text: Section,
        rodata: Section,
        data: Section,
    },
    entry_point: u32 = 0,
    target: std.Target,

    pub fn create(target: std.Target) !Result {
        return Result{
            .sections = .{
                .text = .{ .content = try mmap(page_size, .{ .executable = true }) },
                .rodata = .{ .content = try mmap(page_size, .{ .executable = false }) },
                .data = .{ .content = try mmap(page_size, .{ .executable = false }) },
            },
            .target = target,
        };
    }

    pub fn appendCode(image: *Result, code: []const u8) void {
        const destination = image.sections.text.content[image.sections.text.index..][0..code.len];
        @memcpy(destination, code);
        image.sections.text.index += code.len;
    }

    pub fn appendCodeByte(image: *Result, code_byte: u8) void {
        image.sections.text.content[image.sections.text.index] = code_byte;
        image.sections.text.index += 1;
    }

    fn getEntryPoint(image: *const Result, comptime FunctionType: type) *const FunctionType {
        if (@import("builtin").cpu.arch == .aarch64 and @import("builtin").os.tag == .macos) {
            data_structures.pthread_jit_write_protect_np(true);
        }
        comptime {
            assert(@typeInfo(FunctionType) == .Fn);
        }

        assert(image.sections.text.content.len > 0);
        return @as(*const FunctionType, @ptrCast(&image.sections.text.content[image.entry_point]));
    }

    fn writeElf(image: *const Result, allocator: Allocator, executable_relative_path: []const u8) !void {
        var writer = try elf.Writer.init(allocator);
        try writer.writeToMemory(image);
        try writer.writeToFile(executable_relative_path);
    }

    fn writePe(image: *const Result, allocator: Allocator, executable_relative_path: []const u8) !void {
        var writer = try pe.Writer.init(allocator);
        try writer.writeToMemory(image);
        try writer.writeToFile(executable_relative_path);
    }
};

pub fn InstructionSelector(comptime Instruction: type) type {
    return struct {
        functions: ArrayList(Function),
        allocator: Allocator,

        pub const Function = struct {
            instructions: ArrayList(Instruction) = .{},
            relocations: ArrayList(u32) = .{},
            block_map: AutoHashMap(ir.BasicBlock.Index, u32) = .{},

            pub fn addInstruction(function: *Function, allocator: Allocator, instruction: Instruction) !u32 {
                const index = function.instructions.items.len;
                try function.instructions.append(allocator, instruction);

                return @intCast(index);
            }
        };

        const Selector = @This();
    };
}

pub fn get(comptime arch: std.Target.Cpu.Arch) type {
    const backend = switch (arch) {
        .x86_64 => @import("x86_64.zig"),
        .aarch64 => @import("aarch64.zig"),
        else => {},
    };

    return struct {
        pub fn initialize(allocator: Allocator, intermediate: *ir.Result, descriptor: Compilation.Module.Descriptor) !void {
            switch (arch) {
                .x86_64 => {
                    var mir = try backend.MIR.selectInstructions(allocator, intermediate, descriptor.target);
                    try mir.allocateRegisters();
                    const os = descriptor.target.os.tag;
                    _ = os;
                    const image = try mir.encode();
                    _ = image;

                    // switch (os) {
                    //     .linux => try image.writeElf(allocator, descriptor.executable_path),
                    //     .windows => try image.writePe(allocator, descriptor.executable_path),
                    //     else => unreachable,
                    // }
                },
                else => {
                    const file = try std.fs.cwd().readFileAlloc(allocator, "main", std.math.maxInt(u64));
                    try macho.interpretFile(allocator, descriptor, file);
                },
            }

            // switch (@import("builtin").os.tag) {
            //     .linux => switch (@import("builtin").cpu.arch == arch) {
            //         true => {
            //             std.debug.print("Executing...\n", .{});
            //             const entryPoint = result.getEntryPoint(fn () callconv(.SysV) noreturn);
            //             entryPoint();
            //             std.debug.print("This should not print...\n", .{});
            //         },
            //         false => {},
            //     },
            //     else => {},
            // }
        }
    };
}
