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
    alignment: u32,
    name: []const u8,
    flags: Flags,
    type: Type,
    symbol_table: std.StringArrayHashMapUnmanaged(u32) = .{},

    const Type = enum {
        null,
        loadable_program,
        string_table,
        symbol_table,
    };

    const Flags = packed struct {
        read: bool,
        write: bool,
        execute: bool,
    };
};

pub const Result = struct {
    sections: ArrayList(Section) = .{},
    // sections: struct {
    //     text: Section,
    //     rodata: Section,
    //     data: Section,
    // },
    entry_point: u32,
    target: std.Target,
    allocator: Allocator,

    const text_section_index = 0;

    pub fn create(allocator: Allocator, target: std.Target, entry_point_index: u32) !Result {
        var result = Result{
            // .sections = .{
            //     .text = .{ .content = try mmap(page_size, .{ .executable = true }) },
            //     .rodata = .{ .content = try mmap(page_size, .{ .executable = false }) },
            //     .data = .{ .content = try mmap(page_size, .{ .executable = false }) },
            // },
            .target = target,
            .allocator = allocator,
            .entry_point = entry_point_index,
        };

        _ = try result.addSection(.{
            .name = ".text",
            .size = 0x1000,
            .alignment = 0x1000,
            .flags = .{
                .execute = true,
                .read = true,
                .write = false,
            },
            .type = .loadable_program,
        });

        return result;
    }

    const SectionCreation = struct {
        name: []const u8,
        size: usize,
        alignment: u32,
        flags: Section.Flags,
        type: Section.Type,
    };

    pub fn addSection(result: *Result, arguments: SectionCreation) !usize {
        const index = result.sections.items.len;
        assert(std.mem.isAligned(arguments.size, page_size));

        try result.sections.append(result.allocator, .{
            .content = try mmap(arguments.size, .{ .executable = arguments.flags.execute }),
            .alignment = arguments.alignment,
            .name = arguments.name,
            .flags = arguments.flags,
            .type = arguments.type,
        });

        return index;
    }

    pub fn insertSection(result: *Result, index: usize, arguments: SectionCreation) !usize {
        assert(std.mem.isAligned(arguments.size, page_size));
        try result.sections.insert(result.allocator, index, .{
            .content = try mmap(arguments.size, .{ .executable = arguments.flags.execute }),
            .alignment = arguments.alignment,
            .name = arguments.name,
            .flags = arguments.flags,
            .type = arguments.type,
        });

        return index;
    }

    pub fn alignSection(result: *Result, index: usize, alignment: usize) void {
        const index_ptr = &result.sections.items[index].index;
        index_ptr.* = std.mem.alignForward(usize, index_ptr.*, alignment);
    }

    pub fn writeToSection(image: *Result, section_index: usize, bytes: []const u8) void {
        const section = &image.sections.items[section_index];
        const destination = section.content[section.index..][0..bytes.len];
        @memcpy(destination, bytes);
        section.index += bytes.len;
    }

    pub fn writeByteToSection(image: *Result, section_index: usize, byte: u8) void {
        const section = &image.sections.items[section_index];
        section.content[section.index] = byte;
        section.index += 1;
    }

    pub fn getTextSection(result: *Result) *Section {
        return &result.sections.items[0];
    }

    pub fn appendCode(image: *Result, code: []const u8) void {
        image.writeToSection(text_section_index, code);
    }

    pub fn appendCodeByte(image: *Result, code_byte: u8) void {
        image.writeByteToSection(text_section_index, code_byte);
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

    fn writeElf(image: *Result, executable_relative_path: []const u8) !void {
        const file_in_memory = try elf.writeToMemory(image);
        try writeFile(file_in_memory.items, executable_relative_path);
    }

    fn writeFile(bytes: []const u8, path: []const u8) !void {
        const flags = switch (@import("builtin").os.tag) {
            .windows => .{},
            else => .{
                .mode = 0o777,
            },
        };

        const file_descriptor = try std.fs.cwd().createFile(path, flags);
        try file_descriptor.writeAll(bytes);
        file_descriptor.close();
    }

    fn writePe(image: *Result, executable_relative_path: []const u8) !void {
        _ = executable_relative_path;
        _ = image;
        // var writer = try pe.Writer.init(allocator);
        // try writer.writeToMemory(image);
        // try writer.writeToFile(executable_relative_path);
        unreachable;
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

const x86_64 = @import("x86_64.zig");
const aarch64 = @import("aarch64.zig");

pub const Logger = x86_64.Logger;

pub fn get(comptime arch: std.Target.Cpu.Arch) type {
    const backend = switch (arch) {
        .x86_64 => x86_64,
        .aarch64 => aarch64,
        else => {},
    };

    return struct {
        pub fn initialize(allocator: Allocator, intermediate: *ir.Result, descriptor: Compilation.Module.Descriptor) !void {
            switch (arch) {
                .x86_64 => {
                    var mir = try backend.MIR.selectInstructions(allocator, intermediate, descriptor.target);
                    try mir.allocateRegisters();
                    const os = descriptor.target.os.tag;
                    const image = try mir.encode();

                    switch (os) {
                        .linux => try image.writeElf(descriptor.executable_path),
                        .windows => try image.writePe(descriptor.executable_path),
                        else => unreachable,
                    }
                },
                else => {
                    const file = try std.fs.cwd().readFileAlloc(allocator, "main", std.math.maxInt(u64));
                    try macho.interpretFile(allocator, descriptor, file);
                },
            }

            // switch (@import("builtin").os.tag) {
            //     .linux => switch (@import("builtin").cpu.arch == arch) {
            //         true => {
            //             const entryPoint = result.getEntryPoint(fn () callconv(.SysV) noreturn);
            //             entryPoint();
            //         },
            //         false => {},
            //     },
            //     else => {},
            // }
        }
    };
}
