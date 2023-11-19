const std = @import("std");
const Allocator = std.mem.Allocator;
const log = std.log;
const page_size = std.mem.page_size;
const assert = std.debug.assert;
const expect = std.testing.expect;
const expectEqual = std.testing.expectEqual;

const Compilation = @import("../Compilation.zig");

const ir = @import("intermediate_representation.zig");
const IR = ir.IR;

const data_structures = @import("../data_structures.zig");
const ArrayList = data_structures.ArrayList;
const ArrayListAligned = data_structures.ArrayListAligned;
const AutoHashMap = data_structures.AutoHashMap;
const mmap = data_structures.mmap;

const elf = @import("elf.zig");
const pe = @import("pe.zig");
const macho = @import("macho.zig");

const jit_callconv = .SysV;

const Section = struct {
    bytes: ArrayListAligned(u8, page_size),
    symbol_table: std.StringArrayHashMapUnmanaged(u32) = .{},
    name: []const u8,
    alignment: u32,
    flags: Section.Flags,
    type: Section.Type,

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

const SectionCreation = struct {
    name: []const u8,
    size_guess: usize,
    alignment: u32,
    flags: Section.Flags,
    type: Section.Type,
};

const Relocation = struct {
    source: struct {
        offset: u32,
        index: u16,
    },
    target: struct {
        offset: u32,
        index: u16,
    },
    offset: i8,
};

pub const SectionManager = struct {
    sections: ArrayList(Section) = .{},
    rodata: ?u16 = null,
    null: bool = false,
    linker_relocations: ArrayList(Relocation) = .{},
    allocator: Allocator,

    pub fn addSection(section_manager: *SectionManager, arguments: SectionCreation) !usize {
        const index = section_manager.sections.items.len;

        const r = try section_manager.insertSection(index, arguments);
        assert(index == r);

        return index;
    }

    pub fn getTextSectionIndex(section_manager: *const SectionManager) u16 {
        return @intCast(@intFromBool(section_manager.null));
    }

    pub fn getTextSection(section_manager: *SectionManager) *Section {
        return &section_manager.sections.items[section_manager.getTextSectionIndex()];
    }

    pub fn insertSection(section_manager: *SectionManager, index: usize, arguments: SectionCreation) !usize {
        try section_manager.sections.insert(section_manager.allocator, index, .{
            .bytes = try ArrayListAligned(u8, page_size).initCapacity(section_manager.allocator, arguments.size_guess),
            .alignment = arguments.alignment,
            .name = arguments.name,
            .flags = arguments.flags,
            .type = arguments.type,
        });

        return index;
    }

    pub fn addNullSection(section_manager: *SectionManager) !void {
        const index = try section_manager.insertSection(0, .{
            .name = "",
            .size_guess = page_size,
            .alignment = page_size,
            .flags = .{
                .read = true,
                .write = false,
                .execute = false,
            },
            .type = .loadable_program,
        });
        assert(index == 0);

        section_manager.null = true;
    }

    pub fn appendByteToSection(section_manager: *SectionManager, section_index: usize, byte: u8) !void {
        try section_manager.sections.items[section_index].bytes.append(section_manager.allocator, byte);
    }

    pub fn appendToSection(section_manager: *SectionManager, section_index: usize, bytes: []const u8) !void {
        try section_manager.sections.items[section_index].bytes.appendSlice(section_manager.allocator, bytes);
    }

    pub fn getSectionOffset(section_manager: *SectionManager, section_index: usize) usize {
        return section_manager.sections.items[section_index].bytes.items.len;
    }

    pub fn getCodeOffset(section_manager: *SectionManager) usize {
        return section_manager.getSectionOffset(text_section_index);
    }

    pub fn appendCode(section_manager: *SectionManager, code: []const u8) !void {
        try section_manager.appendToSection(text_section_index, code);
    }

    pub fn appendCodeByte(section_manager: *SectionManager, code_byte: u8) !void {
        try section_manager.appendByteToSection(text_section_index, code_byte);
    }

    const text_section_index = 0;
};

pub const Result = struct {
    section_manager: SectionManager,
    entry_point: u32,
    target: std.Target,

    pub fn create(section_manager: SectionManager, target: std.Target, entry_point_index: u32) !Result {
        var result = Result{
            .section_manager = section_manager,
            .target = target,
            .entry_point = entry_point_index,
        };

        return result;
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
        pub fn initialize(allocator: Allocator, intermediate: *IR, descriptor: Compilation.Module.Descriptor) !void {
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
