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

    pub fn create() !Result {
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
                const jit = switch (os_tag) {
                    .macos => 0x800,
                    .linux => 0,
                    else => unreachable,
                };
                const execute_flag: switch (os_tag) {
                    .linux => u32,
                    .macos => c_int,
                    else => unreachable,
                } = if (flags.executable) std.os.PROT.EXEC else 0;
                const protection_flags: u32 = @intCast(std.os.PROT.READ | std.os.PROT.WRITE | execute_flag);
                const mmap_flags = std.os.MAP.ANONYMOUS | std.os.MAP.PRIVATE | jit;

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
        else => @compileError("Architecture not supported"),
    };

    return struct {
        pub fn initialize(allocator: Allocator, intermediate: *ir.Result) !void {
            std.debug.print("Entry point: {}\n", .{intermediate.entry_point});
            var mir = try backend.MIR.generate(allocator, intermediate);
            try mir.allocateRegisters(allocator, intermediate);
            const result = try mir.encode(intermediate);

            const text_section = result.sections.text.content[0..result.sections.text.index];
            for (text_section) |byte| {
                std.debug.print("0x{x}\n", .{byte});
            }

            switch (@import("builtin").os.tag) {
                .linux => switch (@import("builtin").cpu.arch == arch) {
                    true => {
                        std.debug.print("Executing...\n", .{});
                        const entryPoint = result.getEntryPoint(fn () callconv(.SysV) noreturn);
                        entryPoint();
                        std.debug.print("This should not print...\n", .{});
                    },
                    false => {},
                },
                else => {},
            }
        }
    };
}
