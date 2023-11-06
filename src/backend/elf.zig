const std = @import("std");
const assert = std.debug.assert;
const equal = std.mem.eql;

const data_structures = @import("../data_structures.zig");
const Allocator = data_structures.Allocator;
const ArrayList = data_structures.ArrayList;

const emit = @import("emit.zig");

pub const Writer = struct {
    bytes: ArrayList(u8),
    allocator: Allocator,

    pub fn init(allocator: Allocator) !Writer {
        return .{
            .bytes = try ArrayList(u8).initCapacity(allocator, 0x10000),
            .allocator = allocator,
        };
    }

    pub fn getHeader(writer: *Writer) *Header {
        return @ptrCast(@alignCast(writer.bytes.items.ptr));
    }

    pub fn writeToMemory(writer: *Writer, image: *const emit.Result) !void {
        const section_fields = @typeInfo(@TypeOf(image.sections)).Struct.fields;
        const section_count = blk: {
            var result: u16 = 0;
            inline for (section_fields) |section_field| {
                const section_size = @field(image.sections, section_field.name).index;
                result += @intFromBool(section_size > 0);
            }
            break :blk result;
        };

        const program_header_count = section_count;
        const program_start_offset = @sizeOf(Header) + program_header_count * @sizeOf(ProgramHeader);

        var section_offsets: [section_fields.len]u32 = undefined;

        const program_end_offset = blk: {
            var result: u32 = program_start_offset;
            inline for (section_fields, 0..) |section_field, section_index| {
                const section = &@field(image.sections, section_field.name);
                if (section.index > 0) {
                    const section_offset = std.mem.alignForward(u32, result, section.alignment);
                    section_offsets[section_index] = section_offset;
                    result = std.mem.alignForward(u32, section_offset + @as(u32, @intCast(section.index)), section.alignment);
                }
            }

            break :blk result;
        };

        const elf_file_end_offset = program_end_offset + @sizeOf(SectionHeader) * section_count;
        try writer.bytes.resize(writer.allocator, elf_file_end_offset);

        const base_address = 0x200000;

        writer.getHeader().* = Header{
            .endianness = .little,
            .machine = switch (image.target.cpu.arch) {
                .x86_64 => .AMD64,
                else => unreachable,
            },
            .os_abi = switch (image.target.os.tag) {
                .linux => .systemv,
                else => unreachable,
            },
            .entry = base_address + section_offsets[0] + image.entry_point,
            .section_header_offset = program_end_offset,
            .program_header_count = program_header_count,
            .section_header_count = section_count,
            .name_section_header_index = 0,
        };

        var program_header_offset: usize = @sizeOf(Header);
        var section_header_offset = program_end_offset;
        inline for (section_fields, section_offsets) |section_field, section_offset| {
            const section_name = section_field.name;
            const section = &@field(image.sections, section_name);
            if (section.index > 0) {
                const program_header: *ProgramHeader = @ptrCast(@alignCast(writer.bytes.items[program_header_offset..].ptr));
                program_header.* = .{
                    .type = .load,
                    .flags = .{
                        .executable = equal(u8, section_name, "text"),
                        .writable = equal(u8, section_name, "data"),
                        .readable = true,
                    },
                    .offset = 0,
                    .virtual_address = base_address,
                    .physical_address = base_address,
                    .size_in_file = section.index,
                    .size_in_memory = section.index,
                    .alignment = 0,
                };

                const source = section.content[0..section.index];
                const destination = writer.bytes.items[section_offset..][0..source.len];
                @memcpy(destination, source);

                const section_header: *SectionHeader = @ptrCast(@alignCast(writer.bytes.items[section_header_offset..].ptr));
                section_header.* = .{
                    .name_offset = 0,
                    .type = .program_data,
                    .flags = .{
                        .alloc = equal(u8, section_name, "text"),
                        .executable = equal(u8, section_name, "text"),
                        .writable = equal(u8, section_name, "data"),
                    },
                    .address = base_address + section_offset,
                    .offset = section_offset,
                    .size = section.index,
                    .link = 0,
                    .info = 0,
                    .alignment = 0,
                    .entry_size = 0,
                };
            }
        }
    }

    pub fn writeToFile(writer: *const Writer, file_path: []const u8) !void {
        std.debug.print("Writing file to {s}\n", .{file_path});
        const flags = switch (@import("builtin").os.tag) {
            .windows => .{},
            else => .{
                .mode = 0o777,
            },
        };
        const file_descriptor = try std.fs.cwd().createFile(file_path, flags);
        try file_descriptor.writeAll(writer.bytes.items);
        file_descriptor.close();
    }

    pub fn writeToFileAbsolute(writer: *const Writer, absolute_file_path: []const u8) !void {
        const file = try std.fs.createFileAbsolute(absolute_file_path, .{});
        defer file.close();
        try file.writeAll(writer.bytes.items);
    }
};

const Header = extern struct {
    magic: u8 = 0x7f,
    elf_id: [3]u8 = "ELF".*,
    bit_count: BitCount = .@"64",
    endianness: Endianness = .little,
    header_version: u8 = 1,
    os_abi: ABI,
    abi_version: u8 = 0,
    padding: [7]u8 = [_]u8{0} ** 7,
    object_type: ObjectFileType = .executable, // e_type
    machine: Machine,
    version: u32 = 1,
    entry: u64,
    program_header_offset: u64 = std.mem.alignForward(u16, @sizeOf(Header), @alignOf(ProgramHeader)),
    section_header_offset: u64,
    flags: u32 = 0,
    header_size: u16 = 0x40,
    program_header_size: u16 = @sizeOf(ProgramHeader),
    program_header_count: u16 = 1,
    section_header_size: u16 = @sizeOf(SectionHeader),
    section_header_count: u16,
    name_section_header_index: u16,

    const BitCount = enum(u8) {
        @"32" = 1,
        @"64" = 2,
    };

    const ABI = enum(u8) {
        systemv = 0,
    };

    const ObjectFileType = enum(u16) {
        none = 0,
        relocatable = 1,
        executable = 2,
        dynamic = 3,
        core = 4,
        lo_os = 0xfe00,
        hi_os = 0xfeff,
        lo_proc = 0xff00,
        hi_proc = 0xffff,
    };

    const Machine = enum(u16) {
        AMD64 = 0x3e,
    };

    const Endianness = enum(u8) {
        little = 1,
        big = 2,
    };
};

const ProgramHeader = extern struct {
    type: Type = .load,
    flags: Flags,
    offset: u64,
    virtual_address: u64,
    physical_address: u64,
    size_in_file: u64,
    size_in_memory: u64,
    alignment: u64 = 0,

    const Type = enum(u32) {
        null = 0,
        load = 1,
        dynamic = 2,
        interpreter = 3,
        note = 4,
        shlib = 5, // reserved
        program_header = 6,
        tls = 7,
        lo_os = 0x60000000,
        hi_os = 0x6fffffff,
        lo_proc = 0x70000000,
        hi_proc = 0x7fffffff,
    };

    const Flags = packed struct(u32) {
        executable: bool,
        writable: bool,
        readable: bool,
        reserved: u29 = 0,
    };
};
const SectionHeader = extern struct {
    name_offset: u32,
    type: Type,
    flags: Flags,
    address: u64,
    offset: u64,
    size: u64,
    // section index
    link: u32,
    info: u32,
    alignment: u64,
    entry_size: u64,

    // type
    const Type = enum(u32) {
        null = 0,
        program_data = 1,
        symbol_table = 2,
        string_table = 3,
        relocation_entries_addends = 4,
        symbol_hash_table = 5,
        dynamic_linking_info = 6,
        notes = 7,
        program_space_no_data = 8,
        relocation_entries = 9,
        reserved = 10,
        dynamic_linker_symbol_table = 11,
        array_of_constructors = 14,
        array_of_destructors = 15,
        array_of_pre_constructors = 16,
        section_group = 17,
        extended_section_indices = 18,
        number_of_defined_types = 19,
        start_os_specific = 0x60000000,
    };

    const Flags = packed struct(u64) {
        writable: bool,
        alloc: bool,
        executable: bool,
        reserved: bool = false,
        mergeable: bool = false,
        contains_null_terminated_strings: bool = false,
        info_link: bool = false,
        link_order: bool = false,
        os_non_conforming: bool = false,
        section_group: bool = false,
        tls: bool = false,
        _reserved: u53 = 0,
    };
};
