const std = @import("std");
const assert = std.debug.assert;
const equal = std.mem.eql;

const data_structures = @import("../data_structures.zig");
const Allocator = data_structures.Allocator;
const ArrayList = data_structures.ArrayList;

const emit = @import("emit.zig");
const page_size = 0x1000;

pub fn writeToMemory(image: *emit.Result) !std.ArrayListAlignedUnmanaged(u8, page_size) {
    var file = try std.ArrayListAlignedUnmanaged(u8, 0x1000).initCapacity(image.allocator, 0x100000);
    _ = try image.insertSection(0, .{
        .name = "",
        .size = page_size,
        .alignment = page_size,
        .flags = .{
            .read = true,
            .write = false,
            .execute = false,
        },
        .type = .loadable_program,
    });

    const symbol_table_index = try image.addSection(.{
        .name = ".symtab",
        .size = page_size,
        .alignment = @alignOf(SymbolTable.Entry),
        .flags = .{
            .read = false,
            .write = false,
            .execute = false,
        },
        .type = .symbol_table,
    });
    const string_table_index = try image.addSection(.{
        .name = ".strtab",
        .size = page_size,
        .alignment = 1,
        .flags = .{
            .read = false,
            .write = false,
            .execute = false,
        },
        .type = .string_table,
    });
    const section_header_string_table_index = try image.addSection(.{
        .name = ".shstrtab",
        .size = page_size,
        .alignment = 1,
        .flags = .{
            .read = false,
            .write = false,
            .execute = false,
        },
        .type = .string_table,
    });

    const base_virtual_address = 0x400000;
    const text_section_index = 1;

    const program_header_count = blk: {
        var result: usize = 0;
        for (image.sections.items) |section| {
            result += @intFromBool(switch (section.type) {
                .null => false,
                .loadable_program => true,
                .string_table => false,
                .symbol_table => false,
            });
        }
        break :blk result;
    };

    var symbol_name_offset: u32 = 0;

    image.writeToSection(symbol_table_index, std.mem.asBytes(&SymbolTable.Entry{
        .name_offset = symbol_name_offset,
        .information = 0,
        .other = 0,
        .section_header_index = 0,
        .value = 0,
        .size = 0,
    }));

    image.writeToSection(string_table_index, "");
    image.writeByteToSection(string_table_index, 0);
    symbol_name_offset += 1;

    for (image.sections.items) |section| {
        image.writeToSection(section_header_string_table_index, section.name);
        image.writeByteToSection(section_header_string_table_index, 0);
    }

    {
        var program_segment_offset: usize = 0;

        image.writeToSection(0, std.mem.asBytes(&Header{
            .endianness = .little,
            .machine = switch (image.target.cpu.arch) {
                .x86_64 => .AMD64,
                else => unreachable,
            },
            .os_abi = switch (image.target.os.tag) {
                .linux => .systemv,
                else => unreachable,
            },
            .entry = 0,
            .section_header_offset = 0,
            .program_header_count = @intCast(program_header_count),
            .section_header_count = @intCast(image.sections.items.len),
            .section_header_string_table_index = @intCast(section_header_string_table_index),
        }));

        for (image.sections.items, 0..) |section, section_index| {
            switch (section.type) {
                .loadable_program => {
                    program_segment_offset = std.mem.alignForward(usize, program_segment_offset, section.alignment);
                    const virtual_address = base_virtual_address + program_segment_offset;
                    const program_segment_size = switch (section_index) {
                        0 => @sizeOf(Header) + @sizeOf(ProgramHeader) * program_header_count,
                        else => section.index,
                    };
                    image.writeToSection(0, std.mem.asBytes(&ProgramHeader{
                        .type = .load,
                        .flags = ProgramHeader.Flags{
                            .executable = section.flags.execute,
                            .writable = section.flags.write,
                            .readable = section.flags.read,
                        },
                        .offset = program_segment_offset,
                        .virtual_address = virtual_address,
                        .physical_address = virtual_address,
                        .size_in_file = program_segment_size,
                        .size_in_memory = program_segment_size,
                        .alignment = section.alignment,
                    }));

                    program_segment_offset += program_segment_size;
                },
                .null,
                .string_table,
                .symbol_table,
                => {},
            }
        }
    }

    {
        var section_offset: usize = 0;
        var section_headers = try ArrayList(SectionHeader).initCapacity(image.allocator, image.sections.items.len);
        var section_name_offset: u32 = 0;

        for (image.sections.items, 0..) |section, section_i| {
            section_offset = std.mem.alignForward(usize, section_offset, section.alignment);
            const virtual_address = base_virtual_address + section_offset;

            for (section.symbol_table.keys(), section.symbol_table.values()) |symbol_name, symbol_offset| {
                const symbol_address = virtual_address + symbol_offset;
                image.writeToSection(symbol_table_index, std.mem.asBytes(&SymbolTable.Entry{
                    .name_offset = symbol_name_offset,
                    .information = 0x10,
                    .other = 0,
                    .section_header_index = @intCast(section_i),
                    .value = symbol_address,
                    .size = 0,
                }));

                image.writeToSection(string_table_index, symbol_name);
                image.writeByteToSection(string_table_index, 0);

                symbol_name_offset += @intCast(symbol_name.len + 1);
            }

            const source = section.content[0..section.index];
            file.items.len = section_offset + source.len;
            try file.replaceRange(image.allocator, section_offset, source.len, source);

            section_headers.appendAssumeCapacity(SectionHeader{
                .name_offset = section_name_offset,
                .type = switch (section_i) {
                    0 => .null,
                    else => switch (section.type) {
                        .loadable_program => .program_data,
                        .string_table => .string_table,
                        .symbol_table => .symbol_table,
                        .null => .null,
                    },
                },
                .flags = .{
                    .alloc = true,
                    .executable = section.flags.execute,
                    .writable = section.flags.write,
                },
                .virtual_address = virtual_address,
                .file_offset = section_offset,
                .size = section.index,
                .link = switch (section.type) {
                    .symbol_table => @intCast(string_table_index),
                    else => 0,
                },
                .info = switch (section.type) {
                    .symbol_table => 1,
                    else => 0,
                },
                .alignment = 0,
                .entry_size = switch (section.type) {
                    .symbol_table => @sizeOf(SymbolTable.Entry),
                    else => 0,
                },
            });

            section_offset += section.index;
            section_name_offset += @intCast(section.name.len + 1);
        }

        const section_header_offset = std.mem.alignForward(usize, section_offset, @alignOf(SectionHeader));
        const section_header_bytes = std.mem.sliceAsBytes(section_headers.items);
        try file.ensureTotalCapacity(image.allocator, section_header_offset + section_header_bytes.len);
        file.items.len = section_header_offset + section_header_bytes.len;
        try file.replaceRange(image.allocator, section_header_offset, section_header_bytes.len, section_header_bytes);

        const _start_offset = blk: {
            const entry_offset = image.sections.items[text_section_index].symbol_table.values()[image.entry_point];
            const text_section_virtual_address = section_headers.items[text_section_index].virtual_address;
            break :blk text_section_virtual_address + entry_offset;
        };

        const header: *Header = @ptrCast(file.items.ptr);
        header.section_header_offset = section_header_offset;
        header.entry = _start_offset;
    }

    return file;
}

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
    section_header_string_table_index: u16,

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
    type: Type,
    flags: Flags,
    offset: u64,
    virtual_address: u64,
    physical_address: u64,
    size_in_file: u64,
    size_in_memory: u64,
    alignment: u64,

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
    virtual_address: u64,
    file_offset: u64,
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

const SymbolTable = extern struct {
    const Entry = extern struct {
        name_offset: u32,
        information: u8,
        other: u8,
        section_header_index: u16,
        value: u64,
        size: u64,
    };
};
