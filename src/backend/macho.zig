const std = @import("std");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;
const equal = std.mem.eql;
const print = std.debug.print;

const Compilation = @import("../Compilation.zig");

const data_structures = @import("../data_structures.zig");
const ArrayList = data_structures.ArrayList;
const mmap = data_structures.mmap;

const Header = extern struct {
    magic: u32 = magic,
    cpu_type: CpuType,
    cpu_subtype: extern union {
        arm: ArmSubType,
        x86: X86SubType,
    },
    file_type: FileType,
    load_command_count: u32,
    load_command_size: u32,
    flags: Flags,
    reserved: u32 = 0,

    const magic = 0xfeedfacf;

    const CpuType = enum(u32) {
        VAX = 0x00000001,
        ROMP = 0x00000002,
        NS32032 = 0x00000004,
        NS32332 = 0x00000005,
        MC680x0 = 0x00000006,
        x86 = 0x00000007,
        MIPS = 0x00000008,
        NS32352 = 0x00000009,
        MC98000 = 0x0000000A,
        HPPA = 0x0000000B,
        ARM = 0x0000000C,
        MC88000 = 0x0000000D,
        SPARC = 0x0000000E,
        i860be = 0x0000000F,
        i860_le = 0x00000010,
        RS6000 = 0x00000011,
        PowerPC = 0x00000012,
        arm64 = 0x0000000C | abi64,
        x86_64 = 0x00000007 | abi64,

        const abi64 = 0x01000000;
    };

    const ArmSubType = enum(u32) {
        all = 0x00000000,
        ARM_A500_ARCH = 0x00000001,
        ARM_A500 = 0x00000002,
        ARM_A440 = 0x00000003,
        ARM_M4 = 0x00000004,
        ARM_V4T = 0x00000005,
        ARM_V6 = 0x00000006,
        ARM_V5TEJ = 0x00000007,
        ARM_XSCALE = 0x00000008,
        ARM_V7 = 0x00000009,
        ARM_V7F = 0x0000000A,
        ARM_V7S = 0x0000000B,
        ARM_V7K = 0x0000000C,
        ARM_V8 = 0x0000000D,
        ARM_V6M = 0x0000000E,
        ARM_V7M = 0x0000000F,
        ARM_V7EM = 0x00000010,
        _,
    };

    const X86SubType = enum(u32) {
        All = 0x00000003,
        @"486" = 0x00000004,
        @"486SX" = 0x00000084,
        Pentium_M5 = 0x00000056,
        Celeron = 0x00000067,
        Celeron_Mobile = 0x00000077,
        Pentium_3 = 0x00000008,
        Pentium_3_M = 0x00000018,
        Pentium_3_XEON = 0x00000028,
        Pentium_4 = 0x0000000A,
        Itanium = 0x0000000B,
        Itanium_2 = 0x0000001B,
        XEON = 0x0000000C,
        XEON_MP = 0x0000001C,
        _,
    };

    const FileType = enum(u32) {
        relocatable_object = 0x00000001,
        demand_paged_executable = 0x00000002,
        fixed_vm_shared_library = 0x00000003,
        core = 0x00000004,
        preloaded_executable = 0x00000005,
        dynamic_shared_library = 0x00000006,
        dynamic_link_editor = 0x00000007,
        dynamic_bundle = 0x00000008,
        shared_library_stub = 0x00000009,
        debug_companion = 0x0000000A,
        x86_64_kext = 0x0000000B,
        archive = 0x0000000C,
    };

    const Flags = packed struct(u32) {
        no_undefined_references: bool = true,
        incrementally_linked: bool = false,
        dynamic_linker_input: bool = true,
        dynamic_linker_bound_undefined_references: bool = false,
        prebound_dynamic_undefined_references: bool = false,
        split_ro_and_rw_segments: bool = false,
        _: bool = false,
        two_level_namespace_bindings: bool = true,
        no_symbol_multiple_definition_in_subimages: bool = false,
        no_dyld_prebinding_agent_notification: bool = false,
        can_redo_prebinding: bool = false,
        bind_two_level_namespaces_to_libraries: bool = false,
        safe_to_split_sections_for_dead_code_stripping: bool = false,
        canonicalized_by_unprebinding: bool = false,
        final_external_weak_symbols: bool = false,
        final_weak_symbols: bool = false,
        all_stacks_execute_protected: bool = false,
        safe_for_zero_uid: bool = false,
        safe_for_ugid: bool = false,
        no_check_dependent_dylibs_for_reexport: bool = false,
        load_at_random_address: bool = false,
        no_load_command_for_unreferenced_dylib: bool = true,
        thread_local_variable_section: bool = false,
        run_with_non_executable_heap: bool = false,
        code_linked_for_application_use: bool = false,
        nlist_external_symbols_not_all_dyld_info_symbols: bool = false,
        allow_lc_min_version_macos_lc_build_version: bool = false,
        reserved: u4 = 0,
        dylib_only: bool = false,
    };
};

const UniversalHeader = extern struct {
    magic: u32 = magic,
    binary_count: u32,

    const magic = 0xcafebabe;
};

const LoadCommand = extern struct {
    type: Type,
    size: u32,

    const Type = enum(u32) {
        segment32 = 0x01,
        symbol_table = 0x02,
        symbol_table_information = 0x0b,
        load_dylib = 0x0c,
        id_dylib = 0x0d,
        load_dylinker = 0x0e,
        id_dylinker = 0x0f,
        optional_dynamic_library = 0x18,
        segment64 = 0x19,
        uuid_number = 0x1b,
        code_signature = 0x1d,
        compressed_linkedit_table = 0x22,
        function_starts = 0x26,
        data_in_code = 0x29,
        source_version = 0x2a,
        minimum_os_version = 0x32,
        dyld_exports_trie = 0x80000033,
        dyld_chained_fixups = 0x80000034,
        dyld_main_entry_point = 0x80000028,
    };

    const Segment64 = extern struct {
        type: Type = .segment64,
        size: u32,
        name: [16]u8,
        address: u64,
        address_size: u64,
        file_offset: u64,
        file_size: u64,
        maximum_virtual_memory_protections: VirtualMemoryProtection,
        initial_virtual_memory_protections: VirtualMemoryProtection,
        section_count: u32,
        flags: Flags,

        const VirtualMemoryProtection = packed struct(u32) {
            read: bool,
            write: bool,
            execute: bool,
            reserved: u29 = 0,
        };

        const Flags = packed struct(u32) {
            vm_space_high_part: bool = false,
            vm_fixed_library: bool = false,
            no_relocation: bool = false,
            protected_segment: bool = false,
            read_only_after_relocations: bool = false,
            reserved: u27 = 0,
        };

        const Section = extern struct {
            name: [16]u8,
            segment_name: [16]u8,
            address: u64,
            size: u64,
            file_offset: u32,
            alignment: u32,
            relocation_file_offset: u32,
            relocation_count: u32,
            type: Section.Type,
            reserved: u8 = 0,
            flags: Section.Flags,
            reserved0: u32 = 0,
            reserved1: u32 = 0,
            reserved2: u32 = 0,

            comptime {
                assert(@sizeOf(Section) == 80);
            }

            const Type = enum(u8) {
                regular = 0,
                only_non_lazy_symbol_pointers = 0b110,
                only_lazy_symbol_pointers_only_symbol_stubs = 0b111,
                zero_fill_on_demand_section = 0b1100,
                only_lazy_pointers_to_lazy_loaded_dylibs = 0b10000,
            };

            const Flags = packed struct(u16) {
                local_relocations: bool = false,
                external_relocations: bool = false,
                some_machine_instructions: bool = false,
                reserved: u5 = 0,
                reserved2: u1 = 0,
                debug_section: bool = false,
                i386_code_stubs: bool = false,
                live_blocks_if_reference_live_blocks: bool = false,
                no_dead_stripping: bool = false,
                strip_static_symbols_dyldlink_flag: bool = false,
                coalesced_symbols: bool = false,
                only_machine_instructions: bool = false,
            };
        };

        fn getSize(section_count: u32) u32 {
            return @sizeOf(LoadCommand.Segment64) + section_count * @sizeOf(LoadCommand.Segment64.Section);
        }
    };

    const LinkeditData = extern struct {
        type: Type,
        size: u32 = 16,
        data_offset: u32,
        data_size: u32,
    };

    const SymbolTable = extern struct {
        type: Type,
        size: u32 = 24,
        symbol_offset: u32,
        symbol_count: u32,
        string_table_offset: u32,
        string_table_size: u32,
    };

    const SymbolTableInformation = extern struct {
        type: Type,
        size: u32 = 80,
        local_symbol_index: u32,
        local_symbol_count: u32,
        external_symbol_index: u32,
        external_symbol_count: u32,
        undefined_symbol_index: u32,
        undefined_symbol_count: u32,
        content_table_offset: u32,
        content_table_entry_count: u32,
        module_table_offset: u32,
        module_table_entry_count: u32,
        referenced_symbol_table_offset: u32,
        referenced_symbol_table_entry_count: u32,
        indirect_symbol_table_offset: u32,
        indirect_symbol_table_entry_count: u32,
        external_relocation_offset: u32,
        external_relocation_entry_count: u32,
        local_relocation_offset: u32,
        local_relocation_entry_count: u32,
    };

    const Dylinker = extern struct {
        type: Type,
        size: u32,
        name_offset: u32 = 12,
    };

    const Dylib = extern struct {
        type: Type,
        size: u32,
        name_offset: u32,
        timestamp: u32,
        current_version: u32,
        compatibility_version: u32,
    };

    const Uuid = extern struct {
        type: Type,
        size: u32,
        uuid: [16]u8,
    };

    const MinimumVersion = extern struct {
        type: Type,
        size: u32,
        version: u32,
        sdk: u32,
    };

    const SourceVersion = extern struct {
        type: Type,
        size: u32,
        version: u64,
    };

    const EntryPoint = extern struct {
        type: Type,
        size: u32,
        entry_offset: u64,
        stack_size: u64,
    };
};

const Writer = struct {
    items: []u8,
    index: usize = 0,
    address_offset: usize = 0,
    file_offset: usize = 0,
    load_command_size: u32,
    segment_count: u16,
    segment_index: u16 = 0,
    segment_offset: u16 = @sizeOf(Header),
    linkedit_segment_address_offset: u64 = 0,
    linkedit_segment_file_offset: u64 = 0,
    linkedit_segment_size: u32 = 0,

    fn getWrittenBytes(writer: *const Writer) []const u8 {
        return writer.items[0..writer.index];
    }

    fn append(writer: *Writer, bytes: []const u8) void {
        writer.writeBytesAt(bytes, writer.index);
        writer.index += bytes.len;
    }

    fn writeBytesAt(writer: *Writer, bytes: []const u8, offset: usize) void {
        @memcpy(writer.items[offset..][0..bytes.len], bytes);
    }

    const SegmentCreation = struct {
        name: []const u8,
        sections: []const SectionCreation,
        protection: LoadCommand.Segment64.VirtualMemoryProtection,
    };

    const SectionCreation = struct {
        name: []const u8,
        bytes: []const u8,
        alignment: u32 = 1,
        flags: LoadCommand.Segment64.Section.Flags,
    };

    fn writeSegment(writer: *Writer, descriptor: SegmentCreation) void {
        assert(writer.segment_index < writer.segment_count);
        defer writer.segment_index += 1;

        const segment_name = blk: {
            var result = [1]u8{0} ** 16;
            @memcpy(result[0..descriptor.name.len], descriptor.name);
            break :blk result;
        };

        if (equal(u8, descriptor.name, "__PAGEZERO")) {
            assert(writer.segment_offset == @sizeOf(Header));
            const address_size = 4 * 1024 * 1024 * 1024;
            writer.writeBytesAt(std.mem.asBytes(&LoadCommand.Segment64{
                .size = @sizeOf(LoadCommand.Segment64),
                .name = segment_name,
                .address = 0,
                .address_size = address_size,
                .file_offset = 0,
                .file_size = 0,
                .maximum_virtual_memory_protections = descriptor.protection,
                .initial_virtual_memory_protections = descriptor.protection,
                .section_count = @intCast(descriptor.sections.len),
                .flags = .{},
            }), writer.segment_offset);

            writer.address_offset += address_size;
            writer.segment_offset += @sizeOf(LoadCommand.Segment64);
        } else if (equal(u8, descriptor.name, "__TEXT")) {
            const original_offset = writer.segment_offset;
            assert(original_offset == @sizeOf(Header) + @sizeOf(LoadCommand.Segment64));
            writer.segment_offset += @sizeOf(LoadCommand.Segment64);

            const text_metadata_offset = @sizeOf(Header) + writer.load_command_size;
            var section_address_offset = writer.address_offset + text_metadata_offset;
            var section_file_offset = writer.file_offset + text_metadata_offset;

            for (descriptor.sections) |section| {
                section_address_offset = std.mem.alignForward(usize, section_address_offset, section.alignment);
                section_file_offset = std.mem.alignForward(usize, section_file_offset, section.alignment);

                writer.writeBytesAt(std.mem.asBytes(&LoadCommand.Segment64.Section{
                    .name = blk: {
                        var result = [1]u8{0} ** 16;
                        @memcpy(result[0..section.name.len], section.name);
                        break :blk result;
                    },
                    .segment_name = segment_name,
                    .address = section_address_offset,
                    .size = section.bytes.len,
                    .file_offset = @intCast(section_file_offset),
                    .alignment = std.math.log2(section.alignment),
                    .relocation_file_offset = 0,
                    .relocation_count = 0,
                    .type = .regular,
                    .flags = section.flags,
                }), writer.segment_offset);

                @memcpy(writer.items[section_file_offset..][0..section.bytes.len], section.bytes);

                section_address_offset += section.bytes.len;
                section_file_offset += section.bytes.len;

                writer.segment_offset += @sizeOf(LoadCommand.Segment64.Section);
            }

            const end_segment_offset = writer.segment_offset;
            writer.segment_offset = original_offset;

            const size = end_segment_offset - writer.file_offset;
            const aligned_size = std.mem.alignForward(usize, size, 16 * 1024);

            writer.append(std.mem.asBytes(&LoadCommand.Segment64{
                .size = @sizeOf(LoadCommand.Segment64),
                .name = segment_name,
                .address = writer.address_offset,
                .address_size = aligned_size,
                .file_offset = writer.file_offset,
                .file_size = aligned_size,
                .maximum_virtual_memory_protections = descriptor.protection,
                .initial_virtual_memory_protections = descriptor.protection,
                .section_count = @intCast(descriptor.sections.len),
                .flags = .{},
            }));

            writer.segment_offset = end_segment_offset;

            writer.address_offset += aligned_size;
            writer.file_offset += aligned_size;
        } else {
            unreachable;
        }
    }

    fn writeLinkeditData(writer: *Writer, bytes: []const u8, load_command_type: LoadCommand.Type) void {
        if (writer.linkedit_segment_size == 0) {
            writer.linkedit_segment_address_offset = writer.address_offset;
            writer.linkedit_segment_file_offset = writer.file_offset;
        }

        const data_size: u32 = @intCast(bytes.len);
        @memcpy(writer.items[writer.file_offset..][0..data_size], bytes);

        writer.append(std.mem.asBytes(&LoadCommand.LinkeditData{
            .type = load_command_type,
            .data_offset = @intCast(writer.linkedit_segment_file_offset),
            .data_size = data_size,
        }));

        writer.address_offset += data_size;
        writer.file_offset += data_size;

        writer.linkedit_segment_size += data_size;
    }
};

pub fn interpretFile(allocator: Allocator, descriptor: Compilation.Module.Descriptor, file: []const u8) !void {
    _ = allocator;
    _ = descriptor;
    const header: *const Header = @ptrCast(@alignCast(file.ptr));
    print("Header : {}\n", .{header});
    assert(header.magic == Header.magic);

    var text_segment: LoadCommand.Segment64 = undefined;
    const load_command_start: *const LoadCommand = @ptrCast(@alignCast(file[@sizeOf(Header)..].ptr));
    var load_command_ptr = load_command_start;

    for (0..header.load_command_count) |_| {
        const load_command = load_command_ptr.*;
        switch (load_command.type) {
            .segment64 => {
                const segment_load_command: *const LoadCommand.Segment64 = @ptrCast(@alignCast(load_command_ptr));
                const text_segment_name = "__TEXT";
                if (equal(u8, segment_load_command.name[0..text_segment_name.len], text_segment_name)) {
                    text_segment = segment_load_command.*;
                }
                print("SLC: {}\n", .{segment_load_command});
                print("segment name: {s}\n", .{segment_load_command.name});
                const section_ptr: [*]const LoadCommand.Segment64.Section = @ptrFromInt(@intFromPtr(segment_load_command) + @sizeOf(LoadCommand.Segment64));
                const sections = section_ptr[0..segment_load_command.section_count];
                for (sections) |section| {
                    print("{}\n", .{section});
                    print("Section name: {s}. Segment name: {s}\n", .{ section.name, section.segment_name });
                }
            },
            .dyld_chained_fixups => {
                const command: *const LoadCommand.LinkeditData = @ptrCast(@alignCast(load_command_ptr));
                print("command: {}\n", .{command});
            },
            .dyld_exports_trie => {
                const command: *const LoadCommand.LinkeditData = @ptrCast(@alignCast(load_command_ptr));
                print("command: {}\n", .{command});
            },
            .symbol_table => {
                const command: *const LoadCommand.SymbolTable = @ptrCast(@alignCast(load_command_ptr));
                print("command: {}\n", .{command});
            },
            .symbol_table_information => {
                const command: *const LoadCommand.SymbolTableInformation = @ptrCast(@alignCast(load_command_ptr));
                print("command: {}\n", .{command});
            },
            .load_dylinker => {
                const command: *const LoadCommand.Dylinker = @ptrCast(@alignCast(load_command_ptr));
                print("command: {}\n", .{command});
                const name: [*:0]const u8 = @ptrFromInt(@intFromPtr(command) + command.name_offset);
                print("Name: {s}\n", .{name});
            },
            .uuid_number => {
                const command: *const LoadCommand.Uuid = @ptrCast(@alignCast(load_command_ptr));
                print("command: {}\n", .{command});
            },
            .minimum_os_version => {
                const command: *const LoadCommand.MinimumVersion = @ptrCast(@alignCast(load_command_ptr));
                print("command: {}\n", .{command});
            },
            .source_version => {
                const command: *const LoadCommand.SourceVersion = @ptrCast(@alignCast(load_command_ptr));
                print("command: {}\n", .{command});
            },
            .dyld_main_entry_point => {
                const command: *const LoadCommand.EntryPoint = @ptrCast(@alignCast(load_command_ptr));
                print("command: {}\n", .{command});
            },
            .load_dylib => {
                const command: *const LoadCommand.Dylib = @ptrCast(@alignCast(load_command_ptr));
                print("command: {}\n", .{command});
                print("Dylib: {s}\n", .{@as([*:0]const u8, @ptrFromInt(@intFromPtr(load_command_ptr) + @sizeOf(LoadCommand.Dylib)))});
            },
            .function_starts => {
                const command: *const LoadCommand.LinkeditData = @ptrCast(@alignCast(load_command_ptr));
                print("command: {}\n", .{command});
            },
            .data_in_code => {
                const command: *const LoadCommand.LinkeditData = @ptrCast(@alignCast(load_command_ptr));
                print("command: {}\n", .{command});
            },
            .code_signature => {
                const command: *const LoadCommand.LinkeditData = @ptrCast(@alignCast(load_command_ptr));
                print("command: {}\n", .{command});
            },
            else => |t| @panic(@tagName(t)),
        }

        load_command_ptr = @ptrFromInt(@intFromPtr(load_command_ptr) + load_command.size);
    }

    // const load_command_end = load_command_ptr;
    // const load_command_size = @intFromPtr(load_command_end) - @intFromPtr(load_command_start);
    // assert(load_command_size == header.load_command_size);

    const segment_count = 3;
    var writer = Writer{
        .items = try mmap(0x100000, .{}),
        .load_command_size = segment_count * @sizeOf(LoadCommand.Segment64) +
            2 * @sizeOf(LoadCommand.Segment64.Section) +
            @sizeOf(LoadCommand.LinkeditData) +
            @sizeOf(LoadCommand.LinkeditData) +
            @sizeOf(LoadCommand.SymbolTable) +
            @sizeOf(LoadCommand.SymbolTableInformation) +
            @sizeOf(LoadCommand.Dylinker) + std.mem.alignForward(u32, "/usr/lib/dyld".len, 8) +
            @sizeOf(LoadCommand.Uuid) +
            @sizeOf(LoadCommand.MinimumVersion) +
            @sizeOf(LoadCommand.EntryPoint) +
            @sizeOf(LoadCommand.Dylib) + std.mem.alignForward(u32, "/usr/lib/libSystem.B.dylib".len, 8) +
            3 * @sizeOf(LoadCommand.LinkeditData),
        .segment_count = segment_count,
    };
    writer.index = @sizeOf(Header);
    writer.writeSegment(.{
        .name = "__PAGEZERO",
        .sections = &.{},
        .protection = .{
            .read = false,
            .write = false,
            .execute = false,
        },
    });
    writer.writeSegment(.{
        .name = "__TEXT",
        .sections = &.{
            .{
                .name = "__text",
                .bytes = &.{
                    0x00, 0x00, 0x80, 0x52,
                    0xc0, 0x03, 0x5f, 0xd6,
                },
                .alignment = 4,
                .flags = .{
                    .only_machine_instructions = true,
                },
            },
            .{
                .name = "__unwind_info",
                .bytes = &.{
                    0x01, 0x00, 0x00, 0x00,
                    0x1c, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00,
                    0x1c, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00,
                    0x1c, 0x00, 0x00, 0x00,
                    0x02, 0x00, 0x00, 0x00,
                    0xb0, 0x3f, 0x00, 0x00,
                    0x34, 0x00, 0x00, 0x00,
                    0x34, 0x00, 0x00, 0x00,
                    0xb9, 0x3f, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00,
                    0x34, 0x00, 0x00, 0x00,
                    0x03, 0x00, 0x00, 0x00,
                    0x0c, 0x00, 0x01, 0x00,
                    0x10, 0x00, 0x01, 0x00,
                    0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x02,
                },
                .alignment = 4,
                .flags = .{},
            },
        },
        .protection = .{
            .read = true,
            .write = false,
            .execute = true,
        },
    });

    // TODO: write this later

    // writer.writeSegment(.{
    //     .name = "__LINKEDIT",
    //     .sections = &.{},
    //     .protection = .{
    //         .read = true,
    //         .write = false,
    //         .execute = false,
    //     },
    // });
    assert(writer.segment_index == writer.segment_count - 1);
    writer.index = writer.segment_offset + @sizeOf(LoadCommand.Segment64);

    for (file[16384 + 56 ..][0..48]) |b| {
        print("0x{x}, ", .{b});
    }

    const chained_fixup_bytes = &.{ 0x0, 0x0, 0x0, 0x0, 0x20, 0x0, 0x0, 0x0, 0x30, 0x0, 0x0, 0x0, 0x30, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x3, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };
    writer.writeLinkeditData(chained_fixup_bytes, .dyld_chained_fixups);
    const export_trie_bytes = &.{ 0x0, 0x1, 0x5f, 0x0, 0x9, 0x2, 0x0, 0x0, 0x0, 0x0, 0x2, 0x5f, 0x6d, 0x68, 0x5f, 0x65, 0x78, 0x65, 0x63, 0x75, 0x74, 0x65, 0x5f, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x0, 0x5, 0x6d, 0x61, 0x69, 0x6e, 0x0, 0x25, 0x3, 0x0, 0xb0, 0x7f, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };
    writer.writeLinkeditData(export_trie_bytes, .dyld_exports_trie);
    unreachable;
    // writer.writeSymbolTable(
}

// .bytes = &.{
//     0x0, 0x0, 0x0, 0x0, 0x20, 0x0, 0x0, 0x0, 0x30, 0x0, 0x0, 0x0, 0x30, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x3, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x5f, 0x0, 0x9, 0x2, 0x0, 0x0, 0x0, 0x0, 0x2, 0x5f, 0x6d, 0x68, 0x5f, 0x65, 0x78, 0x65, 0x63, 0x75, 0x74, 0x65, 0x5f, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x0, 0x5, 0x6d, 0x61, 0x69, 0x6e, 0x0, 0x25, 0x3, 0x0, 0xb0, 0x7f, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xb0, 0x7f, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x0, 0xf, 0x1, 0x10, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x16, 0x0, 0x0, 0x0, 0xf, 0x1, 0x0, 0x0, 0xb0, 0x3f, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x20, 0x0, 0x5f, 0x5f, 0x6d, 0x68, 0x5f, 0x65, 0x78, 0x65, 0x63, 0x75, 0x74, 0x65, 0x5f, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x0, 0x5f, 0x6d, 0x61, 0x69, 0x6e, 0x0, 0x0, 0x0, 0x0, 0x0, 0xfa, 0xde, 0xc, 0xc0, 0x0, 0x0, 0x1, 0x11, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x14, 0xfa, 0xde, 0xc, 0x2, 0x0, 0x0, 0x0, 0xfd, 0x0, 0x2, 0x4, 0x0, 0x0, 0x2, 0x0, 0x2, 0x0, 0x0, 0x0, 0x5d, 0x0, 0x0, 0x0, 0x58, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x5, 0x0, 0x0, 0x40, 0xb0, 0x20, 0x2, 0x0, 0xc, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x40, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x6d, 0x61, 0x69, 0x6e, 0x0, 0xb2, 0x2a, 0x3, 0x79, 0x1b, 0x82, 0xf4, 0x71, 0xf1, 0xae, 0xfa, 0x44, 0x53, 0xe0, 0xc2, 0x78, 0x1e, 0x56, 0xd1, 0x9b, 0x36, 0x37, 0x7b, 0x7e, 0x61, 0xf5, 0x8a, 0x59, 0xc4, 0xf0, 0x64, 0x56, 0xad, 0x7f, 0xac, 0xb2, 0x58, 0x6f, 0xc6, 0xe9, 0x66, 0xc0, 0x4, 0xd7, 0xd1, 0xd1, 0x6b, 0x2, 0x4f, 0x58, 0x5, 0xff, 0x7c, 0xb4, 0x7c, 0x7a, 0x85, 0xda, 0xbd, 0x8b, 0x48, 0x89, 0x2c, 0xa7, 0xad, 0x7f, 0xac, 0xb2, 0x58, 0x6f, 0xc6, 0xe9, 0x66, 0xc0, 0x4, 0xd7, 0xd1, 0xd1, 0x6b, 0x2, 0x4f, 0x58, 0x5, 0xff, 0x7c, 0xb4, 0x7c, 0x7a, 0x85, 0xda, 0xbd, 0x8b, 0x48, 0x89, 0x2c, 0xa7, 0x8, 0xdb, 0xee, 0xf5, 0x95, 0x71, 0x3e, 0xcb, 0x29, 0xff, 0x3f, 0x28, 0x46, 0xf0, 0xdc, 0x97, 0xbf, 0x2d, 0x3, 0xf2, 0xec, 0xc, 0x84, 0xa, 0x44, 0x90, 0xf, 0xe0, 0xf4, 0xea, 0x67, 0x97, 0x6b, 0xb0, 0x22, 0x2, 0x0, 0xa7, 0xed, 0x94, 0xb2, 0x3d, 0x86, 0x4d, 0x13, 0xd6, 0xa4, 0xe, 0x1c, 0x1a, 0x6b, 0x9b, 0x82, 0xa0, 0xeb, 0x28, 0x23, 0xfe, 0x8a, 0x51, 0x2a, 0xe5, 0xf9, 0x39,
// },
