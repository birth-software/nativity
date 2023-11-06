const std = @import("std");
const assert = std.debug.assert;
const print = std.debug.print;
const Allocator = std.mem.Allocator;

const data_structures = @import("../data_structures.zig");
const ArrayList = data_structures.ArrayList;
const emit = @import("emit.zig");
pub const Writer = struct {
    in_file: []const u8,
    items: []u8,
    index: usize = 0,
    allocator: Allocator,
    pub fn init(allocator: Allocator) !Writer {
        const file = try std.fs.cwd().readFileAlloc(allocator, "main.exe", 0xfffffffffffff);
        const len = std.mem.alignForward(usize, file.len, 0x1000);
        return Writer{
            .in_file = file,
            .items = try data_structures.mmap(len, .{}),
            .allocator = allocator,
        };
    }

    pub fn writeToMemory(writer: *Writer, image: *const emit.Result) !void {
        print("File len: {}\n", .{writer.in_file.len});
        const dos_header: *const ImageDosHeader = @ptrCast(@alignCast(writer.in_file.ptr));
        print("File address: {}\n", .{dos_header.file_address_of_new_exe_header});
        print("File: {s}\n", .{writer.in_file[0x40..]});
        for (writer.in_file[0x40..], 0..) |byte, index| {
            if (byte == 'T') {
                print("Index: {}\n", .{index});
                break;
            }
        }
        assert(dos_header.magic_number == ImageDosHeader.magic);
        // assert(dos_header.file_address_of_new_exe_header == @sizeOf(ImageDosHeader));
        print("{}\n", .{dos_header});
        const file_header: *const ImageFileHeader = @ptrCast(@alignCast(writer.in_file[dos_header.file_address_of_new_exe_header + 4 ..].ptr));
        print("File header: {}\n", .{file_header});

        writer.append(std.mem.asBytes(&ImageDosHeader{
            .file_address_of_new_exe_header = 208,
        }));
        while (writer.index < 208) : (writer.index += 1) {
            writer.append(&.{0});
        }
        writer.append(std.mem.asBytes(&image_NT_signature));
        writer.append(std.mem.asBytes(&ImageFileHeader{
            .machine = switch (image.target.cpu.arch) {
                .x86_64 => .amd64,
                .aarch64 => .arm64,
                else => @panic("Architecture"),
            },
            .section_count = 3,
            .time_date_stamp = @intCast(std.time.timestamp()),
        }));

        const kernel32 = blk: {
            var library = Library{
                .name = "KERNEL32.DLL",
            };
            try library.symbols.append(writer.allocator, Symbol{
                .name = "ExitProcess",
            });

            break :blk library;
        };

        const libraries = &[_]Library{kernel32};
        _ = libraries;

        const code = &.{
            0x48, 0x83, 0xec, 0x28, //subq    $40, %rsp
            0xb9, 0x2a, 0x00, 0x00, 0x00, //movl    $42, %ecx
            0xff, 0x15, 0xf1, 0x0f, 0x00, 0x00, //callq   *4081(%rip)             # 0x140002000
            0xcc,
        };
        _ = code;

        const pdata = &.{
            0x00, 0x10,
            0x00, 0x00,
            0x10, 0x10,
            0x00, 0x00,
            0x28, 0x21,
            0x00, 0x00,
        };
        _ = pdata;

        // TODO
        // writer.append(std.mem.asBytes(ImageOptionalHeader{
        //     .magic = ImageOptionalHeader.magic,
        //     .size_of_code = code.len,
        // }));

        unreachable;
    }

    fn append(writer: *Writer, bytes: []const u8) void {
        const destination = writer.items[writer.index..][0..bytes.len];
        const source = bytes;
        @memcpy(destination, source);
        writer.index += bytes.len;
    }

    pub fn writeToFile(writer: *Writer, executable_relative_path: []const u8) !void {
        _ = writer;
        _ = executable_relative_path;
        unreachable;
    }
};

const ImageDosHeader = extern struct {
    magic_number: u16 = magic,
    bytes_last_page_of_file: u16 = 0,
    pages_in_file: u16 = 0,
    relocations: u16 = 0,
    size_of_header_in_paragraphs: u16 = 0,
    minimum_extra_paragraphs: u16 = 0,
    maximum_extra_paragraphs: u16 = 0,
    initial_ss_value: u16 = 0,
    initial_sp_value: u16 = 0,
    cheksum: u16 = 0,
    initial_ip_value: u16 = 0,
    initial_cs_value: u16 = 0,
    file_address_of_relocation_table: u16 = 0,
    overlay_number: u16 = 0,
    reserved_words: [4]u16 = .{0} ** 4,
    oem_id: u16 = 0,
    oem_info: u16 = 0,
    reserved_words2: [10]u16 = .{0} ** 10,
    file_address_of_new_exe_header: u32 = @sizeOf(ImageDosHeader),

    const magic = 0x5a4d;

    comptime {
        assert(@sizeOf(ImageDosHeader) == 64);
    }
};
const image_NT_signature: u32 = 0x00004550;

/// COFF header format
const ImageFileHeader = extern struct {
    machine: ImageFileMachine,
    section_count: u16,
    time_date_stamp: u32,
    symbol_table_offset: u32 = 0,
    symbol_count: u32 = 0,
    size_of_optional_header: u16 = @sizeOf(ImageOptionalHeader),
    characteristics: Characteristics = .{},

    const Characteristics = packed struct(u16) {
        relocations_stripped: bool = false,
        executable_image: bool = true,
        stripped_line_count: bool = false,
        stripped_local_symbols: bool = false,
        aggressive_ws_trim: bool = false,
        large_address_aware: bool = true,
        reserved: u1 = 0,
        bytes_reversed_lo: bool = false,
        machine_32bit: bool = false,
        stripped_debug: bool = false,
        removable_run_from_swap: bool = false,
        net_run_from_swap: bool = false,
        system: bool = false,
        dll: bool = false,
        up_systems_only: bool = false,
        bytes_reversed_hi: bool = false,
    };
};

const ImageFileMachine = enum(u16) {
    unknown = 0,
    target_host = 0x0001, // Useful for indicating we want to interact with the host and not a WoW guest.
    i386 = 0x014c, // Intel 386.
    r3000 = 0x0162, // MIPS little-endian, 0x160 big-endian
    r4000 = 0x0166, // MIPS little-endian
    r10000 = 0x0168, // MIPS little-endian
    wcemipsv2 = 0x0169, // MIPS little-endian WCE v2
    alpha = 0x0184, // Alpha_AXP
    sh3 = 0x01a2, // SH3 little-endian
    sh3dsp = 0x01a3,
    sh3e = 0x01a4, // SH3E little-endian
    sh4 = 0x01a6, // SH4 little-endian
    sh5 = 0x01a8, // SH5
    arm = 0x01c0, // ARM Little-Endian
    thumb = 0x01c2, // ARM Thumb/Thumb-2 Little-Endian
    armnt = 0x01c4, // ARM Thumb-2 Little-Endian
    am33 = 0x01d3,
    powerpc = 0x01F0, // IBM PowerPC Little-Endian
    powerpcfp = 0x01f1,
    ia64 = 0x0200, // Intel 64
    mips16 = 0x0266, // MIPS
    alpha64 = 0x0284, // ALPHA64
    mipsfpu = 0x0366, // MIPS
    mipsfpu16 = 0x0466, // MIPS
    tricore = 0x0520, // Infineon
    cef = 0x0CEF,
    ebc = 0x0EBC, // EFI Byte Code
    amd64 = 0x8664, // AMD64 (K8)
    m32r = 0x9041, // M32R little-endian
    arm64 = 0xAA64, // ARM64 Little-Endian
    cee = 0xC0EE,

    const axp64 = ImageFileMachine.alpha64;
};

const ImageOptionalHeader = extern struct {
    magic: u16 = magic,
    major_linker_version: u8 = 0,
    minor_linker_version: u8 = 0,
    size_of_code: u32,
    size_of_initialized_data: u32,
    size_of_uninitialized_data: u32,
    address_of_entry_point: u32,
    base_of_code: u32,
    image_base: u64,
    section_alignment: u32,
    file_alignment: u32,
    major_os_version: u16,
    minor_os_version: u16,
    major_image_version: u16,
    minor_image_version: u16,
    major_subsystem_version: u16,
    minor_subsystem_version: u16,
    win32_version_value: u32,
    size_of_image: u32,
    size_of_headers: u32,
    checksum: u32,
    subsystem: u16,
    dll_characteristics: u16,
    size_of_stack_reserve: u64,
    size_of_stack_commit: u64,
    size_of_heap_reserve: u64,
    size_of_heap_commit: u64,
    loader_flags: u32,
    number_of_RVA_and_sizes: u32,
    data_directory: [image_number_of_directory_entries]ImageDataDirectory,

    const magic = 0x20b;

    comptime {
        assert(@sizeOf(ImageOptionalHeader) == 0xf0);
    }
};

const ImageDataDirectory = extern struct {
    virtual_address: u32,
    size: u32,
};

const image_number_of_directory_entries = 0x10;

const Library = struct {
    symbols: ArrayList(Symbol) = .{},
    name: []const u8,
    name_virtual_address: u32 = 0,
    virtual_address: u32 = 0,
    image_thunk_virtual_address: u32 = 0,
};

const Symbol = struct {
    name: []const u8,
    name_virtual_address: u32 = 0,
    offset_in_data: u32 = 0,
};
