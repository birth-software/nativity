const std = @import("std");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;
const print = std.debug.print;
const emit = @import("emit.zig");
const ir = @import("intermediate_representation.zig");

const Compilation = @import("../Compilation.zig");

const data_structures = @import("../data_structures.zig");
const ArrayList = data_structures.ArrayList;
const AutoArrayHashMap = data_structures.AutoArrayHashMap;
const BlockList = data_structures.BlockList;

const x86_64 = @This();

const Register = struct {
    list: List = .{},
    index: Index,

    const invalid = Register{
        .index = .{
            .physical = .no_register,
        },
    };

    fn isValid(register: Register) bool {
        return switch (register.index) {
            .physical => |physical| physical != .no_register,
            .virtual => true,
        };
    }

    const Index = union(enum) {
        physical: Register.Physical,
        virtual: Register.Virtual.Index,
    };

    const State = union(enum) {
        virtual: Virtual.Index,
        free,
        preassigned,
        livein,
    };
    const Class = enum {
        not_a_register,
        any,
        // gp8,
        // gp16,
        gp32,
        gp64,
        gp64_nosp,

        pub const Descriptor = struct {
            size: u16,
            spill_size: u16,
            spill_alignment: u16,
        };
    };

    const Physical = enum(u9) {
        no_register = 0,
        ah = 1,
        al = 2,
        ax = 3,
        bh = 4,
        bl = 5,
        bp = 6,
        bph = 7,
        bpl = 8,
        bx = 9,
        ch = 10,
        cl = 11,
        cs = 12,
        cx = 13,
        df = 14,
        dh = 15,
        di = 16,
        dih = 17,
        dil = 18,
        dl = 19,
        ds = 20,
        dx = 21,
        eax = 22,
        ebp = 23,
        ebx = 24,
        ecx = 25,
        edi = 26,
        edx = 27,
        eflags = 28,
        eip = 29,
        eiz = 30,
        es = 31,
        esi = 32,
        esp = 33,
        fpcw = 34,
        fpsw = 35,
        fs = 36,
        fs_base = 37,
        gs = 38,
        gs_base = 39,
        hax = 40,
        hbp = 41,
        hbx = 42,
        hcx = 43,
        hdi = 44,
        hdx = 45,
        hip = 46,
        hsi = 47,
        hsp = 48,
        ip = 49,
        mxcsr = 50,
        rax = 51,
        rbp = 52,
        rbx = 53,
        rcx = 54,
        rdi = 55,
        rdx = 56,
        rflags = 57,
        rip = 58,
        riz = 59,
        rsi = 60,
        rsp = 61,
        si = 62,
        sih = 63,
        sil = 64,
        sp = 65,
        sph = 66,
        spl = 67,
        ss = 68,
        ssp = 69,
        tmmcfg = 70,
        _eflags = 71,
        cr0 = 72,
        cr1 = 73,
        cr2 = 74,
        cr3 = 75,
        cr4 = 76,
        cr5 = 77,
        cr6 = 78,
        cr7 = 79,
        cr8 = 80,
        cr9 = 81,
        cr10 = 82,
        cr11 = 83,
        cr12 = 84,
        cr13 = 85,
        cr14 = 86,
        cr15 = 87,
        dr0 = 88,
        dr1 = 89,
        dr2 = 90,
        dr3 = 91,
        dr4 = 92,
        dr5 = 93,
        dr6 = 94,
        dr7 = 95,
        dr8 = 96,
        dr9 = 97,
        dr10 = 98,
        dr11 = 99,
        dr12 = 100,
        dr13 = 101,
        dr14 = 102,
        dr15 = 103,
        fp0 = 104,
        fp1 = 105,
        fp2 = 106,
        fp3 = 107,
        fp4 = 108,
        fp5 = 109,
        fp6 = 110,
        fp7 = 111,
        k0 = 112,
        k1 = 113,
        k2 = 114,
        k3 = 115,
        k4 = 116,
        k5 = 117,
        k6 = 118,
        k7 = 119,
        mm0 = 120,
        mm1 = 121,
        mm2 = 122,
        mm3 = 123,
        mm4 = 124,
        mm5 = 125,
        mm6 = 126,
        mm7 = 127,
        r8 = 128,
        r9 = 129,
        r10 = 130,
        r11 = 131,
        r12 = 132,
        r13 = 133,
        r14 = 134,
        r15 = 135,
        st0 = 136,
        st1 = 137,
        st2 = 138,
        st3 = 139,
        st4 = 140,
        st5 = 141,
        st6 = 142,
        st7 = 143,
        tmm0 = 144,
        tmm1 = 145,
        tmm2 = 146,
        tmm3 = 147,
        tmm4 = 148,
        tmm5 = 149,
        tmm6 = 150,
        tmm7 = 151,
        xmm0 = 152,
        xmm1 = 153,
        xmm2 = 154,
        xmm3 = 155,
        xmm4 = 156,
        xmm5 = 157,
        xmm6 = 158,
        xmm7 = 159,
        xmm8 = 160,
        xmm9 = 161,
        xmm10 = 162,
        xmm11 = 163,
        xmm12 = 164,
        xmm13 = 165,
        xmm14 = 166,
        xmm15 = 167,
        xmm16 = 168,
        xmm17 = 169,
        xmm18 = 170,
        xmm19 = 171,
        xmm20 = 172,
        xmm21 = 173,
        xmm22 = 174,
        xmm23 = 175,
        xmm24 = 176,
        xmm25 = 177,
        xmm26 = 178,
        xmm27 = 179,
        xmm28 = 180,
        xmm29 = 181,
        xmm30 = 182,
        xmm31 = 183,
        ymm0 = 184,
        ymm1 = 185,
        ymm2 = 186,
        ymm3 = 187,
        ymm4 = 188,
        ymm5 = 189,
        ymm6 = 190,
        ymm7 = 191,
        ymm8 = 192,
        ymm9 = 193,
        ymm10 = 194,
        ymm11 = 195,
        ymm12 = 196,
        ymm13 = 197,
        ymm14 = 198,
        ymm15 = 199,
        ymm16 = 200,
        ymm17 = 201,
        ymm18 = 202,
        ymm19 = 203,
        ymm20 = 204,
        ymm21 = 205,
        ymm22 = 206,
        ymm23 = 207,
        ymm24 = 208,
        ymm25 = 209,
        ymm26 = 210,
        ymm27 = 211,
        ymm28 = 212,
        ymm29 = 213,
        ymm30 = 214,
        ymm31 = 215,
        zmm0 = 216,
        zmm1 = 217,
        zmm2 = 218,
        zmm3 = 219,
        zmm4 = 220,
        zmm5 = 221,
        zmm6 = 222,
        zmm7 = 223,
        zmm8 = 224,
        zmm9 = 225,
        zmm10 = 226,
        zmm11 = 227,
        zmm12 = 228,
        zmm13 = 229,
        zmm14 = 230,
        zmm15 = 231,
        zmm16 = 232,
        zmm17 = 233,
        zmm18 = 234,
        zmm19 = 235,
        zmm20 = 236,
        zmm21 = 237,
        zmm22 = 238,
        zmm23 = 239,
        zmm24 = 240,
        zmm25 = 241,
        zmm26 = 242,
        zmm27 = 243,
        zmm28 = 244,
        zmm29 = 245,
        zmm30 = 246,
        zmm31 = 247,
        r8b = 248,
        r9b = 249,
        r10b = 250,
        r11b = 251,
        r12b = 252,
        r13b = 253,
        r14b = 254,
        r15b = 255,
        r8bh = 256,
        r9bh = 257,
        r10bh = 258,
        r11bh = 259,
        r12bh = 260,
        r13bh = 261,
        r14bh = 262,
        r15bh = 263,
        r8d = 264,
        r9d = 265,
        r10d = 266,
        r11d = 267,
        r12d = 268,
        r13d = 269,
        r14d = 270,
        r15d = 271,
        r8w = 272,
        r9w = 273,
        r10w = 274,
        r11w = 275,
        r12w = 276,
        r13w = 277,
        r14w = 278,
        r15w = 279,
        r8wh = 280,
        r9wh = 281,
        r10wh = 282,
        r11wh = 283,
        r12wh = 284,
        r13wh = 285,
        r14wh = 286,
        r15wh = 287,
        k0_k1 = 288,
        k2_k3 = 289,
        k4_k5 = 290,
        k6_k7 = 291,

        const Descriptor = struct {
            subregisters: []const Register.Physical = &.{},
        };
    };

    const Virtual = struct {
        register_class: Register.Class,
        use_def_list_head: Operand.Index = Operand.Index.invalid,

        pub const List = BlockList(@This());
        pub const Index = Virtual.List.Index;
        pub const Allocation = Virtual.List.Allocation;
    };

    const List = struct {
        previous: Operand.Index = Operand.Index.invalid,
        next: Operand.Index = Operand.Index.invalid,
    };
};

const register_descriptors = std.EnumArray(Register.Physical, Register.Physical.Descriptor).init(.{
    .no_register = .{},
    .ah = .{},
    .al = .{},
    .ax = .{},
    .bh = .{},
    .bl = .{},
    .bp = .{},
    .bph = .{},
    .bpl = .{},
    .bx = .{},
    .ch = .{},
    .cl = .{},
    .cs = .{},
    .cx = .{},
    .df = .{},
    .dh = .{},
    .di = .{},
    .dih = .{},
    .dil = .{},
    .dl = .{},
    .ds = .{},
    .dx = .{},
    .eax = .{},
    .ebp = .{},
    .ebx = .{},
    .ecx = .{},
    .edi = .{},
    .edx = .{},
    .eflags = .{},
    .eip = .{
        .subregisters = &.{ .ip, .hip },
    },
    .eiz = .{},
    .es = .{},
    .esi = .{},
    .esp = .{},
    .fpcw = .{},
    .fpsw = .{},
    .fs = .{},
    .fs_base = .{},
    .gs = .{},
    .gs_base = .{},
    .hax = .{},
    .hbp = .{},
    .hbx = .{},
    .hcx = .{},
    .hdi = .{},
    .hdx = .{},
    .hip = .{},
    .hsi = .{},
    .hsp = .{},
    .ip = .{},
    .mxcsr = .{},
    .rax = .{},
    .rbp = .{},
    .rbx = .{},
    .rcx = .{},
    .rdi = .{},
    .rdx = .{},
    .rflags = .{},
    .rip = .{
        .subregisters = &.{.eip},
    },
    .riz = .{},
    .rsi = .{},
    .rsp = .{},
    .si = .{},
    .sih = .{},
    .sil = .{},
    .sp = .{},
    .sph = .{},
    .spl = .{},
    .ss = .{},
    .ssp = .{},
    .tmmcfg = .{},
    ._eflags = .{},
    .cr0 = .{},
    .cr1 = .{},
    .cr2 = .{},
    .cr3 = .{},
    .cr4 = .{},
    .cr5 = .{},
    .cr6 = .{},
    .cr7 = .{},
    .cr8 = .{},
    .cr9 = .{},
    .cr10 = .{},
    .cr11 = .{},
    .cr12 = .{},
    .cr13 = .{},
    .cr14 = .{},
    .cr15 = .{},
    .dr0 = .{},
    .dr1 = .{},
    .dr2 = .{},
    .dr3 = .{},
    .dr4 = .{},
    .dr5 = .{},
    .dr6 = .{},
    .dr7 = .{},
    .dr8 = .{},
    .dr9 = .{},
    .dr10 = .{},
    .dr11 = .{},
    .dr12 = .{},
    .dr13 = .{},
    .dr14 = .{},
    .dr15 = .{},
    .fp0 = .{},
    .fp1 = .{},
    .fp2 = .{},
    .fp3 = .{},
    .fp4 = .{},
    .fp5 = .{},
    .fp6 = .{},
    .fp7 = .{},
    .k0 = .{},
    .k1 = .{},
    .k2 = .{},
    .k3 = .{},
    .k4 = .{},
    .k5 = .{},
    .k6 = .{},
    .k7 = .{},
    .mm0 = .{},
    .mm1 = .{},
    .mm2 = .{},
    .mm3 = .{},
    .mm4 = .{},
    .mm5 = .{},
    .mm6 = .{},
    .mm7 = .{},
    .r8 = .{},
    .r9 = .{},
    .r10 = .{},
    .r11 = .{},
    .r12 = .{},
    .r13 = .{},
    .r14 = .{},
    .r15 = .{},
    .st0 = .{},
    .st1 = .{},
    .st2 = .{},
    .st3 = .{},
    .st4 = .{},
    .st5 = .{},
    .st6 = .{},
    .st7 = .{},
    .tmm0 = .{},
    .tmm1 = .{},
    .tmm2 = .{},
    .tmm3 = .{},
    .tmm4 = .{},
    .tmm5 = .{},
    .tmm6 = .{},
    .tmm7 = .{},
    .xmm0 = .{},
    .xmm1 = .{},
    .xmm2 = .{},
    .xmm3 = .{},
    .xmm4 = .{},
    .xmm5 = .{},
    .xmm6 = .{},
    .xmm7 = .{},
    .xmm8 = .{},
    .xmm9 = .{},
    .xmm10 = .{},
    .xmm11 = .{},
    .xmm12 = .{},
    .xmm13 = .{},
    .xmm14 = .{},
    .xmm15 = .{},
    .xmm16 = .{},
    .xmm17 = .{},
    .xmm18 = .{},
    .xmm19 = .{},
    .xmm20 = .{},
    .xmm21 = .{},
    .xmm22 = .{},
    .xmm23 = .{},
    .xmm24 = .{},
    .xmm25 = .{},
    .xmm26 = .{},
    .xmm27 = .{},
    .xmm28 = .{},
    .xmm29 = .{},
    .xmm30 = .{},
    .xmm31 = .{},
    .ymm0 = .{},
    .ymm1 = .{},
    .ymm2 = .{},
    .ymm3 = .{},
    .ymm4 = .{},
    .ymm5 = .{},
    .ymm6 = .{},
    .ymm7 = .{},
    .ymm8 = .{},
    .ymm9 = .{},
    .ymm10 = .{},
    .ymm11 = .{},
    .ymm12 = .{},
    .ymm13 = .{},
    .ymm14 = .{},
    .ymm15 = .{},
    .ymm16 = .{},
    .ymm17 = .{},
    .ymm18 = .{},
    .ymm19 = .{},
    .ymm20 = .{},
    .ymm21 = .{},
    .ymm22 = .{},
    .ymm23 = .{},
    .ymm24 = .{},
    .ymm25 = .{},
    .ymm26 = .{},
    .ymm27 = .{},
    .ymm28 = .{},
    .ymm29 = .{},
    .ymm30 = .{},
    .ymm31 = .{},
    .zmm0 = .{},
    .zmm1 = .{},
    .zmm2 = .{},
    .zmm3 = .{},
    .zmm4 = .{},
    .zmm5 = .{},
    .zmm6 = .{},
    .zmm7 = .{},
    .zmm8 = .{},
    .zmm9 = .{},
    .zmm10 = .{},
    .zmm11 = .{},
    .zmm12 = .{},
    .zmm13 = .{},
    .zmm14 = .{},
    .zmm15 = .{},
    .zmm16 = .{},
    .zmm17 = .{},
    .zmm18 = .{},
    .zmm19 = .{},
    .zmm20 = .{},
    .zmm21 = .{},
    .zmm22 = .{},
    .zmm23 = .{},
    .zmm24 = .{},
    .zmm25 = .{},
    .zmm26 = .{},
    .zmm27 = .{},
    .zmm28 = .{},
    .zmm29 = .{},
    .zmm30 = .{},
    .zmm31 = .{},
    .r8b = .{},
    .r9b = .{},
    .r10b = .{},
    .r11b = .{},
    .r12b = .{},
    .r13b = .{},
    .r14b = .{},
    .r15b = .{},
    .r8bh = .{},
    .r9bh = .{},
    .r10bh = .{},
    .r11bh = .{},
    .r12bh = .{},
    .r13bh = .{},
    .r14bh = .{},
    .r15bh = .{},
    .r8d = .{},
    .r9d = .{},
    .r10d = .{},
    .r11d = .{},
    .r12d = .{},
    .r13d = .{},
    .r14d = .{},
    .r15d = .{},
    .r8w = .{},
    .r9w = .{},
    .r10w = .{},
    .r11w = .{},
    .r12w = .{},
    .r13w = .{},
    .r14w = .{},
    .r15w = .{},
    .r8wh = .{},
    .r9wh = .{},
    .r10wh = .{},
    .r11wh = .{},
    .r12wh = .{},
    .r13wh = .{},
    .r14wh = .{},
    .r15wh = .{},
    .k0_k1 = .{},
    .k2_k3 = .{},
    .k4_k5 = .{},
    .k6_k7 = .{},
});

// const SubregisterIndex = struct {
//     size: u16,
//     offset: u16 = 0,
// };
//
// const SubRegisterIndexType = enum {
//     sub_8bit,
//     sub_8bit_hi,
//     sub_16bit_,
//     sub_16bit_hi,
//     sub_32bit,
// };

// const subregister_indices = std.EnumArray(SubRegisterIndexType, []const SubregisterIndex).init(.{
//     });

// const Sub8Bit = enum{
//     ax = 0,
//     cx = 1,
//     dx = 2,
//     bx = 3,
// };

const GP32 = enum(u3) {
    a = 0,
    c = 1,
    d = 2,
    b = 3,
    sp = 4,
    bp = 5,
    si = 6,
    di = 7,
};

const GP64 = enum(u4) {
    a = 0,
    c = 1,
    d = 2,
    b = 3,
    sp = 4,
    bp = 5,
    si = 6,
    di = 7,
    r8 = 8,
    r9 = 9,
    r10 = 10,
    r11 = 11,
    r12 = 12,
    r13 = 13,
    r14 = 14,
    r15 = 15,
};

const GP64NOSP = enum(u4) {
    a = 0,
    c = 1,
    d = 2,
    b = 3,
    bp = 5,
    si = 6,
    di = 7,
    r8 = 8,
    r9 = 9,
    r10 = 10,
    r11 = 11,
    r12 = 12,
    r13 = 13,
    r14 = 14,
    r15 = 15,
};

const XMMRegister = u4;

const CallingConvention = struct {
    argument_registers: RegisterGroupMap,
    syscall_registers: []const Register.Physical,

    const Id = Compilation.CallingConvention;
};

const RegisterGroupMap = std.EnumArray(Register.Class, []const Register.Physical);

const zero_register_class_descriptor = Register.Class.Descriptor{
    .size = 0,
    .spill_size = 0,
    .spill_alignment = 0,
};
const register_class_descriptors = std.EnumArray(Register.Class, Register.Class.Descriptor).init(.{
    .not_a_register = zero_register_class_descriptor,
    .any = zero_register_class_descriptor,
    .gp32 = .{
        .size = 32,
        .spill_size = 32,
        .spill_alignment = 32,
    },
    .gp64 = .{
        .size = 64,
        .spill_size = 64,
        .spill_alignment = 64,
    },
    .gp64_nosp = .{
        .size = 64,
        .spill_size = 64,
        .spill_alignment = 64,
    },
});

const registers_by_class = RegisterGroupMap.init(.{
    .not_a_register = &.{},
    .any = &.{},
    .gp32 = &.{
        .eax,
        .ecx,
        .edx,
        .esi,
        .edi,
        .ebx,
        .ebp,
        .esp,
        .r8d,
        .r9d,
        .r10d,
        .r11d,
        .r14d,
        .r15d,
        .r12d,
        .r13d,
    },
    .gp64 = &.{
        .rax,
        .rcx,
        .rdx,
        .rsi,
        .rdi,
        .r8,
        .r9,
        .r10,
        .r11,
        .rbx,
        .r14,
        .r15,
        .r12,
        .r13,
        .rbp,
        .rsp,
    },
    .gp64_nosp = &.{},
});

// TODO: fix this
const system_v_gp32_argument_registers = [4]Register.Physical{ .edi, .esi, .edx, .ecx };
const system_v_gp64_argument_registers = [6]Register.Physical{ .rdi, .rsi, .rdx, .rcx, .r8, .r9 };
const system_v_xmm_argument_registers = [8]Register.Physical{ .xmm0, .xmm1, .xmm2, .xmm3, .xmm4, .xmm5, .xmm6, .xmm7 };
const system_v_syscall_registers = [7]Register.Physical{ .rax, .rdi, .rsi, .rdx, .r10, .r8, .r9 };

const system_v = CallingConvention{
    .argument_registers = RegisterGroupMap.init(.{
        .not_a_register = &.{},
        .any = &.{},
        .gp32 = &system_v_gp32_argument_registers,
        .gp64 = &system_v_gp64_argument_registers,
        .gp64_nosp = &.{},
    }),
    .syscall_registers = &system_v_syscall_registers,
};

const calling_conventions = std.EnumArray(CallingConvention.Id, CallingConvention).init(.{
    .system_v = system_v,
});

const ValueType = struct {
    size: u16,
    element_count: u16,
    element_type: u32,
    data_type: DataType,
    scalarness: Scalarness,

    const DataType = enum(u1) {
        integer = 0,
        float = 1,
    };
    const Scalarness = enum(u1) {
        scalar = 0,
        vector = 1,
    };

    const Id = enum(u32) {
        any = 0,
        // other = 1,
        // i1 = 2,
        // i8 = 3,
        // i16 = 4,
        i32 = 5,
        i64 = 6,
        // i128 = 7,
    };
};

const value_types = std.EnumArray(ValueType.Id, ValueType).init(.{
    .any = .{
        .size = 0,
        .element_count = 1,
        .element_type = @intFromEnum(ValueType.Id.any),
        .data_type = .integer,
        .scalarness = .scalar,
    },
    .i32 = .{
        .size = @sizeOf(u32),
        .element_count = 1,
        .element_type = @intFromEnum(ValueType.Id.i32),
        .data_type = .integer,
        .scalarness = .scalar,
    },
    .i64 = .{
        .size = @sizeOf(u64),
        .element_count = 1,
        .element_type = @intFromEnum(ValueType.Id.i64),
        .data_type = .integer,
        .scalarness = .scalar,
    },
});

const register_classes = std.EnumArray(ValueType.Id, Register.Class).init(.{
    .any = .any,
    .i32 = .gp32,
    .i64 = .gp64,
});

const Memory = struct {
    alignment: u64,
    // low_level_type: LowLevelType,
    pub const List = BlockList(@This());
    pub const Index = List.Index;
    pub const Allocation = List.Allocation;
};

const LowLevelType = packed struct(u64) {
    u: packed union {
        vector: Vector,
        scalar: Scalar,
    },
    scalar: bool,
    pointer: bool,

    const Vector = packed struct(u62) {
        foo: u62 = 0,
    };

    const Scalar = packed struct {};
};

const AddressingMode = struct {
    base: AddressingMode.Base,
    scale: u32 = 1,
    displacement: i32 = 0,
    index_register: u32 = 0,
    const Base = union(enum) {
        register_base: u32,
        frame_index: u32,
    };
};

const StackObject = struct {
    size: u64,
    alignment: u32,
    spill_slot: bool,
    ir: ir.Instruction.Index,
};

const InstructionSelection = struct {
    local_value_map: data_structures.AutoArrayHashMap(ir.Instruction.Index, Register) = .{},
    value_map: data_structures.AutoArrayHashMap(ir.Instruction.Index, Register) = .{},
    block_map: data_structures.AutoHashMap(ir.BasicBlock.Index, BasicBlock.Index) = .{},
    liveins: data_structures.AutoArrayHashMap(Register.Physical, Register.Virtual.Index) = .{},
    memory_map: data_structures.AutoArrayHashMap(ir.Instruction.Index, Memory.Index) = .{},
    stack_map: data_structures.AutoArrayHashMap(ir.Instruction.Index, u32) = .{},
    physical_register_use_or_definition_list: std.EnumArray(Register.Physical, Operand.Index) = std.EnumArray(Register.Physical, Operand.Index).initFill(Operand.Index.invalid),
    current_block: BasicBlock.Index = BasicBlock.Index.invalid,
    stack_objects: ArrayList(StackObject) = .{},
    function: *MIR.Function,
    instruction_cache: ArrayList(Instruction.Index) = .{},

    fn storeRegisterToStackSlot(instruction_selection: *InstructionSelection, mir: *MIR, insert_before_instruction_index: usize, source_register: Register.Physical, kill: bool, frame_index: u32, register_class: Register.Class, virtual_register: Register.Virtual.Index) !void {
        _ = virtual_register;
        const stack_object = instruction_selection.stack_objects.items[frame_index];
        switch (@divExact(stack_object.size, 8)) {
            @sizeOf(u64) => {
                switch (register_class) {
                    .gp64 => {
                        const instruction_id = Instruction.Id.mov64mr;
                        const instruction_descriptor = comptime instruction_descriptors.get(instruction_id);
                        const source_operand_id = instruction_descriptor.operands[1].id;
                        const addressing_mode = AddressingMode{
                            .base = .{
                                .frame_index = frame_index,
                            },
                        };

                        const destination_operand_id = instruction_descriptor.operands[0].id;
                        const destination_operand = Operand{
                            .id = destination_operand_id,
                            .u = .{
                                .memory = .{ .addressing_mode = addressing_mode },
                            },
                            .flags = .{},
                        };
                        const source_operand = Operand{
                            .id = source_operand_id,
                            .u = .{
                                .register = .{
                                    .index = .{
                                        .physical = source_register,
                                    },
                                },
                            },
                            .flags = .{
                                .dead_or_kill = kill,
                            },
                        };

                        const instruction_index = try mir.buildInstruction(instruction_selection, instruction_id, &.{
                            destination_operand,
                            source_operand,
                        });

                        try mir.blocks.get(instruction_selection.current_block).instructions.insert(mir.allocator, insert_before_instruction_index, instruction_index);
                    },
                    else => |t| @panic(@tagName(t)),
                }
            },
            else => std.debug.panic("Stack object size: {}\n", .{stack_object.size}),
        }
    }

    fn loadRegisterFromStackSlot(instruction_selection: *InstructionSelection, mir: *MIR, insert_before_instruction_index: usize, destination_register: Register.Physical, frame_index: u32, register_class: Register.Class, virtual_register: Register.Virtual.Index) !void {
        _ = virtual_register;
        const stack_object = instruction_selection.stack_objects.items[frame_index];
        print("Stack object size: {}\n", .{stack_object.size});
        switch (@divExact(stack_object.size, 8)) {
            @sizeOf(u64) => {
                switch (register_class) {
                    .gp64 => {
                        const instruction_id = Instruction.Id.mov64rm;
                        const instruction_descriptor = comptime instruction_descriptors.get(instruction_id);
                        const source_operand_id = instruction_descriptor.operands[1].id;
                        const addressing_mode = AddressingMode{
                            .base = .{
                                .frame_index = frame_index,
                            },
                        };
                        const source_operand = Operand{
                            .id = source_operand_id,
                            .u = .{
                                .memory = .{ .addressing_mode = addressing_mode },
                            },
                            .flags = .{},
                        };
                        const destination_operand = Operand{
                            .id = .gp64,
                            .u = .{
                                .register = .{
                                    .index = .{
                                        .physical = destination_register,
                                    },
                                },
                            },
                            .flags = .{ .type = .def },
                        };
                        const instruction_index = try mir.buildInstruction(instruction_selection, instruction_id, &.{
                            destination_operand,
                            source_operand,
                        });
                        print("Inserting instruction at index {}", .{insert_before_instruction_index});
                        try mir.blocks.get(instruction_selection.current_block).instructions.insert(mir.allocator, insert_before_instruction_index, instruction_index);
                    },
                    else => |t| @panic(@tagName(t)),
                }
            },
            @sizeOf(u32) => switch (register_class) {
                .gp32 => {
                    const instruction_id = Instruction.Id.mov32rm;
                    const instruction_descriptor = comptime instruction_descriptors.get(instruction_id);
                    const source_operand_id = instruction_descriptor.operands[1].id;
                    const addressing_mode = AddressingMode{
                        .base = .{
                            .frame_index = frame_index,
                        },
                    };
                    const source_operand = Operand{
                        .id = source_operand_id,
                        .u = .{
                            .memory = .{ .addressing_mode = addressing_mode },
                        },
                        .flags = .{},
                    };
                    const destination_operand = Operand{
                        .id = .gp32,
                        .u = .{
                            .register = .{
                                .index = .{
                                    .physical = destination_register,
                                },
                            },
                        },
                        .flags = .{ .type = .def },
                    };
                    const instruction_index = try mir.buildInstruction(instruction_selection, instruction_id, &.{
                        destination_operand,
                        source_operand,
                    });
                    print("Inserting instruction at index {}\n", .{insert_before_instruction_index});
                    try mir.blocks.get(instruction_selection.current_block).instructions.insert(mir.allocator, insert_before_instruction_index, instruction_index);
                },
                else => |t| @panic(@tagName(t)),
            },
            else => std.debug.panic("Stack object size: {}\n", .{stack_object.size}),
        }
    }

    // TODO: add value map on top of local value map?
    fn lookupRegisterForValue(instruction_selection: *InstructionSelection, mir: *MIR, ir_instruction_index: ir.Instruction.Index) !Register {
        if (instruction_selection.value_map.get(ir_instruction_index)) |register| {
            return register;
        }

        const gop = try instruction_selection.local_value_map.getOrPutValue(mir.allocator, ir_instruction_index, Register.invalid);
        return gop.value_ptr.*;
    }

    fn getRegisterForValue(instruction_selection: *InstructionSelection, mir: *MIR, ir_instruction_index: ir.Instruction.Index) !Register {
        const register = try instruction_selection.lookupRegisterForValue(mir, ir_instruction_index);
        if (register.isValid()) {
            return register;
        }

        const instruction = mir.ir.instructions.get(ir_instruction_index);
        if (instruction.* != .stack or !instruction_selection.stack_map.contains(ir_instruction_index)) {
            const ir_type = getIrType(mir.ir, ir_instruction_index);
            const value_type = resolveType(ir_type);
            const register_class = register_classes.get(value_type);
            const new_register = try mir.createVirtualRegister(register_class);
            try instruction_selection.value_map.putNoClobber(mir.allocator, ir_instruction_index, new_register);
            return new_register;
        }

        unreachable;
    }

    // Moving an immediate to a register
    fn materializeInteger(instruction_selection: *InstructionSelection, mir: *MIR, ir_instruction_index: ir.Instruction.Index) !void {
        const destination_register = try instruction_selection.getRegisterForValue(mir, ir_instruction_index);
        const integer = mir.ir.instructions.get(ir_instruction_index).load_integer;
        const value_type = resolveType(integer.type);
        // const destination_register_class = register_classes.get(value_type);
        // const instruction_id: Instruction.Id =
        switch (integer.value.unsigned == 0) {
            true => {
                const instruction_id: Instruction.Id = switch (value_type) {
                    // .i8 => unreachable,
                    // .i16 => unreachable,
                    .i32 => .mov32r0,
                    // .i64 => b: {
                    //     if (std.math.cast(u32, integer.value.unsigned)) |_| {
                    //         break :b .mov32ri64;
                    //     } else if (std.math.cast(i32, integer.value.signed)) |_| {
                    //         unreachable;
                    //     } else {
                    //         unreachable;
                    //     }
                    // },
                    else => |t| @panic(@tagName(t)),
                };
                const instruction_descriptor = instruction_descriptors.get(instruction_id);
                const operand_id = instruction_descriptor.operands[0].id;
                // const register_class = register_classes.get(operand_id);
                const destination_operand = Operand{
                    .id = operand_id,
                    .u = .{
                        .register = destination_register,
                    },
                    .flags = .{ .type = .def },
                };

                const xor = try mir.buildInstruction(instruction_selection, instruction_id, &.{
                    destination_operand,
                });
                try instruction_selection.instruction_cache.append(mir.allocator, xor);
            },
            false => {
                const instruction_id: Instruction.Id = switch (value_type) {
                    .i32 => .mov32ri,
                    .i64 => b: {
                        if (std.math.cast(u32, integer.value.unsigned)) |_| {
                            break :b .mov32ri64;
                        } else if (std.math.cast(i32, integer.value.signed)) |_| {
                            unreachable;
                        } else {
                            unreachable;
                        }
                    },
                    else => |t| @panic(@tagName(t)),
                };

                const instruction_descriptor = instruction_descriptors.get(instruction_id);
                const operand_id = instruction_descriptor.operands[0].id;

                const destination_operand = Operand{
                    .id = operand_id,
                    .u = .{
                        .register = destination_register,
                    },
                    .flags = .{ .type = .def },
                };

                const source_operand = Operand{
                    .id = .immediate,
                    .u = .{
                        .immediate = integer.value.unsigned,
                    },
                    .flags = .{},
                };

                const instr = try mir.buildInstruction(instruction_selection, instruction_id, &.{
                    destination_operand,
                    source_operand,
                });

                try instruction_selection.instruction_cache.append(mir.allocator, instr);
            },
        }
        // const instruction_descriptor = instruction_descriptors.getPtrConst(instruction_id);
        //
        // switch (integer.value.unsigned == 0) {
        //     true => switch (value_type) {
        //         .i32 => .mov32r0,
        //         else => |t| @panic(@tagName(t)),
        //     },
        //     false => blk: {
        //
        //         const destination_register = try mir.createVirtualRegister(destination_register_class);
        //         const destination_operand = mir.constrainOperandRegisterClass(instruction_descriptor, destination_register, 0, .{ .type = .def });
        //
        //         const instr = try mir.buildInstruction(instruction_selection, instruction_id, &.{
        //             destination_operand,
        //             Operand{
        //                 .id = .immediate,
        //                 .u = .{
        //                     .immediate = integer.value.unsigned,
        //                 },
        //                 .flags = .{},
        //             },
        //         });
        //         try instruction_selection.instruction_cache.append(mir.allocator, instr);
        //
        //         break :blk destination_register;
        //     },
        // }
    }

    fn getAddressingModeFromIr(instruction_selection: *InstructionSelection, mir: *MIR, ir_instruction_index: ir.Instruction.Index) AddressingMode {
        const instruction = mir.ir.instructions.get(ir_instruction_index);
        switch (instruction.*) {
            .stack => {
                const frame_index: u32 = @intCast(instruction_selection.stack_map.getIndex(ir_instruction_index).?);
                return AddressingMode{
                    .base = .{
                        .frame_index = frame_index,
                    },
                };
            },
            else => |t| @panic(@tagName(t)),
        }
    }

    fn updateValueMap(instruction_selection: *InstructionSelection, allocator: Allocator, ir_instruction_index: ir.Instruction.Index, register: Register, local: bool) !void {
        if (local) {
            try instruction_selection.local_value_map.putNoClobber(allocator, ir_instruction_index, register);
        } else {
            const gop = try instruction_selection.value_map.getOrPutValue(allocator, ir_instruction_index, Register.invalid);
            if (!gop.value_ptr.isValid()) {
                gop.value_ptr.* = register;
            } else if (!std.meta.eql(gop.value_ptr.index, register.index)) {
                unreachable;
            }
        }
        // const gop = try instruction_selection.local_value_map.getOrPut(allocator, ir_instruction_index);
        // if (gop.found_existing) {
        //     const stored_register = gop.value_ptr.*;
        //     if (std.meta.eql(stored_register, register)) {
        //         unreachable;
        //     } else {
        //         std.debug.panic("Register mismatch: Stored: {} Got: {}\n", .{ stored_register, register });
        //     }
        // } else {
        //     gop.value_ptr.* = register;
        // }
    }

    fn lowerArguments(instruction_selection: *InstructionSelection, mir: *MIR, ir_function: *ir.Function) !void {
        const ir_function_declaration = mir.ir.function_declarations.get(ir_function.declaration);
        const ir_arguments = ir_function_declaration.arguments.values();
        const calling_convention = calling_conventions.get(ir_function_declaration.calling_convention);

        try instruction_selection.local_value_map.ensureUnusedCapacity(mir.allocator, ir_arguments.len);

        var gp_count: u8 = 0;

        for (ir_arguments) |ir_argument_instruction_index| {
            const ir_argument_instruction = mir.ir.instructions.get(ir_argument_instruction_index);
            const ir_argument = mir.ir.arguments.get(ir_argument_instruction.argument);
            switch (ir_argument.type) {
                .i8, .i16, .i32, .i64 => gp_count += 1,
                .void,
                .noreturn,
                => unreachable,
            }
        }

        if (gp_count >= 8) {
            @panic("Cannot lower arguments");
        }

        var gp_i: u8 = 0;
        var fp_i: u8 = 0;
        _ = fp_i;

        for (ir_arguments) |ir_argument_instruction_index| {
            const ir_argument_instruction = mir.ir.instructions.get(ir_argument_instruction_index);
            const ir_argument = mir.ir.arguments.get(ir_argument_instruction.argument);
            const value_type = resolveType(ir_argument.type);
            const register_class = register_classes.get(value_type);
            const argument_registers = calling_convention.argument_registers.get(register_class);
            const physical_register = argument_registers[gp_i];
            const operand_id: Operand.Id = switch (register_class) {
                inline .gp32,
                .gp64,
                => |gp| blk: {
                    gp_i += 1;
                    break :blk switch (gp) {
                        .gp32 => .gp32,
                        .gp64 => .gp64,
                        else => unreachable,
                    };
                },
                else => unreachable,
            };

            // const operand_register_class = register_class_operand_matcher.get(operand_reference.id);

            const virtual_register_index = try instruction_selection.createLiveIn(mir, physical_register, register_class);
            const result_register = try mir.createVirtualRegister(register_class);
            try mir.append(instruction_selection, .copy, &.{
                Operand{
                    .id = operand_id,
                    .u = .{
                        .register = result_register,
                    },
                    .flags = .{
                        .dead_or_kill = true,
                        .type = .def,
                    },
                },
                Operand{
                    .id = operand_id,
                    .u = .{
                        .register = .{
                            .index = .{
                                .virtual = virtual_register_index,
                            },
                        },
                    },
                    .flags = .{
                        .type = .def,
                    },
                },
            });

            mir.blocks.get(instruction_selection.current_block).current_stack_index += 1;

            try instruction_selection.updateValueMap(mir.allocator, ir_argument_instruction_index, result_register, true);
            try instruction_selection.value_map.putNoClobber(mir.allocator, ir_argument_instruction_index, result_register);
        }
    }

    fn addLiveIn(instruction_selection: *InstructionSelection, mir: *MIR, register: Register, register_class: Register.Class.Id) !void {
        _ = mir;
        _ = register_class;
        _ = register;
        _ = instruction_selection;
        unreachable;
    }

    fn addExistingLiveIn(instruction_selection: *InstructionSelection, mir: *MIR, physical_register: Register.Physical.Index, virtual_register: Register) !void {
        _ = mir;
        _ = virtual_register;
        _ = physical_register;
        _ = instruction_selection;
        unreachable;
    }

    fn createLiveIn(instruction_selection: *InstructionSelection, mir: *MIR, physical_register: Register.Physical, register_class: Register.Class) !Register.Virtual.Index {
        const virtual_register_index = try mir.createVirtualRegisterIndexed(register_class);
        try instruction_selection.liveins.putNoClobber(mir.allocator, physical_register, virtual_register_index);

        return virtual_register_index;
    }

    fn emitLiveInCopies(instruction_selection: *InstructionSelection, mir: *MIR, entry_block_index: BasicBlock.Index) !void {
        const entry_block = mir.blocks.get(entry_block_index);
        for (instruction_selection.liveins.keys(), instruction_selection.liveins.values()) |livein_physical_register, livein_virtual_register| {
            const vr = mir.virtual_registers.get(livein_virtual_register);
            const destination_operand = Operand{
                .id = switch (vr.register_class) {
                    .gp32 => .gp32,
                    .gp64 => .gp64,
                    else => |t| @panic(@tagName(t)),
                },
                .u = .{
                    .register = .{
                        .index = .{
                            .virtual = livein_virtual_register,
                        },
                    },
                },
                .flags = .{
                    .type = .def,
                },
            };
            const source_operand = Operand{
                .id = destination_operand.id,
                .u = .{
                    .register = .{
                        .index = .{
                            .physical = livein_physical_register,
                        },
                    },
                },
                .flags = .{},
            };

            const instruction_index = try mir.buildInstruction(instruction_selection, .copy, &.{
                destination_operand,
                source_operand,
            });

            try entry_block.instructions.insert(mir.allocator, 0, instruction_index);

            // TODO: addLiveIn MachineBasicBlock ? unreachable;
        }
        print("After livein: {}\n", .{instruction_selection.function});
    }
};

fn getRegisterClass(register: Register.Physical) Register.Class {
    _ = register;
}

const Instruction = struct {
    id: Id,
    operands: ArrayList(Operand.Index),
    parent: BasicBlock.Index,

    const Id = enum {
        call64pcrel32,
        copy,
        lea64r,
        mov32r0,
        mov32rm,
        mov64rm,
        mov32mr,
        mov64mr,
        mov32ri,
        mov32ri64,
        movsx64rm32,
        movsx64rr32,
        ret,
        syscall,
        ud2,
    };

    pub const Descriptor = struct {
        operands: []const Operand.Reference = &.{},
        opcode: u16 = 0,
        format: Format = .pseudo,
        flags: Flags,
        const Flags = packed struct {
            implicit_def: bool,
        };

        const Format = enum {
            pseudo,
            no_operands,
            add_reg,
            mrm_dest_mem,
            mrm_source_mem,
            mrm_source_reg,
        };
    };

    pub const List = BlockList(@This());
    pub const Index = List.Index;
    pub const Allocation = List.Allocation;

    pub const Iterator = struct {
        pub const Arguments = packed struct {
            use: bool,
            def: bool,
            element: Iterator.Element,
        };
        pub const Element = enum(u1) {
            operand = 0,
            instruction = 1,
        };

        fn Get(comptime arguments: Arguments) type {
            return struct {
                index: Operand.Index,
                mir: *MIR,

                const I = @This();

                fn new(mir: *MIR, index: Operand.Index) I {
                    var it = I{
                        .index = index,
                        .mir = mir,
                    };

                    if (!index.invalid) {
                        const operand = mir.operands.get(index);
                        if ((!arguments.use and operand.flags.type == .use) or (!arguments.def and operand.flags.type == .def)) {
                            it.advance();
                        }
                    }

                    return it;
                }

                const ReturnValue = switch (arguments.element) {
                    .instruction => Instruction,
                    .operand => Operand,
                };

                fn next(it: *I) ?ReturnValue.Index {
                    const original_operand_index = it.index;
                    switch (it.index.invalid) {
                        false => switch (arguments.element) {
                            .instruction => {
                                const original_operand = it.mir.operands.get(original_operand_index);
                                const instruction = original_operand.parent;
                                // const i_desc = it.mir.instructions.get(instruction);
                                // print("Instruction: {}\n", .{i_desc.id});
                                while (true) {
                                    it.advance();
                                    if (it.index.invalid) break;
                                    const it_operand = it.mir.operands.get(it.index);
                                    if (!it_operand.parent.eq(instruction)) break;
                                }

                                return instruction;
                            },
                            .operand => {
                                it.advance();
                                return original_operand_index;
                            },
                        },
                        true => return null,
                    }
                }

                fn nextPointer(it: *I) ?*ReturnValue {
                    if (it.next()) |next_index| {
                        const result = switch (arguments.element) {
                            .instruction => it.mir.instructions.get(next_index),
                            .operand => it.mir.operands.get(next_index),
                        };
                        return result;
                    } else return null;
                }

                fn advance(it: *I) void {
                    assert(!it.index.invalid);
                    it.advanceRaw();

                    if (!arguments.use) {
                        if (!it.index.invalid) {
                            const operand = it.mir.operands.get(it.index);
                            if (operand.flags.type == .use) {
                                it.index = Operand.Index.invalid;
                            } else {
                                //TODO: assert that is not debug
                            }
                        }
                    } else {
                        while (!it.index.invalid) {
                            const operand = it.mir.operands.get(it.index);
                            if (!arguments.def and operand.flags.type == .def) {
                                it.advanceRaw();
                            } else {
                                break;
                            }
                        }
                    }
                }

                fn advanceRaw(it: *I) void {
                    assert(!it.index.invalid);
                    const current_operand = it.mir.operands.get(it.index);
                    assert(current_operand.u == .register);
                    const next_index = current_operand.u.register.list.next;
                    it.index = next_index;
                }
            };
        }
    };
};
pub const Operand = struct {
    id: Operand.Id,
    u: union(enum) {
        register: Register,
        memory: Operand.Memory,
        immediate: Operand.Immediate,
        pc_relative: PCRelative,
        lea64mem: Lea64Mem,
    },
    flags: Flags,
    parent: Instruction.Index = Instruction.Index.invalid,

    pub const List = BlockList(@This());
    pub const Index = Operand.List.Index;
    pub const Allocation = Operand.List.Allocation;

    fn readsRegister(operand: Operand) bool {
        return !operand.flags.undef and !operand.flags.internal_read and (operand.flags.type == .use or operand.flags.subreg);
    }

    fn isOnRegisterUseList(operand: *const Operand) bool {
        assert(operand.u == .register);
        return !operand.u.register.list.previous.invalid;
    }

    const Id = enum {
        unknown,
        i32mem,
        i64mem,
        gp32,
        gp64,
        gp64_nosp,
        immediate,
        i64i32imm_brtarget,
        lea64mem,
    };
    pub const Type = enum(u1) {
        use = 0,
        def = 1,
    };

    const Flags = packed struct {
        type: Type = .use,
        dead_or_kill: bool = false,
        undef: bool = false,
        early_clobber: bool = false,
        internal_read: bool = false,
        subreg: bool = false,
        renamable: bool = false,
        implicit: bool = false,

        fn isDead(flags: Flags) bool {
            return flags.dead_or_kill and flags.type == .def;
        }

        fn isKill(flags: Flags) bool {
            return flags.dead_or_kill and flags.type != .def;
        }
    };

    // fn mapOperandIdToPayloadType(comptime id: Operand.Id) type {
    // }
    fn mapOperandIdToPayloadName(comptime id: Operand.Id) []const u8 {
        return switch (id) {
            .unknown => @compileError("unsupported"),
            .i32mem,
            .i64mem,
            => "memory",
            .gp32,
            .gp64,
            .gp64_nosp,
            => "register",
            .immediate => "immediate",
            .i64i32imm_brtarget => "pc_relative",

            .lea64mem => "lea64mem",
        };
    }

    fn operandUnionPayloadType(comptime id: Operand.Id) type {
        const dumb_union = @field(@as(Operand, undefined), "u");
        return @TypeOf(@field(dumb_union, mapOperandIdToPayloadName(id)));
    }

    const Reference = struct {
        id: Operand.Id,
        kind: Operand.Kind,
    };

    const Kind = enum {
        src,
        dst,
    };

    const Memory = struct {
        addressing_mode: AddressingMode,
        global_offset: i32 = 0,
    };

    const PCRelative = union(enum) {
        function_declaration: ir.Function.Declaration.Index,
        string_literal: ir.StringLiteral.Index,
        imm32: i32,
        imm8: i8,

        fn function(ir_function_decl_index: ir.Function.Declaration.Index) Operand {
            return Operand{
                .i64i32imm_brtarget = PCRelative{
                    .function_declaration = ir_function_decl_index,
                },
            };
        }
    };

    const Lea64Mem = struct {
        gp64: ?Register, // null means RIP, as this register is mandatory
        scale: u8,
        scale_reg: ?Register,
        displacement: PCRelative,

        fn stringLiteral(ir_load_string_literal_index: ir.StringLiteral.Index) Operand {
            return Operand{
                .id = .lea64mem,
                .u = .{
                    .lea64mem = .{
                        .gp64 = null, // rip
                        .scale = 1,
                        .scale_reg = null,
                        .displacement = PCRelative{
                            .string_literal = ir_load_string_literal_index,
                        },
                    },
                },
                .flags = .{},
            };
        }
    };

    const Immediate = u64;
};

const register_class_operand_matcher = std.EnumArray(Operand.Id, Register.Class).init(.{
    .unknown = .any,
    .i64i32imm_brtarget = .not_a_register,
    .i32mem = .not_a_register,
    .i64mem = .not_a_register,
    .gp32 = .gp32,
    .gp64 = .gp64,
    .gp64_nosp = .gp64_nosp,
    .immediate = .not_a_register,
    .lea64mem = .not_a_register,
});

const instruction_descriptors = std.EnumArray(Instruction.Id, Instruction.Descriptor).init(.{
    .call64pcrel32 = .{
        .format = .no_operands,
        .operands = &.{
            .{
                .id = .i64i32imm_brtarget,
                .kind = .src,
            },
        },
        .flags = .{
            .implicit_def = false,
        },
    },
    .copy = .{
        .format = .pseudo,
        .operands = &.{
            .{
                .id = .unknown,
                .kind = .dst,
            },
            .{
                .id = .unknown,
                .kind = .src,
            },
        },
        .flags = .{
            .implicit_def = false,
        },
    },
    .lea64r = .{
        .format = .mrm_source_mem,
        .operands = &.{
            .{
                .id = .gp64,
                .kind = .dst,
            },
            .{
                .id = .lea64mem,
                .kind = .src,
            },
        },
        .flags = .{
            .implicit_def = false,
        },
    },
    .mov32r0 = .{
        .format = .pseudo,
        .operands = &.{
            .{
                .id = .gp32,
                .kind = .dst,
            },
        },
        .flags = .{
            .implicit_def = false,
        },
    },
    .mov32rm = .{
        .format = .mrm_source_mem,
        .operands = &.{
            .{
                .id = .gp32,
                .kind = .dst,
            },
            .{
                .id = .i32mem,
                .kind = .src,
            },
        },
        .flags = .{
            .implicit_def = false,
        },
    },
    .mov64rm = .{
        .format = .mrm_source_mem,
        .operands = &.{
            .{
                .id = .gp64,
                .kind = .dst,
            },
            .{
                .id = .i64mem,
                .kind = .src,
            },
        },
        .flags = .{
            .implicit_def = false,
        },
    },
    .mov32mr = .{
        .format = .mrm_dest_mem,
        .operands = &.{
            .{
                .id = .i32mem,
                .kind = .dst,
            },
            .{
                .id = .gp32,
                .kind = .src,
            },
        },
        .flags = .{
            .implicit_def = false,
        },
    },
    .mov64mr = .{
        .format = .mrm_dest_mem,
        .operands = &.{
            .{
                .id = .i64mem,
                .kind = .dst,
            },
            .{
                .id = .gp64,
                .kind = .src,
            },
        },
        .flags = .{
            .implicit_def = false,
        },
    },
    .mov32ri = .{
        .format = .add_reg,
        .operands = &.{
            .{
                .id = .gp32,
                .kind = .dst,
            },
            .{
                .id = .immediate,
                .kind = .src,
            },
        },
        .flags = .{
            .implicit_def = false,
        },
    },
    .mov32ri64 = .{
        .format = .pseudo,
        .operands = &.{
            .{
                .id = .gp64,
                .kind = .dst,
            },
            .{
                .id = .immediate,
                .kind = .src,
            },
        },
        .flags = .{
            .implicit_def = false,
        },
    },
    .movsx64rm32 = .{
        .format = .mrm_source_reg,
        .operands = &.{
            .{
                .id = .gp64,
                .kind = .dst,
            },
            .{
                .id = .i32mem,
                .kind = .src,
            },
        },
        .flags = .{
            .implicit_def = false,
        },
    },
    .movsx64rr32 = .{
        .format = .mrm_source_reg,
        .operands = &.{
            .{
                .id = .gp64,
                .kind = .dst,
            },
            .{
                .id = .gp32,
                .kind = .src,
            },
        },
        .flags = .{
            .implicit_def = false,
        },
    },
    .ret = .{
        .format = .no_operands,
        .operands = &.{
            .{
                .id = .unknown,
                .kind = .src,
            },
        },
        .flags = .{
            .implicit_def = false,
        },
    },
    .syscall = .{
        .format = .no_operands,
        .operands = &.{},
        .flags = .{
            .implicit_def = false,
        },
    },
    .ud2 = .{
        .format = .no_operands,
        .operands = &.{},
        .flags = .{
            .implicit_def = false,
        },
    },
});

const Size = enum(u2) {
    one = 0,
    two = 1,
    four = 2,
    eight = 3,

    fn fromByteCount(byte_count: u8) Size {
        return @enumFromInt(@as(u2, @intCast(std.math.log2(byte_count))));
    }

    fn fromBitCount(bit_count: u16) Size {
        assert(bit_count % @bitSizeOf(u8) == 0);
        const byte_count: u8 = @intCast(bit_count >> 3);
        return fromByteCount(byte_count);
    }

    fn toInteger(comptime size: Size) type {
        return switch (size) {
            .one => u8,
            .two => u16,
            .four => u32,
            .eight => u64,
        };
    }

    fn fromType(t: ir.Type) Size {
        return fromByteCount(@intCast(t.getSize()));
    }
};

const BasicBlock = struct {
    instructions: ArrayList(Instruction.Index) = .{},
    current_stack_index: usize = 0,
    pub const List = BlockList(@This());
    pub const Index = List.Index;
    pub const Allocation = List.Allocation;
};

pub const MIR = struct {
    allocator: Allocator,
    ir: *ir.Result,
    target: std.Target,
    instructions: BlockList(Instruction) = .{},
    functions: BlockList(Function) = .{},
    blocks: BlockList(BasicBlock) = .{},
    operands: BlockList(Operand) = .{},
    instruction_selections: ArrayList(InstructionSelection) = .{},
    virtual_registers: BlockList(Register.Virtual) = .{},

    pub fn selectInstructions(allocator: Allocator, intermediate: *ir.Result, target: std.Target) !MIR {
        print("\n[INSTRUCTION SELECTION]\n\n", .{});
        var mir_stack = MIR{
            .allocator = allocator,
            .ir = intermediate,
            .target = target,
        };

        const mir = &mir_stack;

        try mir.blocks.ensureCapacity(allocator, intermediate.blocks.len);
        try mir.functions.ensureCapacity(allocator, intermediate.function_definitions.len);
        try mir.instruction_selections.ensureUnusedCapacity(allocator, intermediate.function_definitions.len);

        var function_definition_iterator = intermediate.function_definitions.iterator();

        while (function_definition_iterator.nextPointer()) |ir_function| {
            const fn_name = mir.ir.getFunctionName(ir_function.declaration);
            print("=========\n{}=========\n", .{ir_function});

            const instruction_selection = mir.instruction_selections.addOneAssumeCapacity();
            const function_allocation = try mir.functions.addOne(mir.allocator);
            const function = function_allocation.ptr;
            function.* = .{
                .mir = mir,
                .instruction_selection = instruction_selection,
                .name = fn_name,
            };
            instruction_selection.* = .{
                .function = function,
            };

            const ir_function_declaration = mir.ir.function_declarations.get(ir_function.declaration);
            const calling_convention = calling_conventions.get(ir_function_declaration.calling_convention);

            try instruction_selection.block_map.ensureUnusedCapacity(allocator, @intCast(ir_function.blocks.items.len));
            try function.blocks.ensureTotalCapacity(allocator, ir_function.blocks.items.len);
            for (ir_function.blocks.items) |block| {
                const block_allocation = try mir.blocks.append(allocator, .{});
                instruction_selection.block_map.putAssumeCapacity(block, block_allocation.index);
                function.blocks.appendAssumeCapacity(block_allocation.index);
            }

            for (mir.ir.blocks.get(ir_function.blocks.items[0]).instructions.items) |ir_instruction_index| {
                const ir_instruction = mir.ir.instructions.get(ir_instruction_index);

                // TODO: take into account exceptions, dynamic allocas?
                if (ir_instruction.* == .stack) {
                    const stack = mir.ir.stack_references.get(ir_instruction.stack);
                    const ir_type = getIrType(mir.ir, ir_instruction_index);
                    const value_type = resolveType(ir_type);
                    const type_info = value_types.get(value_type);
                    const total_size = type_info.size * stack.count;
                    const frame_index = try mir.createStackObject(instruction_selection, total_size, @intCast(stack.alignment), ir_instruction_index, false);
                    try instruction_selection.stack_map.putNoClobber(allocator, ir_instruction_index, frame_index);
                }

                // TODO: handle stack references outside blocks
            }

            instruction_selection.current_block = function.blocks.items[0];

            try instruction_selection.lowerArguments(mir, ir_function);

            print("Block count: {}\n", .{function.blocks.items.len});
            var block_i: usize = function.blocks.items.len;

            while (block_i > 0) {
                block_i -= 1;

                const block_index = function.blocks.items[block_i];
                _ = block_index;
                const ir_block_index = ir_function.blocks.items[block_i];
                const ir_block = mir.ir.blocks.get(ir_block_index);

                var instruction_i: usize = ir_block.instructions.items.len;
                print("Instruction count: {}\n", .{instruction_i});

                var folded_load = false;

                while (instruction_i > 0) {
                    instruction_i -= 1;

                    const ir_instruction_index = ir_block.instructions.items[instruction_i];
                    const ir_instruction = mir.ir.instructions.get(ir_instruction_index);

                    instruction_selection.local_value_map.clearRetainingCapacity();

                    print("Instruction #{}\n", .{instruction_i});

                    switch (ir_instruction.*) {
                        .ret => |ir_ret_index| {
                            const ir_ret = mir.ir.returns.get(ir_ret_index);
                            const value_type = resolveType(getIrType(mir.ir, ir_ret.instruction));
                            const source_register = try instruction_selection.getRegisterForValue(mir, ir_ret.instruction);

                            const register_class = register_classes.get(value_type);

                            const physical_register = Register{
                                .index = .{
                                    .physical = switch (register_class) {
                                        .gp32 => .eax,
                                        .gp64 => .rax,
                                        else => unreachable,
                                    },
                                },
                            };
                            const operand_id: Operand.Id = switch (register_class) {
                                .gp32 => .gp32,
                                .gp64 => .gp64,
                                else => unreachable,
                            };

                            const copy = try mir.buildInstruction(instruction_selection, .copy, &.{
                                Operand{
                                    .id = operand_id,
                                    .u = .{
                                        .register = physical_register,
                                    },
                                    .flags = .{
                                        .type = .def,
                                    },
                                },
                                Operand{
                                    .id = operand_id,
                                    .u = .{
                                        .register = source_register,
                                    },
                                    .flags = .{},
                                },
                            });

                            try instruction_selection.instruction_cache.append(mir.allocator, copy);

                            const ret = try mir.buildInstruction(instruction_selection, .ret, &.{
                                Operand{
                                    .id = operand_id,
                                    .u = .{
                                        .register = physical_register,
                                    },
                                    .flags = .{
                                        .implicit = true,
                                    },
                                },
                            });
                            try instruction_selection.instruction_cache.append(mir.allocator, ret);
                        },
                        .load_integer => try instruction_selection.materializeInteger(mir, ir_instruction_index),
                        .@"unreachable" => try instruction_selection.instruction_cache.append(mir.allocator, try mir.buildInstruction(instruction_selection, .ud2, &.{})),
                        .syscall => |ir_syscall_index| {
                            const ir_syscall = mir.ir.syscalls.get(ir_syscall_index);
                            const syscall_register_list = calling_convention.syscall_registers[0..ir_syscall.arguments.items.len];

                            for (ir_syscall.arguments.items, syscall_register_list) |ir_argument_index, syscall_register| {
                                //print("index: {}\n", .{index});
                                const source_register = try instruction_selection.getRegisterForValue(mir, ir_argument_index);
                                const destination_register = Register{
                                    .index = .{
                                        .physical = syscall_register,
                                    },
                                };

                                const source_operand = Operand{
                                    .id = .gp64,
                                    .u = .{
                                        .register = source_register,
                                    },
                                    .flags = .{},
                                };
                                const destination_operand = Operand{
                                    .id = .gp64,
                                    .u = .{
                                        .register = destination_register,
                                    },
                                    .flags = .{ .type = .def },
                                };

                                const argument_copy = try mir.buildInstruction(instruction_selection, .copy, &.{
                                    destination_operand,
                                    source_operand,
                                });

                                try instruction_selection.instruction_cache.append(mir.allocator, argument_copy);
                            }

                            // TODO: handle syscall return value
                            const syscall = try mir.buildInstruction(instruction_selection, .syscall, &.{});
                            try instruction_selection.instruction_cache.append(mir.allocator, syscall);

                            const produce_syscall_return_value = switch (instruction_i == ir_block.instructions.items.len - 2) {
                                true => blk: {
                                    const last_block_instruction = mir.ir.instructions.get(ir_block.instructions.items[ir_block.instructions.items.len - 1]);
                                    break :blk switch (last_block_instruction.*) {
                                        .@"unreachable" => false,
                                        else => |t| @panic(@tagName(t)),
                                    };
                                },
                                false => true,
                            };

                            if (produce_syscall_return_value) {
                                const physical_return_register = Register{
                                    .index = .{
                                        .physical = .rax,
                                    },
                                };
                                const physical_return_operand = Operand{
                                    .id = .gp64,
                                    .u = .{
                                        .register = physical_return_register,
                                    },
                                    .flags = .{ .type = .def },
                                };

                                const virtual_return_register = try instruction_selection.getRegisterForValue(mir, ir_instruction_index);
                                const virtual_return_operand = Operand{
                                    .id = .gp64,
                                    .u = .{
                                        .register = virtual_return_register,
                                    },
                                    .flags = .{ .type = .def },
                                };

                                const syscall_result_copy = try mir.buildInstruction(instruction_selection, .copy, &.{
                                    virtual_return_operand,
                                    physical_return_operand,
                                });
                                try instruction_selection.instruction_cache.append(mir.allocator, syscall_result_copy);
                            }
                        },
                        .sign_extend => |ir_cast_index| {
                            const ir_sign_extend = mir.ir.casts.get(ir_cast_index);
                            assert(!folded_load);
                            const ir_source_instruction = blk: {
                                var source = ir_sign_extend.value;
                                const source_instruction = mir.ir.instructions.get(source);
                                const result = switch (source_instruction.*) {
                                    .load => b: {
                                        const load = mir.ir.loads.get(source_instruction.load);
                                        folded_load = true;
                                        break :b load.instruction;
                                    },
                                    else => |t| @panic(@tagName(t)),
                                };
                                break :blk result;
                            };

                            const destination_type = resolveType(ir_sign_extend.type);

                            const source_type = resolveType(getIrType(mir.ir, ir_source_instruction));

                            if (destination_type != source_type) {
                                const instruction_id: Instruction.Id = switch (source_type) {
                                    .i32 => switch (destination_type) {
                                        .i64 => switch (folded_load) {
                                            true => .movsx64rm32,
                                            false => .movsx64rr32,
                                        },
                                        else => unreachable,
                                    },
                                    else => |t| @panic(@tagName(t)),
                                };

                                const instruction_descriptor = instruction_descriptors.getPtrConst(instruction_id);
                                assert(instruction_descriptor.operands.len == 2);
                                const destination_operand_index = 0;
                                const destination_register = try instruction_selection.getRegisterForValue(mir, ir_instruction_index);
                                const destination_operand = mir.constrainOperandRegisterClass(instruction_descriptor, destination_register, destination_operand_index, .{ .type = .def });
                                const source_operand_index = 1;

                                const source_operand = switch (folded_load) {
                                    true => blk: {
                                        const addressing_mode = instruction_selection.getAddressingModeFromIr(mir, ir_source_instruction);
                                        const memory_id: Operand.Id = switch (source_type) {
                                            .i32 => .i32mem,
                                            .i64 => .i64mem,
                                            else => |t| @panic(@tagName(t)),
                                        };
                                        const operand = Operand{
                                            .id = memory_id,
                                            .u = .{
                                                .memory = .{
                                                    .addressing_mode = addressing_mode,
                                                },
                                            },
                                            .flags = .{},
                                        };
                                        break :blk operand;
                                    },
                                    false => blk: {
                                        const source_register = try instruction_selection.getRegisterForValue(mir, ir_source_instruction);
                                        break :blk mir.constrainOperandRegisterClass(instruction_descriptor, source_register, source_operand_index, .{});
                                    },
                                };

                                const sign_extend = try mir.buildInstruction(instruction_selection, instruction_id, &.{
                                    destination_operand,
                                    source_operand,
                                });

                                try instruction_selection.instruction_cache.append(mir.allocator, sign_extend);

                                try instruction_selection.updateValueMap(mir.allocator, ir_instruction_index, destination_register, false);
                            } else {
                                unreachable;
                            }
                        },
                        .load => |ir_load_index| {
                            if (folded_load) {
                                folded_load = false;
                                continue;
                            }

                            const ir_load = mir.ir.loads.get(ir_load_index);
                            const ir_source = ir_load.instruction;
                            const addressing_mode = instruction_selection.getAddressingModeFromIr(mir, ir_source);
                            const value_type = resolveType(getIrType(mir.ir, ir_source));

                            switch (value_type) {
                                inline .i32,
                                .i64,
                                => |vt| {
                                    const instruction_id: Instruction.Id = switch (vt) {
                                        .i32 => .mov32rm,
                                        .i64 => .mov64rm,
                                        else => |t| @panic(@tagName(t)),
                                    };
                                    const memory_id: Operand.Id = switch (vt) {
                                        .i32 => .i32mem,
                                        .i64 => .i64mem,
                                        else => |t| @panic(@tagName(t)),
                                    };

                                    const instruction_descriptor = instruction_descriptors.getPtrConst(instruction_id);

                                    const destination_register = try instruction_selection.getRegisterForValue(mir, ir_instruction_index);
                                    const destination_operand_index = 0;
                                    const destination_operand_id = instruction_descriptor.operands[destination_operand_index].id;
                                    const destination_operand = Operand{
                                        .id = destination_operand_id,
                                        .u = .{
                                            .register = destination_register,
                                        },
                                        .flags = .{ .type = .def },
                                    };

                                    const source_operand = Operand{
                                        .id = memory_id,
                                        .u = .{
                                            .memory = .{
                                                .addressing_mode = addressing_mode,
                                            },
                                        },
                                        .flags = .{},
                                    };

                                    const load = try mir.buildInstruction(instruction_selection, instruction_id, &.{
                                        destination_operand,
                                        source_operand,
                                    });
                                    try instruction_selection.instruction_cache.append(mir.allocator, load);

                                    try instruction_selection.updateValueMap(mir.allocator, ir_instruction_index, destination_register, false);
                                },
                                else => |t| @panic(@tagName(t)),
                            }
                        },
                        .store => |ir_store_index| {
                            const ir_store = mir.ir.stores.get(ir_store_index);
                            const ir_source = ir_store.source;

                            const ir_destination = ir_store.destination;
                            const addressing_mode = instruction_selection.getAddressingModeFromIr(mir, ir_destination);

                            const source_register = try instruction_selection.getRegisterForValue(mir, ir_source);

                            const value_type = resolveType(getIrType(mir.ir, ir_source));

                            switch (value_type) {
                                inline .i32, .i64 => |vt| {
                                    const instruction_id: Instruction.Id = switch (vt) {
                                        // TODO, non-temporal SSE2 MOVNT
                                        .i32 => .mov32mr,
                                        .i64 => .mov64mr,
                                        else => |t| @panic(@tagName(t)),
                                    };

                                    const instruction_descriptor = comptime instruction_descriptors.getPtrConst(instruction_id);
                                    const source_operand_index = instruction_descriptor.operands.len - 1;
                                    const source_operand_id = instruction_descriptor.operands[source_operand_index].id;
                                    const source_operand = Operand{
                                        .id = source_operand_id,
                                        .u = .{
                                            .register = source_register,
                                        },
                                        .flags = .{},
                                    };

                                    const destination_operand_id = instruction_descriptor.operands[0].id;
                                    const destination_operand = Operand{
                                        .id = destination_operand_id,
                                        .u = .{
                                            .memory = .{
                                                .addressing_mode = addressing_mode,
                                            },
                                        },
                                        .flags = .{},
                                    };

                                    const store = try mir.buildInstruction(instruction_selection, instruction_id, &.{
                                        destination_operand,
                                        source_operand,
                                    });

                                    try instruction_selection.instruction_cache.append(mir.allocator, store);
                                },
                                else => |t| @panic(@tagName(t)),
                            }
                        },
                        .stack => {
                            assert(instruction_selection.stack_map.get(ir_instruction_index) != null);
                        },
                        .call => |ir_call_index| {
                            const ir_call = mir.ir.calls.get(ir_call_index);
                            for (ir_call.arguments, 0..) |ir_argument_index, index| {
                                // print("index: {}\n", .{index});
                                const source_register = try instruction_selection.getRegisterForValue(mir, ir_argument_index);
                                const source_value_type = resolveType(getIrType(mir.ir, ir_argument_index));
                                const source_register_class = register_classes.get(source_value_type);
                                const argument_register = calling_convention.argument_registers.get(source_register_class)[index];
                                // print("Argument register: {}\n", .{argument_register});

                                const destination_register = Register{
                                    .index = .{
                                        .physical = argument_register,
                                    },
                                };

                                const operand_id: Operand.Id = switch (source_register_class) {
                                    .gp32 => .gp32,
                                    .gp64 => .gp64,
                                    else => unreachable,
                                };
                                const source_operand = Operand{
                                    .id = operand_id,
                                    .u = .{
                                        .register = source_register,
                                    },
                                    .flags = .{},
                                };
                                const destination_operand = Operand{
                                    .id = operand_id,
                                    .u = .{
                                        .register = destination_register,
                                    },
                                    .flags = .{},
                                };

                                const copy = try mir.buildInstruction(instruction_selection, .copy, &.{
                                    destination_operand,
                                    source_operand,
                                });

                                try instruction_selection.instruction_cache.append(mir.allocator, copy);
                            }

                            const call = try mir.buildInstruction(instruction_selection, .call64pcrel32, &.{
                                Operand{
                                    .id = .i64i32imm_brtarget,
                                    .u = .{
                                        .pc_relative = .{
                                            .function_declaration = ir_call.function,
                                        },
                                    },
                                    .flags = .{},
                                },
                            });

                            try instruction_selection.instruction_cache.append(mir.allocator, call);

                            const ir_return_type = mir.ir.function_declarations.get(ir_call.function).return_type;
                            switch (ir_return_type) {
                                .void,
                                .noreturn,
                                => {},
                                else => {
                                    const return_type = resolveType(ir_return_type);
                                    switch (return_type) {
                                        inline .i64, .i32 => |rt| {
                                            const register_operand_id = switch (rt) {
                                                .i32 => .gp32,
                                                .i64 => .gp64,
                                                else => unreachable,
                                            };
                                            const physical_return_register = Register{
                                                .index = .{
                                                    .physical = switch (rt) {
                                                        .i32 => .eax,
                                                        .i64 => .rax,
                                                        else => unreachable,
                                                    },
                                                },
                                            };

                                            const physical_return_operand = Operand{
                                                .id = register_operand_id,
                                                .u = .{
                                                    .register = physical_return_register,
                                                },
                                                .flags = .{},
                                            };

                                            const virtual_return_register = try instruction_selection.getRegisterForValue(mir, ir_instruction_index);
                                            const virtual_return_operand = Operand{
                                                .id = register_operand_id,
                                                .u = .{
                                                    .register = virtual_return_register,
                                                },
                                                .flags = .{ .type = .def },
                                            };

                                            const call_result_copy = try mir.buildInstruction(instruction_selection, .copy, &.{
                                                virtual_return_operand,
                                                physical_return_operand,
                                            });

                                            try instruction_selection.instruction_cache.append(mir.allocator, call_result_copy);
                                        },
                                        else => |t| @panic(@tagName(t)),
                                    }
                                },
                            }
                        },
                        else => |t| @panic(@tagName(t)),
                    }

                    var i: usize = instruction_selection.instruction_cache.items.len;
                    const block = mir.blocks.get(instruction_selection.current_block);

                    while (i > 0) {
                        i -= 1;

                        const instruction_index = instruction_selection.instruction_cache.items[i];
                        const instruction = mir.instructions.get(instruction_index);
                        print("Inserting instruction #{} ({s}) into index {} (instruction count: {})\n", .{ instruction_index.uniqueInteger(), @tagName(instruction.id), block.current_stack_index, block.instructions.items.len });
                        try block.instructions.insert(mir.allocator, block.current_stack_index, instruction_index);
                    }

                    instruction_selection.instruction_cache.clearRetainingCapacity();
                }
            }

            try instruction_selection.emitLiveInCopies(mir, function.blocks.items[0]);

            print("=========\n{}=========\n", .{function});
        }

        return mir_stack;
    }

    fn getNextInstructionIndex(mir: *MIR, instruction_index: Instruction.Index) usize {
        const instruction = mir.instructions.get(instruction_index);
        const parent_block = mir.blocks.get(instruction.parent);
        const next = for (parent_block.instructions.items, 0..) |index, i| {
            if (index.eq(instruction_index)) break i + 1;
        } else unreachable;
        return next;
    }

    fn setPhysicalRegister(mir: *MIR, instruction_selection: *InstructionSelection, operand_index: Operand.Index, register: Register.Physical) bool {
        const operand = mir.operands.get(operand_index);
        if (!operand.flags.subreg) {
            mir.setRegisterInOperand(instruction_selection, operand_index, .{
                .physical = register,
            });
            operand.flags.renamable = true;
            return false;
        }

        unreachable;
    }

    fn setRegisterInOperand(mir: *MIR, instruction_selection: *InstructionSelection, operand_index: Operand.Index, register: Register.Index) void {
        const operand = mir.operands.get(operand_index);
        assert(operand.u == .register);
        assert(!std.meta.eql(operand.u.register.index, register));
        operand.flags.renamable = false;
        mir.removeRegisterOperandFromUseList(instruction_selection, operand);
        operand.u.register.index = register;
        mir.addRegisterOperandFromUseList(instruction_selection, operand_index);
    }

    fn addRegisterOperandFromUseList(mir: *MIR, instruction_selection: *InstructionSelection, operand_index: Operand.Index) void {
        const operand = mir.operands.get(operand_index);
        assert(!operand.isOnRegisterUseList());
        const head_index_ptr = mir.getRegisterListHead(instruction_selection, operand.u.register);
        const head_index = head_index_ptr.*;

        switch (head_index.invalid) {
            false => {
                const head_operand = mir.operands.get(head_index);
                assert(std.meta.eql(head_operand.u.register.index, operand.u.register.index));
                const last_operand_index = head_operand.u.register.list.previous;
                const last_operand = mir.operands.get(last_operand_index);
                assert(std.meta.eql(last_operand.u.register.index, operand.u.register.index));
                head_operand.u.register.list.previous = operand_index;
                operand.u.register.list.previous = last_operand_index;

                switch (operand.flags.type) {
                    .def => {
                        operand.u.register.list.next = head_index;
                        head_index_ptr.* = operand_index;
                    },
                    .use => {
                        operand.u.register.list.next = Operand.Index.invalid;
                        last_operand.u.register.list.next = operand_index;
                    },
                }
            },
            true => {
                operand.u.register.list.previous = operand_index;
                operand.u.register.list.next = Operand.Index.invalid;
                head_index_ptr.* = operand_index;
            },
        }
    }

    fn removeRegisterOperandFromUseList(mir: *MIR, instruction_selection: *InstructionSelection, operand: *Operand) void {
        assert(operand.isOnRegisterUseList());
        const head_index_ptr = mir.getRegisterListHead(instruction_selection, operand.u.register);
        const head_index = head_index_ptr.*;
        assert(!head_index.invalid);

        const operand_previous = operand.u.register.list.previous;
        const operand_next = operand.u.register.list.next;

        const head = mir.operands.get(head_index);
        if (operand == head) {
            head_index_ptr.* = operand_next;
        } else {
            const previous = mir.operands.get(operand_previous);
            previous.u.register.list.next = operand_next;
        }

        const next = switch (operand_next.invalid) {
            false => mir.operands.get(operand_next),
            true => head,
        };
        next.u.register.list.previous = operand_previous;

        operand.u.register.list.previous = Operand.Index.invalid;
        operand.u.register.list.next = Operand.Index.invalid;
    }

    fn constrainRegisterClass(mir: *MIR, register: Register, old_register_class: Register.Class) ?Register.Class {
        const new_register_class = switch (register.index) {
            .virtual => |virtual_register_index| mir.virtual_registers.get(virtual_register_index).register_class,
            else => unreachable,
        };

        // print("Old: {}. New: {}\n", .{ old_register_class, new_register_class });
        switch (old_register_class == new_register_class) {
            true => return new_register_class,
            false => unreachable,
        }
        unreachable;
    }

    fn constrainOperandRegisterClass(mir: *MIR, instruction_descriptor: *const Instruction.Descriptor, register: Register, operand_index: usize, flags: Operand.Flags) Operand {
        assert(register.index == .virtual);
        const operand_reference = instruction_descriptor.operands[operand_index];
        const operand_register_class = register_class_operand_matcher.get(operand_reference.id);
        // print("Constraint operand #{} with {} (out of {})\n", .{ operand_index, operand_register_class, operand_reference.id });

        // const register_class = op
        if (mir.constrainRegisterClass(register, operand_register_class) == null) {
            unreachable;
        }

        return Operand{
            .id = operand_reference.id,
            .u = .{
                .register = register,
            },
            .flags = flags,
        };
    }

    fn createVirtualRegister(mir: *MIR, register_class: Register.Class) !Register {
        const virtual_register_index = try mir.createVirtualRegisterIndexed(register_class);
        return Register{
            .index = .{
                .virtual = virtual_register_index,
            },
        };
    }

    fn createVirtualRegisterIndexed(mir: *MIR, register_class: Register.Class) !Register.Virtual.Index {
        const allocation = try mir.virtual_registers.append(mir.allocator, .{
            .register_class = register_class,
        });
        return allocation.index;
    }

    const RegisterBitset = std.EnumSet(Register.Physical);

    const RegisterAllocator = struct {
        reserved: RegisterBitset = RegisterBitset.initEmpty(),
        register_states: std.EnumArray(Register.Physical, Register.State) = std.EnumArray(Register.Physical, Register.State).initFill(.free),
        used_in_instruction: RegisterBitset = RegisterBitset.initEmpty(),
        may_live_across_blocks: std.DynamicBitSetUnmanaged,
        live_virtual_registers: std.AutoArrayHashMapUnmanaged(Register.Virtual.Index, LiveRegister) = .{},
        stack_slots: std.AutoHashMapUnmanaged(Register.Virtual.Index, u32) = .{},
        coalesced: ArrayList(Instruction.Index) = .{},

        fn init(mir: *MIR, instruction_selection: *InstructionSelection) !RegisterAllocator {
            var result = RegisterAllocator{
                .may_live_across_blocks = try std.DynamicBitSetUnmanaged.initEmpty(mir.allocator, mir.virtual_registers.len),
            };

            result.reserved.setPresent(.fpcw, true);
            result.reserved.setPresent(.fpsw, true);
            result.reserved.setPresent(.mxcsr, true);

            for ((try getSubregisters(mir.allocator, .rsp)).keys()) |rsp_subreg| {
                result.reserved.setPresent(rsp_subreg, true);
            }

            result.reserved.setPresent(.ssp, true);

            for ((try getSubregisters(mir.allocator, .rip)).keys()) |rip_subreg| {
                result.reserved.setPresent(rip_subreg, true);
            }

            // TODO: complete
            const has_frame_pointer = instruction_selection.stack_map.entries.len > 0;
            if (has_frame_pointer) {
                for ((try getSubregisters(mir.allocator, .rbp)).keys()) |rbp_subreg| {
                    result.reserved.setPresent(rbp_subreg, true);
                }
            }

            // TODO: complete
            const has_base_pointer = false;
            if (has_base_pointer) {
                // TODO
            }

            result.reserved.setPresent(.cs, true);
            result.reserved.setPresent(.ss, true);
            result.reserved.setPresent(.ds, true);
            result.reserved.setPresent(.es, true);
            result.reserved.setPresent(.fs, true);
            result.reserved.setPresent(.gs, true);

            inline for ([8]Register.Physical{ .st0, .st1, .st2, .st3, .st4, .st5, .st6, .st7 }) |st_reg| {
                result.reserved.setPresent(st_reg, true);
            }

            const has_avx512 = false;
            if (!has_avx512) {
                // TODO xmm alias
            }

            // TODO: callee saved registers (CSR)

            // TODO: more setup

            return result;
        }

        fn useVirtualRegister(register_allocator: *RegisterAllocator, mir: *MIR, instruction_selection: *InstructionSelection, instruction_index: Instruction.Index, virtual_register: Register.Virtual.Index, instruction_operand_index: u8) !bool {
            const instruction = mir.instructions.get(instruction_index);
            const operand_index = instruction.operands.items[instruction_operand_index];
            const operand = mir.operands.get(operand_index);
            const gop = try register_allocator.live_virtual_registers.getOrPut(mir.allocator, virtual_register);
            const live_register = gop.value_ptr;
            switch (gop.found_existing) {
                true => {
                    // TODO: asserts
                    const assert_result = !operand.flags.isKill() or live_register.last_use.eq(instruction_index);
                    if (assert_result) {
                        print("Existing live register at instruction #{}: {}\n", .{ instruction_index.uniqueInteger(), live_register });
                        print("Function until now: {}\n", .{instruction_selection.function});
                        assert(assert_result);
                    }
                },
                false => {
                    if (!operand.flags.isKill()) {
                        // TODO some logic
                        // unreachable;
                        if (register_allocator.mayLiveOut(mir, instruction_selection, virtual_register)) {
                            unreachable;
                        } else {
                            operand.flags.dead_or_kill = true;
                        }
                    }

                    live_register.* = .{
                        .virtual = virtual_register,
                    };
                },
            }

            if (live_register.physical == .no_register) {
                const hint: ?Register = blk: {
                    if (instruction.id == .copy) {
                        const source_operand = mir.operands.get(instruction.operands.items[1]);
                        assert(source_operand.u == .register);
                        if (!source_operand.flags.subreg) {
                            const destination_operand = mir.operands.get(instruction.operands.items[0]);
                            const hint_register = destination_operand.u.register;
                            assert(hint_register.index == .physical);
                            break :blk hint_register;
                        }
                    }
                    break :blk null;
                };
                // TODO: handle allocation error here
                register_allocator.allocateVirtualRegister(mir, instruction_selection, instruction_index, live_register, hint, false) catch unreachable;
            }

            live_register.last_use = instruction_index;

            register_allocator.markUsedRegisterInInstruction(live_register.physical);
            return mir.setPhysicalRegister(instruction_selection, operand_index, live_register.physical);
        }

        fn isRegisterInClass(register: Register.Physical, register_class: Register.Class) bool {
            const result = std.mem.indexOfScalar(Register.Physical, registers_by_class.get(register_class), register) != null;
            return result;
        }

        fn allocateVirtualRegister(register_allocator: *RegisterAllocator, mir: *MIR, instruction_selection: *InstructionSelection, instruction_index: Instruction.Index, live_register: *LiveRegister, maybe_hint: ?Register, look_at_physical_register_uses: bool) !void {
            assert(live_register.physical == .no_register);
            const virtual_register = live_register.virtual;
            const register_class = mir.virtual_registers.get(live_register.virtual).register_class;

            if (maybe_hint) |hint_register| {
                if (hint_register.index == .physical
                // TODO : and isAllocatable
                and isRegisterInClass(hint_register.index.physical, register_class) and !register_allocator.isRegisterUsedInInstruction(hint_register.index.physical, look_at_physical_register_uses)) {
                    if (register_allocator.register_states.get(hint_register.index.physical) == .free) {
                        register_allocator.assignVirtualToPhysicalRegister(live_register, hint_register.index.physical);
                        return;
                    }
                }
            }

            const maybe_hint2 = register_allocator.traceCopies(mir, instruction_selection, virtual_register);
            if (maybe_hint2) |hint| {
                // TODO
                const allocatable = true;
                if (hint == .physical and allocatable and isRegisterInClass(hint.physical, register_class) and !register_allocator.isRegisterUsedInInstruction(hint.physical, look_at_physical_register_uses)) {
                    const physical_register = hint.physical;
                    if (register_allocator.register_states.get(physical_register) == .free) {
                        register_allocator.assignVirtualToPhysicalRegister(live_register, physical_register);
                        return;
                    } else {
                        print("Second hint {s} not free\n", .{@tagName(physical_register)});
                    }
                } else {
                    unreachable;
                }
            } else {
                print("Can't take hint for VR{} for instruction #{}\n", .{ virtual_register.uniqueInteger(), instruction_index.uniqueInteger() });
            }

            const register_class_members = registers_by_class.get(register_class);
            assert(register_class_members.len > 0);

            var best_cost: u32 = SpillCost.impossible;
            var best_register = Register.Physical.no_register;
            // print("Candidates for {s}: ", .{@tagName(register_class)});
            // for (register_class_members) |candidate_register| {
            //     print("{s}, ", .{@tagName(candidate_register)});
            // }
            print("\n", .{});
            for (register_class_members) |candidate_register| {
                if (register_allocator.isRegisterUsedInInstruction(candidate_register, look_at_physical_register_uses)) continue;
                const spill_cost = register_allocator.computeSpillCost(candidate_register);

                if (spill_cost == 0) {
                    register_allocator.assignVirtualToPhysicalRegister(live_register, candidate_register);
                    return;
                }

                if (maybe_hint) |hint| {
                    if (hint.index.physical == candidate_register) {
                        unreachable;
                    }
                }

                if (maybe_hint2) |hint| {
                    if (hint.physical == candidate_register) {
                        unreachable;
                    }
                }

                if (spill_cost < best_cost) {
                    best_register = candidate_register;
                    best_cost = spill_cost;
                }
            }

            assert(best_register != .no_register);

            unreachable;
        }

        fn computeSpillCost(register_allocator: *RegisterAllocator, physical_register: Register.Physical) u32 {
            const register_state = register_allocator.register_states.get(physical_register);
            return switch (register_state) {
                .free => 0,
                .preassigned => SpillCost.impossible,
                .virtual => |virtual_register_index| blk: {
                    const sure_spill = register_allocator.stack_slots.get(virtual_register_index) != null or register_allocator.live_virtual_registers.get(virtual_register_index).?.live_out;
                    break :blk if (sure_spill) SpillCost.clean else SpillCost.dirty;
                },
                .livein => unreachable,
            };
        }

        const SpillCost = struct {
            const clean = 50;
            const dirty = 100;
            const pref_bonus = 20;
            const impossible = std.math.maxInt(u32);
        };

        fn isRegisterUsedInInstruction(register_allocator: *RegisterAllocator, physical_register: Register.Physical, look_at_physical_register_uses: bool) bool {
            _ = look_at_physical_register_uses;

            // TODO: register masks

            if (register_allocator.used_in_instruction.contains(physical_register)) {
                return true;
            }
            // TODO
            //else if (look_at_physical_register_uses and register_classes.ph
            else {
                return false;
            }
        }

        fn traceCopyChain(register_allocator: *RegisterAllocator, mir: *MIR, instruction_selection: *InstructionSelection, register: Register) ?Register.Index {
            _ = register_allocator;
            const chain_length_limit = 3;
            _ = chain_length_limit;
            var chain_try_count: u32 = 0;
            _ = chain_try_count;
            while (true) {
                switch (register.index) {
                    .physical => return register.index,
                    .virtual => |vri| {
                        const virtual_head_index_ptr = mir.getRegisterListHead(instruction_selection, .{
                            .index = .{
                                .virtual = vri,
                            },
                        });

                        var vdef = Instruction.Iterator.Get(.{
                            .use = false,
                            .def = true,
                            .element = .instruction,
                        }).new(mir, virtual_head_index_ptr.*);

                        const vdef_instruction = vdef.nextPointer() orelse break;
                        if (vdef.nextPointer()) |_| break;

                        switch (vdef_instruction.id) {
                            else => |t| @panic(@tagName(t)),
                        }
                        unreachable;
                    },
                }
            }

            return null;
        }

        fn traceCopies(register_allocator: *RegisterAllocator, mir: *MIR, instruction_selection: *InstructionSelection, virtual_register_index: Register.Virtual.Index) ?Register.Index {
            const head_index_ptr = mir.getRegisterListHead(instruction_selection, .{
                .index = .{
                    .virtual = virtual_register_index,
                },
            });
            var define_instructions = Instruction.Iterator.Get(.{
                .use = false,
                .def = true,
                .element = .instruction,
            }).new(mir, head_index_ptr.*);

            const definition_limit = 3;
            var try_count: u32 = 0;
            while (define_instructions.next()) |instruction_index| {
                const instruction = mir.instructions.get(instruction_index);
                switch (instruction.id) {
                    .mov32rm => unreachable,
                    .copy => {
                        const operand_index = instruction.operands.items[1];
                        const operand = mir.operands.get(operand_index);

                        if (register_allocator.traceCopyChain(mir, instruction_selection, operand.u.register)) |register| {
                            return register;
                        }

                        print("Missed oportunity for register allocation tracing copy chain for VR{}\n", .{virtual_register_index.uniqueInteger()});
                    },
                    else => |t| @panic(@tagName(t)),
                }

                try_count += 1;
                if (try_count >= definition_limit) break;
            }

            return null;
        }

        fn assignVirtualToPhysicalRegister(register_allocator: *RegisterAllocator, live_register: *LiveRegister, register: Register.Physical) void {
            const virtual_register = live_register.virtual;
            assert(live_register.physical == .no_register);
            assert(register != .no_register);
            live_register.physical = register;
            register_allocator.register_states.set(register, .{
                .virtual = virtual_register,
            });

            print("Assigning V{} to {s}\n", .{ virtual_register.uniqueInteger(), @tagName(register) });
            // TODO: debug info
        }

        fn usePhysicalRegister(register_allocator: *RegisterAllocator, mir: *MIR, instruction_selection: *InstructionSelection, instruction_index: Instruction.Index, physical_register: Register.Physical) !bool {
            const displaced_any = try register_allocator.displacePhysicalRegister(mir, instruction_selection, instruction_index, physical_register);
            register_allocator.register_states.set(physical_register, .preassigned);
            register_allocator.markUsedRegisterInInstruction(physical_register);
            return displaced_any;
        }

        fn displacePhysicalRegister(register_allocator: *RegisterAllocator, mir: *MIR, instruction_selection: *InstructionSelection, instruction_index: Instruction.Index, physical_register: Register.Physical) !bool {
            const state = register_allocator.register_states.getPtr(physical_register);
            // print("Trying to displace register {s} with state {s}\n", .{ @tagName(physical_register), @tagName(state.*) });
            return switch (state.*) {
                .free => false,
                .preassigned => blk: {
                    state.* = .free;
                    break :blk true;
                },
                .virtual => |virtual_register| blk: {
                    const live_reg = register_allocator.live_virtual_registers.getPtr(virtual_register).?;
                    const before = mir.getNextInstructionIndex(instruction_index);
                    try register_allocator.reload(mir, instruction_selection, before, virtual_register, physical_register);
                    state.* = .free;
                    live_reg.physical = .no_register;
                    live_reg.reloaded = true;
                    break :blk true;
                },
                .livein => unreachable,
            };
        }

        fn reload(register_allocator: *RegisterAllocator, mir: *MIR, instruction_selection: *InstructionSelection, before_index: usize, virtual_register: Register.Virtual.Index, physical_register: Register.Physical) !void {
            const frame_index = try register_allocator.getStackSpaceFor(mir, instruction_selection, virtual_register);
            const register_class = mir.virtual_registers.get(virtual_register).register_class;
            print("Frame index: {}\n", .{frame_index});

            try instruction_selection.loadRegisterFromStackSlot(mir, before_index, physical_register, frame_index, register_class, virtual_register);
        }

        fn getStackSpaceFor(register_allocator: *RegisterAllocator, mir: *MIR, instruction_selection: *InstructionSelection, virtual_register: Register.Virtual.Index) !u32 {
            if (register_allocator.stack_slots.get(virtual_register)) |frame_index| {
                return frame_index;
            } else {
                const register_class = mir.virtual_registers.get(virtual_register).register_class;
                const register_class_descriptor = register_class_descriptors.get(register_class);
                assert(register_class_descriptor.spill_size > 0);
                assert(register_class_descriptor.spill_alignment > 0);
                const frame_index = try mir.createSpillStackObject(instruction_selection, register_class_descriptor.spill_size, register_class_descriptor.spill_alignment);

                try register_allocator.stack_slots.put(mir.allocator, virtual_register, frame_index);
                return frame_index;
            }
        }

        fn freePhysicalRegister(register_allocator: *RegisterAllocator, physical_register: Register.Physical) void {
            const state = register_allocator.register_states.getPtr(physical_register);
            switch (state.*) {
                .free => unreachable,
                .preassigned => state.* = .free,
                .virtual => |virtual_register_index| {
                    const live_register = register_allocator.live_virtual_registers.getPtr(virtual_register_index).?;
                    assert(live_register.physical == physical_register);
                    register_allocator.register_states.set(physical_register, .free);
                    live_register.physical = .no_register;
                },
                .livein => unreachable,
            }
        }

        fn markUsedRegisterInInstruction(register_allocator: *RegisterAllocator, physical_register: Register.Physical) void {
            register_allocator.used_in_instruction.setPresent(physical_register, true);
        }

        fn unmarkUsedRegisterInInstruction(register_allocator: *RegisterAllocator, physical_register: Register.Physical) void {
            register_allocator.used_in_instruction.setPresent(physical_register, false);
        }

        fn definePhysicalRegister(register_allocator: *RegisterAllocator, mir: *MIR, instruction_selection: *InstructionSelection, instruction_index: Instruction.Index, physical_register: Register.Physical) !bool {
            const displaced_any = try register_allocator.displacePhysicalRegister(mir, instruction_selection, instruction_index, physical_register);
            register_allocator.register_states.set(physical_register, .preassigned);
            return displaced_any;
        }

        fn defineVirtualRegister(register_allocator: *RegisterAllocator, mir: *MIR, instruction_selection: *InstructionSelection, instruction_index: Instruction.Index, operand_index: Operand.Index, virtual_register: Register.Virtual.Index, look_at_physical_register_uses: bool) !bool {
            const instruction = mir.instructions.get(instruction_index);
            const operand = mir.operands.get(operand_index);
            const gop = try register_allocator.live_virtual_registers.getOrPut(mir.allocator, virtual_register);
            if (!gop.found_existing) {
                gop.value_ptr.* = .{
                    .virtual = virtual_register,
                };
                if (!operand.flags.dead_or_kill) {
                    var live_out = false;
                    if (live_out) {
                        // TODO
                    } else {
                        operand.flags.dead_or_kill = true;
                    }
                }
            }
            const live_register = gop.value_ptr;
            if (live_register.physical == .no_register) {
                try register_allocator.allocateVirtualRegister(mir, instruction_selection, instruction_index, live_register, null, look_at_physical_register_uses);
            } else {
                assert(!register_allocator.isRegisterUsedInInstruction(live_register.physical, look_at_physical_register_uses));
            }

            const physical_register = live_register.physical;
            assert(physical_register != .no_register);
            if (live_register.reloaded or live_register.live_out) {
                const instruction_descriptor = instruction_descriptors.get(instruction.id);
                if (!instruction_descriptor.flags.implicit_def) {
                    const spill_before = mir.getNextInstructionIndex(instruction_index);
                    const kill = live_register.last_use.invalid;
                    try register_allocator.spill(mir, instruction_selection, spill_before, virtual_register, physical_register, kill, live_register.live_out);

                    live_register.last_use = Instruction.Index.invalid;
                }

                live_register.live_out = false;
                live_register.reloaded = false;
            }

            // bundle?

            register_allocator.markUsedRegisterInInstruction(physical_register);
            return mir.setPhysicalRegister(instruction_selection, operand_index, physical_register);
        }

        fn spill(register_allocator: *RegisterAllocator, mir: *MIR, instruction_selection: *InstructionSelection, spill_before: usize, virtual_register: Register.Virtual.Index, physical_register: Register.Physical, kill: bool, live_out: bool) !void {
            _ = live_out;
            const frame_index = try register_allocator.getStackSpaceFor(mir, instruction_selection, virtual_register);
            const register_class = mir.virtual_registers.get(virtual_register).register_class;
            try instruction_selection.storeRegisterToStackSlot(mir, spill_before, physical_register, kill, frame_index, register_class, virtual_register);
            // TODO: debug operands
        }

        fn mayLiveIn(register_allocator: *RegisterAllocator, mir: *MIR, instruction_selection: *InstructionSelection, virtual_register_index: Register.Virtual.Index) bool {
            if (register_allocator.may_live_across_blocks.isSet(virtual_register_index.uniqueInteger())) {
                unreachable;
            } else {
                const head_index_ptr = mir.getRegisterListHead(instruction_selection, .{
                    .index = .{
                        .virtual = virtual_register_index,
                    },
                });

                // TODO: setup iterator
                var define_instructions = Instruction.Iterator.Get(.{
                    .use = false,
                    .def = true,
                    .element = .instruction,
                }).new(mir, head_index_ptr.*);
                while (define_instructions.next()) |_| {
                    unreachable;
                }

                return false;
            }
        }

        fn mayLiveOut(register_allocator: *RegisterAllocator, mir: *MIR, instruction_selection: *InstructionSelection, virtual_register_index: Register.Virtual.Index) bool {
            if (register_allocator.may_live_across_blocks.isSet(virtual_register_index.uniqueInteger())) {
                unreachable;
            } else {
                if (false) {
                    // TODO: FIXME if block loops
                }

                const head_index_ptr = mir.getRegisterListHead(instruction_selection, .{
                    .index = .{
                        .virtual = virtual_register_index,
                    },
                });
                var iterator = Instruction.Iterator.Get(.{
                    .use = true,
                    .def = false,
                    .element = .instruction,
                }).new(mir, head_index_ptr.*);

                const limit = 8;
                var count: u32 = 0;
                while (iterator.nextPointer()) |use_instruction| {
                    if (!use_instruction.parent.eq(instruction_selection.current_block)) {
                        register_allocator.may_live_across_blocks.set(virtual_register_index.uniqueInteger());
                        // TODO: return !basic_block.successorsEmpty()
                        return false;
                    }

                    count += 1;
                    if (count >= limit) {
                        register_allocator.may_live_across_blocks.set(virtual_register_index.uniqueInteger());
                        // TODO: return !basic_block.successorsEmpty()
                        return false;
                    }

                    // self loop def
                    if (false) {
                        unreachable;
                    }
                }

                return false;
            }
        }

        fn reloadAtBegin(register_allocator: *RegisterAllocator, mir: *MIR, instruction_selection: *InstructionSelection, basic_block: BasicBlock.Index) !void {
            _ = instruction_selection;
            _ = mir;
            _ = register_allocator;
            _ = basic_block;
            // if (register_allocator.live_virtual_registers.entries.len > 0) {
            //     // TODO: basic block liveins (regmasks?)
            //
            //     const live_registers = register_allocator.live_virtual_registers.values();
            //     print("Live register count: {}\n", .{live_registers.len});
            //
            //     for (live_registers) |live_register| {
            //         const physical_register = live_register.physical;
            //         if (physical_register == .no_register) {
            //             continue;
            //         }
            //
            //         if (register_allocator.register_states.get(physical_register) == .livein) {
            //             unreachable;
            //         }
            //
            //         // assert?
            //
            //         const virtual_register = live_register.virtual;
            //         if (false) {
            //             unreachable;
            //         } else {
            //             try register_allocator.reload(mir, instruction_selection, 0, virtual_register, physical_register);
            //         }
            //     }
            //     unreachable;
            // }
        }
    };

    fn getRegisters(operand: *const Operand, register_buffer: []Register) []const Register {
        var registers: []Register = register_buffer;
        registers.len = 0;
        switch (operand.u) {
            .register => |register| {
                registers.len += 1;
                registers[registers.len - 1] = register;
            },
            .lea64mem => |lea64mem| {
                if (lea64mem.gp64) |register| {
                    registers.len += 1;
                    registers[registers.len - 1] = register;
                }

                if (lea64mem.scale_reg) |register| {
                    registers.len += 1;
                    registers[registers.len - 1] = register;
                }
            },
            .memory,
            .immediate,
            .pc_relative,
            => {},
            // else => |t| @panic(@tagName(t)),
        }

        return registers;
    }

    pub fn allocateRegisters(mir: *MIR) !void {
        print("\n[REGISTER ALLOCATION]\n\n", .{});
        const function_count = mir.functions.len;
        var function_iterator = mir.functions.iterator();
        const register_count = @typeInfo(Register.Physical).Enum.fields.len;
        _ = register_count;
        const register_unit_count = 173;
        _ = register_unit_count;

        for (0..function_count) |function_index| {
            const function = function_iterator.nextPointer().?;
            const instruction_selection = &mir.instruction_selections.items[function_index];
            print("Allocating registers for {}\n", .{function});

            var block_i: usize = function.blocks.items.len;
            var register_allocator = try RegisterAllocator.init(mir, instruction_selection);

            while (block_i > 0) {
                block_i -= 1;

                const block_index = function.blocks.items[block_i];
                const block = mir.blocks.get(block_index);

                var instruction_i: usize = block.instructions.items.len;

                while (instruction_i > 0) {
                    instruction_i -= 1;

                    const instruction_index = block.instructions.items[instruction_i];
                    const instruction = mir.instructions.get(instruction_index);
                    print("===============\nInstruction {} (#{})\n", .{ instruction_i, instruction_index.uniqueInteger() });
                    print("{}\n", .{function});

                    register_allocator.used_in_instruction = RegisterBitset.initEmpty();

                    const max_operand_count = 32;
                    var define_bitset = std.StaticBitSet(max_operand_count).initEmpty();
                    var physical_register_bitset = std.StaticBitSet(max_operand_count).initEmpty();
                    var register_mask_bitset = std.StaticBitSet(max_operand_count).initEmpty();
                    var virtual_register_define = false;
                    var assign_live_throughs = false;

                    for (instruction.operands.items, 0..) |operand_index, operand_i| {
                        const operand = mir.operands.get(operand_index);
                        switch (operand.u) {
                            .register => |register| {
                                const is_define = operand.flags.type == .def;
                                const is_physical = register.index == .physical;
                                if (is_define and !is_physical) {
                                    virtual_register_define = true;
                                }
                                define_bitset.setValue(operand_i, is_define);
                                physical_register_bitset.setValue(operand_i, is_physical);
                                if (is_physical and is_define) {
                                    const physical_register = register.index.physical;
                                    const displaced_any = try register_allocator.definePhysicalRegister(mir, instruction_selection, instruction_index, physical_register);
                                    if (!displaced_any) {
                                        operand.flags.dead_or_kill = true;
                                    }
                                }
                            },
                            else => {},
                        }
                    }

                    if (define_bitset.count() > 0) {
                        if (virtual_register_define) {
                            var rearranged_implicit_operands = true;
                            if (assign_live_throughs) {
                                unreachable;
                            } else {
                                while (rearranged_implicit_operands) {
                                    rearranged_implicit_operands = false;

                                    for (instruction.operands.items) |operand_index| {
                                        const operand = mir.operands.get(operand_index);
                                        switch (operand.u) {
                                            .register => |register| switch (operand.flags.type) {
                                                .def => switch (register.index) {
                                                    .virtual => |virtual_register| {
                                                        rearranged_implicit_operands = try register_allocator.defineVirtualRegister(mir, instruction_selection, instruction_index, operand_index, virtual_register, false);
                                                        if (rearranged_implicit_operands) {
                                                            break;
                                                        }
                                                    },
                                                    .physical => {},
                                                },
                                                else => {},
                                            },
                                            .lea64mem => |lea64mem| {
                                                assert(lea64mem.gp64 == null);
                                                assert(lea64mem.scale_reg == null);
                                            },
                                            else => {},
                                        }
                                    }
                                }
                            }
                        }

                        var operand_i = instruction.operands.items.len;
                        while (operand_i > 0) {
                            operand_i -= 1;

                            if (define_bitset.isSet(operand_i) and physical_register_bitset.isSet(operand_i)) {
                                const operand_index = instruction.operands.items[operand_i];
                                const operand = mir.operands.get(operand_index);
                                const physical_register = operand.u.register.index.physical;
                                register_allocator.freePhysicalRegister(physical_register);
                                register_allocator.unmarkUsedRegisterInInstruction(physical_register);
                            }
                        }
                    }

                    if (register_mask_bitset.count() > 0) {
                        unreachable;
                    }

                    // Physical register use
                    if (physical_register_bitset.count() > 0) {
                        for (instruction.operands.items, 0..) |operand_index, operand_i| {
                            if (!define_bitset.isSet(operand_i) and physical_register_bitset.isSet(operand_i)) {
                                const operand = mir.operands.get(operand_index);
                                const physical_register = operand.u.register.index.physical;
                                if (!register_allocator.reserved.contains(physical_register)) {
                                    const displaced_any = try register_allocator.usePhysicalRegister(mir, instruction_selection, instruction_index, physical_register);
                                    if (!displaced_any) {
                                        operand.flags.dead_or_kill = true;
                                    }
                                }
                            }
                        }
                    }

                    var rearranged_implicit_operands = true;
                    while (rearranged_implicit_operands) {
                        rearranged_implicit_operands = false;
                        for (instruction.operands.items, 0..) |operand_index, operand_i| {
                            if (!define_bitset.isSet(operand_i)) {
                                const operand = mir.operands.get(operand_index);
                                if (operand.u == .register and operand.u.register.index == .virtual) {
                                    const virtual_register = operand.u.register.index.virtual;
                                    rearranged_implicit_operands = try register_allocator.useVirtualRegister(mir, instruction_selection, instruction_index, virtual_register, @intCast(operand_i));
                                    if (rearranged_implicit_operands) break;
                                }
                            }
                        }
                    }

                    if (instruction.id == .copy and instruction.operands.items.len == 2) {
                        const dst_register = mir.operands.get(instruction.operands.items[0]).u.register.index;
                        const src_register = mir.operands.get(instruction.operands.items[1]).u.register.index;

                        if (std.meta.eql(dst_register, src_register)) {
                            try register_allocator.coalesced.append(mir.allocator, instruction_index);
                            print("Avoiding copy...\n", .{});
                        }
                    }
                }

                for (register_allocator.coalesced.items) |coalesced| {
                    for (block.instructions.items, 0..) |instruction_index, i| {
                        if (coalesced.eq(instruction_index)) {
                            const result = block.instructions.orderedRemove(i);
                            assert(result.eq(coalesced));
                            break;
                        }
                    } else unreachable;
                }

                print("{}\n============\n", .{function});
            }
        }

        // for (0..function_count) |function_index| {
        //     const function = function_iterator.nextPointer().?;
        //     const instruction_selection = &mir.instruction_selections.items[function_index];
        //     print("FN {s}\n", .{function.name});
        //
        //     var register_allocator = try RegisterAllocator.init(mir, instruction_selection);
        //
        //     for (function.blocks.items) |block_index| {
        //         instruction_selection.current_block = block_index;
        //         register_allocator.coalesced.clearRetainingCapacity();
        //
        //         const block = mir.blocks.get(block_index);
        //         const instruction_count = block.instructions.items.len;
        //         var instruction_i = instruction_count;
        //
        //         while (instruction_i > 0) {
        //             instruction_i -= 1;
        //             print("Instruction #{}\n", .{instruction_i});
        //
        //             register_allocator.used_in_instruction = RegisterBitset.initEmpty();
        //
        //             const instruction_index = block.instructions.items[instruction_i];
        //             const instruction = mir.instructions.get(instruction_index);
        //
        //             var register_define = false;
        //             var virtual_register_define = false;
        //             var early_clobber = false;
        //             var assign_live_throughs = false;
        //             var physical_register_use = false;
        //             var register_mask = false;
        //
        //             for (instruction.operands.items) |operand_index| {
        //                 const operand = mir.operands.get(operand_index);
        //                 var register_buffer: [2]Register = undefined;
        //                 const registers = getRegisters(operand, &register_buffer);
        //
        //                 for (registers) |register| switch (register.index) {
        //                     .virtual => {
        //                         switch (operand.flags.type) {
        //                             .def => {
        //                                 register_define = true;
        //                                 virtual_register_define = true;
        //                                 // TODO early clobber, livethroughs
        //                                 if (operand.flags.early_clobber) {
        //                                     early_clobber = true;
        //                                     assign_live_throughs = true;
        //                                 }
        //
        //                                 // TODO (tied  and tied op undef) or (subreg and !undef)
        //                             },
        //                             .use => {},
        //                         }
        //                     },
        //                     .physical => |physical_register| {
        //                         if (!register_allocator.reserved.contains(physical_register)) {
        //                             switch (operand.flags.type) {
        //                                 .def => {
        //                                     register_define = true;
        //                                     const displaced_any = try register_allocator.definePhysicalRegister(mir, instruction_selection, instruction_index, physical_register);
        //                                     if (operand.flags.early_clobber) {
        //                                         early_clobber = true;
        //                                     }
        //                                     if (!displaced_any) {
        //                                         operand.flags.dead_or_kill = true;
        //                                     }
        //                                 },
        //                                 .use => {},
        //                             }
        //
        //                             if (operand.readsRegister()) {
        //                                 physical_register_use = true;
        //                             }
        //                         }
        //                     },
        //                 };
        //             }
        //
        //             if (register_define) {
        //                 if (virtual_register_define) {
        //                     var rearranged_implicit_operands = true;
        //                     if (assign_live_throughs) {
        //                         unreachable;
        //                     } else {
        //                         while (rearranged_implicit_operands) {
        //                             rearranged_implicit_operands = false;
        //
        //                             for (instruction.operands.items) |operand_index| {
        //                                 const operand = mir.operands.get(operand_index);
        //                                 switch (operand.u) {
        //                                     .register => |register| switch (operand.flags.type) {
        //                                         .def => switch (register.index) {
        //                                             .virtual => |virtual_register| {
        //                                                 rearranged_implicit_operands = try register_allocator.defineVirtualRegister(mir, instruction_selection, instruction_index, operand_index, virtual_register, false);
        //                                                 if (rearranged_implicit_operands) {
        //                                                     break;
        //                                                 }
        //                                             },
        //                                             .physical => {},
        //                                         },
        //                                         else => {},
        //                                     },
        //                                     .lea64mem => |lea64mem| {
        //                                         assert(lea64mem.gp64 == null);
        //                                         assert(lea64mem.scale_reg == null);
        //                                     },
        //                                     else => {},
        //                                 }
        //                             }
        //                         }
        //                     }
        //                 }
        //
        //                 var operand_i = instruction.operands.items.len;
        //                 while (operand_i > 0) {
        //                     operand_i -= 1;
        //                     const operand_index = instruction.operands.items[operand_i];
        //                     const operand = mir.operands.get(operand_index);
        //                     var register_buffer: [2]Register = undefined;
        //                     const registers = getRegisters(operand, &register_buffer);
        //                     for (registers) |register| {
        //                         switch (operand.flags.type) {
        //                             .def => {
        //                                 if (operand.id == .lea64mem) unreachable;
        //                                 // TODO: missing checks
        //                                 switch (register.index) {
        //                                     .virtual => unreachable,
        //                                     .physical => |physical_register| switch (register_allocator.reserved.contains(physical_register)) {
        //                                         true => {},
        //                                         false => {
        //                                             register_allocator.freePhysicalRegister(physical_register);
        //                                             register_allocator.unmarkUsedRegisterInInstruction(physical_register);
        //                                         },
        //                                     },
        //                                 }
        //                             },
        //                             .use => {},
        //                         }
        //                     }
        //                 }
        //             }
        //
        //             if (register_mask) {
        //                 unreachable;
        //             }
        //
        //             if (physical_register_use) {
        //                 unreachable;
        //             }
        //
        //             var undef_use = false;
        //
        //             while (true) {
        //                 var rearrange_implicit_operands = false;
        //                 operand_loop: for (instruction.operands.items, 0..) |operand_index, operand_i| {
        //                     const operand = mir.operands.get(operand_index);
        //                     var register_buffer: [2]Register = undefined;
        //                     const registers = getRegisters(operand, &register_buffer);
        //
        //                     for (registers) |register| {
        //                         switch (operand.flags.type) {
        //                             .use => switch (register.index) {
        //                                 .virtual => |virtual_register_index| switch (operand.flags.undef) {
        //                                     true => undef_use = true,
        //                                     false => {
        //                                         _ = register_allocator.mayLiveIn(mir, instruction_selection, virtual_register_index);
        //                                         assert(!operand.flags.internal_read);
        //                                         assert(operand.readsRegister());
        //
        //                                         if (try register_allocator.useVirtualRegister(mir, instruction_selection, instruction_index, virtual_register_index, @intCast(operand_i))) {
        //                                             break :operand_loop;
        //                                         }
        //                                     },
        //                                 },
        //                                 .physical => {},
        //                             },
        //                             .def => {},
        //                         }
        //                     }
        //                 }
        //
        //                 if (!rearrange_implicit_operands) break;
        //             }
        //
        //             if (undef_use) {
        //                 unreachable;
        //             }
        //
        //             if (early_clobber) {
        //                 unreachable;
        //             }
        //
        //             if (instruction.id == .copy and instruction.operands.items.len == 2) {
        //                 const dst_register = mir.operands.get(instruction.operands.items[0]).u.register;
        //                 const src_register = mir.operands.get(instruction.operands.items[1]).u.register;
        //
        //                 if (std.meta.eql(dst_register, src_register)) {
        //                     try register_allocator.coalesced.append(mir.allocator, instruction_index);
        //                 }
        //             }
        //         }
        //
        //         // TODO:
        //         // try register_allocator.reloadAtBegin(instruction_selection.current_block);
        //
        //         // Remove coalesced instructions
        //         for (register_allocator.coalesced.items) |instruction_index| {
        //             _ = instruction_index;
        //             unreachable;
        //         }
        //
        //         // TODO: fix debug values
        //
        //     }
        //
        //     print("After register allocation before clearing virtual registers:\n{}\n", .{function});
        //
        //     const clear_virtual_registers = true;
        //     if (clear_virtual_registers) {
        //         mir.clearVirtualRegisters();
        //     }
        //
        //     unreachable;
        // }

        unreachable;
    }

    fn clearVirtualRegisters(mir: *MIR) void {
        var vr_it = mir.virtual_registers.iterator();
        var vr_index = vr_it.getCurrentIndex();
        while (vr_it.nextPointer()) |vr| {
            if (!vr.use_def_list_head.valid) {
                continue;
            }

            mir.verifyUseList(vr.use_def_list_head, vr_index);
            vr_index = vr_it.getCurrentIndex();
        }
    }

    fn verifyUseList(mir: *MIR, start_operand_index: Operand.Index, register: Register.Virtual.Index) void {
        var iterator = Instruction.Iterator.Get(.{
            .use = true,
            .def = true,
            .element = .operand,
        }).new(mir, start_operand_index);

        while (iterator.next()) |operand| {
            const instruction_index = operand.parent;
            assert(instruction_index.valid);
            const instruction = mir.instructions.get(instruction_index);
            print("Verifying instruction #{}, operand #{}\n", .{ instruction_index.uniqueInteger(), mir.operands.indexOf(operand).uniqueInteger() });
            _ = instruction;
            assert(operand.u == .register);
            assert(operand.u.register.index == .virtual and operand.u.register.index.virtual.eq(register));
        }
    }

    pub fn encode(mir: *MIR) !emit.Result {
        _ = mir;
        // unreachable;
        return undefined;
    }

    fn getRegisterListHead(mir: *MIR, instruction_selection: *InstructionSelection, register: Register) *Operand.Index {
        switch (register.index) {
            .physical => |physical| {
                const operand_index = instruction_selection.physical_register_use_or_definition_list.getPtr(physical);
                return operand_index;
            },
            .virtual => |virtual_register_index| {
                const virtual_register = mir.virtual_registers.get(virtual_register_index);
                return &virtual_register.use_def_list_head;
            },
        }
    }

    const Function = struct {
        blocks: ArrayList(BasicBlock.Index) = .{},
        instruction_selection: *InstructionSelection,
        mir: *MIR,
        name: []const u8,

        pub fn format(function: *const Function, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
            const function_name = function.name;
            try writer.print("{s}:\n", .{function_name});
            for (function.blocks.items, 0..) |block_index, function_block_index| {
                try writer.print("#{}: ({})\n", .{ function_block_index, block_index.uniqueInteger() });
                const block = function.mir.blocks.get(block_index);
                for (block.instructions.items, 0..) |instruction_index, block_instruction_index| {
                    try writer.print("%{} (${}): ", .{ block_instruction_index, instruction_index.uniqueInteger() });
                    const instruction = function.mir.instructions.get(instruction_index).*;
                    try writer.print("{s}", .{@tagName(instruction.id)});
                    for (instruction.operands.items, 0..) |operand_index, i| {
                        const operand = function.mir.operands.get(operand_index);
                        try writer.print(" O{} ", .{operand_index.uniqueInteger()});
                        switch (operand.u) {
                            .register => |register| {
                                switch (register.index) {
                                    .physical => |physical| try writer.writeAll(@tagName(physical)),
                                    .virtual => |virtual| try writer.print("VR{}", .{virtual.uniqueInteger()}),
                                }
                            },
                            .memory => |memory| {
                                const base = memory.addressing_mode.base;
                                switch (base) {
                                    .register_base => unreachable,
                                    .frame_index => |frame_index| try writer.print("SF{}", .{frame_index}),
                                }
                            },
                            else => try writer.writeAll(@tagName(operand.u)),
                        }
                        // switch (operand.u) {
                        //     .memory =>
                        //     else => |t| @panic(@tagName(t)),
                        // }
                        if (i < instruction.operands.items.len - 1) {
                            try writer.writeByte(',');
                        }
                    }

                    try writer.writeByte('\n');
                }

                try writer.writeByte('\n');
            }
            _ = options;
            _ = fmt;
        }
    };

    fn buildInstruction(mir: *MIR, instruction_selection: *InstructionSelection, instruction: Instruction.Id, operands: []const Operand) !Instruction.Index {
        // Some sanity check
        {
            if (instruction != .copy) {
                const descriptor = instruction_descriptors.getPtrConst(instruction);
                if (descriptor.operands.len != operands.len) unreachable;
                for (descriptor.operands, operands) |descriptor_operand, operand| {
                    switch (descriptor_operand.id) {
                        .unknown => {},
                        else => if (descriptor_operand.id != operand.id) unreachable,
                    }
                }
            }
        }

        var list = try ArrayList(Operand.Index).initCapacity(mir.allocator, operands.len);
        const instruction_allocation = try mir.instructions.addOne(mir.allocator);
        // TODO: MachineRegisterInfo::addRegOperandToUseList
        for (operands) |operand_value| {
            const operand_allocation = try mir.operands.append(mir.allocator, operand_value);
            list.appendAssumeCapacity(operand_allocation.index);
            const operand = operand_allocation.ptr;
            const operand_index = operand_allocation.index;
            operand_allocation.ptr.parent = instruction_allocation.index;

            switch (operand.u) {
                .register => mir.addRegisterOperandFromUseList(instruction_selection, operand_index),
                .lea64mem => |lea64mem| {
                    // TODO
                    assert(lea64mem.gp64 == null);
                    assert(lea64mem.scale_reg == null);
                },
                .memory,
                .immediate,
                .pc_relative,
                => {},
            }
        }

        instruction_allocation.ptr.* = .{
            .id = instruction,
            .operands = list,
            .parent = instruction_selection.current_block,
        };

        if (instruction == .copy) {
            const i = instruction_allocation.ptr.*;
            print("Built copy: DST: {}. SRC: {}\n", .{ mir.operands.get(i.operands.items[0]).u.register.index, mir.operands.get(i.operands.items[1]).u.register.index });
        }

        return instruction_allocation.index;
    }

    fn append(mir: *MIR, instruction_selection: *InstructionSelection, id: Instruction.Id, operands: []const Operand) !void {
        const instruction = try mir.buildInstruction(instruction_selection, id, operands);
        const current_block = mir.blocks.get(instruction_selection.current_block);
        try current_block.instructions.append(mir.allocator, instruction);
    }

    fn createSpillStackObject(mir: *MIR, instruction_selection: *InstructionSelection, spill_size: u32, spill_alignment: u32) !u32 {
        const frame_index = try mir.createStackObject(instruction_selection, spill_size, spill_alignment, ir.Instruction.Index.invalid, true);
        return frame_index;
    }

    fn createStackObject(mir: *MIR, instruction_selection: *InstructionSelection, size: u64, asked_alignment: u32, ir_instruction: ir.Instruction.Index, is_spill_slot: bool) !u32 {
        const stack_realignable = false;
        const alignment = clampStackAlignment(!stack_realignable, asked_alignment, 16);
        const index: u32 = @intCast(instruction_selection.stack_objects.items.len);
        try instruction_selection.stack_objects.append(mir.allocator, .{
            .size = size,
            .alignment = alignment,
            .spill_slot = is_spill_slot,
            .ir = ir_instruction,
        });
        return index;
    }

    fn clampStackAlignment(clamp: bool, alignment: u32, stack_alignment: u32) u32 {
        if (!clamp or alignment <= stack_alignment) return alignment;
        return stack_alignment;
    }
};

// const ModRm = packed struct(u8) {
//     rm: u3,
//     reg: u3,
//     mod: u2,
// };

// const Rex = packed struct(u8) {
//     b: bool,
//     x: bool,
//     r: bool,
//     w: bool,
//     fixed: u4 = 0b0100,
//
//     fn create(args: struct {
//         rm: ?GPRegister = null,
//         reg: ?GPRegister = null,
//         sib: bool = false,
//         rm_size: ?Size = null,
//     }) ?Rex {
//         const rex_byte = Rex{
//             .b = if (args.rm) |rm| @intFromEnum(rm) > std.math.maxInt(u3) else false,
//             .x = args.sib,
//             .r = if (args.reg) |reg| @intFromEnum(reg) > std.math.maxInt(u3) else false,
//             .w = if (args.rm_size) |rm_size| rm_size == .eight else false,
//         };
//
//         if (@as(u4, @truncate(@as(u8, @bitCast(rex_byte)))) != 0) {
//             return rex_byte;
//         } else {
//             return null;
//         }
//     }
// };

fn getIrType(intermediate: *ir.Result, ir_instruction_index: ir.Instruction.Index) ir.Type {
    const ir_instruction = intermediate.instructions.get(ir_instruction_index);
    return switch (ir_instruction.*) {
        .argument => |argument_index| intermediate.arguments.get(argument_index).type,
        .stack => |stack_index| intermediate.stack_references.get(stack_index).type,
        .load => |load_index| getIrType(intermediate, intermediate.loads.get(load_index).instruction),
        .syscall => |_| .i64,
        .load_integer => |integer| integer.type,
        .load_string_literal => .i64,
        .call => |call_index| intermediate.function_declarations.get(intermediate.calls.get(call_index).function).return_type,
        .sign_extend => |cast_index| intermediate.casts.get(cast_index).type,
        else => |t| @panic(@tagName(t)),
    };
}

fn resolveType(ir_type: ir.Type) ValueType.Id {
    return switch (ir_type) {
        inline //.i8,
        //.i16,
        .i32,
        .i64,
        => |ir_type_ct| @field(ValueType.Id, @typeInfo(ir.Type).Enum.fields[@intFromEnum(ir_type_ct)].name),
        .i8, .i16 => unreachable,
        .void,
        .noreturn,
        => unreachable,
    };
}

const RegisterSet = AutoArrayHashMap(Register.Physical, void);

fn getSubregisters(allocator: Allocator, reg: Register.Physical) !RegisterSet {
    var result = RegisterSet{};

    try getSubregistersRecursive(allocator, &result, reg);

    return result;
}

fn getSubregistersRecursive(allocator: Allocator, set: *RegisterSet, reg: Register.Physical) !void {
    if (set.get(reg) == null) {
        try set.putNoClobber(allocator, reg, {});
        const register_descriptor = register_descriptors.getPtrConst(reg);
        for (register_descriptor.subregisters) |subreg| {
            try getSubregistersRecursive(allocator, set, subreg);
        }
    }
}

const LiveRegister = struct {
    last_use: Instruction.Index = Instruction.Index.invalid,
    virtual: Register.Virtual.Index,
    physical: Register.Physical = Register.Physical.no_register,
    live_out: bool = false,
    reloaded: bool = false,
};
