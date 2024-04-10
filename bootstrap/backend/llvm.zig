const std = @import("std");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;
const Compilation = @import("../Compilation.zig");
const write = Compilation.write;
// const log = Compilation.log;
// const logln = Compilation.logln;
const Module = Compilation.Module;
const data_structures = @import("../library.zig");
const MyHashMap = data_structures.MyHashMap;
const UnpinnedArray = data_structures.UnpinnedArray;

pub const bindings = @import("llvm_bindings.zig");

pub const Logger = enum {
    print_module,
    function,

    pub var bitset = std.EnumSet(Logger).initMany(&.{
        .print_module,
        .function,
    });
};

pub const LLVM = struct {
    context: *LLVM.Context,
    module: *LLVM.Module,
    builder: *LLVM.Builder,
    debug_info_builder: *LLVM.DebugInfo.Builder,
    debug_info_file_map: MyHashMap(Compilation.Debug.File.Index, *LLVM.DebugInfo.File) = .{},
    debug_type_map: MyHashMap(Compilation.Type.Index, *LLVM.DebugInfo.Type) = .{},
    type_name_map: MyHashMap(Compilation.Type.Index, []const u8) = .{},
    type_map: MyHashMap(Compilation.Type.Index, *LLVM.Type) = .{},
    function_declaration_map: MyHashMap(*Compilation.Debug.Declaration.Global, *LLVM.Value.Constant.Function) = .{},
    function_definition_map: MyHashMap(*Compilation.Debug.Declaration.Global, *LLVM.Value.Constant.Function) = .{},
    llvm_instruction_map: MyHashMap(Compilation.Instruction.Index, *LLVM.Value) = .{},
    llvm_value_map: MyHashMap(Compilation.V, *LLVM.Value) = .{},
    llvm_block_map: MyHashMap(Compilation.BasicBlock.Index, *LLVM.Value.BasicBlock) = .{},
    llvm_external_functions: MyHashMap(*Compilation.Debug.Declaration.Global, *LLVM.Value.Constant.Function) = .{},
    global_variable_map: MyHashMap(*Compilation.Debug.Declaration.Global, *LLVM.Value.Constant.GlobalVariable) = .{},
    scope_map: MyHashMap(*Compilation.Debug.Scope, *LLVM.DebugInfo.Scope) = .{},
    pointer_type: ?*LLVM.Type.Pointer = null,
    function: *LLVM.Value.Constant.Function = undefined,
    exit_block: *LLVM.Value.BasicBlock = undefined,
    sema_function: *Compilation.Debug.Declaration.Global = undefined,
    argument_allocas: MyHashMap(Compilation.Instruction.Index, *LLVM.Value) = .{},
    return_phi_node: ?*LLVM.Value.Instruction.PhiNode = null,
    scope: *LLVM.DebugInfo.Scope = undefined,
    file: *LLVM.DebugInfo.File = undefined,
    attributes: Attributes,
    // subprogram: *LLVM.DebugInfo.Subprogram = undefined,
    arg_index: u32 = 0,
    tag_count: c_uint = 0,
    inside_branch: bool = false,

    pub const x86_64 = struct{
        pub const initializeTarget = bindings.LLVMInitializeX86Target;
        pub const initializeTargetInfo = bindings.LLVMInitializeX86TargetInfo;
        pub const initializeTargetMC = bindings.LLVMInitializeX86TargetMC;
        pub const initializeAsmPrinter = bindings.LLVMInitializeX86AsmPrinter;
        pub const initializeAsmParser = bindings.LLVMInitializeX86AsmParser;
    };

    pub const aarch64 = struct{
        pub const initializeTarget = bindings.LLVMInitializeAArch64Target;
        pub const initializeTargetInfo = bindings.LLVMInitializeAArch64TargetInfo;
        pub const initializeTargetMC = bindings.LLVMInitializeAArch64TargetMC;
        pub const initializeAsmPrinter = bindings.LLVMInitializeAArch64AsmPrinter;
        pub const initializeAsmParser = bindings.LLVMInitializeAArch64AsmParser;
    };

    pub const Attributes = struct {
        noreturn: *Attribute,
        naked: *Attribute,
        nounwind: *Attribute,
        inreg: *Attribute,
        @"noalias": *Attribute,
    };

    pub const Linkage = enum(c_uint) {
        @"extern" = 0,
        available_external = 1,
        link_once_any = 2,
        link_once_odr = 3,
        weak_any = 4,
        weak_odr = 5,
        appending = 6,
        internal = 7,
        private = 8,
        external_weak = 9,
        common = 10,
    };

    pub const ThreadLocalMode = enum(c_uint) {
        not_thread_local = 0,
    };

    pub const Context = opaque {
        const create = bindings.NativityLLVMCreateContext;
        const createBasicBlock = bindings.NativityLLVMCreateBasicBlock;
        const getConstantInt = bindings.NativityLLVMContextGetConstantInt;
        const getConstString = bindings.NativityLLVMContextGetConstString;
        const getVoidType = bindings.NativityLLVMGetVoidType;
        const getIntegerType = bindings.NativityLLVMGetIntegerType;
        const getFunctionType = bindings.NativityLLVMGetFunctionType;
        const getPointerType = bindings.NativityLLVMGetPointerType;
        const getStructType = bindings.NativityLLVMGetStructType;
        const getIntrinsicType = bindings.NativityLLVMContextGetIntrinsicType;
        const getAttributeFromEnum = bindings.NativityLLVMContextGetAttributeFromEnum;
        const getAttributeFromString = bindings.NativityLLVMContextGetAttributeFromString;
        const getAttributeFromType = bindings.NativityLLVMContextGetAttributeFromType;
        const getAttributeSet = bindings.NativityLLVMContextGetAttributeSet;
    };

    pub const Module = opaque {
        const addGlobalVariable = bindings.NativityLLVMModuleAddGlobalVariable;
        const create = bindings.NativityLLVMCreateModule;
        const getFunction = bindings.NativityLLVMModuleGetFunction;
        const createFunction = bindings.NativityLLVModuleCreateFunction;
        const verify = bindings.NativityLLVMVerifyModule;
        const toString = bindings.NativityLLVMModuleToString;
        const getIntrinsicDeclaration = bindings.NativityLLVMModuleGetIntrinsicDeclaration;
        const createDebugInfoBuilder = bindings.NativityLLVMModuleCreateDebugInfoBuilder;
        const setTargetMachineDataLayout = bindings.NativityLLVMModuleSetTargetMachineDataLayout;
        const setTargetTriple = bindings.NativityLLVMModuleSetTargetTriple;
        const addPassesToEmitFile = bindings.NativityLLVMModuleAddPassesToEmitFile;
    };

    pub const Builder = opaque {
        const create = bindings.NativityLLVMCreateBuilder;
        const setInsertPoint = bindings.NativityLLVMBuilderSetInsertPoint;
        const createAdd = bindings.NativityLLVMBuilderCreateAdd;
        const createAlloca = bindings.NativityLLVMBuilderCreateAlloca;
        const createAnd = bindings.NativityLLVMBuilderCreateAnd;
        const createOr = bindings.NativityLLVMBuilderCreateOr;
        const createCall = bindings.NativityLLVMBuilderCreateCall;
        const createCast = bindings.NativityLLVMBuilderCreateCast;
        const createBranch = bindings.NativityLLVMBuilderCreateBranch;
        const createConditionalBranch = bindings.NativityLLVMBuilderCreateConditionalBranch;
        const createSwitch = bindings.NativityLLVMBuilderCreateSwitch;
        const createGEP = bindings.NativityLLVMBuilderCreateGEP;
        const createStructGEP = bindings.NativityLLVMBuilderCreateStructGEP;
        const createICmp = bindings.NativityLLVMBuilderCreateICmp;
        const createLoad = bindings.NativityLLVMBuilderCreateLoad;
        const createMultiply = bindings.NativityLLVMBuilderCreateMultiply;
        const createRet = bindings.NativityLLVMBuilderCreateRet;
        const createShiftLeft = bindings.NativityLLVMBuilderCreateShiftLeft;
        const createArithmeticShiftRight = bindings.NativityLLVMBuilderCreateArithmeticShiftRight;
        const createLogicalShiftRight = bindings.NativityLLVMBuilderCreateLogicalShiftRight;
        const createStore = bindings.NativityLLVMBuilderCreateStore;
        const createSub = bindings.NativityLLVMBuilderCreateSub;
        const createUnreachable = bindings.NativityLLVMBuilderCreateUnreachable;
        const createXor = bindings.NativityLLVMBuilderCreateXor;
        const createUDiv = bindings.NativityLLVMBuilderCreateUDiv;
        const createSDiv = bindings.NativityLLVMBuilderCreateSDiv;
        const createURem = bindings.NativityLLVMBuilderCreateURem;
        const createSRem = bindings.NativityLLVMBuilderCreateSRem;
        const createExtractValue = bindings.NativityLLVMBuilderCreateExtractValue;
        const createInsertValue = bindings.NativityLLVMBuilderCreateInsertValue;
        const createGlobalString = bindings.NativityLLVMBuilderCreateGlobalString;
        const createGlobalStringPointer = bindings.NativityLLVMBuilderCreateGlobalStringPointer;
        const createPhi = bindings.NativityLLVMBuilderCreatePhi;
        const createMemcpy = bindings.NativityLLVMBuilderCreateMemcpy;

        const getInsertBlock = bindings.NativityLLVMBuilderGetInsertBlock;
        const isCurrentBlockTerminated = bindings.NativityLLVMBuilderIsCurrentBlockTerminated;
        const setCurrentDebugLocation = bindings.NativityLLVMBuilderSetCurrentDebugLocation;
    };

    pub const DebugInfo = struct {
        pub const AttributeType = enum(c_uint) {
            address = 0x01,
            boolean = 0x02,
            complex_float = 0x03,
            float = 0x04,
            signed = 0x05,
            signed_char = 0x06,
            unsigned = 0x07,
            unsigned_char = 0x08,
            imaginary_float = 0x09,
            packed_decimal = 0x0a,
            numeric_string = 0x0b,
            edited = 0x0c,
            signed_fixed = 0x0d,
            unsigned_fixed = 0x0e,
            decimal_float = 0x0f,
            UTF = 0x10,
            UCS = 0x11,
            ASCII = 0x12,
        };

        pub const CallingConvention = enum(c_uint) {
            none = 0,
            normal = 0x01,
            program = 0x02,
            nocall = 0x03,
            pass_by_reference = 0x04,
            pass_by_value = 0x05,
            // Vendor extensions
            GNU_renesas_sh = 0x40,
            GNU_borland_fastcall_i386 = 0x41,
            BORLAND_safecall = 0xb0,
            BORLAND_stdcall = 0xb1,
            BORLAND_pascal = 0xb2,
            BORLAND_msfastcall = 0xb3,
            BORLAND_msreturn = 0xb4,
            BORLAND_thiscall = 0xb5,
            BORLAND_fastcall = 0xb6,
            LLVM_vectorcall = 0xc0,
            LLVM_Win64 = 0xc1,
            LLVM_X86_64SysV = 0xc2,
            LLVM_AAPCS = 0xc3,
            LLVM_AAPCS_VFP = 0xc4,
            LLVM_IntelOclBicc = 0xc5,
            LLVM_SpirFunction = 0xc6,
            LLVM_OpenCLKernel = 0xc7,
            LLVM_Swift = 0xc8,
            LLVM_PreserveMost = 0xc9,
            LLVM_PreserveAll = 0xca,
            LLVM_X86RegCall = 0xcb,
            GDB_IBM_OpenCL = 0xff,
        };

        pub const Builder = opaque {
            const createCompileUnit = bindings.NativityLLVMDebugInfoBuilderCreateCompileUnit;
            const createFile = bindings.NativityLLVMDebugInfoBuilderCreateFile;
            const createFunction = bindings.NativityLLVMDebugInfoBuilderCreateFunction;
            const createSubroutineType = bindings.NativityLLVMDebugInfoBuilderCreateSubroutineType;
            const createLexicalBlock = bindings.NativityLLVMDebugInfoBuilderCreateLexicalBlock;
            const createParameterVariable = bindings.NativityLLVMDebugInfoBuilderCreateParameterVariable;
            const createAutoVariable = bindings.NativityLLVMDebugInfoBuilderCreateAutoVariable;
            const createGlobalVariableExpression = bindings.NativityLLVMDebugInfoBuilderCreateGlobalVariableExpression;
            const createExpression = bindings.NativityLLVMDebugInfoBuilderCreateExpression;
            const createBasicType = bindings.NativityLLVMDebugInfoBuilderCreateBasicType;
            const createPointerType = bindings.NativityLLVMDebugInfoBuilderCreatePointerType;
            const createStructType = bindings.NativityLLVMDebugInfoBuilderCreateStructType;
            const createArrayType = bindings.NativityLLVMDebugInfoBuilderCreateArrayType;
            const createEnumerationType = bindings.NativityLLVMDebugInfoBuilderCreateEnumerationType;
            const createEnumerator = bindings.NativityLLVMDebugInfoBuilderCreateEnumerator;
            const createReplaceableCompositeType = bindings.NativityLLVMDebugInfoBuilderCreateReplaceableCompositeType;
            const createMemberType = bindings.NativityLLVMDebugInfoBuilderCreateMemberType;
            const insertDeclare = bindings.NativityLLVMDebugInfoBuilderInsertDeclare;
            const finalizeSubprogram = bindings.NativityLLVMDebugInfoBuilderFinalizeSubprogram;
            const finalize = bindings.NativityLLVMDebugInfoBuilderFinalize;
            const replaceCompositeTypes = bindings.NativityLLVMDebugInfoBuilderCompositeTypeReplaceTypes;
        };

        pub const CompileUnit = opaque {
            fn toScope(this: *@This()) *Scope {
                return @ptrCast(this);
            }

            pub const EmissionKind = enum(c_uint) {
                no_debug = 0,
                full_debug = 1,
                line_tables_only = 2,
                debug_directives_only = 3,
            };

            pub const NameTableKind = enum(c_uint) {
                default = 0,
                gnu = 1,
                none = 2,
            };
        };

        pub const Expression = opaque {};

        pub const GlobalVariableExpression = opaque {};

        pub const LocalVariable = opaque {};
        pub const LexicalBlock = opaque {
            fn toScope(this: *@This()) *Scope {
                return @ptrCast(this);
            }
        };

        pub const Node = opaque {
            pub const Flags = packed struct(u32) {
                visibility: Visibility,
                forward_declaration: bool,
                apple_block: bool,
                block_by_ref_struct: bool,
                virtual: bool,
                artificial: bool,
                explicit: bool,
                prototyped: bool,
                objective_c_class_complete: bool,
                object_pointer: bool,
                vector: bool,
                static_member: bool,
                lvalue_reference: bool,
                rvalue_reference: bool,
                reserved: bool = false,
                inheritance: Inheritance,
                introduced_virtual: bool,
                bit_field: bool,
                no_return: bool,
                type_pass_by_value: bool,
                type_pass_by_reference: bool,
                enum_class: bool,
                thunk: bool,
                non_trivial: bool,
                big_endian: bool,
                little_endian: bool,
                all_calls_described: bool,
                _: u3 = 0,

                const Visibility = enum(u2) {
                    none = 0,
                    private = 1,
                    protected = 2,
                    public = 3,
                };
                const Inheritance = enum(u2) {
                    none = 0,
                    single = 1,
                    multiple = 2,
                    virtual = 3,
                };
            };
        };

        pub const File = opaque {
            fn toScope(this: *@This()) *Scope {
                return @ptrCast(this);
            }
        };

        pub const Language = enum(c_uint) {
            c = 0x02,
        };

        pub const Scope = opaque {
            const toSubprogram = bindings.NativityLLVMDebugInfoScopeToSubprogram;
        };
        pub const LocalScope = opaque {
            fn toScope(this: *@This()) *Scope {
                return @ptrCast(this);
            }
        };
        pub const Subprogram = opaque {
            const getFile = bindings.NativityLLVMDebugInfoSubprogramGetFile;
            const getArgumentType = bindings.NativityLLVMDebugInfoSubprogramGetArgumentType;
            fn toLocalScope(this: *@This()) *LocalScope {
                return @ptrCast(this);
            }

            pub const Flags = packed struct(u32) {
                virtuality: Virtuality,
                local_to_unit: bool,
                definition: bool,
                optimized: bool,
                pure: bool,
                elemental: bool,
                recursive: bool,
                main_subprogram: bool,
                deleted: bool,
                reserved: bool = false,
                object_c_direct: bool,
                _: u20 = 0,

                const Virtuality = enum(u2) {
                    none = 0,
                    virtual = 1,
                    pure_virtual = 2,
                };
            };
        };

        pub const Type = opaque {
            const isResolved = bindings.NativityLLLVMDITypeIsResolved;
            fn toScope(this: *@This()) *Scope {
                return @ptrCast(this);
            }

            pub const Derived = opaque {
                fn toType(this: *@This()) *LLVM.DebugInfo.Type {
                    return @ptrCast(this);
                }
            };

            pub const Composite = opaque {
                fn toType(this: *@This()) *LLVM.DebugInfo.Type {
                    return @ptrCast(this);
                }
            };

            pub const Enumerator = opaque {};
            pub const Subroutine = opaque {
                fn toType(this: *@This()) *LLVM.DebugInfo.Type {
                    return @ptrCast(this);
                }
            };
        };
    };

    pub const FloatAbi = enum(c_uint) {
        default = 0,
        soft = 1,
        hard = 2,
    };

    pub const FloatOperationFusionMode = enum(c_uint) {
        fast = 0,
        standard = 1,
        strict = 2,
    };

    pub const JumpTableType = enum(c_uint) {
        single = 0,
        arity = 1,
        simplified = 2,
        full = 3,
    };

    pub const ThreadModel = enum(c_uint) {
        posix = 0,
        single = 1,
    };

    pub const BasicBlockSection = enum(c_uint) {
        all = 0,
        list = 1,
        labels = 2,
        preset = 3,
        none = 4,
    };

    pub const EAbi = enum(c_uint) {
        unknown = 0,
        default = 1,
        eabi4 = 2,
        eabi5 = 3,
        gnu = 4,
    };

    pub const DebuggerKind = enum(c_uint) {
        default = 0,
        gdb = 1,
        lldb = 2,
        sce = 3,
        dbx = 4,
    };

    pub const GlobalISelAbortMode = enum(c_uint) {
        disable = 0,
        enable = 1,
        disable_with_diagnostic = 2,
    };

    pub const DebugCompressionType = enum(c_uint) {
        none = 0,
        zlib = 1,
        zstd = 2,
    };

    pub const RelocationModel = enum(c_uint) {
        static = 0,
        pic = 1,
        dynamic_no_pic = 2,
        ropi = 3,
        rwpi = 4,
        ropi_rwpi = 5,
    };

    pub const CodeModel = enum(c_uint) {
        tiny = 0,
        small = 1,
        kernel = 2,
        medium = 3,
        large = 4,
    };

    pub const PicLevel = enum(c_uint) {
        not_pic = 0,
        small_pic = 1,
        big_pic = 2,
    };

    pub const PieLevel = enum(c_uint) {
        default = 0,
        small = 1,
        large = 2,
    };

    pub const TlsModel = enum(c_uint) {
        general_dynamic = 0,
        local_dynamic = 1,
        initial_exec = 2,
        local_exec = 3,
    };

    pub const CodegenOptimizationLevel = enum(c_int) {
        none = 0,
        less = 1,
        default = 2,
        aggressive = 3,
    };

    pub const FramePointerKind = enum(c_uint) {
        none = 0,
        non_leaf = 1,
        all = 2,
    };

    pub const CodeGenFileType = enum(c_uint) {
        assembly = 0,
        object = 1,
        null = 2,
    };

    pub const Target = opaque {
        const createTargetMachine = bindings.NativityLLVMTargetCreateTargetMachine;

        pub const Machine = opaque {};

        // This is a non-LLVM struct
        const Options = extern struct {
            bin_utils_version: struct { i32, i32 },
            fp_math: extern struct {
                unsafe: bool,
                no_infs: bool,
                no_nans: bool,
                no_traping: bool,
                no_signed_zeroes: bool,
                approx_func: bool,
                enable_aix_extended_altivec_abi: bool,
                honor_sign_dependent_rounding: bool,
            },
            no_zeroes_in_bss: bool,
            guaranteed_tail_call_optimization: bool,
            stack_symbol_ordering: bool,
            enable_fast_isel: bool,
            enable_global_isel: bool,
            global_isel_abort_mode: GlobalISelAbortMode,
            use_init_array: bool,
            disable_integrated_assembler: bool,
            debug_compression_type: DebugCompressionType,
            relax_elf_relocations: bool,
            function_sections: bool,
            data_sections: bool,
            ignore_xcoff_visibility: bool,
            xcoff_traceback_table: bool,
            unique_section_names: bool,
            unique_basic_block_section_names: bool,
            trap_unreachable: bool,
            no_trap_after_noreturn: bool,
            tls_size: u8,
            emulated_tls: bool,
            enable_ipra: bool,
            emit_stack_size_section: bool,
            enable_machine_outliner: bool,
            enable_machine_function_splitter: bool,
            support_default_outlining: bool,
            emit_address_significance_table: bool,
            bb_sections: BasicBlockSection,
            emit_call_site_info: bool,
            support_debug_entry_values: bool,
            enable_debug_entry_values: bool,
            value_tracking_variable_locations: bool,
            force_dwarf_frame_section: bool,
            xray_function_index: bool,
            debug_strict_dwarf: bool,
            hotpatch: bool,
            ppc_gen_scalar_mass_entries: bool,
            jmc_instrument: bool,
            cfi_fixup: bool,
            loop_alignment: u32 = 0,
            float_abi_type: FloatAbi,
            fp_operation_fusion: FloatOperationFusionMode,
            thread_model: ThreadModel,
            eabi_version: EAbi,
            debugger_tuning: DebuggerKind,
        };
    };

    const lookupIntrinsic = bindings.NativityLLVMLookupIntrinsic;
    const newPhiNode = bindings.NativityLLVMCreatePhiNode;

    pub const Metadata = opaque {
        pub const Node = opaque {};
        pub const Tuple = opaque {};
    };

    pub const Attribute = opaque {
        pub const Set = opaque {};
        pub const Id = enum(u32) {
            AllocAlign = 1,
            AllocatedPointer = 2,
            AlwaysInline = 3,
            Builtin = 4,
            Cold = 5,
            Convergent = 6,
            DisableSanitizerInstrumentation = 7,
            FnRetThunkExtern = 8,
            Hot = 9,
            ImmArg = 10,
            InReg = 11,
            InlineHint = 12,
            JumpTable = 13,
            MinSize = 14,
            MustProgress = 15,
            Naked = 16,
            Nest = 17,
            NoAlias = 18,
            NoBuiltin = 19,
            NoCallback = 20,
            NoCapture = 21,
            NoCfCheck = 22,
            NoDuplicate = 23,
            NoFree = 24,
            NoImplicitFloat = 25,
            NoInline = 26,
            NoMerge = 27,
            NoProfile = 28,
            NoRecurse = 29,
            NoRedZone = 30,
            NoReturn = 31,
            NoSanitizeBounds = 32,
            NoSanitizeCoverage = 33,
            NoSync = 34,
            NoUndef = 35,
            NoUnwind = 36,
            NonLazyBind = 37,
            NonNull = 38,
            NullPointerIsValid = 39,
            OptForFuzzing = 40,
            OptimizeForSize = 41,
            OptimizeNone = 42,
            PresplitCoroutine = 43,
            ReadNone = 44,
            ReadOnly = 45,
            Returned = 46,
            ReturnsTwice = 47,
            SExt = 48,
            SafeStack = 49,
            SanitizeAddress = 50,
            SanitizeHWAddress = 51,
            SanitizeMemTag = 52,
            SanitizeMemory = 53,
            SanitizeThread = 54,
            ShadowCallStack = 55,
            SkipProfile = 56,
            Speculatable = 57,
            SpeculativeLoadHardening = 58,
            StackProtect = 59,
            StackProtectReq = 60,
            StackProtectStrong = 61,
            StrictFP = 62,
            SwiftAsync = 63,
            SwiftError = 64,
            SwiftSelf = 65,
            WillReturn = 66,
            WriteOnly = 67,
            ZExt = 68,
            ByRef = 69,
            ByVal = 70,
            ElementType = 71,
            InAlloca = 72,
            Preallocated = 73,
            StructRet = 74,
            Alignment = 75,
            AllocKind = 76,
            AllocSize = 77,
            Dereferenceable = 78,
            DereferenceableOrNull = 79,
            Memory = 80,
            StackAlignment = 81,
            UWTable = 82,
            VScaleRange = 83,
        };
    };

    pub const Type = opaque {
        const compare = bindings.NativityLLVMCompareTypes;
        const toStruct = bindings.NativityLLVMTypeToStruct;
        const toFunction = bindings.NativityLLVMTypeToFunction;
        const toArray = bindings.NativityLLVMTypeToArray;
        const toPointer = bindings.NativityLLVMTypeToPointer;
        const isPointer = bindings.NativityLLVMTypeIsPointer;
        const isInteger = bindings.NativityLLVMTypeIsInteger;
        const isVoid = bindings.NativityLLVMTypeIsVoid;
        const assertEqual = bindings.NativityLLVMTypeAssertEqual;

        pub const Array = opaque {
            fn toType(integer: *@This()) *Type {
                return @ptrCast(integer);
            }
            const get = bindings.NativityLLVMGetArrayType;
            const getConstant = bindings.NativityLLVMGetConstantArray;
            const getElementType = bindings.NativityLLVMArrayTypeGetElementType;
        };

        pub const Integer = opaque {
            fn toType(integer: *@This()) *Type {
                return @ptrCast(integer);
            }
        };

        pub const Function = opaque {
            fn toType(integer: *@This()) *Type {
                return @ptrCast(integer);
            }

            const getArgumentType = bindings.NativityLLVMFunctionTypeGetArgumentType;
            const getReturnType = bindings.NativityLLVMFunctionTypeGetReturnType;
        };

        pub const Pointer = opaque {
            fn toType(integer: *@This()) *Type {
                return @ptrCast(integer);
            }

            const getNull = bindings.NativityLLVMPointerTypeGetNull;
        };

        pub const Struct = opaque {
            const getConstant = bindings.NativityLLVMGetConstantStruct;
            fn toType(integer: *@This()) *Type {
                return @ptrCast(integer);
            }
        };

        pub const Error = error{
            void,
            function,
            integer,
            pointer,
            @"struct",
            intrinsic,
            array,
        };

        const getPoison = bindings.NativityLLVMGetPoisonValue;
    };

    pub const Value = opaque {
        const setName = bindings.NativityLLVMValueSetName;
        const getType = bindings.NativityLLVMValueGetType;
        const toConstant = bindings.NativityLLVMValueToConstant;
        const toFunction = bindings.NativityLLVMValueToFunction;
        const toAlloca = bindings.NativityLLVMValueToAlloca;
        const toString = bindings.NativityLLVMValueToString;

        pub const IntrinsicID = enum(u32) {
            none = 0,
            _,
        };

        pub const BasicBlock = opaque {
            const remove = bindings.NativityLLVMBasicBlockRemoveFromParent;
            fn toValue(this: *@This()) *Value {
                return @ptrCast(this);
            }
        };

        pub const Argument = opaque {
            const getIndex = bindings.NativityLLVMArgumentGetIndex;
            fn toValue(this: *@This()) *Value {
                return @ptrCast(this);
            }
        };

        pub const Instruction = opaque {
            fn toValue(this: *@This()) *Value {
                return @ptrCast(this);
            }

            pub const Alloca = opaque {
                fn toValue(this: *@This()) *Value {
                    return @ptrCast(this);
                }

                const getAllocatedType = bindings.NativityLLVMAllocatGetAllocatedType;
            };

            pub const Branch = opaque {
                fn toValue(this: *@This()) *Value {
                    return @ptrCast(this);
                }
            };

            pub const Call = opaque {
                const setCallingConvention = bindings.NativityLLVMCallSetCallingConvention;
                const setAttributes = bindings.NativityLLVMCallSetAttributes;
                fn toValue(this: *@This()) *Value {
                    return @ptrCast(this);
                }
            };

            pub const Cast = opaque {
                pub const Type = enum(c_uint) {
                    truncate = 38,
                    zero_extend = 39,
                    sign_extend = 40,
                    float_to_unsigned_integer = 41,
                    float_to_signed_integer = 42,
                    unsigned_integer_to_float = 43,
                    signed_integer_to_float = 44,
                    float_truncate = 45,
                    float_extend = 46,
                    pointer_to_int = 47,
                    int_to_pointer = 48,
                    bitcast = 49,
                    address_space_cast = 50,
                };

                fn toValue(this: *@This()) *Value {
                    return @ptrCast(this);
                }
            };

            pub const ICmp = opaque {
                fn toValue(this: *@This()) *Value {
                    return @ptrCast(this);
                }

                pub const Kind = enum(c_uint) {
                    eq = 32, // equal
                    ne = 33, // not equal
                    ugt = 34, // unsigned greater than
                    uge = 35, // unsigned greater or equal
                    ult = 36, // unsigned less than
                    ule = 37, // unsigned less or equal
                    sgt = 38, // signed greater than
                    sge = 39, // signed greater or equal
                    slt = 40, // signed less than
                    sle = 41, // signed less or equal
                };
            };

            pub const Load = opaque {
                fn toValue(this: *@This()) *Value {
                    return @ptrCast(this);
                }
            };

            pub const PhiNode = opaque {
                pub const addIncoming = bindings.NativityLLVMPhiAddIncoming;

                fn toValue(this: *@This()) *Value {
                    return @ptrCast(this);
                }
            };

            pub const Store = opaque {
                fn toValue(this: *@This()) *Value {
                    return @ptrCast(this);
                }
            };

            pub const Switch = opaque {
                fn toValue(this: *@This()) *Value {
                    return @ptrCast(this);
                }
            };

            pub const Ret = opaque {
                fn toValue(this: *@This()) *Value {
                    return @ptrCast(this);
                }
            };

            pub const Unreachable = opaque {
                fn toValue(this: *@This()) *Value {
                    return @ptrCast(this);
                }
            };

            pub const Error = error{
                add,
                alloca,
                @"and",
                arithmetic_shift_right,
                call,
                cast,
                conditional_branch,
                extract_value,
                gep,
                icmp,
                insert_value,
                load,
                logical_shift_right,
                multiply,
                @"or",
                ret,
                sdiv,
                shift_left,
                store,
                udiv,
                @"unreachable",
                xor,
            };
        };

        pub const Constant = opaque {
            pub const Function = opaque {
                const getArgument = bindings.NativityLLVMFunctionGetArgument;
                const getArguments = bindings.NativityLLVMFunctionGetArguments;
                const getType = bindings.NativityLLVMFunctionGetType;
                // const addAttributeKey = bindings.NativityLLVMFunctionAddAttributeKey;
                const verify = bindings.NativityLLVMVerifyFunction;
                const toString = bindings.NativityLLVMFunctionToString;
                const setCallingConvention = bindings.NativityLLVMFunctionSetCallingConvention;
                const getCallingConvention = bindings.NativityLLVMFunctionGetCallingConvention;
                const setSubprogram = bindings.NativityLLVMFunctionSetSubprogram;
                const getSubprogram = bindings.NativityLLVMFunctionGetSubprogram;
                const setAttributes = bindings.NativityLLVMFunctionSetAttributes;

                fn toValue(this: *@This()) *Value {
                    return @ptrCast(this);
                }

                fn toConstant(this: *@This()) *Constant {
                    return @ptrCast(this);
                }

                pub const CallingConvention = enum(c_uint) {
                    /// The default llvm calling convention, compatible with C. This convention
                    /// is the only one that supports varargs calls. As with typical C calling
                    /// conventions, the callee/caller have to tolerate certain amounts of
                    /// prototype mismatch.
                    C = 0,

                    // Generic LLVM calling conventions. None of these support varargs calls,
                    // and all assume that the caller and callee prototype exactly match.

                    /// Attempts to make calls as fast as possible (e.g. by passing things in
                    /// registers).
                    Fast = 8,

                    /// Attempts to make code in the caller as efficient as possible under the
                    /// assumption that the call is not commonly executed. As such, these calls
                    /// often preserve all registers so that the call does not break any live
                    /// ranges in the caller side.
                    Cold = 9,

                    /// Used by the Glasgow Haskell Compiler (GHC).
                    GHC = 10,

                    /// Used by the High-Performance Erlang Compiler (HiPE).
                    HiPE = 11,

                    /// Used for stack based JavaScript calls
                    WebKit_JS = 12,

                    /// Used for dynamic register based calls (e.g. stackmap and patchpoint
                    /// intrinsics).
                    AnyReg = 13,

                    /// Used for runtime calls that preserves most registers.
                    PreserveMost = 14,

                    /// Used for runtime calls that preserves (almost) all registers.
                    PreserveAll = 15,

                    /// Calling convention for Swift.
                    Swift = 16,

                    /// Used for access functions.
                    CXX_FAST_TLS = 17,

                    /// Attemps to make calls as fast as possible while guaranteeing that tail
                    /// call optimization can always be performed.
                    Tail = 18,

                    /// Special calling convention on Windows for calling the Control Guard
                    /// Check ICall funtion. The function takes exactly one argument (address of
                    /// the target function) passed in the first argument register, and has no
                    /// return value. All register values are preserved.
                    CFGuard_Check = 19,

                    /// This follows the Swift calling convention in how arguments are passed
                    /// but guarantees tail calls will be made by making the callee clean up
                    /// their stack.
                    SwiftTail = 20,

                    /// This is the start of the target-specific calling conventions, e.g.
                    /// fastcall and thiscall on X86.
                    // FirstTargetCC = 64,

                    /// stdcall is mostly used by the Win32 API. It is basically the same as the
                    /// C convention with the difference in that the callee is responsible for
                    /// popping the arguments from the stack.
                    X86_StdCall = 64,

                    /// 'fast' analog of X86_StdCall. Passes first two arguments in ECX:EDX
                    /// registers, others - via stack. Callee is responsible for stack cleaning.
                    X86_FastCall = 65,

                    /// ARM Procedure Calling Standard (obsolete, but still used on some
                    /// targets).
                    ARM_APCS = 66,

                    /// ARM Architecture Procedure Calling Standard calling convention (aka
                    /// EABI). Soft float variant.
                    ARM_AAPCS = 67,

                    /// Same as ARM_AAPCS, but uses hard floating point ABI.
                    ARM_AAPCS_VFP = 68,

                    /// Used for MSP430 interrupt routines.
                    MSP430_INTR = 69,

                    /// Similar to X86_StdCall. Passes first argument in ECX, others via stack.
                    /// Callee is responsible for stack cleaning. MSVC uses this by default for
                    /// methods in its ABI.
                    X86_ThisCall = 70,

                    /// Call to a PTX kernel. Passes all arguments in parameter space.
                    PTX_Kernel = 71,

                    /// Call to a PTX device function. Passes all arguments in register or
                    /// parameter space.
                    PTX_Device = 72,

                    /// Used for SPIR non-kernel device functions. No lowering or expansion of
                    /// arguments. Structures are passed as a pointer to a struct with the
                    /// byval attribute. Functions can only call SPIR_FUNC and SPIR_KERNEL
                    /// functions. Functions can only have zero or one return values. Variable
                    /// arguments are not allowed, except for printf. How arguments/return
                    /// values are lowered are not specified. Functions are only visible to the
                    /// devices.
                    SPIR_FUNC = 75,

                    /// Used for SPIR kernel functions. Inherits the restrictions of SPIR_FUNC,
                    /// except it cannot have non-void return values, it cannot have variable
                    /// arguments, it can also be called by the host or it is externally
                    /// visible.
                    SPIR_KERNEL = 76,

                    /// Used for Intel OpenCL built-ins.
                    Intel_OCL_BI = 77,

                    /// The C convention as specified in the x86-64 supplement to the System V
                    /// ABI, used on most non-Windows systems.
                    X86_64_SysV = 78,

                    /// The C convention as implemented on Windows/x86-64 and AArch64. It
                    /// differs from the more common \c X86_64_SysV convention in a number of
                    /// ways, most notably in that XMM registers used to pass arguments are
                    /// shadowed by GPRs, and vice versa. On AArch64, this is identical to the
                    /// normal C (AAPCS) calling convention for normal functions, but floats are
                    /// passed in integer registers to variadic functions.
                    Win64 = 79,

                    /// MSVC calling convention that passes vectors and vector aggregates in SSE
                    /// registers.
                    X86_VectorCall = 80,

                    /// Used by HipHop Virtual Machine (HHVM) to perform calls to and from
                    /// translation cache, and for calling PHP functions. HHVM calling
                    /// convention supports tail/sibling call elimination.
                    HHVM = 81,

                    /// HHVM calling convention for invoking C/C++ helpers.
                    HHVM_C = 82,

                    /// x86 hardware interrupt context. Callee may take one or two parameters,
                    /// where the 1st represents a pointer to hardware context frame and the 2nd
                    /// represents hardware error code, the presence of the later depends on the
                    /// interrupt vector taken. Valid for both 32- and 64-bit subtargets.
                    X86_INTR = 83,

                    /// Used for AVR interrupt routines.
                    AVR_INTR = 84,

                    /// Used for AVR signal routines.
                    AVR_SIGNAL = 85,

                    /// Used for special AVR rtlib functions which have an "optimized"
                    /// convention to preserve registers.
                    AVR_BUILTIN = 86,

                    /// Used for Mesa vertex shaders, or AMDPAL last shader stage before
                    /// rasterization (vertex shader if tessellation and geometry are not in
                    /// use, or otherwise copy shader if one is needed).
                    AMDGPU_VS = 87,

                    /// Used for Mesa/AMDPAL geometry shaders.
                    AMDGPU_GS = 88,

                    /// Used for Mesa/AMDPAL pixel shaders.
                    AMDGPU_PS = 89,

                    /// Used for Mesa/AMDPAL compute shaders.
                    AMDGPU_CS = 90,

                    /// Used for AMDGPU code object kernels.
                    AMDGPU_KERNEL = 91,

                    /// Register calling convention used for parameters transfer optimization
                    X86_RegCall = 92,

                    /// Used for Mesa/AMDPAL hull shaders (= tessellation control shaders).
                    AMDGPU_HS = 93,

                    /// Used for special MSP430 rtlib functions which have an "optimized"
                    /// convention using additional registers.
                    MSP430_BUILTIN = 94,

                    /// Used for AMDPAL vertex shader if tessellation is in use.
                    AMDGPU_LS = 95,

                    /// Used for AMDPAL shader stage before geometry shader if geometry is in
                    /// use. So either the domain (= tessellation evaluation) shader if
                    /// tessellation is in use, or otherwise the vertex shader.
                    AMDGPU_ES = 96,

                    /// Used between AArch64 Advanced SIMD functions
                    AArch64_VectorCall = 97,

                    /// Used between AArch64 SVE functions
                    AArch64_SVE_VectorCall = 98,

                    /// For emscripten __invoke_* functions. The first argument is required to
                    /// be the function ptr being indirectly called. The remainder matches the
                    /// regular calling convention.
                    WASM_EmscriptenInvoke = 99,

                    /// Used for AMD graphics targets.
                    AMDGPU_Gfx = 100,

                    /// Used for M68k interrupt routines.
                    M68k_INTR = 101,

                    /// Preserve X0-X13, X19-X29, SP, Z0-Z31, P0-P15.
                    AArch64_SME_ABI_Support_Routines_PreserveMost_From_X0 = 102,

                    /// Preserve X2-X15, X19-X29, SP, Z0-Z31, P0-P15.
                    AArch64_SME_ABI_Support_Routines_PreserveMost_From_X2 = 103,

                    /// The highest possible ID. Must be some 2^k - 1.
                    MaxID = 1023,
                };
            };

            pub const Int = opaque {
                fn toValue(this: *@This()) *Value {
                    return @ptrCast(this);
                }
                fn toConstant(this: *@This()) *Constant {
                    return @ptrCast(this);
                }
            };

            pub const GlobalVariable = opaque {
                pub const setInitializer = bindings.NativityLLVMGlobalVariableSetInitializer;
                fn toValue(this: *@This()) *Value {
                    return @ptrCast(this);
                }
                fn toConstant(this: *@This()) *Constant {
                    return @ptrCast(this);
                }
            };

            pub const PointerNull = opaque {
                fn toValue(this: *@This()) *Value {
                    return @ptrCast(this);
                }
                fn toConstant(this: *@This()) *Constant {
                    return @ptrCast(this);
                }
            };

            pub const Undefined = opaque {
                fn toConstant(this: *@This()) *Constant {
                    return @ptrCast(this);
                }
                fn toValue(this: *@This()) *Value {
                    return @ptrCast(this);
                }
            };

            pub const Poison = opaque {
                fn toConstant(this: *@This()) *Constant {
                    return @ptrCast(this);
                }
                fn toValue(this: *@This()) *Value {
                    return @ptrCast(this);
                }
            };

            fn toValue(this: *@This()) *Value {
                return @ptrCast(this);
            }

            const toInt = bindings.NativityLLVMConstantToInt;
        };

        pub const InlineAssembly = opaque {
            pub const Dialect = enum(c_uint) {
                @"at&t",
                intel,
            };
            const get = bindings.NativityLLVMGetInlineAssembly;
            fn toValue(this: *@This()) *Value {
                return @ptrCast(this);
            }
        };

        pub const Error = error{
            constant_struct,
            constant_int,
            constant_array,
            inline_assembly,
            global_variable,
            intrinsic,
        };
    };

    fn getType(llvm: *LLVM, unit: *Compilation.Unit, context: *const Compilation.Context, type_index: Compilation.Type.Index) !*LLVM.Type {
        if (llvm.type_map.get(type_index)) |llvm_type| {
            return llvm_type;
        } else {
            const sema_type = unit.types.get(type_index);

            const llvm_type: *LLVM.Type = switch (sema_type.*) {
                .function => |function_prototype_index| blk: {
                    const sema_function_prototype = unit.function_prototypes.get(function_prototype_index);
                    const llvm_return_type = try llvm.getType(unit, context, sema_function_prototype.abi.return_type);
                    var parameter_types = try UnpinnedArray(*LLVM.Type).initialize_with_capacity(context.my_allocator, @intCast(sema_function_prototype.abi.parameter_types.len));

                    for (sema_function_prototype.abi.parameter_types) |argument_type_index| {
                        parameter_types.append_with_capacity(try llvm.getType(unit, context, argument_type_index));
                    }

                    const is_var_args = false;
                    const llvm_function_type = LLVM.Context.getFunctionType(llvm_return_type, parameter_types.pointer, parameter_types.length, is_var_args) orelse return Type.Error.function;
                    break :blk llvm_function_type.toType();
                },
                .integer => |integer| switch (integer.kind) {
                    .comptime_int => unreachable,
                    else => blk: {
                        const llvm_integer_type = llvm.context.getIntegerType(integer.bit_count) orelse return Type.Error.integer;
                        break :blk llvm_integer_type.toType();
                    },
                },
                .pointer => {
                    if (llvm.pointer_type) |pointer_type| {
                        return pointer_type.toType();
                    } else {
                        const pointer_type = llvm.context.getPointerType(address_space) orelse return Type.Error.pointer;
                        llvm.pointer_type = pointer_type;
                        return pointer_type.toType();
                    }
                },
                .noreturn,
                .void,
                => blk: {
                    const void_type = llvm.context.getVoidType() orelse return Type.Error.void;
                    break :blk void_type;
                },
                .slice => |slice| blk: {
                    const llvm_pointer_type = try llvm.getType(unit, context, slice.child_pointer_type);
                    const llvm_usize_type = try llvm.getType(unit, context, .usize);
                    const slice_types = [_]*Type{ llvm_pointer_type, llvm_usize_type };
                    const is_packed = false;
                    const struct_type = llvm.context.getStructType(&slice_types, slice_types.len, is_packed) orelse return Type.Error.@"struct";
                    break :blk struct_type.toType();
                },
                .@"struct" => |struct_type_index| switch (unit.structs.get(struct_type_index).kind) {
                    .error_union => |error_union| try llvm.getType(unit, context, error_union.abi),
                    .raw_error_union => |error_union_type_index| blk: {
                        const error_union_type = try llvm.getType(unit, context, error_union_type_index);
                        const boolean_type = try llvm.getType(unit, context, .bool);
                        const types = [2]*LLVM.Type{ error_union_type, boolean_type };
                        const is_packed = false;
                        const struct_type = llvm.context.getStructType(&types, types.len, is_packed) orelse return Type.Error.@"struct";
                        break :blk struct_type.toType();
                    },
                    .abi_compatible_error_union => |error_union| blk: {
                        const error_union_type = try llvm.getType(unit, context, error_union.type);
                        const padding_type = try llvm.getType(unit, context, error_union.padding);
                        const boolean_type = try llvm.getType(unit, context, .bool);
                        const types = [3]*LLVM.Type{ error_union_type, padding_type, boolean_type };
                        const is_packed = false;
                        const struct_type = llvm.context.getStructType(&types, types.len, is_packed) orelse return Type.Error.@"struct";
                        break :blk struct_type.toType();
                    },
                    .@"struct" => |*sema_struct_type| blk: {
                        var field_type_list = try UnpinnedArray(*LLVM.Type).initialize_with_capacity(context.my_allocator, sema_struct_type.fields.length);
                        for (sema_struct_type.fields.slice()) |sema_field_index| {
                            const sema_field = unit.struct_fields.get(sema_field_index);
                            const llvm_type = try llvm.getType(unit, context, sema_field.type);
                            field_type_list.append_with_capacity(llvm_type);
                        }

                        // TODO:
                        const is_packed = false;
                        const struct_type = llvm.context.getStructType(field_type_list.pointer, field_type_list.length, is_packed) orelse return Type.Error.@"struct";

                        break :blk struct_type.toType();
                    },
                    .two_struct => |pair| blk: {
                        const types = [2]*LLVM.Type{
                            try llvm.getType(unit, context, pair[0]),
                            try llvm.getType(unit, context, pair[1]),
                        };
                        const is_packed = false;
                        const struct_type = llvm.context.getStructType(&types, types.len, is_packed) orelse return Type.Error.@"struct";

                        break :blk struct_type.toType();
                    },
                    else => |t| @panic(@tagName(t)),
                },
                .array => |array| blk: {
                    const element_type = try llvm.getType(unit, context, array.type);
                    const extra_element = switch (array.termination) {
                        .none => false,
                        else => true,
                    };
                    const array_type = LLVM.Type.Array.get(element_type, array.count + @intFromBool(extra_element)) orelse return Type.Error.array;
                    break :blk array_type.toType();
                },
                else => |t| @panic(@tagName(t)),
            };

            try llvm.type_map.put_no_clobber(context.my_allocator, type_index, llvm_type);

            return llvm_type;
        }
    }

    fn getDebugInfoFile(llvm: *LLVM, unit: *Compilation.Unit, context: *const Compilation.Context, sema_file_index: Compilation.Debug.File.Index) !*DebugInfo.File {
        if (llvm.debug_info_file_map.get(sema_file_index)) |file| {
            return file;
        } else {
            // if (@intFromEnum(sema_file_index) == 4) @breakpoint();
            const sema_file = unit.files.get(sema_file_index);
            const full_path = try Compilation.joinPath(context, sema_file.package.directory.path, sema_file.relative_path);
            const filename = std.fs.path.basename(full_path);
            const directory = full_path[0 .. full_path.len - filename.len];
            const debug_file = llvm.debug_info_builder.createFile(filename.ptr, filename.len, directory.ptr, directory.len) orelse unreachable;
            try llvm.debug_info_file_map.put_no_clobber(context.my_allocator, sema_file_index, debug_file);
            return debug_file;
        }
    }

    fn renderTypeName(llvm: *LLVM, unit: *Compilation.Unit, context: *const Compilation.Context, sema_type_index: Compilation.Type.Index) ![]const u8 {
        if (llvm.type_name_map.get(sema_type_index)) |result| {
            return result;
        } else {
            if (unit.type_declarations.get(sema_type_index)) |global_declaration| {
                const result = unit.getIdentifier(global_declaration.declaration.name);
                try llvm.type_name_map.put_no_clobber(context.my_allocator, sema_type_index, result);
                return result;
            } else {
                const sema_type = unit.types.get(sema_type_index);
                const result: []const u8 = switch (sema_type.*) {
                    .integer => |integer| switch (integer.kind) {
                        .materialized_int => b: {
                            var buffer: [65]u8 = undefined;
                            const format = data_structures.format_int(&buffer, integer.bit_count, 10, false);
                            const slice_ptr = format.ptr - 1;
                            const slice = slice_ptr[0 .. format.len + 1];
                            slice[0] = switch (integer.signedness) {
                                .signed => 's',
                                .unsigned => 'u',
                            };

                            break :b try context.my_allocator.duplicate_bytes(slice);
                        },
                        .bool => "bool",
                        else => |t| @panic(@tagName(t)),
                    },
                    // .bool => "bool",
                    .pointer => |pointer| b: {
                        var name = UnpinnedArray(u8){};
                        try name.append(context.my_allocator, '&');
                        if (pointer.mutability == .@"const") {
                            try name.append_slice(context.my_allocator, "const");
                        }
                        try name.append(context.my_allocator, ' ');
                        const element_type_name = try llvm.renderTypeName(unit, context, pointer.type);
                        try name.append_slice(context.my_allocator, element_type_name);
                        break :b name.slice();
                    },
                    .@"struct" => |struct_index| switch (unit.structs.get(struct_index).kind) {
                        .@"struct" => "anon_struct", // TODO:
                        else => |t| @panic(@tagName(t)),
                    },
                    // TODO: termination
                    .slice => |slice| b: {
                        var name = UnpinnedArray(u8){};
                        try name.append_slice(context.my_allocator, "[] ");
                        if (slice.mutability == .@"const") {
                            try name.append_slice(context.my_allocator, "const ");
                        }
                        const element_type_name = try llvm.renderTypeName(unit, context, slice.child_type);
                        try name.append_slice(context.my_allocator, element_type_name);
                        break :b name.slice();
                    },
                    .array => |array| b: {
                        var name = UnpinnedArray(u8){};
                        try name.append(context.my_allocator, '[');
                        var buffer: [65]u8 = undefined;
                        const array_count = data_structures.format_int(&buffer, array.count, 10, false);
                        try name.append_slice(context.my_allocator, array_count);
                        try name.append(context.my_allocator, ']');
                        const element_type_name = try llvm.renderTypeName(unit, context, array.type);
                        try name.append_slice(context.my_allocator, element_type_name);

                        break :b name.slice();
                    },
                    // TODO
                    .function => "fn_type",
                    else => |t| @panic(@tagName(t)),
                };

                try llvm.type_name_map.put(context.my_allocator, sema_type_index, result);

                return result;
            }
        }
    }

    fn createDebugStructType(llvm: *LLVM, arguments: struct {
        scope: ?*LLVM.DebugInfo.Scope,
        name: []const u8,
        file: ?*LLVM.DebugInfo.File,
        line: u32,
        bitsize: u64,
        alignment: u32,
        field_types: []const *LLVM.DebugInfo.Type,
        forward_declaration: ?*LLVM.DebugInfo.Type.Composite,
    }) *LLVM.DebugInfo.Type.Composite {
        const flags = LLVM.DebugInfo.Node.Flags{
            .visibility = .none,
            .forward_declaration = false,
            .apple_block = false,
            .block_by_ref_struct = false,
            .virtual = false,
            .artificial = false,
            .explicit = false,
            .prototyped = false,
            .objective_c_class_complete = false,
            .object_pointer = false,
            .vector = false,
            .static_member = false,
            .lvalue_reference = false,
            .rvalue_reference = false,
            .reserved = false,
            .inheritance = .none,
            .introduced_virtual = false,
            .bit_field = false,
            .no_return = false,
            .type_pass_by_value = false,
            .type_pass_by_reference = false,
            .enum_class = false,
            .thunk = false,
            .non_trivial = false,
            .big_endian = false,
            .little_endian = false,
            .all_calls_described = false,
        };

        const struct_type = llvm.debug_info_builder.createStructType(arguments.scope, arguments.name.ptr, arguments.name.len, arguments.file, arguments.line, arguments.bitsize, arguments.alignment, flags, null, arguments.field_types.ptr, arguments.field_types.len, arguments.forward_declaration) orelse unreachable;
        return struct_type;
    }

    fn getDebugStructType(llvm: *LLVM, unit: *Compilation.Unit, context: *const Compilation.Context, sema_type_index: Compilation.Type.Index, scope: *const Compilation.Debug.Scope, fields: []const Compilation.Struct.Field.Index, name: []const u8) !*LLVM.DebugInfo.Type {
        const file = try llvm.getDebugInfoFile(unit, context, scope.file);
        const line = 0;

        const flags = LLVM.DebugInfo.Node.Flags{
            .visibility = .none,
            .forward_declaration = false,
            .apple_block = false,
            .block_by_ref_struct = false,
            .virtual = false,
            .artificial = false,
            .explicit = false,
            .prototyped = false,
            .objective_c_class_complete = false,
            .object_pointer = false,
            .vector = false,
            .static_member = false,
            .lvalue_reference = false,
            .rvalue_reference = false,
            .reserved = false,
            .inheritance = .none,
            .introduced_virtual = false,
            .bit_field = false,
            .no_return = false,
            .type_pass_by_value = false,
            .type_pass_by_reference = false,
            .enum_class = false,
            .thunk = false,
            .non_trivial = false,
            .big_endian = false,
            .little_endian = false,
            .all_calls_described = false,
        };

        var bit_size: u32 = 0;
        for (fields) |struct_field_index| {
            const struct_field = unit.struct_fields.get(struct_field_index);
            const struct_field_type = unit.types.get(struct_field.type);
            const struct_field_bit_size = struct_field_type.getBitSize(unit);
            bit_size += struct_field_bit_size;
        }

        const struct_type = llvm.createDebugStructType(.{
            .scope = null,
            .name = name,
            .file = file,
            .line = line,
            .bitsize = bit_size,
            .alignment = 0,
            .field_types = &.{},
            .forward_declaration = null,
        });
        try llvm.debug_type_map.put_no_clobber(context.my_allocator, sema_type_index, struct_type.toType());
        var field_types = try UnpinnedArray(*LLVM.DebugInfo.Type).initialize_with_capacity(context.my_allocator, @intCast(fields.len));
        bit_size = 0;
        for (fields) |struct_field_index| {
            const struct_field = unit.struct_fields.get(struct_field_index);
            const struct_field_type = unit.types.get(struct_field.type);
            const struct_field_bit_size = struct_field_type.getBitSize(unit);
            const field_type = try llvm.getDebugType(unit, context, struct_field.type);
            //TODO: fix
            const alignment = struct_field_bit_size;
            const member_type = llvm.debug_info_builder.createMemberType(null, "", "".len, file, 0, struct_field_bit_size, alignment, bit_size, flags, field_type).toType();
            field_types.append_with_capacity(member_type);
            bit_size += struct_field_bit_size;
        }

        llvm.debug_info_builder.replaceCompositeTypes(struct_type, field_types.pointer, field_types.length);
        return struct_type.toType();
    }

    fn getDebugType(llvm: *LLVM, unit: *Compilation.Unit, context: *const Compilation.Context, sema_type_index: Compilation.Type.Index) anyerror!*LLVM.DebugInfo.Type {
        if (llvm.debug_type_map.get(sema_type_index)) |result| {
            return result;
        } else {
            const name = try llvm.renderTypeName(unit, context, sema_type_index);
            const sema_type = unit.types.get(sema_type_index);
            const result = switch (sema_type.*) {
                .integer => |*integer| switch (integer.kind) {
                    .bitfield => |*bitfield| try llvm.getDebugStructType(unit, context, sema_type_index, &bitfield.scope.scope, bitfield.fields.slice(), name),
                    .materialized_int => b: {
                        const dwarf_encoding: LLVM.DebugInfo.AttributeType = switch (integer.signedness) {
                            .unsigned => .unsigned,
                            .signed => .signed,
                        };
                        const flags = LLVM.DebugInfo.Node.Flags{
                            .visibility = .none,
                            .forward_declaration = false,
                            .apple_block = false,
                            .block_by_ref_struct = false,
                            .virtual = false,
                            .artificial = false,
                            .explicit = false,
                            .prototyped = false,
                            .objective_c_class_complete = false,
                            .object_pointer = false,
                            .vector = false,
                            .static_member = false,
                            .lvalue_reference = false,
                            .rvalue_reference = false,
                            .reserved = false,
                            .inheritance = .none,
                            .introduced_virtual = false,
                            .bit_field = false,
                            .no_return = false,
                            .type_pass_by_value = false,
                            .type_pass_by_reference = false,
                            .enum_class = false,
                            .thunk = false,
                            .non_trivial = false,
                            .big_endian = false,
                            .little_endian = false,
                            .all_calls_described = false,
                        };
                        const integer_type = llvm.debug_info_builder.createBasicType(name.ptr, name.len, integer.bit_count, dwarf_encoding, flags) orelse unreachable;
                        break :b integer_type;
                    },
                    .bool => b: {
                        const flags = LLVM.DebugInfo.Node.Flags{
                            .visibility = .none,
                            .forward_declaration = false,
                            .apple_block = false,
                            .block_by_ref_struct = false,
                            .virtual = false,
                            .artificial = false,
                            .explicit = false,
                            .prototyped = false,
                            .objective_c_class_complete = false,
                            .object_pointer = false,
                            .vector = false,
                            .static_member = false,
                            .lvalue_reference = false,
                            .rvalue_reference = false,
                            .reserved = false,
                            .inheritance = .none,
                            .introduced_virtual = false,
                            .bit_field = false,
                            .no_return = false,
                            .type_pass_by_value = false,
                            .type_pass_by_reference = false,
                            .enum_class = false,
                            .thunk = false,
                            .non_trivial = false,
                            .big_endian = false,
                            .little_endian = false,
                            .all_calls_described = false,
                        };
                        const boolean_type = llvm.debug_info_builder.createBasicType("bool", "bool".len, 1, .boolean, flags) orelse unreachable;
                        break :b boolean_type;
                    },
                    .@"enum" => |*enum_type| b: {
                        var enumerators = try UnpinnedArray(*LLVM.DebugInfo.Type.Enumerator).initialize_with_capacity(context.my_allocator, enum_type.fields.length);
                        for (enum_type.fields.slice()) |enum_field_index| {
                            const enum_field = unit.enum_fields.get(enum_field_index);
                            const enum_field_name = unit.getIdentifier(enum_field.name);

                            const is_unsigned = true;
                            const enumerator = llvm.debug_info_builder.createEnumerator(enum_field_name.ptr, enum_field_name.len, enum_field.value, is_unsigned) orelse unreachable;
                            enumerators.append_with_capacity(enumerator);
                        }

                        const type_declaration = unit.type_declarations.get(sema_type_index).?;
                        const file = try llvm.getDebugInfoFile(unit, context, type_declaration.declaration.scope.file);
                        const bit_size = integer.bit_count;
                        const sema_backing_type = try unit.getIntegerType(context, .{
                            .kind = .materialized_int,
                            .bit_count = integer.bit_count,
                            .signedness = integer.signedness,
                        });
                        const backing_type = try llvm.getDebugType(unit, context, sema_backing_type);
                        const alignment = 0;
                        const line = type_declaration.declaration.line + 1;
                        const scope = try llvm.getScope(unit, context, enum_type.scope.scope.parent.?);
                        const enumeration_type = llvm.debug_info_builder.createEnumerationType(scope, name.ptr, name.len, file, line, bit_size, alignment, enumerators.pointer, enumerators.length, backing_type) orelse unreachable;
                        break :b enumeration_type.toType();
                    },
                    .@"error" => |*error_type| b: {
                        var enumerators = try UnpinnedArray(*LLVM.DebugInfo.Type.Enumerator).initialize_with_capacity(context.my_allocator, error_type.fields.length);
                        for (error_type.fields.slice()) |error_field_index| {
                            const error_field = unit.error_fields.get(error_field_index);
                            const error_field_name = unit.getIdentifier(error_field.name);

                            const is_unsigned = true;
                            const enumerator = llvm.debug_info_builder.createEnumerator(error_field_name.ptr, error_field_name.len, error_field.value, is_unsigned) orelse unreachable;
                            enumerators.append_with_capacity(enumerator);
                        }

                        const type_declaration = unit.type_declarations.get(sema_type_index).?;
                        const file = try llvm.getDebugInfoFile(unit, context, type_declaration.declaration.scope.file);
                        const bit_size = integer.bit_count;
                        const sema_backing_type = try unit.getIntegerType(context, .{
                            .kind = .materialized_int,
                            .bit_count = integer.bit_count,
                            .signedness = integer.signedness,
                        });
                        const backing_type = try llvm.getDebugType(unit, context, sema_backing_type);
                        const alignment = 0;
                        const line = type_declaration.declaration.line + 1;
                        const scope = try llvm.getScope(unit, context, error_type.scope.scope.parent.?);
                        const enumeration_type = llvm.debug_info_builder.createEnumerationType(scope, name.ptr, name.len, file, line, bit_size, alignment, enumerators.pointer, enumerators.length, backing_type) orelse unreachable;
                        break :b enumeration_type.toType();
                    },
                    else => |t| @panic(@tagName(t)),
                },
                .@"struct" => |struct_index| switch (unit.structs.get(struct_index).kind) {
                    .@"struct" => |*sema_struct_type| try llvm.getDebugStructType(unit, context, sema_type_index, &sema_struct_type.scope.scope, sema_struct_type.fields.slice(), name),
                    else => |t| @panic(@tagName(t)),
                },
                .pointer => |pointer| b: {
                    const element_type = try llvm.getDebugType(unit, context, pointer.type);
                    const pointer_width = @bitSizeOf(usize);
                    const alignment = 3;
                    const pointer_type = llvm.debug_info_builder.createPointerType(element_type, pointer_width, alignment, name.ptr, name.len) orelse unreachable;
                    break :b pointer_type.toType();
                },
                .slice => |slice| b: {
                    const pointer_type = try llvm.getDebugType(unit, context, slice.child_pointer_type);
                    const len_type = try llvm.getDebugType(unit, context, .usize);
                    const scope = null;
                    const file = null;
                    const line = 1;
                    const flags = LLVM.DebugInfo.Node.Flags{
                        .visibility = .none,
                        .forward_declaration = false,
                        .apple_block = false,
                        .block_by_ref_struct = false,
                        .virtual = false,
                        .artificial = false,
                        .explicit = false,
                        .prototyped = false,
                        .objective_c_class_complete = false,
                        .object_pointer = false,
                        .vector = false,
                        .static_member = false,
                        .lvalue_reference = false,
                        .rvalue_reference = false,
                        .reserved = false,
                        .inheritance = .none,
                        .introduced_virtual = false,
                        .bit_field = false,
                        .no_return = false,
                        .type_pass_by_value = false,
                        .type_pass_by_reference = false,
                        .enum_class = false,
                        .thunk = false,
                        .non_trivial = false,
                        .big_endian = false,
                        .little_endian = false,
                        .all_calls_described = false,
                    };

                    const types = [2]*LLVM.DebugInfo.Type{ pointer_type, len_type };
                    const member_types = [2]*LLVM.DebugInfo.Type{
                        llvm.debug_info_builder.createMemberType(null, "", "".len, null, 0, 64, 3, 0, flags, types[0]).toType(),
                        llvm.debug_info_builder.createMemberType(null, "", "".len, null, 0, 64, 3, 64, flags, types[1]).toType(),
                    };
                    const struct_type = llvm.createDebugStructType(.{
                        .scope = scope,
                        .name = name,
                        .file = file,
                        .line = line,
                        .bitsize = 2 * @bitSizeOf(usize),
                        .alignment = @alignOf(usize),
                        .field_types = &member_types,
                        .forward_declaration = null,
                    });
                    break :b struct_type.toType();
                },
                .array => |array| b: {
                    // TODO: compute
                    const byte_size = 1; // array.count * unit.types.get(array.element_type).getSize();
                    const bit_size = byte_size * 8;
                    const element_type = try llvm.getDebugType(unit, context, array.type);
                    const array_type = llvm.debug_info_builder.createArrayType(bit_size, 1, element_type, array.count) orelse unreachable;
                    break :b array_type.toType();
                },
                .function => |function_prototype_index| b: {
                    const function_prototype = unit.function_prototypes.get(function_prototype_index);
                    var parameter_types = try UnpinnedArray(*LLVM.DebugInfo.Type).initialize_with_capacity(context.my_allocator, @intCast(function_prototype.argument_types.len));
                    for (function_prototype.argument_types) |argument_type_index| {
                        const argument_type = try llvm.getDebugType(unit, context, argument_type_index);
                        parameter_types.append_with_capacity(argument_type);
                    }
                    const subroutine_type_flags = LLVM.DebugInfo.Node.Flags{
                        .visibility = .none,
                        .forward_declaration = false,
                        .apple_block = false,
                        .block_by_ref_struct = false,
                        .virtual = false,
                        .artificial = false,
                        .explicit = false,
                        .prototyped = false,
                        .objective_c_class_complete = false,
                        .object_pointer = false,
                        .vector = false,
                        .static_member = false,
                        .lvalue_reference = false,
                        .rvalue_reference = false,
                        .reserved = false,
                        .inheritance = .none,
                        .introduced_virtual = false,
                        .bit_field = false,
                        .no_return = false,
                        .type_pass_by_value = false,
                        .type_pass_by_reference = false,
                        .enum_class = false,
                        .thunk = false,
                        .non_trivial = false,
                        .big_endian = false,
                        .little_endian = false,
                        .all_calls_described = false,
                    };
                    const subroutine_type_calling_convention = LLVM.DebugInfo.CallingConvention.none;
                    const subroutine_type = llvm.debug_info_builder.createSubroutineType(parameter_types.pointer, parameter_types.length, subroutine_type_flags, subroutine_type_calling_convention) orelse unreachable;
                    break :b subroutine_type.toType();
                },
                else => |t| @panic(@tagName(t)),
            };

            try llvm.debug_type_map.put(context.my_allocator, sema_type_index, result);

            assert(@intFromPtr(result) != 0xaaaa_aaaa_aaaa_aaaa);
            return result;
        }
    }

    fn createGEP(llvm: *LLVM, unit: *Compilation.Unit, context: *const Compilation.Context, instruction_index: Compilation.Instruction.Index) !*LLVM.Value {
        const instruction = unit.instructions.get(instruction_index);
        const gep = instruction.get_element_pointer;
        const pointer = llvm.llvm_instruction_map.get(gep.pointer).?;
        const index = try llvm.emitRightValue(unit, context, gep.index);
        const struct_index = llvm.context.getConstantInt(@bitSizeOf(u32), 0, false) orelse unreachable;
        const index_buffer = [2]*LLVM.Value{ struct_index.toValue(), index };
        const indices = index_buffer[@intFromBool(!gep.is_struct)..];
        if (gep.is_struct) assert(indices.len == 2) else assert(indices.len == 1);
        const base_type = try llvm.getType(unit, context, gep.base_type);
        const in_bounds = true;
        if (gep.is_struct and gep.index.type != .u32) unreachable;
        const gep_name = unit.getIdentifier(gep.name);
        const get_element_pointer = llvm.builder.createGEP(base_type, pointer, indices.ptr, indices.len, gep_name.ptr, gep_name.len, in_bounds) orelse unreachable;
        try llvm.llvm_instruction_map.put_no_clobber(context.my_allocator, instruction_index, get_element_pointer);
        return get_element_pointer;
    }

    fn emitLeftValue(llvm: *LLVM, unit: *Compilation.Unit, context: *const Compilation.Context, v: Compilation.V) !*LLVM.Value {
        switch (v.value) {
            .runtime => |instruction_index| {
                if (llvm.llvm_instruction_map.get(instruction_index)) |value| {
                    return value;
                } else {
                    const instruction = unit.instructions.get(instruction_index);
                    switch (instruction.*) {
                        .get_element_pointer => {
                            return try llvm.createGEP(unit, context, instruction_index);
                        },
                        else => |t| @panic(@tagName(t)),
                    }
                }
            },
            .@"comptime" => |ct| switch (ct) {
                .global => |global| switch (global.initial_value) {
                    .function_definition => return llvm.function_definition_map.get(global).?.toValue(),
                    else => return llvm.global_variable_map.get(global).?.toValue(),
                },
                else => |t| @panic(@tagName(t)),
            },
            else => |t| @panic(@tagName(t)),
        }
    }

    fn emitComptimeRightValue(llvm: *LLVM, unit: *Compilation.Unit, context: *const Compilation.Context, ct: Compilation.V.Comptime, type_index: Compilation.Type.Index) anyerror!*LLVM.Value.Constant {
        switch (ct) {
            .constant_int => |integer| {
                const integer_type = unit.types.get(type_index);
                switch (integer_type.*) {
                    .integer => |integer_t| switch (integer_t.kind) {
                        .materialized_int, .bitfield => {
                            const signed = switch (integer_t.signedness) {
                                .signed => true,
                                .unsigned => false,
                            };
                            const constant_int = llvm.context.getConstantInt(integer_t.bit_count, integer.value, signed) orelse unreachable;
                            return constant_int.toConstant();
                        },
                        else => |t| @panic(@tagName(t)),
                    },
                    else => |t| @panic(@tagName(t)),
                }
            },
            .comptime_int => |integer| {
                const integer_type = unit.types.get(type_index);
                switch (integer_type.*) {
                    .integer => |integer_t| switch (integer_t.kind) {
                        else => |t| @panic(@tagName(t)),
                        .materialized_int => {
                            const signed = switch (integer_t.signedness) {
                                .signed => true,
                                .unsigned => false,
                            };
                            const constant_int = llvm.context.getConstantInt(integer_t.bit_count, integer.value, signed) orelse unreachable;
                            return constant_int.toConstant();
                        },
                    },
                    else => |t| @panic(@tagName(t)),
                }
            },
            .enum_value => |enum_field_index| {
                const enum_field = unit.enum_fields.get(enum_field_index);
                const integer = unit.types.get(enum_field.parent).integer;
                const signed = switch (integer.signedness) {
                    .signed => true,
                    .unsigned => false,
                };
                const constant_int = llvm.context.getConstantInt(integer.bit_count, enum_field.value, signed) orelse unreachable;
                return constant_int.toConstant();
            },
            .constant_bitfield => |value| {
                const integer = unit.types.get(type_index).integer;
                const signed = switch (integer.signedness) {
                    .signed => true,
                    .unsigned => false,
                };
                const constant_int = llvm.context.getConstantInt(integer.bit_count, value, signed) orelse unreachable;
                return constant_int.toConstant();
            },
            .constant_struct => |constant_struct_index| return try llvm.getConstantStruct(unit, context, constant_struct_index),
            .undefined => {
                const undefined_type = try llvm.getType(unit, context, type_index);
                const poison = undefined_type.getPoison() orelse unreachable;
                return poison.toConstant();
            },
            .bool => |boolean| {
                const bit_count = 1;
                const signed = false;
                const constant_bool = llvm.context.getConstantInt(bit_count, @intFromBool(boolean), signed) orelse unreachable;
                return constant_bool.toConstant();
            },
            .constant_slice => |constant_slice_index| {
                const constant_slice = try llvm.getConstantSlice(unit, context, constant_slice_index);
                return constant_slice;
            },
            .constant_array => |constant_array_index| {
                const constant_array = try llvm.getConstantArray(unit, context, constant_array_index);
                return constant_array;
            },
            .global => |global| {
                const constant = switch (global.initial_value) {
                    .function_definition => llvm.function_definition_map.get(global).?.toConstant(),
                    .function_declaration => llvm.llvm_external_functions.get(global).?.toConstant(),
                    else => llvm.global_variable_map.get(global).?.toConstant(),
                };
                return constant;
            },
            .null_pointer => {
                const value_type = try llvm.getType(unit, context, type_index);
                const pointer_type = value_type.toPointer() orelse unreachable;
                const constant_null_pointer = pointer_type.getNull();
                return constant_null_pointer.toConstant();
            },
            .error_value => |error_field_index| {
                const error_field = unit.error_fields.get(error_field_index);
                const error_type_index = error_field.type;
                const integer = unit.types.get(error_type_index).integer;
                const bit_count = integer.bit_count;
                const signed = switch (integer.signedness) {
                    .unsigned => false,
                    .signed => true,
                };
                const constant_int = llvm.context.getConstantInt(bit_count, error_field.value, signed) orelse unreachable;
                return constant_int.toConstant();
            },
            else => |t| @panic(@tagName(t)),
        }
    }

    fn emitRightValue(llvm: *LLVM, unit: *Compilation.Unit, context: *const Compilation.Context, v: Compilation.V) !*LLVM.Value {
        switch (v.value) {
            .@"comptime" => |ct| {
                const constant_value = try llvm.emitComptimeRightValue(unit, context, ct, v.type);
                return constant_value.toValue();
            },
            .runtime => |instruction_index| {
                if (llvm.llvm_instruction_map.get(instruction_index)) |instruction| {
                    return instruction;
                } else {
                    unreachable;
                }
            },
            else => |t| @panic(@tagName(t)),
        }
    }

    fn getScope(llvm: *LLVM, unit: *Compilation.Unit, context: *const Compilation.Context, sema_scope: *Compilation.Debug.Scope) anyerror!*LLVM.DebugInfo.Scope {
        switch (sema_scope.kind) {
            .function,
            .block,
            .compilation_unit,
            => {
                return llvm.scope_map.get(sema_scope).?;
            },
            .file => {
                unreachable;
            },
            .file_container => {
                if (llvm.scope_map.get(sema_scope)) |scope| {
                    if (true) unreachable;
                    return scope;
                } else {
                    const global_scope: *Compilation.Debug.Scope.Global = @fieldParentPtr("scope", sema_scope);
                    const struct_type = try llvm.getDebugType(unit, context, global_scope.type);
                    return struct_type.toScope();
                }
            },
            else => |t| @panic(@tagName(t)),
        }
        unreachable;
    }

    fn createBasicBlock(llvm: *LLVM, context: *const Compilation.Context, basic_block_index: Compilation.BasicBlock.Index, name: []const u8) !*BasicBlockList.Node {
        const basic_block = llvm.context.createBasicBlock(name.ptr, name.len, llvm.function, null) orelse return Error.basic_block;
        const basic_block_node = try context.allocator.create(BasicBlockList.Node);
        basic_block_node.* = .{
            .data = basic_block_index,
        };
        try llvm.llvm_block_map.put_no_clobber(context.my_allocator, basic_block_index, basic_block);

        return basic_block_node;
    }

    fn getConstantSlice(llvm: *LLVM, unit: *Compilation.Unit, context: *const Compilation.Context, constant_slice_index: Compilation.V.Comptime.ConstantSlice.Index) !*LLVM.Value.Constant {
        const const_slice = unit.constant_slices.get(constant_slice_index);
        const const_slice_type = try llvm.getType(unit, context, const_slice.type);
        const slice_struct_type = const_slice_type.toStruct() orelse unreachable;
        const slice_fields: [2]*LLVM.Value.Constant = if (const_slice.array) |array| b: {
            const ptr = llvm.global_variable_map.get(array).?;
            const signed = false;
            assert(const_slice.start == 0);
            const len = llvm.context.getConstantInt(@bitSizeOf(usize), const_slice.end, signed) orelse unreachable;
            const slice_fields = [2]*LLVM.Value.Constant{
                ptr.toConstant(),
                len.toConstant(),
            };

            break :b slice_fields;
        } else b: {
            const ptr = llvm.pointer_type.?.toType().getPoison() orelse unreachable;
            const len = llvm.context.getConstantInt(64, 0, false) orelse unreachable;
            break :b .{ ptr.toConstant(), len.toConstant() };
        };

        const constant_slice = slice_struct_type.getConstant(&slice_fields, slice_fields.len) orelse unreachable;
        return constant_slice;
    }

    fn getConstantArray(llvm: *LLVM, unit: *Compilation.Unit, context: *const Compilation.Context, constant_array_index: Compilation.V.Comptime.ConstantArray.Index) !*LLVM.Value.Constant {
        const constant_array = unit.constant_arrays.get(constant_array_index);
        const sema_array_type = unit.types.get(constant_array.type).array;
        const constant_type = try llvm.getType(unit, context, constant_array.type);
        const array_type = constant_type.toArray() orelse unreachable;
        var list = try UnpinnedArray(*LLVM.Value.Constant).initialize_with_capacity(context.my_allocator, @intCast(constant_array.values.len));
        for (constant_array.values) |sema_value| {
            const value = switch (sema_value) {
                .constant_int => |const_int| b: {
                    const integer_type = unit.types.get(sema_array_type.type).integer;
                    const signed = switch (integer_type.signedness) {
                        .signed => true,
                        .unsigned => false,
                    };
                    assert(!signed);
                    const constant_int = llvm.context.getConstantInt(integer_type.bit_count, const_int.value, signed) orelse unreachable;
                    break :b constant_int.toConstant();
                },
                .constant_slice => |constant_slice_index| try llvm.getConstantSlice(unit, context, constant_slice_index),
                .constant_struct => |constant_struct_index| try llvm.getConstantStruct(unit, context, constant_struct_index),
                else => |t| @panic(@tagName(t)),
            };
            list.append_with_capacity(value);
        }

        const result = array_type.getConstant(list.pointer, list.length) orelse unreachable;
        return result;
    }

    fn getConstantStruct(llvm: *LLVM, unit: *Compilation.Unit, context: *const Compilation.Context, constant_struct_index: Compilation.V.Comptime.ConstantStruct.Index) !*LLVM.Value.Constant {
        const constant_struct = unit.constant_structs.get(constant_struct_index);
        var field_values = try UnpinnedArray(*LLVM.Value.Constant).initialize_with_capacity(context.my_allocator, @intCast(constant_struct.fields.len));
        const sema_struct_index = unit.types.get(constant_struct.type).@"struct";
        const sema_struct = unit.structs.get(sema_struct_index);
        switch (sema_struct.kind) {
            .@"struct" => |*sema_struct_type| {
                for (constant_struct.fields, sema_struct_type.fields.slice()) |field_value, field_index| {
                    const field = unit.struct_fields.get(field_index);
                    const constant = try llvm.emitComptimeRightValue(unit, context, field_value, field.type);
                    field_values.append_with_capacity(constant);
                }

                const llvm_type = try llvm.getType(unit, context, constant_struct.type);
                const struct_type = llvm_type.toStruct() orelse unreachable;
                const const_struct = struct_type.getConstant(field_values.pointer, field_values.length) orelse unreachable;
                return const_struct;
            },
            else => |t| @panic(@tagName(t)),
        }
    }

    fn callIntrinsic(llvm: *LLVM, intrinsic_name: []const u8, intrinsic_parameter_types: []const *LLVM.Type, intrinsic_arguments: []const *LLVM.Value) !*LLVM.Value {
        const intrinsic_id = LLVM.lookupIntrinsic(intrinsic_name.ptr, intrinsic_name.len);
        assert(intrinsic_id != .none);

        const intrinsic_function = llvm.module.getIntrinsicDeclaration(intrinsic_id, intrinsic_parameter_types.ptr, intrinsic_parameter_types.len) orelse return LLVM.Value.Error.intrinsic;
        const intrinsic_type = intrinsic_function.getType();
        const void_name: []const u8 = "";
        const name = switch (intrinsic_type.getReturnType().isVoid()) {
            true => void_name,
            false => intrinsic_name,
        };

        const call = llvm.builder.createCall(intrinsic_type, intrinsic_function.toValue(), intrinsic_arguments.ptr, intrinsic_arguments.len, name.ptr, name.len, null) orelse return LLVM.Value.Instruction.Error.call;
        return call.toValue();
    }

    fn emitParameterAttributes(llvm: *LLVM, unit: *Compilation.Unit, context: *const Compilation.Context, abi: Compilation.Function.AbiInfo, is_return: bool) !*const LLVM.Attribute.Set {
        var attributes = UnpinnedArray(*LLVM.Attribute){};
        if (abi.attributes.by_reg) {
            try attributes.append(context.my_allocator, llvm.attributes.inreg);
        }
        switch (abi.kind) {
            .ignore => {
                assert(is_return);
            },
            .direct, .direct_pair, .direct_coerce => {},
            .indirect => |indirect| {
                const indirect_type = try llvm.getType(unit, context, indirect.type);
                if (is_return) {
                    const sret = llvm.context.getAttributeFromType(.StructRet, indirect_type);
                    try attributes.append(context.my_allocator, sret);
                    try attributes.append(context.my_allocator, llvm.attributes.@"noalias");
                    // TODO: alignment
                } else {
                    if (abi.attributes.by_value) {
                        const byval = llvm.context.getAttributeFromType(.ByVal, indirect_type);
                        try attributes.append(context.my_allocator, byval);
                    }
                    //TODO: alignment
                }
            },
            else => |t| @panic(@tagName(t)),
        }
        const attribute_set = llvm.context.getAttributeSet(attributes.pointer, attributes.length);
        return attribute_set;
    }

    fn getFunctionAttributes(llvm: *LLVM, unit: *Compilation.Unit, context: *const Compilation.Context, function_prototype: *Compilation.Function.Prototype) !*const LLVM.Attribute.Set {
        var function_attributes = UnpinnedArray(*LLVM.Attribute){};
        try function_attributes.append(context.my_allocator, llvm.attributes.nounwind);

        switch (unit.types.get(function_prototype.return_type).*) {
            .noreturn => {
                try function_attributes.append(context.my_allocator, llvm.attributes.noreturn);
            },
            else => {},
        }

        if (function_prototype.attributes.naked) {
            try function_attributes.append(context.my_allocator, llvm.attributes.naked);
        }

        const function_attribute_set = llvm.context.getAttributeSet(function_attributes.pointer, function_attributes.length);
        return function_attribute_set;
    }

    const CallOrFunction = union(enum) {
        call: *LLVM.Value.Instruction.Call,
        function: *LLVM.Value.Constant.Function,
    };

    fn setCallOrFunctionAttributes(llvm: *LLVM, unit: *Compilation.Unit, context: *const Compilation.Context, function_prototype: *Compilation.Function.Prototype, call_or_function: CallOrFunction) !void {
        const function_attribute_set = try llvm.getFunctionAttributes(unit, context, function_prototype);

        var parameter_attribute_sets = try UnpinnedArray(*const LLVM.Attribute.Set).initialize_with_capacity(context.my_allocator, @intCast(function_prototype.abi.parameter_types_abi.len + @intFromBool(function_prototype.abi.return_type_abi.kind == .indirect)));
        const return_attribute_set = blk: {
            const attribute_set = try llvm.emitParameterAttributes(unit, context, function_prototype.abi.return_type_abi, true);
            break :blk switch (function_prototype.abi.return_type_abi.kind) {
                .indirect => b: {
                    parameter_attribute_sets.append_with_capacity(attribute_set);
                    break :b llvm.context.getAttributeSet(null, 0);
                },
                else => attribute_set,
            };
        };

        for (function_prototype.abi.parameter_types_abi) |parameter_type_abi| {
            const parameter_attribute_set = try llvm.emitParameterAttributes(unit, context, parameter_type_abi, false);
            parameter_attribute_sets.append_with_capacity(parameter_attribute_set);
        }

        const calling_convention = getCallingConvention(function_prototype.calling_convention);

        switch (call_or_function) {
            .call => |call| {
                call.setAttributes(llvm.context, function_attribute_set, return_attribute_set, parameter_attribute_sets.pointer, parameter_attribute_sets.length);
                call.setCallingConvention(calling_convention);
            },
            .function => |function| {
                function.setAttributes(llvm.context, function_attribute_set, return_attribute_set, parameter_attribute_sets.pointer, parameter_attribute_sets.length);
                function.setCallingConvention(calling_convention);
            },
        }
    }

    fn emitFunctionDeclaration(llvm: *LLVM, unit: *Compilation.Unit, context: *const Compilation.Context, declaration: *Compilation.Debug.Declaration.Global) !void {
        const name = unit.getIdentifier(declaration.declaration.name);
        const function_type = try llvm.getType(unit, context, declaration.declaration.type);
        const is_export = declaration.attributes.contains(.@"export");
        const is_extern = declaration.attributes.contains(.@"extern");
        const export_or_extern = is_export or is_extern;

        const linkage: LLVM.Linkage = switch (export_or_extern) {
            true => .@"extern",
            false => .internal,
        };
        // TODO: Check name collision
        const mangle_name = !export_or_extern;
        _ = mangle_name; // autofix
        const function = llvm.module.createFunction(function_type.toFunction() orelse unreachable, linkage, address_space, name.ptr, name.len) orelse return Error.function;

        const function_prototype = unit.function_prototypes.get(unit.types.get(declaration.declaration.type).function);
        try llvm.setCallOrFunctionAttributes(unit, context, function_prototype, .{
            .function = function,
        });
        // const calling_convention = getCallingConvention(function_prototype.calling_convention);
        // function.setCallingConvention(calling_convention);
        //
        // const function_attribute_set = llvm.getFunctionAttributes(unit, context, function_prototype);
        //
        // var parameter_attribute_sets = try UnpinnedArray(*const LLVM.Attribute.Set).initialize_with_capacity(context.my_allocator, @intCast(function_prototype.abi.parameter_types_abi.len + @intFromBool(function_prototype.abi.return_type_abi.kind == .indirect)));
        // const return_attribute_set = blk: {
        //     const attribute_set = try llvm.emitParameterAttributes(unit, context, function_prototype.abi.return_type_abi, true);
        //     break :blk switch (function_prototype.abi.return_type_abi.kind) {
        //         .indirect => b: {
        //             parameter_attribute_sets.append_with_capacity(attribute_set);
        //             break :b llvm.context.getAttributeSet(null, 0);
        //         },
        //         else => attribute_set,
        //     };
        // };
        //
        // for (function_prototype.abi.parameter_types_abi) |parameter_type_abi| {
        //     const parameter_attribute_set = try llvm.emitParameterAttributes(unit, context, parameter_type_abi, false);
        //     parameter_attribute_sets.append_with_capacity(parameter_attribute_set);
        // }

        // function.setAttributes(llvm.context, function_attribute_set, return_attribute_set, parameter_attribute_sets.pointer, parameter_attribute_sets.length);

        switch (declaration.initial_value) {
            .function_declaration => try llvm.function_declaration_map.put_no_clobber(context.my_allocator, declaration, function),
            .function_definition => try llvm.function_definition_map.put_no_clobber(context.my_allocator, declaration, function),
            else => unreachable,
        }

        if (unit.descriptor.generate_debug_information) {
            // if (data_structures.byte_equal(name, "nat_split_struct_ints")) @breakpoint();
            const debug_file = try llvm.getDebugInfoFile(unit, context, declaration.declaration.scope.file);
            var parameter_types = try UnpinnedArray(*LLVM.DebugInfo.Type).initialize_with_capacity(context.my_allocator, @intCast(function_prototype.argument_types.len));
            for (function_prototype.argument_types) |argument_type_index| {
                const argument_type = try llvm.getDebugType(unit, context, argument_type_index);
                parameter_types.append_with_capacity(argument_type);
            }

            const subroutine_type_flags = LLVM.DebugInfo.Node.Flags{
                .visibility = .none,
                .forward_declaration = is_extern,
                .apple_block = false,
                .block_by_ref_struct = false,
                .virtual = false,
                .artificial = false,
                .explicit = false,
                .prototyped = false,
                .objective_c_class_complete = false,
                .object_pointer = false,
                .vector = false,
                .static_member = false,
                .lvalue_reference = false,
                .rvalue_reference = false,
                .reserved = false,
                .inheritance = .none,
                .introduced_virtual = false,
                .bit_field = false,
                .no_return = false,
                .type_pass_by_value = false,
                .type_pass_by_reference = false,
                .enum_class = false,
                .thunk = false,
                .non_trivial = false,
                .big_endian = false,
                .little_endian = false,
                .all_calls_described = false,
            };
            const subroutine_type_calling_convention = LLVM.DebugInfo.CallingConvention.none;
            const subroutine_type = llvm.debug_info_builder.createSubroutineType(parameter_types.pointer, parameter_types.length, subroutine_type_flags, subroutine_type_calling_convention) orelse unreachable;
            const subprogram_flags = LLVM.DebugInfo.Subprogram.Flags{
                .virtuality = .none,
                .local_to_unit = !export_or_extern,
                .definition = !is_extern,
                .optimized = false,
                .pure = false,
                .elemental = false,
                .recursive = false,
                .main_subprogram = false,
                .deleted = false,
                .object_c_direct = false,
            };
            const subprogram_declaration = null;
            const function_name = unit.getIdentifier(declaration.declaration.name);
            const subprogram = llvm.debug_info_builder.createFunction(debug_file.toScope(), function_name.ptr, function_name.len, function_name.ptr, function_name.len, debug_file, declaration.declaration.line + 1, subroutine_type, declaration.declaration.line + 1, subroutine_type_flags, subprogram_flags, subprogram_declaration) orelse unreachable;
            function.setSubprogram(subprogram);

            switch (declaration.initial_value) {
                .function_declaration => {
                    try llvm.llvm_external_functions.put_no_clobber(context.my_allocator, declaration, function);
                },
                .function_definition => |function_definition_index| {
                    const function_definition = unit.function_definitions.get(function_definition_index);
                    const scope = subprogram.toLocalScope().toScope();

                    try llvm.scope_map.put_no_clobber(context.my_allocator, &function_definition.scope.scope, scope);
                },
                else => |t| @panic(@tagName(t)),
            }
        }
    }
};

fn getCallingConvention(calling_convention: Compilation.Function.CallingConvention) LLVM.Value.Constant.Function.CallingConvention {
    return switch (calling_convention) {
        .auto => .Fast,
        .c => .C,
    };
}

const BasicBlockList = std.DoublyLinkedList(Compilation.BasicBlock.Index);

const Error = error{
    context,
    module,
    builder,
    function,
    basic_block,
    debug_info_builder,
};

const address_space = 0;

pub const Format = enum(c_uint) {
    elf = 0,
    macho = 1,
    coff = 2,
};

pub fn codegen(unit: *Compilation.Unit, context: *const Compilation.Context) !void {
    const llvm_context = LLVM.Context.create() orelse return Error.context;
    const module = LLVM.Module.create(@ptrCast(unit.descriptor.name.ptr), unit.descriptor.name.len, llvm_context) orelse return Error.module;
    // TODO:
    const builder = LLVM.Builder.create(llvm_context) orelse return Error.builder;

    var llvm = LLVM{
        .context = llvm_context,
        .module = module,
        .builder = builder,
        .debug_info_builder = module.createDebugInfoBuilder() orelse return Error.debug_info_builder,
        .attributes = .{
            .naked = llvm_context.getAttributeFromEnum(.Naked, 0),
            .noreturn = llvm_context.getAttributeFromEnum(.NoReturn, 0),
            .nounwind = llvm_context.getAttributeFromEnum(.NoUnwind, 0),
            .inreg = llvm_context.getAttributeFromEnum(.InReg, 0),
            .@"noalias" = llvm_context.getAttributeFromEnum(.NoAlias, 0),
        },
    };

    if (unit.descriptor.generate_debug_information) {
        const full_path = try std.fs.cwd().realpathAlloc(context.allocator, unit.descriptor.main_package_path);
        const filename = std.fs.path.basename(full_path);
        const directory = full_path[0 .. full_path.len - filename.len];
        const debug_info_file = llvm.debug_info_builder.createFile(filename.ptr, filename.len, directory.ptr, directory.len) orelse unreachable;
        const producer = "nativity";
        const is_optimized = false;
        const flags = "";
        const runtime_version = 0;
        const splitname = "";
        const DWOId = 0;
        const debug_info_kind = LLVM.DebugInfo.CompileUnit.EmissionKind.full_debug;
        const split_debug_inlining = true;
        const debug_info_for_profiling = false;
        const name_table_kind = LLVM.DebugInfo.CompileUnit.NameTableKind.default;
        const ranges_base_address = false;
        const sysroot = "";
        const sdk = "";
        const compile_unit = llvm.debug_info_builder.createCompileUnit(LLVM.DebugInfo.Language.c, debug_info_file, producer, producer.len, is_optimized, flags, flags.len, runtime_version, splitname, splitname.len, debug_info_kind, DWOId, split_debug_inlining, debug_info_for_profiling, name_table_kind, ranges_base_address, sysroot, sysroot.len, sdk, sdk.len) orelse unreachable;
        llvm.scope = compile_unit.toScope();

        try llvm.scope_map.put_no_clobber(context.my_allocator, &unit.scope.scope, llvm.scope);
    }

    for (unit.external_functions.values()) |external_function_declaration| {
        try llvm.emitFunctionDeclaration(unit, context, external_function_declaration);
    }

    const functions = unit.code_to_emit.values();

    {
        var function_i: usize = functions.len;
        // Emit it in reverse order so the code goes the right order, from entry point to leaves
        while (function_i > 0) {
            function_i -= 1;
            const function_declaration = functions[function_i];
            try llvm.emitFunctionDeclaration(unit, context, function_declaration);
        }
    }

    // First, cache all the global variables
    for (unit.data_to_emit.slice()) |global_declaration| {
        const name = unit.getIdentifier(global_declaration.declaration.name);

        switch (global_declaration.initial_value) {
            .string_literal => |hash| {
                const string_literal = unit.string_literal_values.get(hash).?;
                const global_variable = llvm.builder.createGlobalString(string_literal.ptr, string_literal.len, name.ptr, name.len, address_space, llvm.module) orelse unreachable;
                try llvm.global_variable_map.put_no_clobber(context.my_allocator, global_declaration, global_variable);
            },
            else => {
                const global_type = try llvm.getType(unit, context, global_declaration.declaration.type);
                const linkage: LLVM.Linkage = switch (global_declaration.attributes.contains(.@"export")) {
                    true => .@"extern",
                    false => .internal,
                };
                const constant = switch (global_declaration.declaration.mutability) {
                    .@"var" => false,
                    .@"const" => true,
                };
                const initializer: ?*LLVM.Value.Constant = null;
                const thread_local_mode = LLVM.ThreadLocalMode.not_thread_local;
                const externally_initialized = false;
                const global_variable = llvm.module.addGlobalVariable(global_type, constant, linkage, initializer, name.ptr, name.len, null, thread_local_mode, address_space, externally_initialized) orelse return LLVM.Value.Error.constant_int;
                try llvm.global_variable_map.put_no_clobber(context.my_allocator, global_declaration, global_variable);
            },
        }

        if (unit.descriptor.generate_debug_information) {
            // Don't emit debug information for strings
            if (@intFromEnum(global_declaration.declaration.scope.kind) < @intFromEnum(Compilation.Debug.Scope.Kind.function)) {
                const scope = try llvm.getScope(unit, context, global_declaration.declaration.scope);
                const file = try llvm.getDebugInfoFile(unit, context, global_declaration.declaration.scope.file);
                const debug_type = try llvm.getDebugType(unit, context, global_declaration.declaration.type);
                const is_local_to_unit = !global_declaration.attributes.contains(.@"export");
                const is_defined = true;
                const expression = null;
                const declaration = null;
                const template_parameters = null;
                const alignment = 0;
                const debug_global_variable = llvm.debug_info_builder.createGlobalVariableExpression(scope, name.ptr, name.len, name.ptr, name.len, file, global_declaration.declaration.line, debug_type, is_local_to_unit, is_defined, expression, declaration, template_parameters, alignment) orelse unreachable;
                _ = debug_global_variable; // autofix
            }
        }
    }

    for (llvm.global_variable_map.keys(), llvm.global_variable_map.values()) |global_declaration, global_variable| {
        if (global_declaration.initial_value == .string_literal) continue;
        const constant_initializer = try llvm.emitComptimeRightValue(unit, context, global_declaration.initial_value, global_declaration.declaration.type);
        global_variable.setInitializer(constant_initializer);
    }

    for (llvm.function_definition_map.keys(), llvm.function_definition_map.values()) |function_declaration, function| {
        const function_definition_index = function_declaration.getFunctionDefinitionIndex();
        const function_definition = unit.function_definitions.get(function_definition_index);
        llvm.function = function;
        llvm.sema_function = function_declaration;
        llvm.inside_branch = false;

        if (unit.descriptor.generate_debug_information) {
            const subprogram = llvm.function.getSubprogram() orelse unreachable;
            llvm.file = subprogram.getFile() orelse unreachable;
            llvm.scope = subprogram.toLocalScope().toScope();
        }

        var alloca_map = MyHashMap(Compilation.Instruction.Index, *LLVM.Value){};

        var block_command_list = BasicBlockList{};

        const entry_block_node = try llvm.createBasicBlock(context, function_definition.basic_blocks.pointer[0], "fn_entry");
        block_command_list.append(entry_block_node);

        var phis = MyHashMap(Compilation.Instruction.Index, *LLVM.Value.Instruction.PhiNode){};

        while (block_command_list.len != 0) {
            const block_node = block_command_list.first orelse unreachable;
            const basic_block_index = block_node.data;
            const sema_basic_block = unit.basic_blocks.get(basic_block_index);
            const basic_block = llvm.llvm_block_map.get(basic_block_index).?;
            llvm.builder.setInsertPoint(basic_block);

            var last_block = block_node;

            for (sema_basic_block.instructions.slice()) |instruction_index| {
                //if (@intFromEnum(instruction_index) == 474) @breakpoint();
                const sema_instruction = unit.instructions.get(instruction_index);

                switch (sema_instruction.*) {
                    .push_scope => |push_scope| {
                        const old_scope = try llvm.getScope(unit, context, push_scope.old);
                        assert(@intFromEnum(push_scope.old.kind) >= @intFromEnum(Compilation.Debug.Scope.Kind.function));

                        const lexical_block = llvm.debug_info_builder.createLexicalBlock(old_scope, llvm.file, push_scope.new.line + 1, push_scope.new.column + 1) orelse unreachable;
                        try llvm.scope_map.put_no_clobber(context.my_allocator, push_scope.new, lexical_block.toScope());
                        llvm.scope = lexical_block.toScope();
                    },
                    .pop_scope => |pop_scope| {
                        const new = try llvm.getScope(unit, context, pop_scope.new);
                        if (pop_scope.new.kind == .function) {
                            assert(new.toSubprogram() orelse unreachable == llvm.function.getSubprogram() orelse unreachable);
                        }
                        llvm.scope = new;
                        var scope = pop_scope.old;
                        while (scope.kind != .function) {
                            scope = scope.parent.?;
                        }
                        const subprogram_scope = try llvm.getScope(unit, context, scope);
                        assert(llvm.function.getSubprogram() orelse unreachable == subprogram_scope.toSubprogram() orelse unreachable);
                    },
                    .debug_checkpoint => |debug_checkpoint| {
                        const scope = try llvm.getScope(unit, context, debug_checkpoint.scope);
                        // assert(scope == llvm.scope);
                        llvm.builder.setCurrentDebugLocation(llvm.context, debug_checkpoint.line + 1, debug_checkpoint.column + 1, scope, llvm.function);
                    },
                    .inline_assembly => |inline_assembly_index| {
                        const assembly_block = unit.inline_assembly.get(inline_assembly_index);

                        var assembly_statements = UnpinnedArray(u8){};
                        var constraints = UnpinnedArray(u8){};
                        var operand_values = UnpinnedArray(*LLVM.Value){};
                        var operand_types = UnpinnedArray(*LLVM.Type){};

                        switch (unit.descriptor.arch) {
                            .x86_64 => {
                                for (assembly_block.instructions) |assembly_instruction_index| {
                                    const instruction = unit.assembly_instructions.get(assembly_instruction_index);
                                    const instruction_id: Compilation.InlineAssembly.x86_64.Instruction = @enumFromInt(instruction.id);

                                    try assembly_statements.append_slice(context.my_allocator, switch (instruction_id) {
                                        .xor => "xorl",
                                        .mov => "movq",
                                        .@"and" => "andq",
                                        .call => "callq",
                                    });
                                    try assembly_statements.append(context.my_allocator, ' ');

                                    if (instruction.operands.len > 0) {
                                        var reverse_operand_iterator = std.mem.reverseIterator(instruction.operands);

                                        while (reverse_operand_iterator.next()) |operand| {
                                            switch (operand) {
                                                .register => |register_value| {
                                                    const register: Compilation.InlineAssembly.x86_64.Register = @enumFromInt(register_value);
                                                    try assembly_statements.append(context.my_allocator, '%');
                                                    try assembly_statements.append_slice(context.my_allocator, @tagName(register));
                                                },
                                                .number_literal => |literal| {
                                                    var buffer: [65]u8 = undefined;
                                                    const number_literal = data_structures.format_int(&buffer, literal, 16, false);
                                                    const slice_ptr = number_literal.ptr - 4;
                                                    const literal_slice = slice_ptr[0 .. number_literal.len + 4];
                                                    literal_slice[0] = '$';
                                                    literal_slice[1] = '$';
                                                    literal_slice[2] = '0';
                                                    literal_slice[3] = 'x';
                                                    try assembly_statements.append_slice(context.my_allocator, try context.my_allocator.duplicate_bytes(literal_slice));
                                                },
                                                .value => |sema_value| {
                                                    if (llvm.llvm_value_map.get(sema_value)) |v| {
                                                        _ = v; // autofix
                                                        unreachable;
                                                    } else {
                                                        const value = try llvm.emitLeftValue(unit, context, sema_value);
                                                        var buffer: [65]u8 = undefined;
                                                        const operand_number = data_structures.format_int(&buffer, operand_values.length, 16, false);
                                                        const slice_ptr = operand_number.ptr - 2;
                                                        const operand_slice = slice_ptr[0 .. operand_number.len + 2];
                                                        operand_slice[0] = '$';
                                                        operand_slice[1] = '{';
                                                        var new_buffer: [65]u8 = undefined;
                                                        @memcpy(new_buffer[0..operand_slice.len], operand_slice);
                                                        new_buffer[operand_slice.len] = ':';
                                                        new_buffer[operand_slice.len + 1] = 'P';
                                                        new_buffer[operand_slice.len + 2] = '}';
                                                        const new_slice = try context.my_allocator.duplicate_bytes(new_buffer[0 .. operand_slice.len + 3]);
                                                        try assembly_statements.append_slice(context.my_allocator, new_slice);
                                                        try operand_values.append(context.my_allocator, value);
                                                        const value_type = value.getType();
                                                        try operand_types.append(context.my_allocator, value_type);
                                                        try constraints.append(context.my_allocator, 'X');
                                                    }
                                                },
                                            }

                                            try assembly_statements.append_slice(context.my_allocator, ", ");
                                        }

                                        _ = assembly_statements.pop();
                                        _ = assembly_statements.pop();
                                    }

                                    try assembly_statements.append_slice(context.my_allocator, "\n\t");
                                }

                                // try constraints.append_slice(context.allocator, ",~{dirflag},~{fpsr},~{flags}");
                            },
                            else => |t| @panic(@tagName(t)),
                        }

                        const is_var_args = false;
                        const function_type = LLVM.Context.getFunctionType(try llvm.getType(unit, context, Compilation.Type.Index.void), operand_types.pointer, operand_types.length, is_var_args) orelse unreachable;
                        const has_side_effects = true;
                        const is_align_stack = true;
                        const dialect = LLVM.Value.InlineAssembly.Dialect.@"at&t";
                        const can_throw = false;

                        const inline_assembly = LLVM.Value.InlineAssembly.get(function_type, assembly_statements.pointer, assembly_statements.length, constraints.pointer, constraints.length, has_side_effects, is_align_stack, dialect, can_throw) orelse return LLVM.Value.Error.inline_assembly;
                        const call = llvm.builder.createCall(function_type, inline_assembly.toValue(), operand_values.pointer, operand_values.length, "", "".len, null) orelse return LLVM.Value.Instruction.Error.call;
                        try llvm.llvm_instruction_map.put_no_clobber(context.my_allocator, instruction_index, call.toValue());
                    },
                    .stack_slot => |stack_slot| {
                        // const stack_slot_type = unit.types.get(stack_slot.type);
                        // const stack_slot_alignment = stack_slot_type.getAbiAlignment(unit);
                        const declaration_type = try llvm.getType(unit, context, stack_slot.type);
                        const type_alignment = unit.types.get(stack_slot.type).getAbiAlignment(unit);
                        const alloca_array_size = null;
                        const declaration_alloca = llvm.builder.createAlloca(declaration_type, address_space, alloca_array_size, "", "".len, type_alignment) orelse return LLVM.Value.Instruction.Error.alloca;
                        try alloca_map.put_no_clobber(context.my_allocator, instruction_index, declaration_alloca.toValue());
                        try llvm.llvm_instruction_map.put_no_clobber(context.my_allocator, instruction_index, declaration_alloca.toValue());
                    },
                    .store => |store| {
                        const right = try llvm.emitRightValue(unit, context, store.source);
                        const source_type = unit.types.get(store.source.type);
                        const alignment = source_type.getAbiAlignment(unit);

                        const is_volatile = false;
                        const left = try llvm.emitLeftValue(unit, context, store.destination);
                        const store_instruction = llvm.builder.createStore(right, left, is_volatile, alignment) orelse return LLVM.Value.Instruction.Error.store;
                        _ = store_instruction; // autofix
                    },
                    .cast => |cast| {
                        const value = try llvm.emitRightValue(unit, context, cast.value);
                        const dest_type = try llvm.getType(unit, context, cast.type);
                        switch (cast.id) {
                            .int_to_pointer => {
                                const cast_type = LLVM.Value.Instruction.Cast.Type.int_to_pointer;
                                const cast_name = @tagName(cast_type);
                                const cast_instruction = llvm.builder.createCast(cast_type, value, value.getType(), cast_name.ptr, cast_name.len) orelse return LLVM.Value.Instruction.Error.cast;
                                try llvm.llvm_instruction_map.put_no_clobber(context.my_allocator, instruction_index, cast_instruction);
                            },
                            // TODO: Poke metadata
                            .pointer_var_to_const,
                            .slice_var_to_const,
                            .enum_to_int,
                            .slice_to_nullable,
                            .slice_to_not_null,
                            .slice_coerce_to_zero_termination,
                            .slice_zero_to_no_termination,
                            .pointer_to_nullable,
                            .pointer_const_to_var,
                            .pointer_to_array_to_pointer_to_many,
                            => {
                                try llvm.llvm_instruction_map.put_no_clobber(context.my_allocator, instruction_index, value);
                            },
                            .sign_extend => {
                                const sign_extend = llvm.builder.createCast(.sign_extend, value, dest_type, "sign_extend", "sign_extend".len) orelse return LLVM.Value.Instruction.Error.cast;
                                try llvm.llvm_instruction_map.put_no_clobber(context.my_allocator, instruction_index, sign_extend);
                            },
                            .zero_extend => {
                                const zero_extend = llvm.builder.createCast(.zero_extend, value, dest_type, "zero_extend", "zero_extend".len) orelse return LLVM.Value.Instruction.Error.cast;
                                try llvm.llvm_instruction_map.put_no_clobber(context.my_allocator, instruction_index, zero_extend);
                            },
                            .bitcast => {
                                const bitcast = llvm.builder.createCast(.bitcast, value, dest_type, "bitcast", "bitcast".len) orelse return LLVM.Value.Instruction.Error.cast;
                                try llvm.llvm_instruction_map.put_no_clobber(context.my_allocator, instruction_index, bitcast);
                            },
                            .pointer_to_int => {
                                const pointer_to_int = llvm.builder.createCast(.pointer_to_int, value, dest_type, "pointer_to_int", "pointer_to_int".len) orelse return LLVM.Value.Instruction.Error.cast;
                                try llvm.llvm_instruction_map.put_no_clobber(context.my_allocator, instruction_index, pointer_to_int);
                            },
                            .truncate => {
                                const truncate = llvm.builder.createCast(.truncate, value, dest_type, "truncate", "truncate".len) orelse return LLVM.Value.Instruction.Error.cast;
                                try llvm.llvm_instruction_map.put_no_clobber(context.my_allocator, instruction_index, truncate);
                            },
                            .error_union_type_int_to_pointer, .error_union_type_upcast, .error_union_type_downcast => unreachable,
                        }
                    },
                    .load => |load| {
                        const value = if (llvm.llvm_value_map.get(load.value)) |v| v else blk: {
                            const value = switch (load.value.value) {
                                .runtime => |instr_index| llvm.llvm_instruction_map.get(instr_index) orelse switch (unit.instructions.get(instr_index).*) {
                                    else => |t| @panic(@tagName(t)),
                                },
                                .@"comptime" => |ct| switch (ct) {
                                    .global => |global| llvm.global_variable_map.get(global).?.toValue(),
                                    else => |t| @panic(@tagName(t)),
                                },
                                else => |t| @panic(@tagName(t)),
                            };
                            try llvm.llvm_value_map.put_no_clobber(context.my_allocator, load.value, value);

                            break :blk value;
                        };

                        const load_type = unit.types.get(load.type);
                        const alignment = if (load.alignment) |alignment| alignment else load_type.getAbiAlignment(unit);
                        const value_type = try llvm.getType(unit, context, load.type);
                        const is_volatile = false;
                        const load_i = llvm.builder.createLoad(value_type, value, is_volatile, "", "".len, alignment) orelse return LLVM.Value.Instruction.Error.load;
                        try llvm.llvm_instruction_map.put_no_clobber(context.my_allocator, instruction_index, load_i.toValue());
                    },
                    .integer_binary_operation => |binary_operation| {
                        assert(binary_operation.left.type == binary_operation.right.type);
                        const left = try llvm.emitRightValue(unit, context, binary_operation.left);
                        const right = try llvm.emitRightValue(unit, context, binary_operation.right);
                        assert(left.getType() == right.getType());
                        const no_signed_wrapping = binary_operation.signedness == .signed;
                        const no_unsigned_wrapping = binary_operation.signedness == .unsigned;
                        const name = @tagName(binary_operation.id);
                        const is_exact = false;
                        const instruction = switch (binary_operation.id) {
                            .add => llvm.builder.createAdd(left, right, name.ptr, name.len, no_unsigned_wrapping, no_signed_wrapping) orelse return LLVM.Value.Instruction.Error.add,
                            .mul => llvm.builder.createMultiply(left, right, name.ptr, name.len, no_unsigned_wrapping, no_signed_wrapping) orelse return LLVM.Value.Instruction.Error.multiply,
                            .sub => llvm.builder.createSub(left, right, name.ptr, name.len, no_unsigned_wrapping, no_signed_wrapping) orelse return LLVM.Value.Instruction.Error.add,
                            .div => switch (binary_operation.signedness) {
                                .unsigned => llvm.builder.createUDiv(left, right, name.ptr, name.len, is_exact) orelse unreachable,
                                .signed => llvm.builder.createSDiv(left, right, name.ptr, name.len, is_exact) orelse unreachable,
                            },
                            .mod => switch (binary_operation.signedness) {
                                .unsigned => llvm.builder.createURem(left, right, name.ptr, name.len) orelse unreachable,
                                .signed => llvm.builder.createSRem(left, right, name.ptr, name.len) orelse unreachable,
                            },
                            .bit_and => llvm.builder.createAnd(left, right, name.ptr, name.len) orelse unreachable,
                            .bit_or => llvm.builder.createOr(left, right, name.ptr, name.len) orelse unreachable,
                            .bit_xor => llvm.builder.createXor(left, right, name.ptr, name.len) orelse unreachable,
                            .shift_left => llvm.builder.createShiftLeft(left, right, name.ptr, name.len, no_unsigned_wrapping, no_signed_wrapping) orelse unreachable,
                            .shift_right => switch (binary_operation.signedness) {
                                .unsigned => llvm.builder.createLogicalShiftRight(left, right, name.ptr, name.len, is_exact) orelse unreachable,
                                .signed => llvm.builder.createArithmeticShiftRight(left, right, name.ptr, name.len, is_exact) orelse unreachable,
                            },
                            //else => |t| @panic(@tagName(t)),
                        };
                        try llvm.llvm_instruction_map.put_no_clobber(context.my_allocator, instruction_index, instruction);
                    },
                    .call => |sema_call| {
                        var argument_buffer: [32]*LLVM.Value = undefined;
                        const argument_count = sema_call.arguments.len;
                        const arguments = argument_buffer[0..argument_count];

                        const call_function_type = unit.types.get(sema_call.function_type);
                        const function_prototype = unit.function_prototypes.get(call_function_type.function);
                        const call_type = try llvm.getType(unit, context, sema_call.function_type);

                        const call = switch (sema_call.callable.value) {
                            .@"comptime" => |ct| switch (ct) {
                                .global => |call_function_declaration| b: {
                                    const callee = switch (call_function_declaration.initial_value) {
                                        .function_definition => llvm.function_definition_map.get(call_function_declaration).?,
                                        .function_declaration => llvm.function_declaration_map.get(call_function_declaration).?,
                                        else => |t| @panic(@tagName(t)),
                                    };

                                    for (sema_call.arguments, arguments) |argument_value, *argument| {
                                        argument.* = try llvm.emitRightValue(unit, context, argument_value);
                                    }
                                    const name = "";
                                    const function_name = unit.getIdentifier(call_function_declaration.declaration.name);
                                    _ = function_name; // autofix
                                    const function_type = call_type.toFunction() orelse unreachable;
                                    for (sema_call.arguments, arguments, function_prototype.abi.parameter_types, 0..) |sema_argument, argument, sema_argument_type, i| {
                                        assert(sema_argument.type == sema_argument_type);
                                        const argument_type = function_type.getArgumentType(@intCast(i));
                                        argument_type.assertEqual(argument.getType());
                                    }
                                    const call_instruction = llvm.builder.createCall(function_type, callee.toValue(), arguments.ptr, arguments.len, name.ptr, name.len, null) orelse return LLVM.Value.Instruction.Error.call;
                                    break :b call_instruction;
                                },
                                else => |t| @panic(@tagName(t)),
                            },
                            .runtime => |ii| b: {
                                const callee = llvm.llvm_instruction_map.get(ii).?;
                                for (sema_call.arguments, arguments) |argument_value, *argument| {
                                    argument.* = try llvm.emitRightValue(unit, context, argument_value);
                                }

                                const name = "";
                                const function_type = call_type.toFunction() orelse unreachable;
                                const call_instruction = llvm.builder.createCall(function_type, callee, arguments.ptr, arguments.len, name.ptr, name.len, null) orelse return LLVM.Value.Instruction.Error.call;
                                break :b call_instruction;
                            },
                            else => |t| @panic(@tagName(t)),
                        };

                        try llvm.llvm_instruction_map.put_no_clobber(context.my_allocator, instruction_index, call.toValue());

                        try llvm.setCallOrFunctionAttributes(unit, context, function_prototype, .{
                            .call = call,
                        });
                    },
                    .ret => |return_value| {
                        const value = switch (return_value.type) {
                            .void => null,
                            else => try llvm.emitRightValue(unit, context, return_value),
                        };
                        const ret = llvm.builder.createRet(value) orelse return LLVM.Value.Instruction.Error.ret;
                        _ = ret; // autofix
                    },
                    .syscall => |syscall| {
                        var syscall_argument_buffer: [7]*LLVM.Value = undefined;
                        var syscall_argument_type_buffer: [7]*LLVM.Type = undefined;
                        const sema_syscall_arguments = syscall.arguments;
                        const syscall_argument_count: usize = sema_syscall_arguments.len;
                        const syscall_arguments = syscall_argument_buffer[0..syscall_argument_count];
                        const syscall_argument_types = syscall_argument_type_buffer[0..syscall_argument_count];

                        for (sema_syscall_arguments, syscall_arguments, syscall_argument_types) |sema_syscall_argument_value_index, *syscall_argument, *syscall_argument_type| {
                            syscall_argument.* = try llvm.emitRightValue(unit, context, sema_syscall_argument_value_index);
                            syscall_argument_type.* = syscall_argument.*.getType();
                        }

                        const return_type = try llvm.getType(unit, context, Compilation.Type.Index.usize);
                        const is_var_args = false;
                        const function_type = LLVM.Context.getFunctionType(return_type, syscall_argument_types.ptr, syscall_argument_types.len, is_var_args) orelse unreachable;
                        var constraints = UnpinnedArray(u8){};

                        const inline_asm = switch (unit.descriptor.arch) {
                            .x86_64 => blk: {
                                try constraints.append_slice(context.my_allocator, "={rax}");

                                const syscall_registers = [7][]const u8{ "rax", "rdi", "rsi", "rdx", "r10", "r8", "r9" };
                                for (syscall_registers[0..syscall_argument_count]) |syscall_register| {
                                    try constraints.append(context.my_allocator, ',');
                                    try constraints.append(context.my_allocator, '{');
                                    try constraints.append_slice(context.my_allocator, syscall_register);
                                    try constraints.append(context.my_allocator, '}');
                                }

                                try constraints.append_slice(context.my_allocator, ",~{rcx},~{r11},~{memory}");

                                const assembly = "syscall";
                                const has_side_effects = true;
                                const is_align_stack = true;
                                const can_throw = false;
                                const inline_assembly = LLVM.Value.InlineAssembly.get(function_type, assembly, assembly.len, constraints.pointer, constraints.length, has_side_effects, is_align_stack, LLVM.Value.InlineAssembly.Dialect.@"at&t", can_throw) orelse return LLVM.Value.Error.inline_assembly;
                                break :blk inline_assembly;
                            },
                            else => |t| @panic(@tagName(t)),
                        };

                        const call_to_asm = llvm.builder.createCall(function_type, inline_asm.toValue(), syscall_arguments.ptr, syscall_arguments.len, "syscall", "syscall".len, null) orelse return LLVM.Value.Instruction.Error.call;
                        try llvm.llvm_instruction_map.put_no_clobber(context.my_allocator, instruction_index, call_to_asm.toValue());
                    },
                    .@"unreachable" => {
                        _ = llvm.builder.createUnreachable() orelse return LLVM.Value.Instruction.Error.@"unreachable";
                    },
                    .abi_argument => |argument_index| {
                        const argument = llvm.function.getArgument(argument_index) orelse unreachable;
                        try llvm.llvm_instruction_map.put_no_clobber(context.my_allocator, instruction_index, argument.toValue());
                    },
                    .debug_declare_argument => |debug_declare| {
                        if (unit.descriptor.generate_debug_information) {
                            const argument_index: c_uint = debug_declare.argument.index;
                            const declaration = &debug_declare.argument.declaration;
                            const debug_declaration_type = try llvm.getDebugType(unit, context, declaration.type);
                            const declaration_alloca = llvm.llvm_instruction_map.get(debug_declare.stack).?;
                            const always_preserve = true;
                            const flags = LLVM.DebugInfo.Node.Flags{
                                .visibility = .none,
                                .forward_declaration = false,
                                .apple_block = false,
                                .block_by_ref_struct = false,
                                .virtual = false,
                                .artificial = false,
                                .explicit = false,
                                .prototyped = false,
                                .objective_c_class_complete = false,
                                .object_pointer = false,
                                .vector = false,
                                .static_member = false,
                                .lvalue_reference = false,
                                .rvalue_reference = false,
                                .reserved = false,
                                .inheritance = .none,
                                .introduced_virtual = false,
                                .bit_field = false,
                                .no_return = false,
                                .type_pass_by_value = false,
                                .type_pass_by_reference = false,
                                .enum_class = false,
                                .thunk = false,
                                .non_trivial = false,
                                .big_endian = false,
                                .little_endian = false,
                                .all_calls_described = false,
                            };
                            const declaration_name = unit.getIdentifier(declaration.name);
                            const line = declaration.line;
                            const column = declaration.column;
                            const debug_parameter_variable = llvm.debug_info_builder.createParameterVariable(llvm.scope, declaration_name.ptr, declaration_name.len, argument_index + 1, llvm.file, line, debug_declaration_type, always_preserve, flags) orelse unreachable;

                            const insert_declare = llvm.debug_info_builder.insertDeclare(declaration_alloca, debug_parameter_variable, llvm.context, line, column, (llvm.function.getSubprogram() orelse unreachable).toLocalScope().toScope(), llvm.builder.getInsertBlock() orelse unreachable);
                            _ = insert_declare;
                        }
                    },
                    .debug_declare_local_variable => |declare_local_variable| {
                        if (unit.descriptor.generate_debug_information) {
                            const local_variable = declare_local_variable.variable;
                            const debug_declaration_type = try llvm.getDebugType(unit, context, local_variable.declaration.type);
                            const always_preserve = true;
                            const flags = LLVM.DebugInfo.Node.Flags{
                                .visibility = .none,
                                .forward_declaration = false,
                                .apple_block = false,
                                .block_by_ref_struct = false,
                                .virtual = false,
                                .artificial = false,
                                .explicit = false,
                                .prototyped = false,
                                .objective_c_class_complete = false,
                                .object_pointer = false,
                                .vector = false,
                                .static_member = false,
                                .lvalue_reference = false,
                                .rvalue_reference = false,
                                .reserved = false,
                                .inheritance = .none,
                                .introduced_virtual = false,
                                .bit_field = false,
                                .no_return = false,
                                .type_pass_by_value = false,
                                .type_pass_by_reference = false,
                                .enum_class = false,
                                .thunk = false,
                                .non_trivial = false,
                                .big_endian = false,
                                .little_endian = false,
                                .all_calls_described = false,
                            };

                            const alignment = 0;
                            const declaration_name = unit.getIdentifier(local_variable.declaration.name);
                            const line = local_variable.declaration.line;
                            const column = local_variable.declaration.column;
                            const debug_local_variable = llvm.debug_info_builder.createAutoVariable(llvm.scope, declaration_name.ptr, declaration_name.len, llvm.file, line, debug_declaration_type, always_preserve, flags, alignment) orelse unreachable;

                            const local = alloca_map.get(declare_local_variable.stack).?;

                            const insert_declare = llvm.debug_info_builder.insertDeclare(local, debug_local_variable, llvm.context, line, column, (llvm.function.getSubprogram() orelse unreachable).toLocalScope().toScope(), llvm.builder.getInsertBlock() orelse unreachable);
                            _ = insert_declare;
                        }
                    },
                    .insert_value => |insert_value| {
                        const aggregate = try llvm.emitRightValue(unit, context, insert_value.expression);
                        const value = try llvm.emitRightValue(unit, context, insert_value.new_value);
                        const indices = [1]c_uint{insert_value.index};
                        const instruction = llvm.builder.createInsertValue(aggregate, value, &indices, indices.len, "", "".len) orelse unreachable;
                        try llvm.llvm_instruction_map.put_no_clobber(context.my_allocator, instruction_index, instruction);
                    },
                    .extract_value => |extract_value| {
                        switch (unit.types.get(extract_value.expression.type).*) {
                            .pointer => unreachable,
                            else => {},
                        }
                        const aggregate = try llvm.emitRightValue(unit, context, extract_value.expression);
                        const aggregate_type = try llvm.getType(unit, context, extract_value.expression.type);
                        assert(aggregate_type == aggregate.getType());
                        assert(!aggregate.getType().isPointer());
                        const indices = [1]c_uint{extract_value.index};
                        const instruction = llvm.builder.createExtractValue(aggregate, &indices, indices.len, "", "".len) orelse unreachable;
                        try llvm.llvm_instruction_map.put_no_clobber(context.my_allocator, instruction_index, instruction);
                    },
                    .integer_compare => |integer_compare| {
                        assert(integer_compare.left.type == integer_compare.right.type);
                        const left = try llvm.emitRightValue(unit, context, integer_compare.left);
                        const right = try llvm.emitRightValue(unit, context, integer_compare.right);
                        assert(left.getType() == right.getType());
                        const comparison_id: LLVM.Value.Instruction.ICmp.Kind = switch (integer_compare.id) {
                            .equal => .eq,
                            .not_equal => .ne,
                            .unsigned_less => .ult,
                            .unsigned_less_equal => .ule,
                            .unsigned_greater => .ugt,
                            .unsigned_greater_equal => .uge,
                            .signed_less => .slt,
                            .signed_less_equal => .sle,
                            .signed_greater => .sgt,
                            .signed_greater_equal => .sge,
                        };
                        const icmp = llvm.builder.createICmp(comparison_id, left, right, "", "".len) orelse unreachable;
                        try llvm.llvm_instruction_map.put_no_clobber(context.my_allocator, instruction_index, icmp);
                    },
                    .jump => |jump| {
                        const target_block = if (llvm.llvm_block_map.get(jump.to)) |target_block| target_block else blk: {
                            const jump_target_block_node = try llvm.createBasicBlock(context, jump.to, "jmp_target");
                            block_command_list.insertAfter(last_block, jump_target_block_node);
                            last_block = jump_target_block_node;

                            // TODO: make this efficient
                            break :blk llvm.llvm_block_map.get(jump_target_block_node.data).?;
                        };

                        const br = llvm.builder.createBranch(target_block) orelse unreachable;
                        try llvm.llvm_instruction_map.put_no_clobber(context.my_allocator, instruction_index, br.toValue());
                    },
                    .branch => |branch| {
                        const taken_node = try llvm.createBasicBlock(context, branch.taken, "taken_block");
                        const not_taken_node = try llvm.createBasicBlock(context, branch.not_taken, "not_taken_block");
                        block_command_list.insertAfter(last_block, taken_node);
                        block_command_list.insertAfter(taken_node, not_taken_node);
                        last_block = not_taken_node;

                        // TODO: make this fast
                        const taken_block = llvm.llvm_block_map.get(taken_node.data).?;
                        const not_taken_block = llvm.llvm_block_map.get(not_taken_node.data).?;

                        const condition = llvm.llvm_instruction_map.get(branch.condition).?;
                        const branch_weights = null;
                        const unpredictable = null;
                        const br = llvm.builder.createConditionalBranch(condition, taken_block, not_taken_block, branch_weights, unpredictable) orelse unreachable;
                        try llvm.llvm_instruction_map.put_no_clobber(context.my_allocator, instruction_index, br.toValue());
                    },
                    .phi => |phi| {
                        const phi_type = try llvm.getType(unit, context, phi.type);
                        const reserved_value_count: c_uint = @intCast(phi.values.length);
                        const phi_name = "phi";
                        const phi_node = llvm.builder.createPhi(phi_type, reserved_value_count, phi_name, phi_name.len) orelse unreachable;

                        try phis.put_no_clobber(context.my_allocator, instruction_index, phi_node);

                        try llvm.llvm_instruction_map.put_no_clobber(context.my_allocator, instruction_index, phi_node.toValue());
                    },
                    .umin => |umin| {
                        const intrinsic_type = try llvm.getType(unit, context, umin.type);
                        const parameter_types = [_]*LLVM.Type{intrinsic_type};
                        const left = try llvm.emitRightValue(unit, context, umin.left);
                        const right = try llvm.emitRightValue(unit, context, umin.right);
                        const arguments = [_]*LLVM.Value{ left, right };
                        const intrinsic_call = try llvm.callIntrinsic("llvm.umin", &parameter_types, &arguments);
                        try llvm.llvm_instruction_map.put_no_clobber(context.my_allocator, instruction_index, intrinsic_call);
                    },
                    .get_element_pointer => {
                        _ = try llvm.createGEP(unit, context, instruction_index);
                    },
                    .trap => {
                        const parameter_types: []const *LLVM.Type = &.{};
                        const parameter_values: []const *LLVM.Value = &.{};
                        const intrinsic_call = try llvm.callIntrinsic("llvm.trap", parameter_types, parameter_values);
                        try llvm.llvm_instruction_map.put_no_clobber(context.my_allocator, instruction_index, intrinsic_call);
                    },
                    .add_overflow => |add_overflow| {
                        const intrinsic_type = try llvm.getType(unit, context, add_overflow.type);
                        const parameter_types = [_]*LLVM.Type{intrinsic_type};
                        const left = try llvm.emitRightValue(unit, context, add_overflow.left);
                        const right = try llvm.emitRightValue(unit, context, add_overflow.right);
                        const arguments = [_]*LLVM.Value{ left, right };
                        const intrinsic_call = try llvm.callIntrinsic("llvm.sadd.with.overflow", &parameter_types, &arguments);
                        try llvm.llvm_instruction_map.put_no_clobber(context.my_allocator, instruction_index, intrinsic_call);
                    },
                    .@"switch" => |switch_expression| {
                        const condition = try llvm.emitRightValue(unit, context, switch_expression.condition);
                        const else_block: ?*LLVM.Value.BasicBlock = if (switch_expression.else_block != .null) b: {
                            const else_block_node = try llvm.createBasicBlock(context, switch_expression.else_block, "switch_else");
                            const bb = llvm.llvm_block_map.get(switch_expression.else_block).?;
                            block_command_list.insertAfter(last_block, else_block_node);
                            last_block = else_block_node;
                            break :b bb;
                        } else null;
                        var basic_block_array = try UnpinnedArray(*LLVM.Value.BasicBlock).initialize_with_capacity(context.my_allocator, switch_expression.cases.length);
                        var condition_array = try UnpinnedArray(*LLVM.Value.Constant.Int).initialize_with_capacity(context.my_allocator, switch_expression.cases.length);
                        for (switch_expression.cases.pointer[0..switch_expression.cases.length]) |case| {
                            const constant_value = try llvm.emitComptimeRightValue(unit, context, case.condition, switch_expression.condition.type);
                            const constant_int = constant_value.toInt() orelse unreachable;
                            const block = if (llvm.llvm_block_map.get(case.basic_block)) |bb| bb else b: {
                                const switch_block_node = try llvm.createBasicBlock(context, case.basic_block, "case_block");
                                block_command_list.insertAfter(last_block, switch_block_node);
                                last_block = switch_block_node;
                                const block = llvm.llvm_block_map.get(case.basic_block).?;
                                break :b block;
                            };
                            condition_array.append_with_capacity(constant_int);
                            basic_block_array.append_with_capacity(block);
                        }

                        const branch_weights = null;
                        const unpredictable = null;
                        const switch_instruction = llvm.builder.createSwitch(condition, else_block, condition_array.pointer, basic_block_array.pointer, condition_array.length, branch_weights, unpredictable);
                        try llvm.llvm_instruction_map.put_no_clobber(context.my_allocator, instruction_index, switch_instruction.toValue());
                    },
                    .memcpy => |memcpy| {
                        const destination = try llvm.emitLeftValue(unit, context, memcpy.destination);
                        const source = try llvm.emitLeftValue(unit, context, memcpy.source);
                        const destination_alignment = if (memcpy.destination_alignment) |alignment| alignment else b: {
                            const ty = unit.types.get(memcpy.destination.type);
                            const alignment = ty.getAbiAlignment(unit);
                            break :b alignment;
                        };
                        const source_alignment = if (memcpy.source_alignment) |alignment| alignment else b: {
                            const ty = unit.types.get(memcpy.source.type);
                            const alignment = ty.getAbiAlignment(unit);
                            break :b alignment;
                        };
                        _ = llvm.builder.createMemcpy(destination, destination_alignment, source, source_alignment, memcpy.size, memcpy.is_volatile);
                    },
                    else => |t| @panic(@tagName(t)),
                }
            }

            _ = block_command_list.popFirst();
        }

        for (phis.keys(), phis.values()) |instruction_index, phi| {
            const instruction = unit.instructions.get(instruction_index);
            const sema_phi = &instruction.phi;
            for (sema_phi.values.slice(), sema_phi.basic_blocks.slice()) |sema_value, sema_block| {
                assert(sema_value.type == sema_phi.type);
                const value_basic_block = llvm.llvm_block_map.get(sema_block).?;
                const value = llvm.llvm_value_map.get(sema_value) orelse try llvm.emitRightValue(unit, context, sema_value);
                phi.addIncoming(value, value_basic_block);
            }
        }

        if (!builder.isCurrentBlockTerminated()) {
            var message_len: usize = 0;
            const function_str = llvm.function.toString(&message_len);
            const function_dump = function_str[0..message_len];
            try write(.panic, function_dump);
            @panic("Function block with no termination");
        }

        if (unit.descriptor.generate_debug_information) {
            llvm.debug_info_builder.finalizeSubprogram(llvm.function.getSubprogram() orelse unreachable, llvm.function);
        }

        const verify_function = true;

        if (verify_function) {
            var function_len: usize = 0;
            const function_ptr = llvm.function.toString(&function_len);
            const function_ir = function_ptr[0..function_len];

            var message_ptr: [*]const u8 = undefined;
            var message_len: usize = 0;
            const result = llvm.function.verify(&message_ptr, &message_len);

            if (!result) {
                // std.debug.print("PANIC: Failed to verify function:\n{s}\n", .{error_message});

                var module_len: usize = 0;
                const module_ptr = llvm.module.toString(&module_len);
                const module_dump = module_ptr[0..module_len];
                _ = module_dump; // autofix

                try write(.panic, function_ir);
                const error_message = message_ptr[0..message_len];
                try write(.panic, error_message);
                // std.debug.print("\nLLVM verification for function inside module failed:\nFull module: {s}\n```\n{s}\n```\n{s}\n", .{ module_dump, function_ir, error_message });
                @panic("LLVM function verification failed");
            }
        }
    }

    llvm.debug_info_builder.finalize();

    var module_len: usize = 0;
    const module_ptr = llvm.module.toString(&module_len);
    const module_string = module_ptr[0..module_len];
    // logln(.llvm, .print_module, "{s}", .{module_string});

    const verify_module = true;
    const print_module = true;
    if (verify_module) {
        var message_ptr: [*]const u8 = undefined;
        var message_len: usize = 0;
        const result = llvm.module.verify(&message_ptr, &message_len);
        if (!result) {
            try write(.llvm, "Module: \n");
            try write(.llvm, module_string);
            try write(.llvm, "\n");
            try write(.llvm, message_ptr[0..message_len]);
            @panic("\nLLVM module verification failed");
        }
    }

    if (print_module) {
        try write(.llvm, "Module: \n");
        try write(.llvm, module_string);
        try write(.llvm, "\n");
    }

    switch (unit.descriptor.arch) {
        inline else => |a| {
            const arch = @field(LLVM, @tagName(a));
            arch.initializeTarget();
            arch.initializeTargetInfo();
            arch.initializeTargetMC();
            arch.initializeAsmPrinter();
            arch.initializeAsmParser();
        }
    }

    // TODO: proper target selection
    const target_triple = switch (unit.descriptor.os) {
        .linux => "x86_64-linux-none",
        .macos => "aarch64-apple-macosx-none",
    };
    const cpu = "generic";
    const features = "";
    const target = blk: {
        var error_message: [*]const u8 = undefined;
        var error_message_len: usize = 0;
        const target = bindings.NativityLLVMGetTarget(target_triple.ptr, target_triple.len, &error_message, &error_message_len) orelse unreachable;
        break :blk target;
    };

    const jit = false;
    const code_model: LLVM.CodeModel = undefined;
    const is_code_model_present = false;
    const codegen_optimization_level = LLVM.CodegenOptimizationLevel.none;
    const target_machine = target.createTargetMachine(target_triple.ptr, target_triple.len, cpu, cpu.len, features, features.len, LLVM.RelocationModel.static, code_model, is_code_model_present, codegen_optimization_level, jit) orelse unreachable;
    llvm.module.setTargetMachineDataLayout(target_machine);
    llvm.module.setTargetTriple(target_triple.ptr, target_triple.len);
    const file_path = unit.descriptor.executable_path;
    const object_file_path = blk: {
        const slice = try context.allocator.alloc(u8, file_path.len + 3);
        @memcpy(slice[0..file_path.len], file_path);
        slice[file_path.len] = '.';
        slice[file_path.len + 1] = 'o';
        slice[file_path.len + 2] = 0;
        const object_file_path = slice[0 .. slice.len - 1 :0];
        break :blk object_file_path;
    };
    const disable_verify = false;
    const result = llvm.module.addPassesToEmitFile(target_machine, object_file_path.ptr, object_file_path.len, LLVM.CodeGenFileType.object, disable_verify);
    if (!result) {
        @panic("can't generate machine code");
    }
}
