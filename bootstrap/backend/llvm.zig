const std = @import("std");
const equal = std.mem.eql;
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;
const Compilation = @import("../Compilation.zig");
const Module = Compilation.Module;
const data_structures = @import("../data_structures.zig");
const ArrayList = data_structures.ArrayList;
const AutoHashMap = data_structures.AutoHashMap;

extern fn NativityLLVMCreateContext() ?*LLVM.Context;
extern fn NativityLLVMCreateModule(module_name_ptr: [*:0]const u8, module_name_len: usize, context: *LLVM.Context) ?*LLVM.Module;
extern fn NativityLLVMCreateBuilder(context: *LLVM.Context) ?*LLVM.Builder;
extern fn NativityLLVMGetFunctionType(return_type: *LLVM.Type, argument_type_ptr: [*]const *LLVM.Type, argument_type_len: usize, is_var_args: bool) ?*LLVM.Type.Function;
extern fn NativityLLVMGetIntegerType(context: *LLVM.Context, bit_count: u32) ?*LLVM.Type.Integer;
extern fn NativityLLVMGetPointerType(context: *LLVM.Context, address_space: u32) ?*LLVM.Type.Pointer;
extern fn NativityLLVMGetArrayType(element_type: *LLVM.Type, element_count: u64) ?*LLVM.Type.Array;
extern fn NativityLLVMCreateStructType(context: *LLVM.Context, type_ptr: [*]const *LLVM.Type, type_count: usize, name_ptr: [*]const u8, name_len: usize, is_packed: bool) ?*LLVM.Type.Struct;
extern fn NativityLLVMConstantStruct(struct_type: *LLVM.Type.Struct, constant_ptr: [*]const *LLVM.Value.Constant, constant_count: usize) ?*LLVM.Value.Constant;
extern fn NativityLLVMModuleGetFunction(module: *LLVM.Module, name_ptr: [*]const u8, name_len: usize) ?*LLVM.Value.Function;
extern fn NativityLLVModuleCreateFunction(module: *LLVM.Module, function_type: *LLVM.Type.Function, linkage: LLVM.Linkage, address_space: c_uint, name_ptr: [*]const u8, name_len: usize) ?*LLVM.Value.Function;
extern fn NativityLLVMModuleCreateDebugInfoBuilder(module: *LLVM.Module) ?*LLVM.DebugInfo.Builder;
extern fn NativityLLVMDebugInfoBuilderCreateFile(builder: *LLVM.DebugInfo.Builder, filename_ptr: [*]const u8, filename_len: usize, directory_ptr: [*]const u8, directory_len: usize) ?*LLVM.DebugInfo.File;
extern fn NativityLLVMDebugInfoBuilderCreateCompileUnit(builder: *LLVM.DebugInfo.Builder, language: LLVM.DebugInfo.Language, file: *LLVM.DebugInfo.File, producer_ptr: [*]const u8, producer_len: usize, is_optimized: bool, flags_ptr: [*]const u8, flags_len: usize, runtime_version: c_uint, split_name_ptr: [*]const u8, split_name_len: usize, debug_info_emission_kind: LLVM.DebugInfo.CompileUnit.EmissionKind, DWOId: u64, split_debug_inlining: bool, debug_info_for_profiling: bool, debug_info_name_table_kind: LLVM.DebugInfo.CompileUnit.NameTableKind, ranges_base_address: bool, sysroot_ptr: [*]const u8, sysroot_len: usize, sdk_ptr: [*]const u8, sdk_len: usize) ?*LLVM.DebugInfo.CompileUnit;
extern fn NativityLLVMDebugInfoBuilderCreateFunction(builder: *LLVM.DebugInfo.Builder, scope: *LLVM.DebugInfo.Scope, name_ptr: [*]const u8, name_len: usize, linkage_name_ptr: [*]const u8, linkage_name_len: usize, file: *LLVM.DebugInfo.File, line_number: c_uint, type: *LLVM.DebugInfo.SubroutineType, scope_line: c_uint, flags: LLVM.DebugInfo.Node.Flags, subprogram_flags: LLVM.DebugInfo.Subprogram.Flags, declaration: ?*LLVM.DebugInfo.Subprogram) ?*LLVM.DebugInfo.Subprogram;
extern fn NativityLLVMDebugInfoBuilderCreateSubroutineType(builder: *LLVM.DebugInfo.Builder, parameter_types_ptr: [*]const *LLVM.DebugInfo.Type, parameter_type_count: usize, flags: LLVM.DebugInfo.Node.Flags, calling_convention: LLVM.DebugInfo.CallingConvention) ?*LLVM.DebugInfo.SubroutineType;
extern fn NativityLLVMDebugInfoBuilderCreateLexicalBlock(builder: *LLVM.DebugInfo.Builder, parent_scope: *LLVM.DebugInfo.Scope, parent_file: *LLVM.DebugInfo.File, line: c_uint, column: c_uint) ?*LLVM.DebugInfo.LexicalBlock;
extern fn NativityLLVMDebugInfoBuilderCreateParameterVariable(builder: *LLVM.DebugInfo.Builder, scope: *LLVM.DebugInfo.Scope, name_ptr: [*]const u8, name_len: usize, argument_index: c_uint, file: *LLVM.DebugInfo.File, line_number: c_uint, type: *LLVM.DebugInfo.Type, always_preserve: bool, flags: LLVM.DebugInfo.Node.Flags) ?*LLVM.DebugInfo.LocalVariable;
extern fn NativityLLVMDebugInfoBuilderCreateAutoVariable(builder: *LLVM.DebugInfo.Builder, scope: *LLVM.DebugInfo.Scope, name_ptr: [*]const u8, name_len: usize, file: *LLVM.DebugInfo.File, line_number: c_uint, type: *LLVM.DebugInfo.Type, always_preserve: bool, flags: LLVM.DebugInfo.Node.Flags, alignment: u32) ?*LLVM.DebugInfo.LocalVariable; // 0 means 1 << 0 (alignment of 1)
extern fn NativityLLVMDebugInfoBuilderInsertDeclare(builder: *LLVM.DebugInfo.Builder, pointer: *LLVM.Value, local_variable: *LLVM.DebugInfo.LocalVariable, context: *LLVM.Context, line: c_uint, column: c_uint, scope: *LLVM.DebugInfo.Scope, basic_block: *LLVM.Value.BasicBlock) ?*LLVM.Value.Instruction;
extern fn NativityLLVMDebugInfoBuilderCreateBasicType(builder: *LLVM.DebugInfo.Builder, name_ptr: [*]const u8, name_len: usize, bit_count: u64, dwarf_encoding: LLVM.DebugInfo.AttributeType, flags: LLVM.DebugInfo.Node.Flags) ?*LLVM.DebugInfo.Type;
extern fn NativityLLVMDebugInfoBuilderCreatePointerType(builder: *LLVM.DebugInfo.Builder, element_type: *LLVM.DebugInfo.Type, pointer_bit_count: u64, alignment: u32, name_ptr: [*]const u8, name_len: usize) ?*LLVM.DebugInfo.Type.Derived;
extern fn NativityLLVMDebugInfoBuilderCreateStructType(builder: *LLVM.DebugInfo.Builder, scope: ?*LLVM.DebugInfo.Scope, name_ptr: [*]const u8, name_len: usize, file: ?*LLVM.DebugInfo.File, line_number: c_uint, bit_count: u64, alignment: u32, flags: LLVM.DebugInfo.Node.Flags, derived_from: ?*LLVM.DebugInfo.Type, element_type_ptr: [*]const *LLVM.DebugInfo.Type, element_type_count: usize) ?*LLVM.DebugInfo.Type.Composite;
extern fn NativityLLVMDebugInfoBuilderCreateArrayType(builder: *LLVM.DebugInfo.Builder, bit_size: u64, alignment: u32, type: *LLVM.DebugInfo.Type, element_count: usize) ?*LLVM.DebugInfo.Type.Composite;
extern fn NativityLLVMDebugInfoBuilderCreateEnumerationType(builder: *LLVM.DebugInfo.Builder, scope: ?*LLVM.DebugInfo.Scope, name_ptr: [*]const u8, name_len: usize, file: *LLVM.DebugInfo.File, line: c_uint, bit_size: u64, alignment: u32, enumerator_ptr: [*]const *LLVM.DebugInfo.Type.Enumerator, enumerator_count: usize, underlying_type: *LLVM.DebugInfo.Type) ?*LLVM.DebugInfo.Type.Composite;
extern fn NativityLLVMDebugInfoBuilderCreateEnumerator(builder: *LLVM.DebugInfo.Builder, name_ptr: [*]const u8, name_len: usize, value: u64, is_unsigned: bool) ?*LLVM.DebugInfo.Type.Enumerator;
extern fn NativityLLVMDebugInfoBuilderCreateReplaceableCompositeType(builder: *LLVM.DebugInfo.Builder, tag: c_uint, name_ptr: [*]const u8, name_len: usize, scope: ?*LLVM.DebugInfo.Scope, file: ?*LLVM.DebugInfo.File, line: c_uint) ?*LLVM.DebugInfo.Type.Composite;
extern fn NativityLLVMDebugInfoBuilderFinalizeSubprogram(builder: *LLVM.DebugInfo.Builder, subprogram: *LLVM.DebugInfo.Subprogram, function: *LLVM.Value.Function) void;
extern fn NativityLLVMDebugInfoBuilderFinalize(builder: *LLVM.DebugInfo.Builder) void;
extern fn NativityLLVMDebugInfoSubprogramGetFile(subprogram: *LLVM.DebugInfo.Subprogram) ?*LLVM.DebugInfo.File;
extern fn NativityLLVMDebugInfoSubprogramGetArgumentType(subprogram: *LLVM.DebugInfo.Subprogram, argument_index: usize) ?*LLVM.DebugInfo.Type;
extern fn NativityLLVMCreateBasicBlock(context: *LLVM.Context, name_ptr: [*]const u8, name_len: usize, parent_function: ?*LLVM.Value.Function, insert_before: ?*LLVM.Value.BasicBlock) ?*LLVM.Value.BasicBlock;
extern fn NativityLLVMBasicBlockRemoveFromParent(basic_block: *LLVM.Value.BasicBlock) void;
extern fn NativityLLVMBuilderSetInsertPoint(builder: *LLVM.Builder, basic_block: *LLVM.Value.BasicBlock) void;
extern fn NativityLLVMBuilderGetInsertBlock(builder: *LLVM.Builder) ?*LLVM.Value.BasicBlock;
extern fn NativityLLVMBuilderSetCurrentDebugLocation(builder: *LLVM.Builder, context: *LLVM.Context, line: c_uint, column: c_uint, scope: *LLVM.DebugInfo.Scope, function: *LLVM.Value.Function) void;
extern fn NativityLLVMValueSetName(value: *LLVM.Value, name_ptr: [*]const u8, name_len: usize) void;
extern fn NativityLLVMValueGetType(value: *LLVM.Value) *LLVM.Type;
extern fn NativityLLVMArgumentGetIndex(argument: *LLVM.Value.Argument) c_uint;
extern fn NativityLLVMFunctionGetArguments(function: *LLVM.Value.Function, argument_ptr: [*]*LLVM.Value.Argument, argument_len: *usize) void;
extern fn NativityLLVMFunctionGetReturnType(function: *LLVM.Value.Function) ?*LLVM.Type;
extern fn NativityLLVMBuilderCreateAlloca(builder: *LLVM.Builder, type: *LLVM.Type, address_space: c_uint, array_size: ?*LLVM.Value, name_ptr: [*]const u8, name_len: usize) ?*LLVM.Value.Instruction.Alloca;
extern fn NativityLLVMBuilderCreateStore(builder: *LLVM.Builder, value: *LLVM.Value, pointer: *LLVM.Value, is_volatile: bool) ?*LLVM.Value.Instruction.Store;
extern fn NativityLLVMContextGetConstantInt(context: *LLVM.Context, bit_count: c_uint, value: u64, is_signed: bool) ?*LLVM.Value.Constant.Int;
extern fn NativityLLVMContextGetConstString(context: *LLVM.Context, name_ptr: [*]const u8, name_len: usize, null_terminate: bool) ?*LLVM.Value.Constant;
extern fn NativityLLVMContextGetConstArray(array_type: *LLVM.Type.Array, value_ptr: [*]const *LLVM.Value.Constant, value_count: usize) ?*LLVM.Value.Constant;
extern fn NativityLLVMBuilderCreateICmp(builder: *LLVM.Builder, integer_comparison: LLVM.Value.Instruction.ICmp.Kind, left: *LLVM.Value, right: *LLVM.Value, name_ptr: [*]const u8, name_len: usize) ?*LLVM.Value;
extern fn NativityLLVMBuilderCreateLoad(builder: *LLVM.Builder, type: *LLVM.Type, value: *LLVM.Value, is_volatile: bool, name_ptr: [*]const u8, name_len: usize) ?*LLVM.Value.Instruction.Load;
extern fn NativityLLVMBuilderCreateRet(builder: *LLVM.Builder, value: ?*LLVM.Value) ?*LLVM.Value.Instruction.Ret;
extern fn NativityLLVMBuilderCreateCast(builder: *LLVM.Builder, cast_type: LLVM.Value.Instruction.Cast.Type, value: *LLVM.Value, type: *LLVM.Type, name_ptr: [*]const u8, name_len: usize) ?*LLVM.Value;
extern fn NativityLLVMFunctionAddAttributeKey(builder: *LLVM.Value.Function, attribute_key: LLVM.Attribute) void;
extern fn NativityLLVMGetVoidType(context: *LLVM.Context) ?*LLVM.Type;
extern fn NativityLLVMGetInlineAssembly(function_type: *LLVM.Type.Function, assembly_ptr: [*]const u8, assembly_len: usize, constraints_ptr: [*]const u8, constrains_len: usize, has_side_effects: bool, is_align_stack: bool, dialect: LLVM.Value.InlineAssembly.Dialect, can_throw: bool) ?*LLVM.Value.InlineAssembly;
extern fn NativityLLVMBuilderCreateCall(builder: *LLVM.Builder, function_type: *LLVM.Type.Function, callee: *LLVM.Value, argument_ptr: [*]const *LLVM.Value, argument_count: usize, name_ptr: [*]const u8, name_len: usize, fp_math_tag: ?*LLVM.Metadata.Node) ?*LLVM.Value.Instruction.Call;
extern fn NativityLLVMBuilderCreateUnreachable(builder: *LLVM.Builder) ?*LLVM.Value.Instruction.Unreachable;
extern fn NativityLLVMModuleAddGlobalVariable(module: *LLVM.Module, type: *LLVM.Type, is_constant: bool, linkage: LLVM.Linkage, initializer: ?*LLVM.Value.Constant, name_ptr: [*]const u8, name_len: usize, insert_before: ?*LLVM.Value.Constant.GlobalVariable, thread_local_mode: LLVM.ThreadLocalMode, address_space: c_uint, externally_initialized: bool) ?*LLVM.Value.Constant.GlobalVariable;

extern fn NativityLLVMBuilderCreateAdd(builder: *LLVM.Builder, left: *LLVM.Value, right: *LLVM.Value, name_ptr: [*]const u8, name_len: usize, no_unsigned_wrapping: bool, no_signed_wrapping: bool) ?*LLVM.Value;
extern fn NativityLLVMBuilderCreateSub(builder: *LLVM.Builder, left: *LLVM.Value, right: *LLVM.Value, name_ptr: [*]const u8, name_len: usize, no_unsigned_wrapping: bool, no_signed_wrapping: bool) ?*LLVM.Value;
extern fn NativityLLVMBuilderCreateMultiply(builder: *LLVM.Builder, left: *LLVM.Value, right: *LLVM.Value, name_ptr: [*]const u8, name_len: usize, no_unsigned_wrapping: bool, no_signed_wrapping: bool) ?*LLVM.Value;
extern fn NativityLLVMBuilderCreateShiftLeft(builder: *LLVM.Builder, left: *LLVM.Value, right: *LLVM.Value, name_ptr: [*]const u8, name_len: usize, no_unsigned_wrapping: bool, no_signed_wrapping: bool) ?*LLVM.Value;

extern fn NativityLLVMBuilderCreateUDiv(builder: *LLVM.Builder, left: *LLVM.Value, right: *LLVM.Value, name_ptr: [*]const u8, name_len: usize, is_exact: bool) ?*LLVM.Value;
extern fn NativityLLVMBuilderCreateSDiv(builder: *LLVM.Builder, left: *LLVM.Value, right: *LLVM.Value, name_ptr: [*]const u8, name_len: usize, is_exact: bool) ?*LLVM.Value;
extern fn NativityLLVMBuilderCreateURem(builder: *LLVM.Builder, left: *LLVM.Value, right: *LLVM.Value, name_ptr: [*]const u8, name_len: usize) ?*LLVM.Value;
extern fn NativityLLVMBuilderCreateSRem(builder: *LLVM.Builder, left: *LLVM.Value, right: *LLVM.Value, name_ptr: [*]const u8, name_len: usize) ?*LLVM.Value;
extern fn NativityLLVMBuilderCreateLogicalShiftRight(builder: *LLVM.Builder, left: *LLVM.Value, right: *LLVM.Value, name_ptr: [*]const u8, name_len: usize, is_exact: bool) ?*LLVM.Value;
extern fn NativityLLVMBuilderCreateArithmeticShiftRight(builder: *LLVM.Builder, left: *LLVM.Value, right: *LLVM.Value, name_ptr: [*]const u8, name_len: usize, is_exact: bool) ?*LLVM.Value;

extern fn NativityLLVMBuilderCreateXor(builder: *LLVM.Builder, left: *LLVM.Value, right: *LLVM.Value, name_ptr: [*]const u8, name_len: usize) ?*LLVM.Value;
extern fn NativityLLVMBuilderCreateAnd(builder: *LLVM.Builder, left: *LLVM.Value, right: *LLVM.Value, name_ptr: [*]const u8, name_len: usize) ?*LLVM.Value;
extern fn NativityLLVMBuilderCreateOr(builder: *LLVM.Builder, left: *LLVM.Value, right: *LLVM.Value, name_ptr: [*]const u8, name_len: usize) ?*LLVM.Value;
extern fn NativityLLVMBuilderCreateGEP(builder: *LLVM.Builder, type: *LLVM.Type, pointer: *LLVM.Value, index_ptr: [*]const *LLVM.Value, index_count: usize, name_ptr: [*]const u8, name_len: usize, in_bounds: bool) ?*LLVM.Value;
extern fn NativityLLVMBuilderCreateBranch(builder: *LLVM.Builder, basic_block: *LLVM.Value.BasicBlock) ?*LLVM.Value.Instruction.Branch;
extern fn NativityLLVMBuilderCreateConditionalBranch(builder: *LLVM.Builder, condition: *LLVM.Value, true_block: *LLVM.Value.BasicBlock, false_block: *LLVM.Value.BasicBlock, branch_weights: ?*LLVM.Metadata.Node, unpredictable: ?*LLVM.Metadata.Node) ?*LLVM.Value.Instruction.Branch;

extern fn NativityLLVMVerifyFunction(function: *LLVM.Value.Function, message_ptr: *[*]const u8, message_len: *usize) bool;
extern fn NativityLLVMVerifyModule(module: *LLVM.Module, message_ptr: *[*]const u8, message_len: *usize) bool;

extern fn NativityLLVMModuleToString(module: *LLVM.Module, message_len: *usize) [*]const u8;
extern fn NativityLLVMFunctionToString(function: *LLVM.Value.Function, message_len: *usize) [*]const u8;

extern fn NativityLLVMGenerateMachineCode(module: *LLVM.Module, object_file_path_ptr: [*]const u8, object_file_path_len: usize, file_path_ptr: [*]const u8, file_path_len: usize) bool;
extern fn NativityLLVMBuilderIsCurrentBlockTerminated(builder: *LLVM.Builder) bool;
extern fn NativityLLVMGetUndefined(type: *LLVM.Type) ?*LLVM.Value.Constant.Undefined;
extern fn NativityLLVMFunctionSetCallingConvention(function: *LLVM.Value.Function, calling_convention: LLVM.Value.Function.CallingConvention) void;
extern fn NativityLLVMFunctionGetCallingConvention(function: *LLVM.Value.Function) LLVM.Value.Function.CallingConvention;
extern fn NativityLLVMFunctionSetSubprogram(function: *LLVM.Value.Function, subprogram: *LLVM.DebugInfo.Subprogram) void;
extern fn NativityLLVMFunctionGetSubprogram(function: *LLVM.Value.Function) ?*LLVM.DebugInfo.Subprogram;

extern fn NativityLLVMCallSetCallingConvention(instruction: *LLVM.Value.Instruction.Call, calling_convention: LLVM.Value.Function.CallingConvention) void;
extern fn NativityLLVMGetStruct(struct_type: *LLVM.Type.Struct, constant_ptr: [*]const *LLVM.Value.Constant, constant_len: usize) ?*LLVM.Value.Constant;

extern fn NativityLLVMValueToConstant(value: *LLVM.Value) ?*LLVM.Value.Constant;
extern fn NativityLLVMValueToFunction(value: *LLVM.Value) ?*LLVM.Value.Function;

extern fn NativityLLVMTypeIsPointer(type: *LLVM.Type) bool;
extern fn NativityLLVMTypeIsInteger(type: *LLVM.Type) bool;

extern fn NativityLLVMTypeToStruct(type: *LLVM.Type) ?*LLVM.Type.Struct;
extern fn NativityLLVMTypeToFunction(type: *LLVM.Type) ?*LLVM.Type.Function;
extern fn NativityLLVMTypeToArray(type: *LLVM.Type) ?*LLVM.Type.Array;

extern fn NativityLLVMArrayTypeGetElementType(array_type: *LLVM.Type.Array) ?*LLVM.Type;
extern fn NativityLLVMLookupIntrinsic(name_ptr: [*]const u8, name_len: usize) LLVM.Value.IntrinsicID;
extern fn NativityLLVMModuleGetIntrinsicDeclaration(module: *LLVM.Module, intrinsic_id: LLVM.Value.IntrinsicID, parameter_types_ptr: [*]const *LLVM.Type, parameter_type_count: usize) ?*LLVM.Value.Function;
extern fn NativityLLVMContextGetIntrinsicType(context: *LLVM.Context, intrinsic_id: LLVM.Value.IntrinsicID, parameter_type_ptr: [*]const *LLVM.Type, parameter_type_count: usize) ?*LLVM.Type.Function;
extern fn NativityLLVMBuilderCreateExtractValue(builder: *LLVM.Builder, aggregate: *LLVM.Value, indices_ptr: [*]const c_uint, indices_len: usize, name_ptr: [*]const u8, name_len: usize) ?*LLVM.Value;
extern fn NativityLLVMBuilderCreateInsertValue(builder: *LLVM.Builder, aggregate: *LLVM.Value, value: *LLVM.Value, indices_ptr: [*]const c_uint, indices_len: usize, name_ptr: [*]const u8, name_len: usize) ?*LLVM.Value;
extern fn NativityLLVMContextCreateGlobalStringPointer(builder: *LLVM.Builder, string_ptr: [*]const u8, string_len: usize, name_ptr: [*]const u8, name_len: usize, address_space: c_uint, module: *LLVM.Module) ?*LLVM.Value.Constant;
extern fn NativityLLVMCompareTypes(a: *LLVM.Type, b: *LLVM.Type) bool;
extern fn NativityLLVMCreatePhiNode(type: *LLVM.Type, reserved_value_count: c_uint, name_ptr: [*]const u8, name_len: usize, basic_block: ?*LLVM.Value.BasicBlock) ?*LLVM.Value.Instruction.PhiNode;

const LLVM = struct {
    context: *LLVM.Context,
    module: *LLVM.Module,
    builder: *LLVM.Builder,
    debug_info_builder: *LLVM.DebugInfo.Builder,
    debug_info_file_map: AutoHashMap(Compilation.File.Index, *LLVM.DebugInfo.File) = .{},
    debug_type_map: AutoHashMap(Compilation.Type.Index, *LLVM.DebugInfo.Type) = .{},
    type_name_map: AutoHashMap(Compilation.Type.Index, []const u8) = .{},
    type_map: AutoHashMap(Compilation.Type.Index, *LLVM.Type) = .{},
    function_definition_map: AutoHashMap(Compilation.Function.Index, *LLVM.Value.Function) = .{},
    pointer_type: ?*LLVM.Type.Pointer = null,
    sema: *Compilation.Module,
    function: *LLVM.Value.Function = undefined,
    exit_block: *LLVM.Value.BasicBlock = undefined,
    sema_function: Compilation.Function.Index = Compilation.Function.Index.invalid,
    allocator: Allocator,
    declaration_map: AutoHashMap(Compilation.Declaration.Index, *LLVM.Value) = .{},
    declaration_names: AutoHashMap(Compilation.Declaration.Index, []const u8) = .{},
    inside_branch: bool = false,
    return_phi_node: ?*LLVM.Value.Instruction.PhiNode = null,
    scope: *LLVM.DebugInfo.Scope = undefined,
    file: *LLVM.DebugInfo.File = undefined,

    const Linkage = enum(c_uint) {
        @"extern" = 0,
    };

    const ThreadLocalMode = enum(c_uint) {
        not_thread_local = 0,
    };

    const Context = opaque {
        const create = NativityLLVMCreateContext;
        const createBasicBlock = NativityLLVMCreateBasicBlock;
        const getConstantInt = NativityLLVMContextGetConstantInt;
        const getConstString = NativityLLVMContextGetConstString;
        const getVoidType = NativityLLVMGetVoidType;
        const getIntegerType = NativityLLVMGetIntegerType;
        const getFunctionType = NativityLLVMGetFunctionType;
        const getPointerType = NativityLLVMGetPointerType;
        const createStructType = NativityLLVMCreateStructType;
        const getIntrinsicType = NativityLLVMContextGetIntrinsicType;
    };

    const Module = opaque {
        const addGlobalVariable = NativityLLVMModuleAddGlobalVariable;
        const create = NativityLLVMCreateModule;
        const getFunction = NativityLLVMModuleGetFunction;
        const createFunction = NativityLLVModuleCreateFunction;
        const verify = NativityLLVMVerifyModule;
        const toString = NativityLLVMModuleToString;
        const getIntrinsicDeclaration = NativityLLVMModuleGetIntrinsicDeclaration;
        const createDebugInfoBuilder = NativityLLVMModuleCreateDebugInfoBuilder;
    };

    const Builder = opaque {
        const create = NativityLLVMCreateBuilder;
        const setInsertPoint = NativityLLVMBuilderSetInsertPoint;
        const createAdd = NativityLLVMBuilderCreateAdd;
        const createAlloca = NativityLLVMBuilderCreateAlloca;
        const createAnd = NativityLLVMBuilderCreateAnd;
        const createOr = NativityLLVMBuilderCreateOr;
        const createCall = NativityLLVMBuilderCreateCall;
        const createCast = NativityLLVMBuilderCreateCast;
        const createBranch = NativityLLVMBuilderCreateBranch;
        const createConditionalBranch = NativityLLVMBuilderCreateConditionalBranch;
        const createGEP = NativityLLVMBuilderCreateGEP;
        const createICmp = NativityLLVMBuilderCreateICmp;
        const createLoad = NativityLLVMBuilderCreateLoad;
        const createMultiply = NativityLLVMBuilderCreateMultiply;
        const createRet = NativityLLVMBuilderCreateRet;
        const createShiftLeft = NativityLLVMBuilderCreateShiftLeft;
        const createArithmeticShiftRight = NativityLLVMBuilderCreateArithmeticShiftRight;
        const createLogicalShiftRight = NativityLLVMBuilderCreateLogicalShiftRight;
        const createStore = NativityLLVMBuilderCreateStore;
        const createSub = NativityLLVMBuilderCreateSub;
        const createUnreachable = NativityLLVMBuilderCreateUnreachable;
        const createXor = NativityLLVMBuilderCreateXor;
        const createUDiv = NativityLLVMBuilderCreateUDiv;
        const createSDiv = NativityLLVMBuilderCreateSDiv;
        const createURem = NativityLLVMBuilderCreateURem;
        const createSRem = NativityLLVMBuilderCreateSRem;
        const createExtractValue = NativityLLVMBuilderCreateExtractValue;
        const createInsertValue = NativityLLVMBuilderCreateInsertValue;
        const createGlobalStringPointer = NativityLLVMContextCreateGlobalStringPointer;

        const getInsertBlock = NativityLLVMBuilderGetInsertBlock;
        const isCurrentBlockTerminated = NativityLLVMBuilderIsCurrentBlockTerminated;
        const setCurrentDebugLocation = NativityLLVMBuilderSetCurrentDebugLocation;
    };

    const DebugInfo = struct {
        const AttributeType = enum(c_uint) {
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
        const CallingConvention = enum(c_uint) {
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

        const Builder = opaque {
            const createCompileUnit = NativityLLVMDebugInfoBuilderCreateCompileUnit;
            const createFile = NativityLLVMDebugInfoBuilderCreateFile;
            const createFunction = NativityLLVMDebugInfoBuilderCreateFunction;
            const createSubroutineType = NativityLLVMDebugInfoBuilderCreateSubroutineType;
            const createLexicalBlock = NativityLLVMDebugInfoBuilderCreateLexicalBlock;
            const createParameterVariable = NativityLLVMDebugInfoBuilderCreateParameterVariable;
            const createAutoVariable = NativityLLVMDebugInfoBuilderCreateAutoVariable;
            const createBasicType = NativityLLVMDebugInfoBuilderCreateBasicType;
            const createPointerType = NativityLLVMDebugInfoBuilderCreatePointerType;
            const createStructType = NativityLLVMDebugInfoBuilderCreateStructType;
            const createArrayType = NativityLLVMDebugInfoBuilderCreateArrayType;
            const createEnumerationType = NativityLLVMDebugInfoBuilderCreateEnumerationType;
            const createEnumerator = NativityLLVMDebugInfoBuilderCreateEnumerator;
            const createReplaceableCompositeType = NativityLLVMDebugInfoBuilderCreateReplaceableCompositeType;
            const insertDeclare = NativityLLVMDebugInfoBuilderInsertDeclare;
            const finalizeSubprogram = NativityLLVMDebugInfoBuilderFinalizeSubprogram;
            const finalize = NativityLLVMDebugInfoBuilderFinalize;
        };

        const CompileUnit = opaque {
            const EmissionKind = enum(c_uint) {
                no_debug = 0,
                full_debug = 1,
                line_tables_only = 2,
                debug_directives_only = 3,
            };

            const NameTableKind = enum(c_uint) {
                default = 0,
                gnu = 1,
                none = 2,
            };
        };

        const LocalVariable = opaque {};
        const LexicalBlock = opaque {
            fn toScope(this: *@This()) *Scope {
                return @ptrCast(this);
            }
        };

        const Node = opaque {
            const Flags = packed struct(u32) {
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

        const File = opaque {
            fn toScope(this: *@This()) *Scope {
                return @ptrCast(this);
            }
        };

        const Language = enum(c_uint) {
            c = 0x02,
        };

        const Scope = opaque {};
        const LocalScope = opaque {
            fn toScope(this: *@This()) *Scope {
                return @ptrCast(this);
            }
        };
        const Subprogram = opaque {
            const getFile = NativityLLVMDebugInfoSubprogramGetFile;
            const getArgumentType = NativityLLVMDebugInfoSubprogramGetArgumentType;
            fn toLocalScope(this: *@This()) *LocalScope {
                return @ptrCast(this);
            }

            const Flags = packed struct(u32) {
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

        const SubroutineType = opaque {};
        const Type = opaque {
            const Derived = opaque {
                fn toType(this: *@This()) *LLVM.DebugInfo.Type {
                    return @ptrCast(this);
                }
            };

            const Composite = opaque {
                fn toType(this: *@This()) *LLVM.DebugInfo.Type {
                    return @ptrCast(this);
                }
            };

            const Enumerator = opaque {};
        };
    };

    const lookupIntrinsic = NativityLLVMLookupIntrinsic;
    const newPhiNode = NativityLLVMCreatePhiNode;

    const Metadata = opaque {
        const Node = opaque {};
    };

    const Attribute = enum(u32) {
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

    const Type = opaque {
        const compare = NativityLLVMCompareTypes;
        const toStruct = NativityLLVMTypeToStruct;
        const toFunction = NativityLLVMTypeToFunction;
        const toArray = NativityLLVMTypeToArray;
        const isPointer = NativityLLVMTypeIsPointer;
        const isInteger = NativityLLVMTypeIsInteger;

        const Array = opaque {
            fn toType(integer: *@This()) *Type {
                return @ptrCast(integer);
            }
            const get = NativityLLVMGetArrayType;
            const getConstant = NativityLLVMContextGetConstArray;
            const getElementType = NativityLLVMArrayTypeGetElementType;
        };

        const Integer = opaque {
            fn toType(integer: *@This()) *Type {
                return @ptrCast(integer);
            }
        };

        const Function = opaque {
            fn toType(integer: *@This()) *Type {
                return @ptrCast(integer);
            }
        };

        const Pointer = opaque {
            fn toType(integer: *@This()) *Type {
                return @ptrCast(integer);
            }
        };

        const Struct = opaque {
            const instantiate = NativityLLVMGetStruct;
            const instantiateConstant = NativityLLVMConstantStruct;
            fn toType(integer: *@This()) *Type {
                return @ptrCast(integer);
            }
        };

        const Error = error{
            void,
            function,
            integer,
            pointer,
            @"struct",
            intrinsic,
            array,
        };

        const getUndefined = NativityLLVMGetUndefined;
    };

    const Value = opaque {
        const setName = NativityLLVMValueSetName;
        const getType = NativityLLVMValueGetType;
        const toConstant = NativityLLVMValueToConstant;
        const toFunction = NativityLLVMValueToFunction;

        const IntrinsicID = enum(u32) {
            none = 0,
            _,
        };

        const Function = opaque {
            const getArguments = NativityLLVMFunctionGetArguments;
            const getReturnType = NativityLLVMFunctionGetReturnType;
            const addAttributeKey = NativityLLVMFunctionAddAttributeKey;
            const verify = NativityLLVMVerifyFunction;
            const toString = NativityLLVMFunctionToString;
            const setCallingConvention = NativityLLVMFunctionSetCallingConvention;
            const getCallingConvention = NativityLLVMFunctionGetCallingConvention;
            const setSubprogram = NativityLLVMFunctionSetSubprogram;
            const getSubprogram = NativityLLVMFunctionGetSubprogram;

            fn toValue(this: *@This()) *Value {
                return @ptrCast(this);
            }

            const CallingConvention = enum(c_uint) {
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

        const BasicBlock = opaque {
            const remove = NativityLLVMBasicBlockRemoveFromParent;
            fn toValue(this: *@This()) *Value {
                return @ptrCast(this);
            }
        };
        const Argument = opaque {
            const getIndex = NativityLLVMArgumentGetIndex;
            fn toValue(this: *@This()) *Value {
                return @ptrCast(this);
            }
        };

        const Instruction = opaque {
            fn toValue(this: *@This()) *Value {
                return @ptrCast(this);
            }
            const Alloca = opaque {
                fn toValue(this: *@This()) *Value {
                    return @ptrCast(this);
                }
            };
            const Branch = opaque {
                fn toValue(this: *@This()) *Value {
                    return @ptrCast(this);
                }
            };
            const Call = opaque {
                const setCallingConvention = NativityLLVMCallSetCallingConvention;
                fn toValue(this: *@This()) *Value {
                    return @ptrCast(this);
                }
            };
            const Cast = opaque {
                const Type = enum(c_uint) {
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
            const ICmp = opaque {
                fn toValue(this: *@This()) *Value {
                    return @ptrCast(this);
                }
                const Kind = enum(c_uint) {
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
            const Load = opaque {
                fn toValue(this: *@This()) *Value {
                    return @ptrCast(this);
                }
            };
            const PhiNode = opaque {
                fn toValue(this: *@This()) *Value {
                    return @ptrCast(this);
                }
            };
            const Store = opaque {
                fn toValue(this: *@This()) *Value {
                    return @ptrCast(this);
                }
            };
            const Ret = opaque {
                fn toValue(this: *@This()) *Value {
                    return @ptrCast(this);
                }
            };
            const Unreachable = opaque {
                fn toValue(this: *@This()) *Value {
                    return @ptrCast(this);
                }
            };

            const Error = error{
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

        const Constant = opaque {
            const Int = opaque {
                fn toValue(this: *@This()) *Value {
                    return @ptrCast(this);
                }
                fn toConstant(this: *@This()) *Constant {
                    return @ptrCast(this);
                }
            };
            const GlobalVariable = opaque {
                fn toValue(this: *@This()) *Value {
                    return @ptrCast(this);
                }
                fn toConstant(this: *@This()) *Constant {
                    return @ptrCast(this);
                }
            };
            const Undefined = opaque {
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
        };
        const InlineAssembly = opaque {
            const Dialect = enum(c_uint) {
                @"at&t",
                intel,
            };
            const get = NativityLLVMGetInlineAssembly;
            fn toValue(this: *@This()) *Value {
                return @ptrCast(this);
            }
        };
        const Error = error{
            constant_struct,
            constant_int,
            constant_array,
            inline_assembly,
            global_variable,
            intrinsic,
        };
    };

    fn getType(llvm: *LLVM, type_index: Compilation.Type.Index) !*LLVM.Type {
        if (llvm.type_map.get(type_index)) |llvm_type| {
            return llvm_type;
        } else {
            const sema_type = llvm.sema.types.array.get(type_index);

            const llvm_type: *LLVM.Type = switch (sema_type.*) {
                .function => |function_prototype_index| blk: {
                    const sema_function_prototype = llvm.sema.types.function_prototypes.get(function_prototype_index);
                    const llvm_return_type = try llvm.getType(sema_function_prototype.return_type);
                    var parameter_types = try ArrayList(*LLVM.Type).initCapacity(llvm.allocator, sema_function_prototype.arguments.items.len);

                    for (sema_function_prototype.arguments.items) |sema_argument_index| {
                        const sema_argument = llvm.sema.values.declarations.get(sema_argument_index);
                        const sema_argument_type = sema_argument.type.resolved;

                        switch (llvm.sema.types.array.get(sema_argument_type).*) {
                            .integer, .pointer, .@"enum" => try parameter_types.append(llvm.allocator, try llvm.getType(sema_argument_type)),
                            .slice => |slice| {
                                const pointer_type = try llvm.getType(llvm.sema.map.pointers.get(.{
                                    .many = true,
                                    .@"const" = slice.@"const",
                                    .termination = slice.termination,
                                    .element_type = slice.element_type,
                                }).?);
                                const usize_type = try llvm.getType(Compilation.Type.usize);
                                try parameter_types.append(llvm.allocator, pointer_type);
                                try parameter_types.append(llvm.allocator, usize_type);
                            },
                            .@"struct" => |struct_index| {
                                const struct_type = llvm.sema.types.structs.get(struct_index);
                                if (!struct_type.backing_type.invalid) {
                                    unreachable;
                                } else {
                                    for (struct_type.fields.items) |field_index| {
                                        const field = llvm.sema.types.container_fields.get(field_index);
                                        const debug_type = try llvm.getType(field.type);
                                        try parameter_types.append(llvm.allocator, debug_type);
                                    }
                                }
                            },
                            else => |t| @panic(@tagName(t)),
                        }
                        // arg_types.appendAssumeCapacity(llvm_argument_type);
                    }

                    const is_var_args = false;
                    const llvm_function_type = LLVM.Context.getFunctionType(llvm_return_type, parameter_types.items.ptr, parameter_types.items.len, is_var_args) orelse return Type.Error.function;
                    break :blk llvm_function_type.toType();
                },
                .integer => |integer| blk: {
                    const llvm_integer_type = llvm.context.getIntegerType(integer.bit_count) orelse return Type.Error.integer;
                    break :blk llvm_integer_type.toType();
                },
                .slice => |slice| blk: {
                    const sema_slice_pointer = Compilation.Type.Pointer{
                        .element_type = slice.element_type,
                        .many = true,
                        .@"const" = slice.@"const",
                        .termination = slice.termination,
                    };
                    const sema_pointer_type = llvm.sema.map.pointers.get(sema_slice_pointer).?;
                    const llvm_pointer_type = try llvm.getType(sema_pointer_type);
                    const llvm_usize_type = try llvm.getType(Compilation.Type.usize);
                    const slice_types = [_]*Type{ llvm_pointer_type, llvm_usize_type };
                    const name = [_]u8{};
                    const is_packed = false;
                    const struct_type = llvm.context.createStructType(&slice_types, slice_types.len, &name, name.len, is_packed) orelse return Type.Error.@"struct";
                    break :blk struct_type.toType();
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
                .@"struct" => |struct_type_index| blk: {
                    const sema_struct_type = llvm.sema.types.structs.get(struct_type_index);
                    switch (sema_struct_type.backing_type.invalid) {
                        true => {
                            var field_type_list = try ArrayList(*LLVM.Type).initCapacity(llvm.allocator, sema_struct_type.fields.items.len);
                            for (sema_struct_type.fields.items) |sema_field_index| {
                                const sema_field = llvm.sema.types.container_fields.get(sema_field_index);
                                const llvm_type = try llvm.getType(sema_field.type);
                                field_type_list.appendAssumeCapacity(llvm_type);
                            }

                            const struct_name: []const u8 = if (llvm.sema.map.types.get(type_index)) |declaration_index| b: {
                                const declaration = llvm.sema.values.declarations.get(declaration_index);
                                const name = llvm.sema.getName(declaration.name).?;
                                break :b name;
                            } else "anonymous_struct";
                            const is_packed = true;
                            const struct_type = llvm.context.createStructType(field_type_list.items.ptr, field_type_list.items.len, struct_name.ptr, struct_name.len, is_packed) orelse return Type.Error.@"struct";

                            break :blk struct_type.toType();
                        },
                        else => |b| @panic(if (b) "true" else "false"),
                    }
                },
                .@"enum" => |enum_index| blk: {
                    const enum_type = llvm.sema.types.enums.get(enum_index);
                    switch (enum_type.backing_type.invalid) {
                        true => {
                            const field_count = enum_type.fields.items.len;
                            const bit_count = @bitSizeOf(@TypeOf(field_count)) - @clz(field_count);
                            const real_bit_count: u32 = if (bit_count <= 8) 8 else if (bit_count <= 16) 16 else if (bit_count <= 32) 32 else if (bit_count <= 64) 64 else unreachable;
                            const llvm_integer_type = llvm.context.getIntegerType(real_bit_count) orelse return Type.Error.integer;
                            break :blk llvm_integer_type.toType();
                        },
                        false => break :blk try llvm.getType(enum_type.backing_type),
                    }
                },
                .optional => |optional| blk: {
                    switch (llvm.sema.types.array.get(optional.element_type).*) {
                        .pointer => |pointer| {
                            _ = pointer;

                            unreachable;
                        },
                        else => {
                            const element_type = try llvm.getType(optional.element_type);
                            const selector_type = try llvm.getType(Compilation.Type.boolean);
                            const optional_types = [2]*LLVM.Type{ element_type, selector_type };
                            const name = "optional_type";
                            const is_packed = false;
                            const struct_type = llvm.context.createStructType(&optional_types, optional_types.len, name, name.len, is_packed) orelse return Type.Error.@"struct";
                            break :blk struct_type.toType();
                        },
                    }
                },
                .bool => blk: {
                    const bit_count = 1;
                    const llvm_integer_type = llvm.context.getIntegerType(bit_count) orelse return Type.Error.integer;
                    break :blk llvm_integer_type.toType();
                },
                .array => |array| blk: {
                    const element_type = try llvm.getType(array.element_type);
                    const array_type = LLVM.Type.Array.get(element_type, array.element_count) orelse return Type.Error.array;
                    break :blk array_type.toType();
                },
                else => |t| @panic(@tagName(t)),
            };

            try llvm.type_map.putNoClobber(llvm.allocator, type_index, llvm_type);

            return llvm_type;
        }
    }

    fn emitDeclaration(llvm: *LLVM, declaration_index: Compilation.Declaration.Index, maybe_argument: ?*LLVM.Value.Argument) !*LLVM.Value {
        const sema_declaration = llvm.sema.values.declarations.get(declaration_index);
        const declaration_name = llvm.sema.getName(sema_declaration.name).?;

        const sema_declaration_type_index = sema_declaration.getType();

        const declaration_type = if (maybe_argument) |argument| blk: {
            const argument_value: *LLVM.Value = argument.toValue();
            break :blk argument_value.getType();
        } else try llvm.getType(sema_declaration_type_index);
        const is_volatile = false;

        const initial_value: ?*LLVM.Value = if (maybe_argument) |argument| blk: {
            assert(sema_declaration.init_value.invalid);
            const argument_value: *LLVM.Value = argument.toValue();
            argument_value.setName(declaration_name.ptr, declaration_name.len);
            break :blk argument_value;
        } else blk: {
            if (!sema_declaration.init_value.invalid) {
                assert(maybe_argument == null);
                break :blk switch (llvm.sema.values.array.get(sema_declaration.init_value).*) {
                    .undefined => null,
                    else => try llvm.emitValue(sema_declaration.init_value, sema_declaration.scope_type),
                };
            } else {
                assert(maybe_argument != null);
                break :blk null;
            }
        };

        const declaration_value: *Value = switch (sema_declaration.scope_type) {
            .local => blk: {
                const sema_declaration_type = llvm.sema.types.array.get(sema_declaration_type_index);
                const alloca_array_size: ?*LLVM.Value = switch (sema_declaration_type.*) {
                    else => null,
                    .array => |array| b: {
                        const is_signed = false;
                        const array_len = llvm.context.getConstantInt(64, array.element_count, is_signed) orelse unreachable;
                        break :b array_len.toValue();
                    },
                };

                const declaration_alloca = llvm.builder.createAlloca(declaration_type, address_space, alloca_array_size, declaration_name.ptr, declaration_name.len) orelse return LLVM.Value.Instruction.Error.alloca;
                const alloca_value: *LLVM.Value = declaration_alloca.toValue();

                const debug_declaration_type = try llvm.getDebugType(sema_declaration.getType());
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
                const local_variable = if (maybe_argument) |argument| b: {
                    const argument_index = argument.getIndex();
                    const parameter_variable = llvm.debug_info_builder.createParameterVariable(llvm.scope, declaration_name.ptr, declaration_name.len, argument_index + 1, llvm.file, sema_declaration.line, debug_declaration_type, always_preserve, flags) orelse unreachable;
                    break :b parameter_variable;
                } else b: {
                    // TODO:
                    const alignment = 0;
                    const auto_variable = llvm.debug_info_builder.createAutoVariable(llvm.scope, declaration_name.ptr, declaration_name.len, llvm.file, sema_declaration.line, debug_declaration_type, always_preserve, flags, alignment) orelse unreachable;
                    break :b auto_variable;
                };

                const insert_declare = llvm.debug_info_builder.insertDeclare(alloca_value, local_variable, llvm.context, sema_declaration.line, sema_declaration.column, (llvm.function.getSubprogram() orelse unreachable).toLocalScope().toScope(), llvm.builder.getInsertBlock() orelse unreachable);
                _ = insert_declare;

                if (initial_value) |init_value| {
                    const store = llvm.builder.createStore(init_value, alloca_value, is_volatile) orelse return LLVM.Value.Instruction.Error.store;
                    _ = store;
                }

                break :blk alloca_value;
            },
            .global => blk: {
                const is_constant = switch (sema_declaration.mutability) {
                    .@"const" => true,
                    .@"var" => false,
                };
                // TODO:
                const linkage = LLVM.Linkage.@"extern";
                const initializer: *LLVM.Value.Constant = if (initial_value) |value| value.toConstant() orelse unreachable else (declaration_type.getUndefined() orelse unreachable).toConstant();
                const thread_local_mode = LLVM.ThreadLocalMode.not_thread_local;
                const externally_initialized = false;
                const global_variable = llvm.module.addGlobalVariable(declaration_type, is_constant, linkage, initializer, declaration_name.ptr, declaration_name.len, null, thread_local_mode, address_space, externally_initialized) orelse return LLVM.Value.Error.constant_int;
                break :blk global_variable.toValue();
            },
            else => unreachable,
        };

        try llvm.declaration_map.putNoClobber(llvm.allocator, declaration_index, declaration_value);

        return declaration_value;
    }

    fn emitLValue(llvm: *LLVM, sema_value_index: Compilation.Value.Index, context: Compilation.ScopeType) anyerror!*LLVM.Value {
        const sema_value = llvm.sema.values.array.get(sema_value_index);

        switch (sema_value.*) {
            .declaration_reference => |declaration_reference| {
                const declaration_index = declaration_reference.value;
                return try llvm.getDeclaration(declaration_index);
            },
            .indexed_access => |indexed_access_index| {
                const indexed_access = llvm.sema.values.indexed_accesses.get(indexed_access_index);
                const indexed = try llvm.emitValue(indexed_access.indexed_expression, context);
                const index = try llvm.emitValue(indexed_access.index_expression, context);
                const indexed_value = llvm.sema.values.array.get(indexed_access.indexed_expression);
                const indexed_type = indexed_value.getType(llvm.sema);
                switch (llvm.sema.types.array.get(indexed_type).*) {
                    .pointer => |pointer| {
                        const element_type = try llvm.getType(pointer.element_type);
                        const is_signed = false;
                        const index_zero = llvm.context.getConstantInt(32, 0, is_signed) orelse unreachable;
                        const indices = [2]*LLVM.Value{ index_zero.toValue(), index };
                        const in_bounds = true;
                        const gep = llvm.builder.createGEP(element_type, indexed, &indices, indices.len, "gep", "gep".len, in_bounds) orelse return LLVM.Value.Instruction.Error.gep;
                        return gep;
                    },
                    else => |t| @panic(@tagName(t)),
                }
            },
            else => |t| @panic(@tagName(t)),
        }
    }

    fn getDeclaration(llvm: *LLVM, declaration_index: Compilation.Declaration.Index) anyerror!*LLVM.Value {
        if (llvm.declaration_map.get(declaration_index)) |declaration_value| {
            return declaration_value;
        } else {
            // This is a global variable
            const declaration_value = try llvm.emitDeclaration(declaration_index, null);
            return declaration_value;
        }
    }

    fn emitValue(llvm: *LLVM, sema_value_index: Compilation.Value.Index, context: Compilation.ScopeType) anyerror!*LLVM.Value {
        const sema_value = llvm.sema.values.array.get(sema_value_index);
        const sema_type = sema_value.getType(llvm.sema);

        switch (sema_value.*) {
            .integer => |integer| {
                const bit_count = llvm.sema.types.array.get(integer.type).integer.bit_count;
                const constant_int = llvm.context.getConstantInt(bit_count, integer.value, switch (integer.signedness) {
                    .unsigned => false,
                    .signed => true,
                }) orelse return LLVM.Value.Error.constant_int;
                return constant_int.toValue();
            },
            .binary_operation => |binary_operation_index| {
                const binary_operation = llvm.sema.values.binary_operations.get(binary_operation_index);

                const sema_left_value = llvm.sema.values.array.get(binary_operation.left);
                const sema_left_type_index = sema_left_value.getType(llvm.sema);
                const sema_right_type_index = llvm.sema.values.array.get(binary_operation.right).getType(llvm.sema);
                assert(sema_left_type_index.eq(sema_right_type_index));
                const sema_left_type = llvm.sema.types.array.get(sema_left_type_index);

                const expected_left_type = try llvm.getType(sema_left_type_index);

                const left = try llvm.emitValue(binary_operation.left, context);
                assert(left.getType() == expected_left_type);
                const right = try llvm.emitValue(binary_operation.right, context);
                assert(right.getType() == expected_left_type);

                switch (binary_operation.id) {
                    .compare_less_than,
                    .compare_greater_or_equal,
                    .compare_equal,
                    => {
                        switch (sema_left_type.*) {
                            .integer => |integer| {
                                const integer_comparison: LLVM.Value.Instruction.ICmp.Kind = switch (integer.signedness) {
                                    .signed => switch (binary_operation.id) {
                                        .compare_less_than => .slt,
                                        .compare_greater_or_equal => .sge,
                                        .compare_equal => .eq,
                                        else => |t| @panic(@tagName(t)),
                                    },
                                    .unsigned => switch (binary_operation.id) {
                                        .compare_less_than => .ult,
                                        .compare_greater_or_equal => .uge,
                                        .compare_equal => .eq,
                                        else => |t| @panic(@tagName(t)),
                                    },
                                };
                                const icmp = llvm.builder.createICmp(integer_comparison, left, right, "cmp", "cmp".len) orelse return LLVM.Value.Instruction.Error.icmp;
                                return icmp;
                            },
                            else => |t| @panic(@tagName(t)),
                        }
                    },
                    .add,
                    .sub,
                    .mul,
                    .shift_left,
                    => {
                        switch (sema_left_type.*) {
                            .integer => |integer_type| {
                                const result = try llvm.arithmeticIntegerBinaryOperation(left, right, binary_operation.id, integer_type, "binary_operation");
                                return result;
                            },
                            else => |t| @panic(@tagName(t)),
                        }
                    },
                    .div => {
                        switch (sema_left_type.*) {
                            .integer => |integer_type| {
                                const is_exact = false;
                                const result = switch (integer_type.signedness) {
                                    .unsigned => llvm.builder.createUDiv(left, right, "udiv", "udiv".len, is_exact) orelse return LLVM.Value.Instruction.Error.udiv,
                                    .signed => llvm.builder.createSDiv(left, right, "sdiv", "sdiv".len, is_exact) orelse return LLVM.Value.Instruction.Error.sdiv,
                                };

                                return result;
                            },
                            else => |t| @panic(@tagName(t)),
                        }
                    },
                    .mod => {
                        switch (sema_left_type.*) {
                            .integer => |integer_type| {
                                const result = switch (integer_type.signedness) {
                                    .unsigned => llvm.builder.createURem(left, right, "urem", "urem".len) orelse return LLVM.Value.Instruction.Error.udiv,
                                    .signed => llvm.builder.createSRem(left, right, "srem", "srem".len) orelse return LLVM.Value.Instruction.Error.sdiv,
                                };

                                return result;
                            },
                            else => |t| @panic(@tagName(t)),
                        }
                    },
                    .shift_right => {
                        switch (sema_left_type.*) {
                            .integer => |integer_type| {
                                const is_exact = false;
                                const result = switch (integer_type.signedness) {
                                    .unsigned => llvm.builder.createLogicalShiftRight(left, right, "logical_shift_right", "logical_shift_right".len, is_exact) orelse return LLVM.Value.Instruction.Error.logical_shift_right,
                                    .signed => llvm.builder.createArithmeticShiftRight(left, right, "arithmetic_shift_right", "arithmetic_shift_right".len, is_exact) orelse return LLVM.Value.Instruction.Error.arithmetic_shift_right,
                                };

                                return result;
                            },
                            else => |t| @panic(@tagName(t)),
                        }
                    },
                    .bit_xor => {
                        const xor = llvm.builder.createXor(left, right, "xor", "xor".len) orelse return LLVM.Value.Instruction.Error.xor;
                        return xor;
                    },
                    .bit_and => {
                        const result = llvm.builder.createAnd(left, right, "and", "and".len) orelse return LLVM.Value.Instruction.Error.@"and";
                        return result;
                    },
                    .bit_or => {
                        const result = llvm.builder.createOr(left, right, "or", "or".len) orelse return LLVM.Value.Instruction.Error.@"or";
                        return result;
                    },
                    else => |t| @panic(@tagName(t)),
                }
            },
            .declaration_reference => |declaration_reference| {
                const declaration_alloca = try llvm.getDeclaration(declaration_reference.value);
                const is_volatile = false;
                const load_type = try llvm.getType(declaration_reference.getType(llvm.sema));
                const load = llvm.builder.createLoad(load_type, declaration_alloca, is_volatile, "declaration_reference", "declaration_reference".len) orelse return LLVM.Value.Instruction.Error.load;
                return load.toValue();
            },
            .intrinsic => |intrinsic_index| return try llvm.emitIntrinsic(intrinsic_index, context),
            .enum_field => |enum_field_index| {
                const enum_field = llvm.sema.types.enum_fields.get(enum_field_index);
                switch (llvm.sema.types.array.get(enum_field.parent).*) {
                    .@"enum" => |enum_index| {
                        const enum_type = llvm.sema.types.enums.get(enum_index);
                        const backing_type = llvm.sema.types.array.get(enum_type.backing_type);
                        switch (backing_type.*) {
                            .integer => |integer| {
                                const is_signed = switch (integer.signedness) {
                                    .signed => true,
                                    .unsigned => false,
                                };
                                assert(!is_signed);
                                const enum_value = llvm.context.getConstantInt(integer.bit_count, enum_field.value, is_signed) orelse unreachable;
                                return enum_value.toValue();
                            },
                            else => |t| @panic(@tagName(t)),
                        }
                    },
                    else => |t| @panic(@tagName(t)),
                }
            },
            .unary_operation => |unary_operation_index| {
                const unary_operation = llvm.sema.values.unary_operations.get(unary_operation_index);
                switch (unary_operation.id) {
                    .pointer_dereference => {
                        const value = try llvm.emitValue(unary_operation.value, context);
                        const is_volatile = false;
                        const load = llvm.builder.createLoad(try llvm.getType(unary_operation.type), value, is_volatile, "pointer_dereference", "pointer_dereference".len) orelse return LLVM.Value.Instruction.Error.load;
                        return load.toValue();
                    },
                    .address_of => {
                        const pointer = try llvm.emitLValue(unary_operation.value, context);
                        return pointer;
                    },
                    else => |t| @panic(@tagName(t)),
                }
            },
            .call => |call_index| {
                assert(context == .local);
                return try llvm.emitCall(call_index, context);
            },
            .function_definition => |function_definition_index| {
                return llvm.function_definition_map.get(function_definition_index).?.toValue();
            },
            .container_initialization => |container_initialization_index| {
                const container_initialization = llvm.sema.values.container_initializations.get(container_initialization_index);
                const container_type = llvm.sema.types.array.get(container_initialization.type);
                const llvm_type = try llvm.getType(container_initialization.type);

                switch (container_type.*) {
                    .@"struct" => |struct_index| {
                        const struct_type = llvm.sema.types.structs.get(struct_index);
                        switch (struct_type.backing_type.invalid) {
                            true => {
                                switch (context) {
                                    .global => {
                                        var initialization_values = try ArrayList(*LLVM.Value.Constant).initCapacity(llvm.allocator, container_initialization.field_initializations.items.len);

                                        for (container_initialization.field_initializations.items) |field_value_index| {
                                            const value = try llvm.emitValue(field_value_index, context);
                                            initialization_values.appendAssumeCapacity(value.toConstant() orelse unreachable);
                                        }

                                        // TODO: fix
                                        const llvm_struct_type = llvm_type.toStruct() orelse unreachable;
                                        const type_declaration = llvm.sema.values.declarations.get(llvm.sema.map.types.get(container_initialization.type).?);
                                        const name = llvm.sema.getName(type_declaration.name).?;
                                        std.debug.print("Type: {s}\n", .{name});
                                        const constant_struct = llvm_struct_type.instantiate(initialization_values.items.ptr, initialization_values.items.len) orelse return LLVM.Value.Error.constant_struct;
                                        return constant_struct.toValue();
                                    },
                                    .local => {
                                        const alloca = llvm.builder.createAlloca(llvm_type, address_space, null, "struct_initialization", "struct initialization".len) orelse return LLVM.Value.Instruction.Error.alloca;

                                        const is_signed = false;

                                        for (struct_type.fields.items, container_initialization.field_initializations.items, 0..) |struct_field_index, field_initialization_value_index, index| {
                                            const struct_field = llvm.sema.types.container_fields.get(struct_field_index);
                                            const field_initialization = llvm.sema.values.array.get(field_initialization_value_index);
                                            const field_initialization_type = field_initialization.getType(llvm.sema);
                                            assert(field_initialization_type.eq(struct_field.type));
                                            const llvm_field_type = try llvm.getType(struct_field.type);
                                            const index_value = llvm.context.getConstantInt(32, index, is_signed) orelse unreachable;
                                            const indices = [_]*LLVM.Value{index_value.toValue()};
                                            const in_bounds = true;
                                            const gep = llvm.builder.createGEP(llvm_field_type, alloca.toValue(), &indices, indices.len, "gep", "gep".len, in_bounds) orelse return LLVM.Value.Instruction.Error.gep;
                                            const load = try llvm.emitValue(field_initialization_value_index, context);
                                            const is_volatile = false;
                                            const store = llvm.builder.createStore(load, gep, is_volatile) orelse return LLVM.Value.Instruction.Error.store;
                                            _ = store;
                                        }

                                        const is_volatile = false;
                                        const load = llvm.builder.createLoad(llvm_type, alloca.toValue(), is_volatile, "struct_init_load", "struct_init_load".len) orelse return LLVM.Value.Instruction.Error.load;
                                        return load.toValue();
                                    },
                                    else => unreachable,
                                }
                            },
                            false => switch (llvm.sema.types.array.get(struct_type.backing_type).*) {
                                else => |t| @panic(@tagName(t)),
                            },
                        }
                    },
                    else => |t| @panic(@tagName(t)),
                }
                // container_initialization.field_initializations.items
            },
            .slice_access => |slice_access_index| {
                const slice_access = llvm.sema.values.slice_accesses.get(slice_access_index);
                switch (llvm.sema.types.array.get(llvm.sema.values.array.get(slice_access.value).getType(llvm.sema)).*) {
                    .slice => |slice| {
                        _ = slice;

                        const slice_access_value = try llvm.emitValue(slice_access.value, context);
                        const index: c_uint = switch (slice_access.field) {
                            .ptr => 0,
                            .len => 1,
                        };
                        const name = switch (slice_access.field) {
                            .ptr => "slice_access_ptr",
                            .len => "slice_access_len",
                        };
                        const indices = [1]c_uint{index};
                        const len_value = llvm.builder.createExtractValue(slice_access_value, &indices, indices.len, name.ptr, name.len) orelse return LLVM.Value.Instruction.Error.extract_value;
                        return len_value;
                    },
                    else => |t| @panic(@tagName(t)),
                }
                // const llvm_type = try llvm.getType(slice_access.type);
            },
            .field_access => |field_access_index| {
                const field_access = llvm.sema.values.field_accesses.get(field_access_index);
                const sema_field = llvm.sema.types.container_fields.get(field_access.field);
                const result_type = try llvm.getType(sema_field.type);
                const value = try llvm.emitValue(field_access.declaration_reference, context);
                _ = result_type;
                // extern fn NativityLLVMBuilderCreateGEP(builder: *LLVM.Builder, type: *LLVM.Type, pointer: *LLVM.Value, index_ptr: [*]const *LLVM.Value, index_count: usize, name_ptr: [*]const u8, name_len: usize, in_bounds: bool) ?*LLVM.Value;
                const indices = [1]u32{sema_field.index};
                const result = llvm.builder.createExtractValue(value, &indices, indices.len, "field_access", "field_access".len) orelse return LLVM.Value.Instruction.Error.extract_value;
                return result;
            },
            .optional_check => |optional_check_index| {
                const optional_check = llvm.sema.values.optional_checks.get(optional_check_index);
                const sema_optional_value = llvm.sema.values.array.get(optional_check.value);
                const optional_type_index = sema_optional_value.getType(llvm.sema);

                switch (llvm.sema.types.array.get(optional_type_index).*) {
                    .optional => |optional| switch (llvm.sema.types.array.get(optional.element_type).*) {
                        .pointer => |pointer| {
                            _ = pointer;

                            @panic("TODO: optional check for pointer");
                        },
                        else => {
                            const optional_value = try llvm.emitValue(optional_check.value, context);
                            const indices = [1]c_uint{1};
                            const result = llvm.builder.createExtractValue(optional_value, &indices, indices.len, "optional_check", "optional_check".len) orelse return LLVM.Value.Instruction.Error.extract_value;
                            return result;
                        },
                    },
                    else => |t| @panic(@tagName(t)),
                }
            },
            .optional_unwrap => |optional_unwrap_index| {
                const optional_unwrap = llvm.sema.values.optional_unwraps.get(optional_unwrap_index);
                const sema_optional_value = llvm.sema.values.array.get(optional_unwrap.value);
                const optional_type_index = sema_optional_value.getType(llvm.sema);
                switch (llvm.sema.types.array.get(optional_type_index).*) {
                    .optional => |optional| switch (llvm.sema.types.array.get(optional.element_type).*) {
                        .pointer => |pointer| {
                            _ = pointer;

                            @panic("TODO: optional check for pointer");
                        },
                        else => {
                            const optional_value = try llvm.emitValue(optional_unwrap.value, context);
                            const indices = [1]c_uint{0};
                            const result = llvm.builder.createExtractValue(optional_value, &indices, indices.len, "optional_unwrap", "optional_unwrap".len) orelse return LLVM.Value.Instruction.Error.extract_value;
                            return result;
                        },
                    },
                    else => |t| @panic(@tagName(t)),
                }
            },
            .optional_null_literal => |optional_type_index| {
                const optional_type = try llvm.getType(optional_type_index);
                const optional_undefined = optional_type.getUndefined() orelse unreachable;

                const indices = [1]c_uint{1};
                const is_signed = false;
                const null_value = llvm.context.getConstantInt(1, 0, is_signed) orelse unreachable;
                const insert_value = llvm.builder.createInsertValue(optional_undefined.toValue(), null_value.toValue(), &indices, indices.len, "optional_null_literal", "optional_null_literal".len) orelse return LLVM.Value.Instruction.Error.insert_value;
                _ = insert_value;

                return optional_undefined.toValue();
            },
            .slice => |slice_expression_index| {
                const slice_expression = llvm.sema.values.slices.get(slice_expression_index);
                const sliceable = try llvm.emitValue(slice_expression.sliceable, context);
                const slice_expression_type = try llvm.getType(slice_expression.type);
                const sema_sliceable = llvm.sema.values.array.get(slice_expression.sliceable);
                const sema_sliceable_type_index = sema_sliceable.getType(llvm.sema);
                const sema_sliceable_type = llvm.sema.types.array.get(sema_sliceable_type_index);
                const start_value = try llvm.emitValue(slice_expression.range.start, context);
                const result = slice_expression_type.getUndefined() orelse unreachable;

                switch (sema_sliceable_type.*) {
                    .slice => |slice| {
                        const indices = [1]c_uint{0};
                        const sliceable_ptr = llvm.builder.createExtractValue(sliceable, &indices, indices.len, "sliceable_ptr", "sliceable_ptr".len) orelse return LLVM.Value.Instruction.Error.extract_value;
                        const element_type = try llvm.getType(slice.element_type);
                        const ptr_indices = [1]*LLVM.Value{start_value};
                        const in_bounds = true;
                        const offset_ptr = llvm.builder.createGEP(element_type, sliceable_ptr, &ptr_indices, ptr_indices.len, "offset_ptr", "offset_ptr".len, in_bounds) orelse unreachable;
                        const insert_slice_ptr = llvm.builder.createInsertValue(result.toValue(), offset_ptr, &indices, indices.len, "insert_slice_ptr", "insert_slice_ptr".len) orelse unreachable;
                        _ = insert_slice_ptr;

                        switch (slice_expression.range.end.invalid) {
                            true => {
                                const no_unsigned_wrapping = true;
                                const no_signed_wrapping = false;
                                const len_indices = [1]c_uint{1};
                                const sliceable_len = llvm.builder.createExtractValue(sliceable, &len_indices, len_indices.len, "sliceable_len", "sliceable_len".len) orelse return LLVM.Value.Instruction.Error.extract_value;
                                const len_sub = llvm.builder.createSub(sliceable_len, start_value, "slice_len_arithmetic", "slice_len_arithmetic".len, no_unsigned_wrapping, no_signed_wrapping) orelse return LLVM.Value.Instruction.Error.add;
                                const insert_slice_len = llvm.builder.createInsertValue(result.toValue(), len_sub, &len_indices, len_indices.len, "insert_slice_len", "insert_slice_len".len) orelse unreachable;
                                _ = insert_slice_len;
                                return result.toValue();
                            },
                            false => unreachable,
                        }
                    },
                    .pointer => |pointer| {
                        const offset_indices = [1]*LLVM.Value{start_value};
                        const ptr_indices = [1]c_uint{0};
                        const element_type = try llvm.getType(pointer.element_type);
                        const in_bounds = true;
                        const offset_ptr = llvm.builder.createGEP(element_type, sliceable, &offset_indices, offset_indices.len, "offset_ptr", "offset_ptr".len, in_bounds) orelse unreachable;
                        const insert_slice_ptr = llvm.builder.createInsertValue(result.toValue(), offset_ptr, &ptr_indices, ptr_indices.len, "insert_slice_ptr", "insert_slice_ptr".len) orelse unreachable;
                        _ = insert_slice_ptr;

                        switch (slice_expression.range.end.invalid) {
                            true => {
                                switch (pointer.many) {
                                    true => @panic("Only pointer to array"),
                                    false => {
                                        switch (llvm.sema.types.array.get(pointer.element_type).*) {
                                            .array => |array| {
                                                const len_indices = [1]c_uint{1};
                                                const is_signed = false;
                                                const constant_len = llvm.context.getConstantInt(64, array.element_count, is_signed) orelse unreachable;
                                                const no_unsigned_wrapping = true;
                                                const no_signed_wrapping = false;
                                                const len_sub = llvm.builder.createSub(constant_len.toValue(), start_value, "slice_len_arithmetic", "slice_len_arithmetic".len, no_unsigned_wrapping, no_signed_wrapping) orelse return LLVM.Value.Instruction.Error.add;
                                                const insert_slice_len = llvm.builder.createInsertValue(result.toValue(), len_sub, &len_indices, len_indices.len, "insert_slice_len", "insert_slice_len".len) orelse unreachable;
                                                _ = insert_slice_len;
                                                return result.toValue();
                                            },
                                            else => |t| @panic(@tagName(t)),
                                        }
                                    },
                                }
                            },
                            false => unreachable,
                        }
                        unreachable;
                    },
                    else => |t| @panic(@tagName(t)),
                }
            },
            .bool => |boolean| {
                const is_signed = false;
                const boolean_constant = llvm.context.getConstantInt(1, @intFromBool(boolean), is_signed) orelse unreachable;
                return boolean_constant.toValue();
            },
            .string_literal => |sema_string_literal| {
                const string = llvm.sema.getName(sema_string_literal.hash) orelse unreachable;
                const llvm_const_string = llvm.builder.createGlobalStringPointer(string.ptr, string.len, "string_literal", "string_literal".len, address_space, llvm.module) orelse unreachable;
                return llvm_const_string.toValue();
            },
            .indexed_access => |indexed_access_index| {
                const indexed_access = llvm.sema.values.indexed_accesses.get(indexed_access_index);
                const indexed_value = llvm.sema.values.array.get(indexed_access.indexed_expression);
                const indexed_type = indexed_value.getType(llvm.sema);
                const index = try llvm.emitValue(indexed_access.index_expression, context);
                const indexed = try llvm.emitValue(indexed_access.indexed_expression, context);

                switch (llvm.sema.types.array.get(indexed_type).*) {
                    .pointer => |pointer| {
                        switch (pointer.many) {
                            true => {
                                const element_type = try llvm.getType(pointer.element_type);
                                const indices = [_]*LLVM.Value{index};
                                const in_bounds = true;
                                const pointer_access = llvm.builder.createGEP(element_type, indexed, &indices, indices.len, "indexed_pointer_access", "indexed_pointer_access".len, in_bounds) orelse unreachable;

                                const result_type = try llvm.getType(sema_type);
                                const is_volatile = false;
                                const name = "indexed_pointer_load";
                                const load = llvm.builder.createLoad(result_type, pointer_access, is_volatile, name, name.len) orelse return LLVM.Value.Instruction.Error.load;
                                const load_value = load.toValue();
                                return load_value;
                            },
                            false => unreachable,
                        }
                    },
                    .slice => |slice| {
                        const slice_indices = [1]c_uint{0};
                        const slice_ptr = llvm.builder.createExtractValue(indexed, &slice_indices, slice_indices.len, "slice_ptr", "slice_ptr".len) orelse return LLVM.Value.Instruction.Error.extract_value;
                        const element_type = try llvm.getType(slice.element_type);
                        const indices = [_]*LLVM.Value{index};
                        const in_bounds = true;
                        const pointer_access = llvm.builder.createGEP(element_type, slice_ptr, &indices, indices.len, "indexed_pointer_access", "indexed_pointer_access".len, in_bounds) orelse unreachable;
                        const result_type = try llvm.getType(sema_type);
                        const is_volatile = false;
                        const name = "indexed_pointer_load";
                        const load = llvm.builder.createLoad(result_type, pointer_access, is_volatile, name, name.len) orelse return LLVM.Value.Instruction.Error.load;

                        const load_value = load.toValue();
                        assert(load_value.getType() == result_type);
                        return load.toValue();
                    },
                    else => |t| @panic(@tagName(t)),
                }
            },
            .character_literal => |ch| {
                const is_signed = false;
                const constant = llvm.context.getConstantInt(8, ch, is_signed) orelse unreachable;
                return constant.toValue();
            },
            .array_initialization => |array_initialization_index| {
                const array_initialization = llvm.sema.values.container_initializations.get(array_initialization_index);
                const initialization_type = try llvm.getType(array_initialization.type);
                const array_type = initialization_type.toArray() orelse unreachable;
                const array_element_type = array_type.getElementType() orelse unreachable;
                const sema_array_element_type = switch (llvm.sema.types.array.get(array_initialization.type).*) {
                    .array => |array| array.element_type,
                    else => |t| @panic(@tagName(t)),
                };

                if (array_initialization.is_comptime) {
                    var list = try ArrayList(*LLVM.Value.Constant).initCapacity(llvm.allocator, array_initialization.field_initializations.items.len);

                    for (array_initialization.field_initializations.items) |element_initialization| {
                        const value = try llvm.emitValue(element_initialization, context);
                        const sema_value_type = llvm.sema.values.array.get(element_initialization).getType(llvm.sema);
                        assert(sema_value_type.eq(sema_array_element_type));
                        const value_type = value.getType();
                        if (!value_type.compare(array_element_type)) {
                            unreachable;
                        }
                        const constant = value.toConstant() orelse unreachable;
                        list.appendAssumeCapacity(constant);
                    }

                    const constant_array = array_type.getConstant(list.items.ptr, list.items.len) orelse unreachable;
                    return constant_array.toValue();
                } else {
                    const array_undefined = initialization_type.getUndefined() orelse unreachable;

                    for (array_initialization.field_initializations.items, 0..) |element_initialization, index| {
                        const value = try llvm.emitValue(element_initialization, context);
                        const indices = [1]c_uint{@intCast(index)};
                        const insert_array_element = llvm.builder.createInsertValue(array_undefined.toValue(), value, &indices, indices.len, "insert_array_element", "insert_array_element".len) orelse unreachable;
                        _ = insert_array_element;
                    }

                    return array_undefined.toValue();
                }
            },
            else => |t| @panic(@tagName(t)),
        }
    }

    fn emitCall(llvm: *LLVM, call_index: Compilation.Call.Index, context: Compilation.ScopeType) !*LLVM.Value {
        assert(context == .local);
        var argument_buffer: [32]*LLVM.Value = undefined;
        const sema_call = llvm.sema.values.calls.get(call_index);
        const sema_call_arguments = llvm.sema.values.argument_lists.get(sema_call.arguments).array.items;
        const argument_count = sema_call_arguments.len;
        const arguments = argument_buffer[0..argument_count];

        const sema_type = llvm.sema.values.array.get(sema_call.value).getType(llvm.sema);

        switch (llvm.sema.values.array.get(sema_call.value).*) {
            .function_definition => |function_definition_index| {
                const function_definition = llvm.sema.types.function_definitions.get(function_definition_index);
                assert(function_definition.prototype.eq(sema_type));

                const function_prototype_type = llvm.sema.types.array.get(function_definition.prototype);
                const function_prototype = llvm.sema.types.function_prototypes.get(function_prototype_type.function);
                const declaration_index = llvm.sema.map.function_definitions.get(function_definition_index).?;
                const declaration = llvm.sema.values.declarations.get(declaration_index);
                const declaration_name = llvm.sema.getName(declaration.name).?;
                std.debug.print("Call to {s}\n", .{declaration_name});
                if (equal(u8, declaration_name, "count_slice_byte_count")) {
                    //@breakpoint();
                }

                const callee = try llvm.emitValue(sema_call.value, context);

                for (function_prototype.arguments.items, sema_call_arguments, arguments) |argument_declaration_index, sema_call_value_index, *argument| {
                    const argument_declaration = llvm.sema.values.declarations.get(argument_declaration_index);
                    const argument_type = argument_declaration.getType();
                    switch (llvm.sema.types.array.get(argument_type).*) {
                        .integer => |_| {
                            argument.* = try llvm.emitValue(sema_call_value_index, context);
                        },
                        .@"struct" => |struct_index| {
                            const struct_type = llvm.sema.types.structs.get(struct_index);
                            if (!struct_type.backing_type.invalid) {
                                unreachable;
                            } else {
                                unreachable;
                            }
                        },
                        else => |t| @panic(@tagName(t)),
                    }
                    // _ = argument_declaration_index;
                    // const call_argument = llvm.sema.values.array.get(sema_call_value_index);
                    // const call_argument_type = call_argument.getType(llvm.sema);
                    // const cat = llvm.sema.types.array.get(call_argument_type);
                    // const argument_declaration = llvm.sema.values.declarations.get(argument_declaration_index);
                    // const argument_declaration_type = argument_declaration.getType();
                    // const argument_type = try llvm.getType(argument_declaration_type);

                    // if (!call_argument_type.eq(argument_declaration_type)) {
                    //     switch (llvm.sema.types.array.get(argument_declaration_type).*) {
                    //         .slice => |slice| {
                    //             _ = slice;
                    //
                    //             const result = argument_type.getUndefined() orelse unreachable;
                    //
                    //             const ptr_indices = [1]c_uint{0};
                    //             const extract_slice_ptr = llvm.builder.createExtractValue(argument.*, &ptr_indices, ptr_indices.len, "extract_slice_ptr", "extract_slice_ptr".len) orelse unreachable;
                    //             const insert_slice_ptr = llvm.builder.createInsertValue(result.toValue(), extract_slice_ptr, &ptr_indices, ptr_indices.len, "insert_slice_ptr", "insert_slice_ptr".len) orelse unreachable;
                    //             _ = insert_slice_ptr;
                    //             const len_indices = [1]c_uint{1};
                    //             const extract_slice_len = llvm.builder.createExtractValue(argument.*, &len_indices, len_indices.len, "extract_slice_ptr", "extract_slice_ptr".len) orelse unreachable;
                    //             const insert_slice_len = llvm.builder.createInsertValue(result.toValue(), extract_slice_len, &len_indices, len_indices.len, "insert_slice_len", "insert_slice_len".len) orelse unreachable;
                    //             _ = insert_slice_len;
                    //             argument.* = result.toValue();
                    //         },
                    //         else => |t| @panic(@tagName(t)),
                    //     }
                    //     // argument.* = llvm.builder.createCast(.bitcast, argument.*, argument_type, "arg_bitcast", "arg_bitcast".len) orelse unreachable;
                    // }
                }

                const function = callee.toFunction() orelse unreachable;
                const llvm_calling_convention = function.getCallingConvention();
                const name = if (sema_call.type.eq(Compilation.Type.void) or sema_call.type.eq(Compilation.Type.noreturn)) "" else "call";
                const callee_type = try llvm.getType(sema_type);
                const function_type = callee_type.toFunction() orelse unreachable;
                const call = llvm.builder.createCall(function_type, callee, arguments.ptr, arguments.len, name.ptr, name.len, null) orelse return LLVM.Value.Instruction.Error.call;
                call.setCallingConvention(llvm_calling_convention);

                return call.toValue();
            },
            else => |t| @panic(@tagName(t)),
        }
    }

    fn arithmeticIntegerBinaryOperation(llvm: *LLVM, left: *LLVM.Value, right: *LLVM.Value, binary_operation: Compilation.BinaryOperation.Id, sema_integer_type: Compilation.Type.Integer, name: []const u8) !*LLVM.Value {
        var no_signed_wrapping = false;
        var no_unsigned_wrapping = false;

        switch (sema_integer_type.signedness) {
            .signed => no_signed_wrapping = true,
            .unsigned => no_unsigned_wrapping = true,
        }

        assert(left.getType().isInteger());
        assert(right.getType().isInteger());

        return switch (binary_operation) {
            .add => llvm.builder.createAdd(left, right, name.ptr, name.len, no_unsigned_wrapping, no_signed_wrapping) orelse return LLVM.Value.Instruction.Error.add,
            .sub => llvm.builder.createSub(left, right, name.ptr, name.len, no_unsigned_wrapping, no_signed_wrapping) orelse return LLVM.Value.Instruction.Error.add,
            .mul => llvm.builder.createMultiply(left, right, name.ptr, name.len, no_unsigned_wrapping, no_signed_wrapping) orelse return LLVM.Value.Instruction.Error.multiply,
            .shift_left => llvm.builder.createShiftLeft(left, right, name.ptr, name.len, no_unsigned_wrapping, no_signed_wrapping) orelse return LLVM.Value.Instruction.Error.shift_left,
            else => |t| @panic(@tagName(t)),
        };
    }

    fn emitStatement(llvm: *LLVM, sema_statement_index: Compilation.Statement.Index, context: Compilation.ScopeType) anyerror!void {
        const sema_statement = llvm.sema.values.statements.get(sema_statement_index);
        const sema_statement_value = llvm.sema.values.array.get(sema_statement.value);

        llvm.builder.setCurrentDebugLocation(llvm.context, sema_statement.line + 1, sema_statement.column + 1, llvm.scope, llvm.function);

        switch (sema_statement_value.*) {
            .declaration => |sema_declaration_index| {
                _ = try llvm.emitDeclaration(sema_declaration_index, null);
            },
            .@"return" => |return_index| {
                const return_expression = llvm.sema.values.returns.get(return_index);
                const sema_value_return_type = llvm.sema.values.array.get(return_expression.value).getType(llvm.sema);
                const sema_function = llvm.sema.types.function_definitions.get(llvm.sema_function);
                const sema_function_prototype = llvm.sema.types.function_prototypes.get(llvm.sema.types.array.get(sema_function.prototype).function);
                const sema_return_type = sema_function_prototype.return_type;
                assert(sema_value_return_type.eq(sema_return_type));
                const return_value = try llvm.emitValue(return_expression.value, context);

                // if (!llvm.inside_branch) {
                const function_return_type = llvm.function.getReturnType() orelse unreachable;
                _ = function_return_type;
                const ret = llvm.builder.createRet(return_value) orelse return LLVM.Value.Instruction.Error.ret;
                _ = ret;
                // } else {
                //     if (llvm.return_phi_node) |return_phi_node| {
                //         _ = return_phi_node;
                //
                //         unreachable;
                //     } else {
                //         const phi_node_count_hint = 2;
                //         const insert_basic_block = null;
                //         _ = insert_basic_block;
                //         const phi_node = LLVM.newPhiNode(return_type, phi_node_count_hint, "phi", "phi".len, null) orelse unreachable;
                //         const go_to_exit = llvm.builder.createBranch(llvm.exit_block) orelse unreachable;
                //         _ = go_to_exit;
                //         llvm.return_phi_node = phi_node;
                //     }
                // }
            },
            .intrinsic => |intrinsic_index| {
                _ = try llvm.emitIntrinsic(intrinsic_index, context);
            },
            .@"unreachable" => {
                const unreachable_instruction = llvm.builder.createUnreachable() orelse return LLVM.Value.Instruction.Error.@"unreachable";
                _ = unreachable_instruction;
            },
            .assign => |assignment_index| {
                const assignment = llvm.sema.values.assignments.get(assignment_index);
                const right = try llvm.emitValue(assignment.source, context);
                const pointer = try llvm.emitLValue(assignment.destination, context);
                const value: *LLVM.Value = if (assignment.operation) |operation| switch (operation) {
                    .add, .sub, .mul, .div => blk: {
                        const is_volatile = false;
                        const name = "compound_assign";
                        const destination_type = try llvm.getType(llvm.sema.values.array.get(assignment.destination).getType(llvm.sema));
                        const load = llvm.builder.createLoad(destination_type, pointer, is_volatile, name, name.len) orelse return LLVM.Value.Instruction.Error.load;
                        const right_value = llvm.sema.values.array.get(assignment.source);
                        const right_type = llvm.sema.types.array.get(right_value.getType(llvm.sema));

                        break :blk switch (right_type.*) {
                            .integer => |integer_type| switch (operation) {
                                .add, .sub, .mul => try llvm.arithmeticIntegerBinaryOperation(load.toValue(), right, operation, integer_type, "compound_assign"),
                                .div => b: {
                                    const is_exact = false;
                                    const result = switch (integer_type.signedness) {
                                        .unsigned => llvm.builder.createUDiv(load.toValue(), right, "udiv", "udiv".len, is_exact) orelse return LLVM.Value.Instruction.Error.udiv,
                                        .signed => llvm.builder.createSDiv(load.toValue(), right, "sdiv", "sdiv".len, is_exact) orelse return LLVM.Value.Instruction.Error.sdiv,
                                    };

                                    break :b result;
                                },
                                else => |t| @panic(@tagName(t)),
                            },
                            else => |t| @panic(@tagName(t)),
                        };
                    },
                    else => |t| @panic(@tagName(t)),
                } else right;

                const is_volatile = false;
                const store = llvm.builder.createStore(value, pointer, is_volatile) orelse return LLVM.Value.Instruction.Error.store;
                _ = store;
            },
            .call => |call_index| {
                assert(context == .local);
                _ = try llvm.emitCall(call_index, context);
            },
            .assembly_block => |assembly_block_index| {
                const assembly_block = llvm.sema.values.assembly_blocks.get(assembly_block_index);

                var assembly_statements = ArrayList(u8){};
                var constraints = ArrayList(u8){};
                var operand_values = ArrayList(*LLVM.Value){};
                var operand_types = ArrayList(*LLVM.Type){};

                switch (llvm.sema.descriptor.target.cpu.arch) {
                    .x86_64 => {
                        for (assembly_block.instructions) |instruction_index| {
                            const instruction = llvm.sema.values.assembly_instructions.get(instruction_index);
                            const instruction_id: Compilation.Assembly.x86_64.Instruction = @enumFromInt(instruction.id);

                            try assembly_statements.appendSlice(llvm.allocator, switch (instruction_id) {
                                .xor => "xorl",
                                .mov => "movq",
                                .@"and" => "andq",
                                .call => "callq",
                            });
                            try assembly_statements.append(llvm.allocator, ' ');

                            if (instruction.operands.len > 0) {
                                var reverse_operand_iterator = std.mem.reverseIterator(instruction.operands);

                                while (reverse_operand_iterator.next()) |operand| {
                                    switch (operand) {
                                        .register => |register_value| {
                                            const register: Compilation.Assembly.x86_64.Register = @enumFromInt(register_value);
                                            try assembly_statements.append(llvm.allocator, '%');
                                            try assembly_statements.appendSlice(llvm.allocator, @tagName(register));
                                        },
                                        .number_literal => |literal| {
                                            try assembly_statements.writer(llvm.allocator).print("$$0x{x}", .{literal});
                                        },
                                        .value_index => |value_index| {
                                            switch (llvm.sema.values.array.get(value_index).*) {
                                                .function_definition => {
                                                    const value = try llvm.emitValue(value_index, context);
                                                    try assembly_statements.writer(llvm.allocator).print("${{{}:P}}", .{operand_values.items.len});
                                                    try operand_values.append(llvm.allocator, value);
                                                    try constraints.append(llvm.allocator, 'X');
                                                    const value_type = value.getType();
                                                    try operand_types.append(llvm.allocator, value_type);
                                                },
                                                else => |t| @panic(@tagName(t)),
                                            }
                                            // try assembly_statements.writer(llvm.allocator).print("%{}", .{operand_values.items.len});
                                        },
                                    }

                                    try assembly_statements.appendSlice(llvm.allocator, ", ");
                                }

                                _ = assembly_statements.pop();
                                _ = assembly_statements.pop();
                            }

                            try assembly_statements.appendSlice(llvm.allocator, "\n\t");
                        }

                        try constraints.appendSlice(llvm.allocator, ",~{dirflag},~{fpsr},~{flags}");
                    },
                    else => |t| @panic(@tagName(t)),
                }

                const is_var_args = false;
                const function_type = LLVM.Context.getFunctionType(try llvm.getType(Compilation.Type.void), operand_types.items.ptr, operand_types.items.len, is_var_args) orelse unreachable;
                const has_side_effects = true;
                const is_align_stack = true;
                const dialect = LLVM.Value.InlineAssembly.Dialect.@"at&t";
                const can_throw = false;

                const inline_assembly = LLVM.Value.InlineAssembly.get(function_type, assembly_statements.items.ptr, assembly_statements.items.len, constraints.items.ptr, constraints.items.len, has_side_effects, is_align_stack, dialect, can_throw) orelse return LLVM.Value.Error.inline_assembly;
                const call = llvm.builder.createCall(function_type, inline_assembly.toValue(), operand_values.items.ptr, operand_values.items.len, "", "".len, null) orelse return LLVM.Value.Instruction.Error.call;
                _ = call;
            },
            .block => |block_index| {
                assert(context == .local);
                const emit_arguments = false;
                try llvm.emitBlock(block_index, context, emit_arguments);
            },
            .branch => |branch_index| {
                const branch = llvm.sema.values.branches.get(branch_index);
                const branch_type = llvm.sema.values.array.get(branch.expression).getType(llvm.sema);
                assert(branch_type.eq(Compilation.Type.boolean));
                const condition_value = try llvm.emitValue(branch.expression, context);
                const previous_inside_branch = llvm.inside_branch;
                llvm.inside_branch = true;
                const taken_basic_block = llvm.context.createBasicBlock("branch_taken", "branch_taken".len, llvm.function, null) orelse return Error.basic_block;
                var not_taken_basic_block: ?*LLVM.Value.BasicBlock = null;
                var fuse_basic_block: ?*LLVM.Value.BasicBlock = null;
                const acting_fuse_block = switch (branch.not_taken_expression.invalid) {
                    true => b: {
                        const block = llvm.context.createBasicBlock("branch_fuse", "branch_fuse".len, llvm.function, null) orelse return Error.basic_block;
                        fuse_basic_block = block;
                        break :b block;
                    },
                    false => b: {
                        const block = llvm.context.createBasicBlock("branch_not_taken", "branch_fuse".len, llvm.function, null) orelse return Error.basic_block;
                        not_taken_basic_block = block;
                        break :b block;
                    },
                };

                const branch_weights = null;
                const unpredictable = null;
                const conditional_branch = llvm.builder.createConditionalBranch(condition_value, taken_basic_block, acting_fuse_block, branch_weights, unpredictable) orelse return LLVM.Value.Instruction.Error.conditional_branch;
                _ = conditional_branch;

                var taken_reaches_end = true;
                {
                    llvm.builder.setInsertPoint(taken_basic_block);

                    switch (llvm.sema.values.array.get(branch.taken_expression).*) {
                        .block => |block_index| {
                            taken_reaches_end = llvm.sema.values.blocks.get(block_index).reaches_end;
                            const emit_arguments = false;
                            try llvm.emitBlock(block_index, context, emit_arguments);
                        },
                        else => |t| @panic(@tagName(t)),
                    }
                }

                if (taken_reaches_end) {
                    assert(!llvm.builder.isCurrentBlockTerminated());
                    if (fuse_basic_block == null) {
                        const fuse_block = llvm.context.createBasicBlock("branch_fuse", "branch_fuse".len, llvm.function, null) orelse return Error.basic_block;
                        fuse_basic_block = fuse_block;
                    }
                    const merge_br = llvm.builder.createBranch(fuse_basic_block orelse unreachable);
                    _ = merge_br;
                }

                var not_taken_reaches_end = true;
                if (!branch.not_taken_expression.invalid) {
                    llvm.builder.setInsertPoint(not_taken_basic_block orelse unreachable);

                    switch (llvm.sema.values.array.get(branch.not_taken_expression).*) {
                        .block => |block_index| {
                            const emit_arguments = false;
                            try llvm.emitBlock(block_index, context, emit_arguments);
                            not_taken_reaches_end = llvm.sema.values.blocks.get(block_index).reaches_end;
                        },
                        else => |t| @panic(@tagName(t)),
                    }

                    if (not_taken_reaches_end) {
                        assert(!llvm.builder.isCurrentBlockTerminated());
                        if (fuse_basic_block == null) {
                            const fuse_block = llvm.context.createBasicBlock("branch_fuse", "branch_fuse".len, llvm.function, null) orelse return Error.basic_block;
                            fuse_basic_block = fuse_block;
                        }

                        const merge_br = llvm.builder.createBranch(fuse_basic_block orelse unreachable);
                        _ = merge_br;
                    }
                }

                if (fuse_basic_block) |end_block| {
                    llvm.builder.setInsertPoint(end_block);
                }

                llvm.inside_branch = previous_inside_branch;
            },
            .loop => |loop_index| {
                const loop = llvm.sema.values.loops.get(loop_index);
                assert(context == .local);
                const previous_inside_branch = llvm.inside_branch;
                llvm.inside_branch = true;
                for (loop.pre.items) |pre_statement_value_index| {
                    try llvm.emitStatement(pre_statement_value_index, context);
                }
                const header_basic_block = llvm.context.createBasicBlock("loop_header", "loop_header".len, llvm.function, null) orelse return Error.basic_block;
                const jump_to_loop = llvm.builder.createBranch(header_basic_block) orelse unreachable;
                _ = jump_to_loop;
                const body_basic_block = llvm.context.createBasicBlock("loop_body", "loop_body".len, llvm.function, null) orelse return Error.basic_block;
                const previous_exit_block = llvm.exit_block;
                const exit_basic_block = llvm.context.createBasicBlock("loop_exit", "loop_exit".len, llvm.function, null) orelse return Error.basic_block;
                llvm.exit_block = exit_basic_block;

                llvm.builder.setInsertPoint(header_basic_block);

                const condition = try llvm.emitValue(loop.condition, context);
                const branch_weights = null;
                const unpredictable = null;
                const conditional_branch = llvm.builder.createConditionalBranch(condition, body_basic_block, exit_basic_block, branch_weights, unpredictable) orelse unreachable;
                _ = conditional_branch;
                llvm.builder.setInsertPoint(body_basic_block);
                try llvm.emitStatement(loop.body, context);

                for (loop.post.items) |post_statement_value_index| {
                    try llvm.emitStatement(post_statement_value_index, context);
                }

                // if (!llvm.builder.isCurrentBlockTerminated()) {
                const jump_to_header = llvm.builder.createBranch(header_basic_block) orelse unreachable;
                _ = jump_to_header;
                // }

                llvm.builder.setInsertPoint(exit_basic_block);
                llvm.exit_block = previous_exit_block;
                llvm.inside_branch = previous_inside_branch;

                // if (llvm.inside_branch and !llvm.builder.isCurrentBlockTerminated()) {
                //     unreachable;
                // }
            },
            .@"break" => {
                const jump_to_exit_block = llvm.builder.createBranch(llvm.exit_block) orelse unreachable;
                _ = jump_to_exit_block;
            },
            else => |t| @panic(@tagName(t)),
        }
    }

    fn emitIntrinsic(llvm: *LLVM, intrinsic_index: Compilation.Intrinsic.Index, context: Compilation.ScopeType) !*LLVM.Value {
        const intrinsic = llvm.sema.values.intrinsics.get(intrinsic_index);
        switch (intrinsic.kind) {
            .syscall => |syscall| {
                var syscall_argument_buffer: [7]*LLVM.Value = undefined;
                var syscall_argument_type_buffer: [7]*LLVM.Type = undefined;
                const sema_syscall_arguments = syscall.items;
                const syscall_argument_count: usize = sema_syscall_arguments.len;
                const syscall_arguments = syscall_argument_buffer[0..syscall_argument_count];
                const syscall_argument_types = syscall_argument_type_buffer[0..syscall_argument_count];

                for (sema_syscall_arguments, syscall_arguments, syscall_argument_types) |sema_syscall_argument_value_index, *syscall_argument, *syscall_argument_type| {
                    syscall_argument.* = try llvm.emitValue(sema_syscall_argument_value_index, context);
                    syscall_argument_type.* = syscall_argument.*.getType();
                }

                const return_type = try llvm.getType(Compilation.Type.usize);
                const is_var_args = false;
                const function_type = LLVM.Context.getFunctionType(return_type, syscall_argument_types.ptr, syscall_argument_types.len, is_var_args) orelse unreachable;
                var constraints = ArrayList(u8){};

                const inline_asm = switch (llvm.sema.descriptor.target.cpu.arch) {
                    .x86_64 => blk: {
                        try constraints.appendSlice(llvm.allocator, "={rax}");

                        const syscall_registers = [7][]const u8{ "rax", "rdi", "rsi", "rdx", "r10", "r8", "r9" };
                        for (syscall_registers[0..syscall_argument_count]) |syscall_register| {
                            try constraints.appendSlice(llvm.allocator, ",{");
                            try constraints.appendSlice(llvm.allocator, syscall_register);
                            try constraints.append(llvm.allocator, '}');
                        }

                        try constraints.appendSlice(llvm.allocator, ",~{rcx},~{r11},~{memory}");

                        const assembly = "syscall";
                        const has_side_effects = true;
                        const is_align_stack = true;
                        const can_throw = false;
                        const inline_assembly = LLVM.Value.InlineAssembly.get(function_type, assembly, assembly.len, constraints.items.ptr, constraints.items.len, has_side_effects, is_align_stack, LLVM.Value.InlineAssembly.Dialect.@"at&t", can_throw) orelse return Value.Error.inline_assembly;
                        break :blk inline_assembly;
                    },
                    else => |t| @panic(@tagName(t)),
                };
                const call_to_asm = llvm.builder.createCall(function_type, inline_asm.toValue(), syscall_arguments.ptr, syscall_arguments.len, "syscall", "syscall".len, null) orelse return LLVM.Value.Instruction.Error.call;
                return call_to_asm.toValue();
            },
            .cast => |sema_cast_value| {
                const value = try llvm.emitValue(sema_cast_value, context);
                const destination_type = llvm.sema.types.array.get(intrinsic.type);
                const source_value = llvm.sema.values.array.get(sema_cast_value);
                const source_type = llvm.sema.types.array.get(source_value.getType(llvm.sema));

                switch (destination_type.*) {
                    .integer => |destination_integer| {
                        switch (source_type.*) {
                            .@"enum" => return value,
                            .integer => |source_integer| {
                                if (source_integer.bit_count == destination_integer.bit_count) {
                                    return value;
                                } else if (source_integer.bit_count < destination_integer.bit_count) {
                                    assert(source_integer.signedness != destination_integer.signedness);
                                    const cast_type: LLVM.Value.Instruction.Cast.Type = switch (destination_integer.signedness) {
                                        .signed => .sign_extend,
                                        .unsigned => .zero_extend,
                                    };
                                    const name = @tagName(cast_type);
                                    const cast = llvm.builder.createCast(cast_type, value, try llvm.getType(intrinsic.type), name.ptr, name.len) orelse return LLVM.Value.Instruction.Error.cast;
                                    return cast;
                                } else if (source_integer.bit_count > destination_integer.bit_count) {
                                    const cast = llvm.builder.createCast(.truncate, value, try llvm.getType(intrinsic.type), "truncate", "truncate".len) orelse return LLVM.Value.Instruction.Error.cast;
                                    return cast;
                                } else unreachable;
                            },
                            .pointer => |pointer| {
                                _ = pointer;
                                assert(destination_integer.bit_count == 64);
                                const cast = llvm.builder.createCast(.pointer_to_int, value, try llvm.getType(intrinsic.type), "pointer_to_int", "pointer_to_int".len) orelse return LLVM.Value.Instruction.Error.cast;
                                return cast;
                            },
                            else => |t| @panic(@tagName(t)),
                        }
                    },
                    .pointer => |pointer| {
                        _ = pointer;

                        switch (source_type.*) {
                            .integer => {
                                const cast = llvm.builder.createCast(.int_to_pointer, value, try llvm.getType(intrinsic.type), "int_to_pointer", "int_to_pointer".len) orelse return LLVM.Value.Instruction.Error.cast;
                                return cast;
                            },
                            else => |t| @panic(@tagName(t)),
                        }
                    },
                    else => |t| @panic(@tagName(t)),
                }
            },
            .sign_extend => |sema_value| {
                const value = try llvm.emitValue(sema_value, context);

                const sign_extend = llvm.builder.createCast(.sign_extend, value, try llvm.getType(intrinsic.type), "sign_extend", "sign_extend".len) orelse return LLVM.Value.Instruction.Error.cast;
                return sign_extend;
            },
            .zero_extend => |sema_value| {
                const value = try llvm.emitValue(sema_value, context);

                const zero_extend = llvm.builder.createCast(.zero_extend, value, try llvm.getType(intrinsic.type), "zero_extend", "zero_extend".len) orelse return LLVM.Value.Instruction.Error.cast;
                return zero_extend;
            },
            .optional_wrap => |sema_value| {
                const optional_type = try llvm.getType(intrinsic.type);
                switch (llvm.sema.types.array.get(intrinsic.type).*) {
                    .optional => |optional| switch (llvm.sema.types.array.get(optional.element_type).*) {
                        .integer => {
                            const alloca = llvm.builder.createAlloca(optional_type, address_space, null, "optional_wrap_alloca", "optional_wrap_alloca".len) orelse return LLVM.Value.Instruction.Error.alloca;
                            const is_signed = false;
                            const index_zero = llvm.context.getConstantInt(32, 0, is_signed) orelse unreachable;
                            const index_one = llvm.context.getConstantInt(32, 1, is_signed) orelse unreachable;

                            const optional_element_type = try llvm.getType(optional.element_type);
                            const boolean_type = try llvm.getType(Compilation.Type.boolean);

                            const indices0 = [_]*LLVM.Value{index_zero.toValue()};
                            const in_bounds = true;
                            const gep0 = llvm.builder.createGEP(optional_element_type, alloca.toValue(), &indices0, indices0.len, "gep", "gep".len, in_bounds) orelse return LLVM.Value.Instruction.Error.gep;
                            const load0 = try llvm.emitValue(sema_value, context);
                            const is_volatile = false;
                            const store0 = llvm.builder.createStore(load0, gep0, is_volatile) orelse return LLVM.Value.Instruction.Error.store;
                            _ = store0;

                            const indices1 = [_]*LLVM.Value{index_one.toValue()};
                            const gep1 = llvm.builder.createGEP(boolean_type, alloca.toValue(), &indices1, indices1.len, "gep", "gep".len, in_bounds) orelse return LLVM.Value.Instruction.Error.gep;
                            const load1 = llvm.context.getConstantInt(1, 1, is_signed) orelse unreachable;
                            const store1 = llvm.builder.createStore(load1.toValue(), gep1, is_volatile) orelse return LLVM.Value.Instruction.Error.store;
                            _ = store1;

                            const load = llvm.builder.createLoad(optional_type, alloca.toValue(), is_volatile, "struct_init_load", "struct_init_load".len) orelse return LLVM.Value.Instruction.Error.load;
                            return load.toValue();
                        },
                        else => |t| @panic(@tagName(t)),
                    },
                    else => |t| @panic(@tagName(t)),
                }
            },
            .min => |sema_values| {
                switch (llvm.sema.types.array.get(intrinsic.type).*) {
                    .integer => |integer_type| {
                        const intrinsic_name = switch (integer_type.signedness) {
                            .unsigned => "llvm.umin",
                            .signed => "llvm.smin",
                        };
                        const intrinsic_id = lookupIntrinsic(intrinsic_name.ptr, intrinsic_name.len);
                        assert(intrinsic_id != .none);

                        const left_type = llvm.sema.values.array.get(sema_values.left).getType(llvm.sema);
                        const right_type = llvm.sema.values.array.get(sema_values.right).getType(llvm.sema);
                        assert(left_type.eq(right_type));
                        assert(left_type.eq(intrinsic.type));
                        const intrinsic_return_type = try llvm.getType(intrinsic.type);
                        const types = [_]*LLVM.Type{intrinsic_return_type};
                        const intrinsic_function = llvm.module.getIntrinsicDeclaration(intrinsic_id, &types, types.len) orelse return LLVM.Value.Error.intrinsic;
                        const intrinsic_function_type = llvm.context.getIntrinsicType(intrinsic_id, &types, types.len) orelse return LLVM.Type.Error.intrinsic;

                        const left = try llvm.emitValue(sema_values.left, context);
                        const right = try llvm.emitValue(sema_values.right, context);
                        const arguments = [_]*LLVM.Value{ left, right };

                        const call = llvm.builder.createCall(intrinsic_function_type, intrinsic_function.toValue(), &arguments, arguments.len, "min".ptr, "min".len, null) orelse return LLVM.Value.Instruction.Error.call;
                        return call.toValue();
                    },
                    else => |t| @panic(@tagName(t)),
                }
            },
            .array_coerce_to_slice => |sema_value| {
                const result_type = try llvm.getType(intrinsic.type);
                const slice_type = result_type.toStruct() orelse unreachable;
                const appointee_value = try llvm.emitValue(sema_value, context);
                switch (llvm.sema.values.array.get(sema_value).*) {
                    .array_initialization => |array_initialization_index| {
                        const array_initialization = llvm.sema.values.container_initializations.get(array_initialization_index);
                        if (array_initialization.is_comptime) {
                            const constant_array = appointee_value.toConstant() orelse unreachable;
                            const array_type = try llvm.getType(array_initialization.type);
                            const is_constant = true;
                            const linkage = LLVM.Linkage.@"extern";
                            const thread_local_mode = LLVM.ThreadLocalMode.not_thread_local;
                            const externally_initialized = false;
                            const global_variable = llvm.module.addGlobalVariable(array_type, is_constant, linkage, constant_array, "", "".len, null, thread_local_mode, address_space, externally_initialized) orelse return LLVM.Value.Error.constant_array;
                            const is_signed = false;
                            const len_constant = llvm.context.getConstantInt(@bitSizeOf(usize), array_initialization.field_initializations.items.len, is_signed) orelse unreachable;
                            const slice_values = [2]*LLVM.Value.Constant{ global_variable.toConstant(), len_constant.toConstant() };
                            const constant = slice_type.instantiateConstant(&slice_values, slice_values.len) orelse unreachable;
                            return constant.toValue();
                        } else {
                            unreachable;
                        }
                        //             const ptr_indices = [1]c_uint{0};
                        //             const is_signed = false;
                        //             const len_indices = [1]c_uint{1};
                        //             const insert_slice_len = llvm.builder.createInsertValue(result.toValue(), len_constant.toValue(), &len_indices, len_indices.len, "insert_slice_len", "insert_slice_len".len) orelse unreachable;
                        //             _ = insert_slice_len;
                        //             _ = insert_slice_ptr;
                        //             return result.toValue();
                        //         } else {
                        //             unreachable;
                        //         }
                    },
                    else => |t| @panic(@tagName(t)),
                }

                // switch (llvm.sema.values.array.get(sema_value).*) {
                //     .string_literal => |string_literal| {
                //         const name = llvm.sema.getName(string_literal.hash).?;
                //         const expected_type = try llvm.getType(string_literal.type);
                //         assert(expected_type.compare(appointee_value.getType() orelse unreachable));
                //         const ptr_indices = [1]c_uint{0};
                //         const insert_slice_ptr = llvm.builder.createInsertValue(result.toValue(), appointee_value, &ptr_indices, ptr_indices.len, "insert_slice_ptr", "insert_slice_ptr".len) orelse unreachable;
                //         const is_signed = false;
                //         const len_constant = llvm.context.getConstantInt(@bitSizeOf(usize), name.len, is_signed) orelse unreachable;
                //         const len_indices = [1]c_uint{1};
                //         const insert_slice_len = llvm.builder.createInsertValue(result.toValue(), len_constant.toValue(), &len_indices, len_indices.len, "insert_slice_len", "insert_slice_len".len) orelse unreachable;
                //         _ = insert_slice_len;
                //         _ = insert_slice_ptr;
                //         return result.toValue();
                //     },
                //     else => |t| @panic(@tagName(t)),
                // }
                unreachable;
            },
            else => |t| @panic(@tagName(t)),
        }
    }

    fn renderDeclarationName(llvm: *LLVM, declaration_index: Compilation.Declaration.Index, mangle: bool) anyerror![]const u8 {
        if (llvm.declaration_names.get(declaration_index)) |name| {
            return name;
        } else {
            const declaration = llvm.sema.values.declarations.get(declaration_index);
            const base_declaration_name = llvm.sema.getName(declaration.name).?;
            var list = ArrayList(u8){};

            try list.insertSlice(llvm.allocator, 0, base_declaration_name);

            if (mangle) {
                var scope_index = declaration.scope;

                var iterations: usize = 0;
                switch (declaration.scope_type) {
                    .global => {
                        while (!scope_index.invalid) {
                            const scope = llvm.sema.values.scopes.get(scope_index);

                            if (llvm.sema.map.types.get(scope.type)) |type_declaration| {
                                const scope_type_declaration = llvm.sema.values.declarations.get(type_declaration);
                                const scope_type_declaration_name = llvm.sema.getName(scope_type_declaration.name).?;
                                try list.insert(llvm.allocator, 0, '.');
                                try list.insertSlice(llvm.allocator, 0, scope_type_declaration_name);

                                scope_index = scope.parent;
                            } else {
                                break;
                            }

                            iterations += 1;
                        }
                    },
                    .local => {},
                    else => unreachable,
                }
            }

            // TODO: enhance declaration name rendering with file scope name
            // const scope =  declaration.scope;
            try llvm.declaration_names.putNoClobber(llvm.allocator, declaration_index, list.items);

            return list.items;
        }
    }

    fn emitBlock(llvm: *LLVM, block_index: Compilation.Block.Index, context: Compilation.ScopeType, emit_arguments: bool) !void {
        const block = llvm.sema.values.blocks.get(block_index);
        const previous_scope = llvm.scope;
        const lexical_block = llvm.debug_info_builder.createLexicalBlock(previous_scope, llvm.file, block.line + 1, block.column + 1) orelse unreachable;
        llvm.scope = lexical_block.toScope();
        llvm.builder.setCurrentDebugLocation(llvm.context, block.line + 1, block.column + 1, llvm.scope, llvm.function);

        if (emit_arguments) {
            const sema_function = llvm.sema.types.function_definitions.get(llvm.sema_function);
            const function_prototype = llvm.sema.types.function_prototypes.get(llvm.sema.types.array.get(sema_function.prototype).function);
            _ = function_prototype;
            // TODO: rewrite
            var argument_buffer: [16]*LLVM.Value.Argument = undefined;
            var argument_count: usize = argument_buffer.len;
            llvm.function.getArguments(&argument_buffer, &argument_count);
            const arguments = argument_buffer[0..argument_count];

            for (arguments) |arg| {
                const argument_value = arg.toValue();
                const alloca_array_size = null;
                const declaration_alloca = llvm.builder.createAlloca(argument_value.getType(), address_space, alloca_array_size, "", "".len) orelse return LLVM.Value.Instruction.Error.alloca;
                const is_volatile = false;
                const store = llvm.builder.createStore(argument_value, declaration_alloca.toValue(), is_volatile) orelse return LLVM.Value.Instruction.Error.store;
                _ = store;
            }
        }

        for (block.statements.items) |sema_statement_value_index| {
            try llvm.emitStatement(sema_statement_value_index, context);
        }

        llvm.scope = previous_scope;
    }

    fn getDebugInfoFile(llvm: *LLVM, sema_file_index: Compilation.File.Index) !*DebugInfo.File {
        if (llvm.debug_info_file_map.get(sema_file_index)) |file| {
            return file;
        } else {
            const sema_file = llvm.sema.values.files.get(sema_file_index);
            const sub_path = std.fs.path.dirname(sema_file.relative_path) orelse "";
            const file_path = std.fs.path.basename(sema_file.relative_path);
            const directory_path = try std.fs.path.join(llvm.allocator, &.{ sema_file.package.directory.path, sub_path });
            const debug_file = llvm.debug_info_builder.createFile(file_path.ptr, file_path.len, directory_path.ptr, directory_path.len) orelse unreachable;
            try llvm.debug_info_file_map.putNoClobber(llvm.allocator, sema_file_index, debug_file);
            return debug_file;
        }
    }

    fn renderTypeName(llvm: *LLVM, sema_type_index: Compilation.Type.Index) ![]const u8 {
        if (llvm.type_name_map.get(sema_type_index)) |typename| {
            return typename;
        } else {
            const sema_type = llvm.sema.types.array.get(sema_type_index);
            const result: []const u8 = switch (sema_type.*) {
                .integer => |integer| b: {
                    const signedness_char: u8 = switch (integer.signedness) {
                        .signed => 's',
                        .unsigned => 'u',
                    };
                    const name = try std.fmt.allocPrint(llvm.allocator, "{c}{}", .{ signedness_char, integer.bit_count });
                    break :b name;
                },
                .slice => |slice| b: {
                    var name = ArrayList(u8){};
                    try name.appendSlice(llvm.allocator, "[] ");
                    if (slice.@"const") {
                        try name.appendSlice(llvm.allocator, "const ");
                    }
                    const element_type_name = try llvm.renderTypeName(slice.element_type);
                    try name.appendSlice(llvm.allocator, element_type_name);
                    break :b name.items;
                },
                .pointer => |pointer| b: {
                    var name = ArrayList(u8){};
                    try name.appendSlice(llvm.allocator, "&");
                    if (pointer.@"const") {
                        try name.appendSlice(llvm.allocator, "const");
                    }
                    try name.appendSlice(llvm.allocator, " ");
                    const element_type_name = try llvm.renderTypeName(pointer.element_type);
                    try name.appendSlice(llvm.allocator, element_type_name);
                    break :b name.items;
                },
                .array => |array| b: {
                    var name = ArrayList(u8){};
                    const element_type_name = try llvm.renderTypeName(array.element_type);
                    try name.writer(llvm.allocator).print("[{}]{s}", .{ array.element_count, element_type_name });
                    break :b name.items;
                },
                .@"enum",
                .@"struct",
                => b: {
                    if (llvm.sema.map.types.get(sema_type_index)) |type_declaration_index| {
                        const declaration = llvm.sema.values.declarations.get(type_declaration_index);
                        const name = llvm.sema.getName(declaration.name).?;
                        break :b name;
                    } else {
                        unreachable;
                    }
                },
                .optional => |optional| b: {
                    var name = ArrayList(u8){};
                    const element_type_name = try llvm.renderTypeName(optional.element_type);
                    try name.writer(llvm.allocator).print("?{s}", .{element_type_name});
                    break :b name.items;
                },
                .bool => "bool",
                else => |t| @panic(@tagName(t)),
            };

            try llvm.type_name_map.putNoClobber(llvm.allocator, sema_type_index, result);
            return result;
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

        const struct_type = llvm.debug_info_builder.createStructType(arguments.scope, arguments.name.ptr, arguments.name.len, arguments.file, arguments.line, arguments.bitsize, arguments.alignment, flags, null, arguments.field_types.ptr, arguments.field_types.len) orelse unreachable;
        return struct_type;
    }

    fn getDebugType(llvm: *LLVM, sema_type_index: Compilation.Type.Index) !*LLVM.DebugInfo.Type {
        if (llvm.debug_type_map.get(sema_type_index)) |t| {
            return t;
        } else {
            const name = try llvm.renderTypeName(sema_type_index);
            const sema_type = llvm.sema.types.array.get(sema_type_index);
            const result: *LLVM.DebugInfo.Type = switch (sema_type.*) {
                .integer => |integer| b: {
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
                .pointer => |pointer| b: {
                    const element_type = try llvm.getDebugType(pointer.element_type);
                    const pointer_width = @bitSizeOf(usize);
                    const alignment = 0;
                    const pointer_type = llvm.debug_info_builder.createPointerType(element_type, pointer_width, alignment, name.ptr, name.len) orelse unreachable;
                    break :b pointer_type.toType();
                },
                .slice => |slice| b: {
                    const pointer_type = try llvm.getDebugType(llvm.sema.map.pointers.get(.{
                        .element_type = slice.element_type,
                        .many = true,
                        .@"const" = slice.@"const",
                        .termination = slice.termination,
                    }).?);
                    const len_type = try llvm.getDebugType(Compilation.Type.usize);
                    const scope = null;
                    const file = null;
                    const line = 1;
                    // const forward_declared_type = llvm.debug_info_builder.createReplaceableCompositeType(tag_count, name.ptr, name.len, scope, file, line) orelse unreachable;
                    // tag_count += 1;

                    const field_types = [2]*LLVM.DebugInfo.Type{ pointer_type, len_type };
                    const struct_type = llvm.createDebugStructType(.{
                        .scope = scope,
                        .name = name,
                        .file = file,
                        .line = line,
                        .bitsize = 2 * @bitSizeOf(usize),
                        .alignment = @alignOf(usize),
                        .field_types = &field_types,
                    });
                    break :b struct_type.toType();
                },
                .@"struct" => |struct_index| b: {
                    const sema_struct_type = llvm.sema.types.structs.get(struct_index);

                    var field_types = try ArrayList(*LLVM.DebugInfo.Type).initCapacity(llvm.allocator, sema_struct_type.fields.items.len);
                    for (sema_struct_type.fields.items) |struct_field_index| {
                        const struct_field = llvm.sema.types.container_fields.get(struct_field_index);
                        const field_type = try llvm.getDebugType(struct_field.type);
                        field_types.appendAssumeCapacity(field_type);
                    }
                    const sema_declaration_index = llvm.sema.map.types.get(sema_type_index) orelse unreachable;
                    const sema_declaration = llvm.sema.values.declarations.get(sema_declaration_index);
                    const file = try llvm.getDebugInfoFile(llvm.sema.values.scopes.get(sema_declaration.scope).file);
                    const line = sema_declaration.line + 1;
                    const struct_type = llvm.createDebugStructType(.{ .scope = null, .name = name, .file = file, .line = line, .bitsize = sema_type.getBitSize(llvm.sema), .alignment = 0, .field_types = field_types.items });
                    break :b struct_type.toType();
                },
                .array => |array| b: {
                    const byte_size = array.element_count * llvm.sema.types.array.get(array.element_type).getSize();
                    const bit_size = byte_size * 8;
                    const element_type = try llvm.getDebugType(array.element_type);
                    // extern fn NativityLLVMDebugInfoBuilderCreateArrayType(builder: *LLVM.DebugInfo.Builder, bit_size: u64, alignment: u32, type: *LLVM.DebugInfo.Type, element_count: usize) ?*LLVM.DebugInfo.Type.Composite;
                    const array_type = llvm.debug_info_builder.createArrayType(bit_size, 1, element_type, array.element_count) orelse unreachable;
                    break :b array_type.toType();
                },
                .@"enum" => |enum_index| b: {
                    const enum_type = llvm.sema.types.enums.get(enum_index);
                    var enumerators = try ArrayList(*LLVM.DebugInfo.Type.Enumerator).initCapacity(llvm.allocator, enum_type.fields.items.len);
                    for (enum_type.fields.items) |enum_field_index| {
                        const enum_field = llvm.sema.types.enum_fields.get(enum_field_index);
                        const enum_field_name = llvm.sema.getName(enum_field.name).?;

                        const is_unsigned = true;
                        const enumerator = llvm.debug_info_builder.createEnumerator(enum_field_name.ptr, enum_field_name.len, enum_field.value, is_unsigned) orelse unreachable;
                        enumerators.appendAssumeCapacity(enumerator);
                    }

                    const sema_declaration_index = llvm.sema.map.types.get(sema_type_index) orelse unreachable;
                    const sema_declaration = llvm.sema.values.declarations.get(sema_declaration_index);
                    const file = try llvm.getDebugInfoFile(llvm.sema.values.scopes.get(sema_declaration.scope).file);
                    const bit_size = llvm.sema.types.array.get(enum_type.backing_type).getBitSize(llvm.sema);
                    const backing_type = try llvm.getDebugType(enum_type.backing_type);
                    const alignment = 0;
                    const line = sema_declaration.line + 1;
                    const enumeration_type = llvm.debug_info_builder.createEnumerationType(llvm.scope, name.ptr, name.len, file, line, bit_size, alignment, enumerators.items.ptr, enumerators.items.len, backing_type) orelse unreachable;
                    break :b enumeration_type.toType();
                },
                .optional => |optional| {
                    const element_type = try llvm.getDebugType(optional.element_type);
                    const bool_type = try llvm.getDebugType(Compilation.Type.boolean);
                    const field_types = [2]*LLVM.DebugInfo.Type{ element_type, bool_type };
                    const struct_type = llvm.createDebugStructType(.{
                        .scope = null,
                        .name = name,
                        .file = null,
                        .line = 1,
                        .bitsize = sema_type.getBitSize(llvm.sema),
                        .alignment = 0,
                        .field_types = &field_types,
                    });
                    return struct_type.toType();
                },
                .bool => {
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
                    return boolean_type;
                },
                else => |t| @panic(@tagName(t)),
            };

            try llvm.debug_type_map.putNoClobber(llvm.allocator, sema_type_index, result);

            return result;
        }
    }
};

var tag_count: c_uint = 0;

const Error = error{
    context,
    module,
    builder,
    function,
    basic_block,
    debug_info_builder,
};

const address_space = 0;
pub fn initialize(compilation: *Compilation, sema_module: *Module) !void {
    const context = LLVM.Context.create() orelse return Error.context;
    const module = LLVM.Module.create(@ptrCast(sema_module.descriptor.name.ptr), sema_module.descriptor.name.len, context) orelse return Error.module;
    const debug_info_builder = module.createDebugInfoBuilder() orelse return Error.debug_info_builder;
    const filename = "main";
    const directory = ".";
    const debug_info_file = debug_info_builder.createFile(filename, filename.len, directory, directory.len) orelse unreachable;
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
    const compile_unit = debug_info_builder.createCompileUnit(LLVM.DebugInfo.Language.c, debug_info_file, producer, producer.len, is_optimized, flags, flags.len, runtime_version, splitname, splitname.len, debug_info_kind, DWOId, split_debug_inlining, debug_info_for_profiling, name_table_kind, ranges_base_address, sysroot, sysroot.len, sdk, sdk.len) orelse unreachable;
    _ = compile_unit;
    const builder = LLVM.Builder.create(context) orelse return Error.builder;

    var llvm = LLVM{
        .context = context,
        .module = module,
        .builder = builder,
        .debug_info_builder = debug_info_builder,
        .sema = sema_module,
        .allocator = compilation.base_allocator,
    };

    var function_definition_iterator = sema_module.types.function_definitions.iterator();

    while (function_definition_iterator.nextIndex()) |function_definition_index| {
        const function_definition = sema_module.types.function_definitions.get(function_definition_index);
        const llvm_prototype = (try llvm.getType(function_definition.prototype)).toFunction() orelse unreachable;
        const function_prototype = llvm.sema.types.function_prototypes.get(llvm.sema.types.array.get(function_definition.prototype).function);

        const mangle_name = !function_prototype.attributes.@"export";
        const declaration_index = llvm.sema.map.function_definitions.get(function_definition_index).?;
        const name = try llvm.renderDeclarationName(declaration_index, mangle_name);
        if (llvm.module.getFunction(name.ptr, name.len)) |_| {
            @panic("Function with same name");
        }

        const linkage = LLVM.Linkage.@"extern";
        const function = llvm.module.createFunction(llvm_prototype, linkage, address_space, name.ptr, name.len) orelse return Error.function;
        switch (llvm.sema.types.array.get(function_prototype.return_type).*) {
            .noreturn => {
                function.addAttributeKey(.NoReturn);
            },
            else => {},
        }

        // TODO: fix this
        switch (function_prototype.attributes.calling_convention) {
            .auto => {
                function.setCallingConvention(.Fast);
            },
            .system_v => {
                function.setCallingConvention(.X86_64_SysV);
            },
            .c => {
                function.setCallingConvention(.C);
            },
            .naked => {
                function.addAttributeKey(.Naked);
            },
        }

        try llvm.function_definition_map.putNoClobber(llvm.allocator, function_definition_index, function);
    }

    function_definition_iterator = sema_module.types.function_definitions.iterator();

    while (function_definition_iterator.nextIndex()) |function_definition_index| {
        llvm.function = llvm.function_definition_map.get(function_definition_index).?;
        llvm.sema_function = function_definition_index;
        llvm.inside_branch = false;
        const declaration_index = llvm.sema.map.function_definitions.get(function_definition_index).?;
        const sema_declaration = llvm.sema.values.declarations.get(declaration_index);
        const sema_scope = llvm.sema.values.scopes.get(sema_declaration.scope);
        const debug_file = try llvm.getDebugInfoFile(sema_scope.file);
        const function_definition = sema_module.types.function_definitions.get(function_definition_index);
        const function_prototype = llvm.sema.types.function_prototypes.get(llvm.sema.types.array.get(function_definition.prototype).function);
        const mangle_name = !function_prototype.attributes.@"export";
        const name = try llvm.renderDeclarationName(declaration_index, mangle_name);

        var parameter_types = try ArrayList(*LLVM.DebugInfo.Type).initCapacity(llvm.allocator, function_prototype.arguments.items.len);
        for (function_prototype.arguments.items) |argument_index| {
            const argument_declaration = llvm.sema.values.declarations.get(argument_index);
            const sema_argument_type = argument_declaration.getType();
            const argument_type = try llvm.getDebugType(sema_argument_type);
            parameter_types.appendAssumeCapacity(argument_type);
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
        const subroutine_type = llvm.debug_info_builder.createSubroutineType(parameter_types.items.ptr, parameter_types.items.len, subroutine_type_flags, subroutine_type_calling_convention) orelse unreachable;
        const scope_line = 0;
        const subprogram_flags = LLVM.DebugInfo.Subprogram.Flags{
            .virtuality = .none,
            .local_to_unit = true,
            .definition = true,
            .optimized = false,
            .pure = false,
            .elemental = false,
            .recursive = false,
            .main_subprogram = false,
            .deleted = false,
            .object_c_direct = false,
        };
        const subprogram_declaration = null;
        const subprogram = llvm.debug_info_builder.createFunction(debug_file.toScope(), name.ptr, name.len, name.ptr, name.len, debug_file, sema_declaration.line + 1, subroutine_type, scope_line, subroutine_type_flags, subprogram_flags, subprogram_declaration) orelse unreachable;
        llvm.function.setSubprogram(subprogram);
        llvm.file = subprogram.getFile() orelse unreachable;
        llvm.scope = subprogram.toLocalScope().toScope();

        const print_function_name = true;
        if (print_function_name) {
            std.debug.print("Compiling {s}...\n", .{name});
        }

        const entry_basic_block_name = "entry";
        const entry_basic_block = llvm.context.createBasicBlock(entry_basic_block_name, entry_basic_block_name.len, llvm.function, null) orelse return Error.basic_block;
        llvm.builder.setInsertPoint(entry_basic_block);

        const context_type = Compilation.ScopeType.local;
        const emit_arguments = true;
        try llvm.emitBlock(function_definition.body, context_type, emit_arguments);

        if (!builder.isCurrentBlockTerminated()) {
            if (function_prototype.return_type.eq(Compilation.Type.noreturn)) {
                _ = builder.createUnreachable() orelse return LLVM.Value.Instruction.Error.@"unreachable";
            } else if (function_prototype.return_type.eq(Compilation.Type.void)) {
                _ = builder.createRet(null) orelse unreachable;
            } else {
                unreachable;
            }
        }

        llvm.debug_info_builder.finalizeSubprogram(subprogram, llvm.function);

        const verify_function = true;
        if (verify_function) {
            var message_ptr: [*]const u8 = undefined;
            var message_len: usize = 0;
            const result = llvm.function.verify(&message_ptr, &message_len);

            if (!result) {
                var function_len: usize = 0;
                const function_ptr = llvm.function.toString(&function_len);
                const function_ir = function_ptr[0..function_len];
                const error_message = message_ptr[0..message_len];
                std.debug.panic("\n{s}. LLVM verification for the function above failed:\n{s}\n", .{ function_ir, error_message });
            }
        }
    }

    llvm.debug_info_builder.finalize();

    const print_module = true;
    if (print_module) {
        var module_len: usize = 0;
        const module_ptr = llvm.module.toString(&module_len);
        const module_string = module_ptr[0..module_len];
        std.debug.print("{s}\n", .{module_string});
    }

    const verify_module = true;
    if (verify_module) {
        var message_ptr: [*]const u8 = undefined;
        var message_len: usize = 0;
        const result = llvm.module.verify(&message_ptr, &message_len);
        if (!result) {
            std.debug.panic("LLVM module verification failed:\n{s}\n", .{message_ptr[0..message_len]});
        }
    }

    const file_path = llvm.sema.descriptor.executable_path;
    const object_file_path = try std.mem.joinZ(llvm.allocator, "", &.{ file_path, ".o" });
    const destination_file_path = try std.mem.joinZ(llvm.allocator, "", &.{file_path});
    const r = NativityLLVMGenerateMachineCode(llvm.module, object_file_path.ptr, object_file_path.len, destination_file_path.ptr, destination_file_path.len);
    if (!r) {
        @panic("Compilation failed!");
    }
}
