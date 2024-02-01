const llvm = @import("llvm.zig");
const LLVM = llvm.LLVM;
pub extern fn NativityLLVMCreateContext() ?*LLVM.Context;
pub extern fn NativityLLVMCreateModule(module_name_ptr: [*:0]const u8, module_name_len: usize, context: *LLVM.Context) ?*LLVM.Module;
pub extern fn NativityLLVMCreateBuilder(context: *LLVM.Context) ?*LLVM.Builder;
pub extern fn NativityLLVMGetFunctionType(return_type: *LLVM.Type, argument_type_ptr: [*]const *LLVM.Type, argument_type_len: usize, is_var_args: bool) ?*LLVM.Type.Function;
pub extern fn NativityLLVMGetIntegerType(context: *LLVM.Context, bit_count: u32) ?*LLVM.Type.Integer;
pub extern fn NativityLLVMGetPointerType(context: *LLVM.Context, address_space: u32) ?*LLVM.Type.Pointer;
pub extern fn NativityLLVMGetArrayType(element_type: *LLVM.Type, element_count: u64) ?*LLVM.Type.Array;
pub extern fn NativityLLVMCreateStructType(context: *LLVM.Context, type_ptr: [*]const *LLVM.Type, type_count: usize, name_ptr: [*]const u8, name_len: usize, is_packed: bool) ?*LLVM.Type.Struct;
pub extern fn NativityLLVMConstantStruct(struct_type: *LLVM.Type.Struct, constant_ptr: [*]const *LLVM.Value.Constant, constant_count: usize) ?*LLVM.Value.Constant;
pub extern fn NativityLLVMModuleGetFunction(module: *LLVM.Module, name_ptr: [*]const u8, name_len: usize) ?*LLVM.Value.Function;
pub extern fn NativityLLVModuleCreateFunction(module: *LLVM.Module, function_type: *LLVM.Type.Function, linkage: LLVM.Linkage, address_space: c_uint, name_ptr: [*]const u8, name_len: usize) ?*LLVM.Value.Function;
pub extern fn NativityLLVMModuleCreateDebugInfoBuilder(module: *LLVM.Module) ?*LLVM.DebugInfo.Builder;
pub extern fn NativityLLVMDebugInfoBuilderCreateFile(builder: *LLVM.DebugInfo.Builder, filename_ptr: [*]const u8, filename_len: usize, directory_ptr: [*]const u8, directory_len: usize) ?*LLVM.DebugInfo.File;
pub extern fn NativityLLVMDebugInfoBuilderCreateCompileUnit(builder: *LLVM.DebugInfo.Builder, language: LLVM.DebugInfo.Language, file: *LLVM.DebugInfo.File, producer_ptr: [*]const u8, producer_len: usize, is_optimized: bool, flags_ptr: [*]const u8, flags_len: usize, runtime_version: c_uint, split_name_ptr: [*]const u8, split_name_len: usize, debug_info_emission_kind: LLVM.DebugInfo.CompileUnit.EmissionKind, DWOId: u64, split_debug_inlining: bool, debug_info_for_profiling: bool, debug_info_name_table_kind: LLVM.DebugInfo.CompileUnit.NameTableKind, ranges_base_address: bool, sysroot_ptr: [*]const u8, sysroot_len: usize, sdk_ptr: [*]const u8, sdk_len: usize) ?*LLVM.DebugInfo.CompileUnit;
pub extern fn NativityLLVMDebugInfoBuilderCreateFunction(builder: *LLVM.DebugInfo.Builder, scope: *LLVM.DebugInfo.Scope, name_ptr: [*]const u8, name_len: usize, linkage_name_ptr: [*]const u8, linkage_name_len: usize, file: *LLVM.DebugInfo.File, line_number: c_uint, type: *LLVM.DebugInfo.SubroutineType, scope_line: c_uint, flags: LLVM.DebugInfo.Node.Flags, subprogram_flags: LLVM.DebugInfo.Subprogram.Flags, declaration: ?*LLVM.DebugInfo.Subprogram) ?*LLVM.DebugInfo.Subprogram;
pub extern fn NativityLLVMDebugInfoBuilderCreateSubroutineType(builder: *LLVM.DebugInfo.Builder, parameter_types_ptr: [*]const *LLVM.DebugInfo.Type, parameter_type_count: usize, flags: LLVM.DebugInfo.Node.Flags, calling_convention: LLVM.DebugInfo.CallingConvention) ?*LLVM.DebugInfo.SubroutineType;
pub extern fn NativityLLVMDebugInfoBuilderCreateLexicalBlock(builder: *LLVM.DebugInfo.Builder, parent_scope: *LLVM.DebugInfo.Scope, parent_file: *LLVM.DebugInfo.File, line: c_uint, column: c_uint) ?*LLVM.DebugInfo.LexicalBlock;
pub extern fn NativityLLVMDebugInfoBuilderCreateParameterVariable(builder: *LLVM.DebugInfo.Builder, scope: *LLVM.DebugInfo.Scope, name_ptr: [*]const u8, name_len: usize, argument_index: c_uint, file: *LLVM.DebugInfo.File, line_number: c_uint, type: *LLVM.DebugInfo.Type, always_preserve: bool, flags: LLVM.DebugInfo.Node.Flags) ?*LLVM.DebugInfo.LocalVariable;
pub extern fn NativityLLVMDebugInfoBuilderCreateAutoVariable(builder: *LLVM.DebugInfo.Builder, scope: *LLVM.DebugInfo.Scope, name_ptr: [*]const u8, name_len: usize, file: *LLVM.DebugInfo.File, line_number: c_uint, type: *LLVM.DebugInfo.Type, always_preserve: bool, flags: LLVM.DebugInfo.Node.Flags, alignment: u32) ?*LLVM.DebugInfo.LocalVariable; // 0 means 1 << 0 (alignment of 1)
pub extern fn NativityLLVMDebugInfoBuilderInsertDeclare(builder: *LLVM.DebugInfo.Builder, pointer: *LLVM.Value, local_variable: *LLVM.DebugInfo.LocalVariable, context: *LLVM.Context, line: c_uint, column: c_uint, scope: *LLVM.DebugInfo.Scope, basic_block: *LLVM.Value.BasicBlock) ?*LLVM.Value.Instruction;
pub extern fn NativityLLVMDebugInfoBuilderCreateBasicType(builder: *LLVM.DebugInfo.Builder, name_ptr: [*]const u8, name_len: usize, bit_count: u64, dwarf_encoding: LLVM.DebugInfo.AttributeType, flags: LLVM.DebugInfo.Node.Flags) ?*LLVM.DebugInfo.Type;
pub extern fn NativityLLVMDebugInfoBuilderCreatePointerType(builder: *LLVM.DebugInfo.Builder, element_type: *LLVM.DebugInfo.Type, pointer_bit_count: u64, alignment: u32, name_ptr: [*]const u8, name_len: usize) ?*LLVM.DebugInfo.Type.Derived;
pub extern fn NativityLLVMDebugInfoBuilderCreateStructType(builder: *LLVM.DebugInfo.Builder, scope: ?*LLVM.DebugInfo.Scope, name_ptr: [*]const u8, name_len: usize, file: ?*LLVM.DebugInfo.File, line_number: c_uint, bit_count: u64, alignment: u32, flags: LLVM.DebugInfo.Node.Flags, derived_from: ?*LLVM.DebugInfo.Type, element_type_ptr: [*]const *LLVM.DebugInfo.Type, element_type_count: usize) ?*LLVM.DebugInfo.Type.Composite;
pub extern fn NativityLLVMDebugInfoBuilderCreateArrayType(builder: *LLVM.DebugInfo.Builder, bit_size: u64, alignment: u32, type: *LLVM.DebugInfo.Type, element_count: usize) ?*LLVM.DebugInfo.Type.Composite;
pub extern fn NativityLLVMDebugInfoBuilderCreateEnumerationType(builder: *LLVM.DebugInfo.Builder, scope: ?*LLVM.DebugInfo.Scope, name_ptr: [*]const u8, name_len: usize, file: *LLVM.DebugInfo.File, line: c_uint, bit_size: u64, alignment: u32, enumerator_ptr: [*]const *LLVM.DebugInfo.Type.Enumerator, enumerator_count: usize, underlying_type: *LLVM.DebugInfo.Type) ?*LLVM.DebugInfo.Type.Composite;
pub extern fn NativityLLVMDebugInfoBuilderCreateEnumerator(builder: *LLVM.DebugInfo.Builder, name_ptr: [*]const u8, name_len: usize, value: u64, is_unsigned: bool) ?*LLVM.DebugInfo.Type.Enumerator;
pub extern fn NativityLLVMDebugInfoBuilderCreateReplaceableCompositeType(builder: *LLVM.DebugInfo.Builder, tag: c_uint, name_ptr: [*]const u8, name_len: usize, scope: ?*LLVM.DebugInfo.Scope, file: ?*LLVM.DebugInfo.File, line: c_uint) ?*LLVM.DebugInfo.Type.Composite;
pub extern fn NativityLLVMDebugInfoBuilderFinalizeSubprogram(builder: *LLVM.DebugInfo.Builder, subprogram: *LLVM.DebugInfo.Subprogram, function: *LLVM.Value.Function) void;
pub extern fn NativityLLVMDebugInfoBuilderFinalize(builder: *LLVM.DebugInfo.Builder) void;
pub extern fn NativityLLVMDebugInfoSubprogramGetFile(subprogram: *LLVM.DebugInfo.Subprogram) ?*LLVM.DebugInfo.File;
pub extern fn NativityLLVMDebugInfoSubprogramGetArgumentType(subprogram: *LLVM.DebugInfo.Subprogram, argument_index: usize) ?*LLVM.DebugInfo.Type;
pub extern fn NativityLLVMDebugInfoScopeToSubprogram(scope: *LLVM.DebugInfo.Scope) ?*LLVM.DebugInfo.Subprogram;
pub extern fn NativityLLVMCreateBasicBlock(context: *LLVM.Context, name_ptr: [*]const u8, name_len: usize, parent_function: ?*LLVM.Value.Function, insert_before: ?*LLVM.Value.BasicBlock) ?*LLVM.Value.BasicBlock;
pub extern fn NativityLLVMBasicBlockRemoveFromParent(basic_block: *LLVM.Value.BasicBlock) void;
pub extern fn NativityLLVMBuilderSetInsertPoint(builder: *LLVM.Builder, basic_block: *LLVM.Value.BasicBlock) void;
pub extern fn NativityLLVMBuilderGetInsertBlock(builder: *LLVM.Builder) ?*LLVM.Value.BasicBlock;
pub extern fn NativityLLVMBuilderSetCurrentDebugLocation(builder: *LLVM.Builder, context: *LLVM.Context, line: c_uint, column: c_uint, scope: *LLVM.DebugInfo.Scope, function: *LLVM.Value.Function) void;
pub extern fn NativityLLVMValueSetName(value: *LLVM.Value, name_ptr: [*]const u8, name_len: usize) void;
pub extern fn NativityLLVMValueGetType(value: *LLVM.Value) *LLVM.Type;
pub extern fn NativityLLVMArgumentGetIndex(argument: *LLVM.Value.Argument) c_uint;
pub extern fn NativityLLVMFunctionGetArguments(function: *LLVM.Value.Function, argument_ptr: [*]*LLVM.Value.Argument, argument_len: *usize) void;
pub extern fn NativityLLVMFunctionGetReturnType(function: *LLVM.Value.Function) ?*LLVM.Type;
pub extern fn NativityLLVMBuilderCreateAlloca(builder: *LLVM.Builder, type: *LLVM.Type, address_space: c_uint, array_size: ?*LLVM.Value, name_ptr: [*]const u8, name_len: usize) ?*LLVM.Value.Instruction.Alloca;
pub extern fn NativityLLVMBuilderCreateStore(builder: *LLVM.Builder, value: *LLVM.Value, pointer: *LLVM.Value, is_volatile: bool) ?*LLVM.Value.Instruction.Store;
pub extern fn NativityLLVMContextGetConstantInt(context: *LLVM.Context, bit_count: c_uint, value: u64, is_signed: bool) ?*LLVM.Value.Constant.Int;
pub extern fn NativityLLVMContextGetConstString(context: *LLVM.Context, name_ptr: [*]const u8, name_len: usize, null_terminate: bool) ?*LLVM.Value.Constant;
pub extern fn NativityLLVMContextGetConstArray(array_type: *LLVM.Type.Array, value_ptr: [*]const *LLVM.Value.Constant, value_count: usize) ?*LLVM.Value.Constant;
pub extern fn NativityLLVMBuilderCreateICmp(builder: *LLVM.Builder, integer_comparison: LLVM.Value.Instruction.ICmp.Kind, left: *LLVM.Value, right: *LLVM.Value, name_ptr: [*]const u8, name_len: usize) ?*LLVM.Value;
pub extern fn NativityLLVMBuilderCreateLoad(builder: *LLVM.Builder, type: *LLVM.Type, value: *LLVM.Value, is_volatile: bool, name_ptr: [*]const u8, name_len: usize) ?*LLVM.Value.Instruction.Load;
pub extern fn NativityLLVMBuilderCreateRet(builder: *LLVM.Builder, value: ?*LLVM.Value) ?*LLVM.Value.Instruction.Ret;
pub extern fn NativityLLVMBuilderCreateCast(builder: *LLVM.Builder, cast_type: LLVM.Value.Instruction.Cast.Type, value: *LLVM.Value, type: *LLVM.Type, name_ptr: [*]const u8, name_len: usize) ?*LLVM.Value;
pub extern fn NativityLLVMFunctionAddAttributeKey(builder: *LLVM.Value.Function, attribute_key: LLVM.Attribute) void;
pub extern fn NativityLLVMGetVoidType(context: *LLVM.Context) ?*LLVM.Type;
pub extern fn NativityLLVMGetInlineAssembly(function_type: *LLVM.Type.Function, assembly_ptr: [*]const u8, assembly_len: usize, constraints_ptr: [*]const u8, constrains_len: usize, has_side_effects: bool, is_align_stack: bool, dialect: LLVM.Value.InlineAssembly.Dialect, can_throw: bool) ?*LLVM.Value.InlineAssembly;
pub extern fn NativityLLVMBuilderCreateCall(builder: *LLVM.Builder, function_type: *LLVM.Type.Function, callee: *LLVM.Value, argument_ptr: [*]const *LLVM.Value, argument_count: usize, name_ptr: [*]const u8, name_len: usize, fp_math_tag: ?*LLVM.Metadata.Node) ?*LLVM.Value.Instruction.Call;
pub extern fn NativityLLVMBuilderCreateUnreachable(builder: *LLVM.Builder) ?*LLVM.Value.Instruction.Unreachable;
pub extern fn NativityLLVMModuleAddGlobalVariable(module: *LLVM.Module, type: *LLVM.Type, is_constant: bool, linkage: LLVM.Linkage, initializer: ?*LLVM.Value.Constant, name_ptr: [*]const u8, name_len: usize, insert_before: ?*LLVM.Value.Constant.GlobalVariable, thread_local_mode: LLVM.ThreadLocalMode, address_space: c_uint, externally_initialized: bool) ?*LLVM.Value.Constant.GlobalVariable;
 
pub extern fn NativityLLVMBuilderCreateAdd(builder: *LLVM.Builder, left: *LLVM.Value, right: *LLVM.Value, name_ptr: [*]const u8, name_len: usize, no_unsigned_wrapping: bool, no_signed_wrapping: bool) ?*LLVM.Value;
pub extern fn NativityLLVMBuilderCreateSub(builder: *LLVM.Builder, left: *LLVM.Value, right: *LLVM.Value, name_ptr: [*]const u8, name_len: usize, no_unsigned_wrapping: bool, no_signed_wrapping: bool) ?*LLVM.Value;
pub extern fn NativityLLVMBuilderCreateMultiply(builder: *LLVM.Builder, left: *LLVM.Value, right: *LLVM.Value, name_ptr: [*]const u8, name_len: usize, no_unsigned_wrapping: bool, no_signed_wrapping: bool) ?*LLVM.Value;
pub extern fn NativityLLVMBuilderCreateShiftLeft(builder: *LLVM.Builder, left: *LLVM.Value, right: *LLVM.Value, name_ptr: [*]const u8, name_len: usize, no_unsigned_wrapping: bool, no_signed_wrapping: bool) ?*LLVM.Value;
 
pub extern fn NativityLLVMBuilderCreateUDiv(builder: *LLVM.Builder, left: *LLVM.Value, right: *LLVM.Value, name_ptr: [*]const u8, name_len: usize, is_exact: bool) ?*LLVM.Value;
pub extern fn NativityLLVMBuilderCreateSDiv(builder: *LLVM.Builder, left: *LLVM.Value, right: *LLVM.Value, name_ptr: [*]const u8, name_len: usize, is_exact: bool) ?*LLVM.Value;
pub extern fn NativityLLVMBuilderCreateURem(builder: *LLVM.Builder, left: *LLVM.Value, right: *LLVM.Value, name_ptr: [*]const u8, name_len: usize) ?*LLVM.Value;
pub extern fn NativityLLVMBuilderCreateSRem(builder: *LLVM.Builder, left: *LLVM.Value, right: *LLVM.Value, name_ptr: [*]const u8, name_len: usize) ?*LLVM.Value;
pub extern fn NativityLLVMBuilderCreateLogicalShiftRight(builder: *LLVM.Builder, left: *LLVM.Value, right: *LLVM.Value, name_ptr: [*]const u8, name_len: usize, is_exact: bool) ?*LLVM.Value;
pub extern fn NativityLLVMBuilderCreateArithmeticShiftRight(builder: *LLVM.Builder, left: *LLVM.Value, right: *LLVM.Value, name_ptr: [*]const u8, name_len: usize, is_exact: bool) ?*LLVM.Value;
 
pub extern fn NativityLLVMBuilderCreateXor(builder: *LLVM.Builder, left: *LLVM.Value, right: *LLVM.Value, name_ptr: [*]const u8, name_len: usize) ?*LLVM.Value;
pub extern fn NativityLLVMBuilderCreateAnd(builder: *LLVM.Builder, left: *LLVM.Value, right: *LLVM.Value, name_ptr: [*]const u8, name_len: usize) ?*LLVM.Value;
pub extern fn NativityLLVMBuilderCreateOr(builder: *LLVM.Builder, left: *LLVM.Value, right: *LLVM.Value, name_ptr: [*]const u8, name_len: usize) ?*LLVM.Value;
pub extern fn NativityLLVMBuilderCreateGEP(builder: *LLVM.Builder, type: *LLVM.Type, pointer: *LLVM.Value, index_ptr: [*]const *LLVM.Value, index_count: usize, name_ptr: [*]const u8, name_len: usize, in_bounds: bool) ?*LLVM.Value;
pub extern fn NativityLLVMBuilderCreateBranch(builder: *LLVM.Builder, basic_block: *LLVM.Value.BasicBlock) ?*LLVM.Value.Instruction.Branch;
pub extern fn NativityLLVMBuilderCreateConditionalBranch(builder: *LLVM.Builder, condition: *LLVM.Value, true_block: *LLVM.Value.BasicBlock, false_block: *LLVM.Value.BasicBlock, branch_weights: ?*LLVM.Metadata.Node, unpredictable: ?*LLVM.Metadata.Node) ?*LLVM.Value.Instruction.Branch;

pub extern fn NativityLLVMVerifyFunction(function: *LLVM.Value.Function, message_ptr: *[*]const u8, message_len: *usize) bool;
pub extern fn NativityLLVMVerifyModule(module: *LLVM.Module, message_ptr: *[*]const u8, message_len: *usize) bool;

pub extern fn NativityLLVMModuleToString(module: *LLVM.Module, message_len: *usize) [*]const u8;
pub extern fn NativityLLVMFunctionToString(function: *LLVM.Value.Function, message_len: *usize) [*]const u8;


pub extern fn NativityLLVMBuilderIsCurrentBlockTerminated(builder: *LLVM.Builder) bool;
pub extern fn NativityLLVMGetUndefined(type: *LLVM.Type) ?*LLVM.Value.Constant.Undefined;
pub extern fn NativityLLVMFunctionSetCallingConvention(function: *LLVM.Value.Function, calling_convention: LLVM.Value.Function.CallingConvention) void;
pub extern fn NativityLLVMFunctionGetCallingConvention(function: *LLVM.Value.Function) LLVM.Value.Function.CallingConvention;
pub extern fn NativityLLVMFunctionSetSubprogram(function: *LLVM.Value.Function, subprogram: *LLVM.DebugInfo.Subprogram) void;
pub extern fn NativityLLVMFunctionGetSubprogram(function: *LLVM.Value.Function) ?*LLVM.DebugInfo.Subprogram;

pub extern fn NativityLLVMCallSetCallingConvention(instruction: *LLVM.Value.Instruction.Call, calling_convention: LLVM.Value.Function.CallingConvention) void;
pub extern fn NativityLLVMGetStruct(struct_type: *LLVM.Type.Struct, constant_ptr: [*]const *LLVM.Value.Constant, constant_len: usize) ?*LLVM.Value.Constant;

pub extern fn NativityLLVMValueToConstant(value: *LLVM.Value) ?*LLVM.Value.Constant;
pub extern fn NativityLLVMValueToFunction(value: *LLVM.Value) ?*LLVM.Value.Function;

pub extern fn NativityLLVMTypeIsPointer(type: *LLVM.Type) bool;
pub extern fn NativityLLVMTypeIsInteger(type: *LLVM.Type) bool;

pub extern fn NativityLLVMTypeToStruct(type: *LLVM.Type) ?*LLVM.Type.Struct;
pub extern fn NativityLLVMTypeToFunction(type: *LLVM.Type) ?*LLVM.Type.Function;
pub extern fn NativityLLVMTypeToArray(type: *LLVM.Type) ?*LLVM.Type.Array;

pub extern fn NativityLLVMArrayTypeGetElementType(array_type: *LLVM.Type.Array) ?*LLVM.Type;
pub extern fn NativityLLVMLookupIntrinsic(name_ptr: [*]const u8, name_len: usize) LLVM.Value.IntrinsicID;
pub extern fn NativityLLVMModuleGetIntrinsicDeclaration(module: *LLVM.Module, intrinsic_id: LLVM.Value.IntrinsicID, parameter_types_ptr: [*]const *LLVM.Type, parameter_type_count: usize) ?*LLVM.Value.Function;
pub extern fn NativityLLVMContextGetIntrinsicType(context: *LLVM.Context, intrinsic_id: LLVM.Value.IntrinsicID, parameter_type_ptr: [*]const *LLVM.Type, parameter_type_count: usize) ?*LLVM.Type.Function;
pub extern fn NativityLLVMBuilderCreateExtractValue(builder: *LLVM.Builder, aggregate: *LLVM.Value, indices_ptr: [*]const c_uint, indices_len: usize, name_ptr: [*]const u8, name_len: usize) ?*LLVM.Value;
pub extern fn NativityLLVMBuilderCreateInsertValue(builder: *LLVM.Builder, aggregate: *LLVM.Value, value: *LLVM.Value, indices_ptr: [*]const c_uint, indices_len: usize, name_ptr: [*]const u8, name_len: usize) ?*LLVM.Value;
pub extern fn NativityLLVMContextCreateGlobalStringPointer(builder: *LLVM.Builder, string_ptr: [*]const u8, string_len: usize, name_ptr: [*]const u8, name_len: usize, address_space: c_uint, module: *LLVM.Module) ?*LLVM.Value.Constant;
pub extern fn NativityLLVMCompareTypes(a: *LLVM.Type, b: *LLVM.Type) bool;
pub extern fn NativityLLVMCreatePhiNode(type: *LLVM.Type, reserved_value_count: c_uint, name_ptr: [*]const u8, name_len: usize, basic_block: ?*LLVM.Value.BasicBlock) ?*LLVM.Value.Instruction.PhiNode;

pub extern fn NativityLLVMAllocatGetAllocatedType(alloca: *LLVM.Value.Instruction.Alloca) *LLVM.Type;
pub extern fn NativityLLVMValueToAlloca(value: *LLVM.Value) ?*LLVM.Value.Instruction.Alloca;
pub extern fn NativityLLVMGlobalVariableSetInitializer(global_variable: *LLVM.Value.Constant.GlobalVariable, constant_initializer: *LLVM.Value.Constant) void;

pub extern fn NativityLLVMGenerateMachineCode(module: *LLVM.Module, object_file_path_ptr: [*]const u8, object_file_path_len: usize, file_path_ptr: [*]const u8, file_path_len: usize) bool;
pub extern fn NativityLLDLink(format: llvm.Format, argument_ptr: [*]const [*:0]const u8, argument_count: usize, stdout_ptr: *[*]const u8, stdout_len: *usize, stderr_ptr: *[*]const u8, stderr_len: *usize) bool;
