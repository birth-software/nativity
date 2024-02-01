#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/IR/DIBuilder.h"

#include "llvm/MC/TargetRegistry.h"

#include "llvm/TargetParser/Host.h"
#include "llvm/Target/TargetOptions.h"
#include "llvm/Target/TargetMachine.h"

#include "llvm/Support/TargetSelect.h"
#include "llvm/Support/FileSystem.h"

#include "lld/Common/CommonLinkerContext.h"

using namespace llvm;

extern "C" LLVMContext* NativityLLVMCreateContext()
{
    auto* context = new LLVMContext();
    return context;
}

extern "C" Module* NativityLLVMCreateModule(const char* name_ptr, size_t name_len, LLVMContext& context)
{
    auto name = StringRef(name_ptr, name_len);
    auto* module = new Module(name, context);
    return module;
}

extern "C" IRBuilder<>* NativityLLVMCreateBuilder(LLVMContext& Context)
{
    auto* builder = new IRBuilder<>(Context);
    return builder;
}

extern "C" DIBuilder* NativityLLVMModuleCreateDebugInfoBuilder(Module& module)
{
    DIBuilder* builder = new DIBuilder(module);
    return builder;
}

extern "C" DIFile* NativityLLVMDebugInfoBuilderCreateFile(DIBuilder& builder, const char* filename_ptr, size_t filename_len, const char* directory_ptr, size_t directory_len)
{
    auto filename = StringRef(filename_ptr, filename_len);
    auto directory = StringRef(directory_ptr, directory_len);
    auto* file = builder.createFile(filename, directory);
    return file;
}

extern "C" DICompileUnit* NativityLLVMDebugInfoBuilderCreateCompileUnit(DIBuilder& builder, unsigned language, DIFile* file, const char* producer_ptr, size_t producer_len, bool is_optimized, const char* flags_ptr, size_t flags_len, unsigned runtime_version, const char* split_name_ptr, size_t split_name_len, DICompileUnit::DebugEmissionKind debug_emission_kind, uint64_t DWOId, bool split_debug_inlining, bool debug_info_for_profiling, DICompileUnit::DebugNameTableKind debug_name_table_kind, bool ranges_base_address, const char* sysroot_ptr, size_t sysroot_len, const char* sdk_ptr, size_t sdk_len)
{
    auto producer = StringRef(producer_ptr, producer_len);
    auto flags = StringRef(flags_ptr, flags_len);
    auto split_name = StringRef(split_name_ptr, split_name_len);
    auto sysroot = StringRef(sysroot_ptr, sysroot_len);
    auto sdk = StringRef(sdk_ptr, sdk_len);
    auto* compile_unit = builder.createCompileUnit(language, file, producer, is_optimized, flags, runtime_version, split_name, debug_emission_kind, DWOId, split_debug_inlining, debug_info_for_profiling, debug_name_table_kind, ranges_base_address, sysroot, sdk);
    return compile_unit;
}

extern "C" DISubprogram* NativityLLVMDebugInfoBuilderCreateFunction(DIBuilder& builder, DIScope* scope, const char* name_ptr, size_t name_len, const char* linkage_name_ptr, size_t linkage_name_len, DIFile* file, unsigned line_number, DISubroutineType* type, unsigned scope_line, DINode::DIFlags flags, DISubprogram::DISPFlags subprogram_flags, DISubprogram* declaration)
{
    auto name = StringRef(name_ptr, name_len);
    auto linkage_name = StringRef(linkage_name_ptr, linkage_name_len);
    DITemplateParameterArray template_parameters = nullptr; 
    DITypeArray thrown_types = nullptr;
    DINodeArray annotations = nullptr;
    StringRef target_function_name = "";

    auto* function = builder.createFunction(scope, name, linkage_name, file, line_number, type, scope_line, flags, subprogram_flags, template_parameters, declaration, thrown_types, annotations, target_function_name);
    return function;
}

extern "C" DISubroutineType* NativityLLVMDebugInfoBuilderCreateSubroutineType(DIBuilder& builder, DIType** parameter_types_ptr, size_t parameter_type_count, DINode::DIFlags flags, dwarf::CallingConvention calling_convention)
{
    auto metadata_list = ArrayRef<Metadata*>(reinterpret_cast<Metadata**>( parameter_types_ptr), parameter_type_count);
    auto parameter_types = builder.getOrCreateTypeArray(metadata_list);
    auto* subroutine_type = builder.createSubroutineType(parameter_types, flags, calling_convention);
    return subroutine_type;
}

extern "C" DILexicalBlock* NativityLLVMDebugInfoBuilderCreateLexicalBlock(DIBuilder& builder, DIScope* parent_scope, DIFile* parent_file, unsigned line, unsigned column)
{
    assert(isa<DILocalScope>(parent_scope));
    auto* block = builder.createLexicalBlock(parent_scope, parent_file, line, column);
    return block;
}

extern "C" void NativityLLVMBuilderSetCurrentDebugLocation(IRBuilder<>& builder, LLVMContext& context, unsigned line, unsigned column, DIScope* scope, Function* function)
{
    auto debug_location = DILocation::get(context, line, column, scope);
    builder.SetCurrentDebugLocation(debug_location);
}

extern "C" DILocalVariable* NativityLLVMDebugInfoBuilderCreateParameterVariable(DIBuilder& builder, DIScope* scope, const char* name_ptr, size_t name_len, unsigned argument_index, DIFile* file, unsigned line_number, DIType* type, bool always_preserve, DINode::DIFlags flags)
{
    assert(isa<DILocalScope>(scope));
    auto name = StringRef(name_ptr, name_len);
    auto* parameter_variable = builder.createParameterVariable(scope, name, argument_index, file, line_number, type, always_preserve, flags);
    return parameter_variable;
}

extern "C" DILocalVariable* NativityLLVMDebugInfoBuilderCreateAutoVariable(DIBuilder& builder, DIScope* scope, const char* name_ptr, size_t name_len, DIFile* file, unsigned line_number, DIType* type, bool always_preserve, DINode::DIFlags flags, uint32_t alignment) // 0 means 1 << 0 (alignment of 1)
{
    auto name = StringRef(name_ptr, name_len);
    auto* auto_variable = builder.createAutoVariable(scope, name, file, line_number, type, always_preserve, flags, alignment);
    return auto_variable;
}

extern "C" Instruction* NativityLLVMDebugInfoBuilderInsertDeclare(DIBuilder& builder, Value* pointer, DILocalVariable* local_variable, LLVMContext& context, unsigned line, unsigned column, DIScope* scope, BasicBlock* basic_block)
{
    auto debug_location = DILocation::get(context, line, column, scope);
    auto* expression = builder.createExpression();
    auto* instruction = builder.insertDeclare(pointer, local_variable, expression, debug_location, basic_block); 
    return instruction;
}

extern "C" DIType* NativityLLVMDebugInfoBuilderCreateBasicType(DIBuilder& builder, const char* name_ptr, size_t name_len, uint64_t bit_count, unsigned dwarf_encoding, DINode::DIFlags flags)
{
    auto name = StringRef(name_ptr, name_len);
    auto* type = builder.createBasicType(name, bit_count, dwarf_encoding, flags);
    return type;
}

extern "C" DIDerivedType* NativityLLVMDebugInfoBuilderCreatePointerType(DIBuilder& builder, DIType* element_type, uint64_t pointer_bit_count, uint32_t alignment, const char* name_ptr, size_t name_len)
{
    auto name = StringRef(name_ptr, name_len);
    std::optional<unsigned> DWARFAddressSpace = std::nullopt;
    DINodeArray annotations = nullptr;
    auto* pointer_type = builder.createPointerType(element_type, pointer_bit_count, alignment, DWARFAddressSpace, name, annotations);
    return pointer_type;
}

extern "C" DICompositeType* NativityLLVMDebugInfoBuilderCreateStructType(DIBuilder& builder, DIScope* scope, const char* name_ptr, size_t name_len, DIFile* file, unsigned line_number, uint64_t bit_count, uint32_t alignment, DINode::DIFlags flags, DIType* derived_from, DIType** element_type_ptr, size_t element_type_count)
{
    auto name = StringRef(name_ptr, name_len);
    auto type_array = ArrayRef<Metadata*>(reinterpret_cast<Metadata**>(element_type_ptr), element_type_count);

    auto* struct_type = builder.createStructType(scope, name, file, line_number, bit_count, alignment, flags, derived_from, builder.getOrCreateArray(type_array));
    return struct_type;
}

extern "C" DICompositeType* NativityLLVMDebugInfoBuilderCreateArrayType(DIBuilder& builder, uint64_t bit_size, uint32_t alignment, DIType* type, size_t element_count)
{
    Metadata* subranges[1] = {
        builder.getOrCreateSubrange(0, element_count),
    };
    DINodeArray subscripts = builder.getOrCreateArray(ArrayRef<Metadata*>(subranges, sizeof(subranges) / sizeof(subranges[0])));

    auto* array_type = builder.createArrayType(bit_size, alignment, type, subscripts);
    return array_type;
}

extern "C" DIEnumerator* NativityLLVMDebugInfoBuilderCreateEnumerator(DIBuilder& builder, const char* name_ptr, size_t name_len, uint64_t value, bool is_unsigned)
{

    // DIEnumerator *DIBuilder::createEnumerator(StringRef Name, uint64_t Val,
    auto name = StringRef(name_ptr, name_len);
    auto* enumerator = builder.createEnumerator(name, value, is_unsigned);
    return enumerator;
}

extern "C" DICompositeType* NativityLLVMDebugInfoBuilderCreateEnumerationType(DIBuilder& builder, DIScope* scope, const char* name_ptr, size_t name_len, DIFile* file, unsigned line, uint64_t bit_size, uint32_t alignment, DIEnumerator** enumerator_ptr, size_t enumerator_count, DIType* underlying_type)
{
    auto name = StringRef(name_ptr, name_len);
    DINodeArray enumerators = builder.getOrCreateArray(ArrayRef<Metadata*>(reinterpret_cast<Metadata**>(enumerator_ptr), enumerator_count));
    auto* enumeration_type = builder.createEnumerationType(scope, name, file, line, bit_size, alignment, enumerators, underlying_type);
    return enumeration_type;
}

extern "C" DICompositeType* NativityLLVMDebugInfoBuilderCreateReplaceableCompositeType(DIBuilder& builder, unsigned tag, const char* name_ptr, size_t name_len, DIScope* scope, DIFile* file, unsigned line)
{
    auto name = StringRef(name_ptr, name_len);
    auto* composite_type = builder.createReplaceableCompositeType(tag, name, scope, file, line);
    return composite_type;
}
extern "C" DISubprogram* NativityLLVMDebugInfoScopeToSubprogram(DIScope* scope)
{
    auto* subprogram = dyn_cast<DISubprogram>(scope);
    return subprogram;
}

extern "C" void NativityLLVMDebugInfoBuilderFinalizeSubprogram(DIBuilder& builder, DISubprogram* subprogram, const Function* function)
{
    assert(subprogram->describes(function));
    builder.finalizeSubprogram(subprogram);
}

extern "C" void NativityLLVMDebugInfoBuilderFinalize(DIBuilder& builder)
{
    builder.finalize();
}

extern "C" DIFile* NativityLLVMDebugInfoSubprogramGetFile(DISubprogram& subprogram)
{
    auto* file = subprogram.getFile();
    return file;
}

extern "C" DIType* NativityLLVMDebugInfoSubprogramGetArgumentType(DISubprogram& subprogram, size_t argument_index)
{
    auto* argument_type = subprogram.getType()->getTypeArray()[argument_index];
    return argument_type;
}

extern "C" unsigned NativityLLVMArgumentGetIndex(Argument& argument)
{
    unsigned argument_index = argument.getArgNo();
    return argument_index;
}

extern "C" FunctionType* NativityLLVMGetFunctionType(Type* return_type, Type** type_ptr, size_t type_count, bool var_args)
{
    auto types = ArrayRef<Type*>(type_ptr, type_count);
    auto* function_type = FunctionType::get(return_type, types, var_args);
    return function_type;
}

extern "C" IntegerType* NativityLLVMGetIntegerType(LLVMContext& context, unsigned bit_count)
{
    auto integer_type = IntegerType::get(context, bit_count);
    return integer_type;
}

extern "C" PointerType* NativityLLVMGetPointerType(LLVMContext& context, unsigned address_space)
{
    auto pointer_type = PointerType::get(context, address_space);
    return pointer_type;
}

extern "C" ArrayType* NativityLLVMGetArrayType(Type* element_type, uint64_t element_count)
{
    auto* array_type = ArrayType::get(element_type, element_count);
    return array_type;
}

extern "C" StructType* NativityLLVMCreateStructType(LLVMContext& context, Type** type_ptr, size_t type_count, const char* name_ptr, size_t name_len, bool is_packed)
{
    auto types = ArrayRef<Type*>(type_ptr, type_count);
    auto name = StringRef(name_ptr, name_len);

    auto* struct_type = StructType::create(context, types, name, is_packed);
    return struct_type;
}
extern "C" Function* NativityLLVMModuleGetFunction(Module& module, const char* name_ptr, size_t name_len)
{
    auto name = StringRef(name_ptr, name_len);
    auto* function = module.getFunction(name);
    return function;
}

extern "C" void NativityLLVMFunctionAddAttributeKey(Function& function, Attribute::AttrKind attribute)
{
    function.addFnAttr(attribute);
}

extern "C" Function* NativityLLVModuleCreateFunction(Module* module, FunctionType* function_type, GlobalValue::LinkageTypes linkage_type, unsigned address_space, const char* name_ptr, size_t name_len)
{
    auto name = StringRef(name_ptr, name_len);
    auto* function = Function::Create(function_type, linkage_type, address_space, name, module);
    return function;
}

extern "C" BasicBlock* NativityLLVMCreateBasicBlock(LLVMContext& context, const char* name_ptr, size_t name_len, Function* parent, BasicBlock* insert_before)
{
    auto name = StringRef(name_ptr, name_len);
    auto* basic_block = BasicBlock::Create(context, name, parent, insert_before);
    return basic_block;
}

extern "C" PHINode* NativityLLVMCreatePhiNode(Type* type, unsigned reserved_value_count, const char* name_ptr, size_t name_len, BasicBlock* basic_block)
{
    auto name = StringRef(name_ptr, name_len);
    auto* phi_node = PHINode::Create(type, reserved_value_count, name, basic_block);
    return phi_node;
}

extern "C" void NativityLLVMBasicBlockRemoveFromParent(BasicBlock* basic_block)
{
    basic_block->eraseFromParent();
}

extern "C" void NativityLLVMBuilderSetInsertPoint(IRBuilder<>& builder, BasicBlock* basic_block)
{
    builder.SetInsertPoint(basic_block);
}

extern "C" void NativityLLVMValueSetName(Value* value, const char* name_ptr, size_t name_len)
{
    auto name = StringRef(name_ptr, name_len);
    value->setName(name);
}

extern "C" Type* NativityLLVMValueGetType(Value* value)
{
    auto* type = value->getType();
    return type;
}

extern "C" void NativityLLVMFunctionGetArguments(Function& function, Argument** argument_ptr, size_t* argument_count)
{
    auto actual_argument_count = function.arg_size();
    assert(actual_argument_count <= *argument_count);
    *argument_count = actual_argument_count;
    size_t arg_i = 0;
    for (auto& Arg : function.args()) {
        argument_ptr[arg_i] = &Arg;
        arg_i += 1;
    }
}

extern "C" void NativityLLVMFunctionSetSubprogram(Function& function, DISubprogram* subprogram)
{
    function.setSubprogram(subprogram);
}

extern "C" DISubprogram* NativityLLVMFunctionGetSubprogram(Function& function)
{
    auto* subprogram = function.getSubprogram();
    return subprogram;
}

extern "C" void NativityLLVMGlobalVariableSetInitializer(GlobalVariable& global_variable, Constant* constant_initializer)
{
    global_variable.setInitializer(constant_initializer);
}

extern "C" Constant* NativityLLVMConstantStruct(StructType* struct_type, Constant** constant_ptr, size_t constant_count)
{
    auto constants = ArrayRef<Constant*>(constant_ptr, constant_count);
    auto* constant_struct = ConstantStruct::get(struct_type, constants);
    return constant_struct;
}

extern "C" StoreInst* NativityLLVMBuilderCreateStore(IRBuilder<>& builder, Value* value, Value* pointer, bool is_volatile)
{
    auto* store = builder.CreateStore(value, pointer, is_volatile);
    return store;
}

extern "C" AllocaInst* NativityLLVMBuilderCreateAlloca(IRBuilder<>& builder, Type* type, unsigned address_space, Value* array_size, const char* name_ptr, size_t name_len)
{
    auto name = StringRef(name_ptr, name_len);
    auto* alloca = builder.CreateAlloca(type, address_space, array_size, name);
    return alloca;
}

extern "C" Type* NativityLLVMGetVoidType(LLVMContext& context)
{
    auto* void_type = Type::getVoidTy(context);
    return void_type;
}

extern "C" Value* NativityLLVMBuilderCreateICmp(IRBuilder<>& builder, CmpInst::Predicate comparation, Value* left, Value* right, const char* name_ptr, size_t name_len)
{
    auto name = StringRef(name_ptr, name_len);
    auto* icmp = builder.CreateICmp(comparation, left, right, name);
    return icmp;
}

extern "C" LoadInst* NativityLLVMBuilderCreateLoad(IRBuilder<>& builder, Type* type, Value* value, bool is_volatile, const char* name_ptr, size_t name_len)
{
    auto name = StringRef(name_ptr, name_len);
    auto* load = builder.CreateLoad(type, value, is_volatile, name);
    return load;
}

extern "C" ReturnInst* NativityLLVMBuilderCreateRet(IRBuilder<>& builder, Value* value)
{
    auto* ret = builder.CreateRet(value);
    return ret;
}

extern "C" InlineAsm* NativityLLVMGetInlineAssembly(FunctionType* function_type, const char* assembly_ptr, size_t assembly_len, const char* constraints_ptr, size_t constrains_len, bool has_side_effects, bool is_align_stack, InlineAsm::AsmDialect dialect, bool can_throw)
{
    auto assembly = StringRef(assembly_ptr, assembly_len);
    auto constraints = StringRef(constraints_ptr, constrains_len);
    auto* inline_asm = InlineAsm::get(function_type, assembly, constraints, has_side_effects, is_align_stack, dialect, can_throw);
    return inline_asm;
}

extern "C" Value* NativityLLVMBuilderCreateCast(IRBuilder<>& builder, Instruction::CastOps cast_type, Value* value, Type* type, const char* name_ptr, size_t name_len)
{
    auto name = StringRef(name_ptr, name_len);
    auto* cast = builder.CreateCast(cast_type, value, type, name);
    return cast;
}

extern "C" CallInst* NativityLLVMBuilderCreateCall(IRBuilder<>& builder, FunctionType* function_type, Value* callee, Value** argument_ptr, size_t argument_count, const char* name_ptr, size_t name_len, MDNode* fp_math_tag)
{
    if (auto* foo = static_cast<FunctionType*>(callee->getType())) {
        int k = 0;
    }
    auto arguments = ArrayRef<Value*>(argument_ptr, argument_count);
    auto name = StringRef(name_ptr, name_len);
    auto* call = builder.CreateCall(function_type, callee, arguments, name, fp_math_tag);
    return call;
}

extern "C" UnreachableInst* NativityLLVMBuilderCreateUnreachable(IRBuilder<>& builder)
{
    auto* unreachable = builder.CreateUnreachable();
    return unreachable;
}

extern "C" GlobalVariable* NativityLLVMModuleAddGlobalVariable(Module& module, Type* type, bool is_constant, GlobalValue::LinkageTypes linkage_type, Constant* initializer, const char* name_ptr, size_t name_len, GlobalVariable* insert_before, GlobalValue::ThreadLocalMode thread_local_mode, unsigned address_space, bool externally_initialized)
{
    auto name = StringRef(name_ptr, name_len);
    auto* global_variable = new GlobalVariable(module, type, is_constant, linkage_type, initializer, name, insert_before, thread_local_mode, address_space, externally_initialized);
    return global_variable;
}

extern "C" Value* NativityLLVMBuilderCreateAdd(IRBuilder<>& builder, Value* left, Value* right, const char* name_ptr, size_t name_len, bool no_unsigned_wrapping, bool no_signed_wrapping)
{
    auto name = StringRef(name_ptr, name_len);
    auto* add = builder.CreateAdd(left, right, name, no_unsigned_wrapping, no_signed_wrapping);
    return add;
}

extern "C" Value* NativityLLVMBuilderCreateSub(IRBuilder<>& builder, Value* left, Value* right, const char* name_ptr, size_t name_len, bool no_unsigned_wrapping, bool no_signed_wrapping)
{
    auto name = StringRef(name_ptr, name_len);
    auto* add = builder.CreateSub(left, right, name, no_unsigned_wrapping, no_signed_wrapping);
    return add;
}

extern "C" Value* NativityLLVMBuilderCreateMultiply(IRBuilder<>& builder, Value* left, Value* right, const char* name_ptr, size_t name_len, bool no_unsigned_wrapping, bool no_signed_wrapping)
{
    auto name = StringRef(name_ptr, name_len);
    auto* multiply = builder.CreateMul(left, right, name, no_unsigned_wrapping, no_signed_wrapping);
    return multiply;
}

extern "C" Value* NativityLLVMBuilderCreateUDiv(IRBuilder<>& builder, Value* left, Value* right, const char* name_ptr, size_t name_len, bool is_exact)
{
    auto name = StringRef(name_ptr, name_len);
    auto* result = builder.CreateUDiv(left, right, name, is_exact);
    return result;
}

extern "C" Value* NativityLLVMBuilderCreateSDiv(IRBuilder<>& builder, Value* left, Value* right, const char* name_ptr, size_t name_len, bool is_exact)
{
    auto name = StringRef(name_ptr, name_len);
    auto* result = builder.CreateSDiv(left, right, name, is_exact);
    return result;
}

extern "C" Value* NativityLLVMBuilderCreateURem(IRBuilder<>& builder, Value* left, Value* right, const char* name_ptr, size_t name_len)
{
    auto name = StringRef(name_ptr, name_len);
    auto* result = builder.CreateURem(left, right, name);
    return result;
}

extern "C" Value* NativityLLVMBuilderCreateSRem(IRBuilder<>& builder, Value* left, Value* right, const char* name_ptr, size_t name_len)
{
    auto name = StringRef(name_ptr, name_len);
    auto* result = builder.CreateSRem(left, right, name);
    return result;
}

extern "C" Value* NativityLLVMBuilderCreateXor(IRBuilder<>& builder, Value* left, Value* right, const char* name_ptr, size_t name_len)
{
    auto name = StringRef(name_ptr, name_len);
    auto* result = builder.CreateXor(left, right, name);
    return result;
}

extern "C" Value* NativityLLVMBuilderCreateAnd(IRBuilder<>& builder, Value* left, Value* right, const char* name_ptr, size_t name_len)
{
    auto name = StringRef(name_ptr, name_len);
    auto* result = builder.CreateAnd(left, right, name);
    return result;
}

extern "C" Value* NativityLLVMBuilderCreateOr(IRBuilder<>& builder, Value* left, Value* right, const char* name_ptr, size_t name_len)
{
    auto name = StringRef(name_ptr, name_len);
    auto* result = builder.CreateOr(left, right, name);
    return result;
}

extern "C" Value* NativityLLVMBuilderCreateShiftLeft(IRBuilder<>& builder, Value* left, Value* right, const char* name_ptr, size_t name_len, bool no_unsigned_wrapping, bool no_signed_wrapping)
{
    auto name = StringRef(name_ptr, name_len);
    auto* shl = builder.CreateShl(left, right, name, no_unsigned_wrapping, no_signed_wrapping);
    return shl;
}

extern "C" Value* NativityLLVMBuilderCreateLogicalShiftRight(IRBuilder<>& builder, Value* left, Value* right, const char* name_ptr, size_t name_len, bool is_exact)
{
    auto name = StringRef(name_ptr, name_len);
    auto* result = builder.CreateLShr(left, right, name, is_exact);
    return result;
}

extern "C" Value* NativityLLVMBuilderCreateArithmeticShiftRight(IRBuilder<>& builder, Value* left, Value* right, const char* name_ptr, size_t name_len, bool is_exact)
{
    auto name = StringRef(name_ptr, name_len);
    auto* result = builder.CreateAShr(left, right, name, is_exact);
    return result;
}

extern "C" Value* NativityLLVMBuilderCreateGEP(IRBuilder<>& builder, Type* type, Value* pointer, Value** index_ptr, size_t index_count, const char* name_ptr, size_t name_len, bool in_bounds)
{
    auto index_list = ArrayRef<Value*>(index_ptr, index_count);
    auto name = StringRef(name_ptr, name_len);
    auto* GEP = builder.CreateGEP(type, pointer, index_list, name, in_bounds);
    return GEP;
}

extern "C" BranchInst* NativityLLVMBuilderCreateBranch(IRBuilder<>& builder, BasicBlock* basic_block)
{
    auto* conditional_branch = builder.CreateBr(basic_block);
    return conditional_branch;
}

extern "C" BranchInst* NativityLLVMBuilderCreateConditionalBranch(IRBuilder<>& builder, Value* condition, BasicBlock* true_block, BasicBlock* false_block, MDNode* branch_weights, MDNode* unpredictable)
{
    auto* conditional_branch = builder.CreateCondBr(condition, true_block, false_block, branch_weights, unpredictable);
    return conditional_branch;
}

extern "C" Intrinsic::ID NativityLLVMLookupIntrinsic(const char* name_ptr, size_t name_len)
{
    auto name = StringRef(name_ptr, name_len);
    Intrinsic::ID id = Function::lookupIntrinsicID(name);
    return id;
}

extern "C" FunctionType* NativityLLVMContextGetIntrinsicType(LLVMContext& context, Intrinsic::ID intrinsic_id, Type** parameter_type_ptr, size_t parameter_type_count)
{
    assert(intrinsic_id < Intrinsic::num_intrinsics);
    auto parameter_types = ArrayRef<Type*>(parameter_type_ptr, parameter_type_count);
    auto* function_type = Intrinsic::getType(context, intrinsic_id, parameter_types);
    return function_type;
}

extern "C" Function* NativityLLVMModuleGetIntrinsicDeclaration(Module* module, Intrinsic::ID intrinsic_id, Type** parameter_types_ptr, size_t parameter_type_count)
{
    auto parameter_types = ArrayRef<Type*>(parameter_types_ptr, parameter_type_count);
    assert(intrinsic_id < Intrinsic::num_intrinsics);
    Function* function = Intrinsic::getDeclaration(module, intrinsic_id, parameter_types);
    return function;
}


extern "C" Value* NativityLLVMBuilderCreateExtractValue(IRBuilder<>& builder, Value* aggregate, unsigned* indices_ptr, size_t indices_len, const char* name_ptr, size_t name_len)
{
    auto indices = ArrayRef<unsigned>(indices_ptr, indices_len);
    auto name = StringRef(name_ptr, name_len);
    auto* value = builder.CreateExtractValue(aggregate, indices, name);
    return value;
}

extern "C" Value* NativityLLVMBuilderCreateInsertValue(IRBuilder<>& builder, Value* aggregate, Value* value, unsigned* indices_ptr, size_t indices_len, const char* name_ptr, size_t name_len)
{
    auto indices = ArrayRef<unsigned>(indices_ptr, indices_len);
    auto name = StringRef(name_ptr, name_len);
    auto* result = builder.CreateInsertValue(aggregate, value, indices, name);
    return result;
}

extern "C" ConstantInt* NativityLLVMContextGetConstantInt(LLVMContext& context, unsigned bit_count, uint64_t value, bool is_signed)
{
    auto int_type = APInt(bit_count, value, is_signed);
    auto constant_int = ConstantInt::get(context, int_type);
    return constant_int;
}

extern "C" Constant* NativityLLVMContextGetConstString(LLVMContext& context, const char* string_ptr, size_t string_len, bool null_terminate)
{
    auto string = StringRef(string_ptr, string_len);
    auto* constant = ConstantDataArray::getString(context, string, null_terminate);
    return constant;
}

extern "C" Constant* NativityLLVMContextGetConstArray(ArrayType* array_type, Constant** value_ptr, size_t value_count)
{
    auto values = ArrayRef<Constant*>(value_ptr, value_count);
    auto* constant_array = ConstantArray::get(array_type, values);
    return constant_array;
}

extern "C" Constant* NativityLLVMContextCreateGlobalStringPointer(IRBuilder<>& builder, const char* string_ptr, size_t string_len, const char* name_ptr, size_t name_len, unsigned address_space, Module* module)
{
    auto string = StringRef(string_ptr, string_len);
    auto name = StringRef(name_ptr, name_len);
    Constant* constant = builder.CreateGlobalStringPtr(string, name, address_space, module);
    return constant;
}

void stream_to_string(raw_string_ostream& stream, const char** message_ptr, size_t* message_len)
{
    stream.flush();

    auto string = stream.str();
    char* result = new char[string.length()];
    memcpy(result, string.c_str(), string.length());

    *message_ptr = result;
    *message_len = string.length();
}

extern "C" bool NativityLLVMVerifyFunction(Function& function, const char** message_ptr, size_t* message_len)
{
    std::string message_buffer;
    raw_string_ostream message_stream(message_buffer);

    bool result = verifyFunction(function, &message_stream);
    auto size = message_stream.str().size();
    stream_to_string(message_stream, message_ptr, message_len);

    // We invert the condition because LLVM conventions are just stupid
    return !result;
}

extern "C" bool NativityLLVMVerifyModule(const Module& module, const char** message_ptr, size_t* message_len)
{
    std::string message_buffer;
    raw_string_ostream message_stream(message_buffer);

    bool result = verifyModule(module, &message_stream);
    stream_to_string(message_stream, message_ptr, message_len);

    // We invert the condition because LLVM conventions are just stupid
    return !result;
}

extern "C" Type* NativityLLVMFunctionGetReturnType(const Function& function)
{
    auto* return_type = function.getReturnType();
    return return_type;
}

extern "C" const char* NativityLLVMFunctionToString(const Function& function, size_t* len)
{
  std::string buf;
  raw_string_ostream os(buf);
  function.print(os);
  os.flush();
  *len = buf.size();
  auto* result = strdup(buf.c_str());
  return result;
}

extern "C" Type* NativityLLVMAllocatGetAllocatedType(AllocaInst& alloca)
{
    auto* type = alloca.getAllocatedType();
    return type;
}

extern "C" AllocaInst* NativityLLVMValueToAlloca(Value* value)
{
    assert(value);
    auto* alloca = dyn_cast<AllocaInst>(value);
    return alloca;
}

extern "C" Constant* NativityLLVMValueToConstant(Value* value)
{
    assert(value);
    auto* constant = dyn_cast<Constant>(value);
    return constant;
}

extern "C" Function* NativityLLVMValueToFunction(Value* value)
{
    assert(value);
    auto* function = dyn_cast<Function>(value);
    return function;
}

extern "C" bool NativityLLVMTypeIsPointer(Type* type)
{
    bool is_pointer = type->isPointerTy();
    return is_pointer;
}

extern "C" bool NativityLLVMTypeIsInteger(Type* type)
{
    bool is_integer = type->isIntegerTy();
    return is_integer;
}

extern "C" StructType* NativityLLVMTypeToStruct(Type* type)
{
    auto* struct_type = dyn_cast<StructType>(type);
    return struct_type;
}

extern "C" FunctionType* NativityLLVMTypeToFunction(Type* type)
{
    auto* function_type = dyn_cast<FunctionType>(type);
    return function_type;
}

extern "C" ArrayType* NativityLLVMTypeToArray(Type* type)
{
    auto* array_type = dyn_cast<ArrayType>(type);
    return array_type;
}

extern "C" Type* NativityLLVMArrayTypeGetElementType(ArrayType* array_type)
{
    auto* element_type = array_type->getElementType();
    return element_type;
}

extern "C" const char* NativityLLVMModuleToString(const Module& module, size_t* len)
{
  std::string buf;
  raw_string_ostream os(buf);
  module.print(os, nullptr);
  os.flush();
  *len = buf.size();
  auto* result = strdup(buf.c_str());
  return result;
}

extern "C" BasicBlock* NativityLLVMBuilderGetInsertBlock(IRBuilder<>& builder)
{
    return builder.GetInsertBlock();
}

extern "C" bool NativityLLVMBuilderIsCurrentBlockTerminated(IRBuilder<>& builder)
{
    return builder.GetInsertBlock()->getTerminator() != nullptr;
}

extern "C" UndefValue* NativityLLVMGetUndefined(Type* type)
{
    auto* undefined_value = UndefValue::get(type);
    return undefined_value;
}

extern "C" void NativityLLVMFunctionSetCallingConvention(Function& function, CallingConv::ID calling_convention)
{
    function.setCallingConv(calling_convention);
}

extern "C" CallingConv::ID NativityLLVMFunctionGetCallingConvention(Function& function)
{
    auto calling_convention = function.getCallingConv();
    return calling_convention;
}

extern "C" void NativityLLVMCallSetCallingConvention(CallBase& call_instruction, CallingConv::ID calling_convention)
{
    call_instruction.setCallingConv(calling_convention);
}

extern "C" Constant* NativityLLVMGetStruct(StructType* struct_type, Constant** constants_ptr, size_t constant_count)
{
    auto constants = ArrayRef(constants_ptr, constant_count);
    auto* named_struct = ConstantStruct::get(struct_type, constants);
    return named_struct;
}

namespace lld {
    namespace coff {
        bool link(llvm::ArrayRef<const char *> args, llvm::raw_ostream &stdoutOS,
                llvm::raw_ostream &stderrOS, bool exitEarly, bool disableOutput);
    }
    namespace elf {
        bool link(llvm::ArrayRef<const char *> args, llvm::raw_ostream &stdoutOS,
                llvm::raw_ostream &stderrOS, bool exitEarly, bool disableOutput);
    }
    namespace wasm {
        bool link(llvm::ArrayRef<const char *> args, llvm::raw_ostream &stdoutOS,
                llvm::raw_ostream &stderrOS, bool exitEarly, bool disableOutput);
    }
    namespace macho {
        bool link(llvm::ArrayRef<const char *> args, llvm::raw_ostream &stdoutOS,
                llvm::raw_ostream &stderrOS, bool exitEarly, bool disableOutput);
    }
}

extern "C" bool NativityLLVMGenerateMachineCode(Module& module, const char* object_file_path_ptr, size_t object_file_path_len, const char* file_path_ptr, size_t file_path_len)
{
    InitializeAllTargetInfos();
    InitializeAllTargets();
    InitializeAllTargetMCs(); InitializeAllAsmParsers();
    InitializeAllAsmPrinters();

    auto target_triple = "x86_64-linux-none";
    auto cpu = "generic";
    auto features = "";
    TargetOptions target_options;

    std::string error;
    auto* target = TargetRegistry::lookupTarget(target_triple, error);
    assert(target);

    auto target_machine = target->createTargetMachine(target_triple, cpu, features, target_options, Reloc::Static);
    assert(target_machine);

    module.setDataLayout(target_machine->createDataLayout());
    module.setTargetTriple(target_triple);

    std::error_code EC;
    auto object_file_path = StringRef(object_file_path_ptr, object_file_path_len);
    raw_fd_ostream stream(object_file_path, EC, sys::fs::OF_None);
    if (EC) {
        return false;
    }

    legacy::PassManager pass;
    bool result = target_machine->addPassesToEmitFile(pass, stream, nullptr, llvm::CGFT_ObjectFile, false);
    if (result) {
        // We invert the condition because LLVM conventions are just stupid
        return false;
    }

    pass.run(module);
    stream.flush();
    
    return true;
}

enum class Format {
    elf = 0,
    macho = 1,
    coff = 2,
};

extern "C" bool NativityLLDLink(Format format, const char** argument_ptr, size_t argument_count, const char** stdout_ptr, size_t* stdout_len, const char** stderr_ptr, size_t* stderr_len)
{
    auto arguments = ArrayRef<const char*>(argument_ptr, argument_count);
    std::string stdout_string;
    raw_string_ostream stdout_stream(stdout_string);

    std::string stderr_string;
    raw_string_ostream stderr_stream(stderr_string);

    bool success = false;
    switch (format) {
        case Format::elf:
            success = lld::elf::link(arguments, stdout_stream, stderr_stream, true, false);
            break;
        case Format::coff:
            success = lld::coff::link(arguments, stdout_stream, stderr_stream, true, false);
        case Format::macho:
            success = lld::macho::link(arguments, stdout_stream, stderr_stream, true, false);
        default:
            break;
    }

    stream_to_string(stdout_stream, stdout_ptr, stdout_len);
    stream_to_string(stderr_stream, stderr_ptr, stderr_len);

    return success;
}

extern "C" bool NativityLLVMCompareTypes(Type* a, Type* b)
{
    if (auto* int_a = dyn_cast<IntegerType>(a)) {
        auto* int_b = dyn_cast<IntegerType>(b);
        assert(int_b);
        auto a_bit_count = int_a->getBitWidth();
        auto b_bit_count = int_b->getBitWidth();
        assert(a_bit_count == b_bit_count);
    }

    return a == b;
}