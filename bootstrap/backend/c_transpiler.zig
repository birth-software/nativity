const std = @import("std");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;
const equal = std.mem.eql;

const Compilation = @import("../Compilation.zig");
const logln = Compilation.logln;
const Module = Compilation.Module;
const Type = Compilation.Type;
const Value = Compilation.Value;
const data_structures = @import("../data_structures.zig");
const ArrayList = data_structures.ArrayList;
const AutoArrayHashMap = data_structures.AutoArrayHashMap;
const StringArrayHashMap = data_structures.StringArrayHashMap;

pub const Logger = enum {
    g,

    pub var bitset = std.EnumSet(Logger).initMany(&.{
        .g,
    });
};

const margin_width = 4;

const TypeSet = struct {
    map: AutoArrayHashMap(Type.Index, TypeValue) = .{},

    const TypeValue = struct {
        underscore: []const u8,
        space: []const u8,
    };

    fn get(type_set: *const TypeSet, type_index: Type.Index, character: u8) ?[]const u8 {
        if (type_set.map.get(type_index)) |value| {
            const result = switch (character) {
                '_' => value.underscore,
                ' ' => value.space,
                else => unreachable,
            };
            return result;
        } else {
            return null;
        }
    }

    fn put(type_set: *TypeSet, allocator: Allocator, type_index: Type.Index, value: TypeValue) !void {
        try type_set.map.putNoClobber(allocator, type_index, value);
    }

    fn getOrPutValue(type_set: *TypeSet, allocator: Allocator, type_index: Type.Index, value: TypeValue) !TypeValue {
        const gop = try type_set.map.getOrPutValue(allocator, type_index, value);
        return gop.value_ptr.*;
    }
};

pub const TranslationUnit = struct {
    string_literals: ArrayList(u8) = .{},
    primitive_type_declarations: ArrayList(u8) = .{},
    type_forward_declarations: ArrayList(u8) = .{},
    macros: ArrayList(u8) = .{},
    type_declarations: ArrayList(u8) = .{},
    function_declarations: ArrayList(u8) = .{},
    global_variable_declarations: ArrayList(u8) = .{},
    function_definitions: ArrayList(u8) = .{},
    syscall_bitset: SyscallBitset = SyscallBitset.initEmpty(),
    function_definition_set: AutoArrayHashMap(Compilation.Function.Index, []const u8) = .{},
    function_declaration_set: AutoArrayHashMap(Compilation.Function.Index, []const u8) = .{},
    macro_set: std.EnumSet(Macro) = std.EnumSet(Macro).initEmpty(),
    struct_type_set: TypeSet = .{},
    optional_type_set: TypeSet = .{},
    slice_type_set: TypeSet = .{},
    array_type_set: TypeSet = .{},
    enum_type_set: TypeSet = .{},
    pointer_type_set: TypeSet = .{},
    declaration_set: AutoArrayHashMap(Compilation.Declaration.Index, []const u8) = .{},

    const SyscallBitset = std.StaticBitSet(7);

    fn create(module: *Module, allocator: Allocator) !*TranslationUnit {
        var unit = try allocator.create(TranslationUnit);
        unit.* = .{};
        try unit.primitive_type_declarations.appendSlice(allocator,
            \\typedef unsigned char u8;
            \\typedef unsigned short u16;
            \\typedef unsigned int u32;
            \\typedef unsigned long u64;
            \\typedef u64 usize;
            \\static_assert(sizeof(u8) == 1);
            \\static_assert(sizeof(u16) == 2);
            \\static_assert(sizeof(u32) == 4);
            \\static_assert(sizeof(u64) == 8);
            \\typedef signed char s8;
            \\typedef signed short s16;
            \\typedef signed int s32;
            \\typedef signed long s64;
            \\typedef s64 ssize;
            \\static_assert(sizeof(s8) == 1);
            \\static_assert(sizeof(s16) == 2);
            \\static_assert(sizeof(s32) == 4);
            \\static_assert(sizeof(s64) == 8);
            \\
            \\
        );

        {
            var function_declarations = module.types.function_declarations.iterator();
            while (function_declarations.nextIndex()) |function_declaration_index| {
                _ = try unit.writeFunctionDeclaration(module, allocator, function_declaration_index);
            }
        }

        {
            var function_definitions = module.types.function_definitions.iterator();
            while (function_definitions.nextIndex()) |function_definition_index| {
                _ = try unit.writeFunctionDefinition(module, allocator, function_definition_index);
            }
        }

        return unit;
    }

    fn writeFunctionDeclaration(unit: *TranslationUnit, module: *Module, allocator: Allocator, function_declaration_index: Compilation.Function.Index) ![]const u8 {
        if (unit.function_declaration_set.getIndex(function_declaration_index)) |index| {
            return unit.function_declaration_set.values()[index];
        } else {
            const function_name = try unit.renderFunctionDeclarationName(module, allocator, function_declaration_index);
            try unit.writeFunctionHeader(module, &unit.function_declarations, allocator, module.types.function_declarations.get(function_declaration_index), function_name);
            try unit.function_declaration_set.putNoClobber(allocator, function_declaration_index, function_name);

            try unit.function_declarations.appendSlice(allocator, ";\n\n");

            return function_name;
        }
    }

    fn writeFunctionDefinition(unit: *TranslationUnit, module: *Module, allocator: Allocator, function_definition_index: Compilation.Function.Index) ![]const u8 {
        if (unit.function_definition_set.getIndex(function_definition_index)) |index| {
            return unit.function_definition_set.values()[index];
        } else {
            const function_definition = module.types.function_definitions.get(function_definition_index);
            const function_prototype_type = function_definition.prototype;
            const function_prototype = module.types.function_prototypes.get(module.types.array.get(function_prototype_type).function);

            const function_name = try unit.renderFunctionDefinitionName(module, allocator, function_definition_index);
            try unit.writeFunctionHeader(module, &unit.function_declarations, allocator, function_definition, function_name);
            try unit.function_definition_set.putNoClobber(allocator, function_definition_index, function_name);

            try unit.writeFunctionHeader(module, &unit.function_definitions, allocator, function_definition, function_name);
            try unit.function_declarations.appendSlice(allocator, ";\n\n");

            try unit.function_definitions.append(allocator, ' ');
            try unit.writeBlock(module, &unit.function_definitions, allocator, function_definition.body, function_prototype.return_type, 0);
            try unit.function_definitions.append(allocator, '\n');

            return function_name;
        }
    }

    fn writeDeclaration(unit: *TranslationUnit, module: *Module, list: *ArrayList(u8), allocator: Allocator, declaration_index: Compilation.Declaration.Index, indentation: usize, separation_character: u8) !void {
        const declaration = module.values.declarations.get(declaration_index);
        const mangle = false;
        const name = try unit.renderDeclarationName(module, allocator, declaration_index, mangle);
        // if (equal(u8, name, "pointer")) {
        //     @breakpoint();
        // }

        if (declaration.mutability == .@"const") {
            switch (module.types.array.get(declaration.getType()).*) {
                .optional => |optional| switch (module.types.array.get(optional.element_type).*) {
                    .pointer => {},
                    else => {
                        try list.appendSlice(allocator, "const ");
                    },
                },
                .pointer => {},
                .integer,
                .@"struct",
                .slice,
                .bool,
                .array,
                => {
                    try list.appendSlice(allocator, "const ");
                },
                else => |t| @panic(@tagName(t)),
                //else => try list.appendSlice(allocator, "const "),
            }
        }

        try unit.writeType(module, list, allocator, declaration.getType(), separation_character);

        try list.append(allocator, ' ');

        try list.appendSlice(allocator, name);

        try list.appendSlice(allocator, " = ");

        try unit.writeValue(module, list, allocator, Type.Index.invalid, indentation, .{
            .value_index = declaration.init_value,
            .type_index = declaration.getType(),
        });
    }

    fn writeAssignment(unit: *TranslationUnit, module: *Module, list: *ArrayList(u8), allocator: Allocator, assignment_index: Compilation.Assignment.Index, function_return_type: Type.Index, indentation: usize) !void {
        const assignment = module.values.assignments.get(assignment_index);
        const left_type = module.values.array.get(assignment.destination).getType(module);
        try unit.writeValue(module, list, allocator, function_return_type, indentation, .{
            .value_index = assignment.destination,
            .type_index = left_type,
        });
        try list.append(allocator, ' ');
        switch (assignment.operation) {
            .none => {},
            .add => try list.append(allocator, '+'),
        }
        try list.appendSlice(allocator, "= ");

        try unit.writeValue(module, list, allocator, function_return_type, indentation, .{
            .value_index = assignment.source,
            .type_index = left_type,
        });
    }

    fn writeReturn(unit: *TranslationUnit, module: *Module, list: *ArrayList(u8), allocator: Allocator, return_index: Compilation.Return.Index, function_return_type: Type.Index, indentation: usize) !void {
        const return_expr = module.values.returns.get(return_index);
        try list.appendSlice(allocator, "return ");
        const return_value = module.values.array.get(return_expr.value);
        const return_value_type_index = return_value.getType(module);
        // _ = return_value_type_index;
        switch (module.types.array.get(function_return_type).*) {
            .optional => switch (module.types.array.get(return_value_type_index).*) {
                .optional => try unit.writeValue(module, list, allocator, function_return_type, indentation, .{
                    .value_index = return_expr.value,
                    .type_index = function_return_type,
                }),
                else => {
                    try list.append(allocator, '(');
                    try unit.writeType(module, list, allocator, function_return_type, '_');
                    try list.appendSlice(allocator, ") {\n");

                    try list.appendNTimes(allocator, ' ', indentation * margin_width);
                    try list.appendSlice(allocator, ".value = ");
                    try unit.writeValue(module, list, allocator, function_return_type, indentation, .{
                        .value_index = return_expr.value,
                        .type_index = return_value_type_index,
                    });
                    try list.appendSlice(allocator, ",\n");
                    try list.appendNTimes(allocator, ' ', indentation * margin_width);
                    try list.appendSlice(allocator, ".is_null = false,\n");
                    try list.appendNTimes(allocator, ' ', indentation * margin_width);
                    try list.append(allocator, '}');
                },
            },
            else => try unit.writeValue(module, list, allocator, function_return_type, indentation, .{
                .value_index = return_expr.value,
                .type_index = function_return_type,
            }),
        }
    }

    fn writeBlock(unit: *TranslationUnit, module: *Module, list: *ArrayList(u8), allocator: Allocator, block_index: Compilation.Block.Index, function_return_type: Type.Index, old_indentation: usize) !void {
        try list.appendSlice(allocator, "{\n");
        const block = module.values.blocks.get(block_index);

        const indentation = old_indentation + 1;

        for (block.statements.items) |statement_index| {
            try list.appendNTimes(allocator, ' ', indentation * margin_width);

            const statement = module.values.array.get(statement_index);
            switch (statement.*) {
                .declaration => |declaration_index| {
                    try unit.writeDeclaration(module, list, allocator, declaration_index, indentation, ' ');
                    try list.append(allocator, ';');
                },
                .assign => |assignment_index| {
                    try unit.writeAssignment(module, list, allocator, assignment_index, function_return_type, indentation);
                    try list.append(allocator, ';');
                },
                .@"return" => |return_index| {
                    try unit.writeReturn(module, list, allocator, return_index, function_return_type, indentation);
                    try list.append(allocator, ';');
                },
                .@"unreachable" => {
                    try writeUnreachable(list, allocator);
                    try list.append(allocator, ';');
                },
                .call => |call_index| {
                    try unit.writeCall(module, list, allocator, call_index, function_return_type, indentation);
                    try list.append(allocator, ';');
                },
                .branch => |branch_index| {
                    if (!try unit.writeBranch(module, list, allocator, branch_index, function_return_type, indentation)) {
                        continue;
                    }
                },
                .assembly_block => |assembly_block_index| {
                    try unit.writeAssembly(module, list, allocator, assembly_block_index, indentation);
                    try list.append(allocator, ';');
                },
                .loop => |loop_index| {
                    const loop = module.values.loops.get(loop_index);
                    try list.appendSlice(allocator, "for (");
                    if (!loop.pre.invalid) {
                        try unit.writeValue(module, list, allocator, function_return_type, indentation, .{
                            .value_index = loop.pre,
                            .type_index = Type.Index.invalid,
                        });
                    }
                    try list.appendSlice(allocator, "; ");

                    try unit.writeValue(module, list, allocator, function_return_type, indentation, .{
                        .value_index = loop.condition,
                        .type_index = Type.boolean,
                    });

                    try list.appendSlice(allocator, "; ");

                    if (!loop.post.invalid) {
                        try unit.writeValue(module, list, allocator, function_return_type, indentation, .{
                            .value_index = loop.post,
                            .type_index = Type.Index.invalid,
                        });
                    }

                    try list.appendSlice(allocator, ") ");

                    try unit.writeValue(module, list, allocator, function_return_type, indentation, .{
                        .value_index = loop.body,
                        .type_index = Type.Index.invalid,
                    });
                },
                .block => |new_block_index| {
                    try unit.writeBlock(module, list, allocator, new_block_index, function_return_type, indentation);
                },
                .switch_expression => |switch_index| {
                    const switch_expression = module.values.switches.get(switch_index);
                    try list.appendSlice(allocator, "switch (");
                    try unit.writeValue(module, list, allocator, function_return_type, indentation, .{
                        .value_index = switch_expression.value,
                        .type_index = Type.Index.invalid,
                    });
                    try list.appendSlice(allocator, ") {\n");

                    for (switch_expression.groups.items) |switch_case_group| {
                        for (switch_case_group.conditions.items) |condition_value_index| {
                            try list.appendNTimes(allocator, ' ', (indentation + 1) * margin_width);
                            try list.appendSlice(allocator, "case ");
                            try unit.writeValue(module, list, allocator, function_return_type, indentation + 1, .{
                                .value_index = condition_value_index,
                                .type_index = Type.Index.invalid,
                            });
                            try list.appendSlice(allocator, ":\n");
                        }

                        _ = list.pop();

                        switch (module.values.array.get(switch_case_group.expression).*) {
                            .block => {
                                try unit.writeValue(module, list, allocator, function_return_type, indentation, .{
                                    .value_index = switch_case_group.expression,
                                    .type_index = Type.Index.invalid,
                                });
                            },
                            else => {
                                try list.appendSlice(allocator, " {\n");

                                try unit.writeValue(module, list, allocator, function_return_type, indentation + 2, .{
                                    .value_index = switch_case_group.expression,
                                    .type_index = Type.Index.invalid,
                                });
                                try list.appendSlice(allocator, ";\n");

                                try list.appendNTimes(allocator, ' ', indentation * margin_width);
                                try list.appendSlice(allocator, "}\n");
                            },
                        }

                        try list.appendNTimes(allocator, ' ', indentation * margin_width);
                        try list.appendSlice(allocator, " break;\n");
                    }

                    try list.appendNTimes(allocator, ' ', indentation * margin_width);
                    try list.appendSlice(allocator, "};\n");
                },
                .intrinsic => |intrinsic_index| {
                    try unit.writeIntrinsic(module, list, allocator, intrinsic_index, function_return_type, indentation, .statement);
                    try list.append(allocator, ';');
                },
                .@"break" => try list.appendSlice(allocator, "break;"),
                else => |t| @panic(@tagName(t)),
            }

            try list.append(allocator, '\n');
        }

        try list.appendNTimes(allocator, ' ', old_indentation * margin_width);
        try list.appendSlice(allocator, "}\n");
    }

    const FunctionHeaderType = enum {
        pointer,
        header,
    };

    fn renderTypeName(unit: *TranslationUnit, module: *Module, allocator: Allocator, type_index: Type.Index) ![]const u8 {
        const declaration_index = module.map.types.get(type_index).?;
        const mangle = true;
        const result = try unit.renderDeclarationName(module, allocator, declaration_index, mangle);
        return result;
    }

    fn renderFunctionDefinitionName(unit: *TranslationUnit, module: *Module, allocator: Allocator, function_definition_index: Compilation.Function.Index) ![]const u8 {
        const function_definition = module.types.function_definitions.get(function_definition_index);
        const function_prototype_type = module.types.array.get(function_definition.prototype);
        const function_prototype_index = function_prototype_type.function;
        const function_prototype = module.types.function_prototypes.get(function_prototype_index);
        const mangle = !(function_prototype.attributes.@"export" or function_prototype.attributes.@"extern");
        const function_declaration_index = module.map.function_definitions.get(function_definition_index).?;
        const name = try unit.renderDeclarationName(module, allocator, function_declaration_index, mangle);
        return name;
    }

    fn renderFunctionDeclarationName(unit: *TranslationUnit, module: *Module, allocator: Allocator, function_declaration_index: Compilation.Function.Index) ![]const u8 {
        const function_declaration = module.types.function_declarations.get(function_declaration_index);
        const function_prototype_type = module.types.array.get(function_declaration.prototype);
        const function_prototype_index = function_prototype_type.function;
        const function_prototype = module.types.function_prototypes.get(function_prototype_index);
        const mangle = !(function_prototype.attributes.@"export" or function_prototype.attributes.@"extern");
        const declaration_index = module.map.function_declarations.get(function_declaration_index).?;
        const name = try unit.renderDeclarationName(module, allocator, declaration_index, mangle);
        return name;
    }

    fn renderDeclarationName(unit: *TranslationUnit, module: *Module, allocator: Allocator, declaration_index: Compilation.Declaration.Index, mangle: bool) anyerror![]const u8 {
        if (unit.declaration_set.getIndex(declaration_index)) |index| {
            return unit.declaration_set.values()[index];
        } else {
            const declaration = module.values.declarations.get(declaration_index);
            const base_declaration_name = blk: {
                const name = module.getName(declaration.name).?;
                if (mangle and declaration.scope_type == .global and equal(u8, name, "main")) {
                    break :blk "user_entry_point";
                } else {
                    break :blk name;
                }
            };
            var list = ArrayList(u8){};

            try list.insertSlice(allocator, 0, base_declaration_name);

            if (mangle) {
                var scope_index = declaration.scope;

                var iterations: usize = 0;
                switch (declaration.scope_type) {
                    .global => {
                        while (!scope_index.invalid) {
                            const scope = module.values.scopes.get(scope_index);

                            if (module.map.types.get(scope.type)) |type_declaration| {
                                const scope_type_declaration = module.values.declarations.get(type_declaration);
                                const scope_type_declaration_name = module.getName(scope_type_declaration.name).?;
                                try list.insert(allocator, 0, '_');
                                try list.insertSlice(allocator, 0, scope_type_declaration_name);

                                scope_index = scope.parent;
                            } else {
                                break;
                            }

                            iterations += 1;
                        }
                    },
                    .local => {},
                }
            }

            // TODO: enhance declaration name rendering with file scope name
            // const scope =  declaration.scope;
            try unit.declaration_set.putNoClobber(allocator, declaration_index, list.items);

            switch (declaration.scope_type) {
                .global => switch (module.types.array.get(declaration.getType()).*) {
                    .function,
                    .type,
                    => {},
                    .integer,
                    .@"struct",
                    .pointer,
                    => {
                        const new_separation_character: u8 = switch (module.types.array.get(declaration.getType()).*) {
                            .integer,
                            .@"struct",
                            => '_',
                            .pointer => ' ',
                            else => unreachable,
                        };
                        try unit.writeDeclaration(module, &unit.global_variable_declarations, allocator, declaration_index, 0, new_separation_character);
                        try unit.global_variable_declarations.append(allocator, ';');
                        try unit.global_variable_declarations.appendNTimes(allocator, '\n', 2);
                    },
                    else => |t| @panic(@tagName(t)),
                },
                .local => {},
            }

            return list.items;
        }
    }

    fn writeFunctionPrototype(unit: *TranslationUnit, module: *Module, list: *ArrayList(u8), allocator: Allocator, function_prototype_index: Compilation.Function.Prototype.Index, name: []const u8) !void {
        const is_main = equal(u8, "main", name);
        if (is_main) {
            try list.appendSlice(allocator, "int main(int argc, char** argv, char** envp)");
        } else {
            const function_prototype = module.types.function_prototypes.get(function_prototype_index);

            if (function_prototype.attributes.@"extern") {
                try list.appendSlice(allocator, "extern ");
            }

            switch (function_prototype.attributes.calling_convention) {
                .system_v => {},
                .naked => try list.appendSlice(allocator, "[[gnu::naked]] "),
            }

            try unit.writeType(module, list, allocator, function_prototype.return_type, ' ');

            try list.append(allocator, ' ');

            try list.appendSlice(allocator, name);

            try list.append(allocator, '(');

            if (function_prototype.arguments.items.len > 0) {
                for (function_prototype.arguments.items, 0..) |argument_index, index| {
                    _ = index;

                    const arg_declaration = module.values.declarations.get(argument_index);
                    if (is_main) {} else {
                        try unit.writeType(module, list, allocator, arg_declaration.getType(), ' ');
                    }
                    try list.append(allocator, ' ');
                    const arg_name = module.getName(arg_declaration.name).?;
                    try list.appendSlice(allocator, arg_name);
                    try list.appendSlice(allocator, ", ");
                }
                _ = list.pop();
                _ = list.pop();
            }

            try list.append(allocator, ')');
        }
    }

    fn writeFunctionHeader(unit: *TranslationUnit, module: *Module, list: *ArrayList(u8), allocator: Allocator, function: *const Compilation.Function, name: []const u8) !void {
        const function_prototype_type = module.types.array.get(function.prototype);
        const function_prototype_index = function_prototype_type.function;

        try unit.writeFunctionPrototype(module, list, allocator, function_prototype_index, name);
    }

    fn writeType(unit: *TranslationUnit, module: *Module, list: *ArrayList(u8), allocator: Allocator, type_index: Type.Index, separation_character: u8) anyerror!void {
        const sema_type = module.types.array.get(type_index);

        switch (sema_type.*) {
            .void => try list.appendSlice(allocator, "void"),
            .noreturn => try list.appendSlice(allocator, "[[noreturn]] void"),
            .bool => try list.appendSlice(allocator, "bool"),
            .integer => |integer| {
                if (type_index.eq(Type.usize)) {
                    try list.appendSlice(allocator, "usize");
                } else if (type_index.eq(Type.ssize)) {
                    try list.appendSlice(allocator, "ssize");
                } else {
                    try list.append(allocator, switch (integer.signedness) {
                        .signed => 's',
                        .unsigned => 'u',
                    });
                    try list.writer(allocator).print("{}", .{integer.bit_count});
                }
            },
            .pointer => {
                const name = try unit.cachePointerType(module, allocator, type_index, separation_character);
                try list.appendSlice(allocator, name);
            },
            .@"struct" => {
                const name = try unit.cacheStructType(module, allocator, type_index, separation_character);
                try list.appendSlice(allocator, name);
            },
            .optional => {
                const name = try unit.cacheOptionalType(module, allocator, type_index, separation_character);
                try list.appendSlice(allocator, name);
            },
            .slice => {
                const name = try unit.cacheSliceType(module, allocator, type_index, separation_character);
                try list.appendSlice(allocator, name);
            },
            .array => {
                const name = try unit.cacheArrayType(module, allocator, type_index, separation_character);
                try list.appendSlice(allocator, name);
            },
            .any => @panic("Internal compiler error: 'any' made it to the backend"),
            .@"enum" => {
                const name = try unit.cacheEnumType(module, allocator, type_index, separation_character);
                try list.appendSlice(allocator, name);
            },
            else => |t| @panic(@tagName(t)),
        }
    }

    fn writeCDeclaration(unit: *TranslationUnit, module: *Module, list: *ArrayList(u8), allocator: Allocator, name: []const u8, type_index: Type.Index, separation_character: u8) !void {
        const declaration_type = module.types.array.get(type_index);
        switch (declaration_type.*) {
            .pointer => |pointer| {
                switch (module.types.array.get(pointer.element_type).*) {
                    .function => |function| return try unit.writeFunctionPrototype(module, list, allocator, function, try std.mem.concat(allocator, u8, &.{ "(*", name, ")" })),
                    .optional => {},
                    else => |t| @panic(@tagName(t)),
                }
            },
            else => {},
        }

        try unit.writeType(module, list, allocator, type_index, separation_character);
        try list.append(allocator, ' ');
        try list.appendSlice(allocator, name);
    }

    fn writeAssembly(unit: *TranslationUnit, module: *Module, list: *ArrayList(u8), allocator: Allocator, assembly_block_index: Compilation.Assembly.Block.Index, indentation: usize) !void {
        const assembly_block = module.values.assembly_blocks.get(assembly_block_index);

        try list.appendSlice(allocator, "__asm__ __volatile__(\n");

        var operand_values = ArrayList(Value.Index){};

        for (assembly_block.instructions) |instruction_index| {
            try list.appendNTimes(allocator, ' ', (indentation + 1) * margin_width);
            try list.append(allocator, '"');

            const generic_instruction = module.values.assembly_instructions.get(instruction_index);

            switch (module.descriptor.target.cpu.arch) {
                .x86_64 => {
                    const architecture = @field(Compilation.Assembly, "x86_64");

                    const instruction: architecture.Instruction = @enumFromInt(generic_instruction.id);
                    const instruction_name = switch (instruction) {
                        .@"and" => "andq",
                        .mov => "movq",
                        .xor => @tagName(instruction),
                        .call => "callq",
                    };
                    try list.appendSlice(allocator, instruction_name);

                    assert(generic_instruction.operands.len <= 2);

                    if (generic_instruction.operands.len > 0) {
                        try list.append(allocator, ' ');

                        var skip = false;

                        var operand_iterator = std.mem.reverseIterator(generic_instruction.operands);
                        while (operand_iterator.next()) |operand| {
                            switch (operand) {
                                .register => |generic_register| {
                                    const register: architecture.Register = @enumFromInt(generic_register);
                                    try list.append(allocator, '%');
                                    try list.appendSlice(allocator, @tagName(register));
                                },
                                .number_literal => |number_literal| {
                                    try list.writer(allocator).print("$0x{x}", .{number_literal});
                                },
                                .value_index => |value_index| {
                                    const operand_value = module.values.array.get(value_index);

                                    switch (operand_value.*) {
                                        .unary_operation => |unary_operation_index| {
                                            const unary_operation = module.values.unary_operations.get(unary_operation_index);
                                            switch (unary_operation.id) {
                                                .address_of => try list.writer(allocator).print("%{}", .{operand_values.items.len}),
                                                else => |t| @panic(@tagName(t)),
                                            }
                                        },
                                        .function_definition => {
                                            try unit.writeValue(module, list, allocator, Type.Index.invalid, indentation + 1, .{
                                                .value_index = value_index,
                                                .type_index = Type.Index.invalid,
                                            });
                                            skip = true;
                                        },
                                        else => |t| @panic(@tagName(t)),
                                    }

                                    if (!skip) {
                                        try operand_values.append(allocator, value_index);
                                    }
                                },
                            }

                            try list.appendSlice(allocator, ", ");
                        }

                        _ = list.pop();
                        _ = list.pop();
                    }
                },
                else => unreachable,
            }

            try list.appendSlice(allocator, "\\n\\t\"\n");
        }

        if (operand_values.items.len > 0) {
            try list.appendNTimes(allocator, ' ', indentation * margin_width);
            try list.appendSlice(allocator, ":\n");
            try list.appendNTimes(allocator, ' ', indentation * margin_width);
            try list.appendSlice(allocator, ": ");

            for (operand_values.items) |operand_value_index| {
                try list.appendSlice(allocator, "\"x\"(");

                try unit.writeValue(module, list, allocator, Type.Index.invalid, indentation + 1, .{
                    .value_index = operand_value_index,
                    .type_index = Type.Index.invalid,
                });

                try list.appendSlice(allocator, "), ");
            }

            _ = list.pop();
            _ = list.pop();

            try list.append(allocator, '\n');
        }

        try list.appendNTimes(allocator, ' ', indentation * margin_width);
        try list.append(allocator, ')');
    }

    fn cacheStructType(unit: *TranslationUnit, module: *Module, allocator: Allocator, type_index: Type.Index, separation_character: u8) ![]const u8 {
        const t = module.types.array.get(type_index);
        assert(t.* == .@"struct");
        const result = if (unit.struct_type_set.get(type_index, separation_character)) |r| r else blk: {
            const type_name = try unit.renderTypeName(module, allocator, type_index);
            // if (std.mem.containsAtLeast(u8, type_name, 1, "Process")) @breakpoint();
            logln(.c, .g, "Registering struct {s}: #{}", .{ type_name, type_index.uniqueInteger() });
            try unit.struct_type_set.put(allocator, type_index, .{
                .underscore = type_name,
                .space = type_name,
            });

            try unit.forwardDeclareContainerType(allocator, .@"struct", type_name);

            const struct_type = module.types.structs.get(t.@"struct");
            // Actually declare the struct
            {
                var list = ArrayList(u8){};
                try list.appendSlice(allocator, "typedef struct ");
                try list.appendSlice(allocator, type_name);
                try list.appendSlice(allocator, " {\n");

                for (struct_type.fields.items) |struct_field_index| {
                    try list.appendNTimes(allocator, ' ', margin_width);

                    const struct_field = module.types.container_fields.get(struct_field_index);
                    const struct_field_name = module.getName(struct_field.name).?;

                    switch (struct_type.backing_type.invalid) {
                        false => {
                            try unit.writeType(module, &list, allocator, struct_type.backing_type, '_');
                            try list.append(allocator, ' ');
                            try list.appendSlice(allocator, struct_field_name);
                            try list.appendSlice(allocator, " : ");
                            try list.writer(allocator).print("{}", .{module.types.array.get(struct_field.type).getBitSize()});
                        },
                        true => try unit.writeCDeclaration(module, &list, allocator, struct_field_name, struct_field.type, ' '),
                    }

                    try list.appendSlice(allocator, ";\n");
                }

                try list.appendSlice(allocator, "} ");
                try list.appendSlice(allocator, type_name);
                try list.appendSlice(allocator, ";\n\n");

                try unit.type_declarations.appendSlice(allocator, list.items);
            }

            break :blk type_name;
        };

        return result;
    }

    fn forwardDeclareContainerType(unit: *TranslationUnit, allocator: Allocator, container_type: Compilation.ContainerType, type_name: []const u8) !void {
        try unit.type_forward_declarations.appendSlice(allocator, "typedef ");
        try unit.type_forward_declarations.appendSlice(allocator, @tagName(container_type));
        try unit.type_forward_declarations.append(allocator, ' ');
        try unit.type_forward_declarations.appendSlice(allocator, type_name);
        try unit.type_forward_declarations.append(allocator, ' ');
        try unit.type_forward_declarations.appendSlice(allocator, type_name);
        try unit.type_forward_declarations.appendSlice(allocator, ";\n");
    }

    fn cacheEnumType(unit: *TranslationUnit, module: *Module, allocator: Allocator, type_index: Type.Index, separation_character: u8) ![]const u8 {
        const result = if (unit.array_type_set.get(type_index, separation_character)) |r| r else blk: {
            const type_name = try unit.renderTypeName(module, allocator, type_index);
            logln(.c, .g, "Registering enum {s}: #{}", .{ type_name, type_index.uniqueInteger() });
            try unit.array_type_set.put(allocator, type_index, .{
                .underscore = type_name,
                .space = type_name,
            });

            try unit.forwardDeclareContainerType(allocator, .@"enum", type_name);

            const t = module.types.array.get(type_index);
            const enum_type = module.types.enums.get(t.@"enum");

            var list = ArrayList(u8){};

            try list.appendSlice(allocator, "typedef enum ");
            try list.appendSlice(allocator, type_name);
            try list.appendSlice(allocator, " {\n");

            for (enum_type.fields.items) |enum_field_index| {
                try list.appendNTimes(allocator, ' ', margin_width);

                const enum_field = module.types.enum_fields.get(enum_field_index);
                const enum_field_name = module.getName(enum_field.name).?;
                try list.appendSlice(allocator, type_name);
                try list.append(allocator, '_');
                try list.appendSlice(allocator, enum_field_name);

                if (!enum_field.value.invalid) {
                    try list.appendSlice(allocator, " = ");

                    try unit.writeValue(module, &list, allocator, Type.Index.invalid, 0, .{
                        .value_index = enum_field.value,
                        .type_index = Type.usize,
                    });
                }

                try list.appendSlice(allocator, ",\n");
            }

            try list.appendSlice(allocator, "} ");
            try list.appendSlice(allocator, type_name);
            try list.appendSlice(allocator, ";\n\n");

            try unit.type_declarations.appendSlice(allocator, list.items);

            break :blk type_name;
        };

        return result;
    }

    fn cacheOptionalType(unit: *TranslationUnit, module: *Module, allocator: Allocator, type_index: Type.Index, separation_character: u8) ![]const u8 {
        const optional_type = module.types.array.get(type_index);
        assert(optional_type.* == .optional);
        const optional = optional_type.optional;

        const result = if (unit.optional_type_set.get(optional.element_type, separation_character)) |r| r else {
            const optional_element_type = module.types.array.get(optional.element_type);

            switch (optional_element_type.*) {
                .pointer => {
                    const name = try unit.cachePointerType(module, allocator, optional.element_type, separation_character);
                    return name;
                },
                else => {
                    var type_name = ArrayList(u8){};
                    try type_name.appendSlice(allocator, "Optional_");
                    try unit.writeType(module, &type_name, allocator, optional.element_type, '_');
                    logln(.c, .g, "Registering optional {s}: #{}", .{ type_name.items, type_index.uniqueInteger() });
                    try unit.optional_type_set.put(allocator, optional.element_type, .{
                        .underscore = type_name.items,
                        .space = type_name.items,
                    });

                    try unit.forwardDeclareContainerType(allocator, .@"struct", type_name.items);

                    var list = ArrayList(u8){};

                    try list.appendSlice(allocator, "typedef struct ");
                    try list.appendSlice(allocator, type_name.items);
                    try list.appendSlice(allocator, " {\n");

                    try list.appendNTimes(allocator, ' ', margin_width);
                    try unit.writeCDeclaration(module, &list, allocator, "value", optional.element_type, separation_character);
                    try list.appendSlice(allocator, ";\n");

                    try list.appendNTimes(allocator, ' ', margin_width);
                    try unit.writeCDeclaration(module, &list, allocator, "is_null", Type.boolean, separation_character);
                    try list.appendSlice(allocator, ";\n");

                    try list.appendSlice(allocator, "} ");
                    try list.appendSlice(allocator, type_name.items);
                    try list.appendSlice(allocator, ";\n\n");

                    try unit.type_declarations.appendSlice(allocator, list.items);

                    return type_name.items;
                },
            }
        };

        return result;
    }

    fn cacheSliceType(unit: *TranslationUnit, module: *Module, allocator: Allocator, type_index: Type.Index, separation_character: u8) ![]const u8 {
        const slice = module.types.array.get(type_index).slice;

        const result = if (unit.slice_type_set.get(slice.element_type, separation_character)) |r| r else blk: {
            var type_name = ArrayList(u8){};
            try type_name.appendSlice(allocator, "Slice_");
            try unit.writeType(module, &type_name, allocator, slice.element_type, separation_character);
            logln(.c, .g, "Registering slice {s}: #{}", .{ type_name.items, type_index.uniqueInteger() });
            try unit.slice_type_set.put(allocator, slice.element_type, .{
                .underscore = type_name.items,
                .space = type_name.items,
            });

            try unit.forwardDeclareContainerType(allocator, .@"struct", type_name.items);

            var list = ArrayList(u8){};

            try list.appendSlice(allocator, "typedef struct ");
            try list.appendSlice(allocator, type_name.items);
            try list.appendSlice(allocator, " {\n");

            try list.appendNTimes(allocator, ' ', margin_width);
            try unit.writeType(module, &list, allocator, slice.element_type, '_');
            try list.appendSlice(allocator, "* ptr;\n");

            try list.appendNTimes(allocator, ' ', margin_width);
            try list.appendSlice(allocator, "usize len;\n");

            try list.appendSlice(allocator, "} ");
            try list.appendSlice(allocator, type_name.items);
            try list.appendSlice(allocator, ";\n\n");

            try unit.type_declarations.appendSlice(allocator, list.items);

            break :blk type_name.items;
        };

        return result;
    }

    fn cachePointerType(unit: *TranslationUnit, module: *Module, allocator: Allocator, pointer_type_index: Type.Index, separation_character: u8) ![]const u8 {
        const result = if (unit.pointer_type_set.get(pointer_type_index, separation_character)) |r| r else blk: {
            var underscore_type_name = ArrayList(u8){};
            var space_type_name = ArrayList(u8){};
            const pointer_type = module.types.array.get(pointer_type_index).pointer;
            try underscore_type_name.appendSlice(allocator, "Pointer_");
            if (pointer_type.@"const") {
                try underscore_type_name.appendSlice(allocator, "const_");
            }
            if (pointer_type.many) {
                try underscore_type_name.appendSlice(allocator, "many_");
            }
            try unit.writeType(module, &underscore_type_name, allocator, pointer_type.element_type, '_');
            try unit.writeType(module, &space_type_name, allocator, pointer_type.element_type, ' ');
            if (pointer_type.@"const") {
                try space_type_name.appendSlice(allocator, " const");
            }
            try space_type_name.append(allocator, '*');

            const result = try unit.pointer_type_set.getOrPutValue(allocator, pointer_type_index, .{
                .underscore = underscore_type_name.items,
                .space = space_type_name.items,
            });

            break :blk switch (separation_character) {
                '_' => result.underscore,
                ' ' => result.space,
                else => unreachable,
            };
        };

        return result;
    }

    fn cacheArrayType(unit: *TranslationUnit, module: *Module, allocator: Allocator, type_index: Type.Index, separation_character: u8) ![]const u8 {
        const array = module.types.array.get(type_index).array;

        const result = if (unit.array_type_set.get(array.element_type, separation_character)) |r| r else blk: {
            var type_name = ArrayList(u8){};
            try type_name.appendSlice(allocator, "Array_");
            try unit.writeType(module, &type_name, allocator, array.element_type, '_');
            try type_name.writer(allocator).print("_{}", .{array.element_count});
            var terminated = false;
            switch (array.termination) {
                .none => {},
                .zero,
                .null,
                => {
                    terminated = true;
                    try type_name.append(allocator, '_');
                    try type_name.writer(allocator).writeAll(@tagName(array.termination));
                    try type_name.appendSlice(allocator, "_terminated");
                },
            }
            logln(.c, .g, "Registering array {s}: #{}", .{ type_name.items, type_index.uniqueInteger() });

            try unit.array_type_set.put(allocator, array.element_type, .{
                .underscore = type_name.items,
                .space = type_name.items,
            });

            try unit.forwardDeclareContainerType(allocator, .@"struct", type_name.items);

            var list = ArrayList(u8){};

            try list.appendSlice(allocator, "typedef struct ");
            try list.appendSlice(allocator, type_name.items);
            try list.appendSlice(allocator, " {\n");

            try list.appendNTimes(allocator, ' ', margin_width);
            try unit.writeType(module, &list, allocator, array.element_type, ' ');
            try list.appendSlice(allocator, " value");

            try list.writer(allocator).print("[{}];\n", .{array.element_count + @intFromBool(terminated)});

            try list.appendSlice(allocator, "} ");
            try list.appendSlice(allocator, type_name.items);
            try list.appendSlice(allocator, ";\n\n");

            try unit.type_declarations.appendSlice(allocator, list.items);

            break :blk type_name.items;
        };

        return result;
    }

    const ValueType = enum {
        statement,
        expression,
    };

    fn writeIntrinsic(unit: *TranslationUnit, module: *Module, list: *ArrayList(u8), allocator: Allocator, intrinsic_index: Compilation.Intrinsic.Index, function_return_type: Type.Index, indentation: usize, value_type: ValueType) !void {
        const intrinsic = module.values.intrinsics.get(intrinsic_index);
        switch (intrinsic.kind) {
            .syscall => |syscall_arguments| {
                const syscall_argument_count = syscall_arguments.items.len;
                if (!unit.syscall_bitset.isSet(syscall_argument_count - 1)) {
                    try unit.function_declarations.appendSlice(allocator, "u64 syscall");
                    try unit.function_declarations.writer(allocator).print("{}(", .{syscall_argument_count});
                    for (0..syscall_argument_count) |arg_i| {
                        try unit.function_declarations.writer(allocator).print("u64 arg{}, ", .{arg_i});
                    }
                    _ = unit.function_declarations.pop();
                    _ = unit.function_declarations.pop();
                    try unit.function_declarations.appendSlice(allocator,
                        \\) {
                        \\
                    );

                    const simple_register_argument_count = @min(syscall_argument_count, 4);
                    const complex_register_argument_count = syscall_argument_count - simple_register_argument_count;
                    const simple_argument_registers = [_]u8{ 'a', 'D', 'S', 'd' };
                    const complex_argument_registers = [_]u8{ 10, 8, 9 };

                    for (0..complex_register_argument_count) |i| {
                        try unit.function_declarations.appendNTimes(allocator, ' ', indentation * margin_width);
                        try unit.function_declarations.writer(allocator).print("register unsigned long r{} __asm__(\"r{}\") = arg{};\n", .{ complex_argument_registers[i], complex_argument_registers[i], simple_argument_registers.len + i });
                    }

                    try unit.function_declarations.appendSlice(allocator,
                        \\    unsigned long ret;
                        \\
                        \\    __asm__ __volatile__("syscall"
                        \\        : "=a"(ret)
                        \\        : 
                    );

                    for (0..simple_register_argument_count, simple_argument_registers[0..simple_register_argument_count]) |arg_i, arg_register| {
                        try unit.function_declarations.writer(allocator).print("\"{c}\"(arg{}), ", .{ arg_register, arg_i });
                    }

                    for (complex_argument_registers[0..complex_register_argument_count]) |arg_register| {
                        try unit.function_declarations.writer(allocator).print("\"r\"(r{}), ", .{arg_register});
                    }

                    _ = unit.function_declarations.pop();
                    _ = unit.function_declarations.pop();

                    try unit.function_declarations.appendSlice(allocator,
                        \\
                        \\        : "rcx", "r11", "memory"
                        \\    );
                        \\
                        \\    return ret;
                        \\}
                        \\
                        \\
                    );

                    unit.syscall_bitset.set(syscall_argument_count - 1);
                }

                try list.writer(allocator).print("syscall{}(", .{syscall_argument_count});

                for (syscall_arguments.items) |argument_index| {
                    try unit.writeValue(module, list, allocator, function_return_type, indentation, .{
                        .value_index = argument_index,
                        .type_index = Type.Index.invalid,
                    });
                    try list.appendSlice(allocator, ", ");
                }

                _ = list.pop();
                _ = list.pop();
                try list.append(allocator, ')');
            },
            .cast => |cast_value_index| {
                if (value_type == .statement) unreachable;

                const cast_type = intrinsic.type;
                const cast_value = module.values.array.get(cast_value_index);

                try list.append(allocator, '(');
                try unit.writeType(module, list, allocator, cast_type, ' ');
                try list.append(allocator, ')');

                const cast_value_type = module.types.array.get(cast_value.getType(module));

                switch (cast_value_type.*) {
                    .@"struct" => |struct_index| {
                        const struct_type = module.types.structs.get(struct_index);
                        switch (struct_type.backing_type.invalid) {
                            false => {
                                try list.appendSlice(allocator, "*(");
                                try unit.writeType(module, list, allocator, struct_type.backing_type, '_');
                                try list.appendSlice(allocator, "*)&(");
                                try unit.writeValue(module, list, allocator, function_return_type, indentation, .{
                                    .value_index = cast_value_index,
                                    .type_index = function_return_type,
                                });
                                try list.append(allocator, ')');
                            },
                            true => @panic("Unable to bitcast non-packed struct"),
                        }
                    },
                    else => try unit.writeValue(module, list, allocator, function_return_type, indentation, .{
                        .value_index = cast_value_index,
                        .type_index = Type.Index.invalid,
                    }),
                }
            },
            .optional_wrap => |value_to_wrap_index| {
                const optional_type = module.types.array.get(intrinsic.type);
                switch (optional_type.*) {
                    .optional => |optional| {
                        const optional_element_type = module.types.array.get(optional.element_type);
                        switch (optional_element_type.*) {
                            .pointer => try unit.writeValue(module, list, allocator, function_return_type, indentation, .{
                                .value_index = value_to_wrap_index,
                                .type_index = optional.element_type,
                            }),
                            else => {
                                try list.append(allocator, '(');
                                try unit.writeType(module, list, allocator, intrinsic.type, '_');
                                try list.appendSlice(allocator, ") {\n");
                                try list.appendNTimes(allocator, ' ', indentation * margin_width);
                                try list.appendSlice(allocator, ".value = ");
                                try unit.writeValue(module, list, allocator, function_return_type, indentation, .{
                                    .value_index = value_to_wrap_index,
                                    .type_index = Type.Index.invalid,
                                });
                                try list.appendSlice(allocator, ",\n");
                                try list.appendNTimes(allocator, ' ', indentation * margin_width);
                                try list.appendSlice(allocator, ".is_null = false,\n");
                                try list.appendNTimes(allocator, ' ', indentation * margin_width);
                                try list.append(allocator, '}');
                            },
                        }
                    },
                    else => |t| @panic(@tagName(t)),
                }
            },
            .array_coerce_to_slice => |array_to_coerce_value_index| {
                try list.append(allocator, '(');
                try unit.writeType(module, list, allocator, intrinsic.type, '_');
                try list.appendSlice(allocator, ") {\n");
                try list.appendNTimes(allocator, ' ', indentation * margin_width);
                try list.appendSlice(allocator, ".ptr = ");
                try unit.writeValue(module, list, allocator, function_return_type, indentation, .{
                    .value_index = array_to_coerce_value_index,
                    .type_index = Type.Index.invalid,
                });
                switch (module.values.array.get(array_to_coerce_value_index).*) {
                    .string_literal => {},
                    else => try list.appendSlice(allocator, ".value"),
                }
                try list.appendSlice(allocator, ",\n");
                try list.appendNTimes(allocator, ' ', indentation * margin_width);
                const array_value = module.values.array.get(array_to_coerce_value_index);
                const array_type = module.types.array.get(array_value.getType(module));
                const array_length = switch (array_type.*) {
                    .array => |array| array.element_count,
                    .pointer => |pointer| switch (module.types.array.get(pointer.element_type).*) {
                        .array => |array| array.element_count,
                        else => |t| @panic(@tagName(t)),
                    },
                    else => |t| @panic(@tagName(t)),
                };
                try list.writer(allocator).print(".len = {},\n", .{array_length});
                try list.appendNTimes(allocator, ' ', indentation * margin_width);
                try list.append(allocator, '}');
            },
            .sign_extend, .zero_extend => |value_index| {
                try unit.writeValue(module, list, allocator, function_return_type, indentation, .{
                    .value_index = value_index,
                    .type_index = intrinsic.type,
                });
            },
            .min => |binary| {
                try list.appendSlice(allocator, try unit.cacheMacro(allocator, .MIN));
                try list.append(allocator, '(');

                try unit.writeValue(module, list, allocator, function_return_type, indentation, .{
                    .value_index = binary.left,
                    .type_index = intrinsic.type,
                });

                try list.appendSlice(allocator, ", ");

                try unit.writeValue(module, list, allocator, function_return_type, indentation, .{
                    .value_index = binary.right,
                    .type_index = intrinsic.type,
                });

                try list.append(allocator, ')');
            },
            else => |t| @panic(@tagName(t)),
        }
    }

    const Macro = enum {
        MIN,
    };

    fn cacheMacro(unit: *TranslationUnit, allocator: Allocator, macro: Macro) ![]const u8 {
        if (!unit.macro_set.contains(macro)) {
            switch (macro) {
                .MIN => {
                    try unit.macros.appendSlice(allocator,
                        \\#define MIN(a, b) \
                        \\  ({ __typeof__ (a) _a = (a); \
                        \\     __typeof__ (b) _b = (b); \
                        \\  _a < _b ? _a : _b; })
                        \\
                        \\
                    );
                },
            }

            unit.macro_set.setPresent(macro, true);
        }

        return @tagName(macro);
    }

    fn writeUnreachable(list: *ArrayList(u8), allocator: Allocator) !void {
        try list.appendSlice(allocator, "__builtin_unreachable()");
    }

    fn writeCall(unit: *TranslationUnit, module: *Module, list: *ArrayList(u8), allocator: Allocator, call_index: Compilation.Call.Index, function_return_type: Type.Index, indentation: usize) !void {
        const call = module.values.calls.get(call_index);
        const call_value = module.values.array.get(call.value);
        var argument_declarations = ArrayList(Compilation.Declaration.Index){};

        const callable_name = switch (call_value.*) {
            .function_definition => |function_definition_index| blk: {
                const name = try unit.renderFunctionDefinitionName(module, allocator, function_definition_index);
                const function_definition = module.types.function_definitions.get(function_definition_index);
                const function_prototype_type = module.types.array.get(function_definition.prototype);
                const function_prototype = module.types.function_prototypes.get(function_prototype_type.function);
                argument_declarations = function_prototype.arguments;

                try list.appendSlice(allocator, name);
                try list.append(allocator, '(');

                break :blk name;
            },
            .function_declaration => |function_declaration_index| blk: {
                const name = try unit.renderFunctionDeclarationName(module, allocator, function_declaration_index);
                const function_declaration = module.types.function_declarations.get(function_declaration_index);
                const function_prototype_type = module.types.array.get(function_declaration.prototype);
                const function_prototype = module.types.function_prototypes.get(function_prototype_type.function);
                argument_declarations = function_prototype.arguments;

                try list.appendSlice(allocator, name);
                try list.append(allocator, '(');

                break :blk name;
            },
            .field_access => |field_access_index| blk: {
                const field_access = module.values.field_accesses.get(field_access_index);
                try unit.writeValue(module, list, allocator, function_return_type, indentation, .{
                    .value_index = field_access.declaration_reference,
                    .type_index = function_return_type,
                });

                const left_type = module.types.array.get(module.values.array.get(field_access.declaration_reference).declaration_reference.getType(module));
                // const is_pointer = switch (left_type) {
                //     .pointer => |pointer| b: {
                //         break :b true;
                //     },
                // };
                const is_pointer = switch (left_type.*) {
                    .pointer => true,
                    else => false,
                };
                const container_field = module.types.container_fields.get(module.values.field_accesses.get(field_access_index).field);
                argument_declarations = switch (module.types.array.get(container_field.type).*) {
                    .pointer => |pointer| switch (module.types.array.get(pointer.element_type).*) {
                        .function => |function| module.types.function_prototypes.get(function).arguments,
                        else => |t| @panic(@tagName(t)),
                    },
                    else => |t| @panic(@tagName(t)),
                };

                if (is_pointer) {
                    try list.appendSlice(allocator, "->");
                } else {
                    try list.append(allocator, '.');
                }

                const field = module.types.container_fields.get(field_access.field);
                const field_name = module.getName(field.name).?;
                try list.appendSlice(allocator, field_name);
                try list.append(allocator, '(');
                break :blk "field_access";
            },
            else => |t| @panic(@tagName(t)),
        };
        _ = callable_name;

        if (!call.arguments.invalid) {
            const argument_list = module.values.argument_lists.get(call.arguments);
            assert(argument_declarations.items.len == argument_list.array.items.len);

            if (argument_list.array.items.len > 0) {
                for (argument_list.array.items, argument_declarations.items, 0..) |argument_index, argument_declaration_index, index| {
                    _ = index;

                    const argument_declaration = module.values.declarations.get(argument_declaration_index);

                    try unit.writeValue(module, list, allocator, function_return_type, indentation, .{
                        .value_index = argument_index,
                        .type_index = argument_declaration.getType(),
                    });
                    try list.appendSlice(allocator, ", ");
                }

                _ = list.pop();
                _ = list.pop();
            }
        }

        try list.append(allocator, ')');
    }

    fn writeBranch(unit: *TranslationUnit, module: *Module, list: *ArrayList(u8), allocator: Allocator, branch_index: Compilation.Branch.Index, function_return_type: Type.Index, indentation: usize) !bool {
        const branch = module.values.branches.get(branch_index);
        const classic = switch (module.values.array.get(branch.taken_expression).*) {
            .block => true,
            else => false,
        };

        if (classic) {
            try list.appendSlice(allocator, "if (");
            try unit.writeValue(module, list, allocator, function_return_type, indentation, .{
                .value_index = branch.expression,
                .type_index = Type.Index.invalid,
            });
            try list.appendSlice(allocator, ") ");
            try unit.writeValue(module, list, allocator, function_return_type, indentation, .{
                .value_index = branch.taken_expression,
                .type_index = function_return_type,
            });

            if (!branch.not_taken_expression.invalid) {
                if (module.values.array.get(branch.taken_expression).* == .block) {
                    _ = list.pop();
                    try list.appendSlice(allocator, " else ");
                } else {
                    unreachable;
                }
                try unit.writeValue(module, list, allocator, function_return_type, indentation, .{
                    .value_index = branch.not_taken_expression,
                    .type_index = function_return_type,
                });

                if (module.values.array.get(branch.not_taken_expression).* == .block) {
                    return false;
                }
            }

            return true;
        } else {
            assert(!branch.not_taken_expression.invalid);

            try list.appendSlice(allocator, "(");
            try unit.writeValue(module, list, allocator, function_return_type, indentation, .{
                .value_index = branch.expression,
                .type_index = Type.Index.invalid,
            });
            try list.appendSlice(allocator, ") ? (");
            try unit.writeValue(module, list, allocator, function_return_type, indentation, .{
                .value_index = branch.taken_expression,
                .type_index = Type.Index.invalid,
            });
            try list.appendSlice(allocator, ") : (");
            try unit.writeValue(module, list, allocator, function_return_type, indentation, .{
                .value_index = branch.not_taken_expression,
                .type_index = Type.Index.invalid,
            });
            try list.appendSlice(allocator, ")");

            return true;
        }
    }

    const ValueArguments = struct {
        value_index: Value.Index,
        type_index: Type.Index,
    };

    fn writeValue(unit: *TranslationUnit, module: *Module, list: *ArrayList(u8), allocator: Allocator, function_return_type: Type.Index, indentation: usize, arguments: ValueArguments) anyerror!void {
        const value_index = arguments.value_index;
        const type_index = arguments.type_index;
        const value = module.values.array.get(value_index);
        //logln(.c, .g, "Generating C code for {s}", .{@tagName(value.*)});
        switch (value.*) {
            .declaration => |declaration_index| {
                try unit.writeDeclaration(module, list, allocator, declaration_index, indentation, '.');
            },
            .assign => |assignment_index| {
                try unit.writeAssignment(module, list, allocator, assignment_index, function_return_type, indentation);
            },
            .integer => |integer| {
                try list.writer(allocator).print("{}", .{integer.value});
            },
            .declaration_reference => |declaration_reference| {
                const mangle = true;
                const name = try unit.renderDeclarationName(module, allocator, declaration_reference.value, mangle);
                try list.appendSlice(allocator, name);
            },
            .binary_operation => |binary_operation_index| {
                const binary_operation = module.values.binary_operations.get(binary_operation_index);

                try list.append(allocator, '(');
                try unit.writeValue(module, list, allocator, function_return_type, indentation, .{
                    .value_index = binary_operation.left,
                    .type_index = binary_operation.type,
                });
                try list.append(allocator, ' ');

                switch (binary_operation.id) {
                    .add => try list.append(allocator, '+'),
                    .sub => try list.append(allocator, '-'),
                    .bit_and => try list.append(allocator, '&'),
                    .bit_or => try list.append(allocator, '|'),
                    .bit_xor => try list.append(allocator, '^'),
                    .multiply => try list.append(allocator, '*'),
                    .divide => try list.append(allocator, '/'),
                    .compare_greater_than => try list.append(allocator, '>'),
                    .compare_less_than => try list.append(allocator, '<'),
                    .shift_left => try list.appendSlice(allocator, "<<"),
                    .shift_right => try list.appendSlice(allocator, ">>"),
                    .compare_equal => try list.appendSlice(allocator, "=="),
                    .compare_not_equal => try list.appendSlice(allocator, "!="),
                    .compare_greater_or_equal => try list.appendSlice(allocator, ">="),
                    .compare_less_or_equal => try list.appendSlice(allocator, "<="),
                }

                try list.append(allocator, ' ');
                try unit.writeValue(module, list, allocator, function_return_type, indentation, .{
                    .value_index = binary_operation.right,
                    .type_index = binary_operation.type,
                });
                try list.append(allocator, ')');
            },
            .string_literal => |string_literal_descriptor| {
                try list.appendSlice(allocator, "(u8 *)");
                const string_literal = module.getName(string_literal_descriptor.hash) orelse unreachable;
                try list.append(allocator, '"');
                try list.appendSlice(allocator, string_literal);
                try list.append(allocator, '"');
            },
            .@"unreachable" => {
                try writeUnreachable(list, allocator);
            },
            .call => |call_index| try unit.writeCall(module, list, allocator, call_index, function_return_type, indentation),
            .bool => |boolean| try list.appendSlice(allocator, if (boolean) "true" else "false"),
            .block => |block_index| try unit.writeBlock(module, list, allocator, block_index, function_return_type, indentation),
            .unary_operation => |unary_operation_index| {
                const unary_operation = module.values.unary_operations.get(unary_operation_index);
                const expression_character: u8 = switch (unary_operation.id) {
                    .boolean_not => '!',
                    .negation => '-',
                    .address_of => '&',
                    .pointer_dereference => '*',
                };

                const emit_expression_character = blk: {
                    var emit = true;
                    if (unary_operation.id == .address_of) {
                        const unary_value_type = module.types.array.get(module.values.array.get(unary_operation.value).getType(module));
                        switch (unary_value_type.*) {
                            .array => |source_array| if (!arguments.type_index.invalid) switch (module.types.array.get(arguments.type_index).*) {
                                .pointer => |pointer| switch (module.types.array.get(pointer.element_type).*) {
                                    .array => {},
                                    .optional => switch (module.types.array.get(source_array.element_type).*) {
                                        .optional => emit = false,
                                        else => |t| @panic(@tagName(t)),
                                    },
                                    else => |t| @panic(@tagName(t)),
                                },
                                else => |t| @panic(@tagName(t)),
                            },
                            .integer,
                            .@"struct",
                            .function,
                            .pointer,
                            => {},
                            else => |t| @panic(@tagName(t)),
                        }
                    }

                    break :blk emit;
                };

                if (emit_expression_character) {
                    try list.append(allocator, expression_character);
                }

                try list.append(allocator, '(');
                try unit.writeValue(module, list, allocator, function_return_type, indentation, .{
                    .value_index = unary_operation.value,
                    .type_index = unary_operation.type,
                });
                try list.append(allocator, ')');

                if (unary_operation.id == .address_of) {
                    if (!arguments.type_index.invalid) {
                        switch (module.types.array.get(arguments.type_index).*) {
                            .pointer => |pointer| switch (module.types.array.get(module.values.array.get(unary_operation.value).getType(module)).*) {
                                .array => switch (module.types.array.get(pointer.element_type).*) {
                                    .array => {},
                                    .optional => try list.appendSlice(allocator, ".value"),
                                    else => |t| @panic(@tagName(t)),
                                },
                                .integer,
                                .@"struct",
                                .function,
                                => {},
                                // .array,
                                // .optional,
                                // .integer,
                                // .@"struct",
                                // .function,
                                // => {},
                                else => |t| @panic(@tagName(t)),
                            },
                            else => |t| @panic(@tagName(t)),
                        }
                    }
                }
            },
            .container_initialization => |container_initialization_index| {
                const container_initialization = module.values.container_initializations.get(container_initialization_index);

                // TODO: obliterate this crap and handle this in sema perfectly (optional_wrap)
                const additional_indentation: usize = if (!type_index.invalid) blk: {
                    switch (module.types.array.get(type_index).*) {
                        .@"struct" => break :blk 0,
                        .optional => |optional| switch (module.types.array.get(optional.element_type).*) {
                            .pointer => break :blk 0,
                            else => {
                                try list.append(allocator, '(');
                                try unit.writeType(module, list, allocator, type_index, '_');
                                try list.appendSlice(allocator, ") {\n");
                                try list.appendNTimes(allocator, ' ', (indentation + 1) * margin_width);
                                try list.appendSlice(allocator, ".value = ");
                                break :blk 1;
                            },
                        },
                        else => |t| @panic(@tagName(t)),
                    }
                } else 0;

                try list.append(allocator, '(');
                try unit.writeType(module, list, allocator, container_initialization.type, '_');
                try list.appendSlice(allocator, ") {\n");

                const container_type = module.types.array.get(container_initialization.type);
                switch (container_type.*) {
                    .@"struct" => {
                        const struct_type = module.types.structs.get(container_type.@"struct");
                        logln(.c, .g, "Struct type: 0x{x}", .{@intFromPtr(struct_type)});

                        for (container_initialization.field_initializations.items, struct_type.fields.items) |field_initialization_index, container_field_index| {
                            try list.appendNTimes(allocator, ' ', (indentation + 1) * margin_width);
                            try list.append(allocator, '.');
                            const container_field = module.types.container_fields.get(container_field_index);
                            const field_name = module.getName(container_field.name).?;
                            try list.appendSlice(allocator, field_name);
                            try list.appendSlice(allocator, " = ");
                            logln(.c, .g, "Name: {s}. Value: #{}. Field #{}", .{ field_name, field_initialization_index.uniqueInteger(), container_field_index.uniqueInteger() });
                            try unit.writeValue(module, list, allocator, function_return_type, indentation + 1, .{
                                .value_index = field_initialization_index,
                                .type_index = container_field.type,
                            });
                            try list.appendSlice(allocator, ",\n");
                        }

                        try list.appendNTimes(allocator, ' ', indentation * margin_width);
                        try list.append(allocator, '}');
                    },
                    .array => |array_type| {
                        try list.appendNTimes(allocator, ' ', (indentation + 1) * margin_width);
                        try list.appendSlice(allocator, ".value = {\n");

                        for (container_initialization.field_initializations.items, 0..) |field_initialization_index, array_index| {
                            try list.appendNTimes(allocator, ' ', (indentation + 2) * margin_width);
                            try list.writer(allocator).print("[{}] = ", .{array_index});

                            try unit.writeValue(module, list, allocator, function_return_type, indentation + 2, .{
                                .value_index = field_initialization_index,
                                .type_index = Type.Index.invalid,
                            });

                            try list.appendSlice(allocator, " ,\n");
                        }

                        switch (array_type.termination) {
                            .none => {},
                            .null, .zero => {
                                try list.appendNTimes(allocator, ' ', (indentation + 2) * margin_width);
                                const termination: []const u8 = switch (array_type.termination) {
                                    .null => "nullptr",
                                    .zero => "0",
                                    else => unreachable,
                                };
                                try list.writer(allocator).print("[{}] = {s},\n", .{ container_initialization.field_initializations.items.len, termination });
                            },
                        }

                        try list.appendNTimes(allocator, ' ', (indentation + 1) * margin_width);
                        try list.appendSlice(allocator, "},\n");

                        try list.appendNTimes(allocator, ' ', indentation * margin_width);
                        try list.append(allocator, '}');
                    },
                    else => |t| @panic(@tagName(t)),
                }

                if (additional_indentation > 0) {
                    try list.appendSlice(allocator, ",\n");
                    try list.appendNTimes(allocator, ' ', (indentation + 1) * margin_width);
                    try list.appendSlice(allocator, "}");
                }
            },
            .array_initialization => |array_initialization_index| {
                const array_initialization = module.values.container_initializations.get(array_initialization_index);
                try list.append(allocator, '(');
                try unit.writeType(module, list, allocator, array_initialization.type, '_');
                try list.appendSlice(allocator, ") { ");

                if (array_initialization.field_initializations.items.len > 0) {
                    for (array_initialization.field_initializations.items) |initialization_index| {
                        try unit.writeValue(module, list, allocator, function_return_type, indentation, .{
                            .value_index = initialization_index,
                            .type_index = module.values.array.get(initialization_index).getType(module),
                        });
                        try list.appendSlice(allocator, ", ");
                        // const container_field = module.types.container_fields.get(initialization_index);
                        // const field_name = module.getName(container_field.name).?;
                    }

                    _ = list.pop();
                }
                _ = list.pop();
                list.appendSliceAssumeCapacity(" }");
            },
            .field_access => |field_access_index| {
                const field_access = module.values.field_accesses.get(field_access_index);
                const left = module.values.array.get(field_access.declaration_reference);
                const left_type = module.types.array.get(left.getType(module));
                const right_field = module.types.container_fields.get(field_access.field);
                const right_field_name = module.getName(right_field.name).?;
                const is_pointer = switch (left_type.*) {
                    .@"struct" => false,
                    .pointer => true,
                    else => |t| @panic(@tagName(t)),
                };
                try unit.writeValue(module, list, allocator, function_return_type, indentation, .{
                    .value_index = field_access.declaration_reference,
                    .type_index = right_field.type,
                });

                if (is_pointer) {
                    try list.appendSlice(allocator, "->");
                } else {
                    try list.append(allocator, '.');
                }

                try list.appendSlice(allocator, right_field_name);
            },
            .pointer_null_literal => try list.appendSlice(allocator, "nullptr"),
            .optional_null_literal => {
                assert(!arguments.type_index.invalid);
                try list.append(allocator, '(');
                try unit.writeType(module, list, allocator, arguments.type_index, '_');
                try list.appendSlice(allocator, ") { .is_null = true }");
            },
            .slice => |slice_index| {
                const slice = module.values.slices.get(slice_index);
                const sliceable = module.values.array.get(slice.sliceable);

                const sliceable_type_index = switch (sliceable.*) {
                    .declaration_reference => |declaration_reference| declaration_reference.getType(module),
                    else => |t| @panic(@tagName(t)),
                };
                const sliceable_type = module.types.array.get(sliceable_type_index);
                const sliceable_element_type = switch (sliceable_type.*) {
                    .pointer => |pointer| pointer.element_type,
                    .slice => |slice_type| slice_type.element_type,
                    .array => |array_type| array_type.element_type,
                    else => |t| @panic(@tagName(t)),
                };

                try list.appendSlice(allocator, "(Slice_");
                try unit.writeType(module, list, allocator, sliceable_element_type, '_');
                try list.appendSlice(allocator, ") {\n");

                try list.appendNTimes(allocator, ' ', (indentation + 1) * margin_width);
                try list.appendSlice(allocator, ".ptr = ");

                switch (sliceable_type.*) {
                    .pointer => {
                        try list.append(allocator, '(');
                        try unit.writeValue(module, list, allocator, function_return_type, indentation + 1, .{
                            .value_index = slice.sliceable,
                            .type_index = sliceable_type_index,
                        });
                        try list.appendSlice(allocator, ") + (");
                        try unit.writeValue(module, list, allocator, function_return_type, indentation + 1, .{
                            .value_index = slice.range.start,
                            .type_index = Type.Index.invalid,
                        });
                        try list.appendSlice(allocator, "),\n");
                    },
                    .slice => {
                        try list.append(allocator, '(');
                        try unit.writeValue(module, list, allocator, function_return_type, indentation + 1, .{
                            .value_index = slice.sliceable,
                            .type_index = sliceable_type_index,
                        });
                        try list.appendSlice(allocator, ").ptr + (");
                        try unit.writeValue(module, list, allocator, function_return_type, indentation + 1, .{
                            .value_index = slice.range.start,
                            .type_index = Type.Index.invalid,
                        });
                        try list.appendSlice(allocator, "),\n");
                    },
                    .array => {
                        try list.append(allocator, '(');
                        try unit.writeValue(module, list, allocator, function_return_type, indentation + 1, .{
                            .value_index = slice.sliceable,
                            .type_index = sliceable_type_index,
                        });
                        try list.appendSlice(allocator, ").value + (");
                        try unit.writeValue(module, list, allocator, function_return_type, indentation + 1, .{
                            .value_index = slice.range.start,
                            .type_index = Type.Index.invalid,
                        });
                        try list.appendSlice(allocator, "),\n");
                    },
                    else => |t| @panic(@tagName(t)),
                }

                try list.appendNTimes(allocator, ' ', (indentation + 1) * margin_width);
                try list.appendSlice(allocator, ".len = ");

                switch (sliceable_type.*) {
                    .pointer => {
                        switch (slice.range.end.invalid) {
                            false => {
                                try list.append(allocator, '(');
                                try unit.writeValue(module, list, allocator, function_return_type, indentation + 1, .{
                                    .value_index = slice.range.end,
                                    .type_index = Type.Index.invalid,
                                });
                                try list.appendSlice(allocator, ") - (");
                                try unit.writeValue(module, list, allocator, function_return_type, indentation + 1, .{
                                    .value_index = slice.range.start,
                                    .type_index = Type.Index.invalid,
                                });
                                try list.appendSlice(allocator, ")\n");
                            },
                            true => {
                                unreachable;
                            },
                        }
                    },
                    .slice, .array => {
                        try list.append(allocator, '(');
                        switch (slice.range.end.invalid) {
                            false => {
                                try unit.writeValue(module, list, allocator, function_return_type, indentation + 1, .{
                                    .value_index = slice.range.end,
                                    .type_index = Type.Index.invalid,
                                });
                            },
                            true => {
                                switch (sliceable_type.*) {
                                    .slice => {
                                        try list.append(allocator, '(');
                                        try unit.writeValue(module, list, allocator, function_return_type, indentation + 1, .{
                                            .value_index = slice.sliceable,
                                            .type_index = Type.Index.invalid,
                                        });
                                        try list.appendSlice(allocator, ").len");
                                    },
                                    .array => |array| {
                                        try list.writer(allocator).print("{}", .{array.element_count});
                                    },
                                    else => |t| @panic(@tagName(t)),
                                }
                            },
                        }

                        try list.appendSlice(allocator, ") - (");
                        try unit.writeValue(module, list, allocator, function_return_type, indentation + 1, .{
                            .value_index = slice.range.start,
                            .type_index = Type.Index.invalid,
                        });
                        try list.appendSlice(allocator, ")\n");
                    },
                    else => |t| @panic(@tagName(t)),
                }

                try list.appendNTimes(allocator, ' ', indentation * margin_width);
                try list.append(allocator, '}');
            },
            .function_definition => |function_definition_index| {
                const function_name = try unit.writeFunctionDefinition(module, allocator, function_definition_index);
                try list.appendSlice(allocator, function_name);
            },
            .optional_check => |optional_check_index| {
                const optional_check = module.values.optional_checks.get(optional_check_index);
                const optional_type = module.types.array.get(module.values.array.get(optional_check.value).getType(module));
                assert(optional_type.* == .optional);
                const optional_element_type = module.types.array.get(optional_type.optional.element_type);
                const is_null_suffix_expression = switch (optional_element_type.*) {
                    .pointer => false,
                    else => true,
                };
                if (is_null_suffix_expression) {
                    try list.append(allocator, '!');
                }

                try list.append(allocator, '(');
                try unit.writeValue(module, list, allocator, function_return_type, indentation, .{
                    .value_index = optional_check.value,
                    .type_index = Type.Index.invalid,
                });
                try list.append(allocator, ')');

                if (is_null_suffix_expression) {
                    try list.appendSlice(allocator, ".is_null");
                }
            },
            .optional_unwrap => |optional_unwrap_index| {
                const optional_unwrap = module.values.optional_unwraps.get(optional_unwrap_index);
                const optional_value = module.values.array.get(optional_unwrap.value);
                const optional_type = module.types.array.get(optional_value.getType(module));
                assert(optional_type.* == .optional);
                const optional_element_type_index = optional_type.optional.element_type;
                const optional_element_type = module.types.array.get(optional_element_type_index);

                try list.append(allocator, '(');
                try unit.writeValue(module, list, allocator, function_return_type, indentation, .{
                    .value_index = optional_unwrap.value,
                    .type_index = optional_element_type_index,
                });
                try list.append(allocator, ')');

                switch (optional_element_type.*) {
                    .pointer => {},
                    else => try list.appendSlice(allocator, ".value"),
                }
            },
            .slice_access => |slice_access_index| {
                const slice_access = module.values.slice_accesses.get(slice_access_index);
                try list.append(allocator, '(');
                try unit.writeValue(module, list, allocator, function_return_type, indentation, .{
                    .value_index = slice_access.value,
                    .type_index = slice_access.type,
                });
                try list.appendSlice(allocator, ").");
                try list.appendSlice(allocator, @tagName(slice_access.field));
            },
            .indexed_access => |indexed_access_index| {
                const indexed_access = module.values.indexed_accesses.get(indexed_access_index);
                try list.append(allocator, '(');
                const indexed_expression_index = indexed_access.indexed_expression;
                const indexed_expression = module.values.array.get(indexed_expression_index);
                const indexed_expression_type_index = indexed_expression.getType(module);
                try unit.writeValue(module, list, allocator, function_return_type, indentation, .{
                    .value_index = indexed_expression_index,
                    .type_index = indexed_expression_type_index,
                });

                const indexed_expression_type = module.types.array.get(indexed_expression_type_index);
                switch (indexed_expression_type.*) {
                    .slice => {
                        try list.appendSlice(allocator, ".ptr");
                    },
                    .array => try list.appendSlice(allocator, ".value"),
                    .pointer => |pointer| {
                        _ = pointer;
                        // logln(.c, .g, "TODO FIXME This looks wrong", .{});
                        // try list.appendSlice(allocator, ".value");

                        // const element_type = module.types.array.get(pointer.element_type);
                        // switch (element_type.*) {
                        //     .optional => |optional| {
                        //         switch (module.types.array.get(optional.element_type).*) {
                        //             else => |t| @panic(@tagName(t)),
                        //         }
                        //     },
                        //     else => |t| @panic(@tagName(t)),
                        // }
                    },
                    else => |t| @panic(@tagName(t)),
                }

                try list.appendSlice(allocator, ")[");
                try unit.writeValue(module, list, allocator, function_return_type, indentation, .{
                    .value_index = indexed_access.index_expression,
                    .type_index = Type.Index.invalid,
                });
                try list.append(allocator, ']');
            },
            .undefined => {
                // Assuming this is only done at initialization
                _ = list.pop();
                _ = list.pop();
                _ = list.pop();
            },
            .enum_field => |enum_field_index| {
                const enum_field = module.types.enum_fields.get(enum_field_index);
                try unit.writeType(module, list, allocator, enum_field.parent, '_');
                try list.append(allocator, '_');
                const enum_field_name = module.getName(enum_field.name).?;
                try list.appendSlice(allocator, enum_field_name);
            },
            .intrinsic => |intrinsic_index| try unit.writeIntrinsic(module, list, allocator, intrinsic_index, function_return_type, indentation, .expression),
            .@"return" => |return_index| {
                try unit.writeReturn(module, list, allocator, return_index, function_return_type, indentation);
            },
            .branch => |branch_index| {
                _ = try unit.writeBranch(module, list, allocator, branch_index, function_return_type, indentation);
            },
            else => |t| @panic(@tagName(t)),
        }
    }
};

pub fn initialize(compilation: *Compilation, module: *Module) !void {
    const allocator = compilation.base_allocator;
    var unit = try TranslationUnit.create(module, allocator);
    const c_source_file_path = try std.mem.concat(allocator, u8, &.{ module.descriptor.executable_path, ".c" });
    const c_source_file = try std.fs.cwd().createFile(c_source_file_path, .{});

    try unit.type_forward_declarations.append(allocator, '\n');

    var offset: u64 = 0;
    const slices = [_][]const u8{ unit.primitive_type_declarations.items, unit.type_forward_declarations.items, unit.macros.items, unit.type_declarations.items, unit.function_declarations.items, unit.global_variable_declarations.items, unit.string_literals.items, unit.function_definitions.items };
    for (slices) |slice| {
        try c_source_file.pwriteAll(slice, offset);
        offset += slice.len;
    }

    c_source_file.close();
    const c_source_file_realpath = try std.fs.cwd().realpathAlloc(allocator, c_source_file_path);
    const c_flags = [_][]const u8{
        "-std=c2x",
        "-g",
        "-funsigned-char",
    };

    var zig_command_line = ArrayList([]const u8){};
    try zig_command_line.append(allocator, "zig");
    try zig_command_line.append(allocator, "build-exe");

    if (module.descriptor.link_libc) {
        try zig_command_line.append(allocator, "-lc");
    }

    for (module.map.libraries.keys()) |library_name| {
        const library_argument = try std.mem.concat(allocator, u8, &.{ "-l", library_name });
        try zig_command_line.append(allocator, library_argument);
    }

    const local_cache_dir = std.fs.cwd().realpathAlloc(allocator, "zig-cache") catch b: {
        std.fs.cwd().makeDir("nat/zig-cache") catch {};
        break :b try std.fs.cwd().realpathAlloc(allocator, "nat/zig-cache");
    };
    const home_directory = std.os.getenv("HOME") orelse @panic("Unable to get HOME environment variable. Did you forget to pass it to the process?");
    const global_cache_dir = try std.mem.concat(allocator, u8, &.{ home_directory, "/.cache/zig" });
    try zig_command_line.append(allocator, "--cache-dir");
    try zig_command_line.append(allocator, local_cache_dir);
    try zig_command_line.append(allocator, "--global-cache-dir");
    try zig_command_line.append(allocator, global_cache_dir);

    try zig_command_line.append(allocator, try std.mem.concat(allocator, u8, &.{ "-femit-bin=", module.descriptor.executable_path }));
    try zig_command_line.append(allocator, "-cflags");

    for (c_flags) |c_flag| {
        try zig_command_line.append(allocator, c_flag);
    }

    try zig_command_line.append(allocator, "--");
    try zig_command_line.append(allocator, c_source_file_realpath);

    const run_result = try std.ChildProcess.run(.{
        .allocator = allocator,
        .argv = zig_command_line.items,
    });
    switch (run_result.term) {
        .Exited => |exit_code| {
            if (exit_code != 0) {
                std.debug.print("\nERROR: Zig command exited with code {}:\n", .{exit_code});
                for (zig_command_line.items) |arg| {
                    std.debug.print("{s} ", .{arg});
                }
                std.debug.print("\n\n{s}", .{run_result.stderr});

                @panic("Internal error");
            }
        },
        else => |t| @panic(@tagName(t)),
    }
}
