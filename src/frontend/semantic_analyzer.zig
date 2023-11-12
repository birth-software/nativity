const std = @import("std");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;
const equal = std.mem.eql;
const panic = std.debug.panic;
const Compilation = @import("../Compilation.zig");
const File = Compilation.File;
const Module = Compilation.Module;
const Package = Compilation.Package;

const ArgumentList = Compilation.ArgumentList;
const Assignment = Compilation.Assignment;
const Block = Compilation.Block;
const Call = Compilation.Call;
const Declaration = Compilation.Declaration;
const Enum = Compilation.Enum;
const Field = Compilation.Field;
const Function = Compilation.Function;
const Intrinsic = Compilation.Intrinsic;
const Loop = Compilation.Loop;
const Scope = Compilation.Scope;
const ScopeType = Compilation.ScopeType;
const Struct = Compilation.Struct;
const Type = Compilation.Type;
const Value = Compilation.Value;

const log = Compilation.log;
const logln = Compilation.logln;

pub const Logger = enum {
    type,
    identifier,
    symbol_declaration,
    scope_node,
    node,
    typecheck,
    @"switch",
    block,
    call,

    pub var bitset = std.EnumSet(Logger).initMany(&.{
        .type,
        .identifier,
        .symbol_declaration,
        .scope_node,
        .node,
        .typecheck,
        .@"switch",
        .block,
        .call,
    });
};

const lexical_analyzer = @import("lexical_analyzer.zig");
const Token = lexical_analyzer.Token;

const syntactic_analyzer = @import("syntactic_analyzer.zig");
const ContainerDeclaration = syntactic_analyzer.ContainerDeclaration;
const Node = syntactic_analyzer.Node;
const SymbolDeclaration = syntactic_analyzer.SymbolDeclaration;

const data_structures = @import("../data_structures.zig");
const ArrayList = data_structures.ArrayList;
const HashMap = data_structures.AutoHashMap;

const Analyzer = struct {
    allocator: Allocator,
    module: *Module,
    current_file: File.Index,

    fn getScopeSourceFile(analyzer: *Analyzer, scope_index: Scope.Index) []const u8 {
        const scope = analyzer.module.scopes.get(scope_index);
        const file = analyzer.module.files.get(scope.file);
        return file.source_code;
    }

    fn getScopeNode(analyzer: *Analyzer, scope_index: Scope.Index, node_index: Node.Index) Node {
        const scope = analyzer.module.scopes.get(scope_index);
        const file = analyzer.module.files.get(scope.file);
        const result = &file.syntactic_analyzer_result.nodes.items[node_index.unwrap()];
        logln(.sema, .scope_node, "Fetching node #{} (0x{x}) from scope #{} from file #{} with id: {s}\n", .{ node_index.uniqueInteger(), @intFromPtr(result), scope_index.uniqueInteger(), scope.file.uniqueInteger(), @tagName(result.id) });
        return result.*;
    }

    fn getScopeToken(analyzer: *Analyzer, scope_index: Scope.Index, token_index: Token.Index) Token {
        const scope = analyzer.module.scopes.get(scope_index);
        const file = analyzer.module.files.get(scope.file);
        const result = file.lexical_analyzer_result.tokens.items[token_index];

        return result;
    }

    fn getScopeNodeList(analyzer: *Analyzer, scope_index: Scope.Index, node: Node) ArrayList(Node.Index) {
        const scope = analyzer.module.scopes.get(scope_index);
        return getFileNodeList(analyzer, scope.file, node);
    }

    fn getFileNodeList(analyzer: *Analyzer, file_index: File.Index, node: Node) ArrayList(Node.Index) {
        assert(node.id == .node_list);
        const file = analyzer.module.files.get(file_index);
        const list_index = node.left;
        return file.syntactic_analyzer_result.node_lists.items[list_index.uniqueInteger()];
    }

    fn getFileToken(analyzer: *Analyzer, file_index: File.Index, token: Token.Index) Token {
        const file = analyzer.module.files.get(file_index);
        const result = file.lexical_analyzer_result.tokens.items[token];
        return result;
    }

    fn getFileNode(analyzer: *Analyzer, file_index: File.Index, node_index: Node.Index) Node {
        const file = analyzer.module.files.get(file_index);
        const result = file.syntactic_analyzer_result.nodes.items[node_index.unwrap()];
        return result;
    }

    fn comptimeBlock(analyzer: *Analyzer, scope_index: Scope.Index, node_index: Node.Index) !Value.Index {
        const comptime_node = analyzer.getScopeNode(scope_index, node_index);

        const comptime_block = try analyzer.block(scope_index, .{ .none = {} }, comptime_node.left);
        const value_allocation = try analyzer.module.values.append(analyzer.allocator, .{
            .block = comptime_block,
        });
        return value_allocation.index;
    }

    fn unresolved(analyzer: *Analyzer, node_index: Node.Index) !Value.Allocation {
        const value_allocation = try analyzer.module.values.addOne(analyzer.allocator);
        value_allocation.ptr.* = .{
            .unresolved = .{
                .node_index = node_index,
            },
        };

        return value_allocation;
    }

    fn unresolvedAllocate(analyzer: *Analyzer, scope_index: Scope.Index, expect_type: ExpectType, node_index: Node.Index) !Value.Allocation {
        const new = try analyzer.unresolved(node_index);
        try analyzer.resolveNode(new.ptr, scope_index, expect_type, node_index);
        return new;
    }

    fn block(analyzer: *Analyzer, scope_index: Scope.Index, expect_type: ExpectType, node_index: Node.Index) anyerror!Block.Index {
        logln(.sema, .block, "Resolving block from scope #{} in file #{}\n", .{ scope_index.uniqueInteger(), analyzer.module.scopes.get(scope_index).file.uniqueInteger() });
        var reaches_end = true;
        const block_node = analyzer.getScopeNode(scope_index, node_index);
        var statement_nodes = ArrayList(Node.Index){};
        switch (block_node.id) {
            .block_one, .comptime_block_one => {
                try statement_nodes.append(analyzer.allocator, block_node.left);
            },
            .block_zero, .comptime_block_zero => {},
            .block_two, .comptime_block_two => {
                try statement_nodes.append(analyzer.allocator, block_node.left);
                try statement_nodes.append(analyzer.allocator, block_node.right);
            },
            .block, .comptime_block => statement_nodes = analyzer.getScopeNodeList(scope_index, analyzer.getScopeNode(scope_index, block_node.left)),
            else => |t| @panic(@tagName(t)),
        }

        const is_comptime = switch (block_node.id) {
            .comptime_block, .comptime_block_zero, .comptime_block_one, .comptime_block_two => true,
            .block, .block_zero, .block_one, .block_two => false,
            else => |t| @panic(@tagName(t)),
        };

        logln(.sema, .block, "Is comptime: {}\n", .{is_comptime});

        var statements = ArrayList(Value.Index){};

        for (statement_nodes.items) |statement_node_index| {
            if (!reaches_end) {
                unreachable;
            }

            const statement_node = analyzer.getScopeNode(scope_index, statement_node_index);
            const statement_value = switch (statement_node.id) {
                .assign => (try analyzer.module.values.append(analyzer.allocator, try analyzer.processAssignment(scope_index, statement_node_index))).index,
                .simple_while => blk: {
                    const loop_allocation = try analyzer.module.loops.append(analyzer.allocator, .{
                        .condition = Value.Index.invalid,
                        .body = Value.Index.invalid,
                        .breaks = false,
                    });
                    loop_allocation.ptr.condition = (try analyzer.unresolvedAllocate(scope_index, ExpectType.boolean, statement_node.left)).index;
                    loop_allocation.ptr.body = (try analyzer.unresolvedAllocate(scope_index, ExpectType.none, statement_node.right)).index;

                    // TODO: bool true
                    reaches_end = loop_allocation.ptr.breaks or unreachable;

                    const value_allocation = try analyzer.module.values.append(analyzer.allocator, .{
                        .loop = loop_allocation.index,
                    });
                    break :blk value_allocation.index;
                },
                .@"unreachable" => blk: {
                    reaches_end = false;
                    break :blk Compilation.Values.@"unreachable".getIndex();
                },
                .simple_symbol_declaration => blk: {
                    const declaration_index = try analyzer.symbolDeclaration(scope_index, statement_node_index, .local);
                    const declaration = analyzer.module.declarations.get(declaration_index);
                    const init_value = analyzer.module.values.get(declaration.init_value);
                    switch (init_value.isComptime() and declaration.mutability == .@"const") {
                        // Dont add comptime declaration statements
                        true => continue,
                        false => {
                            const statement_value_allocation = try analyzer.module.values.append(analyzer.allocator, .{
                                .declaration = declaration_index,
                            });
                            break :blk statement_value_allocation.index;
                        },
                    }
                },
                .@"return" => blk: {
                    reaches_end = false;

                    const return_value_allocation = try analyzer.module.values.append(analyzer.allocator, try analyzer.processReturn(scope_index, expect_type, statement_node_index));

                    break :blk return_value_allocation.index;
                },
                .call_two, .call => (try analyzer.module.values.append(analyzer.allocator, .{
                    .call = try analyzer.processCall(scope_index, statement_node_index),
                })).index,
                .@"switch" => (try analyzer.module.values.append(analyzer.allocator, try analyzer.processSwitch(scope_index, statement_node_index))).index,
                else => |t| @panic(@tagName(t)),
            };

            try statements.append(analyzer.allocator, statement_value);
        }

        const block_allocation = try analyzer.module.blocks.append(analyzer.allocator, .{
            .statements = statements,
            .reaches_end = reaches_end,
        });

        return block_allocation.index;
    }

    fn processCall(analyzer: *Analyzer, scope_index: Scope.Index, node_index: Node.Index) !Call.Index {
        const node = analyzer.getScopeNode(scope_index, node_index);
        logln(.sema, .call, "Node index: {}. Left index: {}\n", .{ node_index.uniqueInteger(), node.left.uniqueInteger() });
        assert(!node.left.invalid);
        const left_value_index = switch (!node.left.invalid) {
            true => blk: {
                const member_or_namespace_node_index = node.left;
                assert(!member_or_namespace_node_index.invalid);
                const this_value_allocation = try analyzer.unresolvedAllocate(scope_index, ExpectType.none, member_or_namespace_node_index);
                break :blk this_value_allocation.index;
            },
            false => unreachable, //Value.Index.invalid,
        };

        const left_type = switch (left_value_index.invalid) {
            false => switch (analyzer.module.values.get(left_value_index).*) {
                .function => |function_index| analyzer.module.function_prototypes.get(analyzer.module.types.get(analyzer.module.functions.get(function_index).prototype).function).return_type,
                else => |t| @panic(@tagName(t)),
            },
            true => Type.Index.invalid,
        };
        const arguments_index = switch (node.id) {
            .call, .call_two => |call_tag| (try analyzer.module.argument_lists.append(analyzer.allocator, .{
                .array = b: {
                    const argument_list_node_index = node.right;
                    const call_argument_node_list = switch (call_tag) {
                        .call => analyzer.getScopeNodeList(scope_index, analyzer.getScopeNode(scope_index, argument_list_node_index)).items,
                        .call_two => &.{argument_list_node_index},
                        else => unreachable,
                    };

                    switch (analyzer.module.values.get(left_value_index).*) {
                        .function => |function_index| {
                            const function = analyzer.module.functions.get(function_index);
                            const function_prototype = analyzer.module.function_prototypes.get(analyzer.module.types.get(function.prototype).function);
                            const argument_declarations = function_prototype.arguments.?;
                            logln(.sema, .call, "Argument declaration count: {}. Argument node list count: {}\n", .{ argument_declarations.len, call_argument_node_list.len });
                            var argument_array = ArrayList(Value.Index){};
                            if (argument_declarations.len == call_argument_node_list.len) {
                                for (argument_declarations, call_argument_node_list) |argument_declaration_index, argument_node_index| {
                                    const argument_declaration = analyzer.module.declarations.get(argument_declaration_index);
                                    // const argument_declaration_type = analyzer.module.types.get(argument_declaration.type);
                                    // assert(argument_declaration.type.valid);
                                    const call_argument_allocation = try analyzer.unresolvedAllocate(scope_index, ExpectType{
                                        .type_index = argument_declaration.type,
                                    }, argument_node_index);
                                    try call_argument_allocation.ptr.typeCheck(analyzer.module, argument_declaration.type);
                                    // const call_argument_type_index = call_argument_allocation.ptr.getType(analyzer.module);
                                    // const call_argument_type = analyzer.module.types.get(call_argument_type_index);
                                    // if (call_argument_type_index != argument_declaration.type) {
                                    //     if (std.meta.activeTag(call_argument_type.*) == std.meta.activeTag(argument_declaration_type.*)) {
                                    //         if (!call_argument_type.equalTypeCanCoerce(argument_declaration_type)) {
                                    //             unreachable;
                                    //         }
                                    //     } else {
                                    //         try call_argument_type.promote(argument_declaration_type);
                                    //         call_argument_allocation.ptr.setType(argument_declaration.type);
                                    //     }
                                    // }

                                    try argument_array.append(analyzer.allocator, call_argument_allocation.index);
                                }

                                break :b argument_array;
                            } else {
                                panic("Function call has argument count mismatch: call has {}, function declaration has {}\n", .{ call_argument_node_list.len, argument_declarations.len });
                            }
                        },
                        else => |t| @panic(@tagName(t)),
                    }
                },
            })).index,
            .call_one => ArgumentList.Index.invalid,
            else => |t| @panic(@tagName(t)),
        };
        const call_allocation = try analyzer.module.calls.append(analyzer.allocator, .{
            .value = left_value_index,
            .arguments = arguments_index,

            .type = left_type,
        });

        return call_allocation.index;
    }

    fn typeCheckEnumLiteral(analyzer: *Analyzer, scope_index: Scope.Index, token_index: Token.Index, enum_type: *const Enum) !?u32 {
        const enum_name = tokenBytes(analyzer.getScopeToken(scope_index, token_index), analyzer.getScopeSourceFile(scope_index));
        const enum_name_hash = try analyzer.processIdentifier(enum_name);

        for (enum_type.fields.items) |enum_field_index| {
            const enum_field = analyzer.module.enum_fields.get(enum_field_index);
            const existing = analyzer.module.getName(enum_field.name).?;
            if (enum_field.name == enum_name_hash) {
                return enum_name_hash;
            }

            logln(.sema, .typecheck, "Existing enum field \"{s}\" != enum literal \"{s}\"\n", .{ existing, enum_name });
        } else {
            return null;
        }
    }

    fn processSwitch(analyzer: *Analyzer, scope_index: Scope.Index, node_index: Node.Index) !Value {
        const node = analyzer.getScopeNode(scope_index, node_index);
        assert(node.id == .@"switch");

        analyzer.debugNode(scope_index, node_index);

        const switch_expr = try analyzer.unresolvedAllocate(scope_index, ExpectType.none, node.left);
        const switch_case_list_node = analyzer.getScopeNode(scope_index, node.right);
        const switch_case_node_list = switch (switch_case_list_node.id) {
            .node_list => analyzer.getScopeNodeList(scope_index, switch_case_list_node).items,
            else => |t| @panic(@tagName(t)),
        };

        switch (switch_expr.ptr.*) {
            .enum_field => |e_field_index| {
                const e_field = analyzer.module.enum_fields.get(e_field_index);
                const enum_type = analyzer.module.enums.get(e_field.parent);
                const enum_field_name = analyzer.module.getName(e_field.name);
                _ = enum_field_name;

                var else_case_index: ?usize = null;
                _ = else_case_index;
                var existing_enums = ArrayList(u32){};
                var switch_case_groups = try ArrayList(ArrayList(u32)).initCapacity(analyzer.allocator, switch_case_node_list.len);

                for (switch_case_node_list, 0..) |switch_case_node_index, index| {
                    _ = index;
                    const switch_case_node = analyzer.getScopeNode(scope_index, switch_case_node_index);
                    switch (switch_case_node.left.invalid) {
                        false => {
                            const switch_case_condition_node = analyzer.getScopeNode(scope_index, switch_case_node.left);
                            var switch_case_group = ArrayList(u32){};
                            switch (switch_case_condition_node.id) {
                                .enum_literal => {
                                    if (try typeCheckEnumLiteral(analyzer, scope_index, switch_case_condition_node.token + 1, enum_type)) |enum_name_hash| {
                                        for (existing_enums.items) |existing| {
                                            if (enum_name_hash == existing) {
                                                // Duplicate case
                                                unreachable;
                                            }
                                        }

                                        try switch_case_group.append(analyzer.allocator, enum_name_hash);
                                        try existing_enums.append(analyzer.allocator, enum_name_hash);
                                    } else {
                                        unreachable;
                                    }
                                },
                                .node_list => {
                                    const node_list = analyzer.getScopeNodeList(scope_index, switch_case_condition_node);
                                    try switch_case_group.ensureTotalCapacity(analyzer.allocator, node_list.items.len);
                                    for (node_list.items) |case_condition_node_index| {
                                        const case_condition_node = analyzer.getScopeNode(scope_index, case_condition_node_index);
                                        switch (case_condition_node.id) {
                                            .enum_literal => {
                                                if (try typeCheckEnumLiteral(analyzer, scope_index, case_condition_node.token + 1, enum_type)) |enum_name_hash| {
                                                    for (existing_enums.items) |existing| {
                                                        if (enum_name_hash == existing) {
                                                            // Duplicate case
                                                            unreachable;
                                                        }
                                                    }

                                                    try existing_enums.append(analyzer.allocator, enum_name_hash);
                                                    switch_case_group.appendAssumeCapacity(enum_name_hash);
                                                } else {
                                                    unreachable;
                                                }
                                            },
                                            else => |t| @panic(@tagName(t)),
                                        }
                                    }
                                },
                                else => |t| @panic(@tagName(t)),
                            }

                            switch_case_groups.appendAssumeCapacity(switch_case_group);
                        },
                        true => {
                            unreachable;
                            // if (existing_enums.items.len == enum_type.fields.items.len) {
                            //     unreachable;
                            // }
                            //
                            // else_case_index = index;
                        },
                    }
                }

                const group_index = for (switch_case_groups.items, 0..) |switch_case_group, switch_case_group_index| {
                    break for (switch_case_group.items) |case_name| {
                        if (e_field.name == case_name) {
                            break switch_case_group_index;
                        }
                    } else continue;
                } else {
                    unreachable;
                };

                logln(.sema, .@"switch", "Index: {}\n", .{group_index});

                const true_switch_case_node = analyzer.getScopeNode(scope_index, switch_case_node_list[group_index]);
                var result = Value{
                    .unresolved = .{
                        .node_index = true_switch_case_node.right,
                    },
                };

                try analyzer.resolveNode(&result, scope_index, ExpectType.none, true_switch_case_node.right);

                return result;
            },
            else => |t| @panic(@tagName(t)),
        }

        unreachable;
    }

    fn processAssignment(analyzer: *Analyzer, scope_index: Scope.Index, node_index: Node.Index) !Value {
        const node = analyzer.getScopeNode(scope_index, node_index);
        assert(node.id == .assign);
        const assignment = switch (node.left.invalid) {
            // In an assignment, the node being invalid means a discarding underscore, like this: ```_ = result```
            true => {
                var result = Value{
                    .unresolved = .{
                        .node_index = node.right,
                    },
                };

                try analyzer.resolveNode(&result, scope_index, ExpectType.none, node.right);

                return result;
            },
            false => {
                // const id = analyzer.tokenIdentifier(.token);
                // logln("id: {s}\n", .{id});
                // const left = try analyzer.expression(scope_index, ExpectType.none, statement_node.left);

                // if (analyzer.module.values.get(left).isComptime() and analyzer.module.values.get(right).isComptime()) {
                //     unreachable;
                // } else {
                //                                 const assignment_index = try analyzer.module.assignments.append(analyzer.allocator, .{
                //                                     .store = result.left,
                //                                     .load = result.right,
                //                                 });
                //                                 return assignment_index;
                // }
                unreachable;
            },
        };
        _ = assignment;

        unreachable;
    }

    fn processReturn(analyzer: *Analyzer, scope_index: Scope.Index, expect_type: ExpectType, node_index: Node.Index) !Value {
        const node = analyzer.getScopeNode(scope_index, node_index);
        const return_expression: Value.Index = switch (node_index.invalid) {
            // TODO: expect type
            false => ret: {
                const return_value_allocation = try analyzer.module.values.addOne(analyzer.allocator);
                return_value_allocation.ptr.* = .{
                    .unresolved = .{
                        .node_index = node.left,
                    },
                };
                try analyzer.resolveNode(return_value_allocation.ptr, scope_index, expect_type, node.left);
                break :ret return_value_allocation.index;
            },
            true => @panic("TODO: ret void"),
        };

        const return_value_allocation = try analyzer.module.returns.append(analyzer.allocator, .{
            .value = return_expression,
        });

        return .{
            .@"return" = return_value_allocation.index,
        };
    }

    fn processBinaryOperation(analyzer: *Analyzer, scope_index: Scope.Index, expect_type: ExpectType, node_index: Node.Index) !Value {
        const node = analyzer.getScopeNode(scope_index, node_index);

        const left_allocation = try analyzer.unresolvedAllocate(scope_index, expect_type, node.left);
        const right_allocation = try analyzer.unresolvedAllocate(scope_index, expect_type, node.right);
        const left_type = left_allocation.ptr.getType(analyzer.module);
        const right_type = right_allocation.ptr.getType(analyzer.module);
        if (!left_type.eq(right_type)) {
            unreachable;
        }

        const binary_operation = try analyzer.module.binary_operations.append(analyzer.allocator, .{
            .left = left_allocation.index,
            .right = right_allocation.index,
            .type = left_type,
            .id = switch (node.id) {
                .add => .add,
                .sub => .sub,
                .logical_and => .logical_and,
                .logical_xor => .logical_xor,
                .logical_or => .logical_or,
                else => |t| @panic(@tagName(t)),
            },
        });

        return .{
            .binary_operation = binary_operation.index,
        };
    }

    const DeclarationLookup = struct {
        declaration: Declaration.Index,
        scope: Scope.Index,
    };

    fn lookupDeclarationInCurrentAndParentScopes(analyzer: *Analyzer, scope_index: Scope.Index, identifier_hash: u32) ?DeclarationLookup {
        var scope_iterator = scope_index;
        while (!scope_iterator.invalid) {
            const scope = analyzer.module.scopes.get(scope_iterator);
            if (scope.declarations.get(identifier_hash)) |declaration_index| {
                return .{
                    .declaration = declaration_index,
                    .scope = scope_iterator,
                };
            }

            scope_iterator = scope.parent;
        }

        return null;
    }

    fn doIdentifier(analyzer: *Analyzer, scope_index: Scope.Index, expect_type: ExpectType, node_token: Token.Index, node_scope_index: Scope.Index) !Value.Index {
        const identifier = analyzer.tokenIdentifier(node_scope_index, node_token);
        logln(.sema, .identifier, "Referencing identifier: \"{s}\"\n", .{identifier});
        const identifier_hash = try analyzer.processIdentifier(identifier);

        if (analyzer.lookupDeclarationInCurrentAndParentScopes(scope_index, identifier_hash)) |lookup| {
            const declaration_index = lookup.declaration;
            const declaration = analyzer.module.declarations.get(declaration_index);

            // Up until now, only arguments have no initialization value
            const typecheck_result = switch (declaration.init_value.invalid) {
                false => blk: {
                    const init_value = analyzer.module.values.get(declaration.init_value);
                    logln(.sema, .identifier, "Declaration found: {}\n", .{init_value});
                    const is_unresolved = init_value.* == .unresolved;
                    switch (is_unresolved) {
                        true => {
                            try analyzer.resolveNode(init_value, lookup.scope, expect_type, init_value.unresolved.node_index);
                            declaration.type = init_value.getType(analyzer.module);
                            switch (init_value.*) {
                                .function => |function_index| {
                                    try analyzer.module.function_name_map.put(analyzer.allocator, function_index, declaration.name);
                                },
                                else => {},
                            }
                        },
                        false => {},
                    }

                    logln(.sema, .identifier, "Declaration resolved as: {}\n", .{init_value});
                    logln(.sema, .identifier, "Declaration mutability: {s}. Is comptime: {}\n", .{ @tagName(declaration.mutability), init_value.isComptime() });

                    const typecheck_result = try analyzer.typeCheck(expect_type, declaration.type);

                    if (init_value.isComptime() and declaration.mutability == .@"const") {
                        assert(!declaration.init_value.invalid);
                        assert(typecheck_result == .success);
                        return declaration.init_value;
                    }

                    break :blk typecheck_result;
                },
                true => try analyzer.typeCheck(expect_type, declaration.type),
            };

            const ref_allocation = try analyzer.module.values.append(analyzer.allocator, .{
                .declaration_reference = .{
                    .value = declaration_index,
                    .type = switch (expect_type) {
                        .none => declaration.type,
                        .type_index => switch (typecheck_result) {
                            .success => expect_type.type_index,
                            else => declaration.type,
                        },
                        .flexible_integer => blk: {
                            assert(!declaration.type.invalid);
                            break :blk declaration.type;
                        },
                    },
                },
            });

            return switch (typecheck_result) {
                .success => ref_allocation.index,
                inline .zero_extend, .sign_extend => |extend| blk: {
                    const cast_allocation = try analyzer.module.casts.append(analyzer.allocator, .{
                        .value = ref_allocation.index,
                        .type = switch (expect_type) {
                            .flexible_integer => |flexible_integer| t: {
                                const cast_type = Type.Integer.getIndex(.{
                                    .signedness = switch (extend) {
                                        .zero_extend => .unsigned,
                                        .sign_extend => .signed,
                                        else => unreachable,
                                    },
                                    .bit_count = flexible_integer.byte_count << 3,
                                });
                                break :t cast_type;
                            },
                            else => |t| @panic(@tagName(t)),
                        },
                    });
                    const value_allocation = try analyzer.module.values.append(analyzer.allocator, @unionInit(Value, @tagName(extend), cast_allocation.index));
                    break :blk value_allocation.index;
                },
            };
        } else {
            const scope = analyzer.module.scopes.get(scope_index);
            panic("Identifier \"{s}\" not found in scope #{} of file #{} referenced by scope #{} of file #{}: {s}", .{ identifier, scope_index.uniqueInteger(), scope.file.uniqueInteger(), node_scope_index.uniqueInteger(), analyzer.module.scopes.get(node_scope_index).file.uniqueInteger(), tokenBytes(analyzer.getScopeToken(scope_index, node_token), analyzer.getScopeSourceFile(scope_index)) });
        }
    }

    fn getArguments(analyzer: *Analyzer, scope_index: Scope.Index, node_index: Node.Index) !ArrayList(Node.Index) {
        var arguments = ArrayList(Node.Index){};
        const node = analyzer.getScopeNode(scope_index, node_index);
        switch (node.id) {
            .compiler_intrinsic_two => {
                try arguments.append(analyzer.allocator, node.left);
                try arguments.append(analyzer.allocator, node.right);
            },
            .compiler_intrinsic => {
                const argument_list_node_index = node.left;
                assert(!argument_list_node_index.invalid);
                const node_list_node = analyzer.getScopeNode(scope_index, argument_list_node_index);
                const node_list = analyzer.getScopeNodeList(scope_index, node_list_node);

                return node_list;
            },
            else => |t| @panic(@tagName(t)),
        }

        return arguments;
    }

    fn resolveNode(analyzer: *Analyzer, value: *Value, scope_index: Scope.Index, expect_type: ExpectType, node_index: Node.Index) anyerror!void {
        const node = analyzer.getScopeNode(scope_index, node_index);
        logln(.sema, .node, "Resolving node #{} in scope #{} from file #{}: {}\n", .{ node_index.uniqueInteger(), scope_index.uniqueInteger(), analyzer.module.scopes.get(scope_index).file.uniqueInteger(), node });

        assert(value.* == .unresolved);

        value.* = switch (node.id) {
            .identifier => blk: {
                const value_index = try analyzer.doIdentifier(scope_index, expect_type, node.token, scope_index);
                const value_ref = analyzer.module.values.get(value_index);
                break :blk value_ref.*;
            },
            .keyword_true => {
                switch (expect_type) {
                    .none => {},
                    .type_index => |expected_type| {
                        if (@as(u32, @bitCast(Type.boolean)) != @as(u32, @bitCast(expected_type))) {
                            @panic("TODO: compile error");
                        }
                    },
                    else => unreachable,
                }

                // TODO
                unreachable;

                // break :blk Values.getIndex(.bool_true);
            },
            .compiler_intrinsic_one, .compiler_intrinsic_two, .compiler_intrinsic => blk: {
                const intrinsic_name = analyzer.tokenIdentifier(scope_index, node.token + 1);
                logln(.sema, .node, "Intrinsic: {s}\n", .{intrinsic_name});
                const intrinsic = data_structures.enumFromString(Intrinsic, intrinsic_name) orelse panic("Unknown intrinsic: {s}\n", .{intrinsic_name});
                switch (intrinsic) {
                    .import => {
                        assert(node.id == .compiler_intrinsic_one);
                        const import_argument = analyzer.getScopeNode(scope_index, node.left);
                        switch (import_argument.id) {
                            .string_literal => {
                                const import_name = analyzer.tokenStringLiteral(scope_index, import_argument.token);
                                const import_file = try analyzer.module.importFile(analyzer.allocator, analyzer.current_file, import_name);
                                logln(.sema, .node, "Importing \"{s}\"...\n", .{import_name});

                                const result = .{
                                    .type = switch (import_file.file.is_new) {
                                        true => true_block: {
                                            const new_file_index = import_file.file.index;
                                            try analyzer.module.generateAbstractSyntaxTreeForFile(analyzer.allocator, new_file_index);
                                            const analyze_result = try analyzeFile(value, analyzer.allocator, analyzer.module, new_file_index);
                                            logln(.sema, .node, "Done analyzing {s}!\n", .{import_name});
                                            break :true_block analyze_result;
                                        },
                                        false => false_block: {
                                            const file_type = import_file.file.ptr.type;
                                            assert(!file_type.invalid);
                                            break :false_block file_type;
                                        },
                                    },
                                };

                                break :blk result;
                            },
                            else => unreachable,
                        }
                    },
                    .syscall => {
                        var argument_nodes = try analyzer.getArguments(scope_index, node_index);
                        logln(.sema, .node, "Argument count: {}\n", .{argument_nodes.items.len});
                        if (argument_nodes.items.len > 0 and argument_nodes.items.len <= 6 + 1) {
                            const argument_expect_type = .{
                                .flexible_integer = .{
                                    .byte_count = 8,
                                },
                            };
                            const number_allocation = try analyzer.unresolvedAllocate(scope_index, argument_expect_type, argument_nodes.items[0]);
                            const number = number_allocation.index;
                            assert(!number.invalid);
                            var arguments = std.mem.zeroes([6]Value.Index);
                            for (argument_nodes.items[1..], 0..) |argument_node_index, argument_index| {
                                const argument_allocation = try analyzer.unresolvedAllocate(scope_index, argument_expect_type, argument_node_index);
                                arguments[argument_index] = argument_allocation.index;
                            }

                            // TODO: typecheck for usize
                            for (arguments[0..argument_nodes.items.len]) |argument| {
                                _ = argument;
                            }

                            break :blk .{
                                .syscall = (try analyzer.module.syscalls.append(analyzer.allocator, .{
                                    .number = number,
                                    .arguments = arguments,
                                    .argument_count = @intCast(argument_nodes.items.len - 1),
                                })).index,
                            };
                        } else {
                            unreachable;
                        }
                    },
                    .@"error" => {
                        assert(node.id == .compiler_intrinsic_one);
                        const message_node = analyzer.getScopeNode(scope_index, node.left);
                        switch (message_node.id) {
                            .string_literal => panic("error: {s}", .{analyzer.tokenStringLiteral(scope_index, message_node.token)}),
                            else => |t| @panic(@tagName(t)),
                        }
                        unreachable;
                    },
                }
                unreachable;
            },
            .function_definition => blk: {
                const function_scope_allocation = try analyzer.allocateScope(.{
                    .parent = scope_index,
                    .file = analyzer.module.scopes.get(scope_index).file,
                });

                const function_prototype_index = try analyzer.functionPrototype(function_scope_allocation.index, node.left);

                const function_body = try analyzer.block(function_scope_allocation.index, .{
                    .type_index = analyzer.functionPrototypeReturnType(function_prototype_index),
                }, node.right);

                const prototype_type = try analyzer.module.types.append(analyzer.allocator, .{
                    .function = function_prototype_index,
                });

                const function_allocation = try analyzer.module.functions.append(analyzer.allocator, .{
                    .prototype = prototype_type.index,
                    .body = function_body,
                    .scope = function_scope_allocation.index,
                });

                break :blk .{
                    .function = function_allocation.index,
                };
            },
            .function_prototype => blk: {
                const function_prototype_index = try analyzer.functionPrototype(scope_index, node_index);
                const function_prototype = analyzer.module.function_prototypes.get(function_prototype_index);

                break :blk switch (function_prototype.attributes.@"extern") {
                    true => b: {
                        const prototype_type = try analyzer.module.types.append(analyzer.allocator, .{
                            .function = function_prototype_index,
                        });
                        const function_allocation = try analyzer.module.functions.append(analyzer.allocator, .{
                            .prototype = prototype_type.index,
                            .body = Block.Index.invalid,
                            .scope = Scope.Index.invalid,
                        });
                        break :b .{
                            .function = function_allocation.index,
                        };
                    },
                    false => unreachable,
                };
            },
            .simple_while => unreachable,
            .block_zero, .block_one => blk: {
                const block_index = try analyzer.block(scope_index, expect_type, node_index);
                break :blk .{
                    .block = block_index,
                };
            },
            .number_literal => switch (std.zig.parseNumberLiteral(analyzer.numberBytes(scope_index, node.token))) {
                .int => |integer| .{
                    .integer = .{
                        .value = integer,
                        .type = switch (expect_type) {
                            .none => Type.comptime_int,
                            .flexible_integer, .type_index => Type.Integer.getIndex(switch (expect_type) {
                                .flexible_integer => |flexible_integer_type| Compilation.Type.Integer{
                                    .bit_count = flexible_integer_type.byte_count << 3,
                                    .signedness = .unsigned,
                                },
                                .type_index => |type_index| a: {
                                    const type_info = analyzer.module.types.get(type_index);
                                    break :a switch (type_info.*) {
                                        .integer => |int| int,
                                        else => |t| @panic(@tagName(t)),
                                    };
                                },
                                else => unreachable,
                            }),
                        },
                        .signedness = .unsigned,
                    },
                },
                else => |t| @panic(@tagName(t)),
            },
            .call, .call_one, .call_two => .{
                .call = try analyzer.processCall(scope_index, node_index),
            },
            .field_access => blk: {
                logln(.sema, .node, "left alocation...\n", .{});
                const identifier = analyzer.tokenIdentifier(scope_index, node.right.value);
                logln(.sema, .node, "Field access identifier for RHS: \"{s}\"\n", .{identifier});
                analyzer.debugNode(scope_index, node_index);
                const left_allocation = try analyzer.unresolvedAllocate(scope_index, ExpectType.none, node.left);

                switch (left_allocation.ptr.*) {
                    .type => |type_index| {
                        if (!type_index.invalid) {
                            const left_type = analyzer.module.types.get(type_index);
                            switch (left_type.*) {
                                .@"struct" => |struct_index| {
                                    const struct_type = analyzer.module.structs.get(struct_index);
                                    const right_index = try analyzer.doIdentifier(struct_type.scope, ExpectType.none, node.right.value, scope_index);
                                    const right_value = analyzer.module.values.get(right_index);
                                    switch (right_value.*) {
                                        .function, .type, .enum_field => break :blk right_value.*,
                                        .declaration_reference => |declaration_reference| {
                                            const declaration = analyzer.module.declarations.get(declaration_reference.value);
                                            const declaration_name = analyzer.module.getName(declaration.name).?;
                                            logln(.sema, .node, "Decl ref: {s}\n", .{declaration_name});
                                            logln(.sema, .node, "TODO: maybe this should not be runtime", .{});
                                            unreachable;
                                        },
                                        else => |t| @panic(@tagName(t)),
                                    }
                                    logln(.sema, .node, "Right: {}\n", .{right_value});
                                    // struct_scope.declarations.get(identifier);

                                    unreachable;
                                },
                                .@"enum" => |enum_index| {
                                    const enum_type = analyzer.module.enums.get(enum_index);
                                    const identifier_hash = try analyzer.processIdentifier(identifier);

                                    const result = for (enum_type.fields.items) |enum_field_index| {
                                        const enum_field = analyzer.module.enum_fields.get(enum_field_index);
                                        if (enum_field.name == identifier_hash) {
                                            break enum_field_index;
                                        }
                                    } else {
                                        @panic("No enum found");
                                    };
                                    const enum_field = analyzer.module.enum_fields.get(result);
                                    const enum_field_name = analyzer.module.getName(enum_field.name).?;
                                    logln(.sema, .node, "Enum field name resolution: {s}\n", .{enum_field_name});
                                    break :blk .{
                                        .enum_field = result,
                                    };
                                },
                                else => |t| @panic(@tagName(t)),
                            }
                            unreachable;
                        } else {
                            panic("Identifier \"{s}\" not found. Type empty", .{identifier});
                        }
                    },
                    .declaration_reference => |declaration_reference| {
                        switch (left_allocation.ptr.*) {
                            .declaration_reference => |reference| {
                                const declaration = analyzer.module.declarations.get(reference.value);
                                const declaration_type_index = declaration.type;
                                const declaration_type = analyzer.module.types.get(declaration_type_index);
                                switch (declaration_type.*) {
                                    .slice => unreachable,
                                    else => |t| @panic(@tagName(t)),
                                }
                            },
                            else => |t| @panic(@tagName(t)),
                        }
                        _ = declaration_reference;
                        unreachable;
                    },
                    else => |t| @panic(@tagName(t)),
                }
                unreachable;
            },
            .string_literal => .{
                .string_literal = try analyzer.processStringLiteral(scope_index, node_index),
            },
            .@"switch" => try analyzer.processSwitch(scope_index, node_index),
            .enum_type => blk: {
                const list_node = analyzer.getScopeNode(scope_index, node.left);
                const field_node_list = switch (list_node.id) {
                    .node_list => analyzer.getScopeNodeList(scope_index, list_node),
                    else => |t| @panic(@tagName(t)),
                };

                var field_list = try ArrayList(Enum.Field.Index).initCapacity(analyzer.allocator, field_node_list.items.len);
                const enum_allocation = try analyzer.module.enums.addOne(analyzer.allocator);
                const type_allocation = try analyzer.module.types.append(analyzer.allocator, .{
                    .@"enum" = enum_allocation.index,
                });

                for (field_node_list.items) |field_node_index| {
                    const field_node = analyzer.getScopeNode(scope_index, field_node_index);
                    const identifier = analyzer.tokenIdentifier(scope_index, field_node.token);
                    logln(.sema, .node, "Enum field: {s}\n", .{identifier});
                    assert(field_node.left.invalid);

                    const enum_hash_name = try analyzer.processIdentifier(identifier);

                    const enum_field_allocation = try analyzer.module.enum_fields.append(analyzer.allocator, .{
                        .name = enum_hash_name,
                        .value = Value.Index.invalid,
                        .parent = enum_allocation.index,
                    });

                    field_list.appendAssumeCapacity(enum_field_allocation.index);
                }

                enum_allocation.ptr.* = .{
                    .scope = Scope.Index.invalid,
                    .fields = field_list,
                    .type = type_allocation.index,
                };

                break :blk .{
                    .type = type_allocation.index,
                };
            },
            .assign => try analyzer.processAssignment(scope_index, node_index),
            .signed_integer_type, .unsigned_integer_type => .{
                .type = try analyzer.resolveType(scope_index, node_index),
            },
            .@"return" => try analyzer.processReturn(scope_index, expect_type, node_index),
            .add,
            .sub,
            .logical_and,
            .logical_xor,
            .logical_or,
            => try analyzer.processBinaryOperation(scope_index, expect_type, node_index),
            .expression_group => return try analyzer.resolveNode(value, scope_index, expect_type, node.left), //unreachable,
            else => |t| @panic(@tagName(t)),
        };
    }

    fn debugNode(analyzer: *Analyzer, scope_index: Scope.Index, node_index: Node.Index) void {
        const node = analyzer.getScopeNode(scope_index, node_index);
        const source_file = analyzer.getScopeSourceFile(scope_index);
        const token = analyzer.getScopeToken(scope_index, node.token);
        logln(.sema, .node, "Debugging node {s}:\n\n```\n{s}\n```\n", .{ @tagName(node.id), source_file[token.start..] });
    }

    fn processStringLiteral(analyzer: *Analyzer, scope_index: Scope.Index, node_index: Node.Index) !u32 {
        const string_literal_node = analyzer.getScopeNode(scope_index, node_index);
        assert(string_literal_node.id == .string_literal);
        const original_string_literal = analyzer.tokenStringLiteral(scope_index, string_literal_node.token);
        const string_literal = for (original_string_literal) |ch| {
            if (ch == '\\') {
                break try fixupStringLiteral(analyzer.allocator, original_string_literal);
            }
        } else original_string_literal;
        const string_key = try analyzer.module.addStringLiteral(analyzer.allocator, string_literal);
        return string_key;
    }

    fn fixupStringLiteral(allocator: Allocator, string_literal: []const u8) ![]const u8 {
        var result = try ArrayList(u8).initCapacity(allocator, string_literal.len - 1);
        var i: usize = 0;

        while (i < string_literal.len) : (i += 1) {
            const ch = string_literal[i];
            if (ch != '\\') {
                result.appendAssumeCapacity(ch);
            } else {
                const next_ch: u8 = switch (string_literal[i + 1]) {
                    'n' => '\n',
                    else => |next_ch| panic("Unexpected character: {c}, 0x{x}", .{ next_ch, next_ch }),
                };
                result.appendAssumeCapacity(next_ch);
                i += 1;
            }
        }

        return result.items;
    }

    fn functionPrototypeReturnType(analyzer: *Analyzer, function_prototype_index: Function.Prototype.Index) Type.Index {
        const function_prototype = analyzer.module.function_prototypes.get(function_prototype_index);
        return function_prototype.return_type;
    }

    fn resolveType(analyzer: *Analyzer, scope_index: Scope.Index, node_index: Node.Index) !Type.Index {
        const type_node = analyzer.getScopeNode(scope_index, node_index);
        const type_index: Type.Index = switch (type_node.id) {
            .identifier => blk: {
                const token = analyzer.getScopeToken(scope_index, type_node.token);
                const source_file = analyzer.getScopeSourceFile(scope_index);
                const identifier = tokenBytes(token, source_file);
                logln(.sema, .type, "Identifier: \"{s}\"", .{identifier});
                const resolved_value_index = try analyzer.doIdentifier(scope_index, ExpectType.type, type_node.token, scope_index);
                const resolved_value = analyzer.module.values.get(resolved_value_index);
                break :blk switch (resolved_value.*) {
                    .type => |type_index| type_index,
                    else => |t| @panic(@tagName(t)),
                };
            },
            .keyword_noreturn => Type.noreturn,
            inline .signed_integer_type, .unsigned_integer_type => |int_type_signedness| blk: {
                const bit_count: u16 = @intCast(type_node.left.value);
                logln(.sema, .type, "Bit count: {}", .{bit_count});
                break :blk switch (bit_count) {
                    inline 8, 16, 32, 64 => |hardware_bit_count| Type.Integer.getIndex(.{
                        .bit_count = hardware_bit_count,
                        .signedness = switch (int_type_signedness) {
                            .signed_integer_type => .signed,
                            .unsigned_integer_type => .unsigned,
                            else => @compileError("OOO"),
                        },
                    }),
                    else => unreachable,
                };
            },
            .many_pointer_type => blk: {
                const type_allocation = try analyzer.module.types.append(analyzer.allocator, .{
                    .pointer = .{
                        .element_type = try resolveType(analyzer, scope_index, type_node.left),
                        .many = true,
                        .@"const" = switch (analyzer.getScopeToken(scope_index, type_node.token + 3).id) {
                            .fixed_keyword_const => true,
                            .fixed_keyword_var => false,
                            else => |t| @panic(@tagName(t)),
                        },
                    },
                });
                break :blk type_allocation.index;
            },
            .slice_type => blk: {
                const type_allocation = try analyzer.module.types.append(analyzer.allocator, .{
                    .slice = .{
                        .element_type = try resolveType(analyzer, scope_index, type_node.right),
                    },
                });
                break :blk type_allocation.index;
            },
            .void_type => Type.void,
            .ssize_type => Type.ssize,
            .usize_type => Type.usize,
            else => |t| @panic(@tagName(t)),
        };
        return type_index;
    }

    fn processSimpleFunctionPrototype(analyzer: *Analyzer, scope_index: Scope.Index, simple_function_prototype_node_index: Node.Index) !Function.Prototype {
        const simple_function_prototype_node = analyzer.getScopeNode(scope_index, simple_function_prototype_node_index);
        assert(simple_function_prototype_node.id == .simple_function_prototype);
        const arguments_node_index = simple_function_prototype_node.left;
        const return_type_node_index = simple_function_prototype_node.right;

        const arguments: ?[]const Declaration.Index = switch (arguments_node_index.invalid) {
            true => null,
            false => blk: {
                const argument_list_node = analyzer.getScopeNode(scope_index, arguments_node_index);
                // logln("Function prototype argument list node: {}\n", .{function_prototype_node.left.uniqueInteger()});
                const argument_node_list = switch (argument_list_node.id) {
                    .node_list => analyzer.getScopeNodeList(scope_index, argument_list_node),
                    else => |t| @panic(@tagName(t)),
                };

                assert(argument_node_list.items.len > 0);
                if (argument_node_list.items.len > 0) {
                    var arguments = try ArrayList(Declaration.Index).initCapacity(analyzer.allocator, argument_node_list.items.len);
                    const scope = analyzer.module.scopes.get(scope_index);
                    _ = scope;
                    for (argument_node_list.items, 0..) |argument_node_index, index| {
                        const argument_node = analyzer.getScopeNode(scope_index, argument_node_index);
                        switch (argument_node.id) {
                            .argument_declaration => {
                                const argument_type = try analyzer.resolveType(scope_index, argument_node.left);
                                const argument_declaration = try analyzer.declarationCommon(scope_index, .local, .@"const", argument_node.token, argument_type, Value.Index.invalid, @intCast(index));

                                arguments.appendAssumeCapacity(argument_declaration);
                            },
                            else => |t| @panic(@tagName(t)),
                        }
                    }

                    break :blk arguments.items;
                } else {
                    break :blk null;
                }
            },
        };

        const return_type = try analyzer.resolveType(scope_index, return_type_node_index);

        return .{
            .arguments = arguments,
            .return_type = return_type,
        };
    }

    fn functionPrototype(analyzer: *Analyzer, scope_index: Scope.Index, node_index: Node.Index) !Function.Prototype.Index {
        const function_prototype_node = analyzer.getScopeNode(scope_index, node_index);
        switch (function_prototype_node.id) {
            .simple_function_prototype => {
                const function_prototype_allocation = try analyzer.module.function_prototypes.append(analyzer.allocator, try analyzer.processSimpleFunctionPrototype(scope_index, node_index));

                return function_prototype_allocation.index;
            },
            .function_prototype => {
                var function_prototype = try analyzer.processSimpleFunctionPrototype(scope_index, function_prototype_node.left);
                const function_prototype_attribute_list_node = analyzer.getScopeNode(scope_index, function_prototype_node.right);
                const attribute_node_list = analyzer.getScopeNodeList(scope_index, function_prototype_attribute_list_node);
                var calling_convention: ?Compilation.CallingConvention = null;

                for (attribute_node_list.items) |attribute_node_index| {
                    const attribute_node = analyzer.getScopeNode(scope_index, attribute_node_index);

                    switch (attribute_node.id) {
                        .extern_qualifier => function_prototype.attributes.@"extern" = true,
                        else => |t| @panic(@tagName(t)),
                    }
                }

                function_prototype.attributes.calling_convention = calling_convention orelse Compilation.CallingConvention.system_v;

                const function_prototype_allocation = try analyzer.module.function_prototypes.append(analyzer.allocator, function_prototype);
                return function_prototype_allocation.index;
            },
            else => |t| @panic(@tagName(t)),
        }
    }

    fn structType(analyzer: *Analyzer, value: *Value, parent_scope_index: Scope.Index, index: Node.Index, file_index: File.Index) !Type.Index {
        var node_buffer: [2]Node.Index = undefined;
        // We have the file because this might be the first file
        const file = analyzer.module.files.get(file_index);
        const node = file.syntactic_analyzer_result.nodes.items[index.unwrap()];
        const nodes = switch (node.id) {
            .main_one => blk: {
                node_buffer[0] = node.left;
                break :blk node_buffer[0..1];
            },
            .main_two => blk: {
                node_buffer[0] = node.left;
                node_buffer[1] = node.right;
                break :blk &node_buffer;
            },
            .main => blk: {
                const node_list_node = analyzer.getFileNode(file_index, node.left);
                const node_list = switch (node_list_node.id) {
                    .node_list => analyzer.getFileNodeList(file_index, node_list_node),
                    else => |t| @panic(@tagName(t)),
                };
                break :blk node_list.items;
                // const node_list = file.syntactic_analyzer_result.node_lists.items[node.left.unwrap()];
                // break :blk node_list.items;
            },
            .main_zero => &.{},
            else => |t| @panic(@tagName(t)),
        };

        if (nodes.len > 0) {
            const new_scope = try analyzer.allocateScope(.{
                .parent = parent_scope_index,
                .file = file_index,
            });
            const scope = new_scope.ptr;
            const scope_index = new_scope.index;

            const is_file = parent_scope_index.invalid;
            assert(is_file);

            const struct_allocation = try analyzer.module.structs.append(analyzer.allocator, .{
                .scope = new_scope.index,
            });
            const type_allocation = try analyzer.module.types.append(analyzer.allocator, .{
                .@"struct" = struct_allocation.index,
            });

            if (parent_scope_index.invalid) {
                file.type = type_allocation.index;
            }

            scope.type = type_allocation.index;
            value.* = .{
                .type = type_allocation.index,
            };

            const count = blk: {
                var result: struct {
                    fields: u32 = 0,
                    declarations: u32 = 0,
                } = .{};
                for (nodes) |member_index| {
                    const member = analyzer.getFileNode(file_index, member_index);
                    const member_type = getContainerMemberType(member.id);

                    switch (member_type) {
                        .declaration => result.declarations += 1,
                        .field => result.fields += 1,
                    }
                }
                break :blk result;
            };

            var declaration_nodes = try ArrayList(Node.Index).initCapacity(analyzer.allocator, count.declarations);
            var field_nodes = try ArrayList(Node.Index).initCapacity(analyzer.allocator, count.fields);

            for (nodes) |member_index| {
                const member = analyzer.getFileNode(file_index, member_index);
                const member_type = getContainerMemberType(member.id);
                const array_list = switch (member_type) {
                    .declaration => &declaration_nodes,
                    .field => &field_nodes,
                };
                array_list.appendAssumeCapacity(member_index);
            }

            for (declaration_nodes.items) |declaration_node_index| {
                const declaration_node = analyzer.getFileNode(file_index, declaration_node_index);
                switch (declaration_node.id) {
                    .@"comptime" => {},
                    .simple_symbol_declaration => _ = try analyzer.symbolDeclaration(scope_index, declaration_node_index, .global),
                    else => unreachable,
                }
            }

            // TODO: consider iterating over scope declarations instead?
            for (declaration_nodes.items) |declaration_node_index| {
                const declaration_node = analyzer.getFileNode(file_index, declaration_node_index);
                switch (declaration_node.id) {
                    .@"comptime" => _ = try analyzer.comptimeBlock(scope_index, declaration_node_index),
                    .simple_symbol_declaration => {},
                    else => |t| @panic(@tagName(t)),
                }
            }

            for (field_nodes.items) |field_index| {
                const field_node = analyzer.getFileNode(file_index, field_index);
                _ = field_node;

                @panic("TODO: fields");
            }

            return type_allocation.index;
        } else {
            return Type.Index.invalid;
        }
    }

    fn declarationCommon(analyzer: *Analyzer, scope_index: Scope.Index, scope_type: ScopeType, mutability: Compilation.Mutability, identifier_token: Token.Index, type_index: Type.Index, init_value: Value.Index, argument_index: ?u32) !Declaration.Index {
        const identifier = analyzer.tokenIdentifier(scope_index, identifier_token);
        const identifier_index = try analyzer.processIdentifier(identifier);

        if (analyzer.lookupDeclarationInCurrentAndParentScopes(scope_index, identifier_index)) |lookup| {
            const declaration_name = analyzer.tokenIdentifier(lookup.scope, identifier_token);
            panic("Existing name in lookup: {s}", .{declaration_name});
        }

        // Check if the symbol name is already occupied in the same scope
        const scope = analyzer.module.scopes.get(scope_index);
        const declaration_allocation = try analyzer.module.declarations.append(analyzer.allocator, .{
            .name = identifier_index,
            .scope_type = scope_type,
            .mutability = mutability,
            .init_value = init_value,
            .type = type_index,
            .argument_index = argument_index,
        });

        try scope.declarations.put(analyzer.allocator, identifier_index, declaration_allocation.index);

        return declaration_allocation.index;
    }

    fn symbolDeclaration(analyzer: *Analyzer, scope_index: Scope.Index, node_index: Node.Index, scope_type: ScopeType) !Declaration.Index {
        const declaration_node = analyzer.getScopeNode(scope_index, node_index);
        assert(declaration_node.id == .simple_symbol_declaration);
        const expect_type = switch (declaration_node.left.invalid) {
            false => switch (scope_type) {
                .local => ExpectType{
                    .type_index = try analyzer.resolveType(scope_index, declaration_node.left),
                },
                .global => ExpectType.none,
            },
            true => ExpectType.none,
        };
        const mutability: Compilation.Mutability = switch (analyzer.getScopeToken(scope_index, declaration_node.token).id) {
            .fixed_keyword_const => .@"const",
            .fixed_keyword_var => .@"var",
            else => |t| @panic(@tagName(t)),
        };
        const expected_identifier_token_index = declaration_node.token + 1;
        const expected_identifier_token = analyzer.getScopeToken(scope_index, expected_identifier_token_index);
        if (expected_identifier_token.id != .identifier) {
            logln(.sema, .symbol_declaration, "Error: found: {}", .{expected_identifier_token.id});
            @panic("Expected identifier");
        }
        // TODO: Check if it is a keyword

        assert(!declaration_node.right.invalid);

        const argument = null;
        assert(argument == null);
        const init_value_allocation = switch (scope_type) {
            .local => try analyzer.unresolvedAllocate(scope_index, expect_type, declaration_node.right),
            .global => try analyzer.module.values.append(analyzer.allocator, .{
                .unresolved = .{
                    .node_index = declaration_node.right,
                },
            }),
        };

        assert(argument == null);
        const type_index = switch (scope_type) {
            .local => init_value_allocation.ptr.getType(analyzer.module),
            .global => Type.Index.invalid,
        };

        const result = try analyzer.declarationCommon(scope_index, scope_type, mutability, expected_identifier_token_index, type_index, init_value_allocation.index, argument);

        return result;
    }

    const MemberType = enum {
        declaration,
        field,
    };

    fn getContainerMemberType(member_id: Node.Id) MemberType {
        return switch (member_id) {
            .@"comptime" => .declaration,
            .simple_symbol_declaration => .declaration,
            else => unreachable,
        };
    }

    fn processIdentifier(analyzer: *Analyzer, string: []const u8) !u32 {
        return analyzer.module.addName(analyzer.allocator, string);
    }

    fn tokenIdentifier(analyzer: *Analyzer, scope_index: Scope.Index, token_index: Token.Index) []const u8 {
        const token = analyzer.getScopeToken(scope_index, token_index);
        assert(token.id == .identifier);
        const source_file = analyzer.getScopeSourceFile(scope_index);
        const identifier = tokenBytes(token, source_file);

        return identifier;
    }

    fn tokenBytes(token: Token, source_code: []const u8) []const u8 {
        return source_code[token.start..][0..token.len];
    }

    fn numberBytes(analyzer: *Analyzer, scope_index: Scope.Index, token_index: Token.Index) []const u8 {
        const token = analyzer.getScopeToken(scope_index, token_index);
        assert(token.id == .number_literal);
        const source_file = analyzer.getScopeSourceFile(scope_index);
        const bytes = tokenBytes(token, source_file);

        return bytes;
    }

    fn tokenStringLiteral(analyzer: *Analyzer, scope_index: Scope.Index, token_index: Token.Index) []const u8 {
        const token = analyzer.getScopeToken(scope_index, token_index);
        assert(token.id == .string_literal);
        const source_file = analyzer.getScopeSourceFile(scope_index);
        // Eat double quotes
        const string_literal = tokenBytes(token, source_file)[1..][0 .. token.len - 2];

        return string_literal;
    }

    fn allocateScope(analyzer: *Analyzer, scope_value: Scope) !Scope.Allocation {
        return analyzer.module.scopes.append(analyzer.allocator, scope_value);
    }

    const TypeCheckResult = enum {
        success,
        zero_extend,
        sign_extend,
    };

    fn typeCheck(analyzer: *Analyzer, expect_type: ExpectType, source: Type.Index) !TypeCheckResult {
        return switch (expect_type) {
            .none => TypeCheckResult.success,
            .type_index => |expected_type_index| {
                if (expected_type_index.eq(source)) {
                    return TypeCheckResult.success;
                }

                const destination_type = analyzer.module.types.get(expected_type_index);
                const source_type = analyzer.module.types.get(source);

                switch (destination_type.*) {
                    .type => switch (source_type.* == .type) {
                        true => return TypeCheckResult.success,
                        false => unreachable,
                    },
                    .integer => |destination_int| switch (source_type.*) {
                        .integer => |source_int| {
                            const dst_size = destination_int.getSize();
                            const src_size = source_int.getSize();
                            logln(.sema, .typecheck, "Dst size: {}. Src size: {}", .{ dst_size, src_size });
                            if (dst_size < src_size) {
                                @panic("Destination integer type is smaller than source");
                            } else if (dst_size > src_size) {
                                unreachable;
                            } else {
                                return TypeCheckResult.success;
                            }
                        },
                        .comptime_int => return TypeCheckResult.success,
                        else => |t| @panic(@tagName(t)),
                    },
                    // TODO: type safety
                    .pointer => |destination_pointer| switch (source_type.*) {
                        .pointer => |source_pointer| {
                            switch (source_pointer.many == destination_pointer.many and source_pointer.element_type.eq(destination_pointer.element_type)) {
                                true => return TypeCheckResult.success,
                                false => unreachable,
                            }
                        },
                        else => |t| @panic(@tagName(t)),
                    },
                    else => |t| @panic(@tagName(t)),
                }
            },
            .flexible_integer => |expected_flexible_integer| {
                const source_type = analyzer.module.types.get(source);
                switch (source_type.*) {
                    .integer => |source_integer| {
                        const source_size = source_integer.getSize();
                        if (expected_flexible_integer.byte_count < source_size) {
                            unreachable;
                        } else if (expected_flexible_integer.byte_count > source_size) {
                            return switch (source_integer.signedness) {
                                .signed => .sign_extend,
                                .unsigned => .zero_extend,
                            };
                        } else {
                            return TypeCheckResult.success;
                        }
                    },
                    // TODO: add type safety
                    .pointer => |pointer| {
                        _ = pointer;
                        switch (expected_flexible_integer.byte_count == 8) {
                            true => return TypeCheckResult.success,
                            false => unreachable,
                        }
                    },
                    else => |t| @panic(@tagName(t)),
                }
                // if (expected_flexible_integer.byte_count <
                // _ = expected_flexible_integer;
            },
            // else => |t| @panic(@tagName(t)),
        };
    }
};

const ExpectType = union(enum) {
    none,
    type_index: Type.Index,
    flexible_integer: FlexibleInteger,

    pub const none = ExpectType{
        .none = {},
    };
    pub const boolean = ExpectType{
        .type_index = Type.boolean,
    };

    pub const @"type" = ExpectType{
        .type_index = Type.type,
    };

    const FlexibleInteger = struct {
        byte_count: u8,
        sign: ?bool = null,
    };
};

pub fn initialize(compilation: *Compilation, module: *Module, package: *Package, main_value: *Value) !void {
    _ = try analyzeExistingPackage(main_value, compilation, module, package);

    var decl_iterator = module.declarations.iterator();
    while (decl_iterator.nextPointer()) |decl| {
        const declaration_name = module.getName(decl.name).?;
        if (equal(u8, declaration_name, "_start")) {
            const value = module.values.get(decl.init_value);
            module.entry_point = switch (value.*) {
                .function => |function_index| function_index,
                .unresolved => panic("Unresolved declaration: {s}\n", .{declaration_name}),
                else => |t| @panic(@tagName(t)),
            };
            break;
        }
    } else {
        @panic("Entry point not found");
    }
}

pub fn analyzeExistingPackage(value: *Value, compilation: *Compilation, module: *Module, package: *Package) !Type.Index {
    const package_import = try module.importPackage(compilation.base_allocator, package);
    assert(!package_import.file.is_new);
    const file_index = package_import.file.index;

    return try analyzeFile(value, compilation.base_allocator, module, file_index);
}

pub fn analyzeFile(value: *Value, allocator: Allocator, module: *Module, file_index: File.Index) !Type.Index {
    const file = module.files.get(file_index);
    assert(value.* == .unresolved);
    assert(file.status == .parsed);

    var analyzer = Analyzer{
        .current_file = file_index,
        .allocator = allocator,
        .module = module,
    };

    const result = try analyzer.structType(value, Scope.Index.invalid, .{ .value = 0 }, file_index);
    return result;
}
