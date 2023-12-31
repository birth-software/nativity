const std = @import("std");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;
const equal = std.mem.eql;
const panic = std.debug.panic;
const Compilation = @import("../Compilation.zig");
const File = Compilation.File;
const Module = Compilation.Module;
const Package = Compilation.Package;

const ArrayType = Compilation.ArrayType;
const ArgumentList = Compilation.ArgumentList;
const Assignment = Compilation.Assignment;
const Block = Compilation.Block;
const Call = Compilation.Call;
const Declaration = Compilation.Declaration;
const Enum = Compilation.Type.Enum;
const Field = Compilation.Field;
const Function = Compilation.Function;
const Intrinsic = Compilation.Intrinsic;
const Loop = Compilation.Loop;
const Range = Compilation.Range;
const Scope = Compilation.Scope;
const ScopeType = Compilation.ScopeType;
const Slice = Compilation.Slice;
const Struct = Compilation.Struct;
const StringLiteral = Compilation.StringLiteral;
const Switch = Compilation.Switch;
const Termination = Compilation.Type.Termination;
const Type = Compilation.Type;
const ValidIntrinsic = Compilation.ValidIntrinsic;
const Value = Compilation.Value;

const log = Compilation.log;
const logln = Compilation.logln;

const ExpectedArrayType = struct {
    element_type: Type.Index,
    len: ?usize = null,
    termination: Termination,
};

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
    scope_lookup,
    debug,
    fn_return_type,
    address_of,
    reaches_end,

    pub var bitset = std.EnumSet(Logger).initMany(&.{
        .type,
        // .identifier,
        // .symbol_declaration,
        // .scope_node,
        // .node,
        // .typecheck,
        // .@"switch",
        // .block,
        // .call,
        // // .scope_lookup,
        // .debug,
        // .fn_return_type,
        // .address_of,
        // .reaches_end,
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

const ExpectType = union(enum) {
    none,
    type_index: Type.Index,
    flexible_integer: FlexibleInteger,
    addressable: Addressable,
    dereferenceable: Dereferenceable,

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

    const Addressable = Type.Pointer;
    const Dereferenceable = struct {
        element_type: Type.Index,
    };
};

pub var unreachable_index = Value.Index.invalid;
pub var optional_null_index = Value.Index.invalid;
pub var pointer_null_index = Value.Index.invalid;
pub var undefined_index = Value.Index.invalid;
pub var boolean_true = Value.Index.invalid;
pub var boolean_false = Value.Index.invalid;

pub var pointer_to_any_type = Type.Index.invalid;
pub var optional_pointer_to_any_type = Type.Index.invalid;
pub var optional_any = Type.Index.invalid;

const Analyzer = struct {
    allocator: Allocator,
    module: *Module,
    current_file: File.Index,
    current_declaration: Declaration.Index = Declaration.Index.invalid,
    payloads: ArrayList(Payload) = .{},
    current_block: Block.Index = Block.Index.invalid,
    maybe_count: usize = 0,
    for_count: usize = 0,

    fn getScopeSourceFile(analyzer: *Analyzer, scope_index: Scope.Index) []const u8 {
        const scope = analyzer.module.values.scopes.get(scope_index);
        const file = analyzer.module.values.files.get(scope.file);
        return file.source_code;
    }

    fn getScopeNode(analyzer: *Analyzer, scope_index: Scope.Index, node_index: Node.Index) Node {
        const scope = analyzer.module.values.scopes.get(scope_index);
        const file = analyzer.module.values.files.get(scope.file);
        const result = &file.syntactic_analyzer_result.nodes.items[node_index.unwrap()];
        // logln(.sema, .scope_node, "Fetching node #{} (0x{x}) from scope #{} from file #{} with id: {s}", .{ node_index.uniqueInteger(), @intFromPtr(result), scope_index.uniqueInteger(), scope.file.uniqueInteger(), @tagName(result.id) });
        return result.*;
    }

    fn getScopeToken(analyzer: *Analyzer, scope_index: Scope.Index, token_index: Token.Index) Token {
        const scope = analyzer.module.values.scopes.get(scope_index);
        const file = analyzer.module.values.files.get(scope.file);
        const result = file.lexical_analyzer_result.tokens.items[token_index];

        return result;
    }

    fn getScopeNodeList(analyzer: *Analyzer, scope_index: Scope.Index, node: Node) ArrayList(Node.Index) {
        const scope = analyzer.module.values.scopes.get(scope_index);
        return getFileNodeList(analyzer, scope.file, node);
    }

    fn getFileNodeList(analyzer: *Analyzer, file_index: File.Index, node: Node) ArrayList(Node.Index) {
        assert(node.id == .node_list);
        const file = analyzer.module.values.files.get(file_index);
        const list_index = node.left;
        return file.syntactic_analyzer_result.node_lists.items[list_index.uniqueInteger()];
    }

    fn getFileToken(analyzer: *Analyzer, file_index: File.Index, token: Token.Index) Token {
        const file = analyzer.module.values.files.get(file_index);
        const result = file.lexical_analyzer_result.tokens.items[token];
        return result;
    }

    fn getFileNode(analyzer: *Analyzer, file_index: File.Index, node_index: Node.Index) Node {
        const file = analyzer.module.values.files.get(file_index);
        const result = file.syntactic_analyzer_result.nodes.items[node_index.unwrap()];
        return result;
    }

    fn comptimeBlock(analyzer: *Analyzer, scope_index: Scope.Index, node_index: Node.Index) !Value.Index {
        const comptime_node = analyzer.getScopeNode(scope_index, node_index);

        const comptime_block = try analyzer.block(scope_index, .{ .none = {} }, comptime_node.left);
        const value_index = try analyzer.module.values.array.append(analyzer.allocator, .{
            .block = comptime_block,
        });
        return value_index;
    }

    fn unresolvedAllocate(analyzer: *Analyzer, scope_index: Scope.Index, expect_type: ExpectType, node_index: Node.Index) !Value.Index {
        const value_index = try analyzer.module.values.array.addOne(analyzer.allocator);
        analyzer.module.values.array.get(value_index).* = .{
            .unresolved = .{
                .node_index = node_index,
            },
        };
        try analyzer.resolveNode(value_index, scope_index, expect_type, node_index);
        return value_index;
    }

    fn block(analyzer: *Analyzer, parent_scope_index: Scope.Index, expect_type: ExpectType, node_index: Node.Index) anyerror!Block.Index {
        logln(.sema, .block, "Resolving block from scope #{} in file #{}", .{ parent_scope_index.uniqueInteger(), analyzer.module.values.scopes.get(parent_scope_index).file.uniqueInteger() });
        var reaches_end = true;
        const block_node = analyzer.getScopeNode(parent_scope_index, node_index);
        const statement_nodes = analyzer.getScopeNodeList(parent_scope_index, analyzer.getScopeNode(parent_scope_index, block_node.left));

        const scope_index = try analyzer.module.values.scopes.append(analyzer.allocator, .{
            .parent = parent_scope_index,
            .file = analyzer.module.values.scopes.get(parent_scope_index).file,
            .token = block_node.token,
        });

        logln(.sema, .type, "Creating block scope #{}. Parent: #{}", .{ scope_index.uniqueInteger(), parent_scope_index.uniqueInteger() });

        const block_index = try analyzer.module.values.blocks.append(analyzer.allocator, .{
            .statements = ArrayList(Value.Index){},
            .reaches_end = true,
        });
        const previous_block = analyzer.current_block;
        analyzer.current_block = block_index;

        for (analyzer.payloads.items) |payload| {
            const declaration_type = Declaration.Type{
                .resolved = payload.type,
            };
            const declaration_index = try analyzer.declarationCommon(scope_index, .local, payload.mutability, payload.name, declaration_type, payload.value, null);
            const statement_value_index = try analyzer.module.values.array.append(analyzer.allocator, .{
                .declaration = declaration_index,
            });
            try analyzer.module.values.blocks.get(block_index).statements.append(analyzer.allocator, statement_value_index);
        }

        analyzer.payloads.clearRetainingCapacity();

        const is_comptime = switch (block_node.id) {
            .comptime_block => true,
            .block => false,
            else => |t| @panic(@tagName(t)),
        };

        logln(.sema, .block, "Is comptime: {}", .{is_comptime});

        for (statement_nodes.items) |statement_node_index| {
            if (!reaches_end) {
                switch (expect_type) {
                    .type_index => |type_index| if (!type_index.eq(Type.noreturn)) {
                        unreachable;
                    },
                    else => |t| @panic(@tagName(t)),
                }
                unreachable;
            }

            const statement_node = analyzer.getScopeNode(scope_index, statement_node_index);
            logln(.sema, .node, "Trying to resolve statement of id {s}", .{@tagName(statement_node.id)});

            const statement_value_index = switch (statement_node.id) {
                .assign, .add_assign => try analyzer.module.values.array.append(analyzer.allocator, try analyzer.processAssignment(scope_index, statement_node_index)),
                .@"unreachable" => blk: {
                    reaches_end = false;
                    logln(.sema, .reaches_end, "Not reaching end because of unreachable", .{});
                    break :blk unreachable_index;
                },
                .simple_symbol_declaration => blk: {
                    const declaration_index = try analyzer.symbolDeclaration(scope_index, statement_node_index, .local);
                    const declaration = analyzer.module.values.declarations.get(declaration_index);
                    const init_value = analyzer.module.values.array.get(declaration.init_value);
                    switch (init_value.isComptime(analyzer.module) and declaration.mutability == .@"const") {
                        // Dont add comptime declaration statements
                        true => continue,
                        false => {
                            const statement_value_index = try analyzer.module.values.array.append(analyzer.allocator, .{
                                .declaration = declaration_index,
                            });
                            break :blk statement_value_index;
                        },
                    }
                },
                .@"return" => blk: {
                    reaches_end = false;
                    logln(.sema, .reaches_end, "Not reaching end because of unreachable", .{});

                    const return_expresssion = try analyzer.processReturn(scope_index, expect_type, statement_node_index);
                    const return_value_index = try analyzer.module.values.array.append(analyzer.allocator, return_expresssion);

                    break :blk return_value_index;
                },
                .call => blk: {
                    const call_index = try analyzer.processCall(scope_index, statement_node_index);
                    const call_statement_index = try analyzer.module.values.array.append(analyzer.allocator, .{
                        .call = call_index,
                    });
                    if (analyzer.getValueType(call_statement_index).eq(Type.noreturn)) {
                        logln(.sema, .reaches_end, "Not reaching end because of function call", .{});
                        reaches_end = false;
                    }
                    break :blk call_statement_index;
                },
                // TODO: reaches end switch statement
                .@"switch" => blk: {
                    const switch_value = try analyzer.processSwitch(scope_index, expect_type, statement_node_index);
                    switch (switch_value) {
                        .@"return" => {
                            logln(.sema, .reaches_end, "Not reaching end because of return inside a switch statement", .{});
                            reaches_end = false;
                        },
                        else => {},
                    }
                    const switch_value_index = try analyzer.module.values.array.append(analyzer.allocator, switch_value);

                    break :blk switch_value_index;
                },
                .if_else => blk: {
                    const if_else_node_index = statement_node_index;
                    const payload_node_index = Node.Index.invalid;
                    switch (try analyzer.processIfElse(scope_index, expect_type, if_else_node_index, payload_node_index)) {
                        .if_else => |if_else_value| {
                            const branch = analyzer.module.values.branches.get(if_else_value.branch);
                            reaches_end = branch.reaches_end;
                            if (!reaches_end) {
                                logln(.sema, .reaches_end, "Not reaching end because of branch statement", .{});
                            }
                            assert(if_else_value.maybe_payload_declaration_index == null);
                            const branch_value_index = try analyzer.module.values.array.append(analyzer.allocator, .{
                                .branch = if_else_value.branch,
                            });
                            break :blk branch_value_index;
                        },
                        .expression => |expression_value_index| break :blk expression_value_index,
                    }
                },
                .if_else_payload => blk: {
                    const if_else_node_index = statement_node.left;
                    const payload_node_index = statement_node.right;
                    switch (try analyzer.processIfElse(scope_index, expect_type, if_else_node_index, payload_node_index)) {
                        .if_else => |if_else_value| {
                            if (if_else_value.maybe_payload_declaration_index) |maybe_payload_declaration| {
                                try analyzer.module.values.blocks.get(block_index).statements.append(analyzer.allocator, maybe_payload_declaration);
                            }

                            const branch = analyzer.module.values.branches.get(if_else_value.branch);
                            reaches_end = branch.reaches_end;
                            if (!reaches_end) {
                                logln(.sema, .reaches_end, "Not reaching end because of branch statement", .{});
                            }
                            const branch_statement_index = try analyzer.module.values.array.append(analyzer.allocator, .{
                                .branch = if_else_value.branch,
                            });
                            break :blk branch_statement_index;
                        },
                        .expression => unreachable,
                    }
                },
                .@"if",
                .if_payload,
                => blk: {
                    const if_statement_node_index = switch (statement_node.id) {
                        .@"if" => statement_node_index,
                        .if_payload => statement_node.left,
                        else => unreachable,
                    };

                    const payload_node_index = switch (statement_node.id) {
                        .@"if" => Node.Index.invalid,
                        .if_payload => statement_node.right,
                        else => unreachable,
                    };

                    const if_expression = try analyzer.processIf(scope_index, expect_type, if_statement_node_index, payload_node_index);

                    switch (if_expression.expression.invalid) {
                        // The condition is not evaluated at comptime, so emit both branches
                        false => {
                            if (if_expression.maybe_payload_declaration_value) |maybe_payload_declaration| {
                                try analyzer.module.values.blocks.get(block_index).statements.append(analyzer.allocator, maybe_payload_declaration);
                            }

                            const branch_index = try analyzer.module.values.branches.append(analyzer.allocator, .{
                                .expression = if_expression.expression,
                                .taken_expression = if_expression.taken_expression,
                                .not_taken_expression = Value.Index.invalid,
                                .reaches_end = true, // The else branch, as it doesnt exist, always reaches the end
                            });
                            const branch_statement_index = try analyzer.module.values.array.append(analyzer.allocator, .{
                                .branch = branch_index,
                            });
                            break :blk branch_statement_index;
                        },
                        true => switch (if_expression.taken_expression.invalid) {
                            true => continue,
                            false => break :blk if_expression.taken_expression,
                        },
                    }
                },
                .compiler_intrinsic => blk: {
                    const intrinsic_value = try analyzer.compilerIntrinsic(scope_index, ExpectType.none, statement_node_index);
                    const value_index = try analyzer.module.values.array.append(analyzer.allocator, intrinsic_value);
                    break :blk value_index;
                },
                .assembly_block => blk: {
                    const assembly_value = try analyzer.assembly(scope_index, ExpectType.none, statement_node_index);
                    const value_index = try analyzer.module.values.array.append(analyzer.allocator, assembly_value);
                    break :blk value_index;
                },
                .for_loop => blk: {
                    const loop_index = try analyzer.forLoop(scope_index, expect_type, statement_node_index);
                    const value_index = try analyzer.module.values.array.append(analyzer.allocator, .{
                        .loop = loop_index,
                    });
                    break :blk value_index;
                },
                .simple_while => blk: {
                    const loop_index = try analyzer.whileLoop(scope_index, expect_type, statement_node_index);
                    const value_index = try analyzer.module.values.array.append(analyzer.allocator, .{
                        .loop = loop_index,
                    });
                    break :blk value_index;
                },
                // TODO: analyze further
                .break_expression => try analyzer.module.values.array.append(analyzer.allocator, .@"break"),
                else => |t| @panic(@tagName(t)),
            };

            try analyzer.module.values.blocks.get(block_index).statements.append(analyzer.allocator, statement_value_index);
        }

        analyzer.module.values.blocks.get(block_index).reaches_end = reaches_end;

        analyzer.current_block = previous_block;

        return block_index;
    }

    fn processAssemblyStatements(analyzer: *Analyzer, comptime architecture: type, scope_index: Scope.Index, assembly_statement_nodes: []const Node.Index) ![]Compilation.Assembly.Instruction.Index {
        var instructions = try ArrayList(Compilation.Assembly.Instruction.Index).initCapacity(analyzer.allocator, assembly_statement_nodes.len);

        for (assembly_statement_nodes) |assembly_statement_node_index| {
            const assembly_statement_node = analyzer.getScopeNode(scope_index, assembly_statement_node_index);
            const instruction_name = analyzer.tokenIdentifier(scope_index, assembly_statement_node.token);
            const instruction = inline for (@typeInfo(architecture.Instruction).Enum.fields) |instruction_enum_field| {
                if (equal(u8, instruction_name, instruction_enum_field.name)) {
                    break @field(architecture.Instruction, instruction_enum_field.name);
                }
            } else unreachable;
            const operand_node_list_node = analyzer.getScopeNode(scope_index, assembly_statement_node.left);
            const operand_nodes = analyzer.getScopeNodeList(scope_index, operand_node_list_node);

            var operand_list = try ArrayList(Compilation.Assembly.Operand).initCapacity(analyzer.allocator, operand_nodes.items.len);

            for (operand_nodes.items) |operand_node_index| {
                const operand_node = analyzer.getScopeNode(scope_index, operand_node_index);
                const operand: Compilation.Assembly.Operand = switch (operand_node.id) {
                    .assembly_register => blk: {
                        const register_name = analyzer.tokenIdentifier(scope_index, operand_node.token);

                        const register = inline for (@typeInfo(architecture.Register).Enum.fields) |register_enum_field| {
                            if (equal(u8, register_name, register_enum_field.name)) {
                                break @field(architecture.Register, register_enum_field.name);
                            }
                        } else unreachable;
                        break :blk .{
                            .register = @intFromEnum(register),
                        };
                    },
                    .number_literal => switch (std.zig.parseNumberLiteral(analyzer.numberBytes(scope_index, operand_node.token))) {
                        .int => |integer| .{
                            .number_literal = integer,
                        },
                        else => |t| @panic(@tagName(t)),
                    },
                    .identifier => .{
                        .value_index = try analyzer.doIdentifier(scope_index, ExpectType.none, operand_node.token, scope_index),
                    },
                    .address_of => .{
                        .value_index = try analyzer.module.values.array.append(analyzer.allocator, try analyzer.addressOf(scope_index, ExpectType.none, operand_node_index)),
                    },
                    else => |t| @panic(@tagName(t)),
                };
                operand_list.appendAssumeCapacity(operand);
            }

            const assembly_instruction_index = try analyzer.module.values.assembly_instructions.append(analyzer.allocator, .{
                .id = @intFromEnum(instruction),
                .operands = operand_list.items,
            });
            instructions.appendAssumeCapacity(assembly_instruction_index);
        }

        return instructions.items;
    }

    fn assembly(analyzer: *Analyzer, scope_index: Scope.Index, expect_type: ExpectType, node_index: Node.Index) !Value {
        _ = expect_type;
        const assembly_node = analyzer.getScopeNode(scope_index, node_index);
        assert(assembly_node.id == .assembly_block);
        assert(assembly_node.right.invalid);
        const assembly_statement_node_list = analyzer.getScopeNode(scope_index, assembly_node.left);
        const assembly_statement_nodes = analyzer.getScopeNodeList(scope_index, assembly_statement_node_list);
        const assembly_statements = switch (analyzer.module.descriptor.target.cpu.arch) {
            .x86_64 => try analyzer.processAssemblyStatements(Compilation.Assembly.x86_64, scope_index, assembly_statement_nodes.items),
            else => unreachable,
        };
        const assembly_block_index = try analyzer.module.values.assembly_blocks.append(analyzer.allocator, .{
            .instructions = assembly_statements,
        });
        return .{
            .assembly_block = assembly_block_index,
        };
    }

    fn processCallToFunctionPrototype(analyzer: *Analyzer, scope_index: Scope.Index, function_prototype_index: Function.Prototype.Index, call_argument_node_list: []const Node.Index, method_object: Value.Index) !ArrayList(Value.Index) {
        const function_prototype = analyzer.module.types.function_prototypes.get(function_prototype_index);

        const method_object_count = @intFromBool(!method_object.invalid);
        const call_argument_count = call_argument_node_list.len + method_object_count;

        var argument_array = try ArrayList(Value.Index).initCapacity(analyzer.allocator, call_argument_count);
        logln(.sema, .call, "Method object valid: {}", .{!method_object.invalid});

        if (!method_object.invalid) {
            const first_argument_index = function_prototype.arguments.items[0];
            const first_argument = analyzer.module.values.declarations.get(first_argument_index);
            const first_argument_type = first_argument.getType();
            const method_object_value = analyzer.module.values.array.get(method_object);
            const method_object_type = method_object_value.getType(analyzer.module);
            // TODO: further typecheck
            const method_object_argument = switch (analyzer.module.types.array.get(first_argument_type).*) {
                .pointer => switch (analyzer.module.types.array.get(method_object_type).*) {
                    .pointer => method_object,
                    else => blk: {
                        const unary_index = try analyzer.module.values.unary_operations.append(analyzer.allocator, .{
                            .id = .address_of,
                            .value = method_object,
                            .type = first_argument_type,
                        });
                        const address_of_index = try analyzer.module.values.array.append(analyzer.allocator, .{
                            .unary_operation = unary_index,
                        });
                        break :blk address_of_index;
                    },
                },
                else => switch (analyzer.module.types.array.get(method_object_type).*) {
                    .pointer => blk: {
                        const unary_index = try analyzer.module.values.unary_operations.append(analyzer.allocator, .{
                            .id = .pointer_dereference,
                            .value = method_object,
                            .type = first_argument_type,
                        });
                        const pointer_dereference_index = try analyzer.module.values.array.append(analyzer.allocator, .{
                            .unary_operation = unary_index,
                        });
                        break :blk pointer_dereference_index;
                    },
                    else => method_object,
                },
            };

            argument_array.appendAssumeCapacity(method_object_argument);
        }

        logln(.sema, .call, "Argument declaration count: {}. Argument node list count: {}", .{ function_prototype.arguments.items.len, call_argument_node_list.len });
        if (function_prototype.arguments.items.len == call_argument_count) {
            for (function_prototype.arguments.items[method_object_count..], call_argument_node_list, 0..) |argument_declaration_index, argument_node_index, _index| {
                const index = _index + method_object_count;
                const argument_declaration = analyzer.module.values.declarations.get(argument_declaration_index);
                const argument_node = analyzer.getScopeNode(scope_index, argument_node_index);
                const value_node_index = switch (argument_node.id) {
                    .identifier => blk: {
                        const identifier = analyzer.tokenIdentifier(scope_index, argument_node.token);
                        const identifier_hash = try analyzer.processIdentifier(identifier);

                        if (identifier_hash == argument_declaration.name) {
                            break :blk argument_node_index;
                        } else {
                            const call_site_name = analyzer.module.getName(identifier_hash).?;
                            const definition_site_name = analyzer.module.getName(argument_declaration.name).?;
                            // const function_name = analyzer.module.getName(analyzer.module.types.function_name_map.get(function_index).?).?;
                            std.debug.panic("At function call, argument #{} must be named the same way. Call site was name '{s}' while function definition has it named as '{s}'", .{ index, call_site_name, definition_site_name });
                        }
                    },
                    .named_argument => blk: {
                        const identifier_node = analyzer.getScopeNode(scope_index, argument_node.left);
                        if (identifier_node.id != .identifier) {
                            @panic("expected identifier");
                        }
                        const identifier = analyzer.tokenIdentifier(scope_index, identifier_node.token);
                        const identifier_hash = try analyzer.processIdentifier(identifier);

                        if (identifier_hash == argument_declaration.name) {
                            break :blk argument_node.right;
                        } else {
                            const call_site_name = analyzer.module.getName(identifier_hash).?;
                            const definition_site_name = analyzer.module.getName(argument_declaration.name).?;
                            // const function_name = analyzer.module.getName(analyzer.module.types.function_name_map.get(function_index).?).?;
                            std.debug.panic("At function call, argument #{} must be named the same way. Call site was name '{s}' while function definition has it named as '{s}'", .{ index, call_site_name, definition_site_name });
                        }
                    },
                    else => |node_id| {
                        const definition_site_name = analyzer.module.getName(argument_declaration.name).?;
                        // const function_name = analyzer.module.getName(analyzer.module.types.function_name_map.get(function_index).?).?;

                        std.debug.panic("Argument #{} of call to function of type {s} must be named as '{s}'", .{ index, @tagName(node_id), definition_site_name });
                    },
                };
                const argument_declaration_type = argument_declaration.getType();
                const argument_expect_type = ExpectType{
                    .type_index = argument_declaration_type,
                };
                const call_argument_value_index = try analyzer.unresolvedAllocate(scope_index, argument_expect_type, value_node_index);
                const call_site_type = analyzer.getValueType(call_argument_value_index);
                const result = try analyzer.typeCheck(argument_expect_type, call_site_type);

                argument_array.appendAssumeCapacity(switch (result) {
                    .array_coerce_to_slice => blk: {
                        const array_coerce_to_slice = try analyzer.module.values.intrinsics.append(analyzer.allocator, .{
                            .kind = .{
                                .array_coerce_to_slice = call_argument_value_index,
                            },
                            .type = argument_declaration_type,
                        });

                        const coertion_value = try analyzer.module.values.array.append(analyzer.allocator, .{
                            .intrinsic = array_coerce_to_slice,
                        });

                        break :blk coertion_value;
                    },
                    else => |t| @panic(@tagName(t)),
                    .success => call_argument_value_index,
                });
            }
        } else {
            panic("{s} call has argument count mismatch: call has {}, function declaration has {}", .{ switch (method_object.invalid) {
                true => "Function",
                false => "Method function",
            }, call_argument_count, function_prototype.arguments.items.len });
        }

        return argument_array;
    }

    fn processCall(analyzer: *Analyzer, scope_index: Scope.Index, node_index: Node.Index) !Call.Index {
        const node = analyzer.getScopeNode(scope_index, node_index);
        assert(!node.left.invalid);
        var is_field_access = false;

        const left_value_index = switch (!node.left.invalid) {
            true => blk: {
                const member_or_namespace_node_index = node.left;
                assert(!member_or_namespace_node_index.invalid);
                const n = analyzer.getScopeNode(scope_index, member_or_namespace_node_index);
                is_field_access = switch (n.id) {
                    .field_access => true,
                    else => false,
                };
                const this_value_index = try analyzer.unresolvedAllocate(scope_index, ExpectType.none, member_or_namespace_node_index);
                break :blk this_value_index;
            },
            false => unreachable, //Value.Index.invalid,
        };

        const left_type = switch (left_value_index.invalid) {
            false => switch (analyzer.module.values.array.get(left_value_index).*) {
                .function_definition => |function_index| analyzer.module.types.function_prototypes.get(analyzer.module.types.array.get(analyzer.module.types.function_definitions.get(function_index).prototype).function).return_type,
                .function_declaration => |function_index| analyzer.module.types.function_prototypes.get(analyzer.module.types.array.get(analyzer.module.types.function_declarations.get(function_index).prototype).function).return_type,
                .field_access => |field_access_index| blk: {
                    const field_access_type_index = analyzer.module.types.container_fields.get(analyzer.module.values.field_accesses.get(field_access_index).field).type;
                    const field_access_type = analyzer.module.types.array.get(field_access_type_index);
                    break :blk switch (field_access_type.*) {
                        .pointer => |pointer| b: {
                            assert(!pointer.many);
                            assert(pointer.@"const");
                            const appointee_type = analyzer.module.types.array.get(pointer.element_type);
                            break :b switch (appointee_type.*) {
                                .function => |function_prototype_index| analyzer.module.types.function_prototypes.get(function_prototype_index).return_type,
                                else => |t| @panic(@tagName(t)),
                            };
                        },
                        else => |t| @panic(@tagName(t)),
                    };
                },
                else => |t| @panic(@tagName(t)),
            },
            true => Type.Index.invalid,
        };

        const arguments_index = switch (node.id) {
            .call => try analyzer.module.values.argument_lists.append(analyzer.allocator, .{
                .array = b: {
                    const argument_list_node_index = node.right;
                    const call_argument_node_list = analyzer.getScopeNodeList(scope_index, analyzer.getScopeNode(scope_index, argument_list_node_index));

                    switch (analyzer.module.values.array.get(left_value_index).*) {
                        .function_definition => |function_index| {
                            const function_definition = analyzer.module.types.function_definitions.get(function_index);
                            const function_prototype_index = analyzer.module.types.array.get(function_definition.prototype).function;

                            logln(.sema, .call, "Is field access: {}", .{is_field_access});
                            const method_object: Value.Index = switch (is_field_access) {
                                true => mob: {
                                    const field_access_node = analyzer.getScopeNode(scope_index, node.left);
                                    assert(field_access_node.id == .field_access);
                                    const maybe_left_value_index = try analyzer.unresolvedAllocate(scope_index, ExpectType.none, field_access_node.left);
                                    const left_value_type_index = analyzer.getValueType(maybe_left_value_index);
                                    const left_value_type = analyzer.module.types.array.get(left_value_type_index);
                                    logln(.sema, .call, "Left value type: {}", .{left_value_type});
                                    break :mob switch (left_value_type.*) {
                                        .type => Value.Index.invalid,
                                        .@"struct" => switch (analyzer.module.values.array.get(left_value_index).*) {
                                            .function_definition => maybe_left_value_index,
                                            else => |t| @panic(@tagName(t)),
                                        },
                                        .pointer => maybe_left_value_index,
                                        // .field_access => maybe_left_value.index,
                                        else => |t| @panic(@tagName(t)),
                                    };
                                },
                                false => Value.Index.invalid,
                            };
                            break :b try analyzer.processCallToFunctionPrototype(scope_index, function_prototype_index, call_argument_node_list.items, method_object);
                        },
                        .function_declaration => |function_index| {
                            const function_declaration = analyzer.module.types.function_declarations.get(function_index);
                            const function_prototype_index = analyzer.module.types.array.get(function_declaration.prototype).function;
                            // TODO:
                            assert(!is_field_access);
                            const method_object = Value.Index.invalid;

                            break :b try analyzer.processCallToFunctionPrototype(scope_index, function_prototype_index, call_argument_node_list.items, method_object);
                        },
                        .field_access => |field_access_index| {
                            const field_access = analyzer.module.values.field_accesses.get(field_access_index);
                            const container_field = analyzer.module.types.container_fields.get(field_access.field);
                            const container_field_type = analyzer.module.types.array.get(container_field.type);
                            switch (container_field_type.*) {
                                .pointer => |function_pointer| {
                                    if (!function_pointer.@"const") {
                                        unreachable;
                                    }

                                    if (function_pointer.many) {
                                        unreachable;
                                    }

                                    const appointee_type = analyzer.module.types.array.get(function_pointer.element_type);
                                    switch (appointee_type.*) {
                                        .function => |function_prototype_index| {
                                            break :b try analyzer.processCallToFunctionPrototype(scope_index, function_prototype_index, call_argument_node_list.items, Value.Index.invalid);
                                        },
                                        else => |t| @panic(@tagName(t)),
                                    }
                                },
                                else => |t| @panic(@tagName(t)),
                            }
                        },
                        else => |t| @panic(@tagName(t)),
                    }
                },
            }),
            else => |t| @panic(@tagName(t)),
        };

        const call_index = try analyzer.module.values.calls.append(analyzer.allocator, .{
            .value = left_value_index,
            .arguments = arguments_index,

            .type = left_type,
        });

        return call_index;
    }

    fn typeCheckEnumLiteral(analyzer: *Analyzer, scope_index: Scope.Index, token_index: Token.Index, enum_type: Enum) !?Enum.Field.Index {
        const enum_name = tokenBytes(analyzer.getScopeToken(scope_index, token_index), analyzer.getScopeSourceFile(scope_index));
        const enum_name_hash = try analyzer.processIdentifier(enum_name);

        for (enum_type.fields.items) |enum_field_index| {
            const enum_field = analyzer.module.types.enum_fields.get(enum_field_index);
            const existing = analyzer.module.getName(enum_field.name).?;
            if (enum_field.name == enum_name_hash) {
                return enum_field_index;
            }

            logln(.sema, .typecheck, "Existing enum field \"{s}\" != enum literal \"{s}\"", .{ existing, enum_name });
        } else {
            return null;
        }
    }

    const TypeCheckSwitchEnums = struct {
        switch_case_groups: ArrayList(ArrayList(Enum.Field.Index)),
        else_switch_case_group_index: ?usize = null,
    };

    fn typecheckSwitchEnums(analyzer: *Analyzer, scope_index: Scope.Index, enum_type: Type.Enum, switch_case_node_list: []const Node.Index) !TypeCheckSwitchEnums {
        var result = TypeCheckSwitchEnums{
            .switch_case_groups = try ArrayList(ArrayList(Enum.Field.Index)).initCapacity(analyzer.allocator, switch_case_node_list.len),
        };

        var existing_enums = ArrayList(Enum.Field.Index){};

        for (switch_case_node_list, 0..) |switch_case_node_index, index| {
            const switch_case_node = analyzer.getScopeNode(scope_index, switch_case_node_index);

            switch (switch_case_node.left.invalid) {
                false => {
                    const switch_case_condition_node = analyzer.getScopeNode(scope_index, switch_case_node.left);
                    var switch_case_group = ArrayList(Enum.Field.Index){};

                    switch (switch_case_condition_node.id) {
                        .enum_literal => {
                            if (try typeCheckEnumLiteral(analyzer, scope_index, switch_case_condition_node.token + 1, enum_type)) |enum_field_index| {
                                for (existing_enums.items) |existing| {
                                    if (enum_field_index.eq(existing)) {
                                        // Duplicate case
                                        unreachable;
                                    }
                                }

                                try switch_case_group.append(analyzer.allocator, enum_field_index);
                                try existing_enums.append(analyzer.allocator, enum_field_index);
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
                                        if (try typeCheckEnumLiteral(analyzer, scope_index, case_condition_node.token + 1, enum_type)) |enum_field_index| {
                                            for (existing_enums.items) |existing| {
                                                if (enum_field_index.eq(existing)) {
                                                    // Duplicate case
                                                    unreachable;
                                                }
                                            }

                                            try existing_enums.append(analyzer.allocator, enum_field_index);
                                            switch_case_group.appendAssumeCapacity(enum_field_index);
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

                    result.switch_case_groups.appendAssumeCapacity(switch_case_group);
                },
                true => {
                    result.else_switch_case_group_index = index;
                },
            }
        }

        return result;
    }

    fn processSwitch(analyzer: *Analyzer, scope_index: Scope.Index, expect_type: ExpectType, node_index: Node.Index) !Value {
        const node = analyzer.getScopeNode(scope_index, node_index);
        assert(node.id == .@"switch");

        // analyzer.debugNode(scope_index, node_index);

        const switch_expression_value_index = try analyzer.unresolvedAllocate(scope_index, ExpectType.none, node.left);
        const switch_case_list_node = analyzer.getScopeNode(scope_index, node.right);
        const switch_case_node_list = switch (switch_case_list_node.id) {
            .node_list => analyzer.getScopeNodeList(scope_index, switch_case_list_node).items,
            else => |t| @panic(@tagName(t)),
        };

        switch (analyzer.module.values.array.get(switch_expression_value_index).*) {
            .enum_field => |e_field_index| {
                const e_field = analyzer.module.types.enum_fields.get(e_field_index);
                const enum_type_general = analyzer.module.types.array.get(e_field.parent);
                const enum_type = analyzer.module.types.enums.get(enum_type_general.@"enum");
                const enum_field_name = analyzer.module.getName(e_field.name);
                _ = enum_field_name;

                const typecheck_enum_result = try analyzer.typecheckSwitchEnums(scope_index, enum_type.*, switch_case_node_list);

                const group_index = for (typecheck_enum_result.switch_case_groups.items, 0..) |switch_case_group, switch_case_group_index| {
                    break for (switch_case_group.items) |enum_field_index| {
                        if (e_field_index.eq(enum_field_index)) {
                            break switch_case_group_index;
                        }
                    } else {
                        continue;
                    };
                } else typecheck_enum_result.else_switch_case_group_index orelse unreachable;

                logln(.sema, .@"switch", "Index: {}", .{group_index});

                const true_switch_case_node = analyzer.getScopeNode(scope_index, switch_case_node_list[group_index]);
                const result_index = try analyzer.unresolvedAllocate(scope_index, expect_type, true_switch_case_node.right);

                return analyzer.module.values.array.get(result_index).*;
            },
            .declaration_reference => |declaration_reference| {
                switch (analyzer.module.types.array.get(declaration_reference.getType(analyzer.module)).*) {
                    .@"enum" => |enum_index| {
                        const enum_type = analyzer.module.types.enums.get(enum_index);
                        const typecheck_enum_result = try analyzer.typecheckSwitchEnums(scope_index, enum_type.*, switch_case_node_list);

                        var group_list = try ArrayList(Switch.Group).initCapacity(analyzer.allocator, switch_case_node_list.len);

                        for (switch_case_node_list, typecheck_enum_result.switch_case_groups.items) |case_node_index, case_enum_group| {
                            const case_node = analyzer.getScopeNode(scope_index, case_node_index);
                            const expression_node_index = case_node.right;
                            const expression_value_index = try analyzer.unresolvedAllocate(scope_index, expect_type, expression_node_index);
                            var value_list = try ArrayList(Value.Index).initCapacity(analyzer.allocator, case_enum_group.items.len);

                            for (case_enum_group.items) |case_enum_item| {
                                const value_index = try analyzer.module.values.array.append(analyzer.allocator, .{
                                    .enum_field = case_enum_item,
                                });

                                value_list.appendAssumeCapacity(value_index);
                            }

                            group_list.appendAssumeCapacity(.{
                                .conditions = value_list,
                                .expression = expression_value_index,
                            });
                        }

                        const switch_expression = try analyzer.module.values.switches.append(analyzer.allocator, .{
                            .value = switch_expression_value_index,
                            .groups = group_list,
                        });

                        const switch_value = Value{
                            .switch_expression = switch_expression,
                        };

                        return switch_value;
                    },
                    else => |t| @panic(@tagName(t)),
                }
            },
            else => |t| @panic(@tagName(t)),
        }
    }

    fn range(analyzer: *Analyzer, scope_index: Scope.Index, node_index: Node.Index) !Range {
        const range_node = analyzer.getScopeNode(scope_index, node_index);
        assert(range_node.id == .range);

        const expect_type = ExpectType{
            .type_index = Type.usize,
        };

        const range_start_index = try analyzer.unresolvedAllocate(scope_index, expect_type, range_node.left);
        const range_end_index = switch (range_node.right.invalid) {
            true => Value.Index.invalid,
            false => try analyzer.unresolvedAllocate(scope_index, expect_type, range_node.right),
        };

        return Range{
            .start = range_start_index,
            .end = range_end_index,
        };
    }

    fn getPayloadName(analyzer: *Analyzer, scope_index: Scope.Index, node_index: Node.Index) ?[]const u8 {
        const payload_node = analyzer.getScopeNode(scope_index, node_index);
        const maybe_payload_name: ?[]const u8 = switch (payload_node.id) {
            .identifier => analyzer.tokenIdentifier(scope_index, payload_node.token),
            .discard => null,
            else => |t| @panic(@tagName(t)),
        };
        return maybe_payload_name;
    }

    fn whileLoop(analyzer: *Analyzer, parent_scope_index: Scope.Index, expect_type: ExpectType, while_node_index: Node.Index) !Loop.Index {
        const while_loop_node = analyzer.getScopeNode(parent_scope_index, while_node_index);
        assert(while_loop_node.id == .simple_while);
        // TODO: complete
        const scope_index = parent_scope_index;
        const condition_index = try analyzer.unresolvedAllocate(scope_index, ExpectType.boolean, while_loop_node.left);
        const body_index = try analyzer.unresolvedAllocate(scope_index, expect_type, while_loop_node.right);
        const reaches_end = switch (analyzer.module.values.array.get(body_index).*) {
            .block => |block_index| analyzer.module.values.blocks.get(block_index).reaches_end,
            else => |t| @panic(@tagName(t)),
        };

        const loop_index = try analyzer.module.values.loops.append(analyzer.allocator, .{
            .pre = Value.Index.invalid,
            .condition = condition_index,
            .body = body_index,
            .post = Value.Index.invalid,
            .reaches_end = reaches_end,
        });

        return loop_index;
    }

    fn forLoop(analyzer: *Analyzer, parent_scope_index: Scope.Index, expect_type: ExpectType, for_node_index: Node.Index) !Loop.Index {
        const for_loop_node = analyzer.getScopeNode(parent_scope_index, for_node_index);
        assert(for_loop_node.id == .for_loop);

        const scope_index = try analyzer.module.values.scopes.append(analyzer.allocator, .{
            .token = for_loop_node.token,
            .file = analyzer.module.values.scopes.get(parent_scope_index).file,
            .parent = parent_scope_index,
        });

        logln(.sema, .type, "Creating for loop scope #{}. Parent: #{}", .{ scope_index.uniqueInteger(), parent_scope_index.uniqueInteger() });

        const for_condition_node = analyzer.getScopeNode(scope_index, for_loop_node.left);
        assert(for_condition_node.id == .for_condition);

        const for_loop_element_node = analyzer.getScopeNode(scope_index, for_condition_node.left);
        var pre = Value.Index.invalid;
        const for_condition = switch (for_loop_element_node.id) {
            .range => blk: {
                const for_range = try analyzer.range(scope_index, for_condition_node.left);

                const for_loop_payload_node = analyzer.getScopeNode(scope_index, for_condition_node.right);
                const maybe_payload_name = switch (for_loop_payload_node.id) {
                    .node_list => b: {
                        const nodes = analyzer.getScopeNodeList(scope_index, for_loop_payload_node);
                        assert(nodes.items.len == 1);
                        const payload_node_index = nodes.items[0];
                        break :b analyzer.getPayloadName(scope_index, payload_node_index);
                    },
                    else => |t| @panic(@tagName(t)),
                };
                const payload_name = if (maybe_payload_name) |name| name else "_";
                const declaration_type = Declaration.Type{
                    .resolved = Type.usize,
                };
                const declaration_index = try analyzer.declarationCommon(scope_index, .local, .@"var", payload_name, declaration_type, for_range.start, null);
                const declaration_value_index = try analyzer.module.values.array.append(analyzer.allocator, .{
                    .declaration = declaration_index,
                });
                pre = declaration_value_index;

                const binary_condition_index = try analyzer.module.values.binary_operations.append(analyzer.allocator, .{
                    .id = .compare_less_than,
                    .type = Type.boolean,
                    .left = try analyzer.doIdentifierString(scope_index, ExpectType{
                        .type_index = Type.usize,
                    }, payload_name, scope_index),
                    .right = for_range.end,
                });

                const condition_index = try analyzer.module.values.array.append(analyzer.allocator, .{
                    .binary_operation = binary_condition_index,
                });
                break :blk condition_index;
            },
            else => |t| @panic(@tagName(t)),
        };

        const for_loop_body_index = try analyzer.unresolvedAllocate(scope_index, expect_type, for_loop_node.right);
        var post = Value.Index.invalid;
        switch (for_loop_element_node.id) {
            .range => {
                const for_condition_value = analyzer.module.values.array.get(for_condition);
                switch (for_condition_value.*) {
                    .binary_operation => |binary_operation_index| {
                        const binary_operation = analyzer.module.values.binary_operations.get(binary_operation_index);
                        const left_index = binary_operation.left;
                        const right_index = try analyzer.module.values.array.append(analyzer.allocator, .{
                            .integer = .{
                                .value = 1,
                                .type = Type.usize,
                                .signedness = .unsigned,
                            },
                        });

                        const assignment_index = try analyzer.module.values.assignments.append(analyzer.allocator, .{
                            .operation = .add,
                            .destination = left_index,
                            .source = right_index,
                        });

                        const assignment_value_index = try analyzer.module.values.array.append(analyzer.allocator, .{
                            .assign = assignment_index,
                        });
                        post = assignment_value_index;
                    },
                    else => |t| @panic(@tagName(t)),
                }
            },
            else => |t| @panic(@tagName(t)),
        }

        const reaches_end = switch (analyzer.module.values.array.get(for_loop_body_index).*) {
            .block => |block_index| analyzer.module.values.blocks.get(block_index).reaches_end,
            else => |t| @panic(@tagName(t)),
        };

        const loop_index = try analyzer.module.values.loops.append(analyzer.allocator, .{
            .pre = pre,
            .condition = for_condition,
            .body = for_loop_body_index,
            .reaches_end = reaches_end,
            .post = post,
        });

        return loop_index;
    }

    fn evaluateComptimeValue(analyzer: *Analyzer, value_index: Value.Index) ?Value.Index {
        const value = analyzer.module.values.array.get(value_index);
        return switch (value.*) {
            .declaration_reference => |declaration_reference| blk: {
                const declaration_index = declaration_reference.value;
                const declaration = analyzer.module.values.declarations.get(declaration_index);

                if (declaration.mutability == .@"const") {
                    if (!declaration.init_value.invalid) {
                        break :blk analyzer.evaluateComptimeValue(declaration.init_value);
                    }
                }

                break :blk null;
            },
            .intrinsic => |intrinsic_index| blk: {
                const intrinsic = analyzer.module.values.intrinsics.get(intrinsic_index);
                break :blk switch (intrinsic.kind) {
                    .cast => null,
                    else => |t| @panic(@tagName(t)),
                };
            },
            .unary_operation => |unary_operation_index| blk: {
                const unary_operation = analyzer.module.values.unary_operations.get(unary_operation_index);
                if (analyzer.evaluateComptimeValue(unary_operation.value)) |_| {
                    unreachable;
                } else {
                    break :blk null;
                }
            },
            .binary_operation => |binary_operation_index| blk: {
                const binary_operation = analyzer.module.values.binary_operations.get(binary_operation_index);
                if (analyzer.evaluateComptimeValue(binary_operation.left)) |left_index| {
                    if (analyzer.evaluateComptimeValue(binary_operation.right)) |right_index| {
                        switch (binary_operation.id) {
                            .compare_equal => {
                                if (left_index.eq(right_index)) break :blk boolean_true;
                                const left = analyzer.module.values.array.get(left_index);
                                const right = analyzer.module.values.array.get(right_index);

                                switch (left.*) {
                                    .enum_field => if (left.enum_field.eq(right.enum_field)) {
                                        break :blk boolean_true;
                                    } else {
                                        break :blk boolean_false;
                                    },
                                    else => |t| @panic(@tagName(t)),
                                }
                            },
                            else => |t| @panic(@tagName(t)),
                        }

                        unreachable;
                    }
                }

                break :blk null;
            },
            // TODO: delete optional unwrap as value
            .optional_unwrap => |optional_unwrap_index| blk: {
                const optional_unwrap = analyzer.module.values.optional_unwraps.get(optional_unwrap_index);
                if (analyzer.evaluateComptimeValue(optional_unwrap.value)) |_| {
                    unreachable;
                } else {
                    break :blk null;
                }
            },
            // TODO: support comptime code?
            .field_access,
            .call,
            .slice_access,
            => null,
            .bool => |boolean_value| switch (boolean_value) {
                true => return boolean_true,
                false => return boolean_false,
            },
            .enum_field => value_index,
            .indexed_access => |indexed_access_index| blk: {
                const indexed_access = analyzer.module.values.indexed_accesses.get(indexed_access_index);
                if (analyzer.evaluateComptimeValue(indexed_access.indexed_expression)) |comptime_indexed| {
                    _ = comptime_indexed;

                    if (analyzer.evaluateComptimeValue(indexed_access.index_expression)) |comptime_index| {
                        _ = comptime_index;

                        unreachable;
                    }
                }

                break :blk null;
            },
            else => |t| @panic(@tagName(t)),
        };
    }

    const If = struct {
        maybe_payload_declaration_value: ?Value.Index,
        expression: Value.Index,
        taken_expression: Value.Index,
        reaches_end: bool,
    };

    const Payload = struct {
        name: []const u8,
        mutability: Compilation.Mutability,
        type: Type.Index,
        value: Value.Index,
    };

    fn processIf(analyzer: *Analyzer, scope_index: Scope.Index, expect_type: ExpectType, if_node_index: Node.Index, payload_node_index: Node.Index) !If {
        const if_branch_node = analyzer.getScopeNode(scope_index, if_node_index);
        // analyzer.debugNode(scope_index, if_node_index);
        assert(if_branch_node.id == .@"if");

        var if_expression_index = try analyzer.unresolvedAllocate(scope_index, ExpectType{
            .type_index = switch (payload_node_index.invalid) {
                true => Type.boolean,
                false => optional_any,
            },
        }, if_branch_node.left);

        if (payload_node_index.invalid) {
            if (analyzer.evaluateComptimeValue(if_expression_index)) |comptime_evaluated_condition| {
                if (comptime_evaluated_condition.eq(boolean_true)) {
                    return If{
                        .maybe_payload_declaration_value = null,
                        .expression = Value.Index.invalid,
                        .taken_expression = try analyzer.unresolvedAllocate(scope_index, expect_type, if_branch_node.right),
                        .reaches_end = true,
                    };
                } else if (comptime_evaluated_condition.eq(boolean_false)) {
                    return If{
                        .maybe_payload_declaration_value = null,
                        .expression = Value.Index.invalid,
                        .taken_expression = Value.Index.invalid,
                        .reaches_end = true,
                    };
                } else {
                    @panic("internal error");
                }
            }
        }

        const maybe_payload_declaration_value_index: ?Value.Index = if (!payload_node_index.invalid) blk: {
            const if_type_index = analyzer.getValueType(if_expression_index);
            logln(.sema, .fn_return_type, "If condition expression has type #{}", .{if_type_index.uniqueInteger()});
            const if_type = analyzer.module.types.array.get(if_type_index);
            assert(if_type.* == .optional);
            const payload_type_index = if_type.optional.element_type;
            const maybe_payload_name = analyzer.getPayloadName(scope_index, payload_node_index);

            switch (analyzer.module.types.array.get(if_type_index).*) {
                .optional => {},
                else => |t| @panic(@tagName(t)),
            }

            const result: ?Value.Index = if (maybe_payload_name) |payload_name| b: {
                const maybe_payload_declaration_type = Declaration.Type{
                    .resolved = if_type_index,
                };

                const maybe_payload_declaration_index = try analyzer.declarationCommon(scope_index, .local, .@"const", try std.fmt.allocPrint(analyzer.allocator, "maybe_{}_{s}", .{ maybe: {
                    const r = analyzer.maybe_count;
                    analyzer.maybe_count += 1;
                    break :maybe r;
                }, payload_name }), maybe_payload_declaration_type, if_expression_index, null);

                const maybe_payload_declaration_value_index = try analyzer.module.values.array.append(analyzer.allocator, .{
                    .declaration = maybe_payload_declaration_index,
                });

                if_expression_index = try analyzer.module.values.array.append(analyzer.allocator, .{
                    .declaration_reference = .{
                        .value = maybe_payload_declaration_index,
                    },
                });

                break :b maybe_payload_declaration_value_index;
            } else null;

            const if_expression_before_optional_check = if_expression_index;

            const optional_check_index = try analyzer.module.values.optional_checks.append(analyzer.allocator, .{
                .value = if_expression_index,
            });

            if_expression_index = try analyzer.module.values.array.append(analyzer.allocator, .{
                .optional_check = optional_check_index,
            });

            if (maybe_payload_name) |payload_name| {
                const optional_unwrap_index = try analyzer.module.values.optional_unwraps.append(analyzer.allocator, .{
                    .value = if_expression_before_optional_check,
                });
                const payload_value_index = try analyzer.module.values.array.append(analyzer.allocator, .{
                    .optional_unwrap = optional_unwrap_index,
                });

                try analyzer.payloads.append(analyzer.allocator, Payload{
                    .name = payload_name,
                    .mutability = .@"const",
                    .type = payload_type_index,
                    .value = payload_value_index,
                });
            }

            break :blk result;
        } else null;

        const taken_expression_index = try analyzer.unresolvedAllocate(scope_index, expect_type, if_branch_node.right);

        const true_reaches_end = switch (analyzer.module.values.array.get(taken_expression_index).*) {
            .block => |block_index| analyzer.module.values.blocks.get(block_index).reaches_end,
            .string_literal => true,
            else => |t| @panic(@tagName(t)),
        };

        const if_result = If{
            .maybe_payload_declaration_value = maybe_payload_declaration_value_index,
            .expression = if_expression_index,
            .taken_expression = taken_expression_index,
            .reaches_end = true_reaches_end,
        };
        return if_result;
    }

    const IfElseResult = union(enum) {
        if_else: struct {
            maybe_payload_declaration_index: ?Value.Index,
            branch: Compilation.Branch.Index,
        },
        expression: Value.Index,
    };

    fn processIfElse(analyzer: *Analyzer, scope_index: Scope.Index, expect_type: ExpectType, node_index: Node.Index, payload_node_index: Node.Index) !IfElseResult {
        const node = analyzer.getScopeNode(scope_index, node_index);
        assert(node.id == .if_else);
        assert(!node.left.invalid);
        assert(!node.right.invalid);

        const if_result = try analyzer.processIf(scope_index, expect_type, node.left, payload_node_index);
        switch (if_result.expression.invalid) {
            // The condition is not evaluated at comptime, so emit both branches
            false => {
                const not_taken_expression_index = try analyzer.unresolvedAllocate(scope_index, expect_type, node.right);
                const false_reaches_end = switch (analyzer.module.values.array.get(not_taken_expression_index).*) {
                    .block => |block_index| analyzer.module.values.blocks.get(block_index).reaches_end,
                    .branch => |branch_index| analyzer.module.values.branches.get(branch_index).reaches_end,
                    .string_literal => true,
                    else => |t| @panic(@tagName(t)),
                };
                const reaches_end = if_result.reaches_end or false_reaches_end;

                const branch_index = try analyzer.module.values.branches.append(analyzer.allocator, .{
                    .expression = if_result.expression,
                    .taken_expression = if_result.taken_expression,
                    .not_taken_expression = not_taken_expression_index,
                    .reaches_end = reaches_end,
                });

                return IfElseResult{
                    .if_else = .{
                        .maybe_payload_declaration_index = if_result.maybe_payload_declaration_value,
                        .branch = branch_index,
                    },
                };
            },
            true => return .{
                .expression = switch (if_result.taken_expression.invalid) {
                    true => try analyzer.unresolvedAllocate(scope_index, expect_type, node.right),
                    false => if_result.taken_expression,
                },
            },
        }
    }

    fn processAssignment(analyzer: *Analyzer, scope_index: Scope.Index, node_index: Node.Index) !Value {
        const node = analyzer.getScopeNode(scope_index, node_index);
        assert(!node.left.invalid);
        const left_node = analyzer.getScopeNode(scope_index, node.left);
        switch (left_node.id) {
            .discard => {
                assert(node.id == .assign);

                const result = try analyzer.unresolvedAllocate(scope_index, ExpectType.none, node.right);

                return analyzer.module.values.array.get(result).*;
            },
            else => {
                // const id = analyzer.tokenIdentifier(.token);
                // logln("id: {s}", .{id});
                const left = try analyzer.unresolvedAllocate(scope_index, ExpectType.none, node.left);
                const left_type_index = analyzer.getValueType(left);
                assert(!left_type_index.invalid);
                const right = try analyzer.unresolvedAllocate(scope_index, ExpectType{
                    .type_index = left_type_index,
                }, node.right);

                if (analyzer.module.values.array.get(left).isComptime(analyzer.module) and analyzer.module.values.array.get(right).isComptime(analyzer.module)) {
                    unreachable;
                } else {
                    const assignment_index = try analyzer.module.values.assignments.append(analyzer.allocator, .{
                        .destination = left,
                        .source = right,
                        .operation = switch (node.id) {
                            .assign => .none,
                            .add_assign => .add,
                            else => unreachable,
                        },
                    });

                    return Value{
                        .assign = assignment_index,
                    };
                }
            },
        }
    }

    fn processReturn(analyzer: *Analyzer, scope_index: Scope.Index, expect_type: ExpectType, node_index: Node.Index) !Value {
        const node = analyzer.getScopeNode(scope_index, node_index);
        const return_value: Value.Index = switch (node_index.invalid) {
            // TODO: expect type
            false => ret: {
                const return_value_index = try analyzer.unresolvedAllocate(scope_index, expect_type, node.left);
                break :ret return_value_index;
            },
            true => @panic("TODO: ret void"),
        };

        const return_expression_index = try analyzer.module.values.returns.append(analyzer.allocator, .{
            .value = return_value,
        });

        return .{
            .@"return" = return_expression_index,
        };
    }

    fn processBinaryOperation(analyzer: *Analyzer, scope_index: Scope.Index, expect_type: ExpectType, node_index: Node.Index) !Value {
        const node = analyzer.getScopeNode(scope_index, node_index);
        const binary_operation_id: Compilation.BinaryOperation.Id = switch (node.id) {
            .add => .add,
            .sub => .sub,
            .bit_and => .bit_and,
            .bit_xor => .bit_xor,
            .bit_or => .bit_or,
            .multiply => .multiply,
            .divide => .divide,
            .shift_left => .shift_left,
            .shift_right => .shift_right,
            .compare_equal => .compare_equal,
            .compare_not_equal => .compare_not_equal,
            .compare_greater_than => .compare_greater_than,
            .compare_greater_or_equal => .compare_greater_or_equal,
            .compare_less_than => .compare_less_than,
            .compare_less_or_equal => .compare_less_or_equal,
            else => |t| @panic(@tagName(t)),
        };
        const left_expect_type: ExpectType = switch (binary_operation_id) {
            .compare_equal,
            .compare_not_equal,
            .compare_less_or_equal,
            .compare_less_than,
            .compare_greater_than,
            .compare_greater_or_equal,
            => ExpectType.none,
            else => expect_type,
        };

        const left_index = try analyzer.unresolvedAllocate(scope_index, left_expect_type, node.left);
        const right_expect_type: ExpectType = switch (binary_operation_id) {
            .add,
            .sub,
            .bit_and,
            .bit_xor,
            .bit_or,
            .multiply,
            .divide,
            => expect_type,
            .shift_left,
            .shift_right,
            => ExpectType{
                .type_index = Type.u8,
            },
            .compare_equal,
            .compare_less_than,
            .compare_greater_or_equal,
            .compare_greater_than,
            .compare_less_or_equal,
            .compare_not_equal,
            => ExpectType{
                .type_index = analyzer.getValueType(left_index),
            },
        };
        const left_type = analyzer.getValueType(left_index);
        const right_index = try analyzer.unresolvedAllocate(scope_index, right_expect_type, node.right);

        const binary_operation_index = try analyzer.module.values.binary_operations.append(analyzer.allocator, .{
            .left = left_index,
            .right = right_index,
            .type = switch (expect_type) {
                .none => switch (binary_operation_id) {
                    .bit_and,
                    .shift_right,
                    .sub,
                    .multiply,
                    => left_type,
                    else => |t| @panic(@tagName(t)),
                },
                .type_index => |type_index| type_index,
                else => |t| @panic(@tagName(t)),
            },
            .id = binary_operation_id,
        });

        return .{
            .binary_operation = binary_operation_index,
        };
    }

    const DeclarationLookup = struct {
        declaration: Declaration.Index,
        scope: Scope.Index,
    };

    fn getScopeSlice(analyzer: *Analyzer, scope_index: Scope.Index) []const u8 {
        const scope = analyzer.module.values.scopes.get(scope_index);

        return analyzer.getScopeSliceCustomToken(scope_index, scope.token);
    }

    fn getScopeSliceCustomToken(analyzer: *Analyzer, scope_index: Scope.Index, custom_token_index: Token.Index) []const u8 {
        const scope = analyzer.module.values.scopes.get(scope_index);
        const token = analyzer.getFileToken(scope.file, custom_token_index);
        const scope_slice = analyzer.module.values.files.get(scope.file).source_code[token.start..];
        return scope_slice;
    }

    fn lookupDeclarationInCurrentAndParentScopes(analyzer: *Analyzer, scope_index: Scope.Index, identifier_hash: u32) ?DeclarationLookup {
        var scope_iterator = scope_index;
        while (!scope_iterator.invalid) {
            const scope = analyzer.module.values.scopes.get(scope_iterator);
            if (Logger.bitset.contains(.scope_lookup)) {
                const scope_slice = analyzer.getScopeSlice(scope_iterator);
                logln(.sema, .scope_lookup, "Searching for identifier 0x{x} in scope #{}:\n```{s}\n```", .{ identifier_hash, scope_iterator.uniqueInteger(), scope_slice });
            }

            if (scope.declarations.get(identifier_hash)) |declaration_index| {
                logln(.sema, .scope_lookup, "Identifier 0x{x} found in scope #{}", .{ identifier_hash, scope_iterator.uniqueInteger() });

                return .{
                    .declaration = declaration_index,
                    .scope = scope_iterator,
                };
            }

            scope_iterator = scope.parent;
        }

        return null;
    }

    fn addressOf(analyzer: *Analyzer, scope_index: Scope.Index, expect_type: ExpectType, node_index: Node.Index) !Value {
        const node = analyzer.getScopeNode(scope_index, node_index);

        const pointer_expect_type: ExpectType = switch (expect_type) {
            .none => expect_type,
            .type_index => |type_index| .{
                .addressable = switch (analyzer.module.types.array.get(type_index).*) {
                    .pointer => |pointer| pointer,
                    .slice => |slice| .{
                        .@"const" = slice.@"const",
                        .many = true,
                        .element_type = slice.element_type,
                        .termination = slice.termination,
                    },
                    else => |t| @panic(@tagName(t)),
                },
            },
            .flexible_integer => unreachable,
            else => unreachable,
        };

        const appointee_value_index = try analyzer.unresolvedAllocate(scope_index, pointer_expect_type, node.left);
        const addressable = switch (pointer_expect_type) {
            .none => switch (analyzer.module.values.array.get(appointee_value_index).*) {
                .declaration_reference => |*declaration_reference| switch (analyzer.module.types.array.get(declaration_reference.getType(analyzer.module)).*) {
                    .integer => ExpectType.Addressable{
                        .element_type = declaration_reference.getType(analyzer.module),
                        .many = false,
                        .@"const" = false,
                        .termination = .none,
                    },
                    .pointer => |pointer| pointer,
                    .any => {
                        // TODO
                        // const declaration = analyzer.module.values.declarations.get(declaration_reference.value);
                        // switch (analyzer.module.types.array.get(declaration.type).*) {
                        //     else => |t| @panic(@tagName(t)),
                        // }
                        unreachable;
                    },
                    else => |t| @panic(@tagName(t)),
                },
                else => |t| @panic(@tagName(t)),
            },
            .addressable => |addressable| addressable,
            else => |t| @panic(@tagName(t)),
        };
        //
        const unary_type_index: Type.Index = try analyzer.getPointerType(.{
            .element_type = analyzer.module.values.array.get(appointee_value_index).getType(analyzer.module),
            .many = addressable.many,
            .@"const" = addressable.@"const",
            .termination = addressable.termination,
        });

        const unary_index = try analyzer.module.values.unary_operations.append(analyzer.allocator, .{
            .id = .address_of,
            .value = appointee_value_index,
            .type = unary_type_index,
        });

        const value: Value = switch (expect_type) {
            .none => .{
                .unary_operation = unary_index,
            },
            .type_index => |type_index| switch (analyzer.module.types.array.get(type_index).*) {
                .slice => b: {
                    const array_coerce_to_slice = try analyzer.module.values.intrinsics.append(analyzer.allocator, .{
                        .kind = .{
                            .array_coerce_to_slice = appointee_value_index,
                        },
                        .type = type_index,
                    });
                    break :b .{
                        .intrinsic = array_coerce_to_slice,
                    };
                },
                else => .{
                    .unary_operation = unary_index,
                },
            },
            else => |t| @panic(@tagName(t)),
        };

        return value;
    }

    fn doIdentifierString(analyzer: *Analyzer, from_scope_index: Scope.Index, expect_type: ExpectType, identifier: []const u8, in_scope_index: Scope.Index) !Value.Index {
        logln(.sema, .identifier, "Referencing identifier: \"{s}\" from scope #{} in scope #{}", .{ identifier, from_scope_index.uniqueInteger(), in_scope_index.uniqueInteger() });
        const identifier_hash = try analyzer.processIdentifier(identifier);

        if (analyzer.lookupDeclarationInCurrentAndParentScopes(from_scope_index, identifier_hash)) |lookup| {
            const declaration_index = lookup.declaration;
            const declaration = analyzer.module.values.declarations.get(declaration_index);

            switch (declaration.init_value.invalid) {
                false => {
                    // logln(.sema, .identifier, "Declaration found: {}", .{init_value});
                    switch (analyzer.module.values.array.get(declaration.init_value).*) {
                        .unresolved => |unresolved| {
                            const previous_declaration = analyzer.current_declaration;
                            analyzer.current_declaration = declaration_index;

                            switch (declaration.type) {
                                .inferred => |inferred_type_index| assert(inferred_type_index.invalid),
                                .unresolved => |node_index| {
                                    declaration.type = .{
                                        .resolved = try analyzer.resolveType(.{
                                            .scope_index = declaration.scope,
                                            .node_index = node_index,
                                        }),
                                    };
                                },
                                else => |t| @panic(@tagName(t)),
                            }

                            try analyzer.resolveNode(declaration.init_value, lookup.scope, expect_type, unresolved.node_index);
                            analyzer.current_declaration = previous_declaration;

                            switch (analyzer.module.values.array.get(declaration.init_value).*) {
                                .function_definition => |function_index| {
                                    const function_definition = analyzer.module.types.function_definitions.get(function_index);
                                    const function_prototype = analyzer.module.types.array.get(function_definition.prototype);
                                    const return_type_index = analyzer.functionPrototypeReturnType(function_prototype.function);
                                    logln(.sema, .fn_return_type, "Function {s} has return type #{}", .{ analyzer.module.getName(declaration.name).?, return_type_index.uniqueInteger() });
                                    try analyzer.module.map.function_definitions.put(analyzer.allocator, function_index, declaration_index);
                                },
                                .function_declaration => |function_index| {
                                    try analyzer.module.map.function_declarations.put(analyzer.allocator, function_index, declaration_index);
                                },
                                .type => |type_index| {
                                    try analyzer.module.map.types.put(analyzer.allocator, type_index, declaration_index);
                                },
                                else => {},
                            }
                        },
                        else => {},
                    }
                },
                true => {
                    switch (declaration.type) {
                        .resolved => {},
                        else => |t| @panic(@tagName(t)),
                    }
                },
            }

            switch (declaration.type) {
                .inferred => |*inferred_type_index| {
                    const declaration_value_type = analyzer.module.values.array.get(declaration.init_value).getType(analyzer.module);
                    switch (inferred_type_index.invalid) {
                        true => inferred_type_index.* = declaration_value_type,
                        false => {},
                    }
                },
                .resolved => {},
                else => |t| @panic(@tagName(t)),
            }

            const declaration_type_index = declaration.getType();
            const typecheck_result = try analyzer.typeCheck(expect_type, declaration_type_index);

            assert(!declaration_type_index.invalid);
            assert(!declaration_type_index.eq(pointer_to_any_type));
            assert(!declaration_type_index.eq(optional_pointer_to_any_type));
            assert(!declaration_type_index.eq(optional_any));

            if (!declaration.init_value.invalid and analyzer.module.values.array.get(declaration.init_value).isComptime(analyzer.module) and declaration.mutability == .@"const") {
                assert(!declaration.init_value.invalid);
                assert(typecheck_result == .success);
                return declaration.init_value;
            } else {
                const declaration_reference = try analyzer.module.values.array.append(analyzer.allocator, .{
                    .declaration_reference = .{
                        .value = declaration_index,
                    },
                });

                const result: Value.Index = switch (typecheck_result) {
                    .success,
                    .take_source,
                    => declaration_reference,
                    .optional_wrap => blk: {
                        const cast_type = switch (expect_type) {
                            .type_index => |type_index| type_index,
                            else => |t| @panic(@tagName(t)),
                        };
                        const intrinsic_index = try analyzer.module.values.intrinsics.append(analyzer.allocator, .{
                            .kind = .{
                                .optional_wrap = declaration_reference,
                            },
                            .type = cast_type,
                        });

                        const value_index = try analyzer.module.values.array.append(analyzer.allocator, .{
                            .intrinsic = intrinsic_index,
                        });
                        break :blk value_index;
                    },
                    inline .zero_extend, .sign_extend => |extension_type| blk: {
                        const intrinsic = try analyzer.module.values.intrinsics.append(analyzer.allocator, .{
                            .kind = @unionInit(Intrinsic.Kind, @tagName(extension_type), declaration_reference),
                            .type = switch (expect_type) {
                                .flexible_integer => |flexible_integer| t: {
                                    const cast_type = Type.Integer.getIndex(.{
                                        .signedness = switch (extension_type) {
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

                        const value_index = try analyzer.module.values.array.append(analyzer.allocator, .{
                            .intrinsic = intrinsic,
                        });
                        break :blk value_index;
                    },
                    else => |t| @panic(@tagName(t)),
                };
                return result;
            }

            // return switch (typecheck_result) {
            //     .success,
            //     .take_source,
            //     => reference_index,
            //     .array_coerce_to_slice => {
            //         const cast_type = switch (expect_type) {
            //             .type_index => |type_index| type_index,
            //             else => |t| @panic(@tagName(t)),
            //         };
            //         _ = cast_type;
            //         unreachable;
            //         // const cast_index = try analyzer.module.values.casts.append(analyzer.allocator, .{
            //         //     .value = reference_index,
            //         //     .type = cast_type,
            //         // });
            //         //
            //         // const value_index = try analyzer.module.values.array.append(analyzer.allocator, .{
            //         //     .array_coerce_to_slice = cast_index,
            //         // });
            //         //
            //         // break :blk value_index;
            //     },
            // };
        } else {
            panic("Identifier \"{s}\" not found as a declaration from scope #{} referenced in scope #{}", .{ identifier, from_scope_index.uniqueInteger(), in_scope_index.uniqueInteger() });
        }
    }

    fn doIdentifier(analyzer: *Analyzer, scope_index: Scope.Index, expect_type: ExpectType, node_token: Token.Index, node_scope_index: Scope.Index) !Value.Index {
        const identifier = analyzer.tokenIdentifier(node_scope_index, node_token);
        return try analyzer.doIdentifierString(scope_index, expect_type, identifier, node_scope_index);
    }

    fn resolveInteger(analyzer: *Analyzer, scope_index: Scope.Index, value_index: Value.Index) usize {
        const value = analyzer.module.values.array.get(value_index);
        return switch (value.*) {
            .declaration_reference => |declaration_reference| blk: {
                const declaration = analyzer.module.values.declarations.get(declaration_reference.value);
                break :blk analyzer.resolveInteger(declaration.scope, declaration.init_value);
            },
            .integer => |integer| integer.value,
            .binary_operation => |binary_operation_index| {
                const binary_operation = analyzer.module.values.binary_operations.get(binary_operation_index);
                const left = analyzer.resolveInteger(scope_index, binary_operation.left);
                const right = analyzer.resolveInteger(scope_index, binary_operation.right);
                return switch (binary_operation.id) {
                    .add => left + right,
                    else => |t| @panic(@tagName(t)),
                };
            },
            else => |t| @panic(@tagName(t)),
        };
    }

    fn resolveNode(analyzer: *Analyzer, value_index: Value.Index, scope_index: Scope.Index, expect_type: ExpectType, node_index: Node.Index) anyerror!void {
        const node = analyzer.getScopeNode(scope_index, node_index);
        // logln(.sema, .node, "Resolving node #{} in scope #{} from file #{}: {}", .{ node_index.uniqueInteger(), scope_index.uniqueInteger(), analyzer.module.values.scopes.get(scope_index).file.uniqueInteger(), node });

        assert(analyzer.module.values.array.get(value_index).* == .unresolved);

        const new_value: Value = switch (node.id) {
            .identifier => blk: {
                const identifier_value_index = try analyzer.doIdentifier(scope_index, expect_type, node.token, scope_index);
                const value_ref = analyzer.module.values.array.get(identifier_value_index);
                break :blk value_ref.*;
            },
            .keyword_true, .keyword_false => blk: {
                switch (expect_type) {
                    .none => {},
                    .type_index => |expected_type| {
                        if (@as(u32, @bitCast(Type.boolean)) != @as(u32, @bitCast(expected_type))) {
                            @panic("TODO: compile error");
                        }
                    },
                    else => unreachable,
                }

                break :blk .{
                    .bool = switch (node.id) {
                        .keyword_true => true,
                        .keyword_false => false,
                        else => unreachable,
                    },
                };
            },
            .compiler_intrinsic => try analyzer.compilerIntrinsic(scope_index, expect_type, node_index),
            .function_definition => blk: {
                const function_prototype_index = try analyzer.functionPrototype(scope_index, node.left);
                const function_prototype = analyzer.module.types.function_prototypes.get(function_prototype_index);
                assert(!function_prototype.attributes.@"extern");
                const function_scope_index = function_prototype.scope;

                const expected_type = ExpectType{
                    .type_index = analyzer.functionPrototypeReturnType(function_prototype_index),
                };
                const function_body = try analyzer.block(function_scope_index, expected_type, node.right);

                const prototype_type_index = try analyzer.module.types.array.append(analyzer.allocator, .{
                    .function = function_prototype_index,
                });

                const function_index = try analyzer.module.types.function_definitions.append(analyzer.allocator, .{
                    .prototype = prototype_type_index,
                    .body = function_body,
                });

                const result = Value{
                    .function_definition = function_index,
                };
                break :blk result;
            },
            .function_prototype => blk: {
                const function_prototype_index = try analyzer.functionPrototype(scope_index, node_index);
                const function_prototype = analyzer.module.types.function_prototypes.get(function_prototype_index);

                break :blk switch (function_prototype.attributes.@"extern") {
                    true => b: {
                        const prototype_type_index = try analyzer.module.types.array.append(analyzer.allocator, .{
                            .function = function_prototype_index,
                        });
                        const function_declaration_index = try analyzer.module.types.function_declarations.append(analyzer.allocator, .{
                            .prototype = prototype_type_index,
                            .body = Block.Index.invalid,
                        });
                        break :b Value{
                            .function_declaration = function_declaration_index,
                        };
                    },
                    false => unreachable,
                };
            },
            .block => blk: {
                const block_index = try analyzer.block(scope_index, expect_type, node_index);
                break :blk Value{
                    .block = block_index,
                };
            },
            .number_literal => switch (std.zig.parseNumberLiteral(analyzer.numberBytes(scope_index, node.token))) {
                .int => |integer| Value{
                    .integer = .{
                        .value = integer,
                        .type = switch (expect_type) {
                            .none => Type.comptime_int,
                            .flexible_integer, .type_index => switch (expect_type) {
                                .flexible_integer => |flexible_integer_type| Type.Integer.getIndex(Compilation.Type.Integer{
                                    .bit_count = flexible_integer_type.byte_count << 3,
                                    .signedness = .unsigned,
                                }),
                                .type_index => |type_index| a: {
                                    const type_info = analyzer.module.types.array.get(type_index);
                                    break :a switch (type_info.*) {
                                        .integer => type_index,
                                        .optional => |optional_type| optional_type.element_type,
                                        else => |t| @panic(@tagName(t)),
                                    };
                                },
                                else => unreachable,
                            },
                            else => unreachable,
                        },
                        .signedness = .unsigned,
                    },
                },
                else => |t| @panic(@tagName(t)),
            },
            .call => .{
                .call = try analyzer.processCall(scope_index, node_index),
            },
            .field_access => blk: {
                logln(.sema, .node, "Field access", .{});
                const identifier = analyzer.tokenIdentifier(scope_index, node.right.value);
                const identifier_hash = try analyzer.processIdentifier(identifier);
                logln(.sema, .node, "Field access identifier for RHS: \"{s}\"", .{identifier});
                // analyzer.debugNode(scope_index, node_index);
                const left_value_index = try analyzer.unresolvedAllocate(scope_index, ExpectType.none, node.left);

                switch (analyzer.module.values.array.get(left_value_index).*) {
                    .type => |type_index| {
                        if (!type_index.invalid) {
                            const left_type = analyzer.module.types.array.get(type_index);
                            switch (left_type.*) {
                                .@"struct" => |struct_index| {
                                    const struct_type = analyzer.module.types.structs.get(struct_index);
                                    const right_index = try analyzer.doIdentifier(struct_type.scope, ExpectType.none, node.right.value, scope_index);
                                    const right_value = analyzer.module.values.array.get(right_index);

                                    break :blk right_value.*;
                                },
                                .@"enum" => |enum_index| {
                                    const enum_type = analyzer.module.types.enums.get(enum_index);

                                    const result = for (enum_type.fields.items) |enum_field_index| {
                                        const enum_field = analyzer.module.types.enum_fields.get(enum_field_index);
                                        if (enum_field.name == identifier_hash) {
                                            break enum_field_index;
                                        }
                                    } else {
                                        const right_index = try analyzer.doIdentifier(enum_type.scope, ExpectType.none, node.right.value, scope_index);
                                        const right_value = analyzer.module.values.array.get(right_index);

                                        switch (right_value.*) {
                                            .function_definition,
                                            .type,
                                            .enum_field,
                                            .declaration_reference,
                                            .integer,
                                            => break :blk right_value.*,
                                            else => |t| @panic(@tagName(t)),
                                        }

                                        logln(.sema, .node, "Right: {}", .{right_value});
                                        // struct_scope.declarations.get(identifier);

                                        unreachable;
                                    };

                                    const enum_field = analyzer.module.types.enum_fields.get(result);
                                    const enum_field_name = analyzer.module.getName(enum_field.name).?;
                                    logln(.sema, .node, "Enum field name resolution: {s}", .{enum_field_name});
                                    break :blk Value{
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
                    .enum_field => |enum_field_index| {
                        const enum_field = analyzer.module.types.enum_fields.get(enum_field_index);
                        const enum_field_name = analyzer.module.getName(enum_field.name).?;
                        std.debug.panic("LEFT: enum {s}. RIGHT: {s}", .{ enum_field_name, identifier });
                    },
                    .declaration_reference => |declaration_reference| {
                        const declaration_type = analyzer.module.types.array.get(declaration_reference.getType(analyzer.module));

                        switch (declaration_type.*) {
                            .@"struct" => |struct_index| {
                                const struct_type = analyzer.module.types.structs.get(struct_index);
                                for (struct_type.fields.items) |struct_field_index| {
                                    const struct_field = analyzer.module.types.container_fields.get(struct_field_index);
                                    if (struct_field.name == identifier_hash) {
                                        const field_access_index = try analyzer.module.values.field_accesses.append(analyzer.allocator, .{
                                            .declaration_reference = left_value_index,
                                            .field = struct_field_index,
                                        });
                                        break :blk Value{
                                            .field_access = field_access_index,
                                        };
                                    }
                                } else {
                                    const declaration_value = try analyzer.doIdentifier(struct_type.scope, ExpectType.none, node.right.value, scope_index);
                                    const value_ref = analyzer.module.values.array.get(declaration_value);
                                    break :blk value_ref.*;
                                }
                            },
                            .pointer => |pointer| {
                                const pointer_element_type = analyzer.module.types.array.get(pointer.element_type);
                                switch (pointer_element_type.*) {
                                    .@"struct" => |struct_index| {
                                        const struct_type = analyzer.module.types.structs.get(struct_index);
                                        for (struct_type.fields.items) |struct_field_index| {
                                            const struct_field = analyzer.module.types.container_fields.get(struct_field_index);
                                            if (struct_field.name == identifier_hash) {
                                                const field_access_index = try analyzer.module.values.field_accesses.append(analyzer.allocator, .{
                                                    .declaration_reference = left_value_index,
                                                    .field = struct_field_index,
                                                });

                                                break :blk Value{
                                                    .field_access = field_access_index,
                                                };
                                            }
                                        } else {
                                            const declaration_value = try analyzer.doIdentifier(struct_type.scope, ExpectType.none, node.right.value, scope_index);
                                            const value_ref = analyzer.module.values.array.get(declaration_value);
                                            break :blk value_ref.*;
                                        }
                                    },
                                    else => |t| @panic(@tagName(t)),
                                }

                                unreachable;
                            },
                            .slice => {
                                const slice_field = inline for (@typeInfo(Slice.Field).Enum.fields) |slice_field| {
                                    if (equal(u8, slice_field.name, identifier)) {
                                        break @field(Slice.Field, slice_field.name);
                                    }
                                } else unreachable;
                                const slice_access_type = switch (slice_field) {
                                    .ptr => t: {
                                        const slice_type_index = analyzer.getValueType(left_value_index);
                                        const slice_type = analyzer.module.types.array.get(slice_type_index);
                                        const slice_type_slice = slice_type.slice;
                                        const pointer_type = try analyzer.getPointerType(.{
                                            .element_type = slice_type_slice.element_type,
                                            .@"const" = slice_type_slice.@"const",
                                            .many = true,
                                            .termination = slice_type_slice.termination,
                                        });
                                        break :t pointer_type;
                                    },
                                    .len => Type.usize,
                                };

                                const field_access_index = try analyzer.module.values.slice_accesses.append(analyzer.allocator, .{
                                    .value = left_value_index,
                                    .field = slice_field,
                                    .type = slice_access_type,
                                });

                                break :blk Value{
                                    .slice_access = field_access_index,
                                };
                            },
                            .array => |array| break :blk Value{
                                .integer = .{
                                    .value = array.element_count,
                                    .type = expect_type.type_index,
                                    .signedness = .unsigned,
                                },
                            },
                            else => |t| @panic(@tagName(t)),
                        }

                        unreachable;
                    },
                    .field_access => |field_access| {
                        const left_field_access = analyzer.module.values.field_accesses.get(field_access);
                        const left_field = analyzer.module.types.container_fields.get(left_field_access.field);
                        const left_field_type = analyzer.module.types.array.get(left_field.type);

                        switch (left_field_type.*) {
                            .@"struct" => |struct_index| {
                                const struct_type = analyzer.module.types.structs.get(struct_index);

                                for (struct_type.fields.items) |struct_field_index| {
                                    const struct_field = analyzer.module.types.container_fields.get(struct_field_index);
                                    if (struct_field.name == identifier_hash) {
                                        const field_access_index = try analyzer.module.values.field_accesses.append(analyzer.allocator, .{
                                            .declaration_reference = left_value_index,
                                            .field = struct_field_index,
                                        });
                                        break :blk Value{
                                            .field_access = field_access_index,
                                        };
                                    }
                                } else {
                                    const scope1 = struct_type.scope;
                                    const scope2 = scope_index;
                                    const declaration_value = try analyzer.doIdentifier(scope1, ExpectType.none, node.right.value, scope2);

                                    const value_ref = analyzer.module.values.array.get(declaration_value);
                                    break :blk value_ref.*;
                                }

                                unreachable;
                            },
                            .slice => |slice| {
                                _ = slice;
                                const slice_field = inline for (@typeInfo(Slice.Field).Enum.fields) |slice_field| {
                                    if (equal(u8, slice_field.name, identifier)) {
                                        break @field(Slice.Field, slice_field.name);
                                    }
                                } else unreachable;

                                const slice_access_type = switch (slice_field) {
                                    .ptr => t: {
                                        const slice_type_index = analyzer.getValueType(left_value_index);
                                        const slice_type = analyzer.module.types.array.get(slice_type_index);
                                        const slice_type_slice = slice_type.slice;
                                        const pointer_type = try analyzer.getPointerType(.{
                                            .element_type = slice_type_slice.element_type,
                                            .@"const" = slice_type_slice.@"const",
                                            .many = true,
                                            .termination = slice_type_slice.termination,
                                        });
                                        break :t pointer_type;
                                    },
                                    .len => Type.usize,
                                };

                                const field_access_index = try analyzer.module.values.slice_accesses.append(analyzer.allocator, .{
                                    .value = left_value_index,
                                    .field = slice_field,
                                    .type = slice_access_type,
                                });

                                break :blk Value{
                                    .slice_access = field_access_index,
                                };
                            },
                            else => |t| @panic(@tagName(t)),
                        }
                        unreachable;
                    },
                    .call => |call_index| {
                        const call = analyzer.module.values.calls.get(call_index);
                        switch (analyzer.module.types.array.get(call.type).*) {
                            .@"struct" => |struct_index| {
                                const struct_type = analyzer.module.types.structs.get(struct_index);

                                for (struct_type.fields.items) |struct_field_index| {
                                    const struct_field = analyzer.module.types.container_fields.get(struct_field_index);
                                    if (struct_field.name == identifier_hash) {
                                        const field_access_index = try analyzer.module.values.field_accesses.append(analyzer.allocator, .{
                                            .declaration_reference = left_value_index,
                                            .field = struct_field_index,
                                        });
                                        break :blk Value{
                                            .field_access = field_access_index,
                                        };
                                    }
                                } else {
                                    const scope1 = struct_type.scope;
                                    const scope2 = scope_index;
                                    const declaration_value = try analyzer.doIdentifier(scope1, ExpectType.none, node.right.value, scope2);

                                    const value_ref = analyzer.module.values.array.get(declaration_value);
                                    break :blk value_ref.*;
                                }

                                unreachable;
                            },
                            else => |t| @panic(@tagName(t)),
                        }
                        unreachable;
                    },
                    .indexed_access => |indexed_access_index| {
                        const indexed_access = analyzer.module.values.indexed_accesses.get(indexed_access_index);
                        const indexed_expression_value = analyzer.module.values.array.get(indexed_access.indexed_expression);
                        const indexed_expression_type = analyzer.module.types.array.get(indexed_expression_value.getType(analyzer.module));

                        const element_type_index = switch (indexed_expression_type.*) {
                            .array => |array_type| array_type.element_type,
                            else => |t| @panic(@tagName(t)),
                        };

                        switch (analyzer.module.types.array.get(element_type_index).*) {
                            .@"struct" => |struct_index| {
                                const struct_type = analyzer.module.types.structs.get(struct_index);

                                for (struct_type.fields.items) |struct_field_index| {
                                    const struct_field = analyzer.module.types.container_fields.get(struct_field_index);
                                    if (struct_field.name == identifier_hash) {
                                        const field_access_index = try analyzer.module.values.field_accesses.append(analyzer.allocator, .{
                                            .declaration_reference = left_value_index,
                                            .field = struct_field_index,
                                        });
                                        break :blk Value{
                                            .field_access = field_access_index,
                                        };
                                    }
                                } else {
                                    const scope1 = struct_type.scope;
                                    const scope2 = scope_index;
                                    const declaration_value = try analyzer.doIdentifier(scope1, ExpectType.none, node.right.value, scope2);

                                    const value_ref = analyzer.module.values.array.get(declaration_value);
                                    break :blk value_ref.*;
                                }

                                unreachable;
                            },
                            else => |t| @panic(@tagName(t)),
                        }

                        unreachable;
                    },
                    else => |t| @panic(@tagName(t)),
                }
            },
            .string_literal => .{
                .string_literal = try analyzer.processStringLiteral(scope_index, node_index),
            },
            .@"switch" => try analyzer.processSwitch(scope_index, expect_type, node_index),
            .enum_type => blk: {
                const list_node = analyzer.getScopeNode(scope_index, node.left);
                const field_node_list = switch (list_node.id) {
                    .node_list => analyzer.getScopeNodeList(scope_index, list_node),
                    else => |t| @panic(@tagName(t)),
                };
                const file = analyzer.module.values.scopes.get(scope_index).file;
                const enum_type = try analyzer.processContainerType(value_index, scope_index, field_node_list.items, file, node_index, .@"enum");
                break :blk .{
                    .type = enum_type,
                };
            },
            .assign => try analyzer.processAssignment(scope_index, node_index),
            .signed_integer_type, .unsigned_integer_type => .{
                .type = try analyzer.resolveType(.{
                    .scope_index = scope_index,
                    .node_index = node_index,
                }),
            },
            .@"return" => try analyzer.processReturn(scope_index, expect_type, node_index),
            .add,
            .sub,
            .bit_and,
            .bit_xor,
            .bit_or,
            .multiply,
            .divide,
            .shift_left,
            .shift_right,
            .compare_equal,
            .compare_greater_than,
            .compare_greater_or_equal,
            .compare_less_than,
            .compare_less_or_equal,
            .compare_not_equal,
            => try analyzer.processBinaryOperation(scope_index, expect_type, node_index),
            .expression_group => return try analyzer.resolveNode(value_index, scope_index, expect_type, node.left), //unreachable,
            .struct_type => blk: {
                const left_node = analyzer.getScopeNode(scope_index, node.left);
                const nodes = analyzer.getScopeNodeList(scope_index, left_node);
                const scope = analyzer.module.values.scopes.get(scope_index);
                const struct_type = try analyzer.processContainerType(value_index, scope_index, nodes.items, scope.file, node_index, .@"struct");
                break :blk .{
                    .type = struct_type,
                };
            },
            .boolean_not => blk: {
                const typecheck_result = try analyzer.typeCheck(expect_type, Type.boolean);
                assert(typecheck_result == .success);
                const not_value_index = try analyzer.unresolvedAllocate(scope_index, ExpectType.boolean, node.left);
                const unary_index = try analyzer.module.values.unary_operations.append(analyzer.allocator, .{
                    .id = .boolean_not,
                    .value = not_value_index,
                    .type = Type.boolean,
                });

                break :blk .{
                    .unary_operation = unary_index,
                };
            },
            .null_literal => switch (expect_type) {
                .type_index => |type_index| switch (analyzer.module.types.array.get(type_index).*) {
                    .optional => |optional| switch (analyzer.module.types.array.get(optional.element_type).*) {
                        .pointer => Value.pointer_null_literal,
                        else => Value.optional_null_literal,
                    },
                    else => |t| @panic(@tagName(t)),
                },
                else => |t| @panic(@tagName(t)),
            },
            .negation => blk: {
                const negation_value_index = try analyzer.unresolvedAllocate(scope_index, expect_type, node.left);
                const unary_index = try analyzer.module.values.unary_operations.append(analyzer.allocator, .{
                    .id = .negation,
                    .value = negation_value_index,
                    .type = analyzer.getValueType(negation_value_index),
                });

                break :blk .{
                    .unary_operation = unary_index,
                };
            },
            .address_of => try analyzer.addressOf(scope_index, expect_type, node_index),
            .pointer_dereference => blk: {
                const new_expect_type = switch (expect_type) {
                    .none => expect_type,
                    .type_index => |type_index| ExpectType{
                        .type_index = try analyzer.getPointerType(.{
                            .element_type = type_index,
                            .@"const" = true, // TODO
                            .many = false, // TODO
                            .termination = .none, // TODO
                        }),
                    },
                    .flexible_integer => unreachable,
                    else => unreachable,
                };
                const pointer_value_index = try analyzer.unresolvedAllocate(scope_index, new_expect_type, node.left);
                const pointer_type = analyzer.module.types.array.get(analyzer.getValueType(pointer_value_index));
                assert(pointer_type.* == .pointer);
                const element_type = pointer_type.pointer.element_type;
                const unary_index = try analyzer.module.values.unary_operations.append(analyzer.allocator, .{
                    .id = .pointer_dereference,
                    .value = pointer_value_index,
                    .type = element_type,
                });

                break :blk .{
                    .unary_operation = unary_index,
                };
            },
            .slice => blk: {
                const expression_to_slice_index = try analyzer.unresolvedAllocate(scope_index, ExpectType.none, node.left);
                const expression_to_slice_type = analyzer.getValueType(expression_to_slice_index);

                const slice_index = try analyzer.module.values.slices.append(analyzer.allocator, .{
                    .sliceable = expression_to_slice_index,
                    .range = try analyzer.range(scope_index, node.right),
                    .type = try analyzer.getSliceType(switch (analyzer.module.types.array.get(expression_to_slice_type).*) {
                        .pointer => |pointer| .{
                            .@"const" = constblk: {
                                assert(pointer.many);
                                break :constblk pointer.@"const";
                            },
                            .element_type = pointer.element_type,
                            .termination = pointer.termination,
                        },
                        .slice => |slice| slice,
                        .array => |array| b: {
                            const is_const = switch (expect_type) {
                                .type_index => |type_index| switch (analyzer.module.types.array.get(type_index).*) {
                                    .slice => |slice| slice.@"const",
                                    else => |t| @panic(@tagName(t)),
                                },
                                else => |t| @panic(@tagName(t)),
                            };

                            break :b .{
                                .@"const" = is_const,
                                .element_type = array.element_type,
                                .termination = array.termination,
                            };
                        },
                        else => |t| @panic(@tagName(t)),
                    }),
                });

                break :blk .{
                    .slice = slice_index,
                };
            },
            .indexed_access => blk: {
                const indexable_expression_index = try analyzer.unresolvedAllocate(scope_index, ExpectType.none, node.left);
                // const indexable_expression_type = switch (analyzer.module.values.array.get(indexable_expression_index).*) {
                //     .declaration_reference => |declaration_reference| declaration_reference.type,
                //     else => |t| @panic(@tagName(t)),
                // };
                const indexable_expression_type = analyzer.getValueType(indexable_expression_index);
                switch (analyzer.module.types.array.get(indexable_expression_type).*) {
                    .slice => {},
                    .array => {},
                    .pointer => |pointer| {
                        switch (pointer.many) {
                            true => {},
                            false => unreachable, // TODO: pointer to array?
                        }
                    },
                    else => |t| @panic(@tagName(t)),
                }
                const index_expression_index = try analyzer.unresolvedAllocate(scope_index, ExpectType{
                    .type_index = Type.usize,
                }, node.right);

                const indexed_access_index = try analyzer.module.values.indexed_accesses.append(analyzer.allocator, .{
                    .indexed_expression = indexable_expression_index,
                    .index_expression = index_expression_index,
                });

                break :blk .{
                    .indexed_access = indexed_access_index,
                };
            },
            .enum_literal => blk: {
                const enum_literal_identifier_token = node.token + 1;
                switch (expect_type) {
                    .type_index => |type_index| {
                        switch (analyzer.module.types.array.get(type_index).*) {
                            .@"enum" => |enum_index| {
                                const enum_type = analyzer.module.types.enums.get(enum_index).*;
                                const enum_field_index = try analyzer.typeCheckEnumLiteral(scope_index, enum_literal_identifier_token, enum_type) orelse unreachable;

                                break :blk .{
                                    .enum_field = enum_field_index,
                                };
                            },
                            else => |t| @panic(@tagName(t)),
                        }
                    },
                    else => |t| @panic(@tagName(t)),
                }
            },
            .undefined => .undefined,
            .empty_container_literal_guess, .container_literal => blk: {
                const list_nodes = analyzer.getScopeNodeList(scope_index, analyzer.getScopeNode(scope_index, node.right));
                const literal_type = try analyzer.resolveType(.{
                    .scope_index = scope_index,
                    .node_index = node.left,
                    .length_hint = list_nodes.items.len,
                });
                const container_initialization = try analyzer.analyzeContainerLiteral(scope_index, literal_type, node.right);
                break :blk .{
                    .container_initialization = container_initialization,
                };
            },
            .anonymous_container_literal => blk: {
                const t = switch (expect_type) {
                    .type_index => |type_index| type_index,
                    .addressable => |addressable| addressable.element_type,
                    .none => Type.Index.invalid,
                    else => |t| @panic(@tagName(t)),
                };
                analyzer.debugNode(scope_index, node_index);
                const container_initialization = try analyzer.analyzeContainerLiteral(scope_index, t, node.right);
                break :blk .{
                    .container_initialization = container_initialization,
                };
            },
            .array_literal => blk: {
                const list_nodes = analyzer.getScopeNodeList(scope_index, analyzer.getScopeNode(scope_index, node.right));
                const literal_type = try analyzer.resolveType(.{
                    .scope_index = scope_index,
                    .node_index = node.left,
                    .length_hint = list_nodes.items.len,
                });

                const array_initialization = try analyzer.analyzeArrayLiteral(scope_index, node.right, switch (analyzer.module.types.array.get(literal_type).*) {
                    .array => |array| .{
                        .element_type = array.element_type,
                        .len = array.element_count,
                        .termination = array.termination,
                    },
                    else => |t| @panic(@tagName(t)),
                });

                break :blk .{
                    .array_initialization = array_initialization,
                };
            },
            .anonymous_array_literal => blk: {
                const expected_array_type = switch (expect_type) {
                    .addressable => |addressable| addr: {
                        assert(addressable.many);
                        break :addr .{
                            .element_type = addressable.element_type,
                            .termination = addressable.termination,
                        };
                    },
                    .type_index => |type_index| switch (analyzer.module.types.array.get(type_index).*) {
                        .array => |array_type| .{
                            .element_type = array_type.element_type,
                            .termination = array_type.termination,
                        },
                        else => |t| @panic(@tagName(t)),
                    },
                    else => |t| @panic(@tagName(t)),
                };

                const array_initialization = try analyzer.analyzeArrayLiteral(scope_index, node.right, expected_array_type);
                break :blk .{
                    .array_initialization = array_initialization,
                };
            },
            .optional_unwrap => blk: {
                const optional_expect_type = ExpectType{
                    .type_index = try analyzer.getOptionalType(switch (expect_type) {
                        .type_index => |type_index| type_index,
                        else => |t| @panic(@tagName(t)),
                    }),
                };

                const optional_value = try analyzer.unresolvedAllocate(scope_index, optional_expect_type, node.left);

                const optional_unwrap = try analyzer.module.values.optional_unwraps.append(analyzer.allocator, .{
                    .value = optional_value,
                });

                const optional_unwrap_value = Value{
                    .optional_unwrap = optional_unwrap,
                };
                break :blk optional_unwrap_value;
            },
            .anonymous_empty_literal => blk: {
                const expected_type_index = switch (expect_type) {
                    .type_index => |type_index| type_index,
                    else => |t| @panic(@tagName(t)),
                };
                switch (analyzer.module.types.array.get(expected_type_index).*) {
                    .@"struct" => |struct_index| {
                        const struct_type = analyzer.module.types.structs.get(struct_index);
                        var list = try ArrayList(Value.Index).initCapacity(analyzer.allocator, struct_type.fields.items.len);
                        for (struct_type.fields.items) |struct_field_index| {
                            const struct_field = analyzer.module.types.container_fields.get(struct_field_index);

                            if (struct_field.default_value.invalid) {
                                unreachable;
                            }

                            logln(.sema, .type, "Field name: {s}", .{analyzer.module.getName(struct_field.name).?});

                            switch (analyzer.module.values.array.get(struct_field.default_value).*) {
                                .unresolved => |unresolved| {
                                    logln(.sema, .type, "IN node index: #{}", .{unresolved.node_index.uniqueInteger()});
                                    try analyzer.resolveNode(struct_field.default_value, struct_type.scope, ExpectType{
                                        .type_index = struct_field.type,
                                    }, unresolved.node_index);
                                },
                                else => {},
                            }

                            list.appendAssumeCapacity(struct_field.default_value);
                        }

                        const container_initialization_index = try analyzer.module.values.container_initializations.append(analyzer.allocator, .{
                            .field_initializations = list,
                            .type = expected_type_index,
                        });
                        break :blk Value{
                            .container_initialization = container_initialization_index,
                        };
                    },
                    else => |t| @panic(@tagName(t)),
                }
            },
            .usize_type => Value{
                .type = Type.usize,
            },
            .if_else => blk: {
                const if_else_node_index = node_index;
                const payload_node_index = Node.Index.invalid;
                switch (try analyzer.processIfElse(scope_index, expect_type, if_else_node_index, payload_node_index)) {
                    .if_else => |if_else_value| {
                        assert(if_else_value.maybe_payload_declaration_index == null);
                        break :blk .{
                            .branch = if_else_value.branch,
                        };
                    },
                    .expression => |expression_value_index| break :blk analyzer.module.values.array.get(expression_value_index).*,
                }
            },
            else => |t| @panic(@tagName(t)),
        };

        analyzer.module.values.array.get(value_index).* = new_value;
    }

    fn analyzeArrayLiteral(analyzer: *Analyzer, scope_index: Scope.Index, node_list_node_index: Node.Index, expected_array_type: ExpectedArrayType) !Compilation.ContainerInitialization.Index {
        const field_initialization_node_list = analyzer.getScopeNode(scope_index, node_list_node_index);
        const field_nodes = analyzer.getScopeNodeList(scope_index, field_initialization_node_list);
        assert(!expected_array_type.element_type.invalid);

        const found_element_count = field_nodes.items.len;
        const element_count = if (expected_array_type.len) |ec| if (ec == found_element_count) ec else @panic("Element count mismatch in array literal") else found_element_count;

        var list = try ArrayList(Value.Index).initCapacity(analyzer.allocator, element_count);
        const element_expect_type = ExpectType{
            .type_index = expected_array_type.element_type,
        };

        for (field_nodes.items) |element_node_index| {
            const array_element_value_index = try analyzer.unresolvedAllocate(scope_index, element_expect_type, element_node_index);
            list.appendAssumeCapacity(array_element_value_index);
            // const element_node = analyzer.getScopeNode(scope_index, element_node_index);
        }

        const container_initialization_index = try analyzer.module.values.container_initializations.append(analyzer.allocator, .{
            .field_initializations = list,
            .type = try analyzer.getArrayType(.{
                .element_count = @intCast(element_count),
                .element_type = expected_array_type.element_type,
                .termination = expected_array_type.termination,
            }),
        });

        return container_initialization_index;
    }

    fn analyzeContainerLiteral(analyzer: *Analyzer, scope_index: Scope.Index, expected_type_index: Type.Index, node_list_node_index: Node.Index) !Compilation.ContainerInitialization.Index {
        const field_initialization_node_list = analyzer.getScopeNode(scope_index, node_list_node_index);
        const field_nodes = analyzer.getScopeNodeList(scope_index, field_initialization_node_list);
        assert(!expected_type_index.invalid);
        const expected_type = analyzer.module.types.array.get(expected_type_index);

        switch (expected_type.*) {
            .@"struct" => |struct_index| {
                const struct_type = analyzer.module.types.structs.get(struct_index);

                var list = try ArrayList(Value.Index).initCapacity(analyzer.allocator, struct_type.fields.items.len);
                var bitset = try std.DynamicBitSetUnmanaged.initEmpty(analyzer.allocator, field_nodes.items.len);

                for (struct_type.fields.items) |struct_field_index| {
                    const struct_field = analyzer.module.types.container_fields.get(struct_field_index);
                    const struct_field_name = analyzer.module.getName(struct_field.name).?;
                    // logln(.sema, .type, "struct field name in container literal: {s}", .{struct_field_name});

                    var value_index = Value.Index.invalid;

                    for (field_nodes.items, 0..) |field_node_index, index| {
                        const field_node = analyzer.getScopeNode(scope_index, field_node_index);
                        assert(field_node.id == .container_field_initialization);
                        const identifier = analyzer.tokenIdentifier(scope_index, field_node.token + 1);
                        const identifier_index = try analyzer.processIdentifier(identifier);

                        if (struct_field.name == identifier_index) {
                            if (!value_index.invalid) {
                                @panic("Field initialized twice");
                            }

                            bitset.set(index);

                            value_index = try analyzer.unresolvedAllocate(scope_index, ExpectType{
                                .type_index = struct_field.type,
                            }, field_node.left);
                        }
                    }

                    if (value_index.invalid) {
                        if (!struct_field.default_value.invalid) {
                            switch (analyzer.module.values.array.get(struct_field.default_value).*) {
                                .unresolved => |unresolved| {
                                    logln(.sema, .type, "Node index: #{}", .{unresolved.node_index.uniqueInteger()});
                                    try analyzer.resolveNode(struct_field.default_value, struct_type.scope, ExpectType{
                                        .type_index = struct_field.type,
                                    }, unresolved.node_index);
                                },
                                else => {},
                            }

                            assert(analyzer.module.values.array.get(struct_field.default_value).* != .unresolved);

                            value_index = struct_field.default_value;
                        } else {
                            std.debug.panic("Field \"{s}\" forgotten in struct initialization", .{struct_field_name});
                        }
                    }

                    logln(.sema, .type, "struct field {s}, container field #{}", .{ struct_field_name, struct_field_index.uniqueInteger() });

                    list.appendAssumeCapacity(value_index);
                }

                if (bitset.count() != bitset.bit_length) {
                    @panic("Some field name in struct initialization is wrong");
                }

                const container_initialization_index = try analyzer.module.values.container_initializations.append(analyzer.allocator, .{
                    .field_initializations = list,
                    .type = expected_type_index,
                });
                return container_initialization_index;
            },
            .array => |array_type| {
                if (field_nodes.items.len != array_type.element_count) {
                    unreachable;
                }

                var list = try ArrayList(Value.Index).initCapacity(analyzer.allocator, array_type.element_count);

                const expect_type = ExpectType{
                    .type_index = array_type.element_type,
                };

                for (field_nodes.items) |array_element_node_index| {
                    const element_value_index = try analyzer.unresolvedAllocate(scope_index, expect_type, array_element_node_index);
                    list.appendAssumeCapacity(element_value_index);
                }

                const container_initialization_index = try analyzer.module.values.container_initializations.append(analyzer.allocator, .{
                    .field_initializations = list,
                    .type = expected_type_index,
                });
                return container_initialization_index;
            },
            .optional => |optional_type| {
                return try analyzer.analyzeContainerLiteral(scope_index, optional_type.element_type, node_list_node_index);
            },
            else => |t| @panic(@tagName(t)),
        }
    }

    fn debugNode(analyzer: *Analyzer, scope_index: Scope.Index, node_index: Node.Index) void {
        const node = analyzer.getScopeNode(scope_index, node_index);
        analyzer.debugToken(scope_index, node.token);
    }

    fn debugToken(analyzer: *Analyzer, scope_index: Scope.Index, token_index: Token.Index) void {
        const source_file = analyzer.getScopeSourceFile(scope_index);
        const token = analyzer.getScopeToken(scope_index, token_index);
        logln(.sema, .debug, "Debugging:\n\n```\n{s}\n```", .{source_file[token.start..]});
    }

    fn processStringLiteral(analyzer: *Analyzer, scope_index: Scope.Index, node_index: Node.Index) !StringLiteral {
        const string_literal_node = analyzer.getScopeNode(scope_index, node_index);
        assert(string_literal_node.id == .string_literal);
        const original_string_literal = analyzer.tokenStringLiteral(scope_index, string_literal_node.token);
        const fixed_string_literal = try fixupStringLiteral(analyzer.allocator, original_string_literal);
        const string_literal = switch (analyzer.module.descriptor.transpile_to_c) {
            true => original_string_literal,
            false => fixed_string_literal,
        };

        const len: u32 = @intCast(fixed_string_literal.len);
        const array_type_descriptor = Type.Array{
            .element_type = Type.u8,
            .element_count = len,
            .termination = .null,
        };
        const array_type = try analyzer.getArrayType(array_type_descriptor);

        const pointer_type = try analyzer.getPointerType(.{
            .many = true,
            .@"const" = true,
            .element_type = array_type,
            .termination = array_type_descriptor.termination,
        });

        const hash = try Module.addString(&analyzer.module.map.strings, analyzer.allocator, string_literal);

        return StringLiteral{
            .hash = hash,
            .type = pointer_type,
        };
    }

    fn fixupStringLiteral(allocator: Allocator, string_literal: []const u8) ![]const u8 {
        var result = try ArrayList(u8).initCapacity(allocator, string_literal.len);
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
        const function_prototype = analyzer.module.types.function_prototypes.get(function_prototype_index);
        return function_prototype.return_type;
    }

    fn resolveType(analyzer: *Analyzer, args: struct {
        scope_index: Scope.Index,
        node_index: Node.Index,
        length_hint: ?usize = null,
        allow_non_primitive_size: bool = false,
    }) anyerror!Type.Index {
        const scope_index = args.scope_index;
        const node_index = args.node_index;

        const type_node = analyzer.getScopeNode(scope_index, node_index);
        const type_index: Type.Index = switch (type_node.id) {
            .identifier => blk: {
                const resolved_value_index = try analyzer.doIdentifier(scope_index, ExpectType.type, type_node.token, scope_index);
                const resolved_value = analyzer.module.values.array.get(resolved_value_index);
                break :blk switch (resolved_value.*) {
                    .type => |type_index| type_index,
                    else => |t| @panic(@tagName(t)),
                };
            },
            .keyword_noreturn => Type.noreturn,
            inline .signed_integer_type, .unsigned_integer_type => |int_type_signedness| blk: {
                const bit_count: u16 = @intCast(type_node.left.value);
                break :blk switch (bit_count) {
                    inline 8, 16, 32, 64 => |hardware_bit_count| Type.Integer.getIndex(.{
                        .bit_count = hardware_bit_count,
                        .signedness = switch (int_type_signedness) {
                            .signed_integer_type => .signed,
                            .unsigned_integer_type => .unsigned,
                            else => @compileError("OOO"),
                        },
                    }),
                    else => switch (args.allow_non_primitive_size) {
                        true => b: {
                            const integer = .{
                                .bit_count = bit_count,
                                .signedness = switch (int_type_signedness) {
                                    .signed_integer_type => .signed,
                                    .unsigned_integer_type => .unsigned,
                                    else => @compileError("OOO"),
                                },
                            };
                            const gop = try analyzer.module.map.non_primitive_integer.getOrPut(analyzer.allocator, integer);

                            if (!gop.found_existing) {
                                const type_index = try analyzer.module.types.array.append(analyzer.allocator, .{
                                    .integer = integer,
                                });

                                gop.value_ptr.* = type_index;
                            }

                            const result = gop.value_ptr.*;
                            break :b result;
                        },
                        false => @panic("non primitive size not allowed"),
                    },
                };
            },
            .void_type => Type.void,
            .ssize_type => Type.ssize,
            .usize_type => Type.usize,
            .bool_type => Type.boolean,
            .simple_function_prototype => blk: {
                const function_prototype_index = try analyzer.module.types.function_prototypes.append(analyzer.allocator, try analyzer.processSimpleFunctionPrototype(scope_index, node_index));

                const function_type_index = try analyzer.module.types.array.append(analyzer.allocator, .{
                    .function = function_prototype_index,
                });
                break :blk function_type_index;
            },
            .field_access => blk: {
                const type_value_index = try analyzer.unresolvedAllocate(scope_index, ExpectType.none, node_index);
                const type_value_ptr = analyzer.module.values.array.get(type_value_index);
                assert(type_value_ptr.* == .type);
                break :blk type_value_ptr.type;
            },
            .optional_type => blk: {
                const element_type = try resolveType(analyzer, .{
                    .scope_index = scope_index,
                    .node_index = type_node.left,
                });

                break :blk try analyzer.getOptionalType(element_type);
            },
            .pointer_type => blk: {
                const list_node = analyzer.getScopeNode(scope_index, type_node.left);
                const node_list = analyzer.getScopeNodeList(scope_index, list_node);

                var is_const = false;
                var type_index = Type.Index.invalid;
                var termination = Termination.none;
                var many = false;

                for (node_list.items) |element_node_index| {
                    const element_node = analyzer.getScopeNode(scope_index, element_node_index);
                    switch (element_node.id) {
                        .simple_function_prototype,
                        .identifier,
                        .unsigned_integer_type,
                        .signed_integer_type,
                        .optional_type,
                        .array_type,
                        .usize_type,
                        .pointer_type,
                        => {
                            if (!type_index.invalid) {
                                unreachable;
                            }
                            type_index = try analyzer.resolveType(.{
                                .scope_index = scope_index,
                                .node_index = element_node_index,
                            });
                        },
                        .const_expression => is_const = true,
                        .many_pointer_expression => many = true,
                        .zero_terminated => {
                            assert(many);
                            assert(termination == .none);
                            termination = .zero;
                        },
                        .null_terminated => {
                            assert(many);
                            assert(termination == .none);
                            termination = .null;
                        },
                        else => |t| @panic(@tagName(t)),
                    }
                }

                assert(!type_index.invalid);

                break :blk try analyzer.getPointerType(.{
                    .@"const" = is_const,
                    .many = many,
                    .element_type = type_index,
                    .termination = termination,
                });
            },
            .slice_type => blk: {
                const list_node = analyzer.getScopeNode(scope_index, type_node.left);
                const node_list = analyzer.getScopeNodeList(scope_index, list_node);

                var is_const = false;
                var type_index = Type.Index.invalid;
                var termination = Termination.none;

                for (node_list.items) |element_node_index| {
                    const element_node = analyzer.getScopeNode(scope_index, element_node_index);
                    switch (element_node.id) {
                        .simple_function_prototype,
                        .identifier,
                        .unsigned_integer_type,
                        => {
                            if (!type_index.invalid) {
                                unreachable;
                            }
                            type_index = try analyzer.resolveType(.{
                                .scope_index = scope_index,
                                .node_index = element_node_index,
                            });
                        },
                        .const_expression => is_const = true,
                        .zero_terminated => {
                            if (termination != .none) {
                                unreachable;
                            }
                            termination = .zero;
                        },
                        else => |t| @panic(@tagName(t)),
                    }
                }

                assert(!type_index.invalid);

                break :blk try analyzer.getSliceType(.{
                    .@"const" = is_const,
                    .element_type = type_index,
                    .termination = termination,
                });
            },
            .array_type => blk: {
                const list_node = analyzer.getScopeNode(scope_index, type_node.left);
                const node_list = analyzer.getScopeNodeList(scope_index, list_node);

                var termination: ?Termination = null;
                var length_expression: ?usize = null;

                for (node_list.items[0 .. node_list.items.len - 1]) |element_node_index| {
                    const element_node = analyzer.getScopeNode(scope_index, element_node_index);
                    switch (element_node.id) {
                        .identifier,
                        .number_literal,
                        .add,
                        => {
                            if (length_expression != null) {
                                unreachable;
                            }

                            length_expression = analyzer.resolveInteger(scope_index, try analyzer.unresolvedAllocate(scope_index, ExpectType{
                                .type_index = Type.usize,
                            }, element_node_index));
                        },
                        .discard => {
                            const length = args.length_hint orelse unreachable;
                            length_expression = length;
                        },
                        .null_terminated => {
                            if (termination != null) {
                                unreachable;
                            }
                            termination = .null;
                        },
                        else => |t| @panic(@tagName(t)),
                    }
                }

                assert(length_expression != null);

                const type_index = try analyzer.resolveType(.{
                    .scope_index = scope_index,
                    .node_index = node_list.items[node_list.items.len - 1],
                });

                assert(!type_index.invalid);

                break :blk try analyzer.getArrayType(.{
                    .element_type = type_index,
                    .element_count = length_expression orelse unreachable,
                    .termination = termination orelse .none,
                });
            },
            else => |t| @panic(@tagName(t)),
        };
        return type_index;
    }

    fn processSimpleFunctionPrototype(analyzer: *Analyzer, old_scope_index: Scope.Index, simple_function_prototype_node_index: Node.Index) !Function.Prototype {
        const simple_function_prototype_node = analyzer.getScopeNode(old_scope_index, simple_function_prototype_node_index);
        assert(simple_function_prototype_node.id == .simple_function_prototype);
        const arguments_node_index = simple_function_prototype_node.left;
        const return_type_node_index = simple_function_prototype_node.right;

        const scope_index = try analyzer.module.values.scopes.append(analyzer.allocator, .{
            .parent = old_scope_index,
            .file = analyzer.module.values.scopes.get(old_scope_index).file,
            .token = simple_function_prototype_node.token,
        });

        var argument_declarations = ArrayList(Declaration.Index){};
        switch (arguments_node_index.invalid) {
            true => {},
            false => {
                const argument_list_node = analyzer.getScopeNode(scope_index, arguments_node_index);
                // logln("Function prototype argument list node: {}\n", .{function_prototype_node.left.uniqueInteger()});
                const argument_node_list = switch (argument_list_node.id) {
                    .node_list => analyzer.getScopeNodeList(scope_index, argument_list_node),
                    else => |t| @panic(@tagName(t)),
                };

                assert(argument_node_list.items.len > 0);
                if (argument_node_list.items.len > 0) {
                    argument_declarations = try ArrayList(Declaration.Index).initCapacity(analyzer.allocator, argument_node_list.items.len);

                    for (argument_node_list.items, 0..) |argument_node_index, index| {
                        const argument_node = analyzer.getScopeNode(scope_index, argument_node_index);
                        switch (argument_node.id) {
                            .argument_declaration => {
                                const argument_name = analyzer.tokenIdentifier(scope_index, argument_node.token);
                                const argument_type = try analyzer.resolveType(.{
                                    .scope_index = scope_index,
                                    .node_index = argument_node.left,
                                });
                                const argument_declaration_type = Declaration.Type{
                                    .resolved = argument_type,
                                };
                                const argument_declaration = try analyzer.declarationCommon(scope_index, .local, .@"const", argument_name, argument_declaration_type, Value.Index.invalid, @intCast(index));
                                argument_declarations.appendAssumeCapacity(argument_declaration);
                            },
                            else => |t| @panic(@tagName(t)),
                        }
                    }
                }
            },
        }

        const return_type = try analyzer.resolveType(.{
            .scope_index = scope_index,
            .node_index = return_type_node_index,
        });

        return .{
            .arguments = argument_declarations,
            .return_type = return_type,
            .scope = scope_index,
        };
    }

    fn functionPrototype(analyzer: *Analyzer, scope_index: Scope.Index, node_index: Node.Index) !Function.Prototype.Index {
        const function_prototype_node = analyzer.getScopeNode(scope_index, node_index);
        switch (function_prototype_node.id) {
            .simple_function_prototype => {
                const function_prototype_index = try analyzer.module.types.function_prototypes.append(analyzer.allocator, try analyzer.processSimpleFunctionPrototype(scope_index, node_index));

                return function_prototype_index;
            },
            .function_prototype => {
                var function_prototype = try analyzer.processSimpleFunctionPrototype(scope_index, function_prototype_node.left);
                const function_prototype_attribute_list_node = analyzer.getScopeNode(scope_index, function_prototype_node.right);
                const attribute_node_list = analyzer.getScopeNodeList(scope_index, function_prototype_attribute_list_node);
                var calling_convention: ?Compilation.CallingConvention = null;

                for (attribute_node_list.items) |attribute_node_index| {
                    const attribute_node = analyzer.getScopeNode(scope_index, attribute_node_index);

                    switch (attribute_node.id) {
                        .export_qualifier => function_prototype.attributes.@"export" = true,
                        .extern_qualifier => {
                            const string_literal_node = analyzer.getScopeNode(scope_index, attribute_node.left);
                            const original_string_literal = analyzer.tokenStringLiteral(scope_index, string_literal_node.token);
                            const fixed_string_literal = try fixupStringLiteral(analyzer.allocator, original_string_literal);
                            _ = try analyzer.module.map.libraries.getOrPut(analyzer.allocator, fixed_string_literal);
                            function_prototype.attributes.@"extern" = true;
                        },
                        .calling_convention => {
                            const calling_convention_type_declaration = try analyzer.forceDeclarationAnalysis(scope_index, "std.builtin.CallingConvention");
                            const calling_convention_type = switch (analyzer.module.values.array.get(calling_convention_type_declaration).*) {
                                .type => |type_index| type_index,
                                else => |t| @panic(@tagName(t)),
                            };
                            const cc_value = try analyzer.unresolvedAllocate(scope_index, ExpectType{
                                .type_index = calling_convention_type,
                            }, attribute_node.left);

                            switch (analyzer.module.values.array.get(cc_value).*) {
                                .enum_field => |enum_field_index| {
                                    const enum_field = analyzer.module.types.enum_fields.get(enum_field_index);
                                    const enum_field_name = analyzer.module.getName(enum_field.name).?;

                                    calling_convention = inline for (@typeInfo(Compilation.CallingConvention).Enum.fields) |cc_enum_field| {
                                        if (equal(u8, cc_enum_field.name, enum_field_name)) {
                                            break @field(Compilation.CallingConvention, cc_enum_field.name);
                                        }
                                    } else unreachable;
                                },
                                else => |t| @panic(@tagName(t)),
                            }
                        },
                        else => |t| @panic(@tagName(t)),
                    }
                }

                function_prototype.attributes.calling_convention = calling_convention orelse Compilation.CallingConvention.system_v;

                const function_prototype_index = try analyzer.module.types.function_prototypes.append(analyzer.allocator, function_prototype);
                return function_prototype_index;
            },
            else => |t| @panic(@tagName(t)),
        }
    }

    fn forceDeclarationAnalysis(analyzer: *Analyzer, scope_index: Scope.Index, whole_expression: []const u8) !Value.Index {
        var expression_iterator = std.mem.tokenizeScalar(u8, whole_expression, '.');
        var before_expression = Value.Index.invalid;
        var last_scope = scope_index;

        while (expression_iterator.next()) |expression_name| {
            const result = switch (before_expression.invalid) {
                true => try analyzer.doIdentifierString(scope_index, ExpectType.type, expression_name, scope_index),
                false => blk: {
                    const expression_name_hash = try analyzer.processIdentifier(expression_name);
                    switch (analyzer.module.values.array.get(before_expression).*) {
                        .type => |type_index| {
                            const expression_type = analyzer.module.types.array.get(type_index);
                            switch (expression_type.*) {
                                .@"struct" => |struct_index| {
                                    const struct_type = analyzer.module.types.structs.get(struct_index);
                                    const struct_type_scope = analyzer.module.values.scopes.get(struct_type.scope);
                                    const declaration_index = struct_type_scope.declarations.get(expression_name_hash).?;
                                    const declaration = analyzer.module.values.declarations.get(declaration_index);
                                    assert(declaration.name == expression_name_hash);
                                    last_scope = declaration.scope;

                                    break :blk declaration.init_value;
                                },
                                else => |t| @panic(@tagName(t)),
                            }
                        },
                        .unresolved => |unresolved| {
                            try analyzer.resolveNode(before_expression, last_scope, ExpectType.none, unresolved.node_index);
                            switch (analyzer.module.values.array.get(before_expression).*) {
                                .type => |type_index| {
                                    const expression_type = analyzer.module.types.array.get(type_index);
                                    switch (expression_type.*) {
                                        .@"struct" => |struct_index| {
                                            const struct_type = analyzer.module.types.structs.get(struct_index);
                                            const struct_type_scope = analyzer.module.values.scopes.get(struct_type.scope);
                                            const declaration_index = struct_type_scope.declarations.get(expression_name_hash).?;
                                            const declaration = analyzer.module.values.declarations.get(declaration_index);
                                            assert(declaration.name == expression_name_hash);
                                            last_scope = declaration.scope;

                                            break :blk declaration.init_value;
                                        },
                                        else => |t| @panic(@tagName(t)),
                                    }
                                },
                                else => |t| @panic(@tagName(t)),
                            }
                        },
                        else => |t| @panic(@tagName(t)),
                    }
                },
            };

            before_expression = result;
        }

        switch (analyzer.module.values.array.get(before_expression).*) {
            .unresolved => |unresolved| {
                try analyzer.resolveNode(before_expression, last_scope, ExpectType.none, unresolved.node_index);
            },
            else => {},
        }

        return before_expression;
    }

    fn processContainerType(analyzer: *Analyzer, value_index: Value.Index, parent_scope_index: Scope.Index, container_nodes: []const Node.Index, file_index: File.Index, container_node_index: Node.Index, comptime container_type: Compilation.ContainerType) !Type.Index {
        const container_node = analyzer.getFileNode(file_index, container_node_index);
        switch (container_type) {
            .@"struct" => assert(container_node.id == .struct_type),
            .@"enum" => assert(container_node.id == .enum_type),
        }
        const scope_index = try analyzer.module.values.scopes.append(analyzer.allocator, .{
            .parent = parent_scope_index,
            .file = file_index,
            .token = container_node.token,
        });
        logln(.sema, .type, "Creating container scope #{}. Parent: #{}", .{
            scope_index.uniqueInteger(), switch (parent_scope_index.invalid) {
                true => 0xffff_ffff,
                false => parent_scope_index.uniqueInteger(),
            },
        });
        const is_file = parent_scope_index.invalid;
        const backing_type = blk: {
            if (!is_file) {
                if (analyzer.getScopeToken(parent_scope_index, container_node.token + 1).id == .left_parenthesis) {
                    const backing_type_token = analyzer.getScopeToken(parent_scope_index, container_node.token + 2);
                    const source_file = analyzer.getScopeSourceFile(parent_scope_index);
                    const token_bytes = tokenBytes(backing_type_token, source_file);

                    break :blk switch (backing_type_token.id) {
                        .keyword_unsigned_integer => if (equal(u8, token_bytes, "u8")) Type.u8 else if (equal(u8, token_bytes, "u16")) Type.u16 else if (equal(u8, token_bytes, "u32")) Type.u32 else if (equal(u8, token_bytes, "u64")) Type.u64 else if (equal(u8, token_bytes, "usize")) Type.usize else unreachable,
                        .fixed_keyword_usize => Type.usize,
                        else => |t| @panic(@tagName(t)),
                    };
                }
            }

            break :blk Type.Index.invalid;
        };

        const container_descriptor = .{
            .scope = scope_index,
            .backing_type = backing_type,
        };
        const container_type_descriptor = switch (container_type) {
            .@"struct" => blk: {
                const struct_index = try analyzer.module.types.structs.append(analyzer.allocator, container_descriptor);
                break :blk Type{
                    .@"struct" = struct_index,
                };
            },
            .@"enum" => blk: {
                const enum_index = try analyzer.module.types.enums.append(analyzer.allocator, container_descriptor);
                break :blk Type{
                    .@"enum" = enum_index,
                };
            },
        };

        const container_type_index = try analyzer.module.types.array.append(analyzer.allocator, container_type_descriptor);
        if (is_file) {
            const file = analyzer.module.values.files.get(file_index);
            file.type = container_type_index;
        }

        analyzer.module.values.scopes.get(scope_index).type = container_type_index;
        analyzer.module.values.array.get(value_index).* = .{
            .type = container_type_index,
        };

        if (!analyzer.current_declaration.invalid) {
            const current_declaration = analyzer.module.values.declarations.get(analyzer.current_declaration);
            switch (current_declaration.type) {
                .inferred => |*inferred_type_index| {
                    assert(inferred_type_index.invalid);
                    inferred_type_index.* = Type.type;
                },
                else => |t| @panic(@tagName(t)),
            }
        }

        const count = blk: {
            var result: struct {
                fields: u32 = 0,
                declarations: u32 = 0,
            } = .{};

            for (container_nodes) |member_index| {
                const member = analyzer.getFileNode(file_index, member_index);
                switch (container_type) {
                    .@"struct" => assert(member.id != .enum_field),
                    .@"enum" => assert(member.id != .container_field),
                }
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

        for (container_nodes) |member_index| {
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

        if (field_nodes.items.len > 0) {
            // This is done in order for the names inside fields not to collision with the declaration ones
            const field_scope_index = try analyzer.module.values.scopes.append(analyzer.allocator, .{
                .token = analyzer.getScopeNode(scope_index, field_nodes.items[0]).token,
                .file = file_index,
                .parent = scope_index,
            });

            logln(.sema, .type, "Creating container field scope #{}. Parent: #{}", .{ field_scope_index.uniqueInteger(), scope_index.uniqueInteger() });

            switch (container_type) {
                .@"struct" => {
                    {
                        const struct_type_general = analyzer.module.types.array.get(container_type_index);
                        const struct_type = analyzer.module.types.structs.get(struct_type_general.@"struct");
                        struct_type.fields = try ArrayList(Compilation.ContainerField.Index).initCapacity(analyzer.allocator, field_nodes.items.len);
                    }

                    for (field_nodes.items) |field_index| {
                        const field_node = analyzer.getFileNode(file_index, field_index);
                        const identifier = analyzer.tokenIdentifier(field_scope_index, field_node.token);
                        const file_path = analyzer.module.values.files.get(file_index).relative_path;
                        logln(.sema, .type, "Field node index for '{s}' in file {s}", .{ identifier, file_path });
                        const identifier_index = try analyzer.processIdentifier(identifier);
                        const type_index = try analyzer.resolveType(.{
                            .scope_index = field_scope_index,
                            .node_index = field_node.left,
                            .allow_non_primitive_size = !backing_type.invalid,
                        });

                        const default_value = if (field_node.right.invalid) Value.Index.invalid else try analyzer.module.values.array.append(analyzer.allocator, .{
                            .unresolved = .{
                                .node_index = blk: {
                                    const def_node = analyzer.getScopeNode(scope_index, field_node.right);
                                    assert(def_node.id != .node_list);
                                    break :blk field_node.right;
                                },
                            },
                        });

                        const container_field_index = try analyzer.module.types.container_fields.append(analyzer.allocator, .{
                            .name = identifier_index,
                            .type = type_index,
                            .default_value = default_value,
                            .parent = container_type_index,
                        });

                        {
                            const struct_type_general = analyzer.module.types.array.get(container_type_index);
                            const struct_type = analyzer.module.types.structs.get(struct_type_general.@"struct");
                            struct_type.fields.appendAssumeCapacity(container_field_index);
                        }
                    }
                },
                .@"enum" => {
                    {
                        const enum_type_general = analyzer.module.types.array.get(container_type_index);
                        const enum_type = analyzer.module.types.enums.get(enum_type_general.@"enum");
                        enum_type.fields = try ArrayList(Compilation.Type.Enum.Field.Index).initCapacity(analyzer.allocator, field_nodes.items.len);
                    }

                    for (field_nodes.items) |field_node_index| {
                        const field_node = analyzer.getScopeNode(scope_index, field_node_index);
                        assert(field_node.id == .enum_field);

                        const identifier = analyzer.tokenIdentifier(scope_index, field_node.token);
                        logln(.sema, .node, "Enum field: {s}", .{identifier});
                        const enum_value = switch (field_node.left.invalid) {
                            false => try analyzer.unresolvedAllocate(scope_index, ExpectType{
                                .type_index = Type.usize,
                            }, field_node.left),
                            true => Value.Index.invalid,
                        };

                        const enum_hash_name = try analyzer.processIdentifier(identifier);

                        const enum_field_index = try analyzer.module.types.enum_fields.append(analyzer.allocator, .{
                            .name = enum_hash_name,
                            .value = enum_value,
                            .parent = container_type_index,
                        });

                        const enum_type_general = analyzer.module.types.array.get(container_type_index);
                        const enum_type = analyzer.module.types.enums.get(enum_type_general.@"enum");
                        enum_type.fields.appendAssumeCapacity(enum_field_index);
                    }
                },
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

        return container_type_index;
    }

    fn declarationCommon(analyzer: *Analyzer, scope_index: Scope.Index, scope_type: ScopeType, mutability: Compilation.Mutability, name: []const u8, declaration_type: Declaration.Type, init_value: Value.Index, argument_index: ?u32) !Declaration.Index {
        const identifier_index = try analyzer.processIdentifier(name);

        if (analyzer.lookupDeclarationInCurrentAndParentScopes(scope_index, identifier_index)) |lookup| {
            const declaration = analyzer.module.values.declarations.get(lookup.declaration);
            const declaration_name = analyzer.module.getName(declaration.name).?;
            panic("Existing name in lookup: {s}.\nSource scope: #{}. Lookup scope: #{}", .{ declaration_name, scope_index.uniqueInteger(), lookup.scope.uniqueInteger() });
        }

        // Check if the symbol name is already occupied in the same scope
        const scope = analyzer.module.values.scopes.get(scope_index);
        const declaration_index = try analyzer.module.values.declarations.append(analyzer.allocator, .{
            .name = identifier_index,
            .scope_type = scope_type,
            .mutability = mutability,
            .init_value = init_value,
            .type = declaration_type,
            .argument_index = argument_index,
            .scope = scope_index,
        });

        try scope.declarations.putNoClobber(analyzer.allocator, identifier_index, declaration_index);

        return declaration_index;
    }

    fn symbolDeclaration(analyzer: *Analyzer, scope_index: Scope.Index, node_index: Node.Index, scope_type: ScopeType) !Declaration.Index {
        const declaration_node = analyzer.getScopeNode(scope_index, node_index);
        assert(declaration_node.id == .simple_symbol_declaration);
        const expected_identifier_token_index = declaration_node.token + 1;
        const identifier = analyzer.tokenIdentifier(scope_index, expected_identifier_token_index);
        logln(.sema, .type, "Analyzing '{s}' declaration in {s} scope #{}", .{ identifier, @tagName(scope_type), scope_index.uniqueInteger() });

        const expect_type = switch (declaration_node.left.invalid) {
            false => switch (scope_type) {
                .local => ExpectType{
                    .type_index = try analyzer.resolveType(.{
                        .scope_index = scope_index,
                        .node_index = declaration_node.left,
                    }),
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
        const expected_identifier_token = analyzer.getScopeToken(scope_index, expected_identifier_token_index);
        if (expected_identifier_token.id != .identifier) {
            logln(.sema, .symbol_declaration, "Error: found: {}", .{expected_identifier_token.id});
            @panic("Expected identifier");
        }
        // TODO: Check if it is a keyword

        assert(!declaration_node.right.invalid);

        const argument = null;
        assert(argument == null);

        const init_value_index = switch (scope_type) {
            .local => try analyzer.unresolvedAllocate(scope_index, expect_type, declaration_node.right),
            .global => try analyzer.module.values.array.append(analyzer.allocator, .{
                .unresolved = .{
                    .node_index = declaration_node.right,
                },
            }),
        };

        assert(argument == null);
        const declaration_type: Declaration.Type = switch (declaration_node.left.invalid) {
            false => switch (scope_type) {
                .local => .{
                    .resolved = expect_type.type_index,
                },
                .global => .{
                    .unresolved = declaration_node.left,
                },
            },
            true => switch (scope_type) {
                .local => .{
                    .inferred = switch (expect_type) {
                        .none => analyzer.module.values.array.get(init_value_index).getType(analyzer.module),
                        .type_index => |type_index| type_index,
                        else => |t| @panic(@tagName(t)),
                    },
                },
                .global => .{
                    .inferred = Type.Index.invalid,
                },
            },
        };

        const result = try analyzer.declarationCommon(scope_index, scope_type, mutability, identifier, declaration_type, init_value_index, argument);

        return result;
    }

    const MemberType = enum {
        declaration,
        field,
    };

    fn getContainerMemberType(member_id: Node.Id) MemberType {
        return switch (member_id) {
            .@"comptime",
            .simple_symbol_declaration,
            => .declaration,
            .enum_field,
            .container_field,
            => .field,
            else => |t| @panic(@tagName(t)),
        };
    }

    fn processIdentifier(analyzer: *Analyzer, string: []const u8) !u32 {
        return analyzer.module.addName(analyzer.allocator, string);
    }

    fn tokenIdentifier(analyzer: *Analyzer, scope_index: Scope.Index, token_index: Token.Index) []const u8 {
        const token = analyzer.getScopeToken(scope_index, token_index);
        // logln(.sema, .identifier, "trying to get identifier from token of id {s}", .{@tagName(token.id)});
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

    const TypeCheckResult = enum {
        success,
        zero_extend,
        sign_extend,
        take_source,
        optional_wrap,
        array_coerce_to_slice,
    };

    fn canCast(analyzer: *Analyzer, expect_type: ExpectType, source: Type.Index) !TypeCheckResult {
        return switch (expect_type) {
            .none => unreachable,
            .flexible_integer => |flexible_integer| blk: {
                const source_type = analyzer.module.types.array.get(source);
                break :blk switch (source_type.*) {
                    .pointer => .success,
                    .optional => b: {
                        const optional_element_type = analyzer.module.types.array.get(source_type.optional.element_type);
                        break :b switch (optional_element_type.*) {
                            .pointer => .success,
                            else => |t| @panic(@tagName(t)),
                        };
                    },
                    .@"struct" => |struct_type_index| {
                        const struct_type = analyzer.module.types.structs.get(struct_type_index);
                        if (!struct_type.backing_type.invalid) {
                            const backing_integer_type = analyzer.module.types.array.get(struct_type.backing_type);
                            if (backing_integer_type.integer.bit_count >> 3 <= flexible_integer.byte_count) {
                                return .success;
                            } else {
                                unreachable;
                            }
                        }

                        unreachable;
                    },
                    .@"enum" => |enum_index| {
                        const enum_type = analyzer.module.types.enums.get(enum_index);
                        if (!enum_type.backing_type.invalid) {
                            const backing_integer_type = analyzer.module.types.array.get(enum_type.backing_type);
                            if (backing_integer_type.integer.bit_count >> 3 <= flexible_integer.byte_count) {
                                return .success;
                            } else {
                                unreachable;
                            }
                        } else {
                            unreachable;
                        }
                    },
                    // TODO: integer cast
                    .integer => return .success,
                    else => |t| @panic(@tagName(t)),
                };
            },
            .type_index => |type_index| blk: {
                if (source.eq(type_index)) {
                    // TODO: turn into a compiler error
                    return .success;
                } else {
                    const destination_type = analyzer.module.types.array.get(type_index);
                    const source_type = analyzer.module.types.array.get(source);

                    break :blk switch (source_type.*) {
                        .integer => |integer| switch (destination_type.*) {
                            .optional => |optional| switch (analyzer.module.types.array.get(optional.element_type).*) {
                                .pointer => if (integer.bit_count == 64) .success else unreachable,
                                .integer => .optional_wrap,
                                else => |t| @panic(@tagName(t)),
                            },
                            .integer => .success,
                            .pointer => .success,
                            else => |t| @panic(@tagName(t)),
                        },
                        .pointer => switch (destination_type.*) {
                            .optional => |destination_optional| switch (analyzer.module.types.array.get(destination_optional.element_type).*) {
                                .pointer => .success,
                                else => |t| @panic(@tagName(t)),
                            },
                            else => .success,
                        },
                        .@"enum" => |enum_type_descriptor| switch (destination_type.*) {
                            .integer => |integer| {
                                _ = integer;
                                const enum_type = analyzer.module.types.enums.get(enum_type_descriptor);
                                if (!enum_type.backing_type.invalid) {
                                    if (enum_type.backing_type.eq(type_index)) {
                                        return .success;
                                    } else {
                                        unreachable;
                                    }
                                } else {
                                    return .success;
                                }
                            },
                            else => |t| @panic(@tagName(t)),
                        },
                        .slice => switch (destination_type.*) {
                            else => |t| @panic(@tagName(t)),
                        },
                        else => |t| @panic(@tagName(t)),
                    };
                }
            },
            else => unreachable,
        };
    }

    fn typeCheck(analyzer: *Analyzer, expect_type: ExpectType, source: Type.Index) !TypeCheckResult {
        return switch (expect_type) {
            .none => TypeCheckResult.success,
            .type_index => |expected_type_index| {
                if (expected_type_index.eq(source)) {
                    return TypeCheckResult.success;
                }

                const destination_type = analyzer.module.types.array.get(expected_type_index);
                const source_type = analyzer.module.types.array.get(source);

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
                        .@"struct" => @panic("Expected int, have struct"),
                        .array => @panic("Expected int, have array"),
                        else => |t| @panic(@tagName(t)),
                    },
                    // TODO: type safety
                    .pointer => |destination_pointer| switch (source_type.*) {
                        .pointer => |source_pointer| {
                            if (source_pointer.many == destination_pointer.many) {
                                if (source_pointer.element_type.eq(destination_pointer.element_type)) {
                                    return .success;
                                } else {
                                    switch (analyzer.module.types.array.get(source_pointer.element_type).*) {
                                        .array => |array| {
                                            if (array.element_type.eq(destination_pointer.element_type)) {
                                                return .success;
                                            } else {
                                                unreachable;
                                            }
                                        },
                                        .optional => |source_optional| switch (analyzer.module.types.array.get(destination_pointer.element_type).*) {
                                            .optional => |destination_optional| {
                                                if (destination_optional.element_type.eq(source_optional.element_type)) {
                                                    return .success;
                                                } else {
                                                    unreachable;
                                                }
                                            },
                                            else => |t| @panic(@tagName(t)),
                                        },
                                        .@"struct" => {
                                            logln(.sema, .type, "Expected pointer to #{}, got pointer to #{} (pointer to struct)", .{ destination_pointer.element_type.uniqueInteger(), source_pointer.element_type.uniqueInteger() });
                                            unreachable;
                                        },
                                        else => |t| @panic(@tagName(t)),
                                    }
                                }
                            } else {
                                unreachable;
                            }
                        },
                        .@"struct" => |struct_index| {
                            _ = struct_index;

                            @panic("expected pointer, found struct");
                        },
                        else => |t| @panic(@tagName(t)),
                    },
                    .bool => switch (source_type.*) {
                        else => |t| @panic(@tagName(t)),
                    },
                    .optional => |destination_optional| switch (source_type.*) {
                        .optional => |source_optional| {
                            if (expected_type_index.eq(optional_any)) {
                                return .take_source;
                            } else {
                                if (destination_optional.element_type.eq(source_optional.element_type)) {
                                    return .success;
                                } else {
                                    const destination_optional_element_type = analyzer.module.types.array.get(destination_optional.element_type);
                                    const source_optional_element_type = analyzer.module.types.array.get(source_optional.element_type);

                                    switch (destination_optional_element_type.*) {
                                        .pointer => |destination_pointer| switch (source_optional_element_type.*) {
                                            .pointer => |source_pointer| {
                                                if (source.eq(optional_pointer_to_any_type)) {
                                                    return .success;
                                                }

                                                if (expected_type_index.eq(optional_pointer_to_any_type)) {
                                                    return .take_source;
                                                }

                                                if (destination_pointer.many == source_pointer.many) {
                                                    if (destination_pointer.@"const" == source_pointer.@"const") {
                                                        if (destination_pointer.element_type.eq(source_pointer.element_type)) {
                                                            return .success;
                                                        }
                                                    }
                                                }

                                                unreachable;
                                            },
                                            .slice => |source_slice| {
                                                _ = source_slice;

                                                unreachable;
                                                // _ = source_slice;
                                                // if (source.eq(optional_any) or expected_type_index.eq(optional_pointer_to_any_type)) {
                                                //     return .success;
                                                // }
                                            },
                                            else => |t| @panic(@tagName(t)),
                                        },
                                        .slice => |destination_slice| switch (source_optional_element_type.*) {
                                            .slice => |source_slice| {
                                                if (destination_slice.element_type.eq(source_slice.element_type)) {
                                                    return .success;
                                                } else {
                                                    unreachable;
                                                }
                                            },
                                            else => |t| @panic(@tagName(t)),
                                        },
                                        else => |t| @panic(@tagName(t)),
                                    }
                                }
                            }
                        },
                        .pointer => |source_pointer| {
                            if (destination_optional.element_type.eq(source)) {
                                return .optional_wrap;
                            } else {
                                const destination_optional_element_type = analyzer.module.types.array.get(destination_optional.element_type);

                                switch (destination_optional_element_type.*) {
                                    .pointer => |destination_pointer| {
                                        if (source.eq(optional_pointer_to_any_type)) {
                                            return .optional_wrap;
                                        }

                                        if (expected_type_index.eq(optional_pointer_to_any_type)) {
                                            return .optional_wrap;
                                        }

                                        if (destination_pointer.many == source_pointer.many) {
                                            if (destination_pointer.@"const" or destination_pointer.@"const" == source_pointer.@"const") {
                                                if (destination_pointer.element_type.eq(source_pointer.element_type)) {
                                                    return .optional_wrap;
                                                }
                                            }
                                        }

                                        std.debug.panic("Destination: {}. Source: {}", .{ destination_pointer, source_pointer });
                                    },
                                    .slice => |destination_slice| {
                                        _ = destination_slice;

                                        // if (destination_slice.element_type.eq(source_slice.element_type)) {
                                        //     return .success;
                                        // } else {
                                        unreachable;
                                        // }
                                    },
                                    else => |t| @panic(@tagName(t)),
                                }
                                unreachable;
                            }
                        },
                        // TODO
                        .integer => if (destination_optional.element_type.eq(source)) {
                            return .optional_wrap;
                        } else {
                            logln(.sema, .type, "Destination optional element type: #{}. Source: #{}", .{ destination_optional.element_type.uniqueInteger(), source.uniqueInteger() });
                            unreachable;
                        },
                        .slice => |source_slice| if (destination_optional.element_type.eq(source)) {
                            return .optional_wrap;
                        } else {
                            switch (analyzer.module.types.array.get(destination_optional.element_type).*) {
                                .slice => |destination_slice| {
                                    if (destination_slice.element_type.eq(source_slice.element_type)) {
                                        return .optional_wrap;
                                    } else {
                                        unreachable;
                                    }
                                },
                                else => |t| @panic(@tagName(t)),
                            }
                        },
                        .array => |source_array| if (destination_optional.element_type.eq(source)) {
                            _ = source_array;
                            return .optional_wrap;
                        } else {
                            unreachable;
                        },
                        .@"struct" => |source_struct| if (destination_optional.element_type.eq(source)) {
                            return .optional_wrap;
                        } else {
                            _ = source_struct;
                            unreachable;
                        },
                        else => |t| @panic(@tagName(t)),
                    },
                    .function => |destination_function| switch (source_type.*) {
                        .function => |source_function| {
                            _ = destination_function;
                            _ = source_function;

                            // TODO: typecheck properly
                            return .success;
                        },
                        else => |t| @panic(@tagName(t)),
                    },
                    .slice => |destination_slice| switch (source_type.*) {
                        .slice => |source_slice| {
                            if (destination_slice.@"const" or destination_slice.@"const" == source_slice.@"const") {
                                if (destination_slice.element_type.eq(source_slice.element_type)) {
                                    return .success;
                                } else {
                                    unreachable;
                                }
                            } else {
                                @panic("Const mismatch");
                            }
                        },
                        .pointer => |source_pointer| {
                            const source_pointer_element_type = analyzer.module.types.array.get(source_pointer.element_type);
                            switch (source_pointer_element_type.*) {
                                .array => |array| {
                                    logln(.sema, .type, "Destination slice: {}", .{destination_slice});
                                    if (array.element_type.eq(Type.u8)) {
                                        if (array.element_type.eq(destination_slice.element_type)) {
                                            if (destination_slice.@"const") {
                                                if (destination_slice.@"const" == source_pointer.@"const") {
                                                    if (source_pointer.many) {
                                                        return .array_coerce_to_slice;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                },
                                else => |t| @panic(@tagName(t)),
                            }
                            //
                            unreachable;
                        },
                        else => |t| @panic(@tagName(t)),
                    },
                    else => |t| @panic(@tagName(t)),
                }
            },
            .flexible_integer => |expected_flexible_integer| {
                const source_type = analyzer.module.types.array.get(source);
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
                    .comptime_int => return .success,
                    else => |t| @panic(@tagName(t)),
                }
            },
            .addressable => |addressable| {
                if (addressable.element_type.eq(source)) return .success else {
                    const destination_type = analyzer.module.types.array.get(addressable.element_type);
                    const source_type = analyzer.module.types.array.get(source);

                    switch (source_type.*) {
                        .array => |source_array| {
                            assert(addressable.termination == source_array.termination);

                            if (source_array.element_type.eq(addressable.element_type)) {
                                return .success;
                            } else {
                                switch (destination_type.*) {
                                    .array => |destination_array| {
                                        logln(.sema, .type, "SRC: {}. DST: {}", .{ source_array, destination_array });
                                        unreachable;
                                    },
                                    else => |t| @panic(@tagName(t)),
                                }
                            }
                        },
                        .function => |source_function| {
                            assert(!addressable.many);
                            assert(addressable.termination == .none);
                            assert(addressable.@"const");

                            if (addressable.element_type.eq(source)) {
                                return .success;
                            } else {
                                switch (destination_type.*) {
                                    .function => |destination_function| {
                                        if (source_function.eq(destination_function)) {
                                            return .success;
                                        } else {
                                            // TODO: FIXME
                                            return .success;
                                        }
                                    },
                                    else => |t| @panic(@tagName(t)),
                                }
                            }
                        },
                        .integer => |source_integer| {
                            assert(!addressable.many);
                            assert(addressable.termination == .none);
                            _ = source_integer;
                            if (addressable.element_type.eq(source)) {
                                return .success;
                            } else {
                                // TODO: hack
                                unreachable;
                            }

                            unreachable;
                        },
                        else => |t| @panic(@tagName(t)),
                    }
                }
            },
            .dereferenceable => {
                unreachable;
            },
            // else => |t| @panic(@tagName(t)),
        };
    }

    fn getPointerType(analyzer: *Analyzer, pointer: Type.Pointer) !Type.Index {
        const gop = try analyzer.module.map.pointers.getOrPut(analyzer.allocator, pointer);
        if (!gop.found_existing) {
            const type_index = try analyzer.module.types.array.append(analyzer.allocator, .{
                .pointer = .{
                    .element_type = pointer.element_type,
                    .many = pointer.many,
                    .@"const" = pointer.@"const",
                    .termination = pointer.termination,
                },
            });
            gop.value_ptr.* = type_index;
        }

        const result = gop.value_ptr.*;
        return result;
    }

    fn getSliceType(analyzer: *Analyzer, slice: Type.Slice) !Type.Index {
        const gop = try analyzer.module.map.slices.getOrPut(analyzer.allocator, slice);

        if (!gop.found_existing) {
            const type_index = try analyzer.module.types.array.append(analyzer.allocator, .{
                .slice = slice,
            });
            gop.value_ptr.* = type_index;
        }

        const result = gop.value_ptr.*;
        return result;
    }

    fn getArrayType(analyzer: *Analyzer, array: Type.Array) !Type.Index {
        const gop = try analyzer.module.map.arrays.getOrPut(analyzer.allocator, array);

        if (!gop.found_existing) {
            const type_index = try analyzer.module.types.array.append(analyzer.allocator, .{
                .array = array,
            });
            gop.value_ptr.* = type_index;
        }

        const result = gop.value_ptr.*;
        return result;
    }

    fn getOptionalType(analyzer: *Analyzer, element_type_index: Type.Index) !Type.Index {
        const gop = try analyzer.module.map.optionals.getOrPut(analyzer.allocator, element_type_index);
        if (!gop.found_existing) {
            const type_index = try analyzer.module.types.array.append(analyzer.allocator, .{
                .optional = .{
                    .element_type = element_type_index,
                },
            });
            gop.value_ptr.* = type_index;
        }

        const result = gop.value_ptr.*;
        return result;
    }

    fn compilerIntrinsic(analyzer: *Analyzer, scope_index: Scope.Index, expect_type: ExpectType, node_index: Node.Index) !Value {
        const intrinsic_node = analyzer.getScopeNode(scope_index, node_index);

        const intrinsic_name = analyzer.tokenIdentifier(scope_index, intrinsic_node.token + 1);
        logln(.sema, .node, "Intrinsic: {s}", .{intrinsic_name});
        const intrinsic = data_structures.enumFromString(ValidIntrinsic, intrinsic_name) orelse panic("Unknown intrinsic: {s}", .{intrinsic_name});
        const intrinsic_argument_node_list = analyzer.getScopeNodeList(scope_index, analyzer.getScopeNode(scope_index, intrinsic_node.left));

        const result = switch (intrinsic) {
            .cast => b: {
                assert(intrinsic_argument_node_list.items.len == 1);
                const value_to_cast_index = try analyzer.unresolvedAllocate(scope_index, ExpectType.none, intrinsic_argument_node_list.items[0]);
                const value_type = analyzer.getValueType(value_to_cast_index);
                assert(expect_type != .none);
                const cast_result = try analyzer.canCast(expect_type, value_type);

                const value: Value = switch (cast_result) {
                    .success => .{
                        .intrinsic = try analyzer.module.values.intrinsics.append(analyzer.allocator, .{
                            .kind = .{
                                .cast = value_to_cast_index,
                            },
                            .type = switch (expect_type) {
                                .none => unreachable,
                                .flexible_integer => |flexible_integer| if (flexible_integer.sign) |sign| switch (sign) {
                                    else => unreachable,
                                } else switch (flexible_integer.byte_count) {
                                    1 => Type.u8,
                                    2 => Type.u16,
                                    4 => Type.u32,
                                    8 => Type.u64,
                                    else => unreachable,
                                },
                                .type_index => |type_index| type_index,
                                else => |t| @panic(@tagName(t)),
                            },
                        }),
                    },
                    .optional_wrap => .{
                        .intrinsic = try analyzer.module.values.intrinsics.append(analyzer.allocator, .{
                            .kind = .{
                                .optional_wrap = value_to_cast_index,
                            },
                            .type = expect_type.type_index,
                        }),
                    },
                    else => |t| @panic(@tagName(t)),
                };
                break :b value;
            },
            .@"error" => {
                assert(intrinsic_argument_node_list.items.len == 1);
                const message_node = analyzer.getScopeNode(scope_index, intrinsic_argument_node_list.items[0]);
                switch (message_node.id) {
                    .string_literal => panic("error: {s}", .{analyzer.tokenStringLiteral(scope_index, message_node.token)}),
                    else => |t| @panic(@tagName(t)),
                }
                unreachable;
            },
            .import => blk: {
                assert(intrinsic_argument_node_list.items.len == 1);
                const import_argument = analyzer.getScopeNode(scope_index, intrinsic_argument_node_list.items[0]);

                switch (import_argument.id) {
                    .string_literal => {
                        const import_name = analyzer.tokenStringLiteral(scope_index, import_argument.token);
                        const import_file = try analyzer.module.importFile(analyzer.allocator, analyzer.current_file, import_name);
                        logln(.sema, .node, "Importing \"{s}\"...", .{import_name});

                        if (import_file.file.is_new) {
                            const new_file_index = import_file.file.index;
                            try analyzer.module.generateAbstractSyntaxTreeForFile(analyzer.allocator, new_file_index);
                            const value_index = try analyzer.module.values.array.append(analyzer.allocator, .{
                                .unresolved = undefined,
                            });
                            const analyze_result = try analyzeFile(value_index, analyzer.allocator, analyzer.module, new_file_index);
                            logln(.sema, .node, "Done analyzing {s}!", .{import_name});
                            const result = Value{
                                .type = analyze_result,
                            };
                            break :blk result;
                        } else {
                            const result = Value{
                                .type = analyzer.module.values.files.get(import_file.file.index).type,
                            };
                            assert(!result.type.invalid);

                            break :blk result;
                        }
                    },
                    else => unreachable,
                }
            },
            .min => blk: {
                assert(intrinsic_argument_node_list.items.len == 2);
                const value1 = try analyzer.unresolvedAllocate(scope_index, expect_type, intrinsic_argument_node_list.items[0]);
                const value2 = try analyzer.unresolvedAllocate(scope_index, expect_type, intrinsic_argument_node_list.items[1]);
                const intrinsic_index = try analyzer.module.values.intrinsics.append(analyzer.allocator, .{
                    .kind = .{
                        .min = .{
                            .left = value1,
                            .right = value2,
                        },
                    },
                    .type = switch (expect_type) {
                        .type_index => |type_index| type_index,
                        .none => analyzer.module.values.array.get(value1).getType(analyzer.module),
                        else => |t| @panic(@tagName(t)),
                    },
                });
                break :blk Value{
                    .intrinsic = intrinsic_index,
                };
            },
            .size => blk: {
                assert(intrinsic_argument_node_list.items.len == 1);
                const intrinsic_argument_value_index = try analyzer.unresolvedAllocate(scope_index, ExpectType.type, intrinsic_argument_node_list.items[0]);
                const type_size = switch (analyzer.module.values.array.get(intrinsic_argument_value_index).*) {
                    .type => |type_index| analyzer.module.types.array.get(type_index).getSize(),
                    else => |t| @panic(@tagName(t)),
                };
                const intrinsic_argument_value = analyzer.module.values.array.get(intrinsic_argument_value_index);
                intrinsic_argument_value.* = .{
                    .integer = .{
                        .value = type_size,
                        .type = switch (expect_type) {
                            .type_index => |type_index| type_index,
                            else => |t| @panic(@tagName(t)),
                        },
                        .signedness = .unsigned,
                    },
                };

                break :blk intrinsic_argument_value.*;
            },
            .syscall => if (intrinsic_argument_node_list.items.len > 0 and intrinsic_argument_node_list.items.len <= 6 + 1) blk: {
                const argument_expect_type = .{
                    .flexible_integer = .{
                        .byte_count = 8,
                    },
                };

                var list = try ArrayList(Value.Index).initCapacity(analyzer.allocator, intrinsic_argument_node_list.items.len);
                for (intrinsic_argument_node_list.items) |argument_node_index| {
                    const argument_value_index = try analyzer.unresolvedAllocate(scope_index, argument_expect_type, argument_node_index);
                    list.appendAssumeCapacity(argument_value_index);
                }

                const intrinsic_index = try analyzer.module.values.intrinsics.append(analyzer.allocator, .{
                    .kind = .{
                        .syscall = list,
                    },
                    .type = Type.usize,
                });

                break :blk Value{
                    .intrinsic = intrinsic_index,
                };
            } else unreachable,
        };

        return result;
    }

    fn getValueType(analyzer: *Analyzer, value_index: Value.Index) Type.Index {
        const value_type_index = analyzer.module.values.array.get(value_index).getType(analyzer.module);
        return value_type_index;
    }
};

pub fn initialize(compilation: *Compilation, module: *Module, package: *Package, main_value_index: Value.Index) !void {
    _ = try analyzeExistingPackage(main_value_index, compilation, module, package);
}

pub fn analyzeExistingPackage(value_index: Value.Index, compilation: *Compilation, module: *Module, package: *Package) !Type.Index {
    const package_import = try module.importPackage(compilation.base_allocator, package);
    assert(!package_import.file.is_new);
    const file_index = package_import.file.index;

    return try analyzeFile(value_index, compilation.base_allocator, module, file_index);
}

pub fn analyzeFile(value_index: Value.Index, allocator: Allocator, module: *Module, file_index: File.Index) !Type.Index {
    const file = module.values.files.get(file_index);
    assert(module.values.array.get(value_index).* == .unresolved);
    assert(file.status == .parsed);

    var analyzer = Analyzer{
        .current_file = file_index,
        .allocator = allocator,
        .module = module,
    };

    const node = file.syntactic_analyzer_result.nodes.items[0];
    const node_list_node = analyzer.getFileNode(file_index, node.left);
    const nodes = analyzer.getFileNodeList(file_index, node_list_node);
    const result = try analyzer.processContainerType(value_index, Scope.Index.invalid, nodes.items, file_index, .{ .value = 0 }, .@"struct");
    return result;
}
