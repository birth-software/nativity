const std = @import("std");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;
const equal = std.mem.eql;
const Compilation = @import("../Compilation.zig");
const File = Compilation.File;
const Module = Compilation.Module;
const Package = Compilation.Package;

const Assignment = Compilation.Assignment;
const Block = Compilation.Block;
const Declaration = Compilation.Declaration;
const Field = Compilation.Field;
const Function = Compilation.Function;
const Loop = Compilation.Loop;
const Scope = Compilation.Scope;
const Struct = Compilation.Struct;
const Type = Compilation.Type;
const Value = Compilation.Value;

const lexical_analyzer = @import("lexical_analyzer.zig");
const Token = lexical_analyzer.Token;

const syntactic_analyzer = @import("syntactic_analyzer.zig");
const ContainerDeclaration = syntactic_analyzer.ContainerDeclaration;
const Node = syntactic_analyzer.Node;
const SymbolDeclaration = syntactic_analyzer.SymbolDeclaration;

const data_structures = @import("../data_structures.zig");
const ArrayList = data_structures.ArrayList;
const HashMap = data_structures.AutoHashMap;

const print = std.debug.print;

const Analyzer = struct {
    source_code: []const u8,
    nodes: []const Node,
    tokens: []const Token,
    file: *File,
    allocator: Allocator,
    module: *Module,

    fn lazyGlobalDeclaration(analyzer: *Analyzer, node_index: Node.Index) void {
        print("Global: {}", .{analyzer.nodes[node_index.unwrap()]});
    }

    fn comptimeBlock(analyzer: *Analyzer, scope: *Scope, node_index: Node.Index) !Value.Index {
        const comptime_node = analyzer.nodes[node_index.unwrap()];

        const comptime_block = try analyzer.block(scope, .{ .none = {} }, comptime_node.left);
        return try analyzer.module.values.append(analyzer.allocator, .{
            .block = comptime_block,
        });
    }

    fn assign(analyzer: *Analyzer, scope: *Scope, node_index: Node.Index) !Assignment.Index {
        _ = node_index;
        _ = scope;
        _ = analyzer;
    }

    fn block(analyzer: *Analyzer, scope: *Scope, expect_type: ExpectType, node_index: Node.Index) anyerror!Block.Index {
        var reaches_end = true;
        const block_node = analyzer.nodes[node_index.unwrap()];
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
            else => |t| @panic(@tagName(t)),
        }

        const is_comptime = switch (block_node.id) {
            .comptime_block_zero, .comptime_block_one, .comptime_block_two => true,
            .block_zero, .block_one, .block_two => false,
            else => |t| @panic(@tagName(t)),
        };
        print("Is comptime: {}\n", .{is_comptime});

        var statements = ArrayList(Value.Index){};

        for (statement_nodes.items) |statement_node_index| {
            if (!reaches_end) {
                unreachable;
            }

            const statement_node = analyzer.nodes[statement_node_index.unwrap()];
            const statement_value = switch (statement_node.id) {
                inline .assign, .simple_while => |statement_id| blk: {
                    const specific_value_index = switch (statement_id) {
                        .assign => {
                            print("Assign: #{}\n", .{node_index.value});
                            assert(statement_node.id == .assign);
                            switch (statement_node.left.valid) {
                                // In an assignment, the node being invalid means a discarding underscore, like this: ```_ = result```
                                false => {
                                    const right = try analyzer.expression(scope, ExpectType.none, statement_node.right);
                                    try statements.append(analyzer.allocator, right);
                                    continue;
                                },
                                true => {
                                    const left_node = analyzer.nodes[statement_node.left.unwrap()];
                                    print("left node index: {}. Left node: {}\n", .{ statement_node.left, left_node });
                                    // const id = analyzer.tokenIdentifier(.token);
                                    // print("id: {s}\n", .{id});
                                    const left = try analyzer.expression(scope, ExpectType.none, statement_node.left);
                                    _ = left;

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
                            }
                        },
                        .simple_while => statement: {
                            const loop_index = try analyzer.module.loops.append(analyzer.allocator, .{
                                .condition = Value.Index.invalid,
                                .body = Value.Index.invalid,
                                .breaks = false,
                            });
                            const loop_structure = analyzer.module.loops.get(loop_index);
                            const while_condition = try analyzer.expression(scope, ExpectType.boolean, statement_node.left);
                            const while_body = try analyzer.expression(scope, expect_type, statement_node.right);
                            loop_structure.condition = while_condition;
                            loop_structure.body = while_body;

                            reaches_end = loop_structure.breaks or while_condition.valid;

                            break :statement loop_index;
                        },
                        else => unreachable,
                    };
                    const value = @unionInit(Value, switch (statement_id) {
                        .assign => "assign",
                        .simple_while => "loop",
                        else => unreachable,
                    }, specific_value_index);
                    const value_index = try analyzer.module.values.append(analyzer.allocator, value);
                    break :blk value_index;
                },
                .@"unreachable" => blk: {
                    reaches_end = false;
                    break :blk Values.@"unreachable".getIndex();
                },
                else => |t| @panic(@tagName(t)),
            };
            try statements.append(analyzer.allocator, statement_value);
        }

        return try analyzer.module.blocks.append(analyzer.allocator, .{
            .statements = statements,
            .reaches_end = reaches_end,
        });
    }

    fn whileExpression(analyzer: *Analyzer, scope: *Scope, expect_type: ExpectType, node: Node) !Loop.Index {
        _ = node;
        _ = expect_type;
        _ = scope;
        _ = analyzer;
    }

    fn resolve(analyzer: *Analyzer, scope: *Scope, expect_type: ExpectType, value: *Value) !void {
        const node_index = switch (value.*) {
            .unresolved => |unresolved| unresolved.node_index,
            else => |t| @panic(@tagName(t)),
        };
        value.* = try analyzer.resolveNode(scope, expect_type, node_index);
    }

    fn doIdentifier(analyzer: *Analyzer, scope: *Scope, expect_type: ExpectType, node: Node) !Value.Index {
        assert(node.id == .identifier);
        const identifier_hash = try analyzer.identifierFromToken(node.token);
        // TODO: search in upper scopes too
        const identifier_scope_lookup = try scope.declarations.getOrPut(analyzer.allocator, identifier_hash);
        if (identifier_scope_lookup.found_existing) {
            const declaration_index = identifier_scope_lookup.value_ptr.*;
            const declaration = analyzer.module.declarations.get(declaration_index);
            const init_value = analyzer.module.values.get(declaration.init_value);
            try analyzer.resolve(scope, expect_type, init_value);
            if (init_value.* != .runtime and declaration.mutability == .@"const") {
                return declaration.init_value;
            } else {
                unreachable;
            }
        } else {
            @panic("TODO: not found");
        }
    }

    fn getArguments(analyzer: *Analyzer, node_index: Node.Index) !ArrayList(Node.Index) {
        var arguments = ArrayList(Node.Index){};
        const node = analyzer.nodes[node_index.unwrap()];
        switch (node.id) {
            .compiler_intrinsic_two => {
                try arguments.append(analyzer.allocator, node.left);
                try arguments.append(analyzer.allocator, node.right);
            },
            else => |t| @panic(@tagName(t)),
        }

        return arguments;
    }

    fn resolveNode(analyzer: *Analyzer, scope: *Scope, expect_type: ExpectType, node_index: Node.Index) anyerror!Value {
        const node = analyzer.nodes[node_index.unwrap()];
        return switch (node.id) {
            .identifier => unreachable,
            .compiler_intrinsic_one, .compiler_intrinsic_two => blk: {
                const intrinsic_name = analyzer.tokenIdentifier(node.token + 1);
                const intrinsic = data_structures.enumFromString(Intrinsic, intrinsic_name) orelse unreachable;
                print("Intrinsic: {s}\n", .{@tagName(intrinsic)});
                switch (intrinsic) {
                    .import => {
                        assert(node.id == .compiler_intrinsic_one);
                        const import_argument = analyzer.nodes[node.left.unwrap()];
                        switch (import_argument.id) {
                            .string_literal => {
                                const import_name = analyzer.tokenStringLiteral(import_argument.token);
                                const imported_file = try analyzer.module.importFile(analyzer.allocator, analyzer.file, import_name);

                                if (imported_file.is_new) {
                                    // TODO: fix error
                                    try analyzer.module.generateAbstractSyntaxTreeForFile(analyzer.allocator, imported_file.file);
                                } else {
                                    unreachable;
                                }

                                break :blk .{
                                    .type = try analyzeFile(analyzer.allocator, analyzer.module, imported_file.file),
                                };
                            },
                            else => unreachable,
                        }
                    },
                    .syscall => {
                        var argument_nodes = try analyzer.getArguments(node_index);
                        print("Argument count: {}\n", .{argument_nodes.items.len});
                        if (argument_nodes.items.len > 0 and argument_nodes.items.len <= 6 + 1) {
                            const number = try analyzer.expression(scope, ExpectType.none, argument_nodes.items[0]);
                            assert(number.valid);
                            var arguments = std.mem.zeroes([6]Value.Index);
                            for (argument_nodes.items[1..], 0..) |argument_node_index, argument_index| {
                                const argument = try analyzer.expression(scope, ExpectType.none, argument_node_index);
                                print("Index: {}. Argument: {}\n", .{ argument_index, argument });
                                arguments[argument_index] = argument;
                            }

                            // TODO: typecheck for usize
                            for (arguments[0..argument_nodes.items.len]) |argument| {
                                _ = argument;
                            }

                            break :blk .{
                                .syscall = try analyzer.module.syscalls.append(analyzer.allocator, .{
                                    .number = number,
                                    .arguments = arguments,
                                    .argument_count = @intCast(argument_nodes.items.len - 1),
                                }),
                            };
                        } else {
                            unreachable;
                        }
                    },
                }
                unreachable;
            },
            .function_definition => blk: {
                const function_prototype_index = try analyzer.functionPrototype(node.left);

                const function_body = try analyzer.block(scope, .{
                    .type_index = analyzer.functionPrototypeReturnType(function_prototype_index),
                }, node.right);

                const function_index = try analyzer.module.functions.append(analyzer.allocator, .{
                    .prototype = function_prototype_index,
                    .body = function_body,
                });
                break :blk .{
                    .function = function_index,
                };
            },
            .keyword_true => unreachable,
            .simple_while => unreachable,
            .block_zero, .block_one => blk: {
                const block_index = try analyzer.block(scope, expect_type, node_index);
                break :blk .{
                    .block = block_index,
                };
            },
            .number_literal => switch (std.zig.parseNumberLiteral(analyzer.tokenBytes(analyzer.tokens[node.token]))) {
                .int => |integer| .{
                    .integer = integer,
                },
                else => |t| @panic(@tagName(t)),
            },
            else => |t| @panic(@tagName(t)),
        };
    }

    fn expression(analyzer: *Analyzer, scope: *Scope, expect_type: ExpectType, node_index: Node.Index) !Value.Index {
        const node = analyzer.nodes[node_index.unwrap()];
        return switch (node.id) {
            .identifier => analyzer.doIdentifier(scope, expect_type, node),
            .keyword_true => blk: {
                switch (expect_type) {
                    .none => {},
                    .type_index => |expected_type| {
                        if (@as(u32, @bitCast(type_boolean)) != @as(u32, @bitCast(expected_type))) {
                            @panic("TODO: compile error");
                        }
                    },
                }

                break :blk Values.getIndex(.bool_true);
            },
            else => try analyzer.module.values.append(analyzer.allocator, try analyzer.resolveNode(scope, expect_type, node_index)),
        };
    }

    fn functionPrototypeReturnType(analyzer: *Analyzer, function_prototype_index: Function.Prototype.Index) Type.Index {
        const function_prototype = analyzer.module.function_prototypes.get(function_prototype_index);
        return function_prototype.return_type;
    }

    fn functionPrototype(analyzer: *Analyzer, node_index: Node.Index) !Function.Prototype.Index {
        const node = analyzer.nodes[node_index.unwrap()];
        switch (node.id) {
            .simple_function_prototype => {
                const arguments: ?[]const Field.Index = blk: {
                    const argument_node = analyzer.nodes[node.left.get() orelse break :blk null];
                    switch (argument_node.id) {
                        else => |t| @panic(@tagName(t)),
                    }
                };
                const return_type_node = analyzer.nodes[node.right.unwrap()];
                const return_type: Type.Index = switch (return_type_node.id) {
                    .identifier => {
                        unreachable;
                    },
                    .keyword_noreturn => .{ .block = 0, .index = FixedTypeKeyword.offset + @intFromEnum(FixedTypeKeyword.noreturn) },
                    else => |t| @panic(@tagName(t)),
                };

                return try analyzer.module.function_prototypes.append(analyzer.allocator, .{
                    .arguments = arguments,
                    .return_type = return_type,
                });
            },
            else => |t| @panic(@tagName(t)),
        }
    }

    fn analyzeDeclaration(analyzer: *Analyzer, scope: *Scope, declaration: *Declaration) !Value.Index {
        _ = declaration;
        _ = scope;
        _ = analyzer;
        // switch (declaration.*) {
        //     .unresolved => |node_index| {
        //         const declaration_node = analyzer.nodes[node_index.unwrap()];
        //         return switch (declaration_node.id) {
        //             .simple_variable_declaration => blk: {
        //                 const expect_type = switch (declaration_node.left.valid) {
        //                     true => unreachable,
        //                     false => @unionInit(ExpectType, "none", {}),
        //                 };
        //
        //                 const initialization_expression = try analyzer.expression(scope, expect_type, declaration_node.right);
        //                 const value = analyzer.module.values.get(initialization_expression);
        //                 if (value.is_comptime and value.is_const) {
        //                     break :blk initialization_expression;
        //                 }
        //
        //                 unreachable;
        //             },
        //             else => |t| @panic(@tagName(t)),
        //         };
        //     },
        //     .struct_type => unreachable,
        // }

        @panic("TODO: analyzeDeclaration");
    }

    fn structType(analyzer: *Analyzer, parent_scope: Scope.Index, container_declaration: syntactic_analyzer.ContainerDeclaration, index: Node.Index) !Type.Index {
        _ = index;
        const new_scope = try analyzer.allocateScope(.{ .parent = parent_scope });
        const scope = new_scope.ptr;

        const is_file = !parent_scope.valid;
        assert(is_file);

        const struct_index = try analyzer.module.structs.append(analyzer.allocator, .{
            .scope = new_scope.index,
        });
        const struct_type = analyzer.module.structs.get(struct_index);
        const type_index = try analyzer.module.types.append(analyzer.allocator, .{
            .@"struct" = struct_index,
        });
        scope.type = type_index;

        _ = struct_type;
        assert(container_declaration.members.len > 0);

        const count = blk: {
            var result: struct {
                fields: u32 = 0,
                declarations: u32 = 0,
            } = .{};
            for (container_declaration.members) |member_index| {
                const member = analyzer.nodes[member_index.unwrap()];
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

        for (container_declaration.members) |member_index| {
            const member = analyzer.nodes[member_index.unwrap()];
            const member_type = getContainerMemberType(member.id);
            const array_list = switch (member_type) {
                .declaration => &declaration_nodes,
                .field => &field_nodes,
            };
            array_list.appendAssumeCapacity(member_index);
        }

        for (declaration_nodes.items) |declaration_node_index| {
            const declaration_node = analyzer.nodes[declaration_node_index.unwrap()];
            switch (declaration_node.id) {
                .@"comptime" => {},
                .simple_variable_declaration => {
                    const mutability: Compilation.Mutability = switch (analyzer.tokens[declaration_node.token].id) {
                        .fixed_keyword_const => .@"const",
                        .fixed_keyword_var => .@"var",
                        else => |t| @panic(@tagName(t)),
                    };
                    const expected_identifier_token_index = declaration_node.token + 1;
                    const expected_identifier_token = analyzer.tokens[expected_identifier_token_index];
                    if (expected_identifier_token.id != .identifier) {
                        print("Error: found: {}", .{expected_identifier_token.id});
                        @panic("Expected identifier");
                    }
                    // TODO: Check if it is a keyword

                    const identifier_index = try analyzer.identifierFromToken(expected_identifier_token_index);

                    const declaration_name = analyzer.tokenIdentifier(expected_identifier_token_index);
                    // Check if the symbol name is already occupied in the same scope
                    const scope_lookup = try scope.declarations.getOrPut(analyzer.allocator, identifier_index);
                    if (scope_lookup.found_existing) {
                        std.debug.panic("Existing name in lookup: {s}", .{declaration_name});
                    }

                    // Check if the symbol name is already occupied in parent scopes
                    var upper_scope_index = scope.parent;

                    while (upper_scope_index.valid) {
                        @panic("TODO: upper scope");
                    }

                    const container_declaration_index = try analyzer.module.declarations.append(analyzer.allocator, .{
                        .name = declaration_name,
                        .scope_type = .global,
                        .mutability = mutability,
                        .init_value = try analyzer.module.values.append(analyzer.allocator, .{
                            .unresolved = .{
                                .node_index = declaration_node.right,
                            },
                        }),
                    });

                    scope_lookup.value_ptr.* = container_declaration_index;
                },
                else => unreachable,
            }
        }

        // TODO: consider iterating over scope declarations instead?
        for (declaration_nodes.items) |declaration_node_index| {
            const declaration_node = analyzer.nodes[declaration_node_index.unwrap()];
            switch (declaration_node.id) {
                .@"comptime" => _ = try analyzer.comptimeBlock(scope, declaration_node_index),
                .simple_variable_declaration => {},
                else => |t| @panic(@tagName(t)),
            }
        }

        for (field_nodes.items) |field_index| {
            const field_node = analyzer.nodes[field_index.unwrap()];
            _ = field_node;

            @panic("TODO: fields");
        }

        return type_index;
    }

    const MemberType = enum {
        declaration,
        field,
    };

    fn getContainerMemberType(member_id: Node.Id) MemberType {
        return switch (member_id) {
            .@"comptime" => .declaration,
            .simple_variable_declaration => .declaration,
            else => unreachable,
        };
    }

    fn identifierFromToken(analyzer: *Analyzer, token_index: Token.Index) !u32 {
        const identifier = analyzer.tokenIdentifier(token_index);
        const key: u32 = @truncate(std.hash.Wyhash.hash(0, identifier));

        const lookup_result = try analyzer.module.string_table.getOrPut(analyzer.allocator, key);

        if (lookup_result.found_existing) {
            return lookup_result.key_ptr.*;
        } else {
            return key;
        }
    }

    fn tokenIdentifier(analyzer: *Analyzer, token_index: Token.Index) []const u8 {
        const token = analyzer.tokens[token_index];
        assert(token.id == .identifier);
        const identifier = analyzer.tokenBytes(token);

        return identifier;
    }

    fn tokenBytes(analyzer: *Analyzer, token: Token) []const u8 {
        return analyzer.source_code[token.start..][0..token.len];
    }

    fn tokenStringLiteral(analyzer: *Analyzer, token_index: Token.Index) []const u8 {
        const token = analyzer.tokens[token_index];
        assert(token.id == .string_literal);
        // Eat double quotes
        const string_literal = analyzer.tokenBytes(token)[1..][0 .. token.len - 2];

        return string_literal;
    }

    const ScopeAllocation = struct {
        ptr: *Scope,
        index: Scope.Index,
    };

    fn allocateScope(analyzer: *Analyzer, scope_value: Scope) !ScopeAllocation {
        const scope_index = try analyzer.module.scopes.append(analyzer.allocator, scope_value);
        const scope = analyzer.module.scopes.get(scope_index);

        return .{
            .ptr = scope,
            .index = scope_index,
        };
    }
};

const ExpectType = union(enum) {
    none,
    type_index: Type.Index,

    pub const none = ExpectType{
        .none = {},
    };
    pub const boolean = ExpectType{
        .type_index = type_boolean,
    };
};

const type_boolean = Type.Index{
    .block = 0,
    .index = FixedTypeKeyword.offset + @intFromEnum(FixedTypeKeyword.bool),
};

// Each time an enum is added here, a corresponding insertion in the initialization must be made
const Values = enum {
    bool_false,
    bool_true,
    @"unreachable",

    fn getIndex(value: Values) Value.Index {
        const absolute: u32 = @intFromEnum(value);
        const foo = @as(Value.Index, undefined);
        const ElementT = @TypeOf(@field(foo, "index"));
        const BlockT = @TypeOf(@field(foo, "block"));
        const divider = std.math.maxInt(ElementT);
        const element_index: ElementT = @intCast(absolute % divider);
        const block_index: BlockT = @intCast(absolute / divider);
        return .{
            .index = element_index,
            .block = block_index,
        };
    }
};

const Intrinsic = enum {
    import,
    syscall,
};

const FixedTypeKeyword = enum {
    void,
    noreturn,
    bool,

    const offset = 0;
};

const HardwareUnsignedIntegerType = enum {
    u8,
    u16,
    u32,
    u64,

    const offset = @typeInfo(FixedTypeKeyword).Enum.fields.len;
};

const HardwareSignedIntegerType = enum {
    s8,
    s16,
    s32,
    s64,

    const offset = HardwareUnsignedIntegerType.offset + @typeInfo(HardwareUnsignedIntegerType).Enum.fields.len;
};

pub fn initialize(compilation: *Compilation, module: *Module, package: *Package) !Type.Index {
    inline for (@typeInfo(FixedTypeKeyword).Enum.fields) |enum_field| {
        _ = try module.types.append(compilation.base_allocator, @unionInit(Type, enum_field.name, {}));
    }

    inline for (@typeInfo(HardwareUnsignedIntegerType).Enum.fields) |enum_field| {
        _ = try module.types.append(compilation.base_allocator, .{
            .integer = .{
                .signedness = .unsigned,
                .bit_count = switch (@field(HardwareUnsignedIntegerType, enum_field.name)) {
                    .u8 => 8,
                    .u16 => 16,
                    .u32 => 32,
                    .u64 => 64,
                },
            },
        });
    }

    inline for (@typeInfo(HardwareSignedIntegerType).Enum.fields) |enum_field| {
        _ = try module.types.append(compilation.base_allocator, .{
            .integer = .{
                .signedness = .signed,
                .bit_count = switch (@field(HardwareSignedIntegerType, enum_field.name)) {
                    .s8 => 8,
                    .s16 => 16,
                    .s32 => 32,
                    .s64 => 64,
                },
            },
        });
    }

    _ = try module.values.append(compilation.base_allocator, .{
        .bool = false,
    });

    _ = try module.values.append(compilation.base_allocator, .{
        .bool = true,
    });

    _ = try module.values.append(compilation.base_allocator, .{
        .@"unreachable" = {},
    });

    return analyzeExistingPackage(compilation, module, package);
}

pub fn analyzeExistingPackage(compilation: *Compilation, module: *Module, package: *Package) !Type.Index {
    const package_import = try module.importPackage(compilation.base_allocator, package);
    assert(!package_import.is_new);
    const package_file = package_import.file;

    return try analyzeFile(compilation.base_allocator, module, package_file);
}

pub fn analyzeFile(allocator: Allocator, module: *Module, file: *File) !Type.Index {
    assert(file.status == .parsed);

    var analyzer = Analyzer{
        .source_code = file.source_code,
        .nodes = file.syntactic_analyzer_result.nodes.items,
        .tokens = file.lexical_analyzer_result.tokens.items,
        .file = file,
        .allocator = allocator,
        .module = module,
    };

    const result = try analyzer.structType(Scope.Index.invalid, try mainNodeToContainerDeclaration(allocator, file), .{ .value = 0 });
    return result;
}

fn mainNodeToContainerDeclaration(allocator: Allocator, file: *File) !ContainerDeclaration {
    const main_node = getNode(file, 0);
    var list_buffer: [2]Node.Index = undefined;
    const left_node = getNode(file, main_node.left.value);
    const node_list: []const Node.Index = blk: {
        if (left_node.id != .node_list) {
            const len = @as(u2, @intFromBool(main_node.left.valid)) + @as(u2, @intFromBool(main_node.right.valid)) - @as(u2, @intFromBool(main_node.left.valid and main_node.right.valid and main_node.left.value == main_node.right.value));
            assert(len > 0);
            list_buffer[0] = main_node.left;
            list_buffer[1] = main_node.right;
            break :blk list_buffer[0..len];
        } else {
            @panic("TODO: get list");
        }
    };

    const owned_node_list = try allocator.alloc(Node.Index, node_list.len);
    @memcpy(owned_node_list, node_list);

    // Deal properly with this allocation
    return .{
        .members = owned_node_list,
    };
}

fn getNode(file: *const File, index: u32) *Node {
    return &file.syntactic_analyzer_result.nodes.items[index];
}
