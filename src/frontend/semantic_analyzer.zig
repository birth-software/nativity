const std = @import("std");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;
const equal = std.mem.eql;
const Compilation = @import("../Compilation.zig");
const File = Compilation.File;
const Module = Compilation.Module;
const Package = Compilation.Package;

const ArgumentList = Compilation.ArgumentList;
const Assignment = Compilation.Assignment;
const Block = Compilation.Block;
const Declaration = Compilation.Declaration;
const Field = Compilation.Field;
const Function = Compilation.Function;
const Loop = Compilation.Loop;
const Scope = Compilation.Scope;
const ScopeType = Compilation.ScopeType;
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
    allocator: Allocator,
    module: *Module,
    current_file: File.Index,

    fn getSourceFile(analyzer: *Analyzer, scope_index: Scope.Index) []const u8 {
        const scope = analyzer.module.scopes.get(scope_index);
        const file = analyzer.module.files.get(scope.file);
        return file.source_code;
    }

    fn getNode(analyzer: *Analyzer, scope_index: Scope.Index, node_index: Node.Index) Node {
        const scope = analyzer.module.scopes.get(scope_index);
        const file = analyzer.module.files.get(scope.file);
        const result = file.syntactic_analyzer_result.nodes.items[node_index.unwrap()];
        return result;
    }

    fn getToken(analyzer: *Analyzer, scope_index: Scope.Index, token_index: Token.Index) Token {
        const scope = analyzer.module.scopes.get(scope_index);
        const file = analyzer.module.files.get(scope.file);
        const result = file.lexical_analyzer_result.tokens.items[token_index];

        return result;
    }

    fn getNodeList(analyzer: *Analyzer, scope_index: Scope.Index, list_index: u32) ArrayList(Node.Index) {
        const scope = analyzer.module.scopes.get(scope_index);
        const file = analyzer.module.files.get(scope.file);
        return file.syntactic_analyzer_result.node_lists.items[list_index];
    }

    fn comptimeBlock(analyzer: *Analyzer, scope_index: Scope.Index, node_index: Node.Index) !Value.Index {
        const comptime_node = analyzer.getNode(scope_index, node_index);

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
        var reaches_end = true;
        const block_node = analyzer.getNode(scope_index, node_index);
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
            .block, .comptime_block => statement_nodes = analyzer.getNodeList(scope_index, block_node.left.unwrap()),
            else => |t| @panic(@tagName(t)),
        }

        const is_comptime = switch (block_node.id) {
            .comptime_block, .comptime_block_zero, .comptime_block_one, .comptime_block_two => true,
            .block, .block_zero, .block_one, .block_two => false,
            else => |t| @panic(@tagName(t)),
        };
        print("Is comptime: {}\n", .{is_comptime});

        var statements = ArrayList(Value.Index){};

        for (statement_nodes.items) |statement_node_index| {
            if (!reaches_end) {
                unreachable;
            }

            const statement_node = analyzer.getNode(scope_index, statement_node_index);
            const statement_value = switch (statement_node.id) {
                inline .assign, .simple_while => |statement_id| blk: {
                    const specific_value_index = switch (statement_id) {
                        .assign => {
                            print("Assign: #{}\n", .{node_index.value});
                            assert(statement_node.id == .assign);
                            switch (statement_node.left.valid) {
                                // In an assignment, the node being invalid means a discarding underscore, like this: ```_ = result```
                                false => {
                                    const right_value_allocation = try analyzer.module.values.addOne(analyzer.allocator);
                                    right_value_allocation.ptr.* = .{
                                        .unresolved = .{
                                            .node_index = statement_node.right,
                                        },
                                    };
                                    try analyzer.resolveNode(right_value_allocation.ptr, scope_index, ExpectType.none, statement_node.right);
                                    // switch (right_value_allocation.ptr.*) {
                                    //     else => |t| std.debug.print("\n\n\n\n\nASSIGN RIGHT: {s}\n\n\n\n", .{@tagName(t)}),
                                    // }
                                    try statements.append(analyzer.allocator, right_value_allocation.index);
                                    continue;
                                },
                                true => {
                                    // const id = analyzer.tokenIdentifier(.token);
                                    // print("id: {s}\n", .{id});
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
                            }
                        },
                        .simple_while => statement: {
                            const loop_allocation = try analyzer.module.loops.append(analyzer.allocator, .{
                                .condition = Value.Index.invalid,
                                .body = Value.Index.invalid,
                                .breaks = false,
                            });
                            loop_allocation.ptr.condition = (try analyzer.unresolvedAllocate(scope_index, ExpectType.boolean, statement_node.left)).index;
                            loop_allocation.ptr.body = (try analyzer.unresolvedAllocate(scope_index, ExpectType.none, statement_node.right)).index;

                            // TODO: bool true
                            reaches_end = loop_allocation.ptr.breaks or unreachable;

                            break :statement loop_allocation.index;
                        },
                        else => unreachable,
                    };
                    const value = @unionInit(Value, switch (statement_id) {
                        .assign => "assign",
                        .simple_while => "loop",
                        else => unreachable,
                    }, specific_value_index);
                    const value_allocation = try analyzer.module.values.append(analyzer.allocator, value);
                    break :blk value_allocation.index;
                },
                .@"unreachable" => blk: {
                    reaches_end = false;
                    break :blk Values.@"unreachable".getIndex();
                },
                .simple_variable_declaration => (try analyzer.module.values.append(analyzer.allocator, .{
                    .declaration = try analyzer.symbolDeclaration(scope_index, statement_node_index, .local),
                })).index,
                .@"return" => blk: {
                    reaches_end = false;
                    const return_expression: Value.Index = switch (statement_node_index.valid) {
                        // TODO: expect type
                        true => ret: {
                            const return_value_allocation = try analyzer.module.values.addOne(analyzer.allocator);
                            return_value_allocation.ptr.* = .{
                                .unresolved = .{
                                    .node_index = statement_node.left,
                                },
                            };
                            try analyzer.resolveNode(return_value_allocation.ptr, scope_index, expect_type, statement_node.left);
                            break :ret return_value_allocation.index;
                        },
                        false => @panic("TODO: ret void"),
                    };

                    const return_value_allocation = try analyzer.module.returns.append(analyzer.allocator, .{
                        .value = return_expression,
                    });

                    const return_expression_value_allocation = try analyzer.module.values.append(analyzer.allocator, .{
                        .@"return" = return_value_allocation.index,
                    });

                    break :blk return_expression_value_allocation.index;
                },
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

    fn doIdentifier(analyzer: *Analyzer, scope_index: Scope.Index, expect_type: ExpectType, node_token: Token.Index, node_scope_index: Scope.Index) !Value.Index {
        const identifier_hash = try analyzer.identifierFromToken(node_scope_index, node_token);
        const scope = analyzer.module.scopes.get(scope_index);
        // TODO: search in upper scopes too
        const identifier_scope_lookup = try scope.declarations.getOrPut(analyzer.allocator, identifier_hash);
        if (identifier_scope_lookup.found_existing) {
            const declaration_index = identifier_scope_lookup.value_ptr.*;
            const declaration = analyzer.module.declarations.get(declaration_index);
            const init_value = analyzer.module.values.get(declaration.init_value);
            print("Declaration found: {}\n", .{init_value});
            switch (init_value.*) {
                .unresolved => |ur| try analyzer.resolveNode(init_value, scope_index, expect_type, ur.node_index),
                else => {},
            }
            if (init_value.isComptime() and declaration.mutability == .@"const") {
                return declaration.init_value;
            } else {
                const ref_allocation = try analyzer.module.values.append(analyzer.allocator, .{
                    .declaration_reference = declaration_index,
                });
                return ref_allocation.index;
            }
        } else {
            std.debug.panic("Identifier not found in scope #{} of file #{} referenced by scope #{} of file #{}: {s}", .{ scope_index.uniqueInteger(), scope.file.uniqueInteger(), node_scope_index.uniqueInteger(), analyzer.module.scopes.get(node_scope_index).file.uniqueInteger(), tokenBytes(analyzer.getToken(scope_index, node_token), analyzer.getSourceFile(scope_index)) });
        }
    }

    fn getArguments(analyzer: *Analyzer, scope_index: Scope.Index, node_index: Node.Index) !ArrayList(Node.Index) {
        var arguments = ArrayList(Node.Index){};
        const node = analyzer.getNode(scope_index, node_index);
        switch (node.id) {
            .compiler_intrinsic_two => {
                try arguments.append(analyzer.allocator, node.left);
                try arguments.append(analyzer.allocator, node.right);
            },
            else => |t| @panic(@tagName(t)),
        }

        return arguments;
    }

    fn resolveNode(analyzer: *Analyzer, value: *Value, scope_index: Scope.Index, expect_type: ExpectType, node_index: Node.Index) anyerror!void {
        const node = analyzer.getNode(scope_index, node_index);
        print("Resolving node #{}: {}\n", .{ node_index.uniqueInteger(), node });

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
                        if (@as(u32, @bitCast(type_boolean)) != @as(u32, @bitCast(expected_type))) {
                            @panic("TODO: compile error");
                        }
                    },
                    else => unreachable,
                }

                // TODO
                unreachable;

                // break :blk Values.getIndex(.bool_true);
            },
            .compiler_intrinsic_one, .compiler_intrinsic_two => blk: {
                const intrinsic_name = analyzer.tokenIdentifier(scope_index, node.token + 1);
                const intrinsic = data_structures.enumFromString(Intrinsic, intrinsic_name) orelse unreachable;
                print("Intrinsic: {s}\n", .{@tagName(intrinsic)});
                switch (intrinsic) {
                    .import => {
                        assert(node.id == .compiler_intrinsic_one);
                        const import_argument = analyzer.getNode(scope_index, node.left);
                        switch (import_argument.id) {
                            .string_literal => {
                                const import_name = analyzer.tokenStringLiteral(scope_index, import_argument.token);
                                const import_file = try analyzer.module.importFile(analyzer.allocator, analyzer.current_file, import_name);

                                if (import_file.file.is_new) {
                                    // TODO: fix error
                                    try analyzer.module.generateAbstractSyntaxTreeForFile(analyzer.allocator, import_file.file.ptr);
                                } else {
                                    unreachable;
                                }

                                break :blk .{
                                    .type = try analyzeFile(value, analyzer.allocator, analyzer.module, import_file.file.ptr, import_file.file.index),
                                };
                            },
                            else => unreachable,
                        }
                    },
                    .syscall => {
                        var argument_nodes = try analyzer.getArguments(scope_index, node_index);
                        print("Argument count: {}\n", .{argument_nodes.items.len});
                        if (argument_nodes.items.len > 0 and argument_nodes.items.len <= 6 + 1) {
                            const number_allocation = try analyzer.unresolvedAllocate(scope_index, .{
                                .flexible_integer = .{
                                    .byte_count = 8,
                                },
                            }, argument_nodes.items[0]);
                            const number = number_allocation.index;
                            assert(number.valid);
                            var arguments = std.mem.zeroes([6]Value.Index);
                            for (argument_nodes.items[1..], 0..) |argument_node_index, argument_index| {
                                const argument_allocation = try analyzer.unresolvedAllocate(scope_index, ExpectType.none, argument_node_index);
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
                }
                unreachable;
            },
            .function_definition => blk: {
                const function_prototype_index = try analyzer.functionPrototype(scope_index, node.left);

                const function_body = try analyzer.block(scope_index, .{
                    .type_index = analyzer.functionPrototypeReturnType(function_prototype_index),
                }, node.right);

                const function_allocation = try analyzer.module.functions.append(analyzer.allocator, .{
                    .prototype = function_prototype_index,
                    .body = function_body,
                });
                break :blk .{
                    .function = function_allocation.index,
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
                .int => |integer| blk: {
                    assert(expect_type != .none);
                    const int_type = switch (expect_type) {
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
                        else => |t| @panic(@tagName(t)),
                    };
                    break :blk .{
                        .integer = .{
                            .value = integer,
                            .type = int_type,
                        },
                    };
                },
                else => |t| @panic(@tagName(t)),
            },
            .call_one => blk: {
                const this_value_node_index = node.left;
                const this_value_allocation = try analyzer.unresolvedAllocate(scope_index, ExpectType.none, this_value_node_index);
                const value_type = switch (this_value_allocation.ptr.*) {
                    .function => |function_index| analyzer.module.function_prototypes.get(analyzer.module.functions.get(function_index).prototype).return_type,
                    else => |t| @panic(@tagName(t)),
                };

                const call_allocation = try analyzer.module.calls.append(analyzer.allocator, .{
                    .value = this_value_allocation.index,
                    .arguments = ArgumentList.Index.invalid,
                    .type = value_type,
                });
                break :blk .{
                    .call = call_allocation.index,
                };
            },
            .field_access => blk: {
                const left_allocation = try analyzer.unresolvedAllocate(scope_index, ExpectType.none, node.left);
                const identifier = analyzer.tokenIdentifier(scope_index, node.right.value);
                _ = identifier;
                switch (left_allocation.ptr.*) {
                    .type => |type_index| {
                        const left_type = analyzer.module.types.get(type_index);
                        switch (left_type.*) {
                            .@"struct" => |struct_index| {
                                const struct_type = analyzer.module.structs.get(struct_index);
                                const right_index = try analyzer.doIdentifier(struct_type.scope, ExpectType.none, node.right.value, scope_index);
                                const right_value = analyzer.module.values.get(right_index);
                                switch (right_value.*) {
                                    .function => break :blk right_value.*,
                                    else => unreachable,
                                }
                                print("Right: {}\n", .{right_value});
                                // struct_scope.declarations.get(identifier);

                                unreachable;
                            },
                            else => |t| @panic(@tagName(t)),
                        }
                        unreachable;
                    },
                    else => |t| @panic(@tagName(t)),
                }
                unreachable;
            },
            else => |t| @panic(@tagName(t)),
        };
    }

    fn functionPrototypeReturnType(analyzer: *Analyzer, function_prototype_index: Function.Prototype.Index) Type.Index {
        const function_prototype = analyzer.module.function_prototypes.get(function_prototype_index);
        return function_prototype.return_type;
    }

    fn functionPrototype(analyzer: *Analyzer, scope_index: Scope.Index, node_index: Node.Index) !Function.Prototype.Index {
        const node = analyzer.getNode(scope_index, node_index);
        switch (node.id) {
            .simple_function_prototype => {
                const arguments: ?[]const Field.Index = blk: {
                    if (node.left.get() == null) break :blk null;
                    const argument_node = analyzer.getNode(scope_index, node.left);
                    switch (argument_node.id) {
                        else => |t| @panic(@tagName(t)),
                    }
                };
                const return_type_node = analyzer.getNode(scope_index, node.right);
                const return_type: Type.Index = switch (return_type_node.id) {
                    .identifier => {
                        unreachable;
                    },
                    .keyword_noreturn => .{ .block = 0, .index = FixedTypeKeyword.offset + @intFromEnum(FixedTypeKeyword.noreturn) },
                    inline .signed_integer_type, .unsigned_integer_type => |int_type_signedness| blk: {
                        const bit_count: u16 = @intCast(return_type_node.left.value);
                        print("Bit count: {}\n", .{bit_count});
                        break :blk switch (bit_count) {
                            inline 8, 16, 32, 64 => |hardware_bit_count| Type.Index{
                                .block = 0,
                                .index = @ctz(hardware_bit_count) - @ctz(@as(u8, 8)) + switch (int_type_signedness) {
                                    .signed_integer_type => HardwareSignedIntegerType,
                                    .unsigned_integer_type => HardwareUnsignedIntegerType,
                                    else => unreachable,
                                }.offset,
                            },
                            else => unreachable,
                        };
                    },
                    else => |t| @panic(@tagName(t)),
                };

                const function_prototype_allocation = try analyzer.module.function_prototypes.append(analyzer.allocator, .{
                    .arguments = arguments,
                    .return_type = return_type,
                });

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
            else => |t| @panic(@tagName(t)),
        };

        if (nodes.len > 0) {
            const new_scope = try analyzer.allocateScope(.{
                .parent = parent_scope_index,
                .file = file_index,
            });
            const scope = new_scope.ptr;
            const scope_index = new_scope.index;

            const is_file = !parent_scope_index.valid;
            assert(is_file);

            const struct_allocation = try analyzer.module.structs.append(analyzer.allocator, .{
                .scope = new_scope.index,
            });
            const type_allocation = try analyzer.module.types.append(analyzer.allocator, .{
                .@"struct" = struct_allocation.index,
            });
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
                    const member = analyzer.getNode(scope_index, member_index);
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
                const member = analyzer.getNode(scope_index, member_index);
                const member_type = getContainerMemberType(member.id);
                const array_list = switch (member_type) {
                    .declaration => &declaration_nodes,
                    .field => &field_nodes,
                };
                array_list.appendAssumeCapacity(member_index);
            }

            for (declaration_nodes.items) |declaration_node_index| {
                const declaration_node = analyzer.getNode(scope_index, declaration_node_index);
                switch (declaration_node.id) {
                    .@"comptime" => {},
                    .simple_variable_declaration => _ = try analyzer.symbolDeclaration(scope_index, declaration_node_index, .global),
                    else => unreachable,
                }
            }

            // TODO: consider iterating over scope declarations instead?
            for (declaration_nodes.items) |declaration_node_index| {
                const declaration_node = analyzer.getNode(scope_index, declaration_node_index);
                switch (declaration_node.id) {
                    .@"comptime" => _ = try analyzer.comptimeBlock(scope_index, declaration_node_index),
                    .simple_variable_declaration => {},
                    else => |t| @panic(@tagName(t)),
                }
            }

            for (field_nodes.items) |field_index| {
                const field_node = analyzer.getNode(scope_index, field_index);
                _ = field_node;

                @panic("TODO: fields");
            }

            return type_allocation.index;
        } else {
            return Type.Index.invalid;
        }
    }

    fn symbolDeclaration(analyzer: *Analyzer, scope_index: Scope.Index, node_index: Node.Index, scope_type: ScopeType) !Declaration.Index {
        const declaration_node = analyzer.getNode(scope_index, node_index);
        assert(declaration_node.id == .simple_variable_declaration);
        assert(!declaration_node.left.valid);
        const mutability: Compilation.Mutability = switch (analyzer.getToken(scope_index, declaration_node.token).id) {
            .fixed_keyword_const => .@"const",
            .fixed_keyword_var => .@"var",
            else => |t| @panic(@tagName(t)),
        };
        const expected_identifier_token_index = declaration_node.token + 1;
        const expected_identifier_token = analyzer.getToken(scope_index, expected_identifier_token_index);
        if (expected_identifier_token.id != .identifier) {
            print("Error: found: {}", .{expected_identifier_token.id});
            @panic("Expected identifier");
        }
        // TODO: Check if it is a keyword

        const identifier_index = try analyzer.identifierFromToken(scope_index, expected_identifier_token_index);

        const declaration_name = analyzer.tokenIdentifier(scope_index, expected_identifier_token_index);
        // Check if the symbol name is already occupied in the same scope
        const scope = analyzer.module.scopes.get(scope_index);
        const scope_lookup = try scope.declarations.getOrPut(analyzer.allocator, identifier_index);
        if (scope_lookup.found_existing) {
            std.debug.panic("Existing name in lookup: {s}", .{declaration_name});
        }

        // Check if the symbol name is already occupied in parent scopes
        var upper_scope_index = scope.parent;

        while (upper_scope_index.valid) {
            @panic("TODO: upper scope");
        }
        assert(declaration_node.right.valid);

        const declaration_allocation = try analyzer.module.declarations.append(analyzer.allocator, .{
            .name = declaration_name,
            .scope_type = scope_type,
            .mutability = mutability,
            .init_value = (try analyzer.module.values.append(analyzer.allocator, .{
                .unresolved = .{
                    .node_index = declaration_node.right,
                },
            })).index,
        });

        scope_lookup.value_ptr.* = declaration_allocation.index;

        return declaration_allocation.index;
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

    fn identifierFromToken(analyzer: *Analyzer, scope_index: Scope.Index, token_index: Token.Index) !u32 {
        const identifier = analyzer.tokenIdentifier(scope_index, token_index);
        const key: u32 = @truncate(std.hash.Wyhash.hash(0, identifier));

        const lookup_result = try analyzer.module.string_table.getOrPut(analyzer.allocator, key);

        if (lookup_result.found_existing) {
            return lookup_result.key_ptr.*;
        } else {
            return key;
        }
    }

    fn tokenIdentifier(analyzer: *Analyzer, scope_index: Scope.Index, token_index: Token.Index) []const u8 {
        const token = analyzer.getToken(scope_index, token_index);
        assert(token.id == .identifier);
        const source_file = analyzer.getSourceFile(scope_index);
        const identifier = tokenBytes(token, source_file);

        return identifier;
    }

    fn tokenBytes(token: Token, source_code: []const u8) []const u8 {
        return source_code[token.start..][0..token.len];
    }

    fn numberBytes(analyzer: *Analyzer, scope_index: Scope.Index, token_index: Token.Index) []const u8 {
        const token = analyzer.getToken(scope_index, token_index);
        assert(token.id == .number_literal);
        const source_file = analyzer.getSourceFile(scope_index);
        const bytes = tokenBytes(token, source_file);

        return bytes;
    }

    fn tokenStringLiteral(analyzer: *Analyzer, scope_index: Scope.Index, token_index: Token.Index) []const u8 {
        const token = analyzer.getToken(scope_index, token_index);
        assert(token.id == .string_literal);
        const source_file = analyzer.getSourceFile(scope_index);
        // Eat double quotes
        const string_literal = tokenBytes(token, source_file)[1..][0 .. token.len - 2];

        return string_literal;
    }

    fn allocateScope(analyzer: *Analyzer, scope_value: Scope) !Scope.Allocation {
        return analyzer.module.scopes.append(analyzer.allocator, scope_value);
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
        .type_index = type_boolean,
    };

    const FlexibleInteger = struct {
        byte_count: u8,
        sign: ?bool = null,
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

pub fn initialize(compilation: *Compilation, module: *Module, package: *Package, file_index: File.Index) !Type.Index {
    _ = file_index;
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

    const value_allocation = try module.values.append(compilation.base_allocator, .{
        .unresolved = .{
            .node_index = .{ .value = 0 },
        },
    });

    const result = analyzeExistingPackage(value_allocation.ptr, compilation, module, package);

    var decl_iterator = module.declarations.iterator();
    while (decl_iterator.nextPointer()) |decl| {
        if (equal(u8, decl.name, "_start")) {
            const value = module.values.get(decl.init_value);
            module.entry_point = switch (value.*) {
                .function => |function_index| function_index.uniqueInteger(),
                else => |t| @panic(@tagName(t)),
            };
            break;
        }
    } else {
        @panic("Entry point not found");
    }

    return result;
}

pub fn analyzeExistingPackage(value: *Value, compilation: *Compilation, module: *Module, package: *Package) !Type.Index {
    const package_import = try module.importPackage(compilation.base_allocator, package);
    assert(!package_import.file.is_new);
    const package_file = package_import.file.ptr;
    const file_index = package_import.file.index;

    return try analyzeFile(value, compilation.base_allocator, module, package_file, file_index);
}

pub fn analyzeFile(value: *Value, allocator: Allocator, module: *Module, file: *File, file_index: File.Index) !Type.Index {
    assert(value.* == .unresolved);
    assert(file.status == .parsed);

    var analyzer = Analyzer{
        .current_file = file_index,
        .allocator = allocator,
        .module = module,
    };

    var buffer = [2]Node.Index{
        Node.Index.invalid,
        Node.Index.invalid,
    };
    _ = buffer;

    const result = try analyzer.structType(value, Scope.Index.invalid, .{ .value = 0 }, file_index);
    return result;
}
