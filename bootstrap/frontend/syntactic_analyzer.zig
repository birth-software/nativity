const std = @import("std");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;
const equal = std.mem.eql;

const data_structures = @import("../data_structures.zig");
const ArrayList = data_structures.ArrayList;
const enumFromString = data_structures.enumFromString;
const HashMap = data_structures.HashMap;

const lexical_analyzer = @import("lexical_analyzer.zig");
const Token = lexical_analyzer.Token;

const Compilation = @import("../Compilation.zig");
const File = Compilation.File;
const log = Compilation.log;
const logln = Compilation.logln;

pub const Result = struct {
    nodes: ArrayList(Node),
    node_lists: ArrayList(Node.List),
    time: u64,
};

pub const Options = packed struct {
    is_comptime: bool,
};

pub const Logger = enum {
    token_errors,
    symbol_declaration,
    node_creation,
    main_node,
    container_members,
    block,
    assign,
    suffix,
    precedence,
    @"switch",

    pub var bitset = std.EnumSet(Logger).initMany(&.{
        .token_errors,
        .symbol_declaration,
        .node_creation,
        .main_node,
        .container_members,
        .block,
        .assign,
        .suffix,
        .precedence,
        .@"switch",
    });
};

// TODO: pack it to be more efficient
pub const Node = struct {
    left: Node.Index,
    right: Node.Index,
    token: Token.Index,
    id: Id,

    pub const List = ArrayList(Node.Index);

    pub const Index = packed struct(u32) {
        value: u31,
        invalid: bool = false,

        pub const invalid = Index{
            .value = 0,
            .invalid = true,
        };

        pub fn get(index: Index) ?u32 {
            return if (index.invvalid) null else index.value;
        }

        pub fn unwrap(index: Index) u32 {
            assert(!index.invalid);
            return index.value;
        }

        pub fn uniqueInteger(index: Index) u32 {
            assert(!index.invalid);
            return index.value;
        }
    };

    pub const Range = struct {
        start: u32,
        end: u32,
    };

    pub const Id = enum {
        main,
        identifier,
        number,
        @"return",
        function_declaration_no_arguments,
        container_declaration,
        string_literal,
        simple_symbol_declaration,
        assign,
        @"comptime",
        node_list,
        simple_while,
        simple_function_prototype,
        function_definition,
        keyword_noreturn,
        keyword_true,
        number_literal,
        @"unreachable",
        field_access,
        comptime_block,
        block,
        unsigned_integer_type,
        signed_integer_type,
        slice_type,
        const_slice_type,
        array_type,
        argument_declaration,
        compiler_intrinsic,
        ssize_type,
        usize_type,
        void_type,
        call,
        const_many_pointer_type,
        many_pointer_type,
        zero_terminated_const_many_pointer_type,
        zero_terminated_many_pointer_type,
        enum_literal,
        address_of,
        pointer_dereference,
        keyword_false,
        compare_equal,
        compare_not_equal,
        compare_less_than,
        compare_greater_than,
        compare_less_or_equal,
        compare_greater_or_equal,
        @"if",
        if_else,
        @"switch",
        switch_case,
        enum_type,
        enum_field,
        extern_qualifier,
        export_qualifier,
        function_prototype,
        add,
        sub,
        bit_and,
        bit_xor,
        expression_group,
        bit_or,
        multiply,
        divide,
        shift_left,
        shift_right,
        bool_type,
        named_argument,
        optional_type,
        container_field,
        struct_type,
        container_literal,
        field_initialization,
        boolean_not,
        null_literal,
        if_else_payload,
        if_payload,
        discard,
        slice,
        range,
        negation,
        anonymous_container_literal,
        const_single_pointer_type,
        single_pointer_type,
        indexed_access,
        calling_convention,
        assembly_register,
        assembly_statement,
        assembly_block,
        for_condition,
        for_loop,
        add_assign,
        undefined,
    };
};

const Error = error{
    unexpected_token,
    not_implemented,
    OutOfMemory,
};

const Analyzer = struct {
    tokens: []const Token,
    token_i: u32 = 0,
    nodes: ArrayList(Node) = .{},
    source_file: []const u8,
    file_index: File.Index,
    allocator: Allocator,
    node_lists: ArrayList(Node.List) = .{},

    fn expectToken(analyzer: *Analyzer, token_id: Token.Id) !u32 {
        const token_i = analyzer.token_i;
        const token = analyzer.tokens[token_i];
        const is_expected_token = token.id == token_id;
        if (is_expected_token) {
            analyzer.token_i += 1;
            const result = token_i;
            return result;
        } else {
            logln(.parser, .token_errors, "Unexpected token {s} when expected {s}\n| |\n v \n```\n{s}\n```", .{ @tagName(token.id), @tagName(token_id), analyzer.source_file[token.start..] });
            @breakpoint();
            return error.unexpected_token;
        }
    }

    fn bytes(analyzer: *const Analyzer, token_index: Token.Index) []const u8 {
        const token = analyzer.tokens[token_index];
        return analyzer.source_file[token.start..][0..token.len];
    }

    fn symbolDeclaration(analyzer: *Analyzer) anyerror!Node.Index {
        const first = analyzer.token_i;
        assert(analyzer.tokens[first].id == .fixed_keyword_var or analyzer.tokens[first].id == .fixed_keyword_const);
        analyzer.token_i += 1;
        const declaration_name_token = try analyzer.expectToken(.identifier);
        const declaration_name = analyzer.bytes(declaration_name_token);
        logln(.parser, .symbol_declaration, "Starting parsing declaration \"{s}\"", .{declaration_name});

        logln(.parser, .symbol_declaration, "Current token: {}", .{analyzer.tokens[analyzer.token_i].id});

        const type_node_index = switch (analyzer.tokens[analyzer.token_i].id) {
            .colon => blk: {
                analyzer.token_i += 1;
                break :blk try analyzer.typeExpression();
            },
            else => Node.Index.invalid,
        };

        _ = try analyzer.expectToken(.equal);

        const init_node_index = try analyzer.expression();

        const init_node = analyzer.nodes.items[init_node_index.unwrap()];
        switch (init_node.id) {
            .function_definition => {},
            else => _ = try analyzer.expectToken(.semicolon),
        }

        // TODO:
        const declaration = Node{
            .id = .simple_symbol_declaration,
            .token = first,
            .left = type_node_index,
            .right = init_node_index,
        };

        logln(.parser, .symbol_declaration, "Adding declaration \"{s}\" with init node of type: {s}", .{ declaration_name, @tagName(init_node.id) });
        // if (analyzer.token_i < analyzer.tokens.len) {
        //     const first_token = analyzer.tokens[first];
        //     const last_token = analyzer.tokens[analyzer.token_i];
        //     const declaration_source_start = first_token.start;
        //     const declaration_source_end = last_token.start;
        //
        //     logln("[ALL]\n", .{});
        //     logln("Source file ({} bytes) :\n```\n{s}\n```\n", .{ analyzer.source_file.len, analyzer.source_file });
        //
        //     logln("[BEFORE]\n", .{});
        //
        //     logln("Tokens before the declaration: ", .{});
        //     for (analyzer.tokens[0..first]) |t| {
        //         logln("{s} ", .{@tagName(t.id)});
        //     }
        //     logln("\n", .{});
        //     logln("Source before the declaration:\n```\n{s}\n```\n", .{analyzer.source_file[0..analyzer.tokens[first].start]});
        //     logln("[DECLARATION]\n", .{});
        //
        //     logln("First token: {}\n", .{first_token});
        //     logln("Last token: {}\n", .{last_token});
        //
        //     logln("Tokens including declaration ([{}-{}])", .{ first, analyzer.token_i });
        //     for (analyzer.tokens[first..][0 .. analyzer.token_i - first]) |t| {
        //         logln("{s} ", .{@tagName(t.id)});
        //     }
        //     logln("\n", .{});
        //
        //     logln("Source for the declaration:\n```\n{s}\n```\n", .{analyzer.source_file[declaration_source_start..declaration_source_end]});
        //     logln("[AFTER]\n", .{});
        //
        //     // TODO
        //     // print("Tokens for file #{}\n", .{analyzer.
        //     // for (analyzer.tokens[
        // }

        return try analyzer.addNode(declaration);
    }

    fn function(analyzer: *Analyzer) !Node.Index {
        const token = analyzer.token_i;
        assert(analyzer.tokens[token].id == .fixed_keyword_fn);
        analyzer.token_i += 1;
        const function_prototype = try analyzer.functionPrototype();
        const is_comptime = false;
        _ = is_comptime;
        return switch (analyzer.tokens[analyzer.token_i].id) {
            .left_brace => try analyzer.addNode(.{
                .id = .function_definition,
                .token = token,
                .left = function_prototype,
                .right = try analyzer.block(.{ .is_comptime = false }),
            }),
            .semicolon => function_prototype,
            else => |t| @panic(@tagName(t)),
        };
    }

    fn functionPrototype(analyzer: *Analyzer) !Node.Index {
        const token = analyzer.token_i;
        assert(analyzer.tokens[token].id == .left_parenthesis);
        const arguments = try analyzer.argumentList(.left_parenthesis, .right_parenthesis);
        const return_type = try analyzer.typeExpression();

        const simple_function_prototype = try analyzer.addNode(.{
            .id = .simple_function_prototype,
            .token = token,
            .left = arguments,
            .right = return_type,
        });

        return switch (analyzer.tokens[analyzer.token_i].id) {
            .semicolon,
            .left_brace,
            .comma,
            => simple_function_prototype,
            else => blk: {
                var list = Node.List{};

                while (true) {
                    const attribute_token = analyzer.token_i;
                    const attribute = switch (analyzer.tokens[attribute_token].id) {
                        .semicolon,
                        .left_brace,
                        => break,
                        .fixed_keyword_extern => b: {
                            const result = try analyzer.addNode(.{
                                .id = .extern_qualifier,
                                .token = attribute_token,
                                .left = Node.Index.invalid,
                                .right = Node.Index.invalid,
                            });
                            analyzer.token_i += 1;
                            break :b result;
                        },
                        .fixed_keyword_export => b: {
                            const result = try analyzer.addNode(.{
                                .id = .export_qualifier,
                                .token = attribute_token,
                                .left = Node.Index.invalid,
                                .right = Node.Index.invalid,
                            });
                            analyzer.token_i += 1;
                            break :b result;
                        },
                        .fixed_keyword_cc => b: {
                            analyzer.token_i += 1;
                            _ = try analyzer.expectToken(.left_parenthesis);
                            const calling_conv_expression = try analyzer.expression();
                            _ = try analyzer.expectToken(.right_parenthesis);

                            const result = try analyzer.addNode(.{
                                .id = .calling_convention,
                                .token = attribute_token,
                                .left = calling_conv_expression,
                                .right = Node.Index.invalid,
                            });
                            break :b result;
                        },
                        else => |t| @panic(@tagName(t)),
                    };

                    try list.append(analyzer.allocator, attribute);
                }

                break :blk try analyzer.addNode(.{
                    .id = .function_prototype,
                    .token = token,
                    .left = simple_function_prototype,
                    .right = try analyzer.nodeList(list),
                });
            },
        };
    }

    fn argumentList(analyzer: *Analyzer, maybe_start_token: ?Token.Id, end_token: Token.Id) !Node.Index {
        if (maybe_start_token) |start_token| {
            _ = try analyzer.expectToken(start_token);
        }

        var list = ArrayList(Node.Index){};

        var foo = false;
        while (analyzer.tokens[analyzer.token_i].id != end_token) {
            const identifier = try analyzer.expectToken(.identifier);
            _ = try analyzer.expectToken(.colon);
            const type_expression = try analyzer.typeExpression();
            // const type_expression_node = analyzer.nodes.items[type_expression.unwrap()];
            // _ = type_expression_node;
            // logln("Type expression node: {}", .{type_expression_node});
            foo = true;

            if (analyzer.tokens[analyzer.token_i].id == .comma) {
                analyzer.token_i += 1;
            }

            try list.append(analyzer.allocator, try analyzer.addNode(.{
                .id = .argument_declaration,
                .token = identifier,
                .left = type_expression,
                .right = Node.Index.invalid,
            }));
        }

        _ = try analyzer.expectToken(end_token);

        if (list.items.len != 0) {
            return try analyzer.nodeList(list);
        } else {
            return Node.Index.invalid;
        }
    }

    fn assignExpressionStatement(analyzer: *Analyzer) !Node.Index {
        const result = try analyzer.assignExpression();
        _ = try analyzer.expectToken(.semicolon);
        return result;
    }

    fn block(analyzer: *Analyzer, options: Options) anyerror!Node.Index {
        const left_brace = try analyzer.expectToken(.left_brace);
        var list = ArrayList(Node.Index){};

        while (analyzer.tokens[analyzer.token_i].id != .right_brace) {
            const first_statement_token = analyzer.tokens[analyzer.token_i];
            logln(.parser, .block, "First statement token: {s}", .{@tagName(first_statement_token.id)});
            const statement_index = switch (first_statement_token.id) {
                .identifier => switch (analyzer.tokens[analyzer.token_i + 1].id) {
                    .colon => {
                        unreachable;
                    },
                    else => try analyzer.assignExpressionStatement(),
                },
                .fixed_keyword_unreachable,
                .fixed_keyword_return,
                .discard,
                => try analyzer.assignExpressionStatement(),

                .fixed_keyword_while => try analyzer.whileExpression(options),
                .fixed_keyword_switch => try analyzer.switchExpression(),
                .fixed_keyword_if => try analyzer.ifExpression(),
                .fixed_keyword_for => try analyzer.forExpression(),
                .fixed_keyword_const,
                .fixed_keyword_var,
                => try analyzer.symbolDeclaration(),
                .hash => blk: {
                    const intrinsic = try analyzer.compilerIntrinsic();
                    _ = try analyzer.expectToken(.semicolon);
                    break :blk intrinsic;
                },
                else => |t| @panic(@tagName(t)),
            };

            const node = analyzer.nodes.items[statement_index.unwrap()];
            logln(.parser, .block, "Adding statement: {s}", .{@tagName(node.id)});

            try list.append(analyzer.allocator, statement_index);
        }

        _ = try analyzer.expectToken(.right_brace);

        return try analyzer.addNode(.{
            .id = switch (options.is_comptime) {
                true => .comptime_block,
                false => .block,
            },
            .token = left_brace,
            .left = try analyzer.nodeList(list),
            .right = Node.Index.invalid,
        });
    }

    fn whileExpression(analyzer: *Analyzer, options: Options) anyerror!Node.Index {
        const while_identifier_index = try analyzer.expectToken(.fixed_keyword_while);

        _ = try analyzer.expectToken(.left_parenthesis);
        // TODO:
        const while_condition = try analyzer.expression();
        _ = try analyzer.expectToken(.right_parenthesis);

        const while_block = try analyzer.block(options);

        return analyzer.addNode(.{
            .id = .simple_while,
            .token = while_identifier_index,
            .left = while_condition,
            .right = while_block,
        });
    }

    fn switchExpression(analyzer: *Analyzer) anyerror!Node.Index {
        logln(.parser, .@"switch", "Parsing switch...", .{});
        const switch_token = analyzer.token_i;
        analyzer.token_i += 1;
        _ = try analyzer.expectToken(.left_parenthesis);
        const switch_expression = try analyzer.expression();
        _ = try analyzer.expectToken(.right_parenthesis);
        logln(.parser, .@"switch", "Parsed switch expression...", .{});
        _ = try analyzer.expectToken(.left_brace);

        var list = Node.List{};

        while (analyzer.tokens[analyzer.token_i].id != .right_brace) {
            const case_token = analyzer.token_i;
            logln(.parser, .@"switch", "Parsing switch case...", .{});
            const case_node = switch (analyzer.tokens[case_token].id) {
                .fixed_keyword_else => blk: {
                    analyzer.token_i += 1;
                    break :blk Node.Index.invalid;
                },
                else => blk: {
                    var array_list = Node.List{};
                    while (true) {
                        try array_list.append(analyzer.allocator, try analyzer.expression());
                        switch (analyzer.tokens[analyzer.token_i].id) {
                            .comma => analyzer.token_i += 1,
                            .equal => switch (analyzer.tokens[analyzer.token_i + 1].id) {
                                .greater => break,
                                else => {},
                            },
                            else => {},
                        }
                    }

                    break :blk switch (array_list.items.len) {
                        0 => unreachable,
                        1 => array_list.items[0],
                        else => try analyzer.nodeList(array_list),
                    };
                },
            };
            _ = try analyzer.expectToken(.equal);
            _ = try analyzer.expectToken(.greater);
            const is_left_brace = analyzer.tokens[analyzer.token_i].id == .left_brace;
            const expr = switch (is_left_brace) {
                true => try analyzer.block(.{
                    .is_comptime = false,
                }),
                false => try analyzer.assignExpression(),
            };

            _ = try analyzer.expectToken(.comma);

            const node = try analyzer.addNode(.{
                .id = .switch_case,
                .token = case_token,
                .left = case_node,
                .right = expr,
            });

            try list.append(analyzer.allocator, node);
        }

        _ = try analyzer.expectToken(.right_brace);

        return try analyzer.addNode(.{
            .id = .@"switch",
            .token = switch_token,
            .left = switch_expression,
            .right = try analyzer.nodeList(list),
        });
    }

    fn ifExpression(analyzer: *Analyzer) anyerror!Node.Index {
        const if_token = analyzer.token_i;
        analyzer.token_i += 1;

        _ = try analyzer.expectToken(.left_parenthesis);
        const if_condition = try analyzer.expression();
        _ = try analyzer.expectToken(.right_parenthesis);

        const payload = if (analyzer.tokens[analyzer.token_i].id == .vertical_bar) blk: {
            analyzer.token_i += 1;
            const payload_node = switch (analyzer.tokens[analyzer.token_i].id) {
                .identifier => try analyzer.identifierNode(),
                .discard => try analyzer.discardNode(),
                else => unreachable,
            };
            _ = try analyzer.expectToken(.vertical_bar);
            break :blk payload_node;
        } else Node.Index.invalid;

        const if_block = try analyzer.block(.{ .is_comptime = false });

        const if_node = try analyzer.addNode(.{
            .id = .@"if",
            .token = if_token,
            .left = if_condition,
            .right = if_block,
        });

        const result = switch (analyzer.tokens[analyzer.token_i].id) {
            .fixed_keyword_else => blk: {
                analyzer.token_i += 1;

                break :blk try analyzer.addNode(.{
                    .id = .if_else,
                    .token = if_token,
                    .left = if_node,
                    .right = try analyzer.expression(),
                });
            },
            else => if_node,
        };

        if (payload.invalid) {
            return result;
        } else {
            return try analyzer.addNode(.{
                .id = switch (result.value == if_node.value) {
                    true => .if_payload,
                    false => .if_else_payload,
                },
                .token = if_token,
                .left = result,
                .right = payload,
            });
        }
    }

    fn forExpression(analyzer: *Analyzer) !Node.Index {
        const token = try analyzer.expectToken(.fixed_keyword_for);
        _ = try analyzer.expectToken(.left_parenthesis);
        const expression_token = analyzer.token_i;
        const first = try analyzer.expression();
        const ForExpression = struct {
            node_index: Node.Index,
            expected_payload_count: usize,
        };
        const for_expression = switch (analyzer.tokens[analyzer.token_i].id) {
            .period => switch (analyzer.tokens[analyzer.token_i + 1].id) {
                .period => blk: {
                    analyzer.token_i += 2;
                    const second = try analyzer.expression();

                    break :blk ForExpression{
                        .node_index = try analyzer.addNode(.{
                            .id = .range,
                            .token = expression_token,
                            .left = first,
                            .right = second,
                        }),
                        .expected_payload_count = 1,
                    };
                },
                else => |t| @panic(@tagName(t)),
            },
            else => |t| @panic(@tagName(t)),
        };

        _ = try analyzer.expectToken(.right_parenthesis);

        _ = try analyzer.expectToken(.vertical_bar);

        var payload_nodes = ArrayList(Node.Index){};
        while (analyzer.tokens[analyzer.token_i].id != .vertical_bar) {
            const payload_token = analyzer.token_i;
            const id: Node.Id = switch (analyzer.tokens[payload_token].id) {
                .identifier => .identifier,
                .discard => .discard,
                else => |t| @panic(@tagName(t)),
            };

            analyzer.token_i += 1;

            switch (analyzer.tokens[analyzer.token_i].id) {
                .vertical_bar => {},
                .comma => analyzer.token_i += 1,
                else => |t| @panic(@tagName(t)),
            }

            try payload_nodes.append(analyzer.allocator, try analyzer.addNode(.{
                .id = id,
                .token = payload_token,
                .left = Node.Index.invalid,
                .right = Node.Index.invalid,
            }));
        }

        _ = try analyzer.expectToken(.vertical_bar);

        if (payload_nodes.items.len != for_expression.expected_payload_count) {
            unreachable;
        }

        const for_condition_node = try analyzer.addNode(.{
            .id = .for_condition,
            .token = token,
            .left = for_expression.node_index,
            .right = try analyzer.nodeList(payload_nodes),
        });

        const for_content_node = switch (analyzer.tokens[analyzer.token_i].id) {
            .left_brace => try analyzer.block(.{
                .is_comptime = false,
            }),
            else => blk: {
                const for_content_expression = try analyzer.expression();
                _ = try analyzer.expectToken(.semicolon);
                break :blk for_content_expression;
            },
        };

        const for_node = try analyzer.addNode(.{
            .id = .for_loop,
            .token = token,
            .left = for_condition_node,
            .right = for_content_node,
        });

        return for_node;
    }

    fn assignExpression(analyzer: *Analyzer) !Node.Index {
        const left = try analyzer.expression();
        const expression_token = analyzer.token_i;
        const expression_id: Node.Id = switch (analyzer.tokens[expression_token].id) {
            .semicolon, .comma => return left,
            .equal => .assign,
            .plus => switch (analyzer.tokens[analyzer.token_i + 1].id) {
                .equal => blk: {
                    analyzer.token_i += 1;
                    break :blk .add_assign;
                },
                else => |t| @panic(@tagName(t)),
            },
            else => |t| @panic(@tagName(t)),
        };

        analyzer.token_i += 1;

        const right = try analyzer.expression();

        const node = Node{
            .id = expression_id,
            .token = expression_token,
            .left = left,
            .right = right,
        };

        logln(.parser, .assign, "assign:\nleft: {}.\nright: {}", .{ node.left, node.right });
        return try analyzer.addNode(node);
    }

    fn parseAsmOperand(analyzer: *Analyzer) !Node.Index {
        const token = analyzer.token_i;
        const result = switch (analyzer.tokens[token].id) {
            .identifier => try analyzer.addNode(.{
                .id = .assembly_register,
                .token = blk: {
                    analyzer.token_i += 1;
                    break :blk token;
                },
                .left = Node.Index.invalid,
                .right = Node.Index.invalid,
            }),
            .number_literal => blk: {
                analyzer.token_i += 1;
                break :blk analyzer.addNode(.{
                    .id = .number_literal,
                    .token = token,
                    .left = Node.Index.invalid,
                    .right = Node.Index.invalid,
                });
            },
            .left_brace => blk: {
                analyzer.token_i += 1;
                const result = try analyzer.expression();
                _ = try analyzer.expectToken(.right_brace);
                break :blk result;
            },
            else => |t| @panic(@tagName(t)),
        };
        return result;
    }

    fn compilerIntrinsic(analyzer: *Analyzer) !Node.Index {
        const hash = try analyzer.expectToken(.hash);
        const intrinsic_token = try analyzer.expectToken(.identifier);
        _ = try analyzer.expectToken(.left_parenthesis);

        if (equal(u8, analyzer.bytes(intrinsic_token), "asm")) {
            _ = try analyzer.expectToken(.left_brace);
            var statements = ArrayList(Node.Index){};

            while (analyzer.tokens[analyzer.token_i].id != .right_brace) {
                const instruction_token = try analyzer.expectToken(.identifier);
                var operand_list = ArrayList(Node.Index){};

                while (analyzer.tokens[analyzer.token_i].id != .semicolon) {
                    const asm_operand = try analyzer.parseAsmOperand();
                    switch (analyzer.tokens[analyzer.token_i].id) {
                        .semicolon => {},
                        .comma => analyzer.token_i += 1,
                        else => |t| @panic(@tagName(t)),
                    }
                    try operand_list.append(analyzer.allocator, asm_operand);
                }

                _ = try analyzer.expectToken(.semicolon);

                try statements.append(analyzer.allocator, try analyzer.addNode(.{
                    .id = .assembly_statement,
                    .token = instruction_token,
                    .left = try analyzer.nodeList(operand_list),
                    .right = Node.Index.invalid,
                }));
            }
            _ = try analyzer.expectToken(.right_brace);
            _ = try analyzer.expectToken(.right_parenthesis);

            return try analyzer.addNode(.{
                .id = .assembly_block,
                .token = hash,
                .left = try analyzer.nodeList(statements),
                .right = Node.Index.invalid,
            });
        } else {
            var list = ArrayList(Node.Index){};
            while (analyzer.tokens[analyzer.token_i].id != .right_parenthesis) {
                const parameter = try analyzer.expression();
                try list.append(analyzer.allocator, parameter);

                switch (analyzer.tokens[analyzer.token_i].id) {
                    .comma => analyzer.token_i += 1,
                    .right_parenthesis => continue,
                    else => unreachable,
                }
            }

            // Consume the right parenthesis
            analyzer.token_i += 1;

            return try analyzer.addNode(.{
                .id = .compiler_intrinsic,
                .token = hash,
                .left = try analyzer.nodeList(list),
                .right = Node.Index.invalid,
            });
        }
    }

    fn expression(analyzer: *Analyzer) anyerror!Node.Index {
        return try analyzer.expressionPrecedence(0);
    }

    const PrecedenceOperator = enum {
        compare_equal,
        compare_not_equal,
        compare_less_than,
        compare_greater_than,
        compare_less_or_equal,
        compare_greater_or_equal,
        add,
        sub,
        bit_and,
        bit_xor,
        bit_or,
        multiply,
        divide,
        shift_left,
        shift_right,
    };

    const operator_precedence = std.EnumArray(PrecedenceOperator, i32).init(.{
        .compare_equal = 30,
        .compare_not_equal = 30,
        .compare_less_than = 30,
        .compare_greater_than = 30,
        .compare_less_or_equal = 30,
        .compare_greater_or_equal = 30,
        .add = 60,
        .sub = 60,
        .bit_and = 40,
        .bit_xor = 40,
        .bit_or = 40,
        .multiply = 70,
        .divide = 70,
        .shift_left = 50,
        .shift_right = 50,
    });

    const operator_associativity = std.EnumArray(PrecedenceOperator, Associativity).init(.{
        .compare_equal = .none,
        .compare_not_equal = .none,
        .compare_less_than = .none,
        .compare_greater_than = .none,
        .compare_less_or_equal = .none,
        .compare_greater_or_equal = .none,
        .add = .left,
        .sub = .left,
        .bit_and = .left,
        .bit_xor = .left,
        .bit_or = .left,
        .multiply = .left,
        .divide = .left,
        .shift_left = .left,
        .shift_right = .left,
    });

    const operator_node_id = std.EnumArray(PrecedenceOperator, Node.Id).init(.{
        .compare_equal = .compare_equal,
        .compare_not_equal = .compare_not_equal,
        .compare_greater_than = .compare_greater_than,
        .compare_less_than = .compare_less_than,
        .compare_greater_or_equal = .compare_greater_or_equal,
        .compare_less_or_equal = .compare_less_or_equal,
        .add = .add,
        .sub = .sub,
        .bit_and = .bit_and,
        .bit_xor = .bit_xor,
        .bit_or = .bit_or,
        .multiply = .multiply,
        .divide = .divide,
        .shift_left = .shift_left,
        .shift_right = .shift_right,
    });

    fn expressionPrecedence(analyzer: *Analyzer, minimum_precedence: i32) !Node.Index {
        var result = try analyzer.prefixExpression();
        if (!result.invalid) {
            const prefix_node = analyzer.nodes.items[result.unwrap()];
            logln(.parser, .precedence, "Prefix: {}", .{prefix_node.id});
        }

        var banned_precedence: i32 = -1;

        while (analyzer.token_i < analyzer.tokens.len) {
            const token = analyzer.tokens[analyzer.token_i];
            // logln("Looping in expression precedence with token {}", .{token});
            const operator: PrecedenceOperator = switch (token.id) {
                .semicolon,
                .right_parenthesis,
                .right_brace,
                .right_bracket,
                .comma,
                .fixed_keyword_const,
                .fixed_keyword_var,
                .fixed_keyword_return,
                .identifier,
                => break,
                else => blk: {
                    const next_token_index = analyzer.token_i + 1;
                    if (next_token_index < analyzer.tokens.len) {
                        const next_token_id = analyzer.tokens[next_token_index].id;
                        const next_to_next_token_id = analyzer.tokens[next_token_index + 1].id;
                        break :blk switch (token.id) {
                            .equal => switch (next_token_id) {
                                .equal => .compare_equal,
                                else => break,
                            },
                            .bang => switch (next_token_id) {
                                .equal => .compare_not_equal,
                                else => unreachable,
                            },
                            .plus => switch (next_token_id) {
                                .plus => unreachable,
                                .equal => break,
                                else => .add,
                            },
                            .minus => switch (next_token_id) {
                                .minus => unreachable,
                                .equal => unreachable,
                                else => .sub,
                            },
                            .ampersand => switch (next_token_id) {
                                .equal => unreachable,
                                else => .bit_and,
                            },
                            .caret => switch (next_token_id) {
                                .equal => unreachable,
                                else => .bit_xor,
                            },
                            .vertical_bar => switch (next_token_id) {
                                .equal => unreachable,
                                else => .bit_or,
                            },
                            .asterisk => switch (next_token_id) {
                                .equal => unreachable,
                                else => .multiply,
                            },
                            .slash => switch (next_token_id) {
                                .equal => unreachable,
                                else => .divide,
                            },
                            .less => switch (next_token_id) {
                                .less => switch (next_to_next_token_id) {
                                    .equal => unreachable,
                                    else => .shift_left,
                                },
                                .equal => .compare_less_or_equal,
                                else => .compare_less_than,
                            },
                            .greater => switch (next_token_id) {
                                .greater => .shift_right,
                                .equal => .compare_greater_or_equal,
                                else => .compare_greater_than,
                            },
                            .period => switch (next_token_id) {
                                .period => break,
                                else => break,
                            },
                            else => |t| @panic(@tagName(t)),
                        };
                    } else {
                        unreachable;
                    }
                },
            };

            const precedence = operator_precedence.get(operator);
            if (precedence < minimum_precedence) {
                logln(.parser, .precedence, "Breaking for minimum_precedence", .{});
                break;
            }

            if (precedence < banned_precedence) {
                logln(.parser, .precedence, "Breaking for banned_precedence", .{});
                break;
            }

            const operator_token = analyzer.token_i;
            const extra_tokens: u32 = switch (operator) {
                .add,
                .sub,
                .bit_and,
                .bit_xor,
                .bit_or,
                .multiply,
                .divide,
                .compare_less_than,
                .compare_greater_than,
                => 0,
                .compare_equal,
                .compare_not_equal,
                .compare_less_or_equal,
                .compare_greater_or_equal,
                .shift_right,
                .shift_left,
                => 1,
                // else => |t| @panic(@tagName(t)),
            };
            analyzer.token_i += @as(u32, 1) + extra_tokens;

            // TODO: fix this
            const right = try analyzer.expressionPrecedence(precedence + 1);

            const node_id = operator_node_id.get(operator);

            result = try analyzer.addNode(.{
                .id = node_id,
                .token = operator_token,
                .left = result,
                .right = right,
            });

            const associativity = operator_associativity.get(operator);

            if (associativity == .none) {
                banned_precedence = precedence;
            }
        }

        return result;
    }

    fn prefixExpression(analyzer: *Analyzer) !Node.Index {
        const token = analyzer.token_i;
        // logln("Prefix...", .{});
        const node_id: Node.Id = switch (analyzer.tokens[token].id) {
            else => |pref| {
                _ = pref;
                return try analyzer.primaryExpression();
            },
            .bang => switch (analyzer.tokens[token + 1].id) {
                .equal => return try analyzer.primaryExpression(),
                else => .boolean_not,
            },
            .minus => .negation,
            .tilde => |t| @panic(@tagName(t)),
        };

        return try analyzer.addNode(.{
            .id = node_id,
            .token = blk: {
                analyzer.token_i += 1;
                break :blk token;
            },
            .left = try analyzer.prefixExpression(),
            .right = Node.Index.invalid,
        });
    }

    fn primaryExpression(analyzer: *Analyzer) !Node.Index {
        const result = switch (analyzer.tokens[analyzer.token_i].id) {
            .identifier => switch (analyzer.tokens[analyzer.token_i + 1].id) {
                .colon => unreachable,
                else => try analyzer.curlySuffixExpression(),
            },
            .string_literal,
            .number_literal,
            .fixed_keyword_true,
            .fixed_keyword_false,
            .fixed_keyword_unreachable,
            .fixed_keyword_null,
            .fixed_keyword_switch,
            .hash,
            .period,
            .left_parenthesis,
            .keyword_signed_integer,
            .keyword_unsigned_integer,
            .fixed_keyword_enum,
            .fixed_keyword_struct,
            .discard,
            .fixed_keyword_undefined,
            => try analyzer.curlySuffixExpression(),
            .fixed_keyword_fn => try analyzer.function(),
            .fixed_keyword_return => try analyzer.addNode(.{
                .id = .@"return",
                .token = blk: {
                    const token = analyzer.token_i;
                    analyzer.token_i += 1;
                    break :blk token;
                },
                .left = try analyzer.expression(),
                .right = Node.Index.invalid,
            }),
            // todo:?
            .left_brace => try analyzer.block(.{ .is_comptime = false }),
            else => |id| std.debug.panic("WARN: By default, calling curlySuffixExpression with {s}", .{@tagName(id)}),
        };

        return result;
    }

    fn curlySuffixExpression(analyzer: *Analyzer) !Node.Index {
        const left = try analyzer.typeExpression();

        return switch (analyzer.tokens[analyzer.token_i].id) {
            .left_brace => try analyzer.addNode(.{
                .id = .container_literal,
                .token = analyzer.token_i,
                .left = left,
                .right = try analyzer.fieldInitialization(),
            }),
            else => left,
        };
    }

    fn noReturn(analyzer: *Analyzer) !Node.Index {
        const token_i = analyzer.token_i;
        assert(analyzer.tokens[token_i].id == .fixed_keyword_noreturn);
        analyzer.token_i += 1;
        return try analyzer.addNode(.{
            .id = .keyword_noreturn,
            .token = token_i,
            .left = Node.Index.invalid,
            .right = Node.Index.invalid,
        });
    }

    fn boolLiteral(analyzer: *Analyzer) !Node.Index {
        const token_i = analyzer.token_i;
        analyzer.token_i += 1;
        return try analyzer.addNode(.{
            .id = switch (analyzer.tokens[token_i].id) {
                .fixed_keyword_true => .keyword_true,
                .fixed_keyword_false => .keyword_false,
                else => unreachable,
            },
            .token = token_i,
            .left = Node.Index.invalid,
            .right = Node.Index.invalid,
        });
    }

    fn pointerTypeExpression(analyzer: *Analyzer, arguments: struct {
        many: bool,
        zero_terminated: bool = false,
        start_token: Token.Index,
    }) !Node.Index {
        const is_const = analyzer.tokens[analyzer.token_i].id == .fixed_keyword_const;
        analyzer.token_i += @intFromBool(is_const);
        // TODO: handle correctly
        switch (analyzer.tokens[analyzer.token_i].id) {
            .fixed_keyword_fn => {},
            .identifier => {},
            .keyword_signed_integer, .keyword_unsigned_integer => {},
            else => |t| @panic(@tagName(t)),
        }

        const pointer_element_type = try analyzer.typeExpression();
        if (!arguments.many) {
            assert(!arguments.zero_terminated);
        }

        return try analyzer.addNode(.{
            .id = switch (arguments.many) {
                true => switch (arguments.zero_terminated) {
                    true => switch (is_const) {
                        true => .const_many_pointer_type,
                        false => .many_pointer_type,
                    },
                    false => switch (is_const) {
                        true => .zero_terminated_const_many_pointer_type,
                        false => .zero_terminated_many_pointer_type,
                    },
                },
                false => switch (is_const) {
                    true => .const_single_pointer_type,
                    false => .single_pointer_type,
                },
            },
            .token = arguments.start_token,
            .left = pointer_element_type,
            .right = Node.Index.invalid,
        });
    }

    fn typeExpression(analyzer: *Analyzer) anyerror!Node.Index {
        const first = analyzer.token_i;
        return switch (analyzer.tokens[first].id) {
            else => try analyzer.errorUnionExpression(),
            .question_mark => blk: {
                analyzer.token_i += 1;
                break :blk try analyzer.addNode(.{
                    .id = .optional_type,
                    .token = first,
                    .left = try analyzer.typeExpression(),
                    .right = Node.Index.invalid,
                });
            },
            .ampersand => blk: {
                analyzer.token_i += 1;
                break :blk try analyzer.pointerTypeExpression(.{
                    .many = false,
                    .start_token = first,
                });
            }, // pointer
            .bang => unreachable, // error
            .left_bracket => switch (analyzer.tokens[analyzer.token_i + 1].id) {
                .ampersand => blk: {
                    // many item pointer
                    analyzer.token_i += 2;
                    var zero_terminated: bool = false;
                    if (analyzer.tokens[analyzer.token_i].id == .colon) {
                        // TODO: parse properly
                        analyzer.token_i += 1;
                        zero_terminated = true;
                        analyzer.token_i += 1;
                    }
                    _ = try analyzer.expectToken(.right_bracket);

                    break :blk try analyzer.pointerTypeExpression(.{
                        .many = true,
                        .start_token = first,
                        .zero_terminated = zero_terminated,
                    });
                },
                .asterisk => @panic("Meant to use ampersand?"),
                else => {
                    const left_bracket = analyzer.token_i;
                    analyzer.token_i += 1;
                    // TODO: compute length
                    const length_expression = switch (analyzer.tokens[analyzer.token_i].id) {
                        .identifier => try analyzer.expression(),
                        .right_bracket => Node.Index.invalid,
                        else => |t| @panic(@tagName(t)),
                    };

                    _ = try analyzer.expectToken(.right_bracket);

                    const is_const = switch (length_expression.invalid) {
                        true => blk: {
                            const is_constant = analyzer.tokens[analyzer.token_i].id == .fixed_keyword_const;
                            analyzer.token_i += @intFromBool(is_constant);
                            break :blk is_constant;
                        },
                        false => false,
                    };

                    const type_expression = try analyzer.typeExpression();
                    const node = switch (length_expression.invalid) {
                        false => Node{
                            .id = .array_type,
                            .token = left_bracket,
                            .left = length_expression,
                            .right = type_expression,
                        },
                        true => Node{ // TODO: modifiers
                            .id = switch (is_const) {
                                true => .const_slice_type,
                                false => .slice_type,
                            },
                            .token = left_bracket,
                            .left = Node.Index.invalid,
                            .right = type_expression,
                        },
                    };

                    const node_index = try analyzer.addNode(node);

                    return node_index;
                },
            },
        };
    }

    fn errorUnionExpression(analyzer: *Analyzer) !Node.Index {
        const suffix_expression = try analyzer.suffixExpression();

        return switch (analyzer.tokens[analyzer.token_i].id) {
            .bang => switch (analyzer.tokens[analyzer.token_i + 1].id) {
                .equal => suffix_expression,
                else => unreachable,
            },
            else => suffix_expression,
        };
    }

    fn suffixExpression(analyzer: *Analyzer) !Node.Index {
        var result = try analyzer.primaryTypeExpression();

        while (true) {
            const suffix_operator = try analyzer.suffixOperator(result);
            if (!suffix_operator.invalid) {
                result = suffix_operator;
            } else {
                if (analyzer.tokens[analyzer.token_i].id == .left_parenthesis) {
                    const left_parenthesis = analyzer.token_i;
                    analyzer.token_i += 1;

                    var expression_list = ArrayList(Node.Index){};
                    while (analyzer.tokens[analyzer.token_i].id != .right_parenthesis) {
                        const current_token = analyzer.token_i;
                        var parameter = try analyzer.expression();
                        const parameter_node = analyzer.nodes.items[parameter.unwrap()];
                        logln(.parser, .suffix, "Paremeter node: {s}", .{@tagName(parameter_node.id)});
                        if (analyzer.tokens[analyzer.token_i].id == .equal) {
                            analyzer.token_i += 1;

                            parameter = try analyzer.addNode(.{
                                .id = .named_argument,
                                .token = current_token,
                                .left = parameter,
                                .right = try analyzer.expression(),
                            });
                        }
                        try expression_list.append(analyzer.allocator, parameter);
                        switch (analyzer.tokens[analyzer.token_i].id) {
                            .comma => analyzer.token_i += 1,
                            .right_parenthesis => {},
                            .colon, .right_brace, .right_bracket => unreachable,
                            else => |t| @panic(@tagName(t)),
                        }
                    }

                    _ = try analyzer.expectToken(.right_parenthesis);
                    // const is_comma = analyzer.tokens[analyzer.token_i].id == .comma;
                    return try analyzer.addNode(.{
                        .id = .call,
                        .token = left_parenthesis,
                        .left = result,
                        .right = try analyzer.nodeList(expression_list),
                    });
                } else {
                    return result;
                }
            }
        }

        unreachable;
    }

    fn fieldInitialization(analyzer: *Analyzer) !Node.Index {
        _ = try analyzer.expectToken(.left_brace);

        var list = ArrayList(Node.Index){};

        while (analyzer.tokens[analyzer.token_i].id != .right_brace) {
            const start_token = analyzer.token_i;
            switch (analyzer.tokens[start_token].id) {
                .period => {
                    analyzer.token_i += 1;
                    _ = try analyzer.expectToken(.identifier);
                    _ = try analyzer.expectToken(.equal);
                    const field_expression_initializer = try analyzer.expression();
                    _ = try analyzer.expectToken(.comma);

                    const field_initialization = try analyzer.addNode(.{
                        .id = .field_initialization,
                        .token = start_token,
                        .left = Node.Index.invalid,
                        .right = field_expression_initializer,
                    });

                    try list.append(analyzer.allocator, field_initialization);
                },
                else => |t| @panic(@tagName(t)),
            }
        }

        _ = try analyzer.expectToken(.right_brace);

        return try analyzer.nodeList(list);
    }

    fn discardNode(analyzer: *Analyzer) !Node.Index {
        const token = analyzer.token_i;
        assert(analyzer.tokens[token].id == .discard);
        analyzer.token_i += 1;
        return try analyzer.addNode(.{
            .id = .discard,
            .token = token,
            .left = Node.Index.invalid,
            .right = Node.Index.invalid,
        });
    }

    fn primaryTypeExpression(analyzer: *Analyzer) anyerror!Node.Index {
        const token_i = analyzer.token_i;
        const token = analyzer.tokens[token_i];

        return try switch (token.id) {
            .fixed_keyword_fn => blk: {
                analyzer.token_i += 1;
                break :blk analyzer.functionPrototype();
            },
            .string_literal => blk: {
                analyzer.token_i += 1;
                break :blk analyzer.addNode(.{
                    .id = .string_literal,
                    .token = token_i,
                    .left = Node.Index.invalid,
                    .right = Node.Index.invalid,
                });
            },
            .number_literal => blk: {
                analyzer.token_i += 1;
                break :blk analyzer.addNode(.{
                    .id = .number_literal,
                    .token = token_i,
                    .left = Node.Index.invalid,
                    .right = Node.Index.invalid,
                });
            },
            .identifier => analyzer.identifierNode(),
            .discard => try analyzer.discardNode(),
            .fixed_keyword_noreturn => analyzer.noReturn(),
            .fixed_keyword_true, .fixed_keyword_false => analyzer.boolLiteral(),
            .fixed_keyword_undefined => analyzer.addNode(.{
                .id = .undefined,
                .token = blk: {
                    analyzer.token_i += 1;
                    break :blk token_i;
                },
                .left = Node.Index.invalid,
                .right = Node.Index.invalid,
            }),
            .fixed_keyword_null => analyzer.addNode(.{
                .id = .null_literal,
                .token = blk: {
                    analyzer.token_i += 1;
                    break :blk token_i;
                },
                .left = Node.Index.invalid,
                .right = Node.Index.invalid,
            }),
            .fixed_keyword_unreachable => analyzer.addNode(.{
                .id = .@"unreachable",
                .token = blk: {
                    analyzer.token_i += 1;
                    break :blk token_i;
                },
                .left = Node.Index.invalid,
                .right = Node.Index.invalid,
            }),
            .hash => analyzer.compilerIntrinsic(),
            .fixed_keyword_bool => analyzer.addNode(.{
                .id = .bool_type,
                .token = blk: {
                    analyzer.token_i += 1;
                    break :blk token_i;
                },
                .left = Node.Index.invalid,
                .right = Node.Index.invalid,
            }),
            .keyword_unsigned_integer, .keyword_signed_integer => |signedness| analyzer.addNode(.{
                .id = switch (signedness) {
                    .keyword_unsigned_integer => .unsigned_integer_type,
                    .keyword_signed_integer => .signed_integer_type,
                    else => unreachable,
                },
                .token = blk: {
                    analyzer.token_i += 1;
                    break :blk token_i;
                },
                .left = @bitCast(@as(u32, try std.fmt.parseInt(u16, analyzer.bytes(token_i)[1..], 10))),
                .right = Node.Index.invalid,
            }),
            .fixed_keyword_usize, .fixed_keyword_ssize => |size_type| analyzer.addNode(.{
                .id = switch (size_type) {
                    .fixed_keyword_usize => .usize_type,
                    .fixed_keyword_ssize => .ssize_type,
                    else => unreachable,
                },
                .token = blk: {
                    analyzer.token_i += 1;
                    break :blk token_i;
                },
                .left = Node.Index.invalid,
                .right = Node.Index.invalid,
            }),
            .fixed_keyword_void => analyzer.addNode(.{
                .id = .void_type,
                .token = blk: {
                    analyzer.token_i += 1;
                    break :blk token_i;
                },
                .left = Node.Index.invalid,
                .right = Node.Index.invalid,
            }),
            .fixed_keyword_switch => try analyzer.switchExpression(),
            .period => switch (analyzer.tokens[token_i + 1].id) {
                .identifier => try analyzer.addNode(.{
                    .id = .enum_literal,
                    .token = blk: {
                        analyzer.token_i += 2;
                        break :blk token_i;
                    },
                    .left = Node.Index.invalid,
                    .right = Node.Index.invalid,
                }),
                .left_brace => try analyzer.addNode(.{
                    .id = .anonymous_container_literal,
                    .token = blk: {
                        analyzer.token_i += 1;
                        break :blk token_i;
                    },
                    .left = try analyzer.fieldInitialization(),
                    .right = Node.Index.invalid,
                }),
                else => |t| @panic(@tagName(t)),
            },
            .fixed_keyword_enum => blk: {
                analyzer.token_i += 1;

                // TODO: is this the best way?
                if (analyzer.tokens[analyzer.token_i].id == .left_parenthesis) {
                    analyzer.token_i += 1;
                    assert(analyzer.tokens[analyzer.token_i + 1].id == .right_parenthesis);
                    analyzer.token_i += 2;
                }

                _ = try analyzer.expectToken(.left_brace);
                const node_list = try analyzer.containerMembers(.@"enum");
                _ = try analyzer.expectToken(.right_brace);

                break :blk try analyzer.addNode(.{
                    .id = .enum_type,
                    .token = token_i,
                    .left = try analyzer.nodeList(node_list),
                    .right = Node.Index.invalid,
                });
            },
            .fixed_keyword_struct => blk: {
                analyzer.token_i += 1;

                // TODO: is this the best way?
                if (analyzer.tokens[analyzer.token_i].id == .left_parenthesis) {
                    analyzer.token_i += 1;
                    assert(analyzer.tokens[analyzer.token_i + 1].id == .right_parenthesis);
                    analyzer.token_i += 2;
                }

                _ = try analyzer.expectToken(.left_brace);
                const node_list = try analyzer.containerMembers(.@"struct");
                _ = try analyzer.expectToken(.right_brace);

                break :blk try analyzer.addNode(.{
                    .id = .struct_type,
                    .token = token_i,
                    .left = try analyzer.nodeList(node_list),
                    .right = Node.Index.invalid,
                });
            },
            .left_parenthesis => blk: {
                analyzer.token_i += 1;
                const expr = try analyzer.expression();
                _ = try analyzer.expectToken(.right_parenthesis);
                break :blk try analyzer.addNode(.{
                    .id = .expression_group,
                    .token = token_i,
                    .left = expr,
                    .right = Node.Index.invalid,
                });
            },
            else => |t| switch (t) {
                .identifier => std.debug.panic("{s}: {s}", .{ @tagName(t), analyzer.bytes(token_i) }),
                else => @panic(@tagName(t)),
            },
        };
    }

    // TODO:
    fn suffixOperator(analyzer: *Analyzer, left: Node.Index) !Node.Index {
        const token = analyzer.token_i;
        return switch (analyzer.tokens[token].id) {
            .left_bracket => blk: {
                analyzer.token_i += 1;
                const index_expression = try analyzer.expression();

                if (analyzer.tokens[analyzer.token_i].id == .period and analyzer.token_i + 1 < analyzer.tokens.len and analyzer.tokens[analyzer.token_i + 1].id == .period) {
                    analyzer.token_i += 2;
                    const range_end_expression = switch (analyzer.tokens[analyzer.token_i].id) {
                        .right_bracket => Node.Index.invalid,
                        else => try analyzer.expression(),
                    };

                    _ = try analyzer.expectToken(.right_bracket);

                    break :blk try analyzer.addNode(.{
                        .id = .slice,
                        .token = token,
                        .left = left,
                        .right = try analyzer.addNode(.{
                            .id = .range,
                            .token = token,
                            .left = index_expression,
                            .right = range_end_expression,
                        }),
                    });
                } else {
                    _ = try analyzer.expectToken(.right_bracket);
                    break :blk try analyzer.addNode(.{
                        .id = .indexed_access,
                        .token = token,
                        .left = left,
                        .right = index_expression,
                    });
                }
            },
            .period => switch (analyzer.tokens[analyzer.token_i + 1].id) {
                .identifier => try analyzer.addNode(.{
                    .id = .field_access,
                    .token = blk: {
                        analyzer.token_i += 1;
                        break :blk token;
                    },
                    .left = left,
                    .right = blk: {
                        //TODO ???
                        const result: Node.Index = @bitCast(analyzer.token_i);
                        analyzer.token_i += 1;
                        logln(.parser, .suffix, "WARNING: rhs has node index {} but it's token #{}", .{ result, token });
                        break :blk result;
                    },
                }),
                .period => Node.Index.invalid,
                .ampersand => try analyzer.addNode(.{
                    .id = .address_of,
                    .token = blk: {
                        analyzer.token_i += 2;
                        break :blk token;
                    },
                    .left = left,
                    .right = Node.Index.invalid,
                }),
                .at => try analyzer.addNode(.{
                    .id = .pointer_dereference,
                    .token = blk: {
                        analyzer.token_i += 2;
                        break :blk token;
                    },
                    .left = left,
                    .right = Node.Index.invalid,
                }),
                else => |t| @panic(@tagName(t)),
            },
            else => Node.Index.invalid,
        };
    }

    fn addNode(analyzer: *Analyzer, node: Node) !Node.Index {
        const index = analyzer.nodes.items.len;
        try analyzer.nodes.append(analyzer.allocator, node);
        logln(.parser, .node_creation, "Adding node #{} (0x{x}) {s} to file #{}", .{ index, @intFromPtr(&analyzer.nodes.items[index]), @tagName(node.id), analyzer.file_index.uniqueInteger() });
        // if (node.id == .identifier) {
        //     logln("Node identifier: {s}", .{analyzer.bytes(node.token)});
        // }
        return Node.Index{
            .value = @intCast(index),
        };
    }

    fn nodeList(analyzer: *Analyzer, node_list: ArrayList(Node.Index)) !Node.Index {
        const index = analyzer.node_lists.items.len;
        try analyzer.node_lists.append(analyzer.allocator, node_list);
        return try analyzer.addNode(.{
            .id = .node_list,
            .token = 0,
            .left = .{ .value = @intCast(index) },
            .right = Node.Index.invalid,
        });
    }

    fn identifierNode(analyzer: *Analyzer) !Node.Index {
        const identifier_token = analyzer.token_i;
        assert(analyzer.tokens[identifier_token].id == .identifier);
        analyzer.token_i += 1;
        return try analyzer.addNode(.{
            .id = .identifier,
            .token = identifier_token,
            .left = Node.Index.invalid,
            .right = Node.Index.invalid,
        });
    }

    fn containerMembers(analyzer: *Analyzer, comptime container_type: Compilation.ContainerType) !ArrayList(Node.Index) {
        var list = ArrayList(Node.Index){};
        while (analyzer.token_i < analyzer.tokens.len and analyzer.tokens[analyzer.token_i].id != .right_brace) {
            const first = analyzer.token_i;
            logln(.parser, .container_members, "First token for container member: {s}", .{@tagName(analyzer.tokens[first].id)});

            const member_node_index: Node.Index = switch (analyzer.tokens[first].id) {
                .fixed_keyword_comptime => switch (analyzer.tokens[analyzer.token_i + 1].id) {
                    .left_brace => blk: {
                        analyzer.token_i += 1;
                        const comptime_block = try analyzer.block(.{ .is_comptime = true });

                        break :blk try analyzer.addNode(.{
                            .id = .@"comptime",
                            .token = first,
                            .left = comptime_block,
                            .right = Node.Index.invalid,
                        });
                    },
                    else => |foo| @panic(@tagName(foo)),
                },
                .identifier => blk: {
                    analyzer.token_i += 1;
                    switch (container_type) {
                        .@"struct" => {
                            _ = try analyzer.expectToken(.colon);

                            const field_type = try analyzer.typeExpression();

                            const field_default_node = if (analyzer.tokens[analyzer.token_i].id == .equal) b: {
                                analyzer.token_i += 1;
                                const default_index = try analyzer.expression();
                                const default_node = analyzer.nodes.items[default_index.unwrap()];
                                _ = default_node;
                                assert(.id != .node_list);
                                break :b default_index;
                            } else Node.Index.invalid;

                            _ = try analyzer.expectToken(.comma);

                            const field_node = try analyzer.addNode(.{
                                .id = .container_field,
                                .token = first,
                                .left = field_type,
                                .right = field_default_node,
                            });

                            break :blk field_node;
                        },
                        .@"enum" => {
                            const value_associated = switch (analyzer.tokens[analyzer.token_i].id) {
                                .comma => Node.Index.invalid,
                                else => value: {
                                    analyzer.token_i += 1;
                                    break :value try analyzer.expression();
                                },
                            };

                            _ = try analyzer.expectToken(.comma);

                            const enum_field_node = try analyzer.addNode(.{
                                .id = .enum_field,
                                .token = first,
                                .left = value_associated,
                                .right = Node.Index.invalid,
                            });

                            break :blk enum_field_node;
                        },
                    }
                },
                .fixed_keyword_const, .fixed_keyword_var => try analyzer.symbolDeclaration(),
                else => |t| @panic(@tagName(t)),
            };

            logln(.parser, .container_members, "Container member {s}", .{@tagName(analyzer.nodes.items[member_node_index.unwrap()].id)});

            try list.append(analyzer.allocator, member_node_index);
        }

        return list;
    }
};

const Members = struct {
    len: usize,
    left: Node.Index,
    right: Node.Index,
};

// Here it is assumed that left brace is consumed

pub fn analyze(allocator: Allocator, tokens: []const Token, source_file: []const u8, file_index: File.Index) !Result {
    const start = std.time.Instant.now() catch unreachable;
    var analyzer = Analyzer{
        .tokens = tokens,
        .source_file = source_file,
        .file_index = file_index,
        .allocator = allocator,
    };
    const node_index = try analyzer.addNode(.{
        .id = .struct_type,
        .token = 0,
        .left = Node.Index.invalid,
        .right = Node.Index.invalid,
    });

    assert(node_index.value == 0);
    assert(!node_index.invalid);

    const members = try analyzer.containerMembers(.@"struct");
    assert(analyzer.token_i == analyzer.tokens.len);

    const node_list = try analyzer.nodeList(members);

    analyzer.nodes.items[0].left = node_list;

    const end = std.time.Instant.now() catch unreachable;

    return .{
        .nodes = analyzer.nodes,
        .node_lists = analyzer.node_lists,
        .time = end.since(start),
    };
}

const ExpressionMutabilityQualifier = enum {
    @"const",
    @"var",
};

const Keyword = enum {
    @"return",
    @"fn",
    @"while",
    void,
    noreturn,
};

// These types are meant to be used by the semantic analyzer
pub const ContainerDeclaration = struct {
    members: []const Node.Index,
};

pub const SymbolDeclaration = struct {
    type_node: Node.Index,
    initialization_node: Node.Index,
    mutability_token: Token.Index,
};

const Associativity = enum {
    none,
    left,
};
