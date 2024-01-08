const std = @import("std");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;
const equal = std.mem.eql;
const panic = std.debug.panic;

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
    file,
    token_errors,
    symbol_declaration,
    node_creation,
    node_creation_detailed,
    main_node,
    container_members,
    block,
    assign,
    suffix,
    precedence,
    @"switch",
    pointer_like_type_expression,
    switch_case,
    consume_token,

    pub var bitset = std.EnumSet(Logger).initMany(&.{
        .file,
        .token_errors,
        .symbol_declaration,
        .node_creation,
        // .node_creation_detailed,
        .main_node,
        .container_members,
        .block,
        .assign,
        .suffix,
        .precedence,
        .@"switch",
        .pointer_like_type_expression,
        .switch_case,
        .consume_token,
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
        constant_symbol_declaration,
        variable_symbol_declaration,
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
        array_type,
        argument_declaration,
        compiler_intrinsic,
        compiler_intrinsic_id,
        ssize_type,
        usize_type,
        void_type,
        call,
        pointer_type,
        enum_literal,
        address_of,
        pointer_dereference,
        keyword_false,
        compare_equal,
        compare_not_equal,
        compare_less,
        compare_greater,
        compare_less_equal,
        compare_greater_equal,
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
        mul,
        div,
        mod,
        bit_and,
        bit_xor,
        expression_group,
        bit_or,
        shift_left,
        shift_right,
        add_assign,
        sub_assign,
        mul_assign,
        div_assign,
        mod_assign,
        discarded_assign,
        bool_type,
        named_argument,
        optional_type,
        container_field,
        struct_type,
        container_literal,
        container_field_initialization,
        array_index_initialization,
        boolean_not,
        null_literal,
        if_else_payload,
        if_payload,
        discard,
        slice,
        range,
        negation,
        anonymous_container_literal,
        anonymous_array_literal,
        array_literal,
        indexed_access,
        calling_convention,
        assembly_register,
        assembly_statement,
        assembly_block,
        for_condition,
        for_loop,
        undefined,
        zero_terminated,
        null_terminated,
        const_expression,
        many_pointer_expression,
        optional_unwrap,
        anonymous_empty_literal,
        empty_container_literal_guess,
        break_expression,
        character_literal,
    };
};

const Error = error{
    unexpected_token,
    not_implemented,
    OutOfMemory,
};

const Analyzer = struct {
    lexer: lexical_analyzer.Result,
    token_i: u32 = 0,
    nodes: ArrayList(Node) = .{},
    source_file: []const u8,
    file_index: File.Index,
    allocator: Allocator,
    node_lists: ArrayList(Node.List) = .{},
    suffix_depth: usize = 0,

    fn expectToken(analyzer: *Analyzer, expected_token_id: Token.Id) !u32 {
        const token_i = analyzer.token_i;
        const token_id = analyzer.peekToken();
        const is_expected_token = token_id == expected_token_id;
        if (is_expected_token) {
            analyzer.consumeToken();
            const result = token_i;
            return result;
        } else {
            const file_offset = analyzer.getTokenOffset(token_i);
            const file_chunk = analyzer.source_file[file_offset..];
            std.debug.print("Unexpected token {s} when expected {s}\n| |\n v \n```\n{s}\n```", .{ @tagName(token_id), @tagName(expected_token_id), file_chunk });
            @breakpoint();
            return error.unexpected_token;
        }
    }

    fn getTokenOffset(analyzer: *Analyzer, token_index: Token.Index) u32 {
        const offset = analyzer.lexer.token_offsets.items[token_index];
        return offset;
    }

    fn peekTokenAhead(analyzer: *Analyzer, ahead_offset: usize) Token.Id {
        const token_index = analyzer.token_i + ahead_offset;
        const token = analyzer.lexer.ids.items[token_index];
        return token;
    }

    fn peekToken(analyzer: *Analyzer) Token.Id {
        const token = analyzer.peekTokenAhead(0);
        return token;
    }

    fn hasTokens(analyzer: *Analyzer) bool {
        return analyzer.token_i < analyzer.lexer.ids.items.len;
    }

    fn consumeToken(analyzer: *Analyzer) void {
        analyzer.consumeTokens(1);
    }

    fn consumeTokens(analyzer: *Analyzer, token_count: u32) void {
        assert(analyzer.token_i + token_count <= analyzer.lexer.ids.items.len);
        log(.parser, .consume_token, "Consuming {} {s}: ", .{ token_count, if (token_count == 1) "token" else "tokens" });

        for (0..token_count) |i| {
            const token = analyzer.peekTokenAhead(i);
            const token_bytes = analyzer.bytes(@intCast(analyzer.token_i + i));
            log(.parser, .consume_token, "{s}, '{s}'", .{ @tagName(token), token_bytes });
        }

        log(.parser, .consume_token, "\n", .{});
        analyzer.token_i += token_count;
    }

    fn bytes(analyzer: *const Analyzer, token_index: Token.Index) []const u8 {
        const offset = analyzer.lexer.token_offsets.items[token_index];
        const len = analyzer.lexer.token_lengths.items[token_index];
        const slice = analyzer.source_file[offset..][0..len];
        return slice;
    }

    fn symbolDeclaration(analyzer: *Analyzer) anyerror!Node.Index {
        const first = analyzer.token_i;
        const mutability_node_id: Node.Id = switch (analyzer.peekToken()) {
            .fixed_keyword_var => .variable_symbol_declaration,
            .fixed_keyword_const => .constant_symbol_declaration,
            else => |t| @panic(@tagName(t)),
        };
        analyzer.consumeToken();
        const declaration_name_token = try analyzer.expectToken(.identifier);
        const declaration_name = analyzer.bytes(declaration_name_token);
        logln(.parser, .symbol_declaration, "Starting parsing declaration \"{s}\"", .{declaration_name});

        logln(.parser, .symbol_declaration, "Current token: {}", .{analyzer.peekToken()});

        const type_node_index = switch (analyzer.peekToken()) {
            .operator_colon => blk: {
                analyzer.consumeToken();
                break :blk try analyzer.typeExpression();
            },
            else => Node.Index.invalid,
        };

        _ = try analyzer.expectToken(.operator_assign);

        const init_node_index = try analyzer.expression();

        const init_node = analyzer.nodes.items[init_node_index.unwrap()];
        switch (init_node.id) {
            .function_definition => {},
            else => _ = try analyzer.expectToken(.operator_semicolon),
        }

        // TODO:
        const declaration = Node{
            .id = mutability_node_id,
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
        assert(analyzer.peekToken() == .fixed_keyword_fn);
        analyzer.consumeToken();
        const function_prototype = try analyzer.functionPrototype();
        const is_comptime = false;
        _ = is_comptime;
        return switch (analyzer.peekToken()) {
            .operator_left_brace => try analyzer.addNode(.{
                .id = .function_definition,
                .token = token,
                .left = function_prototype,
                .right = try analyzer.block(.{ .is_comptime = false }),
            }),
            .operator_semicolon => function_prototype,
            else => |t| @panic(@tagName(t)),
        };
    }

    fn functionPrototype(analyzer: *Analyzer) !Node.Index {
        const token = analyzer.token_i;
        assert(analyzer.peekToken() == .operator_left_parenthesis);
        const arguments = try analyzer.argumentList(.operator_left_parenthesis, .operator_right_parenthesis);
        const return_type = try analyzer.typeExpression();

        const simple_function_prototype = try analyzer.addNode(.{
            .id = .simple_function_prototype,
            .token = token,
            .left = arguments,
            .right = return_type,
        });

        return switch (analyzer.peekToken()) {
            .operator_semicolon,
            .operator_left_brace,
            .operator_comma,
            => simple_function_prototype,
            else => blk: {
                var list = Node.List{};

                while (true) {
                    const attribute_token = analyzer.token_i;
                    const attribute = switch (analyzer.peekToken()) {
                        .operator_semicolon,
                        .operator_left_brace,
                        => break,
                        .fixed_keyword_extern => b: {
                            analyzer.consumeToken();
                            _ = try analyzer.expectToken(.operator_left_parenthesis);
                            const string_literal = try analyzer.addNode(.{
                                .id = .string_literal,
                                .token = try analyzer.expectToken(.string_literal),
                                .left = Node.Index.invalid,
                                .right = Node.Index.invalid,
                            });
                            _ = try analyzer.expectToken(.operator_right_parenthesis);

                            const result = try analyzer.addNode(.{
                                .id = .extern_qualifier,
                                .token = attribute_token,
                                .left = string_literal,
                                .right = Node.Index.invalid,
                            });
                            break :b result;
                        },
                        .fixed_keyword_export => b: {
                            const result = try analyzer.addNode(.{
                                .id = .export_qualifier,
                                .token = attribute_token,
                                .left = Node.Index.invalid,
                                .right = Node.Index.invalid,
                            });
                            analyzer.consumeToken();
                            break :b result;
                        },
                        .fixed_keyword_cc => b: {
                            analyzer.consumeToken();
                            _ = try analyzer.expectToken(.operator_left_parenthesis);
                            const calling_conv_expression = try analyzer.expression();
                            _ = try analyzer.expectToken(.operator_right_parenthesis);

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

        while (analyzer.peekToken() != end_token) {
            const identifier = try analyzer.expectToken(.identifier);
            _ = try analyzer.expectToken(.operator_colon);
            const type_expression = try analyzer.typeExpression();

            if (analyzer.peekToken() == .operator_comma) {
                analyzer.consumeToken();
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
        _ = try analyzer.expectToken(.operator_semicolon);
        return result;
    }

    fn block(analyzer: *Analyzer, options: Options) anyerror!Node.Index {
        const left_brace = try analyzer.expectToken(.operator_left_brace);
        var list = ArrayList(Node.Index){};

        while (analyzer.peekToken() != .operator_right_brace) {
            const first_statement_token = analyzer.peekToken();
            logln(.parser, .block, "First statement token: {s}", .{@tagName(first_statement_token)});
            const statement_index = switch (first_statement_token) {
                .identifier => switch (analyzer.peekTokenAhead(1)) {
                    .operator_colon => {
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
                .fixed_keyword_break => b: {
                    const node_index = try analyzer.breakExpression();
                    _ = try analyzer.expectToken(.operator_semicolon);
                    break :b node_index;
                },
                .intrinsic => blk: {
                    const intrinsic = try analyzer.compilerIntrinsic();
                    _ = try analyzer.expectToken(.operator_semicolon);
                    break :blk intrinsic;
                },
                else => |t| @panic(@tagName(t)),
            };

            const node = analyzer.nodes.items[statement_index.unwrap()];
            logln(.parser, .block, "Adding statement: {s}", .{@tagName(node.id)});

            try list.append(analyzer.allocator, statement_index);
        }

        _ = try analyzer.expectToken(.operator_right_brace);

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

        _ = try analyzer.expectToken(.operator_left_parenthesis);
        // TODO:
        const while_condition = try analyzer.expression();
        _ = try analyzer.expectToken(.operator_right_parenthesis);

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
        analyzer.consumeToken();
        _ = try analyzer.expectToken(.operator_left_parenthesis);
        const switch_expression = try analyzer.expression();
        _ = try analyzer.expectToken(.operator_right_parenthesis);
        logln(.parser, .@"switch", "Parsed switch expression...", .{});
        _ = try analyzer.expectToken(.operator_left_brace);

        var list = Node.List{};

        while (analyzer.peekToken() != .operator_right_brace) {
            const case_token = analyzer.token_i;
            logln(.parser, .@"switch", "Parsing switch case...", .{});
            const case_node = switch (analyzer.peekToken()) {
                .fixed_keyword_else => blk: {
                    analyzer.consumeToken();
                    break :blk Node.Index.invalid;
                },
                else => blk: {
                    var array_list = Node.List{};
                    while (true) {
                        const switch_case_node = try analyzer.expression();
                        try array_list.append(analyzer.allocator, switch_case_node);
                        switch (analyzer.peekToken()) {
                            .operator_comma => analyzer.consumeToken(),
                            .operator_switch_case => break,
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
            _ = try analyzer.expectToken(.operator_switch_case);
            const is_left_brace = analyzer.peekToken() == .operator_left_brace;
            const expr = switch (is_left_brace) {
                true => try analyzer.block(.{
                    .is_comptime = false,
                }),
                false => try analyzer.assignExpression(),
            };

            // logln(.parser, .switch_case, "Comma token: \n```\n{s}\n```\n", .{analyzer.source_file[analyzer.tokens[analyzer.token_i].start..]});
            _ = try analyzer.expectToken(.operator_comma);

            const node = try analyzer.addNode(.{
                .id = .switch_case,
                .token = case_token,
                .left = case_node,
                .right = expr,
            });

            try list.append(analyzer.allocator, node);
        }

        _ = try analyzer.expectToken(.operator_right_brace);

        return try analyzer.addNode(.{
            .id = .@"switch",
            .token = switch_token,
            .left = switch_expression,
            .right = try analyzer.nodeList(list),
        });
    }

    fn ifExpression(analyzer: *Analyzer) anyerror!Node.Index {
        const if_token = analyzer.token_i;
        analyzer.consumeToken();

        _ = try analyzer.expectToken(.operator_left_parenthesis);
        const if_condition = try analyzer.expression();
        _ = try analyzer.expectToken(.operator_right_parenthesis);

        const payload = if (analyzer.peekToken() == .operator_bar) blk: {
            analyzer.consumeToken();
            const payload_node = switch (analyzer.peekToken()) {
                .identifier => try analyzer.identifierNode(),
                .discard => try analyzer.discardNode(),
                else => unreachable,
            };
            _ = try analyzer.expectToken(.operator_bar);
            break :blk payload_node;
        } else Node.Index.invalid;

        const if_taken_expression = try analyzer.expression();

        const if_node = try analyzer.addNode(.{
            .id = .@"if",
            .token = if_token,
            .left = if_condition,
            .right = if_taken_expression,
        });

        const result = switch (analyzer.peekToken()) {
            .fixed_keyword_else => blk: {
                analyzer.consumeToken();

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
        _ = try analyzer.expectToken(.operator_left_parenthesis);

        var for_expression_list = ArrayList(Node.Index){};

        while (analyzer.peekToken() != .operator_right_parenthesis) {
            const expression_token = analyzer.token_i;
            const first = try analyzer.expression();

            const node_index = switch (analyzer.peekToken()) {
                .operator_dot => switch (analyzer.peekTokenAhead(1)) {
                    .operator_dot => blk: {
                        analyzer.consumeTokens(2);

                        break :blk try analyzer.addNode(.{
                            .id = .range,
                            .token = expression_token,
                            .left = first,
                            .right = switch (analyzer.peekToken()) {
                                .operator_right_parenthesis, .operator_comma => Node.Index.invalid,
                                else => try analyzer.expression(),
                            },
                        });
                    },
                    else => |t| @panic(@tagName(t)),
                },
                .operator_right_parenthesis,
                .operator_comma,
                => first,
                else => |t| @panic(@tagName(t)),
            };

            try for_expression_list.append(analyzer.allocator, node_index);

            switch (analyzer.peekToken()) {
                .operator_comma => analyzer.consumeToken(),
                .operator_right_parenthesis => {},
                else => |t| @panic(@tagName(t)),
            }
        }

        _ = try analyzer.expectToken(.operator_right_parenthesis);

        _ = try analyzer.expectToken(.operator_bar);

        var payload_nodes = ArrayList(Node.Index){};

        while (analyzer.peekToken() != .operator_bar) {
            const payload_token = analyzer.token_i;
            const id: Node.Id = switch (analyzer.peekToken()) {
                .identifier => .identifier,
                .discard => .discard,
                else => |t| @panic(@tagName(t)),
            };

            analyzer.consumeToken();

            switch (analyzer.peekToken()) {
                .operator_bar => {},
                .operator_comma => analyzer.consumeToken(),
                else => |t| @panic(@tagName(t)),
            }

            try payload_nodes.append(analyzer.allocator, try analyzer.addNode(.{
                .id = id,
                .token = payload_token,
                .left = Node.Index.invalid,
                .right = Node.Index.invalid,
            }));
        }

        _ = try analyzer.expectToken(.operator_bar);

        if (payload_nodes.items.len != for_expression_list.items.len) {
            unreachable;
        }

        const for_condition_node = try analyzer.addNode(.{
            .id = .for_condition,
            .token = token,
            .left = try analyzer.nodeList(for_expression_list),
            .right = try analyzer.nodeList(payload_nodes),
        });

        const for_content_node = switch (analyzer.peekToken()) {
            .operator_left_brace => try analyzer.block(.{
                .is_comptime = false,
            }),
            else => blk: {
                const for_content_expression = try analyzer.expression();
                _ = try analyzer.expectToken(.operator_semicolon);
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

    fn breakExpression(analyzer: *Analyzer) !Node.Index {
        const t = try analyzer.expectToken(.fixed_keyword_break);
        const node_index = try analyzer.addNode(.{
            .id = .break_expression,
            .token = t,
            .left = Node.Index.invalid,
            .right = Node.Index.invalid,
        });
        return node_index;
    }

    fn assignExpression(analyzer: *Analyzer) !Node.Index {
        const left = try analyzer.expression();
        const expression_token = analyzer.token_i;
        const expression_id: Node.Id = switch (analyzer.peekToken()) {
            .operator_semicolon, .operator_comma => return left,
            .operator_assign => .assign,
            .operator_add_assign => .add_assign,
            .operator_sub_assign => .sub_assign,
            .operator_mul_assign => .mul_assign,
            .operator_div_assign => .div_assign,
            .operator_mod_assign => .mod_assign,
            else => |t| @panic(@tagName(t)),
        };
        analyzer.consumeToken();
        const right = try analyzer.expression();

        const node = Node{
            .id = expression_id,
            .token = expression_token,
            .left = left,
            .right = right,
        };

        logln(.parser, .assign, "assign:\nleft: {}.\nright: {}", .{ node.left, node.right });
        return try analyzer.addNode(node);
        //     .operator_equal => .operator_assign,
        //     .operator_add => switch (analyzer.peekTokenAhead(1)) {
        //         .operator_equal => blk: {
        //             analyzer.consumeToken();
        //             break :blk .operator_add_assign;
        //         },
        //         else => |t| @panic(@tagName(t)),
        //     },
        //     .operator_sub => switch (analyzer.peekTokenAhead(1)) {
        //         .equal => blk: {
        //             analyzer.consumeToken();
        //             break :blk .operator_sub_assign;
        //         },
        //         else => |t| @panic(@tagName(t)),
        //     },
        //     .operator_div => switch (analyzer.peekTokenAhead(1)) {
        //         .operator_equal => blk: {
        //             analyzer.consumeToken();
        //             break :blk .operator_div_assign;
        //         },
        //         else => |t| @panic(@tagName(t)),
        //     },
        //     else => |t| @panic(@tagName(t)),
        // };
        //
        //
    }

    fn parseAsmOperand(analyzer: *Analyzer) !Node.Index {
        const token = analyzer.token_i;
        const result = switch (analyzer.peekToken()) {
            .identifier => try analyzer.addNode(.{
                .id = .assembly_register,
                .token = blk: {
                    analyzer.consumeToken();
                    break :blk token;
                },
                .left = Node.Index.invalid,
                .right = Node.Index.invalid,
            }),
            .number_literal => blk: {
                analyzer.consumeToken();
                break :blk analyzer.addNode(.{
                    .id = .number_literal,
                    .token = token,
                    .left = Node.Index.invalid,
                    .right = Node.Index.invalid,
                });
            },
            .operator_left_brace => blk: {
                analyzer.consumeToken();
                const result = try analyzer.expression();
                _ = try analyzer.expectToken(.operator_right_brace);
                break :blk result;
            },
            else => |t| @panic(@tagName(t)),
        };
        return result;
    }

    fn compilerIntrinsic(analyzer: *Analyzer) !Node.Index {
        const intrinsic_token = try analyzer.expectToken(.intrinsic);
        _ = try analyzer.expectToken(.operator_left_parenthesis);
        const intrinsic_name = analyzer.bytes(intrinsic_token)[1..];

        const intrinsic_id = inline for (@typeInfo(Compilation.ValidIntrinsic).Enum.fields) |enum_field| {
            if (equal(u8, enum_field.name, intrinsic_name)) {
                break @field(Compilation.ValidIntrinsic, enum_field.name);
            }
        } else @panic(intrinsic_name);

        var list = ArrayList(Node.Index){};

        if (intrinsic_id == .@"asm") {
            _ = try analyzer.expectToken(.operator_left_brace);

            while (analyzer.peekToken() != .operator_right_brace) {
                const instruction_token = try analyzer.expectToken(.identifier);
                var operand_list = ArrayList(Node.Index){};

                while (analyzer.peekToken() != .operator_semicolon) {
                    const asm_operand = try analyzer.parseAsmOperand();
                    switch (analyzer.peekToken()) {
                        .operator_semicolon => {},
                        .operator_comma => analyzer.consumeToken(),
                        else => |t| @panic(@tagName(t)),
                    }
                    try operand_list.append(analyzer.allocator, asm_operand);
                }

                _ = try analyzer.expectToken(.operator_semicolon);

                try list.append(analyzer.allocator, try analyzer.addNode(.{
                    .id = .assembly_statement,
                    .token = instruction_token,
                    .left = try analyzer.nodeList(operand_list),
                    .right = Node.Index.invalid,
                }));
            }

            _ = try analyzer.expectToken(.operator_right_brace);
            _ = try analyzer.expectToken(.operator_right_parenthesis);
        } else {
            while (analyzer.peekToken() != .operator_right_parenthesis) {
                const parameter = try analyzer.expression();
                try list.append(analyzer.allocator, parameter);

                switch (analyzer.peekToken()) {
                    .operator_comma => analyzer.consumeToken(),
                    .operator_right_parenthesis => continue,
                    else => |t| @panic(@tagName(t)),
                }
            }

            // Consume the right parenthesis
            analyzer.consumeToken();
        }

        return try analyzer.addNode(.{
            .id = .compiler_intrinsic,
            .token = intrinsic_token,
            .left = try analyzer.nodeList(list),
            .right = .{
                .value = @intFromEnum(intrinsic_id),
            },
        });
    }

    fn expression(analyzer: *Analyzer) anyerror!Node.Index {
        return try analyzer.expressionPrecedence(0);
    }

    const PrecedenceOperator = enum {
        compare_equal,
        compare_not_equal,
        compare_less,
        compare_greater,
        compare_less_equal,
        compare_greater_equal,
        add,
        sub,
        mul,
        div,
        mod,
        bit_and,
        bit_xor,
        bit_or,
        shift_left,
        shift_right,
    };

    const operator_precedence = std.EnumArray(PrecedenceOperator, i32).init(.{
        .compare_equal = 30,
        .compare_not_equal = 30,
        .compare_less = 30,
        .compare_greater = 30,
        .compare_less_equal = 30,
        .compare_greater_equal = 30,
        .add = 60,
        .sub = 60,
        .mul = 70,
        .div = 70,
        .mod = 70,
        .bit_and = 40,
        .bit_xor = 40,
        .bit_or = 40,
        .shift_left = 50,
        .shift_right = 50,
    });

    const operator_associativity = std.EnumArray(PrecedenceOperator, Associativity).init(.{
        .compare_equal = .none,
        .compare_not_equal = .none,
        .compare_less = .none,
        .compare_greater = .none,
        .compare_less_equal = .none,
        .compare_greater_equal = .none,
        .add = .left,
        .sub = .left,
        .bit_and = .left,
        .bit_xor = .left,
        .bit_or = .left,
        .mul = .left,
        .div = .left,
        .mod = .left,
        .shift_left = .left,
        .shift_right = .left,
    });

    const operator_node_id = std.EnumArray(PrecedenceOperator, Node.Id).init(.{
        .compare_equal = .compare_equal,
        .compare_not_equal = .compare_not_equal,
        .compare_greater = .compare_greater,
        .compare_less = .compare_less,
        .compare_greater_equal = .compare_greater_equal,
        .compare_less_equal = .compare_less_equal,
        .add = .add,
        .sub = .sub,
        .bit_and = .bit_and,
        .bit_xor = .bit_xor,
        .bit_or = .bit_or,
        .mul = .mul,
        .div = .div,
        .mod = .mod,
        .shift_left = .shift_left,
        .shift_right = .shift_right,
    });

    fn expressionPrecedence(analyzer: *Analyzer, minimum_precedence: i32) !Node.Index {
        assert(minimum_precedence >= 0);
        var result = try analyzer.prefixExpression();
        if (!result.invalid) {
            const prefix_node = analyzer.nodes.items[result.unwrap()];
            logln(.parser, .precedence, "Prefix: {s}", .{@tagName(prefix_node.id)});
        }

        var banned_precedence: i32 = -1;

        while (analyzer.hasTokens()) {
            const token = analyzer.peekToken();
            // logln("Looping in expression precedence with token {}", .{token});
            const operator: PrecedenceOperator = switch (token) {
                .operator_semicolon,
                .operator_right_parenthesis,
                .operator_right_brace,
                .operator_right_bracket,
                .operator_comma,
                .operator_colon,
                .operator_assign,
                .operator_add_assign,
                .operator_sub_assign,
                .operator_mul_assign,
                .operator_div_assign,
                .operator_mod_assign,
                .operator_dot,
                .fixed_keyword_const,
                .fixed_keyword_var,
                .fixed_keyword_return,
                .fixed_keyword_if,
                .fixed_keyword_else,
                .identifier,
                .discard,
                => break,
                .operator_compare_equal => .compare_equal,
                .operator_compare_not_equal => .compare_not_equal,
                .operator_compare_less => .compare_less,
                .operator_compare_greater => .compare_greater,
                .operator_compare_less_equal => .compare_less_equal,
                .operator_compare_greater_equal => .compare_greater_equal,
                .operator_add => .add,
                .operator_minus => .sub,
                .operator_asterisk => .mul,
                .operator_div => .div,
                .operator_mod => .mod,
                .operator_ampersand => .bit_and,
                .operator_bar => .bit_or,
                .operator_xor => .bit_xor,
                else => |t| @panic(@tagName(t)),
            };

            logln(.parser, .precedence, "Precedence operator: {s}", .{@tagName(operator)});

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
            analyzer.consumeToken();

            // TODO: fix this
            logln(.parser, .precedence, "Going for right in expressionPrecedence with operator {s}", .{@tagName(operator)});
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
        const node_id: Node.Id = switch (analyzer.peekToken()) {
            else => |pref| {
                _ = pref;
                return try analyzer.primaryExpression();
            },
            .operator_bang => .boolean_not,
            .operator_minus => .negation,
            // .tilde => |t| @panic(@tagName(t)),
        };

        return try analyzer.addNode(.{
            .id = node_id,
            .token = blk: {
                analyzer.consumeToken();
                break :blk token;
            },
            .left = try analyzer.prefixExpression(),
            .right = Node.Index.invalid,
        });
    }

    fn primaryExpression(analyzer: *Analyzer) !Node.Index {
        const result = switch (analyzer.peekToken()) {
            .identifier => switch (analyzer.peekTokenAhead(1)) {
                .operator_colon => unreachable,
                else => try analyzer.curlySuffixExpression(),
            },
            .string_literal,
            .character_literal,
            .number_literal,
            .intrinsic,
            .fixed_keyword_true,
            .fixed_keyword_false,
            .fixed_keyword_unreachable,
            .fixed_keyword_null,
            .fixed_keyword_switch,
            .operator_dot,
            .operator_left_parenthesis,
            .keyword_signed_integer,
            .keyword_unsigned_integer,
            .fixed_keyword_ssize,
            .fixed_keyword_usize,
            .fixed_keyword_enum,
            .fixed_keyword_struct,
            .discard,
            .fixed_keyword_undefined,
            .operator_left_bracket,
            => try analyzer.curlySuffixExpression(),
            .fixed_keyword_fn => try analyzer.function(),
            .fixed_keyword_return => try analyzer.addNode(.{
                .id = .@"return",
                .token = blk: {
                    const token = analyzer.token_i;
                    analyzer.consumeToken();
                    break :blk token;
                },
                .left = try analyzer.expression(),
                .right = Node.Index.invalid,
            }),
            // todo:?
            .operator_left_brace => try analyzer.block(.{ .is_comptime = false }),
            .fixed_keyword_if => try analyzer.ifExpression(),
            else => |id| std.debug.panic("WARN: By default, calling curlySuffixExpression with {s}", .{@tagName(id)}),
        };

        return result;
    }

    fn curlySuffixExpression(analyzer: *Analyzer) !Node.Index {
        const left = try analyzer.typeExpression();

        return switch (analyzer.peekToken()) {
            .operator_left_brace => try analyzer.containerLiteral(left),
            else => left,
        };
    }

    fn noReturn(analyzer: *Analyzer) !Node.Index {
        const token_i = analyzer.token_i;
        assert(analyzer.peekToken() == .fixed_keyword_noreturn);
        analyzer.consumeToken();
        return try analyzer.addNode(.{
            .id = .keyword_noreturn,
            .token = token_i,
            .left = Node.Index.invalid,
            .right = Node.Index.invalid,
        });
    }

    fn boolLiteral(analyzer: *Analyzer) !Node.Index {
        return try analyzer.addNode(.{
            .id = switch (analyzer.peekToken()) {
                .fixed_keyword_true => .keyword_true,
                .fixed_keyword_false => .keyword_false,
                else => unreachable,
            },
            .token = blk: {
                const token_i = analyzer.token_i;
                analyzer.consumeToken();
                break :blk token_i;
            },
            .left = Node.Index.invalid,
            .right = Node.Index.invalid,
        });
    }

    const PointerOrArrayTypeExpectedExpression = enum {
        single_pointer_type,
        many_pointer_type,
        array_or_slice_type,
    };

    fn parseTermination(analyzer: *Analyzer) !Node.Index {
        _ = try analyzer.expectToken(.operator_colon);
        const token_i = analyzer.token_i;
        const token = analyzer.peekToken();
        const termination_id: Node.Id = switch (token) {
            .fixed_keyword_null => .null_terminated,
            .number_literal => switch (std.zig.parseNumberLiteral(analyzer.bytes(token_i))) {
                .int => |integer| switch (integer) {
                    0 => .zero_terminated,
                    else => @panic("Invalid number literal terminator"),
                },
                else => @panic("Invalid number literal terminator"),
            },
            else => |t| @panic(@tagName(t)),
        };

        const termination_node_index = try analyzer.addNode(.{
            .id = termination_id,
            .token = token_i,
            .left = Node.Index.invalid,
            .right = Node.Index.invalid,
        });
        analyzer.consumeToken();

        return termination_node_index;
    }

    fn pointerOrArrayTypeExpression(analyzer: *Analyzer, expected: PointerOrArrayTypeExpectedExpression) !Node.Index {
        const first = analyzer.token_i;

        var list = Node.List{};

        const expression_type: Node.Id = switch (expected) {
            .single_pointer_type => blk: {
                analyzer.consumeToken();

                break :blk .pointer_type;
            },
            .many_pointer_type => blk: {
                try list.append(analyzer.allocator, try analyzer.addNode(.{
                    .id = .many_pointer_expression,
                    .token = analyzer.token_i,
                    .left = Node.Index.invalid,
                    .right = Node.Index.invalid,
                }));
                _ = try analyzer.expectToken(.operator_left_bracket);
                _ = try analyzer.expectToken(.operator_ampersand);
                switch (analyzer.peekToken()) {
                    .operator_right_bracket => {},
                    .operator_colon => try list.append(analyzer.allocator, try analyzer.parseTermination()),
                    else => |t| @panic(@tagName(t)),
                }
                _ = try analyzer.expectToken(.operator_right_bracket);

                break :blk .pointer_type;
            },
            .array_or_slice_type => blk: {
                _ = try analyzer.expectToken(.operator_left_bracket);
                switch (analyzer.peekToken()) {
                    .operator_right_bracket => {
                        analyzer.consumeToken();
                        break :blk .slice_type;
                    },
                    .operator_colon => {
                        try list.append(analyzer.allocator, try analyzer.parseTermination());
                        _ = try analyzer.expectToken(.operator_right_bracket);
                        break :blk .slice_type;
                    },
                    else => {
                        const length_expression = try analyzer.expression();
                        try list.append(analyzer.allocator, length_expression);

                        switch (analyzer.peekToken()) {
                            .operator_right_bracket => {},
                            .operator_colon => try list.append(analyzer.allocator, try analyzer.parseTermination()),
                            else => |t| @panic(@tagName(t)),
                        }

                        _ = try analyzer.expectToken(.operator_right_bracket);

                        break :blk .array_type;
                    },
                }
            },
        };

        if (expression_type != .array_type) {
            const const_node = switch (analyzer.peekToken()) {
                .fixed_keyword_const => try analyzer.addNode(.{
                    .id = .const_expression,
                    .token = analyzer.token_i,
                    .left = Node.Index.invalid,
                    .right = Node.Index.invalid,
                }),
                else => Node.Index.invalid,
            };
            analyzer.consumeTokens(@intFromBool(analyzer.peekToken() == .fixed_keyword_const));

            if (!const_node.invalid) {
                try list.append(analyzer.allocator, const_node);
            }
        } else {
            assert(list.items.len > 0);
        }

        const type_expression = try analyzer.typeExpression();
        assert(!type_expression.invalid);
        try list.append(analyzer.allocator, type_expression);

        const node_list = try analyzer.nodeList(list);

        const node = Node{
            .id = expression_type,
            .token = first,
            .left = node_list,
            .right = Node.Index.invalid,
        };

        logln(.parser, .pointer_like_type_expression, "ARRAY START\n===========", .{});
        for (list.items) |ni| {
            const n = analyzer.nodes.items[ni.unwrap()];
            logln(.parser, .pointer_like_type_expression, "{s} node element: {s}", .{ @tagName(expression_type), @tagName(n.id) });
        }
        logln(.parser, .pointer_like_type_expression, "ARRAY END\n=========", .{});

        const node_index = try analyzer.addNode(node);
        logln(.parser, .pointer_like_type_expression, "Pointer end", .{});

        switch (analyzer.peekToken()) {
            .operator_comma,
            .operator_right_parenthesis,
            .operator_left_brace,
            .operator_assign,
            .fixed_keyword_extern,
            => return node_index,
            else => |t| @panic(@tagName(t)),
        }

        return node_index;
    }

    fn typeExpression(analyzer: *Analyzer) anyerror!Node.Index {
        const first = analyzer.token_i;
        return switch (analyzer.peekToken()) {
            else => try analyzer.errorUnionExpression(),
            .operator_optional => blk: {
                analyzer.consumeToken();
                break :blk try analyzer.addNode(.{
                    .id = .optional_type,
                    .token = first,
                    .left = try analyzer.typeExpression(),
                    .right = Node.Index.invalid,
                });
            },
            .operator_ampersand => try analyzer.pointerOrArrayTypeExpression(.single_pointer_type),
            .operator_bang => unreachable, // error
            .operator_left_bracket => switch (analyzer.peekTokenAhead(1)) {
                .operator_ampersand => try analyzer.pointerOrArrayTypeExpression(.many_pointer_type),
                .operator_asterisk => @panic("Meant to use ampersand?"),
                else => try analyzer.pointerOrArrayTypeExpression(.array_or_slice_type),
            },
        };
    }

    fn errorUnionExpression(analyzer: *Analyzer) !Node.Index {
        const suffix_expression = try analyzer.suffixExpression();

        return switch (analyzer.peekToken()) {
            .operator_bang => unreachable,
            else => suffix_expression,
        };
    }

    fn suffixExpression(analyzer: *Analyzer) !Node.Index {
        analyzer.suffix_depth += 1;
        defer analyzer.suffix_depth -= 1;
        var result = try analyzer.primaryTypeExpression();

        while (true) {
            const suffix_operator = try analyzer.suffixOperator(result);
            if (!suffix_operator.invalid) {
                result = suffix_operator;
            } else {
                if (analyzer.peekToken() == .operator_left_parenthesis) {
                    const left_parenthesis = analyzer.token_i;
                    analyzer.consumeToken();

                    var expression_list = ArrayList(Node.Index){};
                    logln(.parser, .suffix, "[DEPTH={}] Initializating suffix call-like expression", .{analyzer.suffix_depth});
                    while (analyzer.peekToken() != .operator_right_parenthesis) {
                        const current_token = analyzer.token_i;
                        // logln(.parser, .suffix, "[DEPTH={}] First token: {s}", .{ analyzer.suffix_depth, @tagName(analyzer.tokens[current_token].id) });
                        var parameter = try analyzer.expression();
                        // const parameter_node = analyzer.nodes.items[parameter.unwrap()];
                        // logln(.parser, .suffix, "[DEPTH={}] Parameter node: {s}", .{ analyzer.suffix_depth, @tagName(parameter_node.id) });
                        if (analyzer.peekToken() == .operator_assign) {
                            analyzer.consumeToken();

                            parameter = try analyzer.addNode(.{
                                .id = .named_argument,
                                .token = current_token,
                                .left = parameter,
                                .right = try analyzer.expression(),
                            });
                        }

                        try expression_list.append(analyzer.allocator, parameter);

                        switch (analyzer.peekToken()) {
                            .operator_right_parenthesis => {},
                            .operator_comma => analyzer.consumeToken(),
                            .operator_colon, .operator_right_brace, .operator_right_bracket => unreachable,
                            .operator_dot => panic("[DEPTH={}] Unexpected period", .{analyzer.suffix_depth}),
                            else => |t| @panic(@tagName(t)),
                        }
                    }

                    logln(.parser, .suffix, "[DEPTH={}] Ending suffix call-like expression", .{analyzer.suffix_depth});

                    _ = try analyzer.expectToken(.operator_right_parenthesis);
                    // const is_comma = analyzer.tokens[analyzer.token_i].id == .comma;
                    result = try analyzer.addNode(.{
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

    fn containerLiteral(analyzer: *Analyzer, type_node: Node.Index) anyerror!Node.Index {
        const token = try analyzer.expectToken(.operator_left_brace);

        var list = ArrayList(Node.Index){};

        const InitializationType = enum {
            anonymous,
            array_indices,
            container_field_names,
            empty_literal,
            empty_container_literal_guess,
            empty_array_literal,
        };

        var current_initialization: ?InitializationType = null;

        while (analyzer.peekToken() != .operator_right_brace) {
            const start_token = analyzer.token_i;
            const iteration_initialization_type: InitializationType = switch (analyzer.peekToken()) {
                .operator_dot => switch (analyzer.peekTokenAhead(1)) {
                    .identifier => switch (analyzer.peekTokenAhead(2)) {
                        .operator_assign => blk: {
                            analyzer.consumeTokens(3);
                            const field_expression_initializer = try analyzer.expression();

                            const field_initialization = try analyzer.addNode(.{
                                .id = .container_field_initialization,
                                .token = start_token,
                                .left = field_expression_initializer,
                                .right = Node.Index.invalid,
                            });

                            try list.append(analyzer.allocator, field_initialization);
                            _ = try analyzer.expectToken(.operator_comma);

                            break :blk .container_field_names;
                        },
                        else => |t| @panic(@tagName(t)),
                    },
                    else => blk: {
                        try list.append(analyzer.allocator, try analyzer.anonymousExpression());
                        _ = try analyzer.expectToken(.operator_comma);
                        break :blk .anonymous;
                    },
                },
                .string_literal,
                .identifier,
                .number_literal,
                .intrinsic,
                .fixed_keyword_if,
                => blk: {
                    const field_expression_initializer = try analyzer.expression();
                    switch (analyzer.peekToken()) {
                        .operator_comma => analyzer.consumeToken(),
                        else => {},
                    }

                    try list.append(analyzer.allocator, field_expression_initializer);
                    break :blk .anonymous;
                },
                else => |t| @panic(@tagName(t)),
            };

            if (current_initialization) |ci| {
                if (ci != iteration_initialization_type) {
                    unreachable;
                }
            }

            current_initialization = iteration_initialization_type;
        }

        _ = try analyzer.expectToken(.operator_right_brace);

        const initialization: InitializationType = current_initialization orelse switch (type_node.invalid) {
            true => .empty_literal,
            false => switch (analyzer.nodes.items[type_node.unwrap()].id) {
                .identifier => .empty_container_literal_guess,
                .array_type => .empty_array_literal,
                else => |t| @panic(@tagName(t)),
            },
        };

        return try analyzer.addNode(.{
            .id = switch (type_node.invalid) {
                true => switch (initialization) {
                    .container_field_names => .anonymous_container_literal,
                    .empty_literal => .anonymous_empty_literal,
                    .anonymous => .anonymous_array_literal,
                    else => |t| @panic(@tagName(t)),
                },
                false => switch (initialization) {
                    .container_field_names => .container_literal,
                    .empty_container_literal_guess => .empty_container_literal_guess,
                    .anonymous => .array_literal,
                    .empty_array_literal => .array_literal,
                    else => |t| @panic(@tagName(t)),
                },
            },
            .token = token,
            .left = type_node,
            .right = try analyzer.nodeList(list),
        });
    }

    fn discardNode(analyzer: *Analyzer) !Node.Index {
        const token = analyzer.token_i;
        assert(analyzer.peekToken() == .discard);
        analyzer.consumeToken();
        return try analyzer.addNode(.{
            .id = .discard,
            .token = token,
            .left = Node.Index.invalid,
            .right = Node.Index.invalid,
        });
    }

    fn primaryTypeExpression(analyzer: *Analyzer) anyerror!Node.Index {
        const token_i = analyzer.token_i;
        const token = analyzer.peekToken();

        return try switch (token) {
            .fixed_keyword_fn => blk: {
                analyzer.consumeToken();
                break :blk analyzer.functionPrototype();
            },
            .string_literal => blk: {
                analyzer.consumeToken();
                break :blk analyzer.addNode(.{
                    .id = .string_literal,
                    .token = token_i,
                    .left = Node.Index.invalid,
                    .right = Node.Index.invalid,
                });
            },
            .character_literal => blk: {
                analyzer.consumeToken();
                break :blk analyzer.addNode(.{
                    .id = .character_literal,
                    .token = token_i,
                    .left = Node.Index.invalid,
                    .right = Node.Index.invalid,
                });
            },
            .number_literal => blk: {
                analyzer.consumeToken();
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
                    analyzer.consumeToken();
                    break :blk token_i;
                },
                .left = Node.Index.invalid,
                .right = Node.Index.invalid,
            }),
            .fixed_keyword_null => analyzer.addNode(.{
                .id = .null_literal,
                .token = blk: {
                    analyzer.consumeToken();
                    break :blk token_i;
                },
                .left = Node.Index.invalid,
                .right = Node.Index.invalid,
            }),
            .fixed_keyword_unreachable => analyzer.addNode(.{
                .id = .@"unreachable",
                .token = blk: {
                    analyzer.consumeToken();
                    break :blk token_i;
                },
                .left = Node.Index.invalid,
                .right = Node.Index.invalid,
            }),
            .intrinsic => analyzer.compilerIntrinsic(),
            .fixed_keyword_bool => analyzer.addNode(.{
                .id = .bool_type,
                .token = blk: {
                    analyzer.consumeToken();
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
                    analyzer.consumeToken();
                    break :blk token_i;
                },
                .left = @bitCast(@as(u32, try std.fmt.parseInt(u16, b: {
                    const slice = analyzer.bytes(token_i)[1..];
                    if (slice.len == 0) unreachable;
                    break :b slice;
                }, 10))),
                .right = Node.Index.invalid,
            }),
            .fixed_keyword_usize, .fixed_keyword_ssize => |size_type| analyzer.addNode(.{
                .id = switch (size_type) {
                    .fixed_keyword_usize => .usize_type,
                    .fixed_keyword_ssize => .ssize_type,
                    else => unreachable,
                },
                .token = blk: {
                    analyzer.consumeToken();
                    break :blk token_i;
                },
                .left = Node.Index.invalid,
                .right = Node.Index.invalid,
            }),
            .fixed_keyword_void => analyzer.addNode(.{
                .id = .void_type,
                .token = blk: {
                    analyzer.consumeToken();
                    break :blk token_i;
                },
                .left = Node.Index.invalid,
                .right = Node.Index.invalid,
            }),
            .fixed_keyword_switch => try analyzer.switchExpression(),
            .operator_dot => try analyzer.anonymousExpression(),
            .fixed_keyword_enum => blk: {
                analyzer.consumeToken();

                const type_node = if (analyzer.peekToken() == .operator_left_parenthesis) b: {
                    analyzer.consumeToken();
                    const result = try analyzer.typeExpression();
                    _ = try analyzer.expectToken(.operator_right_parenthesis);
                    break :b result;
                } else Node.Index.invalid;

                _ = try analyzer.expectToken(.operator_left_brace);
                const node_list = try analyzer.containerMembers(.@"enum");
                _ = try analyzer.expectToken(.operator_right_brace);

                break :blk try analyzer.addNode(.{
                    .id = .enum_type,
                    .token = token_i,
                    .left = try analyzer.nodeList(node_list),
                    .right = type_node,
                });
            },
            .fixed_keyword_struct => blk: {
                analyzer.consumeToken();

                const type_node = if (analyzer.peekToken() == .operator_left_parenthesis) b: {
                    analyzer.consumeToken();
                    const result = try analyzer.typeExpression();
                    _ = try analyzer.expectToken(.operator_right_parenthesis);
                    break :b result;
                } else Node.Index.invalid;

                _ = try analyzer.expectToken(.operator_left_brace);
                const node_list = try analyzer.containerMembers(.@"struct");
                _ = try analyzer.expectToken(.operator_right_brace);

                break :blk try analyzer.addNode(.{
                    .id = .struct_type,
                    .token = token_i,
                    .left = try analyzer.nodeList(node_list),
                    .right = type_node,
                });
            },
            .operator_left_parenthesis => blk: {
                analyzer.consumeToken();
                const expr = try analyzer.expression();
                _ = try analyzer.expectToken(.operator_right_parenthesis);
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

    fn anonymousExpression(analyzer: *Analyzer) !Node.Index {
        const token_i = analyzer.token_i;
        _ = try analyzer.expectToken(.operator_dot);
        return switch (analyzer.peekToken()) {
            .identifier => try analyzer.addNode(.{
                .id = .enum_literal,
                .token = blk: {
                    analyzer.consumeToken();
                    break :blk token_i;
                },
                .left = Node.Index.invalid,
                .right = Node.Index.invalid,
            }),
            .operator_left_brace => try analyzer.containerLiteral(Node.Index.invalid),
            else => |t| @panic(@tagName(t)),
        };
    }

    // TODO:
    fn suffixOperator(analyzer: *Analyzer, left: Node.Index) !Node.Index {
        const token = analyzer.token_i;
        const result: Node.Index = switch (analyzer.peekToken()) {
            .operator_left_bracket => blk: {
                analyzer.consumeToken();
                const index_expression = try analyzer.expression();

                if (analyzer.peekToken() == .operator_dot and analyzer.peekTokenAhead(1) == .operator_dot) {
                    analyzer.consumeTokens(2);
                    const range_end_expression = switch (analyzer.peekToken()) {
                        .operator_right_bracket => Node.Index.invalid,
                        else => try analyzer.expression(),
                    };

                    _ = try analyzer.expectToken(.operator_right_bracket);

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
                    _ = try analyzer.expectToken(.operator_right_bracket);
                    break :blk try analyzer.addNode(.{
                        .id = .indexed_access,
                        .token = token,
                        .left = left,
                        .right = index_expression,
                    });
                }
            },
            .operator_dot => switch (analyzer.peekTokenAhead(1)) {
                .identifier => try analyzer.addNode(.{
                    .id = .field_access,
                    .token = blk: {
                        analyzer.consumeToken();
                        break :blk token;
                    },
                    .left = left,
                    .right = try analyzer.addNode(.{
                        .id = .identifier,
                        .token = blk: {
                            const t = analyzer.token_i;
                            analyzer.consumeToken();
                            break :blk t;
                        },
                        .left = Node.Index.invalid,
                        .right = Node.Index.invalid,
                    }),
                }),
                .operator_dot => Node.Index.invalid,
                .operator_ampersand => try analyzer.addNode(.{
                    .id = .address_of,
                    .token = blk: {
                        analyzer.consumeTokens(2);
                        break :blk token;
                    },
                    .left = left,
                    .right = Node.Index.invalid,
                }),
                .operator_at => try analyzer.addNode(.{
                    .id = .pointer_dereference,
                    .token = blk: {
                        analyzer.consumeTokens(2);
                        break :blk token;
                    },
                    .left = left,
                    .right = Node.Index.invalid,
                }),
                .operator_optional => try analyzer.addNode(.{
                    .id = .optional_unwrap,
                    .token = blk: {
                        analyzer.consumeToken();
                        break :blk token;
                    },
                    .left = left,
                    .right = .{
                        .value = @intCast(blk: {
                            const t = analyzer.token_i;
                            analyzer.consumeToken();
                            break :blk t;
                        }),
                    },
                }),
                else => |t| @panic(@tagName(t)),
            },
            else => Node.Index.invalid,
        };

        return result;
    }

    fn addNode(analyzer: *Analyzer, node: Node) !Node.Index {
        const index = analyzer.nodes.items.len;
        try analyzer.nodes.append(analyzer.allocator, node);
        // if (index == 38 or index == 37) {
        //     @breakpoint();
        // }
        logln(.parser, .node_creation, "Adding node #{} {s} to file #{}", .{ index, @tagName(node.id), analyzer.file_index.uniqueInteger() });
        // if (Logger.bitset.contains(.node_creation_detailed)) {
        //     const chunk_start = analyzer.lexer.offsets.items[node.token];
        //     const chunk_end = analyzer.lexer.offsets.items[node.token + 1];
        //     const chunk_from_start = analyzer.source_file[chunk_start..];
        //     const end = @min(200, chunk_end - chunk_start);
        //     const chunk = chunk_from_start[0..end];
        //     logln(.parser, .node_creation, "[SOURCE]: ```\n{s}\n```\n", .{chunk});
        // }

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
        assert(analyzer.peekToken() == .identifier);
        analyzer.consumeToken();
        return try analyzer.addNode(.{
            .id = .identifier,
            .token = identifier_token,
            .left = Node.Index.invalid,
            .right = Node.Index.invalid,
        });
    }

    fn containerMembers(analyzer: *Analyzer, comptime container_type: Compilation.ContainerType) !ArrayList(Node.Index) {
        var list = ArrayList(Node.Index){};

        while (analyzer.hasTokens() and analyzer.peekToken() != .operator_right_brace) {
            const first = analyzer.token_i;
            logln(.parser, .container_members, "First token for container member: {s}", .{@tagName(analyzer.peekToken())});

            const member_node_index: Node.Index = switch (analyzer.peekToken()) {
                .fixed_keyword_comptime => switch (analyzer.peekTokenAhead(1)) {
                    .operator_left_brace => blk: {
                        analyzer.consumeToken();
                        const comptime_block = try analyzer.block(.{ .is_comptime = true });

                        break :blk try analyzer.addNode(.{
                            .id = .@"comptime",
                            .token = first,
                            .left = comptime_block,
                            .right = Node.Index.invalid,
                        });
                    },
                    else => |t| @panic(@tagName(t)),
                },
                .identifier => blk: {
                    analyzer.consumeToken();
                    switch (container_type) {
                        .@"struct" => {
                            _ = try analyzer.expectToken(.operator_colon);

                            const field_type = try analyzer.typeExpression();

                            const field_default_node = if (analyzer.peekToken() == .operator_assign) b: {
                                analyzer.consumeToken();
                                const default_index = try analyzer.expression();
                                const default_node = analyzer.nodes.items[default_index.unwrap()];
                                assert(default_node.id != .node_list);
                                break :b default_index;
                            } else Node.Index.invalid;

                            _ = try analyzer.expectToken(.operator_comma);

                            const field_node = try analyzer.addNode(.{
                                .id = .container_field,
                                .token = first,
                                .left = field_type,
                                .right = field_default_node,
                            });

                            break :blk field_node;
                        },
                        .@"enum" => {
                            const value_associated = switch (analyzer.peekToken()) {
                                .operator_comma => Node.Index.invalid,
                                else => value: {
                                    analyzer.consumeToken();
                                    break :value try analyzer.expression();
                                },
                            };

                            _ = try analyzer.expectToken(.operator_comma);

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

// Here it is assumed that left brace is consumed
pub fn analyze(allocator: Allocator, lexer: lexical_analyzer.Result, source_file: []const u8, file_index: File.Index) !Result {
    const start = std.time.Instant.now() catch unreachable;
    var analyzer = Analyzer{
        .lexer = lexer,
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
    assert(analyzer.token_i == analyzer.lexer.ids.items.len);

    const node_list = try analyzer.nodeList(members);

    analyzer.nodes.items[0].left = node_list;

    const end = std.time.Instant.now() catch unreachable;

    return .{
        .nodes = analyzer.nodes,
        .node_lists = analyzer.node_lists,
        .time = end.since(start),
    };
}

pub const SymbolDeclaration = struct {
    type_node: Node.Index,
    initialization_node: Node.Index,
    mutability_token: Token.Index,
};

const Associativity = enum {
    none,
    left,
};
