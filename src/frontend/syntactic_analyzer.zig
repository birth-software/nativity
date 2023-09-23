const std = @import("std");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;
const equal = std.mem.eql;
const log = std.log;

const data_structures = @import("../data_structures.zig");
const ArrayList = data_structures.ArrayList;
const enumFromString = data_structures.enumFromString;
const HashMap = data_structures.HashMap;

const lexical_analyzer = @import("lexical_analyzer.zig");
const Token = lexical_analyzer.Token;

pub const Result = struct {
    nodes: ArrayList(Node),
    time: u64,
};

pub const Options = packed struct {
    is_comptime: bool,
};

// TODO: pack it to be more efficient
pub const Node = packed struct(u128) {
    token: u32,
    id: Id,
    left: Node.Index,
    right: Node.Index,

    pub const List = ArrayList(Node.Index);

    pub const Index = packed struct(u32) {
        value: u31,
        valid: bool = true,

        pub const invalid = Index{
            .value = 0,
            .valid = false,
        };

        pub fn get(index: Index) ?u32 {
            return if (index.valid) index.value else null;
        }

        pub fn unwrap(index: Index) u32 {
            assert(index.valid);
            return index.value;
        }
    };

    pub const Range = struct {
        start: u32,
        end: u32,
    };

    pub const Id = enum(u32) {
        main = 0,
        identifier = 1,
        number = 2,
        @"return" = 3,
        block_one = 4,
        function_declaration_no_arguments = 5,
        container_declaration = 6,
        string_literal = 7,
        compiler_intrinsic_one = 8,
        simple_variable_declaration = 9,
        assign = 10,
        @"comptime" = 11,
        node_list = 12,
        block_zero = 13,
        simple_while = 14,
        simple_function_prototype = 15,
        function_definition = 16,
        keyword_noreturn = 17,
        keyword_true = 18,
        comptime_block_zero = 19,
        comptime_block_one = 20,
        number_literal = 21,
        compiler_intrinsic_two = 22,
        comptime_block_two = 23,
        block_two = 24,
        @"unreachable" = 25,
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
    file: []const u8,
    allocator: Allocator,
    temporal_node_heap: ArrayList(Node.Index) = .{},
    node_lists: ArrayList(Node.List) = .{},

    fn expectToken(analyzer: *Analyzer, token_id: Token.Id) !u32 {
        if (analyzer.tokens[analyzer.token_i].id == token_id) {
            const result = analyzer.token_i;
            analyzer.token_i += 1;
            return result;
        } else {
            return error.unexpected_token;
        }
    }

    fn getIdentifier(analyzer: *const Analyzer, token: Token) []const u8 {
        assert(token.id == .identifier);
        const identifier = analyzer.file[token.start..][0..token.len];
        return identifier;
    }

    fn containerMembers(analyzer: *Analyzer) !Members {
        const node_heap_top = analyzer.temporal_node_heap.items.len;
        defer analyzer.temporal_node_heap.shrinkRetainingCapacity(node_heap_top);

        while (analyzer.token_i < analyzer.tokens.len) {
            const first = analyzer.token_i;
            const member_node: Node = switch (analyzer.tokens[first].id) {
                .fixed_keyword_comptime => switch (analyzer.tokens[analyzer.token_i + 1].id) {
                    .left_brace => blk: {
                        analyzer.token_i += 1;
                        const comptime_block = try analyzer.block(.{ .is_comptime = true });

                        break :blk .{
                            .id = .@"comptime",
                            .token = first,
                            .left = comptime_block,
                            .right = Node.Index.invalid,
                        };
                    },
                    else => |foo| std.debug.panic("NI: {s}", .{@tagName(foo)}),
                },
                .fixed_keyword_const, .fixed_keyword_var => blk: {
                    analyzer.token_i += 1;
                    _ = try analyzer.expectToken(.identifier);

                    // TODO: type
                    _ = try analyzer.expectToken(.equal);

                    // TODO: do this in a function
                    const init_node = try analyzer.expression();
                    // const init_node = switch (analyzer.tokens[analyzer.token_i].id) {
                    //     .identifier => unreachable,
                    //     .hash => try analyzer.compilerIntrinsic(),
                    //     .left_parenthesis => try analyzer.function(),
                    //     else => |t| std.debug.panic("NI: {s}", .{@tagName(t)}),
                    // };

                    _ = try analyzer.expectToken(.semicolon);

                    // TODO:
                    const type_node = Node.Index.invalid;
                    const top_level_decl = .{
                        .id = .simple_variable_declaration,
                        .token = first,
                        .left = type_node,
                        .right = init_node,
                    };

                    break :blk top_level_decl;
                },
                .identifier => {
                    unreachable;
                },
                else => |t| std.debug.panic("NI: {s}", .{@tagName(t)}),
            };

            const member_index = try analyzer.addNode(member_node);
            try analyzer.temporal_node_heap.append(analyzer.allocator, member_index);
        }

        const members_array = analyzer.temporal_node_heap.items[node_heap_top..];
        const members: Members = switch (members_array.len) {
            1 => .{
                .len = 1,
                .left = members_array[0],
                .right = Node.Index.invalid,
            },
            2 => .{
                .len = 2,
                .left = members_array[0],
                .right = members_array[1],
            },
            else => |len| std.debug.panic("Len: {}", .{len}),
        };

        return members;
    }

    fn function(analyzer: *Analyzer) !Node.Index {
        const token = analyzer.token_i;
        assert(analyzer.tokens[token].id == .fixed_keyword_fn);
        analyzer.token_i += 1;
        const function_prototype = try analyzer.functionPrototype();
        const is_comptime = false;
        _ = is_comptime;
        const function_body = try analyzer.block(.{ .is_comptime = false });
        return analyzer.addNode(.{
            .id = .function_definition,
            .token = token,
            .left = function_prototype,
            .right = function_body,
        });
    }

    fn functionPrototype(analyzer: *Analyzer) !Node.Index {
        const token = analyzer.token_i;
        assert(analyzer.tokens[token].id == .left_parenthesis);
        const arguments = try analyzer.argumentList(.left_parenthesis, .right_parenthesis);
        const return_type = try analyzer.typeExpression();

        return analyzer.addNode(.{
            .id = .simple_function_prototype,
            .token = token,
            .left = arguments,
            .right = return_type,
        });
    }

    fn argumentList(analyzer: *Analyzer, maybe_start_token: ?Token.Id, end_token: Token.Id) !Node.Index {
        if (maybe_start_token) |start_token| {
            _ = try analyzer.expectToken(start_token);
        }

        var list = ArrayList(Node.Index){};

        while (analyzer.tokens[analyzer.token_i].id != end_token) {
            @panic("TODO: argument list");
        }

        _ = try analyzer.expectToken(end_token);

        if (list.items.len != 0) {
            @panic("TODO: arguments");
        } else {
            return Node.Index.invalid;
        }
    }

    fn assignExpressionStatement(analyzer: *Analyzer) !Node.Index {
        const result = try analyzer.assignExpression();
        _ = try analyzer.expectToken(.semicolon);
        return result;
    }

    fn block(analyzer: *Analyzer, options: Options) !Node.Index {
        const left_brace = try analyzer.expectToken(.left_brace);
        const node_heap_top = analyzer.temporal_node_heap.items.len;
        defer analyzer.temporal_node_heap.shrinkRetainingCapacity(node_heap_top);

        while (analyzer.tokens[analyzer.token_i].id != .right_brace) {
            const first_statement_token = analyzer.tokens[analyzer.token_i];
            const statement_index = switch (first_statement_token.id) {
                .identifier => switch (analyzer.tokens[analyzer.token_i + 1].id) {
                    .colon => {
                        unreachable;
                    },
                    else => try analyzer.assignExpressionStatement(),
                },
                .fixed_keyword_unreachable => try analyzer.assignExpressionStatement(),
                .fixed_keyword_while => try analyzer.whileStatement(options),
                else => unreachable,
            };
            try analyzer.temporal_node_heap.append(analyzer.allocator, statement_index);
        }

        _ = try analyzer.expectToken(.right_brace);

        const statement_array = analyzer.temporal_node_heap.items[node_heap_top..];
        const node: Node = switch (statement_array.len) {
            0 => .{
                .id = switch (options.is_comptime) {
                    true => .comptime_block_zero,
                    false => .block_zero,
                },
                .token = left_brace,
                .left = Node.Index.invalid,
                .right = Node.Index.invalid,
            },
            1 => .{
                .id = switch (options.is_comptime) {
                    true => .comptime_block_one,
                    false => .block_one,
                },
                .token = left_brace,
                .left = statement_array[0],
                .right = Node.Index.invalid,
            },
            2 => .{
                .id = switch (options.is_comptime) {
                    true => .comptime_block_two,
                    false => .block_two,
                },
                .token = left_brace,
                .left = statement_array[0],
                .right = statement_array[1],
            },
            else => |len| std.debug.panic("len: {}", .{len}),
        };
        return analyzer.addNode(node);
    }

    fn whileStatement(analyzer: *Analyzer, options: Options) error{ OutOfMemory, unexpected_token, not_implemented }!Node.Index {
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

    fn assignExpression(analyzer: *Analyzer) !Node.Index {
        const expr = try analyzer.expression();
        const expression_id: Node.Id = switch (analyzer.tokens[analyzer.token_i].id) {
            .semicolon => return expr,
            .equal => .assign,
            else => unreachable,
        };

        const node = Node{
            .id = expression_id,
            .token = blk: {
                const token_i = analyzer.token_i;
                analyzer.token_i += 1;
                break :blk token_i;
            },
            .left = expr,
            .right = try analyzer.expression(),
        };
        std.debug.print("assign:\nleft: {}.\nright: {}\n", .{ node.left, node.right });
        return analyzer.addNode(node);
    }

    fn compilerIntrinsic(analyzer: *Analyzer) !Node.Index {
        const hash = try analyzer.expectToken(.hash);
        _ = try analyzer.expectToken(.identifier);
        _ = try analyzer.expectToken(.left_parenthesis);

        const temporal_heap_top = analyzer.temporal_node_heap.items.len;
        defer analyzer.temporal_node_heap.shrinkRetainingCapacity(temporal_heap_top);

        while (analyzer.tokens[analyzer.token_i].id != .right_parenthesis) {
            const parameter = try analyzer.expression();
            try analyzer.temporal_node_heap.append(analyzer.allocator, parameter);

            switch (analyzer.tokens[analyzer.token_i].id) {
                .comma => analyzer.token_i += 1,
                .right_parenthesis => continue,
                else => unreachable,
            }
        }

        // Consume the right parenthesis
        analyzer.token_i += 1;

        const parameters = analyzer.temporal_node_heap.items[temporal_heap_top..];

        return switch (parameters.len) {
            1 => analyzer.addNode(.{
                .id = .compiler_intrinsic_one,
                .token = hash,
                .left = parameters[0],
                .right = Node.Index.invalid,
            }),
            2 => analyzer.addNode(.{
                .id = .compiler_intrinsic_two,
                .token = hash,
                .left = parameters[0],
                .right = parameters[1],
            }),
            else => unreachable,
        };
    }

    fn expression(analyzer: *Analyzer) error{ OutOfMemory, not_implemented, unexpected_token }!Node.Index {
        return analyzer.expressionPrecedence(0);
    }

    fn expressionPrecedence(analyzer: *Analyzer, minimum_precedence: i32) !Node.Index {
        var result = try analyzer.prefixExpression();

        var banned_precedence: i32 = -1;

        while (analyzer.token_i < analyzer.tokens.len) {
            const precedence: i32 = switch (analyzer.tokens[analyzer.token_i].id) {
                .equal, .semicolon, .right_parenthesis, .right_brace, .comma => -1,
                else => |foo| std.debug.panic("Foo: ({s}) {}", .{ @tagName(foo), foo }),
            };

            if (precedence < minimum_precedence) {
                break;
            }

            if (precedence == banned_precedence) {
                break;
            }

            // TODO: fix this
            const node_index = try analyzer.expressionPrecedence(1);
            _ = node_index;
            unreachable;
        }

        return result;
    }

    fn prefixExpression(analyzer: *Analyzer) !Node.Index {
        switch (analyzer.tokens[analyzer.token_i].id) {
            // .bang => .bool_not,
            // .minus => .negation,
            // .tilde => .bit_not,
            // .minus_percent => .negation_wrap,
            // .ampersand => .address_of,
            // .keyword_try => .@"try",
            // .keyword_await => .@"await",

            else => |pref| {
                _ = pref;
                return analyzer.primaryExpression();
            },
        }

        return error.not_implemented;
    }

    fn primaryExpression(analyzer: *Analyzer) !Node.Index {
        const result = switch (analyzer.tokens[analyzer.token_i].id) {
            .identifier => switch (analyzer.tokens[analyzer.token_i + 1].id) {
                .colon => unreachable,
                else => try analyzer.curlySuffixExpression(),
            },
            .string_literal, .number_literal, .fixed_keyword_true, .fixed_keyword_false, .hash, .fixed_keyword_unreachable => try analyzer.curlySuffixExpression(),
            .fixed_keyword_fn => analyzer.function(),
            // todo:?
            // .left_brace => try analyzer.block(),
            else => |id| {
                log.warn("By default, calling curlySuffixExpression with {s}", .{@tagName(id)});
                unreachable;
            },
        };

        return result;
    }

    fn curlySuffixExpression(analyzer: *Analyzer) !Node.Index {
        const left = try analyzer.typeExpression();

        return switch (analyzer.tokens[analyzer.token_i].id) {
            .left_brace => unreachable,
            else => left,
        };
    }

    fn noReturn(analyzer: *Analyzer) !Node.Index {
        const token_i = analyzer.token_i;
        assert(analyzer.tokens[token_i].id == .fixed_keyword_noreturn);
        analyzer.token_i += 1;
        return analyzer.addNode(.{
            .id = .keyword_noreturn,
            .token = token_i,
            .left = Node.Index.invalid,
            .right = Node.Index.invalid,
        });
    }

    fn boolTrue(analyzer: *Analyzer) !Node.Index {
        const token_i = analyzer.token_i;
        assert(analyzer.tokens[token_i].id == .fixed_keyword_true);
        analyzer.token_i += 1;
        return analyzer.addNode(.{
            .id = .keyword_true,
            .token = token_i,
            .left = Node.Index.invalid,
            .right = Node.Index.invalid,
        });
    }

    fn typeExpression(analyzer: *Analyzer) !Node.Index {
        return switch (analyzer.tokens[analyzer.token_i].id) {
            .identifier, .fixed_keyword_noreturn, .fixed_keyword_true, .fixed_keyword_false, .hash => try analyzer.errorUnionExpression(),
            else => |id| blk: {
                log.warn("By default, calling errorUnionExpression with {s}", .{@tagName(id)});

                const result = try analyzer.errorUnionExpression();

                break :blk result;
            },
        };
    }

    fn errorUnionExpression(analyzer: *Analyzer) !Node.Index {
        const suffix_expression = try analyzer.suffixExpression();

        return switch (analyzer.tokens[analyzer.token_i].id) {
            .bang => unreachable,
            else => suffix_expression,
        };
    }

    fn suffixExpression(analyzer: *Analyzer) !Node.Index {
        var result = try analyzer.primaryTypeExpression();

        while (true) {
            if (analyzer.suffixOperator()) |_| {
                unreachable;
            } else {
                if (analyzer.tokens[analyzer.token_i].id == .left_parenthesis) {
                    analyzer.token_i += 1;

                    var expression_list = ArrayList(Node.Index){};
                    while (analyzer.tokens[analyzer.token_i].id != .right_parenthesis) {
                        const parameter = try analyzer.expression();
                        try expression_list.append(analyzer.allocator, parameter);
                        analyzer.token_i += @intFromBool(switch (analyzer.tokens[analyzer.token_i].id) {
                            .comma, .right_parenthesis => true,
                            .colon, .right_brace, .right_bracket => unreachable,
                            else => unreachable,
                        });
                    }

                    _ = try analyzer.expectToken(.right_parenthesis);
                    @panic("TODO");
                } else {
                    return result;
                }
            }
        }

        unreachable;
    }

    fn primaryTypeExpression(analyzer: *Analyzer) !Node.Index {
        const token_i = analyzer.token_i;
        const token = analyzer.tokens[token_i];
        return switch (token.id) {
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
            .identifier => switch (analyzer.tokens[token_i + 1].id) {
                .colon => unreachable,
                else => blk: {
                    const identifier = analyzer.getIdentifier(token);
                    std.debug.print("identifier: {s}\n", .{identifier});
                    analyzer.token_i += 1;
                    if (equal(u8, identifier, "_")) {
                        break :blk Node.Index.invalid;
                    } else break :blk analyzer.addNode(.{
                        .id = .identifier,
                        .token = token_i,
                        .left = Node.Index.invalid,
                        .right = Node.Index.invalid,
                    });
                },
            },
            .fixed_keyword_noreturn => try analyzer.noReturn(),
            .fixed_keyword_true => try analyzer.boolTrue(),
            .fixed_keyword_unreachable => try analyzer.addNode(.{
                .id = .@"unreachable",
                .token = blk: {
                    analyzer.token_i += 1;
                    break :blk token_i;
                },
                .left = Node.Index.invalid,
                .right = Node.Index.invalid,
            }),
            .hash => analyzer.compilerIntrinsic(),
            else => |foo| {
                switch (foo) {
                    .identifier => std.debug.panic("{s}: {s}", .{ @tagName(foo), analyzer.getIdentifier(analyzer.tokens[token_i]) }),
                    else => std.debug.panic("{s}", .{@tagName(foo)}),
                }
            },
        };
    }

    // TODO:
    fn suffixOperator(analyzer: *Analyzer) ?bool {
        _ = analyzer;

        return null;
    }

    fn addNode(analyzer: *Analyzer, node: Node) !Node.Index {
        const index = analyzer.nodes.items.len;
        try analyzer.nodes.append(analyzer.allocator, node);
        std.debug.print("Adding node #{} {s}\n", .{ index, @tagName(node.id) });
        return Node.Index{
            .value = @intCast(index),
        };
    }
};

const Members = struct {
    len: usize,
    left: Node.Index,
    right: Node.Index,

    pub fn toRange(members: Members) Node.Range {
        return switch (members.len) {
            0 => unreachable,
            1 => .{
                .start = members.left.value,
                .end = members.left.value,
            },
            2 => .{
                .start = members.left.value,
                .end = members.right.value,
            },
            else => unreachable,
        };
    }
};

pub fn analyze(allocator: Allocator, tokens: []const Token, file: []const u8) !Result {
    const start = std.time.Instant.now() catch unreachable;
    var analyzer = Analyzer{
        .tokens = tokens,
        .file = file,
        .allocator = allocator,
    };
    const node_index = try analyzer.addNode(.{
        .id = .main,
        .token = 0,
        .left = Node.Index.invalid,
        .right = Node.Index.invalid,
    });

    assert(node_index.value == 0);
    assert(node_index.valid);
    const members = try analyzer.containerMembers();
    const member_range = members.toRange();
    analyzer.nodes.items[0].left = .{ .value = @intCast(member_range.start) };
    analyzer.nodes.items[0].right = .{ .value = @intCast(member_range.end) };

    const end = std.time.Instant.now() catch unreachable;

    analyzer.temporal_node_heap.clearAndFree(allocator);

    return .{
        .nodes = analyzer.nodes,
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
