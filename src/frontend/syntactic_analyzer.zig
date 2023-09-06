const std = @import("std");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;
const equal = std.mem.eql;
const log = std.log;

const data_structures = @import("../data_structures.zig");
const ArrayList = data_structures.ArrayList;
const HashMap = data_structures.HashMap;

const lexical_analyzer = @import("lexical_analyzer.zig");
const Token = lexical_analyzer.Token;

pub const Result = struct {
    nodes: ArrayList(Node),
    time: u64,

    pub fn free(result: *Result, allocator: Allocator) void {
        result.nodes.clearAndFree(allocator);
    }
};

pub const Node = packed struct(u96) {
    token: u32,
    id: Id,
    left: Node.Index,
    right: Node.Index,

    pub const Index = u27;

    pub const Range = struct {
        start: u32,
        end: u32,
    };

    pub const Id = enum(u10) {
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

    fn free(analyzer: *Analyzer) void {
        _ = analyzer;
    }

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
                .identifier => blk: {
                    const first_identifier_token = analyzer.tokens[first];
                    analyzer.token_i += 1;

                    const identifier = analyzer.getIdentifier(first_identifier_token);

                    if (equal(u8, identifier, "comptime")) {
                        switch (analyzer.tokens[analyzer.token_i].id) {
                            .left_brace => {
                                const comptime_block = try analyzer.block();

                                break :blk .{
                                    .id = .@"comptime",
                                    .token = first,
                                    .left = comptime_block,
                                    .right = 0,
                                };
                            },
                            else => |foo| std.debug.panic("NI: {s}", .{@tagName(foo)}),
                        }
                    } else {
                        const is_const = equal(u8, identifier, "const");
                        const is_var = equal(u8, identifier, "var");
                        assert(is_const or is_var);

                        _ = try analyzer.expectToken(.identifier);

                        // TODO: type
                        _ = try analyzer.expectToken(.equal);

                        // TODO: do this in a function
                        const init_node = switch (analyzer.tokens[analyzer.token_i].id) {
                            .identifier => unreachable,
                            .hash => try analyzer.compilerIntrinsic(),
                            else => |t| std.debug.panic("NI: {s}", .{@tagName(t)}),
                        };

                        _ = try analyzer.expectToken(.semicolon);

                        // TODO:
                        const type_node = 0;
                        const top_level_decl = .{
                            .id = .simple_variable_declaration,
                            .token = first,
                            .left = type_node,
                            .right = init_node,
                        };

                        break :blk top_level_decl;
                    }
                },
                else => |t| std.debug.panic("NI: {s}", .{@tagName(t)}),
            };

            const member_index = try analyzer.addNode(member_node);
            try analyzer.temporal_node_heap.append(analyzer.allocator, member_index);
        }

        const members_array = analyzer.temporal_node_heap.items[node_heap_top..];
        const members: Members = switch (members_array.len) {
            2 => .{
                .len = 2,
                .left = members_array[0],
                .right = members_array[1],
            },
            else => |len| std.debug.panic("Len: {}", .{len}),
        };

        return members;
    }

    fn block(analyzer: *Analyzer) !Node.Index {
        const left_brace = try analyzer.expectToken(.left_brace);
        const node_heap_top = analyzer.temporal_node_heap.items.len;
        defer analyzer.temporal_node_heap.shrinkRetainingCapacity(node_heap_top);

        while (analyzer.tokens[analyzer.token_i].id != .right_brace) {
            const statement_index = try analyzer.statement();
            try analyzer.temporal_node_heap.append(analyzer.allocator, statement_index);
        }
        _ = try analyzer.expectToken(.right_brace);

        const statement_array = analyzer.temporal_node_heap.items[node_heap_top..];
        const node: Node = switch (statement_array.len) {
            1 => .{
                .id = .block_one,
                .token = left_brace,
                .left = statement_array[0],
                .right = 0,
            },
            else => |len| std.debug.panic("len: {}", .{len}),
        };
        return analyzer.addNode(node);
    }

    fn statement(analyzer: *Analyzer) !Node.Index {
        // TODO: more stuff before
        const result = try analyzer.assignExpression();
        _ = try analyzer.expectToken(.semicolon);

        return result;
    }

    fn assignExpression(analyzer: *Analyzer) !Node.Index {
        const expr = try analyzer.expression();
        const expression_id: Node.Id = switch (analyzer.tokens[analyzer.token_i].id) {
            .semicolon => return expr,
            .equal => .assign,
            else => unreachable,
        };

        return analyzer.addNode(.{
            .id = expression_id,
            .token = blk: {
                const token_i = analyzer.token_i;
                analyzer.token_i += 1;
                break :blk token_i;
            },
            .left = expr,
            .right = try analyzer.expression(),
        });
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
                .right = 0,
            }),
            else => unreachable,
        };
    }

    fn expression(analyzer: *Analyzer) !Node.Index {
        return analyzer.expressionPrecedence(0);
    }

    fn expressionPrecedence(analyzer: *Analyzer, minimum_precedence: i32) !Node.Index {
        var result = try analyzer.prefixExpression();

        var banned_precedence: i32 = -1;

        while (analyzer.token_i < analyzer.tokens.len) {
            const precedence: i32 = switch (analyzer.tokens[analyzer.token_i].id) {
                .equal, .semicolon, .right_parenthesis => -1,
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
            .string_literal => try analyzer.curlySuffixExpression(),
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

    fn typeExpression(analyzer: *Analyzer) !Node.Index {
        return switch (analyzer.tokens[analyzer.token_i].id) {
            .string_literal, .identifier => try analyzer.errorUnionExpression(),
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
                    unreachable;
                } else {
                    return result;
                }
            }
        }

        unreachable;
    }

    fn primaryTypeExpression(analyzer: *Analyzer) !Node.Index {
        const token_i = analyzer.token_i;
        return switch (analyzer.tokens[token_i].id) {
            .string_literal => blk: {
                analyzer.token_i += 1;
                break :blk analyzer.addNode(.{
                    .id = .string_literal,
                    .token = token_i,
                    .left = 0,
                    .right = 0,
                });
            },
            .identifier => switch (analyzer.tokens[token_i + 1].id) {
                .colon => unreachable,
                else => analyzer.addNode(.{
                    .id = .identifier,
                    .token = blk: {
                        analyzer.token_i += 1;
                        break :blk token_i;
                    },
                    .left = 0,
                    .right = 0,
                }),
            },
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
        return @intCast(index);
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
                .start = members.left,
                .end = members.left,
            },
            2 => .{
                .start = members.left,
                .end = members.right,
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
    errdefer analyzer.free();
    const node_index = try analyzer.addNode(.{
        .id = .main,
        .token = 0,
        .left = 0,
        .right = 0,
    });

    assert(node_index == 0);
    const members = try analyzer.containerMembers();
    const member_range = members.toRange();
    analyzer.nodes.items[0].left = @intCast(member_range.start);
    analyzer.nodes.items[0].right = @intCast(member_range.end);

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
};
