const std = @import("std");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;
const log = std.log;

const data_structures = @import("data_structures.zig");
const ArrayList = data_structures.ArrayList;
const HashMap = data_structures.HashMap;

const lexer = @import("lexer.zig");

pub const Result = struct {
    function_map: ArrayList(lexer.Identifier),
    nodes: ArrayList(Node),

    pub fn free(result: *Result, allocator: Allocator) void {
        result.functions.clearAndFree(allocator);
    }
};

pub const Node = packed struct(u64) {
    type: Type,
    left: Node.Index,
    right: Node.Index,

    pub const Index = u27;

    pub const Type = enum(u10) {
        root = 0,
        identifier = 1,
        number = 2,
        @"return" = 3,
        block_one = 4,
        function_declaration_no_arguments = 5,
        container_declaration = 6,
    };
};

const Error = error{
    unexpected_token,
    not_implemented,
    OutOfMemory,
};

pub fn parse(allocator: Allocator, lexer_result: *const lexer.Result) !Result {
    var parser = Parser{
        .allocator = allocator,
        .nodes = ArrayList(Node){},
        .function_map = ArrayList(lexer.Identifier){},
        .lexer = .{
            .result = lexer_result,
        },
    };
    errdefer parser.free();

    const node_index = try parser.appendNode(Node{
        .type = .root,
        .left = 0,
        .right = 0,
    });
    _ = node_index;

    const members = try parser.parseContainerMembers();
    _ = members;

    return Result{
        .function_map = parser.function_map,
        .nodes = parser.nodes,
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

const PeekResult = union(lexer.TokenId) {
    identifier: lexer.Identifier,
    operator: lexer.Operator,
    number: lexer.Number,
};

const Lexer = struct {
    result: *const lexer.Result,
    indices: struct {
        identifier: u32 = 0,
        operator: u32 = 0,
        number: u32 = 0,
        id: u32 = 0,
    } = .{},

    fn hasTokens(l: *const Lexer) bool {
        return l.indices.id < l.result.arrays.id.items.len;
    }

    fn currentTokenIndex(l: *const Lexer, comptime token_id: lexer.TokenId) u32 {
        assert(l.isCurrentToken(token_id));
        return @field(l.indices, @tagName(token_id));
    }

    fn consume(l: *Lexer, comptime token_id: lexer.TokenId) void {
        assert(l.isCurrentToken(token_id));
        l.indices.id += 1;
        const index_ptr = &@field(l.indices, @tagName(token_id));
        const index = index_ptr.*;
        const token_value = @field(l.result.arrays, @tagName(token_id)).items[index];
        log.err("Consuming {s} ({})...", .{ @tagName(token_id), token_value });

        index_ptr.* += 1;
    }

    fn isCurrentToken(l: *const Lexer, token_id: lexer.TokenId) bool {
        return l.result.arrays.id.items[l.indices.id] == token_id;
    }

    fn getIdentifier(l: *const Lexer, identifier: Node) []const u8 {
        comptime {
            assert(lexer.Identifier == Node);
        }

        assert(identifier.type == .identifier);

        return l.result.file[identifier.left..][0 .. identifier.right - identifier.left];
    }

    fn expectTokenType(l: *Lexer, comptime expected_token_id: lexer.TokenId) !lexer.TokenTypeMap[@intFromEnum(expected_token_id)] {
        const peek_result = l.peek() orelse return error.not_implemented;
        return switch (peek_result) {
            expected_token_id => |token| blk: {
                l.consume(expected_token_id);
                break :blk token;
            },
            else => error.not_implemented,
        };
    }

    fn expectTokenTypeIndex(l: *Lexer, comptime expected_token_id: lexer.TokenId) !u32 {
        const peek_result = l.peek() orelse return error.not_implemented;
        return switch (peek_result) {
            expected_token_id => blk: {
                const index = l.currentTokenIndex(expected_token_id);
                l.consume(expected_token_id);
                break :blk index;
            },
            else => error.not_implemented,
        };
    }

    fn expectSpecificToken(l: *Lexer, comptime expected_token_id: lexer.TokenId, expected_token: lexer.TokenTypeMap[@intFromEnum(expected_token_id)]) !void {
        const peek_result = l.peek() orelse return error.not_implemented;
        switch (peek_result) {
            expected_token_id => |token| {
                if (expected_token != token) {
                    return error.not_implemented;
                }

                l.consume(expected_token_id);
            },
            else => |token| {
                std.debug.panic("{s}", .{@tagName(token)});
            },
        }
    }

    fn maybeExpectOperator(l: *Lexer, expected_operator: lexer.Operator) bool {
        return switch (l.peek() orelse unreachable) {
            .operator => |operator| {
                const result = operator == expected_operator;
                if (result) {
                    l.consume(.operator);
                }
                return result;
            },
            else => false,
        };
    }

    fn peek(l: *const Lexer) ?PeekResult {
        if (l.indices.id >= l.result.arrays.id.items.len) {
            return null;
        }

        return switch (l.result.arrays.id.items[l.indices.id]) {
            inline else => |token| blk: {
                const tag = @tagName(token);
                const index = @field(l.indices, tag);
                const array = &@field(l.result.arrays, tag);

                break :blk @unionInit(PeekResult, tag, array.items[index]);
            },
        };
    }
};

const Parser = struct {
    lexer: Lexer,
    nodes: ArrayList(Node),
    function_map: ArrayList(lexer.Identifier),
    allocator: Allocator,

    fn appendNode(parser: *Parser, node: Node) !Node.Index {
        const index = parser.nodes.items.len;
        try parser.nodes.append(parser.allocator, node);
        return @intCast(index);
    }

    fn getNode(parser: *Parser, node_index: Node.Index) *Node {
        return &parser.nodes.items[node_index];
    }

    fn free(parser: *Parser) void {
        _ = parser;
    }

    fn parseTypeExpression(parser: *Parser) !Node.Index {
        // TODO: make this decent
        return switch (parser.lexer.peek() orelse unreachable) {
            .identifier => parser.nodeFromToken(.identifier),
            else => unreachable,
        };
    }

    fn parseFunctionDeclaration(parser: *Parser) !Node.Index {
        try parser.lexer.expectSpecificToken(.operator, .left_parenthesis);
        while (!parser.lexer.maybeExpectOperator(.right_parenthesis)) {
            return error.not_implemented;
        }

        const t = try parser.parseTypeExpression();
        const function_declaration = try parser.appendNode(.{
            .type = .function_declaration_no_arguments,
            .left = t,
            .right = try parser.parseBlock(),
        });
        return function_declaration;
    }

    fn parseBlock(parser: *Parser) !Node.Index {
        try parser.lexer.expectSpecificToken(.operator, .left_brace);

        var statements = ArrayList(Node.Index){};

        while (!parser.lexer.maybeExpectOperator(.right_brace)) {
            const statement = try parser.parseStatement();
            try statements.append(parser.allocator, statement);
        }

        const node: Node = switch (statements.items.len) {
            0 => unreachable,
            1 => .{
                .type = .block_one,
                .left = statements.items[0],
                .right = 0,
            },
            else => unreachable,
        };
        log.debug("Parsed block!", .{});
        return parser.appendNode(node);
    }

    fn parseStatement(parser: *Parser) !Node.Index {
        // TODO: more stuff before
        const expression = try parser.parseAssignExpression();
        try parser.lexer.expectSpecificToken(.operator, .semicolon);

        return expression;
    }

    fn parseAssignExpression(parser: *Parser) !Node.Index {
        const expression = try parser.parseExpression();
        switch (parser.lexer.peek() orelse unreachable) {
            .operator => |operator| switch (operator) {
                .semicolon => return expression,
                else => unreachable,
            },
            else => unreachable,
        }

        return error.not_implemented;
    }

    fn parseExpression(parser: *Parser) Error!Node.Index {
        return parser.parseExpressionPrecedence(0);
    }

    fn parseExpressionPrecedence(parser: *Parser, minimum_precedence: i32) !Node.Index {
        var expr_index = try parser.parsePrefixExpression();
        log.debug("Expr index: {}", .{expr_index});

        var banned_precedence: i32 = -1;
        while (parser.lexer.hasTokens()) {
            const precedence: i32 = switch (parser.lexer.peek() orelse unreachable) {
                .operator => |operator| switch (operator) {
                    .semicolon => -1,
                    else => @panic(@tagName(operator)),
                },
                else => |foo| std.debug.panic("Foo: ({s}) {}", .{ @tagName(foo), foo }),
            };

            if (precedence < minimum_precedence) {
                break;
            }

            if (precedence == banned_precedence) {
                unreachable;
            }

            const node_index = try parser.parseExpressionPrecedence(1);
            _ = node_index;

            unreachable;
        }

        log.err("Parsed expression precedence", .{});

        return expr_index;
    }

    fn parsePrefixExpression(parser: *Parser) !Node.Index {
        switch (parser.lexer.peek() orelse unreachable) {
            // .bang => .bool_not,
            // .minus => .negation,
            // .tilde => .bit_not,
            // .minus_percent => .negation_wrap,
            // .ampersand => .address_of,
            // .keyword_try => .@"try",
            // .keyword_await => .@"await",

            else => |pref| {
                log.err("Pref: {s}", .{@tagName(pref)});
                return parser.parsePrimaryExpression();
            },
        }

        return error.not_implemented;
    }

    fn nodeFromToken(parser: *Parser, comptime token_id: lexer.TokenId) !Node.Index {
        const node = try parser.appendNode(.{
            .type = @field(Node.Type, @tagName(token_id)),
            .left = @intCast(parser.lexer.currentTokenIndex(token_id)),
            .right = 0,
        });
        parser.lexer.consume(token_id);

        return node;
    }

    fn parsePrimaryExpression(parser: *Parser) !Node.Index {
        const result = switch (parser.lexer.peek() orelse unreachable) {
            .number => try parser.nodeFromToken(.number),
            .identifier => |identifier| {
                const identifier_name = parser.lexer.getIdentifier(identifier);
                inline for (@typeInfo(Keyword).Enum.fields) |keyword| {
                    if (std.mem.eql(u8, identifier_name, keyword.name)) return switch (@as(Keyword, @enumFromInt(keyword.value))) {
                        .@"return" => blk: {
                            parser.lexer.consume(.identifier);
                            const node_ref = try parser.appendNode(.{
                                .type = .@"return",
                                .left = try parser.parseExpression(),
                                .right = 0,
                            });
                            break :blk node_ref;
                        },
                        .@"fn" => blk: {
                            parser.lexer.consume(.identifier);
                            // TODO: figure out name association
                            break :blk try parser.parseFunctionDeclaration();
                        },
                    };
                }

                unreachable;
            },
            else => |foo| {
                std.debug.panic("foo: {s}. {}", .{ @tagName(foo), foo });
            },
        };

        return result;
    }

    fn parseContainerMembers(parser: *Parser) !void {
        var container_nodes = ArrayList(Node.Index){};
        while (parser.lexer.hasTokens()) {
            const container_node = switch (parser.lexer.peek() orelse unreachable) {
                .identifier => |first_identifier_ref| blk: {
                    parser.lexer.consume(.identifier);

                    const first_identifier = parser.lexer.getIdentifier(first_identifier_ref);

                    if (std.mem.eql(u8, first_identifier, "comptime")) {
                        unreachable;
                    } else {
                        const mutability_qualifier: ExpressionMutabilityQualifier = if (std.mem.eql(u8, first_identifier, @tagName(ExpressionMutabilityQualifier.@"const"))) .@"const" else if (std.mem.eql(u8, first_identifier, @tagName(ExpressionMutabilityQualifier.@"var"))) .@"var" else @panic(first_identifier);
                        _ = mutability_qualifier;

                        const identifier = try parser.appendNode(.{
                            .type = .identifier,
                            .left = @intCast(try parser.lexer.expectTokenTypeIndex(.identifier)),
                            .right = 0,
                        });

                        switch (parser.lexer.peek() orelse unreachable) {
                            .operator => |operator| switch (operator) {
                                .colon => unreachable,
                                .equal => {
                                    parser.lexer.consume(.operator);

                                    const expression = try parser.parseExpression();
                                    break :blk try parser.appendNode(.{
                                        .type = .container_declaration,
                                        .left = expression,
                                        .right = identifier,
                                    });
                                },
                                else => unreachable,
                            },
                            else => |foo| std.debug.panic("WTF: {}", .{foo}),
                        }
                    }
                },
                else => |a| std.debug.panic("{}", .{a}),
            };

            try container_nodes.append(parser.allocator, container_node);
        }
    }
};
