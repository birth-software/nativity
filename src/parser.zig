const std = @import("std");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;

const data_structures = @import("data_structures.zig");
const ArrayList = data_structures.ArrayList;

const lexer = @import("lexer.zig");

pub const Result = struct {
    functions: ArrayList(Function),
    strings: StringMap,

    pub fn free(result: *Result, allocator: Allocator) void {
        result.functions.clearAndFree(allocator);
        result.strings.clearAndFree(allocator);
    }
};

const PeekResult = union(lexer.TokenId) {
    special_character: lexer.SpecialCharacter,
    identifier: []const u8,
};

const Function = struct {
    name: u32,
    return_type: u32,
    arguments: ArrayList(Argument),
    statements: ArrayList(Statement),

    const Argument = struct {
        foo: u32 = 0,
    };
};

const Statement = struct {
    foo: u32 = 0,
};

const StringMap = std.AutoHashMapUnmanaged(u32, []const u8);

const Parser = struct {
    id_index: u32 = 0,
    identifier_index: u32 = 0,
    special_character_index: u32 = 0,
    strings: StringMap,
    allocator: Allocator,
    functions: ArrayList(Function),

    fn parse(parser: *Parser, lexer_result: *const lexer.Result) !Result {
        while (parser.id_index < lexer_result.ids.items.len) {
            try parser.parseTopLevelDeclaration(lexer_result);
        }

        return Result{
            .functions = parser.functions,
            .strings = parser.strings,
        };
    }

    fn parseFunction(parser: *Parser, lexer_result: *const lexer.Result, name: u32) !Function {
        assert(lexer_result.special_characters.items[parser.special_character_index] == .left_parenthesis);
        parser.consume(lexer_result, .special_character);

        while (true) {
            if (parser.expectSpecialCharacter(lexer_result, .right_parenthesis)) {
                break;
            } else |_| {}

            return error.not_implemented;
        }

        try parser.expectSpecialCharacter(lexer_result, .arrow);

        const return_type_identifier = try parser.expectIdentifier(lexer_result);

        try parser.expectSpecialCharacter(lexer_result, .left_brace);

        while (true) {
            if (parser.expectSpecialCharacter(lexer_result, .right_brace)) {
                break;
            } else |_| {}

            return error.not_implemented;
        }

        return Function{
            .name = name,
            .statements = ArrayList(Statement){},
            .arguments = ArrayList(Function.Argument){},
            .return_type = return_type_identifier,
        };
    }

    inline fn consume(parser: *Parser, lexer_result: *const lexer.Result, comptime token_id: lexer.TokenId) void {
        assert(lexer_result.ids.items[parser.id_index] == token_id);
        parser.id_index += 1;
        switch (token_id) {
            .special_character => parser.special_character_index += 1,
            .identifier => parser.identifier_index += 1,
        }
    }

    fn parseTopLevelDeclaration(parser: *Parser, lexer_result: *const lexer.Result) !void {
        const top_level_identifier = try parser.expectIdentifier(lexer_result);
        const next_token = parser.peek(lexer_result);

        switch (next_token) {
            .special_character => |special_character| switch (special_character) {
                .left_parenthesis => {
                    const function = try parser.parseFunction(lexer_result, top_level_identifier);
                    try parser.functions.append(parser.allocator, function);
                },
                else => return error.not_implemented,
            },
            .identifier => |identifier| {
                _ = identifier;
                return error.not_implemented;
            },
        }
    }

    inline fn peek(parser: *const Parser, lexer_result: *const lexer.Result) PeekResult {
        return switch (lexer_result.ids.items[parser.id_index]) {
            .special_character => .{
                .special_character = lexer_result.special_characters.items[parser.special_character_index],
            },
            .identifier => .{
                .identifier = blk: {
                    const identifier_range = lexer_result.identifiers.items[parser.identifier_index];
                    break :blk lexer_result.file[identifier_range.start .. identifier_range.start + identifier_range.end];
                },
            },
        };
    }

    fn expectSpecialCharacter(parser: *Parser, lexer_result: *const lexer.Result, expected: lexer.SpecialCharacter) !void {
        const token_id = lexer_result.ids.items[parser.id_index];
        if (token_id != .special_character) {
            return error.expected_special_character;
        }

        defer parser.id_index += 1;

        const special_character = lexer_result.special_characters.items[parser.special_character_index];
        if (special_character != expected) {
            return error.expected_different_special_character;
        }

        parser.special_character_index += 1;
    }

    fn acceptSpecialCharacter() void {}

    fn expectIdentifier(parser: *Parser, lexer_result: *const lexer.Result) !u32 {
        const token_id = lexer_result.ids.items[parser.id_index];
        if (token_id != .identifier) {
            return Error.expected_identifier;
        }

        parser.id_index += 1;

        const identifier_range = lexer_result.identifiers.items[parser.identifier_index];
        parser.identifier_index += 1;
        const identifier = lexer_result.file[identifier_range.start..identifier_range.end];
        const Hash = std.hash.Wyhash;
        const seed = @intFromPtr(identifier.ptr);
        var hasher = Hash.init(seed);
        std.hash.autoHash(&hasher, identifier.ptr);
        const hash = hasher.final();
        const truncated_hash: u32 = @truncate(hash);
        try parser.strings.put(parser.allocator, truncated_hash, identifier);
        return truncated_hash;
    }

    const Error = error{
        expected_identifier,
        expected_special_character,
        expected_different_special_character,
        not_implemented,
    };
};

pub fn runTest(allocator: Allocator, lexer_result: *const lexer.Result) !Result {
    var parser = Parser{
        .allocator = allocator,
        .strings = StringMap{},
        .functions = ArrayList(Function){},
    };

    return parser.parse(lexer_result) catch |err| {
        std.log.err("error: {}", .{err});
        return err;
    };
}
