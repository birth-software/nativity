const std = @import("std");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;
const equal = std.mem.eql;

const data_structures = @import("data_structures.zig");
const ArrayList = data_structures.ArrayList;
const parser = @import("parser.zig");

const void_type = Type{
    .id = .void,
};

const Type = struct {
    id: Id,

    inline fn isPrimitive(T: Type) bool {
        return switch (T.id) {
            .void => true,
        };
    }
    const Id = enum {
        void,
    };
};

const Error = error{
    type_mismatch,
    internal,
    arguments_not_used,
};

const TopLevelDeclaration = struct {
    type: Id,
    index: u31,

    const Id = enum {
        function,
        expression,
    };
};

const Instruction = struct {
    id: Id,
    index: u16,

    const Id = enum {
        ret_void,
    };
};

const ret_void = Instruction{
    .id = .ret_void,
    .index = 0,
};

const ret = struct {
    is_type: bool,
};

const Function = struct {
    instructions: ArrayList(Instruction),
    return_type: Type,
};

pub const Result = struct {
    top_level_declarations: ArrayList(TopLevelDeclaration),
    functions: ArrayList(Function),

    pub fn free(result: *Result, allocator: Allocator) void {
        for (result.functions.items) |*function| {
            function.instructions.clearAndFree(allocator);
        }
        result.functions.clearAndFree(allocator);
        result.top_level_declarations.clearAndFree(allocator);
    }
};

const Analyzer = struct {
    parser: *const parser.Result,
    top_level_declarations: ArrayList(TopLevelDeclaration),
    functions: ArrayList(Function),
    allocator: Allocator,

    fn analyze(allocator: Allocator, parser_result: *const parser.Result) Error!Result {
        var analyzer = Analyzer{
            .parser = parser_result,
            .top_level_declarations = ArrayList(TopLevelDeclaration){},
            .allocator = allocator,
            .functions = ArrayList(Function){},
        };

        for (parser_result.functions.items) |ast_function| {
            if (ast_function.statements.items.len != 0) {
                for (ast_function.statements.items) |statement| {
                    _ = statement;
                    @panic("TODO: statement");
                }
            } else {
                if (ast_function.arguments.items.len != 0) {
                    return Error.arguments_not_used;
                }

                try analyzer.expectPrimitiveType(void_type, ast_function.return_type);

                const function_index = analyzer.functions.items.len;

                var function = Function{
                    .instructions = ArrayList(Instruction){},
                    .return_type = void_type,
                };

                function.instructions.append(allocator, ret_void) catch return Error.internal;

                analyzer.top_level_declarations.append(allocator, TopLevelDeclaration{
                    .type = .function,
                    .index = @intCast(function_index),
                }) catch return Error.internal;

                analyzer.functions.append(allocator, function) catch return Error.internal;
            }
        }

        return .{
            .top_level_declarations = analyzer.top_level_declarations,
            .functions = analyzer.functions,
        };
    }

    fn expectPrimitiveType(analyzer: *Analyzer, comptime type_value: Type, type_identifier_id: u32) Error!void {
        assert(type_value.isPrimitive());
        const type_identifier = analyzer.parser.strings.get(type_identifier_id) orelse return Error.internal;

        if (!equal(u8, @tagName(type_value.id), type_identifier)) {
            return Error.type_mismatch;
        }
    }
};

pub fn runTest(allocator: Allocator, parser_result: *const parser.Result) !Result {
    return Analyzer.analyze(allocator, parser_result);
}
