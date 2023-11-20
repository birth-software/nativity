const std = @import("std");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;

const Compilation = @import("../Compilation.zig");
const Module = Compilation.Module;
const data_structures = @import("../data_structures.zig");
const ArrayList = data_structures.ArrayList;
const AutoArrayHashMap = data_structures.AutoArrayHashMap;
const StringArrayHashMap = data_structures.StringArrayHashMap;

pub const Logger = enum {
    g,

    pub var bitset = std.EnumSet(Logger).initMany(&.{
        .g,
    });
};

pub const TranslationUnit = struct {
    string_literals: ArrayList(u8) = .{},
    type_declarations: ArrayList(u8) = .{},
    function_declarations: ArrayList(u8) = .{},
    function_definitions: ArrayList(u8) = .{},
    syscall_bitset: SyscallBitset = SyscallBitset.initEmpty(),
    const SyscallBitset = std.StaticBitSet(6);

    fn create(module: *Module, allocator: Allocator) !TranslationUnit {
        var unit = TranslationUnit{};
        try unit.type_declarations.appendSlice(allocator,
            \\typedef unsigned char u8;
            \\typedef unsigned short u16;
            \\typedef unsigned int u32;
            \\typedef unsigned long u64;
            \\typedef u64 usize;
            \\static_assert(sizeof(u8) == 1);
            \\static_assert(sizeof(u16) == 2);
            \\static_assert(sizeof(u32) == 4);
            \\static_assert(sizeof(u64) == 8);
            \\typedef signed char s8;
            \\typedef signed short s16;
            \\typedef signed int s32;
            \\typedef signed long s64;
            \\typedef s64 ssize;
            \\static_assert(sizeof(s8) == 1);
            \\static_assert(sizeof(s16) == 2);
            \\static_assert(sizeof(s32) == 4);
            \\static_assert(sizeof(s64) == 8);
            \\
            \\
        );

        {
            var function_definitions = module.function_definitions.iterator();
            while (function_definitions.nextIndex()) |function_definition_index| {
                const function_definition = module.function_definitions.get(function_definition_index);
                try unit.writeFunctionHeader(module, &unit.function_declarations, allocator, function_definition_index);
                try unit.writeFunctionHeader(module, &unit.function_definitions, allocator, function_definition_index);
                try unit.function_declarations.appendSlice(allocator, ";\n\n");
                try unit.function_definitions.append(allocator, ' ');
                try unit.writeBlock(module, &unit.function_definitions, allocator, function_definition.body, 1);
                try unit.function_definitions.append(allocator, '\n');
            }
        }

        return unit;
    }

    fn writeBlock(unit: *TranslationUnit, module: *Module, list: *ArrayList(u8), allocator: Allocator, block_index: Compilation.Block.Index, indentation: usize) !void {
        try list.appendSlice(allocator, "{\n");
        const block = module.blocks.get(block_index);
        for (block.statements.items) |statement_index| {
            try list.appendNTimes(allocator, ' ', indentation * 4);

            const statement = module.values.get(statement_index);
            switch (statement.*) {
                .declaration => |declaration_index| {
                    const declaration = module.declarations.get(declaration_index);
                    if (declaration.mutability == .@"const") {
                        try list.appendSlice(allocator, "const ");
                    }
                    try unit.writeType(module, list, allocator, declaration.type);

                    try list.append(allocator, ' ');

                    const declaration_name = module.getName(declaration.name).?;
                    try list.appendSlice(allocator, declaration_name);

                    try list.appendSlice(allocator, " = ");

                    try unit.writeValue(module, list, allocator, declaration.init_value, indentation);
                    try list.append(allocator, ';');
                },
                .assign => |assignment_index| {
                    const assignment = module.assignments.get(assignment_index);
                    try unit.writeValue(module, list, allocator, assignment.destination, indentation);
                    try list.appendSlice(allocator, " = ");
                    try unit.writeValue(module, list, allocator, assignment.source, indentation);
                    try list.append(allocator, ';');
                },
                .@"return" => |return_index| {
                    const return_expr = module.returns.get(return_index);
                    try list.appendSlice(allocator, "return ");
                    try unit.writeValue(module, list, allocator, return_expr.value, indentation);
                    try list.append(allocator, ';');
                },
                .syscall => |syscall_index| {
                    try unit.writeSyscall(module, list, allocator, syscall_index, indentation);
                    try list.append(allocator, ';');
                },
                .@"unreachable" => {
                    try writeUnreachable(list, allocator);
                    try list.append(allocator, ';');
                },
                .call => |call_index| {
                    try unit.writeCall(module, list, allocator, call_index, indentation);
                    try list.append(allocator, ';');
                },
                .branch => |branch_index| {
                    const branch = module.branches.get(branch_index);
                    try list.appendSlice(allocator, "if (");
                    try unit.writeValue(module, list, allocator, branch.condition, indentation);
                    try list.appendSlice(allocator, ") ");
                    try unit.writeValue(module, list, allocator, branch.true_expression, indentation);
                    if (!branch.false_expression.invalid) {
                        try list.appendSlice(allocator, " else ");
                        try unit.writeValue(module, list, allocator, branch.false_expression, indentation);
                    }
                },
                else => |t| @panic(@tagName(t)),
            }

            try list.append(allocator, '\n');
        }

        try list.appendSlice(allocator, "}\n");
    }

    fn writeFunctionHeader(unit: *TranslationUnit, module: *Module, list: *ArrayList(u8), allocator: Allocator, function_index: Compilation.Function.Index) !void {
        const function_definition = module.function_definitions.get(function_index);
        const function_prototype_type = module.types.get(function_definition.prototype);
        const function_prototype = module.function_prototypes.get(function_prototype_type.function);
        try unit.writeType(module, list, allocator, function_prototype.return_type);
        try list.append(allocator, ' ');
        const function_name_hash = module.function_name_map.get(function_index).?;
        const function_name = module.getName(function_name_hash).?;
        try list.appendSlice(allocator, function_name);

        try list.append(allocator, '(');
        if (function_prototype.arguments) |function_arguments| {
            for (function_arguments) |argument_index| {
                const arg_declaration = module.declarations.get(argument_index);
                try unit.writeType(module, list, allocator, arg_declaration.type);
                try list.append(allocator, ' ');
                const arg_name = module.getName(arg_declaration.name).?;
                try list.appendSlice(allocator, arg_name);
                try list.append(allocator, ',');
            }
            _ = list.pop();
        }
        try list.appendSlice(allocator, ")");
    }

    fn writeType(unit: *TranslationUnit, module: *Module, list: *ArrayList(u8), allocator: Allocator, type_index: Compilation.Type.Index) !void {
        const sema_type = module.types.get(type_index);
        switch (sema_type.*) {
            .void => try list.appendSlice(allocator, "void"),
            .noreturn => try list.appendSlice(allocator, "[[noreturn]] void"),
            .bool => try list.appendSlice(allocator, "bool"),
            .integer => |integer| {
                try list.append(allocator, switch (integer.signedness) {
                    .signed => 's',
                    .unsigned => 'u',
                });
                try list.writer(allocator).print("{}", .{integer.bit_count});
            },
            .pointer => |pointer| {
                if (pointer.@"const") {
                    try list.appendSlice(allocator, "const ");
                }
                try unit.writeType(module, list, allocator, pointer.element_type);
                try list.append(allocator, '*');
            },
            else => |t| @panic(@tagName(t)),
        }
    }

    fn writeSyscall(unit: *TranslationUnit, module: *Module, list: *ArrayList(u8), allocator: Allocator, syscall_index: Compilation.Syscall.Index, indentation: usize) !void {
        const syscall = module.syscalls.get(syscall_index);
        const arguments = syscall.getArguments();
        if (!unit.syscall_bitset.isSet(arguments.len)) {
            try unit.function_declarations.appendSlice(allocator, "static __inline u64 syscall");
            try unit.function_declarations.writer(allocator).print("{}(", .{arguments.len});
            try unit.function_declarations.appendSlice(allocator, "u64 n, ");
            for (0..arguments.len) |arg_i| {
                try unit.function_declarations.writer(allocator).print("u64 arg{}, ", .{arg_i});
            }
            _ = unit.function_declarations.pop();
            _ = unit.function_declarations.pop();
            try unit.function_declarations.appendSlice(allocator,
                \\) {
                \\    unsigned long ret;
                \\    __asm__ __volatile__("syscall"
                \\        : "=a"(ret)
                \\        : "a"(n), 
            );

            const argument_registers = [_]u8{ 'D', 'S', 'd' };
            if (arguments.len <= 3) {
                for (0..arguments.len, argument_registers[0..arguments.len]) |arg_i, arg_register| {
                    try unit.function_declarations.writer(allocator).print("\"{c}\"(arg{}), ", .{ arg_register, arg_i });
                }
            } else {
                unreachable;
            }
            _ = unit.function_declarations.pop();
            _ = unit.function_declarations.pop();
            try unit.function_declarations.appendSlice(allocator,
                \\
                \\        : "rcx", "r11", "memory"
                \\    );
                \\    return ret;
                \\}
                \\
                \\
            );

            unit.syscall_bitset.set(arguments.len);
        }

        try list.writer(allocator).print("syscall{}(", .{arguments.len});

        try unit.writeValue(module, list, allocator, syscall.number, indentation);
        try list.appendSlice(allocator, ", ");

        for (arguments) |argument_index| {
            try unit.writeValue(module, list, allocator, argument_index, indentation);
            try list.appendSlice(allocator, ", ");
        }

        _ = list.pop();
        _ = list.pop();
        try list.append(allocator, ')');
    }

    fn writeUnreachable(list: *ArrayList(u8), allocator: Allocator) !void {
        try list.appendSlice(allocator, "__builtin_unreachable()");
    }

    fn writeCall(unit: *TranslationUnit, module: *Module, list: *ArrayList(u8), allocator: Allocator, call_index: Compilation.Call.Index, indentation: usize) !void {
        const call = module.calls.get(call_index);
        const call_value = module.values.get(call.value);
        const callable_name = switch (call_value.*) {
            .function_definition => |function_definition_index| module.getName(module.function_name_map.get(function_definition_index).?).?,
            else => |t| @panic(@tagName(t)),
        };
        try list.writer(allocator).print("{s}(", .{callable_name});

        if (!call.arguments.invalid) {
            const argument_list = module.argument_lists.get(call.arguments);
            for (argument_list.array.items) |argument_index| {
                try unit.writeValue(module, list, allocator, argument_index, indentation);
                try list.appendSlice(allocator, ", ");
            }
            _ = list.pop();
            _ = list.pop();
        }

        try list.append(allocator, ')');
    }

    fn writeValue(unit: *TranslationUnit, module: *Module, list: *ArrayList(u8), allocator: Allocator, value_index: Compilation.Value.Index, indentation: usize) anyerror!void {
        const value = module.values.get(value_index);
        switch (value.*) {
            .integer => |integer| {
                try list.writer(allocator).print("{}", .{integer.value});
            },
            .declaration_reference => |declaration_reference| {
                const declaration = module.declarations.get(declaration_reference.value);
                const declaration_name = module.getName(declaration.name).?;
                try list.appendSlice(allocator, declaration_name);
            },
            .binary_operation => |binary_operation_index| {
                const binary_operation = module.binary_operations.get(binary_operation_index);
                try unit.writeValue(module, list, allocator, binary_operation.left, indentation);
                try list.append(allocator, ' ');
                switch (binary_operation.id) {
                    .add => try list.append(allocator, '+'),
                    .sub => try list.append(allocator, '-'),
                    .logical_and => try list.append(allocator, '&'),
                    .logical_or => try list.append(allocator, '|'),
                    .logical_xor => try list.append(allocator, '^'),
                    .multiply => try list.append(allocator, '*'),
                    .divide => try list.append(allocator, '/'),
                    .shift_left => try list.appendSlice(allocator, "<<"),
                    .shift_right => try list.appendSlice(allocator, ">>"),
                    .compare_equal => try list.appendSlice(allocator, "=="),
                }
                try list.append(allocator, ' ');
                try unit.writeValue(module, list, allocator, binary_operation.right, indentation);
            },
            .sign_extend => |cast_index| {
                const sign_extend = module.casts.get(cast_index);
                try unit.writeValue(module, list, allocator, sign_extend.value, indentation);
            },
            .cast => |cast_index| {
                const cast = module.casts.get(cast_index);
                try list.append(allocator, '(');
                try unit.writeType(module, list, allocator, cast.type);
                try list.append(allocator, ')');
                try unit.writeValue(module, list, allocator, cast.value, indentation);
            },
            .string_literal => |string_literal_hash| {
                try list.appendSlice(allocator, "(const u8*)");
                const string_literal = module.string_literals.getValue(string_literal_hash).?;
                try list.append(allocator, '"');
                try list.appendSlice(allocator, string_literal);
                try list.append(allocator, '"');
            },
            .@"unreachable" => try writeUnreachable(list, allocator),
            .call => |call_index| try unit.writeCall(module, list, allocator, call_index, indentation),
            .syscall => |syscall_index| try unit.writeSyscall(module, list, allocator, syscall_index, indentation),
            .bool => |boolean| try list.appendSlice(allocator, if (boolean) "true" else "false"),
            .block => |block_index| try unit.writeBlock(module, list, allocator, block_index, indentation + 1),
            else => |t| @panic(@tagName(t)),
        }
    }
};

// fn writeDeclarationReference(module: *Module, list: *ArrayList(u8), allocator: Allocator, declaration_reference: Compilation.Declaration.Reference) !void {
//     _ = module;
//     _ = list;
//     _ = allocator;
//     _ = declaration_reference;
// }

pub fn initialize(compilation: *Compilation, module: *Module, descriptor: Compilation.Module.Descriptor) !void {
    const allocator = compilation.base_allocator;
    const unit = try TranslationUnit.create(module, allocator);
    const c_source_file_path = try std.mem.concat(allocator, u8, &.{ descriptor.executable_path, ".c" });
    const c_source_file = try std.fs.cwd().createFile(c_source_file_path, .{});

    var offset: u64 = 0;
    const slices = [_][]const u8{ unit.type_declarations.items, unit.function_declarations.items, unit.string_literals.items, unit.function_definitions.items };
    for (slices) |slice| {
        try c_source_file.pwriteAll(slice, offset);
        offset += slice.len;
    }

    c_source_file.close();
    const c_source_file_realpath = try std.fs.cwd().realpathAlloc(allocator, c_source_file_path);
    const c_flags = [_][]const u8{
        "-std=c2x",
        "-g",
    };

    var zig_command_line = ArrayList([]const u8){};
    try zig_command_line.append(allocator, "zig");
    try zig_command_line.append(allocator, "build-exe");
    try zig_command_line.append(allocator, try std.mem.concat(allocator, u8, &.{ "-femit-bin=", descriptor.executable_path }));
    try zig_command_line.append(allocator, "-cflags");
    for (c_flags) |c_flag| {
        try zig_command_line.append(allocator, c_flag);
    }
    try zig_command_line.append(allocator, "--");
    try zig_command_line.append(allocator, c_source_file_realpath);

    const run_result = try std.ChildProcess.run(.{
        .allocator = allocator,
        .argv = zig_command_line.items,
    });
    switch (run_result.term) {
        .Exited => |exit_code| {
            if (exit_code != 0) {
                for (zig_command_line.items) |arg| {
                    std.debug.print("{s} ", .{arg});
                }
                std.debug.panic("\nZig command exited with code {}:\n{s}", .{ exit_code, run_result.stderr });
            }
        },
        else => |t| @panic(@tagName(t)),
    }
}
