const std = @import("std");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;
const log = std.log;

const data_structures = @import("data_structures.zig");
const ArrayList = data_structures.ArrayList;

const fs = @import("fs.zig");

pub inline fn rdtsc() u64 {
    var edx: u32 = undefined;
    var eax: u32 = undefined;

    asm volatile (
        \\rdtsc
        : [eax] "={eax}" (eax),
          [edx] "={edx}" (edx),
    );

    return @as(u64, edx) << 32 | eax;
}

inline fn rdtscFast() u32 {
    return asm volatile (
        \\rdtsc
        : [eax] "={eax}" (-> u32),
        :
        : "edx"
    );
}

const vector_byte_count = 16;
// These two actually take less space due to how Zig handles bool as u1
const VBool = @Vector(vector_byte_count, bool);
const VU1 = @Vector(vector_byte_count, u1);

const VU8 = @Vector(vector_byte_count, u8);

inline fn vand(v1: VBool, v2: VBool) VBool {
    return @bitCast(@as(VU1, @bitCast(v1)) & @as(VU1, @bitCast(v2)));
}

inline fn byteMask(n: u8) VU8 {
    return @splat(n);
}

inline fn endOfIdentifier(ch: u8) bool {
    // TODO: complete
    return ch == ' ' or ch == '(' or ch == ')';
}

const Identifier = struct {
    start: u32,
    end: u32,
};

pub const TokenId = enum {
    identifier,
    special_character,
};

pub const SpecialCharacter = enum(u8) {
    arrow = 0,
    left_parenthesis = '(',
    right_parenthesis = ')',
    left_brace = '{',
    right_brace = '}',
};

pub const Result = struct {
    identifiers: ArrayList(Identifier),
    special_characters: ArrayList(SpecialCharacter),
    ids: ArrayList(TokenId),
    file: []const u8,
    time: u64 = 0,

    pub fn free(result: *Result, allocator: Allocator) void {
        result.identifiers.clearAndFree(allocator);
        result.special_characters.clearAndFree(allocator);
        result.ids.clearAndFree(allocator);
        allocator.free(result.file);
    }
};

fn lex(allocator: Allocator, text: []const u8) !Result {
    const time_start = std.time.Instant.now() catch unreachable;

    var index: usize = 0;

    var result = Result{
        .identifiers = try ArrayList(Identifier).initCapacity(allocator, text.len),
        .special_characters = try ArrayList(SpecialCharacter).initCapacity(allocator, text.len),
        .ids = try ArrayList(TokenId).initCapacity(allocator, text.len),
        .file = text,
    };

    defer {
        const time_end = std.time.Instant.now() catch unreachable;
        result.time = time_end.since(time_start);
    }

    while (index < text.len) {
        const first_char = text[index];
        switch (first_char) {
            'a'...'z', 'A'...'Z', '_' => {
                const start = index;
                // SIMD this
                while (!endOfIdentifier(text[index])) {
                    index += 1;
                }

                result.identifiers.appendAssumeCapacity(.{
                    .start = @intCast(start),
                    .end = @intCast(index),
                });

                result.ids.appendAssumeCapacity(.identifier);
            },
            '(', ')', '{', '}' => |special_character| {
                result.special_characters.appendAssumeCapacity(@enumFromInt(special_character));
                result.ids.appendAssumeCapacity(.special_character);
                index += 1;
            },
            ' ', '\n' => index += 1,
            '-' => {
                if (text[index + 1] == '>') {
                    result.special_characters.appendAssumeCapacity(.arrow);
                    result.ids.appendAssumeCapacity(.special_character);
                    index += 2;
                } else {
                    @panic("TODO");
                }
            },
            else => {
                index += 1;
            },
        }
    }

    return result;
}

pub fn runTest(allocator: Allocator, file: []const u8) !Result {
    const result = try lex(allocator, file);

    return result;
}

test "lexer" {
    const allocator = std.testing.allocator;
    const file_path = fs.first;
    const file = try fs.readFile(allocator, file_path);
    var result = try runTest(allocator, file);
    defer result.free(allocator);
}
