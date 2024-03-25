const Compilation = @import("../Compilation.zig");
const Context = Compilation.Context;
const lld = @import("lld.zig");
pub const Options = struct{
    backend: Backend = .lld,
    output_file_path: []const u8,
    objects: []const Object,
    libraries: []const Library,
    extra_arguments: []const []const u8,
    link_libc: bool,
    link_libcpp: bool,
};

const Backend = enum{
    lld,
};

pub const Object = struct{
    path: []const u8,
};

pub const Library = struct{
    path: []const u8,
};

pub fn link(context: *const Context, options: Options) !void {
    switch (options.backend) {
        .lld => try lld.link(context, options),
    }
}
