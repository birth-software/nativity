const Compilation = @import("../Compilation.zig");
const Module = Compilation.Module;
const Package = Compilation.Package;
pub fn initialize(compilation: *Compilation, module: *Module, package: *Package, main_declaration: Compilation.Declaration.Index) !void {
    _ = main_declaration;
    _ = package;
    _ = module;
    _ = compilation;
}
