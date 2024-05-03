const std = @import("std");
const library = @import("library.zig");

extern fn glfwSetErrorCallback(callback: *const fn (err: c_int, description: [*:0]const u8) callconv(.C) void) void;
extern fn glfwInit() c_int;
extern fn glfwWindowHint(hint: c_int, value: c_int) void;
const GLFWwindow = opaque {};
const GLFWmonitor = opaque {};
extern fn glfwCreateWindow(width: c_int, height: c_int, title: [*:0]const u8, monitor: ?*GLFWmonitor, share: ?*GLFWwindow) *GLFWwindow;
extern fn glfwMakeContextCurrent(window: *GLFWwindow) void;
extern fn glfwWindowShouldClose(window: *GLFWwindow) c_int;
extern fn glfwSwapBuffers(window: *GLFWwindow) void;
extern fn glfwPollEvents() void;
extern fn glfwDestroyWindow(window: *GLFWwindow) void;
extern fn glfwTerminate() void;

const GLFW_CONTEXT_VERSION_MAJOR = 0x00022002;
const GLFW_CONTEXT_VERSION_MINOR = 0x00022003;
const GLFW_OPENGL_PROFILE = 0x00022008;
const GLFW_OPENGL_CORE_PROFILE = 0x00032001;

fn error_callback(err: c_int, description: [*:0]const u8) callconv(.C) void {
    _ = err; // autofix
    const error_description = library.span(description);
    std.io.getStdOut().writeAll("GLFW error: ") catch {};
    std.io.getStdOut().writeAll(error_description) catch {};
    std.posix.exit(1);
}

extern fn silt_init(window: *GLFWwindow) void;
extern fn silt_start_new_frame() void;
extern fn silt_render(window: *GLFWwindow) void;

pub fn main() void {
    glfwSetErrorCallback(&error_callback);
    const result = glfwInit();
    if (result == 0) {
        std.posix.exit(1);
    }

    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 3);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE); // 3.2+ only

    const window = glfwCreateWindow(1024, 768, "Nativity", null, null);
    glfwMakeContextCurrent(window);

    silt_init(window);

    while (glfwWindowShouldClose(window) == 0) {
        defer glfwSwapBuffers(window);
        glfwPollEvents();

        silt_start_new_frame();

        silt_render(window);
    }

    glfwDestroyWindow(window);
    glfwTerminate();
}
