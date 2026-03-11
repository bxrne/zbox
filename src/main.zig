const std = @import("std");
const sandbox = @import("sandbox.zig").Sandbox;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    const allocator = gpa.allocator();

    var box = try sandbox.init(allocator);
    defer box.deinit();

    try box.spawn();
    try box.wait();
}
