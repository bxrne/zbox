//! Entry point for zbox — parses CLI arguments and runs the sandbox.
const std = @import("std");
const args = @import("args.zig");
const sandbox = @import("sandbox.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    const allocator = gpa.allocator();

    var parsed_args = try args.parse(allocator);
    errdefer parsed_args.deinit(allocator);

    var box = try sandbox.Sandbox.init(allocator, parsed_args);
    defer box.deinit();

    try box.spawn();
    try box.wait();
}
