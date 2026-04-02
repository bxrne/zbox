//! Entry point for zbox — parses CLI arguments and runs the sandbox.
const std = @import("std");
const args = @import("args.zig");
const sandbox = @import("sandbox/mod.zig");

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;

    var parsed_args = args.parse(allocator, init.minimal.args);
    errdefer parsed_args.deinit(allocator);

    var box = try sandbox.Sandbox.init(allocator, parsed_args);
    defer box.deinit();

    try box.spawn();
    try box.wait();
}
