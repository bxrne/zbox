//! Entry point for zbox — parses CLI arguments and runs the sandbox.
const std = @import("std");
const args = @import("args.zig");
const sandbox = @import("sandbox/mod.zig");

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;

    var parsed_args = args.parse(allocator, init.minimal.args);

    var box = sandbox.Sandbox.init(allocator, parsed_args) catch |err| {
        parsed_args.deinit(allocator);
        return err;
    };
    defer box.deinit();

    try box.spawn();
    try box.wait();
}
