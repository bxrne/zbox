const std = @import("std");
const sandbox = @import("sandbox.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    const allocator = gpa.allocator();

    const config = try parseArgs(allocator);

    var box = try sandbox.Sandbox.init(allocator, config);
    defer box.deinit();

    try box.spawn();
    try box.wait();
}

fn printHelp() void {
    std.debug.print(
        \\zbox - Minimal Linux namespace sandbox
        \\
        \\Usage: zbox [options]
        \\
        \\Options:
        \\  -b, --binary <path>   Target binary to execute (default: /bin/busybox)
        \\  -r, --root <path>    Container root directory (default: auto-generated)
        \\  -h, --help           Show this help message
        \\
        \\Examples:
        \\  zbox                                    # Run busybox sh in sandbox
        \\  zbox -b /bin/busybox -- ls             # Run busybox ls
        \\
    , .{});
}

fn parseArgs(allocator: std.mem.Allocator) !sandbox.Config {
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    var config = sandbox.Config.init(allocator);

    var i: usize = 1;
    var pass_through = false;
    while (i < args.len) : (i += 1) {
        const arg = args[i];

        if (pass_through) {
            config.args = args[i..];
            break;
        }

        if (std.mem.eql(u8, arg, "--")) {
            pass_through = true;
            continue;
        }

        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            printHelp();
            std.process.exit(0);
        } else if (std.mem.eql(u8, arg, "-b") or std.mem.eql(u8, arg, "--binary")) {
            if (i + 1 >= args.len) {
                std.debug.print("error: {s} requires an argument\n", .{arg});
                std.process.exit(1);
            }
            i += 1;
            allocator.free(config.binary);
            config.binary = try allocator.dupe(u8, args[i]);
        } else if (std.mem.eql(u8, arg, "-r") or std.mem.eql(u8, arg, "--root")) {
            if (i + 1 >= args.len) {
                std.debug.print("error: {s} requires an argument\n", .{arg});
                std.process.exit(1);
            }
            i += 1;
            config.root = try allocator.dupe(u8, args[i]);
        } else {
            std.debug.print("error: unknown argument: {s}\n", .{arg});
            printHelp();
            std.process.exit(1);
        }
    }

    return config;
}
