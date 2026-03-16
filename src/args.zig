//! CLI argument parsing for zbox.
const std = @import("std");
const config = @import("config.zig");

pub const args_max: u32 = 32;

pub const Args = struct {
    config: config.Config,
    child_args: [args_max][:0]const u8 = undefined,
    child_args_count: u32 = 0,

    /// Free all owned memory.
    pub fn deinit(self: *Args, allocator: std.mem.Allocator) void {
        var i: u32 = 0;
        while (i < self.child_args_count) : (i += 1) {
            allocator.free(self.child_args[i]);
        }
        self.config.deinit(allocator);
        self.* = undefined;
    }
};

fn print_help() void {
    std.debug.print(
        \\zbox - Minimal Linux namespace sandbox
        \\
        \\Usage: zbox [options]
        \\
        \\Options:
        \\ -c, --config <path> — path to sandbox config JSON (required)
        \\ -h, --help          — show help
        \\  --                  — forward remaining arguments to the sandboxed binary
        \\
    , .{});
}

/// Parse CLI arguments, load the required JSON config, and return a
/// populated Args struct.
pub fn parse(allocator: std.mem.Allocator) !Args {
    const cli_args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, cli_args);

    var config_path: ?[]const u8 = null;
    var child_args: [args_max][:0]const u8 = undefined;
    var child_args_count: u32 = 0;

    var i: u32 = 1;
    while (i < cli_args.len) : (i += 1) {
        const arg = cli_args[i];

        if (std.mem.eql(u8, arg, "--")) {
            i += 1;
            while (i < cli_args.len) : (i += 1) {
                if (child_args_count >= args_max) {
                    std.debug.print("error: too many arguments (max {d})\n", .{args_max});
                    std.process.exit(1);
                }
                child_args[child_args_count] = try allocator.dupeZ(u8, cli_args[i]);
                child_args_count += 1;
            }
            break;
        }

        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            print_help();
            std.process.exit(0);
        } else if (std.mem.eql(u8, arg, "-c") or std.mem.eql(u8, arg, "--config")) {
            i += 1;
            if (i >= cli_args.len) {
                std.debug.print("error: {s} requires an argument\n", .{arg});
                std.process.exit(1);
            }
            config_path = cli_args[i];
        } else {
            std.debug.print("error: unknown argument: {s}\n", .{arg});
            print_help();
            std.process.exit(1);
        }
    }

    if (config_path == null) {
        std.debug.print("error: -c/--config is required\n", .{});
        print_help();
        std.process.exit(1);
    }

    const loaded = config.load(allocator, config_path.?) catch |err| {
        std.debug.print("error: failed to load config '{s}': {}\n", .{ config_path.?, err });
        std.process.exit(1);
    };

    return Args{
        .config = loaded,
        .child_args = child_args,
        .child_args_count = child_args_count,
    };
}

test "Args.deinit frees child args" {
    const allocator = std.testing.allocator;

    var a = Args{
        .config = .{
            .name = try allocator.dupeZ(u8, "test"),
            .binary = try allocator.dupeZ(u8, "/bin/sh"),
            .root = try allocator.dupeZ(u8, "/tmp/root"),
            .cpu_cores = 1,
            .cpu_limit_percent = 50,
            .memory_limit_mb = 64,
            .port_forwards = &.{},
            .network_access = false,
        },
    };
    a.child_args[0] = try allocator.dupeZ(u8, "ls");
    a.child_args[1] = try allocator.dupeZ(u8, "-la");
    a.child_args_count = 2;
    a.deinit(allocator);
}
