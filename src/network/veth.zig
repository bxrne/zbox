//! Veth pair management.

const std = @import("std");
const posix = std.posix;
const log = std.log;
const mod = @import("mod.zig");
const run_command = mod.run_command;

/// Create a veth pair for network connectivity.
/// Returns the host veth name and sandbox veth name.
pub fn create_veth_pair(allocator: std.mem.Allocator, name: [:0]const u8) !struct { host: [:0]const u8, sandbox: [:0]const u8 } {
    var host_buf: [64]u8 = undefined;
    const host_name = try std.fmt.bufPrintZ(&host_buf, "{s}{s}", .{ mod.VETH_HOST_PREFIX, name });
    const host_name_dup = try allocator.dupeZ(u8, host_name);
    errdefer allocator.free(host_name_dup);

    var sandbox_buf: [64]u8 = undefined;
    const sandbox_name = try std.fmt.bufPrintZ(&sandbox_buf, "{s}{s}", .{ mod.VETH_SANDBOX_PREFIX, name });
    const sandbox_name_dup = try allocator.dupeZ(u8, sandbox_name);
    errdefer allocator.free(sandbox_name_dup);

    const argv = [_][*:0]const u8{ "ip", "link", "add", "name", host_name_dup, "type", "veth", "peer", "name", sandbox_name_dup };
    run_command(&argv) catch {
        log.err("failed to create veth pair", .{});
        return error.VethCreationFailed;
    };

    return .{ .host = host_name_dup, .sandbox = sandbox_name_dup };
}

/// Move the sandbox veth into the sandbox namespace.
pub fn move_veth_to_ns(veth_name: [:0]const u8, pid: posix.pid_t) !void {
    var pid_buf: [16]u8 = undefined;
    const pid_str = std.fmt.bufPrintZ(&pid_buf, "{d}", .{pid}) catch unreachable;
    const argv = [_][*:0]const u8{ "ip", "link", "set", veth_name, "netns", pid_str };
    run_command(&argv) catch {
        log.err("failed to move veth to namespace", .{});
        return error.VethMoveFailed;
    };
}

/// Configure the host side of the veth pair (IP, up, forward).
pub fn configure_host_veth(veth_name: [:0]const u8) !void {
    const argv_addr = [_][*:0]const u8{ "ip", "addr", "add", mod.HOST_IP, "dev", veth_name };
    run_command(&argv_addr) catch {
        log.err("failed to set host IP", .{});
        return error.IpConfigFailed;
    };

    const argv_up = [_][*:0]const u8{ "ip", "link", "set", veth_name, "up" };
    run_command(&argv_up) catch {
        log.err("failed to bring up host veth", .{});
        return error.IpConfigFailed;
    };

    const argv_forward = [_][*:0]const u8{ "sysctl", "-w", "net.ipv4.ip_forward=1" };
    run_command(&argv_forward) catch {
        log.warn("failed to enable IP forwarding (may already be set)", .{});
    };
}

/// Configure the sandbox side of the veth pair inside the namespace.
pub fn configure_sandbox_veth(veth_name: [:0]const u8) !void {
    const argv_addr = [_][*:0]const u8{ "ip", "addr", "add", mod.SANDBOX_IP, "dev", veth_name };
    run_command(&argv_addr) catch {
        log.err("failed to set sandbox IP", .{});
        return error.IpConfigFailed;
    };

    const argv_up = [_][*:0]const u8{ "ip", "link", "set", veth_name, "up" };
    run_command(&argv_up) catch {
        log.err("failed to bring up sandbox veth", .{});
        return error.IpConfigFailed;
    };

    const argv_route = [_][*:0]const u8{ "ip", "route", "add", "default", "via", "10.0.2.1" };
    run_command(&argv_route) catch {
        log.warn("failed to add default route", .{});
    };
}

/// Delete the veth pair.
pub fn delete_veth_pair(veth_name: [:0]const u8) void {
    const argv = [_][*:0]const u8{ "ip", "link", "del", veth_name };
    run_command(&argv) catch {};
}
