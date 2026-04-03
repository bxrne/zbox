//! Veth pair management.

const std = @import("std");
const posix = std.posix;
const log = std.log;
const linux = std.os.linux;
const mod = @import("mod.zig");
const run_command = mod.run_command;

fn make_veth_name(
    buf: *[64]u8,
    prefix: []const u8,
    name: []const u8,
) ![:0]const u8 {
    const max_len: usize = linux.IFNAMESIZE - 1;
    if (prefix.len >= max_len) return error.VethCreationFailed;

    if (prefix.len + name.len <= max_len) {
        return try std.fmt.bufPrintZ(buf, "{s}{s}", .{ prefix, name });
    }

    const suffix_len: usize = max_len - prefix.len;
    if (suffix_len < 4) return error.VethCreationFailed;

    // Truncate to u32 so {x:0>8} always produces exactly 8 hex chars,
    // which fits within the available suffix space (max 11 chars for
    // a 4-char prefix like "zbxh").
    const hash: u32 = @truncate(std.hash.Wyhash.hash(0, name));

    return try std.fmt.bufPrintZ(buf, "{s}{x:0>8}", .{ prefix, hash });
}

/// Create a veth pair for network connectivity.
/// Returns the host veth name and sandbox veth name.
const VethNames = struct { host: [:0]const u8, sandbox: [:0]const u8 };

/// Compute veth pair names without creating them. The caller owns the
/// returned allocations.
pub fn compute_veth_names(allocator: std.mem.Allocator, name: [:0]const u8) !VethNames {
    var host_buf: [64]u8 = undefined;
    const host_name = try make_veth_name(&host_buf, mod.VETH_HOST_PREFIX, name);
    const host_name_dup = try allocator.dupeZ(u8, host_name);
    errdefer allocator.free(host_name_dup);

    var sandbox_buf: [64]u8 = undefined;
    const sandbox_name = try make_veth_name(&sandbox_buf, mod.VETH_SANDBOX_PREFIX, name);
    const sandbox_name_dup = try allocator.dupeZ(u8, sandbox_name);

    return .{ .host = host_name_dup, .sandbox = sandbox_name_dup };
}

/// Create the veth link pair using pre-computed names.
pub fn create_veth_link(host: [:0]const u8, sandbox: [:0]const u8) !void {
    const argv = [_:null]?[*:0]const u8{ "ip", "link", "add", "name", host, "type", "veth", "peer", "name", sandbox };
    run_command(&argv) catch {
        log.err("failed to create veth pair", .{});
        return error.VethCreationFailed;
    };
}

/// Move the sandbox veth into the sandbox namespace.
pub fn move_veth_to_ns(veth_name: [:0]const u8, pid: posix.pid_t) !void {
    var pid_buf: [16]u8 = undefined;
    const pid_str = std.fmt.bufPrintZ(&pid_buf, "{d}", .{pid}) catch unreachable;
    const argv = [_:null]?[*:0]const u8{ "ip", "link", "set", veth_name, "netns", pid_str };
    run_command(&argv) catch {
        log.err("failed to move veth to namespace", .{});
        return error.VethMoveFailed;
    };
}

/// Configure the host side of the veth pair (IP, up, forward).
pub fn configure_host_veth(veth_name: [:0]const u8) !void {
    const argv_addr = [_:null]?[*:0]const u8{ "ip", "addr", "add", mod.HOST_IP, "dev", veth_name };
    run_command(&argv_addr) catch {
        log.err("failed to set host IP", .{});
        return error.IpConfigFailed;
    };

    const argv_up = [_:null]?[*:0]const u8{ "ip", "link", "set", veth_name, "up" };
    run_command(&argv_up) catch {
        log.err("failed to bring up host veth", .{});
        return error.IpConfigFailed;
    };

    const argv_forward = [_:null]?[*:0]const u8{ "sysctl", "-w", "net.ipv4.ip_forward=1" };
    run_command(&argv_forward) catch {
        log.warn("failed to enable IP forwarding (may already be set)", .{});
    };
}

/// Configure the sandbox side of the veth pair inside the namespace.
pub fn configure_sandbox_veth(veth_name: [:0]const u8) !void {
    const argv_addr = [_:null]?[*:0]const u8{ "ip", "addr", "add", mod.SANDBOX_IP, "dev", veth_name };
    run_command(&argv_addr) catch {
        log.err("failed to set sandbox IP", .{});
        return error.IpConfigFailed;
    };

    const argv_up = [_:null]?[*:0]const u8{ "ip", "link", "set", veth_name, "up" };
    run_command(&argv_up) catch {
        log.err("failed to bring up sandbox veth", .{});
        return error.IpConfigFailed;
    };

    const argv_route = [_:null]?[*:0]const u8{ "ip", "route", "add", "default", "via", "10.0.2.1" };
    run_command(&argv_route) catch {
        log.warn("failed to add default route", .{});
    };
}

/// Delete the veth pair.
pub fn delete_veth_pair(veth_name: [:0]const u8) void {
    const argv = [_:null]?[*:0]const u8{ "ip", "link", "del", veth_name };
    run_command(&argv) catch {};
}
