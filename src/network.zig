//! Network setup for sandbox: veth pairs and iptables port forwarding.
const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;
const log = std.log;

pub const NetworkError = error{
    GetFlagsFailed,
    SetFlagsFailed,
    VerifyFailed,
    VethCreationFailed,
    VethMoveFailed,
    IpConfigFailed,
    IptablesFailed,
};

const VETH_HOST_PREFIX = "zbxh";
const VETH_SANDBOX_PREFIX = "zbxs";
const HOST_IP = "10.0.2.1/24";
const SANDBOX_IP = "10.0.2.2/24";

/// Bring up the `lo` interface so sandboxed processes can reach localhost.
pub fn bring_up_loopback() NetworkError!void {
    const fd = posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0) catch
        return error.GetFlagsFailed;
    defer posix.close(fd);

    var ifr = std.mem.zeroInit(posix.ifreq, .{});
    const if_name = "lo";
    comptime std.debug.assert(if_name.len < linux.IFNAMESIZE);
    @memcpy(ifr.ifrn.name[0..if_name.len], if_name);

    if (posix.errno(linux.ioctl(fd, linux.SIOCGIFFLAGS, @intFromPtr(&ifr))) != .SUCCESS)
        return error.GetFlagsFailed;

    var flags: linux.IFF = ifr.ifru.flags;
    flags.UP = true;
    ifr.ifru.flags = flags;

    if (posix.errno(linux.ioctl(fd, linux.SIOCSIFFLAGS, @intFromPtr(&ifr))) != .SUCCESS)
        return error.SetFlagsFailed;

    if (posix.errno(linux.ioctl(fd, linux.SIOCGIFFLAGS, @intFromPtr(&ifr))) != .SUCCESS)
        return error.VerifyFailed;
    std.debug.assert(ifr.ifru.flags.UP);
}

/// Run an external command (ip or iptables) and return the exit code.
fn run_command(argv: anytype) !void {
    const pid = linux.fork();
    if (pid == 0) {
        const argv_sentinel: [*:null]const ?[*:0]const u8 = @ptrCast(argv);
        _ = linux.execve(argv[0], argv_sentinel, &.{null});
        @panic("execve failed");
    }
    const res = posix.waitpid(@intCast(pid), 0);
    if (res.status != 0) {
        return error.IptablesFailed;
    }
}

/// Create a veth pair for network connectivity.
/// Returns the host veth name and sandbox veth name.
pub fn create_veth_pair(allocator: std.mem.Allocator, name: [:0]const u8) !struct { host: [:0]const u8, sandbox: [:0]const u8 } {
    var host_buf: [64]u8 = undefined;
    const host_name = try std.fmt.bufPrintZ(&host_buf, "{s}{s}", .{ VETH_HOST_PREFIX, name });
    const host_name_dup = try allocator.dupeZ(u8, host_name);
    errdefer allocator.free(host_name_dup);

    var sandbox_buf: [64]u8 = undefined;
    const sandbox_name = try std.fmt.bufPrintZ(&sandbox_buf, "{s}{s}", .{ VETH_SANDBOX_PREFIX, name });
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
    const argv_addr = [_][*:0]const u8{ "ip", "addr", "add", HOST_IP, "dev", veth_name };
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
    const argv_addr = [_][*:0]const u8{ "ip", "addr", "add", SANDBOX_IP, "dev", veth_name };
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

/// Set up iptables DNAT rules for port forwarding.
pub fn setup_port_forward(host_port: u16, sandbox_port: u16) !void {
    var host_port_buf: [8]u8 = undefined;
    const host_port_str = std.fmt.bufPrintZ(&host_port_buf, "{d}", .{host_port}) catch unreachable;

    var dest_buf: [24]u8 = undefined;
    const dest_str = std.fmt.bufPrintZ(&dest_buf, "10.0.2.2:{d}", .{sandbox_port}) catch unreachable;

    const argv_preroute = [_][*:0]const u8{
        "iptables", "-t",               "nat",     "-A",          "PREROUTING",
        "-p",       "tcp",              "--dport", host_port_str, "-j",
        "DNAT",     "--to-destination", dest_str,
    };
    run_command(&argv_preroute) catch {
        log.err("failed to add PREROUTING DNAT rule", .{});
        return error.IptablesFailed;
    };

    const argv_output = [_][*:0]const u8{
        "iptables", "-t",               "nat",     "-A",          "OUTPUT",
        "-p",       "tcp",              "--dport", host_port_str, "-j",
        "DNAT",     "--to-destination", dest_str,
    };
    run_command(&argv_output) catch {
        log.err("failed to add OUTPUT DNAT rule", .{});
        return error.IptablesFailed;
    };

    var sandbox_port_buf: [8]u8 = undefined;
    const sandbox_port_str = std.fmt.bufPrintZ(&sandbox_port_buf, "{d}", .{sandbox_port}) catch unreachable;
    const argv_forward = [_][*:0]const u8{
        "iptables", "-A",       "FORWARD",
        "-d",       "10.0.2.2", "-p",
        "tcp",      "--dport",  sandbox_port_str,
        "-j",       "ACCEPT",
    };
    run_command(&argv_forward) catch {
        log.err("failed to add FORWARD rule", .{});
        return error.IptablesFailed;
    };
}

/// Set up MASQUERADE for outbound network access from the sandbox.
pub fn setup_masquerade() !void {
    const argv = [_][*:0]const u8{
        "iptables", "-t",          "nat", "-A",         "POSTROUTING",
        "-s",       "10.0.2.0/24", "-j",  "MASQUERADE",
    };
    run_command(&argv) catch {
        log.err("failed to add MASQUERADE rule", .{});
        return error.IptablesFailed;
    };
}

/// Clean up iptables rules for port forwarding.
pub fn cleanup_port_forward(host_port: u16, sandbox_port: u16) void {
    var host_port_buf: [8]u8 = undefined;
    const host_port_str = std.fmt.bufPrintZ(&host_port_buf, "{d}", .{host_port}) catch unreachable;

    var dest_buf: [24]u8 = undefined;
    const dest_str = std.fmt.bufPrintZ(&dest_buf, "10.0.2.2:{d}", .{sandbox_port}) catch unreachable;

    const argv_preroute = [_][*:0]const u8{
        "iptables", "-t",               "nat",     "-D",          "PREROUTING",
        "-p",       "tcp",              "--dport", host_port_str, "-j",
        "DNAT",     "--to-destination", dest_str,
    };
    run_command(&argv_preroute) catch {};

    const argv_output = [_][*:0]const u8{
        "iptables", "-t",               "nat",     "-D",          "OUTPUT",
        "-p",       "tcp",              "--dport", host_port_str, "-j",
        "DNAT",     "--to-destination", dest_str,
    };
    run_command(&argv_output) catch {};

    var sandbox_port_buf: [8]u8 = undefined;
    const sandbox_port_str = std.fmt.bufPrintZ(&sandbox_port_buf, "{d}", .{sandbox_port}) catch unreachable;
    const argv_forward = [_][*:0]const u8{
        "iptables", "-D",       "FORWARD",
        "-d",       "10.0.2.2", "-p",
        "tcp",      "--dport",  sandbox_port_str,
        "-j",       "ACCEPT",
    };
    run_command(&argv_forward) catch {};
}

/// Delete the veth pair.
pub fn delete_veth_pair(veth_name: [:0]const u8) void {
    const argv = [_][*:0]const u8{ "ip", "link", "del", veth_name };
    run_command(&argv) catch {};
}
