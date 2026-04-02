//! Iptables port forwarding and masquerade rules.

const std = @import("std");
const log = std.log;
const run_command = @import("mod.zig").run_command;
const NetworkError = @import("mod.zig").NetworkError;

/// Shared helper: apply or remove DNAT + FORWARD rules for a port pair.
fn port_forward_rules(action: [*:0]const u8, host_port: u16, sandbox_port: u16) NetworkError!void {
    var host_port_buf: [8]u8 = undefined;
    const host_port_str = std.fmt.bufPrintZ(&host_port_buf, "{d}", .{host_port}) catch unreachable;

    var dest_buf: [24]u8 = undefined;
    const dest_str = std.fmt.bufPrintZ(&dest_buf, "10.0.2.2:{d}", .{sandbox_port}) catch unreachable;

    var sandbox_port_buf: [8]u8 = undefined;
    const sandbox_port_str = std.fmt.bufPrintZ(&sandbox_port_buf, "{d}", .{sandbox_port}) catch unreachable;

    const argv_preroute = [_][*:0]const u8{
        "iptables", "-t",               "nat",     action,        "PREROUTING",
        "-p",       "tcp",              "--dport", host_port_str, "-j",
        "DNAT",     "--to-destination", dest_str,
    };
    run_command(&argv_preroute) catch return error.IptablesFailed;

    const argv_output = [_][*:0]const u8{
        "iptables", "-t",               "nat",     action,        "OUTPUT",
        "-p",       "tcp",              "--dport", host_port_str, "-j",
        "DNAT",     "--to-destination", dest_str,
    };
    run_command(&argv_output) catch return error.IptablesFailed;

    const argv_forward = [_][*:0]const u8{
        "iptables", action,     "FORWARD",
        "-d",       "10.0.2.2", "-p",
        "tcp",      "--dport",  sandbox_port_str,
        "-j",       "ACCEPT",
    };
    run_command(&argv_forward) catch return error.IptablesFailed;
}

/// Set up iptables DNAT rules for port forwarding.
pub fn setup_port_forward(host_port: u16, sandbox_port: u16) !void {
    port_forward_rules("-A", host_port, sandbox_port) catch {
        log.err("failed to add port forward rules", .{});
        return error.IptablesFailed;
    };
}

/// Clean up iptables rules for port forwarding.
pub fn cleanup_port_forward(host_port: u16, sandbox_port: u16) void {
    port_forward_rules("-D", host_port, sandbox_port) catch {};
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
