//! Network setup for sandbox: veth pairs, loopback, and iptables port forwarding.

const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;

pub const NetworkError = error{
    GetFlagsFailed,
    SetFlagsFailed,
    VerifyFailed,
    VethCreationFailed,
    VethMoveFailed,
    IpConfigFailed,
    IptablesFailed,
};

pub const VETH_HOST_PREFIX = "zbxh";
pub const VETH_SANDBOX_PREFIX = "zbxs";
pub const HOST_IP = "10.0.2.1/24";
pub const SANDBOX_IP = "10.0.2.2/24";

pub const bring_up_loopback = @import("loopback.zig").bring_up_loopback;
pub const create_veth_pair = @import("veth.zig").create_veth_pair;
pub const move_veth_to_ns = @import("veth.zig").move_veth_to_ns;
pub const configure_host_veth = @import("veth.zig").configure_host_veth;
pub const configure_sandbox_veth = @import("veth.zig").configure_sandbox_veth;
pub const delete_veth_pair = @import("veth.zig").delete_veth_pair;
pub const setup_port_forward = @import("iptables.zig").setup_port_forward;
pub const cleanup_port_forward = @import("iptables.zig").cleanup_port_forward;
pub const setup_masquerade = @import("iptables.zig").setup_masquerade;

/// Run an external command (ip or iptables) and return on success.
pub fn run_command(argv: anytype) !void {
    const pid = linux.fork();
    if (pid == 0) {
        const argv_sentinel: [*:null]const ?[*:0]const u8 = @ptrCast(argv);
        _ = linux.execve(argv[0], argv_sentinel, &.{null});
        @panic("execve failed");
    }
    var status: u32 = undefined;
    _ = linux.waitpid(@intCast(pid), &status, 0);
    if (status != 0) {
        return error.IptablesFailed;
    }
}

test {
    _ = @import("loopback.zig");
    _ = @import("veth.zig");
    _ = @import("iptables.zig");
}
