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
pub const compute_veth_names = @import("veth.zig").compute_veth_names;
pub const create_veth_link = @import("veth.zig").create_veth_link;
pub const move_veth_to_ns = @import("veth.zig").move_veth_to_ns;
pub const configure_host_veth = @import("veth.zig").configure_host_veth;
pub const configure_sandbox_veth = @import("veth.zig").configure_sandbox_veth;
pub const delete_veth_pair = @import("veth.zig").delete_veth_pair;
pub const setup_port_forward = @import("iptables.zig").setup_port_forward;
pub const cleanup_port_forward = @import("iptables.zig").cleanup_port_forward;
pub const setup_masquerade = @import("iptables.zig").setup_masquerade;

const search_dirs = [_][:0]const u8{ "/usr/sbin/", "/usr/bin/", "/sbin/", "/bin/" };

/// Resolve a bare command name to an absolute path by searching common
/// directories. Returns `null` if the binary is not found.
fn resolve_bin(name: [*:0]const u8, buf: *[256]u8) ?[*:0]const u8 {
    // Already absolute.
    if (name[0] == '/') return name;

    const name_slice = std.mem.span(name);
    for (search_dirs) |dir| {
        const path = std.fmt.bufPrintZ(buf, "{s}{s}", .{ dir, name_slice }) catch continue;
        const rc: isize = @bitCast(linux.access(path.ptr, 1)); // X_OK
        if (rc == 0) return path.ptr;
    }
    return null;
}

/// Run an external command (ip or iptables) and return on success.
pub fn run_command(argv: anytype) !void {
    var resolve_buf: [256]u8 = undefined;
    const arg0: [*:0]const u8 = argv[0] orelse return error.IptablesFailed;
    const bin = resolve_bin(arg0, &resolve_buf) orelse return error.IptablesFailed;

    const pid = linux.fork();
    if (pid == 0) {
        // Redirect stdout/stderr to /dev/null so commands like
        // sysctl and ip don't leak output to the terminal.
        const null_rc: isize = @bitCast(linux.open("/dev/null", .{ .ACCMODE = .WRONLY }, 0));
        if (null_rc >= 0) {
            const null_fd: i32 = @intCast(null_rc);
            _ = linux.dup2(null_fd, 1);
            _ = linux.dup2(null_fd, 2);
            _ = linux.close(null_fd);
        }
        const argv_sentinel: [*:null]const ?[*:0]const u8 = @ptrCast(argv);
        const envp = [_:null]?[*:0]const u8{
            "PATH=/usr/sbin:/usr/bin:/sbin:/bin",
        };
        _ = linux.execve(bin, argv_sentinel, @ptrCast(&envp));
        linux.exit_group(1);
        unreachable;
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
