//! Loopback interface setup.

const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;
const NetworkError = @import("mod.zig").NetworkError;

/// Bring up the `lo` interface so sandboxed processes can reach localhost.
pub fn bring_up_loopback() NetworkError!void {
    const sock_rc: isize = @bitCast(linux.socket(linux.AF.INET, linux.SOCK.DGRAM, 0));
    if (sock_rc < 0) return error.GetFlagsFailed;
    const fd: i32 = @intCast(sock_rc);
    defer _ = linux.close(fd);

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
