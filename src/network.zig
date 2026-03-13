const std = @import("std");

const posix = std.posix;
const linux = std.os.linux;

fn bringUpLoopback() !void {
    // connect to netstack
    const fd = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0);
    defer posix.close(fd);

    // get interface req ready for loopback
    var ifr = std.mem.zeroInit(posix.ifreq, .{});
    const if_name = "lo";
    @memcpy(ifr.ifrn.name[0..if_name.len], if_name);

    // get curr flags
    var err = linux.ioctl(fd, linux.SIOCGIFFLAGS, @intFromPtr(&ifr));
    if (posix.errno(err) != .SUCCESS) return error.GetFlagsFailed;

    // set UP and RUNNING using struct fields
    var flags_struct: linux.IFF = ifr.ifru.flags;
    flags_struct.UP = true;
    flags_struct.RUNNING = true;
    ifr.ifru.flags = flags_struct;

    err = linux.ioctl(fd, linux.SIOCSIFFLAGS, @intFromPtr(&ifr));
    if (posix.errno(err) != .SUCCESS) return error.SetFlagsFailed;
}
