//! User namespace setup (uid/gid mapping).

const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;
const fs = @import("../fs/mod.zig");

pub fn setup_user_namespace(pid: posix.pid_t) !void {
    std.debug.assert(pid > 0);

    const uid: u32 = @intCast(linux.getuid());
    const gid = linux.getgid();
    var path_buf: [128]u8 = undefined;
    var map_buf: [64]u8 = undefined;

    const setgroups = std.fmt.bufPrintZ(
        &path_buf,
        "/proc/{d}/setgroups",
        .{pid},
    ) catch unreachable;
    try fs.write_proc_file(setgroups, "deny");

    const uid_map = std.fmt.bufPrintZ(
        &path_buf,
        "/proc/{d}/uid_map",
        .{pid},
    ) catch unreachable;
    const uid_data = std.fmt.bufPrint(
        &map_buf,
        "0 {d} 1\n",
        .{uid},
    ) catch unreachable;
    try fs.write_proc_file(uid_map, uid_data);

    const gid_map = std.fmt.bufPrintZ(
        &path_buf,
        "/proc/{d}/gid_map",
        .{pid},
    ) catch unreachable;
    const gid_data = std.fmt.bufPrint(
        &map_buf,
        "0 {d} 1\n",
        .{gid},
    ) catch unreachable;
    try fs.write_proc_file(gid_map, gid_data);
}
