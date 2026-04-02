//! Filesystem mount operations.

const std = @import("std");
const linux = std.os.linux;
const log = std.log;

pub fn bind_mount(source: [:0]const u8, target: [:0]const u8) !void {
    std.debug.assert(source.len > 0 and source[0] == '/');
    std.debug.assert(target.len > 0 and target[0] == '/');
    log.info("bind mounting {s} -> {s}", .{ source, target });

    const rc: isize = @bitCast(linux.syscall5(
        .mount,
        @intFromPtr(source.ptr),
        @intFromPtr(target.ptr),
        @intFromPtr(""),
        4096, // MS_BIND
        0,
    ));
    if (rc < 0) return error.MountFailed;
}

/// Mount a filesystem by type (e.g. "proc", "tmpfs") onto `target`.
pub fn mount_fs(
    comptime fstype: [:0]const u8,
    target: [:0]const u8,
) !void {
    log.info("mounting {s} on {s}", .{ fstype, target });
    const rc: isize = @bitCast(linux.syscall5(
        .mount,
        @intFromPtr(fstype.ptr),
        @intFromPtr(target.ptr),
        @intFromPtr(fstype.ptr),
        0,
        0,
    ));
    if (rc < 0) return error.MountFailed;
}
