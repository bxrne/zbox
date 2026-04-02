//! Filesystem utilities.

const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;

pub const join_path = @import("path.zig").join_path;
pub const extract_basename = @import("path.zig").extract_basename;
pub const bind_mount = @import("mount.zig").bind_mount;
pub const mount_fs = @import("mount.zig").mount_fs;

pub fn write_proc_file(path: [:0]const u8, data: []const u8) !void {
    std.debug.assert(path.len > 0 and path[0] == '/');
    const fd = posix.openat(posix.AT.FDCWD, path, .{ .ACCMODE = .WRONLY }, 0) catch return error.WriteFailed;
    defer _ = linux.close(fd);
    _ = linux.write(fd, data.ptr, data.len);
}

pub fn create_dir(dir: [:0]const u8) !void {
    const rc: isize = @bitCast(linux.mkdir(dir.ptr, 0o755));
    if (rc < 0) {
        const err = posix.errno(@bitCast(rc));
        if (err != .EXIST) return error.MkdirFailed;
    }
}

pub fn create_symlink(target: [:0]const u8, link: [:0]const u8) !void {
    const rc: isize = @bitCast(linux.symlink(target.ptr, link.ptr));
    if (rc < 0) {
        const err = posix.errno(@bitCast(rc));
        if (err != .EXIST) return error.SymlinkFailed;
    }
}

pub fn generate_root_path(allocator: std.mem.Allocator) ![:0]const u8 {
    const tid = linux.gettid();
    const ts = std.time.milliTimestamp();
    return std.fmt.allocPrintSentinel(allocator, "/tmp/zbox-{d}-{d}", .{ tid, ts }, 0);
}

test {
    _ = @import("path.zig");
    _ = @import("mount.zig");
}
