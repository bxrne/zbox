//! Container filesystem setup and bind mounts.

const std = @import("std");
const linux = std.os.linux;
const log = std.log;
const fs = @import("../fs/mod.zig");

/// Create the container root filesystem and copy the binary into it.
pub fn setup_container_fs(root: [:0]const u8, binary: [:0]const u8) !void {
    log.info("setting up containerfs at {s}", .{root});
    var buf: [4096]u8 = undefined;

    try fs.create_dir(fs.join_path(&buf, root, ""));
    try fs.create_dir(fs.join_path(&buf, root, "/put_old"));
    try fs.create_dir(fs.join_path(&buf, root, "/proc"));
    try fs.create_dir(fs.join_path(&buf, root, "/dev"));
    try fs.create_dir(fs.join_path(&buf, root, "/tmp"));
    try fs.create_dir(fs.join_path(&buf, root, "/bin"));
    try fs.create_dir(fs.join_path(&buf, root, "/etc"));

    // Copy the configured binary into the container.
    const basename = fs.extract_basename(binary);
    var dst_buf: [4096]u8 = undefined;
    const bin_dst = std.fmt.bufPrintZ(
        &dst_buf,
        "{s}/bin/{s}",
        .{ root, basename },
    ) catch unreachable;
    try copyFile(binary, bin_dst);

    copy_host_configs(root);
    log.info("containerfs setup complete", .{});
}

/// Set up mounts inside the child's mount namespace. The self-bind-mount
/// is required for chroot to work. The proc/dev/tmp mounts are
/// best-effort — the sandbox functions without them but they provide
/// a richer environment when the kernel permits them.
pub fn child_bind_mounts(root: [:0]const u8) !void {
    var buf_src: [4096]u8 = undefined;
    var buf_dst: [4096]u8 = undefined;

    try fs.bind_mount(
        fs.join_path(&buf_src, root, ""),
        fs.join_path(&buf_dst, root, ""),
    );

    // Make the mount private so child mounts don't propagate to the host.
    const MS_PRIVATE = 1 << 18;
    const MS_REC = 16384;
    const rc: isize = @bitCast(linux.syscall5(
        .mount,
        @intFromPtr(""),
        @intFromPtr(fs.join_path(&buf_src, root, "").ptr),
        @intFromPtr(""),
        MS_PRIVATE | MS_REC,
        0,
    ));
    if (rc < 0) log.warn("failed to make root private", .{});

    var buf: [4096]u8 = undefined;
    try fs.mount_fs("proc", fs.join_path(&buf, root, "/proc"));
    try fs.mount_fs("tmpfs", fs.join_path(&buf, root, "/dev"));
    try fs.mount_fs("tmpfs", fs.join_path(&buf, root, "/tmp"));
}

/// Copy well-known host config files into the container. Copies rather
/// than symlinks because symlinks to `/etc/foo` form a loop inside chroot.
fn copy_host_configs(root: [:0]const u8) void {
    const configs = [_][:0]const u8{ "/etc/passwd", "/etc/group", "/etc/resolv.conf" };
    inline for (configs) |conf| {
        const acc_rc: isize = @bitCast(linux.access(conf.ptr, 0));
        if (acc_rc == 0) {
            var buf: [4096]u8 = undefined;
            const dst = fs.join_path(&buf, root, conf);
            copyFile(conf, dst) catch {};
        }
    }
}

fn copyFile(src: [:0]const u8, dst: [:0]const u8) !void {
    const posix = std.posix;
    const src_fd = posix.openat(posix.AT.FDCWD, src, .{}, 0) catch return error.CopyFailed;
    defer _ = linux.close(src_fd);
    const dst_fd_rc: isize = @bitCast(linux.open(dst.ptr, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o755));
    if (dst_fd_rc < 0) return error.CopyFailed;
    const dst_fd: i32 = @intCast(dst_fd_rc);
    defer _ = linux.close(dst_fd);
    var buf: [4096]u8 = undefined;
    while (true) {
        const n = posix.read(src_fd, &buf) catch return error.CopyFailed;
        if (n == 0) break;
        var written: usize = 0;
        while (written < n) {
            const w: isize = @bitCast(linux.write(dst_fd, buf[written..].ptr, n - written));
            if (w < 0) return error.CopyFailed;
            written += @intCast(w);
        }
    }
}
