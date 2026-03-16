//! Rootless Linux sandbox using user, mount, UTS and network namespaces.
const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;
const log = std.log;

const args_mod = @import("args.zig");
const cgroup = @import("cgroup.zig");
const network = @import("network.zig");
const seccomp = @import("seccomp.zig");
const fs = @import("fs.zig");

const STACK_SIZE: u32 = 64 * 1024;

const clone_flags: u32 =
    linux.CLONE.NEWNET |
    linux.CLONE.NEWPID |
    linux.CLONE.NEWUSER |
    linux.CLONE.NEWNS |
    linux.CLONE.NEWUTS |
    linux.SIG.CHLD;

// these flags share address space with the parent and
// would break our fork-style isolation.
comptime {
    std.debug.assert(clone_flags & linux.CLONE.VM == 0);
    std.debug.assert(clone_flags & linux.CLONE.THREAD == 0);
    std.debug.assert(clone_flags & linux.CLONE.SIGHAND == 0);
}

/// Decoded result of a `waitpid` status word.
pub const WaitResult = union(enum) {
    exited: u8,
    signaled: u7,
    stopped: u8,
    continued: void,
};

/// Decode a raw waitpid status. Continued (0xffff) must be checked
/// first because its bit pattern overlaps the stopped encoding.
pub fn decode_wait_status(status: u32) WaitResult {
    if (status == 0xffff) return .continued;
    if ((status & 0x7f) == 0) return .{ .exited = @intCast((status >> 8) & 0xff) };
    if ((status & 0xff) == 0x7f) return .{ .stopped = @intCast((status >> 8) & 0xff) };
    return .{ .signaled = @intCast(status & 0x7f) };
}

pub const Sandbox = struct {
    allocator: std.mem.Allocator,
    args: args_mod.Args,
    stack: []align(16) u8,
    pipe: [2]posix.fd_t,
    pid: posix.pid_t,
    root_path: [:0]const u8,
    generated_root: bool,

    pub fn init(allocator: std.mem.Allocator, args: args_mod.Args) !Sandbox {
        std.debug.assert(args.config.binary.len > 0 and args.config.binary[0] == '/');

        const root_path: [:0]const u8 = try allocator.dupeZ(u8, args.config.root);
        errdefer allocator.free(root_path);

        const stack = try allocator.alignedAlloc(
            u8,
            std.mem.Alignment.fromByteUnits(16),
            STACK_SIZE,
        );
        errdefer allocator.free(stack);

        const pipe = try posix.pipe();

        const self = Sandbox{
            .allocator = allocator,
            .args = args,
            .stack = stack,
            .pipe = pipe,
            .pid = 0,
            .root_path = root_path,
            .generated_root = false,
        };

        // Postconditions on the freshly-built sandbox.
        std.debug.assert(self.pid == 0);
        std.debug.assert(self.stack.len == STACK_SIZE);
        std.debug.assert(self.pipe[0] != self.pipe[1]);
        std.debug.assert(self.root_path.len > 1 and self.root_path[0] == '/');

        return self;
    }

    pub fn deinit(self: *Sandbox) void {
        posix.close(self.pipe[0]);
        posix.close(self.pipe[1]);
        self.allocator.free(self.stack);
        self.allocator.free(self.root_path);
        self.args.deinit(self.allocator);
    }

    /// Clone a child into isolated namespaces, perform parent-side setup,
    /// then signal the child to continue.
    pub fn spawn(self: *Sandbox) !void {
        std.debug.assert(self.pid == 0);

        const stack_top = @intFromPtr(self.stack.ptr) + self.stack.len;
        const raw_pid = linux.clone(
            child_entry,
            stack_top,
            clone_flags,
            @intFromPtr(self),
            null,
            0,
            null,
        );
        const pid: isize = @bitCast(raw_pid);
        if (pid < 0) return error.CloneFailed;
        if (pid == 0) return;

        self.pid = @intCast(pid);
        std.debug.assert(self.pid > 0);
        log.info("child spawned pid={d}", .{self.pid});

        try self.parent_setup();
        try self.signal_child();
    }

    /// Wait for the child to exit, log the result, and clean up.
    pub fn wait(self: *Sandbox) !void {
        std.debug.assert(self.pid > 0);

        const res = posix.waitpid(self.pid, 0);
        switch (decode_wait_status(res.status)) {
            .exited => |code| log.info("child exited code={d}", .{code}),
            .signaled => |sig| log.warn("child killed signal={d}", .{sig}),
            .stopped => |sig| log.warn("child stopped signal={d}", .{sig}),
            .continued => log.debug("child continued", .{}),
        }
        try self.cleanup();
    }

    fn parent_setup(self: *Sandbox) !void {
        std.debug.assert(self.pid > 0);
        log.info("parent performing namespace setup", .{});

        try self.setup_user_namespace();
        try self.setup_container_fs();

        cgroup.create(
            self.args.config.name,
            self.args.config.cpu_cores,
            self.args.config.cpu_limit_percent,
            self.args.config.memory_limit_mb,
        ) catch |err| {
            log.warn("cgroup setup failed: {}", .{err});
            return;
        };
        cgroup.add_process(self.args.config.name, self.pid) catch |err| {
            log.warn("cgroup add_process failed: {}", .{err});
        };
    }

    fn setup_user_namespace(self: *Sandbox) !void {
        std.debug.assert(self.pid > 0);

        const uid = posix.getuid();
        const gid = linux.getgid();
        var path_buf: [128]u8 = undefined;
        var map_buf: [64]u8 = undefined;

        const setgroups = std.fmt.bufPrintZ(
            &path_buf,
            "/proc/{d}/setgroups",
            .{self.pid},
        ) catch unreachable;
        try fs.write_proc_file(setgroups, "deny");

        const uid_map = std.fmt.bufPrintZ(
            &path_buf,
            "/proc/{d}/uid_map",
            .{self.pid},
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
            .{self.pid},
        ) catch unreachable;
        const gid_data = std.fmt.bufPrint(
            &map_buf,
            "0 {d} 1\n",
            .{gid},
        ) catch unreachable;
        try fs.write_proc_file(gid_map, gid_data);
    }

    fn setup_container_fs(self: *Sandbox) !void {
        const root = self.root_path;
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
        const basename = fs.extract_basename(self.args.config.binary);
        var dst_buf: [4096]u8 = undefined;
        const bin_dst = std.fmt.bufPrintZ(
            &dst_buf,
            "{s}/bin/{s}",
            .{ root, basename },
        ) catch unreachable;
        try std.fs.copyFileAbsolute(self.args.config.binary, bin_dst, .{});

        copy_host_configs(root);
        log.info("containerfs setup complete", .{});
    }

    fn signal_child(self: *Sandbox) !void {
        const msg: [1]u8 = .{'x'};
        const n = try posix.write(self.pipe[1], &msg);
        std.debug.assert(n == 1);
    }

    fn cleanup(self: *Sandbox) !void {
        var buf_proc: [4096]u8 = undefined;
        var buf_dev: [4096]u8 = undefined;
        var buf_tmp: [4096]u8 = undefined;

        cgroup.destroy(self.args.config.name);
        log.info("cleaning up bind mounts and container root", .{});
        _ = linux.syscall2(.umount2, @intFromPtr(fs.join_path(&buf_proc, self.root_path, "/proc").ptr), 0);
        _ = linux.syscall2(.umount2, @intFromPtr(fs.join_path(&buf_dev, self.root_path, "/dev").ptr), 0);
        _ = linux.syscall2(.umount2, @intFromPtr(fs.join_path(&buf_tmp, self.root_path, "/tmp").ptr), 0);

        // Only remove the root if we generated it.
        if (self.generated_root) {
            std.fs.deleteTreeAbsolute(self.root_path) catch |err| {
                log.warn("failed to cleanup {s}: {}", .{ self.root_path, err });
            };
        }
        log.info("cleanup complete", .{});
    }
};

/// Set up mounts inside the child's mount namespace. The self-bind-mount
/// is required for chroot to work. The proc/dev/tmp mounts are
/// best-effort — the sandbox functions without them but they provide
/// a richer environment when the kernel permits them.
fn child_bind_mounts(root: [:0]const u8) !void {
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
        if (std.fs.accessAbsolute(conf, .{})) |_| {
            var buf: [4096]u8 = undefined;
            const dst = fs.join_path(&buf, root, conf);
            std.fs.copyFileAbsolute(conf, dst, .{}) catch {};
        } else |_| {}
    }
}

fn child_entry(arg: usize) callconv(.c) u8 {
    std.debug.assert(arg != 0);
    const sandbox_ptr: *Sandbox = @ptrFromInt(arg);

    var buf: [1]u8 = undefined;
    const n = posix.read(sandbox_ptr.pipe[0], &buf) catch |err| {
        log.err("child pipe read failed: {}", .{err});
        return 1;
    };
    if (n == 0) {
        log.err("pipe EOF — parent died before signalling", .{});
        return 1;
    }
    std.debug.assert(n == 1 and buf[0] == 'x');

    // Bind mounts must happen inside the child because CLONE_NEWNS
    // gave *this* process the new mount namespace, not the parent.
    child_bind_mounts(sandbox_ptr.root_path) catch |err| {
        log.err("bind mounts failed: {}", .{err});
        return 1;
    };

    posix.chdir(sandbox_ptr.root_path) catch |err| {
        log.err("chdir failed: {}", .{err});
        return 1;
    };

    const rc = linux.syscall1(.chroot, @intFromPtr(sandbox_ptr.root_path.ptr));
    if (rc != 0) {
        log.err("chroot failed", .{});
        return 1;
    }

    network.bring_up_loopback() catch |err| {
        log.err("loopback failed: {}", .{err});
        return 1;
    };

    // Install seccomp filter last — after all privileged setup is done
    // but before execve hands control to untrusted code.
    seccomp.install() catch |err| {
        log.err("seccomp install failed: {}", .{err});
        return 1;
    };

    return do_execve(sandbox_ptr);
}

/// Build argv from args and call execve. Factored out to keep
/// child_entry under 70 lines.
fn do_execve(sandbox_ptr: *Sandbox) u8 {
    const basename = fs.extract_basename(sandbox_ptr.args.config.binary);
    var bin_buf: [4096]u8 = undefined;
    const bin_path = std.fmt.bufPrintZ(
        &bin_buf,
        "/bin/{s}",
        .{basename},
    ) catch unreachable;
    const bin_ptr: [*:0]const u8 = bin_path.ptr;

    if (sandbox_ptr.args.child_args_count > 0) {
        var argv: [args_mod.args_max + 2]?[*:0]const u8 = undefined;
        argv[0] = bin_ptr;
        var i: u32 = 0;
        while (i < sandbox_ptr.args.child_args_count) : (i += 1) {
            argv[i + 1] = sandbox_ptr.args.child_args[i].ptr;
        }
        argv[sandbox_ptr.args.child_args_count + 1] = null;
        _ = linux.execve(bin_ptr, @ptrCast(&argv), &.{null});
    } else {
        _ = linux.execve(bin_ptr, &.{ bin_ptr, "sh", null }, &.{null});
    }

    log.err("execve failed", .{});
    return 1;
}

test "decode_wait_status — normal exit" {
    const result = decode_wait_status(0x0500); // exit code 5
    switch (result) {
        .exited => |code| try std.testing.expectEqual(@as(u8, 5), code),
        else => return error.UnexpectedResult,
    }
}

test "decode_wait_status — exit zero" {
    const result = decode_wait_status(0x0000);
    switch (result) {
        .exited => |code| try std.testing.expectEqual(@as(u8, 0), code),
        else => return error.UnexpectedResult,
    }
}

test "decode_wait_status — signaled" {
    const result = decode_wait_status(0x0009); // SIGKILL = 9
    switch (result) {
        .signaled => |sig| try std.testing.expectEqual(@as(u7, 9), sig),
        else => return error.UnexpectedResult,
    }
}

test "decode_wait_status — stopped" {
    const result = decode_wait_status(0x137f); // stopped by signal 19
    switch (result) {
        .stopped => |sig| try std.testing.expectEqual(@as(u8, 0x13), sig),
        else => return error.UnexpectedResult,
    }
}

test "decode_wait_status — continued" {
    const result = decode_wait_status(0xffff);
    switch (result) {
        .continued => {},
        else => return error.UnexpectedResult,
    }
}

test "extract_basename simple" {
    try std.testing.expectEqualStrings("busybox", fs.extract_basename("/bin/busybox"));
}

test "extract_basename nested" {
    try std.testing.expectEqualStrings("sh", fs.extract_basename("/usr/bin/sh"));
}

test "join_path appends suffix" {
    var buf: [4096]u8 = undefined;
    const result = fs.join_path(&buf, "/tmp/root", "/proc");
    try std.testing.expectEqualStrings("/tmp/root/proc", result);
}

test "join_path empty suffix" {
    var buf: [4096]u8 = undefined;
    const result = fs.join_path(&buf, "/tmp/root", "");
    try std.testing.expectEqualStrings("/tmp/root", result);
}
