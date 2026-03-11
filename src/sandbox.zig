const std = @import("std");

const posix = std.posix;
const linux = std.os.linux;
const log = std.log;
const fs = std.fs;

const STACK_SIZE = 64 * 1024;

const clone_flags =
    linux.CLONE.NEWUSER |
    linux.CLONE.NEWNS |
    linux.CLONE.NEWUTS |
    linux.SIG.CHLD;

pub const Config = struct {
    allocator: std.mem.Allocator,
    binary: []u8,
    tools: []u8,
    root: ?[]u8 = null,
    args: []const []const u8 = &.{},

    pub fn init(allocator: std.mem.Allocator) Config {
        return Config{
            .allocator = allocator,
            .binary = allocator.dupe(u8, "/bin/busybox") catch unreachable,
            .tools = allocator.dupe(u8, "") catch unreachable,
        };
    }

    pub fn deinit(self: Config) void {
        self.allocator.free(self.binary);
        self.allocator.free(self.tools);
        if (self.root) |r| {
            self.allocator.free(r);
        }
    }
};

pub const Sandbox = struct {
    allocator: std.mem.Allocator,
    config: Config,
    stack: []u8,
    pipe: [2]posix.fd_t,
    pid: posix.pid_t,
    root_path: []u8,

    pub fn init(allocator: std.mem.Allocator, config: Config) !Sandbox {
        const root_path = if (config.root) |r|
            try allocator.dupe(u8, r)
        else
            try generateRootPath(allocator);

        return Sandbox{
            .allocator = allocator,
            .config = config,
            .stack = try allocator.alignedAlloc(
                u8,
                std.mem.Alignment.fromByteUnits(16),
                STACK_SIZE,
            ),
            .pipe = try posix.pipe(),
            .pid = 0,
            .root_path = root_path,
        };
    }

    pub fn deinit(self: *Sandbox) void {
        self.allocator.free(self.stack);
        self.config.deinit();
        self.allocator.free(self.root_path);
        posix.close(self.pipe[0]);
        posix.close(self.pipe[1]);
    }

    pub fn spawn(self: *Sandbox) !void {
        const stack_top = @intFromPtr(self.stack.ptr) + self.stack.len;

        const raw_pid = linux.clone(
            childEntry,
            stack_top,
            clone_flags,
            @intFromPtr(self),
            null,
            0,
            null,
        );

        const pid: isize = @bitCast(raw_pid);

        if (pid < 0)
            return error.CloneFailed;

        if (pid == 0)
            return;

        self.pid = @intCast(pid);

        log.info("child spawned pid={d}", .{self.pid});

        try self.parentSetup();
        try self.signalChild();
    }

    fn generateRootPath(allocator: std.mem.Allocator) ![]u8 {
        const pid = linux.gettid();
        const timestamp = std.time.milliTimestamp();
        return std.fmt.allocPrint(allocator, "/tmp/zbox-{d}-{d}", .{ pid, timestamp });
    }

    fn writeProcFile(path: []const u8, data: []const u8) !void {
        var file = try fs.openFileAbsolute(path, .{ .mode = .write_only });
        defer file.close();

        try file.writeAll(data);
    }

    fn setupUserNamespace(self: *Sandbox) !void {
        const uid = posix.getuid();
        const gid = linux.getgid();

        var path_buf: [128]u8 = undefined;

        const setgroups = try std.fmt.bufPrint(
            &path_buf,
            "/proc/{d}/setgroups",
            .{self.pid},
        );
        try writeProcFile(setgroups, "deny");

        const uid_map = try std.fmt.bufPrint(
            &path_buf,
            "/proc/{d}/uid_map",
            .{self.pid},
        );

        var map_buf: [64]u8 = undefined;
        const uid_map_data = try std.fmt.bufPrint(
            &map_buf,
            "0 {d} 1\n",
            .{uid},
        );

        try writeProcFile(uid_map, uid_map_data);

        const gid_map = try std.fmt.bufPrint(
            &path_buf,
            "/proc/{d}/gid_map",
            .{self.pid},
        );

        const gid_map_data = try std.fmt.bufPrint(
            &map_buf,
            "0 {d} 1\n",
            .{gid},
        );

        try writeProcFile(gid_map, gid_map_data);
    }

    fn createDir(_: *Sandbox, dir: []const u8) !void {
        fs.makeDirAbsolute(dir) catch |err| {
            if (err != error.PathAlreadyExists) return err;
        };
    }

    fn concatPath(self: *Sandbox, a: []const u8, b: []const u8) ![]u8 {
        return std.fmt.allocPrint(self.allocator, "{s}{s}", .{ a, b });
    }

    fn createSymlink(target: []const u8, link: []const u8) !void {
        posix.symlink(target, link) catch |err| {
            if (err != error.PathAlreadyExists) return err;
        };
    }

    fn fileExists(self: *Sandbox, path: []const u8) bool {
        _ = self;
        fs.accessAbsolute(path, .{}) catch return false;
        return true;
    }

    fn setupContainerFS(self: *Sandbox) !void {
        const root = self.root_path;

        log.info("setting up containerfs at {s}", .{root});

        try self.createDir(root);
        try self.createDir(try self.concatPath(root, "/put_old"));
        try self.createDir(try self.concatPath(root, "/proc"));
        try self.createDir(try self.concatPath(root, "/dev"));
        try self.createDir(try self.concatPath(root, "/tmp"));
        try self.createDir(try self.concatPath(root, "/bin"));

        const busybox_src = "/bin/busybox";
        const busybox_dst = try self.concatPath(root, "/bin/busybox");
        try fs.copyFileAbsolute(busybox_src, busybox_dst, .{});

        var it = std.mem.splitScalar(u8, self.config.tools, ',');
        while (it.next()) |tool| {
            const tool_name = std.mem.trim(u8, tool, " \t\r\n");
            if (tool_name.len == 0) continue;

            const link_path = try self.concatPath(try self.concatPath(root, "/bin/"), tool_name);

            var tool_bin_path_buf: [64]u8 = undefined;
            var tool_usr_bin_path_buf: [64]u8 = undefined;

            const bin_path = std.fmt.bufPrint(&tool_bin_path_buf, "/bin/{s}", .{tool_name}) catch continue;
            const usr_bin_path = std.fmt.bufPrint(&tool_usr_bin_path_buf, "/usr/bin/{s}", .{tool_name}) catch continue;

            const target: []const u8 = if (self.fileExists(bin_path)) bin_path else if (self.fileExists(usr_bin_path)) usr_bin_path else {
                log.warn("tool not found: {s}, skipping", .{tool_name});
                self.allocator.free(link_path);
                continue;
            };

            try createSymlink(target, link_path);
            self.allocator.free(link_path);
        }

        const configs = [_][]const u8{ "/etc/passwd", "/etc/group", "/etc/resolv.conf" };
        inline for (configs) |conf| {
            if (fs.accessAbsolute(conf, .{})) |_| {
                const link_path = try self.concatPath(root, conf);
                createSymlink(conf, link_path) catch {};
            } else |_| {}
        }

        log.info("containerfs setup complete", .{});
    }

    fn bindMount(_: *Sandbox, source: []const u8, target: []const u8) !void {
        log.info("bind mounting {s} -> {s}", .{ source, target });

        _ = linux.syscall5(.mount, @intFromPtr(source.ptr), @intFromPtr(target.ptr), @intFromPtr("".ptr), 4096, 0);
    }

    fn parentSetup(self: *Sandbox) !void {
        log.info("parent performing namespace setup", .{});

        try self.setupUserNamespace();
        try self.setupContainerFS();

        const root = self.root_path;
        const proc_path = try self.concatPath(root, "/proc");
        const dev_path = try self.concatPath(root, "/dev");
        const tmp_path = try self.concatPath(root, "/tmp");
        defer self.allocator.free(proc_path);
        defer self.allocator.free(dev_path);
        defer self.allocator.free(tmp_path);

        try self.bindMount(root, root);

        try self.bindMount("/proc", proc_path);
        try self.bindMount("/dev", dev_path);
        try self.bindMount("/tmp", tmp_path);
    }

    fn signalChild(self: *Sandbox) !void {
        const msg: [1]u8 = .{'x'};
        _ = try posix.write(self.pipe[1], &msg);
    }

    pub fn wait(self: *Sandbox) !void {
        const res = posix.waitpid(self.pid, 0);
        const status = res.status;

        if ((status & 0x7f) == 0) {
            log.info("child exited code={d}", .{(status >> 8) & 0xff});
        } else if ((status & 0x7f) != 0x7f) {
            log.warn("child killed by signal={d}", .{status & 0x7f});
        } else if ((status & 0xff) == 0x7f) {
            log.warn("child stopped signal={d}", .{(status >> 8) & 0xff});
        } else if ((status & 0xffff) == 0xffff) {
            log.debug("child continued", .{});
        }

        try self.cleanup();
    }

    fn cleanup(self: *Sandbox) !void {
        const root = self.root_path;

        const proc_path = try self.concatPath(root, "/proc");
        const dev_path = try self.concatPath(root, "/dev");
        const tmp_path = try self.concatPath(root, "/tmp");
        defer self.allocator.free(proc_path);
        defer self.allocator.free(dev_path);
        defer self.allocator.free(tmp_path);

        log.info("cleaning up bind mounts and container root", .{});

        _ = linux.syscall2(.umount2, @intFromPtr(proc_path.ptr), 0);
        _ = linux.syscall2(.umount2, @intFromPtr(dev_path.ptr), 0);
        _ = linux.syscall2(.umount2, @intFromPtr(tmp_path.ptr), 0);

        fs.deleteTreeAbsolute(root) catch |err| {
            log.warn("failed to cleanup {s}: {}", .{ root, err });
        };

        log.info("cleanup complete", .{});
    }
};

fn childEntry(arg: usize) callconv(.c) u8 {
    const sandbox: *Sandbox = @ptrFromInt(arg);

    log.info("child waiting for parent setup", .{});

    var buf: [1]u8 = undefined;

    if (posix.read(sandbox.pipe[0], &buf)) |_| {} else |err| {
        log.err("child pipe read failed: {}", .{err});
        return 1;
    }

    log.info("child starting sandbox workload", .{});

    const root = sandbox.root_path;

    posix.chdir(root) catch |err| {
        log.err("chdir to {s} failed: {}", .{ root, err });
        return 1;
    };

    const errno_chroot = linux.syscall1(.chroot, @intFromPtr(root.ptr));
    if (errno_chroot != 0) {
        log.err("chroot failed", .{});
        return 1;
    }

    log.info("chroot complete, executing {s}", .{sandbox.config.binary});

    const binary_ptr: [*:0]const u8 = @ptrCast(sandbox.config.binary.ptr);
    _ = linux.execve(binary_ptr, &.{ binary_ptr, "sh", null }, &.{null});

    log.err("execve failed", .{});
    return 1;
}
