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

pub const Sandbox = struct {
    allocator: std.mem.Allocator,
    stack: []u8,
    pipe: [2]posix.fd_t,
    pid: posix.pid_t,

    pub fn init(allocator: std.mem.Allocator) !Sandbox {
        return Sandbox{
            .allocator = allocator,
            .stack = try allocator.alignedAlloc(
                u8,
                std.mem.Alignment.fromByteUnits(16),
                STACK_SIZE,
            ),
            .pipe = try posix.pipe(),
            .pid = 0,
        };
    }

    pub fn deinit(self: *Sandbox) void {
        self.allocator.free(self.stack);
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
    fn parentSetup(self: *Sandbox) !void {
        log.info("parent performing namespace setup", .{});

        try self.setupUserNamespace();

        // TODO: mount namespace configuration
        // TODO: bind mounts
        // TODO: pivot_root / chroot

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

    // TODO: exec target binary
    // example:
    // posix.execve(...)

    log.info("child exiting", .{});

    return 0;
}
