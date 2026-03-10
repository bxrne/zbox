const std = @import("std");
const print = std.debug.print;
const posix = std.posix;
const x = std.os.linux;
const runtime = @import("runtime.zig");

var global_pipe_fds: [2]posix.fd_t = undefined;

fn spawn() !void {
    const pipe_fds = try posix.pipe();
    global_pipe_fds = pipe_fds;

    const flags = x.CLONE.NEWNET | x.CLONE.NEWUTS | x.SIG.CHLD;
    var stack: [64 * 1024]u8 align(16) = undefined;
    const raw_pid = x.clone(childEntry, @intFromPtr(&stack) + stack.len, flags, 0, null, 0, null);
    const pid = @as(isize, @bitCast(raw_pid));

    if (pid < 0) {
        print("parent: clone failed\n", .{});
        return error.CloneFailed;
    }

    if (pid == 0) {
        return;
    }

    print("parent: child pid {d}\n", .{pid});
    runtime.createNs() catch |err| {
        print("parent: createNs failed: {}\n", .{err});
        return err;
    };
    runtime.mapNs() catch |err| {
        print("parent: mapNs failed: {}\n", .{err});
        return err;
    };
    _ = posix.write(pipe_fds[1], "x") catch |err| {
        print("parent: write signal failed: {}\n", .{err});
        return err;
    };
    print("parent: done\n", .{});
}

fn childEntry(_: usize) callconv(.c) u8 {
    print("child: waiting on parent\n", .{});
    var buf: [1]u8 = undefined;
    if (posix.read(global_pipe_fds[0], &buf)) |_| {
        print("child: parent signal received\n", .{});
    } else |err| {
        print("child: read failed: {}\n", .{err});
        return 1;
    }
    print("child: exec sandbox program\n", .{});
    runtime.mountNs() catch |err| {
        print("child: mountNs failed: {}\n", .{err});
        return 1;
    };
    runtime.rootFs() catch |err| {
        print("child: rootFs failed: {}\n", .{err});
        return 1;
    };
    runtime.mountFs() catch |err| {
        print("child: mountFs failed: {}\n", .{err});
        return 1;
    };
    runtime.initPIDNs() catch |err| {
        print("child: initPIDNs failed: {}\n", .{err});
        return 1;
    };
    print("child: done\n", .{});
    return 0;
}

pub fn main() !void {
    spawn() catch |err| {
        print("main: spawn failed: {}\n", .{err});
        return err;
    };
}
