//! Child process entry point and execve logic.

const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;
const log = std.log;

const Sandbox = @import("mod.zig").Sandbox;
const args_mod = @import("../args.zig");
const fs = @import("../fs/mod.zig");
const network = @import("../network/mod.zig");
const seccomp = @import("../seccomp.zig");
const container = @import("container.zig");

pub fn child_entry(arg: usize) callconv(.c) u8 {
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
    container.child_bind_mounts(sandbox_ptr.root_path) catch |err| {
        log.err("bind mounts failed: {}", .{err});
        return 1;
    };

    const chdir_rc: isize = @bitCast(linux.chdir(sandbox_ptr.root_path.ptr));
    if (chdir_rc < 0) {
        log.err("chdir failed", .{});
        return 1;
    }

    const rc = linux.syscall1(.chroot, @intFromPtr(sandbox_ptr.root_path.ptr));
    if (rc != 0) {
        log.err("chroot failed", .{});
        return 1;
    }

    network.bring_up_loopback() catch |err| {
        log.err("loopback failed: {}", .{err});
        return 1;
    };

    if (sandbox_ptr.args.config.network_access or sandbox_ptr.args.config.port_forwards.len > 0) {
        var veth_name_buf: [64]u8 = undefined;
        const veth_name = std.fmt.bufPrintZ(&veth_name_buf, "zbxs{s}", .{sandbox_ptr.args.config.name}) catch unreachable;
        network.configure_sandbox_veth(veth_name) catch |err| {
            log.err("sandbox veth config failed: {}", .{err});
            return 1;
        };
    }

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
