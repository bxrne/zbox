//! Cgroup v2 resource limits for sandboxed processes.

const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;
const log = std.log;

pub const CgroupError = error{
    CreateFailed,
    WriteFailed,
    CleanupFailed,
};

/// Write `data` to `/sys/fs/cgroup/{dir}/{file}`.
fn write_cgroup_file(dir: []const u8, file: []const u8, data: []const u8) CgroupError!void {
    var buf: [256]u8 = undefined;
    const path = std.fmt.bufPrintZ(&buf, "/sys/fs/cgroup/{s}/{s}", .{ dir, file }) catch
        return error.WriteFailed;

    const fd = posix.openat(posix.AT.FDCWD, path, .{ .ACCMODE = .WRONLY }, 0) catch
        return error.WriteFailed;
    defer _ = linux.close(fd);

    _ = linux.write(fd, data.ptr, data.len);
}

/// Create a cgroup v2 group and configure CPU and memory limits.
///
/// Creates `/sys/fs/cgroup/{name}` and writes:
///   - `cpu.max`     — "{quota} {period}" (period = 100 000 µs)
///   - `cpuset.cpus` — "0-{cpu_cores-1}"
///   - `memory.max`  — bytes as decimal string
pub fn create(name: []const u8, cpu_cores: u32, cpu_limit_percent: u32, memory_limit_mb: u32) CgroupError!void {
    std.debug.assert(cpu_cores > 0);
    std.debug.assert(cpu_limit_percent > 0 and cpu_limit_percent <= 100);
    std.debug.assert(memory_limit_mb > 0);

    var path_buf: [256]u8 = undefined;
    const path = std.fmt.bufPrintZ(&path_buf, "/sys/fs/cgroup/{s}", .{name}) catch
        return error.CreateFailed;

    const mkdir_rc: isize = @bitCast(linux.mkdir(path.ptr, 0o755));
    if (mkdir_rc < 0) {
        const err = posix.errno(@bitCast(mkdir_rc));
        if (err != .EXIST) return error.CreateFailed;
    }

    // cpu.max format: "{quota} {period}" — period is 100 000 µs
    const period: u64 = 100_000;
    const quota = compute_cpu_quota(period, cpu_cores, cpu_limit_percent);
    var cpu_buf: [64]u8 = undefined;
    const cpu_max = std.fmt.bufPrint(&cpu_buf, "{d} {d}", .{ quota, period }) catch
        return error.WriteFailed;
    try write_cgroup_file(name, "cpu.max", cpu_max);

    // cpuset.cpus format: "0-{N-1}"
    var cpuset_buf: [32]u8 = undefined;
    const cpuset = std.fmt.bufPrint(&cpuset_buf, "0-{d}", .{cpu_cores - 1}) catch
        return error.WriteFailed;
    try write_cgroup_file(name, "cpuset.cpus", cpuset);

    // memory.max in bytes
    const mem_bytes: u64 = @as(u64, memory_limit_mb) * 1024 * 1024;
    var mem_buf: [32]u8 = undefined;
    const mem_max = std.fmt.bufPrint(&mem_buf, "{d}", .{mem_bytes}) catch
        return error.WriteFailed;
    try write_cgroup_file(name, "memory.max", mem_max);

    log.info("cgroup '{s}' created: cpu={d}/{d}µs cpuset=0-{d} mem={d}MB", .{
        name, quota, period, cpu_cores - 1, memory_limit_mb,
    });
}

/// Add a process to the cgroup by writing its PID to `cgroup.procs`.
pub fn add_process(name: []const u8, pid: i32) CgroupError!void {
    std.debug.assert(pid > 0);

    var pid_buf: [16]u8 = undefined;
    const pid_str = std.fmt.bufPrint(&pid_buf, "{d}", .{pid}) catch
        return error.WriteFailed;
    try write_cgroup_file(name, "cgroup.procs", pid_str);
}

/// Remove the cgroup directory. Best-effort: logs a warning on failure.
pub fn destroy(name: []const u8) void {
    var buf: [256]u8 = undefined;
    const path = std.fmt.bufPrintZ(&buf, "/sys/fs/cgroup/{s}", .{name}) catch {
        log.warn("cgroup destroy: path format error for '{s}'", .{name});
        return;
    };

    const rmdir_rc: isize = @bitCast(linux.rmdir(path.ptr));
    if (rmdir_rc < 0) {
        log.warn("cgroup destroy: failed to remove '{s}'", .{path});
        return;
    }

    log.info("cgroup '{s}' destroyed", .{name});
}

/// Compute the CPU quota for `cpu.max`.
///   quota = period × cpu_cores × cpu_limit_percent / 100
fn compute_cpu_quota(period: u64, cpu_cores: u32, cpu_limit_percent: u32) u64 {
    return period * @as(u64, cpu_cores) * @as(u64, cpu_limit_percent) / 100;
}

test "compute_cpu_quota — single core full usage" {
    const quota = compute_cpu_quota(100_000, 1, 100);
    try std.testing.expectEqual(@as(u64, 100_000), quota);
}

test "compute_cpu_quota — two cores at 50 percent" {
    const quota = compute_cpu_quota(100_000, 2, 50);
    try std.testing.expectEqual(@as(u64, 100_000), quota);
}

test "compute_cpu_quota — two cores at 10 percent" {
    // Matches config.json defaults (cpu_cores=2, cpu_limit_percent=10).
    const quota = compute_cpu_quota(100_000, 2, 10);
    try std.testing.expectEqual(@as(u64, 20_000), quota);
}

test "compute_cpu_quota — four cores full usage" {
    const quota = compute_cpu_quota(100_000, 4, 100);
    try std.testing.expectEqual(@as(u64, 400_000), quota);
}
