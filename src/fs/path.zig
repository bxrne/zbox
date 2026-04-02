//! Path manipulation utilities.

const std = @import("std");

/// Join `root` and a comptime-known `suffix` into a sentinel-terminated
/// path using the caller's buffer. No heap allocation.
pub fn join_path(
    buf: *[4096]u8,
    root: []const u8,
    comptime suffix: []const u8,
) [:0]const u8 {
    std.debug.assert(root.len > 0 and root[0] == '/');
    return std.fmt.bufPrintZ(buf, "{s}{s}", .{ root, suffix }) catch
        unreachable;
}

/// Extract the filename after the last `/` in an absolute path.
pub fn extract_basename(path: [:0]const u8) []const u8 {
    std.debug.assert(path.len > 0 and path[0] == '/');
    if (std.mem.lastIndexOfScalar(u8, path, '/')) |idx| {
        return path[idx + 1 ..];
    }
    return path;
}

test "extract_basename simple" {
    try std.testing.expectEqualStrings("busybox", extract_basename("/bin/busybox"));
}

test "extract_basename nested" {
    try std.testing.expectEqualStrings("sh", extract_basename("/usr/bin/sh"));
}

test "join_path appends suffix" {
    var buf: [4096]u8 = undefined;
    const result = join_path(&buf, "/tmp/root", "/proc");
    try std.testing.expectEqualStrings("/tmp/root/proc", result);
}

test "join_path empty suffix" {
    var buf: [4096]u8 = undefined;
    const result = join_path(&buf, "/tmp/root", "");
    try std.testing.expectEqualStrings("/tmp/root", result);
}
