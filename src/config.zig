//! JSON configuration file parsing for zbox sandboxes.

const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;

pub const PortForward = struct {
    host: u16,
    sandbox: u16,
};

pub const Config = struct {
    name: [:0]const u8,
    binary: [:0]const u8,
    root: [:0]const u8,
    cpu_cores: u32,
    cpu_limit_percent: u32,
    memory_limit_mb: u32,
    port_forwards: []PortForward,
    network_access: bool,

    /// Free all owned string fields and zero the struct.
    pub fn deinit(self: *Config, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.binary);
        allocator.free(self.root);
        allocator.free(self.port_forwards);
        self.* = undefined;
    }
};

const JsonConfig = struct {
    name: []const u8,
    binary: []const u8,
    root: []const u8,
    cpu_cores: u32,
    cpu_limit_percent: u32,
    memory_limit_mb: u32,
    port_forwards: ?[]const PortForward = null,
    network_access: ?bool = false,
};

/// Load and validate a Config from a JSON file at `path`.
///
/// All fields are required — missing fields cause a parse error.
/// String fields are duped into owned memory via `allocator`.
pub fn load(allocator: std.mem.Allocator, path: []const u8) !Config {
    const fd = try posix.openat(posix.AT.FDCWD, path, .{}, 0);
    defer _ = linux.close(fd);

    var statx_buf: linux.Statx = undefined;
    const stat_rc: isize = @bitCast(linux.statx(fd, "", linux.AT.EMPTY_PATH, linux.STATX{ .SIZE = true }, &statx_buf));
    if (stat_rc < 0) return error.InvalidConfig;
    const file_size: usize = @intCast(statx_buf.size);

    const data = try allocator.alloc(u8, file_size);
    defer allocator.free(data);
    var total_read: usize = 0;
    while (total_read < file_size) {
        const n = posix.read(fd, data[total_read..]) catch return error.InvalidConfig;
        if (n == 0) break;
        total_read += n;
    }

    const parsed = try std.json.parseFromSlice(JsonConfig, allocator, data, .{
        .ignore_unknown_fields = true,
    });
    defer parsed.deinit();
    const cfg = parsed.value;

    // Validate all fields before allocating owned copies.
    if (cfg.name.len == 0) return error.InvalidConfig;
    if (cfg.binary.len == 0 or cfg.binary[0] != '/') return error.InvalidConfig;
    if (cfg.root.len == 0 or cfg.root[0] != '/') return error.InvalidConfig;
    if (cfg.cpu_cores == 0) return error.InvalidConfig;
    if (cfg.cpu_limit_percent == 0 or cfg.cpu_limit_percent > 100) return error.InvalidConfig;
    if (cfg.memory_limit_mb == 0) return error.InvalidConfig;

    const name = try allocator.dupeZ(u8, cfg.name);
    errdefer allocator.free(name);

    const binary = try allocator.dupeZ(u8, cfg.binary);
    errdefer allocator.free(binary);

    const root = try allocator.dupeZ(u8, cfg.root);
    errdefer allocator.free(root);

    var port_forwards: []PortForward = &.{};
    if (cfg.port_forwards) |pf_arr| {
        port_forwards = try allocator.alloc(PortForward, pf_arr.len);
        errdefer allocator.free(port_forwards);
        for (pf_arr, 0..) |pf, i| {
            port_forwards[i] = .{ .host = pf.host, .sandbox = pf.sandbox };
        }
    }

    const network_access = cfg.network_access orelse false;

    return Config{
        .name = name,
        .binary = binary,
        .root = root,
        .cpu_cores = cfg.cpu_cores,
        .cpu_limit_percent = cfg.cpu_limit_percent,
        .memory_limit_mb = cfg.memory_limit_mb,
        .port_forwards = port_forwards,
        .network_access = network_access,
    };
}

fn writeTestFile(path: [*:0]const u8, content: []const u8) !void {
    const rc: isize = @bitCast(linux.open(path, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644));
    if (rc < 0) return error.TestFileCreateFailed;
    const fd: i32 = @intCast(rc);
    defer _ = linux.close(fd);
    var written: usize = 0;
    while (written < content.len) {
        const w = linux.write(fd, content[written..].ptr, content.len - written);
        const w_signed: isize = @bitCast(w);
        if (w_signed < 0) return error.TestFileCreateFailed;
        written += @intCast(w_signed);
    }
}

fn deleteTestFile(path: [*:0]const u8) void {
    _ = linux.unlink(path);
}

test "load — valid config file" {
    const allocator = std.testing.allocator;

    const json =
        \\{
        \\  "name": "test-sandbox",
        \\  "root": "/tmp/zbox_root",
        \\  "binary": "/bin/busybox",
        \\  "cpu_cores": 2,
        \\  "cpu_limit_percent": 10,
        \\  "memory_limit_mb": 3,
        \\  "port_forwards": [{"host": 8080, "sandbox": 80}],
        \\  "network_access": true
        \\}
    ;

    const tmp_path = "zig-test-config.json";
    try writeTestFile(tmp_path, json);
    defer deleteTestFile(tmp_path);

    var cfg = try load(allocator, tmp_path);
    defer cfg.deinit(allocator);

    try std.testing.expectEqualStrings("test-sandbox", cfg.name);
    try std.testing.expectEqualStrings("/bin/busybox", cfg.binary);
    try std.testing.expectEqualStrings("/tmp/zbox_root", cfg.root);
    try std.testing.expectEqual(@as(u32, 2), cfg.cpu_cores);
    try std.testing.expectEqual(@as(u32, 10), cfg.cpu_limit_percent);
    try std.testing.expectEqual(@as(u32, 3), cfg.memory_limit_mb);
    try std.testing.expectEqual(@as(usize, 1), cfg.port_forwards.len);
    try std.testing.expectEqual(@as(u16, 8080), cfg.port_forwards[0].host);
    try std.testing.expectEqual(@as(u16, 80), cfg.port_forwards[0].sandbox);
    try std.testing.expectEqual(true, cfg.network_access);
}

test "Config.deinit frees owned strings" {
    const allocator = std.testing.allocator;

    var cfg = Config{
        .name = try allocator.dupeZ(u8, "my-sandbox"),
        .binary = try allocator.dupeZ(u8, "/bin/sh"),
        .root = try allocator.dupeZ(u8, "/tmp/root"),
        .cpu_cores = 1,
        .cpu_limit_percent = 50,
        .memory_limit_mb = 64,
        .port_forwards = &.{},
        .network_access = true,
    };

    cfg.deinit(allocator);
    // std.testing.allocator detects leaks — if deinit missed a free the
    // test runner would report it as a failure.
}

test "load — rejects empty name" {
    const allocator = std.testing.allocator;

    const json =
        \\{
        \\  "name": "",
        \\  "root": "/tmp/root",
        \\  "binary": "/bin/sh",
        \\  "cpu_cores": 1,
        \\  "cpu_limit_percent": 50,
        \\  "memory_limit_mb": 64
        \\}
    ;

    const tmp_path = "zig-test-config-empty-name.json";
    try writeTestFile(tmp_path, json);
    defer deleteTestFile(tmp_path);

    try std.testing.expectError(error.InvalidConfig, load(allocator, tmp_path));
}

test "load — rejects non-absolute binary" {
    const allocator = std.testing.allocator;

    const json =
        \\{
        \\  "name": "sandbox",
        \\  "root": "/tmp/root",
        \\  "binary": "busybox",
        \\  "cpu_cores": 1,
        \\  "cpu_limit_percent": 50,
        \\  "memory_limit_mb": 64
        \\}
    ;

    const tmp_path = "zig-test-config-rel-binary.json";
    try writeTestFile(tmp_path, json);
    defer deleteTestFile(tmp_path);

    try std.testing.expectError(error.InvalidConfig, load(allocator, tmp_path));
}

test "load — rejects zero cpu_limit_percent" {
    const allocator = std.testing.allocator;

    const json =
        \\{
        \\  "name": "sandbox",
        \\  "root": "/tmp/root",
        \\  "binary": "/bin/sh",
        \\  "cpu_cores": 1,
        \\  "cpu_limit_percent": 0,
        \\  "memory_limit_mb": 64
        \\}
    ;

    const tmp_path = "zig-test-config-zero-cpu.json";
    try writeTestFile(tmp_path, json);
    defer deleteTestFile(tmp_path);

    try std.testing.expectError(error.InvalidConfig, load(allocator, tmp_path));
}
