//! Seccomp-BPF syscall filtering for sandboxed processes.
const std = @import("std");
const linux = std.os.linux;
const log = std.log;

const SECCOMP = linux.SECCOMP;

// Classic BPF instruction.
const sock_filter = extern struct {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
};

// Classic BPF program descriptor passed to seccomp(2).
const sock_fprog = extern struct {
    len: u16,
    filter: [*]const sock_filter,
};

// BPF instruction classes and modes.
const BPF_LD = 0x00;
const BPF_JMP = 0x05;
const BPF_RET = 0x06;
const BPF_W = 0x00;
const BPF_ABS = 0x20;
const BPF_JEQ = 0x10;
const BPF_K = 0x00;

fn bpf_stmt(code: u16, k: u32) sock_filter {
    return .{ .code = code, .jt = 0, .jf = 0, .k = k };
}

fn bpf_jump(code: u16, k: u32, jt: u8, jf: u8) sock_filter {
    return .{ .code = code, .jt = jt, .jf = jf, .k = k };
}

// Offsets into seccomp_data for BPF loads.
const OFFSET_NR = 0; // offsetof(seccomp_data, nr)
const OFFSET_ARCH = 4; // offsetof(seccomp_data, arch)

/// Syscalls the sandboxed process is allowed to make. Covers what
/// busybox sh needs for basic interactive use (file ops, process
/// management, memory, signals, terminal I/O).
/// Note: This filter is x86_64-specific (hardcoded syscall numbers and
/// architecture check). Other architectures require different syscall
/// numbers and arch identifiers.
const allowed_syscalls = [_]u32{
    // Process lifecycle.
    @intFromEnum(linux.SYS.execve),
    @intFromEnum(linux.SYS.exit),
    @intFromEnum(linux.SYS.exit_group),
    @intFromEnum(linux.SYS.fork),
    @intFromEnum(linux.SYS.clone),
    @intFromEnum(linux.SYS.clone3),
    @intFromEnum(linux.SYS.vfork),
    @intFromEnum(linux.SYS.wait4),
    @intFromEnum(linux.SYS.getpid),
    @intFromEnum(linux.SYS.getppid),
    @intFromEnum(linux.SYS.getuid),
    @intFromEnum(linux.SYS.getgid),
    @intFromEnum(linux.SYS.geteuid),
    @intFromEnum(linux.SYS.getegid),
    @intFromEnum(linux.SYS.getpgrp),
    @intFromEnum(linux.SYS.getpgid),
    @intFromEnum(linux.SYS.setpgid),
    @intFromEnum(linux.SYS.setsid),
    @intFromEnum(linux.SYS.gettid),
    @intFromEnum(linux.SYS.set_tid_address),
    @intFromEnum(linux.SYS.getrlimit),
    @intFromEnum(linux.SYS.setrlimit),

    // File I/O.
    @intFromEnum(linux.SYS.open),
    @intFromEnum(linux.SYS.openat),
    @intFromEnum(linux.SYS.read),
    @intFromEnum(linux.SYS.pread64),
    @intFromEnum(linux.SYS.write),
    @intFromEnum(linux.SYS.close),
    @intFromEnum(linux.SYS.lseek),
    @intFromEnum(linux.SYS.dup),
    @intFromEnum(linux.SYS.dup2),
    @intFromEnum(linux.SYS.dup3),
    @intFromEnum(linux.SYS.pipe2),
    @intFromEnum(linux.SYS.fcntl),
    @intFromEnum(linux.SYS.stat),
    @intFromEnum(linux.SYS.fstat),
    @intFromEnum(linux.SYS.lstat),
    @intFromEnum(linux.SYS.fstatat64),
    @intFromEnum(linux.SYS.statx),
    @intFromEnum(linux.SYS.access),
    @intFromEnum(linux.SYS.faccessat),
    @intFromEnum(linux.SYS.faccessat2),
    @intFromEnum(linux.SYS.readlinkat),
    @intFromEnum(linux.SYS.getdents),
    @intFromEnum(linux.SYS.getdents64),
    @intFromEnum(linux.SYS.getcwd),
    @intFromEnum(linux.SYS.chdir),
    @intFromEnum(linux.SYS.fchdir),
    @intFromEnum(linux.SYS.unlinkat),
    @intFromEnum(linux.SYS.mkdirat),
    @intFromEnum(linux.SYS.renameat2),
    @intFromEnum(linux.SYS.umask),

    // Memory management.
    @intFromEnum(linux.SYS.brk),
    @intFromEnum(linux.SYS.mmap),
    @intFromEnum(linux.SYS.munmap),
    @intFromEnum(linux.SYS.mprotect),
    @intFromEnum(linux.SYS.mremap),
    @intFromEnum(linux.SYS.madvise),

    // Signals.
    @intFromEnum(linux.SYS.rt_sigaction),
    @intFromEnum(linux.SYS.rt_sigprocmask),
    @intFromEnum(linux.SYS.rt_sigreturn),
    @intFromEnum(linux.SYS.sigaltstack),
    @intFromEnum(linux.SYS.kill),
    @intFromEnum(linux.SYS.tgkill),

    // Terminal / misc I/O.
    @intFromEnum(linux.SYS.ioctl),
    @intFromEnum(linux.SYS.writev),
    @intFromEnum(linux.SYS.readv),
    @intFromEnum(linux.SYS.ppoll),
    @intFromEnum(linux.SYS.pselect6),
    @intFromEnum(linux.SYS.poll),
    @intFromEnum(linux.SYS.select),

    // Time and system info.
    @intFromEnum(linux.SYS.clock_gettime),
    @intFromEnum(linux.SYS.nanosleep),
    @intFromEnum(linux.SYS.uname),
    @intFromEnum(linux.SYS.getrandom),
    @intFromEnum(linux.SYS.prlimit64),
    @intFromEnum(linux.SYS.prctl),
    @intFromEnum(linux.SYS.sysinfo),

    // Threading / futex.
    @intFromEnum(linux.SYS.futex),
    @intFromEnum(linux.SYS.set_robust_list),
    @intFromEnum(linux.SYS.rseq),

    // Arch-specific.
    @intFromEnum(linux.SYS.arch_prctl),
};

/// Build the BPF filter program at comptime. The structure is:
///   1. Load arch, reject if not x86_64.
///   2. Load syscall nr.
///   3. For each allowed syscall, jump to ALLOW if equal.
///   4. Default: KILL_PROCESS.
///   5. ALLOW label.
const filter = build_filter();

fn build_filter() [allowed_syscalls.len + 5]sock_filter {
    // 3 (load arch + check arch + load nr) + N (jumps) + 1 (kill) + 1 (allow).
    const n = allowed_syscalls.len;
    var prog: [n + 5]sock_filter = undefined;

    // [0] Load architecture.
    prog[0] = bpf_stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_ARCH);
    // [1] If arch != x86_64, jump to kill (skip n+1 instructions).
    // AUDIT_ARCH_X86_64 = 64BIT | LE | EM_X86_64 = 0xC000003E.
    prog[1] = bpf_jump(
        BPF_JMP | BPF_JEQ | BPF_K,
        0xC000003E,
        0, // jt: continue to [2]
        @intCast(n + 1), // jf: jump to kill
    );
    // [2] Load syscall number.
    prog[2] = bpf_stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_NR);

    // [3..3+n-1] One conditional jump per allowed syscall.
    for (0..n) |i| {
        // Distance to the ALLOW instruction from this instruction.
        const dist_to_allow: u8 = @intCast(n - i);
        prog[3 + i] = bpf_jump(
            BPF_JMP | BPF_JEQ | BPF_K,
            allowed_syscalls[i],
            dist_to_allow, // jt: jump to allow
            0, // jf: continue checking
        );
    }

    // [3+n] Default: kill the process on disallowed syscalls.
    prog[3 + n] = bpf_stmt(BPF_RET | BPF_K, SECCOMP.RET.KILL_PROCESS);
    // [3+n+1] Allow.
    prog[3 + n + 1] = bpf_stmt(BPF_RET | BPF_K, SECCOMP.RET.ALLOW);

    return prog;
}

pub const SeccompError = error{
    SetNoNewPrivsFailed,
    SeccompLoadFailed,
};

/// Install the seccomp filter. Must be called after all privileged
/// setup (mounts, chroot, loopback) but before execve.
pub fn install() SeccompError!void {
    const PR_SET_NO_NEW_PRIVS = 38;

    // seccomp requires NO_NEW_PRIVS to be set first.
    const nnp_rc: isize = @bitCast(linux.prctl(
        PR_SET_NO_NEW_PRIVS,
        1,
        0,
        0,
        0,
    ));
    if (nnp_rc != 0) return error.SetNoNewPrivsFailed;

    const prog = sock_fprog{
        .len = filter.len,
        .filter = &filter,
    };

    const rc: isize = @bitCast(linux.syscall3(
        .seccomp,
        SECCOMP.SET_MODE_FILTER,
        0,
        @intFromPtr(&prog),
    ));
    if (rc < 0) return error.SeccompLoadFailed;

    log.info("seccomp filter installed ({d} syscalls allowed)", .{allowed_syscalls.len});
}

test "filter is built at comptime" {
    // Verify the filter has the expected length.
    const expected_len = allowed_syscalls.len + 5;
    try std.testing.expectEqual(expected_len, filter.len);

    // First instruction loads arch.
    try std.testing.expectEqual(BPF_LD | BPF_W | BPF_ABS, filter[0].code);
    try std.testing.expectEqual(OFFSET_ARCH, filter[0].k);

    // Second checks x86_64 (AUDIT_ARCH_X86_64 = 0xC000003E).
    try std.testing.expectEqual(@as(u32, 0xC000003E), filter[1].k);

    // Last instruction is ALLOW.
    try std.testing.expectEqual(SECCOMP.RET.ALLOW, filter[filter.len - 1].k);

    // Second-to-last is KILL_PROCESS.
    try std.testing.expectEqual(SECCOMP.RET.KILL_PROCESS, filter[filter.len - 2].k);
}

test "allowed_syscalls contains essentials" {
    const essentials = [_]u32{
        @intFromEnum(linux.SYS.read),
        @intFromEnum(linux.SYS.write),
        @intFromEnum(linux.SYS.execve),
        @intFromEnum(linux.SYS.exit_group),
        @intFromEnum(linux.SYS.brk),
        @intFromEnum(linux.SYS.openat),
    };
    for (essentials) |nr| {
        var found = false;
        for (allowed_syscalls) |a| {
            if (a == nr) {
                found = true;
                break;
            }
        }
        try std.testing.expect(found);
    }
}
