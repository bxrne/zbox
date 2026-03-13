# zbox

Minimal rootless Linux sandbox written in [Zig](https://ziglang.org/).

Use cases: build environments, agentic AI sessions, foundation for container runtimes.

Each run creates a fresh, isolated filesystem with its own user/mount/PID/UTS/network namespaces — no sudo required.

## Why Zig?

- **Direct syscall access** — calls Linux syscalls directly without libc, making `clone`, `mount`, `chroot` straightforward
- **No runtime** — no GC, no VM. Produces a tiny static binary ideal for a minimal sandbox
- **Cross-compilation** — built-in support for targeting different architectures

## Requirements

- **x86_64 architecture** — seccomp filter is hardcoded for x86_64 syscall numbers
- **Linux kernel with namespace support** (kernel 5.11+ recommended)
- **Rootless namespaces** — user namespaces must be enabled (check with `sysctl kernel.unprivileged_userns_clone`)
- A statically-linked shell binary (e.g. [busybox](https://busybox.net/)) for testing

### busybox

[BusyBox](https://busybox.net/) combines tiny versions of common UNIX utilities (sh, ls, cat, echo, etc.) into a single ~1 MB static binary.  zbox uses it as the default binary executed inside the sandbox for interactive testing.

### Alternatives

- [toybox](https://landley.net/toybox/) — minimal tool suite (used by Android)
- [sbase](http://git.suckless.org/sbase/) — suckless community tools
- Static builds of coreutils

## Build

```bash
zig build
```

## Test

```bash
zig build test
```

## Running

```bash
./zig-out/bin/zbox
```

Options:
- `-b, --binary <path>` — binary to execute inside the sandbox (default: `/bin/busybox`)
- `-r, --root <path>` — container root directory (default: auto-generated under `/tmp`)
- `-h, --help` — show help
- `--` — forward remaining arguments to the sandboxed binary

## Roadmap

- [x] User namespace with UID/GID mapping (rootless)
- [x] Mount namespace
- [x] UTS namespace isolation
- [x] Filesystem isolation (chroot)
- [x] PID namespace isolation
- [x] Mounts (proc, tmpfs for /dev and /tmp)
- [x] Execute target binary
- [x] Copy configured binary into container
- [x] Fresh filesystem per run
- [x] Interactive shell (stdin/stdout)
- [x] Network namespace isolation
- [x] Syscall filtering (seccomp-BPF whitelist)
- [ ] pivot_root (more secure than chroot)
- [ ] OCI compatibility (run container images)
