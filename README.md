# zbox

Minimal rootless Linux sandbox written in [Zig](https://ziglang.org/).

Use cases: build environments, agentic AI sessions, foundation for container runtimes.

Each run creates a fresh, isolated filesystem with its own user/mount/UTS namespaces - no sudo required.

# Why Zig?

- **Direct syscall access** - Zig calls Linux syscalls directly without a libc, making it easy to use `clone`, `mount`, `chroot`, `pivot_root` without overhead
- **No runtime** - No garbage collector, no VM, no runtime. Produces a tiny static binary - perfect for a minimal sandbox
- **Cross-compilation** - Built-in support for targeting different architectures

# Requirements

- Linux kernel with namespace support
- [busybox](https://busybox.net/) (statically linked) installed

## What is busybox?

[BusyBox](https://busybox.net/) combines tiny versions of many common UNIX utilities (sh, ls, cat, echo, etc.) into a single executable. It's commonly used in embedded systems and containers because it's:

- **Small** - ~1MB static binary
- **Self-contained** - No external library dependencies
- **Fast** - Minimal overhead

## Alternatives to busybox

If you don't want to use busybox, you can configure zbox to use other statically-linked binaries:

- [toybox](https://landley.net/toybox/) - Another minimal tool suite (used by Android)
- [sbase](http://git.suckless.org/sbase/) - Simple tools from the suckless community
- Static builds of coreutils - Some distributions offer static builds

# Build

```bash
zig build
```

# Running

```bash
./zig-out/bin/zbox
```

Options:
- `-b, --binary <path>` - Binary to execute (default: /bin/busybox)
- `-r, --root <path>` - Container root directory
- `-h, --help` - Show help

# Roadmap

- [x] User namespace with UID/GID mapping (rootless)
- [x] Mount namespace
- [x] UTS namespace isolation
- [x] Filesystem isolation (chroot)
- [x] Bind mounts (/proc, /dev, /tmp)
- [x] Execute target binary
- [x] Copy busybox into container
- [x] Fresh filesystem per run
- [x] Interactive shell (stdin/stdout)
- [ ] Network namespace isolation
- [ ] Syscall filtering (seccomp)
- [ ] pivot_root (more secure than chroot)
- [ ] OCI compatibility (run container images)
