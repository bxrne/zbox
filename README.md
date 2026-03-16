# zbox

[![CI](https://github.com/bxrne/zbox/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/bxrne/zbox/actions/workflows/ci.yml) [![Release](https://github.com/bxrne/zbox/actions/workflows/release.yml/badge.svg?branch=master)](https://github.com/bxrne/zbox/actions/workflows/release.yml)


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

### Network Features (Optional)

For `network_access` and `port_forwards`:
- `ip` command (from iproute2 package)
- `iptables`
- Root or `CAP_NET_ADMIN` capability

## Security

### Syscall Filtering

zbox uses **seccomp-BPF with a deny list approach** (similar to Docker's default profile):

- **Default action**: Allow all syscalls
- **Blocked syscalls**: 54 dangerous syscalls are explicitly blocked
- **Blocked categories**:
  - Kernel module loading (`init_module`, `finit_module`, `delete_module`)
  - Kernel execution (`kexec_load`, `kexec_file_load`)
  - Hardware access (`ioperm`, `iopl`, `syslog`)
  - Memory manipulation (`mbind`, `set_mempolicy`, etc.)
  - Network operations (blocked since network namespace is isolated)
  - Device access (`mknod`, `mknodat`)
  - Privilege escalation (`setuid`, `setgid`, etc.)
  - System control (`reboot`, `swapon`, `swapoff`)
  - Debugging (`ptrace`, `process_vm_readv`, etc.)

### Security Features

- **Architecture check**: Only x86_64 syscalls are processed
- **NO_NEW_PRIVS**: Required before seccomp filter installation
- **Namespace isolation**: User, mount, PID, UTS, and network namespaces
- **Filesystem isolation**: chroot into container root

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

## Options

- `-c, --cfg <path>` — Path to JSON config file (default: config.json)
- `-h, --help` — Show help
- `--` — Forward remaining arguments to the sandboxed binary

## Configuration

Configure via JSON file passed with `-c/--cfg`:

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Sandbox identifier (used for cgroup name) |
| `binary` | string | Absolute path to executable inside sandbox |
| `root` | string | Absolute path to sandbox root directory |
| `cpu_cores` | u32 | Number of CPU cores to allow |
| `cpu_limit_percent` | u32 | CPU limit as percentage (1-100) |
| `memory_limit_mb` | u32 | Memory limit in megabytes |
| `network_access` | bool | Enable internet access from sandbox (default: false) |
| `port_forwards` | array | Port mappings for accessing services inside sandbox |

### Port Forwards

| Field | Type | Description |
|-------|------|-------------|
| `host` | u16 | Port on host to listen on |
| `sandbox` | u16 | Port inside sandbox to forward to |

Example:

```json
{
  "name": "zbox-sandbox",
  "root": "/tmp/zbox_root",
  "binary": "/bin/busybox",
  "cpu_cores": 2,
  "cpu_limit_percent": 10,
  "memory_limit_mb": 3,
  "network_access": true,
  "port_forwards": [
    { "host": 8080, "sandbox": 80 },
    { "host": 2222, "sandbox": 22 }
  ]
}
```

### Network Access

When `network_access: true` is set:
- A veth pair is created connecting the sandbox to the host
- Sandbox gets IP `10.0.2.2/24`
- Host gets IP `10.0.2.1/24`
- NAT/masquerading is enabled allowing the sandbox to access the internet
- Port forwards allow services inside the sandbox to be accessed from the host

**Requirements for network features:**
- `ip` command (iproute2 package)
- `iptables` 
- Root or `CAP_NET_ADMIN` capability for network operations

## Resource Limits (cgroups)

zbox uses Linux cgroups v2 for CPU and memory limits. **This requires sudo** because cgroup files in `/sys/fs/cgroup/` are root-only:

```bash
sudo ./zig-out/bin/zbox -c config.json
```

### Rootless Mode

Without sudo, the sandbox runs but **resource limits are not applied**. The kernel does not allow unprivileged users to create or manage cgroups. This is a fundamental Linux limitation - all container tools (Docker, Podman, etc.) require root for resource limits.

The sandbox still provides full isolation via namespaces (user, mount, PID, UTS, network), but CPU/memory constraints require privileged access.

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
- [x] Syscall filtering (seccomp-BPF deny list)
- [x] Resource limits (CPU, Memory via cgroups, requires sudo)
- [x] Network access (NAT/masquerading)
- [x] Port forwarding (veth + iptables)
- [ ] pivot_root (more secure than chroot)
- [ ] OCI compatibility (run container images)
