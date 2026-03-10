# zigbox

> work in progress 

Minimal Linux namespace sandbox written in Zig.
Allows the execution of a program in an isolated process with a minimal filesystem and users own namespace.

# Build

```bash
zig build
```

# Running

Requires root privileges to create user/network/UTS namespaces:

```bash
sudo setcap cap_sys_admin+ep ./zig-out/bin/zbox
./zig-out/bin/zbox
```

Or run with sudo:

```bash
sudo ./zig-out/bin/zbox
```

# Privileges

Zbox uses Linux namespaces which require `CAP_SYS_ADMIN`. To grant without running as root:

```bash
# Build first
zig build

# Grant capabilities
sudo setcap cap_sys_admin+ep ./zig-out/bin/zbox

# Run as regular user
./zig-out/bin/zbox
```

# Additions

Could be cool to add syscall filtering, OCI compat so it could run images, network isolation which would be the core of a runtime. 
