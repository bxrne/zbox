const std = @import("std");
const x = std.os.linux;

const flags = undefined;

// parent runs:

pub fn createNs() !void {
    // TODO: create namespaces with flags
}

pub fn mapNs() !void {
    // TODO: map user namespaces with flags
}

// child runs:

pub fn mountNs() !void {
    // TODO: map user namespaces with flags
}

pub fn rootFs() !void {
    // TODO: do pivot
}

pub fn mountFs() !void {
    // TODO: mount essential filesystems
}

pub fn initPIDNs() !void {
    // TODO: create proc in ns to handle signals and reap zombies, at pid 1
}
