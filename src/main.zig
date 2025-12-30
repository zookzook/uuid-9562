const std = @import("std");
const UUID = @import("uuid");

pub fn main() !void {

    const uuid = UUID.uuid4();
    var buf: [36]u8 = undefined;
    const out = uuid.format(.default, &buf);

    std.debug.print("UUID = {s}\n", .{out});
}

