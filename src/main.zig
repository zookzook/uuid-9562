const std = @import("std");
const UUID = @import("uuid");

pub fn main() !void {
    const uuidv1 = UUID.uuid1();
    std.debug.print("UUIDv1 = {f}\n", .{uuidv1});

    const uuidv3 = UUID.uuid3("This is my string.", "7525E1FC-5512-48CE-A457-74A2EB92350F");
    std.debug.print("UUIDv3 = {f}\n", .{uuidv3});

    const uuidv3_1 = UUID.uuid3WithNamespace("This is my string", UUID.Namespace.url);
    std.debug.print("UUIDv5 = {f}\n", .{uuidv3_1});

    const uuidv4 = UUID.uuid4();
    std.debug.print("UUIDv4 = {f}\n", .{uuidv4});

    const uuidv5 = UUID.uuid5("This is my string.", "7525E1FC-5512-48CE-A457-74A2EB92350F");
    std.debug.print("UUIDv5 = {f}\n", .{uuidv5});

    const uuidv5_1 = UUID.uuid5WithNamespace("This is my string", UUID.Namespace.url);
    std.debug.print("UUIDv5 = {f}\n", .{uuidv5_1});

    const uuidv6 = UUID.uuid6();
    std.debug.print("UUIDv6 = {f}\n", .{uuidv6});
    std.debug.print("UUIDv6 = {d}\n", .{uuidv6.version()});

}

