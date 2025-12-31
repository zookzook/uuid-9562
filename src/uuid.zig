//! This is an implementation of UUIDs specified by the RFC 9562 (https://www.rfc-editor.org/rfc/rfc9562)
//! This package was created as an exercise to learn Zig. The Go and Elixir implementations were used as inspiration.
//! In addition, there are other Zig implementations that cover the same range of functionality.
//!
//! Example:
//!
//!  const std = @import("std");
//!  const UUID = @import("uuid");
//!
//!  pub fn main() !void {
//!      const uuidv1 = UUID.uuid1();
//!      std.debug.print("UUIDv1 = {f}\n", .{uuidv1});
//!
//!      const uuidv3 = UUID.uuid3("This is my string.", "7525E1FC-5512-48CE-A457-74A2EB92350F");
//!      std.debug.print("UUIDv3 = {f}\n", .{uuidv3});
//!
//!      const uuidv3_1 = UUID.uuid3WithNamespace("This is my string", UUID.Namespace.url);
//!      std.debug.print("UUIDv5 = {f}\n", .{uuidv3_1});
//!
//!      const uuidv4 = UUID.uuid4();
//!      std.debug.print("UUIDv4 = {f}\n", .{uuidv4});
//!
//!      const uuidv5 = UUID.uuid5("This is my string.", "7525E1FC-5512-48CE-A457-74A2EB92350F");
//!      std.debug.print("UUIDv5 = {f}\n", .{uuidv5});
//!
//!      const uuidv5_1 = UUID.uuid5WithNamespace("This is my string", UUID.Namespace.url);
//!      std.debug.print("UUIDv5 = {f}\n", .{uuidv5_1});
//!
//!      const uuidv6 = UUID.uuid6();
//!      std.debug.print("UUIDv6 = {f}\n", .{uuidv6});
//!
//!      const uuidv7 = UUID.uuid7();
//!      std.debug.print("UUIDv7 = {f}\n", .{uuidv7});
//!
//!      const uuid = try UUID.parse("6ba7b810-9dad-11d1-80b4-00c04fd430c8");
//!      std.debug.print("Parsed UUID = {f}\n", .{uuid});
//!      std.debug.print("Parsed UUID Version = {d}\n", .{uuid.version()});
//!  }
//!
//! This will print:
//!   UUIDv1 = 1E9F683A-E63A-11F0-8001-73ED1F0C96B5
//!   UUIDv3 = 12F9E540-9E0E-3AC3-B4EA-6D3C9B7A7ADE
//!   UUIDv5 = 1914A756-47FF-363A-A60C-3C8A9B183708
//!   UUIDv4 = D70CB936-2774-48BA-A09D-8D6777E61669
//!   UUIDv5 = 5147DB24-1BF1-5EE1-B018-0E5816943EC5
//!   UUIDv5 = 31249043-62E3-55C1-9111-A4FAFF074551
//!   UUIDv6 = 1F0E63A1-E9F7-6BB0-8002-A32D67D04276
//!   UUIDv7 = 019B741F-6A0A-7889-9C11-B76BEC683A23
//!   Parsed UUID = 6BA7B810-9DAD-11D1-80B4-00C04FD430C8
//!   Parsed UUID Version = 1
//!
const std = @import("std");
const Sha1 = std.crypto.hash.Sha1;
const Md5 = std.crypto.hash.Md5;
const random = std.crypto.random;
const assert = std.debug.assert;

// Indices in the UUID string representation for each byte.
const default_encoded_pos = [16]u8{0, 2, 4, 6, 9, 11, 14, 16, 19, 21, 24, 26, 28, 30, 32, 34};
const hex_encoded_pos = [16]u8{0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30};

// Used to format hex values
const hex = "0123456789ABCDEF";

// UUID layouts and versions
const uuid_v1_mask = 0x10;
const uuid_v3_mask = 0x30;
const uuid_v4_mask = 0x40;
const uuid_v5_mask = 0x50;
const uuid_v6_mask = 0x60;
const uuid_v7_mask = 0x70;

/// see https://www.rfc-editor.org/rfc/rfc9562#name-namespace-id-usage-and-allo
pub const Namespace = enum {
    dns,
    nil,
    oid,
    url,
    x500,
};

/// Specifies the format when calling format function
pub const Format = enum {
    /// Canonical UUID string with hyphens,
    /// e.g. "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
    default,

    /// Hexadecimal representation without hyphens,
    /// e.g. "6ba7b8109dad11d180b400c04fd430c8"
    hex,

    /// Compact URL-safe slug (no padding), e.g. "wjKrAJQUEeyzyJ9r3s7YRg"
    slug,
};

// The predefined namespace ids:
const nil_prefix = [16]u8{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
const dns_prefix = [16]u8{0x6b, 0xa7, 0xb8, 0x10, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8};
const url_prefix = [16]u8{0x6b, 0xa7, 0xb8, 0x11, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8};
const oid_prefix = [16]u8{0x6b, 0xa7, 0xb8, 0x12, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8};
const x500_prefix = [16]u8{0x6b, 0xa7, 0xb8, 0x14, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8};

// Used to calculate the timestamp for UUIDv1 and UUIDv6
const lillian : i64 = 2_299_160;       // Julian day of 15 Oct 1582
const unix : i64= 2_440_587;           // Julian day of 1 Jan 1970
const epoch = unix - lillian;          // Days between epochs
const g1582 = epoch * 86_400;          // seconds between epochs
const g1582ns100 = g1582 * 10_000_000; // 100s of a nanoseconds between epochs

const UUID = @This();

/// Contains the UUID as a array of 16 bytes.
raw : [16]u8,

/// Creates a UUID using the raw bytes in `uuid` without any validations.
pub fn init(uuid: [16]u8) UUID {
    return UUID{
        .raw = uuid
    };
}

/// Creates a UUID using the raw u128 without any validations.
pub fn initWithInt(uuid: u128) UUID {
    var buf: [16]u8 = undefined;
    std.mem.writeInt(u128, &buf, uuid, .big);

    return UUID{
        .raw = buf
    };
}

/// Parses a UUID string like "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
pub fn parse(source: []const u8) !UUID {
    if (source.len != 36)
        return error.InvalidLength;

    var buf: [32]u8 = undefined;
    var j: usize = 0;

    // copy all hex chars, skip hyphens
    for (source) |c| {
        if (c == '-') continue;
        if (j >= 32) return error.InvalidFormat;
        buf[j] = c;
        j += 1;
    }

    if (j != 32)
        return error.InvalidFormat;

    var result: UUID = undefined;
    _ = try std.fmt.hexToBytes(&result.raw, buf[0..]);

    return result;
}

/// Formats this UUID in its canonical textual representation and writes it to the writer.
/// The output uses the standard 8-4-4-4-12 hexadecimal layout with uppercase letters,
/// for example: `7525E1FC-5512-48CE-A457-74A2EB92350F`.
///
/// Example:
///   const uuid = UUID.uuid4();
///   std.debug.print("UUID = {f}\n", .{uuid});
///
/// This will print:
///   UUID = 7525E1FC-5512-48CE-A457-74A2EB92350F
pub fn format(self: UUID, w: *std.Io.Writer) !void {
    return try w.print("{X}-{X}-{X}-{X}-{X}", .{
        self.raw[0..4],
        self.raw[4..6],
        self.raw[6..8],
        self.raw[8..10],
        self.raw[10..16],
    });
}

/// Creates a UUIDv1 using the provided node identifier (typically a 48-bit IEEE 802 MAC address).
///
/// The `nodeId` slice must contain 6 bytes. If you do not have a hardware MAC address,
/// you may call `randomNodeId` once and reuse the value for subsequent calls.
///
/// The clock sequence starts at 1 by default and is incremented automatically for each call.
pub fn uuid1WithNodeId(nodeId: []const u8) UUID {

    var result: UUID = undefined;
    const timestamp : u60 = @intCast(@divTrunc(std.time.nanoTimestamp(), 100) + g1582ns100);
    const seq = incSeq();
    result.raw[0] = @truncate(timestamp >> 24);
    result.raw[1] = @truncate(timestamp >> 16);
    result.raw[2] = @truncate(timestamp >> 8);
    result.raw[3] = @truncate(timestamp);
    result.raw[4] = @truncate(timestamp >> 40);
    result.raw[5] = @truncate(timestamp >> 32);
    result.raw[6] = @as(u8, @truncate(timestamp >> 56)) | uuid_v1_mask; // version
    result.raw[7] = @truncate(timestamp >> 48);
    result.raw[8] = 0x80 | @as(u8, @truncate(seq >> 6)); // variant + seq
    result.raw[9] = @truncate(seq);
    @memcpy(result.raw[10..], nodeId);

    return result;
}

/// Creates a UUIDv1 value. The node id is generated for each call.
/// The clock sequence starts at 1 by default and is incremented automatically for each call.
pub fn uuid1() UUID {

    var result: UUID = undefined;
    const timestamp: u60 = @intCast(@divTrunc(std.time.nanoTimestamp(), 100) + g1582ns100);
    const seq = incSeq();
    result.raw[0] = @truncate(timestamp >> 24);
    result.raw[1] = @truncate(timestamp >> 16);
    result.raw[2] = @truncate(timestamp >> 8);
    result.raw[3] = @truncate(timestamp);
    result.raw[4] = @truncate(timestamp >> 40);
    result.raw[5] = @truncate(timestamp >> 32);
    result.raw[6] = @as(u8, @truncate(timestamp >> 56)) | uuid_v1_mask; // version
    result.raw[7] = @truncate(timestamp >> 48);
    result.raw[8] = 0x80 | @as(u8, @truncate(seq >> 6)); // variant + seq
    result.raw[9] = @truncate(seq);

    // After generating the 48-bit fully randomized node value, implementations MUST set the least significant bit of the first octet of the Node ID to 1
    random.bytes(result.raw[10..]);
    result.raw[10] = result.raw[10] | 0x01;

    return result;
}

/// Generates a UUID version 3 (name-based).
/// The UUID is deterministically derived from the given `name` and `namespace`
/// using the MD5 hash algorithm. The same inputs will always produce the same UUID.
/// Both `name` and `namespace` are expected to be byte slices (e.g. UTF-8 strings or
/// the raw bytes of another UUID).
pub fn uuid3(name: []const u8, namespace: []const u8) UUID {
    return namebasedMd5UUID(namespace, name);
}

/// Generates a UUID version 3 (name-based) using one of the predefined namespaces.
/// The resulting UUID is deterministically derived from the given `name` and
/// `namespace` using the MD5 hash algorithm: identical inputs always produce the
/// same UUID value.
/// The `Namespace` enum corresponds to the well-known namespaces defined in RFC 9562
/// (e.g. DNS, URL, OID, X.500, and NIL).
pub fn uuid3WithNamespace(name: []const u8, namespace: Namespace) UUID {
    switch(namespace) {
        .dns => return namebasedMd5UUID(&dns_prefix, name),
        .url => return namebasedMd5UUID(&url_prefix, name),
        .oid => return namebasedMd5UUID(&oid_prefix, name),
        .x500 => return namebasedMd5UUID(&x500_prefix, name),
        .nil => return namebasedMd5UUID(&nil_prefix, name),
    }
}

/// Generates a UUID version 4 (random-based).
/// The UUID is constructed from cryptographically secure pseudo-random bytes
/// produced by the `crypto` package.
pub fn uuid4() UUID {
    var random_bytes: [16]u8 = undefined;
    random.bytes(&random_bytes);
    random_bytes[6] = (random_bytes[6] & 0x0f) | uuid_v4_mask;
    random_bytes[8] = (random_bytes[8] & 0x3f) | 0x80;
    return UUID {
        .raw = random_bytes,
    };
}

/// Generates a UUID version 5 (name-based).
/// The UUID is deterministically derived from the given `name` and `namespace`
/// using the SHA-1 hash algorithm. The same inputs will always produce the same UUID.
/// Both `name` and `namespace` are expected to be byte slices (e.g. UTF-8 strings or
/// the raw bytes of another UUID).
pub fn uuid5(name: []const u8, namespace: []const u8) UUID {
    return namebasedSha1UUID(namespace, name);
}

/// Generates a UUID version 5 (name-based) using one of the predefined namespaces.
/// The resulting UUID is deterministically derived from the given `name` and
/// `namespace` using the SHA-1 hash algorithm: identical inputs always produce the
/// same UUID value.
/// The `Namespace` enum corresponds to the well-known namespaces defined in RFC 9562
/// (e.g. DNS, URL, OID, X.500, and NIL).
pub fn uuid5WithNamespace(name: []const u8, namespace: Namespace) UUID {
    switch(namespace) {
        .dns => return namebasedSha1UUID(&dns_prefix, name),
        .url => return namebasedSha1UUID(&url_prefix, name),
        .oid => return namebasedSha1UUID(&oid_prefix, name),
        .x500 => return namebasedSha1UUID(&x500_prefix, name),
        .nil => return namebasedSha1UUID(&nil_prefix, name),
    }
}

///
/// Generates a UUID version 6 which is a field-compatible variant of UUIDv1, with the timestamp fields
/// rearranged to improve chronological ordering in databases and indexes.
///
/// Example:
///   const id = UUID.uuid6();
pub fn uuid6() UUID {
    var result: UUID = undefined;
    const timestamp: u60 = @intCast(@divTrunc(std.time.nanoTimestamp(), 100) + g1582ns100);
    const seq = incSeq();

    result.raw[0] = @truncate(timestamp >> 52);
    result.raw[1] = @truncate(timestamp >> 44);
    result.raw[2] = @truncate(timestamp >> 36);
    result.raw[3] = @truncate(timestamp >> 28);
    result.raw[4] = @truncate(timestamp >> 20);
    result.raw[5] = @truncate(timestamp >> 12);
    result.raw[6] = @as(u8, @truncate(timestamp >> 4)) & 0x0f | uuid_v6_mask; // version
    result.raw[7] = @truncate(timestamp);
    result.raw[8] = 0x80 | @as(u8, @truncate(seq >> 6)); // variant + seq
    result.raw[9] = @truncate(seq);

    // After generating the 48-bit fully randomized node value, implementations MUST set the least significant bit of the first octet of the Node ID to 1
    random.bytes(result.raw[10..]);
    result.raw[10] = result.raw[10] | 0x01;

    return result;

}

/// Generates a UUID version 6 (time-ordered) using the specified node identifier.
///
/// The `nodeId` should be a 6-byte slice (typically an IEEE 802 MAC address).
/// If a hardware MAC address is unavailable, you can generate a random node ID
/// once using `randomNodeId()` and reuse it for subsequent UUIDs.
///
/// The clock sequence starts at 1 by default and is automatically incremented
/// with each call to ensure uniqueness.
///
/// Example:
///   var nodeId: [6]u8 = undefined;
///   UUID.randomNodeId(&nodeId);
///   const id = UUID.uuid6WithNodeId(&nodeId);
pub fn uuid6WithNodeId(nodeId: []const u8) UUID {

    var result: UUID = undefined;
    const timestamp: u60 = @intCast(@divTrunc(std.time.nanoTimestamp(), 100) + g1582ns100);
    const seq = incSeq();

    result.raw[0] = @truncate(timestamp >> 52);
    result.raw[1] = @truncate(timestamp >> 44);
    result.raw[2] = @truncate(timestamp >> 36);
    result.raw[3] = @truncate(timestamp >> 28);
    result.raw[4] = @truncate(timestamp >> 20);
    result.raw[5] = @truncate(timestamp >> 12);
    result.raw[6] = @as(u8, @truncate(timestamp >> 4)) & 0x0f | uuid_v6_mask; // version
    result.raw[7] = @truncate(timestamp);
    result.raw[8] = 0x80 | @as(u8, @truncate(seq >> 6)); // variant + seq
    result.raw[9] = @truncate(seq);

    @memcpy(result.raw[10..], nodeId);

    return result;
}

/// Generates a UUID version 7 (time-ordered).
///
/// UUIDv7 encodes the current Unix timestamp with sub-millisecond precision
/// (12-bit fraction) and fills the remaining bits with cryptographically
/// random data. This ensures that UUIDs are roughly sortable by creation time
/// while remaining globally unique.
///
/// Example:
///   const uuid = UUID.uuid7();
///   std.debug.print("UUID = {f}\n", .{uuid});
///
/// This may produce output like:
///   UUID = 019B6FA8-F9E0-700D-8146-BF68584E0EE0
pub fn uuid7() UUID {
    var result: UUID = undefined;
    const timestamp: u60 = nextTimestamp();
    result.raw[0] = @truncate(timestamp >> 52);
    result.raw[1] = @truncate(timestamp >> 44);
    result.raw[2] = @truncate(timestamp >> 36);
    result.raw[3] = @truncate(timestamp >> 28);
    result.raw[4] = @truncate(timestamp >> 20);
    result.raw[5] = @truncate(timestamp >> 12);
    result.raw[6] = @as(u8, @truncate((timestamp >> 4) & 0x0F)) | uuid_v7_mask; // version
    result.raw[7] = @truncate(timestamp);
    random.bytes(result.raw[8..]);
    result.raw[8] = (result.raw[8] & 0x3F) | 0x80; // variant
    return result;
}

// Calculates the next unique timestamp for UUIDv7 generation.
//
// Returns a 60-bit value combining the current time in milliseconds and
// a sequence number (nanoseconds / 256). Specifically:
// `(millis << 12) + seq`
//
// The result is guaranteed to be strictly greater than any value returned
// by previous calls, ensuring monotonically increasing timestamps.
fn nextTimestamp() u60 {
    const LastTimestamp = struct {
        var value : u60 = 0;
    };

    const nanos = std.time.nanoTimestamp();
    const millis = @divTrunc(nanos, 1_000_000);
    // Sequence number is between 0 and 3906 (1_000_000 >> 8)
    const seq = (nanos - millis * 1_000_000) >> 8;
    var timestamp: u60 = @intCast((millis << 12) + seq);

    if(timestamp <= LastTimestamp.value) {
        timestamp = LastTimestamp.value + 1;
    }

    while(true) {
        if(@cmpxchgStrong(u60, &LastTimestamp.value, LastTimestamp.value, timestamp, .monotonic, .monotonic) == null) {
            return timestamp;
        }
        timestamp = LastTimestamp.value + 1;
    }
}

/// Compares two UUIDs lexicographically based on their raw byte arrays.
///
/// This is particularly useful for UUIDv6 or UUIDv7, where the byte order
/// preserves chronological ordering. The function returns a value of type
/// `std.math.Order` indicating whether `lhs` is less than, equal to, or greater
/// than `rhs`.
///
/// Example:
///   const uuid_1 = UUID.uuid6();
///   const uuid_2 = UUID.uuid6();
///
///   try std.testing.expect(uuid_1.order(uuid_2) == .lt);
pub fn order(lhs: *const UUID, rhs: UUID) std.math.Order {
    assert(lhs.version() == 7 or lhs.version() == 6);
    return std.mem.order(u8, lhs.raw[0..8], rhs.raw[0..8]);
}

/// Generates a random node identifier (typically 6 bytes) for use in UUID v1
/// generation when a real MAC address is not available.
///
/// The generated node ID is suitable for use as the `nodeId` parameter in
/// `uuid1WithNodeId()`.
///
/// Example:
///   var nodeId: [6]u8 = undefined;
///   UUID.randomNodeId(&nodeId);
pub fn randomNodeId(out: []u8) void {
    random.bytes(out[0..]);
    out[0] = out[0] | 0x01;
}

/// Returns the UUID as a 128-bit unsigned integer (`u128`).
/// The bytes of the UUID are interpreted in big-endian order,
/// allowing numerical comparisons or storage as a single integer value.
///
/// Example:
///   const uuid = UUID.uuid4();
///   const intValue: u128 = uuid.toInt();
pub fn toInt(self: *const UUID) u128 {
    return std.mem.readInt(u128, self.raw[0..], .big);
}

/// Returns the UUID version field (4-bit), indicating the variant-specific
/// generation algorithm (e.g. 1 = time-based, 3 = name-based MD5, 4 = random,
/// 5 = name-based SHA-1, 7 = Unix-time, etc.).
pub fn version(self: *const UUID) u4 {
    return @truncate(self.raw[6] >> 4);
}

/// Returns true if this UUID uses version 1, i.e. the time-based UUID
/// variant defined in RFC 4122.
pub fn isVersion1(self: *const UUID) bool {
    return self.version() == 1;
}

/// Returns true if this UUID is version 3, the name-based UUID
/// generated using an MD5 hash as defined in RFC 4122.
pub fn isVersion3(self: *const UUID) bool {
    return self.version() == 3;
}

/// Returns true if this UUID is version 4, the randomly generated
/// UUID variant defined in RFC 4122.
pub fn isVersion4(self: *const UUID) bool {
    return self.version() == 4;
}

/// Returns true if this UUID is version 5, the name-based UUID
/// generated using a SHA-1 hash as defined in RFC 4122.
pub fn isVersion5(self: *const UUID) bool {
    return self.version() == 5;
}

/// Returns true if this UUID is version 6, a time-ordered UUID
/// based on reordered UUIDv1 fields.
pub fn isVersion6(self: *const UUID) bool {
    return self.version() == 6;
}

/// Returns true if this UUID is version 7, the Unix time-ordered UUID
/// defined in the newer UUID format drafts (time-ordered, Unix epoch).
pub fn isVersion7(self: *const UUID) bool {
    return self.version() == 7;
}

/// Formats this UUID into the provided output buffer using the given format
/// and returns a slice of the written bytes.
///
/// Supported formats:
/// - `default` – canonical UUID string with hyphens
/// - `hex` – compact hexadecimal string without hyphens
/// - `slug` – URL-safe slug (generated via `url_safe_no_pad`)
pub fn formatUUID(self: *const UUID, f: Format, out: []u8) []const u8  {
    switch(f) {
        .default => return formatDefault(self, out),
        .hex => return formatHex(self, out),
        .slug => return formatSlug(self, out),
    }
}

fn namebasedMd5UUID(prefix: []const u8, data: []const u8) UUID {
    var hasher = Md5.init(.{});
    hasher.update(prefix);
    hasher.update(data);
    var hash_buffer: [16]u8 = undefined;
    hasher.final(&hash_buffer);
    hash_buffer[6] = (hash_buffer[6] & 0x0f) | uuid_v3_mask; // version
    hash_buffer[8] = (hash_buffer[8] & 0x3f) | 0x80; // variant

    return UUID {
        .raw = hash_buffer,
    };
}

fn namebasedSha1UUID(prefix: []const u8, data: []const u8) UUID {
    var hasher = Sha1.init(.{});
    hasher.update(prefix);
    hasher.update(data);
    var hash_buffer: [20]u8 = undefined;
    hasher.final(&hash_buffer);
    hash_buffer[6] = (hash_buffer[6] & 0x0f) | uuid_v5_mask; // version
    hash_buffer[8] = (hash_buffer[8] & 0x3f) | 0x80; // variant

    return UUID {
        .raw = hash_buffer[0..16].*,
    };
}

// Default formating, "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
fn formatDefault(self: *const UUID, out: []u8) []const u8 {
    out[8] = '-';
    out[13] = '-';
    out[18] = '-';
    out[23] = '-';
    inline for (default_encoded_pos, 0..) |i, j| {
        out[i + 0] = hex[self.raw[j] >> 4];
        out[i + 1] = hex[self.raw[j] & 0x0f];
    }

    return out[0..36];
}

// Hex formating, "6ba7b8109dad11d180b400c04fd430c8"
fn formatHex(self: *const UUID, out: []u8) []const u8  {
    inline for (hex_encoded_pos, 0..) |i, j| {
        out[i + 0] = hex[self.raw[j] >> 4];
        out[i + 1] = hex[self.raw[j] & 0x0f];
    }

    return out[0..32];
}

// Slug formating, "wjKrAJQUEeyzyJ9r3s7YRg"
fn formatSlug(self: *const UUID, out: []u8) []const u8  {
    return std.base64.url_safe_no_pad.Encoder.encode(out, &self.raw);
}

// Increase the sequence, used by UUIDv1 and UUIDv6
fn incSeq() u14 {
    const Sequence = struct {
        var value : u14 = 0;
    };

    while(true) {
        const next_seq, const overflow = @addWithOverflow(Sequence.value, 1);
        _ = overflow;
        if(@cmpxchgStrong(u14, &Sequence.value, Sequence.value, next_seq, .monotonic, .monotonic) == null) {
            return next_seq;
        }
    }
}

test "should init with u128 values" {
    const uuid = UUID.initWithInt(@as(u128, 0x00AABBCCDDEE));
    var buf36: [36]u8 = undefined;
    const out = uuid.formatUUID(.default, &buf36);
    try std.testing.expectEqualStrings(out, "00000000-0000-0000-0000-00AABBCCDDEE");

    const uuid_1 = UUID.uuid1();
    const value_1 = uuid_1.toInt();
    const uuid_2 = UUID.initWithInt(value_1);
    const value_2 = uuid_2.toInt();

    try std.testing.expect(value_1 == value_2);
}

test "should return the correct version" {
    const uuidv1 = UUID.uuid1();
    try std.testing.expect(uuidv1.version() == 1);

    const uuidv1_1 = UUID.uuid1WithNodeId(&[6]u8{0x74, 0xA2, 0xEB, 0x92, 0x35,0x0F});
    try std.testing.expect(uuidv1_1.version() == 1);

    const uuidv3 = UUID.uuid3("This is my string.", "7525E1FC-5512-48CE-A457-74A2EB92350F");
    try std.testing.expect(uuidv3.version() == 3);

    const uuidv3_1 = UUID.uuid3WithNamespace("This is my string", UUID.Namespace.url);
    try std.testing.expect(uuidv3_1.version() == 3);

    const uuidv4 = UUID.uuid4();
    try std.testing.expect(uuidv4.version() == 4);

    const uuidv5 = UUID.uuid5("This is my string.", "7525E1FC-5512-48CE-A457-74A2EB92350F");
    try std.testing.expect(uuidv5.version() == 5);

    const uuidv5_1 = UUID.uuid5WithNamespace("This is my string", UUID.Namespace.url);
    try std.testing.expect(uuidv5_1.version() == 5);

    const uuidv6 = UUID.uuid6();
    try std.testing.expect(uuidv6.version() == 6);

    const uuidv6_1 = UUID.uuid6WithNodeId(&[6]u8{0x74, 0xA2, 0xEB, 0x92, 0x35,0x0F});
    try std.testing.expect(uuidv6_1.version() == 6);

    const uuidv7 = UUID.uuid7();
    try std.testing.expect(uuidv7.version() == 7);
}

test "uuidv1 should use the specified node id" {
    const nodeId = [6]u8{0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE};
    var uuid = UUID.uuid1WithNodeId(&nodeId);

    try std.testing.expect(uuid.version() == 1);
    var buf36: [36]u8 = undefined;
    var out = uuid.formatUUID(.default, &buf36);
    try std.testing.expectEqualStrings(out[24..], "00AABBCCDDEE");

    uuid = UUID.uuid1WithNodeId(&nodeId);

    out = uuid.formatUUID(.default, &buf36);
    try std.testing.expectEqualStrings(out[24..], "00AABBCCDDEE");
}

test "uuidv6 should use the specified node id" {
    const nodeId = [6]u8{0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE};
    var uuid = UUID.uuid6WithNodeId(&nodeId);

    try std.testing.expect(uuid.version() == 6);
    var buf36: [36]u8 = undefined;
    var out = uuid.formatUUID(.default, &buf36);
    try std.testing.expectEqualStrings(out[24..], "00AABBCCDDEE");

    uuid = UUID.uuid6WithNodeId(&nodeId);

    out = uuid.formatUUID(.default, &buf36);
    try std.testing.expectEqualStrings(out[24..], "00AABBCCDDEE");
}

test "UUIDv6 should created to be ordered" {
    const uuid_1 = UUID.uuid6();
    const uuid_2 = UUID.uuid6();
    const uuid_3 = UUID.uuid6();
    const uuid_4 = UUID.uuid6();

    try std.testing.expect(uuid_1.order(uuid_2) == .lt or uuid_1.order(uuid_2) == .eq);
    try std.testing.expect(uuid_2.order(uuid_3) == .lt or uuid_2.order(uuid_3) == .eq);
    try std.testing.expect(uuid_3.order(uuid_4) == .lt or uuid_2.order(uuid_3) == .eq);
}

test "UUIDv7 should be generated to be strictly ordered." {
    const uuid_1 = UUID.uuid7();
    const uuid_2 = UUID.uuid7();
    const uuid_3 = UUID.uuid7();
    const uuid_4 = UUID.uuid7();

    try std.testing.expect(uuid_1.order(uuid_2) == .lt);
    try std.testing.expect(uuid_2.order(uuid_3) == .lt);
    try std.testing.expect(uuid_3.order(uuid_4) == .lt);
}

test "should format a UUIDv1 value" {

    var buf36: [36]u8 = undefined;
    const uuid = UUID.init(.{0xC2, 0x32, 0xAB, 0x00, 0x94, 0x14, 0x11, 0xEC, 0xB3, 0xC8, 0x9F, 0x6B, 0xDE, 0xCE, 0xD8, 0x46});
    var out = uuid.formatUUID(.default, &buf36);
    try std.testing.expectEqualStrings(out, "C232AB00-9414-11EC-B3C8-9F6BDECED846");

    out = uuid.formatUUID(.hex, &buf36);
    try std.testing.expectEqualStrings(out, "C232AB00941411ECB3C89F6BDECED846");

    out = uuid.formatUUID(.slug, &buf36);
    try std.testing.expectEqualStrings(out, "wjKrAJQUEeyzyJ9r3s7YRg");

    try std.testing.expect(uuid.version() == 1);
}

test "format should return default, hex and slug strings" {
    var buf36: [36]u8 = undefined;
    const uuid = UUID.init(.{0} ** 16);

    var out = uuid.formatUUID(.default, &buf36);
    try std.testing.expectEqualStrings(out, "00000000-0000-0000-0000-000000000000");

    out = uuid.formatUUID(.hex, &buf36);
    try std.testing.expectEqualStrings(out, "00000000000000000000000000000000");

    out = uuid.formatUUID(.slug, &buf36);
    try std.testing.expectEqualStrings(out, "AAAAAAAAAAAAAAAAAAAAAA");
}


test "seqInc should increment the seq after calling" {
    const start = incSeq();
    try std.testing.expect(incSeq() == start + 1);
    try std.testing.expect(incSeq() == start + 2);
    try std.testing.expect(incSeq() == start + 3);
    try std.testing.expect(incSeq() == start + 4);
}

test "generates a new UUID5 based on a UUID" {
    const uuid = UUID.uuid5("this is my string", "222BA182-5BDF-404F-8D02-BC0C18C80195");
    var buf36: [36]u8 = undefined;
    const out = uuid.formatUUID(.default, &buf36);
    try std.testing.expectEqualStrings(out, "CB3C6E3C-85FE-5023-9830-F807DA0AF3F2");
}

test "generates new UUID3s based on different pre defined namespace" {
    var buf36: [36]u8 = undefined;
    var uuid = UUID.uuid3WithNamespace("this is my string", .dns);
    var out = uuid.formatUUID(.default, &buf36);
    try std.testing.expectEqualStrings(out, "467B3FDF-E05D-3632-9B4A-519AE4921D61");

    uuid = UUID.uuid3WithNamespace("this is my string", .url);
    out = uuid.formatUUID(.default, &buf36);
    try std.testing.expectEqualStrings(out, "ABF9BA64-EE10-3899-AEED-154AA4B64831");

    uuid = UUID.uuid3WithNamespace("this is my string", .oid);
    out = uuid.formatUUID(.default, &buf36);
    try std.testing.expectEqualStrings(out, "8EF1F24D-9A59-31B2-9558-05CDF10DE75E");

    uuid = UUID.uuid3WithNamespace("this is my string", .x500);
    out = uuid.formatUUID(.default, &buf36);
    try std.testing.expectEqualStrings(out, "A4F71444-6F2A-3DDA-87D4-EED37F763531");

    uuid = UUID.uuid3WithNamespace("this is my string", .nil);
    out = uuid.formatUUID(.default, &buf36);
    try std.testing.expectEqualStrings(out, "A0E362D3-1BAE-3DA4-BFF2-AD6AE4F44DBF");

    try std.testing.expect(uuid.version() == 3);
}

test "generates new UUID5s based on different pre defined namespace" {
    var buf36: [36]u8 = undefined;
    var uuid = UUID.uuid5WithNamespace("this is my string", .dns);
    var out = uuid.formatUUID(.default, &buf36);
    try std.testing.expectEqualStrings(out, "618CA8EC-BE67-58C8-91CB-03898F031C15");

    uuid = UUID.uuid5WithNamespace("this is my string", .url);
    out = uuid.formatUUID(.default, &buf36);
    try std.testing.expectEqualStrings(out, "5F7F8A62-9C6E-559A-AF1D-259956DD3F82");

    uuid = UUID.uuid5WithNamespace("this is my string", .oid);
    out = uuid.formatUUID(.default, &buf36);
    try std.testing.expectEqualStrings(out, "C326C1BF-7F09-514F-AB04-FD8E7CEEFB8D");

    uuid = UUID.uuid5WithNamespace("this is my string", .x500);
    out = uuid.formatUUID(.default, &buf36);
    try std.testing.expectEqualStrings(out, "E8BA8088-BA8B-513F-9421-2BC756E682F6");

    uuid = UUID.uuid5WithNamespace("this is my string", .nil);
    out = uuid.formatUUID(.default, &buf36);
    try std.testing.expectEqualStrings(out, "C0A235AC-BD72-571B-84BF-85B22856BC00");

    try std.testing.expect(uuid.version() == 5);
}


test "parses UUID string" {
    var buf36: [36]u8 = undefined;
    const uuid = try UUID.parse("6ba7b810-9dad-11d1-80b4-00c04fd430c8");
    const out = uuid.formatUUID(.default, &buf36);
    try std.testing.expectEqualStrings(out, "6BA7B810-9DAD-11D1-80B4-00C04FD430C8");
}