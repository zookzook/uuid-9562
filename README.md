# UUID library for Zig

This library provides a straightforward implementation of **RFC-compatible UUIDs** for Zig, including versions **1, 3, 4, 5, 6, and 7**. It supports random and name-based UUIDs, custom node IDs, formatting helpers, and conversion to integers.
The focus of this library is **simple usage**, not heavy abstractions.
This package was created as an exercise to learn Zig. The Go and Elixir implementations were used as inspiration.
In addition, there are other Zig implementations that cover the same range of functionality.

## Features

* UUID versions:
    * **v1** – time-based (optionally with custom node ID)
    * **v3** – name-based (MD5)
    * **v4** – random
    * **v5** – name-based (SHA-1)
    * **v6** – reordered time-based (UUIDv6)
    * **v7** – Unix time-based (UUIDv7)
* Conversion between:
    * 16-byte arrays
    * 128-bit integers
* Built-in namespace constants
* Node ID generator for v1/v6
* Formatting helpers for common output formats
* Parsing

## Installation
No external dependencies are required beyond Zig’s standard library.

## Quick Start

### Generate a random UUID (v4)

```zig
const std = @import("std");
const UUID = @import("uuid.zig");

pub fn main() !void {
    const uuid = UUID.uuid4();
    try std.debug.print("UUID v4: {f}\n", .{uuid});
}
```

## Version 1 – time-based

```zig
const v1 = uuid.uuid1();
```

Version 1 using a **custom node ID**:

```zig
var node: [6]u8 = .{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
const v1 = UUID.uuid1WithNodeId(&node);
```

Generate a random node ID:

```zig
var node: [6]u8 = undefined;
uuid.randomNodeId(&node);
```

## Version 3 and 5 – name-based UUIDs

Using raw namespace bytes:

```zig
const v3 = UUID.uuid3("my-name", "my-namespace");
const v5 = UUID.uuid5("my-name", "my-namespace");
```

Using predefined namespaces:

```zig
const v3 = uuid.uuid3WithNamespace("project", UUID.Namespace.dns);
const v5 = uuid.uuid5WithNamespace("project", UUID.Namespace.url);
```

---

## Version 6 and 7 UUIDs

UUID v6:

```zig
const v6 = UUID.uuid6();
```

With custom node ID:

```zig
var node: [6]u8 = ...
const v6 = UUID.uuid6WithNodeId(&node);
```

UUID v7:

```zig
const v7 = UUID.uuid7();
```

## Formatting UUIDs

Available formats (as enum `Format`):

* `.default` – `8-4-4-4-12`
* `.hex` – `32 hex chars`
* `.slug` – `url_safe_no_pad`

Example:

```zig
const uuid = UUID.uuid4();
var buf: [36]u8 = undefined;
const text = uuid.formatUUID(.default, &buf);
```

## Convert to/from integers

From bytes:

```zig
const u = uuid.init(uuid_bytes);
```

From 128-bit integer:

```zig
const u = uuid.initWithInt(42);
```

To 128-bit integer:

```zig
const value: u128 = u.toInt();
```

## Inspecting UUID version

```zig
const v = u.version();
```
Returns a `u4` version number (1, 3, 4, 5, 6, or 7).

## Ordering and comparison

In case of UUIDv7 or UUIDv6 you can call the order function:

```zig

const u1 = UUID.uuid7();
const u2 = UUID.uuid7();
const order = uuid.order(&u1, u2); // order == .lt
```

Returns `std.math.Order.{lt, eq, gt}`.
