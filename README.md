# ALARA UUID

High-quality UUID generation for Erlang with distributed entropy powered by ALARA.

[![Hex.pm](https://img.shields.io/hexpm/v/alara_uuid.svg)](https://hex.pm/packages/alara_uuid)
[![Hex Docs](https://img.shields.io/badge/hex-docs-blue.svg)](https://hexdocs.pm/alara_uuid)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

## Description

ALARA UUID is an RFC 9562 compliant UUID generator that leverages the ALARA distributed entropy network to produce cryptographically strong identifiers. It supports both UUID v7 (time-based with random components) for optimal database performance and UUID v5 (name-based SHA-1) for deterministic generation.

Unlike traditional UUID libraries, ALARA UUID uses a distributed entropy network instead of local randomness, providing superior entropy quality through network-wide consensus. This makes it ideal for distributed systems requiring high-quality randomness and chronologically sortable identifiers.

## Features

- **UUID v7**: Time-based identifiers with millisecond precision and distributed random bits
  - Naturally sortable by creation time
  - Optimized for database indexing (B-tree friendly)
  - No fragmentation in database inserts
  - Powered by ALARA distributed entropy network

- **UUID v5**: Deterministic name-based identifiers using SHA-1
  - Same input always produces same UUID
  - Supports predefined namespaces (DNS, URL, OID, X.500)
  - Custom namespace support
  - No external dependencies required

- **RFC 9562 Compliant**: Fully compatible with the latest UUID specification
- **Multiple Output Formats**: Standard, hexadecimal, URN, and binary representations
- **Comprehensive Test Suite**: 62 EUnit tests covering all functionality
- **Zero Dependencies**: (except ALARA for v7 entropy)

## Quick Start

### UUID v7 - Time-based with ALARA Entropy

```erlang
%% Generate a single UUID v7
UUID = alara_uuid:v7().
%% <<1,154,77,90,96,54,125,10,189,92,48,248,177,65,171,212>>

%% Generate multiple UUIDs
UUIDs = alara_uuid:v7(10).

%% Convert to string
Str = alara_uuid:to_string(UUID).
%% "019a4d5a-6036-7d0a-bd5c-30f8b141abd4"

%% Different formats
Hex = alara_uuid:to_string(UUID, "hex").
%% "019a4d5a60367d0abd5c30f8b141abd4"

URN = alara_uuid:to_string(UUID, "urn").
%% "urn:uuid:019a4d5a-6036-7d0a-bd5c-30f8b141abd4"
```

### UUID v5 - Deterministic Name-based

```erlang
%% Generate UUID v5 with predefined namespace
UUID1 = alara_uuid:v5(dns, "example.com").
UUID2 = alara_uuid:v5(dns, "example.com").
UUID1 =:= UUID2.  % true - always the same

%% Other predefined namespaces
URLBasedUUID = alara_uuid:v5(url, "https://example.com").
OIDBasedUUID = alara_uuid:v5(oid, "1.3.6.1.4.1").
X500BasedUUID = alara_uuid:v5(x500, "cn=John Doe").

%% Custom namespace
CustomNS = alara_uuid:ns_dns(),  % or any 16-byte binary
UUID = alara_uuid:v5(CustomNS, <<"my-custom-name">>).
```

## API Reference

### Generation Functions

#### `v7() -> binary()`
Generate a single UUID v7 with ALARA distributed entropy.

#### `v7(N :: pos_integer()) -> [binary()]`
Generate N UUID v7 identifiers.

#### `v5(Namespace :: atom() | binary(), Name :: string() | binary()) -> binary()`
Generate a deterministic UUID v5 from a namespace and name.

Predefined namespace atoms:
- `dns` - Domain Name System
- `url` - Uniform Resource Locator
- `oid` - Object Identifier
- `x500` - X.500 Distinguished Name

### Namespace Accessors

#### `ns_dns() -> binary()`
Returns the RFC 9562 DNS namespace UUID.

#### `ns_url() -> binary()`
Returns the RFC 9562 URL namespace UUID.

#### `ns_oid() -> binary()`
Returns the RFC 9562 OID namespace UUID.

#### `ns_x500() -> binary()`
Returns the RFC 9562 X.500 namespace UUID.

### Formatting Functions

#### `to_string(UUID :: binary()) -> string()`
Convert UUID to standard format: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`

#### `to_string(UUID :: binary(), Format :: string() | atom()) -> string()`
Convert UUID to specified format:
- `"standard"` or `standard` - Hyphenated format
- `"hex"` or `hex` - Continuous hexadecimal
- `"urn"` or `urn` - URN format with prefix
- `"binary"` or `binary` - Erlang binary representation

## UUID v7 Structure

UUID v7 provides chronological sortability with high-quality randomness:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         unix_ts_ms (48)                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|ver|       rand_a (12)         |var|       rand_b (62)         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- **48 bits**: Unix timestamp in milliseconds
- **4 bits**: Version (0111 = 7)
- **12 bits**: Random data from ALARA (sub-millisecond precision)
- **2 bits**: Variant (10)
- **62 bits**: Random data from ALARA (uniqueness guarantee)

### Why UUID v7?

**Database Performance**
- Natural chronological ordering reduces index fragmentation
- B-tree indexes remain balanced and efficient
- Predictable insert patterns improve write performance

**Distributed Systems**
- Globally unique without coordination
- No central authority needed
- Works across multiple nodes and datacenters

**Better than UUID v4**
- Same uniqueness guarantees
- Added benefit of sortability
- No performance penalty

**Better than UUID v1**
- No MAC address exposure (privacy)
- Better timestamp precision
- Modern design

## UUID v5 Structure

UUID v5 generates deterministic identifiers from namespace and name:

```
UUID = SHA1(namespace_uuid + name)[0:128]
Version = 5
Variant = RFC 4122
```

Use cases:
- Content-addressable identifiers
- Deterministic cache keys
- Reproducible testing
- Consistent mapping from names to UUIDs

## ALARA Integration

UUID v7 leverages ALARA's distributed entropy network for random bit generation. ALARA automatically starts when generating v7 UUIDs.

### How ALARA Enhances UUID Generation

1. **Distributed Entropy**: Random bits come from multiple network nodes
2. **Consensus-Based**: Entropy is validated across the network
3. **High Quality**: Statistical properties verified through distributed agreement
4. **Transparent**: Automatic startup, no configuration needed

### Manual ALARA Control

```erlang
%% ALARA starts automatically, but you can control it:
{ok, Sup} = alara_node_sup:start_link(3).  % 3 nodes

%% Generate UUIDs (ALARA already running)
UUIDs = alara_uuid:v7(100).

%% Stop when done
alara_node_sup:stop().
```

## Testing

Run the comprehensive test suite:

```bash
rebar3 eunit
```

## Use Cases

### Web Applications
```erlang
%% Generate user IDs
UserID = alara_uuid:v7(),
User = #user{id = UserID, email = Email, created_at = erlang:system_time()}.
```

### Distributed Databases
```erlang
%% Primary keys that sort chronologically
lists:foreach(fun(Data) ->
    ID = alara_uuid:v7(),
    db:insert(#record{id = ID, data = Data})
end, Records).

%% Query by time range becomes efficient
RecentRecords = db:query("SELECT * FROM records WHERE id > ?", [SinceUUID]).
```

### Content Addressable Storage
```erlang
%% Deterministic IDs for content
ContentHash = crypto:hash(sha256, Content),
ContentID = alara_uuid:v5(ns_oid(), ContentHash),
store:put(ContentID, Content).

%% Same content always gets same ID
ContentID2 = alara_uuid:v5(ns_oid(), ContentHash),
ContentID =:= ContentID2.  % true
```

### Distributed Tracing
```erlang
%% Trace IDs with temporal ordering
TraceID = alara_uuid:v7(),
SpanID = alara_uuid:v7(),
trace:start_span(TraceID, SpanID, Operation).
```

## RFC 9562 Compliance

ALARA UUID fully implements RFC 9562 (published May 2024), the latest UUID specification:

- Correct version bits (4 bits at position 48-51)
- Correct variant bits (2 bits at position 64-65, value 10)
- Proper timestamp encoding for v7
- Standard namespace UUIDs for v5
- Compatible with all existing UUID parsers and databases

## Contributing

Contributions are welcome. Please ensure:

1. All tests pass: `rebar3 eunit`
2. Code follows OTP design principles
3. New features include tests
4. Documentation is updated

## License

Apache License 2.0

## References

- RFC 9562: Universally Unique IDentifiers (UUIDs)
- [ALARA: Distributed Entropy Network System](https://github.com/Green-Mice/alara)
- UUID v7 Draft Specification

