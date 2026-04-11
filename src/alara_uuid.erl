%% ============================================================================
%% alara_uuid - UUID v7 & v5 Generator
%%
%% Generates RFC 9562 compliant UUIDs:
%%
%%   - **UUID v7** — time-ordered, random.  The 48-bit Unix millisecond
%%     timestamp guarantees monotonic ordering; the remaining 74 bits of
%%     randomness come from ALARA's distributed entropy pool (mixed with
%%     SHA3-256), making collisions practically impossible.
%%
%%   - **UUID v5** — name-based, deterministic.  A SHA-1 digest of a
%%     namespace UUID concatenated with a name; no entropy required.
%%
%% Quick start
%% -----------
%%
%%   %% Single UUID v7
%%   UUID = alara_uuid:v7(),
%%   io:format("~s~n", [alara_uuid:to_string(UUID)]).
%%
%%   %% Batch of 100 UUID v7s
%%   UUIDs = alara_uuid:v7(100).
%%
%%   %% UUID v5 from a DNS name
%%   UUID5 = alara_uuid:v5(dns, "example.com").
%%
%% All UUID v7 functions start the ALARA supervisor automatically if it
%% is not already running.
%% ============================================================================

-module(alara_uuid).

%% ---------------------------------------------------------------------------
%% RFC 9562 predefined namespaces
%% ---------------------------------------------------------------------------
-define(NS_DNS,  <<16#6ba7b810:32, 16#9dad:16, 16#11d1:16, 16#80b4:16, 16#00c04fd430c8:48>>).
-define(NS_URL,  <<16#6ba7b811:32, 16#9dad:16, 16#11d1:16, 16#80b4:16, 16#00c04fd430c8:48>>).
-define(NS_OID,  <<16#6ba7b812:32, 16#9dad:16, 16#11d1:16, 16#80b4:16, 16#00c04fd430c8:48>>).
-define(NS_X500, <<16#6ba7b814:32, 16#9dad:16, 16#11d1:16, 16#80b4:16, 16#00c04fd430c8:48>>).

%% Number of random bytes needed for UUID v7:
%% 12 bits (rand_a) + 62 bits (rand_b) = 74 bits → ceil(74/8) = 10 bytes.
-define(V7_RANDOM_BYTES, 10).

%% Public API
-export([v7/0, v7/1, v5/2, to_string/1, to_string/2]).
-export([ns_dns/0, ns_url/0, ns_oid/0, ns_x500/0]).

%% ---------------------------------------------------------------------------
%% Types
%% ---------------------------------------------------------------------------
-type uuid()        :: <<_:128>>.
-type uuid_format() :: standard | hex | urn | binary | atom() | string().

-export_type([uuid/0, uuid_format/0]).

%% ============================================================================
%% Public API
%% ============================================================================

%% @doc Generate a single RFC 9562 UUID v7.
%%
%% The UUID embeds a 48-bit Unix millisecond timestamp followed by 74 bits
%% of ALARA-distributed entropy (SHA3-256 mixed).  UUIDs generated within
%% the same millisecond are differentiated by the random field.
%%
%% @return A 128-bit UUID binary.
-spec v7() -> uuid().
v7() ->
    ensure_alara_started(),
    generate_uuid_v7().

%% @doc Generate a list of N RFC 9562 UUID v7s.
%%
%% More efficient than calling v7/0 in a loop because the ALARA startup
%% check is performed only once.
%%
%% @param N Number of UUIDs to generate (must be > 0).
%% @return List of 128-bit UUID binaries.
-spec v7(pos_integer()) -> [uuid()].
v7(N) when is_integer(N), N > 0 ->
    ensure_alara_started(),
    [generate_uuid_v7() || _ <- lists:seq(1, N)].

%% @doc Generate a deterministic RFC 9562 UUID v5 from a namespace and name.
%%
%% Supported namespace atoms: dns, url, oid, x500.
%% A custom namespace binary (another UUID) can also be passed directly.
%%
%% UUID v5 does not use entropy: the same {Namespace, Name} pair always
%% produces the same UUID.
%%
%% @param Namespace Atom shorthand or a 128-bit namespace UUID binary.
%% @param Name      String or binary name to hash.
%% @return A 128-bit UUID binary.
-spec v5(dns | url | oid | x500 | uuid(), string() | binary()) -> uuid().
v5(dns,  Name) -> generate_uuid_v5(?NS_DNS,  Name);
v5(url,  Name) -> generate_uuid_v5(?NS_URL,  Name);
v5(oid,  Name) -> generate_uuid_v5(?NS_OID,  Name);
v5(x500, Name) -> generate_uuid_v5(?NS_X500, Name);
v5(Namespace, Name) when is_binary(Namespace) ->
    generate_uuid_v5(Namespace, Name).

%% @doc Convert a UUID binary to its canonical string representation.
%%
%% Equivalent to to_string(UUID, standard).
%%
%% @param UUID 128-bit UUID binary.
%% @return String in the form xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx.
-spec to_string(uuid()) -> string().
to_string(UUID) ->
    format_uuid(UUID, standard).

%% @doc Convert a UUID binary to a string in the specified format.
%%
%% Available formats:
%%
%%   - standard / "standard" — xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
%%   - hex      / "hex"      — xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
%%   - urn      / "urn"      — urn:uuid:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
%%   - binary   / "binary"   — Erlang binary term representation
%%
%% @param UUID   128-bit UUID binary.
%% @param Format Desired output format.
%% @return Formatted UUID string.
-spec to_string(uuid(), uuid_format()) -> string().
to_string(UUID, Format) ->
    format_uuid(UUID, Format).

%% @doc Return the RFC 9562 DNS namespace UUID.
-spec ns_dns() -> uuid().
ns_dns() -> ?NS_DNS.

%% @doc Return the RFC 9562 URL namespace UUID.
-spec ns_url() -> uuid().
ns_url() -> ?NS_URL.

%% @doc Return the RFC 9562 OID namespace UUID.
-spec ns_oid() -> uuid().
ns_oid() -> ?NS_OID.

%% @doc Return the RFC 9562 X.500 namespace UUID.
-spec ns_x500() -> uuid().
ns_x500() -> ?NS_X500.

%% ============================================================================
%% UUID v7 internals
%% ============================================================================

%% Build one UUID v7.
%% Layout (RFC 9562 §5.7):
%%
%%   0                   1                   2                   3
%%   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
%%  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
%%  |                           unix_ts_ms (high 32)                |
%%  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
%%  |       unix_ts_ms (low 16)     |  ver(4)  |    rand_a (12)     |
%%  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
%%  |var(2)|                   rand_b (62)                          |
%%  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
%%  |                        rand_b (cont.)                         |
%%  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-spec generate_uuid_v7() -> uuid().
generate_uuid_v7() ->
    %% 48-bit Unix timestamp in milliseconds.
    UnixMs = erlang:system_time(millisecond),

    %% 10 bytes = 80 random bits from ALARA (we use 74 of them).
    %% Binary pattern matching replaces the old boolean-list approach:
    %% no conversion loop, no list allocation.
    <<RandA:12, RandB:62, _Unused:6>> = alara:generate_random_bytes(?V7_RANDOM_BYTES),

    %% Decompose timestamp for the wire format.
    <<TsHi:32, TsLo:16>> = <<UnixMs:48>>,

    %% Assemble the 128-bit UUID.
    <<TsHi:32, TsLo:16, 7:4, RandA:12, 2:2, RandB:62>>.

%% ============================================================================
%% UUID v5 internals
%% ============================================================================

-spec generate_uuid_v5(uuid(), string() | binary()) -> uuid().
generate_uuid_v5(Namespace, Name) when is_list(Name) ->
    generate_uuid_v5(Namespace, list_to_binary(Name));
generate_uuid_v5(Namespace, Name) when is_binary(Namespace), is_binary(Name) ->
    %% SHA-1 over the namespace UUID concatenated with the name (RFC 9562 §5.5).
    <<TL:32, TM:16, THV:16, CSV:16, Node:48, _/binary>> =
        crypto:hash(sha, <<Namespace/binary, Name/binary>>),

    %% Overwrite version nibble with 5 and variant bits with 10.
    THV2 = (THV band 16#0FFF) bor (5 bsl 12),
    CSV2 = (CSV band 16#3FFF) bor (2 bsl 14),

    <<TL:32, TM:16, THV2:16, CSV2:16, Node:48>>.

%% ============================================================================
%% Internal helpers
%% ============================================================================

%% Ensure the ALARA OTP application is running before generating UUIDs.
%% v7/0 and v7/1 call this once before entering the generation loop.
-spec ensure_alara_started() -> ok.
ensure_alara_started() ->
    case application:ensure_all_started(alara) of
        {ok, _}         -> ok;
        {error, Reason} -> error({alara_start_failed, Reason})
    end.

%% Format a 128-bit UUID binary as a string.
-spec format_uuid(uuid(), uuid_format()) -> string().
format_uuid(<<A:32, B:16, C:16, D:16, E:48>>, Format)
        when Format =:= standard; Format =:= "standard" ->
    lists:flatten(io_lib:format(
        "~8.16.0b-~4.16.0b-~4.16.0b-~4.16.0b-~12.16.0b",
        [A, B, C, D, E]));
format_uuid(<<A:32, B:16, C:16, D:16, E:48>>, Format)
        when Format =:= hex; Format =:= "hex" ->
    lists:flatten(io_lib:format(
        "~8.16.0b~4.16.0b~4.16.0b~4.16.0b~12.16.0b",
        [A, B, C, D, E]));
format_uuid(<<A:32, B:16, C:16, D:16, E:48>>, Format)
        when Format =:= urn; Format =:= "urn" ->
    lists:flatten(io_lib:format(
        "urn:uuid:~8.16.0b-~4.16.0b-~4.16.0b-~4.16.0b-~12.16.0b",
        [A, B, C, D, E]));
format_uuid(UUID, Format)
        when Format =:= binary; Format =:= "binary" ->
    lists:flatten(io_lib:format("~p", [UUID]));
format_uuid(UUID, _Unknown) ->
    format_uuid(UUID, standard).
