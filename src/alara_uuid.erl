%% ============================================================================
%% alara_uuid - UUID v7 & v5 Generator using ALARA
%% Generates RFC 9562 compliant UUIDs with distributed entropy
%% ============================================================================

-module(alara_uuid).

%% Predefined namespaces (RFC 9562)
-define(NS_DNS, <<16#6ba7b810:32, 16#9dad:16, 16#11d1:16, 16#80b4:16, 16#00c04fd430c8:48>>).
-define(NS_URL, <<16#6ba7b811:32, 16#9dad:16, 16#11d1:16, 16#80b4:16, 16#00c04fd430c8:48>>).
-define(NS_OID, <<16#6ba7b812:32, 16#9dad:16, 16#11d1:16, 16#80b4:16, 16#00c04fd430c8:48>>).
-define(NS_X500, <<16#6ba7b814:32, 16#9dad:16, 16#11d1:16, 16#80b4:16, 16#00c04fd430c8:48>>).

%% Public API
-export([v7/0, v7/1, v5/2, to_string/1, to_string/2]).
-export([ns_dns/0, ns_url/0, ns_oid/0, ns_x500/0]).

%% ============================================================================
%% Public API
%% ============================================================================

%% Generate a single UUID v7
v7() ->
    ensure_alara_started(),
    generate_uuid_v7().

%% Generate N UUID v7s
v7(N) when is_integer(N), N > 0 ->
    ensure_alara_started(),
    [generate_uuid_v7() || _ <- lists:seq(1, N)].

%% Generate UUID v5 from predefined namespace
v5(dns, Name) -> generate_uuid_v5(?NS_DNS, Name);
v5(url, Name) -> generate_uuid_v5(?NS_URL, Name);
v5(oid, Name) -> generate_uuid_v5(?NS_OID, Name);
v5(x500, Name) -> generate_uuid_v5(?NS_X500, Name);
%% Generate UUID v5 from custom namespace UUID
v5(Namespace, Name) when is_binary(Namespace) ->
    generate_uuid_v5(Namespace, Name).

%% Namespace accessors
ns_dns() -> ?NS_DNS.
ns_url() -> ?NS_URL.
ns_oid() -> ?NS_OID.
ns_x500() -> ?NS_X500.

%% Convert UUID binary to string
to_string(UUID) ->
    lists:flatten(format_uuid(UUID, "standard")).

to_string(UUID, Format) ->
    lists:flatten(format_uuid(UUID, Format)).

%% ============================================================================
%% UUID v7 Generation (RFC 9562) - Time-based with Random
%% ============================================================================

generate_uuid_v7() ->
    %% 1. Get Unix timestamp in milliseconds (48 bits)
    UnixMs = erlang:system_time(millisecond),
    
    %% 2. Generate random bits using ALARA (74 bits total random)
    %%    - 12 bits for sub-millisecond precision
    %%    - 62 bits for uniqueness
    RandomBits = alara:generate_random_bools(74),
    
    %% 3. Construct UUID v7 structure
    construct_uuid_v7(UnixMs, RandomBits).

construct_uuid_v7(UnixMs, RandomBits) ->
    %% Split timestamp into bytes (48 bits = 6 bytes)
    <<TimestampHi:32, TimestampLo:16>> = <<UnixMs:48>>,
    
    %% Extract random sections from ALARA bits
    {RandA, Rest1} = lists:split(12, RandomBits),
    {RandB, _RandC} = lists:split(62, Rest1),
    
    %% Convert boolean lists to integers
    RandAInt = bools_to_int(RandA),
    RandBInt = bools_to_int(RandB),
    
    %% Construct UUID v7 according to RFC 9562:
    %% - 48 bits: timestamp_ms
    %% - 4 bits: version (0111 for v7)
    %% - 12 bits: rand_a
    %% - 2 bits: variant (10)
    %% - 62 bits: rand_b
    
    Version = 7,
    Variant = 2, %% Binary: 10
    
    <<TimestampHi:32,           %% 32 bits timestamp high
      TimestampLo:16,           %% 16 bits timestamp low
      Version:4,                %% 4 bits version
      RandAInt:12,              %% 12 bits random A
      Variant:2,                %% 2 bits variant
      RandBInt:62>>.            %% 62 bits random B

%% ============================================================================
%% UUID v5 Generation (RFC 9562) - Name-based SHA-1
%% ============================================================================

generate_uuid_v5(Namespace, Name) when is_binary(Namespace), is_list(Name) ->
    generate_uuid_v5(Namespace, list_to_binary(Name));

generate_uuid_v5(Namespace, Name) when is_binary(Namespace), is_binary(Name) ->
    %% 1. Concatenate namespace UUID and name
    Data = <<Namespace/binary, Name/binary>>,
    
    %% 2. Compute SHA-1 hash
    Hash = crypto:hash(sha, Data),
    
    %% 3. Take first 128 bits (16 bytes)
    <<TimeLow:32, TimeMid:16, TimeHiVersion:16, 
      ClockSeqVariant:16, Node:48, _Rest/binary>> = Hash,
    
    %% 4. Set version (5) and variant bits
    Version = 5,
    Variant = 2,
    
    %% Clear version bits and set to 5 (0101)
    TimeHiVersion2 = (TimeHiVersion band 16#0FFF) bor (Version bsl 12),
    
    %% Clear variant bits and set to 10
    ClockSeqVariant2 = (ClockSeqVariant band 16#3FFF) bor (Variant bsl 14),
    
    <<TimeLow:32, TimeMid:16, TimeHiVersion2:16, 
      ClockSeqVariant2:16, Node:48>>.

%% ============================================================================
%% Helper Functions
%% ============================================================================

%% Ensure ALARA supervisor is started (for v7 only)
ensure_alara_started() ->
    case whereis(alara_node_sup) of
        undefined ->
            %% Start the supervisor if not running
            case alara_node_sup:start_link(3) of
                {ok, _Pid} -> ok;
                {error, {already_started, _}} -> ok;
                Error -> 
                    error({alara_start_failed, Error})
            end;
        _Pid ->
            ok
    end.

%% Convert list of booleans to integer
bools_to_int(Bools) ->
    bools_to_int(Bools, 0).

bools_to_int([], Acc) ->
    Acc;
bools_to_int([H|T], Acc) ->
    Bit = case H of
        true -> 1;
        false -> 0;
        1 -> 1;
        0 -> 0
    end,
    bools_to_int(T, (Acc bsl 1) bor Bit).

%% Format UUID for display
format_uuid(<<A:32, B:16, C:16, D:16, E:48>>, standard) ->
    io_lib:format("~8.16.0b-~4.16.0b-~4.16.0b-~4.16.0b-~12.16.0b", 
                  [A, B, C, D, E]);
format_uuid(<<A:32, B:16, C:16, D:16, E:48>>, "standard") ->
    io_lib:format("~8.16.0b-~4.16.0b-~4.16.0b-~4.16.0b-~12.16.0b", 
                  [A, B, C, D, E]);

format_uuid(<<A:32, B:16, C:16, D:16, E:48>>, hex) ->
    io_lib:format("~8.16.0b~4.16.0b~4.16.0b~4.16.0b~12.16.0b", 
                  [A, B, C, D, E]);
format_uuid(<<A:32, B:16, C:16, D:16, E:48>>, "hex") ->
    io_lib:format("~8.16.0b~4.16.0b~4.16.0b~4.16.0b~12.16.0b", 
                  [A, B, C, D, E]);

format_uuid(UUID, binary) ->
    io_lib:format("~p", [UUID]);
format_uuid(UUID, "binary") ->
    io_lib:format("~p", [UUID]);

format_uuid(<<A:32, B:16, C:16, D:16, E:48>>, urn) ->
    io_lib:format("urn:uuid:~8.16.0b-~4.16.0b-~4.16.0b-~4.16.0b-~12.16.0b", 
                  [A, B, C, D, E]);
format_uuid(<<A:32, B:16, C:16, D:16, E:48>>, "urn") ->
    io_lib:format("urn:uuid:~8.16.0b-~4.16.0b-~4.16.0b-~4.16.0b-~12.16.0b", 
                  [A, B, C, D, E]);

format_uuid(UUID, _) ->
    format_uuid(UUID, standard).
