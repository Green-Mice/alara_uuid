%% ============================================================================
%% alara_uuid_v7_tests - EUnit Tests for UUID v7
%% Tests RFC 9562 compliant UUID v7 (time-based with ALARA entropy)
%% ============================================================================

-module(alara_uuid_v7_tests).

-include_lib("eunit/include/eunit.hrl").

%% ============================================================================
%% Test Fixtures
%% ============================================================================

%% Setup: Ensure ALARA is available for tests
alara_setup() ->
    %% ALARA will auto-start in v7(), but we can pre-start for efficiency
    case whereis(alara_node_sup) of
        undefined ->
            {ok, _} = alara_node_sup:start_link(3);
        _ ->
            ok
    end.

alara_cleanup(_) ->
    %% Leave ALARA running for other tests
    ok.

%% Fixture for tests that need ALARA
alara_test_() ->
    {setup,
     fun alara_setup/0,
     fun alara_cleanup/1,
     [
         fun v7_generation_test/0,
         fun v7_multiple_generation_test/0,
         fun v7_batch_generation_test/0
     ]}.

%% ============================================================================
%% Basic Generation Tests
%% ============================================================================

v7_generation_test() ->
    UUID = alara_uuid:v7(),
    ?assert(is_binary(UUID)),
    ?assertEqual(16, byte_size(UUID)).

v7_multiple_generation_test() ->
    UUID1 = alara_uuid:v7(),
    UUID2 = alara_uuid:v7(),
    
    ?assert(is_binary(UUID1)),
    ?assert(is_binary(UUID2)),
    ?assertNotEqual(UUID1, UUID2).

v7_batch_generation_test() ->
    UUIDs = alara_uuid:v7(10),
    
    ?assertEqual(10, length(UUIDs)),
    ?assert(lists:all(fun is_binary/1, UUIDs)),
    ?assert(lists:all(fun(U) -> byte_size(U) =:= 16 end, UUIDs)),
    
    %% All should be unique
    ?assertEqual(10, length(lists:usort(UUIDs))).

%% ============================================================================
%% Uniqueness Tests
%% ============================================================================

v7_uniqueness_small_batch_test_() ->
    {timeout, 10, fun() ->
        UUIDs = alara_uuid:v7(100),
        ?assertEqual(100, length(lists:usort(UUIDs)))
    end}.

v7_uniqueness_large_batch_test_() ->
    {timeout, 30, fun() ->
        UUIDs = alara_uuid:v7(1000),
        ?assertEqual(1000, length(lists:usort(UUIDs)))
    end}.

v7_uniqueness_concurrent_test_() ->
    {timeout, 10, fun() ->
        %% Generate UUIDs in parallel
        Parent = self(),
        Pids = [spawn(fun() -> 
            UUIDs = alara_uuid:v7(10),
            Parent ! {uuids, UUIDs}
        end) || _ <- lists:seq(1, 10)],
        
        %% Collect all UUIDs
        AllUUIDs = lists:flatten([
            receive {uuids, Us} -> Us end
        || _ <- Pids]),
        
        %% All should be unique
        ?assertEqual(100, length(AllUUIDs)),
        ?assertEqual(100, length(lists:usort(AllUUIDs)))
    end}.

%% ============================================================================
%% RFC 9562 Compliance Tests
%% ============================================================================

v7_version_field_test() ->
    UUID = alara_uuid:v7(),
    <<_:48, Version:4, _:76>> = UUID,
    ?assertEqual(7, Version).

v7_variant_field_test() ->
    UUID = alara_uuid:v7(),
    <<_:64, Variant:2, _:62>> = UUID,
    ?assertEqual(2, Variant). %% Binary: 10

v7_format_structure_test() ->
    UUID = alara_uuid:v7(),
    <<Timestamp:48, Version:4, _RandA:12, Variant:2, _RandB:62>> = UUID,
    
    ?assertEqual(7, Version),
    ?assertEqual(2, Variant),
    
    %% Timestamp should be reasonable (not zero, not in future)
    Now = erlang:system_time(millisecond),
    ?assert(Timestamp > 0),
    ?assert(Timestamp =< Now + 1000). %% Allow 1s clock skew

v7_all_fields_test() ->
    UUID = alara_uuid:v7(),
    <<TimestampHi:32, TimestampLo:16, Version:4, _RandA:12,
      Variant:2, _RandB:62>> = UUID,
    
    ?assertEqual(7, Version),
    ?assertEqual(2, Variant),
    
    %% Reconstruct timestamp
    Timestamp = (TimestampHi bsl 16) bor TimestampLo,
    Now = erlang:system_time(millisecond),
    ?assert(Timestamp > 0),
    ?assert(Timestamp =< Now + 1000).

%% ============================================================================
%% Timestamp Tests (Critical for v7)
%% ============================================================================

v7_timestamp_ordering_test() ->
    UUID1 = alara_uuid:v7(),
    timer:sleep(10), %% 10ms delay
    UUID2 = alara_uuid:v7(),
    
    %% UUID2 should be greater than UUID1 (lexicographic order)
    ?assert(UUID2 > UUID1).

v7_timestamp_monotonic_test() ->
    UUIDs = [begin
        U = alara_uuid:v7(),
        timer:sleep(1),
        U
    end || _ <- lists:seq(1, 10)],
    
    %% Check all UUIDs are in increasing order
    Sorted = lists:sort(UUIDs),
    ?assertEqual(Sorted, UUIDs).

v7_timestamp_extraction_test() ->
    BeforeGen = erlang:system_time(millisecond),
    UUID = alara_uuid:v7(),
    AfterGen = erlang:system_time(millisecond),
    
    %% Extract timestamp from UUID
    <<Timestamp:48, _:80>> = UUID,
    
    %% Timestamp should be between before and after
    ?assert(Timestamp >= BeforeGen),
    ?assert(Timestamp =< AfterGen).

v7_timestamp_precision_test() ->
    %% Generate multiple UUIDs quickly
    Start = erlang:system_time(millisecond),
    UUIDs = alara_uuid:v7(5),
    End = erlang:system_time(millisecond),
    
    %% Extract all timestamps
    Timestamps = [begin
        <<T:48, _:80>> = U,
        T
    end || U <- UUIDs],
    
    %% All timestamps should be within the generation window
    ?assert(lists:all(fun(T) -> T >= Start andalso T =< End end, Timestamps)).

%% ============================================================================
%% Sortability Tests (Key feature of v7)
%% ============================================================================

v7_natural_sort_test() ->
    %% Generate UUIDs with delays
    UUIDs = [begin
        U = alara_uuid:v7(),
        timer:sleep(2),
        U
    end || _ <- lists:seq(1, 5)],
    
    %% Sort using Erlang's natural binary comparison
    Sorted = lists:sort(UUIDs),
    
    %% Should already be sorted (chronological = lexicographic)
    ?assertEqual(UUIDs, Sorted).

v7_string_sort_test() ->
    %% Generate UUIDs with delays
    UUIDs = [begin
        U = alara_uuid:v7(),
        timer:sleep(2),
        U
    end || _ <- lists:seq(1, 5)],
    
    %% Convert to strings and sort
    Strings = [alara_uuid:to_string(U) || U <- UUIDs],
    SortedStrings = lists:sort(Strings),
    
    %% Should already be sorted
    ?assertEqual(Strings, SortedStrings).

%% ============================================================================
%% String Formatting Tests
%% ============================================================================

v7_to_string_standard_format_test() ->
    UUID = alara_uuid:v7(),
    Str = alara_uuid:to_string(UUID),
    
    %% Check format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    ?assertEqual(36, length(Str)),
    ?assertEqual($-, lists:nth(9, Str)),
    ?assertEqual($-, lists:nth(14, Str)),
    ?assertEqual($-, lists:nth(19, Str)),
    ?assertEqual($-, lists:nth(24, Str)),
    
    %% Check version appears in string (at position 15, should be '7')
    ?assertEqual($7, lists:nth(15, Str)).

v7_to_string_hex_format_test() ->
    UUID = alara_uuid:v7(),
    Hex = alara_uuid:to_string(UUID, "hex"),
    
    %% Check format: no hyphens, 32 hex chars
    ?assertEqual(32, length(Hex)),
    ?assert(lists:all(fun(C) -> 
        (C >= $0 andalso C =< $9) orelse 
        (C >= $a andalso C =< $f)
    end, Hex)).

v7_to_string_urn_format_test() ->
    UUID = alara_uuid:v7(),
    URN = alara_uuid:to_string(UUID, "urn"),
    
    %% Check URN prefix
    ?assertEqual("urn:uuid:", lists:sublist(URN, 9)),
    ?assertEqual(45, length(URN)).

%% ============================================================================
%% ALARA Entropy Tests
%% ============================================================================

v7_uses_alara_entropy_test() ->
    %% Generate multiple UUIDs and check random parts are truly random
    UUIDs = alara_uuid:v7(100),
    
    %% Extract random bits (everything after timestamp and version)
    RandomParts = [begin
        <<_:48, _:4, RandA:12, _:2, RandB:62>> = U,
        <<RandA:12, RandB:62>>
    end || U <- UUIDs],
    
    %% All random parts should be different
    ?assertEqual(100, length(lists:usort(RandomParts))).

v7_random_distribution_test() ->
    %% Check that random bits have reasonable distribution
    UUIDs = alara_uuid:v7(1000),
    
    %% Extract first random byte from each UUID
    RandomBytes = [begin
        <<_:48, _:4, FirstRandByte:8, _:68>> = U,
        FirstRandByte
    end || U <- UUIDs],
    
    %% Calculate distribution (should be roughly uniform)
    %% Each of 256 values should appear roughly 1000/256 ≈ 4 times
    %% We'll be lenient: each should appear at least once in 1000 samples
    UniqueValues = length(lists:usort(RandomBytes)),
    ?assert(UniqueValues > 200). %% At least 200 of 256 possible values

%% ============================================================================
%% Performance Tests
%% ============================================================================

v7_generation_performance_test_() ->
    {timeout, 10, fun() ->
        Start = erlang:monotonic_time(millisecond),
        _ = alara_uuid:v7(1000),
        End = erlang:monotonic_time(millisecond),
        Duration = End - Start,
        
        %% Should generate 1000 UUIDs in less than 5 seconds
        ?assert(Duration < 5000)
    end}.

v7_single_generation_speed_test() ->
    Iterations = 100,
    Start = erlang:monotonic_time(microsecond),
    _ = [alara_uuid:v7() || _ <- lists:seq(1, Iterations)],
    End = erlang:monotonic_time(microsecond),
    
    Duration = End - Start,
    AvgPerUUID = Duration / Iterations,
    
    %% Each UUID should take less than 1ms on average
    ?assert(AvgPerUUID < 1000).

%% ============================================================================
%% Edge Cases
%% ============================================================================

v7_zero_batch_test() ->
    %% Edge case: requesting 0 UUIDs
    ?assertError(function_clause, alara_uuid:v7(0)).

v7_negative_batch_test() ->
    %% Edge case: negative count
    ?assertError(function_clause, alara_uuid:v7(-1)).

%% ============================================================================
%% Comparison with v5
%% ============================================================================

v7_vs_v5_version_test() ->
    UUID_v7 = alara_uuid:v7(),
    UUID_v5 = alara_uuid:v5(dns, "test.com"),
    
    <<_:48, V7:4, _:76>> = UUID_v7,
    <<_:48, V5:4, _:76>> = UUID_v5,
    
    ?assertEqual(7, V7),
    ?assertEqual(5, V5).

v7_vs_v5_uniqueness_test() ->
    %% v7 should always be different
    UUID_v7_1 = alara_uuid:v7(),
    UUID_v7_2 = alara_uuid:v7(),
    ?assertNotEqual(UUID_v7_1, UUID_v7_2),
    
    %% v5 should be same for same input
    UUID_v5_1 = alara_uuid:v5(dns, "test.com"),
    UUID_v5_2 = alara_uuid:v5(dns, "test.com"),
    ?assertEqual(UUID_v5_1, UUID_v5_2).

%% ============================================================================
%% Integration Tests
%% ============================================================================

v7_mixed_operations_test() ->
    %% Generate UUIDs, convert to strings, verify they maintain order
    UUIDs = [begin
        timer:sleep(2),
        alara_uuid:v7()
    end || _ <- lists:seq(1, 5)],
    
    Strings = [alara_uuid:to_string(U) || U <- UUIDs],
    
    %% Both binary and string representations should be sorted
    ?assertEqual(UUIDs, lists:sort(UUIDs)),
    ?assertEqual(Strings, lists:sort(Strings)).

v7_all_formats_test() ->
    UUID = alara_uuid:v7(),
    
    Standard = alara_uuid:to_string(UUID),
    Hex = alara_uuid:to_string(UUID, "hex"),
    URN = alara_uuid:to_string(UUID, "urn"),
    
    %% All should represent the same UUID
    %% Version '7' should appear in standard format
    ?assertEqual($7, lists:nth(15, Standard)),
    
    %% All formats should be different strings
    ?assertNotEqual(Standard, Hex),
    ?assertNotEqual(Standard, URN),
    ?assertNotEqual(Hex, URN).
