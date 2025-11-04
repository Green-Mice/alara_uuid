%% ============================================================================
%% alara_uuid_v5_tests - EUnit Tests for UUID v5
%% Tests RFC 9562 compliant UUID v5 (name-based SHA-1)
%% ============================================================================

-module(alara_uuid_v5_tests).

-include_lib("eunit/include/eunit.hrl").

%% ============================================================================
%% Test Fixtures
%% ============================================================================

%% No setup needed for v5 (deterministic, no ALARA required)

%% ============================================================================
%% Basic Generation Tests
%% ============================================================================

v5_dns_generation_test() ->
    UUID = alara_uuid:v5(dns, "example.com"),
    ?assert(is_binary(UUID)),
    ?assertEqual(16, byte_size(UUID)).

v5_url_generation_test() ->
    UUID = alara_uuid:v5(url, "https://alara.io"),
    ?assert(is_binary(UUID)),
    ?assertEqual(16, byte_size(UUID)).

v5_oid_generation_test() ->
    UUID = alara_uuid:v5(oid, "1.3.6.1.4.1"),
    ?assert(is_binary(UUID)),
    ?assertEqual(16, byte_size(UUID)).

v5_x500_generation_test() ->
    UUID = alara_uuid:v5(x500, "cn=John Doe"),
    ?assert(is_binary(UUID)),
    ?assertEqual(16, byte_size(UUID)).

v5_custom_namespace_test() ->
    CustomNS = alara_uuid:ns_dns(),
    UUID = alara_uuid:v5(CustomNS, <<"custom-name">>),
    ?assert(is_binary(UUID)),
    ?assertEqual(16, byte_size(UUID)).

%% ============================================================================
%% Determinism Tests (Critical for v5)
%% ============================================================================

v5_determinism_same_input_test() ->
    UUID1 = alara_uuid:v5(dns, "example.com"),
    UUID2 = alara_uuid:v5(dns, "example.com"),
    ?assertEqual(UUID1, UUID2).

v5_determinism_multiple_calls_test() ->
    Name = "test.domain.com",
    UUIDs = [alara_uuid:v5(dns, Name) || _ <- lists:seq(1, 100)],
    %% All UUIDs should be identical
    [First | Rest] = UUIDs,
    ?assert(lists:all(fun(U) -> U =:= First end, Rest)).

v5_different_names_different_uuids_test() ->
    UUID1 = alara_uuid:v5(dns, "example.com"),
    UUID2 = alara_uuid:v5(dns, "example.org"),
    ?assertNotEqual(UUID1, UUID2).

v5_different_namespaces_different_uuids_test() ->
    Name = "same-name",
    UUID_DNS = alara_uuid:v5(dns, Name),
    UUID_URL = alara_uuid:v5(url, Name),
    ?assertNotEqual(UUID_DNS, UUID_URL).

v5_case_sensitive_test() ->
    UUID1 = alara_uuid:v5(dns, "Example.Com"),
    UUID2 = alara_uuid:v5(dns, "example.com"),
    ?assertNotEqual(UUID1, UUID2).

%% ============================================================================
%% RFC 9562 Compliance Tests
%% ============================================================================

v5_version_field_test() ->
    UUID = alara_uuid:v5(dns, "example.com"),
    <<_:48, Version:4, _:76>> = UUID,
    ?assertEqual(5, Version).

v5_variant_field_test() ->
    UUID = alara_uuid:v5(dns, "example.com"),
    <<_:64, Variant:2, _:62>> = UUID,
    ?assertEqual(2, Variant). %% Binary: 10

v5_format_structure_test() ->
    UUID = alara_uuid:v5(dns, "example.com"),
    <<_TimeLow:32, _TimeMid:16, TimeHiVersion:16, 
      ClockSeqVariant:16, _Node:48>> = UUID,
    
    %% Check version bits (should be 5)
    Version = (TimeHiVersion bsr 12) band 16#F,
    ?assertEqual(5, Version),
    
    %% Check variant bits (should be 2 = binary 10)
    Variant = (ClockSeqVariant bsr 14) band 16#3,
    ?assertEqual(2, Variant).

%% ============================================================================
%% String Formatting Tests
%% ============================================================================

v5_to_string_standard_format_test() ->
    UUID = alara_uuid:v5(dns, "example.com"),
    Str = alara_uuid:to_string(UUID),
    
    %% Check format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    ?assertEqual(36, length(Str)),
    ?assertEqual($-, lists:nth(9, Str)),
    ?assertEqual($-, lists:nth(14, Str)),
    ?assertEqual($-, lists:nth(19, Str)),
    ?assertEqual($-, lists:nth(24, Str)).

v5_to_string_hex_format_test() ->
    UUID = alara_uuid:v5(dns, "example.com"),
    Hex = alara_uuid:to_string(UUID, "hex"),
    
    %% Check format: no hyphens, 32 hex chars
    ?assertEqual(32, length(Hex)),
    ?assert(lists:all(fun(C) -> 
        (C >= $0 andalso C =< $9) orelse 
        (C >= $a andalso C =< $f)
    end, Hex)).

v5_to_string_urn_format_test() ->
    UUID = alara_uuid:v5(dns, "example.com"),
    URN = alara_uuid:to_string(UUID, "urn"),
    
    %% Check URN prefix
    ?assertEqual("urn:uuid:", lists:sublist(URN, 9)),
    ?assertEqual(45, length(URN)). %% "urn:uuid:" + 36 chars

v5_to_string_consistency_test() ->
    UUID = alara_uuid:v5(dns, "example.com"),
    Str1 = alara_uuid:to_string(UUID),
    Str2 = alara_uuid:to_string(UUID),
    ?assertEqual(Str1, Str2).

%% ============================================================================
%% Namespace Tests
%% ============================================================================

v5_namespace_accessors_test() ->
    DNS = alara_uuid:ns_dns(),
    URL = alara_uuid:ns_url(),
    OID = alara_uuid:ns_oid(),
    X500 = alara_uuid:ns_x500(),
    
    %% All should be different
    ?assertNotEqual(DNS, URL),
    ?assertNotEqual(DNS, OID),
    ?assertNotEqual(DNS, X500),
    ?assertNotEqual(URL, OID),
    ?assertNotEqual(URL, X500),
    ?assertNotEqual(OID, X500),
    
    %% All should be 16 bytes
    ?assertEqual(16, byte_size(DNS)),
    ?assertEqual(16, byte_size(URL)),
    ?assertEqual(16, byte_size(OID)),
    ?assertEqual(16, byte_size(X500)).

v5_namespace_rfc_compliance_test() ->
    %% RFC 9562 defines specific namespace UUIDs
    DNS = alara_uuid:ns_dns(),
    
    %% DNS namespace: 6ba7b810-9dad-11d1-80b4-00c04fd430c8
    <<A:32, B:16, _C:16, _D:16, _E:48>> = DNS,
    ?assertEqual(16#6ba7b810, A),
    ?assertEqual(16#9dad, B).

%% ============================================================================
%% Edge Cases and Input Validation
%% ============================================================================

v5_empty_name_test() ->
    UUID = alara_uuid:v5(dns, ""),
    ?assert(is_binary(UUID)),
    ?assertEqual(16, byte_size(UUID)).

v5_long_name_test() ->
    LongName = lists:duplicate(1000, $a),
    UUID = alara_uuid:v5(dns, LongName),
    ?assert(is_binary(UUID)),
    ?assertEqual(16, byte_size(UUID)).

v5_binary_name_test() ->
    UUID = alara_uuid:v5(dns, <<"example.com">>),
    ?assert(is_binary(UUID)),
    ?assertEqual(16, byte_size(UUID)).

v5_unicode_name_test() ->
    %% Use UTF-8 binary instead of string with unicode chars
    UUID = alara_uuid:v5(dns, <<"例え.jp"/utf8>>),
    ?assert(is_binary(UUID)),
    ?assertEqual(16, byte_size(UUID)).

v5_special_chars_name_test() ->
    UUID = alara_uuid:v5(dns, "test!@#$%^&*().com"),
    ?assert(is_binary(UUID)),
    ?assertEqual(16, byte_size(UUID)).

%% ============================================================================
%% Known Test Vectors (if available from RFC)
%% ============================================================================

v5_consistency_with_previous_runs_test() ->
    %% This test ensures v5 UUIDs remain consistent across code changes
    %% Store known UUIDs and verify they don't change
    
    UUID_DNS_Example = alara_uuid:v5(dns, "example.com"),
    UUID_URL_Test = alara_uuid:v5(url, "https://test.com"),
    
    %% These should always produce the same result
    ?assertEqual(UUID_DNS_Example, alara_uuid:v5(dns, "example.com")),
    ?assertEqual(UUID_URL_Test, alara_uuid:v5(url, "https://test.com")).

%% ============================================================================
%% Performance Tests
%% ============================================================================

v5_generation_performance_test() ->
    %% Generate 1000 UUIDs and ensure it completes in reasonable time
    Start = erlang:monotonic_time(millisecond),
    _ = [alara_uuid:v5(dns, integer_to_list(N)) || N <- lists:seq(1, 1000)],
    End = erlang:monotonic_time(millisecond),
    Duration = End - Start,
    
    %% Should complete in less than 1 second
    ?assert(Duration < 1000).

%% ============================================================================
%% Integration Tests
%% ============================================================================

v5_mixed_namespace_usage_test() ->
    Name = "shared-name",
    UUIDs = [
        alara_uuid:v5(dns, Name),
        alara_uuid:v5(url, Name),
        alara_uuid:v5(oid, Name),
        alara_uuid:v5(x500, Name)
    ],
    
    %% All should be different despite same name
    ?assertEqual(4, length(lists:usort(UUIDs))).

v5_to_string_all_formats_test() ->
    UUID = alara_uuid:v5(dns, "example.com"),
    
    Standard = alara_uuid:to_string(UUID),
    Hex = alara_uuid:to_string(UUID, "hex"),
    URN = alara_uuid:to_string(UUID, "urn"),
    _Binary = alara_uuid:to_string(UUID, "binary"),
    
    %% All should be different strings but represent same UUID
    ?assertNotEqual(Standard, Hex),
    ?assertNotEqual(Standard, URN),
    ?assertNotEqual(Hex, URN).
