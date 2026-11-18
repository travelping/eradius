%% Copyright (c) 2010-2017, Travelping GmbH <info@travelping.com>
%%
%% SPDX-License-Identifier: MIT
%%
-module(eradius_test_lib).

-compile([export_all, nowarn_export_all]).

-define(IP4_LOOPBACK, {127, 0, 0, 1}).
-define(IP6_LOOPBACK, {0, 0, 0, 0, 0, 0, 0, 1}).

%%%===================================================================
%%% Helper functions
%%%===================================================================

has_ipv6_test_config() ->
    try
        {ok, IfList} = inet:getifaddrs(),
        Lo = proplists:get_value("lo", IfList),
        V6 = [X || {addr, X = {0,0,0,0,0,0,0,1}} <- Lo],
        ct:pal("V6: ~p", [V6]),
        length(V6) > 0
    catch
        _:_ ->
            false
    end.

inet_family(ipv4) -> inet;
inet_family(ipv6) -> inet6;
inet_family(ipv4_mapped_ipv6) -> inet6.

localhost(ipv4, _) ->
    ?IP4_LOOPBACK;
localhost(ipv6, _) ->
    ?IP6_LOOPBACK;
localhost(ipv4_mapped_ipv6, native) ->
    ?IP4_LOOPBACK;
localhost(ipv4_mapped_ipv6, mapped) ->
    inet:ipv4_mapped_ipv6_address(?IP4_LOOPBACK).
