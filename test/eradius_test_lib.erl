%% Copyright (c) 2010-2017, Travelping GmbH <info@travelping.com>
%%
%% SPDX-License-Identifier: MIT
%%
-module(eradius_test_lib).

-compile([export_all, nowarn_export_all]).

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

badhost(Family)
  when Family =:= ipv4; Family =:= ipv4_mapped_ipv6 ->
    {127, 0, 0, 2};
badhost(ipv6) ->
    {0, 0, 0, 0, 0, 0, 0, 2}.

localhost(Type) ->
    localhost(ipv4, Type).

localhost(Family, string) when Family =:= ipv4; Family =:= ipv4_mapped_ipv6 ->
    "ip4-loopback";
localhost(ipv6, string) ->
    "ip6-loopback";
localhost(Family, binary) ->
    list_to_binary(localhost(Family, string));
localhost(Family, tuple) when Family =:= ipv4; Family =:= ipv4_mapped_ipv6 ->
    {ok, IP} = inet:getaddr(localhost(ipv4, string), inet),
    IP;
localhost(ipv6, tuple) ->
    {ok, IP} = inet:getaddr(localhost(ipv6, string), inet6),
    IP;
localhost(Family, ip) ->
    inet:ntoa(localhost(Family, tuple));
localhost(Family, atom) ->
    list_to_atom(localhost(Family, ip)).
