%% Copyright (c) 2010-2017, Travelping GmbH <info@travelping.com>
%%
%% SPDX-License-Identifier: MIT
%%
-module(eradius_client_SUITE).

-compile([export_all, nowarn_export_all]).

-behaviour(ct_suite).

-include("test/eradius_test.hrl").

%%%===================================================================
%%% Defines
%%%===================================================================

-define(SERVER, eradius_test_handler).
-define(HUT_SOCKET, eradius_client_socket).

-define(BAD_SERVER_INITIAL_RETRIES, 3).
-define(BAD_SERVER_TUPLE_INITIAL(Family),
        {{eradius_test_lib:localhost(Family, mapped), 1920},
         ?BAD_SERVER_INITIAL_RETRIES, 0}).
-define(BAD_SERVER_TUPLE(Family),
        {{eradius_test_lib:localhost(Family, mapped), 1920},
         ?BAD_SERVER_INITIAL_RETRIES, 1}).

-define(GOOD_SERVER_INITIAL_RETRIES, 3).
-define(GOOD_SERVER_TUPLE(Family),
        {{eradius_test_lib:localhost(Family, mapped), 1812},
         ?GOOD_SERVER_INITIAL_RETRIES, 0}).
-define(GOOD_SERVER_2_TUPLE(Family),
        {{eradius_test_lib:localhost(Family, mapped), 1813},
         ?GOOD_SERVER_INITIAL_RETRIES, 0}).

-define(RADIUS_SERVERS(Family),
        [?GOOD_SERVER_TUPLE(Family),
         ?BAD_SERVER_TUPLE_INITIAL(Family),
         ?GOOD_SERVER_2_TUPLE(Family)]).

%%%===================================================================
%%% Setup
%%%===================================================================

-spec all() -> [ct_suite:ct_test_def(), ...].
all() ->
    [{group, ipv4},
     {group, ipv4_mapped_ipv6},
     {group, ipv6}].

common() ->
    [send_request,
     wanna_send,
     reconf_address,
     wanna_send,
     reconf_ports_30,
     wanna_send,
     reconf_ports_10,
     wanna_send,
     send_request_failover,
     check_upstream_servers,
     clobber_does_not_hang,
     connected_socket_matches_reply,
     retire_holds_then_closes,
     retire_waits_for_pending,
     client_config_defaults,
     pool_rolls_and_retires,
     pool_cap_backpressures,
     cooling_socket_reclaimed
    ].

-spec groups() -> [ct_suite:ct_group_def(), ...].
groups() ->
    SocketGroups = [{group, inet}, {group, socket}],
    [{inet, [], common()},
     {socket, [], common()},
     {ipv4, [], SocketGroups},
     {ipv4_mapped_ipv6, [], SocketGroups},
     {ipv6, [], SocketGroups}].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(eradius),
    logger:set_primary_config(level, debug),
    Config.

end_per_suite(_Config) ->
    application:stop(eradius),
    ok.

init_per_group(inet, Config) ->
    [{inet_backend, inet} | Config];
init_per_group(socket, Config) ->
    [{inet_backend, socket} | Config];
init_per_group(ipv6 = Group, Config) ->
    %% {skip, "no IPv6 server support (yet)"};
    case eradius_test_lib:has_ipv6_test_config() of
        true ->
            [{family, Group} | Config];
        _ ->
            {skip, "IPv6 test IPs not configured"}
    end;
init_per_group(ipv4_mapped_ipv6 = Group, Config) ->
    case eradius_test_lib:has_ipv6_test_config() of
        true ->
            [{family, Group} | Config];
        _ ->
            {skip, "IPv6 test IPs not configured"}
    end;
init_per_group(ipv4 = Group, Config) ->
    [{family, Group} | Config].

end_per_group(_Group, _Config) ->
    application:stop(eradius),
    ok.

start_handler(Config) ->
    Backend = proplists:get_value(inet_backend, Config, inet),
    Family = proplists:get_value(family, Config),
    eradius_test_handler:start(Backend, Family).

start_client(Config) ->
    Backend = proplists:get_value(inet_backend, Config, inet),
    Family = proplists:get_value(family, Config),
    eradius_test_handler:start_client(Backend, Family).

init_per_testcase(send_request, Config) ->
    start_handler(Config),
    Config;
init_per_testcase(send_request_failover, Config) ->
    start_handler(Config),
    Config;
init_per_testcase(check_upstream_servers, Config) ->
    start_handler(Config),
    Config;
init_per_testcase(wanna_send, Config) ->
    start_client(Config),
    %% The named client persists across the group; a preceding reconf_address
    %% may have left it bound to a non-existent IP. Restore a usable client_ip
    %% and the default port count so socket opens succeed.
    Family = proplists:get_value(family, Config),
    ok = eradius_client_mngr:reconfigure(
           ?SERVER, #{ip => eradius_test_lib:localhost(Family, native),
                      no_ports => 10}),
    Config;
init_per_testcase(_Test, Config) ->
    Config.

end_per_testcase(send_request, Config) ->
    eradius_test_handler:stop(),
    Config;
end_per_testcase(send_request_failover, Config) ->
    eradius_test_handler:stop(),
    Config;
end_per_testcase(check_upstream_servers, Config) ->
    eradius_test_handler:stop(),
    Config;
end_per_testcase(_Test, Config) ->
    Config.

%% TESTS

send_request(_Config) ->
    ?equal(accept, eradius_test_handler:send_request(one)),
    ok.

%% true iff every pool keeps at most K active fillers (family-agnostic).
all_pools_within_k(St, K) ->
    lists:all(fun(#{active := A}) -> length(A) =< K end,
              maps:values(maps:get(pools, St))).

wanna_send(_Config) ->
    %% Allocations stay within K active fillers per server. Server `one`
    %% is configured by eradius_test_handler:start_client/2 at port 1812.
    K = 10,
    lists:foreach(
      fun(_) ->
              {ok, {_Pid, _Id, one, _S, _I}} =
                  eradius_client_mngr:wanna_send(?SERVER, [one], [])
      end, lists:seq(1, 50)),
    St = eradius_client_mngr:get_state(?SERVER),
    ?equal(true, all_pools_within_k(St, K)),
    ok.

reconf_address(Config) ->
    IP = case proplists:get_value(family, Config) of
             ipv4 -> {7, 13, 23, 42};
             ipv4_mapped_ipv6 -> inet:ipv4_mapped_ipv6_address({7, 13, 23, 42});
             ipv6 -> {16#fd96, 16#dcd2, 16#efdb, 16#41c3, 0, 0, 16#100, 1}
         end,
    {ok, _} = eradius_client_mngr:wanna_send(?SERVER, [one], []),
    ok = eradius_client_mngr:reconfigure(?SERVER, #{ip => IP}),
    timer:sleep(100),
    St = eradius_client_mngr:get_state(?SERVER),
    ?equal(#{}, maps:get(pools, St)),
    ok.

reconf_ports_30(_Config) ->
    ok = eradius_client_mngr:reconfigure(?SERVER, #{no_ports => 30}),
    St = eradius_client_mngr:get_state(?SERVER),
    ?equal(30, maps:get(k_ports, St)),
    ok.

reconf_ports_10(_Config) ->
    ok = eradius_client_mngr:reconfigure(?SERVER, #{no_ports => 10}),
    St = eradius_client_mngr:get_state(?SERVER),
    ?equal(10, maps:get(k_ports, St)),
    ok.

send_request_failover(Config) ->
    Family = proplists:get_value(family, Config),
    ?equal(accept, eradius_test_handler:send_request_failover(bad)),
    {ok, Timeout} = application:get_env(eradius, unreachable_timeout),
    timer:sleep(Timeout * 1000),
    ?equal(?BAD_SERVER_TUPLE(Family), eradius_client_mngr:server(?SERVER, bad)),
    ok.

check_upstream_servers(Config) ->
    Family = proplists:get_value(family, Config),
    Servers = eradius_client_mngr:servers(?SERVER),
    ct:pal("Servers: ~p~nExpected: ~p", [Servers, ?RADIUS_SERVERS(Family)]),
    ?equal(true,
           sets:is_subset(sets:from_list(?RADIUS_SERVERS(Family)),
                          sets:from_list(Servers))),
    ok.

clobber_does_not_hang() ->
    [{doc, "A pending request whose entry is overwritten by a same-ReqId "
      "request must still return {error,timeout} to its caller, not hang"}].
clobber_does_not_hang(Config) ->
    Family = proplists:get_value(family, Config, ipv4),
    InetFamily = eradius_test_lib:inet_family(Family),
    LH = eradius_test_lib:localhost(Family, native),
    BindIP = eradius_test_lib:localhost(Family, mapped),
    %% black-hole server: a real UDP socket that never replies, so the connected
    %% client socket sees a listener (no ICMP econnrefused) and the clobber is exercised.
    {ok, BH} = gen_udp:open(0, [binary, {active, false}, InetFamily, {ip, BindIP}]),
    {ok, BHPort} = inet:port(BH),
    Peer = {LH, BHPort},
    {ok, Sock} = eradius_client_socket:start_link(
                   #{family => InetFamily, active_n => 10, server_addr => Peer,
                     reqid_reuse_timeout => 30000}),
    ReqId = 1,
    Packet = <<1, ReqId, 0, 20, 0:128>>,   %% 20-byte minimal RADIUS header
    Caller = self(),
    %% First caller: stays pending (2 s socket-side timeout)
    P1 = spawn(fun() ->
                       R = eradius_client_socket:send_request(
                             Sock, Peer, ReqId, Packet, 2000),
                       Caller ! {p1, R}
               end),
    timer:sleep(200),
    %% Second caller: SAME ReqId -> overwrites P1's pending entry
    spawn(fun() ->
                  eradius_client_socket:send_request(Sock, Peer, ReqId, Packet, 2000)
          end),
    %% P1 must not hang; with the bounded call timeout it gets {error,timeout}
    Result =
        receive
            {p1, R} -> R
        after 6000 ->
                exit(P1, kill),
                ct:fail("P1 hung after its pending entry was clobbered")
        end,
    gen_udp:close(BH),
    eradius_client_socket:close(Sock),
    ?equal({error, timeout}, Result).

connected_socket_matches_reply() ->
    [{doc, "A connected socket sends without an explicit dest and matches a "
      "reply to the pending request by ReqId alone"}].
connected_socket_matches_reply(Config) ->
    Family = proplists:get_value(family, Config, ipv4),
    InetFamily = eradius_test_lib:inet_family(Family),
    LH = eradius_test_lib:localhost(Family, native),
    BindIP = eradius_test_lib:localhost(Family, mapped),
    {ok, Server} = gen_udp:open(0, [binary, {active, false}, InetFamily, {ip, BindIP}]),
    {ok, SrvPort} = inet:port(Server),
    {ok, Sock} = eradius_client_socket:start_link(
                   #{family => InetFamily, active_n => 10,
                     server_addr => {LH, SrvPort}, reqid_reuse_timeout => 30000}),
    ReqId = 7,
    Req = <<1, ReqId, 0, 20, 0:128>>,
    Caller = self(),
    spawn(fun() ->
                  R = eradius_client_socket:send_request(
                        Sock, {LH, SrvPort}, ReqId, Req, 3000),
                  Caller ! {done, R}
          end),
    {ok, {FromIP, FromPort, <<_, ReqId, _/binary>>}} = gen_udp:recv(Server, 0, 2000),
    Reply = <<2, ReqId, 0, 20, 1:128>>,
    ok = gen_udp:send(Server, FromIP, FromPort, Reply),
    receive
        {done, Result} ->
            ?match({ok, <<2, ReqId, _/binary>>, <<>>}, Result)
    after 4000 ->
            ct:fail("connected socket did not deliver the reply")
    end,
    gen_udp:close(Server).

retire_holds_then_closes() ->
    [{doc, "A retired socket with no pending requests stays alive during the "
      "cooldown and exits normally once it elapses"}].
retire_holds_then_closes(Config) ->
    Family = proplists:get_value(family, Config, ipv4),
    InetFamily = eradius_test_lib:inet_family(Family),
    LH = eradius_test_lib:localhost(Family, native),
    {ok, Sock} = eradius_client_socket:start_link(
                   #{family => InetFamily, active_n => 10,
                     server_addr => {LH, 1}, reqid_reuse_timeout => 700}),
    MRef = erlang:monitor(process, Sock),
    eradius_client_socket:retire(Sock),
    timer:sleep(300),
    ?equal(true, is_process_alive(Sock)),
    receive
        {'DOWN', MRef, process, Sock, Reason} ->
            ?equal(normal, Reason)
    after 2000 ->
            ct:fail("retired socket did not close after cooldown")
    end.

retire_waits_for_pending() ->
    [{doc, "A retired socket does not close while a request is still pending; "
      "it closes after the pending request resolves and cooldown elapsed"}].
retire_waits_for_pending(Config) ->
    Family = proplists:get_value(family, Config, ipv4),
    InetFamily = eradius_test_lib:inet_family(Family),
    LH = eradius_test_lib:localhost(Family, native),
    BindIP = eradius_test_lib:localhost(Family, mapped),
    %% black-hole server (real listener, never replies): avoids ICMP econnrefused.
    {ok, BH} = gen_udp:open(0, [binary, {active, false}, InetFamily, {ip, BindIP}]),
    {ok, BHPort} = inet:port(BH),
    Peer = {LH, BHPort},
    %% cooldown 1500ms; force-close at 2x = 3000ms. Retire first so the cooldown
    %% starts at t=0, then send a request whose 2500ms timeout resolves between
    %% the cooldown (1500ms) and the force-close (3000ms): the close is driven by
    %% pending-drain, with comfortable margins around the 1800ms alive-check.
    {ok, Sock} = eradius_client_socket:start_link(
                   #{family => InetFamily, active_n => 10,
                     server_addr => Peer, reqid_reuse_timeout => 1500}),
    MRef = erlang:monitor(process, Sock),
    Caller = self(),
    eradius_client_socket:retire(Sock),
    spawn(fun() ->
                  R = eradius_client_socket:send_request(
                        Sock, Peer, 3, <<1, 3, 0, 20, 0:128>>, 2500),
                  Caller ! {p, R}
          end),
    %% at ~1800ms the cooldown has elapsed but the request is still pending -> alive
    timer:sleep(1800),
    ?equal(true, is_process_alive(Sock)),
    receive {p, {error, timeout}} -> ok after 4000 -> ct:fail("request never resolved") end,
    receive
        {'DOWN', MRef, process, Sock, normal} -> ok
    after 4000 ->
            ct:fail("retired socket did not close after pending drained")
    end,
    gen_udp:close(BH).

client_config_defaults() ->
    [{doc, "new client config carries no_ports (K), max_ports and "
      "reqid_reuse_timeout with sane defaults"}].
client_config_defaults(Config) ->
    Family = proplists:get_value(family, Config, ipv4),
    {ok, _} = application:ensure_all_started(eradius),
    Server = #{ip => eradius_test_lib:localhost(Family, native), port => 1812,
               secret => <<"secret">>, retries => 3},
    {ok, Client} =
        eradius_client_mngr:start_client(
          #{family => eradius_test_lib:inet_family(Family), ip => any,
            servers => #{test_server => Server}}),
    St = eradius_client_mngr:get_state(Client),
    ?equal(10, maps:get(k_ports, St)),
    ?equal(256, maps:get(max_ports, St)),
    ?equal(30000, maps:get(reqid_reuse_timeout, St)),
    ok.

pool_rolls_and_retires() ->
    [{doc, "with no_ports=1 the single filler issues ids 0..255 then rolls to a "
      "fresh socket on the 257th send; the exhausted socket is retired"}].
pool_rolls_and_retires(Config) ->
    Family = proplists:get_value(family, Config, ipv4),
    {ok, _} = application:ensure_all_started(eradius),
    Server = #{ip => eradius_test_lib:localhost(Family, native), port => 1812,
               secret => <<"secret">>, retries => 3},
    {ok, Client} =
        eradius_client_mngr:start_client(
          #{family => eradius_test_lib:inet_family(Family), ip => any,
            no_ports => 1, reqid_reuse_timeout => 30000,
            servers => #{test_server => Server}}),
    Allocs =
        [begin
             {ok, {Pid, ReqId, test_server, _Srv, _Info}} =
                 eradius_client_mngr:wanna_send(Client, [test_server], []),
             {Pid, ReqId}
         end || _ <- lists:seq(1, 257)],
    {Pids, Ids} = lists:unzip(Allocs),
    ?equal(lists:seq(0, 255) ++ [0], Ids),
    First256 = lists:sublist(Pids, 256),
    ?equal(1, length(lists:usort(First256))),
    Socket257 = lists:nth(257, Pids),
    ?equal(false, lists:member(Socket257, First256)),
    ?equal(2, length(lists:usort(Pids))),
    %% the retired socket was told to retire but is still alive (cooling, 30s)
    ?equal(true, is_process_alive(hd(First256))),
    ok.

pool_cap_backpressures() ->
    [{doc, "with no_ports=1 and max_ports_per_server=2, once both sockets are "
      "exhausted-and-cooling wanna_send returns {error, no_ports}"}].
pool_cap_backpressures(Config) ->
    Family = proplists:get_value(family, Config, ipv4),
    {ok, _} = application:ensure_all_started(eradius),
    Server = #{ip => eradius_test_lib:localhost(Family, native), port => 1812,
               secret => <<"secret">>, retries => 3},
    {ok, Client} =
        eradius_client_mngr:start_client(
          #{family => eradius_test_lib:inet_family(Family), ip => any,
            no_ports => 1, max_ports_per_server => 2,
            reqid_reuse_timeout => 60000,    %% long: cooling sockets stay open
            servers => #{test_server => Server}}),
    %% 512 allocations exhaust 2 sockets (256 ids each); both go to cooling and
    %% cannot be replaced (cap = 2). The 513th allocation must be rejected.
    ok = lists:foreach(
           fun(_) ->
                   {ok, {_Pid, _Id, test_server, _S, _I}} =
                       eradius_client_mngr:wanna_send(Client, [test_server], [])
           end, lists:seq(1, 512)),
    ?equal({error, no_ports},
           eradius_client_mngr:wanna_send(Client, [test_server], [])),
    ok.

cooling_socket_reclaimed() ->
    [{doc, "after a retired socket finishes its cooldown and exits, the manager "
      "drops it from the pool (cooling shrinks back to empty)"}].
cooling_socket_reclaimed(Config) ->
    Family = proplists:get_value(family, Config, ipv4),
    {ok, _} = application:ensure_all_started(eradius),
    Server = #{ip => eradius_test_lib:localhost(Family, native), port => 1812,
               secret => <<"secret">>, retries => 3},
    {ok, Client} =
        eradius_client_mngr:start_client(
          #{family => eradius_test_lib:inet_family(Family), ip => any,
            no_ports => 1, reqid_reuse_timeout => 400,
            servers => #{test_server => Server}}),
    %% 256 allocations exhaust the single filler -> it retires (cooling=1),
    %% and a replacement filler opens (active=1). The client has exactly one
    %% server, so read its sole pool via maps:values (avoids family-mapped keys).
    ok = lists:foreach(
           fun(_) ->
                   {ok, _} = eradius_client_mngr:wanna_send(Client, [test_server], [])
           end, lists:seq(1, 256)),
    #{pools := P0} = eradius_client_mngr:get_state(Client),
    [#{cooling := Cool0}] = maps:values(P0),
    ?equal(1, length(Cool0)),
    %% wait out the cooldown (400ms); the cooling socket exits and is reclaimed
    timer:sleep(1200),
    #{pools := P1} = eradius_client_mngr:get_state(Client),
    [#{active := Act1, cooling := Cool1}] = maps:values(P1),
    ?equal(0, length(Cool1)),
    ?equal(1, length(Act1)),
    ok.
