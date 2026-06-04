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
     no_ports_one_wraps,
     clobber_does_not_hang,
     connected_socket_matches_reply,
     retire_holds_then_closes,
     retire_waits_for_pending
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

%% STUFF

getSocketCount() ->
    eradius_client_mngr:get_socket_count(?SERVER).

testSocket(undefined) ->
    true;
testSocket(Pid) ->
    not is_process_alive(Pid).

split(N, List) -> split2(N, [], List).

split2(0, List1, List2)     -> {lists:reverse(List1), List2};
split2(_, List1, [])        -> {lists:reverse(List1), []};
split2(N, List1, [L|List2]) -> split2(N-1, [L|List1], List2).

meckStart() ->
    ok = meck:new(eradius_client_socket, [passthrough]),
    ok = meck:expect(eradius_client_socket, init,
                     fun(_) -> {ok, undefined} end),
    ok = meck:expect(eradius_client_socket, handle_call,
                     fun(_Request, _From, State) -> {noreply, State} end),
    ok = meck:expect(eradius_client_socket, handle_cast,
                     fun(close, State) -> {stop, normal, State};
                        (_Request, State) -> {noreply, State} end),
    ok = meck:expect(eradius_client_socket, handle_info,
                     fun(_Info, State) -> {noreply, State} end),
    ok.

meckStop() ->
    ok = meck:unload(eradius_client_socket).

parse_ip(undefined) ->
    {ok, undefined};
parse_ip(any) ->
    {ok, any};
parse_ip(Address) when is_list(Address) ->
    inet_parse:address(Address);
parse_ip(T = {_, _, _, _}) ->
    {ok, T};
parse_ip(T = {_, _, _, _, _, _, _, _}) ->
    {ok, T}.

%% CHECK

test(true, _Msg) -> true;
test(false, Msg) ->
    ct:pal("~s", [Msg]),
    false.

check(OldState, NewState = #{no_ports := P}, null, A) -> check(OldState, NewState, P, A);
check(OldState, NewState = #{socket_id := {_, A}}, P, null) -> check(OldState, NewState, P, A);
check(#{sockets := OS, no_ports := _OP, idcounters := _OC, socket_id := {_, OA}},
      #{sockets := NS, no_ports := NP, idcounters := NC, socket_id := {_, NA}},
      P, A) ->
    {ok, PA} = parse_ip(A),
    test(PA == NA, "Address not configured") and
        case NA of
            OA  ->
                ct:pal("NP: ~p, NC: ~p", [NP, NC]),
                {_, Rest} = split(NP, array:to_list(OS)),
                test(P == NP,"Ports not configured") and
                    test(maps:fold( fun(_Peer, {NextPortIdx, _NextReqId}, Akk) ->
                                            Akk and (NextPortIdx =< NP)
                                    end, true, NC), "Invalid port counter") and
                    test(getSocketCount() =< NP, "Sockets not closed") and
                    test(array:size(NS) =< NP, "Socket array not resized") and
                    test(lists:all(fun(Pid) -> testSocket(Pid) end, Rest), "Sockets still available");
            _   ->
                test(array:size(NS) == 0, "Socket array not cleaned") and
                    test(getSocketCount() == 0, "Sockets not closed") and
                    test(lists:all(fun(Pid) -> testSocket(Pid) end, array:to_list(OS)), "Sockets still available")
        end.

%% TESTS

send_request(_Config) ->
    ?equal(accept, eradius_test_handler:send_request(one)),
    ok.

send(FUN, Ports, Address) ->
    meckStart(),
    OldState = eradius_client_mngr:get_state(?SERVER),
    FUN(),
    NewState = eradius_client_mngr:get_state(?SERVER),
    true = check(OldState, NewState, Ports, Address),
    meckStop().

wanna_send(_Config) ->
    lists:map(fun(X) ->
                      Server = binary_to_atom(<<(X+$A)>>),
                      FUN = fun() -> eradius_client_mngr:wanna_send(?SERVER, [Server], []) end,
                      send(FUN, null, null)
              end, lists:seq(0, 9)).

reconf_address(Config) ->
    IP = case proplists:get_value(family, Config) of
             ipv4 ->
                 {7, 13, 23, 42};
             ipv4_mapped_ipv6 ->
                 inet:ipv4_mapped_ipv6_address({7, 13, 23, 42});
             ipv6 ->
                 {16#fd96, 16#dcd2, 16#efdb, 16#41c3, 0, 0, 16#100, 1}
         end,
    FUN = fun() ->
                  eradius_client_mngr:reconfigure(?SERVER, #{ip => IP}),
                  %% socket shutdown is done asynchronous,
                  %% the tests need to wait a bit for it to finish.
                  timer:sleep(100)
          end,
    send(FUN, null, inet:ntoa(IP)).

reconf_ports_30(_Config) ->
    FUN = fun() ->
                  eradius_client_mngr:reconfigure(?SERVER, #{no_ports => 30}),
                  %% socket shutdown is done asynchronous,
                  %% the tests need to wait a bit for it to finish.
                  timer:sleep(100)
          end,
    send(FUN, 30, null).

reconf_ports_10(_Config) ->
    FUN = fun() ->
                  eradius_client_mngr:reconfigure(?SERVER, #{no_ports => 10}),
                  %% socket shutdown is done asynchronous,
                  %% the tests need to wait a bit for it to finish.
                  timer:sleep(100)
          end,
    send(FUN, 10, null).

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

no_ports_one_wraps() ->
    [{doc, "wanna_send must not crash when no_ports = 1 and the req-id wraps past 255"}].
no_ports_one_wraps(Config) ->
    Family = proplists:get_value(family, Config, ipv4),
    {ok, _} = application:ensure_all_started(eradius),
    Server = #{ip => eradius_test_lib:localhost(Family, native), port => 1812,
               secret => <<"secret">>, retries => 3},
    {ok, Client} =
        eradius_client_mngr:start_client(
          #{family => eradius_test_lib:inet_family(Family), ip => any, no_ports => 1,
            servers => #{test_server => Server}}),
    %% 257 allocations force the {PortIdx, 255} wrap branch at least once
    lists:foreach(
      fun(_) ->
              ?match({ok, {_Sock, _ReqId, test_server, _Srv, _Info}},
                     eradius_client_mngr:wanna_send(Client, [test_server], []))
      end, lists:seq(1, 257)),
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
