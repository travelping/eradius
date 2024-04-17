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

-define(HUT_SOCKET, eradius_client_socket).

-define(BAD_SERVER_IP(Family),
        {eradius_test_lib:localhost(Family, ip), 1820, "secret"}).
-define(BAD_SERVER_INITIAL_RETRIES, 3).
-define(BAD_SERVER_TUPLE_INITIAL(Family),
        {{eradius_test_lib:localhost(Family, tuple), 1820},
         ?BAD_SERVER_INITIAL_RETRIES,
         ?BAD_SERVER_INITIAL_RETRIES}).
-define(BAD_SERVER_TUPLE(Family),
        {{eradius_test_lib:localhost(Family, tuple), 1820},
         ?BAD_SERVER_INITIAL_RETRIES - 1,
         ?BAD_SERVER_INITIAL_RETRIES}).
-define(BAD_SERVER_IP_ETS_KEY(Family),
        {eradius_test_lib:localhost(Family, tuple), 1820}).

-define(GOOD_SERVER_INITIAL_RETRIES, 3).
-define(GOOD_SERVER_TUPLE(Family),
        {{eradius_test_lib:localhost(Family, tuple), 1812},
         ?GOOD_SERVER_INITIAL_RETRIES,
         ?GOOD_SERVER_INITIAL_RETRIES}).
-define(GOOD_SERVER_2_TUPLE(Family),
        {{eradius_test_lib:badhost(Family), 1813},
         ?GOOD_SERVER_INITIAL_RETRIES,
         ?GOOD_SERVER_INITIAL_RETRIES}).

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
     check_upstream_servers
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
    {skip, "no IPv6 server support (yet)"};
    %% case eradius_test_lib:has_ipv6_test_config() of
    %%     true ->
    %%         [{family, Group} | Config];
    %%     _ ->
    %%         {skip, "IPv6 test IPs not configured"}
    %% end;
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

init_per_testcase(send_request, Config) ->
    application:stop(eradius),
    start_handler(Config),
    Config;
init_per_testcase(send_request_failover, Config) ->
    application:stop(eradius),
    start_handler(Config),
    Config;
init_per_testcase(check_upstream_servers, Config) ->
    application:stop(eradius),
    start_handler(Config),
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
    Counts = supervisor:count_children(eradius_client_socket_sup),
    proplists:get_value(active, Counts).

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
parse_ip(T = {_, _, _, _, _, _}) ->
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
    test(PA == NA, "Adress not configured") and
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

send_request(Config) ->
    Family = proplists:get_value(family, Config),
    ?equal(accept,
           eradius_test_handler:send_request(eradius_test_lib:localhost(Family, tuple))),
    ?equal(accept,
           eradius_test_handler:send_request(eradius_test_lib:localhost(Family, ip))),
    ?equal(accept,
           eradius_test_handler:send_request(eradius_test_lib:localhost(Family, string))),
    ?equal(accept,
           eradius_test_handler:send_request(eradius_test_lib:localhost(Family, binary))),
    ok.

send(FUN, Ports, Address) ->
    meckStart(),
    OldState = eradius_client_mngr:get_state(),
    FUN(),
    NewState = eradius_client_mngr:get_state(),
    true = check(OldState, NewState, Ports, Address),
    meckStop().

wanna_send(_Config) ->
    lists:map(fun(_) ->
                      IP = {rand:uniform(100), rand:uniform(100), rand:uniform(100), rand:uniform(100)},
                      Port = rand:uniform(100),
                      FUN = fun() -> eradius_client_mngr:wanna_send({undefined, {IP, Port}}) end,
                      send(FUN, null, null)
              end, lists:seq(1, 10)).

%% socket shutdown is done asynchronous, the tests need to wait a bit for it to finish.
reconf_address(_Config) ->
    FUN = fun() ->
                  eradius_client_mngr:reconfigure(#{ip => "7.13.23.42"}),
                  timer:sleep(100)
          end,
    send(FUN, null, "7.13.23.42").

reconf_ports_30(_Config) ->
    FUN = fun() ->
                  eradius_client_mngr:reconfigure(#{no_ports => 30}),
                  timer:sleep(100)
          end,
    send(FUN, 30, null).

reconf_ports_10(_Config) ->
    FUN = fun() ->
                  eradius_client_mngr:reconfigure(#{no_ports => 10}),
                  timer:sleep(100)
          end,
    send(FUN, 10, null).

send_request_failover(Config) ->
    Family = proplists:get_value(family, Config),
    ?equal(accept, eradius_test_handler:send_request_failover(?BAD_SERVER_IP(Family))),
    {ok, Timeout} = application:get_env(eradius, unreachable_timeout),
    timer:sleep(Timeout * 1000),
    ?equal([?BAD_SERVER_TUPLE(Family)],
           eradius_client_mngr:servers(?BAD_SERVER_IP_ETS_KEY(Family))),
    ok.

check_upstream_servers(Config) ->
    Family = proplists:get_value(family, Config),
    ?equal(lists:keysort(1, ?RADIUS_SERVERS(Family)), eradius_client_mngr:servers()),
    ok.
