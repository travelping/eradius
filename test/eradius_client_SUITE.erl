% Copyright (c) 2010-2017 by Travelping GmbH <info@travelping.com>

% Permission is hereby granted, free of charge, to any person obtaining a
% copy of this software and associated documentation files (the "Software"),
% to deal in the Software without restriction, including without limitation
% the rights to use, copy, modify, merge, publish, distribute, sublicense,
% and/or sell copies of the Software, and to permit persons to whom the
% Software is furnished to do so, subject to the following conditions:

% The above copyright notice and this permission notice shall be included in
% all copies or substantial portions of the Software.

% THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
% IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
% FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
% AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
% LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
% FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
% DEALINGS IN THE SOFTWARE.

-module(eradius_client_SUITE).
-compile(export_all).

-include("test/eradius_test.hrl").

-define(BAD_SERVER_IP, {eradius_test_handler:localhost(ip), 1820, "secret"}).
-define(BAD_SERVER_INITIAL_RETRIES, 3).
-define(BAD_SERVER_TUPLE_INITIAL, {{eradius_test_handler:localhost(tuple), 1820},
                                   ?BAD_SERVER_INITIAL_RETRIES,
                                   ?BAD_SERVER_INITIAL_RETRIES}).
-define(BAD_SERVER_TUPLE, {{eradius_test_handler:localhost(tuple), 1820},
                           ?BAD_SERVER_INITIAL_RETRIES - 1,
                           ?BAD_SERVER_INITIAL_RETRIES}).
-define(BAD_SERVER_IP_ETS_KEY, {eradius_test_handler:localhost(tuple), 1820}).

-define(GOOD_SERVER_INITIAL_RETRIES, 3).
-define(GOOD_SERVER_TUPLE, {{eradius_test_handler:localhost(tuple), 1812},
                            ?GOOD_SERVER_INITIAL_RETRIES,
                            ?GOOD_SERVER_INITIAL_RETRIES}).
-define(GOOD_SERVER_2_TUPLE, {{{127, 0, 0, 2}, 1813},
                              ?GOOD_SERVER_INITIAL_RETRIES,
                              ?GOOD_SERVER_INITIAL_RETRIES}).

-define(RADIUS_SERVERS, [?GOOD_SERVER_TUPLE,
                         ?BAD_SERVER_TUPLE_INITIAL,
                         ?GOOD_SERVER_2_TUPLE]).

all() -> [
    send_request,
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

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(eradius),
    startSocketCounter(),
    Config.

end_per_suite(_Config) ->
    stopSocketCounter(),
    application:stop(eradius),
    ok.

init_per_testcase(send_request, Config) ->
    application:stop(eradius),
    eradius_test_handler:start(),
    Config;
init_per_testcase(send_request_failover, Config) ->
    application:stop(eradius),
    eradius_test_handler:start(),
    Config;
init_per_testcase(check_upstream_servers, Config) ->
    application:stop(eradius),
    eradius_test_handler:start(),
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

socketCounter(Count) ->
    receive
        add         -> socketCounter(Count+1);
        del         -> socketCounter(Count-1);
        {get, PID}  -> PID ! {ok, Count}, socketCounter(Count);
        stop        -> done
    end.

startSocketCounter() ->
    register(socketCounter, spawn(?MODULE, socketCounter, [0])).

stopSocketCounter() ->
    socketCounter ! stop,
    unregister(socketCounter).

addSocket() -> socketCounter ! add.
delSocket() -> socketCounter ! del.

getSocketCount() ->
    socketCounter ! {get, self()},
    receive
        {ok, Count} -> Count
    end.

testSocket(undefined) -> true;
testSocket(Pid) ->
    Pid ! {status, self()},
    receive
        {ok, active}    -> false;
        {ok, inactive}  -> true
    after
        50 -> true
    end.

-record(state, {
    socket_ip :: inet:ip_address(),
    no_ports = 1 :: pos_integer(),
    idcounters = maps:new() :: map(),
    sockets = array:new() :: array:array(),
    sup :: pid(),
    subscribed_clients = [] :: [{{integer(),integer(),integer(),integer()}, integer()}]
}).

split(N, List) -> split2(N, [], List).

split2(0, List1, List2)     -> {lists:reverse(List1), List2};
split2(_, List1, [])        -> {lists:reverse(List1), []};
split2(N, List1, [L|List2]) -> split2(N-1, [L|List1], List2).

meckStart() ->
    ok = meck:new(eradius_client_socket),
    ok = meck:expect(eradius_client_socket, start, fun(X, Y, Z) -> eradius_client_socket_test:start(X, Y, Z) end),
    ok = meck:expect(eradius_client_socket, init, fun(X) -> eradius_client_socket_test:init(X) end),
    ok = meck:expect(eradius_client_socket, handle_call, fun(X, Y, Z) -> eradius_client_socket_test:handle_call(X, Y, Z) end),
    ok = meck:expect(eradius_client_socket, handle_cast, fun(X, Y) -> eradius_client_socket_test:handle_cast(X, Y) end),
    ok = meck:expect(eradius_client_socket, handle_info, fun(X, Y) -> eradius_client_socket_test:handle_info(X, Y) end),
    ok = meck:expect(eradius_client_socket, terminate, fun(X, Y) -> eradius_client_socket_test:terminate(X, Y) end),
    ok = meck:expect(eradius_client_socket, code_change, fun(X, Y, Z) -> eradius_client_socket_test:code_change(X, Y, Z) end).

meckStop() ->
    ok = meck:unload(eradius_client_socket).

parse_ip(undefined) ->
    {ok, undefined};
parse_ip(Address) when is_list(Address) ->
    inet_parse:address(Address);
parse_ip(T = {_, _, _, _}) ->
    {ok, T};
parse_ip(T = {_, _, _, _, _, _}) ->
    {ok, T}.

%% CHECK

test(true, _Msg) -> true;
test(false, Msg) ->
    io:format(standard_error, "~s~n", [Msg]),
    false.

check(OldState, NewState = #state{no_ports = P}, null, A) -> check(OldState, NewState, P, A);
check(OldState, NewState = #state{socket_ip = A}, P, null) -> check(OldState, NewState, P, A);
check(#state{sockets = OS, no_ports = _OP, idcounters = _OC, socket_ip = OA},
        #state{sockets = NS, no_ports = NP, idcounters = NC, socket_ip = NA},
        P, A) ->
    {ok, PA} = parse_ip(A),
    test(PA == NA, "Adress not configured") and
    case NA of
        OA  ->
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
    ?equal(accept, eradius_test_handler:send_request(eradius_test_handler:localhost(tuple))),
    ?equal(accept, eradius_test_handler:send_request(eradius_test_handler:localhost(ip))),
    ?equal(accept, eradius_test_handler:send_request(eradius_test_handler:localhost(string))),
    ?equal(accept, eradius_test_handler:send_request(eradius_test_handler:localhost(binary))),
    ok.

send(FUN, Ports, Address) ->
    meckStart(),
    {ok, OldState} = gen_server:call(eradius_client, debug),
    FUN(),
    {ok, NewState} = gen_server:call(eradius_client, debug),
    true = check(OldState, NewState, Ports, Address),
    meckStop().

wanna_send(_Config) ->
    lists:map(fun(_) ->
                        IP = {rand:uniform(100), rand:uniform(100), rand:uniform(100), rand:uniform(100)},
                        Port = rand:uniform(100),
                        MetricsInfo = {{undefined, undefined, undefined}, {undefined, undefined, undefined}},
                        FUN = fun() -> gen_server:call(eradius_client, {wanna_send, {undefined, {IP, Port}}, MetricsInfo}) end,
                        send(FUN, null, null)
                end, lists:seq(1, 10)).

%% I've catched some data races with `delSocket()' and `getSocketCount()' when
%% `delSocket()' happens after `getSocketCount()' (because `delSocket()' is sent from another process).
%% I don't know a better decision than add some delay before `getSocketCount()'
reconf_address(_Config) ->
    FUN = fun() -> gen_server:call(eradius_client, reconfigure), timer:sleep(100) end,
    application:set_env(eradius, client_ip, "7.13.23.42"),
    send(FUN, null, "7.13.23.42").

reconf_ports_30(_Config) ->
    FUN = fun() -> gen_server:call(eradius_client, reconfigure), timer:sleep(100) end,
    application:set_env(eradius, client_ports, 30),
    send(FUN, 30, null).

reconf_ports_10(_Config) ->
    FUN = fun() -> gen_server:call(eradius_client, reconfigure), timer:sleep(100) end,
    application:set_env(eradius, client_ports, 10),
    send(FUN, 10, null).

send_request_failover(_Config) ->
    ?equal(accept, eradius_test_handler:send_request_failover(?BAD_SERVER_IP)),
    {ok, Timeout} = application:get_env(eradius, unreachable_timeout),
    timer:sleep(Timeout * 1000),
    ?equal([?BAD_SERVER_TUPLE], ets:lookup(eradius_client, ?BAD_SERVER_IP_ETS_KEY)),
    ok.

check_upstream_servers(_Config) ->
    ?equal(?RADIUS_SERVERS, ets:tab2list(eradius_client)),
    ok.
