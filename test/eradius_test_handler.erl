-module(eradius_test_handler).

-behaviour(eradius_server).

-export([start/0, start/2, stop/0, send_request/1, send_request_failover/1, radius_request/3]).

-include("include/eradius_lib.hrl").

start() ->
    start(inet, ipv4).

start(Backend, Family) ->
    application:load(eradius),
    application:set_env(eradius, radius_callback, ?MODULE),
    %% application:set_env(eradius, client_ip, eradius_test_lib:localhost(tuple)),
    application:set_env(eradius, session_nodes, local),
    application:set_env(eradius, one,
                        [{{"ONE", []}, [{eradius_test_lib:localhost(ip), "secret"}]}]),
    application:set_env(eradius, two,
                        [{{"TWO", [{default_route, {{127, 0, 0, 2}, 1813, <<"secret">>}}]},
                          [{eradius_test_lib:localhost(ip), "secret"}]}]),
    application:set_env(eradius, servers,
                        [{one, {eradius_test_lib:localhost(ip), [1812]}},
                         {two, {eradius_test_lib:localhost(ip), [1813]}}]),
    application:set_env(eradius, unreachable_timeout, 2),
    application:set_env(eradius, servers_pool,
                        [{test_pool,
                          [{eradius_test_lib:localhost(tuple), 1812, "secret"},
                           %% fake upstream server for fail-over
                           {eradius_test_lib:localhost(string), 1820, "secret"}]}]),
    application:ensure_all_started(eradius),

    ClientConfig =
        #{inet_backend => Backend,
          family => eradius_test_lib:inet_family(Family),
          ip => eradius_test_lib:localhost(Family, tuple),
          servers => [{one, {eradius_test_lib:localhost(Family, ip), [1812]}},
                      {two, {eradius_test_lib:localhost(Family, ip), [1813]}}],
          servers_pool =>
              [{test_pool, [{eradius_test_lib:localhost(Family, tuple), 1812, "secret"},
                            %% fake upstream server for fail-over
                            {eradius_test_lib:localhost(Family, string), 1820, "secret"}]}]
         },
    eradius_client_mngr:reconfigure(ClientConfig),
    eradius:modules_ready([?MODULE]).

stop() ->
    application:stop(eradius),
    application:unload(eradius),
    application:start(eradius).

send_request(IP) ->
    {ok, R, A} = eradius_client:send_request({IP, 1812, "secret"}, #radius_request{cmd = request}, []),
    #radius_request{cmd = Cmd} = eradius_lib:decode_request(R, <<"secret">>, A),
    Cmd.

send_request_failover(Server) ->
    {ok, Pools} = application:get_env(eradius, servers_pool),
    SecondaryServers = proplists:get_value(test_pool, Pools),
    {ok, R, A} = eradius_client:send_request(Server, #radius_request{cmd = request}, [{retries, 1},
                                                                                      {timeout, 2000},
                                                                                      {failover, SecondaryServers}]),
    #radius_request{cmd = Cmd} = eradius_lib:decode_request(R, <<"secret">>, A),
    Cmd.

radius_request(#radius_request{cmd = request}, _Nasprop, _Args) ->
    {reply, #radius_request{cmd = accept}}.
