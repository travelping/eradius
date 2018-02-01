-module(eradius_test_handler).

-behaviour(eradius_server).

-export([start/0, stop/0, send_request/1, radius_request/3]).

-include("include/eradius_lib.hrl").

start() ->
    application:load(eradius),
    application:set_env(eradius, radius_callback, ?MODULE),
    application:set_env(eradius, client_ip, {127,0,0,1}),
    application:set_env(eradius, session_nodes, local),
    application:set_env(eradius, one, [{{"ONE", []}, [{"127.0.0.1", "secret"}]}]),
    application:set_env(eradius, servers, [{one, {"127.0.0.1", [1812]}}]),
    application:set_env(eradius, metrics, []),
    application:ensure_all_started(eradius),
    eradius:modules_ready([?MODULE]).

stop() ->
    application:stop(eradius),
    application:unload(eradius),
    application:start(eradius).

send_request(IP) ->
    {ok, R, A} = eradius_client:send_request({IP, 1812, "secret"}, #radius_request{cmd = request}, []),
    #radius_request{cmd = Cmd} = eradius_lib:decode_request(R, <<"secret">>, A),
    Cmd.

radius_request(#radius_request{cmd = request}, _Nasprop, _Args) ->
    {reply, #radius_request{cmd = accept}}.
