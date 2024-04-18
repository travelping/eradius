-module(eradius_test_handler).
-compile([export_all, nowarn_export_all]).

-behaviour(eradius_server).

-include("include/eradius_lib.hrl").

-define(SERVER, ?MODULE).

start() ->
    start(inet, ipv4).

start(Backend, Family) ->
    application:stop(eradius),

    application:load(eradius),
    application:set_env(eradius, unreachable_timeout, 2),
    application:ensure_all_started(eradius),

    ok = start_client(Backend, Family),

    SrvOpts = #{handler => {?MODULE, []},
                clients => #{eradius_test_lib:localhost(Family, native) =>
                                #{secret => "secret", client => <<"ONE">>}}},
    {ok, _} = eradius:start_server(
                eradius_test_lib:localhost(Family, native), 1812, SrvOpts#{server_name => one}),
    {ok, _} = eradius:start_server(
                eradius_test_lib:localhost(Family, native), 1813, SrvOpts#{server_name => two}),
    ok.

stop() ->
    application:stop(eradius),
    application:unload(eradius).

start_client(Backend, Family) ->
    application:ensure_all_started(eradius),

    Clients =
        maps:from_list(
          [{binary_to_atom(<<(X+$A)>>), #{ip => eradius_test_lib:localhost(Family, native),
                                          port => 1820 + X, secret => "secret"}}
           || X <- lists:seq(0, 9)]),
    ClientConfig =
        #{inet_backend => Backend,
          family => eradius_test_lib:inet_family(Family),
          ip => eradius_test_lib:localhost(Family, native),
          servers => Clients#{one => #{ip => eradius_test_lib:localhost(Family, native),
                                       port => 1812,
                                       secret => "secret",
                                       retries => 3},
                              two => #{ip => eradius_test_lib:localhost(Family, native),
                                       port => 1813,
                                       secret => "secret",
                                       retries => 3},
                              bad => #{ip => eradius_test_lib:localhost(Family, native),
                                       port => 1920,
                                       secret => "secret",
                                       retries => 3},
                              test_pool => [one, two]}
         },
    case eradius_client_mngr:start_client({local, ?SERVER}, ClientConfig) of
        {ok, _} -> ok;
        {error, {already_started, _}} -> ok
    end.

send_request(ServerName) ->
    ct:pal("about to send"),
    {{ok, Resp}, _Req} =
        eradius_client:send_request(?SERVER, ServerName, eradius_req:new(request), #{}),
    {_, #{cmd := Cmd}} = eradius_req:attrs(Resp),
    Cmd.

send_request_failover(Server) ->
    Opts = #{retries => 1, timeout => 2000, failover => [test_pool]},
    {{ok, Resp}, _Req} =
        eradius_client:send_request(?SERVER, Server, eradius_req:new(request), Opts),
    {_, #{cmd := Cmd}} = eradius_req:attrs(Resp),
    Cmd.

radius_request(Req = #{cmd := request}, _Args) ->
    {reply, eradius_req:set_attrs([], Req#{cmd := accept})}.
