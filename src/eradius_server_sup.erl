%% @private
%% @doc Supervisor for RADIUS server processes.
-module(eradius_server_sup).
-export([start_link/0, start_instance/1, stop_instance/2, all/0]).

-behaviour(supervisor).
-export([init/1]).
-import(eradius_lib, [printable_peer/2]).

-include_lib("kernel/include/logger.hrl").

-define(SERVER, ?MODULE).

%% ------------------------------------------------------------------------------------------
%% -- API
start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

start_instance(_ServerAddr = {ServerName, {IP, Port}}) ->
    ?LOG(info, "Starting RADIUS Listener at ~s", [printable_peer(IP, Port)]),
    supervisor:start_child(?SERVER, [ServerName, IP, Port]);

start_instance(_ServerAddr = {ServerName, {IP, Port, Opts}}) ->
    ?LOG(info, "Starting RADIUS Listener at ~s", [printable_peer(IP, Port)]),
    supervisor:start_child(?SERVER, [ServerName, IP, Port, Opts]).

stop_instance(_ServerAddr = {_ServerName, {IP, Port}}, Pid) ->
    ?LOG(info, "Stopping RADIUS Listener at ~s", [printable_peer(IP, Port)]),
    supervisor:terminate_child(?SERVER, Pid);

stop_instance(ServerAddr = {_ServerName, {_IP, _Port, _Opts}}, Pid) ->
    stop_instance(ServerAddr, Pid).

all() ->
    lists:map(fun({_, Child, _, _}) -> Child end, supervisor:which_children(?SERVER)).

%% ------------------------------------------------------------------------------------------
%% -- supervisor callbacks
init([]) ->
    RestartStrategy = simple_one_for_one,
    Restarts = 10,
    RestartInterval = 2,

    SupFlags = {RestartStrategy, Restarts, RestartInterval},
    Child = {'_', {eradius_server, start_link, []}, transient, 1000, worker, [eradius_server]},

    {ok, {SupFlags, [Child]}}.
