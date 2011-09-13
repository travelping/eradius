%% @private
%% @doc Supervisor for RADIUS server processes.
-module(eradius_server_sup).
-export([start_link/0, start_instance/2, stop_instance/2]).

-behaviour(supervisor).
-export([init/1]).

-define(SERVER, ?MODULE).

%% ------------------------------------------------------------------------------------------
%% -- API
start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

start_instance(IP = {A,B,C,D}, Port) ->
    eradius:info_report("Starting RADIUS Listener at ~p.~p.~p.~p:~p~n", [A,B,C,D,Port]),
    supervisor:start_child(?SERVER, [IP, Port]).

stop_instance(IP = {A,B,C,D}, Port) ->
    {ok, Pid} = eradius_server_mon:lookup_pid(IP, Port),
    eradius:info_report("Stopping RADIUS Listener at ~p.~p.~p.~p:~p~n", [A,B,C,D,Port]),
    stop_instance(Pid).

stop_instance(Pid) when is_pid(Pid) ->
    supervisor:terminate_child(?SERVER, Pid).

%% ------------------------------------------------------------------------------------------
%% -- supervisor callbacks
init([]) ->
    RestartStrategy = simple_one_for_one,
    Restarts = 10,
    RestartInterval = 2,

    SupFlags = {RestartStrategy, Restarts, RestartInterval},
    Child = {'_', {eradius_server, start_link, []}, transient, 1000, worker, [eradius_server]},

    {ok, {SupFlags, [Child]}}.
