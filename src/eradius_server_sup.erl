%% @private
%% @doc Supervisor for RADIUS server processes.
-module(eradius_server_sup).
-export([start_link/0, start_instance/2, stop_instance/3, all/0]).

-behaviour(supervisor).
-export([init/1]).

-define(SERVER, ?MODULE).

%% ------------------------------------------------------------------------------------------
%% -- API
start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

start_instance(IP, Port) ->
    IPString = inet_parse:ntoa(IP),
    eradius:info_report("Starting RADIUS Listener at ~s:~b~n", [IPString, Port]),
    supervisor:start_child(?SERVER, [IP, Port]).

stop_instance(IP, Port, Pid) ->
    IPString = inet_parse:ntoa(IP),
    eradius:info_report("Stopping RADIUS Listener at ~s:~b~n", [IPString, Port]),
    supervisor:terminate_child(?SERVER, Pid).

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
