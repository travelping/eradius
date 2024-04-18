%% @private
%% @doc Supervisor for RADIUS server processes.
-module(eradius_server_sup).
-behaviour(supervisor).

-export([start_link/0, start_instance/1, all/0]).

-export([init/1]).
-import(eradius_lib, [printable_peer/2]).

-ignore_xref([start_link/0, all/0]).

-include_lib("kernel/include/logger.hrl").

-define(SERVER, ?MODULE).

%% ------------------------------------------------------------------------------------------
%% -- API
start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

start_instance(Opts) ->
    supervisor:start_child(?SERVER, Opts).

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
