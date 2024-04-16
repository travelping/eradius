%% @private
-module(eradius_sup).
-behaviour(supervisor).

-export([start_link/0]).
-export([init/1]).

-define(SERVER, ?MODULE).

start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

%% ------------------------------------------------------------------------------------------
%% -- supervisor callbacks
init([]) ->
    RestartStrategy = one_for_one,
    MaxRestarts = 10,
    MaxSecondsBetweenRestarts = 5,

    SupFlags = {RestartStrategy, MaxRestarts, MaxSecondsBetweenRestarts},

    DictServer   = {dict, {eradius_dict, start_link, []}, permanent, brutal_kill, worker, [eradius_dict]},
    StatsServer  = {counter, {eradius_counter, start_link, []}, permanent, brutal_kill, worker, [eradius_counter]},
    StatsCollect = {aggregator, {eradius_counter_aggregator, start_link, []}, permanent, brutal_kill, worker, [eradius_counter_aggregator]},
    NodeMon      = {node_mon, {eradius_node_mon, start_link, []}, permanent, brutal_kill, worker, [eradius_node_mon]},
    RadiusLog    = {radius_log, {eradius_log, start_link, []}, permanent, brutal_kill, worker, [eradius_log]},
    ServerTopSup = {server_top_sup, {eradius_server_top_sup, start_link, []}, permanent, infinity, supervisor, [eradius_server_top_sup]},
    ClientMngr =
        #{id => client_mngr,
          start => {eradius_client_mngr, start_link, []},
          restart => permanent,
          shutdown => 500,
          type => worker,
          modules => [eradius_client_mngr]},
    ClientSocketSup =
         #{id => eradius_client_socket_sup,
           start => {eradius_client_socket_sup, start_link, []},
           restart => permanent,
           shutdown => 5000,
           type => supervisor,
           modules => [eradius_client_socket_sup]},

    {ok, {SupFlags, [DictServer, NodeMon, StatsServer, StatsCollect, RadiusLog,
                     ServerTopSup, ClientSocketSup, ClientMngr]}}.
