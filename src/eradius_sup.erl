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
    ServerSup =
        #{id => server_sup,
          start => {eradius_server_sup, start_link, []},
          restart => permanent,
          shutdown => infinity,
          type => supervisor,
          modules => [eradius_server_sup]},
    ClientTopSup =
        #{id => client_top_sup,
          start => {eradius_client_top_sup, start_link, []},
          restart => permanent,
          shutdown => infinity,
          type => supervisor,
          modules => [eradius_client_top_sup]},

    {ok, {SupFlags, [DictServer, ServerSup, ClientTopSup]}}.
