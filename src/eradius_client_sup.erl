-module(eradius_client_sup).

-behaviour(supervisor).

%% API
-export([start_link/1, new/2]).

%% Supervisor callbacks
-export([init/1]).

-define(SERVER, ?MODULE).

%%%===================================================================
%%% API functions
%%%===================================================================

-spec start_link(Config :: eradius_client:client_config()) ->
          {ok, Pid :: pid()} |
          {error, {already_started, Pid :: pid()}} |
          {error, {shutdown, term()}} |
          {error, term()} |
          ignore.
start_link(Config) ->
    supervisor:start_link(?MODULE, [Config]).

new(Owner, SocketId) ->
    Children = supervisor:which_children(Owner),
    case lists:keyfind(eradius_client_socket_sup, 1, Children) of
        {eradius_client_socket_sup, SupPid, _, _} when is_pid(SupPid) ->
            supervisor:start_child(SupPid, [SocketId]);
        _ ->
            {error, dead}
    end.

%%%===================================================================
%%% Supervisor callbacks
%%%===================================================================

-spec init(Args :: term()) ->
          {ok, {SupFlags :: supervisor:sup_flags(),
                [ChildSpec :: supervisor:child_spec()]}} |
          ignore.
init([Opts]) ->
    SupFlags = #{strategy => one_for_one,
                 intensity => 5,
                 period => 10},
    Client =
        #{id => eradius_client,
          start => {eradius_client, start_link, [self(), Opts]},
          restart => permanent,
          shutdown => 5000,
          type => worker,
          modules => [eradius_client]},
    SocketSup =
        #{id => eradius_client_socket_sup,
          start => {eradius_client_socket_sup, start_link, []},
          restart => permanent,
          shutdown => 5000,
          type => supervisor,
          modules => [eradius_client_socket_sup]},

    {ok, {SupFlags, [Client, SocketSup]}}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
