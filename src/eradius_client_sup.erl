-module(eradius_client_sup).

-behaviour(supervisor).

%% API
-export([start_link/0, new/2]).

%% Supervisor callbacks
-export([init/1]).

-define(SERVER, ?MODULE).

%%%===================================================================
%%% API functions
%%%===================================================================

-spec start_link() -> {ok, Pid :: pid()} |
          {error, {already_started, Pid :: pid()}} |
          {error, {shutdown, term()}} |
          {error, term()} |
          ignore.
start_link() ->
    supervisor:start_link(?MODULE, []).

new(Sup, SocketId) ->
    supervisor:start_child(Sup, [SocketId]).

%%%===================================================================
%%% Supervisor callbacks
%%%===================================================================

-spec init(Args :: term()) ->
          {ok, {SupFlags :: supervisor:sup_flags(),
                [ChildSpec :: supervisor:child_spec()]}} |
          ignore.
init([]) ->
    SupFlags = #{strategy => simple_one_for_one,
                 intensity => 5,
                 period => 10},

    Child = #{id => eradius_client_socket,
              start => {eradius_client_socket, start_link, []},
              restart => transient,
              shutdown => 5000,
              type => worker,
              modules => [eradius_client_socket]},

    {ok, {SupFlags, [Child]}}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
