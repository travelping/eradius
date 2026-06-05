%% Copyright (c) 2024 Travelping GmbH <info@travelping.com>
%%
%% SPDX-License-Identifier: MIT
%%
%% @private
-module(eradius_client_socket_sup).

-behaviour(supervisor).

%% API
-export([start_link/0, new/2]).

%% Supervisor callbacks
-export([init/1]).

-ignore_xref([start_link/0]).

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

new(Supervisor, Config) ->
    supervisor:start_child(Supervisor, [Config]).

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

    %% Pool sockets are managed by eradius_client_mngr: it opens them on demand,
    %% monitors them, and reclaims them on exit. They must NOT auto-restart -- a
    %% restarted socket would be a pid the manager never learns about (an orphaned
    %% FD/source port). The manager reopens a replacement on the next allocation.
    Child = #{id => eradius_client_socket,
              start => {eradius_client_socket, start_link, []},
              restart => temporary,
              shutdown => 5000,
              type => worker,
              modules => [eradius_client_socket]},

    {ok, {SupFlags, [Child]}}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
