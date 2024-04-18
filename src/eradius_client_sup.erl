%% Copyright (c) 2024 Travelping GmbH <info@travelping.com>
%%
%% SPDX-License-Identifier: MIT
%%
%% @private
-module(eradius_client_sup).

-behaviour(supervisor).

%% API
-export([start_link/1, socket_supervisor/1]).

%% Supervisor callbacks
-export([init/1]).

-ignore_xref([start_link/1]).

-define(SERVER, ?MODULE).

%%%===================================================================
%%% API functions
%%%===================================================================

-spec start_link(Config :: eradius_client_mngr:client_opts()) ->
          {ok, Pid :: pid()} |
          {error, {already_started, Pid :: pid()}} |
          {error, {shutdown, term()}} |
          {error, term()} |
          ignore.
start_link(Opts) ->
    supervisor:start_link(?MODULE, Opts).

socket_supervisor(Owner) ->
    Children = supervisor:which_children(Owner),
    case lists:keyfind(eradius_client_socket_sup, 1, Children) of
        {eradius_client_socket_sup, Pid, _, _} when is_pid(Pid) ->
            {ok, Pid};
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
init(Opts) ->
    SupFlags = #{strategy => one_for_one,
                 intensity => 5,
                 period => 10},
    ClientSocketSup =
        #{id => eradius_client_socket_sup,
          start => {eradius_client_socket_sup, start_link, []},
          restart => permanent,
          shutdown => 5000,
          type => supervisor,
          modules => [eradius_client_socket_sup]},
    ClientMngr =
        #{id => eradius_client_mngr,
          start => {eradius_client_mngr, start_link, [self() | Opts]},
          restart => permanent,
          shutdown => 5000,
          type => worker,
          modules => [eradius_client_mngr]},

    {ok, {SupFlags, [ClientSocketSup, ClientMngr]}}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
