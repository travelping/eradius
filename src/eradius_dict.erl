-module(eradius_dict).
%%%----------------------------------------------------------------------
%%% File    : eradius_dict.erl
%%% Author  : Torbjorn Tornkvist <tobbe@bluetail.com>
%%% Purpose : Radius dictionary handling.
%%% Created : 25 Sep 2003 by Torbjorn Tornkvist <tobbe@bluetail.com>
%%%----------------------------------------------------------------------
-behaviour(gen_server).

%% External exports
-export([start/0,start_link/0, lookup/1]).
-export([load_tables/1, load_tables/2]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2,
         code_change/3]).


-include("eradius_dict.hrl").


-define(SERVER    , ?MODULE).
-define(TABLENAME , ?MODULE).

-record(state, {}).

%%%----------------------------------------------------------------------
%%% API
%%%----------------------------------------------------------------------

lookup(Id) ->
    ets:lookup(?TABLENAME, Id).

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

start() ->
    gen_server:start({local, ?SERVER}, ?MODULE, [], []).


load_tables(Tables) ->
    load_tables(code:priv_dir(eradius), Tables).
load_tables(Dir, Tables) ->
    gen_server:call(?SERVER, {load_tables, Dir, Tables}, infinity).

%%%----------------------------------------------------------------------
%%% Callback functions from gen_server
%%%----------------------------------------------------------------------

%%----------------------------------------------------------------------
%% Func: init/1
%% Returns: {ok, State}          |
%%          {ok, State, Timeout} |
%%          ignore               |
%%          {stop, Reason}
%%----------------------------------------------------------------------
init([]) ->
    process_flag(trap_exit, true),
    create_table(),
    {ok, #state{}}.

create_table() ->
    ets:new(?TABLENAME, [named_table, {keypos, 2}, public]).

%%----------------------------------------------------------------------
%% Func: handle_call/3
%% Returns: {reply, Reply, State}          |
%%          {reply, Reply, State, Timeout} |
%%          {noreply, State}               |
%%          {noreply, State, Timeout}      |
%%          {stop, Reason, Reply, State}   | (terminate/2 is called)
%%          {stop, Reason, State}            (terminate/2 is called)
%%----------------------------------------------------------------------
handle_call({load_tables, Dir, Tables}, _From, State) ->
    Res = (catch lists:foreach(fun(Tab) -> load_table(Dir, Tab) end, Tables)),
    {reply, Res, State}.

%%----------------------------------------------------------------------
%% Func: handle_cast/2
%% Returns: {noreply, State}          |
%%          {noreply, State, Timeout} |
%%          {stop, Reason, State}            (terminate/2 is called)
%%----------------------------------------------------------------------
handle_cast(_Msg, State) ->
    {noreply, State}.

%%----------------------------------------------------------------------
%% Func: handle_info/2
%% Returns: {noreply, State}          |
%%          {noreply, State, Timeout} |
%%          {stop, Reason, State}            (terminate/2 is called)
%%----------------------------------------------------------------------
handle_info(_Info, State) ->
    {noreply, State}.

%%----------------------------------------------------------------------
%% Func: terminate/2
%% Purpose: Shutdown the server
%% Returns: any (ignored by gen_server)
%%----------------------------------------------------------------------
terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, _NewVsn, State) ->
    {ok, state}.

%%%----------------------------------------------------------------------
%%% Internal functions
%%%----------------------------------------------------------------------


%%% --------------------------------------------------------------------
%%% Load dictionary table
%%% --------------------------------------------------------------------

load_table(Dir, Table) ->
    MapFile = filename:join(Dir, Table ++ ".map"),
    case file:consult(MapFile) of
        {ok, Res} ->
            lists:foreach(fun(R) -> ets:insert(?TABLENAME, R) end, Res),
            ok;
        _ ->
            {error, load_table}
    end.
