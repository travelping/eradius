%% @private
%% @doc Dictionary server
-module(eradius_dict).
-export([start_link/0, lookup/1, lookup/2, load_tables/1, load_tables/2, unload_tables/1, unload_tables/2]).
-export_type([attribute/0, attr_value/0, table_name/0, attribute_id/0, attribute_type/0,
              attribute_prim_type/0, attribute_encryption/0, vendor_id/0, value_id/0]).

-behaviour(gen_server).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-include("eradius_dict.hrl").

-define(SERVER, ?MODULE).
-define(TABLENAME, ?MODULE).

-type table_name() :: atom() | string().
-type attribute_id() :: pos_integer() | {vendor_id(), pos_integer()}.
-type attribute_encryption() :: 'no' | 'scramble' | 'salt_crypt'.
-type attribute_type() :: attribute_prim_type() | {tagged, attribute_prim_type()}.
-type attribute_prim_type() :: 'string' | 'integer' | 'integer64' | 'ipaddr' | 'ipv6addr'
                             | 'ipv6prefix' | 'date' | 'abinary' | 'binary' | 'octets'.

-type value_id() :: {attribute_id(), pos_integer()}.
-type vendor_id() :: pos_integer().

-type attribute()  :: #attribute{} | attribute_id().
-type attr_value() :: term().

-record(state, {}).

%% ------------------------------------------------------------------------------------------
%% -- API
-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

-spec lookup(attribute_id() | value_id()) -> [#attribute{} | #value{} | #vendor{}].
lookup(Id) ->
    ets:lookup(?TABLENAME, Id).

-spec lookup(attribute | vendor | value, attribute_id() | value_id() | vendor_id()) -> false | #attribute{} | #value{} | #vendor{}.
lookup(Type, Id) ->
    case {Type, eradius_dict:lookup(Id)} of
        {attribute, [Attr = #attribute{}]} ->
            Attr;
        {vendor, [Attr = #vendor{}]} ->
            Attr;
        {value, [Attr = #value{}]} ->
            Attr;
        {_, [_H | _T] = L} ->
            lists:keyfind(Type, 1, L);
        {_, _} ->
            false
    end.

-spec load_tables(list(table_name())) -> ok | {error, {consult, table_name()}}.
load_tables(Tables) when is_list(Tables) ->
    load_tables(code:priv_dir(eradius), Tables).

-spec load_tables(file:filename(), list(table_name())) -> ok | {error, {consult, table_name()}}.
load_tables(Dir, Tables) when is_list(Tables) ->
    gen_server:call(?SERVER, {load_tables, Dir, Tables}, infinity).

-spec unload_tables(list(table_name())) -> ok | {error, {consult, table_name()}}.
unload_tables(Tables) when is_list(Tables) ->
    unload_tables(code:priv_dir(eradius), Tables).

-spec unload_tables(file:filename(), list(table_name())) -> ok | {error, {consult, table_name()}}.
unload_tables(Dir, Tables) when is_list(Tables) ->
    gen_server:call(?SERVER, {unload_tables, Dir, Tables}, infinity).

%% ------------------------------------------------------------------------------------------
%% -- gen_server callbacks
init([]) ->
    create_table(),
    {ok, InitialLoadTables} = application:get_env(eradius, tables),
    do_load_tables(code:priv_dir(eradius), InitialLoadTables),
    {ok, #state{}}.

create_table() ->
    ets:new(?TABLENAME, [bag, named_table, {keypos, 2}, protected]).

handle_call({load_tables, Dir, Tables}, _From, State) ->
    {reply, do_load_tables(Dir, Tables), State};

handle_call({unload_tables, Dir, Tables}, _From, State) ->
    {reply, do_unload_tables(Dir, Tables), State}.

%% unused callbacks
handle_cast(_Msg, State)   -> {noreply, State}.
handle_info(_Info, State)  -> {noreply, State}.
terminate(_Reason, _State) -> ok.
code_change(_OldVsn, _NewVsn, _State) -> {ok, state}.

%% ------------------------------------------------------------------------------------------
%% -- gen_server callbacks
mapfile(A) when is_atom(A) -> mapfile(atom_to_list(A));
mapfile(A) when is_list(A) -> A ++ ".map".

-spec do_load_tables(file:filename(), [table_name()]) -> ok | {error, {consult, file:filename()}}.
do_load_tables(_Dir, []) ->
    ok;
do_load_tables(Dir, Tables) ->
    try
        All = lists:flatmap(fun (Tab) ->
                                     TabFile = filename:join(Dir, mapfile(Tab)),
                                     case file:consult(TabFile) of
                                         {ok, Res}       -> Res;
                                         {error, _Error} -> throw({consult, TabFile})
                                     end
                             end, Tables),
        {MoreIncludes, Defs} = lists:partition(fun({include, _}) -> true; (_) -> false end, All),
        ets:insert(?TABLENAME, Defs),
        lager:info("Loaded RADIUS tables: ~p", [Tables]),
        do_load_tables(Dir, [T || {include, T} <- MoreIncludes])
    catch
        throw:{consult, FailedTable} ->
            lager:error("Failed to load RADIUS table: ~s (wanted: ~p)", [FailedTable, Tables]),
            {error, {consult, FailedTable}}
    end.

do_unload_tables(_Dir, []) ->
    ok;
do_unload_tables(Dir, Tables) ->
    try
        All = lists:flatmap(fun (Tab) ->
                                     TabFile = filename:join(Dir, mapfile(Tab)),
                                     case file:consult(TabFile) of
                                         {ok, Res}       -> Res;
                                         {error, _Error} -> throw({consult, TabFile})
                                     end
                             end, Tables),
	% Unlike of what we do in do_load_tables, we don't treat includes here.
	% Usually when you want to purge some tables you want to do exactly
	% this, and you don't want to purge some extra tables.
        {_MoreIncludes, Defs} = lists:partition(fun({include, _}) -> true; (_) -> false end, All),
        [ begin Id = case X of #attribute{} -> X#attribute.id; #value{} -> X#value.id; #vendor{} -> X#vendor.type end, ets:delete(?TABLENAME, Id) end || X <- Defs ],
        lager:info("Unloaded RADIUS tables: ~p", [Tables])
    catch
        throw:{consult, FailedTable} ->
            lager:error("Failed to unload RADIUS table: ~s (wanted: ~p)", [FailedTable, Tables]),
            {error, {consult, FailedTable}}
    end.
