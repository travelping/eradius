%% @private
%% @doc Dictionary server
-module(eradius_dict).
-export([start_link/0, lookup/2, load_tables/1, load_tables/2, unload_tables/1, unload_tables/2]).
-export_type([attribute/0, attr_value/0, table_name/0, attribute_id/0, attribute_type/0,
              attribute_prim_type/0, attribute_encryption/0, vendor_id/0, value_id/0]).

-behaviour(gen_server).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-include_lib("kernel/include/logger.hrl").
-include("eradius_dict.hrl").

-define(SERVER, ?MODULE).

-type table_name() :: atom() | string().
-type attribute_id() :: pos_integer() | {vendor_id(), pos_integer()}.
-type attribute_encryption() :: 'no' | 'scramble' | 'salt_crypt' | 'ascend'.
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

-spec lookup(attribute | vendor | value, attribute_id() | value_id() | vendor_id()) -> false | #attribute{} | #value{} | #vendor{}.
lookup(Type, Id) ->
    dict_lookup(Type, Id).

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
    {ok, InitialLoadTables} = application:get_env(eradius, tables),
    do_load_tables(code:priv_dir(eradius), InitialLoadTables),
    {ok, #state{}}.

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
        {MoreIncludes, Defs} = prepare_tables(Dir, Tables),
        dict_insert(Defs),
        ?LOG(info, "Loaded RADIUS tables: ~p", [Tables]),
        do_load_tables(Dir, [T || {include, T} <- MoreIncludes])
    catch
        throw:{consult, FailedTable} ->
            ?LOG(error, "Failed to load RADIUS table: ~s (wanted: ~p)", [FailedTable, Tables]),
            {error, {consult, FailedTable}}
    end.

-spec do_unload_tables(file:filename(), [table_name()]) -> ok | {error, {consult, file:filename()}}.
do_unload_tables(_Dir, []) ->
    ok;
do_unload_tables(Dir, Tables) ->
    try
        %% Unlike of what we do in do_load_tables, we don't treat includes here.
        %% Usually when you want to purge some tables you want to do exactly
        %% this, and you don't want to purge some extra tables.
        {_, Defs} = prepare_tables(Dir, Tables),
        dict_delete(Defs),
        ?LOG(info, "Unloaded RADIUS tables: ~p", [Tables])
    catch
        throw:{consult, FailedTable} ->
            ?LOG(error, "Failed to unload RADIUS table: ~s (wanted: ~p)", [FailedTable, Tables]),
            {error, {consult, FailedTable}}
    end.

-spec prepare_tables(file:filename(), [table_name()]) -> {list(), list()}.
prepare_tables(Dir, Tables) ->
    All = lists:flatmap(fun (Tab) ->
                                TabFile = filename:join(Dir, mapfile(Tab)),
                                case file:consult(TabFile) of
                                    {ok, Res}       -> Res;
                                    {error, _Error} -> throw({consult, TabFile})
                                end
                        end, Tables),
    lists:partition(fun({include, _}) -> true; (_) -> false end, All).

dict_insert(Value) when is_list(Value) ->
    [dict_insert(V) || V <- Value];
dict_insert(Value) when is_tuple(Value) ->
    Key = {?MODULE, element(1, Value), element(2, Value)},
    persistent_term:put(Key, Value).

dict_delete(Value) when is_list(Value) ->
    [dict_delete(V) || V <- Value];
dict_delete(Value) when is_tuple(Value) ->
    Key = {?MODULE, element(1, Value), element(2, Value)},
    persistent_term:erase(Key).

dict_lookup(Type, Id) ->
    try
        persistent_term:get({?MODULE, Type, Id})
    catch
        error:badarg ->
            false
    end.
