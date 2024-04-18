%% @doc Main module of the eradius application.
-module(eradius).

-behaviour(application).

%% API
-export([load_tables/1, load_tables/2,
        start_server/3, start_server/4]).
-ignore_xref([load_tables/1, load_tables/2,
              start_server/3, start_server/4]).

%% application callbacks
-export([start/2, stop/1]).

%% internal use

-include("eradius_lib.hrl").

%%%=========================================================================
%%%  API
%%%=========================================================================

%% @doc Load RADIUS dictionaries from the default directory.
-spec load_tables(list(eradius_dict:table_name())) -> ok | {error, {consult, eradius_dict:table_name()}}.
load_tables(Tables) ->
    eradius_dict:load_tables(Tables).

%% @doc Load RADIUS dictionaries from a certain directory.
-spec load_tables(Dir :: file:filename(), Tables :: [Table :: eradius_dict:table_name()]) ->
          ok | {error, {consult, Table :: eradius_dict:table_name()}}.
load_tables(Dir, Tables) ->
    eradius_dict:load_tables(Dir, Tables).

start_server(IP, Port, #{handler := {_, _}, clients := #{}} = Opts)
  when (IP =:= any orelse is_tuple(IP)) andalso
       is_integer(Port) andalso Port >= 0 andalso Port < 65536 ->
    eradius_server:start_instance(IP, Port, Opts).

start_server(ServerName, IP, Port, #{handler := {_, _}, clients := #{}} = Opts)
  when (IP =:= any orelse is_tuple(IP)) andalso
       is_integer(Port) andalso Port >= 0 andalso Port < 65536 ->
    eradius_server:start_instance(ServerName, IP, Port, Opts).

%%%===================================================================
%%% application callbacks
%%%===================================================================

%% @private
start(_StartType, _StartArgs) ->
    eradius_sup:start_link().

%% @private
stop(_State) ->
    ok.
