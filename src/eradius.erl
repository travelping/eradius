%% @doc Main module of the eradius application.   
-module(eradius).
-export([load_tables/1, load_tables/2]).

-behaviour(application).
-export([start/2, stop/1]).

%% internal use
-export([error_report/2, info_report/2]).

-include("eradius_lib.hrl").

start(_StartType, _StartArgs) ->
    eradius_sup:start_link().

stop(_State) ->
    ok.

%% @doc Load RADIUS dictionaries from the default directory.
-spec load_tables(list(eradius_dict:table_name())) -> ok | {error, {consult, eradius_dict:table_name()}}.
load_tables(Tables) ->
    eradius_dict:load_tables(Tables).

%% @doc Load RADIUS dictionaries from a certain directory.
-spec load_tables(file:filename(), list(eradius_dict:table_name())) -> ok | {error, {consult, eradius_dict:table_name()}}.
load_tables(Dir, Tables) ->
    eradius_dict:load_tables(Dir, Tables).

%% @private
%% @doc Log an error using error_logger
error_report(Fmt, Vals) ->
    error_logger:error_report(lists:flatten(io_lib:format(Fmt, Vals))).

%% @private
%% @doc Log an error using error_logger
info_report(Fmt, Vals) ->
    error_logger:info_report(lists:flatten(io_lib:format(Fmt, Vals))).
