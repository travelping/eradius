%% @doc Main module of the eradius application.
-module(eradius).
-export([load_tables/1, load_tables/2, modules_ready/1, modules_ready/2, trace_on/3, trace_off/3]).

-behaviour(application).
-export([start/2, stop/1, config_change/3]).

%% internal use
-export([error_report/2, info_report/2]).

-include("eradius_lib.hrl").

%% @doc Load RADIUS dictionaries from the default directory.
-spec load_tables(list(eradius_dict:table_name())) -> ok | {error, {consult, eradius_dict:table_name()}}.
load_tables(Tables) ->
    eradius_dict:load_tables(Tables).

%% @doc Load RADIUS dictionaries from a certain directory.
-spec load_tables(file:filename(), list(eradius_dict:table_name())) -> ok | {error, {consult, eradius_dict:table_name()}}.
load_tables(Dir, Tables) ->
    eradius_dict:load_tables(Dir, Tables).

%% @equiv modules_ready(self(), Modules)
modules_ready(Modules) ->
    eradius_node_mon:modules_ready(self(), Modules).

%% @doc Announce request handler module availability.
%%    Applications need to call this function (usually from their application master)
%%    in order to make their modules (which should implement the {@link eradius_server} behaviour)
%%    available for processing. The modules will be revoked when the given Pid goes down.
modules_ready(Pid, Modules) ->
    eradius_node_mon:modules_ready(Pid, Modules).

%% @doc Start tracing requests from the given NAS coming in on the given server.
%%   Do not do do this on a production system, it generates lots of output.
trace_on(ServerIP, ServerPort, NasIP) ->
    eradius_server_mon:set_trace(ensure_ip(ServerIP), ServerPort, ensure_ip(NasIP), true).

%% @doc Stop tracing requests from the given NAS.
trace_off(ServerIP, ServerPort, NasIP) ->
    eradius_server_mon:set_trace(ensure_ip(ServerIP), ServerPort, ensure_ip(NasIP), false).

ensure_ip(IP = {_,_,_,_}) -> IP;
ensure_ip(IP = {_,_,_,_,_,_,_,_}) -> IP;
ensure_ip(IPString) when is_list(IPString) ->
    case inet_parse:address(IPString) of
        {ok, Address}   -> Address;
        {error, einval} -> error(badarg, [IPString])
    end;
ensure_ip(IP) ->
    error(badarg, [IP]).

%% @private
%% @doc Log an error using error_logger
error_report(Fmt, Vals) ->
    error_logger:error_report(lists:flatten(io_lib:format(Fmt, Vals))).

%% @private
%% @doc Log a message using error_logger
info_report(Fmt, Vals) ->
    error_logger:info_report(lists:flatten(io_lib:format(Fmt, Vals))).

%% ----------------------------------------------------------------------------------------------------
%% -- application callbacks

%% @private
start(_StartType, _StartArgs) ->
    eradius_sup:start_link().

%% @private
stop(_State) ->
    ok.

%% @private
config_change(Added, Changed, _Removed) ->
    lists:foreach(fun do_config_change/1, Added),
    lists:foreach(fun do_config_change/1, Changed),
    eradius_client:reconfigure().

do_config_change({tables, NewTables}) ->
    eradius_dict:load_tables(NewTables);
do_config_change({servers, _}) ->
    eradius_server_mon:reconfigure();
do_config_change({_, _}) ->
    ok.
