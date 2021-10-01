%% @private
%% @doc Manager for RADIUS server processes.
%%   This module manages the RADIUS server registry and
%%   validates and applies the server configuration from the application environment.
%%   It starts all servers that are configured as part of its initialization,
%%   then sends ping requests to all nodes that are part of the configuration in order
%%   to keep them connected.
-module(eradius_server_mon).
-export([start_link/0, reconfigure/0, lookup_handler/3, lookup_pid/2, all_nas_keys/0]).
-export_type([handler/0]).

-behaviour(gen_server).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-include_lib("kernel/include/logger.hrl").
-include("eradius_lib.hrl").

-define(SERVER, ?MODULE).
-define(NAS_TAB, eradius_nas_tab).
-export_type([server/0]).

-import(eradius_lib, [printable_peer/2]).

-record(nas, {
    key :: {server(), inet:ip_address()},
    server_name :: server_name(),
    handler :: handler(),
    prop :: #nas_prop{}
}).

%% ------------------------------------------------------------------------------------------
%% -- API
start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%% @doc Apply NAS config from the application environment.
%%   Walks the list of configured servers and NASs,
%%   starting and stopping servers as necessary.
%%   If the configuration is invalid, no servers are modified.
%%
-spec reconfigure() -> ok | {error, invalid_config}.
reconfigure() ->
    gen_server:call(?SERVER, reconfigure).

%% @doc Fetch the RADIUS secret, handler and trace flag for a given server/NAS combination.
%%   This is a very fast operation that is called for every
%%   request by the RADIUS server process.
-spec lookup_handler(inet:ip_address(), eradius_server:port_number(), inet:ip_address()) -> {ok, handler(), #nas_prop{}} | {error, not_found}.
lookup_handler(IP, Port, NasIP) ->
    case ets:lookup(?NAS_TAB, {{IP, Port}, NasIP}) of
        [] when NasIP == {0, 0, 0, 0} ->
            {error, not_found};
        [] ->
            lookup_handler(IP, Port, {0, 0, 0, 0});
        [Rec] ->
            Prop = (Rec#nas.prop)#nas_prop{server_ip = IP, server_port = Port},
            {ok, Rec#nas.handler, Prop}
    end.

%% @doc Fetches the pid of RADIUS server at IP:Port, if there is one.
-spec lookup_pid(inet:ip_address(), eradius_server:port_number()) -> {ok, pid()} | {error, not_found}.
lookup_pid(ServerIP, ServerPort) ->
    gen_server:call(?SERVER, {lookup_pid, {ServerIP, ServerPort}}).

%% @doc returns the list of all currently configured NASs
-spec all_nas_keys() -> [term()].
all_nas_keys() ->
        ets:select(?NAS_TAB, [{#nas{key = '$1', _ = '_'}, [], ['$1']}]).

%% ------------------------------------------------------------------------------------------
%% -- gen_server callbacks
-record(state, {running}).

init([]) ->
    ?NAS_TAB = ets:new(?NAS_TAB, [named_table, protected, {keypos, #nas.key}]),
    case configure(#state{running = []}) of
        {error, invalid_config} -> {stop, invalid_config};
        Else                    -> Else
    end.

handle_call({lookup_pid, Server}, _From, State) ->
    case proplists:get_value(Server, State#state.running) of
        undefined ->
            {reply, {error, not_found}, State};
        Pid ->
            {reply, {ok, Pid}, State}
    end;
handle_call(reconfigure, _From, State) ->
    case configure(State) of
        {error, invalid_config} -> {reply, {error, invalid_config}, State};
        {ok, NState}            -> {reply, ok, NState}
    end;
handle_call(_Request, _From, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

%% unused callbacks
handle_cast(_Msg, State)            -> {noreply, State}.
terminate(_Reason, _State)          -> ok.
code_change(_OldVsn, State, _Extra) -> {ok, State}.

%% ------------------------------------------------------------------------------------------
%% -- helpers

configure(#state{running = Running}) ->
    {ok, ConfServList} = application:get_env(servers),
    case eradius_config:validate_config(ConfServList) of
        {invalid, Message} ->
            ?LOG(error, "Invalid server config, ~s", [Message]),
            {error, invalid_config};
        ServList -> %% list of {ServerName, ServerAddr, NasHandler} tuples
            NasList = lists:flatmap(fun(Server) -> server_naslist(Server) end, ServList),
            Tab = ets:tab2list(?NAS_TAB),
            ToDelete = Tab -- NasList,
            ToInsert = NasList -- Tab,
            update_nases(ToDelete, ToInsert),
            NewServAddrs = [{ServerName, ServerAddr} || {ServerName, ServerAddr, _} <- ServList],
            OldServAddrs =[{ServerName, ServerAddr} || {ServerName, ServerAddr, _} <- Running],
            ToStop  = OldServAddrs -- NewServAddrs,
            ToStart = NewServAddrs -- OldServAddrs,
            NewRunning = update_server(Running, ToStop, ToStart),
            NasHandler = [ NasInfo || {_ServerName, _Addr, NasInfo} <- ServList],
            eradius_node_mon:set_nodes(config_nodes(NasHandler)),
            {ok, #state{running = NewRunning}}
    end.

server_naslist({ServerName, {IP, Port, _Opts}, HandlerList}) ->
    server_naslist({ServerName, {IP, Port}, HandlerList});
server_naslist({ServerName, {IP, Port}, HandlerList}) ->
    lists:map(fun({NasId, NasIP, Secret, HandlerNodes, HandlerMod, HandlerArgs}) ->
                ServerInfo = eradius_lib:make_addr_info({ServerName, {IP, Port}}),
                NasInfo = eradius_lib:make_addr_info({NasId, {NasIP, undefined}}),
                #nas{key = {{IP, Port}, NasIP}, server_name = ServerName, handler = {HandlerMod, HandlerArgs},
                prop = #nas_prop{handler_nodes = HandlerNodes, nas_id = NasId, nas_ip = NasIP, secret = Secret,
                                 metrics_info = {ServerInfo, NasInfo}}}
              end, HandlerList).

config_nodes(NasHandler) ->
    ordsets:from_list(lists:concat([N || {_, _, N, _, _} <- NasHandler, N /= local, N/= node()])).

update_server(Running, ToStop, ToStart) ->
    Stopped = lists:map(fun(ServerAddr = {_ServerName, Addr}) ->
                                 StoppedServer = {_, _, Pid} = lists:keyfind(Addr, 2, Running),
                                 eradius_server_sup:stop_instance(ServerAddr, Pid),
                                 StoppedServer
                        end, ToStop),
    StartFn = fun({ServerName, Addr = {IP, Port, _Opts}}=ServerAddr) ->
        case eradius_server_sup:start_instance(ServerAddr) of
            {ok, Pid} ->
                {ServerName, Addr, Pid};
            {error, Error} ->
                ?LOG(error, "Could not start listener on host: ~s, occurring error: ~p",
                [printable_peer(IP, Port), Error])
        end
    end,
    NewStarted = lists:map(fun
        ({ServerName, {IP, Port}}) ->
            StartFn({ServerName, {IP, Port, []}});
        (ServerAddr) ->
            StartFn(ServerAddr)
        end,
        ToStart),
    (Running -- Stopped) ++ NewStarted.

update_nases(ToDelete, ToInsert) ->
    lists:foreach(fun(Nas) -> ets:delete_object(?NAS_TAB, Nas) end, ToDelete),
    lists:foreach(fun(Nas) -> ets:insert(?NAS_TAB, Nas) end, ToInsert).
