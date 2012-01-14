%% @private
%% @doc Manager for RADIUS server processes.
%%   This module manages the RADIUS server registry and
%%   validates and applies the server configuration from the application environment.
%%   It starts all servers that are configured as part of its initialization,
%%   then sends ping requests to all nodes that are part of the configuration in order
%%   to keep them connected.
-module(eradius_server_mon).
-export([start_link/0, reconfigure/0, lookup_handler/3, lookup_pid/2, set_trace/4, all_nas_keys/0]).
-export_type([handler/0]).

-behaviour(gen_server).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-include("eradius_lib.hrl").

-define(SERVER, ?MODULE).
-define(NAS_TAB, eradius_nas_tab).

-type server()  :: {inet:ip_address(), eradius_server:port_number()}.
-type handler() :: {module(), term()}.

-record(nas, {
    key :: {server(), inet:ip_address()},
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
        [] ->
            {error, not_found};
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

%% @doc Set or clear the trace flag for a given Server/NAS combination.
-spec set_trace(inet:ip_address(), eradius_server:port_number(), inet:ip_address(), boolean()) -> ok.
set_trace(ServerIP, ServerPort, NasIP, Trace) when is_boolean(Trace) ->
    gen_server:call(?SERVER, {set_trace, {{ServerIP, ServerPort}, NasIP}, Trace}).

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
handle_call({set_trace, NasKey, Trace}, _From, State) ->
    case ets:lookup(?NAS_TAB, NasKey) of
        [] ->
            {reply, {error, not_found}, State};
        [Rec = #nas{prop = Prop}] ->
            NewNas = Rec#nas{prop = Prop#nas_prop{trace = Trace}},
            ets:insert(?NAS_TAB, NewNas),
            {reply, ok, State}
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
    case validate_config(ConfServList) of
        {invalid, Message} ->
            eradius:error_report("invalid server config: ~s", [Message]),
            {error, invalid_config};
        ServList ->
            NasList = lists:flatmap(fun(Server) ->
                                            List = server_naslist(Server),
                                            ets:insert(?NAS_TAB, List),
                                            List
                                    end, ServList),
            ets:foldl(fun(Nas, _) ->
                              case lists:member(Nas, NasList) of
                                  true    -> done;
                                  false   -> ets:delete(?NAS_TAB, Nas)
                              end
                      end, [], ?NAS_TAB),
            Run     = sets:from_list([element(1, T) || T <- Running]),
            New     = sets:from_list([element(1, T) || T <- ServList]),
            ToStart = sets:subtract(New, Run),
            ToStop  = sets:subtract(Run, New),
            Started = sets:fold(fun (Key, List) ->
                                        lists:keydelete(Key, 1, List),
                                        {{IP, Port}, Pid} = lists:keyfind(Key, 1, Running),
                                        eradius_server_sup:stop_instance(IP, Port, Pid)
                                end, Running, ToStop),
            NRunning = sets:fold(fun ({IP, Port}, Acc) ->
                                         case eradius_server_sup:start_instance(IP, Port) of
                                             {ok, Pid} ->
                                                 [{{IP, Port}, Pid} | Acc];
                                             {error, Error} ->
                                                 Host = inet_parse:ntoa(IP),
                                                 eradius:error_report("Could not start listener ~s:~b: ~p~n", [Host, Port, Error]),
                                                 Acc
                                         end
                                 end, Started, ToStart),
            eradius_node_mon:set_nodes(config_nodes(ServList)),
            {ok, #state{running = NRunning}}
    end.

-spec server_naslist(valid_server()) -> list(#nas{}).
server_naslist({{IP, Port}, HandlerList}) ->
    [#nas{key = {{IP, Port}, NasIP},
          handler = {HandlerMod, HandlerArgs},
          prop = #nas_prop{handler_nodes = HandlerNodes, nas_ip = NasIP, secret = Secret, trace = false}}
      || {NasIP, Secret, HandlerNodes, HandlerMod, HandlerArgs} <- HandlerList].

-spec config_nodes(valid_config()) -> list(node()).
config_nodes(Config) ->
    ordsets:from_list(lists:concat([N || {_Server, HandlerList} <- Config,
                                         {_, _, N, _, _} <- HandlerList,
                                         N /= local, N /= node()])).

%% ------------------------------------------------------------------------------------------
%% -- config validation
-define(pos_int(X), is_integer(X), X >= 0).
-define(ip4_address_num(X), ?pos_int(X), X < 256).
-define(ip4_address(T), ?ip4_address_num(element(1, T)), ?ip4_address_num(element(2, T)),
                        ?ip4_address_num(element(3, T)), ?ip4_address_num(element(4, T))).

-type valid_nas()    :: {inet:ip_address(), binary(), list(atom()), module(), term()}.
-type valid_server() :: {server(), list(valid_nas())}.
-type valid_config() :: list(valid_server()).

-spec validate_config(list(term())) -> valid_config() | {invalid, io_lib:chars()}.
validate_config(Config) ->
    validate_server_config(dedup_keys(Config)).

-spec validate_server_config(list(term())) -> valid_config() | {invalid, io_lib:chars()}.
validate_server_config([]) ->
    [];
validate_server_config([{Server, NasList} | ConfigRest]) ->
    case validate_server(Server) of
        E = {invalid, _} ->
            E;
        ValidServer ->
            case validate_nas_list(NasList) of
                E = {invalid, _} ->
                    E;
                ValidNasList ->
                    case validate_server_config(ConfigRest) of
                        E = {invalid, _} ->
                            E;
                        ValidConfigRest ->
                            [{ValidServer, ValidNasList} | ValidConfigRest]
                    end
            end
    end;
validate_server_config([InvalidTerm | _ConfigRest]) ->
    {invalid, io_lib:format("bad term in server list: ~p", [InvalidTerm])}.

validate_server({IP, Port}) when is_list(Port) ->
    case (catch list_to_integer(Port)) of
        {'EXIT', _} ->
            {invalid, io_lib:format("bad port number: ~p", [Port])};
        Num when ?pos_int(Num) ->
            validate_server({IP, Num});
        Num ->
            {invalid, io_lib:format("port number out of range: ~p", [Num])}
    end;
validate_server({IP, Port}) when is_list(IP), ?pos_int(Port) ->
    case inet_parse:ipv4_address(IP) of
        {ok, Address} ->
            {Address, Port};
        {error, einval} ->
            {invalid, io_lib:format("bad IP address: ~p", [IP])}
    end;
validate_server({IP, Port}) when ?ip4_address(IP), ?pos_int(Port) ->
    {IP, Port};
validate_server(String) when is_list(String) ->
    %% TODO: IPv6 address support
    case string:tokens(String, ":") of
        [IP, Port] ->
            validate_server({IP, Port});
        _ ->
            {invalid, io_lib:format("bad address/port combination: ~p", [String])}
    end;
validate_server(X) ->
    {invalid, io_lib:format("bad address/port combination: ~p", [X])}.

validate_nas_list([]) ->
    [];
validate_nas_list([{NasAddress, Secret, HandlerNodes, Module, Args} | NasListRest]) when is_list(NasAddress) ->
    case inet_parse:ipv4_address(NasAddress) of
        {ok, ValidAddress} ->
            validate_nas_list([{ValidAddress, Secret, HandlerNodes, Module, Args} | NasListRest]);
        {error, einval} ->
            {invalid, io_lib:format("bad IP address in NAS specification: ~p", [NasAddress])}
    end;
validate_nas_list([{NasAddress, Secret, HandlerNodes, Module, Args} | NasListRest]) when ?ip4_address(NasAddress) ->
    case validate_secret(Secret) of
        E = {invalid, _} ->
            E;
        ValidSecret ->
            case validate_handler_nodes(HandlerNodes) of
                E = {invalid, _} ->
                    E;
                ValidHandlerNodes ->
                    case Module of
                        _ when is_atom(Module) ->
                            case validate_nas_list(NasListRest) of
                                E = {invalid, _} ->
                                    E;
                                ValidNasListRest ->
                                    [{NasAddress, ValidSecret, ValidHandlerNodes, Module, Args} | ValidNasListRest]
                            end;
                        _Else ->
                            {invalid, io_lib:format("bad module in NAS specifification: ~p", [Module])}
                    end
            end
    end;
validate_nas_list([{InvalidAddress, _, _, _, _} | _NasListRest]) ->
    {invalid, io_lib:format("bad IP address in NAS specification: ~p", [InvalidAddress])};
validate_nas_list([OtherTerm | _NasListRest]) ->
    {invalid, io_lib:format("bad term in NAS specification: ~p", [OtherTerm])}.

validate_secret(Secret) when is_list(Secret) ->
    unicode:characters_to_binary(Secret);
validate_secret(Secret) when is_binary(Secret) ->
    Secret;
validate_secret(OtherTerm) ->
    {invalid, io_lib:format("bad RADIUS secret: ~p", [OtherTerm])}.

validate_handler_nodes(local) ->
    local;
validate_handler_nodes("local") ->
    local;
validate_handler_nodes([]) ->
    {invalid, "empty node list"};
validate_handler_nodes(NodeL) when is_list(NodeL) ->
    validate_node_list(NodeL);
validate_handler_nodes(OtherTerm) ->
    {invalid, io_lib:format("bad node list: ~p", [OtherTerm])}.

validate_node_list([]) ->
    [];
validate_node_list([Node | Rest]) when is_atom(Node) ->
    case validate_node_list(Rest) of
        E = {invalid, _} ->
            E;
        ValidRest ->
            [Node | ValidRest]
    end;
validate_node_list([OtherTerm | _]) ->
    {invalid, io_lib:format("bad term in node list: ~p", [OtherTerm])}.

dedup_keys(Proplist) ->
    dedup_keys1(lists:keysort(1, Proplist)).

dedup_keys1(Proplist) ->
    lists:foldr(fun ({K, V1}, [{K, V2} | R]) ->
                        [{K, plmerge(V1, V2)} | R];
                    ({K, V}, R) ->
                        [{K, V} | R]
                end, [], Proplist).

plmerge(List1, List2) ->
    M1 = [{K, V} || {K, V} <- List1, not proplists:is_defined(K, List2)],
    lists:keysort(1, M1 ++ List2).
