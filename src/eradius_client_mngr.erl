%% Copyright (c) 2002-2007, Martin Björklund and Torbjörn Törnkvist
%% Copyright (c) 2011, Travelping GmbH <info@travelping.com>
%%
%% SPDX-License-Identifier: MIT
%%
-module(eradius_client_mngr).

-behaviour(gen_server).

%% external API
-export([start_link/0, wanna_send/1, wanna_send/2, reconfigure/0, reconfigure/1]).

%% internal API
-export([store_radius_server_from_pool/3,
         request_failed/3,
         restore_upstream_server/1,
         find_suitable_peer/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-ifdef(TEST).
-export([get_state/0, servers/0, servers/1, init_server_status_metrics/0]).
-endif.

-include_lib("kernel/include/logger.hrl").
-include_lib("kernel/include/inet.hrl").
-include("eradius_internal.hrl").

-type client_opts() ::
        #{family => inet | inet6,
          ip => any | inet:ip_address(),
          active_n => once | non_neg_integer(),
          recbuf => non_neg_integer(),
          sndbuf => non_neg_integer(),
          server_pool => [term()],
          servers => [term()]}.
-type client_config() ::
        #{family := inet | inet6,
          ip := any | inet:ip_address(),
          active_n := once | non_neg_integer(),
          recbuf := non_neg_integer(),
          sndbuf := non_neg_integer(),
          servers_pool => [term()],
          servers => [term()]}.

-export_type([client_config/0]).

-record(state, {
                config :: client_config(),
                socket_id :: {Family :: inet | inet6, IP :: any | inet:ip_address()},
                no_ports = 1 :: pos_integer(),
                idcounters = maps:new() :: map(),
                sockets = array:new() :: array:array(),
                clients = [] :: [{{integer(),integer(),integer(),integer()}, integer()}]
               }).

-define(SERVER, ?MODULE).

-define(RECONFIGURE_TIMEOUT, 15000).

%%%=========================================================================
%%%  API
%%%=========================================================================

start_link() ->
    case client_config(default_client_opts()) of
        {ok, Config} -> gen_server:start_link({local, ?SERVER}, ?MODULE, [Config], []);
        {error, _} = Error -> Error
    end.

wanna_send(Peer) ->
    gen_server:call(?SERVER, {wanna_send, Peer}).

wanna_send(Node, Peer) ->
    gen_server:call({?SERVER, Node}, {wanna_send, Peer}).

%% @private
reconfigure() ->
    case client_config(default_client_opts()) of
        {ok, Config} -> reconfigure(Config);
        {error, _} = Error -> Error
    end.

%% @doc reconfigure the Radius client
reconfigure(Config) ->
    catch gen_server:call(?SERVER, {reconfigure, Config}, ?RECONFIGURE_TIMEOUT).

request_failed(ServerIP, Port, Options) ->
    case ets:lookup(?MODULE, {ServerIP, Port}) of
        [{{ServerIP, Port}, Retries, InitialRetries}] ->
            FailedTries = proplists:get_value(retries, Options, ?DEFAULT_RETRIES),
            %% Mark the given RADIUS server as 'non-active' if there were more tries
            %% than possible
            if FailedTries >= Retries ->
                    ets:delete(?MODULE, {ServerIP, Port}),
                    Timeout = application:get_env(eradius, unreachable_timeout, 60),
                    timer:apply_after(Timeout * 1000, ?MODULE, restore_upstream_server,
                                      [{ServerIP, Port, InitialRetries, InitialRetries}]);
               true ->
                    %% RADIUS client tried to send a request to the {ServierIP, Port} RADIUS
                    %% server. There were done FailedTries tries and all of them failed.
                    %% So decrease amount of tries for the given RADIUS server that
                    %% that will be used for next RADIUS requests towards this RADIUS server.
                    ets:update_counter(?MODULE, {ServerIP, Port}, -FailedTries)
            end;
        [] ->
            ok
    end.

restore_upstream_server({ServerIP, Port, Retries, InitialRetries}) ->
    ets:insert(?MODULE, {{ServerIP, Port}, Retries, InitialRetries}).

find_suitable_peer(undefined) ->
    [];
find_suitable_peer([]) ->
    [];
find_suitable_peer([{Host, Port, Secret} | Pool]) when is_list(Host) ->
    try
        IP = get_ip(Host),
        find_suitable_peer([{IP, Port, Secret} | Pool])
    catch _:_ ->
            %% can't resolve ip by some reasons, just ignore it
            find_suitable_peer(Pool)
    end;
find_suitable_peer([{IP, Port, Secret} | Pool]) ->
    case ets:lookup(?MODULE, {IP, Port}) of
        [] ->
            find_suitable_peer(Pool);
        [{{IP, Port}, _Retries, _InitialRetries}] ->
            {{IP, Port, Secret}, Pool}
    end;
find_suitable_peer([{IP, Port, Secret, _Opts} | Pool]) ->
    find_suitable_peer([{IP, Port, Secret} | Pool]).

-ifdef(TEST).

get_state() ->
    State = sys:get_state(?SERVER),
    Keys = record_info(fields, state),
    Values = tl(tuple_to_list(State)),
    maps:from_list(lists:zip(Keys, Values)).

servers() ->
    ets:tab2list(?MODULE).

servers(Key) ->
    ets:lookup(?MODULE, Key).

-endif.

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([#{no_ports := NPorts} = Config]) ->
    ets:new(?MODULE, [public, named_table, ordered_set, {keypos, 1}, {write_concurrency,true}]),
    prepare_pools(Config),

    State = #state{
               config = Config,
               socket_id = socket_id(Config),
               no_ports = NPorts},
    {ok, State}.

%% @private
handle_call({wanna_send, Peer = {_PeerName, PeerSocket}}, _From,
            #state{config = Config,
                   no_ports = NoPorts, idcounters = IdCounters,
                   sockets = Sockets, clients = Clients} = State0) ->
    {PortIdx, ReqId, NewIdCounters} = next_port_and_req_id(PeerSocket, NoPorts, IdCounters),
    {SocketProcess, NewSockets} = find_socket_process(PortIdx, Sockets, Config),
    State1 = State0#state{idcounters = NewIdCounters, sockets = NewSockets},
    State =
        case lists:member(Peer, Clients) of
            false -> State1#state{clients = [Peer | Clients]};
            true  -> State1
        end,
    {reply, {SocketProcess, ReqId}, State};

%% @private
handle_call({reconfigure, Config}, _From, State0) ->
    ets:delete_all_objects(?MODULE),
    prepare_pools(Config),

    State = reconfigure_address(Config, State0),
    {reply, ok, State};

%% @private
handle_call(_OtherCall, _From, State) ->
    {noreply, State}.

%% @private
handle_cast(_Msg, State) -> {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

%% @private
terminate(_Reason, _State) -> ok.

%% @private
code_change(_OldVsn, State, _Extra) -> {ok, State}.

%%%=========================================================================
%%%  internal functions
%%%=========================================================================

socket_id(#{family := Family, ip := IP}) ->
    {Family, IP}.

get_ip(Host) ->
    case inet:gethostbyname(Host) of
        {ok, #hostent{h_addrtype = inet, h_addr_list = [IP]}} ->
            IP;
        {ok, #hostent{h_addrtype = inet, h_addr_list = [_ | _] = IPs}} ->
            Index = rand:uniform(length(IPs)),
            lists:nth(Index, IPs);
        _ -> error(badarg)
    end.

%% @private
-spec default_client_opts() -> client_opts().
default_client_opts() ->
    #{ip => application:get_env(eradius, client_ip, any),
      no_ports => application:get_env(eradius, client_ports, 10),
      active_n => application:get_env(eradius, active_n, 100),
      recbuf => application:get_env(eradius, recbuf, 8192),
      sndbuf => application:get_env(eradius, sndbuf, 131072),
      servers_pool => application:get_env(eradius, servers_pool, []),
      servers => application:get_env(eradius, servers, [])
     }.


-spec client_config(client_opts()) -> {ok, client_config()} | {error, _}.
client_config(#{ip := IP} = Opts) when is_atom(IP) ->
    {ok, Opts#{family => inet6, ip := any}};
client_config(#{ip := {_, _, _, _}} = Opts)  ->
    {ok, Opts#{family => inet}};
client_config(#{ip := {_, _, _, _, _, _, _, _}} = Opts) ->
    {ok, Opts#{family => inet6}};
client_config(#{ip := Address} = Opts) when is_list(Address) ->
    case inet_parse:address(Address) of
        {ok, {_, _, _, _} = IP} ->
            {ok, Opts#{family => inet, ip => IP}};
        {ok, {_, _, _, _, _, _, _, _} = IP} ->
            {ok, Opts#{family => inet6, ip => IP}};
        _ ->
            ?LOG(error, "Invalid RADIUS client IP (parsing failed): ~p", [Address]),
            {error, {bad_client_ip, Address}}
    end.

%% private
prepare_pools(#{servers_pool := PoolList, servers := ServerList}) ->
    lists:foreach(fun({_PoolName, Servers}) -> prepare_pool(Servers) end, PoolList),
    lists:foreach(fun(Server) -> store_upstream_servers(Server) end, ServerList),
    init_server_status_metrics().

prepare_pool([]) -> ok;
prepare_pool([{Addr, Port, _, Opts} | Servers]) ->
    Retries = proplists:get_value(retries, Opts, ?DEFAULT_RETRIES),
    store_radius_server_from_pool(Addr, Port, Retries),
    prepare_pool(Servers);
prepare_pool([{Addr, Port, _} | Servers]) ->
    store_radius_server_from_pool(Addr, Port, ?DEFAULT_RETRIES),
    prepare_pool(Servers).

store_upstream_servers({Server, _}) ->
    store_upstream_servers(Server);
store_upstream_servers({Server, _, _}) ->
    store_upstream_servers(Server);
store_upstream_servers(Server) ->
    %% TBD: move proxy config into the proxy logic...

    HandlerDefinitions = application:get_env(eradius, Server, []),
    UpdatePoolFn = fun (HandlerOpts) ->
                           {DefaultRoute, Routes, Retries} = eradius_proxy:get_routes_info(HandlerOpts),
                           eradius_proxy:put_default_route_to_pool(DefaultRoute, Retries),
                           eradius_proxy:put_routes_to_pool(Routes, Retries)
                   end,
    lists:foreach(fun (HandlerDefinition) ->
                          case HandlerDefinition of
                              {{_, []}, _} ->             ok;
                              {{_, _, []}, _} ->          ok;
                              {{_, HandlerOpts}, _} ->    UpdatePoolFn(HandlerOpts);
                              {{_, _, HandlerOpts}, _} -> UpdatePoolFn(HandlerOpts);
                              _HandlerDefinition ->       ok
                          end
                  end,
                  HandlerDefinitions).

%% private
store_radius_server_from_pool(Addr, Port, Retries)
  when is_tuple(Addr), is_integer(Port), is_integer(Retries) ->
    ets:insert(?MODULE, {{Addr, Port}, Retries, Retries});
store_radius_server_from_pool(Addr, Port, Retries)
  when is_list(Addr), is_integer(Port), is_integer(Retries) ->
    IP = get_ip(Addr),
    ets:insert(?MODULE, {{IP, Port}, Retries, Retries});
store_radius_server_from_pool(Addr, Port, Retries) ->
    ?LOG(error, "bad RADIUS upstream server specified in RADIUS servers pool configuration ~p", [{Addr, Port, Retries}]),
    error(badarg).

reconfigure_address(#{no_ports := NPorts} = Config,
                    #state{socket_id = OAdd, sockets = Sockts} = State) ->
    NAdd = socket_id(Config),
    case OAdd of
        NAdd    ->
            reconfigure_ports(State, NPorts);
        _ ->
            ?LOG(info, "Reopening RADIUS client sockets (client_ip changed to ~s)", [inet:ntoa(NAdd)]),
            array:map(
              fun(_PortIdx, undefined) ->
                      ok;
                 (_PortIdx, Socket) ->
                      eradius_client_socket:close(Socket)
              end, Sockts),
            State#state{sockets = array:new(), socket_id = NAdd, no_ports = NPorts}
    end.

reconfigure_ports(State = #state{no_ports = OPorts, sockets = Sockets}, NPorts) ->
    if
        OPorts =< NPorts ->
            State#state{no_ports = NPorts};
        true ->
            Counters = fix_counters(NPorts, State#state.idcounters),
            NSockets = close_sockets(NPorts, Sockets),
            State#state{sockets = NSockets, no_ports = NPorts, idcounters = Counters}
    end.

fix_counters(NPorts, Counters) ->
    maps:map(fun(_Peer, Value = {NextPortIdx, _NextReqId}) when NextPortIdx < NPorts -> Value;
                (_Peer, {_NextPortIdx, NextReqId}) -> {0, NextReqId}
             end, Counters).

close_sockets(NPorts, Sockets) ->
    case array:size(Sockets) =< NPorts of
        true    ->
            Sockets;
        false   ->
            List = array:to_list(Sockets),
            {_, Rest} = lists:split(NPorts, List),
            lists:map(
              fun(undefined) -> ok;
                 (Socket) -> eradius_client_socket:close(Socket)
              end, Rest),
            array:resize(NPorts, Sockets)
    end.

next_port_and_req_id(Peer, NumberOfPorts, Counters) ->
    case Counters of
        #{Peer := {NextPortIdx, ReqId}} when ReqId < 255 ->
            NextReqId = (ReqId + 1);
        #{Peer := {PortIdx, 255}} ->
            NextPortIdx = (PortIdx + 1) rem (NumberOfPorts - 1),
            NextReqId = 0;
        _ ->
            NextPortIdx = erlang:phash2(Peer, NumberOfPorts),
            NextReqId = 0
    end,
    NewCounters = Counters#{Peer => {NextPortIdx, NextReqId}},
    {NextPortIdx, NextReqId, NewCounters}.

find_socket_process(PortIdx, Sockets, Config) ->
    case array:get(PortIdx, Sockets) of
        undefined ->
            {ok, Socket} = eradius_client_socket:new(Config),
            {Socket, array:set(PortIdx, Socket, Sockets)};
        Socket ->
            {Socket, Sockets}
    end.

%% @private
init_server_status_metrics() ->
    case application:get_env(eradius, server_status_metrics_enabled, false) of
        false ->
            ok;
        true ->
            %% That will be called at eradius startup and we must be sure that prometheus
            %% application already started if server status metrics supposed to be used
            application:ensure_all_started(prometheus),
            ets:foldl(fun ({{Addr, Port}, _, _}, _Acc) ->
                              eradius_counter:set_boolean_metric(server_status, [Addr, Port], false)
                      end, [], ?MODULE)
    end.
