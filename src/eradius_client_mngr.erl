%% Copyright (c) 2002-2007, Martin Björklund and Torbjörn Törnkvist
%% Copyright (c) 2011, Travelping GmbH <info@travelping.com>
%%
%% SPDX-License-Identifier: MIT
%%
%% @doc This module contains the management logic for the RADIUS client instances.
%%   A counter is kept for every client instance in order to determine the next request id and sender port
%%   for each outgoing request.
%%
%%   The client uses OS-assigned ports. The maximum number of open ports can be specified through the
%%   ``client_ports'' option, it defaults to ``20''. The number of ports should not
%%   be set too low. If ``N'' ports are opened, the maximum number of concurrent requests is ``N * 256''.
%%
%%   The IP address used to send requests is configured through the ``ip'' option.
%%   Changing it currently requires a restart. It can be given as a string or ip address tuple,
%%   or the atom ``any'' (the default), which uses whatever address the OS selects.
-module(eradius_client_mngr).
-feature(maybe_expr, enable).

-behaviour(gen_server).

%% external API
-export([start_client/1, start_client/2]).

%% internal API
-export([start_link/2, start_link/3]).
-export([wanna_send/3, reconfigure/2]).
-export([request_failed/2]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-ifdef(TEST).
-export([get_state/1, servers/1, server/2, get_socket_count/1]).
-ignore_xref([get_state/1, servers/1, server/2, get_socket_count/1]).
-endif.

-ignore_xref([start_client/1, start_client/2]).
-ignore_xref([start_link/2, start_link/3]).
-ignore_xref([reconfigure/2]).

-include_lib("kernel/include/logger.hrl").
-include_lib("kernel/include/inet.hrl").
-include("eradius_internal.hrl").

-type server_name() :: atom() | binary().
%% Name of RADIUS server (or client).

-type server_opts() :: #{ip := inet:ip_address(),
                         port := inet:port_number(),
                         secret := binary,
                         retries => non_neg_integer(),
                         timeout => non_neg_integer()}.
%% Options to describe a RADIUS server.

-type server() :: #{ip := inet:ip_address(),
                    port := inet:port_number(),
                    secret := binary,
                    retries := non_neg_integer(),
                    timeout := non_neg_integer(),
                    failed := non_neg_integer()}.
%% Options to describe a RADIUS server.
%% Conceptually the same as `t:server_opts/0', except that may fields are mandatory.

-type server_pool() :: [server_name()].
%% List of server names that form a pool.

-type servers() :: #{server_name() := server() | server_pool()}.
%% Map of server and pool definition. Key is the name of the entry.

-type client_opts() ::
        #{name => server_name(),
          servers :=  #{server_name() := server_opts() | server_pool()},
          family => inet | inet6,
          ip => any | inet:ip_address(),
          active_n => once | non_neg_integer(),
          no_ports => non_neg_integer(),
          recbuf => non_neg_integer(),
          sndbuf => non_neg_integer(),
          metrics_callback => eradius_req:metrics_callback()
         }.
%% Options to configure the RADIUS client.

-type client_config() ::
        #{name := server_name(),
          servers := servers(),
          family := inet | inet6,
          ip := any | inet:ip_address(),
          active_n := once | non_neg_integer(),
          no_ports := non_neg_integer(),
          recbuf := non_neg_integer(),
          sndbuf := non_neg_integer(),
          metrics_callback := 'undefined' | eradius_req:metrics_callback()
         }.
%% Options to configure the RADIUS client.
%% Conceptually the same as `t:client_opts/0', except that may fields are mandatory.

-export_type([server_name/0, server_pool/0, servers/0, client_opts/0]).

-record(state, {
                owner :: pid(),
                config :: client_config(),
                client_name :: server_name(),
                client_addr :: any | inet:ip_address(),
                servers :: servers(),
                socket_id :: {Family :: inet | inet6, IP :: any | inet:ip_address()},
                no_ports = 1 :: pos_integer(),
                idcounters = maps:new() :: map(),
                sockets = array:new() :: array:array(),
                metrics_callback :: undefined | eradius_req:metrics_callback()
               }).

-define(RECONFIGURE_TIMEOUT, 15000).
-define(DEFAULT_MAX_RETRIES, 20).
-define(DEFAULT_DOWN_TIME, 1000).

%%%=========================================================================
%%%  API
%%%=========================================================================

%% @doc Start a new RADIUS client that is managed by the eradius applications supervisor tree.
-spec start_client(client_opts()) ->
          {ok, pid()} | {error, supervisor:startchild_err()}.
start_client(Opts) ->
    eradius_client_top_sup:start_client([Opts]).

%% @doc Start a new, named RADIUS client that is managed by the eradius applications supervisor tree.
-spec start_client(server_name(), client_opts()) ->
          {ok, pid()} | {error, supervisor:startchild_err()}.
start_client(ServerName, Opts) ->
    maybe
        ok ?= check_already_started(ServerName),
        eradius_client_top_sup:start_client([ServerName, Opts])
    end.

%% @private
-spec start_link(pid(), client_opts()) ->
          {ok, pid()} | {error, supervisor:startchild_err()}.
start_link(Owner, Opts) ->
    maybe
        {ok, Config} ?= client_config(maps:merge(default_client_opts(), Opts)),
        gen_server:start_link(?MODULE, [Owner, Config], [])
    end.

%% @private
-spec start_link(pid(), server_name(), client_opts()) ->
          {ok, pid()} | {error, supervisor:startchild_err()}.
start_link(Owner, ServerName, Opts) ->
    maybe
        ok ?= check_already_started(ServerName),
        {ok, Config} ?= client_config(maps:merge(default_client_opts(), Opts)),
        gen_server:start_link(ServerName, ?MODULE, [Owner, Config], [])
    end.

%% @private
wanna_send(Server, Peer, Tried) ->
    gen_server:call(Server, {wanna_send, Peer, Tried}).

%% @private
request_failed(Server, Peer) ->
    gen_server:call(Server, {failed, Peer}).

%% @doc reconfigure the Radius client
reconfigure(ServerRef, Opts) ->
    gen_server:call(ServerRef, {reconfigure, Opts}, ?RECONFIGURE_TIMEOUT).

-ifdef(TEST).

get_state(ServerRef) ->
    State = sys:get_state(ServerRef),
    Keys = record_info(fields, state),
    Values = tl(tuple_to_list(State)),
    maps:from_list(lists:zip(Keys, Values)).

get_socket_count(ServerRef) ->
    #state{owner = Owner} = sys:get_state(ServerRef),
    {ok, SockSup} = eradius_client_sup:socket_supervisor(Owner),
    Counts = supervisor:count_children(SockSup),
    proplists:get_value(active, Counts).

servers(ServerRef) ->
    #state{servers = Servers} = sys:get_state(ServerRef),
    maps:fold(
      fun(_, #{ip := IP, port := Port, retries := Retries, failed := Failed} = _, M)
            when Failed < Retries ->
              [{{IP, Port}, Retries, Failed} | M];
         (_, _, M) -> M
      end, [], Servers).

server(ServerRef, Key) ->
    #state{servers = Servers} = sys:get_state(ServerRef),
    case Servers of
        #{Key := #{ip := IP, port := Port, retries := Retries, failed := Failed}} ->
            {{IP, Port}, Retries, Failed};
        _ ->
            undefined
    end.

-endif.

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

%% @private
init([Owner, #{name := ClientName, servers := Servers,
               ip := IP, no_ports := NPorts,
               metrics_callback := MetricsCallback} = Config]) ->
    process_flag(trap_exit, true),
    ?LOG(info, "Starting RADIUS client"),
    State = #state{
               client_name = ClientName,
               client_addr = IP,
               owner = Owner,
               config = Config,
               servers = Servers,
               socket_id = socket_id(Config),
               no_ports = NPorts,
               metrics_callback = MetricsCallback
              },
    {ok, State}.

%% @private
handle_call({wanna_send, Candidates, Tried}, _From,
            #state{
               client_name = ClientName,
               client_addr = ClientAddr,
               servers = Servers,
               no_ports = NoPorts, idcounters = IdCounters,
               sockets = Sockets,
               metrics_callback = MetricsCallback} = State0) ->
    case select_server(Candidates, Tried, Servers) of
        {ok, {ServerName, #{ip := IP, port := Port} = Server}} ->
            ServerAddr = {IP, Port},
            {PortIdx, ReqId, NewIdCounters} =
                next_port_and_req_id(ServerAddr, NoPorts, IdCounters),
            {SocketProcess, NewSockets} = find_socket_process(PortIdx, Sockets, State0),
            State = State0#state{idcounters = NewIdCounters, sockets = NewSockets},
            ReqInfo =
                #{server => ServerName, server_addr => ServerAddr,
                  client => ClientName, client_addr => ClientAddr,
                  metrics_callback => MetricsCallback},
            Reply = {ok, {SocketProcess, ReqId, ServerName, Server, ReqInfo}},
            {reply, Reply, State};
        {error, _} = Error ->
            {reply, Error, State0}
    end;

handle_call({failed, Peer}, _From, #state{servers = Servers0} = State0) ->
    Servers =
        case Servers0 of
            #{Peer := #{retries := Retries, failed := Failed} = Server}
              when Failed < Retries ->
                Servers0#{Peer := Server#{failed := Failed + 1}};
            #{Peer := #{retries := Retries, failed := Failed} = Server}
              when Failed =:= Retries ->
                erlang:start_timer(?DEFAULT_DOWN_TIME, self(), {reset, Peer}),
                Servers0#{Peer := Server#{failed := Failed + 1}};
            _ ->
                Servers0
        end,
    State = State0#state{servers = Servers},
    {reply, ok, State};

%% @private
handle_call({reconfigure, Opts}, _From, #state{config = OConfig} = State0) ->
    case client_config(maps:merge(OConfig, Opts)) of
        {ok, Config} ->
            State = reconfigure_address(Config, State0#state{config = Config}),
            {reply, ok, State};

        {error, _} = Error ->
            {reply, Error, State0}
    end;

%% @private
handle_call(_OtherCall, _From, State) ->
    {noreply, State}.

%% @private
handle_cast(_Msg, State) -> {noreply, State}.

%% @private
handle_info({timeout, _, {reset, Peer}}, #state{servers = Servers0} = State0) ->
    Servers =
        case Servers0 of
            #{Peer := Server} ->
                Servers0#{Peer := Server#{failed := 0}};
            _ ->
                Servers0
        end,
    State = State0#state{servers = Servers},
    {noreply, State};

handle_info(_Info, State) ->
   {noreply, State}.

%% @private
terminate(Reason, _State) ->
    ?LOG(info, "RADIUS client stopped with ~p", [Reason]),
    ok.

%% @private
code_change(_OldVsn, State, _Extra) -> {ok, State}.

%%%=========================================================================
%%%  internal functions
%%%=========================================================================

check_already_started(Name) ->
    case where(Name) of
        Pid when is_pid(Pid) ->
            {error, {already_started, Pid}};
        undefined ->
            ok
    end.

where({global, Name}) -> global:whereis_name(Name);
where({via, Module, Name}) -> Module:whereis_name(Name);
where({local, Name})  -> whereis(Name);
where(ServerName) ->
    error(badarg, [ServerName]).

socket_id(#{family := Family, ip := IP}) ->
    {Family, IP}.

socket_id_str({_, IP}) when is_tuple(IP) ->
    inet:ntoa(IP);
socket_id_str({_, IP}) when is_atom(IP) ->
    atom_to_list(IP).

%% @private
default_client_opts() ->
    #{family => inet6,
      ip => any,
      no_ports => 10,
      active_n => 100,
      recbuf => 8192,
      sndbuf => 131072,
      metrics_callback => undefined
     }.

socket_ip(inet, {_, _, _, _} = IP) ->
    IP;
socket_ip(inet6, {_, _, _, _} = IP) ->
    inet:ipv4_mapped_ipv6_address(IP);
socket_ip(inet6, {_, _, _, _,_, _, _, _} = IP) ->
    IP.

select_server(Candidates, Tried, Servers) ->
    case select_servers(Candidates, Servers, []) -- Tried of
        [] ->
            {error, no_active_servers};
        PL ->
            N = rand:uniform(length(PL)),
            ServerName =  lists:nth(N, PL),
            {ok, {ServerName, maps:get(ServerName, Servers)}}
    end.

select_servers([], _Servers, Selected) ->
    Selected;
select_servers([Candidate|More], Servers, Selected) ->
    case Servers of
        #{Candidate := [_|_] = Pool} ->
            select_servers(More, Servers, select_servers(Pool, Servers, Selected));
        #{Candidate := #{retries := Retries, failed := Failed}}
          when Failed < Retries ->
            select_servers(More, Servers, [Candidate | Selected]);
        _ ->
            select_servers(More, Servers, Selected)
    end.

-spec client_config(client_opts()) -> {ok, client_config()} | {error, _}.
client_config_ip(#{ip := IP} = Opts) when is_atom(IP) ->
    {ok, Opts#{ip := any}};
client_config_ip(#{family := Family, ip := IP} = Opts) when is_tuple(IP) ->
    {ok, Opts#{ip := socket_ip(Family, IP)}};
client_config_ip(#{ip := Address} = Opts) when is_list(Address) ->
    case inet_parse:address(Address) of
        {ok, IP} ->
            client_config_ip(Opts#{ip => IP});
        _ ->
            ?LOG(error, "Invalid RADIUS client IP (parsing failed): ~p", [Address]),
            {error, {bad_client_ip, Address}}
    end.

client_config_servers(none, _, Servers) ->
    {ok, Servers};
client_config_servers({ServerName, #{ip := IP, port := _, secret := _} = SIn, Next},
                      #{family := Family} = Opts, Servers) ->
    Server = SIn#{ip := socket_ip(Family, IP),
                  retries => maps:get(retries, SIn, ?DEFAULT_MAX_RETRIES),
                  failed => 0},
    client_config_servers(maps:next(Next), Opts, Servers#{ServerName => Server});
client_config_servers({ServerPoolName, [_|_] = Pool, Next},
                      #{servers := CfgServers} = Opts, Servers) ->
    HasAll = lists:all(fun(SrvId) -> is_map_key(SrvId, CfgServers) end, Pool),
    case HasAll of
        true -> client_config_servers(maps:next(Next), Opts, Servers#{ServerPoolName => Pool});
        false -> {error, {server_definition_missing, Pool}}
    end;
client_config_servers({ServerName, _, _}, _, _) ->
    {error, {mandatory_opts_missing, ServerName}}.

client_config_servers(#{servers := Servers} = Opts) ->
    maybe
        {ok, NewServers} ?=
            client_config_servers(maps:next(maps:iterator(Servers)), Opts, #{}),
        {ok, Opts#{servers := NewServers}}
    end.

client_config_name(#{name := _} = Opts) ->
    {ok, Opts};
client_config_name(#{netdev := NetDev} = Opts) ->
    client_config_name([$%, NetDev], Opts);
client_config_name(#{netns := NetNS} = Opts) ->
    client_config_name([$@, NetNS], Opts);
client_config_name(Opts) ->
    client_config_name([], Opts).

client_config_name(Tag, #{family := inet6, ip := IP, ipv6_v6only := true} = Opts)
  when IP =:= any; IP =:= {0, 0, 0, 0, 0, 0, 0, 0} ->
    client_config_name("*", Tag, Opts);
client_config_name(Tag, #{family := inet6, ip := any} = Opts) ->
     client_config_name("[::]", Tag, Opts);
client_config_name(Tag, #{family := inet, ip := any} = Opts) ->
     client_config_name("[0.0.0.0]", Tag, Opts);
client_config_name(Tag, #{family := inet6, ip := IP} = Opts) ->
     client_config_name([$[, inet:ntoa(IP), $]], Tag, Opts);
client_config_name(Tag, #{family := inet, ip := IP} = Opts) ->
     client_config_name(inet:ntoa(IP), Tag, Opts).

client_config_name(IP, Tag,  Opts) ->
    {ok, Opts#{name => iolist_to_binary([IP, Tag])}}.

client_config(Opts0) ->
    maybe
        {ok, Opts1} ?= client_config_ip(Opts0),
        {ok, Opts2} ?= client_config_servers(Opts1),
        {ok, Opts} ?= client_config_name(Opts2),
        {ok, Opts#{metrics_callback => maps:get(metrics_callback, Opts0, undefined)}}
    end.

reconfigure_address(#{no_ports := NPorts} = Config,
                    #state{socket_id = OAdd, sockets = Sockts} = State) ->
    NAdd = socket_id(Config),
    case OAdd of
        NAdd    ->
            reconfigure_ports(NPorts, State);
        _ ->
            ?LOG(info, "Reopening RADIUS client sockets (client_ip changed to ~s)",
                 [socket_id_str(NAdd)]),
            array:map(
              fun(_PortIdx, undefined) ->
                      ok;
                 (_PortIdx, Socket) ->
                      eradius_client_socket:close(Socket)
              end, Sockts),
            Counters = fix_counters(NPorts, State#state.idcounters),
            State#state{sockets = array:new(), socket_id = NAdd,
                        no_ports = NPorts, idcounters = Counters}
    end.

reconfigure_ports(NPorts, #state{no_ports = OPorts, sockets = Sockets} = State) ->
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

find_socket_process(PortIdx, Sockets, #state{owner = Owner, config = Config}) ->
    case array:get(PortIdx, Sockets) of
        undefined ->
            {ok, Supervisor} = eradius_client_sup:socket_supervisor(Owner),
            {ok, Socket} = eradius_client_socket:new(Supervisor, Config),
            {Socket, array:set(PortIdx, Socket, Sockets)};
        Socket ->
            {Socket, Sockets}
    end.
