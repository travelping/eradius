%% Copyright (c) 2002-2007, Martin Björklund and Torbjörn Törnkvist
%% Copyright (c) 2011, Travelping GmbH <info@travelping.com>
%%
%% SPDX-License-Identifier: MIT

-module(eradius_client_mngr).

-moduledoc """
RADIUS client instance manager.

Manages a pool of UDP sockets and the state of configured RADIUS servers.
Each client manager is a `gen_server` supervised by the eradius application tree.
Requests are dispatched through `m:eradius_client`.

== Configuration ==

A client is started with a `t:client_opts/0` map. The mandatory `servers` key maps
server names to either a `t:server_opts/0` map (a concrete server) or a
`t:server_pool/0` list of server names (a named pool for failover):

```
{ok, _} = eradius_client_mngr:start_client({local, my_client},
                                           #{family  => inet,
                                             ip      => any,
                                             servers => #{
                                                          primary   => #{ip => {10,0,0,1}, port => 1812,
                                                                         secret => <<"secret1">>, retries => 3},
                                                          secondary => #{ip => {10,0,0,2}, port => 1812,
                                                                         secret => <<"secret2">>},
                                                          auth_pool => [primary, secondary]
                                                         }}).
```

== Failure tracking ==

The manager tracks server failures. A server that fails to respond is marked as
unreachable for a configurable period (`unreachable_timeout` application env, default 2 s).
Pool-based failover in `m:eradius_client` automatically skips unreachable servers.

== Socket pool ==

The client opens `no_ports` UDP sockets (default: 1) on OS-assigned ports.
Each socket supports up to 256 concurrent requests (one per RADIUS request id).
Increase `no_ports` for higher concurrency requirements.
""".

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
                         secret := binary(),
                         retries => non_neg_integer(),
                         timeout => non_neg_integer()}.
%% Options to describe a RADIUS server.

-type server() :: #{ip := inet:ip_address(),
                    port := inet:port_number(),
                    secret := binary(),
                    retries := non_neg_integer(),
                    timeout := non_neg_integer(),
                    failed := non_neg_integer()}.
%% Options to describe a RADIUS server.
%% Conceptually the same as server_opts(), except that mandatory fields use :=.

-type server_pool() :: [server_name()].
%% List of server names that form a pool.

-type servers() :: #{server_name() := server() | server_pool()}.
%% Map of server and pool definition. Key is the name of the entry.

-type client_opts() ::
        #{name => server_name(),
          servers :=  #{server_name() := server_opts() | server_pool()},
          family => inet | inet6,
          inet_backend => inet | socket,
          ip => any | inet:ip_address(),
          active_n => once | non_neg_integer(),
          no_ports => pos_integer(),
          max_ports_per_server => pos_integer(),
          reqid_reuse_timeout => pos_integer(),
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
%% Conceptually the same as client_opts(), except that mandatory fields use :=.

-export_type([server_name/0, server_pool/0, servers/0, client_opts/0]).

-define(RECONFIGURE_TIMEOUT, 15000).
-define(DEFAULT_MAX_RETRIES, 20).
-define(DEFAULT_DOWN_TIME, 1000).
-define(DEFAULT_K_PORTS, 10).
-define(DEFAULT_MAX_PORTS_PER_SERVER, 256).
-define(DEFAULT_REQID_REUSE_TIMEOUT, 30000).

-record(state, {
                owner :: pid(),
                config :: client_config(),
                client_name :: server_name(),
                client_addr :: any | inet:ip_address(),
                servers :: servers(),
                socket_id :: {Family :: inet | inet6, IP :: any | inet:ip_address()},
                k_ports = ?DEFAULT_K_PORTS :: pos_integer(),
                max_ports = ?DEFAULT_MAX_PORTS_PER_SERVER :: pos_integer(),
                reqid_reuse_timeout = ?DEFAULT_REQID_REUSE_TIMEOUT :: pos_integer(),
                pools = #{} :: #{server_addr() => pool()},
                socket_refs = #{} :: #{reference() => server_addr()},
                no_ports_rejections = 0 :: non_neg_integer(),
                metrics_callback :: undefined | eradius_req:metrics_callback()
               }).

-type server_addr() :: {inet:ip_address(), inet:port_number()}.
-type filler() :: #{pid := pid(), monitor := reference(),
                    next_id := 0..255, issued := 0..256}.
-type pool() :: #{active := [filler()], cooling := [pid()]}.

%%%=========================================================================
%%%  API
%%%=========================================================================

-doc """
Start a new RADIUS client that is managed by the eradius applications supervisor tree.
Returns the client manager pid (usable with eradius_client:send_request/3,4).
""".
-spec start_client(client_opts()) ->
          {ok, pid()} | {error, supervisor:startchild_err()}.
start_client(Opts) ->
    case eradius_client_top_sup:start_client([Opts]) of
        {ok, SupPid} ->
            client_mngr_pid(SupPid);
        Error ->
            Error
    end.

-doc "Start a new, named RADIUS client that is managed by the eradius applications supervisor tree.".
-spec start_client(gen_server:server_name(), client_opts()) ->
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
-spec start_link(pid(), gen_server:server_name(), client_opts()) ->
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

-doc """
Reconfigure a running RADIUS client manager.

Merges `Opts` into the current configuration. The manager will update its server list
and socket pool accordingly, closing sockets that are no longer needed and opening new ones.
Waits up to 15 seconds for the reconfiguration to complete.
""".
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
            when Failed =< Retries ->
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
               k_ports = NPorts,
               max_ports = maps:get(max_ports_per_server, Config,
                                    ?DEFAULT_MAX_PORTS_PER_SERVER),
               reqid_reuse_timeout = maps:get(reqid_reuse_timeout, Config,
                                              ?DEFAULT_REQID_REUSE_TIMEOUT),
               metrics_callback = MetricsCallback
              },
    {ok, State}.

%% @private
handle_call({wanna_send, Candidates, Tried}, _From,
            #state{client_name = ClientName, client_addr = ClientAddr,
                   servers = Servers,
                   metrics_callback = MetricsCallback} = State0) ->
    case select_server(Candidates, Tried, Servers) of
        {ok, {ServerName, #{ip := IP, port := Port} = Server}} ->
            ServerAddr = {IP, Port},
            case allocate(ServerAddr, State0) of
                {ok, Pid, ReqId, State} ->
                    ReqInfo =
                        #{server => ServerName, server_addr => ServerAddr,
                          client => ClientName, client_addr => ClientAddr,
                          metrics_callback => MetricsCallback},
                    {reply, {ok, {Pid, ReqId, ServerName, Server, ReqInfo}}, State};
                {error, no_ports, #state{no_ports_rejections = N} = State1} ->
                    State = State1#state{no_ports_rejections = N + 1},
                    ?LOG(warning, "RADIUS client port pool for ~p saturated", [ServerAddr]),
                    {reply, {error, no_ports}, State}
            end;
        {error, _} = Error ->
            {reply, Error, State0}
    end;

handle_call({failed, Peer}, _From, #state{servers = Servers} = State0)
  when is_map_key(Peer, Servers) ->
    #{retries := Retries, failed := Failed} = Server = map_get(Peer, Servers),
    case Failed > Retries of
        true  -> erlang:start_timer(?DEFAULT_DOWN_TIME, self(), {reset, Peer});
        false -> ok
    end,
    State = State0#state{servers = Servers#{Peer := Server#{failed := Failed + 1}}},
    {reply, ok, State};
handle_call({failed, _Peer}, _From, State) ->
    {reply, ok, State};

%% @private
handle_call({reconfigure, Opts}, _From, #state{config = OConfig} = State0) ->
    case client_config(maps:merge(OConfig, Opts)) of
        {ok, #{servers := Servers} = Config} ->
            State1 = State0#state{config = Config, servers = Servers},
            State = reconfigure_address(Config, State1),
            {reply, ok, State};

        {error, _} = Error ->
            {reply, Error, State0}
    end;

%% @private
handle_call(_OtherCall, _From, State) ->
    {reply, {error, unknown_request}, State}.

%% @private
handle_cast(_Msg, State) -> {noreply, State}.

%% @private
handle_info({'DOWN', Ref, process, Pid, _Reason},
            #state{socket_refs = Refs} = State) ->
    case maps:take(Ref, Refs) of
        {ServerAddr, Refs1} ->
            Pool = pool_of(ServerAddr, State),
            Pool1 = remove_socket(Pid, Ref, Pool),
            {noreply, put_pool(ServerAddr, Pool1, State#state{socket_refs = Refs1})};
        error ->
            {noreply, State}
    end;

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

%% Retained for an upcoming task that reworks reconfigure_address to close
%% sockets and log the new client address.
-compile({nowarn_unused_function, socket_id_str/1}).
socket_id_str({_, IP}) when is_tuple(IP) ->
    inet:ntoa(IP);
socket_id_str({_, IP}) when is_atom(IP) ->
    atom_to_list(IP).

%% @private
default_client_opts() ->
    #{family => inet6,
      ip => any,
      no_ports => ?DEFAULT_K_PORTS,
      max_ports_per_server => ?DEFAULT_MAX_PORTS_PER_SERVER,
      reqid_reuse_timeout => ?DEFAULT_REQID_REUSE_TIMEOUT,
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
          when Failed =< Retries ->
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
                    #state{socket_id = OAdd, socket_refs = Refs} = State) ->
    NAdd = socket_id(Config),
    case OAdd of
        NAdd -> reconfigure_ports(NPorts, State);
        _    ->
            %% address changed: drop all pools. Demonitor first so the abandoned
            %% sockets' DOWNs don't linger in the mailbox. (Task A8 also closes them.)
            maps:foreach(fun(Ref, _SA) -> erlang:demonitor(Ref, [flush]) end, Refs),
            State#state{socket_id = NAdd, k_ports = NPorts,
                        pools = #{}, socket_refs = #{}}
    end.

reconfigure_ports(NPorts, State) ->
    State#state{k_ports = NPorts}.

-spec new_pool() -> pool().
new_pool() -> #{active => [], cooling => []}.

pool_of(ServerAddr, #state{pools = Pools}) ->
    maps:get(ServerAddr, Pools, new_pool()).

put_pool(ServerAddr, Pool, #state{pools = Pools} = State) ->
    State#state{pools = Pools#{ServerAddr => Pool}}.

%% active fillers + cooling (retired-but-open) sockets. cooling pids are reclaimed
%% when their socket exits (the 'DOWN' handler), bounding the per-server total.
pool_total(#{active := A, cooling := C}) -> length(A) + length(C).

%% Drop a dead socket (by pid) from a pool, whether it was an active filler or
%% a cooling socket.
remove_socket(Pid, _Ref, #{active := Active, cooling := Cooling} = Pool) ->
    Pool#{active := [F || F <- Active, maps:get(pid, F) =/= Pid],
          cooling := lists:delete(Pid, Cooling)}.

%% Allocate {Pid, ReqId} for ServerAddr, growing/rolling the pool as needed.
-spec allocate(server_addr(), #state{}) ->
          {ok, pid(), 0..255, #state{}} | {error, no_ports, #state{}}.
allocate(ServerAddr, State0) ->
    State1 = ensure_active(ServerAddr, State0),
    Pool = pool_of(ServerAddr, State1),
    case maps:get(active, Pool) of
        [] ->
            {error, no_ports, State1};
        [#{pid := Pid, next_id := ReqId, issued := Issued0} = F | Rest] ->
            Issued = Issued0 + 1,
            case Issued >= 256 of
                true ->
                    %% filler exhausted: retire it (socket cools+closes itself),
                    %% move it to cooling, and open a replacement.
                    ok = eradius_client_socket:retire(Pid),
                    Pool1 = Pool#{active := Rest,
                                  cooling := [Pid | maps:get(cooling, Pool)]},
                    State2 = put_pool(ServerAddr, Pool1, State1),
                    State3 = ensure_active(ServerAddr, State2),
                    {ok, Pid, ReqId, State3};
                false ->
                    %% round-robin: advance this filler and move it to the tail.
                    F1 = F#{next_id := (ReqId + 1) rem 256, issued := Issued},
                    Pool1 = Pool#{active := Rest ++ [F1]},
                    {ok, Pid, ReqId, put_pool(ServerAddr, Pool1, State1)}
            end
    end.

%% Open fillers until there are K active (or the per-server cap is hit, or a
%% socket open fails). Idempotent.
-spec ensure_active(server_addr(), #state{}) -> #state{}.
ensure_active(ServerAddr, #state{k_ports = K, max_ports = Max} = State) ->
    Pool = pool_of(ServerAddr, State),
    Active = maps:get(active, Pool),
    case length(Active) < K andalso pool_total(Pool) < Max of
        true ->
            case open_filler(ServerAddr, State) of
                {ok, Filler, State1} ->
                    Pool1 = pool_of(ServerAddr, State1),
                    Pool2 = Pool1#{active := maps:get(active, Pool1) ++ [Filler]},
                    ensure_active(ServerAddr, put_pool(ServerAddr, Pool2, State1));
                {error, _} ->
                    State
            end;
        false ->
            State
    end.

-spec open_filler(server_addr(), #state{}) ->
          {ok, filler(), #state{}} | {error, term()}.
open_filler(ServerAddr, #state{owner = Owner, config = Config,
                               reqid_reuse_timeout = RT,
                               socket_refs = Refs} = State) ->
    {ok, Supervisor} = eradius_client_sup:socket_supervisor(Owner),
    SockConfig = Config#{server_addr => ServerAddr, reqid_reuse_timeout => RT},
    case eradius_client_socket:new(Supervisor, SockConfig) of
        {ok, Pid} ->
            Ref = erlang:monitor(process, Pid),
            Filler = #{pid => Pid, monitor => Ref, next_id => 0, issued => 0},
            {ok, Filler, State#state{socket_refs = Refs#{Ref => ServerAddr}}};
        {error, _} = Error ->
            ?LOG(warning, "could not open RADIUS client socket for ~p: ~p",
                 [ServerAddr, Error]),
            Error
    end.

client_mngr_pid(SupPid) ->
    case lists:keyfind(eradius_client_mngr, 1, supervisor:which_children(SupPid)) of
        {eradius_client_mngr, Pid, worker, _} when is_pid(Pid) ->
            {ok, Pid};
        _ ->
            {error, not_started}
    end.
