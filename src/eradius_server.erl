%% Copyright (c) 2002-2007, Martin Björklund and Torbjörn Törnkvist
%% Copyright (c) 2011, Travelping GmbH <info@travelping.com>
%%
%% SPDX-License-Identifier: MIT
%%
-module(eradius_server).
-feature(maybe_expr, enable).

-behaviour(gen_server).

%% API
-export([start_instance/3, start_instance/4, stop_instance/1]).
-export([start_link/3, start_link/4]).
-export_type([req_id/0]).

%% internal API
-export([do_radius/4]).
-ignore_xref([do_radius/4]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-ignore_xref([start_link/3, start_link/4]).
-ignore_xref([start_instance/3, start_instance/4, stop_instance/1]).

-include_lib("stdlib/include/ms_transform.hrl").
-include_lib("kernel/include/logger.hrl").
-include("eradius_lib.hrl").
-include("dictionary.hrl").
-include("eradius_dict.hrl").

-import(eradius_lib, [printable_peer/1, printable_peer/2]).

-define(RESEND_TIMEOUT, 5000).          % how long the binary response is kept after sending it on the socket
-define(RESEND_RETRIES, 3).             % how often a reply may be resent

-export_type([handler/0]).

-type req_id()      :: byte().
%% RADIUS request id

-type socket_opts() :: #{family => inet | inet6,
                         ifaddr => inet:ip_address() | any,
                         port => inet:port_number(),
                         active_n => 'once' | non_neg_integer(),
                         ipv6_v6only => boolean,
                         inet_backend => inet | socket,
                         recbuf => non_neg_integer(),
                         sndbuf => non_neg_integer()
                        }.
%% Options to configure the RADIUS server UDP socket.

-type socket_config() :: #{family := inet | inet6,
                           ifaddr := inet:ip_address() | any,
                           port := inet:port_number(),
                           active_n := 'once' | non_neg_integer(),
                           ipv6_v6only => boolean,
                           inet_backend => inet | socket,
                           recbuf => non_neg_integer(),
                           sndbuf => non_neg_integer()
                          }.
%% Options to configure the RADIUS server UDP socket.
%% Conceptually the same as `t:socket_opts/0', except that may fields are mandatory.

-type server_opts() :: #{server_name => term(),
                         socket_opts => socket_opts(),
                         handler := {module(), term()},
                         metrics_callback => eradius_req:metrics_callback(),
                         clients := map()}.
%% Options to configure the RADIUS server.

-type server_config() :: #{server_name := term(),
                           socket_opts := socket_config(),
                           handler := {module(), term()},
                           metrics_callback := undefined | eradius_req:metrics_callback(),
                           clients := map()}.
%% Options to configure the RADIUS server.
%% Conceptually the same as `t:server_opts/0', except that may fields are mandatory.

-type client() :: #{client := binary(),
                    secret := eradius_req:secret()}.
%% RADIUS client settings

-export_type([server_name/0, client/0]).

-record(state, {
                name           :: atom(),            % server name
                family         :: inet:address_family(),
                socket         :: gen_udp:socket(),      % Socket Reference of opened UDP port
                server         :: {inet:ip_address() | any, inet:port_number()}, % IP and port to which this socket is bound
                active_n       :: 'once' | non_neg_integer(),
                transacts      :: ets:tid(),         % ETS table containing current transactions
                handler        :: handler(),
                metrics_callback :: eradius_req:metrics_callback(),
                clients        :: #{inet:ip_address() => client()}
               }).

-callback radius_request(eradius_req:req(), HandlerData :: term()) ->
    {reply, eradius_req:req()} | noreply | {error, timeout}.

%%%=========================================================================
%%%  API
%%%=========================================================================

-spec start_instance(IP :: 'any' | inet:ip_address(), Port :: inet:port_number(),
                     Opts :: server_opts()) ->  gen_server:start_ret().
start_instance(IP, Port, Opts)
  when (IP =:= any orelse is_tuple(IP)) andalso
       is_integer(Port) andalso Port >= 0 andalso Port < 65536 ->
    eradius_server_sup:start_instance([IP, Port, Opts]).

-spec start_instance(ServerName :: gen_server:server_name(),
                     IP :: 'any' | inet:ip_address(), Port :: inet:port_number(),
                     Opts :: server_opts()) ->  gen_server:start_ret().
start_instance(ServerName, IP, Port, Opts)
  when (IP =:= any orelse is_tuple(IP)) andalso
       is_integer(Port) andalso Port >= 0 andalso Port < 65536 ->
    eradius_server_sup:start_instance([ServerName, IP, Port, Opts]).

-spec stop_instance(Pid :: pid()) -> ok.
stop_instance(Pid) ->
    try gen_server:call(Pid, stop)
    catch exit:_ -> ok end.

-spec start_link(IP :: 'any' | inet:ip_address(), Port :: inet:port_number(),
                 Opts :: server_opts()) ->  gen_server:start_ret().
start_link(IP, Port, #{handler := {_, _}, clients := #{}} = Opts)
  when (IP =:= any orelse is_tuple(IP)) andalso
       is_integer(Port) andalso Port >= 0 andalso Port < 65536 ->
    maybe
        {ok, Config} ?= config(IP, Port, Opts),
        gen_server:start_link(?MODULE, [Config], [])
    end.

-spec start_link(ServerName :: gen_server:server_name(),
                 IP :: 'any' | inet:ip_address(), Port :: inet:port_number(),
                 Opts :: server_opts()) ->  gen_server:start_ret().
start_link(ServerName, IP, Port, #{handler := {_, _}, clients := #{}} = Opts)
  when (IP =:= any orelse is_tuple(IP)) andalso
       is_integer(Port) andalso Port >= 0 andalso Port < 65536 ->
    maybe
        {ok, Config} ?= config(IP, Port, Opts),
        gen_server:start_link(ServerName, ?MODULE, [Config], [])
    end.

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

%% @private
init([#{server_name := ServerName,
        socket_opts := #{family := Family, active_n := ActiveN,
                         ifaddr := IP, port := Port} = SocketOpts,
        handler := Handler, metrics_callback := MetricsCallback,
        clients := Clients} = _Config]) ->
    process_flag(trap_exit, true),

    InetOpts = inet_opts(SocketOpts, [{active, ActiveN}, binary, Family]),
    Server = {IP, Port},
    ?LOG(debug, "Starting RADIUS server on ~s with socket options ~0p",
         [printable_peer(Server), InetOpts]),

    case gen_udp:open(Port, InetOpts) of
        {ok, Socket} ->
            State =
                #state{
                   name = ServerName,
                   family = Family,
                   socket = Socket,
                   server = {IP, Port},
                   active_n = ActiveN,
                   handler = Handler,
                   clients = Clients,
                   transacts = ets:new(transacts, []),
                   metrics_callback = MetricsCallback
                  },
            {ok, State};
        {error, Reason} ->
            ?LOG(debug, "Starting RADIUS server on ~s failed with ~0p",
                 [printable_peer(Server), Reason]),
            {stop, Reason}
    end.

%% @private
handle_call(stop, _From, State) ->
    {stop, normal, ok, State};
handle_call(_Call, _From, State) ->
    {reply, ok, State}.

%% @private
handle_cast(_Msg, State) ->
    {noreply, State}.

%% @private
handle_info({udp_passive, _Socket}, #state{socket = Socket, active_n = ActiveN} = State) ->
    inet:setopts(Socket, [{active, ActiveN}]),
    {noreply, State};

handle_info({udp, Socket, FromIP, FromPortNo, <<Header:20/bytes, Body/binary>>},
            #state{name = ServerName, server = Server, transacts = Transacts,
                   handler = Handler, clients = Clients,
                   metrics_callback = MetricsCallback} = State)
  when is_map_key(FromIP, Clients) ->
    NAS = maps:get(FromIP, Clients),
    <<_, ReqId:8, _/binary>> = Header,
    Req0 = eradius_req:request(Header, Body, NAS, MetricsCallback),
    Req1 = Req0#{socket => Socket,
                 server => ServerName,
                 server_addr => Server,
                 client_addr => {FromIP, FromPortNo}},
    ReqKey = {FromIP, FromPortNo, ReqId},

    case ets:lookup(Transacts, ReqKey) of
        [] ->
            Req = eradius_req:record_metric(request, #{}, Req1),
            HandlerPid =
                proc_lib:spawn_link(?MODULE, do_radius, [self(), Handler, ReqKey, Req]),
            ets:insert(Transacts, {ReqKey, {handling, HandlerPid}}),
            ets:insert(Transacts, {HandlerPid, ReqKey});

        [{_ReqKey, {handling, HandlerPid}}] ->
            %% handler process is still working on the request
            ?LOG(debug, "~s From: ~s INF: Handler process ~p is still working on the request."
                 " duplicate request (being handled) ~p",
                 [printable_peer(Server),
                  printable_peer(FromIP, FromPortNo), HandlerPid, ReqKey]),
            eradius_req:record_metric(discard, #{reason => duplicate}, Req1);
        [{_ReqKey, {replied, HandlerPid}}] ->
            %% handler process waiting for resend message
            HandlerPid ! {self(), resend},
            ?LOG(debug, "~s From: ~s INF: Handler ~p waiting for resent message. "
                 "duplicate request (resent) ~p",
                 [printable_peer(Server),
                  printable_peer(FromIP, FromPortNo), HandlerPid, ReqKey]),
            eradius_req:record_metric(retransmission, #{reason => duplicate}, Req1)
    end,
    flow_control(State),
    {noreply, State};

handle_info({udp, _Socket, _FromIP, _FromPortNo, _Packet},
            #state{name = ServerName, metrics_callback = MetricsCallback} = State) ->
    %% TBD: this should go into a malformed counter
    eradius_req:metrics_callback(MetricsCallback, invalid_request, #{server => ServerName}),
    flow_control(State),
    {noreply, State};

handle_info({replied, ReqKey, HandlerPid}, State = #state{transacts = Transacts}) ->
    ets:insert(Transacts, {ReqKey, {replied, HandlerPid}}),
    {noreply, State};

handle_info({'EXIT', HandlerPid, _Reason}, State = #state{transacts = Transacts}) ->
    [ets:delete(Transacts, ReqKey) || {_, ReqKey} <- ets:take(Transacts, HandlerPid)],
    {noreply, State};

handle_info(_Info, State) ->
    {noreply, State}.

%% @private
terminate(_Reason, State) ->
    gen_udp:close(State#state.socket),
    ok.

%% @private
code_change(_OldVsn, State, _Extra) -> {ok, State}.

%%%=========================================================================
%%% handler functions
%%%=========================================================================

%% @private
-spec do_radius(pid(), handler(), term(), eradius_req:req()) -> any().
do_radius(ServerPid, {HandlerMod, HandlerArg}, ReqKey,
          #{server := Server, client_addr := Client} = Req0) ->
    case apply_handler_mod(HandlerMod, HandlerArg, Req0) of
        {reply, Packet, Resp0, Req} ->
            ?LOG(debug, "~s From: ~s INF: Sending response for request ~0p",
                 [printable_peer(Server), printable_peer(Client), ReqKey]),

            Resp = eradius_req:record_metric(reply, #{request => Req}, Resp0),
            send_response(Resp, Packet),
            case application:get_env(eradius, resend_timeout, 2000) of
                ResendTimeout when ResendTimeout > 0, is_integer(ResendTimeout) ->
                    ServerPid ! {replied, ReqKey, self()},
                    wait_resend_init(ServerPid, ReqKey, Resp, Packet, ResendTimeout, ?RESEND_RETRIES);
                _ -> ok
            end;
        {discard, Reason} ->
            ?LOG(debug, "~s From: ~s INF: Handler discarded the request ~p for reason ~1000.p",
                 [printable_peer(Server), printable_peer(Client), Reason, ReqKey]),
            eradius_req:record_metric(discard, #{reason => Reason}, Req0);
        {exit, Reason} ->
            ?LOG(debug, "~s From: ~s INF: Handler exited for reason ~p, discarding request ~p",
                 [printable_peer(Server), printable_peer(Client), Reason, ReqKey]),
            eradius_req:record_metric(discard, #{reason => dropped}, Req0)
    end.

wait_resend_init(ServerPid, ReqKey, Resp, Packet, ResendTimeout, Retries) ->
    erlang:send_after(ResendTimeout, self(), timeout),
    wait_resend(ServerPid, ReqKey, Resp, Packet, Retries).

wait_resend(_ServerPid, _ReqKey, _Resp, _Packet, 0) ->
    ok;
wait_resend(ServerPid, ReqKey, Resp, Packet, Retries) ->
    receive
        {ServerPid, resend} ->
            send_response(Resp, Packet),
            wait_resend(ServerPid, ReqKey, Resp, Packet, Retries - 1);
        timeout -> ok
    end.

send_response(#{socket := Socket, client_addr := {ClientIP, ClientPort}}, Packet) ->
    gen_udp:send(Socket, ClientIP, ClientPort, Packet).

-spec apply_handler_mod(module(), term(), eradius_req:req()) ->
          {discard, term()} |
          {exit, term()} |
          {reply, binary(), eradius_req:req(), eradius_req:req()}.
apply_handler_mod(HandlerMod, HandlerArg,
                  #{cmd := Cmd, req_id := ReqId, server := Server, client_addr := {ClientIP, _}} = Req) ->
    try HandlerMod:radius_request(Req, HandlerArg) of
        {reply, Resp0} ->
            {Packet, Resp} = eradius_req:packet(Resp0),
            {reply, Packet, Resp, Req};
        noreply ->
            ?LOG(error, "~ts INF: Noreply for request ~tp from handler ~tp: returned value: ~tp",
                 [printable_peer(Server), ReqId, HandlerArg, noreply]),
            {discard, handler_returned_noreply};
        {error, timeout} ->
            ReqType = eradius_log:format_cmd(Cmd),
            ?LOG(error, "~ts INF: Timeout after waiting for response to ~ts(~w) from RADIUS Client: ~s",
                 [printable_peer(Server), ReqType, ReqId, inet:ntoa(ClientIP)]),
            {discard, {bad_return, {error, timeout}}};
        OtherReturn ->
            ?LOG(error, "~ts INF: Unexpected return for request ~0tp from handler ~tp: returned value: ~tp",
                 [printable_peer(Server), ReqId, HandlerArg, OtherReturn]),
            {discard, {bad_return, OtherReturn}}
    catch
        Class:Reason:S ->
            ?LOG(error, "~ts INF: Handler crashed after request ~tp, radius handler class: ~tp, reason of crash: ~tp, stacktrace: ~tp",
                 [printable_peer(Server), ReqId, Class, Reason, S]),
            {exit, {Class, Reason}}
    end.

%%%=========================================================================
%%%  internal functions
%%%=========================================================================

-spec config(IP :: inet:ip_address() | any, inet:port_number(),
             server_opts()) -> {ok, server_config()}.
config(IP, Port, #{handler := {_, _}, clients := Clients} = Opts0)
  when (IP =:= any orelse is_tuple(IP)) andalso
       is_map(Clients) andalso
       is_integer(Port) andalso Port >= 0 andalso Port < 65536 ->
    SocketOpts0 = maps:get(socket_opts, Opts0, #{}),
    SocketOpts = #{family := Family, ifaddr := IfAddr} =
        maps:merge(default_socket_opts(IP, Port), to_map(SocketOpts0)),

    Opts =
        Opts0#{server_name => server_name(IP, Port, Opts0),
               socket_opts => SocketOpts#{ifaddr := socket_ip(Family, IfAddr)},
               metrics_callback => maps:get(metrics_callback, Opts0, undefined),
               clients =>
                   maps:fold(fun(K, V, M) -> M#{socket_ip(Family, K) => V} end, #{}, Clients)
              },
    {ok, Opts}.

flow_control(#state{socket = Socket, active_n = once}) ->
    inet:setopts(Socket, [{active, once}]);
flow_control(_) ->
    ok.

server_name(_, _, #{server_name := ServerName}) ->
    ServerName;
server_name(IP, Port, _) ->
    iolist_to_binary(server_name(IP, Port)).

server_name(IP, Port) ->
    [inet:ntoa(IP), $:, integer_to_list(Port)].

to_map(Opts) when is_list(Opts) ->
    maps:from_list(Opts);
to_map(Opts) when is_map(Opts) ->
    Opts.

%% @private
socket_ip(_, any) ->
    any;
socket_ip(inet, {_, _, _, _} = IP) ->
    IP;
socket_ip(inet6, {_, _, _, _} = IP) ->
    inet:ipv4_mapped_ipv6_address(IP);
socket_ip(inet6, {_, _, _, _,_, _, _, _} = IP) ->
    IP.

default_socket_opts(Port) ->
    #{port => Port,
      active_n => 100,
      recbuf => application:get_env(eradius, recbuf, 8192),
      sndbuf => application:get_env(eradius, sndbuf, 131072)
     }.

default_socket_opts(any, Port) ->
    Opts = default_socket_opts(Port),
    Opts#{family => inet6,
          ifaddr => any,
          ipv6_v6only => false};
default_socket_opts({_, _, _, _} = IP, Port) ->
    Opts = default_socket_opts(Port),
    Opts#{family => inet,
          ifaddr => IP};
default_socket_opts({_, _, _, _, _, _, _, _} = IP, Port) ->
    Opts = default_socket_opts(Port),
    Opts#{family => inet6,
          ifaddr => IP,
          ipv6_v6only => false}.

inet_opts(Config, Opts0) ->
    Opts =
        maps:to_list(
          maps:with([recbuf, sndbuf, ifaddr,
                     ipv6_v6only, netns, bind_to_device, read_packets], Config)) ++ Opts0,
    case Config of
        #{inet_backend := Backend} when Backend =:= inet; Backend =:= socket ->
            [{inet_backend, Backend} | Opts];
        _ ->
            Opts
    end.
