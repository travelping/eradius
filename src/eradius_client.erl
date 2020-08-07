%% @doc This module contains a RADIUS client that can be used to send authentication and accounting requests.
%%   A counter is kept for every NAS in order to determine the next request id and sender port
%%   for each outgoing request. The implementation naively assumes that you won't send requests to a
%%   distinct number of NASs over the lifetime of the VM, which is why the counters are not garbage-collected.
%%
%%   The client uses OS-assigned ports. The maximum number of open ports can be specified through the
%%   ``client_ports'' application environment variable, it defaults to ``20''. The number of ports should not
%%   be set too low. If ``N'' ports are opened, the maximum number of concurrent requests is ``N * 256''.
%%
%%   The IP address used to send requests is read <emph>once</emph> (at startup) from the ``client_ip''
%%   parameter. Changing it currently requires a restart. It can be given as a string or ip address tuple,
%%   or the atom ``undefined'' (the default), which uses whatever address the OS selects.
-module(eradius_client).
-export([start_link/0, send_request/2, send_request/3, send_remote_request/3, send_remote_request/4]).
%% internal
-export([reconfigure/0, send_remote_request_loop/8]).

-behaviour(gen_server).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-import(eradius_lib, [printable_peer/2]).

-include_lib("kernel/include/logger.hrl").
-include("eradius_lib.hrl").
-define(SERVER, ?MODULE).
-define(DEFAULT_RETRIES, 3).
-define(DEFAULT_TIMEOUT, 5000).
-define(RECONFIGURE_TIMEOUT, 15000).
-define(GOOD_CMD(Req), (Req#radius_request.cmd == 'request' orelse
                        Req#radius_request.cmd == 'accreq' orelse
                        Req#radius_request.cmd == 'coareq' orelse
                        Req#radius_request.cmd == 'discreq')).

-type nas_address() :: {string() | binary() | inet:ip_address(), 
                        eradius_server:port_number(), 
                        eradius_lib:secret()}.
-type options() :: [{retries, pos_integer()} |
                    {timeout, timeout()} |
                    {server_name, atom()} |
                    {metrics_info, {atom(), atom(), atom()}}].

-export_type([nas_address/0, options/0]).

-include_lib("kernel/include/inet.hrl").

%% ------------------------------------------------------------------------------------------
%% -- API
% @private
start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

% @equiv send_request(NAS, Request, [])
-spec send_request(nas_address(), #radius_request{}) -> {ok, binary()} | {error, 'timeout' | 'socket_down'}.
send_request(NAS, Request) ->
    send_request(NAS, Request, []).

% @doc Send a radius request to the given NAS.
%   If no answer is received within the specified timeout, the request will be sent again.
-spec send_request(nas_address(), #radius_request{}, options()) ->
    {ok, binary(), eradius_lib:authenticator()} | {error, 'timeout' | 'socket_down'}.
send_request({Host, Port, Secret}, Request, Options) 
  when ?GOOD_CMD(Request) andalso is_binary(Host) ->
    send_request({erlang:binary_to_list(Host), Port, Secret}, Request, Options);
send_request({Host, Port, Secret}, Request, Options) 
  when ?GOOD_CMD(Request) andalso is_list(Host) ->
    case inet:gethostbyname(Host) of
        {ok, #hostent{h_addrtype = inet, h_addr_list = [IP]}} -> 
            send_request({IP, Port, Secret}, Request, Options);
        {ok, #hostent{h_addrtype = inet, h_addr_list = [_ | _] = IPs}} -> 
            Index = rand:uniform(length(IPs)),
            IP = lists:nth(Index, IPs),
            send_request({IP, Port, Secret}, Request, Options);
        _ -> error(badarg)
    end;
send_request({IP, Port, Secret}, Request, Options) when ?GOOD_CMD(Request) andalso is_tuple(IP) ->
    TS1 = eradius_metrics:timestamp(milli_seconds),
    ServerName = proplists:get_value(server_name, Options, undefined),
    MetricsInfo = make_metrics_info(Options, {IP, Port}),
    Retries = proplists:get_value(retries, Options, ?DEFAULT_RETRIES),
    Timeout = proplists:get_value(timeout, Options, ?DEFAULT_TIMEOUT),
    Peer = {ServerName, {IP, Port}},
    {Socket, ReqId} = gen_server:call(?SERVER, {wanna_send, Peer, MetricsInfo}),
    Response = send_request_loop(Socket, ReqId, Peer, Request#radius_request{reqid = ReqId, secret = Secret}, Retries, Timeout, MetricsInfo),
    proceed_response(Request, Response, Peer, TS1, MetricsInfo);
send_request({_IP, _Port, _Secret}, _Request, _Options) ->
    error(badarg).

% @equiv send_remote_request(Node, NAS, Request, [])
-spec send_remote_request(node(), nas_address(), #radius_request{}) -> {ok, binary()} | {error, 'timeout' | 'node_down' | 'socket_down'}.
send_remote_request(Node, NAS, Request) ->
    send_remote_request(Node, NAS, Request, []).

% @doc Send a radius request to the given NAS through a socket on the specified node.
%   If no answer is received within the specified timeout, the request will be sent again.
%   The request will not be sent again if the remote node is unreachable.
-spec send_remote_request(node(), nas_address(), #radius_request{}, options()) -> {ok, binary()} | {error, 'timeout' | 'node_down' | 'socket_down'}.
send_remote_request(Node, {IP, Port, Secret}, Request, Options) when ?GOOD_CMD(Request) ->
    TS1 = eradius_metrics:timestamp(milli_seconds),
    ServerName = proplists:get_value(server_name, Options, undefined),
    MetricsInfo = make_metrics_info(Options, {IP, Port}),
    Peer = {ServerName, {IP, Port}},
    try gen_server:call({?SERVER, Node}, {wanna_send, Peer, MetricsInfo}) of
        {Socket, ReqId} ->
            Request1 = case eradius_node_mon:get_remote_version(Node) of
                           {0, Minor} when Minor < 6 ->
                               {_, EncRequest} = eradius_lib:encode_request(Request#radius_request{reqid = ReqId, secret = Secret}),
                               EncRequest;
                           _ ->
                               Request#radius_request{reqid = ReqId, secret = Secret}
                       end,
            Retries = proplists:get_value(retries, Options, ?DEFAULT_RETRIES),
            Timeout = proplists:get_value(timeout, Options, ?DEFAULT_TIMEOUT),
            SenderPid = spawn(Node, ?MODULE, send_remote_request_loop,
                             [self(), Socket, ReqId, Peer, Request1, Retries, Timeout, MetricsInfo]),
            SenderMonitor = monitor(process, SenderPid),
            Response = receive
                       {SenderPid, Result} ->
                            erlang:demonitor(SenderMonitor, [flush]),
                            Result;
                        {'DOWN', SenderMonitor, process, SenderPid, _Reason} ->
                            {error, socket_down}
                    end,
            proceed_response(Request, Response, Peer, TS1, MetricsInfo)
    catch
        exit:{{nodedown, Node}, _} ->
            {error, node_down}
    end;
send_remote_request(_Node, {_IP, _Port, _Secret}, _Request, _Options) ->
    error(badarg).

proceed_response(Request, {ok, Response, Secret, Authenticator}, _Peer = {_ServerName, {ServerIP, Port}}, TS1, MetricsInfo) ->
    update_client_request(Request#radius_request.cmd, MetricsInfo, eradius_metrics:timestamp(milli_seconds) - TS1),
    case eradius_lib:decode_request(Response, Secret, Authenticator) of
        {bad_pdu, Reason} ->
            update_client_response(dropped, MetricsInfo),
            ?LOG(error, "~s INF: Noreply for request ~p. Could not decode the request, reason: ~s", [printable_peer(ServerIP, Port), Request, Reason]),
            noreply;
        Decoded ->
            update_client_response(Decoded#radius_request.cmd, MetricsInfo),
            {ok, Response, Authenticator}
    end;
proceed_response(Request, Response, _Peer, TS1, MetricsInfo) ->
    update_client_request(Request#radius_request.cmd, MetricsInfo, eradius_metrics:timestamp(milli_seconds) - TS1),
    Response.

% @private
send_remote_request_loop(ReplyPid, Socket, ReqId, Peer, EncRequest, Retries, Timeout, MetricsInfo) ->
    ReplyPid ! {self(), send_request_loop(Socket, ReqId, Peer, EncRequest, Retries, Timeout, MetricsInfo)}.

send_request_loop(Socket, ReqId, Peer, Request = #radius_request{}, Retries, Timeout, undefined) ->
    send_request_loop(Socket, ReqId, Peer, Request, Retries, Timeout, eradius_metrics:make_addr_info(Peer));
send_request_loop(Socket, ReqId, Peer, Request, Retries, Timeout, MetricsInfo) ->
    {Authenticator, EncRequest} = eradius_lib:encode_request(Request),
    SMon = erlang:monitor(process, Socket),
    send_request_loop(Socket, SMon, Peer, ReqId, Authenticator, EncRequest, Timeout, Retries, MetricsInfo, Request#radius_request.secret).

send_request_loop(_Socket, SMon, _Peer, _ReqId, _Authenticator, _EncRequest, Timeout, 0, MetricsInfo, _Secret) ->
    update_client_request(timeout, MetricsInfo, Timeout),
    erlang:demonitor(SMon, [flush]),
    {error, timeout};
send_request_loop(Socket, SMon, Peer = {_ServerName, {IP, Port}}, ReqId, Authenticator, EncRequest, Timeout, RetryN, MetricsInfo, Secret) ->
    Socket ! {self(), send_request, {IP, Port}, ReqId, EncRequest},
    update_client_request(pending, MetricsInfo, 1),
    receive
        {Socket, response, ReqId, Response} ->
            update_client_request(pending, MetricsInfo, -1),
            {ok, Response, Secret, Authenticator};
        {'DOWN', SMon, process, Socket, _} ->
            {error, socket_down};
        {Socket, error, Error} ->
            {error, Error}
    after
        Timeout ->
            update_client_request(retransmission, MetricsInfo, Timeout),
            send_request_loop(Socket, SMon, Peer, ReqId, Authenticator, EncRequest, Timeout, RetryN - 1, MetricsInfo, Secret)
    end.

% @private
update_client_request(request, MetricsInfo, Ms) ->
    eradius_metrics:update_client_request("access", MetricsInfo, Ms);
update_client_request(accreq, MetricsInfo, Ms) ->
    eradius_metrics:update_client_request("accounting", MetricsInfo, Ms);
update_client_request(coareq, MetricsInfo, Ms) ->
    eradius_metrics:update_client_request("coa", MetricsInfo, Ms);
update_client_request(discreq, MetricsInfo, Ms) ->
    eradius_metrics:update_client_request("disconnect", MetricsInfo, Ms);
update_client_request(retransmission, MetricsInfo, Ms) ->
    eradius_metrics:update_client_request("retransmission", MetricsInfo, Ms);
update_client_request(pending, MetricsInfo, Pending) ->
    eradius_metrics:update_client_request("pending", MetricsInfo, Pending);
update_client_request(timeout, MetricsInfo, Ms) ->
    eradius_metrics:update_client_request("timeout", MetricsInfo, Ms);
update_client_request(_, _, _) ->
    ok.

%% @private
update_client_response(accept, MetricsInfo) ->
    eradius_metrics:update_client_response("access_accept", MetricsInfo);
update_client_response(reject, MetricsInfo) ->
    eradius_metrics:update_client_response("access_reject", MetricsInfo);
update_client_response(challenge, MetricsInfo) ->
    eradius_metrics:update_client_response("access_challenge", MetricsInfo);
update_client_response(accresp, MetricsInfo) ->
    eradius_metrics:update_client_response("accounting", MetricsInfo);
update_client_response(coanak, MetricsInfo) ->
    eradius_metrics:update_client_response("coa_nak", MetricsInfo);
update_client_response(coaack, MetricsInfo) ->
    eradius_metrics:update_client_response("coa_ack", MetricsInfo);
update_client_response(discnak, MetricsInfo) ->
    eradius_metrics:update_client_response("disconnect_nak", MetricsInfo);
update_client_response(discack, MetricsInfo) ->
    eradius_metrics:update_client_response("disconnect_ack", MetricsInfo);
update_client_response(dropped, MetricsInfo) ->
    eradius_metrics:update_client_response("dropped", MetricsInfo);
update_client_response(_, _) ->
    ok.

%% @private
reconfigure() ->
    catch gen_server:call(?SERVER, reconfigure, ?RECONFIGURE_TIMEOUT).

%% ------------------------------------------------------------------------------------------
%% -- socket process manager
-record(state, {
    socket_ip :: null | inet:ip_address(),
    no_ports = 1 :: pos_integer(),
    idcounters = maps:new() :: map(),
    sockets = array:new() :: array:array(),
    sup :: pid(),
    clients = [] :: [{{integer(),integer(),integer(),integer()}, integer()}]
}).

%% @private
init([]) ->
    {ok, Sup} = eradius_client_sup:start(),
    case configure(#state{socket_ip = null, sup = Sup}) of
        {error, Error}  -> {stop, Error};
        Else            -> Else
    end.

%% @private
handle_call({wanna_send, Peer = {_PeerName, PeerSocket}, MetricsInfo}, _From, State) ->
    {PortIdx, ReqId, NewIdCounters} = next_port_and_req_id(PeerSocket, State#state.no_ports, State#state.idcounters),
    {SocketProcess, NewSockets} = find_socket_process(PortIdx, State#state.sockets, State#state.socket_ip, State#state.sup),
    IsCreated = lists:member(Peer, State#state.clients),
    NewState = case IsCreated of
                   false ->
                       eradius_metrics:create_client(MetricsInfo),
                       State#state{idcounters = NewIdCounters, sockets = NewSockets, clients = [Peer | State#state.clients]};
                   true  ->
                       State#state{idcounters = NewIdCounters, sockets = NewSockets}
               end,
    {reply, {SocketProcess, ReqId}, NewState};

%% @private
handle_call(reconfigure, _From, State) ->
    case configure(State) of
        {error, Error}  -> {reply, Error, State};
        {ok, NState}    -> {reply, ok, NState}
    end;

%% @private
handle_call(debug, _From, State) ->
    {reply, {ok, State}, State};

%% @private
handle_call(_OtherCall, _From, State) ->
    {noreply, State}.

%% @private
handle_cast(_Msg, State) -> {noreply, State}.

%% @private
handle_info({PortIdx, Pid}, State = #state{sockets = Sockets}) ->
    NSockets = update_socket_process(PortIdx, Sockets, Pid),
    {noreply, State#state{sockets = NSockets}};

handle_info(_Info, State) ->
    {noreply, State}.

%% @private
terminate(_Reason, _State) -> ok.

%% @private
code_change(_OldVsn, State, _Extra) -> {ok, State}.

%% @private
configure(State) ->
    {ok, ClientPortCount} = application:get_env(eradius, client_ports),
    {ok, ClientIP} = application:get_env(eradius, client_ip),
    case parse_ip(ClientIP) of
        {ok, Address} ->
            configure_address(State, ClientPortCount, Address);
        {error, _} ->
            ?LOG(error, "Invalid RADIUS client IP (parsing failed): ~p", [ClientIP]),
            {error, {bad_client_ip, ClientIP}}
    end.

configure_address(State = #state{socket_ip = OAdd, sockets = Sockts}, NPorts, NAdd) ->
    case OAdd of
        null    ->
            {ok, State#state{socket_ip = NAdd, no_ports = NPorts}};
        NAdd    ->
            configure_ports(State, NPorts);
        _       ->
            ?LOG(info, "Reopening RADIUS client sockets (client_ip changed to ~s)", [inet:ntoa(NAdd)]),
            array:map(  fun(_PortIdx, Pid) ->
                                case Pid of
                                    undefined   -> done;
                                    _           -> Pid ! close
                                end
                         end, Sockts),
            {ok, State#state{sockets = array:new(), socket_ip = NAdd, no_ports = NPorts}}
    end.

configure_ports(State = #state{no_ports = OPorts, sockets = Sockets}, NPorts) ->
    if
        OPorts =< NPorts ->
            {ok, State#state{no_ports = NPorts}};
        true ->
            Counters = fix_counters(NPorts, State#state.idcounters),
            NSockets = close_sockets(NPorts, Sockets),
            {ok, State#state{sockets = NSockets, no_ports = NPorts, idcounters = Counters}}
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
            lists:map(  fun(Pid) ->
                                case Pid of
                                    undefined   -> done;
                                    _           -> Pid ! close
                                end
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

find_socket_process(PortIdx, Sockets, SocketIP, Sup) ->
    case array:get(PortIdx, Sockets) of
        undefined ->
            Res = supervisor:start_child(Sup, {PortIdx,
                {eradius_client_socket, start, [SocketIP, self(), PortIdx]},
                transient, brutal_kill, worker, [eradius_client_socket]}),
            Pid = case Res of
                {ok, P} -> P;
                {error, already_present} ->
                    {ok, P} = supervisor:restart_child(Sup, PortIdx),
                    P
            end,
            {Pid, array:set(PortIdx, Pid, Sockets)};
        Pid when is_pid(Pid) ->
            {Pid, Sockets}
    end.

update_socket_process(PortIdx, Sockets, Pid) ->
    array:set(PortIdx, Pid, Sockets).

parse_ip(undefined) ->
    {ok, undefined};
parse_ip(Address) when is_list(Address) ->
    inet_parse:address(Address);
parse_ip(T = {_, _, _, _}) ->
    {ok, T};
parse_ip(T = {_, _, _, _, _, _}) ->
    {ok, T}.

make_metrics_info(Options, {ServerIP, ServerPort}) ->
    ServerName = proplists:get_value(server_name, Options, undefined),
    ClientName = proplists:get_value(client_name, Options, undefined),
    ClientIP = application:get_env(eradius, client_ip, undefined),
    {ok, ParsedClientIP} = parse_ip(ClientIP),
    ClientAddrInfo = eradius_metrics:make_addr_info({ClientName, {ParsedClientIP, undefined}}),
    ServerAddrInfo = eradius_metrics:make_addr_info({ServerName, {ServerIP, ServerPort}}),
    {ClientAddrInfo, ServerAddrInfo}.

