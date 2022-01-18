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
-export([reconfigure/0, send_remote_request_loop/8, find_suitable_peer/1,
         restore_upstream_server/1, store_radius_server_from_pool/3,
         init_server_status_metrics/0]).

-behaviour(gen_server).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-import(eradius_lib, [printable_peer/2]).

-include_lib("stdlib/include/ms_transform.hrl").
-include_lib("kernel/include/logger.hrl").
-include("eradius_dict.hrl").
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
    IP = get_ip(Host),
    send_request({IP, Port, Secret}, Request, Options);
send_request({IP, Port, Secret}, Request, Options) when ?GOOD_CMD(Request) andalso is_tuple(IP) ->
    TS1 = erlang:monotonic_time(),
    ServerName = proplists:get_value(server_name, Options, undefined),
    MetricsInfo = make_metrics_info(Options, {IP, Port}),
    Retries = proplists:get_value(retries, Options, ?DEFAULT_RETRIES),
    Timeout = proplists:get_value(timeout, Options, ?DEFAULT_TIMEOUT),
    SendReqFn = fun () ->
        Peer = {ServerName, {IP, Port}},
        update_client_requests(MetricsInfo),
        {Socket, ReqId} = gen_server:call(?SERVER, {wanna_send, Peer, MetricsInfo}),
        Response = send_request_loop(Socket, ReqId, Peer,
                                     Request#radius_request{reqid = ReqId, secret = Secret},
                                     Retries, Timeout, MetricsInfo),
        proceed_response(Request, Response, Peer, TS1, MetricsInfo, Options)
    end,
    % If we have other RADIUS upstream servers check current one,
    % maybe it is already marked as inactive and try to find another
    % one
    case proplists:get_value(failover, Options, []) of
        [] ->
            SendReqFn();
        UpstreamServers ->
            case find_suitable_peer([{IP, Port, Secret} | UpstreamServers]) of
                [] ->
                    no_active_servers;
                {{IP, Port, Secret}, _NewPool} ->
                    SendReqFn();
                {NewPeer, []} ->
                    % Special case, we don't have servers in the pool anymore, but we need
                    % to preserve `failover` option to mark current server as inactive if
                    % it will fail
                    NewOptions = lists:keyreplace(failover, 1, Options, {failover, undefined}),
                    send_request(NewPeer, Request, NewOptions);
                {NewPeer, NewPool} ->
                    % current server is not in list of active servers, so use another one
                    NewOptions = lists:keyreplace(failover, 1, Options, {failover, NewPool}),
                    send_request(NewPeer, Request, NewOptions)
            end
    end;
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
    TS1 = erlang:monotonic_time(),
    ServerName = proplists:get_value(server_name, Options, undefined),
    MetricsInfo = make_metrics_info(Options, {IP, Port}),
    update_client_requests(MetricsInfo),
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
            proceed_response(Request, Response, Peer, TS1, MetricsInfo, Options)
    catch
        exit:{{nodedown, Node}, _} ->
            {error, node_down}
    end;
send_remote_request(_Node, {_IP, _Port, _Secret}, _Request, _Options) ->
    error(badarg).

restore_upstream_server({ServerIP, Port, Retries, InitialRetries}) ->
    ets:insert(?MODULE, {{ServerIP, Port}, Retries, InitialRetries}).

proceed_response(Request, {ok, Response, Secret, Authenticator}, _Peer = {_ServerName, {ServerIP, Port}}, TS1, MetricsInfo, Options) ->
    update_client_request(Request#radius_request.cmd, MetricsInfo, erlang:monotonic_time() - TS1, Request),
    update_client_responses(MetricsInfo),
    case eradius_lib:decode_request(Response, Secret, Authenticator) of
        {bad_pdu, "Message-Authenticator Attribute is invalid" = Reason} ->
            update_client_response(bad_authenticator, MetricsInfo, Request),
            ?LOG(error, "~s INF: Noreply for request ~p. Could not decode the request, reason: ~s", [printable_peer(ServerIP, Port), Request, Reason]),
            noreply;
        {bad_pdu, "Authenticator Attribute is invalid" = Reason} ->
            update_client_response(bad_authenticator, MetricsInfo, Request),
            ?LOG(error, "~s INF: Noreply for request ~p. Could not decode the request, reason: ~s", [printable_peer(ServerIP, Port), Request, Reason]),
            noreply;
        {bad_pdu, "unknown request type" = Reason} ->
            update_client_response(unknown_req_type, MetricsInfo, Request),
            ?LOG(error, "~s INF: Noreply for request ~p. Could not decode the request, reason: ~s", [printable_peer(ServerIP, Port), Request, Reason]),
            noreply;
        {bad_pdu, Reason} ->
            update_client_response(dropped, MetricsInfo, Request),
            ?LOG(error, "~s INF: Noreply for request ~p. Could not decode the request, reason: ~s", [printable_peer(ServerIP, Port), Request, Reason]),
            maybe_failover(Request, noreply, {ServerIP, Port}, Options);
        Decoded ->
            update_server_status_metric(ServerIP, Port, true, Options),
            update_client_response(Decoded#radius_request.cmd, MetricsInfo, Request),
            {ok, Response, Authenticator}
    end;

proceed_response(Request, Response, {_ServerName, {ServerIP, Port}}, TS1, MetricsInfo, Options) ->
    update_client_responses(MetricsInfo),
    update_client_request(Request#radius_request.cmd, MetricsInfo, erlang:monotonic_time() - TS1, Request),
    maybe_failover(Request, Response, {ServerIP, Port}, Options).

maybe_failover(Request, Response, {ServerIP, Port}, Options) ->
    update_server_status_metric(ServerIP, Port, false, Options),
    case proplists:get_value(failover, Options, []) of
        [] ->
            Response;
        UpstreamServers ->
            handle_failed_request(Request, {ServerIP, Port}, UpstreamServers, Response, Options)
    end.

handle_failed_request(Request, {ServerIP, Port} = _FailedServer, UpstreamServers, Response, Options) ->
    case ets:lookup(?MODULE, {ServerIP, Port}) of
        [{{ServerIP, Port}, Retries, InitialRetries}] ->
            FailedTries = proplists:get_value(retries, Options, ?DEFAULT_RETRIES),
            % Mark the given RADIUS server as 'non-active' if there were more tries
            % than possible
            if FailedTries >= Retries ->
                    ets:delete(?MODULE, {ServerIP, Port}),
                    Timeout = application:get_env(eradius, unreachable_timeout, 60),
                    timer:apply_after(Timeout * 1000, ?MODULE, restore_upstream_server,
                                      [{ServerIP, Port, InitialRetries, InitialRetries}]);
               true ->
                    % RADIUS client tried to send a request to the {ServierIP, Port} RADIUS
                    % server. There were done FailedTries tries and all of them failed.
                    % So decrease amount of tries for the given RADIUS server that
                    % that will be used for next RADIUS requests towards this RADIUS server.
                    ets:update_counter(?MODULE, {ServerIP, Port}, -FailedTries)
            end;
        [] ->
            ok
    end,
    case find_suitable_peer(UpstreamServers) of
        [] ->
            Response;
        {NewPeer, NewPool} ->
            % leave only active upstream servers
            NewOptions = lists:keyreplace(failover, 1, Options, {failover, NewPool}),
            send_request(NewPeer, Request, NewOptions)
    end.

% @private
send_remote_request_loop(ReplyPid, Socket, ReqId, Peer, EncRequest, Retries, Timeout, MetricsInfo) ->
    ReplyPid ! {self(), send_request_loop(Socket, ReqId, Peer, EncRequest, Retries, Timeout, MetricsInfo)}.

send_request_loop(Socket, ReqId, Peer, Request = #radius_request{}, Retries, Timeout, undefined) ->
    send_request_loop(Socket, ReqId, Peer, Request, Retries, Timeout, eradius_lib:make_addr_info(Peer));
send_request_loop(Socket, ReqId, Peer, Request, Retries, Timeout, MetricsInfo) ->
    {Authenticator, EncRequest} = eradius_lib:encode_request(Request),
    SMon = erlang:monitor(process, Socket),
    send_request_loop(Socket, SMon, Peer, ReqId, Authenticator, EncRequest, Timeout, Retries, MetricsInfo, Request#radius_request.secret, Request).

send_request_loop(_Socket, SMon, _Peer, _ReqId, _Authenticator, _EncRequest, Timeout, 0, MetricsInfo, _Secret, Request) ->
    TS = erlang:convert_time_unit(Timeout, millisecond, native),
    update_client_request(timeout, MetricsInfo, TS, Request),
    erlang:demonitor(SMon, [flush]),
    {error, timeout};
send_request_loop(Socket, SMon, Peer = {_ServerName, {IP, Port}}, ReqId, Authenticator, EncRequest, Timeout, RetryN, MetricsInfo, Secret, Request) ->
    Socket ! {self(), send_request, {IP, Port}, ReqId, EncRequest},
    update_client_request(pending, MetricsInfo, 1, Request),
    receive
        {Socket, response, ReqId, Response} ->
            update_client_request(pending, MetricsInfo, -1, Request),
            {ok, Response, Secret, Authenticator};
        {'DOWN', SMon, process, Socket, _} ->
            {error, socket_down};
        {Socket, error, Error} ->
            {error, Error}
    after
        Timeout ->
            TS = erlang:convert_time_unit(Timeout, millisecond, native),
            update_client_request(retransmission, MetricsInfo, TS, Request),
            send_request_loop(Socket, SMon, Peer, ReqId, Authenticator, EncRequest, Timeout, RetryN - 1, MetricsInfo, Secret, Request)
    end.

% @private
update_client_requests(MetricsInfo) ->
    eradius_counter:inc_counter(requests, MetricsInfo).

% @private
update_client_request(pending, MetricsInfo, Pending, _) ->
    if Pending =< 0 -> eradius_counter:dec_counter(pending, MetricsInfo);
       true -> eradius_counter:inc_counter(pending, MetricsInfo)
    end;
update_client_request(Cmd, MetricsInfo, Ms, Request) ->
    eradius_counter:observe(eradius_client_request_duration_milliseconds, MetricsInfo, Ms, "Execution time of a RADIUS request"),
    update_client_request_by_type(Cmd, MetricsInfo, Ms, Request).

% @private
update_client_request_by_type(request, MetricsInfo, Ms, _) ->
    eradius_counter:observe(eradius_client_access_request_duration_milliseconds, MetricsInfo, Ms, "Access-Request execution time"),
    eradius_counter:inc_counter(accessRequests, MetricsInfo);
update_client_request_by_type(accreq, MetricsInfo, Ms, Request) ->
    eradius_counter:observe(eradius_client_accounting_request_duration_milliseconds, MetricsInfo, Ms, "Accounting-Request execution time"),
    inc_request_counter_accounting(MetricsInfo, Request);
update_client_request_by_type(coareq, MetricsInfo, Ms, _) ->
    eradius_counter:observe(eradius_client_coa_request_duration_milliseconds, MetricsInfo, Ms, "Coa request execution time"),
    eradius_counter:inc_counter(coaRequests, MetricsInfo);
update_client_request_by_type(discreq, MetricsInfo, Ms, _) ->
    eradius_counter:observe(eradius_client_disconnect_request_duration_milliseconds, MetricsInfo, Ms, "Disconnect execution time"),
    eradius_counter:inc_counter(discRequests, MetricsInfo);
update_client_request_by_type(retransmission, MetricsInfo, _Ms, _) ->
    eradius_counter:inc_counter(retransmissions, MetricsInfo);
update_client_request_by_type(timeout, MetricsInfo, _Ms, _) ->
    eradius_counter:inc_counter(timeouts, MetricsInfo);
update_client_request_by_type(_, _, _, _) -> ok.

%% @private
update_client_responses(MetricsInfo) -> eradius_counter:inc_counter(replies, MetricsInfo).

%% @private
update_client_response(accept, MetricsInfo, _)            -> eradius_counter:inc_counter(accessAccepts, MetricsInfo);
update_client_response(reject, MetricsInfo, _)            -> eradius_counter:inc_counter(accessRejects, MetricsInfo);
update_client_response(challenge, MetricsInfo, _)         -> eradius_counter:inc_counter(accessChallenges, MetricsInfo);
update_client_response(accresp, MetricsInfo, Request)     -> inc_responses_counter_accounting(MetricsInfo, Request);
update_client_response(coanak, MetricsInfo, _)            -> eradius_counter:inc_counter(coaNaks, MetricsInfo);
update_client_response(coaack, MetricsInfo, _)            -> eradius_counter:inc_counter(coaAcks, MetricsInfo);
update_client_response(discnak, MetricsInfo, _)           -> eradius_counter:inc_counter(discNaks, MetricsInfo);
update_client_response(discack, MetricsInfo, _)           -> eradius_counter:inc_counter(discAcks, MetricsInfo);
update_client_response(dropped, MetricsInfo, _)           -> eradius_counter:inc_counter(packetsDropped, MetricsInfo);
update_client_response(bad_authenticator, MetricsInfo, _) -> eradius_counter:inc_counter(badAuthenticators, MetricsInfo);
update_client_response(unknown_req_type, MetricsInfo, _)  -> eradius_counter:inc_counter(unknownTypes, MetricsInfo);
update_client_response(_, _, _)                           -> ok.

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
handle_call({wanna_send, Peer = {_PeerName, PeerSocket}, _MetricsInfo}, _From, State) ->
    {PortIdx, ReqId, NewIdCounters} = next_port_and_req_id(PeerSocket, State#state.no_ports, State#state.idcounters),
    {SocketProcess, NewSockets} = find_socket_process(PortIdx, State#state.sockets, State#state.socket_ip, State#state.sup),
    IsCreated = lists:member(Peer, State#state.clients),
    NewState = case IsCreated of
                   false ->
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
    case ets:info(?MODULE) of
        undefined ->
            prepare_pools();
        _ ->
            % if ets table is already exists - which could be in a case of
            % reconfigure, just re-create the table and fill it with newly
            % configured pools of RADIUS upstream servers
            ets:delete(?MODULE),
            prepare_pools()
    end,
    {ok, ClientPortCount} = application:get_env(eradius, client_ports),
    {ok, ClientIP} = application:get_env(eradius, client_ip),
    case parse_ip(ClientIP) of
        {ok, Address} ->
            configure_address(State, ClientPortCount, Address);
        {error, _} ->
            ?LOG(error, "Invalid RADIUS client IP (parsing failed): ~p", [ClientIP]),
            {error, {bad_client_ip, ClientIP}}
    end.

%% private
prepare_pools() ->
    ets:new(?MODULE, [ordered_set, public, named_table, {keypos, 1}, {write_concurrency,true}]),
    lists:foreach(fun({_PoolName, Servers}) -> prepare_pool(Servers) end, application:get_env(eradius, servers_pool, [])),
    lists:foreach(fun(Server) -> store_upstream_servers(Server) end, application:get_env(eradius, servers, [])),
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
store_radius_server_from_pool(Addr, Port, Retries) when is_tuple(Addr) and is_integer(Port) and is_integer(Retries) ->
    ets:insert(?MODULE, {{Addr, Port}, Retries, Retries});
store_radius_server_from_pool(Addr, Port, Retries) when is_list(Addr) and is_integer(Port) and is_integer(Retries) ->
    IP = get_ip(Addr),
    ets:insert(?MODULE, {{IP, Port}, Retries, Retries});
store_radius_server_from_pool(Addr, Port, Retries) ->
    ?LOG(error, "bad RADIUS upstream server specified in RADIUS servers pool configuration ~p", [{Addr, Port, Retries}]),
    error(badarg).

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

init_server_status_metrics() ->
    case application:get_env(eradius, server_status_metrics_enabled, false) of
        false ->
            ok;
        true ->
            % That will be called at eradius startup and we must be sure that prometheus
            % application already started if server status metrics supposed to be used
            application:ensure_all_started(prometheus),
            ets:foldl(fun ({{Addr, Port}, _, _}, _Acc) ->
                eradius_counter:set_boolean_metric(server_status, [Addr, Port], false)
            end, [], ?MODULE)
    end.

make_metrics_info(Options, {ServerIP, ServerPort}) ->
    ServerName = proplists:get_value(server_name, Options, undefined),
    ClientName = proplists:get_value(client_name, Options, undefined),
    ClientIP = application:get_env(eradius, client_ip, undefined),
    {ok, ParsedClientIP} = parse_ip(ClientIP),
    ClientAddrInfo = eradius_lib:make_addr_info({ClientName, {ParsedClientIP, undefined}}),
    ServerAddrInfo = eradius_lib:make_addr_info({ServerName, {ServerIP, ServerPort}}),
    {ClientAddrInfo, ServerAddrInfo}.

inc_request_counter_accounting(MetricsInfo, #radius_request{attrs = Attrs}) ->
    Requests = ets:match_spec_run(Attrs, client_request_counter_account_match_spec_compile()),
    [eradius_counter:inc_counter(Type, MetricsInfo) || Type <-  Requests],
    ok;
inc_request_counter_accounting(_, _) ->
    ok.

inc_responses_counter_accounting(MetricsInfo, #radius_request{attrs = Attrs}) ->
    Responses = ets:match_spec_run(Attrs, client_response_counter_account_match_spec_compile()),
    [eradius_counter:inc_counter(Type, MetricsInfo) || Type <- Responses],
    ok;
inc_responses_counter_accounting(_, _) ->
    ok.

update_server_status_metric(IP, Port, false, _Options) ->
    eradius_counter:set_boolean_metric(server_status, [IP, Port], false);
update_server_status_metric(IP, Port, true, Options) ->
    UpstreamServers = proplists:get_value(failover, Options, []),
    % set all servesr from pool as inactive
    if is_list(UpstreamServers) ->
        lists:foreach(fun (Server) ->
            case Server of
                {ServerIP, ServerPort, _} ->
                    eradius_counter:set_boolean_metric(server_status, [ServerIP, ServerPort], false);
                {ServerIP, ServerPort, _, _} ->
                    eradius_counter:set_boolean_metric(server_status, [ServerIP, ServerPort], false);
                _ ->
                    ok
            end

        end, UpstreamServers);
    true ->
        ok
    end,
    % set current service as active
    eradius_counter:set_boolean_metric(server_status, [IP, Port], true).

%% check if we can use persistent_term for config
%% persistent term was added in OTP 21.2 but we can't
%% check minor versions with macros so we're stuck waiting
%% for OTP 22
-ifdef(HAVE_PERSISTENT_TERM).

client_request_counter_account_match_spec_compile() ->
    case persistent_term:get({?MODULE, ?FUNCTION_NAME}, undefined) of
        undefined ->
            MatchSpecCompile = ets:match_spec_compile(ets:fun2ms(fun
                ({?RStatus_Type, ?RStatus_Type_Start})  -> accountRequestsStart;
                ({?RStatus_Type, ?RStatus_Type_Stop})   -> accountRequestsStop;
                ({?RStatus_Type, ?RStatus_Type_Update}) -> accountRequestsUpdate;
                ({#attribute{id = ?RStatus_Type}, ?RStatus_Type_Start})  -> accountRequestsStart;
                ({#attribute{id = ?RStatus_Type}, ?RStatus_Type_Stop})   -> accountRequestsStop;
                ({#attribute{id = ?RStatus_Type}, ?RStatus_Type_Update}) -> accountRequestsUpdate end)),
            persistent_term:put({?MODULE, ?FUNCTION_NAME}, MatchSpecCompile),
            MatchSpecCompile;
        MatchSpecCompile ->
            MatchSpecCompile
    end.

client_response_counter_account_match_spec_compile() ->
    case persistent_term:get({?MODULE, ?FUNCTION_NAME}, undefined) of
        undefined ->
            MatchSpecCompile = ets:match_spec_compile(ets:fun2ms(fun
                ({?RStatus_Type, ?RStatus_Type_Start})  -> accountResponsesStart;
                ({?RStatus_Type, ?RStatus_Type_Stop})   -> accountResponsesStop;
                ({?RStatus_Type, ?RStatus_Type_Update}) -> accountResponsesUpdate;
                ({#attribute{id = ?RStatus_Type}, ?RStatus_Type_Start})  -> accountResponsesStart;
                ({#attribute{id = ?RStatus_Type}, ?RStatus_Type_Stop})   -> accountResponsesStop;
                ({#attribute{id = ?RStatus_Type}, ?RStatus_Type_Update}) -> accountResponsesUpdate end)),
            persistent_term:put({?MODULE, ?FUNCTION_NAME}, MatchSpecCompile),
            MatchSpecCompile;
        MatchSpecCompile ->
            MatchSpecCompile
    end.

-else.

client_request_counter_account_match_spec_compile() ->
    ets:match_spec_compile(ets:fun2ms(fun
        ({?RStatus_Type, ?RStatus_Type_Start})  -> accountRequestsStart;
        ({?RStatus_Type, ?RStatus_Type_Stop})   -> accountRequestsStop;
        ({?RStatus_Type, ?RStatus_Type_Update}) -> accountRequestsUpdate;
        ({#attribute{id = ?RStatus_Type}, ?RStatus_Type_Start})  -> accountRequestsStart;
        ({#attribute{id = ?RStatus_Type}, ?RStatus_Type_Stop})   -> accountRequestsStop;
        ({#attribute{id = ?RStatus_Type}, ?RStatus_Type_Update}) -> accountRequestsUpdate end)).

client_response_counter_account_match_spec_compile() ->
    ets:match_spec_compile(ets:fun2ms(fun
        ({?RStatus_Type, ?RStatus_Type_Start})  -> accountResponsesStart;
        ({?RStatus_Type, ?RStatus_Type_Stop})   -> accountResponsesStop;
        ({?RStatus_Type, ?RStatus_Type_Update}) -> accountResponsesUpdate;
        ({#attribute{id = ?RStatus_Type}, ?RStatus_Type_Start})  -> accountResponsesStart;
        ({#attribute{id = ?RStatus_Type}, ?RStatus_Type_Stop})   -> accountResponsesStop;
        ({#attribute{id = ?RStatus_Type}, ?RStatus_Type_Update}) -> accountResponsesUpdate end)).

-endif.

find_suitable_peer(undefined) ->
    [];
find_suitable_peer([]) ->
    [];
find_suitable_peer([{IP, Port, Secret} | Pool]) ->
    case ets:lookup(?MODULE, {IP, Port}) of
        [] ->
            find_suitable_peer(Pool);
        [{{IP, Port}, _Retries, _InitialRetries}] ->
            {{IP, Port, Secret}, Pool}
    end;
find_suitable_peer([{IP, Port, Secret, _Opts} | Pool]) ->
    find_suitable_peer([{IP, Port, Secret} | Pool]).

get_ip(Host) ->
    case inet:gethostbyname(Host) of
        {ok, #hostent{h_addrtype = inet, h_addr_list = [IP]}} ->
            IP;
        {ok, #hostent{h_addrtype = inet, h_addr_list = [_ | _] = IPs}} ->
            Index = rand:uniform(length(IPs)),
            lists:nth(Index, IPs);
        _ -> error(badarg)
    end.
