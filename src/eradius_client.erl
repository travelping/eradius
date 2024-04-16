%% Copyright (c) 2002-2007, Martin Björklund and Torbjörn Törnkvist
%% Copyright (c) 2011, Travelping GmbH <info@travelping.com>
%%
%% SPDX-License-Identifier: MIT
%%
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

%% API
-export([send_request/2, send_request/3,
         send_remote_request/3, send_remote_request/4]).

%% internal API
-export([send_remote_request_loop/8]).

-import(eradius_lib, [printable_peer/2]).

-include_lib("stdlib/include/ms_transform.hrl").
-include_lib("kernel/include/logger.hrl").
-include_lib("kernel/include/inet.hrl").
-include("eradius_dict.hrl").
-include("eradius_lib.hrl").
-include("eradius_internal.hrl").

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

-define(SERVER, ?MODULE).

%%%=========================================================================
%%%  API
%%%=========================================================================

%% @equiv send_request(NAS, Request, [])
-spec send_request(nas_address(), #radius_request{}) -> {ok, binary()} | {error, 'timeout' | 'socket_down'}.
send_request(NAS, Request) ->
    send_request(NAS, Request, []).

%% @doc Send a radius request to the given NAS.
%%   If no answer is received within the specified timeout, the request will be sent again.
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
                        {Socket, ReqId} = eradius_client_mngr:wanna_send(Peer),
                        Response = send_request_loop(Socket, ReqId, Peer,
                                                     Request#radius_request{reqid = ReqId, secret = Secret},
                                                     Retries, Timeout, MetricsInfo),
                        proceed_response(Request, Response, Peer, TS1, MetricsInfo, Options)
                end,
    %% If we have other RADIUS upstream servers check current one,
    %% maybe it is already marked as inactive and try to find another
    %% one
    case proplists:get_value(failover, Options, []) of
        [] ->
            SendReqFn();
        UpstreamServers ->
            case eradius_client_mngr:find_suitable_peer([{IP, Port, Secret} | UpstreamServers]) of
                [] ->
                    no_active_servers;
                {{IP, Port, Secret}, _NewPool} ->
                    SendReqFn();
                {NewPeer, []} ->
                    %% Special case, we don't have servers in the pool anymore, but we need
                    %% to preserve `failover` option to mark current server as inactive if
                    %% it will fail
                    NewOptions = lists:keyreplace(failover, 1, Options, {failover, undefined}),
                    send_request(NewPeer, Request, NewOptions);
                {NewPeer, NewPool} ->
                    %% current server is not in list of active servers, so use another one
                    NewOptions = lists:keyreplace(failover, 1, Options, {failover, NewPool}),
                    send_request(NewPeer, Request, NewOptions)
            end
    end;
send_request({_IP, _Port, _Secret}, _Request, _Options) ->
    error(badarg).

%% @equiv send_remote_request(Node, NAS, Request, [])
-spec send_remote_request(node(), nas_address(), #radius_request{}) -> {ok, binary()} | {error, 'timeout' | 'node_down' | 'socket_down'}.
send_remote_request(Node, NAS, Request) ->
    send_remote_request(Node, NAS, Request, []).

%% @doc Send a radius request to the given NAS through a socket on the specified node.
%%   If no answer is received within the specified timeout, the request will be sent again.
%%   The request will not be sent again if the remote node is unreachable.
-spec send_remote_request(node(), nas_address(), #radius_request{}, options()) -> {ok, binary()} | {error, 'timeout' | 'node_down' | 'socket_down'}.
send_remote_request(Node, {IP, Port, Secret}, Request, Options) when ?GOOD_CMD(Request) ->
    TS1 = erlang:monotonic_time(),
    ServerName = proplists:get_value(server_name, Options, undefined),
    MetricsInfo = make_metrics_info(Options, {IP, Port}),
    update_client_requests(MetricsInfo),
    Peer = {ServerName, {IP, Port}},
    try eradius_client_mngr:wanna_send(Node, Peer) of
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

proceed_response(Request, {ok, Response, Secret, Authenticator}, _Peer = {_ServerName, {ServerIP, Port}}, TS1, MetricsInfo, Options) ->
    update_client_request(Request#radius_request.cmd, MetricsInfo, erlang:monotonic_time() - TS1, Request),
    update_client_responses(MetricsInfo),
    case eradius_lib:decode_request(Response, Secret, Authenticator) of
        {bad_pdu, Reason} ->
            eradius_client_mngr:request_failed(ServerIP, Port, Options),
            update_server_status_metric(ServerIP, Port, false, Options),

            case Reason of
                "Message-Authenticator Attribute is invalid" ->
                    update_client_response(bad_authenticator, MetricsInfo, Request),
                    ?LOG(error, "~s INF: Noreply for request ~p. "
                         "Message-Authenticator Attribute is invalid",
                         [printable_peer(ServerIP, Port), Request]),
                    noreply;
                "Authenticator Attribute is invalid" ->
                    update_client_response(bad_authenticator, MetricsInfo, Request),
                    ?LOG(error, "~s INF: Noreply for request ~p. "
                         "Authenticator Attribute is invalid",
                         [printable_peer(ServerIP, Port), Request]),
                    noreply;
                "unknown request type" ->
                    update_client_response(unknown_req_type, MetricsInfo, Request),
                    ?LOG(error, "~s INF: Noreply for request ~p. "
                         "unknown request type",
                         [printable_peer(ServerIP, Port), Request]),
                    noreply;
                _ ->
                    update_client_response(dropped, MetricsInfo, Request),
                    ?LOG(error, "~s INF: Noreply for request ~p. "
                         "Could not decode the request, reason: ~s",
                         [printable_peer(ServerIP, Port), Request, Reason]),
                    maybe_failover(Request, noreply, Options)
            end;
        Decoded ->
            update_server_status_metric(ServerIP, Port, true, Options),
            update_client_response(Decoded#radius_request.cmd, MetricsInfo, Request),
            {ok, Response, Authenticator}
    end;

proceed_response(Request, Response, {_ServerName, {ServerIP, Port}}, TS1, MetricsInfo, Options) ->
    update_client_responses(MetricsInfo),
    update_client_request(Request#radius_request.cmd, MetricsInfo, erlang:monotonic_time() - TS1, Request),

    eradius_client_mngr:request_failed(ServerIP, Port, Options),
    update_server_status_metric(ServerIP, Port, false, Options),

    maybe_failover(Request, Response, Options).

maybe_failover(Request, Response, Options) ->
    UpstreamServers = proplists:get_value(failover, Options, []),
    case eradius_client_mngr:find_suitable_peer(UpstreamServers) of
        [] ->
            Response;
        {NewPeer, NewPool} ->
            %% leave only active upstream servers
            NewOptions = lists:keyreplace(failover, 1, Options, {failover, NewPool}),
            send_request(NewPeer, Request, NewOptions)
    end.

%% @private
%% send_remote_request_loop/8
send_remote_request_loop(ReplyPid, Socket, ReqId, Peer, EncRequest, Retries, Timeout, MetricsInfo) ->
    ReplyPid ! {self(), send_request_loop(Socket, ReqId, Peer, EncRequest, Retries, Timeout, MetricsInfo)}.

%% send_remote_request_loop/7
send_request_loop(Socket, ReqId, Peer, Request = #radius_request{},
                  Retries, Timeout, undefined) ->
    send_request_loop(Socket, ReqId, Peer, Request, Retries, Timeout, eradius_lib:make_addr_info(Peer));
send_request_loop(Socket, ReqId, Peer, Request,
                  Retries, Timeout, MetricsInfo) ->
    {Authenticator, EncRequest} = eradius_lib:encode_request(Request),
    send_request_loop(Socket, Peer, ReqId, Authenticator, EncRequest,
                      Timeout, Retries, MetricsInfo, Request#radius_request.secret, Request).

%% send_remote_request_loop/10
send_request_loop(_Socket, _Peer, _ReqId, _Authenticator, _EncRequest,
                  Timeout, 0, MetricsInfo, _Secret, Request) ->
    TS = erlang:convert_time_unit(Timeout, millisecond, native),
    update_client_request(timeout, MetricsInfo, TS, Request),
    {error, timeout};
send_request_loop(Socket, Peer = {_ServerName, {IP, Port}}, ReqId, Authenticator, EncRequest,
                  Timeout, RetryN, MetricsInfo, Secret, Request) ->
    Result =
        try
            update_client_request(pending, MetricsInfo, 1, Request),
            eradius_client_socket:send_request(Socket, {IP, Port}, ReqId, EncRequest, Timeout)
        after
            update_client_request(pending, MetricsInfo, -1, Request)
        end,

    case Result of
        {response, ReqId, Response} ->
            {ok, Response, Secret, Authenticator};
        {error, close} ->
            {error, socket_down};
        {error, timeout} ->
            TS = erlang:convert_time_unit(Timeout, millisecond, native),
            update_client_request(retransmission, MetricsInfo, TS, Request),
            send_request_loop(Socket, Peer, ReqId, Authenticator, EncRequest,
                              Timeout, RetryN - 1, MetricsInfo, Secret, Request);
        {error, _} = Error ->
            Error
    end.

%% @private
update_client_requests(MetricsInfo) ->
    eradius_counter:inc_counter(requests, MetricsInfo).

%% @private
update_client_request(pending, MetricsInfo, Pending, _) ->
    if Pending =< 0 -> eradius_counter:dec_counter(pending, MetricsInfo);
       true -> eradius_counter:inc_counter(pending, MetricsInfo)
    end;
update_client_request(Cmd, MetricsInfo, Ms, Request) ->
    eradius_counter:observe(eradius_client_request_duration_milliseconds, MetricsInfo, Ms, "Execution time of a RADIUS request"),
    update_client_request_by_type(Cmd, MetricsInfo, Ms, Request).

%% @private
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

%%%=========================================================================
%%%  internal functions
%%%=========================================================================

parse_ip(undefined) ->
    {ok, undefined};
parse_ip(Address) when is_list(Address) ->
    inet_parse:address(Address);
parse_ip(T = {_, _, _, _}) ->
    {ok, T};
parse_ip(T = {_, _, _, _, _, _, _, _}) ->
    {ok, T}.

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
    %% set all servesr from pool as inactive
    if is_list(UpstreamServers) ->
            lists:foreach(
              fun (Server) ->
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
    %% set current service as active
    eradius_counter:set_boolean_metric(server_status, [IP, Port], true).

client_request_counter_account_match_spec_compile() ->
    case persistent_term:get({?MODULE, ?FUNCTION_NAME}, undefined) of
        undefined ->
            MatchSpecCompile =
                ets:match_spec_compile(
                  ets:fun2ms(
                    fun ({?RStatus_Type, ?RStatus_Type_Start})  -> accountRequestsStart;
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
            MatchSpecCompile =
                ets:match_spec_compile(
                  ets:fun2ms(
                    fun ({?RStatus_Type, ?RStatus_Type_Start})  -> accountResponsesStart;
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

get_ip(Host) ->
    case inet:gethostbyname(Host) of
        {ok, #hostent{h_addrtype = inet, h_addr_list = [IP]}} ->
            IP;
        {ok, #hostent{h_addrtype = inet, h_addr_list = [_ | _] = IPs}} ->
            Index = rand:uniform(length(IPs)),
            lists:nth(Index, IPs);
        _ -> error(badarg)
    end.
