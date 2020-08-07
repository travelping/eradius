%% @doc
%%   This module implements a generic RADIUS server. A handler callback module
%%   is used to process requests. The handler module is selected based on the NAS that
%%   sent the request. Requests from unknown NASs are discarded.
%%
%%   It is also possible to run request handlers on remote nodes. If configured,
%%   the server process will balance load among connected nodes.
%%   Please see the Overview page for a detailed description of the server configuration.
%%
%%   == Callback Description ==
%%
%%   There are two callbacks at the moment.
%%
%%   === validate_arguments(Args :: list()) -> boolean() | {true, NewArgs :: list()} | Error :: term(). ===
%%
%%   This is optional callback and can be absent. During application configuration processing `eradius_config`
%%   calls this for the handler to validate and transform handler arguments.
%%
%%   === radius_request(#radius_request{}, #nas_prop{}, HandlerData :: term()) -> {reply, #radius_request{}} | noreply ===
%%
%%   This function is called for every RADIUS request that is received by the server.
%%   Its first argument is a request record which contains the request type and AVPs.
%%   The second argument is a NAS descriptor. The third argument is an opaque term from the
%%   server configuration.
%%
%%   Both records are defined in 'eradius_lib.hrl', but their definition is reproduced here for easy reference.
%%
%%   ```
%%   -record(radius_request, {
%%       reqid         :: byte(),
%%       cmd           :: 'request' | 'accept' | 'challenge' | 'reject' | 'accreq' | 'accresp' | 'coareq' | 'coaack' | 'coanak' | 'discreq' | 'discack' | 'discnak'm
%%       attrs         :: eradius_lib:attribute_list(),
%%       secret        :: eradius_lib:secret(),
%%       authenticator :: eradius_lib:authenticator(),
%%       msg_hmac      :: boolean(),
%%       eap_msg       :: binary()
%%   }).
%%
%%   -record(nas_prop, {
%%       server_ip     :: inet:ip_address(),
%%       server_port   :: eradius_server:port_number(),
%%       nas_ip        :: inet:ip_address(),
%%       nas_port      :: eradius_server:port_number(),
%%       nas_id        :: term(),
%%       metrics_info  :: {atom_address(), atom_address()},
%%       secret        :: eradius_lib:secret(),
%%       trace         :: boolean(),
%%       handler_nodes :: 'local' | list(atom())
%%   }).
%%   '''
-module(eradius_server).
-export([start_link/3]).
-export_type([port_number/0, req_id/0]).

%% internal
-export([do_radius/6, handle_request/3, handle_remote_request/5, stats/2]).

-import(eradius_lib, [printable_peer/2]).

-behaviour(gen_server).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-include_lib("kernel/include/logger.hrl").
-include("eradius_lib.hrl").
-include("dictionary.hrl").

-define(RESEND_TIMEOUT, 5000).          % how long the binary response is kept after sending it on the socket
-define(RESEND_RETRIES, 3).             % how often a reply may be resent
-define(HANDLER_REPLY_TIMEOUT, 15000).  % how long to wait before a remote handler is considered dead

-type port_number() :: 1..65535.
-type req_id()      :: byte().
-type udp_socket()  :: port().
-type udp_packet()  :: {udp, udp_socket(), inet:ip_address(), port_number(), binary()}.

-record(state, {
    socket         :: udp_socket(),      % Socket Reference of opened UDP port
    ip = {0,0,0,0} :: inet:ip_address(), % IP to which this socket is bound
    port = 0       :: port_number(),     % Port number we are listening on
    transacts      :: ets:tid(),         % ETS table containing current transactions
    counter        :: #server_counter{}, % statistics counter,
    name           :: atom()             % server name
}).

-optional_callbacks([validate_arguments/1]).

-callback validate_arguments(Args :: list()) -> 
    boolean() | {true, NewArgs :: list()}.

-callback radius_request(#radius_request{}, #nas_prop{}, HandlerData :: term()) -> 
    {reply, #radius_request{}} | noreply | {error, timeout}.

%% @private
-spec start_link(atom(), inet:ip4_address(), port_number()) -> {ok, pid()} | {error, term()}.
start_link(ServerName, IP = {A,B,C,D}, Port) ->
    Name = list_to_atom(lists:flatten(io_lib:format("eradius_server_~b.~b.~b.~b:~b", [A,B,C,D,Port]))),
    gen_server:start_link({local, Name}, ?MODULE, {ServerName, IP, Port}, []).

stats(Server, Function) ->
    gen_server:call(Server, {stats, Function}).

%% ------------------------------------------------------------------------------------------
%% -- gen_server Callbacks
%% @private
init({ServerName, IP, Port}) ->
    process_flag(trap_exit, true),
    RecBuf = application:get_env(eradius, recbuf, 8192),
    case gen_udp:open(Port, [{active, once}, {ip, IP}, binary, {recbuf, RecBuf}]) of
        {ok, Socket} ->
            MetricsAddress = eradius_metrics:make_addr_info({ServerName, {IP, Port}}),
            eradius_metrics:update_server_time("last_reset", MetricsAddress),
            {ok, #state{socket = Socket,
                        ip = IP, port = Port, name = ServerName,
                        transacts = ets:new(transacts, []),
                        counter = eradius_counter:init_counter({IP, Port})}};
        {error, Reason} ->
            {stop, Reason}
    end.

%% @private
handle_info(ReqUDP = {udp, Socket, FromIP, FromPortNo, Packet},
            State  = #state{name = ServerName, transacts = Transacts, ip = IP, port = Port}) ->
    TS1 = eradius_metrics:timestamp(milli_seconds),
    ServerAddress = {ServerName, {IP, Port}},
    case lookup_nas(State, FromIP, Packet) of
        {ok, ReqID, Handler, NasProp} ->
            #nas_prop{server_ip = ServerIP, server_port = Port} = NasProp,
            ReqKey = {FromIP, FromPortNo, ReqID},
            NNasProp = NasProp#nas_prop{nas_port = FromPortNo},
            case ets:lookup(Transacts, ReqKey) of
                [] ->
                    HandlerPid = proc_lib:spawn_link(?MODULE, do_radius, [self(), ReqKey, Handler, NNasProp, ReqUDP, TS1]),
                    ets:insert(Transacts, {ReqKey, {handling, HandlerPid}}),
                    ets:insert(Transacts, {HandlerPid, ReqKey}),
                    eradius_metrics:update_nas_request("pending", NasProp#nas_prop.metrics_info, 1);
                [{_ReqKey, {handling, HandlerPid}}] ->
                    %% handler process is still working on the request
                    ?LOG(debug, "~s From: ~s INF: Handler process ~p is still working on the request. duplicate request (being handled) ~p",
                        [printable_peer(ServerIP, Port), printable_peer(FromIP, FromPortNo), HandlerPid, ReqKey]),
                    TS2 = eradius_metrics:timestamp(milli_seconds),
                    eradius_metrics:update_nas_request("duplicate", NasProp#nas_prop.metrics_info, TS2 - TS1),
                    eradius_counter:inc_counter(dupRequests, NasProp);
                [{_ReqKey, {replied, HandlerPid}}] ->
                    %% handler process waiting for resend message
                    HandlerPid ! {self(), resend, Socket},
                    ?LOG(debug, "~s From: ~s INF: Handler ~p waiting for resent message. duplicate request (resent) ~p",
                         [printable_peer(ServerIP, Port), printable_peer(FromIP, FromPortNo), HandlerPid, ReqKey]),
                    TS2 = eradius_metrics:timestamp(milli_seconds),
                    eradius_metrics:update_nas_request("retransmission", NasProp#nas_prop.metrics_info, TS2 - TS1),
                    eradius_metrics:update_nas_response("retransmission", NasProp#nas_prop.metrics_info),
                    eradius_counter:inc_counter(dupRequests, NasProp)
            end,
            NewState = State;
        {discard, Reason} ->
            TS2 = eradius_metrics:timestamp(milli_seconds),
            ServerInfo = eradius_metrics:make_addr_info(ServerAddress),
            eradius_metrics:update_server_request(Reason, ServerInfo, TS2 - TS1),
            NewState = State#state{counter = eradius_counter:inc_counter(discardNoHandler, State#state.counter)}
    end,
    inet:setopts(Socket, [{active, once}]),
    {noreply, NewState};
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
handle_call({stats, pull}, _From, State = #state{counter = Counter}) ->
    {reply, Counter, State#state{counter = eradius_counter:reset_counter(Counter)}};
handle_call({stats, read}, _From, State = #state{counter = Counter}) ->
    {reply, Counter, State};
handle_call({stats, reset}, _From, State = #state{counter = Counter}) ->
    {reply, ok, State#state{counter = eradius_counter:reset_counter(Counter)}}.

%% -- unused callbacks
%% @private
handle_cast(_Msg, State)            -> {noreply, State}.
%% @private
code_change(_OldVsn, State, _Extra) -> {ok, State}.

-spec lookup_nas(#state{}, inet:ip_address(), binary()) -> {ok, req_id(), eradius_server_mon:handler(), #nas_prop{}} | {discard, invalid | malformed}.
lookup_nas(#state{ip = IP, port = Port}, NasIP, <<_Code, ReqID, _/binary>>) ->
    case eradius_server_mon:lookup_handler(IP, Port, NasIP) of
        {ok, Handler, NasProp} ->
            {ok, ReqID, Handler, NasProp};
        {error, not_found} ->
            {discard, invalid}
    end;
lookup_nas(_State, _NasIP, _Packet) ->
    {discard, malformed}.

%% ------------------------------------------------------------------------------------------
%% -- Request Handler
%% @private
-spec do_radius(pid(), term(), eradius_server_mon:handler(), #nas_prop{}, udp_packet(), integer()) -> any().
do_radius(ServerPid, ReqKey, Handler = {HandlerMod, _}, NasProp, {udp, Socket, FromIP, FromPort, EncRequest}, TS1) ->
    #nas_prop{server_ip = ServerIP, server_port = Port} = NasProp,
    Nodes = eradius_node_mon:get_module_nodes(HandlerMod),
    case run_handler(Nodes, NasProp, Handler, EncRequest) of
        {reply, EncReply, Cmds} ->
            ?LOG(debug, "~s From: ~s INF: Sending response for request ~p",
                        [printable_peer(ServerIP, Port), printable_peer(FromIP, FromPort), ReqKey]),
            TS2 = eradius_metrics:timestamp(milli_seconds),
            inc_counter(Cmds, NasProp, TS2 - TS1),
            gen_udp:send(Socket, FromIP, FromPort, EncReply),
            case application:get_env(eradius, resend_timeout, 2000) of
                ResendTimeout when ResendTimeout > 0, is_integer(ResendTimeout) ->
                   ServerPid ! {replied, ReqKey, self()},
                   wait_resend_init(ServerPid, ReqKey, FromIP, FromPort, EncReply, ResendTimeout, ?RESEND_RETRIES);
                _ -> ok
            end;
        {discard, Reason} ->
            ?LOG(debug, "~s From: ~s INF: Handler discarded the request ~p for reason ~1000.p",
                        [printable_peer(ServerIP, Port), printable_peer(FromIP, FromPort), Reason, ReqKey]),
            TS2 = eradius_metrics:timestamp(milli_seconds),
            inc_discard_counter(Reason, NasProp, TS2 - TS1);
        {exit, Reason} ->
            ?LOG(debug, "~s From: ~s INF: Handler exited for reason ~p, discarding request ~p",
                        [printable_peer(ServerIP, Port), printable_peer(FromIP, FromPort), Reason, ReqKey]),
            TS2 = eradius_metrics:timestamp(milli_seconds),
            inc_discard_counter(Reason, NasProp, TS2 - TS1)
    end,
    eradius_metrics:update_nas_request("pending", NasProp#nas_prop.metrics_info, -1).

wait_resend_init(ServerPid, ReqKey, FromIP, FromPort, EncReply, ResendTimeout, Retries) ->
    erlang:send_after(ResendTimeout, self(), timeout),
    wait_resend(ServerPid, ReqKey, FromIP, FromPort, EncReply, Retries).

wait_resend(_ServerPid, _ReqKey, _FromIP, _FromPort, _EncReply, 0) -> ok;
wait_resend(ServerPid, ReqKey, FromIP, FromPort, EncReply, Retries) ->
    receive
        {ServerPid, resend, Socket} ->
            gen_udp:send(Socket, FromIP, FromPort, EncReply),
            wait_resend(ServerPid, ReqKey, FromIP, FromPort, EncReply, Retries - 1);
        timeout -> ok
    end.

run_handler([], _NasProp, _Handler, _EncRequest) ->
    {discard, no_nodes};
run_handler(NodesAvailable, NasProp = #nas_prop{handler_nodes = local}, Handler, EncRequest) ->
    case lists:member(node(), NodesAvailable) of
        true ->
            handle_request(Handler, NasProp, EncRequest);
        false ->
            {discard, no_nodes_local}
    end;
run_handler(NodesAvailable, NasProp, Handler, EncRequest) ->
    case ordsets:intersection(lists:usort(NodesAvailable), lists:usort(NasProp#nas_prop.handler_nodes)) of
        [LocalNode] when LocalNode == node() ->
            handle_request(Handler, NasProp, EncRequest);
        [RemoteNode] ->
            run_remote_handler(RemoteNode, Handler, NasProp, EncRequest);
        Nodes ->
            %% humble testing at the erlang shell indicated that phash2 distributes N
            %% very well even for small lenghts.
            N = erlang:phash2(make_ref(), length(Nodes)) + 1,
            case lists:nth(N, Nodes) of
                LocalNode when LocalNode == node() ->
                    handle_request(Handler, NasProp, EncRequest);
                RemoteNode ->
                    run_remote_handler(RemoteNode, Handler, NasProp, EncRequest)
            end
    end.

run_remote_handler(Node, {HandlerMod, HandlerArgs}, NasProp, EncRequest) ->
    RemoteArgs = [self(), HandlerMod, HandlerArgs, NasProp, EncRequest],
    HandlerPid = spawn_link(Node, ?MODULE, handle_remote_request, RemoteArgs),
    receive
        {HandlerPid, ReturnValue} ->
            ReturnValue
    after
        ?HANDLER_REPLY_TIMEOUT ->
            %% this happens if the remote handler doesn't terminate
            unlink(HandlerPid),
            {discard, {remote_handler_reply_timeout, Node}}
    end.

%% @private
-spec handle_request(eradius_server_mon:handler(), #nas_prop{}, binary()) -> any().
handle_request({HandlerMod, HandlerArg}, NasProp = #nas_prop{secret = Secret, nas_ip = ServerIP, nas_port = Port}, EncRequest) ->
    case eradius_lib:decode_request(EncRequest, Secret) of
        Request = #radius_request{} ->
            Sender = {ServerIP, Port, Request#radius_request.reqid},
            ?LOG(info, "~s", [eradius_log:collect_message(Sender, Request)],
                 maps:from_list(eradius_log:collect_meta(Sender, Request))),
            eradius_log:write_request(Sender, Request),
            apply_handler_mod(HandlerMod, HandlerArg, Request, NasProp);
        {bad_pdu, Reason} ->
            ?LOG(error, "~s INF: Could not decode the request, reason: ~s", [printable_peer(ServerIP, Port), Reason]),
            {discard, malformed}
    end.

%% @private
%% @doc this function is spawned on a remote node to handle a radius request.
%%   remote handlers need to be upgraded if the signature of this function changes.
%%   error reports go to the logger of the node that executes the request.
handle_remote_request(ReplyPid, HandlerMod, HandlerArg, NasProp, EncRequest) ->
    Result = handle_request({HandlerMod, HandlerArg}, NasProp, EncRequest),
    ReplyPid ! {self(), Result}.

-spec apply_handler_mod(module(), term(), #radius_request{}, #nas_prop{}) -> {discard, term()} | {exit, term()} | {reply, binary()}.
apply_handler_mod(HandlerMod, HandlerArg, Request, NasProp) ->
    #nas_prop{server_ip = ServerIP, server_port = Port} = NasProp,
    try HandlerMod:radius_request(Request, NasProp, HandlerArg) of
        {reply, Reply = #radius_request{cmd = ReplyCmd, attrs = ReplyAttrs, msg_hmac = MsgHMAC, eap_msg = EAPmsg}} ->
            Sender = {NasProp#nas_prop.nas_ip, NasProp#nas_prop.nas_port, Request#radius_request.reqid},
            EncReply = eradius_lib:encode_reply(Request#radius_request{cmd = ReplyCmd, attrs = ReplyAttrs,
                                                                       msg_hmac = Request#radius_request.msg_hmac or MsgHMAC or (size(EAPmsg) > 0),
                                                                       eap_msg = EAPmsg}),
            ?LOG(info, "~s", [eradius_log:collect_message(Sender, Reply)],
                 maps:from_list(eradius_log:collect_meta(Sender, Reply))),
            eradius_log:write_request(Sender, Reply),
            {reply, EncReply,{Request#radius_request.cmd, ReplyCmd}};
        noreply ->
            ?LOG(error, "~s INF: Noreply for request ~p from handler ~p: returned value: ~p",
                        [printable_peer(ServerIP, Port), Request, HandlerArg, noreply]),
            {discard, handler_returned_noreply};
        {error, timeout} ->
            ReqType = eradius_log:format_cmd(Request#radius_request.cmd),
            ReqId = integer_to_list(Request#radius_request.reqid),
            S = {NasProp#nas_prop.nas_ip, NasProp#nas_prop.nas_port, Request#radius_request.reqid},
            NAS = eradius_lib:get_attr(Request, ?NAS_Identifier),
            NAS_IP = inet_parse:ntoa(NasProp#nas_prop.nas_ip),
            ?LOG(error, "~s INF: Timeout after waiting for response to ~s(~s) from RADIUS NAS: ~s NAS_IP:~s",
                 [printable_peer(ServerIP, Port), ReqType, ReqId, NAS, NAS_IP],
                 maps:from_list(eradius_log:collect_meta(S, Request))),
            {discard, {bad_return, {error, timeout}}};
        OtherReturn ->
            ?LOG(error, "~s INF: Unexpected return for request ~p from handler ~p: returned value: ~p",
                        [printable_peer(ServerIP, Port), Request, HandlerArg, OtherReturn]),
            {discard, {bad_return, OtherReturn}}
    catch
        Class:Reason:S ->
            ?LOG(error, "~s INF: Handler crashed after request ~p, radius handler class: ~p, reason of crash: ~p, stacktrace: ~p",
                        [printable_peer(ServerIP, Port), Request, Class, Reason, S]),
            {exit, {Class, Reason}}
    end.

inc_counter({ReqCmd, RespCmd}, NasProp, Ms) ->
    inc_request_counter(ReqCmd, NasProp, Ms),
    inc_reply_counter(RespCmd, NasProp).

inc_request_counter(request, NasProp, Ms) ->
    eradius_metrics:update_nas_request("access", NasProp#nas_prop.metrics_info, Ms),
    eradius_counter:inc_request_counter(accessRequests, NasProp);
inc_request_counter(accreq, NasProp, Ms) ->
    eradius_metrics:update_nas_request("accounting", NasProp#nas_prop.metrics_info, Ms),
    eradius_counter:inc_request_counter(accountRequests, NasProp);
inc_request_counter(coareq, NasProp, Ms) ->
    eradius_metrics:update_nas_request("coa", NasProp#nas_prop.metrics_info, Ms),
    eradius_counter:inc_request_counter(coaRequests, NasProp);
inc_request_counter(discreq, NasProp, Ms) ->
    eradius_metrics:update_nas_request("disconnect", NasProp#nas_prop.metrics_info, Ms),
    eradius_counter:inc_request_counter(discRequests, NasProp);
inc_request_counter(_Cmd, _NasProp, _Ms) ->
    ok.

inc_reply_counter(accept, NasProp) ->
    eradius_metrics:update_nas_response("access_accept", NasProp#nas_prop.metrics_info),
    eradius_counter:inc_reply_counter(accessAccepts, NasProp);
inc_reply_counter(reject, NasProp) ->
    eradius_metrics:update_nas_response("access_reject", NasProp#nas_prop.metrics_info),
    eradius_counter:inc_reply_counter(accessRejects, NasProp);
inc_reply_counter(challenge, NasProp) ->
    eradius_metrics:update_nas_response("access_challenge", NasProp#nas_prop.metrics_info),
    eradius_counter:inc_reply_counter(accessChallenges, NasProp);
inc_reply_counter(accresp, NasProp) ->
    eradius_metrics:update_nas_response("accounting", NasProp#nas_prop.metrics_info),
    eradius_counter:inc_reply_counter(accountResponses, NasProp);
inc_reply_counter(coaack, NasProp) ->
    eradius_metrics:update_nas_response("coa_ack", NasProp#nas_prop.metrics_info),
    eradius_counter:inc_reply_counter(coaAcks, NasProp);
inc_reply_counter(coanak, NasProp) ->
    eradius_metrics:update_nas_response("coa_nak", NasProp#nas_prop.metrics_info),
    eradius_counter:inc_reply_counter(coaNaks, NasProp);
inc_reply_counter(discack, NasProp) ->
    eradius_metrics:update_nas_response("disconnect_ack", NasProp#nas_prop.metrics_info),
    eradius_counter:inc_reply_counter(discAcks, NasProp);
inc_reply_counter(discnak, NasProp) ->
    eradius_metrics:update_nas_response("disconnect_nak", NasProp#nas_prop.metrics_info),
    eradius_counter:inc_reply_counter(discNaks, NasProp);
inc_reply_counter(_Cmd, _NasProp) ->
    ok.

%% @TODO: extend for other failures
inc_discard_counter(malformed, NasProp, Ms) ->
    eradius_metrics:update_nas_request("malformed", NasProp#nas_prop.metrics_info, Ms),
    eradius_counter:inc_counter(malformedRequests, NasProp);
inc_discard_counter(_Reason, NasProp, Ms) ->
    eradius_metrics:update_nas_request("dropped", NasProp#nas_prop.metrics_info, Ms),
    eradius_counter:inc_counter(packetsDropped, NasProp).
