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
%%   There is only one callback at the moment.
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
%%       secret        :: eradius_lib:secret(),
%%       trace         :: boolean(),
%%       handler_nodes :: 'local' | list(atom())
%%   }).
%%   '''
-module(eradius_server).
-export([start_link/3, behaviour_info/1]).
-export_type([port_number/0, req_id/0]).

%% internal
-export([do_radius/7, handle_request/3, handle_remote_request/5, stats/2]).
-export([printable_peer/2]).

-behaviour(gen_server).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-include("eradius_lib.hrl").

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

-spec behaviour_info('callbacks') -> [{module(), non_neg_integer()}].
behaviour_info(callbacks) -> [{radius_request,3}].

%% @private
-spec start_link(atom(), inet:ip4_address(), port_number()) -> {ok, pid()} | {error, term()}.
start_link(ServerName, IP = {A,B,C,D}, Port) ->
    Name = list_to_atom(lists:flatten(io_lib:format("eradius_server_~b.~b.~b.~b:~b", [A,B,C,D,Port]))),
    io:format("Name: ~p~n", [Name]),
    eradius_metrics:subscribe_server(ServerName, server),
    gen_server:start_link({local, Name}, ?MODULE, {ServerName, IP, Port}, []).

stats(Server, Function) ->
    gen_server:call(Server, {stats, Function}).

%% ------------------------------------------------------------------------------------------
%% -- gen_server Callbacks
%% @private
init({ServerName, IP, Port}) ->
    process_flag(trap_exit, true),
    case gen_udp:open(Port, [{active, once}, {ip, IP}, binary]) of
        {ok, Socket} ->
            {ok, #state{socket = Socket,
                        ip = IP, port = Port, name = ServerName,
                        transacts = ets:new(transacts, []),
                        counter = eradius_counter:init_counter({IP, Port})}};
        {error, Reason} ->
            {stop, Reason}
    end.

%% @private
handle_info(ReqUDP = {udp, Socket, FromIP, FromPortNo, Packet}, State = #state{name = ServerName, transacts = Transacts, ip = _IP, port = Port}) ->
    TS1 = eradius_metrics:timestamp(ms),
    case lookup_nas(State, FromIP, Packet) of
        {ok, ReqID, Handler, NasProp} ->
            #nas_prop{server_ip = ServerIP, server_port = Port} = NasProp,
            ReqKey = {FromIP, FromPortNo, ReqID},
            NNasProp = NasProp#nas_prop{nas_port = FromPortNo},
            case ets:lookup(Transacts, ReqKey) of
                [] ->
                    HandlerPid = proc_lib:spawn_link(?MODULE, do_radius, [self(), ReqKey, Handler, NNasProp, ReqUDP, ServerName, TS1]),
                    ets:insert(Transacts, {ReqKey, {handling, HandlerPid}}),
                    eradius_metrics:update_nas_prop_metric(requests, NasProp, 1),
                    eradius_counter:inc_counter(requests, NasProp);
                [{_ReqKey, {handling, HandlerPid}}] ->
                    %% handler process is still working on the request
                    lager:debug("~s From: ~s INF: Handler process ~p is still working on the request. duplicate request (being handled) ~p",
                        [printable_peer(ServerIP, Port), printable_peer(FromIP, FromPortNo), HandlerPid, ReqKey]),
                    eradius_metrics:update_nas_prop_metric(dup_requests, NasProp, 1),
                    eradius_counter:inc_counter(dupRequests, NasProp)
            end,
            NewState = State;
        {discard, Reason} when Reason == no_nodes_local, Reason == no_nodes ->
            exometer:update_or_create([eradius, server, State#state.name, invalid_requests], 1, counter, []),
            NewState = State#state{counter = eradius_counter:inc_counter(discardNoHandler, State#state.counter)};
        {discard, _Reason} ->
            exometer:update_or_create([eradius, server, State#state.name, discards_no_handler], 1, counter, []),
            NewState = State#state{counter = eradius_counter:inc_counter(invalidRequests, State#state.counter)}
    end,
    inet:setopts(Socket, [{active, once}]),
    {noreply, NewState};
handle_info({free, ReqKey}, State = #state{transacts = Transacts}) ->
    ets:delete(Transacts, ReqKey),
    {noreply, State};
handle_info({'EXIT', _HandlerPid, normal}, State) ->
    {noreply, State};
handle_info({'EXIT', HandlerPid, _OtherReason}, State = #state{transacts = Transacts}) ->
    ets:match_delete(Transacts, {'_', {'_', HandlerPid}}),
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

-spec lookup_nas(#state{}, inet:ip_address(), binary()) -> {ok, req_id(), eradius_server_mon:handler(), #nas_prop{}} | {discard, unknown_nas | bad_pdu}.
lookup_nas(#state{ip = IP, port = Port}, NasIP, <<_Code, ReqID, _/binary>>) ->
    case eradius_server_mon:lookup_handler(IP, Port, NasIP) of
        {ok, Handler, NasProp} ->
            {ok, ReqID, Handler, NasProp};
        {error, not_found} ->
            {discard, unknown_nas}
    end;
lookup_nas(_State, _NasIP, _Packet) ->
    {discard, bad_pdu}.

%% ------------------------------------------------------------------------------------------
%% -- Request Handler
%% @private
-spec do_radius(pid(), term(), eradius_server_mon:handler(), #nas_prop{}, udp_packet(), atom(), integer()) -> any().
do_radius(ServerPid, ReqKey, Handler = {HandlerMod, _}, NasProp, {udp, Socket, FromIP, FromPort, EncRequest}, ServerName, TS1) ->
    #nas_prop{server_ip = ServerIP, server_port = Port} = NasProp,
    Nodes = eradius_node_mon:get_module_nodes(HandlerMod),
    case run_handler(Nodes, NasProp, Handler, EncRequest) of
        {reply, EncReply} ->
            lager:debug("~s From: ~s INF: Sending response for request ~p",
                 [printable_peer(ServerIP, Port), printable_peer(FromIP, FromPort), ReqKey]),
            TS2 = eradius_metrics:timestamp(ms),
            RequestHandletime = TS2 - TS1,
            exometer:update_or_create([eradius, server, ServerName, request_handle_time], RequestHandletime, histogram, [{truncate, false}]),
            gen_udp:send(Socket, FromIP, FromPort, EncReply),
            ServerPid ! {free, ReqKey},
            eradius_metrics:update_nas_prop_metric(replies, NasProp, 1),
            eradius_counter:inc_counter(replies, NasProp);
        {discard, Reason} ->
            lager:debug("~s From: ~s INF: Handler discarded the request ~p for reason ~1000.p",
                [printable_peer(ServerIP, Port), printable_peer(FromIP, FromPort), Reason, ReqKey]),
            discard_inc_counter(Reason, NasProp),
            ServerPid ! {free, ReqKey};
        {exit, Reason} ->
            lager:debug("~s From: ~s INF: Handler exited for reason ~p, discarding request ~p",
                        [printable_peer(ServerIP, Port), printable_peer(FromIP, FromPort), Reason, ReqKey]),
            eradius_metrics:update_nas_prop_metric(handler_failures, NasProp, 1),
            eradius_counter:inc_counter(handlerFailure, NasProp),
            ServerPid ! {free, ReqKey}
    end.

%% @TODO: extend for other failures
discard_inc_counter(bad_pdu, NasProp) ->
    eradius_metrics:update_nas_prop_metric(malformed_requests, NasProp, 1),
    eradius_counter:inc_counter(malformedRequests, NasProp);
discard_inc_counter(_Reason, NasProp) ->
    eradius_metrics:update_nas_prop_metric(packets_dropped, NasProp, 1),
    eradius_counter:inc_counter(packetsDropped, NasProp).

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
    NasPropTuple = nas_prop_record_to_tuple(NasProp),
    RemoteArgs = [self(), HandlerMod, HandlerArgs, NasPropTuple, EncRequest],
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
handle_request({HandlerMod, HandlerArg}, NasProp, EncRequest) ->
    case eradius_lib:decode_request(EncRequest, NasProp#nas_prop.secret) of
        Request = #radius_request{} ->
            request_inc_counter(Request#radius_request.cmd, NasProp),
            Sender = {NasProp#nas_prop.nas_ip, NasProp#nas_prop.nas_port, Request#radius_request.reqid},
            lager:info(eradius_log:collect_meta(Sender, Request),"~s",
                       [eradius_log:collect_message(Sender, Request)]),
            eradius_log:write_request(Sender, Request),
            apply_handler_mod(HandlerMod, HandlerArg, Request, NasProp);
        bad_pdu ->
            {discard, bad_pdu}
    end.

%% @private
%% @doc this function is spawned on a remote node to handle a radius request.
%%   remote handlers need to be upgraded if the signature of this function changes.
%%   error reports go to the logger of the node that executes the request.
handle_remote_request(ReplyPid, HandlerMod, HandlerArg, NasPropTuple, EncRequest) ->
    NasProp = nas_prop_tuple_to_record(NasPropTuple),
    Result = handle_request({HandlerMod, HandlerArg}, NasProp, EncRequest),
    ReplyPid ! {self(), Result}.

nas_prop_record_to_tuple(R = #nas_prop{}) ->
    {nas_prop_v1, R#nas_prop.server_ip, R#nas_prop.server_port,
                  R#nas_prop.nas_ip, R#nas_prop.nas_port,
                  R#nas_prop.secret, R#nas_prop.handler_nodes}.

nas_prop_tuple_to_record({nas_prop_v1, ServerIP, ServerPort, NasIP, NasPort, Secret, _Trace, Nodes}) ->
    #nas_prop{server_ip = ServerIP, server_port = ServerPort,
              nas_ip = NasIP, nas_port = NasPort,
              secret = Secret, handler_nodes = Nodes}.

-spec apply_handler_mod(module(), term(), #radius_request{}, #nas_prop{}) -> {discard, term()} | {exit, term()} | {reply, binary()}.
apply_handler_mod(HandlerMod, HandlerArg, Request, NasProp) ->
    #nas_prop{server_ip = ServerIP, server_port = Port} = NasProp,
    try HandlerMod:radius_request(Request, NasProp, HandlerArg) of
        {reply, Reply = #radius_request{cmd = ReplyCmd, attrs = ReplyAttrs, msg_hmac = MsgHMAC, eap_msg = EAPmsg}} ->
            Sender = {NasProp#nas_prop.nas_ip, NasProp#nas_prop.nas_port, Request#radius_request.reqid},
            EncReply = eradius_lib:encode_reply_request(Request#radius_request{cmd = ReplyCmd, attrs = ReplyAttrs,
                                                                               msg_hmac = Request#radius_request.msg_hmac or MsgHMAC or (size(EAPmsg) > 0),
                                                                               eap_msg = EAPmsg}),
            reply_inc_counter(ReplyCmd, NasProp),
            lager:info(eradius_log:collect_meta(Sender, Reply),"~s",
                       [eradius_log:collect_message(Sender, Reply)]),
            eradius_log:write_request(Sender, Reply),
            {reply, EncReply};
        noreply ->
            {discard, handler_returned_noreply};
        OtherReturn ->
            lager:error("~s INF: Unexpected return for request ~p from handler ~p: returned value: ~p",
            [printable_peer(ServerIP, Port), Request, HandlerArg, OtherReturn]),
            {discard, {bad_return, OtherReturn}}
    catch
        Class:Reason ->
            lager:error("~s INF: Handler crashed after request ~p, radius handler class: ~p, reason of crash: ~p, stacktrace: ~p",
                [printable_peer(ServerIP, Port), Request, Class, Reason, erlang:get_stacktrace()]),
            {exit, {Class, Reason}}
    end.

-spec printable_peer(inet:ip4_address(),eradius_server:port_number()) -> io_lib:chars().
printable_peer({IA,IB,IC,ID}, Port) ->
    io_lib:format("~b.~b.~b.~b:~b",[IA,IB,IC,ID,Port]).

request_inc_counter(request, NasProp) ->
    eradius_metrics:update_nas_prop_metric(access_requests, NasProp, 1),
    eradius_counter:inc_counter(accessRequests, NasProp);
request_inc_counter(accreq, NasProp) ->
    eradius_metrics:update_nas_prop_metric(account_requests, NasProp, 1),
    eradius_counter:inc_counter(accountRequests, NasProp);
request_inc_counter(coareq, NasProp) ->
    eradius_metrics:update_nas_prop_metric(coa_requests, NasProp, 1),
    eradius_counter:inc_counter(coaRequests, NasProp);
request_inc_counter(discreq, NasProp) ->
    eradius_metrics:update_nas_prop_metric(disconnect_requests, NasProp, 1),
    eradius_counter:inc_counter(discRequests, NasProp);
request_inc_counter(_Cmd, _NasProp) ->
    ok.

reply_inc_counter(accept, NasProp) ->
    eradius_metrics:update_nas_prop_metric(access_accepts, NasProp, 1),
    eradius_counter:inc_counter(accessAccepts, NasProp);
reply_inc_counter(reject, NasProp) ->
    eradius_metrics:update_nas_prop_metric(access_rejects, NasProp, 1),
    eradius_counter:inc_counter(accessRejects, NasProp);
reply_inc_counter(challenge, NasProp) ->
    eradius_metrics:update_nas_prop_metric(access_challenges, NasProp, 1),
    eradius_counter:inc_counter(accessChallenges, NasProp);
reply_inc_counter(accresp, NasProp) ->
    eradius_metrics:update_nas_prop_metric(account_responses, NasProp, 1),
    eradius_counter:inc_counter(accountResponses, NasProp);
reply_inc_counter(coaack, NasProp) ->
    eradius_metrics:update_nas_prop_metric(coa_acks, NasProp, 1),
    eradius_counter:inc_counter(coaAcks, NasProp);
reply_inc_counter(coanak, NasProp) ->
    eradius_metrics:update_nas_prop_metric(coa_naks, NasProp, 1),
    eradius_counter:inc_counter(coaNaks, NasProp);
reply_inc_counter(discack, NasProp) ->
    eradius_metrics:update_nas_prop_metric(disc_acks, NasProp, 1),
    eradius_counter:inc_counter(discAcks, NasProp);
reply_inc_counter(discnak, NasProp) ->
    eradius_metrics:update_nas_prop_metric(disc_naks, NasProp, 1),
    eradius_counter:inc_counter(discNaks, NasProp);
reply_inc_counter(_Cmd, _NasProp) ->
    ok.