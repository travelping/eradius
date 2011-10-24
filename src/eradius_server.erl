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
%%       cmd           :: 'request' | 'accept' | 'challenge' | 'reject' | 'accreq' | 'accresp',
%%       attrs         :: eradius_lib:attribute_list(),
%%       secret        :: eradius_lib:secret(),
%%       authenticator :: eradius_lib:authenticator()
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
-export([start_link/2, behaviour_info/1]).
-export_type([port_number/0, req_id/0]).

%% internal
-export([do_radius/5, handle_request/3, handle_remote_request/5]).

-behaviour(gen_server).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-include("eradius_lib.hrl").

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
    transacts      :: ets:tid()          % ETS table containing current transactions
}).

-spec behaviour_info('callbacks') -> [{module(), non_neg_integer()}].
behaviour_info(callbacks) -> [{radius_request,3}].

%% @private
-spec start_link(inet:ip4_address(), port_number()) -> {ok, pid()} | {error, term()}.
start_link(IP = {A,B,C,D}, Port) ->
    Name = list_to_atom(lists:flatten(io_lib:format("eradius_server_~b.~b.~b.~b:~b", [A,B,C,D,Port]))),
    gen_server:start_link({local, Name}, ?MODULE, {IP, Port}, []).

%% ------------------------------------------------------------------------------------------
%% -- gen_server Callbacks
%% @private
init({IP, Port}) ->
    process_flag(trap_exit, true),
    case gen_udp:open(Port, [{active, once}, {ip, IP}, binary]) of
        {ok, Socket} ->
            {ok, #state{socket = Socket,
                        ip = IP, port = Port,
                        transacts = ets:new(transacts, [])}};
        {error, Reason} ->
            {stop, Reason}
    end.

%% @private
handle_info(ReqUDP = {udp, Socket, FromIP, FromPortNo, Packet}, State = #state{transacts = Transacts}) ->
    case lookup_nas(State, FromIP, Packet) of
        {ok, ReqID, Handler, NasProp} ->
            ReqKey = {FromIP, FromPortNo, ReqID},
            NNasProp = NasProp#nas_prop{nas_port = FromPortNo},
            case ets:lookup(Transacts, ReqKey) of
                [] ->
                    HandlerPid = proc_lib:spawn_link(?MODULE, do_radius, [self(), ReqKey, Handler, NNasProp, ReqUDP]),
                    ets:insert(Transacts, {ReqKey, {handling, HandlerPid}});
                [{_ReqKey, {handling, _HandlerPid}}] ->
                    %% handler process is still working on the request
                    dbg(NasProp, "duplicate request (being handled) ~p~n", [ReqKey]);
                [{_ReqKey, {replied, HandlerPid}}] ->
                    %% handler process waiting for resend message
                    HandlerPid ! {self(), resend, Socket},
                    dbg(NasProp, "duplicate request (resend) ~p~n", [ReqKey])
            end;
        {discard, _Reason} ->
            ok
    end,
    inet:setopts(Socket, [{active, once}]),
    {noreply, State};
handle_info({replied, ReqKey, HandlerPid}, State = #state{transacts = Transacts}) ->
    ets:insert(Transacts, {ReqKey, {replied, HandlerPid}}),
    {noreply, State};
handle_info({discarded, ReqKey}, State = #state{transacts = Transacts}) ->
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

%% -- unused callbacks
%% @private
handle_call(_Request, _From, State) -> {noreply, State}.
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
-spec do_radius(pid(), term(), eradius_server_mon:handler(), #nas_prop{}, udp_packet()) -> any().
do_radius(ServerPid, ReqKey, Handler = {HandlerMod, _}, NasProp, {udp, Socket, FromIP, FromPort, EncRequest}) ->
    Nodes = eradius_node_mon:get_module_nodes(HandlerMod),
    case run_handler(Nodes, NasProp, Handler, EncRequest) of
        {reply, EncReply} ->
            dbg(NasProp, "sending response for ~p~n", [ReqKey]),
            gen_udp:send(Socket, FromIP, FromPort, EncReply),
            ServerPid ! {replied, ReqKey, self()},
            wait_resend(ServerPid, ReqKey, FromIP, FromPort, EncReply, ?RESEND_RETRIES);
        {discard, Reason} ->
            dbg(NasProp, "discarding request ~p: ~1000.p~n", [ReqKey, Reason]),
            ServerPid ! {discarded, ReqKey};
        {exit, Reason} ->
            dbg(NasProp, "discarding request (handler EXIT) ~p: ~p~n", [ReqKey, Reason]),
            ServerPid ! {discarded, ReqKey}
    end.

wait_resend(ServerPid, ReqKey, _FromIP, _FromPort, _EncReply, 0) ->
    ServerPid ! {discarded, ReqKey};
wait_resend(ServerPid, ReqKey, FromIP, FromPort, EncReply, Retries) ->
    receive
        {ServerPid, resend, Socket} ->
            gen_udp:send(Socket, FromIP, FromPort, EncReply),
            wait_resend(ServerPid, ReqKey, FromIP, FromPort, EncReply, Retries - 1)
    after
        ?RESEND_TIMEOUT ->
            ServerPid ! {discarded, ReqKey}
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
            Sender = {NasProp#nas_prop.nas_ip, NasProp#nas_prop.nas_port, Request#radius_request.reqid},
            {ok, RadiusLog} = eradius_log:open(),
            eradius_log:write_request(RadiusLog, Sender, Request),
            apply_handler_mod(HandlerMod, HandlerArg, Request, NasProp);
        bad_pdu ->
            {discard, bad_pdu}
    end.

%% @private
%% @doc this function is spawned on a remote node to handle a radius request.
%%   remote handlers need to be upgraded if the signature of this function changes.
%%   error reports go to the logger of the node that executes the request.
handle_remote_request(ReplyPid, HandlerMod, HandlerArg, NasPropTuple, EncRequest) ->
    group_leader(whereis(user), self()),
    NasProp = nas_prop_tuple_to_record(NasPropTuple),
    Result = handle_request({HandlerMod, HandlerArg}, NasProp, EncRequest),
    ReplyPid ! {self(), Result}.

nas_prop_record_to_tuple(R = #nas_prop{}) ->
    {nas_prop_v1, R#nas_prop.server_ip, R#nas_prop.server_port,
                  R#nas_prop.nas_ip, R#nas_prop.nas_port,
                  R#nas_prop.secret, R#nas_prop.trace, R#nas_prop.handler_nodes}.

nas_prop_tuple_to_record({nas_prop_v1, ServerIP, ServerPort, NasIP, NasPort, Secret, Trace, Nodes}) ->
    #nas_prop{server_ip = ServerIP, server_port = ServerPort,
              nas_ip = NasIP, nas_port = NasPort,
              secret = Secret, trace = Trace, handler_nodes = Nodes}.

-spec apply_handler_mod(module(), term(), #radius_request{}, #nas_prop{}) -> {discard, term()} | {exit, term()} | {reply, binary()}.
apply_handler_mod(HandlerMod, HandlerArg, Request, NasProp) ->
    try HandlerMod:radius_request(Request, NasProp, HandlerArg) of
        {reply, #radius_request{cmd = ReplyCmd, attrs = ReplyAttrs}} ->
            EncReply = eradius_lib:encode_reply_request(Request#radius_request{cmd = ReplyCmd, attrs = ReplyAttrs}),
            {reply, EncReply};
        noreply ->
            {discard, handler_returned_noreply};
        OtherReturn ->
            {discard, {bad_return, OtherReturn}}
    catch
        Reason ->
            {exit, Reason}
    end.

-spec dbg(#nas_prop{}, string(), list()) -> ok.
dbg(#nas_prop{trace = true}, Fmt, Vals) ->
    io:put_chars([printable_date(), " -- ", io_lib:format(Fmt, Vals)]);
dbg(_, _, _) ->
    ok.

-spec printable_date() -> io_lib:chars().
printable_date() ->
    {_ , _, MicroSecs} = Now = now(),
    {{Y, Mo, D}, {H, M, S}} = calendar:now_to_local_time(Now),
    io_lib:format("~4..0b-~2..0b-~2..0b ~2..0b:~2..0b:~2..0b:~4..0b", [Y,Mo,D,H,M,S,MicroSecs div 1000]).
