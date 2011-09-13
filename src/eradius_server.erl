%% @doc
%%   This module implements a generic RADIUS server. A handler callback module
%%   is used to process requests. The handler module is selected based on the NAS that
%%   sent the request. Requests from unknown NASs are discarded.
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
%%   -record(nas_prop, {
%%       server_ip          :: inet:ip_address(),
%%       server_port        :: eradius_server:port_number(),
%%       nas_ip             :: inet:ip_address(),
%%       secret             :: eradius_lib:secret(),
%%       trace = true       :: boolean()
%%   }).
%%
%%   -record(radius_request, {
%%       cmd                :: 'request' | 'accept' | 'challenge' | 'reject' | 'accreq' | 'accresp',
%%       servers            :: list(),
%%       timeout = infinity :: timeout(),
%%       attrs = []         :: [eradius_dict:attribute()]
%%   }).
%%   '''
-module(eradius_server).
-export([start_link/2, behaviour_info/1]).
-export_type([port_number/0]).

%% internal
-export([do_radius/5]).

-behaviour(gen_server).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-include("eradius_lib.hrl").

-type port_number() :: 1..65535.
-type req_id()      :: byte().
-type udp_socket()  :: port().
-type udp_packet()  :: {udp, udp_socket(), inet:ip_address(), port_number(), binary()}.

-record(state, {
    socket             :: udp_socket(),      % Socket Reference of opened UDP port
    ip     = {0,0,0,0} :: inet:ip_address(), % IP to which this socket is bound
    port   = 0         :: port_number(),     % Port number we are listening on
    transacts          :: ets:tid()          % ETS table containing current transactions
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
            {ok, #state{socket = Socket, ip = IP, port = Port, transacts = ets:new(transacts, [])}};
        {error, Reason} ->
            {stop, Reason}
    end.

%% @private
handle_info(ReqUDP = {udp, Socket, FromIP, FromPortNo, Packet}, State = #state{transacts = Transacts}) ->
    case dec_radius(State, FromIP, Packet) of
        {ok, ReqID, Handler, NasProp} ->
            ReqKey = {ReqID, FromIP},
            case ets:lookup(Transacts, ReqKey) of
                [] ->
                    dbg(NasProp, "new request: ~p~n", [{ReqID, FromIP, FromPortNo}]),
                    Pid = proc_lib:spawn_link(?MODULE, do_radius, [self(), ReqUDP, ReqID, Handler, NasProp]),
                    ets:insert(Transacts, {ReqKey, Pid}),
                    inet:setopts(Socket, [{active, once}]),
                    {noreply, State};
                [{{ReqID, FromIP}, _HandlerPid}] ->
                    %% Duplicate request.  We assume that the previous
                    %% request will still answer.  We should probably
                    %% also store old responses for some time so we
                    %% can return what was originally sent if the
                    %% duplicate request arrived after we had already
                    %% sent our answer. This is the only reason to
                    %% even store the transaction.
                    dbg(NasProp, "duplicate request: ~p~n", [{ReqID, FromIP, FromPortNo}]),
                    inet:setopts(Socket, [{active, once}]),
                    {noreply, State}
            end;
        {discard, Message, _Reason} ->
            eradius:error_report("Discarded request from ~1000.p, Reason: ~1000.p~n", [{FromIP, FromPortNo}, Message]),
            inet:setopts(Socket, [{active, once}]),
            {noreply, State}
    end;
handle_info({handled, ReqID, FromIP}, State = #state{transacts = Transacts}) ->
    ets:delete(Transacts, {ReqID, FromIP}),
    {noreply, State};
handle_info({'EXIT', _HandlerPid, normal}, State) ->
    {noreply, State};
handle_info({'EXIT', HandlerPid, _OtherReason}, State = #state{transacts = Transacts}) ->
    ets:match_delete(Transacts, {'_', HandlerPid}),
    {noreply, State};
handle_info(_Info, State) ->
    {noreply, State}.

%% @private
terminate(_Reason, State) ->
    gen_udp:close(State#state.socket),
    ok.

%% ---------------- unused callbacks
%% @private
handle_call(_Request, _From, State) -> {noreply, State}.
%% @private
handle_cast(_Msg, State)            -> {noreply, State}.
%% @private
code_change(_OldVsn, State, _Extra) -> {ok, State}.

%% ------------------------------------------------------------------------------------------
%% -- Internal Functions
-spec dec_radius(#state{}, inet:ip_address(), binary()) -> {ok, req_id(), eradius_server_mon:handler(), #nas_prop{}} | {discard, string(), atom()}.
dec_radius(#state{ip = IP, port = Port}, NasIP, <<_Code, ReqID, _/binary>>) ->
    case eradius_server_mon:lookup_handler(IP, Port, NasIP) of
        {ok, Handler, NasProp} ->
            {ok, ReqID, Handler, NasProp};
        {error, not_found} ->
            {discard, "Radius Request from non allowed IP address.", dis_bad_ras}
    end;
dec_radius(_State, _NasIP, _Packet) ->
    {discard, "Radius request packet size too small to start", dis_bad_packet}.

%% @private
%% @doc handler function (spawned for every request)
-spec do_radius(pid(), udp_packet(), req_id(), eradius_server_mon:handler(), #nas_prop{}) -> any().
do_radius(ServerPid, {udp, Socket, FromIP, FromPortNo, Packet}, ReqID, Handler, NasProp) ->
    Secret = NasProp#nas_prop.secret,
    case (catch eradius_lib:dec_packet(Packet, Secret)) of
        ReqPDU = #rad_pdu{} ->
            case apply_handler(Handler, ReqPDU, NasProp) of
                {reply, ReplyPacket} ->
                    dbg(NasProp, "sending response for ~1000.p~n", [{ReqID, FromIP, FromPortNo}]),
                    gen_udp:send(Socket, FromIP, FromPortNo, ReplyPacket),
                    ServerPid ! {handled, ReqID, FromIP};
                {discard, Reason} ->
                    dbg(NasProp, "discarding response for ~1000.p~n", [{ReqID, FromIP, Reason}]),
                    ServerPid ! {handled, ReqID, FromIP}
            end;
        NonPDU ->
            dbg(NasProp, "discarding response for ~1000.p~n", [{ReqID, FromIP, NonPDU}]),
            ServerPid ! {handled, ReqID, FromIP}
    end.

-spec apply_handler(eradius_server_mon:handler(), #rad_pdu{}, #nas_prop{}) -> {discard, term()} | {reply, iolist()}.
apply_handler({HandlerMod, HandlerArg}, ReqPDU, NasProp) ->
    try HandlerMod:radius_request(ReqPDU#rad_pdu.req, NasProp, HandlerArg) of
        {reply, Reply = #radius_request{}} ->
            EncReply = eradius_lib:enc_reply_pdu(ReqPDU#rad_pdu{req = Reply}),
            {reply, EncReply};
        noreply ->
            {discard, handler_returned_noreply};
        OtherReturn ->
            eradius:error_report("Bad return value from RADIUS handler ~s: ~p", [HandlerMod, OtherReturn])
    catch
        Exn ->
            {discard, Exn}
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
    io_lib:format("~p-~p-~p_~p:~p:~p:~p", [Y,Mo,D,H,M,S,MicroSecs div 1000]).
