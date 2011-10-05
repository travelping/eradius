-module(eradius_client).
-export([start_link/0, send_request/2, send_request/3]).
-export([socket/1]).

-compile(export_all).

-behaviour(gen_server).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-include("eradius_lib.hrl").
-define(SERVER, ?MODULE).
-define(DEFAULT_RETRIES, 3).
-define(DEFAULT_TIMEOUT, 5000).

-type nas_address() :: {inet:ip_address(), eradius_server:port_number(), eradius_lib:secret()}.
-type options() :: [{retries, pos_integer()} | {timeout, timeout()}].

%% ------------------------------------------------------------------------------------------
%% -- API
start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

-spec send_request(nas_address(), #radius_request{}) -> {ok, binary()} | {error, 'timeout' | 'socket_down'}.
send_request(NAS, Request) ->
    send_request(NAS, Request, []).

-spec send_request(nas_address(), #radius_request{}, options()) -> {ok, binary()} | {error, 'timeout' | 'socket_down' | 'badcmd'}.
send_request({IP, Port, Secret}, Request = #radius_request{cmd = Cmd}, Options) when Cmd =:= 'request'; Cmd =:= 'accreq' ->
    Retries = proplists:get_value(retries, Options, ?DEFAULT_RETRIES),
    Timeout = proplists:get_value(timeout, Options, ?DEFAULT_TIMEOUT),
    {Socket, ReqId} = gen_server:call(?SERVER, {wanna_send, {IP, Port}}),
    SMon = erlang:monitor(process, Socket),
    EncRequest = encode_request(Request#radius_request{reqid = ReqId, secret = Secret}),
    send_retry_loop(Socket, SMon, {IP, Port}, ReqId, EncRequest, Timeout, Retries).

encode_request(Req = #radius_request{cmd = request}) ->
    eradius_lib:encode_request(Req#radius_request{authenticator = eradius_lib:random_authenticator()});
encode_request(Req = #radius_request{cmd = accreq}) ->
    eradius_lib:encode_reply_request(Req#radius_request{authenticator = eradius_lib:zero_authenticator()}).

send_retry_loop(_Socket, SMon, _Peer, _ReqId, _EncRequest, _Timeout, 0) ->
    erlang:demonitor(SMon, [flush]),
    {error, timeout};
send_retry_loop(Socket, SMon, Peer, ReqId, EncRequest, Timeout, RetryN) ->
    Socket ! {self(), send_request, Peer, ReqId, EncRequest},
    receive
        {Socket, response, ReqId, Response} ->
            {ok, Response};
        {'DOWN', SMon, process, Socket, _} ->
            {error, socket_down}
    after
        Timeout ->
            send_retry_loop(Socket, SMon, Peer, ReqId, EncRequest, Timeout, RetryN - 1)
    end.

%% ------------------------------------------------------------------------------------------
%% -- socket process manager
-record(state, {
    no_ports = 1 :: pos_integer(),
    idcounters = dict:new() :: dict(),
    sockets = array:new() :: array()
}).

%% @private
init([]) ->
    %% we want terminate to be called...
    {ok, ClientPortCount} = application:get_env(eradius, client_ports),
    NewState = #state{no_ports = ClientPortCount},
    {ok, NewState}.

%% @private
handle_call({wanna_send, Peer}, _From, State) ->
    {PortIdx, ReqId, NewIdCounters} = next_port_and_req_id(Peer, State#state.no_ports, State#state.idcounters),
    {SocketProcess, NewSockets} = find_socket_process(PortIdx, State#state.sockets),
    NewState = State#state{idcounters = NewIdCounters, sockets = NewSockets},
    {reply, {SocketProcess, ReqId}, NewState};

%% @private
handle_call(_OtherCall, _From, State) ->
    {noreply, State}.

%% @private
handle_cast(_Msg, State) -> {noreply, State}.
%% @private
handle_info(_Info, State) -> {noreply, State}.
%% @private
terminate(_Reason, _State) -> ok.
%% @private
code_change(_OldVsn, State, _Extra) -> {ok, State}.

next_port_and_req_id(Peer, NumberOfPorts, Counters) ->
    case dict:find(Peer, Counters) of
        {ok, {NextPortIdx, ReqId}} when ReqId < 255 ->
            NextReqId = (ReqId + 1);
        {ok, {PortIdx, 255}} ->
            NextPortIdx = (PortIdx + 1) rem (NumberOfPorts - 1),
            NextReqId = 0;
        error ->
            NextPortIdx = erlang:phash2(Peer, NumberOfPorts),
            NextReqId = 0
    end,
    NewCounters = dict:store(Peer, {NextPortIdx, NextReqId}, Counters),
    {NextPortIdx, NextReqId, NewCounters}.

find_socket_process(PortIdx, Sockets) ->
    case array:get(PortIdx, Sockets) of
        undefined ->
            Pid = proc_lib:spawn_link(?MODULE, socket, [self()]),
            {Pid, array:set(PortIdx, Pid, Sockets)};
        Pid when is_pid(Pid) ->
            {Pid, Sockets}
    end.


%% ------------------------------------------------------------------------------------------
%% -- socket process
%% @private
socket(Client) ->
    {ok, Socket} = gen_udp:open(0, [{active, once}, binary]),
    Pending = dict:new(),
    socket_loop(Client, Socket, Pending).

socket_loop(Client, Socket, Pending) ->
    receive
        {SenderPid, send_request, {IP, Port}, ReqId, EncRequest} ->
            gen_udp:send(Socket, IP, Port, EncRequest),
            ReqKey = {IP, Port, ReqId},
            socket_loop(Client, Socket, dict:store(ReqKey, SenderPid, Pending));
        {udp, Socket, FromIP, FromPort, EncRequest} ->
            case eradius_lib:decode_request_id(EncRequest) of
                {ReqId, EncRequest} ->
                    case dict:find({FromIP, FromPort, ReqId}, Pending) of
                        error ->
                            %% discard reply because we didn't expect it
                            inet:setopts(Socket, [{active, once}]),
                            socket_loop(Client, Socket, Pending);
                        {ok, WaitingSender} ->
                            WaitingSender ! {self(), response, ReqId, EncRequest},
                            inet:setopts(Socket, [{active, once}]),
                            socket_loop(Client, Socket, dict:erase({FromIP, FromPort, ReqId}, Pending))
                    end;
                bad_pdu ->
                    %% discard reply because it was malformed
                    inet:setopts(Socket, [{active, once}]),
                    socket_loop(Client, Socket, Pending)
            end
    end.
