-module(eradius_client_socket).

-behaviour(gen_server).

-export([start/3]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-record(state, {client, socket, pending, mode, active_n, counter}).

-include_lib("kernel/include/logger.hrl").

start(SocketIP, Client, PortIdx) ->
    gen_server:start_link(?MODULE, [SocketIP, Client, PortIdx], []).

init([SocketIP, Client, PortIdx]) ->
    Client ! {PortIdx, self()},
    RecBuf = application:get_env(eradius, recbuf, 256*1024),
    SndBuf = application:get_env(eradius, sndbuf, 256*1024),

    SockAddr =
        case SocketIP of
            undefined -> any;
            _ when is_tuple(SocketIP) -> SocketIP
        end,
    {ok, Socket} = socket:open(inet, dgram, udp),
    ok = socket:bind(Socket, #{family => inet, port => 0, addr => SockAddr}),
    ok = socket:setopt(Socket, socket, rcvbuf, RecBuf),
    ok = socket:setopt(Socket, socket, sndbuf, SndBuf),

    self() ! {'$socket', Socket, select, undefined},

    State = #state{client = Client,
                   socket = Socket,
                   pending = maps:new(),
                   mode = active,
                   active_n = 100,
                   counter = 0},
    {ok, State}.

handle_call(_Request, _From, State) ->
    {noreply, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info({'$socket', Socket, select, Info}, #state{socket = Socket} = State) ->
    handle_input(Socket, Info, State);

handle_info({SenderPid, send_request, {IP, Port}, ReqId, EncRequest},
        State = #state{socket = Socket, pending = Pending, counter = Counter}) ->
    case socket:sendto(Socket, EncRequest, #{family => inet, port => Port, addr => IP}) of
        ok ->
            ReqKey = {IP, Port, ReqId},
            NPending = maps:put(ReqKey, SenderPid, Pending),
            {noreply, State#state{pending = NPending, counter = Counter+1}};
        {error, Reason} ->
            SenderPid ! {error, Reason},
            {noreply, State}
    end;

handle_info(close, State = #state{counter = Counter}) ->
    case Counter of
        0   -> {stop, normal, State};
        _   -> {noreply, State#state{mode = inactive}}
    end;

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

handle_input(Socket, Info, #state{active_n = ActiveN} = State) ->
    handle_input(Socket, Info, 0, ActiveN, State).

handle_input(_Socket, _Info, _Cnt, _Max, #state{mode = inactive, counter = 0} = State) ->
    {stop, normal, State};
handle_input(Socket, _Info, Cnt, Max, State0)
  when Cnt >= Max ->
    %% break the loop and restart
    self() ! {'$socket', Socket, select, undefined},
    {noreply, State0};

handle_input(Socket, Info, Cnt, Max, State0) ->
    case socket:recvfrom(Socket, 0, [], nowait) of
        {error, _} ->
            State = handle_err_input(Socket, State0),
            handle_input(Socket, Info, Cnt + 1, Max, State);

        {ok, {#{addr := IP, port := Port}, Data}} ->
            ArrivalTS = erlang:monotonic_time(),
            State = handle_message(ArrivalTS, IP, Port, Data, State0),
            handle_input(Socket, Info, Cnt + 1, Max, State);

        {select, _SelectInfo} when Cnt == 0 ->
            %% there must be something in the error queue
            State = handle_err_input(Socket, State0),
            handle_input(Socket, Info, Cnt + 1, Max, State);

        {select, _SelectInfo} ->
            {noreply, State0}
    end.

handle_err_input(Socket, State) ->
    case socket:recvmsg(Socket, [errqueue], 0) of
        {ok, #{addr := #{addr := IP, port := Port}, ctrl := Ctrl}} ->
            %% lists:foreach(handle_socket_error(_, IP, Port, State), Ctrl),
            ok;
        {error, timeout} ->
            ok;
        {error, ewouldblock} ->
            ok;

        Other ->
            ?LOG(error, "got unhandled error input: ~p", [Other])
    end,
    State.

handle_message(ArrivalTS, FromIP, FromPort, EncRequest,
               #state{pending = Pending, mode = Mode, counter = Counter} = State) ->
    case eradius_lib:decode_request_id(EncRequest) of
        {ReqId, EncRequest} ->
            case maps:find({FromIP, FromPort, ReqId}, Pending) of
                error ->
                    %% discard reply because we didn't expect it
                    State;
                {ok, WaitingSender} ->
                    WaitingSender ! {self(), response, ReqId, EncRequest},
                    NPending = maps:remove({FromIP, FromPort, ReqId}, Pending),
                    State#state{pending = NPending, counter = Counter - 1}
            end;
        {bad_pdu, _} ->
            %% discard reply because it was malformed
            State
    end.
