
-module(eradius_client_socket_test).

-behaviour(gen_server).

-export([start/3]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-record(state, {client, socket, pending, mode, counter}).

start(SocketIP, Client, PortIdx) ->
    gen_server:start_link(?MODULE, [SocketIP, Client, PortIdx], []).

init([_SocketIP, Client, PortIdx]) ->
    Client ! {PortIdx, self()},
    eradius_client_SUITE:addSocket(),
    Pending = dict:new(),
    {ok, #state{pending = Pending, mode = active, counter = 0}}.

handle_call(_Request, _From, State) ->
    {noreply, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info({SenderPid, send_request, {IP, Port}, ReqId, _EncRequest},
        State = #state{pending = Pending, counter = Counter}) ->
    ReqKey = {IP, Port, ReqId},
    NPending = dict:store(ReqKey, SenderPid, Pending),
    {noreply, State#state{pending = NPending, counter = Counter+1}};

handle_info(close, State) ->
    %~ {noreply, State#state{mode = inactive}};
    {stop, normal, State};

handle_info({status, Pid}, State = #state{mode = Mode}) ->
    Pid ! {ok, Mode},
    {noreply, State};

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    eradius_client_SUITE:delSocket().

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

