%% Copyright (c) 2002-2007, Martin Björklund and Torbjörn Törnkvist
%% Copyright (c) 2011, Travelping GmbH <info@travelping.com>
%%
%% SPDX-License-Identifier: MIT
%%
-module(eradius_client_socket).

-behaviour(gen_server).

%% API
-export([new/1, start_link/1, send_request/5, close/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-record(state, {socket, active_n, pending, mode, counter}).

%%%=========================================================================
%%%  API
%%%=========================================================================

new(Config) ->
    eradius_client_socket_sup:new(Config).

start_link(Config) ->
    gen_server:start_link(?MODULE, [Config], []).

send_request(Socket, Peer, ReqId, Request, Timeout) ->
    try
        gen_server:call(Socket, {send_request, Peer, ReqId, Request}, Timeout)
    catch
        exit:{timeout, _} ->
            {error, timeout};
        exit:{noproc, _} ->
            {error, closed};
        {nodedown, _} ->
            {error, closed}
    end.

close(Socket) ->
    gen_server:cast(Socket, close).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([#{family := Family, ip := IP, active_n := ActiveN,
        recbuf := RecBuf, sndbuf := SndBuf} = _Config]) ->
    case IP of
        any ->
            ExtraOptions = [];
        _ when is_tuple(IP) ->
            ExtraOptions = [{ip, IP}]
    end,

    Opts = [{active, ActiveN}, binary, {recbuf, RecBuf}, {sndbuf, SndBuf},
            Family | ExtraOptions],
    {ok, Socket} = gen_udp:open(0, Opts),

    State = #state{
               socket = Socket,
               active_n = ActiveN,
               pending = #{},
               mode = active
              },
    {ok, State}.

handle_call({send_request, {IP, Port}, ReqId, Request}, From,
            #state{socket = Socket, pending = Pending} = State) ->
    case gen_udp:send(Socket, IP, Port, Request) of
        ok ->
            ReqKey = {IP, Port, ReqId},
            NPending = Pending#{ReqKey => From},
            {noreply, State#state{pending = NPending}};
        {error, Reason} ->
            {reply, {error, Reason}, State}
    end;

handle_call(_Request, _From, State) ->
    {noreply, State}.

handle_cast(close, #state{pending = Pending} = State)
  when map_size(Pending) =:= 0 ->
    {stop, normal, State};
handle_cast(close, State) ->
    {noreply, State#state{mode = inactive}};

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info({udp_passive, _Socket}, #state{socket = Socket, active_n = ActiveN} = State) ->
    inet:setopts(Socket, [{active, ActiveN}]),
    {noreply, State};

handle_info({udp, Socket, FromIP, FromPort, Request},
            State = #state{socket = Socket, pending = Pending, mode = Mode}) ->
    case eradius_lib:decode_request_id(Request) of
        {ReqId, Request} ->
            case Pending of
                #{{FromIP, FromPort, ReqId} := From} ->
                    gen_server:reply(From, {response, ReqId, Request}),

                    flow_control(State),
                    NPending = maps:remove({FromIP, FromPort, ReqId}, Pending),
                    NState = State#state{pending = NPending},
                    case Mode of
                        inactive when map_size(NPending) =:= 0 ->
                            {stop, normal, NState};
                        _ ->
                            {noreply, NState}
                    end;
                _ ->
                    %% discard reply because we didn't expect it
                    flow_control(State),
                    {noreply, State}
            end;
        {bad_pdu, _} ->
            %% discard reply because it was malformed
            flow_control(State),
            {noreply, State}
    end;

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%=========================================================================
%%%  internal functions
%%%=========================================================================

flow_control(#state{socket = Socket, active_n = once}) ->
    inet:setopts(Socket, [{active, once}]);
flow_control(_) ->
    ok.
