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

-record(state, {family, socket, active_n, pending, mode, counter}).

%%%=========================================================================
%%%  API
%%%=========================================================================

new(Config) ->
    eradius_client_socket_sup:new(Config).

start_link(Config) ->
    gen_server:start_link(?MODULE, [Config], []).

send_request(Socket, Peer, ReqId, Request, Timeout) ->
    try
        gen_server:call(Socket, {send_request, Peer, ReqId, Request, Timeout}, infinity)
    catch
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

init([#{family := Family, active_n := ActiveN} = Config]) ->
    Opts = inet_opts(Config, [{active, ActiveN}, binary, Family]),
    {ok, Socket} = gen_udp:open(0, Opts),

    State = #state{
               family = Family,
               socket = Socket,
               active_n = ActiveN,
               pending = #{},
               mode = active
              },
    {ok, State}.

handle_call({send_request, {IP, Port}, ReqId, Request, Timeout}, From,
            #state{family = Family, socket = Socket} = State) ->
    case send_ip(Family, IP) of
        {ok, SendIP} ->
            case gen_udp:send(Socket, SendIP, Port, Request) of
                ok ->
                    ReqKey = {SendIP, Port, ReqId},
                    {noreply, pending_request(ReqKey, From, Timeout, State)};
                {error, _} = Error ->
                    {reply, Error, State}
            end;
        {error, _} = Error ->
            {reply, Error, State}
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

handle_info({udp, Socket, FromIP, FromPort, Response},
            State = #state{socket = Socket, mode = Mode}) ->
    case eradius_lib:decode_request_id(Response) of
        {ReqId, Response} ->
            NState = request_done({FromIP, FromPort, ReqId}, {ok, Response}, State),
            case Mode of
                inactive when map_size(State#state.pending) =:= 0 ->
                    {stop, normal, NState};
                _ ->
                    flow_control(NState),
                    {noreply, NState}
            end;
        {bad_pdu, _} ->
            %% discard reply because it was malformed
            flow_control(State),
            {noreply, State}
    end;

handle_info({timeout, TRef, ReqKey}, #state{pending = Pending} = State) ->
    NState =
        case Pending of
            #{ReqKey := {From, TRef}} ->
                gen_server:reply(From, {error, timeout}),
                State#state{pending = maps:remove(ReqKey, Pending)};
            _ ->
                State
        end,
    {noreply, NState};

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

pending_request(ReqKey, From, Timeout,
                #state{pending = Pending} = State) ->
    TRef = erlang:start_timer(Timeout, self(), ReqKey),
    State#state{pending = Pending#{ReqKey => {From, TRef}}}.

request_done(ReqKey, Reply, #state{pending = Pending} = State) ->
    case Pending of
        #{ReqKey := {From, TRef}} ->
            gen_server:reply(From, Reply),
            erlang:cancel_timer(TRef),
            State#state{pending = maps:remove(ReqKey, Pending)};
        _ ->
            State
    end.

send_ip(inet, {_, _, _, _} = IP) ->
    {ok, IP};
send_ip(inet6, {_, _, _, _} = IP) ->
    {ok, inet:ipv4_mapped_ipv6_address(IP)};
send_ip(inet6, {_, _, _, _,_, _, _, _} = IP) ->
    {ok, IP};
send_ip(_, _) ->
    {error, eafnosupport}.

inet_opts(Config, Opts0) ->
    Opts =
        maps:to_list(
          maps:with([recbuf, sndbuf, ip,
                     ipv6_v6only, netns, bind_to_device, read_packets], Config)) ++ Opts0,
    case Config of
        #{inet_backend := Backend} when Backend =:= inet; Backend =:= socket ->
            [{inet_backend, Backend} | Opts];
        _ ->
            Opts
    end.
