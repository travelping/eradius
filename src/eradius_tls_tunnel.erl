-module(eradius_tls_tunnel).
-behavior(gen_fsm).

-export([start/0, activate/2]).
-export([init/1, handle_info/3, handle_event/3, handle_sync_event/4, code_change/4, terminate/3]).
-export([handshake/2, running/2, tlv_acked/2]).

%% transport helper
-export([transport_recv/1, transport_send/3]).

-include("eradius_lib.hrl").
-include("eradius_eap.hrl").
-include("eradius_dict.hrl").
-include("dictionary.hrl").
-include("dictionary_microsoft.hrl").
-include_lib("ssl/src/ssl_record.hrl").

-record(state, {socket, reqid, inner_state, eap_state}).

-define(EAP_TLV_SUCCESS, 1).
-define(EAP_TLV_ACK_RESULT, 3).

start() ->
    {ok, Socket} = eradius_ssl_stream:transport_create(self(),
						       [{ssl_imp, new},
							{active, false},
							{verify, 0},
							{mode,binary},
							{reuseaddr, true},
							{ciphers, [{rsa,rc4_128,sha}, {rsa,rc4_128,md5}]},
							{cacertfile, "certs/etc/server/cacerts.pem"},
							{certfile, "certs/etc/server/cert.pem"},
							{keyfile, "certs/etc/server/key.pem"}
						       ]),
    {ok, Tunnel} = gen_fsm:start(?MODULE, {Socket}, []),
    eradius_ssl_stream:controlling_process(Socket, Tunnel),
    gen_fsm:send_event(Tunnel, accept),
    {ok, {Socket, Tunnel}}.

activate({_Socket, Tunnel}, ReqId) ->
    gen_fsm:send_event(Tunnel, {activate, ReqId}).

%% transport helper
transport_recv({Socket, _Tunnel}) ->
    eradius_ssl_stream:transport_send(Socket).

transport_send({Socket, Tunnel}, ReqId, Data) ->
    gen_fsm:send_all_state_event(Tunnel, {reqid, ReqId}),
    eradius_ssl_stream:transport_recv(Socket, Data).

%% ------------------------------------------------------------------------------------------
%% -- gen_fsm Callbacks
%% @private
init({Socket}) ->
    {ok, handshake, #state{socket = Socket, inner_state = challenge}}.

handshake(accept, State = #state{socket = Socket}) ->
    Reply = eradius_ssl_stream:ssl_accept(Socket),
    io:format("ssl_accept: ~w~n", [Reply]),
    {next_state, running, State};

handshake(activate, State) ->
    io:format("got Activate in handshake~n"),
    {next_state, handshake, State}.

running({activate, _ReqId}, State) ->
    NewState = State#state{eap_state = eradius_eap:new([?EAP_MSCHAPv2])},
    send_request({identity, <<>>}, running, NewState);

running(Data, State = #state{socket = Socket, inner_state = challenge, eap_state = StateEAP})
  when is_binary(Data) ->
%%    {ok, EAP} = eradius_eap_packet:decode(Data),
    case eradius_eap:run(Data, StateEAP) of
	{ReplyType, ReplyAttrs, NewStateEAP} ->
	    Reply = proplists:get_value(?REAP_Message, ReplyAttrs, <<>>),
	    io:format("Tunneled response: ~p~n", [ReplyAttrs]),
	    eradius_ssl_stream:send(Socket, challenge, Reply),
	    {next_state, running, State#state{inner_state = ReplyType, eap_state = NewStateEAP}};
	R ->
	    io:format("unexpected return from RUN: ~w~n", [R]),
	    {next_state, running, State}
    end;

running(Data, State = #state{socket = Socket})
  when is_binary(Data) ->
    {ok, EAP} = eradius_eap_packet:decode(Data),
    {_, ReqId, _} = EAP,
    io:format("inner state finished: ~w, got: ~w~n", [State#state.inner_state, EAP]),
    Reply = eradius_eap_packet:encode(request, ReqId + 1, <<?EAP_TLV:8, 16#80:8, ?EAP_TLV_ACK_RESULT, 2:16/integer, 0, ?EAP_TLV_SUCCESS>>),
    eradius_ssl_stream:send(Socket, challenge, Reply),
    {next_state, tlv_acked, State}.

tlv_acked(Data, State = #state{socket = Socket, eap_state = _StateEAP})
  when is_binary(Data) ->
    {ok, EAP} = eradius_eap_packet:decode(Data),
    io:format("TLV ACK send: ~w, got: ~w~n", [State#state.inner_state, EAP]),
    %% Reply = eradius_eap_packet:encode(request, ReqId + 1, <<?EAP_TLV:8, 16#80:8, ?EAP_TLV_ACK_RESULT, 2:16/integer, 0, ?EAP_TLV_SUCCESS>>),

    PrfLabel = <<"client EAP encryption">>,
    {RecvKey, SendKey} = mppe_keys(PrfLabel, Socket),
    ReplyAttrs = [{?MS_MPPE_Send_Key, SendKey},
		  {?MS_MPPE_Recv_Key, RecvKey}],
    eradius_ssl_stream:finish(Socket, State#state.inner_state, ReplyAttrs),

    %% we need to tell the outer session that we are done
    %%  - send Success, Failure on outer session
    %%  - add RADIUS crypto attributes....
    %% but we also need to keep TLS session information....

    %% Verdict handling might be redundant, we always do an explicit EAP TLV ack, then discard the TLS session, (keep the session state though)
    %% and return Success/Failure on the externl EAP session.....

    {next_state, tlv_acked, State}.

handle_info({ssl, _Socket, Data}, StateName, State) ->
    io:format("got in ~w, got ~w~n", [StateName, Data]),
    ?MODULE:StateName(Data, State);

handle_info(Info, StateName, State) ->
    io:format("got Info ~w in ~w~n", [Info, StateName]),
    {next_state, StateName, State}.

handle_event({reqid, ReqId}, StateName, State) ->
    {next_state, StateName, State#state{reqid = ReqId}}.

handle_sync_event(Event, From, _StateName, State) ->
    {stop, {invalid_sync_event, Event, From}, State}.

terminate(_Reason, _StateName, #state{socket = Socket}) ->
    (catch eradius_ssl_stream:close(Socket)),
    ok.

code_change(_OldVsn, _StateName, State, _Extra) ->
    State.

%% ------------------------------------------------------------------------------------------

send_request(Msg, NextStateName, NextState = #state{socket = Socket, reqid = ReqId}) ->
    EAP = eradius_eap_packet:encode(request, ReqId + 1, Msg),
    io:format("inner PayLoad: ~w~n", [EAP]),
    eradius_ssl_stream:send(Socket, challenge, EAP),
    {next_state, NextStateName, NextState}.

%%
%% Generate keys according to RFC 2716
%%
mppe_keys(PrfLabel, Socket) ->
    #security_parameters{
	   master_secret = MasterSecret,
	   client_random = ClientRandom,
	   server_random = ServerRandom
	  } = eradius_ssl_stream:security_parameters(Socket),

    <<RecvKey:32/bytes, SendKey:32/bytes>> = prf(MasterSecret, PrfLabel, [ClientRandom, ServerRandom], 64),
    {RecvKey, SendKey}.


%%--------------------------------------------------------------------
%% copied from ssl_tls.erl
%%
%% FIXME: the SSL session PRF should be used, it is currently not
%%        exported, but should probably....
%%--------------------------------------------------------------------
-define(NULL, 0).

%%%% HMAC and the Pseudorandom Functions RFC 2246 & 4346 - 5.%%%%
hmac_hash(?NULL, _, _) ->
    <<>>;
hmac_hash(?MD5, Key, Value) ->
    crypto:md5_mac(Key, Value);
hmac_hash(?SHA, Key, Value) ->
    crypto:sha_mac(Key, Value).

% First, we define a data expansion function, P_hash(secret, data) that
% uses a single hash function to expand a secret and seed into an
% arbitrary quantity of output:
%% P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
%%                        HMAC_hash(secret, A(2) + seed) +
%%                        HMAC_hash(secret, A(3) + seed) + ...

p_hash(Secret, Seed, WantedLength, Method) ->
    p_hash(Secret, Seed, WantedLength, Method, 0, []).

p_hash(_Secret, _Seed, WantedLength, _Method, _N, [])
  when WantedLength =< 0 ->
    [];
p_hash(_Secret, _Seed, WantedLength, _Method, _N, [Last | Acc])
  when WantedLength =< 0 ->
    Keep = byte_size(Last) + WantedLength,
    <<B:Keep/binary, _/binary>> = Last,
    lists:reverse(Acc, [B]);
p_hash(Secret, Seed, WantedLength, Method, N, Acc) ->
    N1 = N+1,
    Bin = hmac_hash(Method, Secret, [a(N1, Secret, Seed, Method), Seed]),
    p_hash(Secret, Seed, WantedLength - byte_size(Bin), Method, N1, [Bin|Acc]).

%% ... Where  A(0) = seed
%%            A(i) = HMAC_hash(secret, A(i-1))
%% a(0, _Secret, Seed, _Method) -> 
%%     Seed.
%% a(N, Secret, Seed, Method) ->
%%     hmac_hash(Method, Secret, a(N-1, Secret, Seed, Method)).
a(0, _Secret, Seed, _Method) ->
    Seed;
a(N, Secret, Seed0, Method) ->
    Seed = hmac_hash(Method, Secret, Seed0),
    a(N-1, Secret, Seed, Method).

split_secret(BinSecret) ->
    %% L_S = length in bytes of secret;
    %% L_S1 = L_S2 = ceil(L_S / 2);
    %% The secret is partitioned into two halves (with the possibility of
    %% one shared byte) as described above, S1 taking the first L_S1 bytes,
    %% and S2 the last L_S2 bytes.
    Length = byte_size(BinSecret),
    Div = Length div 2,
    EvenLength = Length - Div,
    <<Secret1:EvenLength/binary, _/binary>> = BinSecret,
    <<_:Div/binary, Secret2:EvenLength/binary>> = BinSecret,
    {Secret1, Secret2}.

prf(Secret, Label, Seed, WantedLength) -> 
    %% PRF(secret, label, seed) = P_MD5(S1, label + seed) XOR
    %%                            P_SHA-1(S2, label + seed);
    {S1, S2} = split_secret(Secret),
    LS = list_to_binary([Label, Seed]),
    crypto:exor(p_hash(S1, LS, WantedLength, ?MD5),
                p_hash(S2, LS, WantedLength, ?SHA)).
    
