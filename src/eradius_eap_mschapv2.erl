-module(eradius_eap_mschapv2).

-export([register/0, unregister/0]).
-export([decode_eap_type/2, encode_eap_type/1]).
-export([chat_init/2, chat_run/3]).

-include("eradius_eap.hrl").

-record(state, {challenge, keys}).

-define(EAP_TAG, mschapv2).

register() ->
    eradius_eap:register_type({?EAP_MSCHAPv2, ?EAP_TAG}, ?MODULE).

unregister() ->
    eradius_eap:unregister_type({?EAP_MSCHAPv2, ?EAP_TAG}).

decode_eap_type(_Id, Msg = <<1:8, ReqId:8, Length:16, CSize:8, Challenge:CSize/bytes, Name/binary>>)
  when Length == size(Msg) ->
    {?EAP_TAG, challenge, ReqId, Challenge, Name};

decode_eap_type(_Id, Msg = <<2:8, ReqId:8, Length:16, CSize:8, Response:CSize/bytes, Name/binary>>)
  when Length == size(Msg) ->
    <<PeerChallenge:16/bytes, _Res1:8/bytes, NTResponse:24/bytes, Flag:8>> = Response,
    {?EAP_TAG, response, ReqId, PeerChallenge, NTResponse, Flag, Name};

decode_eap_type(_Id, Msg = <<3:8, ReqId:8, Length:16, Message/binary>>)
  when Length == size(Msg) ->
    {?EAP_TAG, success, ReqId, Message};
decode_eap_type(_Id, <<3:8>>) ->
    {?EAP_TAG, success};

decode_eap_type(_Id, Msg = <<4:8, ReqId:8, Length:16, Message/binary>>)
  when Length == size(Msg) ->
    {?EAP_TAG, failure, ReqId, Message};
decode_eap_type(_Id, <<4:8>>) ->
    {?EAP_TAG, failure};

decode_eap_type(_Id, Msg = <<7:8,  ReqId:8, Length:16, EncPassword:516/bytes,
			     EncHash:16/bytes, PeerChallenge:16/bytes, _Res1:8/bytes,
			     NTResponse:24/bytes, Flag:16>>)
  when Length == size(Msg) ->
    {?EAP_TAG, response, ReqId, EncPassword, EncHash, PeerChallenge, NTResponse, Flag}.

encode_eap_type({?EAP_TAG, challenge, ReqId, Challenge, Name}) ->
    CSize = size(Challenge),
    Length = 4 + 1 + CSize + size(Name),
    <<?EAP_MSCHAPv2:8, 1:8, ReqId:8, Length:16, CSize:8, Challenge:CSize/bytes, Name/binary>>;

encode_eap_type({?EAP_TAG, response, ReqId, PeerChallenge, NTResponse, Flag, Name}) ->
    Length = 4 + 1 + 49 + size(Name),
    <<?EAP_MSCHAPv2:8, 2:8, ReqId:8, Length:16, 49:8/integer, PeerChallenge:16/bytes, 0:64, NTResponse:24/bytes, Flag:8, Name/binary>>;

encode_eap_type({?EAP_TAG, success, ReqId, Message}) ->
    Length = 4 + size(Message),
    <<?EAP_MSCHAPv2:8, 3:8, ReqId:8, Length:16, Message/binary>>;
encode_eap_type({?EAP_TAG, success}) ->
    <<?EAP_MSCHAPv2:8, 3:8>>;

encode_eap_type({?EAP_TAG, failure, ReqId, Message}) ->
    Length = 4 + size(Message),
    <<?EAP_MSCHAPv2:8, 4:8, ReqId:8, Length:16, Message/binary>>;
encode_eap_type({?EAP_TAG, failure}) ->
    <<?EAP_MSCHAPv2:8, 4:8>>;

encode_eap_type({?EAP_TAG, response, ReqId, EncPassword, EncHash, PeerChallenge, NTResponse, Flag}) ->
    <<?EAP_MSCHAPv2:8, 7:8,  ReqId:8, 591:16, EncPassword:516/bytes, EncHash:16/bytes,
      PeerChallenge:16/bytes, 0:64, NTResponse:24/bytes, Flag:16>>.

chat_init(ReqId, _Args) ->
    io:format("Start EAP 26 (MS-CHAP-v2~n"),
    State = init_state(),
    send_response(challenge, ReqId, {?EAP_TAG, challenge, ReqId + 1, State#state.challenge, <<"as">>}, [], State).

chat_run(ReqId, {?EAP_TAG, response, ChapReqId, PeerChallenge, NTResponse, Flag, Name}, State) ->
    Passwd = <<"as">>,
    case eradius_auth:eap_ms_chap_v2(Name, Passwd, State#state.challenge, PeerChallenge, NTResponse, Flag) of
	false ->
	    send_response(reject, ReqId, {?EAP_TAG, failure, ChapReqId + 1, <<"E=691 R=1 C=00000000000000000000000000000000 V=3 M=Failure">>}, [], State);
	{AuthResponse, Keys} ->
	    %% TODO: add MS-CHAP-Keys????
	    send_response(accept, ReqId, {?EAP_TAG, success, ChapReqId + 1, AuthResponse}, [], State#state{keys = Keys})
    end;

chat_run(_ReqId, Args, _State) ->
    io:format("EAP MS-CHAP-v2 got: ~w~n", [Args]),
    ok.

%% ----------------------------------------------------------------------------------------

init_state() ->
    #state{challenge = crypto:rand_bytes(16)}.

send_response(Type, ReqId, Reply, ReplyAttrs, State) ->
    {Type, request, ReqId + 1, Reply, ReplyAttrs, State}.
