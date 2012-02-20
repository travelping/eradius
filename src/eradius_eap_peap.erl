-module(eradius_eap_peap).

-export([register/0, unregister/0]).
-export([decode_eap_type/2, encode_eap_type/1]).
-export([chat_init/2, chat_run/3]).

-include("eradius_eap.hrl").

-record(state, {version, last_req, pending, recv_q, tunnel, verdict}).

-define(SSL_TAG, peap).
-define(PEAP_VER, 2).

register() ->
    eradius_eap:register_type({?EAP_PEAP, peap}, ?MODULE).

unregister() ->
    eradius_eap:unregister_type({?EAP_PEAP, peap}).

decode_eap_type(_Id, <<1:1, M:1, S:1, _R:2, Ver:3, Length:32, Data:Length/binary>>) ->
    {peap, M, S, Ver, Length, Data};
decode_eap_type(_Id, <<0:1, M:1, S:1, _R:2, Ver:3, Data/binary>>) ->
    {peap, M, S, Ver, Data}.

encode_eap_type({peap, M, S, Ver, Data}) ->
    <<?EAP_PEAP:8, 0:1, M:1, S:1, 0:2, Ver:3, Data/binary>>;
encode_eap_type({peap, M, S, Ver, Length, Data}) ->
    <<?EAP_PEAP:8, 1:1, M:1, S:1, 0:2, Ver:3, Length:32, Data/binary>>;
encode_eap_type(Msg) ->
    io:format("PEAP Msg (err): ~w~n", [Msg]),
    <<>>.

chat_init(ReqId, _Args) ->
    io:format("Start EAP 25~n"),
    State = init_state(),
    send_response(challenge, ReqId, peap_start(State), [], State).

chat_run(ReqId, Args, State) ->
    process_msg(ReqId, Args, State).

%% ----------------------------------------------------------------------------------------

init_state() ->
    {ok, Tunnel} = eradius_ssl_proxy:start(),
    #state{pending = <<>>, recv_q = [], tunnel = Tunnel, verdict = challenge}.

handle_msg(ReqId, <<>>, State = #state{tunnel = Tunnel}) ->
    case send_more(ReqId, State) of
	done ->
	    %% there is not more data to send and we got an empty response from the peer
	    %% so it's our turn to generate something to send.....
	    eradius_ssl_proxy:activate(Tunnel, ReqId),
	    {Verdict, Msg, ReplyAttrs} = eradius_ssl_proxy:transport_recv(Tunnel),
	    send_msg(ReqId, Msg, ReplyAttrs, State#state{verdict = Verdict});

	Repl ->
	    Repl
    end;

handle_msg(ReqId, Data, State = #state{tunnel = Tunnel}) ->
    eradius_ssl_proxy:transport_send(Tunnel, Data),
    case send_more(ReqId, State) of
	done -> {Verdict, Msg, ReplyAttrs} = eradius_ssl_proxy:transport_recv(Tunnel),
		send_msg(ReqId, Msg, ReplyAttrs, State#state{verdict = Verdict});
	Repl -> Repl
    end.

process_msg(ReqId, _, State = #state{last_req = {ReqId, EAP}}) ->
    %% resend...
    {State, EAP};
process_msg(ReqId, {peap, M, S, Ver, Length, Data}, State) ->
    State0 = process_start(S, State),
    State1 = peap_version(Ver, State0),
    process_msg(ReqId, M, Ver, {Length, Data}, State1);
process_msg(ReqId, {peap, M, S, Ver, Data}, State) ->
    State0 = process_start(S, State),
    State1 = peap_version(Ver, State0),
    process_msg(ReqId, M, Ver, Data, State1).

process_start(_Start = 1, State) ->
    State;
process_start(_Start = 0, State) ->
    State.

process_msg(ReqId, M, _Ver, Data, State) ->
    State0 = State#state{recv_q = [Data|State#state.recv_q]},
    finish_msg(ReqId, M, State0).

finish_msg(ReqId, _More = 1, State) ->
    %% frame ACK
    send_response(challenge, ReqId, peap_frame_ack(State), [], State);
finish_msg(ReqId, _More = 0, State) ->
    PayLoad = lists:foldr(fun({Length, Msg}, Acc) -> {Length, <<Msg/binary, Acc/binary>>};
			     (Msg, Acc)           -> <<Msg/binary, Acc/binary>>
			  end,
			  <<>>, State#state.recv_q),
    NewState = State#state{recv_q = []},
    case PayLoad of
	{Length, Data} when Length == size(Data) ->
	    handle_msg(ReqId, Data, NewState);
	Data when is_binary(Data) ->
	    handle_msg(ReqId, Data, NewState);
	_ ->
	    {error, NewState}
    end.

send_response(accept, ReqId, _Reply, ReplyAttrs, State) ->
    {accept, success, ReqId + 1, <<>>, ReplyAttrs, State};
send_response(reject, ReqId, _Reply, ReplyAttrs, State) ->
    {reject, failure, ReqId + 1, <<>>, ReplyAttrs, State};
send_response(Type, ReqId, Reply, ReplyAttrs, State) ->
    {Type, request, ReqId + 1, Reply, ReplyAttrs, State}.

send_msg(ReqId, Msg, ReplyAttrs, State) when is_list(Msg) ->
    send_msg(ReqId, list_to_binary(lists:flatten(Msg)), ReplyAttrs, State);

send_msg(ReqId, <<First:1024/bytes, Rest/binary>>, ReplyAttrs, State) ->
    send_msg(ReqId, First, Rest, ReplyAttrs, State);
send_msg(ReqId, Data, ReplyAttrs, State) ->
    send_msg(ReqId, Data, <<>>, ReplyAttrs, State).
			    
send_msg(ReqId, Msg, Rest, ReplyAttrs, State) ->
    NewState = State#state{pending = Rest},
    More = get_send_more_and_ack(ReqId, Rest, State),
    Length = case Rest of
		 <<>> -> size(Msg);
		 _    -> size(Msg) + size(Rest)
	     end,
    Ver = peap_version(State),
    Type = response_type(Rest, State),
    send_response(Type, ReqId, {peap, More, 0, Ver, Length, Msg}, ReplyAttrs, NewState).

send_more(_ReqId, _State = #state{pending = <<>>}) ->
    done;
send_more(ReqId, State = #state{pending = <<First:1024/bytes, Rest/binary>>}) ->
    send_more(ReqId, First, Rest, State);
send_more(ReqId, State = #state{pending = Data}) ->
    send_more(ReqId, Data, <<>>, State).

send_more(ReqId, Msg, Rest, State) ->
    NewState = State#state{pending = Rest},
    More = get_send_more_and_ack(ReqId, Rest, State),
    Ver = peap_version(State),
    Type = response_type(Rest, State),
    send_response(Type, ReqId, {peap, More, 0, Ver, Msg}, [], NewState).

peap_version(_State = #state{version = undefined}) ->
    ?PEAP_VER;
peap_version(_State = #state{version = Ver}) ->
    Ver.

peap_version(Ver, State = #state{version = undefined}) ->
    State#state{version = Ver};
peap_version(_Ver, State) ->
    State.

get_send_more_and_ack(_ReqId, <<>>, _State) ->
    0;
get_send_more_and_ack(_, _, _State) ->
    1.

peap_start(State) ->
    Ver = peap_version(State),
    {peap, 0, 1, Ver, <<>>}.

peap_frame_ack(State) ->
    Ver = peap_version(State),
    {peap, 0, 0, Ver, <<>>}.

response_type(<<>>, #state{verdict = Verdict}) ->
    Verdict;
response_type(_, _) ->
    challenge.


    
