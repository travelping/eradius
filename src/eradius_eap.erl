%    __                        __      _
%   / /__________ __   _____  / /___  (_)___  ____ _
%  / __/ ___/ __ `/ | / / _ \/ / __ \/ / __ \/ __ `/
% / /_/ /  / /_/ /| |/ /  __/ / /_/ / / / / / /_/ /
% \__/_/   \__,_/ |___/\___/_/ .___/_/_/ /_/\__, /
%                           /_/            /____/
%
% Copyright (c) Travelping GmbH <info@travelping.com>

-module(eradius_eap).
-export([start/0, lookup_type/1, register_type/2, unregister_type/1]).
-export([new/1, run/2]).

%% -- gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-behaviour(gen_server).

-include_lib("eradius_lib.hrl").
-include_lib("eradius_eap.hrl").

-record(eap_state, {step, methods, identity, current, last_reqid, last_reply, mod_state}).
-define(NAME, ?MODULE).

%% ------------------------------------------------------------------------------------------
%% -- API
start() ->
    gen_server:start({local, ?NAME}, ?MODULE, [], []).

%% @doc lookup the handler module for an extended EAP type
lookup_type(TypeOrTag) ->
    case ets:lookup(?NAME, TypeOrTag) of
	[{_, Module}] -> Module;
	_             -> undefined
    end.

%% @doc register the handler module for an extended EAP type
register_type({Type, Tag}, Module) when is_integer(Type), is_atom(Tag) ->
    gen_server:call(?NAME, {register, Type, Tag, Module}).

%% @doc unregister the handler module for an extended EAP type
unregister_type({Type, Tag}) when is_integer(Type), is_atom(Tag) ->
    gen_server:call(?NAME, {unregister, Type, Tag}).

%% ------------------------------------------------------------------------------------------
%% -- gen_server callbacks
%% @private
init([]) ->
    Table = ets:new(?NAME, [ordered_set, protected, named_table, {read_concurrency, true}]),
    {ok, Table}.

%% @private
handle_call({register, Type, Tag, Module}, _From, Table) ->
    ets:insert(Table, {Type, Module}),
    ets:insert(Table, {Tag, Module}),
    {reply, ok, Table};

handle_call({unregister, Type, Tag}, _From, Table) ->
    ets:delete(Type, Table),
    ets:delete(Tag, Table),
    {reply, ok, Table}.

%% @private
handle_cast(_Request, State) -> {noreply, State}.
%% @private
handle_info(_Info, State) -> {noreply, State}.
%% @private
terminate(_Reason, _State) -> ok.
%% @private
code_change(_OldVsn, State, _Extra) -> {ok, State}.

%% ------------------------------------------------------------------------------------------
%% process logic

new(Methods) ->
    #eap_state{step = new, methods = Methods}.
    
run(Data, State = #eap_state{}) ->
    try
	{ok, Msg} = eradius_eap_packet:decode(Data),
	case process_resend(Msg, State) of
	    {ReplyType, EAPType, ReplyId, Reply, ReplyAttrs, NewState} ->
		io:format("EAP reply: ~w ~p~n", [ReplyType, {EAPType, ReplyId, Reply}]),
		EAP = eradius_eap_packet:encode(EAPType, ReplyId, Reply),
		eap_reply(ReplyType, EAP, ReplyAttrs, NewState);
	    {reply, ReplyAttrs, NewState} ->
		{reject, ReplyAttrs, NewState};

	    {reject, ReplyAttrs, NewState} ->
		{reject, ReplyAttrs, NewState}
	end
    catch
	Error ->
	    io:format("got Error: ~w~n", [Error]),
	    {reject, <<"unexpected error">>, State}
    end.

eap_reply(ReplyType, EAP, ReplyAttrs, State) ->
    {ReplyType, [{?REAP_Message, EAP}|ReplyAttrs], State#eap_state{last_reply = EAP}}.

%% FIXME: the resend mechanism is broken at the moment
process_resend({_, ReqId, _}, State = #eap_state{last_reqid = ReqId, last_reply = EAP}) ->
    {reply, EAP, State};
process_resend(EAP = {_, ReqId, _}, State) ->
    process(EAP, State#eap_state{last_reqid = ReqId, last_reply = undefined}).

process(EAP = {response, _ReqId, {identity, Identity}}, State = #eap_state{step = new}) ->
    process(EAP, State#eap_state{step = init, identity = Identity});

process({response, ReqId, Request}, State = #eap_state{step = init, methods = [First|Methods]}) ->
    NewState = State#eap_state{step = run, methods = Methods, current = First},
    case First of
	md5_challenge ->
	    Challenge =  crypto:rand_bytes(16),
	    {challenge, request, ReqId + 1, {md5_challenge, Challenge, <<>>}, [], NewState#eap_state{mod_state = Challenge}};

	ms_chap_v2 ->
	    {challenge, request, ReqId + 1, <<>>, [], NewState};

	?EAP_PEAP ->
	    {ReplyType, EAPType, ReplyReqId, Reply, ReplyAttrs, ModState} = eradius_eap_peap:chat_init(ReqId, Request),
	    {ReplyType, EAPType, ReplyReqId, Reply, ReplyAttrs, NewState#eap_state{mod_state = ModState}};

	?EAP_MSCHAPv2 ->
	    {ReplyType, EAPType, ReplyReqId, Reply, ReplyAttrs, ModState} = eradius_eap_mschapv2:chat_init(ReqId, Request),
	    {ReplyType, EAPType, ReplyReqId, Reply, ReplyAttrs, NewState#eap_state{mod_state = ModState}}
    end;

process(EAP = {response, _ReqId, {nak, SupportedMethods}}, State = #eap_state{step = run, methods = Methods}) ->
    MethsToTry = lists:filter(fun(M) -> lists:member(M , Methods) end, SupportedMethods),
    io:format("NAK: Methods left: ~w, (~w)~n", [MethsToTry, Methods]),
    case MethsToTry of
	[] -> {reject, <<"no nore EAP methods">>, State};
	[_NextMeth|_] ->
	    process(EAP, State#eap_state{step = init, methods = MethsToTry})
    end;

process({response, ReqId, Request}, State = #eap_state{step = run, current = Current}) ->
    io:format("run_eap: ~w~n", [Current]),
    case Current of
	md5_challenge ->
	    Hash = crypto:md5([ReqId, <<"as">>, State#eap_state.mod_state]),
	    case Request of
		{md5_challenge, Hash, _TheirName} ->
		    io:format("MD5 response ok~n"),
		    {accept, success, ReqId + 1, <<>>, [], State};

		{md5_challenge, TheirHash, _TheirName} ->
		    io:format("MD5 response:~nWant: ~w~n, Got:  ~w~n", [Hash, TheirHash]),
		    {reject, failure, ReqId + 1, <<>>, [{?RReply_Msg, <<"MD5 failure">>}], State};

		_ ->
		    {reject, [{?RReply_Msg, <<"invalid MD5 response">>}], State}
	    end;

	ms_chap_v2 ->
            {reject, [{?RReply_Msg, <<"ms_chap_v2 not impl.">>}], State};

	?EAP_PEAP ->
	    {ReplyType, EAPType, ReplyId, Reply, ReplyAttrs, ModState} = eradius_eap_peap:chat_run(ReqId, Request, State#eap_state.mod_state),
	    {ReplyType, EAPType, ReplyId, Reply, ReplyAttrs, State#eap_state{mod_state = ModState}};

	?EAP_MSCHAPv2 ->
	    {ReplyType, EAPType, ReplyId, Reply, ReplyAttrs, ModState} = eradius_eap_mschapv2:chat_run(ReqId, Request, State#eap_state.mod_state),
	    {ReplyType, EAPType, ReplyId, Reply, ReplyAttrs, State#eap_state{mod_state = ModState}}
    end;

process(EAP, State) ->
    io:format("invalid EAP message: ~w~nState: ~w~n", [EAP, State]),
    {reject, [{?RReply_Msg, <<"invalid EAP message">>}], State}.
