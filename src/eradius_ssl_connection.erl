-module(eradius_ssl_connection).

-behaviour(gen_fsm).

%% Called by ssl_connection_sup
-export([start_link/7]). 

%% gen_fsm callbacks
-export([init/1, hello/2, certify/2, cipher/2, connection/2, 
	 abbreviated/2, handle_event/3,
         handle_sync_event/4, handle_info/3, terminate/3, code_change/4]).
-export([send/3, finish/3, transport_recv/1]).

%% SSL callbacks
-export([controlling_process/2, close/1, send/2]).

-record(state, {fsm_state, tunnel, send_q, pending, verdict = challenge}).

transport_recv(Pid) ->
    gen_fsm:sync_send_all_state_event(Pid, transport_recv).

%%--------------------------------------------------------------------
%%-spec send(pid(), term(), iodata()) -> ok | {error, reason()}.
%%
%% Description: Sends data over the ssl connection
%%--------------------------------------------------------------------
send(Pid, Verdict, Data) -> 
    gen_fsm:sync_send_all_state_event(Pid, {eradius_data, Verdict, 
					    %% iolist_to_binary should really
					    %% be called iodata_to_binary()
					    erlang:iolist_to_binary(Data)}, infinity).

finish(Pid, Verdict, ReplyAttrs) ->
    gen_fsm:sync_send_all_state_event(Pid, {eradius_finish, Verdict, ReplyAttrs}).

%%====================================================================
%% ssl_connection_sup API
%%====================================================================

%%--------------------------------------------------------------------
%%-spec start_link(atom(), host(), inet:port_number(), port(), list(), pid(), tuple()) ->
%%    {ok, pid()} | ignore |  {error, reason()}.
%%
%% Description: Creates a gen_fsm process which calls Module:init/1 to
%% initialize. To ensure a synchronized start-up procedure, this function
%% does not return until Module:init/1 has returned.  
%%--------------------------------------------------------------------
start_link(Role, Host, Port, Socket, Options, User, CbInfo) ->
    gen_fsm:start_link(?MODULE, [Role, Host, Port, Socket, Options,
				 User, CbInfo], []).

%%====================================================================
%% gen_fsm callbacks
%%====================================================================
%%--------------------------------------------------------------------
%% these are wrappers to the ssl_connection state callbacks
%%--------------------------------------------------------------------

init(Options) ->
    Result = ssl_connection:init(Options),
    case element(1, Result) of
	ok -> from_fsm(3, Result, #state{send_q = queue:new()});
	_ -> Result
    end.
	    
hello(Event, StateData) ->
    Result = ssl_connection:hello(Event, to_fsm(StateData)),
    from_fsm(3, Result, StateData).

certify(Event, StateData) ->
    Result = ssl_connection:certify(Event, to_fsm(StateData)),
    from_fsm(3, Result, StateData).

cipher(Event, StateData) ->
    Result = ssl_connection:cipher(Event, to_fsm(StateData)),
    from_fsm(3, Result, StateData).

connection(Event, StateData) ->
    Result = ssl_connection:connection(Event, to_fsm(StateData)),
    from_fsm(3, Result, StateData).

abbreviated(Event, StateData) ->
    Result = ssl_connection:abbreviated(Event, to_fsm(StateData)),
    from_fsm(3, Result, StateData).

handle_event(Event, StateName, StateData) ->
    Result = ssl_connection:handle_event(Event, StateName, to_fsm(StateData)),
    from_fsm(3, Result, StateData).

handle_sync_event({eradius_data, Verdict, Data}, From, StateName, StateData) ->
    StateData0 = StateData#state{verdict = Verdict},
    handle_sync_event({application_data, Data}, From, StateName, StateData0);

handle_sync_event({eradius_finish, Verdict, ReplyAttrs}, _From, StateName, StateData = #state{pending = From, send_q = Q}) ->
    gen_fsm:reply(From, {Verdict, queue:to_list(Q), ReplyAttrs}),
    {reply, ok, StateName, StateData#state{send_q = queue:new()}};

handle_sync_event(transport_recv, From, StateName, StateData = #state{send_q = Q, verdict = Verdict}) ->
    case queue:is_empty(Q) of
	true ->
	    {next_state, StateName, StateData#state{pending = From}};
	false ->
	    {reply, {Verdict, queue:to_list(Q), []}, StateName, StateData#state{send_q = queue:new()}}
    end;

handle_sync_event(Event, From, StateName, StateData) ->
    Result = ssl_connection:handle_sync_event(Event, From, StateName, to_fsm(StateData)),
    case element(1, Result) of
	reply -> from_fsm(4, Result, StateData);
	_ ->     from_fsm(3, Result, StateData)
    end.

handle_info({tls, Data}, StateName, StateData = #state{pending = Pending, send_q = Q, verdict = Verdict}) ->
    Q1 = tls_recv_loop(Q, Data),
    StateData0 = case Pending of
		     undefined -> StateData#state{send_q = Q1};
		     From ->      gen_fsm:reply(From, {Verdict, queue:to_list(Q1), []}),
				  StateData#state{send_q = queue:new(), pending = undefined}
		 end,
    {next_state, StateName, StateData0};

handle_info(Info, StateName, StateData) ->
    Result = ssl_connection:handle_info(Info, StateName, to_fsm(StateData)),
    from_fsm(3, Result, StateData).

terminate(Reason, StateName, StateData) ->
    ssl_connection:terminate(Reason, StateName, to_fsm(StateData)).

code_change(OldVsn, StateName, StateData, Extra) ->
    Result = ssl_connection:code_change(OldVsn, StateName, to_fsm(StateData), Extra),
    from_fsm(3, Result, StateData).

%% helper
to_fsm(#state{fsm_state = State}) ->
    State.
from_fsm(Field, FsmReturn, MyState) ->
    MyNewState = MyState#state{fsm_state = element(Field, FsmReturn)},
    setelement(Field, FsmReturn, MyNewState).

tls_recv_loop(Q, Msg) ->
    Q1 = queue:in(Msg, Q),
    receive
	{tls, MoreData} -> tls_recv_loop(Q1, MoreData)
    after
	0 ->
	    Q1
    end.

%% ssl support functions
controlling_process(_HandlerState, _Pid) ->
    ok.
close(_HandlerState) ->
    ok.
send(_HandlerState, Data) ->
    self() ! {tls, Data}.
