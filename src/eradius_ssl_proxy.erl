-module(eradius_ssl_proxy).
-behavior(gen_server).

-export([start/0, transport_recv/1, transport_send/2, activate/2, reqid/1, verdict/2, finish/3]).
-export([init/1, handle_cast/2, handle_call/3, handle_info/2]).

%% SSL callbacks
-export([controlling_process/2, close/1, send/2, flush/1]).

-record(state, {state = init, socket, tunnel, reqid, verdict, msg, send_q, pending}).

start() ->
    gen_server:start(?MODULE, [], []).

transport_recv(Proxy) ->
    gen_server:call(Proxy, transport_recv).

transport_send(Proxy, Data) ->
    gen_server:call(Proxy, {transport_send, Data}).

activate(Proxy, ReqId) ->
    gen_server:call(Proxy, {activate, ReqId}).

verdict(Proxy, Type) ->
    gen_server:call(Proxy, {verdict, Type}).

finish(Proxy, Verdict, ReplyAttrs) ->
    gen_server:call(Proxy, {finish, Verdict, ReplyAttrs}).
    
reqid(Proxy) ->
    gen_server:call(Proxy, reqid).

%% ------------------------------------------------------------------------------------------
%% -- gen_server Callbacks
%% @private
init([]) ->
    {ok, Socket} = eradius_ssl_stream:transport_create(self(), {?MODULE, tcp, tcp_closed, tcp_error},
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
    {ok, Tunnel} = eradius_ssl_tunnel:start(self(), Socket),
    eradius_ssl_stream:controlling_process(Socket, Tunnel),
    eradius_ssl_tunnel:accept(Tunnel),

    {ok, #state{socket = Socket, tunnel = Tunnel, verdict = challenge, msg = [], send_q = queue:new()}}.

handle_call(reqid, _From, State) ->
    {reply, State#state.reqid, State};

handle_call({verdict, Type}, _From, State) ->
    {reply, ok, State#state{verdict = Type}};

handle_call({finish, Verdict, ReplyAttrs}, _From, State = #state{pending = From}) ->
    gen_server:reply(From, {Verdict, <<>>, ReplyAttrs}),
    {reply, ok, State};

handle_call({transport_send, Data}, _From, State = #state{socket = Socket}) ->
    Result = eradius_ssl_stream:transport_recv(Socket, Data),
    {reply, Result, State};

handle_call({activate, ReqId}, _From, State = #state{tunnel = Tunnel}) ->
    io:format("Activate: ~w~n", [ReqId]),
    eradius_ssl_tunnel:activate(Tunnel, ReqId),
    {reply, ok, State#state{reqid = ReqId}};

handle_call(transport_recv, From, State = #state{msg = []}) ->
    io:format("Waiting for Data from SSL~n"),
    {noreply, State#state{pending = From}};
handle_call(transport_recv, _From, State = #state{verdict = Verdict, msg = Msg}) ->
    {reply, {Verdict, Msg, []}, State#state{msg = []}};

handle_call({tls, Data}, _From, State = #state{send_q = Q}) ->
    {reply, ok, State#state{send_q = queue:in(Data, Q)}};
handle_call(tls_flush, _From, State = #state{verdict = Verdict, msg = Msg, send_q = Q, pending = Pending}) ->
    Msg0 = Msg ++ queue:to_list(Q),
    State0 = case Pending of
		 undefined -> State#state{msg = Msg0};
		 From ->      gen_server:reply(From, {Verdict, Msg0, []}),
			      State#state{msg = [], pending = undefined}
	     end,
    {reply, ok, State0#state{send_q = queue:new()}};

handle_call(_Request, _From, Socket) ->
    {reply, ok, Socket}.

handle_cast(_Request, Socket) ->
    {reply, ok, Socket}.

handle_info(Info, Socket) ->
    io:format("got Info: ~p~n", [Info]),
    {noreply, Socket}.


%% ssl support functions
controlling_process(_HandlerState, _Pid) ->
    ok.
close(_HandlerState) ->
    ok.
send(HandlerState, Data) ->
    gen_server:call(HandlerState, {tls, Data}).

flush(HandlerState) ->
    gen_server:call(HandlerState, tls_flush).
