%% @doc
%%  This module implements the statitics counter for RADIUS servers and clients

-module(eradius_counter).
-export([init_counter/1, inc_counter/2, dec_counter/2, reset_counter/1, inc_request_counter/2, inc_reply_counter/2, observe/4, observe/5]).

-behaviour(gen_server).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).
-export([start_link/0, reset/0, pull/0, read/0, aggregate/1]).
-export([collect/2]).

-include("eradius_lib.hrl").

-record(state, {
         reset :: erlang:timestamp()
        }).

-type srv_counters() :: [#server_counter{}].
-type nas_counters() :: {erlang:timestamp(), [#nas_counter{}]}.
-type stats() :: {srv_counters(), nas_counters()}.

%% ------------------------------------------------------------------------------------------
%% API
%% @doc initialize a counter structure
init_counter({ServerIP, ServerPort, ServerName}) when is_integer(ServerPort) ->
    #server_counter{key = {ServerIP, ServerPort}, startTime = eradius_lib:timestamp(), resetTime = eradius_lib:timestamp(), server_name = ServerName};
init_counter(#nas_prop{server_ip = ServerIP, server_port = ServerPort, nas_ip = NasIP, nas_id = NasId}) ->
    #nas_counter{key = {{ServerIP, ServerPort}, NasIP, NasId}};
init_counter({{ServerIP, ServerPort}, NasIP})
  when is_tuple(ServerIP), is_integer(ServerPort), is_tuple(NasIP) ->
    #nas_counter{key = {{ServerIP, ServerPort}, NasIP}};
init_counter({{ClientName, ClientIP, ClientPort}, {ServerName, ServerIp, ServerPort}}) ->
    #client_counter{key = {{ClientName, ClientIP, ClientPort}, {ServerName, ServerIp, ServerPort}}, server_name = ServerName}.

%% @doc reset counters
reset_counter(#server_counter{startTime = Up}) -> #server_counter{startTime = Up, resetTime = eradius_lib:timestamp()};
reset_counter(Nas = #nas_prop{}) ->
    init_counter(Nas).

%% @doc increment requests counters
inc_request_counter(Counter, Nas) ->
    inc_counter(Counter, Nas).

%% @doc increment reply counters
inc_reply_counter(Counter, Nas) ->
    inc_counter(Counter, Nas).

%% @doc increment a specific counter value
inc_counter(invalidRequests,  Counters = #server_counter{invalidRequests  = Value}) ->
    Counters#server_counter{invalidRequests  = Value + 1};
inc_counter(discardNoHandler, Counters = #server_counter{discardNoHandler = Value}) ->
    Counters#server_counter{discardNoHandler = Value + 1};
inc_counter(Counter, Nas = #nas_prop{}) ->
    gen_server:cast(?MODULE, {inc_counter, Counter, Nas});
inc_counter(Counter, {{ClientName, ClientIP, ClientPort}, {ServerName, ServerIp, ServerPort}}) ->
    gen_server:cast(?MODULE, {inc_counter, Counter, {{ClientName, ClientIP, ClientPort}, {ServerName, ServerIp, ServerPort}}}).

dec_counter(Counter, Nas = #nas_prop{}) ->
    gen_server:cast(?MODULE, {dec_counter, Counter, Nas});
dec_counter(Counter, {{ClientName, ClientIP, ClientPort}, {ServerName, ServerIp, ServerPort}}) ->
    gen_server:cast(?MODULE, {dec_counter, Counter, {{ClientName, ClientIP, ClientPort}, {ServerName, ServerIp, ServerPort}}}).

%% @doc reset all counters to zero
reset() ->
    gen_server:call(?MODULE, reset).

%% @doc read counters and reset to zero
-spec pull() -> stats().
pull() ->
    gen_server:call(?MODULE, pull).

%% @doc read counters
-spec read() -> stats().
read() ->
    gen_server:call(?MODULE, read).

%% @doc calculate the per server sum of all counters of a per NAS list of counters
-spec aggregate(stats()) -> stats().
aggregate({Servers, {ResetTS, Nass}}) ->
    NSums = lists:foldl(fun(Nas = #nas_counter{key = {ServerId, _}}, Acc) ->
                                orddict:update(ServerId, fun(Value) -> add_counter(Value, Nas) end, Nas#nas_counter{key = ServerId}, Acc)
                        end,
                        orddict:new(), Nass),
    NSum1 = [Value || {_Key, Value} <- orddict:to_list(NSums)],
    {Servers, {ResetTS, NSum1}}.

%% @doc Update the given histogram metric value
%% NOTE: We use prometheus_histogram collector here instead of eradius_counter ets table because
%% it is much easy to use histograms in this way. As we don't need to manage buckets and do
%% the other histogram things in eradius, but prometheus.erl will do it for us
observe(Name, {{ClientName, ClientIP, _}, {ServerName, ServerIP, ServerPort}} = MetricsInfo, Value, Help) ->
    case code:is_loaded(prometheus) of
        true ->
            try
                prometheus_histogram:observe(Name, [ServerIP, ServerPort, ServerName, ClientName, ClientIP], Value)
            catch _:_ ->
                    Buckets = application:get_env(eradius, histogram_buckets, [10, 30, 50, 75, 100, 1000, 2000]),
                    prometheus_histogram:new([{name, Name}, {labels, [server_ip, server_port, server_name, client_name, client_ip]},
                                              {buckets, Buckets}, {help, Help}]),
                    observe(Name, MetricsInfo, Value, Help)
            end;
        _ ->
            ok
    end.
observe(Name, #nas_prop{server_ip = ServerIP, server_port = ServerPort, nas_ip = NasIP, nas_id = NasId} = Nas, Value, ServerName, Help) ->
    case code:is_loaded(prometheus) of
        true ->
            try
                prometheus_histogram:observe(Name, [inet:ntoa(ServerIP), ServerPort, ServerName, inet:ntoa(NasIP), NasId], Value)
            catch _:_ ->
                    Buckets = application:get_env(eradius, histogram_buckets, [10, 30, 50, 75, 100, 1000, 2000]),
                    prometheus_histogram:new([{name, Name}, {labels, [server_ip, server_port, server_name, nas_ip, nas_id]},
                                              {buckets, Buckets}, {help, Help}]),
                    observe(Name, Nas, Value, ServerName, Help)
            end;
        _ ->
            ok
    end.

%% helper to be called from the aggregator to fetch this nodes values
%% @private
collect(Ref, Process) ->
    lists:foreach(fun(Node) -> gen_server:cast({?MODULE, Node}, {collect, Ref, Process}) end,
                  eradius_node_mon:get_module_nodes(?MODULE)).

%% @private
-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

%% ------------------------------------------------------------------------------------------
%% -- gen_server Callbacks
%% @private
init([]) ->
    ets:new(?MODULE, [ordered_set, protected, named_table, {keypos, #nas_counter.key}, {write_concurrency,true}]),
    eradius:modules_ready([?MODULE]),
    {ok, #state{reset = eradius_lib:timestamp()}}.

%% @private
handle_call(pull, _From, State) ->
    NassAndClients = read_stats(State),
    Servers = server_stats(pull),
    ets:delete_all_objects(?MODULE),
    {reply, {Servers, NassAndClients}, State#state{reset = eradius_lib:timestamp()}};
handle_call(read, _From, State) ->
    NassAndClients = read_stats(State),
    Servers = server_stats(read),
    {reply, {Servers, NassAndClients}, State};
handle_call(reset, _From, State) ->
    server_stats(reset),
    ets:delete_all_objects(?MODULE),
    {reply, ok, State#state{reset = eradius_lib:timestamp()}}.

%% @private
handle_cast({inc_counter, Counter, Key = {{_ClientName, _ClientIP, _ClientPort}, {_ServerName, _ServerIp, _ServerPort}}}, State) ->
    Cnt0 = case ets:lookup(?MODULE, Key) of
               [] -> init_counter(Key);
               [Cnt] -> Cnt
    end,
    ets:insert(?MODULE, do_inc_counter(Counter, Cnt0)),
    {noreply, State};

handle_cast({inc_counter, Counter, Nas = #nas_prop{server_ip = ServerIP, server_port = ServerPort, nas_ip = NasIP, nas_id = NasId}}, State) ->
    Key = {{ServerIP, ServerPort}, NasIP, NasId},
    Cnt0 = case ets:lookup(?MODULE, Key) of
               [] -> init_counter(Nas);
               [Cnt] -> Cnt
    end,
    {{ServerName, _, _}, _} = Nas#nas_prop.metrics_info,
    Cnt1 = Cnt0#nas_counter{server_name = ServerName},
    ets:insert(?MODULE, do_inc_counter(Counter, Cnt1)),
    {noreply, State};

handle_cast({dec_counter, Counter, Key = {{_ClientName, _ClientIP, _ClientPort}, {_ServerName, _ServerIp, _ServerPort}}}, State) ->
    Cnt0 = case ets:lookup(?MODULE, Key) of
               [] -> init_counter(Key);
               [Cnt] -> Cnt
    end,
    ets:insert(?MODULE, do_dec_counter(Counter, Cnt0)),
    {noreply, State};

handle_cast({dec_counter, Counter, Nas = #nas_prop{server_ip = ServerIP, server_port = ServerPort, nas_ip = NasIP, nas_id = NasId}}, State) ->
    Key = {{ServerIP, ServerPort}, NasIP, NasId},
    Cnt0 = case ets:lookup(?MODULE, Key) of
               [] -> init_counter(Nas);
               [Cnt] -> Cnt
    end,
    {{ServerName, _, _}, _} = Nas#nas_prop.metrics_info,
    Cnt1 = Cnt0#nas_counter{server_name = ServerName},
    ets:insert(?MODULE, do_dec_counter(Counter, Cnt1)),
    {noreply, State};

handle_cast({collect, Ref, Process}, State) ->
    Process ! {collect, Ref, ets:tab2list(?MODULE)},
    ets:delete_all_objects(?MODULE),
    {noreply, State#state{reset = eradius_lib:timestamp()}};

handle_cast(_Msg, State) ->
    {noreply, State}.

%% -- unused callbacks
%% @private
handle_info(_Info, State)           -> {noreply, State}.
%% @private
code_change(_OldVsn, State, _Extra) -> {ok, State}.
%% @private
terminate(_Reason, _State)           -> ok.

%% ------------------------------------------------------------------------------------------
%% -- helper functions
%% @private

read_stats(State) ->
    {State#state.reset, ets:tab2list(?MODULE)}.

server_stats(Func) ->
    lists:foldl(fun(S, Acc) -> [eradius_server:stats(S, Func)|Acc] end, [], eradius_server_sup:all()).

%% @private
do_inc_counter(requests,                Counters = #nas_counter{requests = Value})                -> Counters#nas_counter{requests = Value + 1};
do_inc_counter(replies,                 Counters = #nas_counter{replies = Value})                 -> Counters#nas_counter{replies = Value + 1};
do_inc_counter(dupRequests,             Counters = #nas_counter{dupRequests = Value})             -> Counters#nas_counter{dupRequests = Value + 1};
do_inc_counter(malformedRequests,       Counters = #nas_counter{malformedRequests = Value})       -> Counters#nas_counter{malformedRequests = Value + 1};
do_inc_counter(accessRequests,          Counters = #nas_counter{accessRequests = Value})          -> Counters#nas_counter{accessRequests = Value + 1};
do_inc_counter(accessAccepts,           Counters = #nas_counter{accessAccepts = Value})           -> Counters#nas_counter{accessAccepts = Value + 1};
do_inc_counter(accessRejects,           Counters = #nas_counter{accessRejects = Value})           -> Counters#nas_counter{accessRejects = Value + 1};
do_inc_counter(accessChallenges,        Counters = #nas_counter{accessChallenges = Value})        -> Counters#nas_counter{accessChallenges = Value + 1};
do_inc_counter(noRecords,               Counters = #nas_counter{noRecords = Value})               -> Counters#nas_counter{noRecords = Value + 1};
do_inc_counter(badAuthenticators,       Counters = #nas_counter{badAuthenticators = Value})       -> Counters#nas_counter{badAuthenticators = Value + 1};
do_inc_counter(packetsDropped,          Counters = #nas_counter{packetsDropped = Value})          -> Counters#nas_counter{packetsDropped = Value + 1};
do_inc_counter(unknownTypes,            Counters = #nas_counter{unknownTypes = Value})            -> Counters#nas_counter{unknownTypes = Value + 1};
do_inc_counter(handlerFailure,          Counters = #nas_counter{handlerFailure = Value})          -> Counters#nas_counter{handlerFailure = Value + 1};
do_inc_counter(coaRequests,             Counters = #nas_counter{coaRequests = Value})             -> Counters#nas_counter{coaRequests = Value + 1};
do_inc_counter(coaAcks,                 Counters = #nas_counter{coaAcks = Value})                 -> Counters#nas_counter{coaAcks = Value + 1};
do_inc_counter(coaNaks,                 Counters = #nas_counter{coaNaks = Value})                 -> Counters#nas_counter{coaNaks = Value + 1};
do_inc_counter(discRequests,            Counters = #nas_counter{discRequests = Value})            -> Counters#nas_counter{discRequests = Value + 1};
do_inc_counter(discAcks,                Counters = #nas_counter{discAcks = Value})                -> Counters#nas_counter{discAcks = Value + 1};
do_inc_counter(discNaks,                Counters = #nas_counter{discNaks = Value})                -> Counters#nas_counter{discNaks = Value + 1};
do_inc_counter(retransmissions,         Counters = #nas_counter{retransmissions = Value})         -> Counters#nas_counter{retransmissions = Value + 1};
do_inc_counter(pending,                 Counters = #nas_counter{pending = Value})                 -> Counters#nas_counter{pending = Value + 1};
do_inc_counter(accountRequestsStart,   Counters = #nas_counter{accountRequestsStart = Value})     -> Counters#nas_counter{accountRequestsStart = Value + 1};
do_inc_counter(accountRequestsStop,    Counters = #nas_counter{accountRequestsStop = Value})      -> Counters#nas_counter{accountRequestsStop = Value + 1};
do_inc_counter(accountRequestsUpdate,  Counters = #nas_counter{accountRequestsUpdate = Value})    -> Counters#nas_counter{accountRequestsUpdate = Value + 1};
do_inc_counter(accountResponsesStart,  Counters = #nas_counter{accountResponsesStart = Value})    -> Counters#nas_counter{accountResponsesStart = Value + 1};
do_inc_counter(accountResponsesStop,   Counters = #nas_counter{accountResponsesStop = Value})     -> Counters#nas_counter{accountResponsesStop = Value + 1};
do_inc_counter(accountResponsesUpdate, Counters = #nas_counter{accountResponsesUpdate = Value})   -> Counters#nas_counter{accountResponsesUpdate = Value + 1};

do_inc_counter(requests,          Counters = #client_counter{requests = Value})          -> Counters#client_counter{requests = Value + 1};
do_inc_counter(replies,           Counters = #client_counter{replies = Value})           -> Counters#client_counter{replies = Value + 1};
do_inc_counter(accessRequests,    Counters = #client_counter{accessRequests = Value})    -> Counters#client_counter{accessRequests = Value + 1};
do_inc_counter(coaRequests,       Counters = #client_counter{coaRequests = Value})       -> Counters#client_counter{coaRequests = Value + 1};
do_inc_counter(discRequests,      Counters = #client_counter{discRequests = Value})      -> Counters#client_counter{discRequests = Value + 1};
do_inc_counter(retransmissions,   Counters = #client_counter{retransmissions = Value})   -> Counters#client_counter{retransmissions = Value + 1};
do_inc_counter(timeouts,          Counters = #client_counter{timeouts = Value})          -> Counters#client_counter{timeouts = Value + 1};
do_inc_counter(accessAccepts,     Counters = #client_counter{accessAccepts = Value})     -> Counters#client_counter{accessAccepts = Value + 1};
do_inc_counter(accessRejects,     Counters = #client_counter{accessRejects = Value})     -> Counters#client_counter{accessRejects = Value + 1};
do_inc_counter(accessChallenges,  Counters = #client_counter{accessChallenges = Value})  -> Counters#client_counter{accessChallenges = Value + 1};
do_inc_counter(coaNaks,           Counters = #client_counter{coaNaks = Value})           -> Counters#client_counter{coaNaks = Value + 1};
do_inc_counter(coaAcks,           Counters = #client_counter{coaAcks = Value})           -> Counters#client_counter{coaAcks = Value + 1};
do_inc_counter(discNaks,          Counters = #client_counter{discNaks = Value})          -> Counters#client_counter{discNaks = Value + 1};
do_inc_counter(discAcks,          Counters = #client_counter{discAcks = Value})          -> Counters#client_counter{discAcks = Value + 1};
do_inc_counter(badAuthenticators, Counters = #client_counter{badAuthenticators = Value}) -> Counters#client_counter{badAuthenticators = Value + 1};
do_inc_counter(packetsDropped,    Counters = #client_counter{packetsDropped = Value})    -> Counters#client_counter{packetsDropped = Value + 1};
do_inc_counter(unknownTypes,      Counters = #client_counter{unknownTypes = Value})      -> Counters#client_counter{unknownTypes = Value + 1};
do_inc_counter(pending,           Counters = #client_counter{pending = Value})           -> Counters#client_counter{pending = Value + 1};
do_inc_counter(accountRequestsStart,   Counters = #client_counter{accountRequestsStart = Value})   -> Counters#client_counter{accountRequestsStart = Value + 1};
do_inc_counter(accountRequestsStop,    Counters = #client_counter{accountRequestsStop = Value})    -> Counters#client_counter{accountRequestsStop = Value + 1};
do_inc_counter(accountRequestsUpdate,  Counters = #client_counter{accountRequestsUpdate = Value})  -> Counters#client_counter{accountRequestsUpdate = Value + 1}; 
do_inc_counter(accountResponsesStart,  Counters = #client_counter{accountResponsesStart = Value})  -> Counters#client_counter{accountResponsesStart = Value + 1};
do_inc_counter(accountResponsesStop,   Counters = #client_counter{accountResponsesStop = Value})   -> Counters#client_counter{accountResponsesStop = Value + 1};
do_inc_counter(accountResponsesUpdate, Counters = #client_counter{accountResponsesUpdate = Value}) -> Counters#client_counter{accountResponsesUpdate = Value + 1}.

%% @private
do_dec_counter(pending, Counters = #nas_counter{pending = Value}) -> Counters#nas_counter{pending = Value - 1};
do_dec_counter(pending, Counters = #client_counter{pending = Value}) -> Counters#client_counter{pending = Value - 1}.

add_counter(Cnt1 = #nas_counter{}, Cnt2 = #nas_counter{}) ->
    #nas_counter{
             key                      = Cnt1#nas_counter.key,
             requests                 = Cnt1#nas_counter.requests                  + Cnt2#nas_counter.requests,
             replies                  = Cnt1#nas_counter.replies                   + Cnt2#nas_counter.replies,
             dupRequests              = Cnt1#nas_counter.dupRequests               + Cnt2#nas_counter.dupRequests,
             malformedRequests        = Cnt1#nas_counter.malformedRequests         + Cnt2#nas_counter.malformedRequests,
             accessRequests           = Cnt1#nas_counter.accessRequests            + Cnt2#nas_counter.accessRequests,
             accessAccepts            = Cnt1#nas_counter.accessAccepts             + Cnt2#nas_counter.accessAccepts,
             accessRejects            = Cnt1#nas_counter.accessRejects             + Cnt2#nas_counter.accessRejects,
             accessChallenges         = Cnt1#nas_counter.accessChallenges          + Cnt2#nas_counter.accessChallenges,
             accountRequestsStart     = Cnt1#nas_counter.accountRequestsStart      + Cnt2#nas_counter.accountRequestsStart,
             accountRequestsStop      = Cnt1#nas_counter.accountRequestsStop       + Cnt2#nas_counter.accountRequestsStop,
             accountRequestsUpdate    = Cnt1#nas_counter.accountRequestsUpdate     + Cnt2#nas_counter.accountRequestsUpdate,
             accountResponsesStart    = Cnt1#nas_counter.accountResponsesStart     + Cnt2#nas_counter.accountResponsesStart,
             accountResponsesStop     = Cnt1#nas_counter.accountResponsesStop      + Cnt2#nas_counter.accountResponsesStop,
             accountResponsesUpdate   = Cnt1#nas_counter.accountResponsesUpdate    + Cnt2#nas_counter.accountResponsesUpdate,
             noRecords                = Cnt1#nas_counter.noRecords                 + Cnt2#nas_counter.noRecords,
             badAuthenticators        = Cnt1#nas_counter.badAuthenticators         + Cnt2#nas_counter.badAuthenticators,
             packetsDropped           = Cnt1#nas_counter.packetsDropped            + Cnt2#nas_counter.packetsDropped,
             unknownTypes             = Cnt1#nas_counter.unknownTypes              + Cnt2#nas_counter.unknownTypes,
             handlerFailure           = Cnt1#nas_counter.handlerFailure            + Cnt2#nas_counter.handlerFailure,
             coaRequests              = Cnt1#nas_counter.coaRequests               + Cnt2#nas_counter.coaRequests,
             coaAcks                  = Cnt1#nas_counter.coaAcks                   + Cnt2#nas_counter.coaAcks,
             coaNaks                  = Cnt1#nas_counter.coaNaks                   + Cnt2#nas_counter.coaNaks,
             discRequests             = Cnt1#nas_counter.discRequests              + Cnt2#nas_counter.discRequests,
             discAcks                 = Cnt1#nas_counter.discAcks                  + Cnt2#nas_counter.discAcks,
             discNaks                 = Cnt1#nas_counter.discNaks                  + Cnt2#nas_counter.discNaks,
             retransmissions          = Cnt1#nas_counter.retransmissions           + Cnt2#nas_counter.retransmissions,
             pending                  = Cnt1#nas_counter.pending                   + Cnt2#nas_counter.pending
      }.
