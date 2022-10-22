%% @doc
%%  This module implements the statitics counter for RADIUS servers and clients

-module(eradius_counter).
-export([init_counter/1, init_counter/2, inc_counter/2, dec_counter/2, reset_counter/1, reset_counter/2,
         inc_request_counter/2, inc_reply_counter/2, observe/4, observe/5,
         set_boolean_metric/3]).

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
init_counter({{ClientName, ClientIP, ClientPort}, {ServerName, ServerIp, ServerPort}}) ->
    #client_counter{key = {{ClientName, ClientIP, ClientPort}, {ServerName, ServerIp, ServerPort}}, server_name = ServerName}.
init_counter(#nas_prop{server_ip = ServerIP, server_port = ServerPort, nas_ip = NasIP, nas_id = NasId}, ServerName) ->
    #nas_counter{key = {{ServerIP, ServerPort}, NasIP, NasId}, server_name = ServerName}.

%% @doc reset counters
reset_counter(#server_counter{startTime = Up}) -> #server_counter{startTime = Up, resetTime = eradius_lib:timestamp()}.
reset_counter(Nas = #nas_prop{}, ServerName) ->
    init_counter(Nas, ServerName).

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

%% @doc Set Value for the given prometheus boolean metric by the given Name with
%% the given values
set_boolean_metric(Name, Labels, Value) ->
    case code:is_loaded(prometheus) of
        {file, _} ->
            try
                prometheus_boolean:set(Name, Labels, Value)
            catch _:_ ->
                prometheus_boolean:declare([{name, server_status}, {labels, [server_ip, server_port]},
                                            {help, "Status of an upstream RADIUS Server"}]),
                prometheus_boolean:set(Name, Labels, Value)
            end;
        _ ->
            ok
    end.

%% @doc Update the given histogram metric value
%% NOTE: We use prometheus_histogram collector here instead of eradius_counter ets table because
%% it is much easy to use histograms in this way. As we don't need to manage buckets and do
%% the other histogram things in eradius, but prometheus.erl will do it for us
observe(Name, {{ClientName, ClientIP, _}, {ServerName, ServerIP, ServerPort}} = MetricsInfo, Value, Help) ->
    case code:is_loaded(prometheus) of
        {file, _} ->
            try
                prometheus_histogram:observe(Name, [ServerIP, ServerPort, ServerName, ClientName, ClientIP], Value)
            catch _:_ ->
                    Buckets = application:get_env(eradius, histogram_buckets, [10, 30, 50, 75, 100, 1000, 2000]),
                    prometheus_histogram:declare([{name, Name}, {labels, [server_ip, server_port, server_name, client_name, client_ip]},
                                                  {duration_unit, milliseconds},
                                                  {buckets, Buckets}, {help, Help}]),
                    observe(Name, MetricsInfo, Value, Help)
            end;
        _ ->
            ok
    end.
observe(Name, #nas_prop{server_ip = ServerIP, server_port = ServerPort, nas_ip = NasIP, nas_id = NasId} = Nas, Value, ServerName, Help) ->
    case code:is_loaded(prometheus) of
        {file, _} ->
            try
                prometheus_histogram:observe(Name, [inet:ntoa(ServerIP), ServerPort, ServerName, inet:ntoa(NasIP), NasId], Value)
            catch _:_ ->
                    Buckets = application:get_env(eradius, histogram_buckets, [10, 30, 50, 75, 100, 1000, 2000]),
                    prometheus_histogram:declare([{name, Name}, {labels, [server_ip, server_port, server_name, nas_ip, nas_id]},
                                                  {duration_unit, milliseconds},
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
    ets:update_counter(?MODULE, Key, {counter_idx(Counter, client), 1}, init_counter(Key)),
    {noreply, State};

handle_cast({inc_counter, Counter, Nas = #nas_prop{server_ip = ServerIP, server_port = ServerPort, nas_ip = NasIP, nas_id = NasId}}, State) ->
    Key = {{ServerIP, ServerPort}, NasIP, NasId},
    {{ServerName, _, _}, _} = Nas#nas_prop.metrics_info,
    ets:update_counter(?MODULE, Key, {counter_idx(Counter, nas), 1}, init_counter(Nas, ServerName)),
    {noreply, State};

handle_cast({dec_counter, Counter, Key = {{_ClientName, _ClientIP, _ClientPort}, {_ServerName, _ServerIp, _ServerPort}}}, State) ->
    ets:update_counter(?MODULE, Key, {counter_idx(Counter, client), -1}, init_counter(Key)),
    {noreply, State};

handle_cast({dec_counter, Counter, Nas = #nas_prop{server_ip = ServerIP, server_port = ServerPort, nas_ip = NasIP, nas_id = NasId}}, State) ->
    Key = {{ServerIP, ServerPort}, NasIP, NasId},
    {{ServerName, _, _}, _} = Nas#nas_prop.metrics_info,
    ets:update_counter(?MODULE, Key, {counter_idx(Counter, nas), -1}, init_counter(Nas, ServerName)),
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
counter_idx(requests, nas) ->               #nas_counter.requests;
counter_idx(replies, nas) ->                #nas_counter.replies;
counter_idx(dupRequests, nas) ->            #nas_counter.dupRequests;
counter_idx(malformedRequests, nas) ->      #nas_counter.malformedRequests;
counter_idx(accessRequests, nas) ->         #nas_counter.accessRequests;
counter_idx(accessAccepts, nas) ->          #nas_counter.accessAccepts;
counter_idx(accessRejects, nas) ->          #nas_counter.accessRejects;
counter_idx(accessChallenges, nas) ->       #nas_counter.accessChallenges;
counter_idx(badAuthenticators, nas) ->      #nas_counter.badAuthenticators;
counter_idx(packetsDropped, nas) ->         #nas_counter.packetsDropped;
counter_idx(unknownTypes, nas) ->           #nas_counter.unknownTypes;
counter_idx(handlerFailure, nas) ->         #nas_counter.handlerFailure;
counter_idx(coaRequests, nas) ->            #nas_counter.coaRequests;
counter_idx(coaAcks, nas) ->                #nas_counter.coaAcks;
counter_idx(coaNaks, nas) ->                #nas_counter.coaNaks;
counter_idx(discRequests, nas) ->           #nas_counter.discRequests;
counter_idx(discAcks, nas) ->               #nas_counter.discAcks;
counter_idx(discNaks, nas) ->               #nas_counter.discNaks;
counter_idx(retransmissions, nas) ->        #nas_counter.retransmissions;
counter_idx(pending, nas) ->                #nas_counter.pending;
counter_idx(accountRequestsStart, nas) ->   #nas_counter.accountRequestsStart;
counter_idx(accountRequestsStop, nas) ->    #nas_counter.accountRequestsStop;
counter_idx(accountRequestsUpdate, nas) ->  #nas_counter.accountRequestsUpdate;
counter_idx(accountResponsesStart, nas) ->  #nas_counter.accountResponsesStart;
counter_idx(accountResponsesStop, nas) ->   #nas_counter.accountResponsesStop;
counter_idx(accountResponsesUpdate, nas) -> #nas_counter.accountResponsesUpdate;

counter_idx(requests, client) ->               #client_counter.requests;
counter_idx(replies, client) ->                #client_counter.replies;
counter_idx(accessRequests, client) ->         #client_counter.accessRequests;
counter_idx(coaRequests, client) ->            #client_counter.coaRequests;
counter_idx(discRequests, client) ->           #client_counter.discRequests;
counter_idx(retransmissions, client) ->        #client_counter.retransmissions;
counter_idx(accessAccepts, client) ->          #client_counter.accessAccepts;
counter_idx(accessRejects, client) ->          #client_counter.accessRejects;
counter_idx(accessChallenges, client) ->       #client_counter.accessChallenges;
counter_idx(coaNaks, client) ->                #client_counter.coaNaks;
counter_idx(coaAcks, client) ->                #client_counter.coaAcks;
counter_idx(discNaks, client) ->               #client_counter.discNaks;
counter_idx(discAcks, client) ->               #client_counter.discAcks;
counter_idx(badAuthenticators, client) ->      #client_counter.badAuthenticators;
counter_idx(packetsDropped, client) ->         #client_counter.packetsDropped;
counter_idx(unknownTypes, client) ->           #client_counter.unknownTypes;
counter_idx(pending, client) ->                #client_counter.pending;
counter_idx(timeouts, client) ->               #client_counter.timeouts;
counter_idx(accountRequestsStart, client) ->   #client_counter.accountRequestsStart;
counter_idx(accountRequestsStop, client) ->    #client_counter.accountRequestsStop;
counter_idx(accountRequestsUpdate, client) ->  #client_counter.accountRequestsUpdate;
counter_idx(accountResponsesStart, client) ->  #client_counter.accountResponsesStart;
counter_idx(accountResponsesStop, client) ->   #client_counter.accountResponsesStop;
counter_idx(accountResponsesUpdate, client) -> #client_counter.accountResponsesUpdate.

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
