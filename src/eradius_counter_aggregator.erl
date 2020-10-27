-module(eradius_counter_aggregator).

-behaviour(gen_server).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).
-export([start_link/0, reset/0, pull/0, read/0]).

-include("eradius_lib.hrl").

-define(INIT_HB, 1000).
-define(INTERVAL_HB, 5000).

-record(state, {
          me    :: reference(),
          reset :: erlang:timestamp()
        }).

%% @doc reset all counters to zero
reset() ->
    gen_server:call(?MODULE, reset).
%% @doc read counters and reset to zero
-spec pull() -> eradius_counter:stats().
pull() ->
    gen_server:call(?MODULE, pull).
%% @doc read counters
-spec read() -> eradius_counter:stats().
read() ->
    gen_server:call(?MODULE, read).

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
    EnableAggregator = application:get_env(eradius, counter_aggregator, true),
    if EnableAggregator == true ->
            erlang:send_after(?INIT_HB, self(), heartbeat);
       true ->
            ok
    end,
    {ok, #state{me = make_ref(), reset = eradius_lib:timestamp()}}.

%% @private
handle_call(pull, _From, State) ->
    Nass = read_stats(State),
    Servers = server_stats(pull),
    ets:delete_all_objects(?MODULE),
    {reply, {Servers, Nass}, State#state{reset = eradius_lib:timestamp()}};
handle_call(read, _From, State) ->
    Nass = read_stats(State),
    Servers = server_stats(read),
    {reply, {Servers, Nass}, State};
handle_call(reset, _From, State) ->
    server_stats(reset),
    ets:delete_all_objects(?MODULE),
    {reply, ok, State#state{reset = eradius_lib:timestamp()}}.

%% @private
handle_info(heartbeat, State) ->
    eradius_counter:collect(State#state.me, self()),
    erlang:send_after(?INTERVAL_HB, self(), heartbeat),
    {noreply, State};
handle_info({collect, Ref, Stats}, State = #state{me = Ref}) ->
    lists:foreach(fun update_stats/1, Stats),
    {noreply, State};
handle_info({collect, Ref, Stats}, State) ->
    io:format("invalid stats answer: ~p~n", [{collect, Ref, Stats}]),
    {noreply, State}.

%% -- unused callbacks
%% @private
handle_cast(_Msg, State)            -> {noreply, State}.
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

update_stats(Rec = #nas_counter{key = Key}) ->
    Cnt0 = case ets:lookup(?MODULE, Key) of
               [] -> #nas_counter{key = Key};
               [Cnt] -> Cnt
    end,
    ets:insert(?MODULE, add_counter(Cnt0, Rec));
update_stats(Rec = #client_counter{key = Key}) ->
    Cnt0 = case ets:lookup(?MODULE, Key) of
               [] -> #client_counter{key = Key};
               [Cnt] -> Cnt
    end,
    ets:insert(?MODULE, add_counter(Cnt0, Rec)).

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
             discNaks                 = Cnt1#nas_counter.discNaks                  + Cnt2#nas_counter.discNaks
      };
add_counter(Cnt1 = #client_counter{}, Cnt2 = #client_counter{}) ->
    #client_counter{
             key                      = Cnt1#client_counter.key,
             requests                 = Cnt1#client_counter.requests               + Cnt2#client_counter.requests,
             replies                  = Cnt1#client_counter.replies                + Cnt2#client_counter.replies,
             accessRequests           = Cnt1#client_counter.accessRequests         + Cnt2#client_counter.accessRequests,
             accessAccepts            = Cnt1#client_counter.accessAccepts          + Cnt2#client_counter.accessAccepts,
             accessRejects            = Cnt1#client_counter.accessRejects          + Cnt2#client_counter.accessRejects,
             accessChallenges         = Cnt1#client_counter.accessChallenges       + Cnt2#client_counter.accessChallenges,
             accountRequestsStart     = Cnt1#client_counter.accountRequestsStart   + Cnt2#client_counter.accountRequestsStart,
             accountRequestsStop      = Cnt1#client_counter.accountRequestsStop    + Cnt2#client_counter.accountRequestsStop,
             accountRequestsUpdate    = Cnt1#client_counter.accountRequestsUpdate  + Cnt2#client_counter.accountRequestsUpdate,
             accountResponsesStart    = Cnt1#client_counter.accountResponsesStart  + Cnt2#client_counter.accountResponsesStart,
             accountResponsesStop     = Cnt1#client_counter.accountResponsesStop   + Cnt2#client_counter.accountResponsesStop,
             accountResponsesUpdate   = Cnt1#client_counter.accountResponsesUpdate + Cnt2#client_counter.accountResponsesUpdate,
             badAuthenticators        = Cnt1#client_counter.badAuthenticators      + Cnt2#client_counter.badAuthenticators,
             packetsDropped           = Cnt1#client_counter.packetsDropped         + Cnt2#client_counter.packetsDropped,
             unknownTypes             = Cnt1#client_counter.unknownTypes           + Cnt2#client_counter.unknownTypes,
             coaRequests              = Cnt1#client_counter.coaRequests            + Cnt2#client_counter.coaRequests,
             coaAcks                  = Cnt1#client_counter.coaAcks                + Cnt2#client_counter.coaAcks,
             coaNaks                  = Cnt1#client_counter.coaNaks                + Cnt2#client_counter.coaNaks,
             discRequests             = Cnt1#client_counter.discRequests           + Cnt2#client_counter.discRequests,
             discAcks                 = Cnt1#client_counter.discAcks               + Cnt2#client_counter.discAcks,
             discNaks                 = Cnt1#client_counter.discNaks               + Cnt2#client_counter.discNaks,
             retransmissions          = Cnt1#client_counter.retransmissions        + Cnt2#client_counter.retransmissions,
             timeouts                 = Cnt1#client_counter.timeouts               + Cnt2#client_counter.timeouts,
             pending                  = Cnt1#client_counter.pending                + Cnt2#client_counter.pending
      }.
