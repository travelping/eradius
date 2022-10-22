-module(eradius_prometheus_collector).

-behaviour(prometheus_collector).

-include_lib("eradius/include/eradius_lib.hrl").
-include_lib("prometheus/include/prometheus.hrl").

-export([deregister_cleanup/1, collect_mf/2, collect_metrics/2, fetch_counter/2, fetch_counter/3, fetch_histogram/2]).
-export([augment_counters/1]).

-import(prometheus_model_helpers, [create_mf/5, gauge_metric/2, counter_metric/1]).

-define(METRIC_NAME_PREFIX, "eradius_").

-define(METRICS, [
                  {uptime_milliseconds, gauge, "RADIUS server uptime"},
                  {since_last_reset_milliseconds, gauge, "RADIUS last server reset time"},

                  {requests_total, counter, "Amount of requests received by the RADIUS server"},
                  {replies_total, counter, "Amount of responses"},

                  {access_requests_total, counter, "Amount of Access requests received by the RADIUS server"},
                  {accounting_requests_total, counter, "Amount of Accounting requests received by RADIUS server"},
                  {coa_requests_total, counter, "Amount of CoA requests received by the RADIUS server"},
                  {disconnect_requests_total, counter, "Amount of Disconnect requests received by the RADIUS server"},
                  {accept_responses_total, counter, "Amount of Access-Accept responses"},
                  {reject_responses_total, counter, "Amount of Access-Reject responses"},
                  {access_challenge_total, counter, "Amount of Access-Challenge responses"},
                  {accounting_responses_total, counter, "Amount of Accounting responses"},
                  {coa_acks_total, counter, "Amount of CoA ACK responses"},
                  {coa_nacks_total, counter, "Amount of CoA Nack responses"},
                  {disconnect_acks_total, counter, "Amount of Disconnect-Ack responses"},
                  {disconnect_nacks_total, counter, "Amount of Disconnect-Nack responses"},
                  {malformed_requests_total, counter, "Amount of malformed requests on RADIUS server"},
                  {invalid_requests_total, counter, "Amount of invalid requests on RADIUS server"},
                  {retransmissions_total, counter, "Amount of retrasmissions done by NAS"},
                  {duplicated_requests_total, counter, "Amount of duplicated requests"},
                  {pending_requests_total, gauge, "Amount of pending requests"},
                  {packets_dropped_total, counter, "Amount of dropped packets"},
                  {unknown_type_request_total, counter, "Amount of RADIUS requests with unknown type"},
                  {bad_authenticator_request_total, counter, "Amount of RADIUS requests with bad authenticator"},

                  {client_requests_total, counter, "Amount of requests sent by a client"},
                  {client_replies_total, counter, "Amount of replies received by a client"},
                  {client_access_requests_total, counter, "Amount of Access requests sent by a client"},
                  {client_accounting_requests_total, counter, "Amount of Accounting requests sent by a client"},
                  {client_coa_requests_total, counter, "Amount of CoA requests sent by a client"},
                  {client_disconnect_requests_total, counter, "Amount of Disconnect requests sent by client"},
                  {client_retransmissions_total, counter, "Amount of retransmissions done by a cliet"},
                  {client_timeouts_total, counter, "Amount of timeout errors triggered on a client"},
                  {client_accept_responses_total, counter, "Amount of Accept responses received by a client"},
                  {client_reject_responses_total, counter, "Amount of Reject responses received by a client"},
                  {client_access_challenge_total, counter, "Amount of Access-Challenge responses"},
                  {client_accounting_responses_total, counter, "Amount of Accounting responses received by a client"},
                  {client_coa_nacks_total, counter, "Amount of CoA Nack received by a client"},
                  {client_coa_acks_total, counter, "Amount of CoA Ack received by a client"},
                  {client_disconnect_acks_total, counter, "Amount of Disconnect Acks received by a client"},
                  {client_disconnect_nacks_total, counter, "Amount of Disconnect Nacks received by a client"},
                  {client_packets_dropped_total, counter, "Amount of dropped packets"},
                  {client_unknown_type_request_total, counter, "Amount of RADIUS requests with unknown type"},
                  {client_bad_authenticator_request_total, counter, "Amount of RADIUS requests with bad authenticator"},
                  {client_pending_requests_total, gauge, "Amount of pending requests on client site"}
                 ]).

-define(ACCT_TYPES, [start, stop, update]).

collect_mf(_Registry, Callback) ->
    {Stats, NasCntFields, ClientCntFields} = get_stats(),
    [mf(Callback, Metric, {Stats, NasCntFields, ClientCntFields}) || Metric <- ?METRICS],
    ok.

mf(Callback, {Name, PromMetricType, Help}, Data) ->
    Callback(create_mf(?METRIC_NAME(Name), Help, PromMetricType, ?MODULE,
                       {PromMetricType, fun (_) -> Name end, Data})),
    ok.

collect_metrics(_, {PromMetricType, Fun, Stats}) ->
    build_metric(Fun(Stats), PromMetricType, Stats).

fetch_histogram(Name, Labels) ->
    try
        lists:flatten(lists:map(fun ({LabelsFromStat, Buckets, DurationUnit}) ->
            case compare_labels(Labels, LabelsFromStat) of
                true ->
                    {Buckets1, Values} = lists:unzip(Buckets),
                    Values1 = augment_counters(Values),
                    Buckets2 = lists:zip(Buckets1, Values1),
                    {Buckets2, LabelsFromStat, DurationUnit};
                _ -> []
            end
        end, prometheus_histogram:values(default, Name)))
    catch _:_ -> [] end.

fetch_counter(Name, Labels) ->
    {Stats, NasCntFields, ClientCntFields} = get_stats(),
    fetch_counter(Name, {Stats, NasCntFields, ClientCntFields}, Labels).

fetch_counter(uptime_milliseconds, Stat, Labels) ->
    {{ServerMetrics, _}, _, _} = Stat,
    lists:flatten(lists:map(fun (#server_counter{} = Cnt) ->
        fetch_server_value(Labels, Cnt, fun () -> erlang:system_time(milli_seconds) - Cnt#server_counter.startTime end)
    end, ServerMetrics));
fetch_counter(since_last_reset_milliseconds, Stat, Labels) ->
    {{ServerMetrics, _}, _, _} = Stat,
    lists:flatten(lists:map(fun (#server_counter{} = Cnt) ->
        fetch_server_value(Labels, Cnt, fun () -> erlang:system_time(milli_seconds) - Cnt#server_counter.resetTime end)
    end, ServerMetrics));
fetch_counter(Name, Stat, Labels) ->
    case get_metric_info(Name, Stat) of
        {_, undefined, _} ->
            [];
        {Metrics, MetricIdx, RadiusMetricType} ->
            lists:flatten(lists:map(fun (Cnt) ->
                  case get_labels_and_val(MetricIdx, {Cnt, RadiusMetricType}, {Name, Labels}) of
                      {Value, LabelsFromStat} ->
                          case compare_labels(Labels, LabelsFromStat) of
                              true -> {Value, LabelsFromStat};
                              _ -> []
                          end;
                      List ->
                          lists:map(fun ({Value, LabelsFromStat}) ->
                              case compare_labels(Labels, LabelsFromStat) of
                                  true -> {Value, LabelsFromStat};
                                  _ -> []
                              end
                          end, List)
                  end
            end, Metrics))
    end.

%% from prometheus.erl as prometheus_histogram:values/1 returns
%% non-cumulative values
augment_counters([Start | Counters]) ->
  augment_counters(Counters, [Start], Start).

augment_counters([], LAcc, _CAcc) ->
  LAcc;
augment_counters([Counter | Counters], LAcc, CAcc) ->
  augment_counters(Counters, LAcc ++ [CAcc + Counter], CAcc + Counter).

build_metric(uptime_milliseconds, Type, Stat) ->
    {{ServerMetrics, _}, _, _} = Stat,
    lists:map(fun (#server_counter{} = Cnt) ->
                      build_server_metric_value(Type, Cnt, fun () -> erlang:system_time(milli_seconds) - Cnt#server_counter.startTime end)
              end, ServerMetrics);
build_metric(since_last_reset_milliseconds, Type, Stat) ->
    {{ServerMetrics, _}, _, _} = Stat,
    lists:map(fun (#server_counter{} = Cnt) ->
                      build_server_metric_value(Type, Cnt, fun () -> erlang:system_time(milli_seconds) - Cnt#server_counter.resetTime end)
              end, ServerMetrics);
build_metric(MetricName, Type, Stat)
  when MetricName =:= client_accounting_requests_total; 
       MetricName =:= client_accounting_responses_total;
       MetricName =:= accounting_requests_total;
       MetricName =:= accounting_responses_total ->
    lists:flatten(lists:map(fun (AcctType) ->
        case get_metric_info(MetricName, Stat) of
            {_, undefined, _} ->
                [];
            {Metrics, MetricIdx, RadiusMetricType} ->
                lists:map(fun (Cnt) ->
                    {Value, Labels} = get_labels_and_val(MetricIdx, {Cnt, RadiusMetricType}, {MetricName, [{acct_type, AcctType}]}),
                    metric(Type, Value, Labels)
                end, Metrics)
        end
    end, [start, stop, update]));
build_metric(MetricName, Type, Stat) ->
    case get_metric_info(MetricName, Stat) of
        {_, undefined, _} ->
            [];
        {Metrics, MetricIdx, RadiusMetricType} ->
            lists:flatten(lists:map(fun (Cnt) ->
                {Value, Labels} = get_labels_and_val(MetricIdx, {Cnt, RadiusMetricType}, {}),
                metric(Type, Value, Labels)
            end, Metrics))
    end.

metric(_, [], []) -> undefined;
metric(counter, Value, Labels) -> counter_metric({Labels, Value});
metric(gauge, Value, Labels)   -> gauge_metric(Labels, Value).

deregister_cleanup(_) -> ok.

%% helper to make mapping between prometheus metrics names and eradius_counter fields
%% @private
map_record_field(requests_total)                         -> {requests, server};
map_record_field(replies_total)                          -> {replies, server};
map_record_field(access_requests_total)                  -> {accessRequests, server};
map_record_field(accounting_requests_total)              -> {accountRequestsStart, server};
map_record_field(coa_requests_total)                     -> {coaRequests, server};
map_record_field(disconnect_requests_total)              -> {discRequests, server};
map_record_field(accept_responses_total)                 -> {accessAccepts, server};
map_record_field(access_challenge_total)                 -> {accessChallenges, server};
map_record_field(reject_responses_total)                 -> {accessRejects, server};
map_record_field(accounting_responses_total)             -> {accountResponsesStart, server};
map_record_field(coa_acks_total)                         -> {coaAcks, server};
map_record_field(coa_nacks_total)                        -> {coa_nacks_total, server};
map_record_field(disconnect_acks_total)                  -> {discAcks, server};
map_record_field(disconnect_nacks_total)                 -> {discNaks, server};
map_record_field(malformed_requests_total)               -> {malformedRequests, server};
map_record_field(invalid_requests_total)                 -> {invalidRequests, server};
map_record_field(retransmissions_total)                  -> {retransmissions, server};
map_record_field(duplicated_requests_total)              -> {dupRequests, server};
map_record_field(pending_requests_total)                 -> {pending, server};
map_record_field(packets_dropped_total)                  -> {packetsDropped, server};
map_record_field(unknown_type_request_total)             -> {unknownTypes, server};
map_record_field(bad_authenticator_request_total)        -> {badAuthenticators, server};
map_record_field(client_requests_total)                  -> {requests, client};
map_record_field(client_replies_total)                   -> {replies, client};
map_record_field(client_access_requests_total)           -> {accessRequests, client};
map_record_field(client_accept_responses_total)          -> {accessAccepts, client};
map_record_field(client_access_challenge_total)          -> {accessChallenges, client};
map_record_field(client_reject_responses_total)          -> {accessRejects, client};
map_record_field(client_accounting_requests_total)       -> {accountRequestsStart, client};
map_record_field(client_accounting_responses_total)      -> {accountResponsesStart, client};
map_record_field(client_coa_requests_total)              -> {coaRequests, client};
map_record_field(client_coa_nacks_total)                 -> {coaNaks, client};
map_record_field(client_coa_acks_total)                  -> {coaAcks, client};
map_record_field(client_disconnect_requests_total)       -> {discRequests, client};
map_record_field(client_disconnect_nacks_total)          -> {discNaks, client};
map_record_field(client_disconnect_acks_total)           -> {discAcks, client};
map_record_field(client_retransmissions_total)           -> {retransmissions, client};
map_record_field(client_pending_requests_total)          -> {pending, client};
map_record_field(client_timeouts_total)                  -> {timeouts, client};
map_record_field(client_packets_dropped_total)           -> {packetsDropped, client};
map_record_field(client_unknown_type_request_total)      -> {unknownTypes, client};
map_record_field(client_bad_authenticator_request_total) -> {badAuthenticators, client};
map_record_field(_)                                -> undefined.

%% Helper to fetch stats from eradius_counter
%% @private
get_stats() ->
    Stats = eradius_counter:read(),
    NasCntFields = lists:zip(record_info(fields, nas_counter), lists:seq(1, length(record_info(fields, nas_counter)))),
    ClientCntFields = lists:zip(record_info(fields, client_counter), lists:seq(1, length(record_info(fields, client_counter)))),
    {Stats, NasCntFields, ClientCntFields}.

%% Helper to get value for the given metric from the #server_counter{}
%% @private
fetch_server_value(Labels, #server_counter{} = Cnt, FnVal) ->
    {ServerIP, ServerPort} = Cnt#server_counter.key,
    LabelsFromStat = [{server_name, Cnt#server_counter.server_name},
                      {server_ip, inet:ntoa(ServerIP)},
                      {server_port, ServerPort}],
    case compare_labels(Labels, LabelsFromStat) of
        true -> {FnVal(), LabelsFromStat};
        _ -> []
    end.

%% Helper to build prometheus metric for the given metric from the #server_counter{}
%% @private
build_server_metric_value(Type, #server_counter{} = Cnt, FnVal) ->
    {ServerIP, ServerPort} = Cnt#server_counter.key,
    metric(Type, FnVal(), [{server_name, Cnt#server_counter.server_name},
                           {server_ip, inet:ntoa(ServerIP)},
                           {server_port, ServerPort}]).

%% Helper to compare Labels from a query and labels from eradius_counter stat
%% @private
compare_labels(_, []) -> false;
compare_labels(LabelsFromQuery, LabelsFromStat) ->
    lists:all(fun ({K, V}) -> V == proplists:get_value(K, LabelsFromStat, undefined) end, LabelsFromQuery).

%% Helper to fetch a metric information from eradius_counter stats by the given metric name
%% @private
get_metric_info(Name, Stat) ->
    {{_, {_, Metrics}}, NasFields, ClientFields} = Stat,
    {Metric, RadiusMetricType} = map_record_field(Name),
    case RadiusMetricType of
        client -> {Metrics, proplists:get_value(Metric, ClientFields), RadiusMetricType};
        server -> {Metrics, proplists:get_value(Metric, NasFields), RadiusMetricType}
    end.

%% Helper to get a value of a server/nas metric by the given #nas_counter{} or #client_counter{} index
%% @private
get_labels_and_val(_, {#nas_counter{} = Cnt, server}, {Name, Labels})
  when Name =:= accounting_requests_total;
       Name =:= accounting_responses_total ->
    Type = proplists:get_value(acct_type, Labels),
    {{ServerIP, ServerPort}, NasIP, NasId} = Cnt#nas_counter.key,
    case get_value(Name, Type, Cnt) of
        undefined ->
            lists:map(fun (AcctType) ->
                ResLabels = get_labels(Cnt, ServerIP, ServerPort, NasId, NasIP),
                {get_value(Name, AcctType, Cnt), [{acct_type, AcctType} | ResLabels]}
            end, ?ACCT_TYPES);
        Value ->
            ResLabels = get_labels(Cnt, ServerIP, ServerPort, NasId, NasIP),
            {Value, [{acct_type, Type} | ResLabels]}
    end;
get_labels_and_val(MetricIdx, {#nas_counter{} = Cnt, server}, _) ->
    {{ServerIP, ServerPort}, NasIP, NasId} = Cnt#nas_counter.key,
    {element(MetricIdx + 1, Cnt), get_labels(Cnt, ServerIP, ServerPort, NasId, NasIP)};
get_labels_and_val(_, {#client_counter{} = Cnt, client}, {Name, Labels})
  when Name =:= client_accounting_requests_total; 
       Name =:= client_accounting_responses_total ->
    Type = proplists:get_value(acct_type, Labels),
    {{ClientName, ClientIP, _ClientPort}, {_, ServerIP, ServerPort}} = Cnt#client_counter.key,
    case get_value(Name, Type, Cnt) of
        undefined ->
            lists:map(fun (AcctType) ->
                ResLabels = get_labels(Cnt, ServerIP, ServerPort, ClientName, ClientIP),
                {get_value(Name, AcctType, Cnt), [{acct_type, AcctType} | ResLabels]}
            end, ?ACCT_TYPES);
        Value ->
            ResLabels = get_labels(Cnt, ServerIP, ServerPort, ClientName, ClientIP),
            {Value, [{acct_type, Type} | ResLabels]}
    end;
get_labels_and_val(MetricIdx, {#client_counter{} = Cnt, client}, _) ->
   {{ClientName, ClientIP, _ClientPort}, {_, ServerIP, ServerPort}} = Cnt#client_counter.key,
   {element(MetricIdx + 1, Cnt), get_labels(Cnt, ServerIP, ServerPort, ClientName, ClientIP)};
get_labels_and_val(_, _, _) ->
    {[], []}.

%% @private
get_labels(#client_counter{server_name = ServerName}, ServerIP, ServerPort, ClientName, ClientIP) ->
    [{server_name, ServerName}, {server_ip, ServerIP},
     {server_port, ServerPort}, {client_name, ClientName}, {client_ip, ClientIP}];
get_labels(#nas_counter{server_name = ServerName}, ServerIP, ServerPort, NasId, NasIP) ->
    [{server_name, ServerName}, {server_ip, inet:ntoa(ServerIP)},
     {server_port, ServerPort}, {nas_id, NasId}, {nas_ip, inet:ntoa(NasIP)}].

%% @private
get_value(accounting_requests_total, start, #nas_counter{accountRequestsStart = Value})               -> Value;
get_value(accounting_requests_total, stop, #nas_counter{accountRequestsStop = Value})                 -> Value;
get_value(accounting_requests_total, update, #nas_counter{accountRequestsUpdate = Value})             -> Value;
get_value(accounting_responses_total, start, #nas_counter{accountResponsesStart = Value})             -> Value;
get_value(accounting_responses_total, stop, #nas_counter{accountResponsesStop = Value})               -> Value;
get_value(accounting_responses_total, update, #nas_counter{accountResponsesUpdate = Value})           -> Value;
get_value(client_accounting_requests_total, start, #client_counter{accountRequestsStart = Value})     -> Value;
get_value(client_accounting_requests_total, stop, #client_counter{accountRequestsStop = Value})       -> Value;
get_value(client_accounting_requests_total, update, #client_counter{accountRequestsUpdate = Value})   -> Value;
get_value(client_accounting_responses_total, start, #client_counter{accountResponsesStart = Value})   -> Value;
get_value(client_accounting_responses_total, stop, #client_counter{accountResponsesStop = Value})     -> Value;
get_value(client_accounting_responses_total, update, #client_counter{accountResponsesUpdate = Value}) -> Value;
get_value(_, _, _)                                                                                    -> undefined.
