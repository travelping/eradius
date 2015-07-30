-module(eradius_metrics).

-export([subscriptions/1, start_subscriptions/0, start_subscriptions/2]).
-export([update_client_counter_metric/2, update_nas_prop_metric/3]).

-define(DEFAULT_INTERVAL, 500).
-define(CLIENT_TYPES, [client_requests, client_remote_requests, client_socket_error, client_socket_dow, client_responses]).

start_subscriptions() ->
    Metrics = application:get_env(eradius, metrics),
    case Metrics of
        {ok, MetricsList} -> [start_subscriptions(Reporter, MetricsList) || {Reporter, _} <- exometer_report:list_reporters()];
        _ -> ok
    end.

start_subscriptions(Reporter, Metrics) ->
    [exometer_report:subscribe(Reporter, Name, DataPoint, Time, [], true) || {Name, DataPoint, Time} <- subscriptions(Metrics)].

subscriptions([]) ->
    [];
subscriptions(MetricsList) ->
    AvailableMetrics = lists:filter(fun(Metric) -> lists:memeber(Metric, MetricsList) end, ?CLIENT_TYPES),
    lists:map(fun(MetricName) -> {[eradius, MetricName], value, ?DEFAULT_INTERVAL} end, AvailableMetrics).

update_client_counter_metric(Metric, Value) ->
    exometer:update_or_create([eradius, Metric], Value, counter, []).

update_nas_prop_metric(Metric, {nas_prop, _, Port, NAS, _, _ ,_, _} = _N, Value) ->
    Key = binary_to_atom(erlang:iolist_to_binary([NAS, <<":">>, integer_to_binary(Port)]), utf8),
    exometer:update_or_create([eradius, Key, Metric], Value, counter, []).
