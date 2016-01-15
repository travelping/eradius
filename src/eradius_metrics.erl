-module(eradius_metrics).

-include("metrics.hrl").

-export([get_metric_name/4, subscribe_client/1, subscribe_server/2, timestamp/1, update_uptime/1, unsubscribe_server/2]).
-export([update_client_counter_metric/4, update_nas_prop_metric/3, update_client_histogram_metric/4]).

get_metrics_by_type(Type) ->
    case Type of
        server -> {?SERVER_METRICS, value};
        nas -> {?NAS_METRICS, value}
    end.

unsubscribe_server(SubscriptionName, SubscriptionType) ->
    {ok, EnabledMetrics} = application:get_env(eradius, metrics),
    {MetricsList, MetricType} = get_metrics_by_type(SubscriptionType),
    lists:foreach(fun({Reporter, _}) ->
                  case lists:member(SubscriptionType, EnabledMetrics) of
                      true ->
                          lists:foreach(fun(Metric) ->
                                                ServerId = get_server_id(SubscriptionName),
                                                Name = [eradius, SubscriptionType, ServerId, Metric],
                                                exometer_report:unsubscribe_all(Reporter, Name),
                                                exometer:delete(Name)
                                        end, MetricsList ++ [uptime]);
                      false ->
                          ok
                  end
     end,
     exometer_report:list_reporters()).

get_server_id(SubscriptionName) ->
    case is_atom(SubscriptionName) of
        true -> SubscriptionName;
        false -> binary_to_atom(SubscriptionName, utf8)
    end.

subscribe_server(SubscriptionName, SubscriptionType) ->
    {ok, EnabledMetrics} = application:get_env(eradius, metrics),
    ServerId = get_server_id(SubscriptionName),
    lists:foreach(fun({Reporter, _}) ->
                  {MetricsList, MetricType} = get_metrics_by_type(SubscriptionType),
                  case lists:member(SubscriptionType, EnabledMetrics) of
                      true ->
                          lists:foreach(fun(Metric) ->
                                            Name = [eradius, SubscriptionType, ServerId, Metric],
                                            case Metric of
                                                request_handle_time ->
                                                    exometer_report:subscribe(Reporter, Name, [mean, max], 1000,
                                                                              [{SubscriptionType, {from_name, 3}}], true);
                                                _ ->
                                                    exometer_report:subscribe(Reporter, Name, MetricType, 1000,
                                                                              [{SubscriptionType, {from_name, 3}}], true)
                                            end
                                        end, MetricsList);
                      false ->
                          ok
                  end
    end,
    exometer_report:list_reporters()),

    % update server uptime and reset time metrics
    case SubscriptionType of
        server ->
            StartTime = round(timestamp(s)),
            exometer:update_or_create([eradius, server, ServerId, start_time], StartTime, gauge, []),
            exometer:update_or_create([eradius, server, ServerId, reset_time], StartTime, gauge, []),
            UptimeMetricName = [eradius, server, ServerId, uptime],
            case exometer:info(UptimeMetricName) of
                undefined ->
                    exometer:new(UptimeMetricName, {function, eradius_metrics, update_uptime, [ServerId], proplist, [counter]}),
                    lists:foreach(fun({Reporter, _}) ->
                                          exometer_report:subscribe(Reporter, UptimeMetricName, counter, 10000, [{uptime, {from_name, 3}}], true)
                                  end,
                                  exometer_report:list_reporters());
                _ ->
                    % we already have this metric, so, do nothing
                    ok
            end;
        _ ->
            ok
    end.

subscribe_client(Name) ->
    [client_subscriptions(Name, Reporter, ?CLIENT_METRICS) || {Reporter, _} <- exometer_report:list_reporters()].

client_subscriptions({IP, Port}, Reporter, Metrics) ->
    {ok, EnabledMetrics} = application:get_env(eradius, metrics),
    case lists:member(client, EnabledMetrics) of
        true ->
            lists:foreach(fun({Metric, MetricType}) ->
                                  DataPoint = case MetricType of
                                                  counter -> value;
                                                  histogram -> [mean, max]
                                              end,
                                  maybe_subscribe(Reporter, Metric, IP, Port, DataPoint)
                          end, Metrics);
        false ->
            ok
    end.

%% Helper
update_nas_prop_metric(Metric, {nas_prop, _, _Port, NAS, _, _ ,_, _} = _N, Value) ->
    exometer:update_or_create([eradius, nas, binary_to_atom(NAS, utf8), Metric], Value, counter, []).

%% Helpers for client metrics
update_client_histogram_metric(Metric, ClientIp, Port, Value) ->
    MetricId = get_metric_name(ClientIp, Port, Metric, client),
    exometer:update_or_create(MetricId, Value, histogram, [{truncate, false}]).

update_client_counter_metric(Metric, ClientIp, Port, Value) ->
    MetricId = get_metric_name(ClientIp, Port, Metric, client),
    exometer:update_or_create(MetricId, Value, counter, []).

get_metric_name(IP, Port, MetricName, MetricType) ->
    Name = addr_to_bin(IP, Port),
    [eradius, MetricType, binary_to_atom(Name, utf8), MetricName].

addr_to_bin(IP, Port) ->
    {N1, N2, N3, N4} = IP,
    erlang:iolist_to_binary([integer_to_binary(N1), <<".">>,
                             integer_to_binary(N2), <<".">>,
                             integer_to_binary(N3), <<".">>,
                             integer_to_binary(N4), <<":">>, integer_to_binary(Port)]).

update_uptime(ServerName) ->
    {ok, [{value, ServerStartTime}, _]} = exometer:get_value([eradius, server, ServerName, start_time]),
    CurrentTime = timestamp(s),
    [{counter, round(CurrentTime - ServerStartTime)}].

timestamp(Unit) ->
    {MegaSecs, Secs, MicroSecs} = os:timestamp(),
    case Unit of
        s   ->         Secs + (MegaSecs * 1000000) + (MicroSecs / 10000000);
        ms  -> 1000 * (Secs + (MegaSecs * 1000000) + (MicroSecs / 10000000))
    end.

maybe_subscribe(Reporter, Metric, IP, Port, DataPoint) ->
    SubscribedReporters = exometer_report:list_subscriptions(Reporter),
    SubscribersList = lists:filter(fun({ReporterMetric, ReporterDataPoint, _, _}) ->
                                       (ReporterMetric == get_metric_name(IP, Port, Metric, client)) and (ReporterDataPoint == DataPoint)
                                   end, SubscribedReporters),
    SubscribersList == [] andalso exometer_report:subscribe(Reporter, get_metric_name(IP, Port, Metric, client),
                                                            DataPoint, 1000, [{client, {from_name, 3}}], true).

%% ------------------------------------------------------------------------------------------
%% -- EUnit Tests
-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

get_metric_name_test() ->
    ?assertEqual(eradius_metrics:get_metric_name({127, 0, 0, 1}, 1813, reset_time, client),
                 [eradius, client, '127.0.0.1:1813', reset_time]),
    ok.
-endif.
