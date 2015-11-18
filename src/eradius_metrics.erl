-module(eradius_metrics).

-include("metrics.hrl").

-export([get_metric_name/4, subscribe_client/1, addr_to_bin/2, subscribe_server/3, timestamp/0, update_uptime/1]).
-export([update_client_counter_metric/4, update_nas_prop_metric/3, update_client_histogram_metric/4]).

subscribe_server(IP, Port, SubscriptionType) ->
    {ok, EnabledMetrics} = application:get_env(eradius, metrics),
    lists:foreach(fun({Reporter, _}) ->
        {MetricsList, MetricType} = case SubscriptionType of
					server -> {?SERVER_METRICS, value};
					nas -> {?NAS_METRICS, value}
				    end,

	case lists:member(SubscriptionType, EnabledMetrics) of
	    true ->
		lists:foreach(fun(Metric) ->
		    Name = server_metric_name(IP, Port, Metric, SubscriptionType),
		    exometer_report:subscribe(Reporter, Name, MetricType, 1000, [{SubscriptionType, {from_name, 3}}], true)
		end, MetricsList);
	    false ->
		ok
	end
    end,
    exometer_report:list_reporters()),

    % update server uptime and reset time metrics
    case SubscriptionType of
        server ->
            StartTime = round(timestamp()),
            exometer:update_or_create(eradius_metrics:get_metric_name(IP, Port, start_time, server), StartTime, gauge, []),
            exometer:update_or_create(eradius_metrics:get_metric_name(IP, Port, reset_time, server), StartTime, gauge, []),
            UptimeMetricName = eradius_metrics:get_metric_name(IP, Port, uptime, server),
            exometer:new(UptimeMetricName, {function, eradius_metrics, update_uptime, [{IP, Port}], value, [counter]}),
            lists:foreach(fun({Reporter, _}) ->
                exometer_report:subscribe(Reporter, UptimeMetricName, value, 10000, [{uptime, {from_name, 3}}], true)
	    end,
	    exometer_report:list_reporters());
        _ ->
            ok
    end.

server_metric_name(IP, Port, Metric, Type) ->
    case Type of
	server ->
	    eradius_metrics:get_metric_name(IP, Port, Metric, Type);
	_ ->
	    FormatNasName = [IP, <<":">>, integer_to_binary(Port)],
	    Key = binary_to_atom(erlang:iolist_to_binary(FormatNasName), utf8),
	    [eradius, Type, Key, Metric]
    end.

subscribe_client(Name) ->
    [client_subscriptions(Name, Reporter, ?CLIENT_METRICS) || {Reporter, _} <- exometer_report:list_reporters()].

client_subscriptions({IP, Port}, Reporter, Metrics) ->
    {ok, EnabledMetrics} = application:get_env(eradius, metrics),
    case lists:member(client, EnabledMetrics) of
	true ->
	    lists:foreach(fun({Metric, MetricType}) ->
				  DataPoint = case MetricType of
						  counter ->   value;
						  histogram -> mean;
						  _ -> ok
					      end,
				  exometer_report:subscribe(Reporter, get_metric_name(IP, Port, Metric, client),
							    DataPoint, 1000, [{client, {from_name, 3}}], true)
			  end, Metrics);
	fase ->
	    ok
    end.

%% Helper
update_nas_prop_metric(Metric, {nas_prop, _, Port, NAS, _, _ ,_, _} = _N, Value) ->
    Key = binary_to_atom(erlang:iolist_to_binary([NAS, <<":">>, integer_to_binary(Port)]), utf8),
    exometer:update_or_create([eradius, nas, Key, Metric], Value, counter, []).

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

update_uptime({IP, Port}) ->
    {ok, [{value, ServerStartTime}, _]} = exometer:get_value(get_metric_name(IP, Port, start_time, server)),
    CurrentTime = timestamp(),
    round(CurrentTime - ServerStartTime).

timestamp() ->
    {MegaSecs, Secs, MicroSecs} = os:timestamp(),
    Secs + (MegaSecs * 1000000) + (MicroSecs / 10000000).

%% ------------------------------------------------------------------------------------------
%% -- EUnit Tests
-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

get_metric_name_test() ->
    ?assertEqual(eradius_metrics:get_metric_name({127, 0, 0, 1}, 1813, reset_time, client),
		 [eradius, client, '127.0.0.1:1813', reset_time]),
    ?assertEqual(eradius_metrics:get_metric_name({127, 0, 0, 1}, 1812, reset_time, server),
		 [eradius, server, '127.0.0.1:1812', reset_time]),
    ok.
-endif.
