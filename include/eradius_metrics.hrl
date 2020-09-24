%% This file contains the definitions for all metrics used by prometheus.erl
%%
%% First the used entries and probes for prometheus will be described and
%% then the actual metrics. These definitions contain the way metrics are
%% exposed, e.g. for requests:
%%
%%   - request handle time (gauge)
%%   - request counter (counter)
%%
%% In a similar way this holds for other metrics.

%% this will be prepended to all eradius metrics
-define(DEFAULT_ENTRIES, <<"eradius", "_", "radius">>).

%% contains all metric definitions defined below sorted by service
-define(METRICS, [{server,  ?SERVER_METRICS},       %% metrics from all NAS together for one server socket
                  {nas,     ?NAS_METRICS},          %% metrics from single NAS
                  {client,  ?CLIENT_METRICS}]).     %% metrics from single client


%% prometheus basic configuration used for metrics
-define(COUNTER,        {counter,   %% metric type
                         []}).      %% type options

-define(GAUGE,          {gauge,
                         []}).

-define(HISTOGRAM_60000, {histogram,
                         [{min_heap_size, 233},
                          {slot_period, 100},
                          {time_span, 60000}]}).

-define(FUNCTION_UPTIME,{{function, eradius_metrics,
                          update_uptime, undefined,
                          proplist, [value]},
                         []}).

-define(FUNCTION_SINCE_LAST_REQUEST,
                        {{function, eradius_metrics,
                          update_since_last_request, undefined,
                          proplist, [value]},
                         []}).

-define(BASIC_TIME_METRICS, [
     {"time", "last_reset", [
       {"ticks", ?GAUGE}]},
     {"time", "last_config_reset", [
       {"ticks", ?GAUGE}]},
     {"time", "up", [
       {"ticks", ?FUNCTION_UPTIME}]}
     ]).

-define(BASIC_REQUEST_METRICS, [
     {"request", "total", [
       {"gauge", ?HISTOGRAM_60000},
       {"counter", ?COUNTER}]},
     {"request", "access", [
       {"gauge", ?HISTOGRAM_60000},
       {"counter", ?COUNTER}]},
     {"request", "accounting", [
       {"gauge", ?HISTOGRAM_60000},
       {"counter", ?COUNTER}]},
     {"request", "coa", [
       {"gauge", ?HISTOGRAM_60000},
       {"counter", ?COUNTER}]},
     {"request", "disconnect", [
       {"gauge", ?HISTOGRAM_60000},
       {"counter", ?COUNTER}]},

     %% RESPONSES
     {"response", "total", [
       {"counter", ?COUNTER}]},
     {"response", "access", [
       {"counter", ?COUNTER}]},
     {"response", "accounting", [
       {"counter", ?COUNTER}]},
     {"response", "access_accept", [
       {"counter", ?COUNTER}]},
     {"response", "access_reject", [
       {"counter", ?COUNTER}]},
     {"response", "access_challenge", [
       {"counter", ?COUNTER}]},
     {"response", "disconnect_ack", [
       {"counter", ?COUNTER}]},
     {"response", "disconnect_nak", [
       {"counter", ?COUNTER}]},
     {"response", "coa_ack", [
       {"counter", ?COUNTER}]},
     {"response", "coa_nak", [
       {"counter", ?COUNTER}]},
     {"request", "pending", [
       {"counter", ?COUNTER}]},

     {"time", "last_request", [
       {"ticks", ?GAUGE}]},
     {"time", "since_last_request", [
       {"ticks", ?FUNCTION_SINCE_LAST_REQUEST}]}
     ]).


-define(SERVER_METRICS, [
     {"request", "invalid", [
       {"gauge", ?HISTOGRAM_60000},
       {"counter", ?COUNTER}]},
     {"request", "malformed", [
       {"gauge", ?HISTOGRAM_60000},
       {"counter", ?COUNTER}]}
     ] ++ ?NAS_METRICS
       ++ ?BASIC_TIME_METRICS).

-define(NAS_METRICS, [
     {"request", "dropped", [
       {"gauge", ?HISTOGRAM_60000},
       {"counter", ?COUNTER}]},
     {"request", "retransmission", [
       {"gauge", ?HISTOGRAM_60000},
       {"counter", ?COUNTER}]},
     {"response", "retransmission", [
       {"counter", ?COUNTER}]},
     {"request", "duplicate", [
       {"gauge", ?HISTOGRAM_60000},
       {"counter", ?COUNTER}]},
     {"request", "bad_authenticator", [     %TODO: this metric is just initialized and not updated within eradius
       {"gauge", ?HISTOGRAM_60000},
       {"counter", ?COUNTER}]},
     {"request", "unknown_type", [
       {"gauge", ?HISTOGRAM_60000},
       {"counter", ?COUNTER}]}
     ] ++ ?BASIC_REQUEST_METRICS).


-define(CLIENT_METRICS, [
     {"request", "retransmission", [
       {"gauge", ?HISTOGRAM_60000},
       {"counter", ?COUNTER}]},
     {"request", "timeout", [
       {"gauge", ?HISTOGRAM_60000},
       {"counter", ?COUNTER}]},
     {"response", "bad_authenticator", [    %TODO: this metric is just initialized and not updated within eradius
       {"counter", ?COUNTER}]},
     {"response", "malformed", [            %TODO: this metric is just initialized and not updated within eradius
       {"counter", ?COUNTER}]},
     {"response", "unknown_type", [         %TODO: this metric is just initialized and not updated within eradius
       {"counter", ?COUNTER}]},
     {"response", "dropped", [
       {"counter", ?COUNTER}]}
     ] ++ ?BASIC_REQUEST_METRICS).
