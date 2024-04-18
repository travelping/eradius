%% Copyright (c) 2024, Travelping GmbH <info@travelping.com>
%%
%% SPDX-License-Identifier: MIT
%%
%% @doc Provides metrics callbacks for recording metrics with prometheus.erl
-module(eradius_metrics_prometheus).

-export([init/1, reset/0]).
-export([client_metrics_callback/3, server_metrics_callback/3]).

-ignore_xref([init/1, reset/0]).
-ignore_xref([client_metrics_callback/3, server_metrics_callback/3]).

-include_lib("kernel/include/logger.hrl").
-include("dictionary.hrl").
-include("eradius_lib.hrl").
-include("eradius_dict.hrl").

-define(DEFAULT_BUCKETS, [10, 30, 50, 75, 100, 1000, 2000]).
-define(CONFIG, #{histogram_buckets => ?DEFAULT_BUCKETS,
                  client_metrics => true,
                  server_metrics => true}).
-define(TS_CLIENT_KEY, '_prometheus_metrics_client_ts').
-define(TS_SERVER_KEY, '_prometheus_metrics_server_ts').

%%%=========================================================================
%%% Setup
%%%=========================================================================

%% @doc Initialize the prometheus metrics
-spec init(#{histogram_buckets => [pos_integer()],
             client_metrics => boolean(),
             server_metrics => boolean()}) -> ok.
init(Opts) ->
    Config = maps:merge(?CONFIG, Opts),

    init_client_metrics(Config),
    init_server_metrics(Config),
    ok.

reset() ->
    ok.

init_client_metrics(#{histogram_buckets := Buckets, client_metrics := true}) ->
    %%
    %% Client Side Metrics
    %%

    %% Server Status
    prometheus_boolean:declare(
      [{name, eradius_server_status},
       {labels, [server_ip, server_port]},
       {help, "Status of an upstream RADIUS Server"}]),

    ClientLabels = [server_ip, server_port, server_name, client_ip, client_name],
    prometheus_counter:declare(
      [{name, eradius_client_requests_total},
       {labels, ClientLabels},
       {help, "Amount of requests sent by a client"}]),
    prometheus_counter:declare(
      [{name, eradius_client_replies_total},
       {labels, ClientLabels},
       {help, "Amount of replies received by a client"}]),
    prometheus_counter:declare(
      [{name, eradius_client_access_requests_total},
       {labels, ClientLabels},
       {help, "Amount of Access requests sent by a client"}]),
    prometheus_counter:declare(
      [{name, eradius_client_accounting_requests_total},
       {labels, ClientLabels ++ [acct_type]},
       {help, "Amount of Accounting requests sent by a client"}]),
    prometheus_counter:declare(
      [{name, eradius_client_coa_requests_total},
       {labels, ClientLabels},
       {help, "Amount of CoA requests sent by a client"}]),
    prometheus_counter:declare(
      [{name, eradius_client_disconnect_requests_total},
       {labels, ClientLabels},
       {help, "Amount of Disconnect requests sent by client"}]),
    prometheus_counter:declare(
      [{name, eradius_client_retransmissions_total},
       {labels, ClientLabels},
       {help, "Amount of retransmissions done by a cliet"}]),
    prometheus_counter:declare(
      [{name, eradius_client_timeouts_total},
       {labels, ClientLabels},
       {help, "Amount of timeout errors triggered on a client"}]),
    prometheus_counter:declare(
      [{name, eradius_client_accept_responses_total},
       {labels, ClientLabels},
       {help, "Amount of Accept responses received by a client"}]),
    prometheus_counter:declare(
      [{name, eradius_client_reject_responses_total},
       {labels, ClientLabels},
       {help, "Amount of Reject responses received by a client"}]),
    prometheus_counter:declare(
      [{name, eradius_client_access_challenge_total},
       {labels, ClientLabels},
       {help, "Amount of Access-Challenge responses"}]),
    prometheus_counter:declare(
      [{name, eradius_client_accounting_responses_total},
       {labels, ClientLabels ++ [acct_type]},
       {help, "Amount of Accounting responses received by a client"}]),
    prometheus_counter:declare(
      [{name, eradius_client_coa_nacks_total},
       {labels, ClientLabels},
       {help, "Amount of CoA Nack received by a client"}]),
    prometheus_counter:declare(
      [{name, eradius_client_coa_acks_total},
       {labels, ClientLabels},
       {help, "Amount of CoA Ack received by a client"}]),
    prometheus_counter:declare(
      [{name, eradius_client_disconnect_acks_total},
       {labels, ClientLabels},
       {help, "Amount of Disconnect Acks received by a client"}]),
    prometheus_counter:declare(
      [{name, eradius_client_disconnect_nacks_total},
       {labels, ClientLabels},
       {help, "Amount of Disconnect Nacks received by a client"}]),
    prometheus_counter:declare(
      [{name, eradius_client_packets_dropped_total},
       {labels, ClientLabels},
       {help, "Amount of dropped packets"}]),
    prometheus_counter:declare(
      [{name, eradius_client_unknown_type_request_total},
       {labels, ClientLabels},
       {help, "Amount of RADIUS requests with unknown type"}]),
    prometheus_counter:declare(
      [{name, eradius_client_bad_authenticator_request_total},
       {labels, ClientLabels},
       {help, "Amount of RADIUS requests with bad authenticator"}]),
    prometheus_gauge:declare(
      [{name, eradius_client_pending_requests_total},
       {labels, ClientLabels},
       {help, "Amount of pending requests on client side"}]),

    %% Histograms
    prometheus_histogram:declare(
      [{name, eradius_client_request_duration_milliseconds},
       {labels, ClientLabels},
       {duration_unit, milliseconds},
       {buckets, Buckets},
       {help, "Execution time of a RADIUS request"}]),
    prometheus_histogram:declare(
      [{name, eradius_client_access_request_duration_milliseconds},
       {labels, ClientLabels},
       {duration_unit, milliseconds},
       {buckets, Buckets},
       {help, "Access-Request execution time"}]),
    prometheus_histogram:declare(
      [{name, eradius_client_accounting_request_duration_milliseconds},
       {labels, ClientLabels ++ [acct_type]},
       {duration_unit, milliseconds},
       {buckets, Buckets},
       {help, "Accounting-Request execution time"}]),
    prometheus_histogram:declare(
      [{name, eradius_client_coa_request_duration_milliseconds},
       {labels, ClientLabels},
       {duration_unit, milliseconds},
       {buckets, Buckets},
       {help, "CoA request execution time"}]),
    prometheus_histogram:declare(
      [{name, eradius_client_disconnect_request_duration_milliseconds},
       {labels, ClientLabels},
       {duration_unit, milliseconds},
       {buckets, Buckets},
       {help, "Disconnect execution time"}]),
    ok;
init_client_metrics(_Config) ->
    ok.

init_server_metrics(#{histogram_buckets := Buckets, server_metrics := true}) ->
    %%
    %% Server Side Metrics
    %%

    %% this need a collector...
    %% {uptime_milliseconds, gauge, "RADIUS server uptime"},
    %% {since_last_reset_milliseconds, gauge, "RADIUS last server reset time"},

    ServerLabels = [server_ip, server_port, server_name, nas_ip, nas_id],
    prometheus_counter:declare(
      [{name, eradius_requests_total},
       {labels, ServerLabels},
       {help, "Amount of requests received by the RADIUS server"}]),
    prometheus_counter:declare(
      [{name, eradius_replies_total},
       {labels, ServerLabels},
       {help, "Amount of responses"}]),
    prometheus_counter:declare(
      [{name, eradius_access_requests_total},
       {labels, ServerLabels},
       {help, "Amount of Access requests received by the RADIUS server"}]),
    prometheus_counter:declare(
      [{name, eradius_accounting_requests_total},
       {labels, ServerLabels ++ [acct_type]},
       {help, "Amount of Accounting requests received by RADIUS server"}]),
    prometheus_counter:declare(
      [{name, eradius_coa_requests_total},
       {labels, ServerLabels},
       {help, "Amount of CoA requests received by the RADIUS server"}]),
    prometheus_counter:declare(
      [{name, eradius_disconnect_requests_total},
       {labels, ServerLabels},
       {help, "Amount of Disconnect requests received by the RADIUS server"}]),
    prometheus_counter:declare(
      [{name, eradius_accept_responses_total},
       {labels, ServerLabels},
       {help, "Amount of Access-Accept responses"}]),
    prometheus_counter:declare(
      [{name, eradius_reject_responses_total},
       {labels, ServerLabels},
       {help, "Amount of Access-Reject responses"}]),
    prometheus_counter:declare(
      [{name, eradius_access_challenge_total},
       {labels, ServerLabels},
       {help, "Amount of Access-Challenge responses"}]),
    prometheus_counter:declare(
      [{name, eradius_accounting_responses_total},
       {labels, ServerLabels ++ [acct_type]},
       {help, "Amount of Accounting responses"}]),
    prometheus_counter:declare(
      [{name, eradius_coa_acks_total},
       {labels, ServerLabels},
       {help, "Amount of CoA ACK responses"}]),
    prometheus_counter:declare(
      [{name, eradius_coa_nacks_total},
       {labels, ServerLabels},
       {help, "Amount of CoA Nack responses"}]),
    prometheus_counter:declare(
      [{name, eradius_disconnect_acks_total},
       {labels, ServerLabels},
       {help, "Amount of Disconnect-Ack responses"}]),
    prometheus_counter:declare(
      [{name, eradius_disconnect_nacks_total},
       {labels, ServerLabels},
       {help, "Amount of Disconnect-Nack responses"}]),
    prometheus_counter:declare(
      [{name, eradius_malformed_requests_total},
       {labels, ServerLabels},
       {help, "Amount of malformed requests on RADIUS server"}]),
    prometheus_counter:declare(
      [{name, eradius_invalid_requests_total},
       {labels, ServerLabels},
       {help, "Amount of invalid requests on RADIUS server"}]),
    prometheus_counter:declare(
      [{name, eradius_retransmissions_total},
       {labels, ServerLabels},
       {help, "Amount of retrasmissions done by NAS"}]),
    prometheus_counter:declare(
      [{name, eradius_duplicated_requests_total},
       {labels, ServerLabels},
       {help, "Amount of duplicated requests"}]),
    prometheus_gauge:declare(
      [{name, eradius_pending_requests_total},
       {labels, ServerLabels},
       {help, "Amount of pending requests"}]),
    prometheus_counter:declare(
      [{name, eradius_packets_dropped_total},
       {labels, ServerLabels},
       {help, "Amount of dropped packets"}]),
    prometheus_counter:declare(
      [{name, eradius_unknown_type_request_total},
       {labels, ServerLabels},
       {help, "Amount of RADIUS requests with unknown type"}]),
    prometheus_counter:declare(
      [{name, eradius_bad_authenticator_request_total},
       {labels, ServerLabels},
       {help, "Amount of RADIUS requests with bad authenticator"}]),

    %% Histograms
    prometheus_histogram:declare(
      [{name, eradius_request_duration_milliseconds},
       {labels, ServerLabels},
       {duration_unit, milliseconds},
       {buckets, Buckets},
       {help, "RADIUS request execution time"}]),
    prometheus_histogram:declare(
      [{name, eradius_access_request_duration_milliseconds},
       {labels, ServerLabels},
       {duration_unit, milliseconds},
       {buckets, Buckets},
       {help, "Access-Request execution time"}]),
    prometheus_histogram:declare(
      [{name, eradius_accounting_request_duration_milliseconds},
       {labels, ServerLabels ++ [acct_type]},
       {duration_unit, milliseconds},
       {buckets, Buckets},
       {help, "Accounting-Request execution time"}]),
    prometheus_histogram:declare(
      [{name, eradius_coa_request_duration_milliseconds},
       {labels, ServerLabels},
       {duration_unit, milliseconds},
       {buckets, Buckets},
       {help, "Coa-Request execution time"}]),
    prometheus_histogram:declare(
      [{name, eradius_disconnect_request_duration_milliseconds},
       {labels, ServerLabels},
       {duration_unit, milliseconds},
       {buckets, Buckets},
       {help, "Disconnect-Request execution time"}]),
    ok;
init_server_metrics(_Config) ->
    ok.

%%%=========================================================================
%%% Metrics Handler
%%%=========================================================================

%% @doc Function for use as `t:eradius_req:metrics_callback/0' for a `t:eradius_req:req/0'
%% object in a RADIUS client to record prometheus metrics
-spec client_metrics_callback(Event :: eradius_req:metrics_event(),
                              MetaData :: term(),
                              Req :: eradius_req:req()) -> eradius_req:req().
client_metrics_callback(Event, MetaData,
                        #{server := Server, server_addr := {ServerIP, ServerPort},
                          client := Client, client_addr := ClientIP
                         } = Req) ->
    ?LOG(debug, "Client-Metric:~nEvent: ~p~nMetaData: ~p~nReq: ~p~n",
         [Event, MetaData, Req]),

    Labels = [ServerIP, ServerPort, Server, ClientIP, Client],
    case Event of
        request ->
            client_request_metrics(MetaData, Labels, Req);
        retransmission ->
            prometheus_counter:inc(eradius_client_retransmissions_total, Labels, 1),
            Req;
        reply ->
            client_reply_metrics(MetaData, Labels, Req);
        _ ->
            Req
    end;
client_metrics_callback(Event, MetaData, Req) ->
    ?LOG(error, "BROKEN Client-Metric:~nEvent: ~p~nMetaData: ~p~nReq: ~p~n",
         [Event, MetaData, Req]),
    Req.

client_request_metrics(_MetaData, Labels, #{cmd := Cmd} = Req) ->
    prometheus_counter:inc(eradius_client_requests_total, Labels, 1),
    case Cmd of
        request ->
            prometheus_counter:inc(eradius_client_access_requests_total, Labels, 1);
        accreq ->
            AcctStatusType = acct_status_type(Req),
            prometheus_counter:inc(
              eradius_client_accounting_requests_total, Labels ++ [AcctStatusType], 1);
        coareq ->
            prometheus_counter:inc(eradius_client_coa_requests_total, Labels, 1);
        discreq ->
            prometheus_counter:inc(eradius_client_disconnect_requests_total, Labels, 1);
        _ ->
            %% WTF? how can a client generate a request with an unknown type?
            %% should probably be _response_, keep it for compatibility
            prometheus_counter:inc(eradius_client_unknown_type_request_total, Labels, 1)
    end,
    Req#{?TS_CLIENT_KEY => erlang:monotonic_time()}.

client_request_duration(#{request := #{cmd := ReqCmd}}, Labels,
                        #{?TS_CLIENT_KEY := TS} = Req) ->
    Duration = erlang:monotonic_time() - TS,
    prometheus_histogram:observe(
      eradius_request_duration_milliseconds, Labels, Duration),

    case ReqCmd of
        request ->
            prometheus_histogram:observe(
              eradius_client_access_request_duration_milliseconds, Labels, Duration);
        accreq ->
            AcctStatusType = acct_status_type(Req),
            prometheus_histogram:observe(
              eradius_client_accounting_request_duration_milliseconds,
              Labels ++ [AcctStatusType], Duration);
        coareq ->
            prometheus_histogram:observe(
              eradius_client_coa_request_duration_milliseconds, Labels, Duration);
        discreq ->
            prometheus_histogram:observe(
              eradius_client_disconnect_request_duration_milliseconds, Labels, Duration);
        _ ->
            ok
    end,
    Req.

client_reply_metrics(MetaData, Labels,
                     #{cmd := Cmd, server_addr := {ServerIP, ServerPort}} = Req) ->
    prometheus_boolean:set(eradius_server_status, [ServerIP, ServerPort], true),
    case Cmd of
        accept ->
            prometheus_counter:inc(eradius_client_accept_responses_total, Labels, 1);
        reject ->
            prometheus_counter:inc(eradius_client_reject_responses_total, Labels, 1);
        challenge ->
            prometheus_counter:inc(eradius_client_access_challenge_total, Labels, 1);
        accresp ->
            AcctStatusType = acct_status_type(Req),
            prometheus_counter:inc(
              eradius_client_accounting_responses_total, Labels ++ [AcctStatusType], 1);
        coaack ->
            prometheus_counter:inc(eradius_client_coa_acks_total, Labels, 1);
        coanak ->
            prometheus_counter:inc(eradius_client_coa_nacks_total, Labels, 1);
        discack ->
            prometheus_counter:inc(eradius_client_disconnect_acks_total, Labels, 1);
        discnak ->
            prometheus_counter:inc(eradius_client_disconnect_nacks_total, Labels, 1);
        _ ->
            %% should probably be _response_, keep it for compatibility
            prometheus_counter:inc(eradius_client_unknown_type_request_total, Labels, 1)
    end,
    client_request_duration(MetaData, Labels, Req).

%% @doc Function for use as `t:eradius_req:metrics_callback/0' for a `t:eradius_req:req/0'
%% object in a RADIUS server to record prometheus metrics
-spec server_metrics_callback(Event :: eradius_req:metrics_event(),
                              MetaData :: term(),
                              Req :: eradius_req:req()) -> eradius_req:req().
server_metrics_callback(Event, MetaData,
                        #{server := Server, server_addr := {ServerIP, ServerPort},
                          client := Client, client_addr := ClientIP
                         } = Req) ->
    ?LOG(debug, "Server-Metric:~nEvent: ~p~nMetaData: ~p~nReq: ~p~n",
         [Event, MetaData, Req]),

    Labels = [ServerIP, ServerPort, Server, ClientIP, Client],
    case Event of
        request ->
            server_request_metrics(MetaData, Labels, Req);
        retransmission ->
            prometheus_counter:inc(eradius_requests_total, Labels, 1),
            prometheus_counter:inc(eradius_retransmissions_total, Labels, 1),
            Req;
        discard ->
            server_discard_metrics(MetaData, Labels, Req);
        reply ->
            server_reply_metrics(MetaData, Labels, Req);
        _ ->
            ?LOG(error, "Unexpected Server-Metric:~nEvent: ~p~nMetaData: ~p~nReq: ~p~n",
                 [Event, MetaData, Req]),
            Req
    end;
server_metrics_callback(invalid_request, #{server := Server} = _MetaData, _) ->
    prometheus_counter:inc(eradius_invalid_requests_total, [Server], 1),
    ok;
server_metrics_callback(Event, MetaData, Req) ->
    ?LOG(error, "Unexpected Server-Metric:~nEvent: ~p~nMetaData: ~p~nReq: ~p~n",
         [Event, MetaData, Req]),
    Req.

server_request_metrics(_MetaData, Labels, #{cmd := Cmd} = Req) ->
    prometheus_counter:inc(eradius_requests_total, Labels, 1),
    prometheus_gauge:inc(eradius_pending_requests_total, Labels, 1),
    case Cmd of
        request ->
            prometheus_counter:inc(eradius_access_requests_total, Labels, 1);
        accreq ->
            AcctStatusType = acct_status_type(Req),
            prometheus_counter:inc(
              eradius_accounting_requests_total, Labels ++ [AcctStatusType], 1);
        coareq ->
            prometheus_counter:inc(eradius_coa_requests_total, Labels, 1);
        discreq ->
            prometheus_counter:inc(eradius_disconnect_requests_total, Labels, 1);
        _ ->
            prometheus_counter:inc(eradius_unknown_type_request_total, Labels, 1)
    end,
    Req#{?TS_SERVER_KEY => erlang:monotonic_time()}.

server_discard_metrics(MetaData, Labels, Req) ->
    prometheus_gauge:inc(eradius_pending_requests_total, Labels, -1),
    prometheus_counter:inc(eradius_requests_total, Labels, 1),
    prometheus_counter:inc(eradius_packets_dropped_total, Labels, 1),
    case MetaData of
        #{reason := duplicate} ->
            prometheus_counter:inc(eradius_duplicated_requests_total, Labels, 1);
        #{reason := bad_authenticator} ->
            prometheus_counter:inc(eradius_bad_authenticator_request_total, Labels, 1);
        #{reason := unknown_req_type} ->
            prometheus_counter:inc(eradius_unknown_type_request_total, Labels, 1);
        #{reason := malformed} ->
            prometheus_counter:inc(eradius_malformed_requests_total, Labels, 1);
        _ ->
            ?LOG(error, "Unexpected Server-Metric:~nEvent: ~p~nMetaData: ~p~nReq: ~p~n",
                 [discard, MetaData, Req]),
            ok
    end,
    Req.

server_request_duration(#{request := #{cmd := ReqCmd}}, Labels,
                        #{?TS_SERVER_KEY := TS} = Req) ->
    Duration = erlang:monotonic_time() - TS,
    prometheus_histogram:observe(
      eradius_request_duration_milliseconds, Labels, Duration),

    case ReqCmd of
        request ->
            prometheus_histogram:observe(
              eradius_access_request_duration_milliseconds, Labels, Duration);
        accreq ->
            AcctStatusType = acct_status_type(Req),
            prometheus_histogram:observe(
              eradius_accounting_request_duration_milliseconds,
              Labels ++ [AcctStatusType], Duration);
        coareq ->
            prometheus_histogram:observe(
              eradius_coa_request_duration_milliseconds, Labels, Duration);
        discreq ->
            prometheus_histogram:observe(
              eradius_disconnect_request_duration_milliseconds, Labels, Duration);
        _ ->
            ok
    end,
    Req.

server_reply_metrics(MetaData, Labels, #{cmd := Cmd} = Req) ->
    prometheus_counter:inc(eradius_replies_total, Labels, 1),
    prometheus_gauge:inc(eradius_pending_requests_total, Labels, -1),
    case Cmd of
        accept ->
            prometheus_counter:inc(eradius_accept_responses_total, Labels, 1);
        reject ->
            prometheus_counter:inc(eradius_reject_responses_total, Labels, 1);
        challenge ->
            prometheus_counter:inc(eradius_access_challenge_total, Labels, 1);
        accresp ->
            AcctStatusType = acct_status_type(Req),
            prometheus_counter:inc(
              eradius_accounting_responses_total, Labels ++ [AcctStatusType], 1);
        coaack ->
            prometheus_counter:inc(eradius_coa_acks_total, Labels, 1);
        coanak ->
            prometheus_counter:inc(eradius_coa_nacks_total, Labels, 1);
        discack ->
            prometheus_counter:inc(eradius_disconnect_acks_total, Labels, 1);
        discnak ->
            prometheus_counter:inc(eradius_disconnect_nacks_total, Labels, 1);
        _ ->
            ok
    end,
    server_request_duration(MetaData, Labels, Req).

acct_status_type(#{attrs := Attrs}) when is_list(Attrs) ->
    acct_status_type_list(Attrs);
acct_status_type(#{body := Body}) when is_binary(Body) ->
    acct_status_type_scan(Body);
acct_status_type(_) ->
    invalid.

acct_status_type_list([]) ->
    invalid;
acct_status_type_list([{?Acct_Status_Type, Type}|_]) ->
    acct_status_type_label(Type);
acct_status_type_list([{#attribute{id = ?Acct_Status_Type}, Type}|_]) ->
    acct_status_type_label(Type);
acct_status_type_list([_|Next]) ->
    acct_status_type_list(Next).

acct_status_type_scan(<<?Acct_Status_Type, 6, Type:32, _/binary>>) ->
    acct_status_type_label(Type);
acct_status_type_scan(<<_, Len, Rest/binary>>) ->
    case Rest of
        <<_:(Len-2)/bytes, Next/binary>> ->
            acct_status_type_scan(Next);
        _ ->
            invalid
    end;
acct_status_type_scan(_) ->
    invalid.

acct_status_type_label(?RStatus_Type_Start)  -> start;
acct_status_type_label(?RStatus_Type_Stop)   -> stop;
acct_status_type_label(?RStatus_Type_Update) -> update;
acct_status_type_label(?RStatus_Type_On)     -> on;
acct_status_type_label(?RStatus_Type_Off)    -> off;
acct_status_type_label(Type) -> integer_to_list(Type).
