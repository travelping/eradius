%% Copyright (c) 2010-2017 by Travelping GmbH <info@travelping.com>

%% Permission is hereby granted, free of charge, to any person obtaining a
%% copy of this software and associated documentation files (the "Software"),
%% to deal in the Software without restriction, including without limitation
%% the rights to use, copy, modify, merge, publish, distribute, sublicense,
%% and/or sell copies of the Software, and to permit persons to whom the
%% Software is furnished to do so, subject to the following conditions:

%% The above copyright notice and this permission notice shall be included in
%% all copies or substantial portions of the Software.

%% THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
%% IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
%% FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
%% AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
%% LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
%% FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
%% DEALINGS IN THE SOFTWARE.

-module(eradius_metrics_SUITE).
-compile(export_all).

-include_lib("stdlib/include/assert.hrl").
-include_lib("eradius/include/eradius_lib.hrl").
-include_lib("eradius/include/eradius_dict.hrl").
-include_lib("eradius/include/dictionary.hrl").
-include("eradius_test.hrl").

-define(SERVER, ?MODULE).
-define(SECRET, <<"secret">>).
-define(ATTRS_GOOD, [{?NAS_Identifier, "good"}, {?RStatus_Type, ?RStatus_Type_Start}]).
-define(ATTRS_BAD, [{?NAS_Identifier, "bad"}]).
-define(ATTRS_ERROR, [{?NAS_Identifier, "error"}]).
-define(ATTRS_AS_RECORD, [{#attribute{id = ?RStatus_Type}, ?RStatus_Type_Start}]).

%%%===================================================================
%%% Setup
%%%===================================================================

%% test callbacks
all() -> [good_requests, bad_requests, error_requests, request_with_attrs_as_record].

init_per_suite(Config) ->
    logger:set_primary_config(level, debug),
    application:load(eradius),
    application:set_env(eradius, unreachable_timeout, 2),
    {ok, _} = application:ensure_all_started(eradius),

    ok = start_client(Config),
    ok = start_servers(Config),

    Config.

end_per_suite(_Config) ->
    application:stop(eradius),
    application:stop(prometheus),
    ok.

init_per_testcase(_, Config) ->
    application:stop(prometheus),
    {ok, _} = application:ensure_all_started(prometheus),
    eradius_metrics_prometheus:init(#{}),
    Config.

%%%===================================================================
%%% Helper
%%%===================================================================

start_client(_Config) ->
    Backend = inet, Family = ipv4,
    ClientConfig =
        #{inet_backend => Backend,
          family => eradius_test_lib:inet_family(Family),
          ip => eradius_test_lib:localhost(Family, native),
          servers => #{good => #{ip => eradius_test_lib:localhost(Family, native),
                                 port => 1812,
                                 secret => ?SECRET,
                                 retries => 3},
                       bad => #{ip => eradius_test_lib:localhost(Family, native),
                                port => 1813,
                                secret => ?SECRET,
                                retries => 3},
                       error => #{ip => eradius_test_lib:localhost(Family, native),
                                  port => 1814,
                                  secret => ?SECRET,
                                  retries => 3}
                      },
          metrics_callback => fun eradius_metrics_prometheus:client_metrics_callback/3
         },
    case eradius_client_mngr:start_client({local, ?SERVER}, ClientConfig) of
        {ok, _} -> ok;
        {error, {already_started, _}} -> ok
    end.

start_servers(_Config) ->
    Family = ipv4,

    SrvOpts =
        fun(Name, NasId) ->
                #{handler => {?MODULE, []},
                  server_name => Name,
                  metrics_callback => fun eradius_metrics_prometheus:server_metrics_callback/3,
                  clients => #{eradius_test_lib:localhost(Family, native) =>
                                   #{secret => ?SECRET, client => NasId}}
                 }
        end,
    eradius:start_server(
      eradius_test_lib:localhost(Family, native), 1812, SrvOpts(good, <<"good_nas">>)),
    eradius:start_server(
      eradius_test_lib:localhost(Family, native), 1813, SrvOpts(bad, <<"bad_nas">>)),
    eradius:start_server(
      eradius_test_lib:localhost(Family, native), 1814, SrvOpts(error, <<"error_nas">>)),
    ok.

%%%===================================================================
%%% tests
%%%===================================================================

good_requests(_Config) ->
    Requests = [{request, access, access_accept},
                {accreq, accounting, accounting},
                {coareq, coa, coa_ack},
                {discreq, disconnect, disconnect_ack}],
    [check_single_request(good, EradiusRequestType, RequestType, ResponseType) ||
        {EradiusRequestType, RequestType, ResponseType} <- Requests ],
    check_total_requests(good, length(Requests)).

bad_requests(_Config) ->
    Requests = [{request, access, access_reject},
                {coareq, coa, coa_nak},
                {discreq, disconnect, disconnect_nak}],
    [check_single_request(bad, EradiusRequestType, RequestType, ResponseType) ||
        {EradiusRequestType, RequestType, ResponseType} <- Requests ],
    check_total_requests(bad, length(Requests)).

error_requests(_Config) ->
    check_single_request(error, request, access, access_accept).

request_with_attrs_as_record(_Config) ->
    ok = send_request(good, accreq, ?ATTRS_AS_RECORD,
                      #{server_name => good, client_name => test_records}),
    check_metric(accreq, eradius_client_accounting_requests_total, [{"server_name", good}, {"acct_type", start}], 1).

%% helpers
check_single_request(good, EradiusRequestType, _RequestType, _ResponseType) ->
    ok = send_request(good, EradiusRequestType, ?ATTRS_GOOD,
                      #{server_name => good, client_name => test}),

    Metrics = prometheus_text_format:format(default),
    ERadM = re:run(Metrics, "^eradius.*", [multiline, global, {capture, all, binary}]),
    ct:pal("Metrics:~n~p~n", [ERadM]),

    check_metric(eradius_client_access_requests_total, [{"server_name", good}], 1),
    check_metric_multi(EradiusRequestType, eradius_client_accounting_requests_total, [{"server_name", good}], 1),
    check_metric_multi({bad_type, EradiusRequestType}, eradius_client_accounting_requests_total, [{"server_name", good}, {"acct_type", bad_type}], 0),
    check_metric(EradiusRequestType, eradius_client_accounting_requests_total, [{"server_name", good}, {"acct_type", start}], 1),
    check_metric(EradiusRequestType, eradius_client_accounting_requests_total, [{"server_name", good}, {"acct_type", stop}], 0),
    check_metric(EradiusRequestType, eradius_client_accounting_requests_total, [{"server_name", good}, {"acct_type", update}], 0),
    check_metric(eradius_client_accept_responses_total, [{"server_name", good}], 1),
    check_metric(eradius_accept_responses_total, [{"server_name", good}], 1),
    check_metric(eradius_access_requests_total, [{"server_name", good}], 1),
    check_metric(eradius_server_status, true, [eradius_test_lib:localhost(ipv4, native), 1812]);
check_single_request(bad, EradiusRequestType, _RequestType, _ResponseType) ->
    ok = send_request(bad, EradiusRequestType, ?ATTRS_BAD,
                      #{server_name => bad, client_name => test}),
    check_metric(eradius_client_access_requests_total, [{"server_name", bad}], 1),
    check_metric(eradius_client_reject_responses_total, [{"server_name", bad}], 1),
    check_metric(eradius_access_requests_total, [{"server_name", bad}], 1),
    check_metric(eradius_reject_responses_total, [{"server_name", bad}], 1),
    check_metric(eradius_server_status, true, [eradius_test_lib:localhost(ipv4, native), 1813]);
check_single_request(error, EradiusRequestType, _RequestType, _ResponseType) ->
    ok = send_request(error, EradiusRequestType, ?ATTRS_ERROR,
                      #{server_name => error, client_name => test, timeout => 100,
                        failover => []}),
    check_metric(eradius_client_access_requests_total, [{"server_name", error}], 1),
    check_metric(eradius_client_retransmissions_total, [{"server_name", error}], 1),
    check_metric(eradius_access_requests_total, [{"server_name", error}], 1),
    check_metric(eradius_accept_responses_total, [{"server_name", error}], 1),
    check_metric(eradius_duplicated_requests_total, [{"server_name", error}], 1),
    check_metric(eradius_client_requests_total, [{"server_name", error}], 1),
    check_metric(eradius_requests_total, [{"server_name", error}], 2),
    check_metric(eradius_server_status, undefined, [eradius_test_lib:localhost(ipv4, native), 1812]),
    check_metric(eradius_server_status, undefined, [eradius_test_lib:localhost(ipv4, native), 1813]),
    check_metric(eradius_server_status, true, [eradius_test_lib:localhost(ipv4, native), 1814]),
    ok.

check_total_requests(good, N) ->
    check_metric(eradius_requests_total, [{"server_name", good}], N),
    check_metric(eradius_replies_total, [{"server_name", good}], N);
check_total_requests(bad, N) ->
    check_metric(eradius_requests_total, [{"server_name", bad}], N),
    check_metric(eradius_replies_total, [{"server_name", bad}], N).

check_metric_multi({bad_type, accreq}, Id, Labels, _Count) ->
    Values = prometheus_counter:values(default, Id),
    Filtered =
        lists:filter(
          fun({ValueLabels, _}) -> Labels -- ValueLabels =:= [] end,
          Values),
    ct:pal("check_metric-accreg-bad: ~p, ~p~nFetch: ~p~nFilteredL ~p~n",
           [Id, Labels, Values, Filtered]),
    ?assertEqual([], Filtered);
check_metric_multi(accreq, Id, Labels, Count) ->
    Values = prometheus_counter:values(default, Id),
    Filtered =
        lists:filter(
          fun({ValueLabels, _}) -> Labels -- ValueLabels =:= [] end,
          Values),
    ct:pal("check_metric-accreg-#1: ~p, ~p~nFetch: ~p~nFilteredL ~p~n",
           [Id, Labels, Values, Filtered]),
    case Filtered of
        [{_, Count}|_] -> ok;
        [] when Count =:= 0 -> ok;
        _ -> ?assertMatch([{_, Count}|_], Filtered)
    end;
check_metric_multi(_, _, _, _) ->
    ok.

check_metric(accreq, Id, Labels, Count) ->
    check_metric(Id, Labels, Count);
check_metric(_, _, _, _) ->
    ok.

check_metric(eradius_server_status = Id, Value, LabelValues) ->
    ct:pal("check_metric-#0 ~p: ~p, ~p", [Id, LabelValues, Value]),
    ?assertEqual(Value, prometheus_boolean:value(Id, LabelValues));
check_metric(Id, Labels, Count) ->
    Values = prometheus_counter:values(default, Id),
    Filtered =
        lists:filter(
          fun({ValueLabels, _}) -> Labels -- ValueLabels =:= [] end,
          Values),
    ct:pal("check_metric-#1: ~p, ~p, ~p~nFetch: ~p~nFilteredL ~p~n",
           [Id, Labels, Count, Values, Filtered]),
    case Filtered of
        [{_, Count}|_] -> ok;
        [] when Count =:= 0 -> ok;
        _ -> ?assertMatch([{_, Count}|_], Filtered)
    end.

send_request(ServerName, Command, Attrs, Opts) ->
    ok = eradius_dict:load_tables([dictionary]),
    Req0 = eradius_req:new(Command),
    Req = eradius_req:set_attrs(Attrs, Req0),
    send_radius_request(ServerName, Req, Opts).

send_radius_request(ServerName, Req, Opts) ->
    case eradius_client:send_request(?SERVER, ServerName, Req, Opts) of
        {{ok, _Result}, _ReqN} ->
            ok;
        Error ->
            Error
    end.

%% RADIUS NAS callbacks for 'good' requests
radius_request(#{cmd := request, client := <<"good_nas">>} = Req, _) ->
    {reply, Req#{cmd := accept}};
radius_request(#{cmd := accreq, client := <<"good_nas">>} = Req, _) ->
    {reply, Req#{cmd := accresp}};
radius_request(#{cmd := coareq, client := <<"good_nas">>} = Req, _) ->
    {reply, Req#{cmd := coaack}};
radius_request(#{cmd := discreq, client := <<"good_nas">>} = Req, _) ->
    {reply, Req#{cmd := discack}};

%% RADIUS NAS callbacks for 'bad' requests
radius_request(#{cmd := request, client := <<"bad_nas">>} = Req, _) ->
    {reply, Req#{cmd := reject}};
radius_request(#{cmd := coareq, client := <<"bad_nas">>} = Req, _) ->
    {reply, Req#{cmd := coanak}};
radius_request(#{cmd := discreq, client := <<"bad_nas">>} = Req, _) ->
    {reply, Req#{cmd := discnak}};

%% RADIUS NAS callbacks for 'error' requests
radius_request(#{cmd := request, client := <<"error_nas">>} = Req, _) ->
    timer:sleep(150), %% this will by default trigger one resend
    {reply, Req#{cmd := accept}}.
