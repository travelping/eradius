% Copyright (c) 2010-2017 by Travelping GmbH <info@travelping.com>

% Permission is hereby granted, free of charge, to any person obtaining a
% copy of this software and associated documentation files (the "Software"),
% to deal in the Software without restriction, including without limitation
% the rights to use, copy, modify, merge, publish, distribute, sublicense,
% and/or sell copies of the Software, and to permit persons to whom the
% Software is furnished to do so, subject to the following conditions:

% The above copyright notice and this permission notice shall be included in
% all copies or substantial portions of the Software.

% THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
% IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
% FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
% AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
% LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
% FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
% DEALINGS IN THE SOFTWARE.

-module(eradius_metrics_SUITE).
-compile(export_all).

-include_lib("eradius/include/eradius_lib.hrl").
-include_lib("eradius/include/eradius_dict.hrl").
-include_lib("eradius/include/dictionary.hrl").
-include("eradius_test.hrl").

-define(SECRET, <<"secret">>).
-define(ATTRS_GOOD, [{?NAS_Identifier, "good"}, {?RStatus_Type, ?RStatus_Type_Start}]).
-define(ATTRS_BAD, [{?NAS_Identifier, "bad"}]).
-define(ATTRS_ERROR, [{?NAS_Identifier, "error"}]).
-define(ATTRS_AS_RECORD, [{#attribute{id = ?RStatus_Type}, ?RStatus_Type_Start}]).
-define(LOCALHOST, eradius_test_handler:localhost(atom)).

%% test callbacks
all() -> [good_requests, bad_requests, error_requests, request_with_attrs_as_record].

init_per_suite(Config) ->
    application:load(eradius),
    EradiusConfig = [{radius_callback, ?MODULE},
                     {servers, [{good,  {eradius_test_handler:localhost(ip), [1812]}},  %% for 'positive' responses, e.g. access accepts
                                {bad,   {eradius_test_handler:localhost(ip), [1813]}},  %% for 'negative' responses, e.g. coa naks
                                {error, {eradius_test_handler:localhost(ip), [1814]}}   %% here things go wrong, e.g. duplicate requests
                               ]},
                     {session_nodes, [node()]},
                     {servers_pool,
                      [{test_pool, [{eradius_test_handler:localhost(tuple), 1814, ?SECRET},
                                    {eradius_test_handler:localhost(tuple), 1813, ?SECRET},
                                    {eradius_test_handler:localhost(tuple), 1812, ?SECRET}]}]
                     },
                     {good, [
                             { {"good", [] }, [{"127.0.0.2", ?SECRET, [{nas_id, <<"good_nas">>}]}] }
                            ]},
                     {bad, [
                              { {"bad", [] }, [{"127.0.0.2", ?SECRET, [{nas_id, <<"bad_nas">>}]}] }
                             ]},
                     {error, [
                              { {"error", [] }, [{"127.0.0.2", ?SECRET, [{nas_id, <<"error_nas">>}]}] }
                             ]},
                     {tables, [dictionary]},
                     {client_ip, {127,0,0,2}},
                     {client_ports, 20},
                     {counter_aggregator, false},
                     {server_status_metrics_enabled, true}
                    ],
    [application:set_env(eradius, Key, Value) || {Key, Value} <- EradiusConfig],
    application:set_env(prometheus, collectors, [eradius_prometheus_collector]),
    % prometheus is not included directly to eradius but prometheus_eradius_collector
    % should include it
    application:ensure_all_started(prometheus),
    {ok, _} = application:ensure_all_started(eradius),
    spawn(fun() ->
                  eradius:modules_ready([?MODULE]),
                  timer:sleep(infinity)
          end),
    Config.

end_per_suite(_Config) ->
    application:stop(eradius),
    application:stop(prometheus),
    ok.

init_per_testcase(_, Config) ->
    eradius_client:init_server_status_metrics(),
    Config.

%% tests
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
    ok = send_request(accreq, eradius_test_handler:localhost(tuple), 1812, ?ATTRS_AS_RECORD, [{server_name, good}, {client_name, test_records}]),
    ok = check_metric(accreq, client_accounting_requests_total, [{server_name, good}, {client_name, test_records}, {acct_type, start}], 1).

%% helpers
check_single_request(good, EradiusRequestType, _RequestType, _ResponseType) ->
    ok = send_request(EradiusRequestType, eradius_test_handler:localhost(tuple), 1812, ?ATTRS_GOOD, [{server_name, good}, {client_name, test}]),
    ok = check_metric(client_access_requests_total, [{server_name, good}], 1),
    ok = check_metric_multi(EradiusRequestType, client_accounting_requests_total, [{server_name, good}], 1),
    ok = check_metric_multi({bad_type, EradiusRequestType}, client_accounting_requests_total, [{server_name, good}, {acct_type, bad_type}], 0),
    ok = check_metric(EradiusRequestType, client_accounting_requests_total, [{server_name, good}, {acct_type, start}], 1),
    ok = check_metric(EradiusRequestType, client_accounting_requests_total, [{server_name, good}, {acct_type, stop}], 0),
    ok = check_metric(EradiusRequestType, client_accounting_requests_total, [{server_name, good}, {acct_type, update}], 0),
    ok = check_metric(client_accept_responses_total, [{server_name, good}], 1),
    ok = check_metric(accept_responses_total, [{server_name, good}], 1),
    ok = check_metric(access_requests_total, [{server_name, good}], 1),
    ok = check_metric(server_status, true, [eradius_test_handler:localhost(tuple), 1812]);
check_single_request(bad, EradiusRequestType, _RequestType, _ResponseType) ->
    ok = send_request(EradiusRequestType, eradius_test_handler:localhost(tuple), 1813, ?ATTRS_BAD, [{server_name, bad}, {client_name, test}]),
    ok = check_metric(client_access_requests_total, [{server_name, bad}], 1),
    ok = check_metric(client_reject_responses_total, [{server_name, bad}], 1),
    ok = check_metric(access_requests_total, [{server_name, bad}], 1),
    ok = check_metric(reject_responses_total, [{server_name, bad}], 1),
    ok = check_metric(server_status, true, [eradius_test_handler:localhost(tuple), 1813]);
check_single_request(error, EradiusRequestType, _RequestType, _ResponseType) ->
    ok = send_request(EradiusRequestType, eradius_test_handler:localhost(tuple), 1814, ?ATTRS_ERROR,
                      [{server_name, error}, {client_name, test}, {timeout, 1000},
                       {failover, [{eradius_test_handler:localhost(tuple), 1812, ?SECRET}]}]),
    ok = check_metric(client_access_requests_total, [{server_name, error}], 1),
    ok = check_metric(client_retransmissions_total, [{server_name, error}], 1),
    ok = check_metric(access_requests_total, [{server_name, error}], 1),
    ok = check_metric(accept_responses_total, [{server_name, error}], 1),
    ok = check_metric(duplicated_requests_total, [{server_name, error}], 1),
    ok = check_metric(client_requests_total, [{server_name, error}], 1),
    ok = check_metric(requests_total, [{server_name, error}], 2),
    ok = check_metric(server_status, false, [eradius_test_handler:localhost(tuple), 1812]),
    ok = check_metric(server_status, false, [eradius_test_handler:localhost(tuple), 1813]),
    ok = check_metric(server_status, true, [eradius_test_handler:localhost(tuple), 1814]),
    ok = check_metric(server_status, undefined, [eradius_test_handler:localhost(tuple), 1815]).


check_total_requests(good, N) ->
    ok = check_metric(requests_total, [{server_name, good}], N),
    ok = check_metric(replies_total, [{server_name, good}], N);
check_total_requests(bad, N) ->
    ok = check_metric(requests_total, [{server_name, bad}], N),
    ok = check_metric(replies_total, [{server_name, bad}], N).

check_metric_multi({bad_type, accreq}, Id, Labels, _) ->
    case eradius_prometheus_collector:fetch_counter(Id, Labels) of
        [] ->
            ok;
        _ ->
            {error, Id, Labels}
    end;
check_metric_multi(accreq, Id, Labels, Count) ->
    case eradius_prometheus_collector:fetch_counter(Id, Labels) of
        [{Count, _} | _] ->
            ok;
        _ ->
            {error, Id, Count}
    end;
check_metric_multi(_, _, _, _) ->
    ok.

check_metric(accreq, Id, Labels, Count) ->
    check_metric(Id, Labels, Count);
check_metric(_, _, _, _) ->
    ok.

check_metric(server_status, Value, Labels) ->
    ?equal(Value, prometheus_boolean:value(server_status, Labels)),
    ok;
check_metric(Id, Labels, Count) ->
    case eradius_prometheus_collector:fetch_counter(Id, Labels) of
        [{Count, _}] ->
            ok;
        _ ->
            {error, Id, Count}
    end.

send_request(Command, IP, Port, Attrs, Opts) ->
    ok = eradius_dict:load_tables([dictionary]),
    Request = eradius_lib:set_attributes(#radius_request{cmd = Command}, Attrs),
    send_radius_request(IP, Port, ?SECRET, Request, Opts).

send_radius_request(Ip, Port, Secret, Request, Opts) ->
    case eradius_client:send_request({Ip, Port, Secret}, Request, Opts) of
        {ok, _Result, _Auth} ->
            ok;
        Error ->
            Error
    end.

%% RADIUS NAS callbacks for 'good' requests
radius_request(#radius_request{cmd = request}, #nas_prop{nas_id = <<"good_nas">>}, _) ->
    {reply, #radius_request{cmd = accept}};
radius_request(#radius_request{cmd = accreq}, #nas_prop{nas_id = <<"good_nas">>}, _) ->
    {reply, #radius_request{cmd = accresp}};
radius_request(#radius_request{cmd = coareq}, #nas_prop{nas_id = <<"good_nas">>}, _) ->
    {reply, #radius_request{cmd = coaack}};
radius_request(#radius_request{cmd = discreq}, #nas_prop{nas_id = <<"good_nas">>}, _) ->
    {reply, #radius_request{cmd = discack}};

%% RADIUS NAS callbacks for 'bad' requests
radius_request(#radius_request{cmd = request}, #nas_prop{nas_id = <<"bad_nas">>}, _) ->
    {reply, #radius_request{cmd = reject}};
radius_request(#radius_request{cmd = coareq}, #nas_prop{nas_id = <<"bad_nas">>}, _) ->
    {reply, #radius_request{cmd = coanak}};
radius_request(#radius_request{cmd = discreq}, #nas_prop{nas_id = <<"bad_nas">>}, _) ->
    {reply, #radius_request{cmd = discnak}};

%% RADIUS NAS callbacks for 'error' requests
radius_request(#radius_request{cmd = request}, #nas_prop{nas_id = <<"error_nas">>}, _) ->
    timer:sleep(1500), %% this will by default trigger one resend
    {reply, #radius_request{cmd = accept}}.

