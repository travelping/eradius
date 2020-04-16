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

-define(SECRET, <<"secret">>).
-define(ATTRS_GOOD, [{?NAS_Identifier, "good"}]).
-define(ATTRS_BAD, [{?NAS_Identifier, "bad"}]).
-define(ATTRS_ERROR, [{?NAS_Identifier, "error"}]).
-define(LOCALHOST, eradius_test_handler:localhost(atom)).
-define(CLIENT_ID_FORMAT_GOOD(Name, Type, Unit), [eradius, radius, Name, Type, client, test, '127.0.0.2', undefined, good, eradius_test_handler:localhost(atom), '1812', Unit]).
-define(CLIENT_ID_FORMAT_BAD(Name, Type, Unit), [eradius, radius, Name, Type, client, test, '127.0.0.2', undefined, bad, eradius_test_handler:localhost(atom), '1813', Unit]).
-define(CLIENT_ID_FORMAT_ERROR(Name, Type, Unit), [eradius, radius, Name, Type, client, test, '127.0.0.2', undefined, error, eradius_test_handler:localhost(atom), '1814', Unit]).
-define(SERVER_ID_FORMAT_GOOD(Name, Type, Unit), [eradius, radius, Name, Type, server, good, eradius_test_handler:localhost(atom), '1812', good_nas, '127.0.0.2', undefined, Unit]).
-define(SERVER_ID_FORMAT_GOOD_TOTAL(Name, Type, Unit), [eradius, radius, Name, Type, server, good, eradius_test_handler:localhost(atom), '1812', total, undefined, undefined, Unit]).
-define(SERVER_ID_FORMAT_BAD(Name, Type, Unit), [eradius, radius, Name, Type, server, bad, eradius_test_handler:localhost(atom), '1813', bad_nas, '127.0.0.2', undefined, Unit]).
-define(SERVER_ID_FORMAT_BAD_TOTAL(Name, Type, Unit), [eradius, radius, Name, Type, server, bad, eradius_test_handler:localhost(atom), '1813', total, undefined, undefined, Unit]).
-define(SERVER_ID_FORMAT_ERROR(Name, Type, Unit), [eradius, radius, Name, Type, server, error, eradius_test_handler:localhost(atom), '1814', error_nas, '127.0.0.2', undefined, Unit]).


%% test callbacks
all() -> [good_requests, bad_requests, error_requests].

init_per_suite(Config) ->
    application:load(eradius),
    EradiusConfig = [{radius_callback, ?MODULE},
                     {servers, [{good,  {eradius_test_handler:localhost(ip), [1812]}},  %% for 'positive' responses, e.g. access accepts
                                {bad,  {eradius_test_handler:localhost(ip), [1813]}},   %% for 'negative' responses, e.g. coa naks
                                {error,  {eradius_test_handler:localhost(ip), [1814]}}  %% here things go wrong, e.g. duplicate requests
                               ]},
                     {session_nodes, [node()]},
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
                     {metrics, [{enabled, [server, nas, client]},
                                {subscribe_opts, []}]},
                     {client_ip, {127,0,0,2}},
                     {client_ports, 20}
                    ],
    [application:set_env(eradius, Key, Value) || {Key, Value} <- EradiusConfig],
    {ok, _} = application:ensure_all_started(eradius),
    spawn(fun() ->
                  eradius:modules_ready([?MODULE]),
                  timer:sleep(infinity)
          end),
    Config.

end_per_suite(_Config) ->
    application:stop(eradius),
    ok.


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


%% helpers
check_single_request(good, EradiusRequestType, RequestType, ResponseType) ->
    ok = send_request(EradiusRequestType, eradius_test_handler:localhost(tuple), 1812, ?ATTRS_GOOD, [{server_name, good}, {client_name, test}]),
    ok = check_metric(?CLIENT_ID_FORMAT_GOOD(request, RequestType, counter), 1),
    ok = check_metric(?CLIENT_ID_FORMAT_GOOD(response, ResponseType, counter), 1),
    ok = check_metric(?SERVER_ID_FORMAT_GOOD(request, RequestType, counter), 1),
    ok = check_metric(?SERVER_ID_FORMAT_GOOD(response, ResponseType, counter), 1),
    ok = check_metric(?SERVER_ID_FORMAT_GOOD_TOTAL(request, RequestType, counter), 1),
    ok = check_metric(?SERVER_ID_FORMAT_GOOD_TOTAL(response, ResponseType, counter), 1);
check_single_request(bad, EradiusRequestType, RequestType, ResponseType) ->
    ok = send_request(EradiusRequestType, eradius_test_handler:localhost(tuple), 1813, ?ATTRS_BAD, [{server_name, bad}, {client_name, test}]),
    ok = check_metric(?CLIENT_ID_FORMAT_BAD(request, RequestType, counter), 1),
    ok = check_metric(?CLIENT_ID_FORMAT_BAD(response, ResponseType, counter), 1),
    ok = check_metric(?SERVER_ID_FORMAT_BAD(request, RequestType, counter), 1),
    ok = check_metric(?SERVER_ID_FORMAT_BAD(response, ResponseType, counter), 1),
    ok = check_metric(?SERVER_ID_FORMAT_BAD_TOTAL(request, RequestType, counter), 1),
    ok = check_metric(?SERVER_ID_FORMAT_BAD_TOTAL(response, ResponseType, counter), 1);
check_single_request(error, EradiusRequestType, RequestType, ResponseType) ->
    ok = send_request(EradiusRequestType, eradius_test_handler:localhost(tuple), 1814, ?ATTRS_ERROR, [{server_name, error}, {client_name, test}, {timeout, 1000}]),
    ok = check_metric(?CLIENT_ID_FORMAT_ERROR(request, RequestType, counter), 1),
    ok = check_metric(?CLIENT_ID_FORMAT_ERROR(request, retransmission, counter), 1),
    ok = check_metric(?SERVER_ID_FORMAT_ERROR(request, RequestType, counter), 1),
    ok = check_metric(?SERVER_ID_FORMAT_ERROR(response, ResponseType, counter), 1),
    ok = check_metric(?SERVER_ID_FORMAT_ERROR(request, duplicate, counter), 1),
    %% retransmissions don't count into client statistics
    ok = check_metric(?CLIENT_ID_FORMAT_ERROR(request, total, counter), 1),
    ok = check_metric(?SERVER_ID_FORMAT_ERROR(request, total, counter), 2).

check_total_requests(good, N) ->
    ok = check_metric(?SERVER_ID_FORMAT_GOOD_TOTAL(request, total, counter), N),
    ok = check_metric(?SERVER_ID_FORMAT_GOOD_TOTAL(response, total, counter), N);
check_total_requests(bad, N) ->
    ok = check_metric(?SERVER_ID_FORMAT_BAD_TOTAL(request, total, counter), N),
    ok = check_metric(?SERVER_ID_FORMAT_BAD_TOTAL(response, total, counter), N).

check_metric(Id, Count) ->
    case exometer:get_value(Id) of
        {ok, [{value, Count} | _]} ->
            ok;
        Else ->
            {error, {Count, Else}}
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

%% RADIUS NAS callbacks for 'bad' requests
radius_request(#radius_request{cmd = request}, #nas_prop{nas_id = <<"error_nas">>}, _) ->
    timer:sleep(1500), %% this will by default trigger one resend
    {reply, #radius_request{cmd = accept}}.

