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

-define(CLIENT_ID_FORMAT_GOOD(Name, Type, Unit), list_to_binary(["eradius_radius_", Name, "_", Type, "_client_undefined_", Unit])).
-define(CLIENT_ID_FORMAT_BAD(Name, Type, Unit), list_to_binary(["eradius_radius_", Name, "_", Type, "_client_undefined_", Unit])).
-define(CLIENT_ID_FORMAT_ERROR(Name, Type, Unit), list_to_binary(["eradius_radius_", Name, "_", Type, "_client_undefined_", Unit])).
-define(SERVER_ID_FORMAT_GOOD(Name, Type, Unit), list_to_binary(["eradius_radius_", Name, "_", Type, "_server_undefined_", Unit])).
-define(SERVER_ID_FORMAT_GOOD_TOTAL(Name, Type, Unit), list_to_binary(["eradius_radius_", Name, "_", Type, "_server_total_undefined_undefined_", Unit])).
-define(SERVER_ID_FORMAT_BAD(Name, Type, Unit), list_to_binary(["eradius_radius_", Name,  "_", Type, "_server_undefined_", Unit])).
-define(SERVER_ID_FORMAT_BAD_TOTAL(Name, Type, Unit), list_to_binary(["eradius_radius_", Name, "_", Type, "_server_total_undefined_undefined_", Unit])).
-define(SERVER_ID_FORMAT_ERROR(Name, Type, Unit), list_to_binary(["eradius_radius_", Name, "_", Type, "_server_undefined_", Unit])).


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
    ok = check_metric(?CLIENT_ID_FORMAT_GOOD("request", atom_to_list(RequestType), "counter"),
                      ["test", "127_0_0_2", "good", eradius_test_handler:localhost(atom), "1812"],
                      1),
    ok = check_metric(?CLIENT_ID_FORMAT_GOOD("response", atom_to_list(ResponseType), "counter"),
                      ["test", "127_0_0_2", "good", eradius_test_handler:localhost(atom), "1812"],
                      1),
    ok = check_metric(?SERVER_ID_FORMAT_GOOD("request", atom_to_list(RequestType), "counter"),
                      ["good", eradius_test_handler:localhost(atom), "1812", "good_nas", "127_0_0_2"],
                      1),
    ok = check_metric(?SERVER_ID_FORMAT_GOOD("response", atom_to_list(ResponseType), "counter"),
                      ["good", eradius_test_handler:localhost(atom), "1812", "good_nas", "127_0_0_2"],
                      1),
    ok = check_metric(?SERVER_ID_FORMAT_GOOD_TOTAL("request", atom_to_list(RequestType), "counter"),
                      ["good", eradius_test_handler:localhost(atom), "1812"],
                      1),
    ok = check_metric(?SERVER_ID_FORMAT_GOOD_TOTAL("response", atom_to_list(ResponseType), "counter"),
                      ["good", eradius_test_handler:localhost(atom), "1812"],
                      1);
check_single_request(bad, EradiusRequestType, RequestType, ResponseType) ->
    ok = send_request(EradiusRequestType, eradius_test_handler:localhost(tuple), 1813, ?ATTRS_BAD, [{server_name, bad}, {client_name, test}]),
    ok = check_metric(?CLIENT_ID_FORMAT_BAD("request", atom_to_list(RequestType), "counter"),
                      ["test", "127_0_0_2", "bad", eradius_test_handler:localhost(atom), "1813"],
                      1),
    ok = check_metric(?CLIENT_ID_FORMAT_BAD("response", atom_to_list(ResponseType), "counter"),
                      ["test", "127_0_0_2", "bad", eradius_test_handler:localhost(atom), "1813"],
                      1),
    ok = check_metric(?SERVER_ID_FORMAT_BAD("request", atom_to_list(RequestType), "counter"),
                      ["bad", eradius_test_handler:localhost(atom), "1813", "bad_nas", "127_0_0_2"],
                      1),
    ok = check_metric(?SERVER_ID_FORMAT_BAD("response", atom_to_list(ResponseType), "counter"),
                      ["bad", eradius_test_handler:localhost(atom), "1813", "bad_nas", "127_0_0_2"],
                      1),
    ok = check_metric(?SERVER_ID_FORMAT_BAD_TOTAL("request", atom_to_list(RequestType), "counter"),
                      ["bad", eradius_test_handler:localhost(atom), "1813"],
                      1),
    ok = check_metric(?SERVER_ID_FORMAT_BAD_TOTAL("response", atom_to_list(ResponseType), "counter"),
                      ["bad", eradius_test_handler:localhost(atom), "1813"],
                      1);
check_single_request(error, EradiusRequestType, RequestType, ResponseType) ->
    ok = send_request(EradiusRequestType, eradius_test_handler:localhost(tuple), 1814, ?ATTRS_ERROR,
                      [{server_name, error}, {client_name, test}, {timeout, 1000}]),
    ok = check_metric(?CLIENT_ID_FORMAT_ERROR("request", atom_to_list(RequestType), "counter"),
                      ["test", "127_0_0_2", "error", eradius_test_handler:localhost(atom), "1814"],
                      1),
    ok = check_metric(?CLIENT_ID_FORMAT_ERROR("request", "retransmission", "counter"),
                      ["test", "127_0_0_2", "error", eradius_test_handler:localhost(atom), "1814"],
                      1),
    ok = check_metric(?SERVER_ID_FORMAT_ERROR("request", atom_to_list(RequestType), "counter"),
                      ["error", eradius_test_handler:localhost(atom), "1814", "error_nas", "127_0_0_2"],
                      1),
    ok = check_metric(?SERVER_ID_FORMAT_ERROR("response", atom_to_list(ResponseType), "counter"),
                      ["error", eradius_test_handler:localhost(atom), "1814", "error_nas", "127_0_0_2"],
                      1),
    ok = check_metric(?SERVER_ID_FORMAT_ERROR("request", "duplicate", "counter"),
                      ["error", eradius_test_handler:localhost(atom), "1814", "error_nas", "127_0_0_2"],
                      1),
    %% retransmissions don't count into client statistics
    ok = check_metric(?CLIENT_ID_FORMAT_ERROR("request", "total", "counter"),
                      ["test", "127_0_0_2", "error", eradius_test_handler:localhost(atom), "1814"],
                      1),
    ok = check_metric(?SERVER_ID_FORMAT_ERROR("request", "total", "counter"),
                      ["error", eradius_test_handler:localhost(atom), "1814", "error_nas", "127_0_0_2"],
                      2).

check_total_requests(good, N) ->
    ok = check_metric(?SERVER_ID_FORMAT_GOOD_TOTAL("request", "total", "counter"),
                      ["good", eradius_test_handler:localhost(atom), "1812"],
                      N),
    ok = check_metric(?SERVER_ID_FORMAT_GOOD_TOTAL("response", "total", "counter"),
                      ["good", eradius_test_handler:localhost(atom), "1812"],
                      N);
check_total_requests(bad, N) ->
    ok = check_metric(?SERVER_ID_FORMAT_BAD_TOTAL("request", "total", "counter"),
                      ["bad", eradius_test_handler:localhost(atom), "1813"],
                      N),
    ok = check_metric(?SERVER_ID_FORMAT_BAD_TOTAL("response", "total", "counter"),
                      ["bad", eradius_test_handler:localhost(atom), "1813"],
                      N).

check_metric(Id, Labels, Count) ->
    case prometheus_counter:value(Id, Labels) of
	Count ->
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

