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

-module(eradius_logtest).

-export([start/0, test/0, radius_request/3, validate_arguments/1, test_client/0, test_client/1, test_proxy/0, test_proxy/1]).
-import(eradius_lib, [get_attr/2]).

-include_lib("eradius/include/eradius_lib.hrl").
-include_lib("eradius/include/eradius_dict.hrl").
-include_lib("eradius/include/dictionary.hrl").
-include_lib("eradius/include/dictionary_3gpp.hrl").

-define(ALLOWD_USERS, [undefined, <<"user">>, <<"user@domain">>, <<"proxy_test">>]).
-define(SECRET, <<"secret">>).
-define(SECRET2, <<"proxy_secret">>).
-define(SECRET3, <<"test_secret">>).

-define(CLIENT_REQUESTS_COUNT, 1).
-define(CLIENT_PROXY_REQUESTS_COUNT, 4).

-define(NAS1_ACCESS_REQS, 1).
-define(NAS2_ACCESS_REQS, 4).

start() ->
    application:load(eradius),
    ProxyConfig = [{default_route, {eradius_test_lib:localhost(tuple), 1813, ?SECRET}},
                   {options, [{type, realm}, {strip, true}, {separator, "@"}]},
                   {routes, [{"test", {eradius_test_lib:localhost(tuple), 1815, ?SECRET3}}
                            ]}
                  ],
    Config = [{radius_callback, eradius_logtest},
              {servers, [{root,  {eradius_test_lib:localhost(ip), [1812, 1813]}},
                         {test,  {eradius_test_lib:localhost(ip), [1815]}},
                         {proxy, {eradius_test_lib:localhost(ip), [11812, 11813]}}
                        ]},
              {session_nodes, [node()]},
              {root, [
                      { {eradius_logtest, "root", [] }, [{"127.0.0.1/24", ?SECRET, [{nas_id, <<"Test_Nas_Id">>}]}] }
                     ]},
              {test, [
                      { {eradius_logtest, "test", [] }, [{eradius_test_lib:localhost(ip), ?SECRET3, [{nas_id, <<"Test_Nas_Id_test">>}]}] }
                     ]},
              {proxy, [
                       { {eradius_proxy, "proxy", ProxyConfig }, [{eradius_test_lib:localhost(ip), ?SECRET2, [{nas_id, <<"Test_Nas_proxy">>}]}] }
                      ]}
             ],
    [application:set_env(eradius, Key, Value) || {Key, Value} <- Config],
    {ok, _} = application:ensure_all_started(eradius),
    spawn(fun() ->
                  eradius:modules_ready([?MODULE, eradius_proxy]),
                  timer:sleep(infinity)
          end),
    ok.

test() ->
    %% application:set_env(lager, handlers, [{lager_journald_backend, []}]),
    eradius_logtest:start(),
    eradius_logtest:test_client(),
    eradius_logtest:test_proxy(),
    ok.

radius_request(#radius_request{cmd = request} = Request, _NasProp, _) ->
    UserName = get_attr(Request, ?User_Name),
    case lists:member(UserName, ?ALLOWD_USERS) of
        true ->
            {reply, #radius_request{cmd = accept}};
        false ->
            {reply, #radius_request{cmd = reject}}
    end;

radius_request(#radius_request{cmd = accreq}, _NasProp, _) ->
    {reply, #radius_request{cmd = accresp}}.

validate_arguments(_Args) -> true.

test_client() ->
    test_client(request).

test_client(Command) ->
    eradius_dict:load_tables([dictionary, dictionary_3gpp]),
    Request = eradius_lib:set_attributes(#radius_request{cmd = Command, msg_hmac = true}, attrs("user")),
    send_request(eradius_test_lib:localhost(tuple), 1813, ?SECRET, Request).

test_proxy() ->
    test_proxy(request).

test_proxy(Command) ->
    eradius_dict:load_tables([dictionary, dictionary_3gpp]),
    send_request(eradius_test_lib:localhost(tuple), 11813, ?SECRET2, #radius_request{cmd = Command}),
    Request = eradius_lib:set_attributes(#radius_request{cmd = Command, msg_hmac = true}, attrs("proxy_test")),
    send_request(eradius_test_lib:localhost(tuple), 11813, ?SECRET2, Request),
    Request2 = eradius_lib:set_attributes(#radius_request{cmd = Command, msg_hmac = true}, attrs("user@test")),
    send_request(eradius_test_lib:localhost(tuple), 11813, ?SECRET2, Request2),
    Request3 = eradius_lib:set_attributes(#radius_request{cmd = Command, msg_hmac = true}, attrs("user@domain@test")),
    send_request(eradius_test_lib:localhost(tuple), 11813, ?SECRET2, Request3).

send_request(Ip, Port, Secret, Request) ->
    case eradius_client:send_request({Ip, Port, Secret}, Request) of
        {ok, Result, Auth} ->
            eradius_lib:decode_request(Result, Secret, Auth);
        Error ->
            Error
    end.

attrs(User) ->
    [{?NAS_Port, 8888},
     {?User_Name, User},
     {?NAS_IP_Address, {88,88,88,88}},
     {?Calling_Station_Id, "0123456789"},
     {?Service_Type, 2},
     {?Framed_Protocol, 7},
     {30,"some.id.com"},                  %Called-Station-Id
     {61,18},                             %NAS_PORT_TYPE
     {{10415,1}, "1337"},                 %X_3GPP-IMSI
     {{127,42},18}                        %Unbekannte ID
    ].
