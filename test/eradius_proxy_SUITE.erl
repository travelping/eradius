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

-module(eradius_proxy_SUITE).
-compile(export_all).
-include("eradius_lib.hrl").
-include("dictionary.hrl").
-include("eradius_test.hrl").

all() -> [
    resolve_routes_test,
    validate_arguments_test,
    validate_options_test,
    new_request_test,
    get_key_test,
    strip_test
    ].

resolve_routes_test(_) ->
    DefaultRoute = {eradius_test_handler:localhost(tuple), 1813, <<"secret">>},
    Prod = {eradius_test_handler:localhost(tuple), 1812, <<"prod">>},
    Test = {eradius_test_handler:localhost(tuple), 11813, <<"test">>},
    Dev = {eradius_test_handler:localhost(tuple), 11814, <<"dev">>},
    {ok, R1} = re:compile("prod"),
    {ok, R2} = re:compile("test"),
    {ok, R3} = re:compile("^dev_.*"),
    Routes = [{R1, Prod}, {R2, Test, [{pool, test_pool}]}, {R3, Dev}],
    % default
    ?equal({undefined, DefaultRoute}, eradius_proxy:resolve_routes(undefined, DefaultRoute, Routes,[])),
    ?equal({"user", DefaultRoute}, eradius_proxy:resolve_routes(<<"user">>, DefaultRoute, Routes, [])),
    ?equal({"user@prod", Prod}, eradius_proxy:resolve_routes(<<"user@prod">>, DefaultRoute, Routes,[])),
    ?equal({"user@test", {Test, [{pool, test_pool}]}}, eradius_proxy:resolve_routes(<<"user@test">>, DefaultRoute, Routes,[])),
    % strip
    Opts = [{strip, true}],
    ?equal({"user", DefaultRoute}, eradius_proxy:resolve_routes(<<"user">>, DefaultRoute, Routes, Opts)),
    ?equal({"user", Prod}, eradius_proxy:resolve_routes(<<"user@prod">>, DefaultRoute, Routes, Opts)),
    ?equal({"user", {Test, [{pool, test_pool}]}}, eradius_proxy:resolve_routes(<<"user@test">>, DefaultRoute, Routes, Opts)),
    ?equal({"user", Dev}, eradius_proxy:resolve_routes(<<"user@dev_server">>, DefaultRoute, Routes, Opts)),
    ?equal({"user", DefaultRoute}, eradius_proxy:resolve_routes(<<"user@dev-server">>, DefaultRoute, Routes, Opts)),

    % prefix
    Opts1 = [{type, prefix}, {separator, "/"}],
    ?equal({"user/example", DefaultRoute}, eradius_proxy:resolve_routes(<<"user/example">>, DefaultRoute, Routes, Opts1)),
    ?equal({"test/user", {Test, [{pool, test_pool}]}}, eradius_proxy:resolve_routes(<<"test/user">>, DefaultRoute, Routes, Opts1)),
    % prefix and strip
    Opts2 = Opts ++ Opts1,
    ?equal({"example", DefaultRoute}, eradius_proxy:resolve_routes(<<"user/example">>, DefaultRoute, Routes, Opts2)),
    ?equal({"user", {Test, [{pool, test_pool}]}}, eradius_proxy:resolve_routes(<<"test/user">>, DefaultRoute, Routes, Opts2)),
    ok.

validate_arguments_test(_) ->
    GoodConfig = [{default_route, {eradius_test_handler:localhost(tuple), 1813, <<"secret">>}},
                  {options, [{type, realm}, {strip, true}, {separator, "@"}]},
                  {routes, [{"test_1", {eradius_test_handler:localhost(tuple), 1815, <<"secret1">>}, [{pool, test_pool}]},
                            {"test_2", {<<"localhost">>, 1816, <<"secret2">>}}
                           ]}
                 ],
    GoodOldConfig = [{default_route, {eradius_test_handler:localhost(tuple), 1813, <<"secret">>}, test_pool},
		     {options, [{type, realm}, {strip, true}, {separator, "@"}]},
		     {routes, [{"test_1", {eradius_test_handler:localhost(tuple), 1815, <<"secret1">>}, [{pool, test_pool}]},
			       {"test_2", {<<"localhost">>, 1816, <<"secret2">>}}
			      ]}
		    ],

    BadConfig = [{default_route, {eradius_test_handler:localhost(tuple), 1813, <<"secret">>}},
                 {options, [{type, abc}]}
                 ],
    BadConfig1 = [{default_route, {eradius_test_handler:localhost(tuple), 0, <<"secret">>}}],
    BadConfig2 = [{default_route, {abc, 123, <<"secret">>}}],
    BadConfig3 = [{default_route, {eradius_test_handler:localhost(tuple), 1813, <<"secret">>}},
                  {options, [{type, realm}, {strip, true}, {separator, "@"}]},
                  {routes,  [{"test_1", {wrong_ip, 1815, <<"secret1">>}},
                             {"test_2", {<<"localhost">>, 1816, <<"secret2">>}}
                            ]}],
    BadConfig4 = [{default_route, {eradius_test_handler:localhost(tuple), 1813, <<"secret">>}},
                  {options, [{type, realm}, {strip, true}, {separator, "@"}, {timeout, "wrong"}]},
                  {routes,  [{"test", {wrong_ip, 1815, <<"secret1">>}},
                             {"test_2", {<<"localhost">>, 1816, <<"secret2">>}}
                            ]}],
    BadConfig5 = [{default_route, {eradius_test_handler:localhost(tuple), 1813, <<"secret">>}},
                  {options, [{type, realm}, {strip, true}, {separator, "@"}, {retries, "wrong"}]},
                  {routes,  [{"test", {wrong_ip, 1815, <<"secret1">>}},
                             {"test_2", {"localhost", 1816, <<"secret2">>}}
                            ]}],
    BadConfig6 = [{default_route, {eradius_test_handler:localhost(tuple), 1813, <<"secret">>, [{pool, "wrong_pool"}]}}],
    BadConfig7 = [{default_route, {eradius_test_handler:localhost(tuple), 1813, <<"secret">>}},
                  {routes,  [{"test", {wrong_ip, 1815, <<"secret1">>}, [{pool, "wrong_pool"}]}]}],
    {Result, ConfigData} = eradius_proxy:validate_arguments(GoodConfig),
    ?equal(true, Result),
    {Valid, _} = eradius_proxy:validate_arguments(GoodOldConfig),
    ?equal(true, Valid),
    {routes, Routes} = lists:keyfind(routes, 1, ConfigData),
    [{{CompiledRegexp_1, _, _, _, _}, _, _}, {{CompiledRegexp_2, _, _, _, _}, _, _}] = Routes,
    ?equal(re_pattern, CompiledRegexp_1),
    ?equal(re_pattern, CompiledRegexp_2),
    ?equal(default_route, eradius_proxy:validate_arguments([])),
    ?equal(options, eradius_proxy:validate_arguments(BadConfig)),
    ?equal(default_route, eradius_proxy:validate_arguments(BadConfig1)),
    ?equal(default_route, eradius_proxy:validate_arguments(BadConfig2)),
    ?equal(routes, eradius_proxy:validate_arguments(BadConfig3)),
    ?equal(options, eradius_proxy:validate_arguments(BadConfig4)),
    ?equal(options, eradius_proxy:validate_arguments(BadConfig5)),
    ?equal(default_route, eradius_proxy:validate_arguments(BadConfig6)),
    ?equal(routes, eradius_proxy:validate_arguments(BadConfig7)),
    ok.

validate_options_test(_) ->
    DefaultOptions = [{type, realm}, {strip, false}, {separator, "@"}],
    ?equal(true, eradius_proxy:validate_options(DefaultOptions)),
    ?equal(true, eradius_proxy:validate_options([{type, prefix}, {separator, "/"}, {strip, true}])),
    ?equal(true, eradius_proxy:validate_options(DefaultOptions ++ [{timeout, 5000}])),
    ?equal(true, eradius_proxy:validate_options(DefaultOptions ++ [{retries, 5}])),
    ?equal(true, eradius_proxy:validate_options(DefaultOptions ++ [{timeout, 5000}, {retries, 5}])),
    ?equal(false, eradius_proxy:validate_options([{type, unknow}])),
    ?equal(false, eradius_proxy:validate_options([strip, abc])),
    ?equal(false, eradius_proxy:validate_options([abc, abc])),
    ?equal(false, eradius_proxy:validate_options(DefaultOptions ++ [{timeout, "5000"}])),
    ?equal(false, eradius_proxy:validate_options(DefaultOptions ++ [{retries, "5"}])),
    ok.

new_request_test(_) ->
    Req0 = #radius_request{},
    Req1 = eradius_lib:set_attr(Req0, ?User_Name, "user1"),
    ?equal(Req0, eradius_proxy:new_request(Req0, "user", "user")),
    ?equal(Req1, eradius_proxy:new_request(Req0, "user", "user1")),
    ?equal(Req0, eradius_proxy:new_request(Req0, undefined, undefined)),
    ok.

get_key_test(_) ->
    ?equal({"example", "user@example"}, eradius_proxy:get_key("user@example", realm, false, "@")),
    ?equal({"user", "user/domain@example"}, eradius_proxy:get_key("user/domain@example", prefix, false, "/")),
    ?equal({"example", "user"}, eradius_proxy:get_key("user@example", realm, true, "@")),
    ?equal({"example", "user@domain"}, eradius_proxy:get_key("user@domain@example", realm, true, "@")),
    ?equal({"user", "domain@example"}, eradius_proxy:get_key("user/domain@example", prefix, true, "/")),
    ?equal({"user", "domain/domain2@example"}, eradius_proxy:get_key("user/domain/domain2@example", prefix, true, "/")),
    ?equal({not_found, []}, eradius_proxy:get_key([], realm, false, "@")),
    ok.


strip_test(_) ->
    ?equal("user", eradius_proxy:strip("user", realm, false, "@")),
    ?equal("user", eradius_proxy:strip("user", prefix, false, "@")),
    ?equal("user", eradius_proxy:strip("user", realm, true, "@")),
    ?equal("user", eradius_proxy:strip("user", prefix, true, "@")),
    ?equal("user", eradius_proxy:strip("user@example", realm, true, "@")),
    ?equal("user2@example",  eradius_proxy:strip("user/user2@example", prefix, true, "/")),
    ?equal("user/user2@example", eradius_proxy:strip("user/user2@example@roaming", realm, true, "@")),
    ?equal("user/user2",  eradius_proxy:strip("user/user2@example", realm, true, "@")),
    ok.
