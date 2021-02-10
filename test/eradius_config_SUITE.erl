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

-module(eradius_config_SUITE).
-compile(export_all).
-include("../include/eradius_lib.hrl").
-include("eradius_test.hrl").

all() -> [config_1, config_2, config_nas_removing, config_with_ranges, generate_ip_list_test].

init_per_suite(Config) ->
    % Is it a good practise? Copied fron client test
    {ok, _} = application:ensure_all_started(eradius),
    Config.

end_per_suite(_Config) ->
    application:stop(eradius),
    ok.

config_1(_Config) ->
    Conf = [{session_nodes, ['node1@host1', 'node2@host2']},
            {radius_callback, ?MODULE},
            {servers, [
                          {root, {eradius_test_handler:localhost(ip), [1812, 1813]}}
                      ]},
            {root, [
                      { {"NAS1", [arg1, arg2]},
                          [{"10.18.14.2/30", <<"secret1">>}]},
                      { {"NAS2", [arg1, arg2]},
                          [{{10, 18, 14, 3}, <<"secret2">>, [{nas_id, <<"name">>}]}]}
                   ]}],
    apply_conf(Conf),
    LocalHost = eradius_test_handler:localhost(tuple),
    ?match({ok, {?MODULE,[arg1,arg2]},
                #nas_prop{
                          server_ip = LocalHost,
                          server_port = 1813,
                          nas_id = <<"name">>,
                          nas_ip = {10,18,14,3},
                          handler_nodes = ['node1@host1', 'node2@host2']
                         }}, eradius_server_mon:lookup_handler(LocalHost, 1813, {10,18,14,3})),
    ?match({ok, {?MODULE,[arg1,arg2]},
                #nas_prop{
                          server_ip = LocalHost,
                          server_port = 1812,
                          nas_id = <<"name">>,
                          nas_ip = {10,18,14,3},
                          handler_nodes = ['node1@host1', 'node2@host2']
                         }}, eradius_server_mon:lookup_handler(LocalHost, 1812, {10,18,14,3})),
    ?match({ok, {?MODULE,[arg1,arg2]},
                #nas_prop{
                          server_ip = LocalHost,
                          server_port = 1813,
                          nas_id = <<"NAS1_10.18.14.2">>,
                          nas_ip = {10,18,14,2},
                          handler_nodes = ['node1@host1', 'node2@host2']
                         }}, eradius_server_mon:lookup_handler(LocalHost, 1813, {10,18,14,2})),
    ok.

config_2(_Config) ->
    Conf = [{session_nodes, [
                             {"NodeGroup1", ['node1@host1', 'node2@host2']},
                             {"NodeGroup2", ['node3@host3', 'node4@host4']}
                            ]
            },
            {servers, [
                          {root, {eradius_test_handler:localhost(ip), [1812, 1813]}}
                      ]},
            {root, [
                      { {handler1, "NAS1", [arg1, arg2]},
                          [ {"10.18.14.3", <<"secret1">>, [{group, "NodeGroup1"}]},
                            {"10.18.14.4", <<"secret1">>, [{group, "NodeGroup1"}]} ] },
                      { {handler2, "NAS2", [arg3, arg4]},
                          [ {"10.18.14.2", <<"secret2">>, [{group, "NodeGroup2"}]} ] }
                 ]}],
    apply_conf(Conf),
    LocalHost = eradius_test_handler:localhost(tuple),
    ?match({ok, {handler1,[arg1,arg2]},
                #nas_prop{
                          server_ip = LocalHost,
                          server_port = 1813,
                          nas_id = <<"NAS1_10.18.14.3">>,
                          nas_ip = {10,18,14,3},
                          handler_nodes = ['node1@host1', 'node2@host2']
                         }}, eradius_server_mon:lookup_handler(LocalHost, 1813, {10,18,14,3})),
    ?match({ok, {handler1,[arg1,arg2]},
                #nas_prop{
                          server_ip = LocalHost,
                          server_port = 1813,
                          nas_id = <<"NAS1_10.18.14.4">>,
                          nas_ip = {10,18,14,4},
                          handler_nodes = ['node1@host1', 'node2@host2']
                         }}, eradius_server_mon:lookup_handler(LocalHost, 1813, {10,18,14,4})),
    ?match({ok, {handler2,[arg3,arg4]},
                #nas_prop{
                          server_ip = LocalHost,
                          server_port = 1813,
                          nas_id = <<"NAS2_10.18.14.2">>,
                          nas_ip = {10,18,14,2},
                          handler_nodes = ['node3@host3', 'node4@host4']
                         }}, eradius_server_mon:lookup_handler(LocalHost, 1813, {10,18,14,2})),
    ok.

config_nas_removing(_Config) ->
    Conf = [{servers, [ {root, {eradius_test_handler:localhost(ip), [1812, 1813]}} ]},
            {root, [ ]}],
    apply_conf(Conf),
    ?match([], ets:tab2list(eradius_nas_tab)),
    ok.

config_with_ranges(_Config) ->
    Nodes = ['node1@host1', 'node2@host2'],
    Conf = [{session_nodes, [
                             {"NodeGroup", Nodes}
                            ]
            },
            {servers, [
                          {root, {eradius_test_handler:localhost(ip), [1812, 1813]}}
                      ]},
            {root, [
                      { {handler, "NAS", []},
                          [ {"10.18.14.2/30", <<"secret2">>, [{group, "NodeGroup"}]} ] }
                 ]}],
    apply_conf(Conf),
    LocalHost = eradius_test_handler:localhost(tuple),
    ?match({ok, {handler,[]},
                #nas_prop{
                          server_ip = LocalHost,
                          server_port = 1812,
                          nas_id = <<"NAS_10.18.14.2">>,
                          nas_ip = {10,18,14,2},
                          handler_nodes = Nodes
                         }}, eradius_server_mon:lookup_handler(LocalHost, 1812, {10,18,14,2})),
    ?match({ok, {handler,[]},
                #nas_prop{
                          server_ip = LocalHost,
                          server_port = 1812,
                          nas_id = <<"NAS_10.18.14.3">>,
                          nas_ip = {10,18,14,3},
                          handler_nodes = Nodes
                         }}, eradius_server_mon:lookup_handler(LocalHost, 1812, {10,18,14,3})),
    ?match({ok, {handler,[]},
                #nas_prop{
                          server_ip = LocalHost,
                          server_port = 1813,
                          nas_id = <<"NAS_10.18.14.1">>,
                          nas_ip = {10,18,14,1},
                          handler_nodes = Nodes
                         }}, eradius_server_mon:lookup_handler(LocalHost, 1813, {10,18,14,1})),
    ?match({ok, {handler,[]},
                #nas_prop{
                          server_ip = LocalHost,
                          server_port = 1813,
                          nas_id = <<"NAS_10.18.14.2">>,
                          nas_ip = {10,18,14,2},
                          handler_nodes = Nodes
                         }}, eradius_server_mon:lookup_handler(LocalHost, 1813, {10,18,14,2})),
    ok.

set_env(Config) ->
    [application:set_env(eradius, Env, Value) || {Env, Value} <- Config].

apply_conf(Config) ->
    set_env(Config),
    eradius_server_mon:reconfigure().

generate_ip_list_test(_) ->
    ?equal([{192, 168, 11, 148}, {192, 168, 11, 149}, {192, 168, 11, 150}, {192, 168, 11, 151}],
                 eradius_config:generate_ip_list({192, 168, 11, 150}, "30")),
    eradius_config:generate_ip_list({192, 168, 11, 150}, 24),
    ?equal(256, length(eradius_config:generate_ip_list({192, 168, 11, 150}, 24))),
    ?equal(2048, length(eradius_config:generate_ip_list({192, 168, 11, 10}, 21))),
    ?match({invalid, _}, eradius_config:generate_ip_list({192, 168, 11, 150}, "34")),
    ok.
