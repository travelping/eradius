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

all() -> [config_1, config_2, config_options,
          config_socket_options, config_nas_removing,
          config_with_ranges, log_test, generate_ip_list_test,
          test_validate_server].

init_per_suite(Config) ->
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
    ok = apply_conf(Conf),
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
    ok = apply_conf(Conf),
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

config_socket_options(_Config) ->
    Opts = [{netns, "/var/run/netns/net1"}],
    ?match(Opts, eradius_config:validate_socket_options(Opts)),
    Invalid = [{buffer, 512}, {active, false}],
    ?match({invalid, _}, eradius_config:validate_socket_options(Invalid)),
    Invalid2 = [{buffer, 512}, {ip, {127, 0, 0, 10}}],
    ?match({invalid, _}, eradius_config:validate_socket_options(Invalid2)),
    ok.

config_options(_Config) ->
    Opts = [{socket_opts, [{recbuf, 8192},
                           {netns, "/var/run/netns/net1"}]}],
    ?match(Opts, eradius_config:validate_options(Opts)),
    ok.
test_validate_server(_Config) ->
    SocketOpts = [{socket_opts, [{recbuf, 8192}, {netns, "/var/run/netns/net1"}]}],
    Opts = {{127, 0, 0, 1}, 1812, SocketOpts},
    ?match(Opts, eradius_config:validate_server(Opts)),
    Opts2 = {{127, 0, 0, 1}, "1812", SocketOpts},
    ?match({{127, 0, 0, 1}, 1812, SocketOpts}, eradius_config:validate_server(Opts2)),
    Opts3 = {{127, 0, 0, 1}, 1812},
    ?match(Opts3, eradius_config:validate_server(Opts3)),
    ok.

config_nas_removing(_Config) ->
    Conf = [{servers, [ {root, {eradius_test_handler:localhost(ip), [1812, 1813]}} ]},
            {root, [ ]}],
    ok = apply_conf(Conf),
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
    ok = apply_conf(Conf),
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

log_test(_Config) ->
    LogFile0 = "./radius.log",
    LogFile1 = "./radius1.log",
    LogOn0 = [{logging, true}, {logfile, LogFile0}],
    LogOn1 = [{logging, true}, {logfile, LogFile1}],
    LogOff = [{logging, false}],

    % via eradius_log:reconfigure/0
    set_env(LogOn0),
    ok = eradius_log:reconfigure(),
    ?match(true, logger_disabled /= gen_server:call(eradius_log, get_state)),
    ?match(true, filelib:is_file(LogFile0)),

    set_env(LogOff),
    ok = eradius_log:reconfigure(),
    logger_disabled = gen_server:call(eradius_log, get_state),

    set_env(LogOn1),
    ?match(false, filelib:is_file(LogFile1)),
    ok = eradius_log:reconfigure(),
    ?match(true, logger_disabled /= gen_server:call(eradius_log, get_state)),
    ?match(true, filelib:is_file(LogFile1)),

    % via eradius:config_change/3
    set_env(LogOff),
    eradius:config_change([], LogOff, []),
    logger_disabled = gen_server:call(eradius_log, get_state),

    set_env(LogOn0),
    eradius:config_change([], LogOn1, []),
    ?match(true, logger_disabled /= gen_server:call(eradius_log, get_state)),

    % check default value for logging
    application:unset_env(eradius, logging),
    eradius:config_change([], [], [logging]),
    logger_disabled = gen_server:call(eradius_log, get_state),

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
