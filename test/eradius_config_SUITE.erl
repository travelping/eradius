%    __                        __      _
%   / /__________ __   _____  / /___  (_)___  ____ _
%  / __/ ___/ __ `/ | / / _ \/ / __ \/ / __ \/ __ `/
% / /_/ /  / /_/ /| |/ /  __/ / /_/ / / / / / /_/ /
% \__/_/   \__,_/ |___/\___/_/ .___/_/_/ /_/\__, /
%                           /_/            /____/
%
% Copyright (c) Travelping GmbH <info@travelping.com>

-module(eradius_config_SUITE).
-compile(export_all).
-include("../include/eradius_lib.hrl").

-define(match(Guard, Expr),
        ((fun () ->
                  case (Expr) of
                      Guard ->
                          ok;
                      V ->
                          ct:pal("MISMATCH(~s:~b, ~s)~nExpected: ~p~nActual:   ~p~n", [?FILE, ?LINE, ??Expr, ??Guard, V]),
                          error(badmatch)
                  end
          end)())).

all() -> [config_1, config_2, config_with_ranges].

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
                          {root, {"127.0.0.1", [1812, 1813]}}
                      ]},
            {root, [
                      { {"NAS1", [arg1, arg2]},
                          [{"10.18.14.2/30", <<"secret1">>}]},
                      { {"NAS2", [arg1, arg2]},
                          [{"10.18.14.3", <<"secret2">>, [{nas_id, <<"name">>}]}]}
                   ]}],
    apply_conf(Conf),
    ?match({ok, {?MODULE,[arg1,arg2]},
                #nas_prop{
                          server_ip = {127,0,0,1},
                          server_port = 1813,
                          nas_id = <<"name">>,
                          nas_ip = {10,18,14,3},
                          handler_nodes = ['node1@host1', 'node2@host2']
                         }}, eradius_server_mon:lookup_handler({127,0,0,1}, 1813, {10,18,14,3})),
    ?match({ok, {?MODULE,[arg1,arg2]},
                #nas_prop{
                          server_ip = {127,0,0,1},
                          server_port = 1812,
                          nas_id = <<"name">>,
                          nas_ip = {10,18,14,3},
                          handler_nodes = ['node1@host1', 'node2@host2']
                         }}, eradius_server_mon:lookup_handler({127,0,0,1}, 1812, {10,18,14,3})),
    ?match({ok, {?MODULE,[arg1,arg2]},
                #nas_prop{
                          server_ip = {127,0,0,1},
                          server_port = 1813,
                          nas_id = <<"NAS1_10.18.14.2">>,
                          nas_ip = {10,18,14,2},
                          handler_nodes = ['node1@host1', 'node2@host2']
                         }}, eradius_server_mon:lookup_handler({127,0,0,1}, 1813, {10,18,14,2})),
    ok.

config_2(_Config) ->
    Conf = [{session_nodes, [
                             {"NodeGroup1", ['node1@host1', 'node2@host2']},
                             {"NodeGroup2", ['node3@host3', 'node4@host4']}
                            ]
            },
            {servers, [
                          {root, {"127.0.0.1", [1812, 1813]}}
                      ]},
            {root, [
                      { {handler1, "NAS1", [arg1, arg2]},
                          [ {"10.18.14.3", <<"secret1">>, [{group, "NodeGroup1"}]},
                            {"10.18.14.4", <<"secret1">>, [{group, "NodeGroup1"}]} ] },
                      { {handler2, "NAS2", [arg3, arg4]},
                          [ {"10.18.14.2", <<"secret2">>, [{group, "NodeGroup2"}]} ] }
                 ]}],
    apply_conf(Conf),
    ?match({ok, {handler1,[arg1,arg2]},
                #nas_prop{
                          server_ip = {127,0,0,1},
                          server_port = 1813,
                          nas_id = <<"NAS1_10.18.14.3">>,
                          nas_ip = {10,18,14,3},
                          handler_nodes = ['node1@host1', 'node2@host2']
                         }}, eradius_server_mon:lookup_handler({127,0,0,1}, 1813, {10,18,14,3})),
    ?match({ok, {handler1,[arg1,arg2]},
                #nas_prop{
                          server_ip = {127,0,0,1},
                          server_port = 1813,
                          nas_id = <<"NAS1_10.18.14.4">>,
                          nas_ip = {10,18,14,4},
                          handler_nodes = ['node1@host1', 'node2@host2']
                         }}, eradius_server_mon:lookup_handler({127,0,0,1}, 1813, {10,18,14,4})),
    ?match({ok, {handler2,[arg3,arg4]},
                #nas_prop{
                          server_ip = {127,0,0,1},
                          server_port = 1813,
                          nas_id = <<"NAS2_10.18.14.2">>,
                          nas_ip = {10,18,14,2},
                          handler_nodes = ['node3@host3', 'node4@host4']
                         }}, eradius_server_mon:lookup_handler({127,0,0,1}, 1813, {10,18,14,2})),
    ok.

config_with_ranges(_Config) ->
    Nodes = ['node1@host1', 'node2@host2'],
    Conf = [{session_nodes, [
                             {"NodeGroup", Nodes}
                            ]
            },
            {servers, [
                          {root, {"127.0.0.1", [1812, 1813]}}
                      ]},
            {root, [
                      { {handler, "NAS", []},
                          [ {"10.18.14.2/30", <<"secret2">>, [{group, "NodeGroup"}]} ] }
                 ]}],
    apply_conf(Conf),
    ?match({ok, {handler,[]},
                #nas_prop{
                          server_ip = {127,0,0,1},
                          server_port = 1812,
                          nas_id = <<"NAS_10.18.14.2">>,
                          nas_ip = {10,18,14,2},
                          handler_nodes = Nodes
                         }}, eradius_server_mon:lookup_handler({127,0,0,1}, 1812, {10,18,14,2})),
    ?match({ok, {handler,[]},
                #nas_prop{
                          server_ip = {127,0,0,1},
                          server_port = 1812,
                          nas_id = <<"NAS_10.18.14.3">>,
                          nas_ip = {10,18,14,3},
                          handler_nodes = Nodes
                         }}, eradius_server_mon:lookup_handler({127,0,0,1}, 1812, {10,18,14,3})),
    ?match({ok, {handler,[]},
                #nas_prop{
                          server_ip = {127,0,0,1},
                          server_port = 1813,
                          nas_id = <<"NAS_10.18.14.1">>,
                          nas_ip = {10,18,14,1},
                          handler_nodes = Nodes
                         }}, eradius_server_mon:lookup_handler({127,0,0,1}, 1813, {10,18,14,1})),
    ?match({ok, {handler,[]},
                #nas_prop{
                          server_ip = {127,0,0,1},
                          server_port = 1813,
                          nas_id = <<"NAS_10.18.14.2">>,
                          nas_ip = {10,18,14,2},
                          handler_nodes = Nodes
                         }}, eradius_server_mon:lookup_handler({127,0,0,1}, 1813, {10,18,14,2})),
    ok.

apply_conf(Config) ->
    [application:set_env(eradius, Env, Value) || {Env, Value} <- Config],
    eradius_server_mon:reconfigure().
