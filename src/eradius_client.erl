%% Copyright (c) 2002-2007, Martin Björklund and Torbjörn Törnkvist
%% Copyright (c) 2011, Travelping GmbH <info@travelping.com>
%%
%% SPDX-License-Identifier: MIT
%%
%% @doc This module contains a RADIUS client that can be used to send authentication and accounting requests.
%%   A counter is kept for every client instance in order to determine the next request id and sender port
%%   for each outgoing request.
%%
%%   The client uses OS-assigned ports. The maximum number of open ports can be specified through the
%%   ``client_ports'' application environment variable, it defaults to ``20''. The number of ports should not
%%   be set too low. If ``N'' ports are opened, the maximum number of concurrent requests is ``N * 256''.
%%
%%   The IP address used to send requests is read <emph>once</emph> (at startup) from the ``client_ip''
%%   parameter. Changing it currently requires a restart. It can be given as a string or ip address tuple,
%%   or the atom ``any'' (the default), which uses whatever address the OS selects.
-module(eradius_client).

%% API
-export([send_request/3, send_request/4]).
-ignore_xref([send_request/3, send_request/4]).

-import(eradius_lib, [printable_peer/2]).


-include_lib("stdlib/include/ms_transform.hrl").
-include_lib("kernel/include/logger.hrl").
-include_lib("kernel/include/inet.hrl").
-include("eradius_dict.hrl").
-include("eradius_lib.hrl").
-include("eradius_internal.hrl").

-define(GOOD_CMD(Cmd), (Cmd == 'request' orelse
                        Cmd == 'accreq' orelse
                        Cmd == 'coareq' orelse
                        Cmd == 'discreq')).

-type options() :: #{retries => pos_integer(),
                     timeout => timeout(),
                     failover => [eradius_client_mngr:server_name()]
                    }.
%% Options for a RADIUS request to override configure
%% server defaults and to add failover alternatives

-export_type([options/0]).

-define(DEFAULT_REQUEST_OPTS, #{retries => 3, timeout => 5_000, failover => []}).
-define(SERVER, ?MODULE).

%%%=========================================================================
%%%  API
%%%=========================================================================

%% @equiv send_request(ServerRef, ServerName, Req, [])
-spec send_request(gen_server:server_ref(),
                   eradius_client_mngr:server_name() | [eradius_client_mngr:server_name()],
                   eradius_req:req()) ->
          {{ok, eradius_req:req()} | {error, 'timeout' | 'socket_down'}, eradius_req:req()}.
send_request(ServerRef, ServerName, #{cmd := _, payload := _} = Req) ->
    send_request(ServerRef, ServerName, Req, #{}).

%% @doc Send a radius request to the given server or server pool.
%%   If no answer is received within the specified timeout, the request will be sent again.
-spec send_request(gen_server:server_ref(),
                   eradius_client_mngr:server_name() | [eradius_client_mngr:server_pool()],
                   eradius_req:req(), options()) ->
          {{ok, eradius_req:req()} | {error, 'timeout' | 'socket_down'}, eradius_req:req()}.
send_request(ServerRef, ServerName, #{cmd := Cmd} = Req, Opts)
  when ?GOOD_CMD(Cmd), is_map(Opts), is_list(ServerName) ->
    do_send_request(ServerRef, ServerName, [], Req, Opts);
send_request(ServerRef, ServerName, Req, Opts) when not is_list(ServerName) ->
    send_request(ServerRef, [ServerName], Req, Opts).

do_send_request(_ServerRef, [], _Tried, _Req, _Opts) ->
    {error, no_active_servers};
do_send_request(ServerRef, Peers, Tried, Req0, Opts0) ->
    case eradius_client_mngr:wanna_send(ServerRef, Peers, Tried) of
        {ok, {Socket, ReqId, ServerName, Server, ReqInfo}} ->
            #{secret := Secret} = Server,

            ServerOpts0 = maps:with([retries, timeout], Server),
            ServerOpts = maps:merge(?DEFAULT_REQUEST_OPTS, ServerOpts0),
            Opts = maps:merge(ServerOpts, Opts0),

            Req1 = maps:merge(Req0, ReqInfo),
            Req2 = eradius_req:record_metric(request, #{}, Req1),

            {Response, Req} =
                send_request_loop(
                  Socket, ReqId, Req2#{req_id => ReqId, secret => Secret}, Opts),
            proceed_response(ServerRef, [ServerName | Tried], Req, Response, ServerName, Opts);

        {error, _} = Error ->
            maybe_failover(ServerRef, Tried, Req0, Error, Opts0)
    end.

proceed_response(_ServerRef, _Tried, Req, {ok, Resp0}, _ServerName, _Opts) ->
    Resp = eradius_req:record_metric(reply, #{request => Req}, Resp0),
    {{ok, Resp}, Req};

proceed_response(ServerRef, Tried, Req0, {error, Error} = Response, ServerName, Opts) ->
    Req = eradius_req:record_metric(discard, #{reason => Error, request => Req0}, Req0),
    eradius_client_mngr:request_failed(ServerRef, ServerName),
    maybe_failover(ServerRef, Tried, Req, Response, Opts).

maybe_failover(ServerRef, Tried, Req, _Response, #{failover := [_|_] = FailOver} = Opts) ->
    do_send_request(ServerRef, FailOver, Tried, Req, Opts#{failover := []});
maybe_failover(_, _, Req, Response, _) ->
    {Response, Req}.

%% send_request_loop/4
send_request_loop(Socket, ReqId, Req0, Opts) ->
    {Packet, Req} = eradius_req:packet(Req0),
    send_request_loop(Socket, ReqId, Packet, Opts, Req).

%% send_request_loop/8
send_request_loop(_Socket, _ReqId, _Packet, #{retries := 0}, Req) ->
    {{error, timeout}, Req};
send_request_loop(Socket, ReqId, Packet,
                  #{timeout := Timeout, retries := RetryN} = Opts,
                  #{server_addr := PeerAddress} = Req) ->
    Result =
        try
            %% update_client_request(pending, 1),
            eradius_client_socket:send_request(Socket, PeerAddress, ReqId, Packet, Timeout)
        after
            %% update_client_request(pending, -1)
            ok
        end,

    case Result of
        {ok, Header, Body} ->
            {{ok, eradius_req:response(Header, Body, Req)}, Req};
        {error, close} ->
            {{error, socket_down}, Req};
        {error, timeout} ->
            ReqN = eradius_req:record_metric(retransmission, #{}, Req),
            send_request_loop(Socket, ReqId, Packet,
                              Opts#{retries := RetryN - 1}, ReqN);
        {error, _} = Error ->
            {Error, Req}
    end.
