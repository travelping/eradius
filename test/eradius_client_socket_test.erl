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

-module(eradius_client_socket_test).

-behaviour(gen_server).

-export([start/3]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-record(state, {pending, mode, counter}).

start(SocketIP, Client, PortIdx) ->
    gen_server:start_link(?MODULE, [SocketIP, Client, PortIdx], []).

init([_SocketIP, Client, PortIdx]) ->
    Client ! {PortIdx, self()},
    eradius_client_SUITE:addSocket(),
    {ok, #state{pending = maps:new(), mode = active, counter = 0}}.

handle_call(_Request, _From, State) ->
    {noreply, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info({SenderPid, send_request, {IP, Port}, ReqId, _EncRequest},
        State = #state{pending = Pending, counter = Counter}) ->
    ReqKey = {IP, Port, ReqId},
    NPending = Pending#{ReqKey => SenderPid},
    {noreply, State#state{pending = NPending, counter = Counter+1}};

handle_info(close, State) ->
    %~ {noreply, State#state{mode = inactive}};
    {stop, normal, State};

handle_info({status, Pid}, State = #state{mode = Mode}) ->
    Pid ! {ok, Mode},
    {noreply, State};

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    eradius_client_SUITE:delSocket().

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

