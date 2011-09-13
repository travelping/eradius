-module(eradius_example_handler).

-behaviour(eradius_server).
-export([radius_request/3]).

-include("eradius_lib.hrl").

radius_request(Request, NasProp, _Args) ->
    io:format("GOT REQUEST:~n   Req: ~p~n   Nas: ~p~n~n", [Request, NasProp]),
    {reply, #radius_request{cmd = accresp}}.
