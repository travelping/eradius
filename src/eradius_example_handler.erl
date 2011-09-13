-module(eradius_example_handler).

-behaviour(eradius_server).
-export([radius_request/3]).

radius_request(Request, NasProp, _Args) ->
    io:format("GOT REQUEST:~nReq:    ~p~nNas:    ~p~n~n", [Request, NasProp]).
