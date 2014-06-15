-module(eradius_inet).
-export([setopts/2]).

setopts(Socket, Options) ->
    inet:setopts(Socket, Options).
