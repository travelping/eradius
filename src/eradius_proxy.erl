-module(eradius_proxy).

-behaviour(eradius_server).
-export([radius_request/3]).

-include("eradius_lib.hrl").

radius_request(Request, NasProp, Args) ->
    Secret = proplists:get_value(secret, Args, NasProp#nas_prop.secret),
    case proplists:get_value(to, Args) of
        undefined -> 
            lager:error("~p: invalid configuration ('to' is not set)", [?MODULE]), 
            bad_configuration;
        {Ip, Port} -> send_to_server(Request, Ip, Port, Secret);
        Ip -> send_to_server(Request, Ip, 1812, Secret)
    end.

% @private
send_to_server(#radius_request{reqid = ReqID} = Request, Server, Port, Secret) ->
    case eradius_client:send_request({Server, Port, Secret}, Request, [{retries, 1}]) of
        {ok, Result, Auth} -> decode_request(Result, ReqID, Secret, Auth);
        Error -> 
            lager:error("~p: error during send_request (~p)", [?MODULE, Error]), 
            Error
    end.

% @private
decode_request(Result, ReqID, Secret, Auth) ->
    case eradius_lib:decode_request(Result, Secret, Auth) of
        Reply = #radius_request{} ->
            {reply, Reply#radius_request{reqid = ReqID}};
        Error -> 
            lager:error("~p: error during decode_request (~p)", [?MODULE, Error]), 
            Error
    end.
