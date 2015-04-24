-module(eradius_logtest).

-export([start/0, radius_request/3, client_test/0, client_test/1]).
-import(eradius_lib, [get_attr/2]).

-include_lib("eradius/include/eradius_lib.hrl").
-include_lib("eradius/include/eradius_dict.hrl").
-include_lib("eradius/include/dictionary.hrl").
-include_lib("eradius/include/dictionary_3gpp.hrl").

-define(ALLOWD_USERS, [<<"test">>]).
-define(SECRET, <<"secret">>).

start() ->
    application:load(eradius),
    Config = [{radius_callback, eradius_logtest},
              {servers, [{root, {"127.0.0.1", [1812, 1813]}}]},
              {session_nodes, [node()]},
              {root,
                      [
                       { {"test", [] }, [{"127.0.0.1", ?SECRET}] }
                      ]
              }
             ],
    [application:set_env(eradius, Key, Value) || {Key, Value} <- Config],
    {ok, _} = application:ensure_all_started(eradius),
    {ok, spawn(fun() ->
                   eradius:modules_ready([?MODULE]),
                   timer:sleep(infinity)
               end)}.

radius_request(#radius_request{cmd = request} = Request, _NasProp, _) ->
    UserName = get_attr(Request, ?User_Name),
    case lists:member(UserName, ?ALLOWD_USERS) of
        true ->
            {reply, #radius_request{cmd = accept}};
        false ->
            {reply, #radius_request{cmd = reject}}
    end;

radius_request(#radius_request{cmd = accreq}, _NasProp, _) ->
    {reply, #radius_request{cmd = accresp}}.

client_test() ->
  client_test(request).

client_test(Command) ->
    eradius_dict:load_tables([dictionary, dictionary_3gpp]),
    Request = eradius_lib:set_attributes(#radius_request{cmd = Command, msg_hmac = true},[
                {?NAS_Port, 8888},
                {?User_Name, "test"},
                {?NAS_IP_Address, {88,88,88,88}},
                {?Calling_Station_Id, "0123456789"},
                {?Service_Type, 2},
                {?Framed_Protocol, 7},
                {30,"some.id.com"},               %Called-Station-Id
                {61,18},                                %NAS_PORT_TYPE
                {{10415,1}, "1337"},                    %X_3GPP-IMSI
                {{127,42},18}                           %Unbekannte ID
                ] ),
    case eradius_client:send_request({{127, 0, 0, 1}, 1813, ?SECRET}, Request) of
        {ok, Result, Auth} ->
            eradius_lib:decode_request(Result, ?SECRET, Auth);
        Error ->
            Error
    end.
