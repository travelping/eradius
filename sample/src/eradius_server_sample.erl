-module(eradius_server_sample).

-behaviour(application).
-behaviour(eradius_server).

-export([start/2,
         stop/1,
         radius_request/3,
         test/0]).

-include_lib("eradius/include/eradius_lib.hrl").
-include_lib("eradius/include/dictionary.hrl").

start(_StartType, _StartArgs) ->
    eradius:modules_ready([?MODULE]),
    {ok, self()}.

stop(_State) ->
    ok.

radius_request(R = #radius_request{cmd = request}, _NasProp, _Args) ->
    Response = #radius_request{cmd = accept, attrs = [{?Realm, "foo"}]},
    {reply, Response};

radius_request(R = #radius_request{cmd = accreq}, _NasProp, _Args) ->
    Response = #radius_request{cmd = accresp, attrs = [{?Menu, <<"foo">>}]},
    {reply, Response}.

test() ->
    {Time, Count} = timer:tc(fun() -> do_test(1000) end),
    io:format("~f req/sec.~n", [Count / (Time / 1000 / 1000)]).

do_test(Count) ->
    Tasks = [run_task(fun() ->
                              Port = erlang:phash2(self(), 1) + 1812, % 1812, 1813
                              {ok, R, A} = eradius_client:send_request({{127,0,0,1}, Port, "secret"}, 
                                                                       #radius_request{cmd = request}, []),
                              #radius_request{} = eradius_lib:decode_request(R, <<"secret">>, A)
                      end)
             || _ <- lists:seq(1, Count)],
    [await(Task) || Task <- Tasks],
    Count.

run_task(Fun) ->
    Self = self(),
    spawn(fun() -> Fun(), Self ! self() end).

await(Task) ->
    receive 
        Task -> ok
    end.
