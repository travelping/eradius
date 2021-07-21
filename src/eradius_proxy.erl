%% @doc
%%   This module implements a RADIUS proxy.
%%
%%   It accepts following configuration:
%%
%%   ```
%%   [{default_route, {{127, 0, 0, 1}, 1813, <<"secret">>}, pool_name},
%%    {options, [{type, realm}, {strip, true}, {separator, "@"}]},
%%    {routes,  [{"^test-[0-9].", {{127, 0, 0, 1}, 1815, <<"secret1">>}, pool_name}]}]
%%   '''
%%
%%   Where the pool_name is optional field that contains list of
%%   RADIUS servers pool name that will be used for fail-over.
%%
%%   Pools of RADIUS servers are defined in eradius configuration:
%%
%%   ```
%%   {servers_pool, [{pool_name, [
%%                     {{127, 0, 0, 1}, 1815, <<"secret">>, [{retries, 3}]},
%%                     {{127, 0, 0, 1}, 1816, <<"secret">>}]}]}
%%   '''
%%
%%   == WARNING ==
%%
%%   Define `routes' carefully. The `test' here in example above, is
%%   a regular expression that may cause to problemts with performance.
-module(eradius_proxy).

-behaviour(eradius_server).
-export([radius_request/3, validate_arguments/1, get_routes_info/1,
        put_default_route_to_pool/2, put_routes_to_pool/2]).

-ifdef(TEST).
-export([resolve_routes/4, validate_options/1, new_request/3,
         get_key/4, strip/4]).
-endif.

-include_lib("kernel/include/logger.hrl").
-include("eradius_lib.hrl").
-include("dictionary.hrl").

-define(DEFAULT_TYPE, realm).
-define(DEFAULT_STRIP, false).
-define(DEFAULT_SEPARATOR, "@").
-define(DEFAULT_TIMEOUT, 5000).
-define(DEFAULT_RETRIES, 1).
-define(DEFAULT_CLIENT_RETRIES, 3).

-define(DEFAULT_OPTIONS, [{type, ?DEFAULT_TYPE},
                          {strip, ?DEFAULT_STRIP},
                          {separator, ?DEFAULT_SEPARATOR},
                          {timeout, ?DEFAULT_TIMEOUT},
                          {retries, ?DEFAULT_RETRIES}]).

-type route() :: eradius_client:nas_address() |
                 {eradius_client:nas_address(), PoolName :: atom()}.
-type routes() :: [{Name :: string(), eradius_client:nas_address()}] |
                  [{Name :: string(), eradius_client:nas_address(), PoolName :: atom()}].
-type undefined_route() :: {undefined, 0, []}.

radius_request(Request, _NasProp, Args) ->
    DefaultRoute = get_proxy_opt(default_route, Args, {undefined, 0, []}),
    Routes = get_proxy_opt(routes, Args, []),
    Options = proplists:get_value(options, Args, ?DEFAULT_OPTIONS),
    Username = eradius_lib:get_attr(Request, ?User_Name),
    {NewUsername, Route} = resolve_routes(Username, DefaultRoute, Routes, Options),
    Retries = proplists:get_value(retries, Options, ?DEFAULT_RETRIES),
    Timeout = proplists:get_value(timeout, Options, ?DEFAULT_TIMEOUT),
    SendOpts = [{retries, Retries}, {timeout, Timeout}],
    send_to_server(new_request(Request, Username, NewUsername), Route, SendOpts).

validate_arguments(Args) ->
    DefaultRoute = get_proxy_opt(default_route, Args, {undefined, 0, []}),
    Options = proplists:get_value(options, Args, ?DEFAULT_OPTIONS),
    Routes = get_proxy_opt(routes, Args, undefined),
    case {validate_route(DefaultRoute), validate_options(Options), compile_routes(Routes)} of
        {false, _, _} -> default_route;
        {_, false, _} -> options;
        {_, _, false} -> routes;
        {_, _, NewRoutes} ->
            {true, [{default_route, DefaultRoute}, {options, Options}, {routes, NewRoutes}]}
    end.

compile_routes(undefined) -> [];
compile_routes(Routes) ->
    RoutesOpts = lists:map(fun (Route) ->
        {Name, Relay, Pool} = route(Route),
        case re:compile(Name) of
            {ok, R} ->
                case validate_route({Relay, Pool}) of
                    false -> false;
                    _ -> {R, Relay, Pool}
                end;
            {error, {Error, Position}} ->
                throw("Error during regexp compilation - " ++ Error ++ " at position " ++ integer_to_list(Position))
        end
    end, Routes),
    RelaysRegexps = lists:any(fun(Route) -> Route == false end, RoutesOpts),
    if RelaysRegexps == false ->
            RoutesOpts;
       true ->
            false
    end.

% @private
-spec send_to_server(Request :: #radius_request{}, 
                     Route :: undefined_route() | route(), 
                     Options :: eradius_client:options()) ->
    {reply, Reply :: #radius_request{}} | term().
send_to_server(_Request, {undefined, 0, []}, _) ->
    {error, no_route};
send_to_server(#radius_request{reqid = ReqID} = Request, {{Server, Port, Secret}, Pool}, Options) ->
    Pools = application:get_env(eradius, servers_pool, []),
    UpstreamServers = proplists:get_value(Pool, Pools, []),
    case eradius_client:send_request({Server, Port, Secret}, Request, [{failover, UpstreamServers} | Options]) of
        {ok, Result, Auth} ->
            decode_request(Result, ReqID, Secret, Auth);
        no_active_servers ->
            % If all RADIUS servers are marked as inactive for now just use
            % just skip fail-over mechanism and use default given Peer
            send_to_server(Request, {Server, Port, Secret}, Options);
        Error ->
            ?LOG(error, "~p: error during send_request (~p)", [?MODULE, Error]),
            Error
    end;
send_to_server(#radius_request{reqid = ReqID} = Request, {Server, Port, Secret}, Options) ->
    case eradius_client:send_request({Server, Port, Secret}, Request, Options) of
        {ok, Result, Auth} -> decode_request(Result, ReqID, Secret, Auth);
        Error ->
            ?LOG(error, "~p: error during send_request (~p)", [?MODULE, Error]),
            Error
    end.

% @private
decode_request(Result, ReqID, Secret, Auth) ->
    case eradius_lib:decode_request(Result, Secret, Auth) of
        Reply = #radius_request{} ->
            {reply, Reply#radius_request{reqid = ReqID}};
        Error ->
            ?LOG(error, "~p: request is incorrect (~p)", [?MODULE, Error]),
            Error
    end.


% @private
-spec validate_route(Route :: route()) -> boolean().
validate_route({{Host, Port, Secret}, PoolName}) when is_atom(PoolName) ->
    validate_route({Host, Port, Secret});
validate_route({_Host, Port, _Secret}) when not is_integer(Port); Port =< 0; Port > 65535 -> false;
validate_route({_Host, _Port, Secret}) when not is_list(Secret), not is_binary(Secret) -> false;
validate_route({Host, _Port, _Secret}) when is_list(Host) -> true;
validate_route({Host, Port, Secret}) when is_tuple(Host) ->
    case inet_parse:ntoa(Host) of
        {error, _} -> false;
        Address -> validate_route({Address, Port, Secret})
    end;
validate_route({Host, _Port, _Secret}) when is_binary(Host) -> true;
validate_route(_) -> false.

% @private
-spec validate_options(Options :: [proplists:property()]) -> boolean().
validate_options(Options) ->
    Keys = proplists:get_keys(Options),
    lists:all(fun(Key) -> validate_option(Key, proplists:get_value(Key, Options)) end, Keys).

% @private
-spec validate_option(Key :: atom(), Value :: term()) -> boolean().
validate_option(type, Value) when Value =:= realm; Value =:= prefix -> true;
validate_option(type, _Value) -> false;
validate_option(strip, Value) when is_boolean(Value) -> true;
validate_option(strip, _Value) -> false;
validate_option(separator, Value) when is_list(Value) -> true;
validate_option(timeout, Value) when is_integer(Value) -> true;
validate_option(retries, Value) when is_integer(Value) -> true;
validate_option(_, _) -> false.


% @private
-spec new_request(Request :: #radius_request{},
                  Username :: undefined | binary(),
                  NewUsername :: string()) ->
    NewRequest :: #radius_request{}.
new_request(Request, Username, Username) -> Request;
new_request(Request, _Username, NewUsername) ->
    eradius_lib:set_attr(eradius_lib:del_attr(Request, ?User_Name),
                         ?User_Name, NewUsername).

% @private
-spec resolve_routes(Username :: undefined | binary(),
                     DefaultRoute :: undefined_route() | route(),
                     Routes :: routes(), Options :: [proplists:property()]) ->
                     {NewUsername :: string(), Route :: route()}.
resolve_routes( undefined, DefaultRoute, _Routes, _Options) ->
    {undefined, DefaultRoute};
resolve_routes(Username, DefaultRoute, Routes, Options) ->
    Type = proplists:get_value(type, Options, ?DEFAULT_TYPE),
    Strip = proplists:get_value(strip, Options, ?DEFAULT_STRIP),
    Separator = proplists:get_value(separator, Options, ?DEFAULT_SEPARATOR),
    case get_key(Username, Type, Strip, Separator) of
        {not_found, NewUsername} ->
            {NewUsername, DefaultRoute};
        {Key, NewUsername} ->
            {NewUsername, find_suitable_relay(Key, Routes, DefaultRoute)}
    end.

find_suitable_relay(_Key, [], DefaultRoute) -> DefaultRoute;
find_suitable_relay(Key, [{Regexp, Relay} | Routes], DefaultRoute) ->
    case re:run(Key, Regexp, [{capture, none}]) of
        nomatch -> find_suitable_relay(Key, Routes, DefaultRoute);
        _ -> Relay
    end;
find_suitable_relay(Key, [{Regexp, Relay, PoolName} | Routes], DefaultRoute) ->
    case re:run(Key, Regexp, [{capture, none}]) of
        nomatch -> find_suitable_relay(Key, Routes, DefaultRoute);
        _ -> {Relay, PoolName}
    end.

% @private
-spec get_key(Username :: binary() | string() | [], Type :: atom(), Strip :: boolean(), Separator :: list()) ->
    {Key :: not_found | string(), NewUsername :: string()}.
get_key([], _, _, _) -> {not_found, []};
get_key(Username, Type, Strip, Separator) when is_binary(Username) ->
    get_key(binary_to_list(Username), Type, Strip, Separator);
get_key(Username, realm, Strip, Separator) ->
    Realm = lists:last(string:tokens(Username, Separator)),
    {Realm, strip(Username, realm, Strip, Separator)};
get_key(Username, prefix, Strip, Separator) ->
    Prefix = hd(string:tokens(Username, Separator)),
    {Prefix, strip(Username, prefix, Strip, Separator)};
get_key(Username, _, _, _) -> {not_found, Username}.

% @private
-spec strip(Username :: string(), Type :: atom(), Strip :: boolean(), Separator :: list()) ->
    NewUsername :: string().
strip(Username, _, false, _) -> Username;
strip(Username, realm, true, Separator) ->
    case string:tokens(Username, Separator) of
        [Username] -> Username;
        [_ | _] = List ->
            [_ | Tail] = lists:reverse(List),
            string:join(lists:reverse(Tail), Separator)
    end;
strip(Username, prefix, true, Separator) ->
    case string:tokens(Username, Separator) of
        [Username] -> Username;
        [_ | Tail] -> string:join(Tail, Separator)
    end.

route({RouteName, RouteRelay}) -> {RouteName, RouteRelay, undefined};
route({_RouteName, _RouteRelay, _Pool} = Route) -> Route.

get_routes_info(HandlerOpts) ->
    DefaultRoute = lists:keyfind(default_route, 1, HandlerOpts),
    Routes = lists:keyfind(routes, 1, HandlerOpts),
    Options = lists:keyfind(options, 1, HandlerOpts),
    Retries = case Options of
                  false ->
                      ?DEFAULT_CLIENT_RETRIES;
                  {options, Opts} ->
                      proplists:get_value(retries, Opts, ?DEFAULT_CLIENT_RETRIES)
              end,
    {DefaultRoute, Routes, Retries}.

put_default_route_to_pool(false, _) -> ok;
put_default_route_to_pool({default_route, {Host, Port, _Secret}}, Retries) ->
    eradius_client:store_radius_server_from_pool(Host, Port, Retries);
put_default_route_to_pool({default_route, {Host, Port, _Secret}, _PoolName}, Retries) ->
    eradius_client:store_radius_server_from_pool(Host, Port, Retries);
put_default_route_to_pool(_, _) -> ok.

put_routes_to_pool(false, _Retries) -> ok;
put_routes_to_pool({routes, Routes}, Retries) ->
    lists:foreach(fun (Route) ->
        case Route of
            {_RouteName, {Host, Port, _Secret}} ->
                eradius_client:store_radius_server_from_pool(Host, Port, Retries);
            {_RouteName, {Host, Port, _Secret}, _Pool} ->
                eradius_client:store_radius_server_from_pool(Host, Port, Retries);
            {Host, Port, _Secret, _Opts} ->
                eradius_client:store_radius_server_from_pool(Host, Port, Retries);
            _ -> ok
        end
    end, Routes).

get_proxy_opt(_, [], Default)                            -> Default;
get_proxy_opt(OptName, [{OptName, AddrOrRoutes} | _], _) -> AddrOrRoutes;
get_proxy_opt(OptName, [{OptName, Addr, Pool} | _], _)   -> {Addr, Pool};
get_proxy_opt(OptName, [_ | Args], Default)              -> get_proxy_opt(OptName, Args, Default).
