%% @doc
%%   This module implements a RADIUS proxy.
%%
%%   It accepts following configuration:
%%
%%   ```
%%   [{default_route, {{127, 0, 0, 1}, 1813, <<"secret">>}},
%%    {options, [{type, realm}, {strip, true}, {separator, "@"}]},
%%    {routes,  [{"^test-[0-9].", {{127, 0, 0, 1}, 1815, <<"secret1">>}}]}],
%%   ```
%%
%%   == WARNING ==
%%
%%   Define `routes` carefully. The `test` here in example above, is
%%   a regular expression that may cause to problemts with performance.
-module(eradius_proxy).

-behaviour(eradius_server).
-export([radius_request/3, validate_arguments/1]).

-ifdef(TEST).
-export([resolve_routes/4, validate_options/1, new_request/3,
         get_key/4, strip/4]).
-endif.

-include("eradius_lib.hrl").
-include("dictionary.hrl").

-define(DEFAULT_TYPE, realm).
-define(DEFAULT_STRIP, false).
-define(DEFAULT_SEPARATOR, "@").

-define(DEFAULT_OPTIONS, [{type, ?DEFAULT_TYPE},
                          {strip, ?DEFAULT_STRIP},
                          {separator, ?DEFAULT_SEPARATOR}]).

-type route() :: eradius_client:nas_address().
-type routes() :: [{Name :: string(), route()}].
-type undefined_route() :: {undefined, 0, []}.

radius_request(Request, _NasProp, Args) ->
    DefaultRoute = proplists:get_value(default_route, Args),
    Options = proplists:get_value(options, Args, ?DEFAULT_OPTIONS),
    Username = eradius_lib:get_attr(Request, ?User_Name),
    Routes = proplists:get_value(routes, Args, []),
    {NewUsername, Route} = resolve_routes(Username, DefaultRoute, Routes, Options),
    send_to_server(new_request(Request, Username, NewUsername), Route).

validate_arguments(Args) ->
    DefaultRoute = proplists:get_value(default_route, Args, {undefined, 0, []}),
    Options = proplists:get_value(options, Args, ?DEFAULT_OPTIONS),
    Routes = proplists:get_value(routes, Args, []),
    case {validate_route(DefaultRoute), validate_options(Options), compile_routes(Routes)} of
        {false, _, _} -> default_route;
        {_, false, _} -> options;
        {_, _, false} -> routes;
        {_, _, NewRoutes} ->
            {true, [{default_route, DefaultRoute}, {options, Options}, {routes, NewRoutes}]}
    end.

compile_routes(Routes) ->
    RoutesOpts = lists:map(fun ({Name, Relay}) ->
        case re:compile(Name) of
            {ok, R} ->
                case validate_route(Relay) of
                    false -> false;
                    _ -> {R, Relay}
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
-spec send_to_server(Request :: #radius_request{}, Route :: undefined_route() | route()) ->
    {reply, Reply :: #radius_request{}} | term().
send_to_server(_Request, {undefined, 0, []}) ->
    {error, no_route};
send_to_server(#radius_request{reqid = ReqID} = Request, {Server, Port, Secret}) ->
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
            lager:error("~p: request is incorrect (~p)", [?MODULE, Error]),
            Error
    end.

% @private
-spec validate_route({Ip :: list() | inet:ip_address(), Port :: eradius_server:port_number(), Secret :: eradius_lib:secret()}) ->
    boolean().
validate_route({_Ip, Port, _Secret}) when not is_integer(Port); Port =< 0; Port > 65535 -> false;
validate_route({_Ip, _Port, Secret}) when not is_list(Secret), not is_binary(Secret) -> false;
validate_route({Ip, _Port, _Secret}) when is_list(Ip) ->
    {Res, _} = inet_parse:address(Ip),
    Res =:= ok;
validate_route({Ip, Port, Secret}) when is_tuple(Ip) ->
    case inet_parse:ntoa(Ip) of
        {error, _} -> false;
        Address -> validate_route({Address, Port, Secret})
    end;
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
            case find_suitable_relay(Key, Routes) of
                {Key, {_IP, _Port, _Secret} = Route} -> {NewUsername, Route};
                _ -> {NewUsername, DefaultRoute}
            end
    end.

find_suitable_relay(_Key, []) -> [];
find_suitable_relay(Key, [{Regexp, Relay} | Routes]) ->
    case re:run(Key, Regexp, [{capture, none}]) of
        nomatch -> find_suitable_relay(Key, Routes);
        _ -> {Key, Relay}
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

% @TODO have no need in it right nowm but maybe we will use it later
%update_proxy_metric(DefaultRouter, IP, Port) ->
%    case DefaultRouter of
%	undefined ->
%	    MetricName = eradius_metrics:get_metric_name(IP, Port, routes_not_resolved, proxy),
%	    exometer:update_or_create(MetricName, 1, spiral, [{time_span, 1000}]);
%	_ ->
%	    MetricName = eradius_metrics:get_metric_name(IP, Port, routes_resolved, proxy),
%	    exometer:update_or_create(MetricName, 1, spiral, [{time_span, 1000}])
%    end.

