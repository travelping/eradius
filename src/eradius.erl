-module(eradius).

-moduledoc "Main module of the eradius application.".

-behaviour(application).

%% API
-export([load_tables/1, load_tables/2,
         start_server/3, start_server/4]).
-ignore_xref([load_tables/1, load_tables/2,
              start_server/3, start_server/4]).

%% application callbacks
-export([start/2, stop/1]).

%% internal use

-include("eradius_lib.hrl").

%%%=========================================================================
%%%  API
%%%=========================================================================

-doc "Load RADIUS dictionaries from the default directory.".
-spec load_tables(list(eradius_dict:table_name())) -> ok | {error, {consult, eradius_dict:table_name()}}.
load_tables(Tables) ->
    eradius_dict:load_tables(Tables).

-doc "Load RADIUS dictionaries from a certain directory.".
-spec load_tables(Dir :: file:filename(), Tables :: [Table :: eradius_dict:table_name()]) ->
          ok | {error, {consult, Table :: eradius_dict:table_name()}}.
load_tables(Dir, Tables) ->
    eradius_dict:load_tables(Dir, Tables).

-doc """
Start a RADIUS server under the eradius supervision tree.

`IP` is the address to listen on (`any` binds on all interfaces).
`Port` is the UDP port (e.g. 1812 for authentication, 1813 for accounting).
`Opts` must include `handler` (a `{Module, HandlerData}` tuple) and `clients`
(a map of `inet:ip_address() => t:eradius_server:client/0`).

Example:
```
{ok, Pid} = eradius:start_server({127,0,0,1}, 1812,
    #{handler => {my_handler, []},
      clients => #{{127,0,0,1} => #{secret => <<"mysecret">>,
                                    client => <<"my-nas">>}}}).
```

See `eradius_server:start_instance/3`.
""".
-spec start_server(IP :: 'any' | inet:ip_address(), Port :: inet:port_number(),
                   Opts :: eradius_server:server_opts()) -> gen_server:start_ret().
start_server(IP, Port, #{handler := {_, _}, clients := #{}} = Opts)
  when (IP =:= any orelse is_tuple(IP)) andalso
       is_integer(Port) andalso Port >= 0 andalso Port < 65536 ->
    eradius_server:start_instance(IP, Port, Opts).

-doc """
Start a named RADIUS server under the eradius supervision tree.

Same as `start_server/3` but registers the process under `ServerName`.

See `eradius_server:start_instance/4`.
""".
-spec start_server(ServerName :: gen_server:server_name(),
                   IP :: 'any' | inet:ip_address(), Port :: inet:port_number(),
                   Opts :: eradius_server:server_opts()) -> gen_server:start_ret().
start_server(ServerName, IP, Port, #{handler := {_, _}, clients := #{}} = Opts)
  when (IP =:= any orelse is_tuple(IP)) andalso
       is_integer(Port) andalso Port >= 0 andalso Port < 65536 ->
    eradius_server:start_instance(ServerName, IP, Port, Opts).

%%%===================================================================
%%% application callbacks
%%%===================================================================

%% @private
start(_StartType, _StartArgs) ->
    eradius_sup:start_link().

%% @private
stop(_State) ->
    ok.
