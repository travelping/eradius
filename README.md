# eradius

[![Hex.pm Version][hexpm version]][hexpm]
[![Hex.pm Downloads][hexpm downloads]][hexpm]
[![Build Status][gh badge]][gh]
[![Erlang Versions][erlang version badge]][gh]

eradius is a library for embedding [RADIUS] client and server functionality in Erlang applications.

v3 is a ground-up rewrite. It is **not API-compatible with v2**.

# Contents

* [Why a major, breaking rewrite?](#why-a-major-breaking-rewrite)
* [Erlang Version Support](#erlang-version-support)
* [Building eradius](#building-eradius)
* [Using eradius](#using-eradius)
* [Metrics](#metrics)
* [Tables](#tables)

# Why a major, breaking rewrite?

**The API was already broken.** In the period leading up to v3, several features were added
to v2 that introduced incompatible changes in call signatures (per-server timeout/retries,
IPv6 support, socket option tuning). A clean slate was cheaper than continued patching.

**Request dispatching is not a RADIUS concern.** v2 included cluster-aware request routing —
distributing requests across nodes, tracking node availability, and selecting targets based
on cluster state. None of that logic is specific to RADIUS. It belongs in a generic
load-balancer or service-mesh layer that the application already has (or should have).
Keeping it in eradius created coupling between the protocol library and deployment topology.

**The built-in proxy belongs elsewhere.** v2 shipped a RADIUS proxy implementation. A
production-grade proxy requires policy engines, accounting correlation, attribute rewriting,
and operational tooling that a library can never provide adequately. Purpose-built RADIUS
servers (FreeRADIUS, Radiator) do this far better. The proxy in v2 was a maintenance
liability that gave a false sense of completeness.

**Jungerl heritage.** The codebase traces back to Martin Björklund and Torbjörn Törnkvist's
2002–2007 Jungerl code, written before records were replaced by maps, before `supervisor`
had modern child-spec conventions, and before the OTP documentation system existed.
Continuing to layer features on top meant carrying forward API shapes that had no rationale
beyond historical accident.

**Maps over records.** The entire request/response lifecycle is now expressed as a single
`eradius_req:req()` map. Handler modules receive a plain map, transform it, and return it.
No record definitions to import, no opaque types to thread through. The same approach
applies to client and server configuration — one map, no positional tuples.

**Metrics as a callback.** v2 hard-wired Prometheus. v3 exposes a `metrics_callback`
option: a 3-arity fun the application provides. Any metrics backend works. Applications
that do not want metrics pay no overhead.

**OTP 27 as baseline.** Requiring OTP 27.3 lets the library use `maybe` expressions
natively, the new `-doc`/`-moduledoc` attributes for proper documentation tooling, and
the latest supervision and gen_server interfaces without compatibility shims.

# Erlang Version Support

eradius v3.0 requires OTP-27.3 or later.

When in doubt check the `otp_release` section in [main.yml](.github/workflows/main.yml) for
the exact versions tested in CI.

# Building eradius

```sh
$ rebar3 compile
```

# Using eradius

## Implementing a RADIUS server

A RADIUS server handler is a module that implements the `eradius_server` behaviour.
It receives decoded `eradius_req:req()` maps and returns a response:

```erlang
-module(my_handler).
-behaviour(eradius_server).

-include_lib("eradius/include/eradius_lib.hrl").   %% attribute macros

radius_request(#{cmd := request} = Req, _HandlerData) ->
    %% Inspect attributes
    {Attrs, _} = eradius_req:attrs(Req),
    UserName = proplists:get_value(?User_Name, Attrs),
    io:format("Access-Request from ~s~n", [UserName]),

    %% Build and return the response
    Resp = eradius_req:set_attrs([], Req#{cmd := accept}),
    {reply, Resp};
radius_request(_Req, _HandlerData) ->
    noreply.
```

Start the server (requires the `eradius` application to be running):

```erlang
{ok, _Pid} = eradius:start_server({127,0,0,1}, 1812,
    #{server_name => my_radius_server,
      handler     => {my_handler, []},
      clients     => #{{127,0,0,1} => #{secret => <<"mysecret">>,
                                        client => <<"my-nas">>}}}).
```

The `clients` map controls which source IPs are accepted. Packets from unlisted IPs are
silently discarded. See `eradius_server:server_opts()` for the full option reference.

## Sending RADIUS requests (client)

Start a named client manager, then use `eradius_client:send_request/3,4` to send requests:

```erlang
%% Start a client manager once (e.g. in your application start)
{ok, _} = eradius_client_mngr:start_client({local, my_client},
    #{family  => inet,
      ip      => any,
      servers => #{
          auth_server => #{ip      => {192,168,1,1},
                           port    => 1812,
                           secret  => <<"mysecret">>,
                           retries => 3,
                           timeout => 5000}
      }}),

%% Send an Access-Request
Req = eradius_req:set_attrs(
    [{?User_Name,     <<"alice">>},
     {?User_Password, <<"password">>}],
    eradius_req:new(request)),

{{ok, Resp}, _Req} = eradius_client:send_request(my_client, auth_server, Req, #{}),
accept = eradius_req:cmd(Resp).
```

## Failover between servers

Define a pool as a list of server names, then pass the pool in the `failover` option:

```erlang
{ok, _} = eradius_client_mngr:start_client({local, my_client},
    #{family  => inet,
      ip      => any,
      servers => #{
          primary   => #{ip => {10,0,0,1}, port => 1812, secret => <<"s1">>},
          secondary => #{ip => {10,0,0,2}, port => 1812, secret => <<"s2">>},
          auth_pool => [primary, secondary]
      }}),

%% Try primary first; on failure, try each server in auth_pool
{{ok, Resp}, _} = eradius_client:send_request(my_client, primary, Req,
    #{retries => 1, failover => [auth_pool]}).
```

See `eradius_client:options()` and `eradius_client_mngr:client_opts()` for all options.

# Metrics

A sample metrics callback module is provided that exposes metrics through prometheus.erl that
are compatible with the metrics that where included in previous versions.

See more in [METRICS.md](METRICS.md).

# Tables

A list of RADIUS dictionaries to be loaded at startup. The atoms in this list are resolved to files in
the `priv` directory of the eradius application.

Example:

```
    [dictionary, dictionary_cisco, dictionary_travelping]
```

<!-- Badges and Links-->
[hexpm]: https://hex.pm/packages/eradius
[hexpm version]: https://img.shields.io/hexpm/v/eradius.svg?style=flat-square
[hexpm downloads]: https://img.shields.io/hexpm/dt/eradius.svg?style=flat-square
[gh]: https://github.com/travelping/eradius/actions/workflows/main.yml
[gh badge]: https://img.shields.io/github/workflow/status/travelping/eradius/CI?style=flat-square
[erlang version badge]: https://img.shields.io/badge/erlang-27.3%2B-blue.svg?style=flat-square
[RADIUS]: https://en.wikipedia.org/wiki/RADIUS
