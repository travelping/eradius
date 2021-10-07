# eradius

[![Hex.pm Version][hexpm version]][hexpm]
[![Hex.pm Downloads][hexpm downloads]][hexpm]
[![Coverage Status][coveralls badge]][coveralls]
[![Build Status][gh badge]][gh]
[![Erlang Versions][erlang version badge]][gh]

This fork of `eradius` is a radical deviation from the original
Jungerl code. It contains a generic [RADIUS](https://en.wikipedia.org/wiki/RADIUS) client, support for
several authentication mechanisms and dynamic configuration
(it implements the `config_change/3` application callback).

# Contents

* [Erlang Version Support](#erlang-version-support)
* [Building eradius](#building-eradius)
* [Using eradius](#using-eradius)
* [Run sample server](#run-sample-server)
* [Metrics](#metrics)
* [RADIUS server configuration](#radius-server-configuration)
  * [eradius configuration example 1](#eradius-configuration-example-1)
  * [eradius configuration example 2](#eradius-configuration-example-2)
  * [eradius configuration example 3](#eradius-configuration-example-3)
  * [eradius configuration example 4](#eradius-configuration-example-4)
* [Support of failover for client](#support-of-failover-for-client)
  * [Failover configuration](#failover-configuration)
  * [Failover Erlang code usage](#failover-erlang-code-usage)
* [Eradius counter aggregator](#eradius-counter-aggregator)
* [Tables](#tables)

# Erlang Version Support

All minor version of the current major release and the highest minor version of the
previous major release will be supported.
At the moment this means OTP `21.3`, OTP `22.x`, OTP `23.x` and OTP `24.x` are supported. OTP versions before `21.0`
do not work due the use of logger. When in doubt check the `otp_release` section in
[main.yml](.github/workflows/main.yml) for tested versions.

# Building eradius

```sh
$ rebar3 compile
```

# Using eradius

Eradius requires a certain degree of configuration which is described in the
app.src file. Minimal examples of server callbacks can be found in the tests.

# Run sample server

```sh
$ cd sample
$ rebar3 shell --config example.config --apps eradius_server_sample
```

Then run a simple benchmark:

```erlang
1> eradius_server_sample:test().
...
13:40:43.979 [info] 127.0.0.1:59254 [8]: Access-Accept
13:40:43.979 [info] 127.0.0.1:59254 [6]: Access-Accept
13:40:43.980 [info] 127.0.0.1:59254 [3]: Access-Accept
13:40:43.980 [info] 127.0.0.1:59254 [0]: Access-Accept
4333.788381 req/sec.
ok
```

# Metrics

Eradius exposes following metrics via exometer:
  * counter and handle time for requests
  * counter for responses (this includes acks, naks, accepts etc.)

The measurements are available for client, server and also for the specific
NAS callbacks. Further they are exposed in a 'total' fashion but also itemized
by request/response type (e.g. access request, accounting response etc.).

It is possible to expose measurements compliant with [RFC 2619](https://tools.ietf.org/html/rfc2619) and [RFC 2621](https://tools.ietf.org/html/rfc2621) using
the build in metrics.

The handle time metrics are generated internally using histograms. These histograms
all have a time span of 60s. The precise metrics are defined in [include/eradius_metrics.hrl](include/eradius_metrics.hrl).

See more in [METRICS.md](METRICS.md).

# RADIUS server configuration

> :warning: **Notes** :warning:
> * Square brackets ([]) denote an array that consists of n comma-separated objects.
> * Curly brackets ({}) denote a tuple that consists of a defined number of objects.

Servers in this configuration are endpoints consisting of an IPv4 address and one or more ports.  
`servers` is a list `[]` of said endpoints:
```
servers == { servers, [<Server>] }
```
Each server is tuple ({}):
```
Server == { <SymbolicName>, { <IP>, [<Ports>] } } | { <SymbolicName>, { <IP>, [<Ports>], <ExtraSocketOptions> } }
ExtraServerOptions == [<ServerOption>]
ExtraSocketOptions == [{socket_opts, [socket_setopt()]}] (see: https://erlang.org/doc/man/inet.html#setopts-2)
ServerOption == {rate_config, <SymbolicNameLimit> | <RateConfigList>}
```

Rate configuration can be configured per server, in extra configuration, with a symbolic name or directly in server
```
{SymbolicNameLimit, RateConfigList}
RateConfigList == [<RateOption>]
RateOption == { limit | max_size | max_time, integer() | undefined }
```

Each server is assigned a list of handlers. This list defines the NASes that are allowed to send RADIUS requests to a server and
which handler is to process the request.

Handler assignment: `{<SymbolicName>, [<Handlers>]}`

```
SymbolicName == Reference to a previously defined server.
Handler == { <HandlerDefinition>, [<Sources>] }
```

If only one handler module is used, it can be defined globally as `{radius_callback, <HandlerMod>}`.
If more than one handler modules are used, they have to be given in the HandlerDefinition:

```
HandlerDefinition == {<HandlerMod>, <NasId>, <HandlerArgs>} | {<NasId>, <HandlerArgs>}
HandlerMod == Handler module to process the received requests.
NasId == String describing the Source.
HandlerArgs == List of arguments givent the handler module.
Source == {<IP>, <Secret>} | {<IP>, <Secret>, [<SourceOption>]}
SourceOption == {group, <GroupName>} | {nas_id, <NasId> }

IP == IPv4 source address.
Secret == Binary. Passphrase, the NAS authenticates with.
GroupName:
RADIUS requests received by a server are forwarded to lists of nodes.
The lists are assigned to handlers, so the RADIUS requests of every handler can be forwarded to different nodes, if necessary.
The lists are referenced by a GroupName. If only one group is defined, the GroupName can be omitted.
In this case, all handlers forward their requests to the same list of nodes.
Session nodes == {session_nodes, ['node@host', ...]} | {session_nodes, [{<GroupName>, ['node@host', ...]}]}
```

## eradius configuration example 1

All requests are forwarded to the same globally defined list of nodes.
Only one handler module is used.

```erlang
[{eradius, [
    {session_nodes, ['node1@host1', 'node2@host2']},
    {radius_callback, tposs_pcrf_radius},
    {servers, [
        {root, {"127.0.0.1", [1812, 1813]}}
    ]},
    {root, [
        {
            {"NAS1", [handler_arg1, handler_arg2]},
            [ {"10.18.14.2", <<"secret1">>} ]
        },
        {
            {"NAS2", [handler_arg1, handler_arg2]},
            [ {"10.18.14.3", <<"secret2">>, [{nas_id, <<"name">>}]} ]
        }
    ]}
]}]
```

## eradius configuration example 2

Requests of different sources are forwarded to different nodes.
Different handlers are used for the sources.

```erlang
[{eradius, [
    {session_nodes, [
        {"NodeGroup1", ['node1@host1', 'node2@host2']},
        {"NodeGroup2", ['node3@host3', 'node4@host4']}
    ]},
    {servers, [
        {root, {"127.0.0.1", [1812, 1813]}}
    ]},
    {root, [
        {
            {tposs_pcrf_handler1, "NAS1", [handler_arg1, handler_arg2]},
            [ {"10.18.14.2", <<"secret1">>, [{group, "NodeGroup1"}]} ]
        },
        {
            {tposs_pcrf_handler2, "NAS2", [handler_arg3, handler_arg4]},
            [ {"10.18.14.3", <<"secret2">>, [{group, "NodeGroup2"}]} ]
        }
    ]}
]}]
```

## eradius configuration example 3

Requests of different sources are forwarded to different nodes.
Different handlers are used for the sources.

```erlang
[{eradius, [
    {session_nodes, [
        {"NodeGroup1", ['node1@host1', 'node2@host2']},
        {"NodeGroup2", ['node3@host3', 'node4@host4']}
    ]},
    {servers, [
        {root, {"127.0.0.1", [1812, 1813], [{socket_opts, [{recbuf, 8192},
                                                           {netns, "/var/run/netns/myns"}]}]}}
    ]},
    {root, [
        {
            {tposs_pcrf_handler1, "NAS1", [handler_arg1, handler_arg2]},
            [ {"10.18.14.2", <<"secret1">>, [{group, "NodeGroup1"}]} ]
        },
        {
            {tposs_pcrf_handler2, "NAS2", [handler_arg3, handler_arg4]},
            [ {"10.18.14.3", <<"secret2">>, [{group, "NodeGroup2"}]} ]
        }
    ]}
]}]
```

## eradius configuration example 4

Example of full configuration with keys which can use in `eradius`:

```erlang
[{eradius, [
    %% The IP address used to send RADIUS requests
    {client_ip, {127, 0, 0, 1}},
    %% The maximum number of open ports that will be used by RADIUS clients
    {client_ports, 256},
    %% how long the binary response is kept before re-sending it
    {resend_timeout, 500},
    %% List of RADIUS dictionaries
    {tables, [dictionary]},
    %% List of nodes where RADIUS requests possibly will be forwarded by a RADIUS server
    {session_nodes, local},
    %% A RADIUS requests handler callback module
    {radius_callback, eradius_server_sample},
    %% NAS specified for `root` RADIUS server
    {root, [
        {{"root", []}, [{"127.0.0.1", "secret"}]}
    ]},
    %% NAS specified for `acct` RADIUS server
    {acct, [
        {{eradius_proxy, "radius_acct", [{default_route, {{127, 0, 0, 2}, 1813, <<"secret">>}, pool_name}]},
        [{"127.0.0.1", "secret"}]}
    ]},
    %% List of RADIUS servers
    {servers, [
        {root, {"127.0.0.1", [1812]}},
        {acct, {"127.0.0.1", [1813]}}
    ]},
    {counter_aggregator, false},
    %% List of histogram buckets for RADIUS servers metrics 
    {histogram_buckets, [10, 30, 50, 75, 100, 1000, 2000]},
    %% Simple file-based logging of RADIUS requests and metadata
    {logging, true},
    %% Path to log file
    {logfile, "./radius.log"},
    %% List of upstream RADIUS servers pools 
    {servers_pool, [
        {pool_name, [
            {{127, 0, 0, 2}, 1812, <<"secret">>, [{retries, 3}]},
            {{127, 0, 0, 3}, 1812, <<"secret">>}
        ]}
    ]},
    {server_status_metrics_enabled, false},
    {counter_aggregator, false},
    %% Size of RADIUS receive buffer
    {recbuf, 8192}
]}].
```

# Support of failover for client

Added support for fail-over.  
Set of secondary RADIUS servers could be passed to the RADIUS client API `eradius_client:send_request/3` via options or to RADIUS proxy via configuration.

If the response wasn't received after a number of requests specified by `retries` RADIUS client options - such RADIUS servers will be marked as non-active and RADIUS requests will not be sent for such non-active RADIUS servers, while configurable timeout (`eradius.unreachable_timeout`) is not expired.

Secondary RADIUS servers could be specified via RADIUS proxy configuration, with the new configuration option - pool name.

## Failover configuration

Configuration example of failover where the `pool_name` is `atom` specifies name of a pool of secondary RADIUS servers.

```erlang
[{eradius, [
    %%% ...
    {default_route, {{127, 0, 0, 1}, 1812, <<"secret">>}, pool_name}
    %%% ...
]}]
```
All pools are configured via:
```erlang
[{eradius, [
    %%% ...
    {servers_pool, [
        {pool_name, [
            {{127, 0, 0, 2}, 1812, <<"secret">>, [{retries, 3}]},
            {{127, 0, 0, 3}, 1812, <<"secret">>}
        ]}
    ]}
    %%% ...
]}]
```

## Failover Erlang code usage
In a case when RADIUS proxy (eradius_proxy handler) is not used, a list of RADIUS upstream servers could be passed to the `eradius_client:send_radius_request/3` via options, for example:

```erlang
eradius_client:send_request(Server, Request, [{failover, [{"localhost", 1814, <<"secret">>}]}]).
```

If `failover` option was not passed to the client through the options or RADIUS proxy configuration there should not be any performance impact as RADIUS client will try to a RADIUS request to only one RADIUS server that is defined in `eradius_client:send_request/3` options.

For each secondary RADIUS server server status metrics could be enabled via boolean `server_status_metrics_enabled` configuration option.

# Eradius counter aggregator
The `eradius_counter_aggregator` would go over all nodes in an Erlang cluster and aggregate the counter values from all nodes.  
Configuration value of `counter_aggregator` can be `true` or `false` where `true` - is enable, `false` - is disable counter aggregator.  
By default the `counter_aggregator` is disabled and have default value `false`.
Configuration example:
```erlang
[{eradius, [
    %%% ...
    {counter_aggregator, true}
    %%% ...
]}]
```

# Tables

A list of RADIUS dictionaries to be loaded at startup. The atoms in this list are resolved to files in
the `priv` directory of the eradius application.

Example:

```
    [dictionary, dictionary_cisco, dictionary_travelping]
```

<!-- Badges -->
[hexpm]: https://hex.pm/packages/eradius
[hexpm version]: https://img.shields.io/hexpm/v/eradius.svg?style=flat-square
[hexpm downloads]: https://img.shields.io/hexpm/dt/eradius.svg?style=flat-square
[coveralls]: https://coveralls.io/github/travelping/eradius
[coveralls badge]: https://img.shields.io/coveralls/travelping/eradius/master.svg?style=flat-square
[gh]: https://github.com/travelping/eradius/actions/workflows/main.yml
[gh badge]: https://img.shields.io/github/workflow/status/travelping/eradius/CI?style=flat-square
[erlang version badge]: https://img.shields.io/badge/erlang-22.0%20to%2024.0.1-blue.svg?style=flat-square
