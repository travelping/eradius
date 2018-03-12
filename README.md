# eradius [![Build Status](https://travis-ci.org/travelping/eradius.svg)](https://travis-ci.org/travelping/eradius) [![Coverage Status](https://coveralls.io/repos/travelping/eradius/badge.svg?branch=master&service=github)](https://coveralls.io/github/travelping/eradius?branch=master)

This fork of eradius is a radical deviation from the original
Jungerl code. It contains a generic RADIUS client, support for
several authentication mechanisms and dynamic configuration
(it implements the `config_change/3` application callback).

## Building eradius

```
$ rebar3 compile
```

## Using eradius

Eradius requires a certain degree of configuration which is described in the
app.src file. Minimal examples of server callbacks can be found in the tests.

## Run sample server

```
$ cd sample
$ rebar3 shell --config example.config --apps eradius_server_sample
```

Then run a simple benchmark:

```
1> eradius_server_sample:test().
...
13:40:43.979 [info] 127.0.0.1:59254 [8]: Access-Accept
13:40:43.979 [info] 127.0.0.1:59254 [6]: Access-Accept
13:40:43.980 [info] 127.0.0.1:59254 [3]: Access-Accept
13:40:43.980 [info] 127.0.0.1:59254 [0]: Access-Accept
4333.788381 req/sec.
ok
```

## Metrics

Eradius exposes following metrics via exometer:

  * counter and handle time for requests
  * counter for responses (this includes acks, naks, accepts etc.)

The measurements are available for client, server and also for the specific
NAS callbacks. Further they are exposed in a 'total' fashion but also itemized
by request/response type (e.g. access request, accounting response etc.).

It is possible to expose measurements compliant with RFC 2619 and RFC 2621 using
the build in metrics.

The handle time metrics are generated internally using histograms. These histograms
all have a time span of 60s. The precise metrics are defined in `include/eradius_metrics`.

See more in [METRICS.md](METRICS.md).
