# eradius

[![Build Status][travis badge]][travis]
[![Coverage Status][coveralls badge]][coveralls]
[![Erlang Versions][erlang version badge]][travis]

This fork of eradius is a radical deviation from the original
Jungerl code. It contains a generic RADIUS client, support for
several authentication mechanisms and dynamic configuration
(it implements the `config_change/3` application callback).

## Erlang Version Support

All minor version of the current major release and the highest minor version of the
previous major release will be supported.
At the moment this means OTP 21.3 and OTP 22.x are supported. OTP versions before 21.0
do not work due the use of logger. When in doubt check the `otp_release` section in
[.travis.yml](.travis.yml) for tested versions.

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

<!-- Badges -->
[travis]: https://travis-ci.com/travelping/eradius
[travis badge]: https://img.shields.io/travis/com/travelping/eradius/master.svg?style=flat-square
[coveralls]: https://coveralls.io/github/travelping/eradius
[coveralls badge]: https://img.shields.io/coveralls/travelping/eradius/master.svg?style=flat-square
[erlang version badge]: https://img.shields.io/badge/erlang-R21.0%20to%2022.3-blue.svg?style=flat-square
