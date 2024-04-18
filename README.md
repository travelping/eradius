# eradius

[![Hex.pm Version][hexpm version]][hexpm]
[![Hex.pm Downloads][hexpm downloads]][hexpm]
[![Build Status][gh badge]][gh]
[![Erlang Versions][erlang version badge]][gh]

eradius is a library to add [RADIUS] client and server funtionality to Erlang applications.

v3 of eradius is in many places a full rewrite of the v2 versions and is not API compatible
with older versions.

Previous versions provided generic, standalone [RADIUS] servers and proxies. This generic
functionality is better handled by existing, feature rich, stand alone RADIUS servers.

This versions aims a providing support for implementing a versatile, simple to use
RADIUS client and a flexible library for implementing sue case specific RADIUS server
functionality.

v2 was based on the original Jungerl code, some piece of it might have survived.
This fork of `eradius` is a radical deviation from the original
Jungerl code. It contains a generic [RADIUS](https://en.wikipedia.org/wiki/RADIUS) client, support for
several authentication mechanisms and dynamic configuration
(it implements the `config_change/3` application callback).

# Contents

* [Erlang Version Support](#erlang-version-support)
* [Building eradius](#building-eradius)
* [Using eradius](#using-eradius)
* [Metrics](#metrics)
* [Tables](#tables)

# Erlang Version Support

All minor version of the current major release and the highest minor version of the
previous major release will be supported.
At the time of writing, OTP `25.3`, `26.0` `26.1` and `26.2` are supported.
When in doubt check the `otp_release` section in [main.yml](.github/workflows/main.yml) for
tested versions.

> #### NOTE {: .tip}
>
> OTP-25 does not support the `-feature(maybe_expr, enable).` compiler directive, it is therefore necessary to pass the `-enable-feature all` option to the compiler.

## Planned incompatiblities

### v3.1 will require OTP-27

The current planning is to switch to documentation support introduced with OTP-27 for the v3.1
release. That release will therefore drop support for pre OTP-27 releases.

# Building eradius

```sh
$ rebar3 compile
```

# Using eradius

Eradius client are started and configured through their APIs. See `m:eradius_server` and
`m:eradius_client` for the APIs and settings.

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
[erlang version badge]: https://img.shields.io/badge/erlang-25.3%20to%2026.2-blue.svg?style=flat-square
[RADIUS]: https://en.wikipedia.org/wiki/RADIUS
