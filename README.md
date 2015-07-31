# eradius [![Build Status](https://travis-ci.org/travelping/eradius.svg)](https://travis-ci.org/travelping/eradius) [![Coverage Status](https://coveralls.io/repos/travelping/eradius/badge.svg?branch=master&service=github)](https://coveralls.io/github/travelping/eradius?branch=master)

This fork of eradius is a radical deviation from the original
Jungerl code. It contains a generic RADIUS client, support for 
several authentication mechanisms and dynamic configuration
(it implements the `config_change/3` application callback).

## Building eradius

```
$ rebar get-deps && rebar compile
```
