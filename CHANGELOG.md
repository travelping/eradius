eradius
=======

A generic RADIUS client and server.

Version 2.2.4 - 9 August 2021
---------------------------

**Bugfixes** :bug:
* [#213](https://github.com/travelping/eradius/pull/213) Fix updating of server status metric

Version 2.2.3 - 29 July 2021
---------------------------

**Features** :rocket:
* [#208](https://github.com/travelping/eradius/pull/208) Add `server_status` metric
* [#210](https://github.com/travelping/eradius/pull/210) Make server status metrics optional

**Bugfixes** :bug:
* [#209](https://github.com/travelping/eradius/pull/209) Fix `NAS` name in metrics test commen

Version 2.2.2 - 23 June 2021
---------------------------

**Features** :rocket:
* [#203](https://github.com/travelping/eradius/pull/203) Adding `RADIUS` dictionary for `APC` by `Schneider Electric`

**Bugfixes** :bug:
* [#192](https://github.com/travelping/eradius/pull/192) Fix building of eradius with `persistent_term`
* [#204](https://github.com/travelping/eradius/pull/204) Fix gathering of `RADIUS` `Accounting` metrics

**Refactorings** :fire:
* [#194](https://github.com/travelping/eradius/pull/194) Use `ets:update_counter` to update `RADIUS` metrics

**Dependencies** :gear:
* [#205](https://github.com/travelping/eradius/pull/205) Update [prometheus](https://github.com/deadtrickster/prometheus.erl) tag to [4.8.1](https://github.com/deadtrickster/prometheus.erl/releases/tag/v4.8.1)

Version 2.2.1 - 4 February 2021
---------------------------

**Features** :rocket:
* [#176](https://github.com/travelping/eradius/pull/176) Added [SemVer](https://semver.org/)

**Bugfixes** :bug:
* [#177](https://github.com/travelping/eradius/pull/177) Set servers_pool to empty list by default
* [#178](https://github.com/travelping/eradius/pull/178) Fix getting of `servers_pools` from configuration in `eradius_proxy` handler
* [#175](https://github.com/travelping/eradius/pull/175) Update `hex` package

**Refactorings** :fire:
* [#179](https://github.com/travelping/eradius/pull/179) Remove non use documentation

Version 2.2.0 - 24 December 2020
---------------------------

* Use `prometheus_histogram:declare/1` instead `prometheus_histogram:new/1` - [PR #173](https://github.com/travelping/eradius/pull/173)
* Remove `metrics` env what was use for exameter - [PR #172](https://github.com/travelping/eradius/pull/172)
* Cleanup `eradius.app.src` - [#171](https://github.com/travelping/eradius/pull/171)

Version 2.1.0 - 12 November 2020
---------------------------

* Add support for `failover` to `RADIUS` client - [PR #154](https://github.com/travelping/eradius/pull/154)
* Add missing documentation of configuration - [PR #167](https://github.com/travelping/eradius/pull/167)
* Add dictionary unloading functionality: `eradius_dict:unload_tables/1` `eradius_dict:unload_tables/2` - [PR #169](https://github.com/travelping/eradius/pull/169)
* Update `meck` dependency to `0.9.0` - [PR #168](https://github.com/travelping/eradius/pull/168)
* Remove `stacktrace_compat` dependency - [PR #168](https://github.com/travelping/eradius/pull/168)

Version 2.0.1 - 28 October 2020
---------------------------

* Fix collecting of metrics in `eradius_counter_aggregator` - [PR #164](https://github.com/travelping/eradius/pull/164)

Version 2.0.0 - 26 October 2020
---------------------------

* Add Ituma dictionary - [PR #159](https://github.com/travelping/eradius/pull/159)
* Replace exometer with prometheus - [PR #158](https://github.com/travelping/eradius/pull/158)
* Divide accounting metrics - [PR #157](https://github.com/travelping/eradius/pull/157)

Version 1.0.1 - 11 May 2020
---------------------------

* Fix order of arguments of ?LOG macro which contains meta information

Version 1.0.0 - 11 May 2020
---------------------------

* bump minimum OTP Version to 21.0 + Erlang/OTP 23 compatibility
* use Erlang OTP logger for logging, drop lager
* use persistent_term module for dictionary
* Update 3GPP dictionary
* RFC 6911 dictionary added
* eradius_auth:check_password/2 specification fixed

Version 0.9.2 - 12 Mar 2018
---------------------------

* Rework eradius sample server
* Rework eradius_server behaviour with -callback (to using with Elixir 1.6)
* Some fixes and cleanup in metrics docs and rebar.config.script

Version 0.9.1 - 22 Feb 2018
---------------------------

* [METRICS] Set min_heap_size to default value(233) for exometer histograms

Version 0.9.0 - 07 Feb 2018
---------------------------

* Remove nas_prop explicit transformations in remote handler
* Resolve domain name during send request on client, it includes the fix for pass proxy handler validation
* Fix GOOD_CMD guard to have ability to combine it with others guards
* Fix dictionary collisions

Version 0.8.9 - 12 Dec 2017
---------------------------
* Reworks dicts to maps in client and node_mon
* Parse $INCLUDE directive in priv/dictionaries/dictionary\* files
* Get rid of tetrapak

Version 0.8.8 - 09 Nov 2017
---------------------------
* Allow 0.0.0.0 as NAS IP to avoid checking source IP

Version 0.8.7 - 27 Oct 2017
---------------------------
* Add METRICS.md
* Set client options in `radius_request` callback of proxy module

Version 0.8.6 - 25 Oct 2017
---------------------------
* Fix badmatch when `eradius_proxy` sends to server

Version 0.8.5 - 19 Oct 2017
---------------------------
* Move `meck` to the test profile

Version 0.8.4 - 18 Oct 2017
---------------------------
* Fix warning when run common test suites
* `timeout` and `retries` configuration options for `eradius_proxy`
* Do not send RADIUS request if a suitable route was not found in proxy

Version 0.8.3 - 4 Oct 2017
---------------------------
* `eradius_proxy` is able to match relays with a regular expression

Version 0.8.2 - 28 Sep 2017
---------------------------
* Rework unit test to common test
* Fix ipv6prefix coding
* Fix compile error on Windows. Fix for Issue #102
* Get rid of `rebar2` and move to `rebar3`
* Add missed `update_client_request()` for a request timeout metric

Version 0.8.1 - 18 Jul 2017
---------------------------
* add TP-Trace-Id to Travelping dictionary
* set minimum OTP version to 18.0 in rebar.config
* fix dictionary compiler to build basic dictionaries first
* use crypto:strong_rand_bytes/1 instead of crypto:rand_bytes/1
* use correct authenticator in attribute encoding
* fix compile warnings for OTP20
* simplify the server freeing TX mechanism

Version 0.8.0 - 16 Dec 2016
---------------------------
* add socket receive buffer configuration
* [metrics] add metric for dropped packets on the client
* [logs] extend authentication check logs
* [radius] add authentication of response
* [logs] improve logging timeout error
* [bug] fix crash in eradius_proxy when User-Name is empty
* [logs] update lager to 3.2.2
* [tests] increase Erlang versions in Travis and add rebar3 env
* [radius] proper type for RFC 3162 IPv6 attributes
* [radius] use hooks to compile and clean Radius dictionaries
* [radius] ruckus radius dictionary
* [metrics] counter and handle time are available for all kinds of requests
* [metrics] counter are now available for all kinds of responses
* [metrics] all metrics are uniformly available for client, server and nas
  callbacks
* [metrics] retransmissions are handled separately on client side according
  to RFC 2620
* [metrics] metrics are deactivated if no reporter is given (updates of metrics
  only result in a ets lookup, which is empty)
* [metrics] exometer updates don't involve any type transformations, every
  of an exometer id is an atom
* [metrics] metrics are instantly and completely visible after application start
* [metrics] removal of the dependence on exometer_influxdb
* [metrics] exometer ids are uniformly formatted which makes the configuration
  of potential subscribe options easy
* [metrics] metrics are defined and read from a data structure in metrics.hrl
  which makes extensions and documentation much easier for the future
* make possible to disable retransmittion by setting resend_timeout to 0
* [logs] default disable file logging
* set default client_ports to 100 to allow more parallel sockets in the client
* [metrics] fix server uptime metric

Version 0.7.0 - 28 Dec 2015
---------------------------
* use NasId instead of NasIp and Server name instead of Server name + port
* Fixed removing nas from nas_tab when reconfiguring
* Fixed metrics datapoints
* deleted uptime from SERVER_METRICS list to prevent duplicated subscriptions
* fixed return value of the update_uptime/1
* add IP ranges for NAS clients
* added request-type and -id to request logging
* add tetrapak override for erlang:timestamp/0
* add possibility to reconfigure logger
* disable logging on failure
* fix ip4_address format for NAS IP and add test case
* ensure the encoded values do not exceed the maximum attribute length
* properly initialize the authenticator
* initial support for exometer metrics
* add client metrics

Version 0.6.5 - 1 Jul 2015
---------------------------
* remote handler doesn't change io to standart io of local node anymore
* eradius_proxy can proxy requests without setted username

Version 0.6.4 - 7 May 2015
---------------------------
* add optional callback validate_arguments/1 to eradius handlers
* add eradius_proxy for default proxies

Version 0.6.3 - 23 Mar 2015
---------------------------
* update Travelping dictionary

Version 0.6.2 - 23 Apr 2015
---------------------------
* fix/add decoding for 24 bit integer datatype
* add backwards compatibility with old eradius versions
* fix request encoding and validation
* add rebar support

Version 0.6.1 - 05 Mar 2015
---------------------------
* switching to lager logging
* using systemds journal for informational eradius logging

Version 0.6.0 - 11 Feb 2015
---------------------------

* fix Message-Authenitcatior validation in access replies (API change)
* fix case of CAPWAP Power Travelping attributes

Version 0.5.2 - 17 Dec 2014
---------------------------

* change radius.log to a append only log file
* added wtp version attributes
* implement resend

Version 0.5.0 - 20 Jun 2014
---------------------------

* added new vendor Travelping attributes
* add generic nas id

Version 0.3.2 - 25 Sep 2013
---------------------------

* SNMP support moved to seperate application

Version 0.3.1 - 19 Sep 2013
---------------------------

* Add Travelping TLS and CAPWAP Attributes to dictionary
* Add CoA and Disconnect protocol support
* Fix RCF 2868 Tunnel-Type attributes
