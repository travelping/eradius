eradius
=======

A generic RADIUS client and server.

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
