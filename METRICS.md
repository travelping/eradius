# eradius metrics

`eradius` uses exometer core to implement various operation metrics. 
For now, there are 3 groups of metrics:

* `server`
* `nas` (server metrics separated per nas)
* `client`

Collecting of each group can be enabled/disabled though setting `metrics` env for `eradius` application:

      {metrics, [{enabled, [server, nas, client]}]},

By default it is `[server, nas, client]`.

### The following `server` metrics exist:

_All metrics start with `[eradius, radius]` prefix and the prefix is not included into table to save space._

| Metric                                                                                            | Type      |
| ------------------------------------------------------------------------------------------------- | --------- |
| [request, invalid, server, $NAME, $IP, $PORT, total, undefined, undefined, gauge]                 | histogram |
| [request, invalid, server, $NAME, $IP, $PORT, total, undefined, undefined, counter]               | counter   |
| [request, malformed, server, $NAME, $IP, $PORT, total, undefined, undefined, gauge]               | histogram |
| [request, malformed, server, $NAME, $IP, $PORT, total, undefined, undefined, counter]             | counter   |
| [request, dropped, server, $NAME, $IP, $PORT, total, undefined, undefined, gauge]                 | histogram |
| [request, dropped, server, $NAME, $IP, $PORT, total, undefined, undefined, counter]               | counter   |
| [request, retransmission, server, $NAME, $IP, $PORT, total, undefined, undefined, counter]        | counter   |
| [request, duplicate, server, $NAME, $IP, $PORT, total, undefined, undefined, gauge]               | histogram |
| [request, duplicate, server, $NAME, $IP, $PORT, total, undefined, undefined, counter]             | counter   |
| [request, bad_authenticator, server, $NAME, $IP, $PORT, total, undefined, undefined, gauge] `*`   | histogram |
| [request, bad_authenticator, server, $NAME, $IP, $PORT, total, undefined, undefined, counter] `*` | counter   | 
| [request, unknown_type, server, $NAME, $IP, $PORT, total, undefined, undefined, gauge]            | histogram |
| [request, unknown_type, server, $NAME, $IP, $PORT, total, undefined, undefined, counter]          | counter   |
| [request, total, server, $NAME, $IP, $PORT, total, undefined, undefined, gauge]                   | histogram |
| [request, total, server, $NAME, $IP, $PORT, total, undefined, undefined, counter]                 | counter   |
| [request, access, server, $NAME, $IP, $PORT, total, undefined, undefined, gauge]                  | gauge     |
| [request, access, server, $NAME, $IP, $PORT, total, undefined, undefined, counter]                | histogram |
| [request, accounting, server, $NAME, $IP, $PORT, total, undefined, undefined, gauge]              | histogram |
| [request, accounting, server, $NAME, $IP, $PORT, total, undefined, undefined, counter]            | counter   |
| [request, coa, server, $NAME, $IP, $PORT, total, undefined, undefined, gauge]                     | histogram |
| [request, coa, server, $NAME, $IP, $PORT, total, undefined, undefined, counter]                   | counter   |
| [request, disconnect, server, $NAME, $IP, $PORT, total, undefined, undefined, gauge]              | histogram |
| [request, disconnect, server, $NAME, $IP, $PORT, total, undefined, undefined, counter]            | counter   |
| [response, total ,server, $NAME, $IP, $PORT, total, undefined, undefined, counter]                | counter   |
| [response, access, server, $NAME, $IP, $PORT, total, undefined, undefined, counter]               | counter   |
| [response, accounting, server, $NAME, $IP, $PORT, total, undefined, undefined, counter]           | counter   |
| [response, access_accept, server, $NAME, $IP, $PORT, total, undefined, undefined, counter]        | counter   |
| [response, access_reject, server, $NAME, $IP, $PORT, total, undefined, undefined, counter]        | counter   |
| [response, access_challenge, server, $NAME, $IP, $PORT, total, undefined, undefined, counter]     | counter   |
| [response, disconnect_ack, server, $NAME, $IP, $PORT, total, undefined, undefined, counter]       | counter   |
| [response, disconnect_nak, server, $NAME, $IP, $PORT, total, undefined, undefined, counter]       | counter   |
| [response, coa_ack, server, $NAME, $IP, $PORT, total, undefined, undefined, counter]              | counter   |
| [response, coa_nak, server, $NAME, $IP, $PORT, total, undefined, undefined, counter]              | counter   |
| [request, pending, server, $NAME, $IP, $PORT, total, undefined, undefined, counter]               | counter   |
| [time, last_request, server, $NAME, $IP, $PORT, total, undefined, undefined, ticks]               | gauge     |
| [time, since_last_request, server, $NAME, $IP, $PORT, total, undefined, undefined, ticks]         | gauge     |
| [time, last_reset, server, $NAME, $IP, $PORT, total, undefined, undefined, ticks]                 | gauge     |
| [time, last_config_reset, server, $NAME, $IP, $PORT, total, undefined, undefined, ticks]          | gauge     |
| [time, up, server, $NAME, $IP, $PORT, total, undefined, undefined, ticks]                         | gauge     |


`*` - these metrics exist but not been updating.

### The following `nas` metrics exist:

_All metrics start with `[eradius, radius]` prefix and the prefix is not included into table to save space._


| Metric                                                                                          | Type      |
| ----------------------------------------------------------------------------------------------- | --------- |
| [request, dropped, server, $NAME, $IP, $PORT, $NASID, $NASIP, undefined, gauge]                 | histogram |
| [request, dropped, server, $NAME, $IP, $PORT, $NASID, $NASIP, undefined, counter]               | counter   |
| [request, retransmission, server, $NAME, $IP, $PORT, $NASID, $NASIP, undefined, counter]        | counter   |
| [request, duplicate, server, $NAME, $IP, $PORT, $NASID, $NASIP, undefined, gauge]               | histogram |
| [request, duplicate, server, $NAME, $IP, $PORT, $NASID, $NASIP, undefined, counter]             | counter   |
| [request, bad_authenticator, server, $NAME, $IP, $PORT, $NASID, $NASIP, undefined, gauge] `*`   | histogram |
| [request, bad_authenticator, server, $NAME, $IP, $PORT, $NASID, $NASIP, undefined, counter] `*` | counter   |
| [request, unknown_type, server, $NAME, $IP, $PORT, $NASID, $NASIP, undefined, gauge]            | histogram |
| [request, unknown_type, server, $NAME, $IP, $PORT, $NASID, $NASIP, undefined, counter]          | counter   |
| [request, total, server, $NAME, $IP, $PORT, $NASID, $NASIP, undefined, gauge]                   | histogram |
| [request, total, server, $NAME, $IP, $PORT, $NASID, $NASIP, undefined, counter]                 | counter   |
| [request, access, server, $NAME, $IP, $PORT, $NASID, $NASIP, undefined, gauge]                  | histogram |
| [request, access, server, $NAME, $IP, $PORT, $NASID, $NASIP, undefined, counter]                | counter   |
| [request, accounting, server, $NAME, $IP, $PORT, $NASID, $NASIP, undefined, gauge]              | histogram |
| [request, accounting, server, $NAME, $IP, $PORT, $NASID, $NASIP, undefined, counter]            | counter   |
| [request, coa, server, $NAME, $IP, $PORT, $NASID, $NASIP, undefined, gauge]                     | histogram |
| [request, coa, server, $NAME, $IP, $PORT, $NASID, $NASIP, undefined, counter]                   | counter   |
| [request, disconnect, server, $NAME, $IP, $PORT, $NASID, $NASIP, undefined, gauge]              | histogram |
| [request, disconnect, server, $NAME, $IP, $PORT, $NASID, $NASIP, undefined, counter]            | counter   |
| [response, total, server, $NAME, $IP, $PORT, $NASID, $NASIP, undefined, counter]                | counter   |
| [response, access, server, $NAME, $IP, $PORT, $NASID, $NASIP, undefined, counter]               | counter   |
| [response, accounting, server, $NAME, $IP, $PORT, $NASID, $NASIP, undefined, counter]           | counter   |
| [response, access_accept, server, $NAME, $IP, $PORT, $NASID, $NASIP, undefined, counter]        | counter   |
| [response, access_reject, server, $NAME, $IP, $PORT, $NASID, $NASIP, undefined, counter]        | counter   |
| [response, access_challenge, server, $NAME, $IP, $PORT, $NASID, $NASIP, undefined, counter]     | counter   |
| [response, disconnect_ack, server, $NAME, $IP, $PORT, $NASID, $NASIP, undefined, counter]       | counter   |
| [response, disconnect_nak, server, $NAME, $IP, $PORT, $NASID, $NASIP, undefined, counter]       | counter   |
| [response, coa_ack, server, $NAME, $IP, $PORT, $NASID, $NASIP, undefined, counter]              | counter   |
| [response, coa_nak, server, $NAME, $IP, $PORT, $NASID, $NASIP, undefined, counter]              | counter   |
| [request, pending, server, $NAME, $IP, $PORT, $NASID, $NASIP, undefined, counter]               | counter   |
| [time, last_request, server, $NAME, $IP, $PORT, $NASID, $NASIP, undefined, ticks]               | gauge     |
| [time, since_last_request, server, $NAME, $IP, $PORT, $NASID, $NASIP, undefined, ticks]         | gauge     |

`*` - these metrics exist but not been updating.

### The following `client` metrics exist:

_All metrics start with `[eradius, radius]` prefix and the prefix is not included into table to save space._

| Metric                                                                                          | Type      |
| ----------------------------------------------------------------------------------------------- | --------- |
| [request, retransmission, client, $CNAME, $CIP, undefined, $SNAME, $SIP, $SPORT, gauge]          | histogram |
| [request, retransmission, client, $CNAME, $CIP, undefined, $SNAME, $SIP, $SPORT, counter]        | counter   |
| [request, timeout, client, $CNAME, $CIP, undefined, $SNAME, $SIP, $SPORT, gauge]                 | histogram |
| [request, timeout, client, $CNAME, $CIP, undefined, $SNAME, $SIP, $SPORT, counter]               | counter   |
| [request, bad_authenticator, client, $CNAME, $CIP, undefined, $SNAME, $SIP, $SPORT, counter] `*` | counter   |
| [request, malformed, client, $CNAME, $CIP, undefined, $SNAME, $SIP, $SPORT, counter] `*`         | counter   |
| [request, unknown_type, client, $CNAME, $CIP, undefined, $SNAME, $SIP, $SPORT, counter] `*`      | counter   | 
| [request, total, client, $CNAME, $CIP, undefined, $SNAME, $SIP, $SPORT, gauge]                   | histogram | 
| [request, total, client, $CNAME, $CIP, undefined, $SNAME, $SIP, $SPORT, counter]                 | counter   |
| [request, access, client, $CNAME, $CIP, undefined, $SNAME, $SIP, $SPORT, gauge]                  | histogram |
| [request, access, client, $CNAME, $CIP, undefined, $SNAME, $SIP, $SPORT, counter]                | counter   |
| [request, accounting, client, $CNAME, $CIP, undefined, $SNAME, $SIP, $SPORT, gauge]              | histogram |
| [request, accounting, client, $CNAME, $CIP, undefined, $SNAME, $SIP, $SPORT, counter]            | counter   |
| [request, coa, client, $CNAME, $CIP, undefined, $SNAME, $SIP, $SPORT, gauge]                     | histogram |
| [request, coa, client, $CNAME, $CIP, undefined, $SNAME, $SIP, $SPORT, counter]                   | counter   |
| [request, disconnect, client, $CNAME, $CIP, undefined, $SNAME, $SIP, $SPORT, gauge]              | histogram |
| [request, disconnect, client, $CNAME, $CIP, undefined, $SNAME, $SIP, $SPORT, counter]            | counter   |
| [response, total, client, $CNAME, $CIP, undefined, $SNAME, $SIP, $SPORT, counter]                | counter   |
| [response, access, client, $CNAME, $CIP, undefined, $SNAME, $SIP, $SPORT, counter]               | counter   |
| [response, accounting, client, $CNAME, $CIP, undefined, $SNAME, $SIP, $SPORT, counter]           | counter   |
| [response, access_accept, client, $CNAME, $CIP, undefined, $SNAME, $SIP, $SPORT, counter]        | counter   |
| [response, access_reject, client, $CNAME, $CIP, undefined, $SNAME, $SIP, $SPORT, counter]        | counter   |
| [response, access_challenge, client, $CNAME, $CIP, undefined, $SNAME, $SIP, $SPORT, counter]     | counter   |
| [response, dropped, client, $CNAME, $CIP, undefined, $SNAME, $SIP, $SPORT, counter]              | counter   |
| [response, disconnect_ack, client, $CNAME, $CIP, undefined, $SNAME, $SIP, $SPORT, counter]       | counter   |
| [response, disconnect_nak, client, $CNAME, $CIP, undefined, $SNAME, $SIP, $SPORT, counter]       | counter   |
| [response, coa_ack, client, $CNAME, $CIP, undefined, $SNAME, $SIP, $SPORT, counter]              | counter   |
| [response, coa_nak, client, $CNAME, $CIP, undefined, $SNAME, $SIP, $SPORT, counter]              | counter   |
| [request, pending, client, $CNAME, $CIP, undefined, $SNAME, $SIP, $SPORT, counter]               | counter   |
| [time, last_request, client, $CNAME, $CIP, undefined, $SNAME, $SIP, $SPORT, ticks]               | gauge     |
| [time, since_last_request, client, $CNAME, $CIP, undefined, $SNAME, $SIP, $SPORT, ticks]         | gauge     |

`*` - these metrics exist but not been updating.

`$NAME` - Server name. `$IP:$PORT` or name from configuration if exists. For this configuration:

    {servers, [
        {root, {"127.0.0.1", [1812, 1813]}}
    ]}

`root` will be used as a name. 

`$IP` - server listener IP from configuration.

`$PORT` - server listener port from configuration.

`$NASID` - `ID_$NASID` or `nas_id` from configuration if exists.

`$NASIP` - NAS-IP-Address from configuration.

    {root, [
        { {"NAS1", [arg1, arg2]},
            [{"10.18.14.2", <<"secret1">>}]},
        { {"NAS2", [arg1, arg2]},
            [{{10, 18, 14, 3}, <<"secret2">>, [{nas_id, <<"name">>}]}]}
    ]}]

The configuration above describes two NASes fro one root RADIUS server.
For "NAS1" `$NASID` will be generated from ID an IP(`NAS1_10.18.14.2`), `$NASIP` = "10.18.14.2".
For "NAS2" `nas_id` will be used for `$NASID`(`name`)  `$NASIP` = "10.18.14.2".

`$CNAME` - name from `client_name` option fduring call `eradius_client:send_request/3` or `undefined` by default.

`$CIP` - `client_ip` from `eradius` enviroment.

`$SNAME` - name from `server_name` option fduring call `eradius_client:send_request/3` or `undefined` by default.

`$SIP` - IP address of destination server.

`$SPORT` - Port of destination server.

Histograms are created with `slot_period` = 100 and `time_span` = 60000.
All timing values in the histograms are in microseconds (µs).
