# eradius metrics

`eradius` uses `prometheus.erl` to implement various operation metrics.
For now, there are 3 groups of metrics:

* `server`
* `nas` (server metrics separated per nas)
* `client`

Collecting of each group can be enabled/disabled though setting `metrics` env for `eradius` application:

      {metrics, [{enabled, [server, nas, client]}]},

By default it is `[server, nas, client]`.

### The following `server` metrics exist:

_All metrics start with `eradius_radius_` prefix and the prefix is not included into table to save space._

| Metric                                                             | Labels                  | Type      |
| -------------------------------------------------------------------|-------------------------|-----------|
| request_invalid_server_total_undefined_undefined_gauge             | [$NAME, $IP, $PORT]     | histogram |
| request_invalid_server_total_undefined_undefined_counter           | [$NAME, $IP, $PORT]     | counter   |
| request_malformed_server_total_undefined_undefined_gauge           | [$NAME, $IP, $PORT]     | histogram |
| request_malformed_server_total_undefined_undefined_counter         | [$NAME, $IP, $PORT]     | counter   |
| request_dropped_server_total_undefined_undefined_gauge             | [$NAME, $IP, $PORT]     | histogram |
| request_dropped_server_total_undefined_undefined_counter           | [$NAME, $IP, $PORT]     | counter   |
| request_retransmission_server_total_undefined_undefined_counter    | [$NAME, $IP, $PORT]     | counter   |
| request_duplicate_server_total_undefined_undefined_gauge           | [$NAME, $IP, $PORT]     | histogram |
| request_duplicate_server_total_undefined_undefined_counter         | [$NAME, $IP, $PORT]     | counter   |
| request_bad_authenticator_server_total_undefined_undefined_gauge   | [$NAME, $IP, $PORT] `*` | histogram |
| request_bad_authenticator_server_total_undefined_undefined_counter | [$NAME, $IP, $PORT] `*` | counter   |
| request_unknown_type_server_total_undefined_undefined_gauge        | [$NAME, $IP, $PORT]     | histogram |
| request_unknown_type_server_total_undefined_undefined_counter      | [$NAME, $IP, $PORT]     | counter   |
| request_total_server_total_undefined_undefined_gauge               | [$NAME, $IP, $PORT]     | histogram |
| request_total_server_total_undefined_undefined_counter             | [$NAME, $IP, $PORT]     | counter   |
| request_access_server_total_undefined_undefined_gauge              | [$NAME, $IP, $PORT]     | gauge     |
| request_access_server_total_undefined_undefined_counter            | [$NAME, $IP, $PORT]     | histogram |
| request_accounting_server_total_undefined_undefined_gauge          | [$NAME, $IP, $PORT]     | histogram |
| request_accounting_server_total_undefined_undefined_counter        | [$NAME, $IP, $PORT]     | counter   |
| request_coa_server_total_undefined_undefined_gauge                 | [$NAME, $IP, $PORT]     | histogram |
| request_coa_server_total_undefined_undefined_counter               | [$NAME, $IP, $PORT]     | counter   |
| request_disconnect_server_total_undefined_undefined_gauge          | [$NAME, $IP, $PORT]     | histogram |
| request_disconnect_server_total_undefined_undefined_counter        | [$NAME, $IP, $PORT]     | counter   |
| response_total_server_total_undefined_undefined_counter            | [$NAME, $IP, $PORT]     | counter   |
| response_access_server_total_undefined_undefined_counter           | [$NAME, $IP, $PORT]     | counter   |
| response_accounting_server_total_undefined_undefined_counter       | [$NAME, $IP, $PORT]     | counter   |
| response_access_accept_server_total_undefined_undefined_counter    | [$NAME, $IP, $PORT]     | counter   |
| response_access_reject_server_total_undefined_undefined_counter    | [$NAME, $IP, $PORT]     | counter   |
| response_access_challenge_server_total_undefined_undefined_counter | [$NAME, $IP, $PORT]     | counter   |
| response_disconnect_ack_server_total_undefined_undefined_counter   | [$NAME, $IP, $PORT]     | counter   |
| response_disconnect_nak_server_total_undefined_undefined_counter   | [$NAME, $IP, $PORT]     | counter   |
| response_coa_ack_server_total_undefined_undefined_counter          | [$NAME, $IP, $PORT]     | counter   |
| response_coa_nak_server_total_undefined_undefined_counter          | [$NAME, $IP, $PORT]     | counter   |
| request_pending_server_total_undefined_undefined_counter           | [$NAME, $IP, $PORT]     | counter   |
| time_last_request_server_total_undefined_undefined_ticks           | [$NAME, $IP, $PORT]     | gauge     |
| time_since_last_request_server_total_undefined_undefined_ticks     | [$NAME, $IP, $PORT]     | gauge     |
| time_last_reset_server_total_undefined_undefined_ticks             | [$NAME, $IP, $PORT]     | gauge     |
| time_last_config_reset_server_total_undefined_undefined_ticks      | [$NAME, $IP, $PORT]     | gauge     |
| time_up_server_total_undefined_undefined_ticks                     | [$NAME, $IP, $PORT]     | gauge     |


`*` - these metrics exist but not been updating.

### The following `nas` metrics exist:

_All metrics start with `eradius_radius_` prefix and the prefix is not included into table to save space._


| Metric                                             | Labels                                  | Type      |
| ---------------------------------------------------|-----------------------------------------| --------- |
| request_droppedserver_undefined_gauge              | [$NAME, $IP, $PORT, $NASID, $NASIP]     | histogram |
| request_dropped_server_undefined_counter           | [$NAME, $IP, $PORT, $NASID, $NASIP]     | counter   |
| request_retransmission_server_undefined_counter    | [$NAME, $IP, $PORT, $NASID, $NASIP]     | counter   |
| request_duplicate_server_undefined_gauge           | [$NAME, $IP, $PORT, $NASID, $NASIP]     | histogram |
| request_duplicate_server_undefined_counter         | [$NAME, $IP, $PORT, $NASID, $NASIP]     | counter   |
| request_bad_authenticator_server_undefined_gauge   | [$NAME, $IP, $PORT, $NASID, $NASIP] `*` | histogram |
| request_bad_authenticator_server_undefined_counter | [$NAME, $IP, $PORT, $NASID, $NASIP] `*` | counter   |
| request_unknown_type_server_undefined_gauge        | [$NAME, $IP, $PORT, $NASID, $NASIP]     | histogram |
| request_unknown_type_server_undefined_counter      | [$NAME, $IP, $PORT, $NASID, $NASIP]     | counter   |
| request_total_server_undefined_gauge               | [$NAME, $IP, $PORT, $NASID, $NASIP]     | histogram |
| request_total_server_undefined_counter             | [$NAME, $IP, $PORT, $NASID, $NASIP]     | counter   |
| request_access_server_undefined_gauge              | [$NAME, $IP, $PORT, $NASID, $NASIP]     | histogram |
| request_access_server_undefined_counter            | [$NAME, $IP, $PORT, $NASID, $NASIP]     | counter   |
| request_accounting_server_undefined_gauge          | [$NAME, $IP, $PORT, $NASID, $NASIP]     | histogram |
| request_accounting_server_undefined_counter        | [$NAME, $IP, $PORT, $NASID, $NASIP]     | counter   |
| request_coa_server_undefined_gauge                 | [$NAME, $IP, $PORT, $NASID, $NASIP]     | histogram |
| request_coa_server_undefined_counter               | [$NAME, $IP, $PORT, $NASID, $NASIP]     | counter   |
| request_disconnect_server_undefined_gauge          | [$NAME, $IP, $PORT, $NASID, $NASIP]     | histogram |
| request_disconnect_server_undefined_counter        | [$NAME, $IP, $PORT, $NASID, $NASIP]     | counter   |
| response_total_server_undefined_counter            | [$NAME, $IP, $PORT, $NASID, $NASIP]     | counter   |
| response_access_server_undefined_counter           | [$NAME, $IP, $PORT, $NASID, $NASIP]     | counter   |
| response_accounting_server_undefined_counter       | [$NAME, $IP, $PORT, $NASID, $NASIP]     | counter   |
| response_access_accept_server_undefined_counter    | [$NAME, $IP, $PORT, $NASID, $NASIP]     | counter   |
| response_access_reject_server_undefined_counter    | [$NAME, $IP, $PORT, $NASID, $NASIP]     | counter   |
| response_access_challenge_server_undefined_counter | [$NAME, $IP, $PORT, $NASID, $NASIP]     | counter   |
| response_disconnect_ack_server_undefined_counter   | [$NAME, $IP, $PORT, $NASID, $NASIP]     | counter   |
| response_disconnect_nak_server_undefined_counter   | [$NAME, $IP, $PORT, $NASID, $NASIP]     | counter   |
| response_coa_ack_server_undefined_counter          | [$NAME, $IP, $PORT, $NASID, $NASIP]     | counter   |
| response_coa_nak_server_undefined_counter          | [$NAME, $IP, $PORT, $NASID, $NASIP]     | counter   |
| request_pending_server_undefined_counter           | [$NAME, $IP, $PORT, $NASID, $NASIP]     | counter   |
| time_last_request_server_undefined_ticks           | [$NAME, $IP, $PORT, $NASID, $NASIP]     | gauge     |
| time_since_last_request_server_undefined_ticks     | [$NAME, $IP, $PORT, $NASID, $NASIP]     | gauge     |

`*` - these metrics exist but not been updating.

### The following `client` metrics exist:

_All metrics start with `eradius_radius_` prefix and the prefix is not included into table to save space._

| Metric                                             | Labels                                    | Type      |
| ---------------------------------------------------|-------------------------------------------|-----------|
| request_retransmission_client_undefined_gauge      | [$CNAME, $CIP,  $SNAME, $SIP, $SPORT]     | histogram |
| request_retransmission_client_undefined_counter    | [$CNAME, $CIP,  $SNAME, $SIP, $SPORT]     | counter   |
| request_timeout_client_undefined_gauge             | [$CNAME, $CIP,  $SNAME, $SIP, $SPORT]     | histogram |
| request_timeout_client_undefined_counter           | [$CNAME, $CIP,  $SNAME, $SIP, $SPORT]     | counter   |
| request_bad_authenticator_client_undefined_counter | [$CNAME, $CIP,  $SNAME, $SIP, $SPORT] `*` | counter   |
| request_malformed_client_undefined_counter         | [$CNAME, $CIP,  $SNAME, $SIP, $SPORT] `*` | counter   |
| request_unknown_type_client_undefined_counter      | [$CNAME, $CIP,  $SNAME, $SIP, $SPORT] `*` | counter   |
| request_total_client_undefined_gauge               | [$CNAME, $CIP,  $SNAME, $SIP, $SPORT]     | histogram |
| request_total_client_undefined_counter             | [$CNAME, $CIP,  $SNAME, $SIP, $SPORT]     | counter   |
| request_access_client_undefined_gauge              | [$CNAME, $CIP,  $SNAME, $SIP, $SPORT]     | histogram |
| request_access_client_undefined_counter            | [$CNAME, $CIP,  $SNAME, $SIP, $SPORT]     | counter   |
| request_accounting_client_undefined_gauge          | [$CNAME, $CIP,  $SNAME, $SIP, $SPORT]     | histogram |
| request_accounting_client_undefined_counter        | [$CNAME, $CIP,  $SNAME, $SIP, $SPORT]     | counter   |
| request_coa_client_undefined_gauge                 | [$CNAME, $CIP,  $SNAME, $SIP, $SPORT]     | histogram |
| request_coa_client_undefined_counter               | [$CNAME, $CIP,  $SNAME, $SIP, $SPORT]     | counter   |
| request_disconnect_client_undefined_gauge          | [$CNAME, $CIP,  $SNAME, $SIP, $SPORT]     | histogram |
| request_disconnect_client_undefined_counter        | [$CNAME, $CIP,  $SNAME, $SIP, $SPORT]     | counter   |
| response_total_client_undefined_counter            | [$CNAME, $CIP,  $SNAME, $SIP, $SPORT]     | counter   |
| response_access_client_undefined_counter           | [$CNAME, $CIP,  $SNAME, $SIP, $SPORT]     | counter   |
| response_accounting_client_undefined_counter       | [$CNAME, $CIP,  $SNAME, $SIP, $SPORT]     | counter   |
| response_access_accept_client_undefined_counter    | [$CNAME, $CIP,  $SNAME, $SIP, $SPORT]     | counter   |
| response_access_reject_client_undefined_counter    | [$CNAME, $CIP,  $SNAME, $SIP, $SPORT]     | counter   |
| response_access_challenge_client_undefined_counter | [$CNAME, $CIP,  $SNAME, $SIP, $SPORT]     | counter   |
| response_dropped_client_undefined_counter          | [$CNAME, $CIP,  $SNAME, $SIP, $SPORT]     | counter   |
| response_disconnect_ack_client_undefined_counter   | [$CNAME, $CIP,  $SNAME, $SIP, $SPORT]     | counter   |
| response_disconnect_nak_client_undefined_counter   | [$CNAME, $CIP,  $SNAME, $SIP, $SPORT]     | counter   |
| response_coa_ack_client_undefined_counter          | [$CNAME, $CIP,  $SNAME, $SIP, $SPORT]     | counter   |
| response_coa_nak_client_undefined_counter          | [$CNAME, $CIP,  $SNAME, $SIP, $SPORT]     | counter   |
| request_pending_client_undefined_counter           | [$CNAME, $CIP,  $SNAME, $SIP, $SPORT]     | counter   |
| time_last_request_client_undefined_ticks           | [$CNAME, $CIP,  $SNAME, $SIP, $SPORT]     | gauge     |
| time_since_last_request_client_undefined_ticks     | [$CNAME, $CIP,  $SNAME, $SIP, $SPORT]     | gauge     |

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

All timing values in the histograms are in microseconds (µs).
