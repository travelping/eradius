-define(SERVER_METRICS, [start_time, uptime, reset_time, invalid_requests, discards_no_handler]).

-define(CLIENT_METRICS, [{socket_errors, counter}, {sockets_down, counter}, {access_requests, counter},
                         {reject_requests, counter}, {accept_requests, counter}, {challenge_requests, counter},
                         {accounting_requests, counter}, {accounting_responses, counter},
                         {coa_requests, counter}, {coa_naks, counter}, {disconnect_requests, counter},
                         {disconnect_acks, counter}, {disconnect_naks, counter}, {unknown_type_requests, counter},
                         {access_retransmissions, counter}, {requests_time, histogram}, {remote_requests_time, histogram}]).

-define(NAS_METRICS, [requests, dup_requests, replies, access_requests, access_accepts,
		      access_rejects, access_challenges, account_requests, account_responses,
		      packets_dropped, handler_failures, coa_requests, coaAcks, coaNaks,
		      disconnect_requests, disc_naks, disc_acks, malformedRequests]).
