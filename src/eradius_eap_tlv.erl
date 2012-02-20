-module(eradius_eap_tlv).

-export([register/0, unregister/0]).
-export([decode_eap_type/2, encode_eap_type/1]).

-include("eradius_eap.hrl").

-define(EAP_TAG, tlv).

register() ->
    eradius_eap:register_type({?EAP_TLV, ?EAP_TAG}, ?MODULE).

unregister() ->
    eradius_eap:unregister_type({?EAP_TLV, ?EAP_TAG}).

%% see: draft-kamath-pppext-peapv0-00, Sect. 2.3.1. Result AVP

decode_eap_type(_Id, <<_M:1, _R:1, 3:14, 2:16, Status:16/integer>>) ->
    {?EAP_TAG, ack, status(Status)}.

encode_eap_type({?EAP_TAG, ack, Status}) ->
    <<?EAP_TLV:8, 1:1, 0:1, 3:14, 2:16, (status(Status)):16>>.

status(1) -> success;
status(2) -> failure;
status(success) -> 1;
status(failure) -> 2.
