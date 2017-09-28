-module(eradius_lib).
-export([del_attr/2, get_attr/2, encode_request/1, encode_reply/1, decode_request/2, decode_request/3, decode_request_id/1]).
-export([random_authenticator/0, zero_authenticator/0, pad_to/2, set_attr/3, get_attributes/1, set_attributes/2]).
-export([timestamp/0, printable_peer/2]).
-export_type([command/0, secret/0, authenticator/0, attribute_list/0]).

% -compile(bin_opt_info).

-ifdef(TEST).
-export([encode_value/2, decode_value/2, scramble/3]).
-export([salt_encrypt/4, salt_decrypt/3, encode_attribute/3, decode_attribute/5]).
-endif.
-include("eradius_lib.hrl").
-include("eradius_dict.hrl").

-type command() :: 'request' | 'accept' | 'challenge' | 'reject' | 'accreq' | 'accresp' | 'coareq' | 'coaack' | 'coanak' | 'discreq' | 'discack' | 'discnak'.
-type secret() :: binary().
-type authenticator() :: <<_:128>>.
-type salt() :: binary().
-type attribute_list() :: list({eradius_dict:attribute(), term()}).

-define(IS_ATTR(Key, Attr), ?IS_KEY(Key, element(1, Attr))).
-define(IS_KEY(Key, Attr), ((is_record(Attr, attribute) andalso (element(2, Attr) == Key))
                           orelse
                           (Attr == Key)) ).
%% ------------------------------------------------------------------------------------------
%% -- Request Accessors
-spec random_authenticator() -> authenticator().
random_authenticator() -> crypto:strong_rand_bytes(16).

-spec zero_authenticator() -> authenticator().
zero_authenticator() -> <<0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0>>.

-spec set_attributes(#radius_request{}, attribute_list()) -> #radius_request{}.
set_attributes(Req = #radius_request{attrs = Attrs}, NewAttrs) ->
    Req#radius_request{attrs = NewAttrs ++ Attrs}.

-spec get_attributes(#radius_request{}) -> attribute_list().
get_attributes(#radius_request{attrs = Attrs}) ->
    Attrs.

-spec set_attr(#radius_request{}, eradius_dict:attribute_id(), eradius_dict:attr_value()) -> #radius_request{}.
set_attr(Req = #radius_request{attrs = Attrs}, Id, Val) ->
    Req#radius_request{attrs = [{Id, Val} | Attrs]}.

-spec get_attr(#radius_request{}, eradius_dict:attribute_id()) -> eradius_dict:attr_value() | undefined.
get_attr(#radius_request{attrs = Attrs}, Id) ->
    get_attr_loop(Id, Attrs).

del_attr(Req = #radius_request{attrs = Attrs}, Id) ->
    Req#radius_request{attrs = lists:reverse(lists:foldl(fun(Attr, Acc) when ?IS_ATTR(Id, Attr) -> Acc;
                                                            (Attr, Acc) -> [Attr | Acc]
                                                         end, [], Attrs))}.

get_attr_loop(Key, [{Id, Val}|_T]) when ?IS_KEY(Key, Id) -> Val;
get_attr_loop(Key, [_|T])                                -> get_attr_loop(Key, T);
get_attr_loop(_, [])                                     -> undefined.

%% ------------------------------------------------------------------------------------------
%% -- Wire Encoding

%% @doc Convert a RADIUS request to the wire format.
%%   The Message-Authenticator MUST be used in Access-Request that include an EAP-Message attribute [RFC 3579].
-spec encode_request(#radius_request{}) -> {binary(), binary()}.
encode_request(Req = #radius_request{reqid = ReqID, cmd = Command, attrs = Attributes}) when (Command == request) ->
    Authenticator = random_authenticator(),
    Req1 = Req#radius_request{authenticator = Authenticator},
    EncReq1 = encode_attributes(Req1, Attributes),
    EncReq2 = encode_eap_message(Req1, EncReq1),
    {Body, BodySize} = encode_message_authenticator(Req1, EncReq2),
    {Authenticator, <<(encode_command(Command)):8, ReqID:8, (BodySize + 20):16, Authenticator:16/binary, Body/binary>>};
encode_request(Req = #radius_request{reqid = ReqID, cmd = Command, attrs = Attributes}) ->
    {Body, BodySize} = encode_attributes(Req, Attributes),
    Head = <<(encode_command(Command)):8, ReqID:8, (BodySize + 20):16>>,
    Authenticator = crypto:hash(md5, [Head, zero_authenticator(), Body, Req#radius_request.secret]),
    {Authenticator, <<Head/binary, Authenticator:16/binary, Body/binary>>}.

%% @doc Convert a RADIUS reply to the wire format.
%%   This function performs the same task as {@link encode_request/2},
%%   except that it includes the authenticator substitution required for replies.
%%   The Message-Authenticator MUST be used in Access-Accept, Access-Reject or Access-Chalange
%%   replies that includes an EAP-Message attribute [RFC 3579].
-spec encode_reply(#radius_request{}) -> binary().
encode_reply(Req = #radius_request{reqid = ReqID, cmd = Command, authenticator = RequestAuthenticator, attrs = Attributes}) ->
    EncReq1 = encode_attributes(Req, Attributes),
    EncReq2 = encode_eap_message(Req, EncReq1),
    {Body, BodySize} = encode_message_authenticator(Req, EncReq2),
    Head = <<(encode_command(Command)):8, ReqID:8, (BodySize + 20):16>>,
    ReplyAuthenticator = crypto:hash(md5, [Head, <<RequestAuthenticator:16/binary>>, Body, Req#radius_request.secret]),
    <<Head/binary, ReplyAuthenticator:16/binary, Body/binary>>.

-spec encode_command(command()) -> byte().
encode_command(request)   -> ?RAccess_Request;
encode_command(accept)    -> ?RAccess_Accept;
encode_command(challenge) -> ?RAccess_Challenge;
encode_command(reject)    -> ?RAccess_Reject;
encode_command(accreq)    -> ?RAccounting_Request;
encode_command(accresp)   -> ?RAccounting_Response;
encode_command(coareq)    -> ?RCoa_Request;
encode_command(coaack)    -> ?RCoa_Ack;
encode_command(coanak)    -> ?RCoa_Nak;
encode_command(discreq)   -> ?RDisconnect_Request;
encode_command(discack)   -> ?RDisconnect_Ack;
encode_command(discnak)   -> ?RDisconnect_Nak.

-spec encode_message_authenticator(#radius_request{}, {binary(), non_neg_integer()}) -> {binary(), non_neg_integer()}.
encode_message_authenticator(_Req = #radius_request{msg_hmac = false}, Request) ->
    Request;
encode_message_authenticator(Req = #radius_request{reqid = ReqID, cmd = Command, authenticator = Authenticator, msg_hmac = true}, {Body, BodySize}) ->
    Head = <<(encode_command(Command)):8, ReqID:8, (BodySize + 20 + 2 +16):16>>,
    ReqAuth = <<Authenticator:16/binary>>,
    HMAC = crypto:hmac(md5, Req#radius_request.secret, [Head, ReqAuth, Body, <<?RMessage_Authenticator,18,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0>>]),
    {<<Body/binary, ?RMessage_Authenticator, 18, HMAC/binary>>, BodySize + 2 + 16}.

chunk(Bin, Length) ->
    case Bin of
	<<First:Length/bytes, Rest/binary>> -> {First, Rest};
	_ -> {Bin, <<>>}
    end.

encode_eap_attribute({<<>>, _}, EncReq) ->
    EncReq;
encode_eap_attribute({Value, Rest}, {Body, BodySize}) ->
    EncAttr = <<?REAP_Message, (byte_size(Value) + 2):8, Value/binary>>,
    EncReq = {<<Body/binary, EncAttr/binary>>, BodySize + byte_size(EncAttr)},
    encode_eap_attribute(chunk(Rest, 253), EncReq).

-spec encode_eap_message(#radius_request{}, {binary(), non_neg_integer()}) -> {binary(), non_neg_integer()}.
encode_eap_message(#radius_request{eap_msg = EAP}, EncReq)
  when is_binary(EAP); size(EAP) > 0 ->
    encode_eap_attribute(chunk(EAP, 253), EncReq);
encode_eap_message(#radius_request{eap_msg = <<>>}, EncReq) ->
    EncReq.

-spec encode_attributes(#radius_request{}, attribute_list()) -> {binary(), non_neg_integer()}.
encode_attributes(Req, Attributes) ->
    F = fun ({A = #attribute{}, Val}, {Body, BodySize}) ->
                EncAttr = encode_attribute(Req, A, Val),
                {<<Body/binary, EncAttr/binary>>, BodySize + byte_size(EncAttr)};
            ({ID, Val}, {Body, BodySize}) ->
                case eradius_dict:lookup(ID) of
                    [A = #attribute{}] ->
                        EncAttr = encode_attribute(Req, A, Val),
                        {<<Body/binary, EncAttr/binary>>, BodySize + byte_size(EncAttr)};
                    _ ->
                        {Body, BodySize}
                end
        end,
    lists:foldl(F, {<<>>, 0}, Attributes).

-spec encode_attribute(#radius_request{}, #attribute{}, term()) -> binary().
encode_attribute(_Req, _Attr = #attribute{id = ?RMessage_Authenticator}, _) ->
    %% message authenticator is handled through the msg_hmac flag
    <<>>;
encode_attribute(_Req, _Attr = #attribute{id = ?REAP_Message}, _) ->
    %% EAP-Message attributes are handled through the eap_msg field
    <<>>;
encode_attribute(Req, Attr = #attribute{id = {Vendor, ID}}, Value) ->
    EncValue = encode_attribute(Req, Attr#attribute{id = ID}, Value),
    if byte_size(EncValue) + 6 > 255 ->
	    error(badarg, [{Vendor, ID}, Value]);
       true -> ok
    end,
    <<?RVendor_Specific:8, (byte_size(EncValue) + 6):8, Vendor:32, EncValue/binary>>;
encode_attribute(Req, #attribute{type = {tagged, Type}, id = ID, enc = Enc}, Value) ->
    case Value of
        {Tag, UntaggedValue} when Tag >= 1, Tag =< 16#1F -> ok;
        UntaggedValue                                    -> Tag = 0
    end,
    EncValue = encrypt_value(Req, encode_value(Type, UntaggedValue), Enc),
    if byte_size(EncValue) + 3 > 255 ->
	    error(badarg, [ID, Value]);
       true -> ok
    end,
    <<ID, (byte_size(EncValue) + 3):8, Tag:8, EncValue/binary>>;
encode_attribute(Req, #attribute{type = Type, id = ID, enc = Enc}, Value)->
    EncValue = encrypt_value(Req, encode_value(Type, Value), Enc),
    if byte_size(EncValue) + 2 > 255 ->
	    error(badarg, [ID, Value]);
       true -> ok
    end,
    <<ID, (byte_size(EncValue) + 2):8, EncValue/binary>>.

-spec encrypt_value(#radius_request{}, binary(), eradius_dict:attribute_encryption()) -> binary().
encrypt_value(Req, Val, scramble)   -> scramble(Req#radius_request.secret, Req#radius_request.authenticator, Val);
encrypt_value(Req, Val, salt_crypt) -> salt_encrypt(generate_salt(), Req#radius_request.secret, Req#radius_request.authenticator, Val);
encrypt_value(_Req, Val, no)        -> Val.

-spec encode_value(eradius_dict:attribute_prim_type(), term()) -> binary().
encode_value(_, V) when is_binary(V) ->
    V;
encode_value(binary, V) ->
    V;
encode_value(integer, V) ->
    <<V:32>>;
encode_value(integer24, V) ->
    <<V:24>>;
encode_value(integer64, V) ->
    <<V:64>>;
encode_value(ipaddr, {A,B,C,D}) ->
    <<A:8, B:8, C:8, D:8>>;
encode_value(ipv6addr, {A,B,C,D,E,F,G,H}) ->
    <<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>>;
encode_value(ipv6prefix, {{A,B,C,D,E,F,G,H}, PLen}) ->
    L = (PLen + 7) div 8,
    <<IP:L/bytes, _R/binary>> = <<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>>,
    <<0, PLen, IP/binary>>;
encode_value(string, V) when is_list(V) ->
    unicode:characters_to_binary(V);
encode_value(octets, V) when is_list(V) ->
    iolist_to_binary(V);
encode_value(octets, V) when is_integer(V) ->
    <<V:32>>;
encode_value(date, V) when is_list(V) ->
    unicode:characters_to_binary(V);
encode_value(date, Date = {{_,_,_},{_,_,_}}) ->
    EpochSecs = calendar:datetime_to_gregorian_seconds(Date) - calendar:datetime_to_gregorian_seconds({{1970,1,1},{0,0,0}}),
    <<EpochSecs:32>>.

%% ------------------------------------------------------------------------------------------
%% -- Wire Decoding

-spec decode_request_id(binary()) -> {0..255, binary()} | {bad_pdu, list()}.
decode_request_id(Req = <<_Cmd:8, ReqId:8, _Rest/binary>>) -> {ReqId, Req};
decode_request_id(_Req) -> {bad_pdu, "invalid request id"}.

-spec decode_request(binary(), secret()) -> #radius_request{} | {bad_pdu, list()}.
decode_request(Packet, Secret) ->
    decode_request(Packet, Secret, undefined).

-spec decode_request(binary(), secret(), authenticator()) -> #radius_request{} | {bad_pdu, list()}.
decode_request(Packet, Secret, Authenticator) ->
    case (catch decode_request0(Packet, Secret, Authenticator)) of
        {'EXIT', _} -> {bad_pdu, "decode packet error"};
        Else        -> Else
    end.

-spec decode_request0(binary(), secret(), authenticator() | 'undefined') -> #radius_request{}.
decode_request0(<<Cmd:8, ReqId:8, Len:16, PacketAuthenticator:16/binary, Body0/binary>>, Secret, RequestAuthenticator) ->
    ActualBodySize = byte_size(Body0),
    GivenBodySize  = Len - 20,
    Body = if
              ActualBodySize > GivenBodySize ->
                  throw({bad_pdu, "false packet size"});
              ActualBodySize == GivenBodySize ->
                  Body0;
              true ->
                  binary:part(Body0, 0, GivenBodySize)
           end,
    Command = decode_command(Cmd),
    PartialRequest = #radius_request{cmd = Command, reqid = ReqId, authenticator = PacketAuthenticator, secret = Secret, msg_hmac = false},
    DecodedState = decode_attributes(PartialRequest, RequestAuthenticator, Body),
    Request = PartialRequest#radius_request{attrs = lists:reverse(DecodedState#decoder_state.attrs),
					    eap_msg = list_to_binary(lists:reverse(DecodedState#decoder_state.eap_msg))},
    validate_authenticator(Command, <<Cmd:8, ReqId:8, Len:16>>, RequestAuthenticator, PacketAuthenticator, Body, Secret),
    if
	is_integer(DecodedState#decoder_state.hmac_pos) ->
	    validate_packet_authenticator(Cmd, ReqId, Len, Body, DecodedState#decoder_state.hmac_pos, Secret, PacketAuthenticator, RequestAuthenticator),
	    Request#radius_request{msg_hmac = true};
	true -> Request
    end.

-spec validate_packet_authenticator(non_neg_integer(), non_neg_integer(), non_neg_integer(), non_neg_integer(), binary(), binary(), authenticator(), authenticator() | 'undefined') -> ok.
validate_packet_authenticator(Cmd, ReqId, Len, Body, Pos, Secret, PacketAuthenticator, undefined) ->
    validate_packet_authenticator(Cmd, ReqId, Len, PacketAuthenticator, Body, Pos, Secret);
validate_packet_authenticator(Cmd, ReqId, Len, Body, Pos, Secret, _PacketAuthenticator, RequestAuthenticator) ->
    validate_packet_authenticator(Cmd, ReqId, Len, RequestAuthenticator, Body, Pos, Secret).

-spec validate_packet_authenticator(non_neg_integer(), non_neg_integer(), non_neg_integer(), authenticator(), non_neg_integer(), binary(), binary()) -> ok.
validate_packet_authenticator(Cmd, ReqId, Len, Auth, Body, Pos, Secret) ->
    case Body of
        <<Before:Pos/bytes, Value:16/bytes, After/binary>> ->
            case crypto:hmac(md5, Secret, [<<Cmd:8, ReqId:8, Len:16>>, Auth, Before, zero_authenticator(), After]) of
            Value ->
                ok;
            _     ->
                throw({bad_pdu, "Message-Authenticator Attribute is invalid"})
            end;
        _ ->
            throw({bad_pdu, "Message-Authenticator Attribute is malformed"})
    end.

validate_authenticator(accreq, Head, _RequestAuthenticator, PacketAuthenticator, Body, Secret) ->
    compare_authenticator(crypto:hash(md5, [Head, zero_authenticator(), Body, Secret]), PacketAuthenticator);
validate_authenticator(Cmd, Head, RequestAuthenticator, PacketAuthenticator, Body, Secret)
    when
        (Cmd =:= accept)  orelse
        (Cmd =:= reject)  orelse
        (Cmd =:= accresp) orelse
        (Cmd =:= coaack)  orelse
        (Cmd =:= coanak)  orelse
        (Cmd =:= discack) orelse
        (Cmd =:= discnak) orelse
        (Cmd =:= challenge) ->
    compare_authenticator(crypto:hash(md5, [Head, RequestAuthenticator, Body, Secret]), PacketAuthenticator);
validate_authenticator(_Cmd, _Head, _RequestAuthenticator, _PacketAuthenticator,
                       _Body, _Secret) ->
    true.

compare_authenticator(Authenticator, Authenticator) ->
    true;
compare_authenticator(_RequestAuthenticator, _PacketAuthenticator) ->
    throw({bad_pdu, "Authenticator Attribute is invalid"}).

-spec decode_command(byte()) -> command().
decode_command(?RAccess_Request)      -> request;
decode_command(?RAccess_Accept)       -> accept;
decode_command(?RAccess_Reject)       -> reject;
decode_command(?RAccess_Challenge)    -> challenge;
decode_command(?RAccounting_Request)  -> accreq;
decode_command(?RAccounting_Response) -> accresp;
decode_command(?RCoa_Request)         -> coareq;
decode_command(?RCoa_Ack)             -> coaack;
decode_command(?RCoa_Nak)             -> coanak;
decode_command(?RDisconnect_Request)  -> discreq;
decode_command(?RDisconnect_Ack)      -> discack;
decode_command(?RDisconnect_Nak)      -> discnak;
decode_command(_)                     -> error({bad_pdu, "unknown request type"}).

append_attr(Attr, State) ->
    State#decoder_state{attrs = [Attr | State#decoder_state.attrs]}.

-spec decode_attributes(#radius_request{}, binary(), binary()) -> #decoder_state{}.
decode_attributes(Req, RequestAuthenticator, As) ->
    decode_attributes(Req, As, 0, #decoder_state{request_authenticator = RequestAuthenticator}).

-spec decode_attributes(#radius_request{}, binary(), non_neg_integer(), #decoder_state{}) -> #decoder_state{}.
decode_attributes(_Req, <<>>, _Pos, State) ->
    State;
decode_attributes(Req, <<Type:8, ChunkLength:8, ChunkRest/binary>>, Pos, State) ->
    ValueLength = ChunkLength - 2,
    <<Value:ValueLength/binary, PacketRest/binary>> = ChunkRest,
    NewState = case eradius_dict:lookup(Type) of
		   [AttrRec = #attribute{}] ->
		       decode_attribute(Value, Req, AttrRec, Pos + 2, State);
		   _ ->
		       append_attr({Type, Value}, State)
    end,
    decode_attributes(Req, PacketRest, Pos + ChunkLength, NewState).

%% gotcha: the function returns a LIST of attribute-value pairs because
%% a vendor-specific attribute blob might contain more than one attribute.
-spec decode_attribute(binary(), #radius_request{}, #attribute{}, non_neg_integer(), #decoder_state{}) -> #decoder_state{}.
decode_attribute(<<VendorID:32/integer, ValueBin/binary>>, Req, #attribute{id = ?RVendor_Specific}, Pos, State) ->
    decode_vendor_specific_attribute(Req, VendorID, ValueBin, Pos + 4, State);
decode_attribute(<<Value/binary>>, _Req, Attr = #attribute{id = ?REAP_Message}, _Pos, State) ->
    NewState = State#decoder_state{eap_msg = [Value | State#decoder_state.eap_msg]},
    append_attr({Attr, Value}, NewState);
decode_attribute(<<EncValue/binary>>, Req, Attr = #attribute{id = ?RMessage_Authenticator, type = Type, enc = Encryption}, Pos, State) ->
    append_attr({Attr, decode_value(decrypt_value(Req, State, EncValue, Encryption), Type)}, State#decoder_state{hmac_pos = Pos});
decode_attribute(<<EncValue/binary>>, Req, Attr = #attribute{type = Type, enc = Encryption}, _Pos, State) when is_atom(Type) ->
    append_attr({Attr, decode_value(decrypt_value(Req, State, EncValue, Encryption), Type)}, State);
decode_attribute(WholeBin = <<Tag:8, Bin/binary>>, Req, Attr = #attribute{type = {tagged, Type}}, _Pos, State) ->
    case {decode_tag_value(Tag), Attr#attribute.enc} of
        {0, no} ->
            % decode including tag byte if tag is out of range
            append_attr({Attr, {0, decode_value(WholeBin, Type)}}, State);
        {TagV, no} ->
            append_attr({Attr, {TagV, decode_value(Bin, Type)}}, State);
        {TagV, Encryption} ->
            % for encrypted attributes, tag byte is never part of the value
            append_attr({Attr, {TagV, decode_value(decrypt_value(Req, State, Bin, Encryption), Type)}}, State)
    end.

-compile({inline, decode_tag_value/1}).
decode_tag_value(Tag) when (Tag >= 1) and (Tag =< 16#1F) -> Tag;
decode_tag_value(_OtherTag)                              -> 0.

-spec decode_value(binary(), eradius_dict:attribute_prim_type()) -> term().
decode_value(<<Bin/binary>>, Type) ->
    case Type of
        octets ->
            Bin;
        binary ->
            Bin;
        abinary ->
            Bin;
        string ->
            Bin;
        integer ->
            decode_integer(Bin);
        integer24 ->
            decode_integer(Bin);
        integer64 ->
            decode_integer(Bin);
        date ->
            case decode_integer(Bin) of
                Int when is_integer(Int) ->
                    calendar:now_to_universal_time({Int div 1000000, Int rem 1000000, 0});
                _ ->
                    Bin
            end;
        ipaddr ->
            <<B,C,D,E>> = Bin,
            {B,C,D,E};
        ipv6addr ->
            <<B:16,C:16,D:16,E:16,F:16,G:16,H:16,I:16>> = Bin,
            {B,C,D,E,F,G,H,I};
        ipv6prefix ->
            <<0,PLen,P/binary>> = Bin,
            <<B:16,C:16,D:16,E:16,F:16,G:16,H:16,I:16>> = pad_to(16, P),
            {{B,C,D,E,F,G,H,I}, PLen}
    end.

-compile({inline, decode_integer/1}).
decode_integer(Bin) ->
    ISize = bit_size(Bin),
    case Bin of
        <<Int:ISize/integer>> -> Int;
        _                     -> Bin
    end.

-spec decrypt_value(#radius_request{}, #decoder_state{}, binary(),
		    eradius_dict:attribute_encryption()) -> eradius_dict:attr_value().
decrypt_value(#radius_request{secret = Secret, authenticator = Authenticator},
	      _, <<Val/binary>>, scramble) ->
    scramble(Secret, Authenticator, Val);
decrypt_value(#radius_request{secret = Secret},
	      #decoder_state{request_authenticator = RequestAuthenticator},
	      <<Val/binary>>, salt_crypt)
when is_binary(RequestAuthenticator) ->
    salt_decrypt(Secret, RequestAuthenticator, Val);
decrypt_value(_Req, _State, <<Val/binary>>, _Type) ->
    Val.

-spec decode_vendor_specific_attribute(#radius_request{}, non_neg_integer(), binary(), non_neg_integer(), #decoder_state{}) -> #decoder_state{}.
decode_vendor_specific_attribute(_Req, _VendorID, <<>>, _Pos, State) ->
    State;
decode_vendor_specific_attribute(Req, VendorID, <<Type:8, ChunkLength:8, ChunkRest/binary>>, Pos, State) ->
    ValueLength = ChunkLength - 2,
    <<Value:ValueLength/binary, PacketRest/binary>> = ChunkRest,
    VendorAttrKey = {VendorID, Type},
    NewState = case eradius_dict:lookup(VendorAttrKey) of
		   [AttrRec = #attribute{}] ->
		       decode_attribute(Value, Req, AttrRec, Pos + 2, State);
		   _ ->
		       append_attr({VendorAttrKey, Value}, State)
    end,
    decode_vendor_specific_attribute(Req, VendorID, PacketRest, Pos + ChunkLength, NewState).

%% ------------------------------------------------------------------------------------------
%% -- Attribute Encryption
-spec scramble(secret(), authenticator(), binary()) -> binary().
scramble(SharedSecret, RequestAuthenticator, <<PlainText/binary>>) ->
    B = crypto:hash(md5, [SharedSecret, RequestAuthenticator]),
    do_scramble(SharedSecret, B, pad_to(16, PlainText), << >>).

do_scramble(SharedSecret, B, <<PlainText:16/binary, Remaining/binary>>, CipherText) ->
    NewCipherText = crypto:exor(PlainText, B),
    Bnext = crypto:hash(md5, [SharedSecret, NewCipherText]),
    do_scramble(SharedSecret, Bnext, Remaining, <<CipherText/binary, NewCipherText/binary>>);

do_scramble(_SharedSecret, _B, << >>, CipherText) ->
    CipherText.

-spec generate_salt() -> salt().
generate_salt() ->
    <<Salt1, Salt2>> = crypto:strong_rand_bytes(2),
    <<(Salt1 bor 16#80), Salt2>>.

-spec salt_encrypt(salt(), secret(), authenticator(), binary()) -> binary().
salt_encrypt(Salt, SharedSecret, RequestAuthenticator, PlainText) ->
    CipherText = do_salt_crypt(encrypt, Salt, SharedSecret, RequestAuthenticator, (pad_to(16, << (byte_size(PlainText)):8, PlainText/binary >>))),
    <<Salt/binary, CipherText/binary>>.

-spec salt_decrypt(secret(), authenticator(), binary()) -> binary().
salt_decrypt(SharedSecret, RequestAuthenticator, <<Salt:2/binary, CipherText/binary>>) ->
    << Length:8/integer, PlainText/binary >> = do_salt_crypt(decrypt, Salt, SharedSecret, RequestAuthenticator, CipherText),
    if
        Length < byte_size(PlainText) ->
            binary:part(PlainText, 0, Length);
        true ->
            PlainText
    end.

do_salt_crypt(Op, Salt, SharedSecret, RequestAuthenticator, <<CipherText/binary>>) ->
    B = crypto:hash(md5, [SharedSecret, RequestAuthenticator, Salt]),
    salt_crypt(Op, SharedSecret, B, CipherText, << >>).

salt_crypt(Op, SharedSecret, B, <<PlainText:16/binary, Remaining/binary>>, CipherText) ->
    NewCipherText = crypto:exor(PlainText, B),
    Bnext = case Op of
		decrypt -> crypto:hash(md5, [SharedSecret, PlainText]);
		encrypt -> crypto:hash(md5, [SharedSecret, NewCipherText])
	    end,
    salt_crypt(Op, SharedSecret, Bnext, Remaining, <<CipherText/binary, NewCipherText/binary>>);

salt_crypt(_Op, _SharedSecret, _B, << >>, CipherText) ->
    CipherText.

%% @doc pad binary to specific length
%%   See <a href="http://www.erlang.org/pipermail/erlang-questions/2008-December/040709.html">
%%          http://www.erlang.org/pipermail/erlang-questions/2008-December/040709.html
%%       </a>
-compile({inline, pad_to/2}).
pad_to(Width, Binary) ->
     case (Width - byte_size(Binary) rem Width) rem Width of
         0 -> Binary;
         N -> <<Binary/binary, 0:(N*8)>>
     end.

-spec timestamp() -> erlang:timestamp().
timestamp() ->
    try
        erlang:timestamp()
    catch
        error:undef ->
            % call erlang:now() via erlang:apply/3
            % for getting rid annoying compile warning on OTP >= 18
            erlang:apply(erlang, now, [])
    end.

-spec printable_peer(inet:ip4_address(),eradius_server:port_number()) -> io_lib:chars().
printable_peer({IA,IB,IC,ID}, Port) ->
    io_lib:format("~b.~b.~b.~b:~b",[IA,IB,IC,ID,Port]).
