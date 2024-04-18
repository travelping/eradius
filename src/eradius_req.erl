%% Copyright (c) 2024, Travelping GmbH <info@travelping.com>
%%
%% SPDX-License-Identifier: MIT

-module(eradius_req).

-export([is_valid/1,
         req_id/1,
         cmd/1,
         authenticator/1,
         request_authenticator/1,
         msg_hmac/1,
         eap_msg/1,
         packet/1,
         attrs/1,
         attr/2]).
-export([new/1, new/2,
         request/4,
         response/3,
         set_secret/2,
         set_body/2,
         set_attrs/2,
         add_attr/3,
         set_attr/3,
         set_msg_hmac/2,
         set_eap_msg/2,
         set_metrics_callback/2]).
-export([record_metric/3, metrics_callback/3]).

-ignore_xref([is_valid/1,
              req_id/1,
              cmd/1,
              authenticator/1,
              request_authenticator/1,
              msg_hmac/1,
              eap_msg/1,
              packet/1,
              attrs/1,
              attr/2]).
-ignore_xref([new/1, new/2,
              request/4,
              response/3,
              set_secret/2,
              set_body/2,
              set_attrs/2,
              add_attr/3,
              set_attr/3,
              set_msg_hmac/2,
              set_eap_msg/2,
              set_metrics_callback/2]).

-ifdef(TEST).
-export([encode_value/2, decode_value/2, scramble/3, ascend/3]).
-export([salt_encrypt/4, salt_decrypt/3, encode_attribute/3, decode_attribute/4]).
-ignore_xref([encode_value/2, decode_value/2, scramble/3, ascend/3]).
-ignore_xref([salt_encrypt/4, salt_decrypt/3, encode_attribute/3, decode_attribute/4]).
-endif.

-include("eradius_lib.hrl").
-include("eradius_dict.hrl").

-type command() :: 'request' | 'accept' | 'challenge' | 'reject' | 'accreq' | 'accresp' |
                   'coareq' | 'coaack' | 'coanak' | 'discreq' | 'discack' | 'discnak'.
-type secret() :: binary().
-type authenticator() :: <<_:128>>.
-type salt() :: binary().
-type attribute_list() :: [{eradius_dict:attribute(), term()}].
-export_type([command/0, secret/0, authenticator/0, salt/0, attribute_list/0]).

-type metrics_event() :: 'request' | 'reply' |
                         'retransmission' | 'discard' |
                         'invalid_request'.
-type metrics_callback() ::
        fun((Event :: metrics_event(), MetaData :: term(), Req :: req()) -> req()).
-export_type([metrics_event/0, metrics_callback/0]).

-type req() ::
        #{
          %% public fields
          is_valid              := undefined | boolean(),
          cmd                   := command(),
          secret                => secret(),
          req_id                => byte(),
          authenticator         => authenticator(),
          request_authenticator => authenticator(),

          %% public, server only
          client                => binary(),
          client_addr           => {IP :: inet:ip_address(), inet:port_number()},

          server                => eradius_server:server_name(),
          server_addr           => {IP :: inet:ip_address(), inet:port_number()},

          %% private fields
          arrival_time          => integer(),
          socket                => gen_udp:socket(),

          head                  => binary(),
          body                  := undefined | binary(),
          attrs                 := undefined | attribute_list(),
          eap_msg               := undefined | binary(),
          msg_hmac              := undefined | boolean() | integer(),

          metrics_callback      := undefined | metrics_callback(),

          _ => _
         }.

-export_type([req/0]).

%%%=========================================================================
%%%  API
%%%=========================================================================

%% @doc Return validation state of the request.
%%
%% - `true' for a requests if has been encoded to binary form,
%%
%% - `true' for a response if has been decoded from binary form
%%    and the authenticator has been validate,
%%
%% - `true' for a response if has been decoded from binary form
%%    and the authenticator failed to validate,
%%
%% - `undefined' otherwise
%% @end
-spec is_valid(req()) -> true | false | undefined.
is_valid(#{is_valid := IsValid}) -> IsValid.

-spec req_id(req()) -> byte() | undefined.
req_id(#{req_id := ReqId}) -> ReqId;
req_id(_) -> undefined.

-spec cmd(req()) -> command().
cmd(#{cmd := Cmd}) -> Cmd.

-spec authenticator(req()) -> authenticator() | undefined.
authenticator(#{authenticator := Authenticator}) -> Authenticator;
authenticator(_) -> undefined.

-spec request_authenticator(req()) -> authenticator() | undefined.
request_authenticator(#{authenticator := Authenticator}) -> Authenticator;
request_authenticator(_) -> undefined.

-spec msg_hmac(req()) -> boolean() | undefined.
msg_hmac(#{msg_hmac := MsgHMAC}) -> MsgHMAC;
msg_hmac(_) -> undefined.

-spec eap_msg(req()) -> binary() | undefined.
eap_msg(#{eap_msg := EAPmsg}) -> EAPmsg;
eap_msg(_) -> undefined.

%% @doc Convert a RADIUS request to the wire format.
-spec packet(req()) -> {binary(), req()} | no_return().
packet(#{req_id := _, cmd := _, authenticator := _, body := Body, secret := _} = Req)
  when is_binary(Body) ->
    %% body must be fully prepared
    encode_body(Req, Body);
packet(#{req_id := _, cmd := _, secret := _, attrs := Attrs, eap_msg := EAPmsg} = Req)
  when is_list(Attrs) ->
    Body0 = encode_attributes(Req, Attrs, <<>>),
    Body1 = encode_eap_message(EAPmsg, Body0),
    Body = encode_message_authenticator(Req, Body1),
    encode_body(Req, Body);
packet(Req) ->
    erlang:error(badarg, [Req]).

-spec attrs(req()) -> {attribute_list(), req()} | no_return().
attrs(#{attrs := Attrs, is_valid := IsValid} = Req)
  when is_list(Attrs), IsValid =/= false ->
    {Attrs, Req};
attrs(#{body := Body, secret := _} = Req0)
  when is_binary(Body) ->
    try
        #{attrs := Attrs} = Req = decode_body(Body, Req0),
        {Attrs, Req}
    catch
        exit:_ ->
            throw({bad_pdu, decoder_error})
    end;
attrs(Req) ->
    erlang:error(badarg, [Req]).

attr(Id, #{attrs := Attrs, is_valid := IsValid})
  when is_list(Attrs), IsValid =/= false ->
    get_attr(Id, Attrs);
attr(_, _) ->
    undefined.

get_attr(_Id, []) ->
    undefined;
get_attr(Id, [Head|Tail]) ->
    case Head of
        {#attribute{id = Id}, Value} -> Value;
        {Id, Value} -> Value;
        _ -> get_attr(Id, Tail)
    end.


-spec new(command()) -> req().
new(Command) ->
    new(Command, undefined).

-spec new(command(), 'undefined' | metrics_callback()) -> req().
new(Command, MetricsCallback)
  when MetricsCallback =:= undefined; is_function(MetricsCallback, 3) ->
    #{is_valid => undefined,
      cmd => Command,

      body => undefined,
      attrs => [],
      eap_msg => undefined,
      msg_hmac => undefined,

      metrics_callback => MetricsCallback
     }.

-spec request(binary(), binary(), eradius_server:client(), 'undefined' | metrics_callback()) ->
          req() | no_return().
request(<<Cmd, ReqId, Len:16, Authenticator:16/bytes>> = Header, Body,
        #{secret := Secret, client := ClientId}, MetricsCallback) ->
    Command = decode_command(Cmd),
    Req = new(Command, MetricsCallback),
    mk_req(Command, ReqId, Len, Authenticator, Header, Body,
           Req#{req_id => ReqId, request_authenticator => Authenticator,
                client => ClientId, secret => Secret}).

-spec response(binary(), binary(), req()) -> req() | no_return();
              (command(), undefined | attribute_list(), req()) -> req().
response(<<Cmd, ReqId, Len:16, Authenticator:16/bytes>> = Header, Body,
         #{req_id := ReqId, secret := _} = Req) ->
    Command = decode_command(Cmd),
    mk_req(Command, ReqId, Len, Authenticator, Header, Body, Req);

response(Response, Attrs, Req) when is_atom(Response) ->
    Req#{cmd := Response, body := undefined, attrs := Attrs, is_valid := undefined}.

-spec set_secret(req(), secret()) -> req().
set_secret(Req, Secret) ->
    Req#{secret => Secret, is_valid := undefined}.

-spec set_body(req(), binary()) -> req().
set_body(Req, Body) when is_binary(Body) ->
    Req#{body := Body, attrs := undefined, is_valid := undefined}.

-spec set_attrs(attribute_list(), req()) -> req().
set_attrs(Attrs, Req) when is_list(Attrs) ->
    Req#{body := undefined, attrs := Attrs, is_valid := undefined}.

add_attr(Id, Value, #{attrs := Attrs} = Req)
  when is_list(Attrs) ->
    Req#{attrs := [{Id, Value} | Attrs], is_valid := undefined}.

set_attr(Id, Value, #{attrs := Attrs} = Req)
  when is_list(Attrs) ->
    Req#{attrs := lists:keystore(Id, 1, Attrs, {Id, Value}), is_valid := undefined}.

-spec set_msg_hmac(boolean(), req()) -> req().
set_msg_hmac(MsgHMAC, Req)
  when is_boolean(MsgHMAC) ->
    Req#{msg_hmac => MsgHMAC}.

-spec set_eap_msg(binary(), req()) -> req().
set_eap_msg(EAPmsg, Req)
  when is_binary(EAPmsg) ->
    Req#{body := undefined, eap_msg := EAPmsg}.

-spec set_metrics_callback(undefined | metrics_callback(), req()) -> req().
set_metrics_callback(MetricsCallback, Req) ->
    Req#{metrics_callback => MetricsCallback}.

-spec metrics_callback(Cb :: undefined | eradius_req:metrics_callback(), Event :: metrics_event(), MetaData :: term()) -> any().
metrics_callback(Cb, Event, MetaData)
  when is_function(Cb, 3) ->
    Cb(Event, MetaData, undefined);
metrics_callback(_, _, _) ->
    undefined.

-spec record_metric(Event :: metrics_event(), MetaData :: term(), Req :: req()) -> req().
record_metric(Event, MetaData, #{metrics_callback := Cb} = Req)
  when is_function(Cb, 3) ->
    Cb(Event, MetaData, Req);
record_metric(_, _, Req) ->
    Req.

%%%===================================================================
%%% binary format handling
%%%===================================================================

%% ------------------------------------------------------------------------------------------
%% -- Request Accessors
-spec random_authenticator() -> authenticator().
random_authenticator() -> crypto:strong_rand_bytes(16).

-spec zero_authenticator() -> authenticator().
zero_authenticator() -> <<0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0>>.

mk_req(Cmd, ReqId, Len, Authenticator, Header, Body0, #{req_id := ReqId} = Req)
  when byte_size(Body0) >= (Len - 20) ->
    <<Body:(Len - 20)/bytes, _/binary>> = Body0,
    <<Head:4/bytes, _/binary>> = Header,

    validate_authenticator(Cmd, Head, Authenticator, Body, Req),
    Req#{cmd := Cmd,
         authenticator => Authenticator,
         is_valid := true,
         msg_hmac := undefined,
         eap_msg := undefined,
         head => Head,
         body := Body,
         attrs := undefined};
mk_req(_, ResponseReqId, _, _, _, _, #{req_id := ReqId})
  when ResponseReqId =/= ReqId ->
    throw({bad_pdu, invalid_req_id});
mk_req(_, _, Len, _, _, Body, _)
  when byte_size(Body) =< (Len - 20) ->
    throw({bad_pdu, invalid_packet_size}).

%% ------------------------------------------------------------------------------------------
%% -- Wire Encoding

encode_body(#{req_id := ReqId, cmd := Cmd} = Req, Body)
  when Cmd =:= request ->
    Authenticator = random_authenticator(),
    Packet = <<(encode_command(Cmd)):8, ReqId:8, (byte_size(Body) + 20):16,
               Authenticator:16/binary, Body/binary>>,
    {Packet, Req#{is_valid := true, request_authenticator => Authenticator}};

encode_body(#{req_id := ReqId, cmd := Cmd, secret := Secret} = Req, Body)
  when Cmd =:= accreq; Cmd =:= coareq; Cmd =:= discreq ->
    Head = <<(encode_command(Cmd)):8, ReqId:8, (byte_size(Body) + 20):16>>,
    Authenticator = crypto:hash(md5, [Head, zero_authenticator(), Body, Secret]),
    Packet = <<Head/binary, Authenticator:16/binary, Body/binary>>,
    {Packet, Req#{is_valid := true, request_authenticator => Authenticator}};

encode_body(#{req_id := ReqId, cmd := Cmd,
              request_authenticator := Authenticator,
              secret := Secret} = Req, Body) ->
    Head = <<(encode_command(Cmd)):8, ReqId:8, (byte_size(Body) + 20):16>>,

    ReplyAuthenticator = crypto:hash(md5, [Head, <<Authenticator:16/binary>>, Body, Secret]),
    Packet = <<Head/binary, ReplyAuthenticator:16/binary, Body/binary>>,
    {Packet, Req#{is_valid := true}}.

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

-spec encode_message_authenticator(req(), binary()) -> binary().
encode_message_authenticator(#{reqid := ReqId, cmd := Cmd,
                               authenticator := Authenticator,
                               secret := Secret,
                               msg_hmac := true}, Body) ->
    Head = <<(encode_command(Cmd)):8, ReqId:8, (byte_size(Body) + 20 + 2 + 16):16>>,
    HMAC = message_authenticator(
             Secret, [Head, Authenticator, Body,
                      <<?RMessage_Authenticator,18,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0>>]),
    <<Body/binary, ?RMessage_Authenticator, 18, HMAC/binary>>;
encode_message_authenticator(_Req, Body) ->
    Body.

chunk(Bin, Length) ->
    case Bin of
        <<First:Length/bytes, Rest/binary>> -> {First, Rest};
        _ -> {Bin, <<>>}
    end.

encode_eap_attribute({<<>>, _}, EncReq) ->
    EncReq;
encode_eap_attribute({Value, Rest}, Body) ->
    EncAttr = <<?REAP_Message, (byte_size(Value) + 2):8, Value/binary>>,
    encode_eap_attribute(chunk(Rest, 253), <<Body/binary, EncAttr/binary>>).

-spec encode_eap_message(binary(), binary()) -> binary().
encode_eap_message(EAP, EncReq)
  when EAP =:= <<>>; EAP =:= undefined ->
    EncReq;
encode_eap_message(EAP, EncReq) when is_binary(EAP) ->
    encode_eap_attribute(chunk(EAP, 253), EncReq).

-spec encode_attributes(req(), attribute_list(), binary()) -> binary().
encode_attributes(Req, Attributes, Init) ->
    lists:foldl(
      fun ({A = #attribute{}, Val}, Body) ->
              EncAttr = encode_attribute(Req, A, Val),
              <<Body/binary, EncAttr/binary>>;
          ({Id, Val}, Body) ->
              case eradius_dict:lookup(attribute, Id) of
                  AttrRec = #attribute{} ->
                      EncAttr = encode_attribute(Req, AttrRec, Val),
                      <<Body/binary, EncAttr/binary>>;
                  _ ->
                      Body
                end
      end, Init, Attributes).

-spec encode_attribute(eradius_req:req(), #attribute{}, term()) -> binary().
encode_attribute(_Req, _Attr = #attribute{id = ?RMessage_Authenticator}, _) ->
    %% message authenticator is handled through the msg_hmac flag
    <<>>;
encode_attribute(_Req, _Attr = #attribute{id = ?REAP_Message}, _) ->
    %% EAP-Message attributes are handled through the eap_msg field
    <<>>;
encode_attribute(Req, Attr = #attribute{id = {Vendor, Id}}, Value) ->
    EncValue = encode_attribute(Req, Attr#attribute{id = Id}, Value),
    if byte_size(EncValue) + 6 > 255 ->
            error(badarg, [{Vendor, Id}, Value]);
       true -> ok
    end,
    <<?RVendor_Specific:8, (byte_size(EncValue) + 6):8, Vendor:32, EncValue/binary>>;
encode_attribute(Req, #attribute{type = {tagged, Type}, id = Id, enc = Enc}, Value) ->
    case Value of
        {Tag, UntaggedValue} when Tag >= 1, Tag =< 16#1F -> ok;
        UntaggedValue                                    -> Tag = 0
    end,
    EncValue = encrypt_value(Req, encode_value(Type, UntaggedValue), Enc),
    if byte_size(EncValue) + 3 > 255 ->
            error(badarg, [Id, Value]);
       true -> ok
    end,
    <<Id, (byte_size(EncValue) + 3):8, Tag:8, EncValue/binary>>;
encode_attribute(Req, #attribute{type = Type, id = Id, enc = Enc}, Value)->
    EncValue = encrypt_value(Req, encode_value(Type, Value), Enc),
    if byte_size(EncValue) + 2 > 255 ->
            error(badarg, [Id, Value]);
       true -> ok
    end,
    <<Id, (byte_size(EncValue) + 2):8, EncValue/binary>>.

-spec encrypt_value(req(), binary(), eradius_dict:attribute_encryption()) -> binary().
encrypt_value(#{authenticator := Authenticator, secret := Secret}, Val, scramble) ->
    scramble(Secret, Authenticator, Val);
encrypt_value(#{authenticator := Authenticator, secret := Secret}, Val, salt_crypt) ->
    salt_encrypt(generate_salt(), Secret, Authenticator, Val);
encrypt_value(#{authenticator := Authenticator, secret := Secret}, Val, ascend) ->
    ascend(Secret, Authenticator, Val);
encrypt_value(_Req, Val, no) ->
    Val.

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
    EpochSecs = calendar:datetime_to_gregorian_seconds(Date) -
        calendar:datetime_to_gregorian_seconds({{1970,1,1},{0,0,0}}),
    <<EpochSecs:32>>.

%% ------------------------------------------------------------------------------------------
%% -- Wire Decoding

-spec decode_body(binary(), req()) -> req().
decode_body(Body, #{is_valid := true, head := Head} = Req0) ->
    Req1 = Req0#{msg_hmac => 0, attrs => [], eap_msg => <<>>},
    Req2 = decode_attributes(Body, 0, Req1),

    case Req2 of
        #{msg_hmac := Pos} when Pos > 0 ->
            validate_packet_authenticator(Head, Body, Pos, Req2),
            Req2#{msg_hmac := true};
        _ ->
            Req2#{msg_hmac := false}
    end.

validate_packet_authenticator(Head, Body, Pos,
                              #{request_authenticator := Authenticator, secret := Secret}) ->
    validate_packet_authenticator(Head, Body, Pos, Authenticator, Secret);
validate_packet_authenticator(Head, Body, Pos,
                              #{authenticator := Authenticator, secret := Secret}) ->
    validate_packet_authenticator(Head, Body, Pos, Authenticator, Secret).

validate_packet_authenticator(Head, Body, Pos, Auth, Secret) ->
    case Body of
        <<Before:Pos/bytes, Value:16/bytes, After/binary>> ->
            case message_authenticator(Secret, [Head, Auth, Before, zero_authenticator(), After]) of
                Value ->
                    ok;
                _     ->
                    throw({bad_pdu, "Message-Authenticator Attribute is invalid"})
            end;
        _ ->
            throw({bad_pdu, "Message-Authenticator Attribute is malformed"})
    end.

validate_authenticator(Cmd, Head, PacketAuthenticator, Body,
                       #{authenticator := RequestAuthenticator, secret := Secret})
  when Cmd =:= accept; Cmd =:= reject; Cmd =:= accresp;  Cmd =:= coaack;
       Cmd =:= coanak; Cmd =:= discack; Cmd =:= discnak; Cmd =:= challenge ->
    compare_authenticator(crypto:hash(md5, [Head, RequestAuthenticator, Body, Secret]), PacketAuthenticator);
validate_authenticator(accreq, Head, PacketAuthenticator, Body,
                       #{secret := Secret}) ->
    compare_authenticator(crypto:hash(md5, [Head, zero_authenticator(), Body, Secret]), PacketAuthenticator);
validate_authenticator(_Cmd, _Head, _RequestAuthenticator, _Body, _Req) ->
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

append_attr(Attr, #{attrs := Attrs} = Req) ->
    Req#{attrs := [Attr | Attrs]}.

decode_attributes(<<>>, _Pos, #{attrs := Attrs} = Req) ->
    Req#{attrs := lists:reverse(Attrs)};
decode_attributes(<<Type:8, ChunkLength:8, ChunkRest/binary>>, Pos, Req0) ->
    ValueLength = ChunkLength - 2,
    <<Value:ValueLength/binary, PacketRest/binary>> = ChunkRest,
    Req = case eradius_dict:lookup(attribute, Type) of
              AttrRec = #attribute{} ->
                  decode_attribute(Value, AttrRec, Pos + 2, Req0);
              _ ->
                  append_attr({Type, Value}, Req0)
          end,
    decode_attributes(PacketRest, Pos + ChunkLength, Req).

%% gotcha: the function returns a LIST of attribute-value pairs because
%% a vendor-specific attribute blob might contain more than one attribute.
-spec decode_attribute(binary(), #attribute{}, non_neg_integer(), req()) -> req().
decode_attribute(<<VendorId:32/integer, ValueBin/binary>>,
                 #attribute{id = ?RVendor_Specific}, Pos, Req) ->
    decode_vendor_specific_attribute(ValueBin, VendorId, Pos + 4, Req);
decode_attribute(<<Value/binary>>,
                 #attribute{id = ?REAP_Message}, _Pos, #{eap_msg := EAP} = Req) ->
    Req#{eap_msg := <<EAP/binary, Value/binary>>};
decode_attribute(<<EncValue/binary>>,
                 Attr = #attribute{
                           id = ?RMessage_Authenticator, type = Type, enc = Encryption},
                 Pos, Req) ->
    AVP = {Attr, decode_value(decrypt_value(Req, EncValue, Encryption), Type)},
    append_attr(AVP, Req#{msg_hmac := Pos});

decode_attribute(<<EncValue/binary>>,
                 Attr = #attribute{type = Type, enc = Encryption}, _Pos, Req)
  when is_atom(Type) ->
    append_attr({Attr, decode_value(decrypt_value(Req, EncValue, Encryption), Type)}, Req);
decode_attribute(WholeBin = <<Tag:8, Bin/binary>>,
                 Attr = #attribute{type = {tagged, Type}}, _Pos, Req) ->
    case {decode_tag_value(Tag), Attr#attribute.enc} of
        {0, no} ->
            %% decode including tag byte if tag is out of range
            append_attr({Attr, {0, decode_value(WholeBin, Type)}}, Req);
        {TagV, no} ->
            append_attr({Attr, {TagV, decode_value(Bin, Type)}}, Req);
        {TagV, Encryption} ->
            %% for encrypted attributes, tag byte is never part of the value
            AVP = {Attr, {TagV, decode_value(decrypt_value(Req, Bin, Encryption), Type)}},
            append_attr(AVP, Req)
    end.

-compile({inline, decode_tag_value/1}).
decode_tag_value(Tag) when (Tag >= 1) and (Tag =< 16#1F) -> Tag;
decode_tag_value(_OtherTag)                              -> 0.

-spec decode_value(binary(), eradius_dict:attribute_prim_type()) -> term().
decode_value(Bin, octets) ->
    Bin;
decode_value(Bin, binary) ->
    Bin;
decode_value(Bin, abinary) ->
    Bin;
decode_value(Bin, string) ->
    Bin;
decode_value(Bin, integer) ->
    binary:decode_unsigned(Bin);
decode_value(Bin, integer24) ->
    binary:decode_unsigned(Bin);
decode_value(Bin, integer64) ->
    binary:decode_unsigned(Bin);
decode_value(Bin, date) ->
    Int = binary:decode_unsigned(Bin),
    calendar:now_to_universal_time({Int div 1000000, Int rem 1000000, 0});
decode_value(<<B,C,D,E>>, ipaddr) ->
    {B,C,D,E};
decode_value(<<B:16,C:16,D:16,E:16,F:16,G:16,H:16,I:16>>, ipv6addr) ->
    {B,C,D,E,F,G,H,I};
decode_value(<<_0, PLen, P/binary>>, ipv6prefix) ->
    <<B:16,C:16,D:16,E:16,F:16,G:16,H:16,I:16>> = pad_to(16, P),
    {{B,C,D,E,F,G,H,I}, PLen}.

-spec decrypt_value(req(), binary(), eradius_dict:attribute_encryption()) ->
          eradius_dict:attr_value().
decrypt_value(#{secret := Secret, authenticator := Authenticator}, Val, scramble) ->
    scramble(Secret, Authenticator, Val);
decrypt_value(#{secret := Secret, authenticator := Authenticator}, Val, salt_crypt) ->
    salt_decrypt(Secret, Authenticator, Val);
decrypt_value(#{secret := Secret, authenticator := Authenticator}, Val, ascend) ->
    ascend(Secret, Authenticator, Val);
decrypt_value(_Req, Val, _Type) ->
    Val.

-spec decode_vendor_specific_attribute(binary(), non_neg_integer(), pos_integer(), req()) ->
          req().
decode_vendor_specific_attribute(<<>>, _VendorId, _Pos, Req) ->
    Req;
decode_vendor_specific_attribute(<<Type:8, ChunkLength:8, ChunkRest/binary>>,
                                 VendorId, Pos, Req0) ->
    ValueLength = ChunkLength - 2,
    <<Value:ValueLength/binary, PacketRest/binary>> = ChunkRest,
    VendorAttrKey = {VendorId, Type},
    Req = case eradius_dict:lookup(attribute, VendorAttrKey) of
              Attr = #attribute{} ->
                  decode_attribute(Value, Attr, Pos + 2, Req0);
              _ ->
                  append_attr({VendorAttrKey, Value}, Req0)
          end,
    decode_vendor_specific_attribute(PacketRest, VendorId, Pos + ChunkLength, Req).

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

-spec ascend(secret(), authenticator(), binary()) -> binary().
ascend(SharedSecret, RequestAuthenticator, <<PlainText/binary>>) ->
    Digest = crypto:hash(md5, [RequestAuthenticator, SharedSecret]),
    crypto:exor(Digest, pad_to(16, PlainText)).

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

%% @doc calculate the MD5 message authenticator
-if(?OTP_RELEASE >= 23).
%% crypto API changes in OTP >= 23
message_authenticator(Secret, Msg) ->
    crypto:mac(hmac, md5, Secret, Msg).
-else.
message_authenticator(Secret, Msg) ->
    crypto:hmac(md5, Secret, Msg).

-endif.
