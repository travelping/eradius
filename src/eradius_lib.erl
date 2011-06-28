-module(eradius_lib).
%%%-------------------------------------------------------------------
%%% File        : eradius_lib.erl
%%% Author      : Martin Bjorklund <mbj@bluetail.com>
%%% Description : Radius encode/decode routines (RFC-2865).
%%% Created     :  7 Oct 2002 by Martin Bjorklund <mbj@bluetail.com>
%%%
%%% $Id: eradius_lib.erl,v 1.5 2004/03/26 17:47:19 seanhinde Exp $
%%%-------------------------------------------------------------------
-export([enc_pdu/1, enc_reply_pdu/1, dec_packet/2, enc_accreq/3]).
-export([mk_authenticator/0, pad_to/2]).

-export([set_attr/3]).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.
-include("eradius_lib.hrl").
-include("eradius_dict.hrl").

-define(DBG(F,A), io:format("(~w:~b): " ++ F ++ "~n", [?MODULE, ?LINE] ++ A)).

%%====================================================================
%% Create Attributes
%%====================================================================

%%% Generate an unpredictable 16 byte token.
mk_authenticator() ->
    crypto:rand_bytes(16).

scramble(SharedSecret, RequestAuthenticator, PlainText) ->
    B = crypto:md5([SharedSecret, RequestAuthenticator]),
    do_scramble(SharedSecret, B, pad_to(16, PlainText), << >>).

do_scramble(SharedSecret, B, <<PlainText:16/binary, Remaining/binary>>, CipherText) ->
    NewCipherText = crypto:exor(PlainText, B),
    Bnext = crypto:md5([SharedSecret, NewCipherText]),
    do_scramble(SharedSecret, Bnext, Remaining, <<CipherText/binary, NewCipherText/binary>>);

do_scramble(_SharedSecret, _B, << >>, CipherText) ->
    CipherText.

%%
%% pad binary to specific length
%%   -> http://www.erlang.org/pipermail/erlang-questions/2008-December/040709.html
%%
pad_to(Width, Binary) ->
     case (Width - size(Binary) rem Width) rem Width of
	 0 -> Binary;
	 N -> <<Binary/binary, 0:(N*8)>>
     end.

generate_salt() ->
    Salt1 = crypto:rand_uniform(128, 256),
    Salt2 = crypto:rand_uniform(0, 256),
    << Salt1, Salt2 >>.

%%
%% salt encrypt
%%
salt_encrypt(Salt, SharedSecret, RequestAuthenticator, PlainText) ->
    CipherText = do_salt_crypt(Salt, SharedSecret, RequestAuthenticator, (pad_to(16, << (size(PlainText)):8, PlainText/binary >>))),
    << Salt/binary, CipherText/binary >>.

salt_decrypt(SharedSecret, RequestAuthenticator, <<Salt:2/binary, CipherText/binary>>) ->
    << Length:8/integer, PlainText/binary >> = do_salt_crypt(Salt, SharedSecret, RequestAuthenticator, CipherText),
    if
	Length < size(PlainText) -> 
	    binary:part(PlainText, 0, Length);
	true ->
	    PlainText
    end.

do_salt_crypt(Salt, SharedSecret, RequestAuthenticator, CipherText) ->
    B = crypto:md5([SharedSecret, RequestAuthenticator, Salt]),
    salt_crypt(SharedSecret, B, CipherText, << >>).

salt_crypt(SharedSecret, B, <<PlainText:16/binary, Remaining/binary>>, CipherText) ->
    NewCipherText = crypto:exor(PlainText, B),
    Bnext = crypto:md5([SharedSecret, NewCipherText]),
    salt_crypt(SharedSecret, Bnext, Remaining, <<CipherText/binary, NewCipherText/binary>>);

salt_crypt(_SharedSecret, _B, << >>, CipherText) ->
    CipherText.

%%====================================================================
%% Encode/Decode Functions
%%====================================================================

%% Ret: io_list(). Specific format of io_list is relied on by 
%% enc_reply_pdu/2
enc_pdu(Pdu) ->
    {Cmd, CmdPdu} = enc_cmd(Pdu, Pdu#rad_pdu.req),
    [<<Cmd:8, (Pdu#rad_pdu.reqid):8, (io_list_len(CmdPdu) + 20):16>>, 
     <<(Pdu#rad_pdu.authenticator):16/binary>>,
     CmdPdu].

%% This one includes the authenticator substitution required for 
%% sending replies from the server.
enc_reply_pdu(Pdu) ->
    [Head, Auth, Cmd] = enc_pdu(Pdu),
    Reply_auth = crypto:md5([Head, Auth, Cmd, Pdu#rad_pdu.secret]),
    [Head, Reply_auth, Cmd].

enc_apply_enc(Pdu, Val, scramble) ->
    scramble(Pdu#rad_pdu.secret, Pdu#rad_pdu.authenticator, Val);

enc_apply_enc(Pdu, Val, salt_crypt) ->
    salt_encrypt(generate_salt(), Pdu#rad_pdu.secret, Pdu#rad_pdu.authenticator, Val);

enc_apply_enc(_Pdu, Val, _) ->
    Val.

enc_attrib(Pdu, {Vendor, Id}, V, Type, Enc) ->
    Val = enc_attrib(Pdu, Id, V, Type, Enc),
    <<?RVendor_Specific:8, (size(Val) + 6):8, Vendor:32, Val/binary >>;

enc_attrib(_Pdu, Id, V, {tagged, Type}, no) ->
    case V of
	{Tag, Val} when Tag >= 1, Tag =< 16#1F ->
	    E = type_conv(Val, Type),
	    <<Id, (size(Val) + 3):8, Tag:8, E/binary>>;
	Val ->
	    E = type_conv(Val, Type),
	    <<Id, (size(Val) + 2):8, E/binary>>
    end;

enc_attrib(Pdu, Id, V, {tagged, Type}, Enc) ->
    case V of
	{Tag, Val} when Tag >= 1, Tag =< 16#1F ->
	    E = enc_apply_enc(Pdu, type_conv(Val, Type), Enc),
	    <<Id, (size(Val) + 3):8, Tag:8, E/binary>>;
	Val ->
	    E = enc_apply_enc(Pdu, type_conv(Val, Type), Enc),
	    <<Id, (size(Val) + 3):8, 0:8, E/binary>>
    end;

enc_attrib(Pdu, Id, V, Type, Enc) ->
    Val = enc_apply_enc(Pdu, type_conv(V, Type), Enc),
    <<Id, (size(Val) + 2):8, Val/binary>>.

type_conv(V, _) when is_binary(V) -> V;
type_conv(V, binary)         -> V;
type_conv(V, integer)        -> <<V:32>>;
type_conv(V, integer64)      -> <<V:64>>;
type_conv({A,B,C,D}, ipaddr) -> <<A:8, B:8, C:8, D:8>>;
type_conv({A,B,C,D,E,F,G,H}, ipv6addr) -> <<A:16, B:16, C:16, D:16,
					    E:16, F:16, G:16, H:16>>;
type_conv({{A,B,C,D,E,F,G,H}, PLen}, ipv6prefix) ->
    L = (PLen + 7) div 8,
    <<IP:L, _R/binary>> = <<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>>,
    <<0, PLen, IP>>;
type_conv(V, string) when
      is_list(V) -> iolist_to_binary(V);
type_conv(V, string) when
      is_binary(V) -> V;
type_conv(V, octets) when
      is_list(V) -> iolist_to_binary(V);
type_conv(V, octets) when
      is_binary(V) -> V;
type_conv(V, octets) when
      is_integer(V) -> << V:32 >>;
type_conv({{_,_,_},{_,_,_}} = Date, date) ->
    EpochSecs = calendar:datetime_to_gregorian_seconds(Date)
	- calendar:datetime_to_gregorian_seconds({{1970,1,1},{0,0,0}}),
    <<EpochSecs:32>>;
type_conv(V, date) when
      is_list(V) -> iolist_to_binary(V);
type_conv(V, date) when
      is_binary(V) -> V.

%%
%% encode attributes
%% TODO: filter attributes!
%%
enc_cmd(Pdu, Req) when Req#radius_request.cmd =:= request ->
    {?RAccess_Request, [enc_attributes(Pdu, Req#radius_request.attrs)]};

enc_cmd(Pdu, Req) when Req#radius_request.cmd =:= accept      ->
    {?RAccess_Accept, [enc_attributes(Pdu, Req#radius_request.attrs)]};

enc_cmd(Pdu, Req) when Req#radius_request.cmd =:= challenge ->
    {?RAccess_Challenge, [enc_attributes(Pdu, Req#radius_request.attrs)]};

enc_cmd(Pdu, Req) when Req#radius_request.cmd =:= reject ->
    {?RAccess_Reject, [enc_attributes(Pdu, Req#radius_request.attrs)]};

enc_cmd(Pdu, Req) when Req#radius_request.cmd =:= accreq ->
    {?RAccounting_Request, [enc_attributes(Pdu, Req#radius_request.attrs)]};

enc_cmd(_Pdu, Req) when Req#radius_request.cmd =:= accresp ->
    {?RAccounting_Response, []}.

enc_attributes(Pdu, As) ->
    F = fun({#attribute{id = Id} = A, Val}, Acc) ->
		[enc_attrib(Pdu, Id, Val, A#attribute.type, A#attribute.enc) | Acc];
           ({Id, Val}, Acc) ->
		case eradius_dict:lookup(Id) of
		    [A] when is_record(A, attribute) ->
			[enc_attrib(Pdu, Id, Val, A#attribute.type, A#attribute.enc) | Acc];
		    _ ->
			Acc
		end
	end,
    lists:foldl(F, [], As).

io_list_len(L) -> io_list_len(L, 0).
io_list_len([H|T], N) ->
    if
	H >= 0, H =< 255 -> io_list_len(T, N+1);
	is_list(H) -> io_list_len(T, io_list_len(H,N));
	is_binary(H) -> io_list_len(T, size(H) + N)
    end;
io_list_len(H, N) when is_binary(H) ->
    size(H) + N;
io_list_len([], N) ->
    N.

%% Ret: #rad_pdu | Reason
dec_packet(Packet, Secret) ->
    case (catch dec_packet0(Packet, Secret)) of
        {'EXIT', R} ->
            error_logger:warning_msg("decoding of a RADIUS packet failed~nError: ~p~n", [R]),  
            bad_pdu;
        Else ->
            Else
    end.

dec_packet0(Packet, Secret) ->
    <<Cmd:8, ReqId:8, Len:16, Auth:16/binary, Attribs0/binary>> = Packet,
    Size = size(Attribs0),
    Attr_len = Len - 20,
    Attribs = 
	if 
	    Attr_len > Size -> 
		throw(bad_pdu);
	    Attr_len == Size -> 
		Attribs0;
	    true ->
		<<Attribs1:Attr_len/binary, _/binary>> = Attribs0,
		Attribs1
	end,
    P = #rad_pdu{reqid = ReqId, authenticator = Auth, secret = Secret},
    case Cmd of
	?RAccess_Request ->
	    P#rad_pdu{req = #radius_request{cmd = request, attrs = dec_attributes(P, Attribs)}};
	?RAccess_Accept ->
	    P#rad_pdu{req = #radius_request{cmd = accept, attrs = dec_attributes(P, Attribs)}};
	?RAccess_Challenge ->
	    P#rad_pdu{req = #radius_request{cmd = challenge, attrs = dec_attributes(P, Attribs)}};
	?RAccess_Reject ->
	    P#rad_pdu{req = #radius_request{cmd = reject, attrs = dec_attributes(P, Attribs)}};
	?RAccounting_Request ->
	    P#rad_pdu{req = #radius_request{cmd = accreq, attrs = dec_attributes(P, Attribs)}};
	?RAccounting_Response ->
	    P#rad_pdu{req = #radius_request{cmd = accresp, attrs = dec_attributes(P, Attribs)}}
    end.

-define(dec_attrib(A0, Type, Val, A1),
	<<Type:8, __Len0:8, __R/binary>> = A0,
	__Len1 = __Len0 - 2,
	<<Val:__Len1/binary, A1/binary>> = __R).

dec_apply_enc(Pdu, Val, scramble) ->
    scramble(Pdu#rad_pdu.secret, Pdu#rad_pdu.authenticator, Val);

dec_apply_enc(Pdu, Val, salt_crypt) ->
    salt_decrypt(Pdu#rad_pdu.secret, Pdu#rad_pdu.authenticator, Val);

dec_apply_enc(_Pdu, Val, _) ->
    Val.

dec_attributes(Pdu, As) -> 
    lists:flatten(dec_attributes(Pdu, As, [])).

dec_attributes(_Pdu, <<>>, Acc) -> Acc;
dec_attributes(Pdu, A0, Acc) ->
    ?dec_attrib(A0, Type, Val, A1),
    case eradius_dict:lookup(Type) of
        [A = #attribute{}] ->
            dec_attributes(Pdu, A1, [dec_attr(Pdu, A, Val) | Acc]);
        _ ->
            dec_attributes(Pdu, A1, [{Type, Val} | Acc])
    end.

dec_attr(Pdu, #attribute{id = Id} = _A, <<VendId:32/integer, VendVal/binary>>)
  when Id =:= ?RVendor_Specific ->
    %% TODO: add Vendor Type lookup
    dec_vendor_v1_attr_val(Pdu, VendId, VendVal);

dec_attr(_Pdu, #attribute{type = {tagged, Type}, enc = Enc} = A, <<T:8, R/binary>> = Bin)
  when Enc =:= no->
    Val = if 
	      T >= 1, T =< 16#1F -> {T, dec_attr_val(Type, R)};
	      true -> {0, dec_attr_val(Type, Bin)}
	  end,
    {A, Val};

dec_attr(Pdu, #attribute{type = {tagged, Type}, enc = Enc} = A, <<T:8, R/binary>> = _Bin) ->
    Tag = if 
	T >= 1, T =< 16#1F -> T;
	      true -> 0
	  end,
    {A, {Tag, dec_attr_val(Type, dec_apply_enc(Pdu, R, Enc))}};

dec_attr(Pdu, #attribute{type = Type, enc = Enc} = A, Bin) ->
    {A, dec_attr_val(Type, dec_apply_enc(Pdu, Bin, Enc))}.

dec_attr_val(string, Bin) ->
    binary_to_list(Bin);

dec_attr_val(octets, Bin) ->
    Bin;

dec_attr_val(integer, I0) ->
    L = size(I0)*8,
    case I0 of
        <<I:L/integer>> ->
	    I;
        _ ->
            I0
    end;

dec_attr_val(integer64, I0) ->
    L = size(I0)*8,
    case I0 of
        <<I:L/integer>> ->
            I;
        _ ->
            I0
    end;

dec_attr_val(date, I0) ->
    L = size(I0)*8,
    case I0 of
        <<I:L/integer>> ->
            calendar:now_to_universal_time({I div 1000000, I rem 1000000, 0});
        _ ->
            I0
    end;

dec_attr_val(ipaddr, <<B,C,D,E>>) ->
    {B,C,D,E};

dec_attr_val(ipv6addr, <<B:16,C:16,D:16,E:16,F:16,G:16,H:16,I:16>>) ->
    {B,C,D,E,F,G,H,I};

dec_attr_val(ipv6prefix, <<0,PLen,P/binary>>) ->
    <<B:16,C:16,D:16,E:16,F:16,G:16,H:16,I:16>> = pad_to(128, P),
    {{B,C,D,E,F,G,H,I}, PLen};

dec_attr_val(Type, Val) -> 
    io:format("Uups...Type=~p~n",[Type]),
    Val.

dec_vendor_v1_attr_val(_Pdu, _VendId, <<>>) -> [];
dec_vendor_v1_attr_val(Pdu, VendId, <<Vtype:8, Vlen:8, Vbin/binary>>) ->
    Len = Vlen - 2,
    <<Vval:Len/binary,Vrest/binary>> = Vbin,
    Vkey = {VendId, Vtype},
    case eradius_dict:lookup(Vkey) of
	[A] when is_record(A, attribute) ->
	    [dec_attr(Pdu, A, Vval) | dec_vendor_v1_attr_val(Pdu, VendId, Vrest)];
	_ ->
	    [{Vkey, Vval} | dec_vendor_v1_attr_val(Pdu, VendId, Vrest)]
    end.
    

%%% ====================================================================
%%% Radius Accounting specifics
%%% ====================================================================

enc_accreq(Id, Secret, Req) ->
    Rpdu = #rad_pdu{reqid = Id,
		    authenticator = zero16(),
		    secret = Secret,
		    req = Req},
    PDU = enc_pdu(Rpdu),
    patch_authenticator(PDU, l2b(Secret)).

patch_authenticator(Req,Secret) ->
    case {crypto:md5([Req,Secret]),list_to_binary(Req)} of
	{Auth,<<Head:4/binary, _:16/binary, Rest/binary>>} ->
	    B = l2b(Auth),
	    <<Head/binary, B/binary, Rest/binary>>;
	_Urk ->
	    exit(patch_authenticator)
    end.

%%% An empty Acc-Req Authenticator
zero16() ->
    zero_bytes(16).

zero_bytes(N) ->
    <<0:N/?BYTE>>.

l2b(L) when is_list(L)   -> list_to_binary(L);
l2b(B) when is_binary(B) -> B.

%%% Radius Attribute handling

%%% Set (any) Attribute
set_attr(R, Id, Val) when is_record(R, radius_request) ->
    R#radius_request{attrs = [{Id, Val} | R#radius_request.attrs]}.

-ifdef(TEST).

%%
%% EUnit Tests
%%
-define(SALT, <<171,213>>).
-define(REQUEST_AUTHENTICATOR, << 1, 2, 3, 4, 5, 6, 7, 8 >>).
-define(USER, "test").
-define(SECRET, <<"secret">>).
-define(PLAIN_TEXT, "secret").
-define(PLAIN_TEXT_PADDED, <<"secret",0,0,0,0,0,0,0,0,0,0>>).
-define(CIPHER_TEXT, <<171,213,166,95,152,126,124,120,86,10,78,216,190,216,26,87,55,15>>).
-define(ENC_PASSWORD, 186,128,194,207,68,25,190,19,23,226,48,206,244,143,56,238).
-define(PDU, #rad_pdu{ reqid = 1, secret = ?SECRET, authenticator = ?REQUEST_AUTHENTICATOR }).

selt_encrypt_test() ->
    ?CIPHER_TEXT = salt_encrypt(?SALT, ?SECRET, ?REQUEST_AUTHENTICATOR, << ?PLAIN_TEXT >>).

salt_decrypt_test() ->
    << ?PLAIN_TEXT >> = salt_decrypt(?SECRET, ?REQUEST_AUTHENTICATOR, ?CIPHER_TEXT).

scramble_enc_test() ->
    << ?ENC_PASSWORD >> = scramble(?SECRET, ?REQUEST_AUTHENTICATOR, << ?PLAIN_TEXT >>).

scramble_dec_test() ->
    ?PLAIN_TEXT_PADDED = scramble(?SECRET, ?REQUEST_AUTHENTICATOR, << ?ENC_PASSWORD >>).

enc_simple_test() ->
    L = length(?USER) + 2,
    << ?RUser_Name, L:8, ?USER >> = enc_attrib(?PDU, ?RUser_Name, << ?USER >>, string, []).

enc_scramble_test() ->
    L = 16 + 2,
    << ?RUser_Passwd, L:8, ?ENC_PASSWORD >> = enc_attrib(?PDU, ?RUser_Passwd, << ?PLAIN_TEXT >>, string, scramble).

enc_salt_test() ->
    L = 16 + 4,
    << ?RUser_Passwd, L:8, Enc/binary >> = enc_attrib(?PDU, ?RUser_Passwd, << ?PLAIN_TEXT >>, string, salt_crypt),
    %% need to decrypt to verfiy due to salt
    << ?PLAIN_TEXT >> = salt_decrypt(?SECRET, ?REQUEST_AUTHENTICATOR, Enc).

enc_vendor_test() ->
    L = length(?USER),
    E = << ?RVendor_Specific, (L+8):8, 18681:32, 1:8, (L+2):8, ?USER >>,
    E = enc_attrib(?PDU, {18681,1}, << ?USER >>, string, no).

enc_vendor_octet_test() ->
    E = << ?RVendor_Specific, (4+8):8, 311:32, 7:8, (4+2):8, 7:32 >>,
    E = enc_attrib(?PDU, {311,7}, 7, octets, no).

dec_simple_integer_test() ->
    {{attribute,40,integer,undefined,no}, 1} = dec_attr(?PDU, #attribute{id = 40, type = integer, enc = no}, <<0,0,0,1>>).

dec_simple_string_test() ->
    {{attribute,44,string,undefined,no}, "29113"} = dec_attr(?PDU, #attribute{id = 44, type = string, enc = no}, <<"29113">>).

dec_simple_ipv4_test() ->
    {{attribute,4,ipaddr,undefined,no},{10,33,0,1}} = dec_attr(?PDU, #attribute{id = 4, type = ipaddr, enc = no}, <<10,33,0,1>>).
    
dec_vendor_integer_test() ->
    [{{attribute,{10415,3},integer,"X_3GPP-PDP-Type",no},0}] = dec_attr(?PDU, #attribute{id = ?RVendor_Specific, type = octets, enc = no}, <<0,0,40,175,3,6,0,0,0,0>>).

dec_vendor_string_test() ->
    [{{attribute,{10415,8},string,"X_3GPP-IMSI-MCC-MNC",no},"23415"}] = dec_attr(?PDU, #attribute{id = ?RVendor_Specific, type = octets, enc = no}, <<0,0,40,175,8,7,"23415">>).

dec_vendor_ipv4_test() ->
    [{{attribute,{10415,6},ipaddr,"X_3GPP-SGSN-Address",no},{212,183,144,246}}] = dec_attr(?PDU, #attribute{id = ?RVendor_Specific, type = octets, enc = no}, <<0,0,40,175,6,6,212,183,144,246>>).

%% TODO: add more tests

-endif.
