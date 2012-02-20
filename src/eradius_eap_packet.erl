%% @doc
%%  This module implements the EAP RFC-3748 message encoder and decoder functions
-module(eradius_eap_packet).

-export([decode/1, encode/3, decode_eap_type/2, encode_eap_type/1, decode_hexstr/1]).

-include("eradius_eap.hrl").

%% ------------------------------------------------------------------------------------------
%% -- decoder functions

int(C) when $0 =< C, C =< $9 ->
    C - $0;
int(C) when $A =< C, C =< $F ->
    C - $A + 10;
int(C) when $a =< C, C =< $f ->
    C - $a + 10.

hexstr_to_list([X,Y|T]) ->
    [int(X)*16 + int(Y) | hexstr_to_list(T)];
hexstr_to_list([]) ->
    [].

decode_hexstr(HexStr) ->
    decode(list_to_binary(hexstr_to_list(HexStr))).

%% @doc decode a EPA message
decode(<<Code:8, Id:8, Len:16, Rest/binary>>) ->
    DataLen = Len - 4,
    case Rest of
	<<Data:DataLen/bytes, _/binary>> -> 
	    do_decode_payload(code(Code), Id, Data);
	_ ->
	    {error, invalid_length}
    end.

%% @doc endecode a EPA message
encode(Code, Id, Msg) ->
    Data = encode_payload(Code, Msg),
    Len = size(Data) + 4,
    <<(code(Code)):8, Id:8, Len:16, Data/binary>>.

do_decode_payload(Code, Id, Data) ->
    try
	decode_payload(Code, Id, Data)
    catch
	_ -> {error, invalid_payload}
    end.

decode_payload(Code, Id, <<Type:8, TypeData/binary>>)
  when Code == request; Code == response ->
    T = decode_eap_type(Type, TypeData),
    {ok, {Code, Id, T}};
decode_payload(Code, Id, Data)
  when Code == success; Code == failure ->
    case Data of
	<<>> -> {ok, {Code, Id}};
	_ ->    {error, invalid_length}
	  end.

%% @doc EAP decoder functions for RFC-3784 types

%%    1       Identity
decode_eap_type(1, Data) ->
    {identity, Data};

%%    2       Notification
decode_eap_type(2, Data) ->
    {notification, Data};

%%    3       Nak (Response only)
decode_eap_type(3, Data) ->
    {nak, binary_to_list(Data)};

%%    4       MD5-Challenge
decode_eap_type(4, <<Size:8, Value:Size/bytes, Name/binary>>) ->
    {md5_challenge, Value, Name};

%%    5       One Time Password (OTP)
decode_eap_type(5, Data) ->
    {otp, Data};

%%    6       Generic Token Card (GTC)
decode_eap_type(6, Data) ->
    {gtc, Data};

%%  254       Expanded Types
decode_eap_type(254, <<Vendor:24, Type:32, Data/binary>>) ->
    decode_eap_type({Vendor, Type}, Data);

%%  255       Experimental use
decode_eap_type(255, Data) ->
    {experimental, Data};

%%   0, 3       Expanded Nak (Response only)
decode_eap_type({0, 3}, Data) ->
    {nak_ext, [{Vendor,Type} || <<_T:8, Vendor:24, Type:32>> <= Data]};

decode_eap_type(Type, Data) ->
	case eradius_eap:lookup_type(Type) of
	    undefined -> {Type, Data};
	    Module    -> Module:decode_eap_type(Type, Data)
	end.

encode_payload(Code, Msg)
  when Code == request; Code == response ->
    encode_eap_type(Msg);
encode_payload(Code, _Msg)
  when Code == success; Code == failure ->
    <<>>.

%% @doc EAP encoder functions for RFC-3784 types

%%    1       Identity
encode_eap_type({identity, Data})
  when is_binary(Data) ->
    <<1:8, Data/binary>>;

%%    2       Notification
encode_eap_type({notification, Data})
  when is_binary(Data) ->
    <<2:8, Data/binary>>;

%%    3       Nak (Response only)
encode_eap_type({nak, Data})
  when is_list(Data) ->
    <<3:8, (list_to_binary(Data))/binary>>;

%%    4       MD5-Challenge
encode_eap_type({md5_challenge, Value, Name}) ->
    Size = size(Value),
    <<4:8, Size:8, Value/binary, Name/binary>>;

%%    5       One Time Password (OTP)
encode_eap_type({otp, Data})
  when is_binary(Data) ->
    <<5:8, Data/binary>>;

%%    6       Generic Token Card (GTC)
encode_eap_type({gtc, Data})
  when is_binary(Data) ->
    <<6:8, Data>>;

%%  254       Expanded Types
encode_eap_type({{Vendor, Type}, Data})
  when is_integer(Vendor), is_integer(Type), is_binary(Data) ->
    <<254:8, Vendor:24, Type:32, Data/binary>>;

%%  255       Experimental use
encode_eap_type({experimental, Data})
  when is_binary(Data) ->
    <<255:8, Data/binary>>;

%%   0, 3       Expanded Nak (Response only)
encode_eap_type({nak_ext, Data})
  when is_list(Data) ->
    encode_eap_type({{0, 3}, << <<254:8, Vendor:24, Type:32>> || {Vendor, Type} <- Data >>});

encode_eap_type(Msg)
  when is_binary(Msg) ->
    Msg;

encode_eap_type(Msg)
  when is_tuple(Msg) ->
    case eradius_eap:lookup_type(element(1, Msg)) of
	undefined -> <<>>;
	Module    -> Module:encode_eap_type(Msg)
    end.

code(1) -> request;
code(2) -> response;
code(3) -> success;
code(4) -> failure;

code(request) ->  1;
code(response) -> 2;
code(success) ->  3;
code(failure) ->  4;

code(_) -> error.

