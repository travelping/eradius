%% @doc user authentication helper functions
-module(eradius_auth).
-export([check_password/2]).
-export([pap/2, chap/3, ms_chap/3, ms_chap_v2/4]).
-export([des_key_from_hash/1, nt_password_hash/1, challenge_response/2,
         ascii_to_unicode/1]).

-ifdef(TEST).
-export([nt_hash/1, v2_generate_nt_response/4, mppe_get_master_key/2,
         mppe_generate_session_keys/3, mppe_get_asymetric_send_start_key/2,
         v2_generate_authenticator_response/5]).
-endif.

-include("eradius_lib.hrl").
-include("eradius_dict.hrl").
-include("dictionary.hrl").
-include("dictionary_microsoft.hrl").

%% ------------------------------------------------------------------------------------------
%% -- high level interface

%% @doc check the request password using all available authentication mechanisms.
%%    Tries CHAP, then MS-CHAP, then MS-CHAPv2, finally PAP.
-spec check_password(binary(), #radius_request{}) -> 
    false | {boolean(), eradius_lib:attribute_list()}.
check_password(Password, Req = #radius_request{authenticator = Authenticator, attrs = AVPs}) ->
    case lookup_auth_attrs(AVPs) of
        {false, Chap_pass, false, false, false, false} ->
            {chap(Password, Chap_pass, Authenticator), []};
        {false, Chap_pass, Challenge, false, false, false} ->
            {chap(Password, Chap_pass, Challenge), []};
        {false, _, _, Challenge, Response, false} when Challenge =/= false, Response =/= false ->
            ms_chap(Password, Challenge, Response);
        {false, _, _, Challenge, false, Response} when Challenge =/= false, Response =/= false ->
            Username = eradius_lib:get_attr(Req, ?User_Name),
            ms_chap_v2(Username, Password, Challenge, Response);
        {ReqPassword, _, _, _, _, _} when ReqPassword =/= false ->
            {pap(Password, ReqPassword), []};
        {_, _, _, _, _, _} ->
            {false, []}
    end.

%% composite lookup function, retrieve User_Password, CHAP_Password and CHAP_Challenge at once
lookup_auth_attrs(AVPs) ->
    lookup_auth_attrs({false, false, false, false, false, false}, AVPs).

lookup_auth_attrs(Attrs, [{#attribute{id = ?User_Password}, Val}|T]) ->
    lookup_auth_attrs(setelement(1, Attrs, Val), T);
lookup_auth_attrs(Attrs, [{#attribute{id = ?CHAP_Password}, Val}|T]) ->
    lookup_auth_attrs(setelement(2, Attrs, Val), T);
lookup_auth_attrs(Attrs, [{#attribute{id = ?CHAP_Challenge}, Val}|T]) ->
    lookup_auth_attrs(setelement(3, Attrs, Val), T);
lookup_auth_attrs(Attrs, [{#attribute{id = ?MS_CHAP_Challenge}, Val}|T]) ->
    lookup_auth_attrs(setelement(4, Attrs, Val), T);
lookup_auth_attrs(Attrs, [{#attribute{id = ?MS_CHAP_Response}, Val}|T]) ->
    lookup_auth_attrs(setelement(5, Attrs, Val), T);
lookup_auth_attrs(Attrs, [{#attribute{id = ?MS_CHAP2_Response}, Val}|T]) ->
    lookup_auth_attrs(setelement(6, Attrs, Val), T);

lookup_auth_attrs(Attrs, [{{_,_} = Id, Val}|T]) ->
    %% fallback for undecoded AVPs
    lookup_auth_attrs(Attrs, [{#attribute{id = Id}, Val}|T]);
lookup_auth_attrs(Attrs, [_|T]) ->
    lookup_auth_attrs(Attrs, T);
lookup_auth_attrs(Attrs, []) ->
    Attrs.

%% ------------------------------------------------------------------------------------------
%% -- PAP/CHAP
%% @doc PAP authentication
-spec pap(binary(), binary()) -> boolean().
pap(<<C, PasswdRest/binary>>, <<C, ReqRest/binary>>) ->
    pap(PasswdRest, ReqRest);
pap(<<_C, _/binary>>, <<_OtherChar, _/binary>>) ->
    false;
pap(<<_C, _/binary>>, <<>>) ->
    false;
pap(<<>>, <<ReqRest/binary>>) ->
    only_null(ReqRest).

-compile({inline, only_null/1}).
only_null(<<0, R/binary>>) ->
    only_null(R);
only_null(<<_, _/binary>>) ->
    false;
only_null(<<>>) ->
    true.

%% @doc CHAP authentication
-spec chap(binary(), binary(), binary()) -> boolean().
chap(Passwd, <<ChapId, ChapPassword/binary>>, ChapChallenge) ->
    EncPassword = crypto:hash(md5, [ChapId, Passwd, ChapChallenge]),
    EncPassword == ChapPassword.

%% @doc build a des key from a hash
set_des_parity_odd(P0) ->
    P1 = P0 bxor (P0 bsr 4),
    P2 = P1 bxor (P1 bsr 2),
    P3 = P2 bxor (P2 bsr 1),

    (P0 bsl 1) bor ((bnot P3) band 1).

des_key_from_hash(Hash) ->
    << << (set_des_parity_odd(X)) >> || <<X:7>> <= Hash >>.

%% @doc turn a plain text password (either binary or list representation)
%% into UTF-16 binary representation.
ascii_to_unicode(Bin) when is_binary(Bin) ->
    << <<X, 0>> || <<X>> <= Bin >>;
ascii_to_unicode(Lst) when is_list(Lst) ->
    list_to_binary([[X, 0] || X <- Lst]).

%% @doc calculte MD4 hash for value
nt_hash(Value) ->
    crypto:hash(md4, Value).

%% @doc calculate the MD4 hash of a plain text password the NT way
nt_password_hash(Passwd) ->
    crypto:hash(md4, ascii_to_unicode(Passwd)).

%% ------------------------------------------------------------------------------------------
%% -- MS-CHAP
%% @doc generate MS-CHAP NT-Response
v2_generate_nt_response(AuthenticatorChallenge, PeerChallenge, UserName, PasswdHash) ->
    ChallengeHash = v2_challenge_hash(PeerChallenge, AuthenticatorChallenge, UserName),
    challenge_response(ChallengeHash, PasswdHash).

%% @doc calculate MS-CHAP challenge hash
v2_challenge_hash(PeerChallenge, AuthenticatorChallenge, UserName) ->
    binary:part(crypto:hash(sha, [PeerChallenge, AuthenticatorChallenge, UserName]), 0, 8).

%% crypto API changes in OTP >= 23
-if(?OTP_RELEASE >= 23).
%% @doc calculate MS-CHAP challenge response
challenge_response(Challenge, PasswdHash) ->
    Hash = eradius_lib:pad_to(21, PasswdHash),
    <<Key1:8/binary, Key2:8/binary, Key3:8/binary>> = des_key_from_hash(Hash),

    Resp1 = crypto:crypto_one_time(des_ecb, Key1, Challenge, true),
    Resp2 = crypto:crypto_one_time(des_ecb, Key2, Challenge, true),
    Resp3 = crypto:crypto_one_time(des_ecb, Key3, Challenge, true),

    <<Resp1/binary, Resp2/binary, Resp3/binary>>.
-else.
%% @doc calculate MS-CHAP challenge response
challenge_response(Challenge, PasswdHash) ->
    Hash = eradius_lib:pad_to(21, PasswdHash),
    <<Key1:8/binary, Key2:8/binary, Key3:8/binary>> = des_key_from_hash(Hash),

    Resp1 = crypto:block_encrypt(des_ecb, Key1, Challenge),
    Resp2 = crypto:block_encrypt(des_ecb, Key2, Challenge),
    Resp3 = crypto:block_encrypt(des_ecb, Key3, Challenge),

    <<Resp1/binary, Resp2/binary, Resp3/binary>>.
-endif.

v2_generate_authenticator_response(PasswdHash, NTResponse, PeerChallenge, AuthenticatorChallenge, UserName) ->
    PasswdHashHash = nt_hash(PasswdHash),

    Digest = crypto:hash(sha, [PasswdHashHash, NTResponse, v2_magic1()]),
    ChallengeHash = v2_challenge_hash(PeerChallenge, AuthenticatorChallenge, UserName),
    FinalDigest = crypto:hash(sha, [Digest, ChallengeHash, v2_magic2()]),

    %% trailing space needed for some implementations...
    <<"S=", (eradius_lib:bin_to_hexstr(FinalDigest))/binary, " ">>.

%% crypto API changes in OTP >= 23
-if(?OTP_RELEASE >= 23).
des_hash(<< Key:7/binary >>) ->
    crypto:crypto_one_time(des_ecb, des_key_from_hash(Key), <<"KGS!@#$%">>, true).
-else.
des_hash(<< Key:7/binary >>) ->
    crypto:block_encrypt(des_ecb, des_key_from_hash(Key), <<"KGS!@#$%">>).
-endif.

lm_password(Password) ->
    binary:part(eradius_lib:pad_to(14, list_to_binary(string:to_upper(binary_to_list(Password)))), 0, 14).

lm_password_hash(Password) ->
    << Key1:7/binary, Key2:7/binary >> = lm_password(Password),
    << (des_hash(Key1))/binary, (des_hash(Key2))/binary >>.

%% @doc MS-CHAP authentication
-spec ms_chap(binary(), binary(), binary()) -> false | {true, eradius_lib:attribute_list()}.
ms_chap(Passwd, Challenge, <<_Ident:1/binary, Flags:1/integer-unit:8, LMResponse:24/binary, NTResponse:24/binary>>) ->
    LmPasswdHash = lm_password_hash(Passwd),
    NtPasswdHash = nt_password_hash(Passwd),

    Resp1 = if
                Flags == 1; NTResponse =/= << 0:24/unit:8 >> ->
                    NTResponse =:= challenge_response(Challenge, NtPasswdHash);
                true ->
                    false
             end,
    Resp2 = if
                Resp1 == false ->
                    LMResponse =:= challenge_response(Challenge, LmPasswdHash);
                Resp1 ->
                    Resp1
            end,

    Resp2 andalso {true, ms_chap_attrs(LmPasswdHash, NtPasswdHash)}.

%% @doc MS-CHAP-V2 authentication
-spec ms_chap_v2(binary(), binary(), binary(), binary()) -> false | {true, eradius_lib:attribute_list()}.
ms_chap_v2(UserName, Passwd, AuthenticatorChallenge, <<Ident:1/binary, _Flags:1/binary, PeerChallenge:16/binary, _Reserved:8/binary, Response/binary>>) ->
    PasswdHash = nt_password_hash(Passwd),
    ExpectedResponse = v2_generate_nt_response(AuthenticatorChallenge, PeerChallenge, UserName, PasswdHash),

    if
        ExpectedResponse == Response ->
            {true, ms_chap_v2_attrs(UserName, PasswdHash, AuthenticatorChallenge, Ident, PeerChallenge, Response)};
        true ->
            false
    end.

%% @doc calculate MS-CHAP response attributes
ms_chap_attrs(LmPasswdHash, NtPasswdHash) ->
    Key1 = binary:part(LmPasswdHash, 0, 8),
    Key2 = binary:part(nt_hash(NtPasswdHash), 0, 16),
    [{?MS_CHAP_MPPE_Keys, <<Key1/binary, Key2/binary>>}].

%% @doc calculate MS-CHAPv2 response attributes
ms_chap_v2_attrs(UserName, PasswdHash, AuthenticatorChallenge, Ident, PeerChallenge, Response) ->
    SFlag = 1, LFlag = 0, EncPolicy = 2, %% TODO: determine from config or something...
    {SendKey, ReceiveKey} = mppe_generate_session_keys(PasswdHash, Response, 128),
    AuthResponse = v2_generate_authenticator_response(PasswdHash, Response, PeerChallenge, AuthenticatorChallenge, UserName),
    [{?MS_MPPE_Send_Key, SendKey},
     {?MS_MPPE_Recv_Key, ReceiveKey},
     {?MS_MPPE_Encryption_Policy, EncPolicy},
     {?MS_MPPE_Encryption_Types, <<0:29, SFlag:1, LFlag:1, 0:1>>},
     {?MS_CHAP2_Success, <<Ident/binary , AuthResponse/binary>>}].

%% ------------------------------------------------------------------------------------------
%% -- MS-CHAP-V2 MPPE key functions
%% @doc calculate MPPE master key
mppe_get_master_key(PasswordHashHash, NTResponse) ->
    binary:part(crypto:hash(sha, [PasswordHashHash, NTResponse, mppe_magic1()]), 0, 16).

%% @doc calculate next MPPE key from current
mppe_get_new_key_from_sha(StartKey, SessionKey, SessionKeyLength) ->
    Key = crypto:hash(sha, [StartKey, mppe_sha_pad1(), SessionKey, mppe_sha_pad2()]),
    binary:part(Key, 0, SessionKeyLength).

%% @doc calculate first MPPE send key
mppe_get_asymetric_send_start_key(MasterKey, SessionKeyLength) ->
    mppe_get_new_key_from_sha(MasterKey, mppe_magic3(), SessionKeyLength).

%% @doc calculate first MPPE recieve key
mppe_get_asymetric_recv_start_key(MasterKey, SessionKeyLength) ->
    mppe_get_new_key_from_sha(MasterKey, mppe_magic2(), SessionKeyLength).

mppe_generate_session_keys(PasswdHash, NTResponse, SessionKeyStrength) ->
    PasswdHashHash = nt_hash(PasswdHash),
    MasterKey = mppe_get_master_key(PasswdHashHash, NTResponse),

    SessionKeyLength = case SessionKeyStrength of
                           128 -> 16;
                           40 ->  8;
                           56 ->  8
                       end,
    MasterSendKey = mppe_get_asymetric_send_start_key(MasterKey, SessionKeyLength),
    MasterReceiveKey = mppe_get_asymetric_recv_start_key(MasterKey, SessionKeyLength),

    {MasterSendKey, MasterReceiveKey}.

%% ------------------------------------------------------------------------------------------
%% -- MV-CHAP-V2 magic constants
v2_magic1() ->
    <<16#4D, 16#61, 16#67, 16#69, 16#63, 16#20, 16#73, 16#65, 16#72, 16#76,
      16#65, 16#72, 16#20, 16#74, 16#6F, 16#20, 16#63, 16#6C, 16#69, 16#65,
      16#6E, 16#74, 16#20, 16#73, 16#69, 16#67, 16#6E, 16#69, 16#6E, 16#67,
      16#20, 16#63, 16#6F, 16#6E, 16#73, 16#74, 16#61, 16#6E, 16#74>>.

v2_magic2() ->
    <<16#50, 16#61, 16#64, 16#20, 16#74, 16#6F, 16#20, 16#6D, 16#61, 16#6B,
      16#65, 16#20, 16#69, 16#74, 16#20, 16#64, 16#6F, 16#20, 16#6D, 16#6F,
      16#72, 16#65, 16#20, 16#74, 16#68, 16#61, 16#6E, 16#20, 16#6F, 16#6E,
      16#65, 16#20, 16#69, 16#74, 16#65, 16#72, 16#61, 16#74, 16#69, 16#6F,
      16#6E>>.

%% ------------------------------------------------------------------------------------------
%% -- MPPE magic constants when used with MS-CHAP-V2
mppe_magic1() ->
   <<16#54, 16#68, 16#69, 16#73, 16#20, 16#69, 16#73, 16#20, 16#74,
     16#68, 16#65, 16#20, 16#4d, 16#50, 16#50, 16#45, 16#20, 16#4d,
     16#61, 16#73, 16#74, 16#65, 16#72, 16#20, 16#4b, 16#65, 16#79>>.

mppe_magic2() ->
    <<16#4F, 16#6E, 16#20, 16#74, 16#68, 16#65, 16#20, 16#63, 16#6C, 16#69,
      16#65, 16#6E, 16#74, 16#20, 16#73, 16#69, 16#64, 16#65, 16#2C, 16#20,
      16#74, 16#68, 16#69, 16#73, 16#20, 16#69, 16#73, 16#20, 16#74, 16#68,
      16#65, 16#20, 16#73, 16#65, 16#6E, 16#64, 16#20, 16#6B, 16#65, 16#79,
      16#3B, 16#20, 16#6F, 16#6E, 16#20, 16#74, 16#68, 16#65, 16#20, 16#73,
      16#65, 16#72, 16#76, 16#65, 16#72, 16#20, 16#73, 16#69, 16#64, 16#65,
      16#2C, 16#20, 16#69, 16#74, 16#20, 16#69, 16#73, 16#20, 16#74, 16#68,
      16#65, 16#20, 16#72, 16#65, 16#63, 16#65, 16#69, 16#76, 16#65, 16#20,
      16#6B, 16#65, 16#79, 16#2E>>.

mppe_magic3() ->
    <<16#4F, 16#6E, 16#20, 16#74, 16#68, 16#65, 16#20, 16#63, 16#6C, 16#69,
      16#65, 16#6E, 16#74, 16#20, 16#73, 16#69, 16#64, 16#65, 16#2C, 16#20,
      16#74, 16#68, 16#69, 16#73, 16#20, 16#69, 16#73, 16#20, 16#74, 16#68,
      16#65, 16#20, 16#72, 16#65, 16#63, 16#65, 16#69, 16#76, 16#65, 16#20,
      16#6B, 16#65, 16#79, 16#3B, 16#20, 16#6F, 16#6E, 16#20, 16#74, 16#68,
      16#65, 16#20, 16#73, 16#65, 16#72, 16#76, 16#65, 16#72, 16#20, 16#73,
      16#69, 16#64, 16#65, 16#2C, 16#20, 16#69, 16#74, 16#20, 16#69, 16#73,
      16#20, 16#74, 16#68, 16#65, 16#20, 16#73, 16#65, 16#6E, 16#64, 16#20,
      16#6B, 16#65, 16#79, 16#2E>>.

mppe_sha_pad1() ->
    <<16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00,
      16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00,
      16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00,
      16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00>>.

mppe_sha_pad2() ->
    <<16#F2, 16#F2, 16#F2, 16#F2, 16#F2, 16#F2, 16#F2, 16#F2, 16#F2, 16#F2,
      16#F2, 16#F2, 16#F2, 16#F2, 16#F2, 16#F2, 16#F2, 16#F2, 16#F2, 16#F2,
      16#F2, 16#F2, 16#F2, 16#F2, 16#F2, 16#F2, 16#F2, 16#F2, 16#F2, 16#F2,
      16#F2, 16#F2, 16#F2, 16#F2, 16#F2, 16#F2, 16#F2, 16#F2, 16#F2, 16#F2>>.

