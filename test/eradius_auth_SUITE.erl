% Copyright (c) 2010-2017 by Travelping GmbH <info@travelping.com>

% Permission is hereby granted, free of charge, to any person obtaining a
% copy of this software and associated documentation files (the "Software"),
% to deal in the Software without restriction, including without limitation
% the rights to use, copy, modify, merge, publish, distribute, sublicense,
% and/or sell copies of the Software, and to permit persons to whom the
% Software is furnished to do so, subject to the following conditions:

% The above copyright notice and this permission notice shall be included in
% all copies or substantial portions of the Software.

% THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
% IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
% FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
% AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
% LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
% FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
% DEALINGS IN THE SOFTWARE.

-module(eradius_auth_SUITE).
-compile(export_all).
-include("eradius_test.hrl").

all() -> [
    unicode_test,
    password_hash_test,
    unicode_password_hash_test,
    password_hashhash_test,
    password_hash2_test,
    des_key_test,
    nt_response_test,
    v2_authenticator_test,
    mppe_master_key_test,
    mppe_sendstart_key40_test,
    mppe_sendstart_key56_test,
    mppe_sendstart_key128_test,
    mppe_start_key40_test,
    mppe_start_key56_test,
    mppe_start_key128_test
    ].


%% 0-to-256-char UserName
-define(USERNAME, <<16#55, 16#73, 16#65, 16#72>>).

%% Password
-define(PASSWORD, <<16#63, 16#6C, 16#69, 16#65, 16#6E, 16#74, 16#50, 16#61, 16#73, 16#73>>).

%% 0-to-256-unicode-char Password
-define(UNICODE_PASSWORD, <<16#63, 16#00, 16#6C, 16#00, 16#69, 16#00, 16#65, 16#00, 16#6E, 16#00, 16#74, 16#00, 16#50, 16#00, 16#61, 16#00, 16#73, 16#00, 16#73, 16#00>>).

%% 16-octet AuthenticatorChallenge:
-define(AUTHENTICATOR_CHALLENGE, <<16#5B, 16#5D, 16#7C, 16#7D, 16#7B, 16#3F, 16#2F, 16#3E, 16#3C, 16#2C, 16#60, 16#21, 16#32, 16#26, 16#26, 16#28>>).

%% 16-octet PeerChallenge:
-define(PEER_CHALLENGE, <<16#21, 16#40, 16#23, 16#24, 16#25, 16#5E, 16#26, 16#2A, 16#28, 16#29, 16#5F, 16#2B, 16#3A, 16#33, 16#7C, 16#7E>>).

%% 16-octet PasswordHash:
-define(PASSWORD_HASH, <<16#44, 16#EB, 16#BA, 16#8D, 16#53, 16#12, 16#B8, 16#D6, 16#11, 16#47, 16#44, 16#11, 16#F5, 16#69, 16#89, 16#AE>>).

%% 24 octet NT-Response:
-define(NT_RESPONSE, <<16#82, 16#30, 16#9E, 16#CD, 16#8D, 16#70, 16#8B, 16#5E, 16#A0, 16#8F, 16#AA, 16#39, 16#81, 16#CD, 16#83, 16#54, 16#42, 16#33, 16#11, 16#4A, 16#3D, 16#85, 16#D6, 16#DF>>).

%% 16-octet PasswordHashHash:
-define(PASSWORD_HASHHASH, <<16#41, 16#C0, 16#0C, 16#58, 16#4B, 16#D2, 16#D9, 16#1C, 16#40, 16#17, 16#A2, 16#A1, 16#2F, 16#A5, 16#9F, 16#3F>>).

%% 42-octet AuthenticatorResponse:
-define(AUTHENTICATOR_RESPONSE, <<"S=407A5589115FD0D6209F510FE9C04566932CDA56 ">>).

%% MPPE keys
-define(MASTER_KEY, <<16#FD, 16#EC, 16#E3, 16#71, 16#7A, 16#8C, 16#83, 16#8C, 16#B3, 16#88, 16#E5, 16#27, 16#AE, 16#3C, 16#DD, 16#31>>).
-define(SEND_START_KEY40, <<16#8B, 16#7C, 16#DC, 16#14, 16#9B, 16#99, 16#3A, 16#1B>>).
-define(SEND_START_KEY56, <<16#8B, 16#7C, 16#DC, 16#14, 16#9B, 16#99, 16#3A, 16#1B>>).
-define(SEND_START_KEY128, <<16#8B, 16#7C, 16#DC, 16#14, 16#9B, 16#99, 16#3A, 16#1B, 16#A1, 16#18, 16#CB, 16#15, 16#3F, 16#56, 16#DC, 16#CB>>).

%% 0-to-256-unicode-char Password:
-define(PASSWORD2, <<16#4D, 16#79, 16#50, 16#77>>).

%% 16-octet PasswordHash:
-define(PASSWORD_HASH2, <<16#FC, 16#15, 16#6A, 16#F7, 16#ED, 16#CD, 16#6C, 16#0E, 16#DD, 16#E3, 16#33, 16#7D, 16#42, 16#7F, 16#4E, 16#AC>>).

%% parity-corrected DES key:
-define(DES_KEY, <<16#FD, 16#0B, 16#5B, 16#5E, 16#7F, 16#6E, 16#34, 16#D9, 16#0E, 16#6E, 16#79, 16#67, 16#37, 16#EA, 16#08, 16#FE, 16#4F, 16#57>>).

unicode_test(_) ->
    ?equal(?UNICODE_PASSWORD, eradius_auth:ascii_to_unicode(binary_to_list(?PASSWORD))),
    ?equal(?UNICODE_PASSWORD, eradius_auth:ascii_to_unicode(?PASSWORD)).

password_hash_test(_) ->
    ?equal(?PASSWORD_HASH, eradius_auth:nt_password_hash(?PASSWORD)).

unicode_password_hash_test(_) ->
    ?equal(?PASSWORD_HASH, eradius_auth:nt_hash(?UNICODE_PASSWORD)).

password_hashhash_test(_) ->
    ?equal(?PASSWORD_HASHHASH, eradius_auth:nt_hash(eradius_auth:nt_hash(?UNICODE_PASSWORD))).

password_hash2_test(_) ->
    ?equal(?PASSWORD_HASH2, eradius_auth:nt_password_hash(?PASSWORD2)).

des_key_test(_) ->
    ?equal(?DES_KEY, eradius_auth:des_key_from_hash(?PASSWORD_HASH2)).

nt_response_test(_) ->
    ?equal(?NT_RESPONSE, eradius_auth:v2_generate_nt_response(?AUTHENTICATOR_CHALLENGE, ?PEER_CHALLENGE, ?USERNAME, ?PASSWORD_HASH)).

v2_authenticator_test(_) ->
    ?equal(?AUTHENTICATOR_RESPONSE, eradius_auth:v2_generate_authenticator_response(?PASSWORD_HASH, ?NT_RESPONSE, ?PEER_CHALLENGE, ?AUTHENTICATOR_CHALLENGE, ?USERNAME)).

mppe_master_key_test(_) ->
    ?equal(?MASTER_KEY, eradius_auth:mppe_get_master_key(?PASSWORD_HASHHASH, ?NT_RESPONSE)).

mppe_sendstart_key40_test(_)->
    ?equal(?SEND_START_KEY40, eradius_auth:mppe_get_asymetric_send_start_key(?MASTER_KEY, 8)).

mppe_sendstart_key56_test(_)->
    ?equal(?SEND_START_KEY56, eradius_auth:mppe_get_asymetric_send_start_key(?MASTER_KEY, 8)).

mppe_sendstart_key128_test(_)->
    ?equal(?SEND_START_KEY128, eradius_auth:mppe_get_asymetric_send_start_key(?MASTER_KEY, 16)).

mppe_start_key40_test(_)->
    ?match({?SEND_START_KEY40, _ }, eradius_auth:mppe_generate_session_keys(?PASSWORD_HASH, ?NT_RESPONSE, 40)).

mppe_start_key56_test(_)->
    ?match({?SEND_START_KEY56, _ }, eradius_auth:mppe_generate_session_keys(?PASSWORD_HASH, ?NT_RESPONSE, 56)).

mppe_start_key128_test(_)->
    ?match({?SEND_START_KEY128, _ }, eradius_auth:mppe_generate_session_keys(?PASSWORD_HASH, ?NT_RESPONSE, 128)).

