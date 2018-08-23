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

-module(eradius_lib_SUITE).
-include("eradius_lib.hrl").
-include("eradius_dict.hrl").
-include("eradius_test.hrl").
-compile(export_all).

-define(SALT, <<171,213>>).
-define(REQUEST_AUTHENTICATOR, << 1, 2, 3, 4, 5, 6, 7, 8 >>).
-define(USER, "test").
-define(SECRET, <<"secret">>).
-define(PLAIN_TEXT, "secret").
-define(PLAIN_TEXT_PADDED, <<"secret",0,0,0,0,0,0,0,0,0,0>>).
-define(CIPHER_TEXT, <<171,213,166,95,152,126,124,120,86,10,78,216,190,216,26,87,55,15>>).
-define(ENC_PASSWORD, 186,128,194,207,68,25,190,19,23,226,48,206,244,143,56,238).
-define(ENC_PASSWORD_ASCEND, 222,170,194,83,115,231,228,55,75,17,20,6,198,33,112,197).
-define(PDU, #radius_request{ reqid = 1, secret = ?SECRET, authenticator = ?REQUEST_AUTHENTICATOR }).


%% test callbacks
all() -> [ipv6prefix,
          selt_encrypt_test,
          salt_decrypt_test,
          scramble_enc_test,
          scramble_dec_test,
          ascend_enc_test,
          ascend_dec_test,
          enc_simple_test,
          enc_scramble_test,
          enc_salt_test,
          enc_vendor_test,
          enc_vendor_octet_test,
          dec_simple_integer_test,
          dec_simple_string_test,
          dec_simple_ipv4_test,
          dec_vendor_integer_t,
          dec_vendor_string_t,
          dec_vendor_ipv4_t,
          vendor_attribute_id_conflict_test
         ].

init_per_suite(Config) -> Config.
end_per_suite(_Config) -> ok.

init_per_testcase(Test, Config) when   Test == dec_vendor_integer_t
                                orelse Test == dec_vendor_string_t
                                orelse Test == dec_vendor_ipv4_t
                                orelse Test == vendor_attribute_id_conflict_test ->
    application:set_env(eradius, tables, [dictionary]),
    eradius_dict:start_link(),
    Config;
init_per_testcase(_, Config) -> Config.


ipv6prefix(_Config) ->
    IPv6Prefix0 = {{8193, 0, 0, 0, 0, 0, 0, 0}, 128},
    ?equal(IPv6Prefix0, ipv6prefix_enc_dec(IPv6Prefix0)),

    IPv6Prefix1 = {{8193, 255, 0, 0, 0, 0, 0, 0}, 128},
    ?equal(IPv6Prefix1, ipv6prefix_enc_dec(IPv6Prefix1)),

    IPv6Prefix2 = {{8193, 0, 0, 0, 0, 0, 0, 0}, 64},
    ?equal(IPv6Prefix2, ipv6prefix_enc_dec(IPv6Prefix2)),
    ok.

ipv6prefix_enc_dec(Prefix) ->
    Bin = eradius_lib:encode_value(ipv6prefix, Prefix),
    eradius_lib:decode_value(Bin, ipv6prefix).

selt_encrypt_test(_) ->
    ?equal(?CIPHER_TEXT, eradius_lib:salt_encrypt(?SALT, ?SECRET, ?REQUEST_AUTHENTICATOR, << ?PLAIN_TEXT >>)).

salt_decrypt_test(_) ->
    ?equal(<< ?PLAIN_TEXT >>, eradius_lib:salt_decrypt(?SECRET, ?REQUEST_AUTHENTICATOR, ?CIPHER_TEXT)).

scramble_enc_test(_) ->
    ?equal(<< ?ENC_PASSWORD >>, eradius_lib:scramble(?SECRET, ?REQUEST_AUTHENTICATOR, << ?PLAIN_TEXT >>)).

scramble_dec_test(_) ->
    ?equal(?PLAIN_TEXT_PADDED, eradius_lib:scramble(?SECRET, ?REQUEST_AUTHENTICATOR, << ?ENC_PASSWORD >>)).

ascend_enc_test(_) ->
    ?equal(<< ?ENC_PASSWORD_ASCEND >>, eradius_lib:ascend(?SECRET, ?REQUEST_AUTHENTICATOR, << ?PLAIN_TEXT >>)).

ascend_dec_test(_) ->
    ?equal(?PLAIN_TEXT_PADDED, eradius_lib:ascend(?SECRET, ?REQUEST_AUTHENTICATOR, << ?ENC_PASSWORD_ASCEND >>)).

enc_simple_test(_) ->
    L = length(?USER) + 2,
    ?equal(<< ?RUser_Name, L:8, ?USER >>, eradius_lib:encode_attribute(?PDU, #attribute{id = ?RUser_Name, type = string, enc = no}, << ?USER >>)).

enc_scramble_test(_) ->
    L = 16 + 2,
    ?equal(<< ?RUser_Passwd, L:8, ?ENC_PASSWORD >>, eradius_lib:encode_attribute(?PDU, #attribute{id = ?RUser_Passwd, type = string, enc = scramble}, << ?PLAIN_TEXT >>)).

enc_salt_test(_) ->
    L = 16 + 4,
    << ?RUser_Passwd, L:8, Enc/binary >> = eradius_lib:encode_attribute(?PDU, #attribute{id = ?RUser_Passwd, type = string, enc = salt_crypt}, << ?PLAIN_TEXT >>),
    %% need to decrypt to verfiy due to salt
    ?equal(<< ?PLAIN_TEXT >>, eradius_lib:salt_decrypt(?SECRET, ?REQUEST_AUTHENTICATOR, Enc)).

enc_vendor_test(_) ->
    L = length(?USER),
    E = << ?RVendor_Specific, (L+8):8, 18681:32, 1:8, (L+2):8, ?USER >>,
    ?equal(E, eradius_lib:encode_attribute(?PDU, #attribute{id = {18681,1}, type = string, enc = no}, << ?USER >>)).

enc_vendor_octet_test(_) ->
    E = << ?RVendor_Specific, (4+8):8, 311:32, 7:8, (4+2):8, 7:32 >>,
    ?equal(E, eradius_lib:encode_attribute(?PDU, #attribute{id = {311,7}, type = octets, enc = no}, 7)).

decode_attribute(A, B, C) ->
    eradius_lib:decode_attribute(A, B, C, 0, #decoder_state{}).

dec_simple_integer_test(_) ->
    State = decode_attribute(<<0,0,0,1>>, ?PDU, #attribute{id = 40, type = integer, enc = no}),
    [{_, 1}] = State#decoder_state.attrs.

dec_simple_string_test(_) ->
    State = decode_attribute(<<"29113">>, ?PDU, #attribute{id = 44, type = string, enc = no}),
    [{_, <<"29113">>}] = State#decoder_state.attrs.

dec_simple_ipv4_test(_) ->
    State = decode_attribute(<<10,33,0,1>>, ?PDU, #attribute{id = 4, type = ipaddr, enc = no}),
    [{_, {10,33,0,1}}] = State#decoder_state.attrs.

dec_vendor_integer_t(_) ->
    State = decode_attribute(<<0,0,40,175,3,6,0,0,0,0>>, ?PDU, #attribute{id = ?RVendor_Specific, type = octets, enc = no}),
    [{_, <<0, 0, 0, 0>>}] = State#decoder_state.attrs.

dec_vendor_string_t(_) ->
    State = decode_attribute(<<0,0,40,175,8,7,"23415">>, ?PDU, #attribute{id = ?RVendor_Specific, type = octets, enc = no}),
    [{_, <<"23415">>}] = State#decoder_state.attrs.

dec_vendor_ipv4_t(_) ->
    State = decode_attribute(<<0,0,40,175,6,6,212,183,144,246>>, ?PDU, #attribute{id = ?RVendor_Specific, type = octets, enc = no}),
    [{_, <<212,183,144,246>>}] = State#decoder_state.attrs.

vendor_attribute_id_conflict_test(_) ->
    #attribute{} = eradius_dict:lookup(attribute, 52),
    #vendor{} = eradius_dict:lookup(vendor, 52),
    #value{} = eradius_dict:lookup(value, {6,1}).