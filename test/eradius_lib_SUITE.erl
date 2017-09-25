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
-compile(export_all).

-define(equal(Expected, Actual),
    (fun (Expected@@@, Expected@@@) -> true;
	 (Expected@@@, Actual@@@) ->
	     ct:pal("MISMATCH(~s:~b, ~s)~nExpected: ~p~nActual:   ~p~n",
		    [?FILE, ?LINE, ??Actual, Expected@@@, Actual@@@]),
	     false
     end)(Expected, Actual) orelse error(badmatch)).


%% test callbacks
all() -> [ipv6prefix].

init_per_suite(Config) ->
    Config.

end_per_suite(_Config) ->
    ok.

%% tests

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
