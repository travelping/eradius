%% Copyright (c) 2002-2007, Martin Björklund and Torbjörn Törnkvist
%% Copyright (c) 2011, Travelping GmbH <info@travelping.com>
%%
%% SPDX-License-Identifier: MIT
%%
%% @private
-module(eradius_lib).

-export([pad_to/2]).
-export([printable_peer/1, printable_peer/2]).

%% -compile(bin_opt_info).

-include("eradius_lib.hrl").
-include("eradius_dict.hrl").

-define(IS_KEY(Key, Attr), ((is_record(Attr, attribute) andalso (element(2, Attr) == Key))
                            orelse
                              (Attr == Key)) ).
%% ------------------------------------------------------------------------------------------
%% -- Request Accessors

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

-spec printable_peer(server_name() | {inet:ip_address() | any, inet:port_number()}) -> io_lib:chars().
printable_peer(Atom) when is_atom(Atom) ->
    [atom_to_list(Atom)];
printable_peer(Binary) when is_binary(Binary) ->
    [Binary];
printable_peer({IP, Port}) ->
    printable_peer(IP, Port).

-spec printable_peer(inet:ip_address() | any, inet:port_number()) -> io_lib:chars().
printable_peer(any, Port) ->
    ["any:", integer_to_list(Port)];
printable_peer({_, _, _, _} = IP, Port) ->
    [inet:ntoa(IP), $:, integer_to_list(Port)];
printable_peer({_, _, _, _, _, _, _, _} = IP, Port) ->
    [$[, inet:ntoa(IP), $], $:, integer_to_list(Port)].
