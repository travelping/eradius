%% Copyright (c) 2010, 2011, Travelping GmbH <info@travelping.com>
%%
%% SPDX-License-Identifier: MIT
%%
-module(eradius_log).

%% API
-export([update_logger_process_metadata/1, line/1]).
-export([collect_meta/1, format_req/1]).
-export([bin_to_hexstr/1, format_cmd/1]).

-ignore_xref([?MODULE]).

-include_lib("kernel/include/logger.hrl").
-include("eradius_lib.hrl").
-include("eradius_dict.hrl").
-include("dictionary.hrl").

%%%===================================================================
%%% API
%%%===================================================================

%% @doc copy RADIUS AVPs into `m:logger' metadata.
%%
%% Helper function for use in a RADIUS server handler that will
%% copy all RADIUS attributes into `m:logger' metadata.
%%
%% <blockquote><h4 class="warning">WARNING</h4>
%% The function will format all attribute values to strings,
%% the resulting processing load can be significant.
%% </blockquote>
-spec update_logger_process_metadata(eradius_req:req()) -> ok.
update_logger_process_metadata(Req) ->
    Metadata = maps:from_list(collect_meta(Req)),
    logger:update_process_metadata(Metadata).

%% @doc Serialize `t:eradius_req:req/0' object into a proplist.
%%
%% Helper function for use in a RADIUS server handler that will
%% serialize a RADIUS `t:eradius_req:req/0' object into a Key/Value lists.
%%
%% All values will be converted to human readable strings.
-spec collect_meta(eradius_req:req()) -> [{term(), term()}].
collect_meta(#{cmd := Cmd, req_id := ReqId, attrs := Attrs}) ->
    RequestType = binary_to_list(format_cmd(Cmd)),
    RequestId = integer_to_list(ReqId),
    [{request_type, RequestType},
     {request_id, RequestId}|
     [collect_attr(Key, Val) || {Key, Val} <- Attrs]].

%% @doc Format `t:eradius_req:req/0' object into a RADIUS short log entry
%%
%% The short log format is not part of any RADIUS RFC, but has been
%% used by many RADIUS server implementations.
%%
%% The format is: `<Client-IP>:<Client-Port> [<Request-Id>]: <Command> [AcctStatusType]'
-spec line(eradius_req:req()) -> iolist().
line(#{cmd := Cmd, req_id := ReqId, server_addr := {IP, Port}} = Req) ->
    StatusType = format_acct_status_type(Req),
    io_lib:format("~s:~p [~p]: ~s ~s", [inet:ntoa(IP), Port, ReqId, format_cmd(Cmd), StatusType]).

%% @doc Format `t:eradius_req:req/0' object into a RADIUS log entry
%%
%% The long log format is not part of any RADIUS RFC, but has been
%% used by many RADIUS server implementations in the past.
%%
%% The format is:
%% ```
%% <TimeStamp> <Client-IP>:<Client-Port> [<Request-Id>] <Command>
%%     [<Key> = <Value>]+
%% '''
-spec format_req(eradius_req:req()) -> binary().
format_req(Req) ->
    Time =
        case Req of
            #{arrival_time := ATime} -> ATime + erlang:time_offset();
            _ -> erlang:system_time()
        end,
    format_message(Time, Req).

%%%===================================================================
%%% Internal functions
%%%===================================================================

%% -- formatting
format_message(Time, #{cmd := Cmd} = Req) ->
    BinTStamp = radius_date(Time),
    BinSender = format_sender(Req),
    BinCommand = format_cmd(Cmd),
    BinPacket = format_packet(Req),
    <<BinTStamp/binary, " ", BinSender/binary, " ", BinCommand/binary, "\n", BinPacket/binary, "\n">>.

format_sender(#{req_id := ReqId, server_addr := {IP, Port}}) ->
    <<(format_ip(IP))/binary, $:, (i2b(Port))/binary, " [", (i2b(ReqId))/binary, $]>>.

%% @private
format_cmd(request)   -> <<"Access-Request">>;
format_cmd(accept)    -> <<"Access-Accept">>;
format_cmd(reject)    -> <<"Access-Reject">>;
format_cmd(challenge) -> <<"Access-Challenge">>;
format_cmd(accreq)    -> <<"Accounting-Request">>;
format_cmd(accresp)   -> <<"Accounting-Response">>;
format_cmd(coareq)    -> <<"Coa-Request">>;
format_cmd(coaack)    -> <<"Coa-Ack">>;
format_cmd(coanak)    -> <<"Coa-Nak">>;
format_cmd(discreq)   -> <<"Disconnect-Request">>;
format_cmd(discack)   -> <<"Disconnect-Ack">>;
format_cmd(discnak)   -> <<"Disconnect-Nak">>.

format_ip(IP) ->
    list_to_binary(inet_parse:ntoa(IP)).

format_packet(#{attrs := Attrs} = _Req) ->
    << <<(print_attr(Key, Val))/binary>> || {Key, Val} <- Attrs >>.

print_attr(Key = #attribute{name = Attr, type = Type}, InVal) ->
    FmtValUnquoted = printable_attr_value(Key, InVal),
    FmtVal         = case Type of
                         string -> <<$", FmtValUnquoted/binary, $">>;
                         _      -> FmtValUnquoted
                     end,
    <<"\t", (list_to_binary(Attr))/binary, " = ", FmtVal/binary, "\n">>;
print_attr(Id, Val) ->
    case eradius_dict:lookup(attribute, Id) of
        Attr = #attribute{} ->
            print_attr(Attr, Val);
        _ ->
            Name = format_unknown(Id),
            print_attr(#attribute{id = Id, name = Name, type = octets}, Val)
    end.

collect_attr(Key = #attribute{name = Attr, type = _Type}, InVal) ->
    FmtVal = collectable_attr_value(Key, InVal),
    {list_to_atom(lists:flatten(Attr)), FmtVal};
collect_attr(Id, Val) ->
    case eradius_dict:lookup(attribute, Id) of
        Attr = #attribute{} ->
            collect_attr(Attr, Val);
        _ ->
            Name = format_unknown(Id),
            collect_attr(#attribute{id = Id, name = Name, type = octets}, Val)
    end.

printable_attr_value(Attr = #attribute{type = {tagged, RealType}}, {Tag, RealVal}) ->
    ValBin = printable_attr_value(Attr#attribute{type = RealType}, RealVal),
    TagBin = case Tag of
                 undefined -> <<>>;
                 Int       -> <<(i2b(Int))/binary, ":">>
             end,
    <<TagBin/binary, ValBin/binary>>;
printable_attr_value(#attribute{type = string}, Value) when is_binary(Value) ->
    << <<(escape_char(C))/binary>> || <<C:8>> <= Value >>;
printable_attr_value(#attribute{type = string}, Value) when is_list(Value) ->
    << <<(escape_char(C))/binary>> || <<C:8>> <= iolist_to_binary(Value) >>;
printable_attr_value(#attribute{type = ipaddr}, {A, B, C, D}) ->
    <<(i2b(A))/binary, ".", (i2b(B))/binary, ".", (i2b(C))/binary, ".", (i2b(D))/binary>>;
printable_attr_value(#attribute{id = ID, type = integer}, Val) when is_integer(Val) ->
    case eradius_dict:lookup(value, {ID, Val}) of
        #value{name = VName} -> list_to_binary(VName);
        _                    -> i2b(Val)
    end;
printable_attr_value(#attribute{type = date}, {{Y,Mo,D},{H,Min,S}}) ->
    list_to_binary(io_lib:fwrite("~4..0B-~2..0B-~2..0BT~2..0B:~2..0B:~2..0B", [Y, Mo, D, H, Min, S]));
printable_attr_value(_Attr, <<Val/binary>>) ->
    <<"0x", (bin_to_hexstr(Val))/binary>>;
printable_attr_value(_Attr, Val) ->
    list_to_binary(io_lib:format("~p", [Val])).

collectable_attr_value(Attr = #attribute{type = {tagged, RealType}}, {Tag, RealVal}) ->
    ValCol = collectable_attr_value(Attr#attribute{type = RealType}, RealVal),
    TagCol = case Tag of
                 undefined -> empty;
                 Int       -> Int
             end,
    {TagCol, ValCol};
collectable_attr_value(#attribute{type = string}, Value) when is_binary(Value) ->
    binary_to_list(Value);
collectable_attr_value(#attribute{type = string}, Value) when is_list(Value) ->
    Value;
collectable_attr_value(#attribute{type = ipaddr}, IP) ->
    inet_parse:ntoa(IP);
collectable_attr_value(#attribute{id = ID, type = integer}, Val) when is_integer(Val) ->
    case eradius_dict:lookup(value, {ID, Val}) of
        #value{name = VName} -> VName;
        _                      -> Val
    end;
collectable_attr_value(#attribute{type = date}, {{Y,Mo,D},{H,Min,S}}) ->
    io_lib:fwrite("~4..0B-~2..0B-~2..0BT~2..0B:~2..0B:~2..0B", [Y, Mo, D, H, Min, S]);
collectable_attr_value(_Attr, <<Val/binary>>) ->
    "0x"++binary_to_list(bin_to_hexstr(Val));
collectable_attr_value(_Attr, Val) ->
    io_lib:format("~p", [Val]).

radius_date(Time) ->
    {{YYYY, MM, DD} = Date, {Hour, Min, Sec}} =
        calendar:system_time_to_universal_time(Time, native),
    DayNumber = calendar:day_of_the_week(Date),
    list_to_binary(
      io_lib:format("~s ~3.s ~2.2.0w ~2.2.0w:~2.2.0w:~2.2.0w ~4.4.0w",
                    [day(DayNumber), month(MM), DD, Hour, Min, Sec, YYYY])).

format_unknown({VendId, Id}) ->
    case eradius_dict:lookup(vendor, VendId) of
        #vendor{name = Name} ->
            ["Unkown-", Name, $-, integer_to_list(Id)];
        _ ->
            ["Unkown-", integer_to_list(VendId), $-, integer_to_list(Id)]
    end;
format_unknown(Id) when is_integer(Id) ->
    ["Unkown-", integer_to_list(Id)].

escape_char($") -> <<"\\\"">>;
escape_char(C) when C >= 32, C < 127 -> <<C>>;
escape_char(C) -> <<"\\", (i2b(C))/binary>>.

day(1) -> "Mon";
day(2) -> "Tue";
day(3) -> "Wed";
day(4) -> "Thu";
day(5) -> "Fri";
day(6) -> "Sat";
day(7) -> "Sun".

month(1) -> "Jan";
month(2) -> "Feb";
month(3) -> "Mar";
month(4) -> "Apr";
month(5) -> "May";
month(6) -> "Jun";
month(7) -> "Jul";
month(8) -> "Aug";
month(9) -> "Sep";
month(10) -> "Oct";
month(11) -> "Nov";
month(12) -> "Dec".

-compile({inline, i2b/1}).
i2b(I) -> list_to_binary(integer_to_list(I)).

-compile({inline,hexchar/1}).
hexchar(X) when X >= 0, X < 10 ->
    X + $0;
hexchar(X) when X >= 10, X < 16 ->
    X + ($A - 10).

%% @private
-compile({inline, bin_to_hexstr/1}).
bin_to_hexstr(Bin) ->
    << << (hexchar(X)) >> || <<X:4>> <= Bin >>.

format_acct_status_type(Req) ->
    StatusType = eradius_req:attr(?Acct_Status_Type, Req),
    case StatusType of
        undefined ->
            "";
        1 ->
            "Start";
        2 ->
            "Stop";
        3 ->
            "Interim Update";
        7 ->
            "Accounting-On";
        8 ->
            "Accounting-Off"
    end.
