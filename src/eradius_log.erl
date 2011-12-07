%% @private
-module(eradius_log).
-export([open/0, close/1, write_request/3]).
-export([radius_date/1, printable_attr_value/2, bin_to_hexstr/1]).
-export_type([log/0]).

-include("eradius_lib.hrl").
-include("eradius_dict.hrl").
-define(DISK_LOG_NAME, eradius_request_log).

-opaque log() :: term().

-type sender() :: {inet:ip_address(), eradius_server:port_number(), eradius_server:req_id()}.

%% ------------------------------------------------------------
%% -- API
-spec open() -> {ok, log()}.
open() ->
    {ok, LogFile} = application:get_env(eradius, logfile),
    disk_log:open([{name, ?DISK_LOG_NAME}, {file, LogFile}, {format, external}, {type, halt}]).

-spec close(log()) -> ok.
close(Log) ->
    disk_log:close(Log).

-spec write_request(log(), sender(), #radius_request{}) -> ok.
write_request(Log, Sender, Request = #radius_request{}) ->
    Time = calendar:universal_time(),
    case catch format_message(Time, Sender, Request) of
        {'EXIT', Error} ->
            eradius:error_report("Failed to log RADIUS request: ~p~n~p", [Error, Request]),
            ok;
        Msg ->
            disk_log:blog(Log, Msg)
    end.

%% ------------------------------------------------------------------------------------------
%% -- formatting
format_message(Time, Sender, Request) ->
    BinTStamp = radius_date(Time),
    BinSender = format_sender(Sender),
    BinCommand = format_cmd(Request#radius_request.cmd),
    BinPacket = format_packet(Request),
    <<BinTStamp/binary, " ", BinSender/binary, " ", BinCommand/binary, "\n", BinPacket/binary, "\n">>.

format_sender({NASIP, NASPort, ReqID}) ->
    <<(format_ip(NASIP))/binary, $:, (i2b(NASPort))/binary, " [", (i2b(ReqID))/binary, $]>>.

format_cmd(request)   -> <<"Access-Request">>;
format_cmd(accept)    -> <<"Access-Accept">>;
format_cmd(reject)    -> <<"Access-Reject">>;
format_cmd(challenge) -> <<"Access-Challenge">>;
format_cmd(accreq)    -> <<"Accounting-Request">>;
format_cmd(accresp)   -> <<"Accounting-Response">>.

format_ip(IP) ->
    list_to_binary(inet_parse:ntoa(IP)).

format_packet(Request) ->
    Attrs = Request#radius_request.attrs,
    << <<(print_attr(Key, Val))/binary>> || {Key, Val} <- Attrs >>.

print_attr(Key = #attribute{name = Attr, type = Type}, InVal) ->
    FmtValUnquoted = printable_attr_value(Key, InVal),
    FmtVal         = case Type of
                         string -> <<$", FmtValUnquoted/binary, $">>;
                         _      -> FmtValUnquoted
                     end,
    <<"\t", (list_to_binary(Attr))/binary, " = ", FmtVal/binary, "\n">>;
print_attr(Id, Val) ->
    case eradius_dict:lookup(Id) of
        [Attr = #attribute{}] ->
            print_attr(Attr, Val);
        _ ->
            Name = format_unknown(Id),
            print_attr(#attribute{id = Id, name = Name, type = octets}, Val)
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
    case eradius_dict:lookup({ID, Val}) of
        [#value{name = VName}] -> list_to_binary(VName);
        _                      -> i2b(Val)
    end;
printable_attr_value(#attribute{type = date}, {{Y,Mo,D},{H,Min,S}}) ->
    list_to_binary(io_lib:fwrite("~4..0B-~2..0B-~2..0BT~2..0B:~2..0B:~2..0B", [Y, Mo, D, H, Min, S]));
printable_attr_value(_Attr, <<Val/binary>>) ->
    <<"0x", (bin_to_hexstr(Val))/binary>>;
printable_attr_value(_Attr, Val) ->
    list_to_binary(io_lib:format("~p", [Val])).

radius_date({{YYYY,MM,DD},{Hour,Min,Sec}}) ->
    DayNumber = calendar:day_of_the_week(YYYY, MM, DD),
    list_to_binary(
        io_lib:format("~s ~3.s ~2.2.0w ~2.2.0w:~2.2.0w:~2.2.0w ~4.4.0w",
            [day(DayNumber), month(MM), DD, Hour, Min, Sec, YYYY])).

format_unknown({VendId, Id}) ->
    case eradius_dict:lookup(VendId) of
        [#vendor{name = Name}] ->
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

-compile({inline, bin_to_hexstr/1}).
bin_to_hexstr(Bin) ->
    << <<(hd(integer_to_list(X, 16)))/utf8>> || <<X:4>> <= Bin >>.
