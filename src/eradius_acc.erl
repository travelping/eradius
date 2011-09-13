%% @deprecated
%% @doc Construction and sending of RADIUS Accounting Requests.
%%   Do not use this module, it will be removed soon.
-module(eradius_acc).
-export([set_user/2, set_nas_ip_address/1, set_nas_ip_address/2,
         set_session_id/2, new/0,
         set_servers/2, set_timeout/2,
         set_tc_ureq/1,
         set_tc_itimeout/1,set_tc_stimeout/1,
         set_tc_areset/1, set_tc_areboot/1,
         set_tc_nasrequest/1, set_tc_nasreboot/1]).
-export([punch/3, send_recv_msg/5]).

-include("eradius_lib.hrl").
-include_lib("kernel/include/inet.hrl").

%% ------------------------------------------------------------------------------------------
%% -- API

%% Create ADT
new() -> #radius_request{ cmd = accreq }.

%% User
set_user(R, User) when is_record(R, radius_request),
		       R#radius_request.cmd =:= accreq ->
    eradius_lib:set_attr(R, ?RUser_Name, any2bin(User)).

%% NAS-IP
set_nas_ip_address(R) when is_record(R, radius_request),
			   R#radius_request.cmd =:= accreq ->
    eradius_lib:set_attr(R, ?RNAS_Ip_Address, nas_ip_address()).

set_nas_ip_address(R, Ip) when is_record(R, radius_request),
			       R#radius_request.cmd =:= accreq,
			       is_tuple(Ip) ->
    eradius_lib:set_attr(R, ?RNAS_Ip_Address, Ip).

%% Terminate Cause
set_tc_ureq(R) when is_record(R, radius_request),
		    R#radius_request.cmd =:= accreq ->
    eradius_lib:set_attr(R, ?RTerminate_Cause, ?RTCUser_Request).

set_tc_itimeout(R) when is_record(R, radius_request),
			R#radius_request.cmd =:= accreq ->
    eradius_lib:set_attr(R, ?RTerminate_Cause, ?RTCIdle_Timeout).

set_tc_stimeout(R) when is_record(R, radius_request),
			R#radius_request.cmd =:= accreq ->
    eradius_lib:set_attr(R, ?RTerminate_Cause, ?RTCSession_Timeout).

set_tc_areset(R) when is_record(R, radius_request),
		      R#radius_request.cmd =:= accreq ->
    eradius_lib:set_attr(R, ?RTerminate_Cause, ?RTCAdmin_Reset).

set_tc_areboot(R) when is_record(R, radius_request),
		       R#radius_request.cmd =:= accreq ->
    eradius_lib:set_attr(R, ?RTerminate_Cause, ?RTCAdmin_Reboot).

set_tc_nasrequest(R) when is_record(R, radius_request),
			  R#radius_request.cmd =:= accreq ->
    eradius_lib:set_attr(R, ?RTerminate_Cause, ?RTCNAS_Request).

set_tc_nasreboot(R) when is_record(R, radius_request),
			 R#radius_request.cmd =:= accreq ->
    eradius_lib:set_attr(R, ?RTerminate_Cause, ?RTCNAS_Reboot).

%% Session ID
set_session_id(R, Id) when is_record(R, radius_request),
			   R#radius_request.cmd =:= accreq ->
    eradius_lib:set_attr(R, ?RSession_Id, any2bin(Id)).

%% Server Info
set_servers(R, Srvs) when is_record(R, radius_request),
			  R#radius_request.cmd =:= accreq ->
    R#radius_request{servers = Srvs}.

set_timeout(R, Timeout) when is_record(R, radius_request),
			     R#radius_request.cmd =:= accreq,
			     is_integer(Timeout) ->
    R#radius_request{timeout = Timeout}.

%% ------------------------------------------------------------------------------------------
%% -- Sending Requests
punch(Srvs, Timeout, Req) ->
    spawn(fun() -> do_punch(Srvs, Timeout, Req) end).

do_punch([], _Timeout, _Req) ->
    %% FIXME some nice syslog message somewhere perhaps ?
    false;
do_punch([[Ip,Port,Shared] | Rest], Timeout, Req) ->
    Id  = 0, %% @todo: improve ID generation
    PDU = eradius_lib:enc_accreq(Id, Shared, Req),
    case send_recv_msg(Ip, Port, PDU, Timeout, Shared) of
       timeout ->
           %% NB: We could implement a re-send strategy here
           %% along the lines of what the RFC proposes.
           do_punch(Rest, Timeout, Req);
       Resp when is_record(Resp, rad_pdu) ->
           %% Not really necessary...
           R = Resp#rad_pdu.req,
           if is_record(R, radius_request),
              R#radius_request.cmd =:= accreq -> true;
              true                            -> false
           end
    end.

send_recv_msg(Ip, Port, ReqBinary, Timeout, Secret) ->
    {ok, S} = gen_udp:open(0, [binary]),
    gen_udp:send(S, Ip, Port, ReqBinary),
    receive
        {udp, S, _IP, _Port, Packet} ->
            Reply = eradius_lib:dec_packet(Packet, Secret)
    after
        Timeout ->
            Reply = timeout
    end,
    gen_udp:close(S),
    Reply.

%% ------------------------------------------------------------------------------------------
%% -- Helpers
any2bin(I) when is_integer(I) -> list_to_binary(integer_to_list(I));
any2bin(L) when is_list(L)    -> list_to_binary(L);
any2bin(B) when is_binary(B)  -> B.

nas_ip_address() ->
    node2ip(node()).

node2ip(Node) ->
    host2ip(node2host(Node)).

node2host(Node) ->
    n2h(atom_to_list(Node)).

n2h([$@ | Host]) -> Host;
n2h([_H | T])    -> n2h(T);
n2h([])          -> [].

host2ip(Host) ->
    {ok, #hostent{h_addr_list = [Ip | _]}} = inet:gethostbyname(Host),
    Ip.
