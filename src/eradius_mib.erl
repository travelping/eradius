-module(eradius_mib).
%%%-----------------------------------------------------------------
%%% Description: This module implements the ERADIUS_MIB.
%%% The tables are implemented as shadow tables with the module
%%% snmp_shadow_table.  Here the update functions are implemented.
%%%-----------------------------------------------------------------

-include("ERADIUS-MIB.hrl").
-include("eradius_lib.hrl").

%% API
-export([load/1, unload/1]).

%% SNMP instrumentation
-export([eradius_server_table/1, eradius_server_table/3]).
-export([eradius_client_table/1, eradius_client_table/3]).

%% SNMP shadow functions
-export([update_eradius_server_table/0]).
-export([update_eradius_client_table/0]).

%% Shadow tables  
-record(eradiusServerTable, {
		  key,
		  eradiusServerIdent,
		  eradiusServerUpTime               = 0,
		  eradiusServerResetTime            = 0,
		  eradiusServerConfigReset          = running,
		  eradiusServerInvalidRequests      = 0,
		  eradiusServerDiscardNoHandler     = 0,
		  eradiusServerRequests             = 0,
		  eradiusServerReplies              = 0,
		  eradiusServerDupRequests          = 0,
		  eradiusServerMalformedRequests    = 0,
		  eradiusServerAccessRequests       = 0,
		  eradiusServerAccessAccepts        = 0,
		  eradiusServerAccessRejects        = 0,
		  eradiusServerAccessChallenges     = 0,
		  eradiusServerAccountRequests      = 0,
		  eradiusServerAccountResponses     = 0,
		  eradiusServerNoRecords            = 0,
		  eradiusServerBadAuthenticators    = 0,
		  eradiusServerPacketsDropped       = 0,
		  eradiusServerUnknownTypes         = 0,
		  eradiusServerHandlerFailure       = 0,
		  eradiusServerCounterDiscontinuity = 0
}).

-record(eradiusClientTable, {
		  key,
		  eradiusClientID,
		  eradiusServerRequests,
		  eradiusServerReplies,
		  eradiusServerDupRequests,
		  eradiusServerMalformedRequests,
		  eradiusServerAccessRequests,
		  eradiusServerAccessAccepts,
		  eradiusServerAccessRejects,
		  eradiusServerAccessChallenges,
		  eradiusServerAccountRequests,
		  eradiusServerAccountResponses,
		  eradiusServerNoRecords,
		  eradiusServerBadAuthenticators,
		  eradiusServerPacketsDropped,
		  eradiusServerUnknownTypes,
		  eradiusServerHandlerFailure,
		  eradiusServerCounterDiscontinuity
}).

%% Shadow argument macros 
-define(eradiusServerShadowArgs, 
        {eradiusServerTable, {integer, string, integer}, record_info(fields, eradiusServerTable), 5000,
         fun ?MODULE:update_eradius_server_table/0}).
-define(eradiusClientShadowArgs, 
        {eradiusClientTable, {integer, string, integer, integer, string}, record_info(fields, eradiusClientTable), 5000,
         fun ?MODULE:update_eradius_client_table/0}).

%%%=========================================================================
%%%  API
%%%=========================================================================

%%-------------------------------------------------------------------------
%% load(Agent) ->  ok | {error, Reason}
%% Agent - pid() | atom()
%% Reason - term()
%% Description: Loads the ERADIUS-MIB
%%-------------------------------------------------------------------------
load(Agent) ->
    MibDir = filename:join(code:priv_dir(eradius), "mibs"),
    snmpa:load_mibs(Agent, [filename:join(MibDir, "ERADIUS-MIB")]).

%%-------------------------------------------------------------------------
%% unload(Agent) ->  ok | {error, Reason}
%% Agent - pid() | atom()
%% Reason - term()
%% Description: Unloads the ERADIUS-MIB
%%-------------------------------------------------------------------------
unload(Agent) ->
    snmpa:unload_mibs(Agent, ["ERADIUS-MIB"]).

%%%=========================================================================
%%%  SNMP instrumentation
%%%=========================================================================
eradius_server_table(Op) ->
    snmp_shadow_table:table_func(Op, ?eradiusServerShadowArgs).

eradius_server_table(Op, RowIndex, Cols) ->
    snmp_shadow_table:table_func(Op, RowIndex, Cols, ?eradiusServerShadowArgs).

eradius_client_table(Op) ->
    snmp_shadow_table:table_func(Op, ?eradiusClientShadowArgs).

eradius_client_table(Op, RowIndex, Cols) ->
    snmp_shadow_table:table_func(Op, RowIndex, Cols, ?eradiusClientShadowArgs).

%%%=========================================================================
%%%  SNMP shadow functions
%%%=========================================================================
update_eradius_server_table() ->
    delete_all(eradiusServerTable),
	Cnts = eradius_counter:aggregate(eradius_counter_aggregator:read()),
	insert_server_counter(Cnts),
	ok.

update_eradius_client_table() ->
    delete_all(eradiusClientTable),
	{_, {TStamp, NasCnts}} = eradius_counter_aggregator:read(),
	Nass = eradius_server_mon:all_nas_keys(),
	gen_merged(TStamp, Nass, NasCnts),
	ok.

%%%========================================================================
%%% Internal functions
%%%========================================================================
delete_all(Name) -> delete_all(mnesia:dirty_first(Name), Name).
delete_all('$end_of_table', _Name) -> done;
delete_all(Key, Name) ->
    Next = mnesia:dirty_next(Name, Key),
    ok = mnesia:dirty_delete({Name, Key}),
    delete_all(Next, Name).

gen_merged(_ResetTS, [], []) ->
	ok;
gen_merged(ResetTS, [], [Cnt = #nas_counter{}|CntRest]) ->
	insert_client_stats(ResetTS, Cnt),
	gen_merged(ResetTS, [], CntRest);
gen_merged(ResetTS, [Nas|Rest], [Cnt = #nas_counter{key = Nas}|CntRest]) ->
	insert_client_stats(ResetTS, Cnt),
	gen_merged(ResetTS, Rest, CntRest);
gen_merged(ResetTS, Nass = [Nas|_], [Cnt = #nas_counter{key = Key}|CntRest])
  when Key < Nas->
	insert_client_stats(ResetTS, Cnt),
	gen_merged(ResetTS, Nass, CntRest);
gen_merged(ResetTS, [Nas|Rest], NasCnts) ->
	insert_client_stats(ResetTS, eradius_counter:init_counter(Nas)),
	gen_merged(ResetTS, Rest, NasCnts).

insert_client_stats(ResetTS, Cnt = #nas_counter{}) ->
	mnesia:dirty_write(map_client_counter(ResetTS, Cnt)).

addr_to_snmp(Addr) ->
	AddrType = if
				   tuple_size(Addr) == 4 -> 1;
				   tuple_size(Addr) == 8 -> 2;
				   true -> 0
			   end,
	{AddrType, tuple_to_list(Addr)}.

map_client_counter(ResetTS, Counter = #nas_counter{key = {{Server, Port}, Client}}) ->
	{SAddrType, SAddr} = addr_to_snmp(Server),
	{CAddrType, CAddr} = addr_to_snmp(Client),
	Key = {SAddrType, SAddr, Port, CAddrType, CAddr},
	#eradiusClientTable{
			key                                 = Key,
			eradiusClientID                     = "no id",
			eradiusServerRequests               = Counter#nas_counter.requests,
			eradiusServerReplies                = Counter#nas_counter.replies,
			eradiusServerDupRequests            = Counter#nas_counter.dupRequests,
			eradiusServerMalformedRequests      = Counter#nas_counter.malformedRequests,
			eradiusServerAccessRequests         = Counter#nas_counter.accessRequests,
			eradiusServerAccessAccepts          = Counter#nas_counter.accessAccepts,
			eradiusServerAccessRejects          = Counter#nas_counter.accessRejects,
			eradiusServerAccessChallenges       = Counter#nas_counter.accessChallenges,
			eradiusServerAccountRequests        = Counter#nas_counter.accountRequests,
			eradiusServerAccountResponses       = Counter#nas_counter.accountResponses,
			eradiusServerNoRecords              = Counter#nas_counter.noRecords,
			eradiusServerBadAuthenticators      = Counter#nas_counter.badAuthenticators,
			eradiusServerPacketsDropped         = Counter#nas_counter.packetsDropped,
			eradiusServerUnknownTypes           = Counter#nas_counter.unknownTypes,
			eradiusServerHandlerFailure         = Counter#nas_counter.handlerFailure,
			eradiusServerCounterDiscontinuity   = tstamp_to_ticks(ResetTS)
		   }.

insert_server_counter({SrvCnt, {TStamp, NasCnt}}) ->
	lists:foreach(fun(Srv = #server_counter{key = {Server, Port}}) ->
						  {SAddrType, SAddr} = addr_to_snmp(Server),
						  SrvCntEntry = #eradiusServerTable{
							key                               = {SAddrType, SAddr, Port},
							eradiusServerIdent                = "no id",
							eradiusServerUpTime               = tstamp_to_ticks(Srv#server_counter.upTime),
							eradiusServerResetTime            = tstamp_to_ticks(Srv#server_counter.resetTime),
							eradiusServerInvalidRequests      = Srv#server_counter.invalidRequests,
							eradiusServerDiscardNoHandler     = Srv#server_counter.discardNoHandler
						   },
						  Nas = lists:keyfind(Srv#server_counter.key, #nas_counter.key, NasCnt),
						  SrvCntEntry1 = map_server_client_counter(TStamp, Nas, SrvCntEntry),
						  mnesia:dirty_write(SrvCntEntry1)
				  end, SrvCnt).

map_server_client_counter(_, false, SrvCntEntry) ->
	SrvCntEntry;
map_server_client_counter(ResetTS, Counter = #nas_counter{}, SrvCntEntry) ->
	SrvCntEntry#eradiusServerTable{
	  eradiusServerRequests               = Counter#nas_counter.requests,
	  eradiusServerReplies                = Counter#nas_counter.replies,
	  eradiusServerDupRequests            = Counter#nas_counter.dupRequests,
	  eradiusServerMalformedRequests      = Counter#nas_counter.malformedRequests,
	  eradiusServerAccessRequests         = Counter#nas_counter.accessRequests,
	  eradiusServerAccessAccepts          = Counter#nas_counter.accessAccepts,
	  eradiusServerAccessRejects          = Counter#nas_counter.accessRejects,
	  eradiusServerAccessChallenges       = Counter#nas_counter.accessChallenges,
	  eradiusServerAccountRequests        = Counter#nas_counter.accountRequests,
	  eradiusServerAccountResponses       = Counter#nas_counter.accountResponses,
	  eradiusServerNoRecords              = Counter#nas_counter.noRecords,
	  eradiusServerBadAuthenticators      = Counter#nas_counter.badAuthenticators,
	  eradiusServerPacketsDropped         = Counter#nas_counter.packetsDropped,
	  eradiusServerUnknownTypes           = Counter#nas_counter.unknownTypes,
	  eradiusServerHandlerFailure         = Counter#nas_counter.handlerFailure,
	  eradiusServerCounterDiscontinuity   = tstamp_to_ticks(ResetTS)
	 }.

tstamp_to_ticks(TStamp) ->
	round(timer:now_diff(now(), TStamp) / 10000).
