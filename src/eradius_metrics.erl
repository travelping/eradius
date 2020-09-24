-module(eradius_metrics).

-include("eradius_metrics.hrl").
-include("eradius_lib.hrl").

-export([create_server/1,
         create_nas/1,
         create_client/1,
         delete_server/1,
         delete_nas/1,
         delete_client/1]).
-export([update_server_request/3, update_server_response/2, update_server_time/2,
         update_nas_request/3, update_nas_response/2, update_nas_time/2,
         update_client_request/3, update_client_response/2, update_client_time/2]).
-export([make_addr_info/1, timestamp/1, update_uptime/2, update_since_last_request/2]).

%% -------------------------------------------------------
%% API for metric creation.
%% -------------------------------------------------------
-spec create_server(atom_address()) -> ok.
create_server(Address) ->
    create(server, Address).

-spec delete_server(atom_address()) -> ok.
delete_server(Address) ->
    delete(server, Address).

-spec create_nas(atom_address_pair()) -> ok.
create_nas({{SName, SIP, SPort}, {NID, NIP, _NPort}}) ->
    create(nas, {SName, SIP, SPort, NID, NIP}).

-spec delete_nas(atom_address_pair()) -> ok.
delete_nas({{SName, SIP, SPort}, {NID, NIP, _NPort}}) ->
    delete(nas, {SName, SIP, SPort, NID, NIP}).

-spec create_client(atom_address_pair()) -> ok.
create_client({{CName, CIP, undefined}, {SName, SIP, SPort}}) ->
    create(client, {CName, CIP, SName, SIP, SPort}).

-spec delete_client(atom_address_pair()) -> ok.
delete_client({{CName, CIP, undefined}, {SName, SIP, SPort}}) ->
    delete(client, {CName, CIP, SName, SIP, SPort}).

%% -------------------------------------------------------
%% API for metric updates.
%% -------------------------------------------------------
-spec update_server_request(atom(), atom_address(), integer()) -> any().
update_server_request("pending", Address, Pending) ->
    update_request(server, "pending", Address, Pending);
update_server_request(Type, Address, Ms) ->
    [update_request(server, ReqType, Address, Ms) || ReqType <- [Type, "total"]],
    update_server_time("last_request", Address).

-spec update_server_response(atom(), atom_address()) -> any().
update_server_response(Type, Address) ->
    [update_response(server, ReqType, Address) || ReqType <- [Type, "total"]].

-spec update_server_time(last_reset | last_config_reset | last_request, atom_address()) -> any().
update_server_time(Type, Address) ->
    update_time(server, Type, Address).

-spec update_nas_request(atom(), atom_address_pair(), integer()) -> any().
update_nas_request("pending", {ServerAddress = {SName, SIP, SPort}, {NID, NIP, _NPort}}, Pending) ->
    update_server_request("pending", ServerAddress, Pending),
    update_request(nas, "pending", {SName, SIP, SPort, NID, NIP}, Pending);
update_nas_request(Type, MetricsInfo = {ServerAddress = {SName, SIP, SPort}, {NID, NIP, _NPort}}, Ms) ->
    update_server_request(Type, ServerAddress, Ms),
    [update_request(nas, ReqType, {SName, SIP, SPort, NID, NIP}, Ms) || ReqType <- [Type, "total"]],
    update_nas_time(last_request, MetricsInfo).

-spec update_nas_response(atom(), atom_address_pair()) -> any().
update_nas_response(Type, {ServerAddress = {SName, SIP, SPort}, {NID, NIP, _NPort}}) ->
    update_server_response(Type, ServerAddress),
    [update_response(nas, ReqType, {SName, SIP, SPort, NID, NIP}) || ReqType <- [Type, "total"]].

-spec update_nas_time(last_request, atom_address_pair()) -> any().
update_nas_time(last_request, {{SName, SIP, SPort}, {NID, NIP, _NPort}}) ->
    update_time(nas, "last_request", {SName, SIP, SPort, NID, NIP}).

-spec update_client_request(atom(), atom_address_pair(), integer()) -> any().
update_client_request("pending", {{CName, CIP, undefined}, {SName, SIP, SPort}}, Pending) ->
    update_request(client, "pending", {CName, CIP, SName, SIP, SPort}, Pending);
update_client_request("retransmission", {{CName, CIP, undefined}, {SName, SIP, SPort}}, Ms) ->
    update_request(client, "retransmission", {CName, CIP, SName, SIP, SPort}, Ms);
update_client_request(Type, MetricsInfo = {{CName, CIP, undefined}, {SName, SIP, SPort}}, Ms) ->
    [update_request(client, ReqType, {CName, CIP, SName, SIP, SPort}, Ms) || ReqType <- [Type, "total"]],
    update_client_time(last_request, MetricsInfo).

-spec update_client_response(atom(), atom_address_pair()) -> any().
update_client_response(Type, {{CName, CIP, undefined}, {SName, SIP, SPort}}) ->
    [update_response(client, ReqType, {CName, CIP, SName, SIP, SPort}) || ReqType <- [Type, "total"]].

-spec update_client_time(last_request, atom_address_pair()) -> any().
update_client_time(last_request, {{CName, CIP, undefined}, {SName, SIP, SPort}}) ->
    update_time(client, "last_request", {CName, CIP, SName, SIP, SPort}).

-spec make_addr_info({term(), {inet:ip_address(), integer()}}) -> atom_address().
make_addr_info({undefined, {IP, Port}}) ->
    {socket_to_atom(IP, Port), ip_to_atom(IP), port_to_atom(Port)};
make_addr_info({Name, {IP, Port}}) ->
    {to_atom(Name), ip_to_atom(IP), port_to_atom(Port)}.

-spec timestamp(erlang:time_unit()) -> integer().
timestamp(Unit) ->
    erlang:system_time(Unit).

%% -----------------------------------------------------------------
%% Internal
%% -----------------------------------------------------------------
create(Service, Args) ->
    metrics_action(create, Service, Args).

delete(Service, Args) ->
    metrics_action(delete, Service, Args).

metrics_action(Action, Service, Args) ->
    Metrics = proplists:get_value(Service, ?METRICS, undefined),
    {ok, MetricsOpts} = application:get_env(eradius, metrics),
    EnabledServices = proplists:get_value(enabled, MetricsOpts, []),
    case lists:member(Service, EnabledServices) of
        true ->
            proceed_metrics_action(Action, Service, Args, Metrics);
        false ->
            ok
    end.

%% this function traverses the datastructures in eradius_metrics.hrl
proceed_metrics_action(Action, Service, Args, Metrics) ->
    lists:foreach(
        fun({MetricName, MetricType, Units}) ->
            lists:foreach(
                fun({UnitType, {ExoType, _ExoTypeOpts}}) ->
                    {PartId, Labels, _} = case Service of
                                              server    -> server_layout(Args);
                                              nas       -> nas_layout(Args);
                                              client    -> client_layout(Args)
                                          end,

                    %% this is the final id of the metric
                    FinalId = list_to_binary([?DEFAULT_ENTRIES, "_", MetricName, "_", MetricType, "_", PartId, "_", UnitType]),
                    case Action of
                      create ->
                        case ExoType of
                          {function,_,_,_,_,_} ->
                            try
                              MetricCb = element(3, ExoType),
                              prometheus_gauge:declare([{name, FinalId}, {help, ""}, {labels, Labels}]),
                              % update UpTime metric each 5000 seconds
                              timer:apply_interval(5000, ?MODULE, MetricCb, [Service, Args])
                              catch _:_ -> ok
                              end;
                          _ ->
                            create_metric(FinalId, Labels, ExoType)
                          end;
                      delete ->
                        delete_metric(FinalId, Labels, ExoType)
                    end
                end, Units)
        end, Metrics).

create_metric(Name, Labels, counter) ->
    prometheus_counter:declare([{name, Name}, {help, ""}, {labels, Labels}]);
create_metric(Name, Labels, histogram) ->
    prometheus_histogram:declare([{name, Name}, {help, ""}, {labels, Labels}, {buckets, [10, 30, 50, 75, 100, 1000, 2000]}]);
create_metric(Name, Labels, gauge) ->
    prometheus_gauge:declare([{name, Name}, {help, ""}, {labels, Labels}]);
create_metric(_, _, _) ->
    ok.

delete_metric(Name, Labels, counter) ->
    prometheus_counter:remove(Name, Labels);
delete_metric(Name, Labels, histogram) ->
    prometheus_histogram:remove(Name, Labels);
delete_metric(Name, Labels, gauge) ->
    prometheus_gauge:remove(Name, Labels);
delete_metric(_, _, _) ->
    ok.

update_request(server, Type, Args, Ms) ->
    Args1 = server_layout(Args),
    update_exo_request(Type, Args1, Ms);
update_request(nas, Type, Args, Ms) ->
    Args1 = nas_layout(Args),
    update_exo_request(Type, Args1, Ms);
update_request(client, Type, Args, Ms) ->
    Args1 = client_layout(Args),
    update_exo_request(Type, Args1, Ms).

update_response(server, Type, Args) ->
    Args1 = server_layout(Args),
    update_exo_request(Type, Args1);
update_response(nas, Type, Args) ->
    Args1 = nas_layout(Args),
    update_exo_request(Type, Args1);
update_response(client, Type, Args) ->
    Args1 = client_layout(Args),
    update_exo_request(Type, Args1).

update_time(server, Type, Args) ->
    Sec = timestamp(milli_seconds),
    Args1 = server_layout(Args),
    update_exo_time(Type, Args1, Sec);
update_time(nas, Type, Args) ->
    Sec = timestamp(milli_seconds),
    Args1 = nas_layout(Args),
    update_exo_time(Type, Args1, Sec);
update_time(client, Type, Args) ->
    Sec = timestamp(milli_seconds),
    Args1 = client_layout(Args),
    update_exo_time(Type, Args1, Sec).

update_exo_request("pending", {Args, _, Labels}, Value) ->
    Id = list_to_binary([?DEFAULT_ENTRIES, "_", "request", "_", "pending", "_", Args, "_counter"]),
    try
        if Value < 0 ->
                prometheus_gauge:dec(Id, Labels);
           true ->
                prometheus_gauge:inc(Id, Labels)
        end
    catch _:_ ->
            undefined
    end;

update_exo_request(Type, {Args, _, Labels}, Ms) ->
    IdCounter = list_to_binary([?DEFAULT_ENTRIES, "_", "request", "_", Type, "_", Args, "_counter"]),
    IdHistogram = list_to_binary([?DEFAULT_ENTRIES, "_", "request", "_", Type, "_", Args, "_gauge"]),
    try
        prometheus_histogram:observe(IdHistogram, Labels, Ms),
        prometheus_counter:inc(IdCounter, Labels)
    catch _:_ ->
            undefined
    end.

update_exo_request(Type, {Args, _, Labels}) ->
    Id = list_to_binary([?DEFAULT_ENTRIES, "_", "response", "_", Type, "_", Args, "_counter"]),
    try
        prometheus_counter:inc(Id, Labels)
    catch _:_ ->
            undefined
    end.

update_exo_time(Type, {Args, _, Labels}, Sec) ->
    Id = list_to_binary([?DEFAULT_ENTRIES, "_", "time", "_", Type, "_", Args, "_ticks"]),
    try
        prometheus_gauge:set(Id, Labels, Sec)
    catch _:_ ->
        undefined
    end.

server_layout({ServerName, ServerIP, ServerPort}) ->
    Server = atom_to_list(ServerName),
    IP = string:join(string:replace(atom_to_list(ServerIP), ".", "_", all), ""),
    Port = atom_to_list(ServerPort),
    {list_to_binary(["server", "_", "total", "_", "undefined", "_", "undefined"]),
     [server_name, server_ip, server_port],
     [Server, IP, Port]}.
nas_layout({ServerName, ServerIP, ServerPort, NasId, NasIP}) ->
    Server = atom_to_list(ServerName),
    IP = string:join(string:replace(atom_to_list(ServerIP), ".", "_", all), ""),
    Port = atom_to_list(ServerPort),
    NasIdList = string:join(string:replace(atom_to_list(NasId), ".", "_", all), ""),
    NasIPList = string:join(string:replace(atom_to_list(NasIP), ".", "_", all), ""),
    {list_to_binary(["server", "_", "undefined"]),
     [server_name, server_ip, server_port, nas_id, nas_ip],
     [Server, IP, Port, NasIdList, NasIPList]}.
client_layout({ClientName, ClientIP, ServerName, ServerIP, ServerPort}) ->
    Client = atom_to_list(ClientName),
    CIP = string:join(string:replace(atom_to_list(ClientIP), ".", "_", all), ""),
    Server = string:join(string:replace(atom_to_list(ServerName), ".", "_", all), ""),
    SIP = string:join(string:replace(atom_to_list(ServerIP), ".", "_", all), ""),
    SPort = atom_to_list(ServerPort),
    {list_to_binary(["client", "_", "undefined"]),
     [client_name, client_ip, server_name, server_ip, server_port],
     [Client, CIP, Server, SIP, SPort]}.

to_atom(Value) when is_atom(Value) -> Value;
to_atom(Value) when is_binary(Value) -> binary_to_atom(Value, latin1);
to_atom(Value) when is_list(Value) -> list_to_atom(Value).

socket_to_atom(IP, undefined) ->
    ip_to_atom(IP);
socket_to_atom(IP, Port) when is_tuple(IP) ->
    list_to_atom(inet:ntoa(IP) ++ ":" ++ integer_to_list(Port));
socket_to_atom(IP, Port) when is_binary(IP) ->
    binary_to_atom(erlang:iolist_to_binary([IP, <<":">>, Port]), latin1);
socket_to_atom(IP, Port) when is_atom(IP) ->
    binary_to_atom(erlang:iolist_to_binary([atom_to_binary(IP, latin1), <<":">>, Port]), latin1).

ip_to_atom(IP) when is_atom(IP) -> IP;
ip_to_atom(IP) -> list_to_atom(inet:ntoa(IP)).

port_to_atom(undefined) -> undefined;
port_to_atom(Port) when is_atom(Port) -> Port;
port_to_atom(Port) -> list_to_atom(integer_to_list(Port)).

update_uptime(server, ServerAddress) ->
    {Args, _, Labels} = server_layout(ServerAddress),
    LastResetId = list_to_binary([?DEFAULT_ENTRIES, "_", "time", "_", "last_reset", "_", Args, "_", "ticks"]),
    try
        LastReset = prometheus_gauge:value(LastResetId, Labels),
        Uptime = round(timestamp(milli_seconds) - LastReset),
        prometheus_gauge:set(list_to_binary([?DEFAULT_ENTRIES, "_", "time", "_", "up", "_", Args, "_", "ticks"]), Labels, Uptime)
    catch _:_ ->
            undefined
    end.

update_since_last_request(Service, Address) ->
    {Args, _, Labels} = case Service of
                            server    -> server_layout(Address);
                            nas       -> nas_layout(Address);
                            client    -> client_layout(Address)
                     end,
    LastRequestId = list_to_binary([?DEFAULT_ENTRIES, "_", "time", "_", "last_request", "_", Args, "_", "ticks"]),
    try
        LastRequestTs = prometheus_gauge:value(LastRequestId, Labels),
        NewValue = round(timestamp(milli_seconds) - LastRequestTs),
        prometheus_gauge:set(list_to_binary([?DEFAULT_ENTRIES, "_", "time", "_", "since_last_request", "_", Args, "_", "ticks"]),
                             Labels, NewValue)
    catch _:_ ->
            undefined
    end.
