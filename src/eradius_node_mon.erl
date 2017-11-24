%% @private
%% @doc A server that keeps track of handler nodes.
%%   Handler nodes should call {@link eradius:modules_ready/2} from their application master
%%   as soon as they are ready, which makes them available for request processing.
%%   The node_mon server monitors the application master and removes it from
%%   request processing when it goes down.
-module(eradius_node_mon).
-export([start_link/0, modules_ready/2, set_nodes/1, get_module_nodes/1, get_remote_version/1]).

-behaviour(gen_server).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-define(NODE_TAB, eradius_node_mon).
-define(NODE_INFO_TAB, eradius_node_info).
-define(PING_INTERVAL, 3000). % 3 sec
-define(PING_TIMEOUT, 300).   % 0.3 sec
-define(SERVER, ?MODULE).

%% ------------------------------------------------------------------------------------------
%% -- API
start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

-spec modules_ready(pid(), list(module())) -> ok.
modules_ready(ApplicationMaster, Modules) when is_pid(ApplicationMaster), is_list(Modules) ->
    gen_server:cast(?SERVER, {modules_ready, ApplicationMaster, Modules}).

-spec set_nodes(list(node())) -> ok.
set_nodes(Nodes) ->
    gen_server:call(?SERVER, {set_nodes, Nodes}).

-spec get_module_nodes(module()) -> [node()].
get_module_nodes(Module) ->
    try
        ets:lookup_element(?NODE_TAB, Module, 2)
    catch
        error:badarg ->
            []
    end.

-spec get_remote_version(node()) -> {integer(), integer()} | undefined.
get_remote_version(Node) ->
    try
        ets:lookup_element(?NODE_INFO_TAB, Node, 2)
    catch
        error:badarg ->
            undefined
    end.

%% ------------------------------------------------------------------------------------------
%% -- gen_server callbacks
-record(state, {
    live_registrar_nodes = sets:new() :: sets:set(),
    dead_registrar_nodes = sets:new() :: sets:set(),
    app_masters = maps:new()          :: map(),
    ping_timer                        :: reference()
}).

init([]) ->
    ets:new(?NODE_TAB, [bag, named_table, protected, {read_concurrency, true}]),
    ets:new(?NODE_INFO_TAB, [set, named_table, protected, {read_concurrency, true}]),
    PingTimer = erlang:send_after(?PING_INTERVAL, self(), ping_dead_nodes),
    {ok, #state{ping_timer = PingTimer}}.

handle_call(remote_get_regs_v1, From, State) ->
    check_eradius_version(From),
    Registrations = maps:to_list(State#state.app_masters),
    {reply, {ok, Registrations}, State};
handle_call({set_nodes, Nodes}, _From, State) ->
    NewState = State#state{live_registrar_nodes = sets:new(),
                           dead_registrar_nodes = sets:from_list(Nodes)},
    self() ! ping_dead_nodes,
    {reply, ok, NewState}.

handle_cast({remote_modules_ready_v1, ApplicationMaster, Modules}, State) ->
    NewState = State#state{app_masters = register_locally({ApplicationMaster, Modules}, State#state.app_masters)},
    {noreply, NewState};
handle_cast({modules_ready, ApplicationMaster, Modules}, State) ->
    NewState = State#state{app_masters = register_locally({ApplicationMaster, Modules}, State#state.app_masters)},
    lists:foreach(fun (Node) ->
                      check_eradius_version(Node),
                      gen_server:cast({?SERVER, Node}, {remote_modules_ready_v1, ApplicationMaster, Modules})
                  end, nodes()),
    {noreply, NewState}.

handle_info({'DOWN', _MRef, process, {?SERVER, Node}, _Reason}, State = #state{live_registrar_nodes = LiveRegistrars}) ->
    case sets:is_element(Node, LiveRegistrars) of
        false ->
            %% ignore the 'DOWN', it's from a node we don't really want to monitor anymore
            %% and that shouldn't get into dead_registrar_nodes
            {noreply, State};
        true ->
            {noreply, State#state{live_registrar_nodes = sets:del_element(Node, LiveRegistrars),
                                  dead_registrar_nodes = sets:add_element(Node, State#state.dead_registrar_nodes)}}
    end;
handle_info({'DOWN', _MRef, process, Pid, _Reason}, State = #state{app_masters = AppMasters}) when is_pid(Pid) ->
    case maps:find(Pid, AppMasters) of
        error ->
            {noreply, State};
        {ok, Modules} ->
            ServerNode = node(Pid),
            lists:foreach(fun (Mod) -> ets:delete_object(?NODE_TAB, {Mod, ServerNode}) end, Modules),
            NewState = State#state{app_masters = maps:remove(Pid, AppMasters)},
            {noreply, NewState}
    end;
handle_info(ping_dead_nodes, State = #state{app_masters = AppMasters, live_registrar_nodes = LiveRegistrars}) ->
    erlang:cancel_timer(State#state.ping_timer),
    {NewLive, NewDead, NewAppMasters} =
        sets:fold(fun (Node, {Live, Dead, AppMastersAcc}) ->
                          case (catch gen_server:call({?SERVER, Node}, remote_get_regs_v1, ?PING_TIMEOUT)) of
                              {ok, Registrations} ->
                                  NewAppMastersAcc = lists:foldl(fun register_locally/2, AppMastersAcc, Registrations),
                                  erlang:monitor(process, {?SERVER, Node}),
                                  {sets:add_element(Node, Live), Dead, NewAppMastersAcc};
                              {'EXIT', _Reason} ->
                                  {Live, sets:add_element(Node, Dead), AppMastersAcc}
                          end
                  end, {LiveRegistrars, sets:new(), AppMasters}, State#state.dead_registrar_nodes),
    NewPingTimer = erlang:send_after(?PING_INTERVAL, self(), ping_dead_nodes),
    NewState = State#state{live_registrar_nodes = NewLive,
                           dead_registrar_nodes = NewDead,
                           app_masters = NewAppMasters,
                           ping_timer = NewPingTimer},
    {noreply, NewState};
handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) -> ok.
code_change(_OldVsn, State, _Extra) -> {ok, State}.

%% ------------------------------------------------------------------------------------------
%% -- helpers
-spec dict_prepend(term(), list(term()), map()) -> map().
dict_prepend(Key, List, Map) ->
    update_with(Key, fun (Old) -> List ++ Old end, List, Map).

% NOTE:
% copy-pasted from maps.erl to have backward compatability with OTP 18
% it can be rewmoved if minimal version of OTP will be set to 19.
update_with(Key,Fun,Init,Map) when is_function(Fun,1), is_map(Map) ->
    case maps:find(Key,Map) of
        {ok,Val} -> maps:update(Key,Fun(Val),Map);
        error -> maps:put(Key,Init,Map)
    end;
update_with(Key,Fun,Init,Map) ->
    erlang:error(error_type(Map),[Key,Fun,Init,Map]).

-define(IS_ITERATOR(I), is_tuple(I) andalso tuple_size(I) == 3; I == none; is_integer(hd(I)) andalso is_map(tl(I))).
error_type(M) when is_map(M); ?IS_ITERATOR(M) -> badarg;
error_type(V) -> {badmap, V}.

register_locally({ApplicationMaster, Modules}, AppMasters) ->
    case maps:is_key(ApplicationMaster, AppMasters) of
        true ->
            ok; %% already monitored
        false ->
            monitor(process, ApplicationMaster)
    end,
    ServerNode = node(ApplicationMaster),
    ets:insert(?NODE_TAB, [{Mod, ServerNode} || Mod <- Modules]),
    dict_prepend(ApplicationMaster, Modules, AppMasters).

check_eradius_version({Pid, _}) when is_pid(Pid) ->
    check_eradius_version(Pid);
check_eradius_version(Pid) when is_pid(Pid) ->
    check_eradius_version(node(Pid));
check_eradius_version(Node) ->
    case rpc:call(Node, application, get_key, [eradius, vsn]) of
        {ok, Vsn} ->
            try interpret_vsn(Vsn) of
                Version ->
                    ets:insert(?NODE_INFO_TAB, {Node, Version})
            catch
                _:_ ->
                    lager:warning("unknown eradius version format ~p on node ~p", [Vsn, Node])
            end;
        _ ->
            lager:warning("eradius version do not known on node ~p", [Node])
    end.

interpret_vsn(Vsn) ->
    BinVsn = list_to_binary(Vsn),
    [MajorVsn, MinorVsn | _] = binary:split(BinVsn, <<".">>, [global]),
    {binary_to_integer(MajorVsn), binary_to_integer(MinorVsn)}.
