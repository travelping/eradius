-module(eradius_dict).
%%%----------------------------------------------------------------------
%%% File    : eradius_dict.erl
%%% Author  : Torbjorn Tornkvist <tobbe@bluetail.com>
%%% Purpose : Radius dictionary handling.
%%% Created : 25 Sep 2003 by Torbjorn Tornkvist <tobbe@bluetail.com>
%%%----------------------------------------------------------------------
-behaviour(gen_server).

%% External exports
-export([start/0,start_link/0, lookup/1]).
-export([load_tables/1, load_tables/2, mk_dict/1, parse_dict/1, make/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).


-include("eradius_dict.hrl").


-define(SERVER    , ?MODULE).
-define(TABLENAME , ?MODULE).

-record(state, {}).

%%%----------------------------------------------------------------------
%%% API
%%%----------------------------------------------------------------------

lookup(Id) -> 
    ets:lookup(?TABLENAME, Id).

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).
 
start() ->
    gen_server:start({local, ?SERVER}, ?MODULE, [], []).


load_tables(Tables) ->
    load_tables(code:priv_dir(eradius), Tables).
load_tables(Dir, Tables) ->
    gen_server:call(?SERVER, {load_tables, Dir, Tables}, infinity).

%%%----------------------------------------------------------------------
%%% Callback functions from gen_server
%%%----------------------------------------------------------------------

%%----------------------------------------------------------------------
%% Func: init/1
%% Returns: {ok, State}          |
%%          {ok, State, Timeout} |
%%          ignore               |
%%          {stop, Reason}
%%----------------------------------------------------------------------
init([]) ->
    process_flag(trap_exit, true),
    create_table(),
    {ok, #state{}}.

create_table() ->
    ets:new(?TABLENAME, [named_table, {keypos, 2}, public]).


%%----------------------------------------------------------------------
%% Func: handle_call/3
%% Returns: {reply, Reply, State}          |
%%          {reply, Reply, State, Timeout} |
%%          {noreply, State}               |
%%          {noreply, State, Timeout}      |
%%          {stop, Reason, Reply, State}   | (terminate/2 is called)
%%          {stop, Reason, State}            (terminate/2 is called)
%%----------------------------------------------------------------------
handle_call({load_tables, Dir, Tables}, _From, State) ->
    Res = (catch lists:foreach(fun(Tab) -> load_table(Dir, Tab) end, Tables)),
    {reply, Res, State}.

%%----------------------------------------------------------------------
%% Func: handle_cast/2
%% Returns: {noreply, State}          |
%%          {noreply, State, Timeout} |
%%          {stop, Reason, State}            (terminate/2 is called)
%%----------------------------------------------------------------------
handle_cast(_Msg, State) ->
    {noreply, State}.

%%----------------------------------------------------------------------
%% Func: handle_info/2
%% Returns: {noreply, State}          |
%%          {noreply, State, Timeout} |
%%          {stop, Reason, State}            (terminate/2 is called)
%%----------------------------------------------------------------------
handle_info(_Info, State) ->
    {noreply, State}.

%%----------------------------------------------------------------------
%% Func: terminate/2
%% Purpose: Shutdown the server
%% Returns: any (ignored by gen_server)
%%----------------------------------------------------------------------
terminate(_Reason, _State) ->
    ok.

%%%----------------------------------------------------------------------
%%% Internal functions
%%%----------------------------------------------------------------------


%%% --------------------------------------------------------------------
%%% Load dictionary table
%%% --------------------------------------------------------------------

load_table(Dir, Table) ->
    MapFile = Dir ++ "/" ++ Table ++ ".map",
    case file:consult(MapFile) of
	{ok, Res} ->
	    lists:foreach(fun(R) -> ets:insert(?TABLENAME, R) end, Res),
	    ok;
	_ ->
	    {error, load_table}
    end.
			  


%%% --------------------------------------------------------------------
%%% Dictionary making
%%% --------------------------------------------------------------------

%%% Assume this function is called from the Makefile in the priv dir.
make([File]) ->
    {ok, Dir} = file:get_cwd(),
    mk_dict(Dir ++ "/" ++ atom_to_list(File)),
    init:stop().
    

mk_dict(File) ->
    Res = parse_dict(File),
    Dir = dir(?MODULE),
    mk_outfiles(Res, Dir, o2u(File)).

mk_outfiles(Res, Dir, File) ->
    {Hrl, Map} = open_files(Dir, File),
    emit(Res, Hrl, Map),
    close_files(Hrl, Map).

%% emit([A|T], Hrl, Map) when is_record(A, attribute), A#attribute.attrs =:= undefined ->
%%     io:format(Hrl, "-define( ~s , ~w ).~n", 
%% 	      [d2u(A#attribute.name), A#attribute.id]),
%%     io:format(Map, "{attribute, ~w, ~w, \"~s\"}.~n", 
%% 	      [A#attribute.id, A#attribute.type, A#attribute.name]),
%%     emit(T, Hrl, Map);

emit([A|T], Hrl, Map) when is_record(A, attribute) ->
    io:format(Hrl, "-define( ~s , ~w ).~n", 
	      [d2u(A#attribute.name), A#attribute.id]),
    io:format(Map, "{attribute, ~w, ~w, \"~s\", ~p}.~n", 
	      [A#attribute.id, A#attribute.type, A#attribute.name, A#attribute.enc]),
    emit(T, Hrl, Map);

emit([V|T], Hrl, Map) when is_record(V, vendor) ->
    io:format(Hrl, "-define( ~s , ~w ).~n", 
	      [d2u(V#vendor.name), V#vendor.type]),
    io:format(Map, "{vendor, ~w, \"~s\"}.~n", 
	      [V#vendor.type, V#vendor.name]),
    emit(T, Hrl, Map);
emit([V|T], Hrl, Map) when is_record(V, value) ->
%%    io:format(Hrl, "-define( ~s , ~w ).~n", 
%%	      [V#value.attribute, d2u(V#value.name), V#value.id]),
    io:format(Map, "{value, ~w, \"~s\"}.~n", 
	      [V#value.id, V#value.name]),
    emit(T, Hrl, Map);
emit([_|T], Hrl, Map) ->
    emit(T, Hrl, Map);
emit([], _, _) ->
    true.

open_files(Dir, File) ->
    [Name|_] = lists:reverse(string:tokens(File, "/")),
    Hfile = Dir ++ "/include/" ++ Name ++ ".hrl",
    {ok,Hrl} = file:open(Hfile, [write]),
    Mfile = Dir ++ "/priv/" ++ Name ++ ".map",
    {ok,Map} = file:open(Mfile, [write]),
    io:format("Creating files: ~n  <~s>~n  <~s>~n", [Hfile, Mfile]),
    {Hrl, Map}.

close_files(Hrl, Map) ->
    file:close(Hrl),
    file:close(Map).

parse_dict(File) when is_list(File) ->
    {ok,B} = file:read_file(File),
    F = fun(Line,{undefined = Vendor, AccList}) ->
                case pd(string:tokens(Line,"\s\t\r")) of
                    {ok,E} -> {Vendor, [E|AccList]};
                    {begin_vendor, VendId} -> {{vendor, VendId}, AccList};
                    _      -> {Vendor, AccList}
                end;
           (Line, {{vendor, VendId} = Vendor, AccList}) ->
                case pd(string:tokens(Line, "\s\t\r"), VendId) of
                    {end_vendor} -> {undefined, AccList};
                    {ok,E} -> {Vendor, [E|AccList]};
                    _ -> {Vendor, AccList}
                end
	end,
    {_, L} = lists:foldl(F,{undefined, []},string:tokens(b2l(B),"\n")),
    L.

paa(Attr, ["has_tag"]) ->
    Attr#attribute{ type = {tagged, Attr#attribute.type} };

paa(Attr, ["encrypt", Enc]) ->
    case l2i(Enc) of
	1 -> Attr#attribute{ enc = scramble };
	2 -> Attr#attribute{ enc = salt_crypt };
	_ -> Attr
    end;

paa(Attr, [Vendor]) ->
    case get({vendor, Vendor}) of
	undefined -> Attr;
	VendId -> Attr#attribute{ id = {VendId, Attr#attribute.id} }
    end.

parse_attribute_attrs(Attr, []) ->
    Attr;

parse_attribute_attrs(Attr, [ [$# | _ ] | _]) ->
    Attr;

parse_attribute_attrs(Attr, [Attribute|Tail]) ->
    [Token | Rest] = string:tokens(Attribute, ","),
    NewAttr = paa(Attr, string:tokens(Token, "=")),
    parse_attribute_attrs(NewAttr, Rest ++ Tail).

pd(["BEGIN-VENDOR", Name]) ->
    case get({vendor, Name}) of
	undefined -> {begin_vendor, Name};
	VendId -> {begin_vendor, VendId}
    end;

pd(["VENDOR", Name, Id]) ->
    put({vendor,Name}, l2i(Id)),
    {ok, #vendor{type = l2i(Id), name = Name}};

pd(["ATTRIBUTE", Name, Id, Type | Tail]) -> 
    Attr = parse_attribute_attrs(#attribute{name = Name, id = id2i(Id), type = l2a(Type)}, Tail),
    put({attribute, Attr#attribute.name}, Attr#attribute.id),
    {ok, Attr};

pd(["VALUE", Attr, Name, Id]) -> 
    case get({attribute, Attr}) of
	undefined ->
	    io:format("missing: ~p~n", [Attr]),
	    false;
	AttrId ->
	    {ok,#value{id = {AttrId, id2i(Id)}, name = Name}}
    end;
pd(_X) -> 
    %%io:format("Skipping: ~p~n", [X]),
    false.

pd(["END-VENDOR", _Name], _VendId) ->
    {end_vendor};

pd(["ATTRIBUTE", Name, Id, Type | Tail], VendId) -> 
    Attr = parse_attribute_attrs(#attribute{name = Name, id = {VendId, id2i(Id)}, type = l2a(Type)}, Tail),
    put({attribute, Attr#attribute.name}, Attr#attribute.id),
    {ok, Attr};

pd(["VALUE", Attr, Name, Id], _VendId) -> 
    case get({attribute, Attr}) of
	undefined ->
	    io:format("missing: ~p~n", [Attr]),
	    false;
	AttrId ->
	    {ok,#value{id = {AttrId, id2i(Id)}, name = Name}}
    end;
pd(_X, _VendId) ->
    %%io:format("Skipping: ~p~n", [_X]),
    false.


priv_dir() ->
    dir(?MODULE) ++ "/priv".

dir(Mod) ->
    P = code:which(Mod),
    [_,_|R] = lists:reverse(string:tokens(P,"/")),
    lists:foldl(fun(X,Acc) -> Acc ++ [$/|X] end, "", lists:reverse(R)).

id2i(Id) ->
    case catch l2i(Id) of
	I when is_integer(I) -> I;
	{'EXIT', _} ->
	    hex2i(Id)
    end.

hex2i("0x" ++ L) -> erlang:list_to_integer(L, 16).

b2l(B) when is_binary(B) -> binary_to_list(B);
b2l(L) when is_list(L)   -> L.

l2i(L) when is_list(L)    -> list_to_integer(L);
l2i(I) when is_integer(I) -> I.

l2a(L) when is_list(L) -> list_to_atom(L);
l2a(A) when is_atom(A) -> A.

%%% Replace all dashes with underscore characters.
d2u(L) when is_list(L) ->
    repl(L, $-, $_).

%%% Replace all dots with underscore characters.
o2u(L) when is_list(L) ->
    repl(L, $., $_).

repl(L,X,Y) when is_list(L) ->
    F = fun(Z) when Z == X -> Y;
	   (C) -> C
	end,
    lists:map(F,L).

