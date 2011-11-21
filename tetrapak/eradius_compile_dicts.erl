-include("eradius_dict.hrl").

-task({"build:dicts", "Compile eradius dictionaries"}).
-task({"clean:dicts", "Delete compiled dictionaries"}).
-hook({"build:dicts", run_before, "build:erlang"}).

check("build:dicts") ->
    InDir  = tetrapak:path("priv/dictionaries"),
    OutDir = tetrapak:path("include"),
    Files  = [{filename:join(InDir, F), filename:join(OutDir, re:replace(F, "\\.", "_", [{return, list}]) ++ ".hrl")}
                 || F <- filelib:wildcard("*", InDir)],
    tpk_util:check_files_mtime(Files).

run("build:dicts", DictFiles) ->
    lists:foreach(fun ({F, _}) -> mk_dict(F) end, DictFiles);

run("clean:dicts", _) ->
    tpk_file:delete("\\.map$", tetrapak:path("priv")),
    tpk_file:delete("dictionary.*\\.hrl", tetrapak:path("include")).


%%% --------------------------------------------------------------------
%%% Dictionary making
%%% --------------------------------------------------------------------

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
    io:format(Map, "~w.~n", [A]),
    emit(T, Hrl, Map);

emit([V|T], Hrl, Map) when is_record(V, vendor) ->
    io:format(Hrl, "-define( ~s , ~w ).~n",
	      [d2u(V#vendor.name), V#vendor.type]),
    io:format(Map, "~w.~n", [V]),
    emit(T, Hrl, Map);
emit([V|T], Hrl, Map) when is_record(V, value) ->
%%    io:format(Hrl, "-define( ~s , ~w ).~n",
%%	      [V#value.attribute, d2u(V#value.name), V#value.id]),
    io:format(Map, "~w.~n", [V]),
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
