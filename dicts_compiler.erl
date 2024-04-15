#!/usr/bin/env escript
%%%-------------------------------------------------------------------
%%% @author sdhillon
%%% @copyright (C) 2014, <COMPANY>
%%% @doc
%%%
%%% @end
%%% Created : 16. Nov 2014 6:25 PM
%%%-------------------------------------------------------------------
-include("include/eradius_dict.hrl").

main(["compile"]) -> compile();
main(["clean"]) -> clean();
main(_) -> ok.

compile() ->
    case find_files("priv/dictionaries", "^dictionary.*") of
        [] -> 
            ok;
        Dictionaries0 ->
            {ok, Basedir} = file:get_cwd(),
            IncludeDir = filename:join([Basedir, "include"]),
            ok = filelib:ensure_dir(IncludeDir),
                                                % sort dictionaries in alphabetical order to be sure that
                                                % basic `priv/dictionaries/dictionary` builds first
                                                % because it contains some attributes which may be needed 
                                                % for vendor's dictionaries
            Dictionaries = lists:sort(Dictionaries0),
            Targets = [{Dictionary, out_files(Dictionary)} || Dictionary <- Dictionaries],
            compile_each(Targets)
    end.

clean() ->
    case find_files("priv/dictionaries", "^dictionary.*") of
        [] -> 
            ok;
        Dictionaries ->
            Targets = [{Dictionary, out_files(Dictionary)} || Dictionary <- Dictionaries],
            clean_each(Targets)
    end.

find_files(Dir, Regex) ->
    find_files(Dir, Regex, true).

find_files(Dir, Regex, Recursive) ->
    filelib:fold_files(Dir, Regex, Recursive,
                       fun(F, Acc) -> [F | Acc] end, []).

out_files(DictionaryFile) ->
    {ok, Basedir} = file:get_cwd(),
    DictionaryFileBase = filename:basename(DictionaryFile),
    OutfileBase = re:replace(DictionaryFileBase, "\\.", "_", [global, {return, list}]),
    Headerfile = string:join([OutfileBase, "hrl"], "."),
    HeaderfileFQ = filename:join([Basedir, "include", Headerfile]),
    Mapfile = string:join([OutfileBase, "map"], "."),
    MapfileFQ = filename:join([Basedir, "priv", Mapfile]),
    {HeaderfileFQ, MapfileFQ}.

needs_compile(Src, Target) ->
    filelib:last_modified(Src) > filelib:last_modified(Target).

compile_each([]) ->
    ok;
compile_each([{Dictionary, {Headerfile, Mapfile}}|Rest]) ->
    case needs_compile(Dictionary, Headerfile)
        or needs_compile(Dictionary, Mapfile) of
        false ->
            compile_each(Rest);
        true ->
            Res = parse_dict(Dictionary),
            {ok, Hrl} = file:open(Headerfile, [write]),
            {ok, Map} = file:open(Mapfile, [write]),
            emit(Res, {Hrl, Headerfile}, Map),
            io:format("Compiled ~s~n", [Dictionary]),
            compile_each(Rest)
    end.

clean_each([]) ->
    ok;
clean_each([{_Dictionary, {Headerfile, Mapfile}}|Rest]) ->
    file:delete(Headerfile),
    file:delete(Mapfile),
    clean_each(Rest).

%%% --------------------------------------------------------------------
%%% Dictionary making
%%% --------------------------------------------------------------------
emit([A|T], {HrlPid, _} = Hrl, Map) when is_record(A, attribute) ->
    io:format(HrlPid, "-define( '~s' , ~w ).~n",
              [d2u(A#attribute.name), A#attribute.id]),
    io:format(Map, "~110p.~n", [A]),
    emit(T, Hrl, Map);
emit([V|T], {HrlPid, _} = Hrl, Map) when is_record(V, vendor) ->
    io:format(HrlPid, "-define( '~s' , ~w ).~n",
              [d2u(V#vendor.name), V#vendor.type]),
    io:format(Map, "~p.~n", [V]),
    emit(T, Hrl, Map);
emit([V|T], Hrl, Map) when is_record(V, value) ->
    io:format(Map, "~100p.~n", [V]),
    emit(T, Hrl, Map);
emit([{include, Include}|T], {HrlPid, _} = Hrl, Map) ->
    EscapedInclude = re:replace(Include, "\\.", "_", [global, {return, list}]),
    io:format(HrlPid, "-include( \"~s.hrl\" ).~n", [EscapedInclude]),
                                                % No need to add ".map" extension here. It will be added by eradius_dict
                                                % server automatically.
    io:format(Map, "{include, ~p}.~n", [EscapedInclude]),
    emit(T, Hrl, Map);
emit([header|T], {HrlPid, HrlName} = Hrl, Map) ->
    GuardDef = string:to_upper(filename:basename(HrlName, ".hrl")) ++ "_INCLUDED",
    io:format(HrlPid, "-ifndef( ~s ).~n", [GuardDef]),
    io:format(HrlPid, "-define( ~s, true ).~n~n", [GuardDef]),
    emit(T, Hrl, Map);
emit([footer|T], {HrlPid, HrlName} = Hrl, Map) ->
    GuardDef = string:to_upper(filename:basename(HrlName, ".hrl")) ++ "_INCLUDED",
    io:format(HrlPid, "~n-endif. % ~s~n", [GuardDef]),
    emit(T, Hrl, Map);
emit([_|T], Hrl, Map) ->
    emit(T, Hrl, Map);
emit([], _, _) ->
    true.

parse_dict(File) when is_list(File) ->
    {ok,B} = file:read_file(File),
    F = fun(Line,{undefined = Vendor, AccList}) ->
                case pd(string:tokens(Line,"\s\t\r")) of
                    {ok,E} -> {Vendor, [E|AccList]};
                    {include,Hrl} -> {Vendor, [{include, Hrl}|AccList]};
                    {begin_vendor, VendId} -> {{vendor, VendId}, AccList};
                    _      -> {Vendor, AccList}
                end;
           (Line, {{vendor, VendId} = Vendor, AccList}) ->
                case pd(string:tokens(Line, "\s\t\r"), VendId) of
                    {end_vendor} -> {undefined, AccList};
                    {include,Hrl} -> {Vendor, [{include, Hrl}|AccList]};
                    {ok,E} -> {Vendor, [E|AccList]};
                    _ -> {Vendor, AccList}
                end
        end,
    {_, L} = lists:foldl(F,{undefined, []},string:tokens(b2l(B),"\n")),
    [header|L] ++ [footer].

paa(Attr = #attribute{type = integer}, ["has_tag"]) ->
    Attr#attribute{ type = {tagged, integer24} };
paa(Attr, ["has_tag"]) ->
    Attr#attribute{ type = {tagged, Attr#attribute.type} };

paa(Attr, ["encrypt", Enc]) ->
    case l2i(Enc) of
        1 -> Attr#attribute{ enc = scramble };
        2 -> Attr#attribute{ enc = salt_crypt };
        3 -> Attr#attribute{ enc = ascend };
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

pd(["$INCLUDE", Name]) ->
    {include, Name};

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
pd(_X, _VendId) -> false.

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

repl(L,X,Y) when is_list(L) ->
    F = fun(Z) when Z == X -> Y;
           (C) -> C
        end,
    lists:map(F,L).
