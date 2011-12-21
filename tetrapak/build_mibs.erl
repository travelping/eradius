-task({"build:mibsbin", "Build the SNMP MIBS"}).
-task({"build:mibshrl", "Build the SNMP MIBS"}).
-task({"clean:mibsbin", "Clean the SNMP MIBS"}).
-task({"clean:mibshrl", "Clean the SNMP MIBS"}).

-hook({"build:mibsbin", run_before, "build:mibshrl"}).
-hook({"build:mibshrl", run_before, "build:erlang"}).

check("build:mibsbin") ->
    MibsBinDir = tetrapak:path("priv/mibs"),
    MibsSrcDir = tetrapak:path("mibs"),
    tpk_util:check_files_mtime(MibsSrcDir, ".mib", MibsBinDir, ".bin");

check("clean:mibsbin") ->
    MibsBinDir = tetrapak:path("priv/mibs"),
    MibsSrcDir = tetrapak:path("mibs"),
    tpk_util:check_files_exist(MibsSrcDir, ".mib", MibsBinDir, ".bin");

check("build:mibshrl") ->
    MibsBinDir = tetrapak:path("priv/mibs"),
    IncludeDir = tetrapak:path("include"),
    tpk_util:check_files_mtime(MibsBinDir, ".bin", IncludeDir, ".hrl");

check("clean:mibshrl") ->
    MibsBinDir = tetrapak:path("priv/mibs"),
    IncludeDir = tetrapak:path("include"),
    tpk_util:check_files_exist(MibsBinDir, ".bin", IncludeDir, ".hrl").

run("build:mibsbin", Files) ->
	ExtraSNMPcOptions = tetrapak:config("build.snmpc_options", []),
    MibsBinDir = tetrapak:path("priv/mibs"),
	file:make_dir(tetrapak:path("priv")),
	file:make_dir(tetrapak:path("priv/mibs")),
    compile_foreach(fun ({InputFile, _OutputFile}) ->
                            run_compiler(snmpc, compile, [InputFile, [{outdir, MibsBinDir} | ExtraSNMPcOptions]])
					end, Files);

run("clean:mibsbin", Files) ->
    lists:foreach(fun ({_, MibFile}) -> tpk_file:delete(MibFile) end, Files);

run("build:mibshrl", Files) ->
    compile_foreach(fun ({InputFile, OutputFile}) ->
							MibName = filename:basename(InputFile, ".bin"),
                            run_compiler(snmpc_mib_to_hrl, convert, [InputFile, OutputFile, MibName])
					end, Files);

run("clean:mibshrl", Files) ->
    lists:foreach(fun ({_, HrlFile}) -> tpk_file:delete(HrlFile) end, Files).

compile_foreach(Function, List) ->
    Res = lists:foldl(fun (Item, DoFail) ->
                              case Function(Item) of
                                  ok    -> DoFail;
                                  error -> true
                              end
                      end, false, List),
    if Res  -> tetrapak:fail("compilation failed");
       true -> ok
    end.

run_compiler(M, F, A = [File | _]) ->
    BaseDir = tetrapak:dir(),
    io:format("Compiling ~s~n", [tpk_file:relative_path(File, BaseDir)]),
    case apply(M, F, A) of
		ok -> ok;
        {ok, _BinFileName} -> ok;
        error ->
            error;
        {error, _Reason} ->
            error
    end.
