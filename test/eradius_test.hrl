-define(match(Guard, Expr),
        ((fun () ->
                  case (Expr) of
                      Guard ->
                          ok;
                      V ->
                          ct:pal("MISMATCH(~s:~b, ~s)~nExpected: ~p~nActual:   ~p~n", [?FILE, ?LINE, ??Expr, ??Guard, V]),
                          error(badmatch)
                  end
          end)())).

-define(equal(Expected, Actual),
        (fun (Expected@@@, Expected@@@) -> true;
             (Expected@@@, Actual@@@) ->
                 ct:pal("MISMATCH(~s:~b, ~s)~nExpected: ~p~nActual:   ~p~n",
                        [?FILE, ?LINE, ??Actual, Expected@@@, Actual@@@]),
                 false
         end)(Expected, Actual) orelse error(badmatch)).
