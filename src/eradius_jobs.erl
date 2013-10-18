-module(eradius_jobs).
-export([start/2]).

start(Name, undefined) ->
    jobs:add_queue(Name, approve);

start(Name, Options0) ->
    {value, {limit, Limit}, Options} = lists:keytake(limit, 1, Options0),
    Regulators = [{counter, [{name, Name}, {limit, Limit}]}],
    JobsOptions = [{regulators, Regulators} | Options],
    jobs:add_queue(Name, JobsOptions).
