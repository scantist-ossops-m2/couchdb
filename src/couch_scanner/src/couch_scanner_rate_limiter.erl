% Licensed under the Apache License, Version 2.0 (the "License"); you may not
% use this file except in compliance with the License. You may obtain a copy of
% the License at
%
%   http://www.apache.org/licenses/LICENSE-2.0
%
% Unless required by applicable law or agreed to in writing, software
% distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
% WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
% License for the specific language governing permissions and limitations under
% the License.

% Basic leaky bucket and AIMD algorithm [1] to rate limit plugins:
%
%  * couch_scanner_sever initializes a new instance. Then passes it the to each
%    running plugin process.
%
%  * couch_scanner_server periodically calls refill/2 to fill up the configured
%    number of allowed credits in each bucket.
%
%  * couch_scanner_plugin periodically calls update/2 function when
%    performing operations. It updates the backoff value and returns the
%    the updated value and the new rlimiter state.
%
% [1] https://en.wikipedia.org/wiki/Additive_increase/multiplicative_decrease
%

-module(couch_scanner_rate_limiter).

-export([
    % Called by the server
    new/0,
    refill/2,
    % Called by plugin
    update/2
]).

% AIMD parameters
-define(INIT_BACKOFF, 0.05).
-define(MULTIPLICATIVE_FACTOR, 1.1).
-define(ADDITIVE_FACTOR, 0.01).
-define(MAX_BACKOFF, 1.0).

% Default rates
-define(DB_RATE_DEFAULT, 10).
-define(SHARD_RATE_DEFAULT, 10).
-define(DOC_RATE_DEFAULT, 1000).

% Atomic ref indices. They start at 1.
-define(INDICES, #{db => 1, shard => 2, doc => 3}).

-record(rlst, {
    ref,
    backoffs = #{
        db => ?INIT_BACKOFF,
        shard => ?INIT_BACKOFF,
        doc => ?INIT_BACKOFF
    }
}).

new() ->
    #rlst{ref = atomics:new(map_size(?INDICES), [])}.

refill(#rlst{ref = Ref} = St, Period) when is_integer(Period), Period >= 0 ->
    ok = atomics:put(Ref, map_get(db, ?INDICES), db_limit() * Period),
    ok = atomics:put(Ref, map_get(shard, ?INDICES), shard_limit() * Period),
    ok = atomics:put(Ref, map_get(doc, ?INDICES), doc_limit() * Period),
    St.

update(#rlst{ref = Ref, backoffs = Backoffs} = St, Type) ->
    AtLimit = atomics:sub_get(Ref, map_get(Type, ?INDICES), 1) =< 0,
    Backoff = map_get(Type, Backoffs),
    Backoff1 = update_backoff(AtLimit, Backoff),
    St1 = St#rlst{backoffs = Backoffs#{Type := Backoff1}},
    {Backoff1, St1}.

update_backoff(true, Backoff) ->
    min(?MAX_BACKOFF, Backoff * ?MULTIPLICATIVE_FACTOR);
update_backoff(false, Backoff) ->
    Backoff1 = max(0, Backoff - ?ADDITIVE_FACTOR),
    case Backoff1 < 0.001 of
        true -> 0;
        false -> Backoff1
    end.

db_limit() ->
    cfg_int("db_rate_limit", ?DB_RATE_DEFAULT).

shard_limit() ->
    cfg_int("shard_rate_limit", ?SHARD_RATE_DEFAULT).

doc_limit() ->
    cfg_int("doc_rate_limit", ?DOC_RATE_DEFAULT).

cfg_int(Key, Default) when is_list(Key), is_integer(Default) ->
    config:get_integer("couch_scanner", Key, Default).

-ifdef(TEST).

-include_lib("couch/include/couch_eunit.hrl").

couch_scanner_rate_limiter_test_() ->
    {
        foreach,
        fun setup/0,
        fun teardown/1,
        [
            ?TDEF_FE(t_init),
            ?TDEF_FE(t_update),
            ?TDEF_FE(t_refill)
        ]
    }.

t_init(_) ->
    St = new(),
    ?assertMatch(#rlst{}, refill(St, 1)),
    ?assertMatch({Val, #rlst{}} when is_number(Val), update(St, db)),
    ?assertMatch({Val, #rlst{}} when is_number(Val), update(St, shard)),
    ?assertMatch({Val, #rlst{}} when is_number(Val), update(St, doc)).

t_update(_) ->
    St = new(),
    Seqs = lists:seq(1, 1000),
    Fun = fun(_, Acc) ->
        {_, Acc1} = update(Acc, db),
        Acc1
    end,
    St1 = lists:foldl(Fun, St, Seqs),
    {Backoff, _} = update(St1, db),
    % Should have hit max backoff value
    ?assertEqual(1.0, Backoff).

t_refill(_) ->
    St = new(),
    Seqs = lists:seq(1, 1000),
    Fun = fun(_, Acc) ->
        {_, Acc1} = update(Acc, db),
        Acc1
    end,
    St1 = lists:foldl(Fun, St, Seqs),
    {Backoff1, _} = update(St1, db),
    % Should have hit max backoff value
    ?assertEqual(1.0, Backoff1),
    St2 = refill(St1, 1000),
    St3 = lists:foldl(Fun, St2, Seqs),
    {Backoff2, _} = update(St3, db),
    % With so many tokens we should have gotten back to 0
    ?assertEqual(0, Backoff2).

setup() ->
    meck:new(config, [passthrough]),
    meck:expect(config, get, fun(_, _, Default) -> Default end),
    ok.

teardown(_) ->
    meck:unload().

-endif.
