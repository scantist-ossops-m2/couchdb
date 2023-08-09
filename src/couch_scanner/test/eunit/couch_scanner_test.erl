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

-module(couch_scanner_test).

-include_lib("couch/include/couch_eunit.hrl").
-include_lib("couch/include/couch_db.hrl").

couch_scanner_test_() ->
    {
        foreach,
        fun setup/0,
        fun teardown/1,
        [
            ?TDEF_FE(t_top_level_api),
            ?TDEF_FE(t_start_stop),
            ?TDEF_FE(t_start_plugin, 10),
            ?TDEF_FE(t_run_through_all_callbacks_basic, 10),
            ?TDEF_FE(t_find_reporting_works, 10),
            ?TDEF_FE(t_test_skips, 10)
        ]
    }.

-define(DOC1, <<"scanner_test_doc1">>).
-define(DOC2, <<"_design/scanner_test_doc2">>).
-define(DOC3, <<"scanner_test_doc3">>).
-define(DOC4, <<"_design/scanner_test_doc4">>).

-define(FIND_PLUGIN, couch_scanner_plugin_find).

setup() ->
    {module, _} = code:ensure_loaded(?FIND_PLUGIN),
    meck:new(?FIND_PLUGIN, [passthrough]),
    meck:new(couch_scanner_server, [passthrough]),
    meck:new(couch_scanner_plugin, [passthrough]),
    Ctx = test_util:start_couch([fabric, couch_scanner]),
    DbName1 = ?tempdb(),
    DbName2 = ?tempdb(),
    ok = fabric:create_db(DbName1, [{q, "2"}, {n, "1"}]),
    ok = fabric:create_db(DbName2, [{q, "2"}, {n, "1"}]),
    ok = add_doc(DbName1, ?DOC1, #{<<"foo1">> => <<"bar">>}),
    ok = add_doc(DbName1, ?DOC2, #{<<"foo2">> => <<"baz">>}),
    ok = add_doc(DbName2, ?DOC3, #{<<"foo3">> => <<"baz">>}),
    ok = add_doc(DbName2, ?DOC4, #{<<"foo4">> => <<"baz">>}),
    couch_scanner:reset_checkpoints(),
    {Ctx, {DbName1, DbName2}}.

teardown({Ctx, {DbName1, DbName2}}) ->
    config:delete("couch_scanner", "maintenance_mode", false),
    config_delete_section("couch_scanner"),
    config_delete_section("couch_scanner_plugins"),
    Plugin = atom_to_list(?FIND_PLUGIN),
    config_delete_section(Plugin),
    config_delete_section(Plugin ++ ".skip_dbs"),
    config_delete_section(Plugin ++ ".skip_ddocs"),
    config_delete_section(Plugin ++ ".skip_docs"),
    couch_scanner:resume(),
    couch_scanner:reset_checkpoints(),
    fabric:delete_db(DbName1),
    fabric:delete_db(DbName2),
    test_util:stop_couch(Ctx),
    meck:unload().

t_top_level_api(_) ->
    ?assertMatch(#{}, couch_scanner:checkpoints()),
    ?assertMatch(#{stopped := false}, couch_scanner:status()),
    ?assertMatch(#{}, couch_scanner:reset_checkpoints()),
    ?assertEqual(#{}, couch_scanner:checkpoints()),
    ?assertEqual(ok, couch_scanner:resume()).

t_start_stop(_) ->
    ?assertMatch(#{stopped := false}, couch_scanner:status()),
    ?assertEqual(ok, couch_scanner:stop()),
    ?assertMatch(#{stopped := true}, couch_scanner:status()),
    ?assertEqual(ok, couch_scanner:stop()),
    ?assertMatch(#{stopped := true}, couch_scanner:status()),
    ?assertEqual(ok, couch_scanner_server:resume()),
    ?assertMatch(#{stopped := false}, couch_scanner:status()),
    ?assertEqual(ok, couch_scanner_server:resume()),
    ?assertMatch(#{stopped := false}, couch_scanner:status()).

t_start_plugin(_) ->
    meck:reset(?FIND_PLUGIN),
    config:set("couch_scanner_plugins", atom_to_list(?FIND_PLUGIN), "true", false),
    meck:wait(?FIND_PLUGIN, start, 2, 5000),
    ok.

t_run_through_all_callbacks_basic({_, {DbName1, DbName2}}) ->
    meck:reset(?FIND_PLUGIN),
    config:set("couch_scanner_plugins", atom_to_list(?FIND_PLUGIN), "true", false),
    meck:wait(?FIND_PLUGIN, stop, 1, 10000),
    % Check that all callbacks we exected to be called were called
    ?assertEqual(1, num_calls(start, 2)),
    ?assertEqual(0, num_calls(resume, 2)),
    ?assertEqual(1, num_calls(stop, 1)),
    ?assertEqual(1, num_calls(checkpoint, 1)),
    ?assertEqual(1, num_calls(db, ['_', DbName1])),
    ?assertEqual(1, num_calls(db, ['_', DbName2])),
    ?assertEqual(1, num_calls(ddoc, ['_', DbName1, '_'])),
    ?assertEqual(1, num_calls(ddoc, ['_', DbName2, '_'])),
    ?assert(num_calls(shards, 2) >= 2),
    DbOpenedCount = num_calls(db_opened, 2),
    ?assert(DbOpenedCount >= 4),
    ?assertEqual(1, num_calls(doc_id, ['_', ?DOC1, '_'])),
    ?assertEqual(1, num_calls(doc_id, ['_', ?DOC2, '_'])),
    ?assertEqual(1, num_calls(doc_id, ['_', ?DOC3, '_'])),
    ?assertEqual(1, num_calls(doc_id, ['_', ?DOC4, '_'])),
    ?assert(num_calls(doc, 3) >= 4),
    DbClosingCount = num_calls(db_closing, 2),
    ?assertEqual(DbOpenedCount, DbClosingCount),
    ?assertEqual(0, log_calls(warning)).

t_find_reporting_works({_, {DbName1, DbName2}}) ->
    meck:reset(?FIND_PLUGIN),
    config:set("couch_scanner_plugins", atom_to_list(?FIND_PLUGIN), "true", false),
    meck:wait(?FIND_PLUGIN, stop, 1, 10000),
    % Check that all callbacks we exected to be called were called
    ?assertEqual(1, num_calls(start, 2)),
    ?assertEqual(0, num_calls(resume, 2)),
    ?assertEqual(1, num_calls(stop, 1)),
    ?assertEqual(1, num_calls(checkpoint, 1)),
    ?assertEqual(1, num_calls(db, ['_', DbName1])),
    ?assertEqual(1, num_calls(db, ['_', DbName2])),
    ?assertEqual(1, num_calls(ddoc, ['_', DbName1, '_'])),
    ?assertEqual(1, num_calls(ddoc, ['_', DbName2, '_'])),
    ?assert(num_calls(shards, 2) >= 2),
    DbOpenedCount = num_calls(db_opened, 2),
    ?assert(DbOpenedCount >= 4),
    ?assertEqual(1, num_calls(doc_id, ['_', ?DOC1, '_'])),
    ?assertEqual(1, num_calls(doc_id, ['_', ?DOC2, '_'])),
    ?assertEqual(1, num_calls(doc_id, ['_', ?DOC3, '_'])),
    ?assertEqual(1, num_calls(doc_id, ['_', ?DOC4, '_'])),
    ?assert(num_calls(doc, 3) >= 4),
    DbClosingCount = num_calls(db_closing, 2),
    ?assertEqual(DbOpenedCount, DbClosingCount),
    ?assertEqual(0, log_calls(warning)).

t_test_skips({_, {DbName1, DbName2}}) ->
    meck:reset(?FIND_PLUGIN),
    Plugin = atom_to_list(?FIND_PLUGIN),
    config:set(Plugin ++ ".skip_dbs", binary_to_list(DbName2), "true", false),
    config:set(Plugin ++ ".skip_docs", binary_to_list(?DOC1), "true", false),
    config:set(Plugin ++ ".skip_ddocs", binary_to_list(?DOC2), "true", false),
    config:set("couch_scanner_plugins", Plugin, "true", false),
    meck:wait(?FIND_PLUGIN, stop, 1, 10000),
    % Check that all callbacks we exected to be called were called
    ?assertEqual(1, num_calls(start, 2)),
    ?assertEqual(0, num_calls(resume, 2)),
    ?assertEqual(1, num_calls(stop, 1)),
    ?assertEqual(1, num_calls(checkpoint, 1)),
    ?assertEqual(1, num_calls(db, ['_', DbName1])),
    ?assertEqual(0, num_calls(db, ['_', DbName2])),
    ?assertEqual(0, num_calls(ddoc, ['_', DbName1, '_'])),
    ?assertEqual(0, num_calls(ddoc, ['_', DbName2, '_'])),
    DbOpenedCount = num_calls(db_opened, 2),
    ?assert(DbOpenedCount >= 2),
    ?assertEqual(0, num_calls(doc_id, ['_', ?DOC1, '_'])),
    ?assertEqual(1, num_calls(doc_id, ['_', ?DOC2, '_'])),
    ?assertEqual(0, num_calls(doc_id, ['_', ?DOC3, '_'])),
    ?assertEqual(0, num_calls(doc_id, ['_', ?DOC4, '_'])),
    DbClosingCount = num_calls(db_closing, 2),
    ?assertEqual(DbOpenedCount, DbClosingCount).

config_delete_section(Section) ->
    [config:delete(K, V, false) || {K, V} <- config:get(Section)].

add_doc(DbName, DocId, Body) ->
    {ok, _} = fabric:update_doc(DbName, mkdoc(DocId, Body), [?ADMIN_CTX]),
    ok.

mkdoc(Id, #{} = Body) ->
    Body1 = Body#{<<"_id">> => Id},
    jiffy:decode(jiffy:encode(Body1)).

num_calls(Fun, Args) ->
    meck:num_calls(?FIND_PLUGIN, Fun, Args).

log_calls(Level) ->
    meck:num_calls(couch_scanner_plugin, log, [Level, ?FIND_PLUGIN, '_', '_', '_']).
