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

% Scanner plugin to find document contents matching a regular experssion.
%

-module(couch_scanner_plugin_find).

-behaviour(couch_scanner_plugin).

-export([
    start/2,
    resume/2,
    stop/1,
    checkpoint/1,
    db/2,
    ddoc/3,
    shards/2,
    db_opened/2,
    doc_id/3,
    doc/3,
    db_closing/2
]).

-include_lib("couch_scanner/include/couch_scanner_plugin.hrl").

-record(st, {
    sid,
    regexes = #{},
    compiled_regexes = #{}
}).

% Behavior callbacks

start(SId, #{} = _CheckpointEJson) ->
    ?INFO("Starting.", [], #{sid => SId}),
    Regexes = regexes(),
    St = #st{sid = SId, regexes = Regexes},
    {ok, compile_regexes(St)}.

resume(SId, #{} = CheckpointEJson) ->
    #{<<"regexes">> := OldRegexes} = CheckpointEJson,
    Regexes = regexes(),
    case OldRegexes == Regexes of
        true ->
            % Config matches checkpoint config, continue
            ?INFO("Resuming.", [], #{sid => SId}),
            St = #st{sid = SId, regexes = Regexes},
            {ok, compile_regexes(St)};
        false ->
            % Config changed, reset
            ?INFO("Resetting", [], #{sid => SId}),
            reset
    end.

stop(#st{sid = SId}) ->
    ?INFO("Stopped", [], #{sid => SId}),
    {ok, #{}}.

checkpoint(#st{sid = SId, regexes = CurRegexes}) ->
    case CurRegexes == regexes() of
        true ->
            {ok, #{<<"regexes">> => CurRegexes}};
        false ->
            % Config changed => reset
            ?INFO("Resetting", [], #{sid => SId}),
            reset
    end.

db(#st{} = St, DbName) ->
    #st{sid = SId, compiled_regexes = Pats} = St,
    Meta = #{sid => SId, db => DbName},
    report_match(DbName, Pats, Meta),
    {ok, St}.

ddoc(#st{} = St, _DbName, #doc{} = _DDoc) ->
    % We'll check doc bodies during the shard scan
    % so no need to keep inspecting ddocs
    {stop, St}.

shards(#st{sid = SId} = St, Shards) ->
    case debug() of
        true -> ?DEBUG(" ~p shards", [length(Shards)], #{sid => SId});
        false -> ok
    end,
    {Shards, St}.

db_opened(#st{sid = SId} = St, Db) ->
    case debug() of
        true -> ?DEBUG("", [], #{sid => SId, db => Db});
        false -> ok
    end,
    {ok, St}.

doc_id(#st{} = St, DocId, Db) ->
    #st{sid = SId, compiled_regexes = Pats} = St,
    Meta = #{sid => SId, doc => DocId, db => Db},
    report_match(DocId, Pats, Meta),
    {ok, St}.

doc(#st{} = St, Db, #doc{id = DocId, body = Body}) ->
    #st{sid = SId, compiled_regexes = Pats} = St,
    Meta = #{sid => SId, doc => DocId, db => Db},
    report_match(Body, Pats, Meta),
    {ok, St}.

db_closing(#st{sid = SId} = St, Db) ->
    case debug() of
        true -> ?DEBUG("", [], #{sid => SId, db => Db});
        false -> ok
    end,
    {ok, St}.

% Private

regexes() ->
    Section = atom_to_list(?MODULE) ++ ".regexes",
    Regexes = config:get(Section),
    lists:foldl(fun regex_fold/2, #{}, Regexes).

regex_fold({K, V}, #{} = Acc) ->
    PatId = list_to_binary(K),
    PatVal = list_to_binary(V),
    try re:compile(PatVal) of
        {ok, _} ->
            Acc#{PatId => PatVal};
        Err ->
            ?WARN("Invalid pattern ~p : ~p", [PatId, Err]),
            Acc
    catch
        _Tag:Err ->
            ?WARN("Invalid pattern ~p : ~p", [PatId, Err]),
            Acc
    end.

compile_regexes(#st{regexes = Regexes} = St) ->
    Fun = fun(_PatId, PatVal) ->
        {ok, Regex} = re:compile(PatVal),
        Regex
    end,
    St#st{compiled_regexes = maps:map(Fun, Regexes)}.

report_match(Obj, Pats, Meta) ->
    try
        match(Obj, Pats)
    catch
        {throw, PatId} ->
            ?WARN("found ~s", [PatId], Meta)
    end.

match({Props}, Pats) when is_list(Props) ->
    match(Props, Pats);
match([], _Pats) ->
    nomatch;
match([{K, V} | Rest], Pats) ->
    nomatch = match(K, Pats),
    nomatch = match(V, Pats),
    match(Rest, Pats);
match(Str, #{} = Pats) when is_binary(Str) ->
    Fun = fun(PatId, PatVal) ->
        case re:run(Str, PatVal, [{capture, none}]) of
            match -> throw({match, PatId});
            nomatch -> nomatch
        end
    end,
    ok = maps:foreach(Fun, Pats),
    nomatch;
match(Num, _Pats) when is_number(Num) ->
    nomatch;
match(Atom, _Pats) when is_atom(Atom) ->
    nomatch.

debug() ->
    config:get_boolean(atom_to_list(?MODULE), "debug", false).
