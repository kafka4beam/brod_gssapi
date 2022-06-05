-module(brod_gssapi_SUITE).

-compile(export_all).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

%%%%%%%%%%%%%%%%%%
%%%  CT hooks  %%%
%%%%%%%%%%%%%%%%%%

all() ->
    [
        simple,
        simple_interact,
        simple_interact_two,
        error_on_kinit,
        error_on_client_new,
        error_on_client_start,
        error_on_client_start2,
        error_on_handshake1,
        error_on_handshake2,
        error_on_send_sasl_token,
        error_on_client_step,
        error_on_finish
    ].

-define(MOCK_MODULES, [sasl_auth, inet, ssl, kpro_req_lib, kpro_lib, kpro]).

init_per_suite(Config) ->
    meck:new(
        ?MOCK_MODULES,
        [passthrough, no_link, unstick]
    ),
    Config.

end_per_suite(Config) ->
    meck:unload(?MOCK_MODULES),
    Config.

init_per_testcase(_Tc, Config) ->
    Config.

end_per_testcase(Tc, Config) ->
    validate_mocks(?MOCK_MODULES) orelse erlang:error(Tc ++ " failed meck validation"),
    reset_mocks(?MOCK_MODULES),
    Config.

simple(_Config) ->
    meck:expect(sasl_auth, kinit, fun(_, _) -> ok end),
    meck:expect(sasl_auth, client_new, fun(_, _, _) -> {ok, make_ref()} end),
    meck:expect(sasl_auth, client_start, fun(_) -> {ok, {sasl_ok, <<"token">>}} end),
    meck:expect(kpro_req_lib, make, fun(_, _, _) -> req end),
    meck:expect(kpro_lib, send_and_recv, fun(_, _, _, _, _) -> rsp end),
    meck:expect(
        kpro,
        find,
        fun
            (error_code, rsp) ->
                no_error;
            (auth_bytes, rsp) ->
                <<"auth_bytes">>
        end
    ),
    meck:expect(inet, setopts, fun(_, _) -> ok end),
    ?assertMatch(
        ok,
        brod_gssapi:auth(
            "host",
            make_ref(),
            1,
            gen_tcp,
            <<"client_id">>,
            42,
            {gssapi, "path/to/keytab", principal}
        )
    ).

simple_interact(_config) ->
    meck:expect(sasl_auth, kinit, fun(_, _) -> ok end),
    meck:expect(sasl_auth, client_new, fun(_, _, _) -> {ok, make_ref()} end),
    meck:expect(
        sasl_auth,
        client_start,
        fun(_) -> {ok, {sasl_continue, <<"challenge">>}} end
    ),
    meck:expect(kpro_req_lib, make, fun(_, _, _) -> req end),
    meck:expect(kpro_lib, send_and_recv, fun(_, _, _, _, _) -> rsp end),
    meck:expect(
        kpro,
        find,
        fun
            (error_code, rsp) ->
                no_error;
            (auth_bytes, rsp) ->
                <<"auth_bytes">>
        end
    ),
    meck:expect(
        sasl_auth,
        client_step,
        fun(_, <<"auth_bytes">>) -> {ok, {sasl_ok, <<"token">>}} end
    ),
    meck:expect(ssl, setopts, fun(_, _) -> ok end),
    ?assertMatch(
        ok,
        brod_gssapi:auth(
            "host",
            make_ref(),
            1,
            ssl,
            <<"client_id">>,
            42,
            {gssapi, <<"path/to/keytab">>, "principal"}
        )
    ).

simple_interact_two(_Config) ->
    meck:expect(sasl_auth, kinit, fun(_, _) -> ok end),
    meck:expect(sasl_auth, client_new, fun(_, _, _) -> {ok, make_ref()} end),
    meck:expect(
        sasl_auth,
        client_start,
        fun(_) -> {ok, {sasl_continue, <<"challenge1">>}} end
    ),
    meck:expect(
        kpro_req_lib,
        make,
        fun
            (_, _, [{mechanism, <<"GSSAPI">>}]) ->
                req1;
            (_, _, [{auth_bytes, <<"challenge1">>}]) ->
                req2;
            (_, _, [{auth_bytes, <<"challenge2">>}]) ->
                req3;
            (_, _, [{auth_bytes, <<"challenge3">>}]) ->
                req4
        end
    ),
    meck:expect(
        kpro_lib,
        send_and_recv,
        fun
            (req1, _, _, _, _) ->
                rsp1;
            (req2, _, _, _, _) ->
                rsp2;
            (req3, _, _, _, _) ->
                rsp3;
            (req4, _, _, _, _) ->
                rsp4
        end
    ),
    meck:expect(
        kpro,
        find,
        fun
            (error_code, rsp1) ->
                no_error;
            (error_code, rsp2) ->
                no_error;
            (error_code, rsp3) ->
                no_error;
            (error_code, rsp4) ->
                no_error;
            (auth_bytes, rsp2) ->
                <<"challenge1">>;
            (auth_bytes, rsp3) ->
                <<"challenge2">>;
            (auth_bytes, rsp4) ->
                <<"challenge3">>
        end
    ),
    meck:expect(
        sasl_auth,
        client_step,
        fun
            (_, <<"challenge1">>) ->
                {ok, {sasl_continue, <<"challenge2">>}};
            (_, <<"challenge2">>) ->
                {ok, {sasl_ok, <<"challenge3">>}}
        end
    ),
    meck:expect(inet, setopts, fun(_, _) -> ok end),
    ?assertMatch(
        ok,
        brod_gssapi:auth(
            "host",
            make_ref(),
            1,
            gen_tcp,
            <<"client_id">>,
            42,
            {gssapi, "path/to/keytab", "principal"}
        )
    ).

error_on_kinit(_Config) ->
    meck:expect(sasl_auth, kinit, fun(_, _) -> {error, {"kinit failed", 42, "description"}} end),
    ?assertMatch(
        {error, {"kinit failed", 42, "description"}},
        brod_gssapi:auth(
            "host",
            make_ref(),
            1,
            gen_tcp,
            <<"client_id">>,
            42,
            {gssapi, "path/to/keytab", "principal"}
        )
    ).

error_on_client_new(_Config) ->
    meck:expect(sasl_auth, kinit, fun(_, _) -> ok end),
    meck:expect(sasl_auth, client_new, fun(_, _, _) -> {error, {sasl_fail, "error msg"}} end),
    ?assertMatch(
        {error, {sasl_fail, "error msg"}},
        brod_gssapi:auth(
            "host",
            make_ref(),
            1,
            gen_tcp,
            <<"client_id">>,
            42,
            {gssapi, "path/to/keytab", "principal"}
        )
    ).

error_on_client_start(_Config) ->
    meck:expect(sasl_auth, kinit, fun(_, _) -> ok end),
    meck:expect(sasl_auth, client_new, fun(_, _, _) -> {ok, make_ref()} end),
    meck:expect(sasl_auth, client_start, fun(_) -> {error, {sasl_fail, <<"error">>}} end),
    ?assertMatch(
        {error, {sasl_fail, <<"error">>}},
        brod_gssapi:auth(
            "host",
            make_ref(),
            1,
            gen_tcp,
            <<"client_id">>,
            42,
            {gssapi, "path/to/keytab", "principal"}
        )
    ).

error_on_client_start2(_Config) ->
    meck:expect(sasl_auth, kinit, fun(_, _) -> ok end),
    meck:expect(sasl_auth, client_new, fun(_, _, _) -> {ok, make_ref()} end),
    meck:expect(sasl_auth, client_start, fun(_) -> {error, {sasl_continue, {error, <<"42">>}}} end),
    ?assertMatch(
        {error, {sasl_continue, {error, <<"42">>}}},
        brod_gssapi:auth(
            "host",
            make_ref(),
            1,
            gen_tcp,
            <<"client_id">>,
            42,
            {gssapi, "path/to/keytab", "principal"}
        )
    ).

error_on_handshake1(_Config) ->
    meck:expect(sasl_auth, kinit, fun(_, _) -> ok end),
    meck:expect(sasl_auth, client_new, fun(_, _, _) -> {ok, make_ref()} end),
    meck:expect(sasl_auth, client_start, fun(_) -> {ok, {sasl_ok, <<"token">>}} end),
    meck:expect(kpro_req_lib, make, fun(_, _, _) -> req end),
    meck:expect(kpro_lib, send_and_recv, fun(_, _, _, _, _) -> rsp end),
    meck:expect(kpro, find, fun
        (error_code, rsp) -> 42;
        (error_message, rsp) -> <<"message">>
    end),
    %% TODO: Fix return in code
    ?assertMatch(
        {error, 42},
        brod_gssapi:auth(
            "host",
            make_ref(),
            1,
            gen_tcp,
            <<"client_id">>,
            42,
            {gssapi, "path/to/keytab", "principal"}
        )
    ).

error_on_handshake2(_Config) ->
    meck:expect(sasl_auth, kinit, fun(_, _) -> ok end),
    meck:expect(sasl_auth, client_new, fun(_, _, _) -> {ok, make_ref()} end),
    meck:expect(sasl_auth, client_start, fun(_) -> {ok, {sasl_ok, <<"token">>}} end),
    meck:expect(kpro_req_lib, make, fun(_, _, _) -> req end),
    meck:expect(kpro_lib, send_and_recv, fun(_, _, _, _, _) -> rsp end),
    meck:expect(kpro, find, fun
        (error_code, rsp) -> unsupported_sasl_mechanism;
        (enabled_mechanisms, rsp) -> ["foo", "bar", "baz"]
    end),
    ?assertMatch(
        {error,
            <<"sasl mechanism GSSAPI is not enabled in kafka, enabled mechanism(s): foo,bar,baz">>},
        brod_gssapi:auth(
            "host",
            make_ref(),
            1,
            gen_tcp,
            <<"client_id">>,
            42,
            {gssapi, "path/to/keytab", "principal"}
        )
    ).
error_on_send_sasl_token(_Config) ->
    meck:expect(sasl_auth, kinit, fun(_, _) -> ok end),
    meck:expect(sasl_auth, client_new, fun(_, _, _) -> {ok, make_ref()} end),
    meck:expect(
        sasl_auth,
        client_start,
        fun(_) -> {ok, {sasl_continue, <<"challenge1">>}} end
    ),
    meck:expect(
        kpro_req_lib,
        make,
        fun
            (_, _, [{mechanism, <<"GSSAPI">>}]) ->
                req1;
            (_, _, [{auth_bytes, <<"challenge1">>}]) ->
                req2
        end
    ),
    meck:expect(
        kpro_lib,
        send_and_recv,
        fun
            (req1, _, _, _, _) ->
                rsp1;
            (req2, _, _, _, _) ->
                rsp2
        end
    ),
    meck:expect(
        kpro,
        find,
        fun
            (error_code, rsp1) ->
                no_error;
            (error_code, rsp2) ->
                42;
            (error_message, rsp2) ->
                <<"everything">>
        end
    ),

    ?assertMatch(
        {error, <<"everything">>},
        brod_gssapi:auth(
            "host",
            make_ref(),
            1,
            gen_tcp,
            <<"client_id">>,
            42,
            {gssapi, "path/to/keytab", "principal"}
        )
    ).

error_on_finish(_Config) ->
    meck:expect(sasl_auth, kinit, fun(_, _) -> ok end),
    meck:expect(sasl_auth, client_new, fun(_, _, _) -> {ok, make_ref()} end),
    meck:expect(
        sasl_auth,
        client_start,
        fun(_) -> {ok, {sasl_continue, <<"challenge1">>}} end
    ),
    meck:expect(
        kpro_req_lib,
        make,
        fun
            (_, _, [{mechanism, <<"GSSAPI">>}]) ->
                req1;
            (_, _, [{auth_bytes, <<"challenge1">>}]) ->
                req2;
            (_, _, [{auth_bytes, <<"challenge2">>}]) ->
                req3
        end
    ),
    meck:expect(
        kpro_lib,
        send_and_recv,
        fun
            (req1, _, _, _, _) ->
                rsp1;
            (req2, _, _, _, _) ->
                rsp2;
            (req3, _, _, _, _) ->
                rsp3
        end
    ),
    meck:expect(
        kpro,
        find,
        fun
            (error_code, rsp1) ->
                no_error;
            (error_code, rsp2) ->
                no_error;
            (error_code, rsp3) ->
                42;
            (error_message, rsp3) ->
                <<"everything">>;
            (auth_bytes, rsp2) ->
                <<"challenge1">>;
            (auth_bytes, rsp3) ->
                <<"challenge2">>
        end
    ),
    meck:expect(
        sasl_auth,
        client_step,
        fun(_, <<"challenge1">>) ->
            {ok, {sasl_ok, <<"challenge2">>}}
        end
    ),
    meck:expect(inet, setopts, fun(_, _) -> ok end),
    ?assertMatch(
        {error, <<"everything">>},
        brod_gssapi:auth(
            "host",
            make_ref(),
            1,
            gen_tcp,
            <<"client_id">>,
            42,
            {gssapi, "path/to/keytab", "principal"}
        )
    ).

error_on_client_step(_config) ->
    meck:expect(sasl_auth, kinit, fun(_, _) -> ok end),
    meck:expect(sasl_auth, client_new, fun(_, _, _) -> {ok, make_ref()} end),
    meck:expect(
        sasl_auth,
        client_start,
        fun(_) -> {ok, {sasl_continue, <<"challenge">>}} end
    ),
    meck:expect(kpro_req_lib, make, fun(_, _, _) -> req end),
    meck:expect(kpro_lib, send_and_recv, fun(_, _, _, _, _) -> rsp end),
    meck:expect(
        kpro,
        find,
        fun
            (error_code, rsp) ->
                no_error;
            (auth_bytes, rsp) ->
                <<"auth_bytes">>
        end
    ),
    meck:expect(
        sasl_auth,
        client_step,
        fun(_, <<"auth_bytes">>) -> {error, {sasl_fail, <<"oops">>}} end
    ),
    ?assertMatch(
        {error, {sasl_fail, <<"oops">>}},
        brod_gssapi:auth(
            "host",
            make_ref(),
            1,
            gen_tcp,
            <<"client_id">>,
            42,
            {gssapi, "path/to/keytab", "principal"}
        )
    ).

%%%%%%%%%%%%%%%%%%
%%%  Helpers   %%%
%%%%%%%%%%%%%%%%%%

validate_mocks(Modules) ->
    lists:all(fun(Mod) -> meck:validate(Mod) end, Modules).

reset_mocks(Modules) ->
    meck:reset(Modules),
    [
        meck:delete(Module, Fun, Arity, false)
     || {Module, Fun, Arity} <- meck:expects(Modules, true)
    ].
