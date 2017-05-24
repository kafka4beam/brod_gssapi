%%%-------------------------------------------------------------------
%% @doc
%% SASL GSSAPI auth backend for brod
%% @end
%%%-------------------------------------------------------------------
-module(brod_gssapi).

-include_lib("brod_gssapi/include/brod_gssapi.hrl").

-export([auth/6]).

%%%-------------------------------------------------------------------
%% @doc
%% Returns 'ok' if authentication successfully completed. See spec in behavior
%% @end
%%%-------------------------------------------------------------------
auth(Host, Sock, Mod, _ClientId, Timeout, _SaslOpts = {_Method = gssapi, Keytab, Principal}) ->
    ?SASL_OK = sasl_auth:sasl_client_init(),
    {ok, _} = sasl_auth:kinit(Keytab, Principal),
    ok = setopts(Sock, Mod, [{active, false}]),
    case sasl_auth:sasl_client_new(<<"kafka">>, list_to_binary(Host), Principal) of
        ?SASL_OK ->
            sasl_auth:sasl_listmech(),
            CondFun = fun(?SASL_INTERACT) -> continue; (Other) -> Other end,
            StartCliFun = fun() ->
                {SaslRes, Token} = sasl_auth:sasl_client_start(),
                if
                    SaslRes >= 0 ->
                        send_sasl_token(Token, Sock, Mod),
                        SaslRes;
                    true ->
                        SaslRes
                end
                          end,
            SaslRes =
                case do_while(StartCliFun, CondFun) of
                    SomeRes when SomeRes /= ?SASL_OK andalso SomeRes /= ?SASL_CONTINUE ->
                        {error, SomeRes};
                    Other ->
                        Other
                end,
            case SaslRes of
                ?SASL_OK ->
                    ok = setopts(Sock, Mod, [{active, once}]);
                ?SASL_CONTINUE ->
                    sasl_recv(Mod, Sock, Timeout)
            end;
        Other ->
            {error, Other}
    end.

sasl_recv(Mod, Sock, Timeout) ->
    case Mod:recv(Sock, 4, Timeout) of
        {ok, <<0:32>>} ->
            ok = setopts(Sock, Mod, [{active, once}]);
        {ok, <<BrokerTokenSize:32>>} ->
            case Mod:recv(Sock, BrokerTokenSize, Timeout) of
                {ok, BrokerToken} ->
                    CondFun = fun(?SASL_INTERACT) -> continue; (Other) -> Other end,
                    CliStepFun = fun() ->
                        {SaslRes, Token} = sasl_auth:sasl_client_step(BrokerToken),
                        if
                            SaslRes >= 0 ->
                                send_sasl_token(Token, Sock, Mod),
                                SaslRes;
                            true ->
                                SaslRes
                        end
                                 end,
                    case do_while(CliStepFun, CondFun) of
                        ?SASL_OK ->
                            ok = setopts(Sock, Mod, [{active, once}]);
                        ?SASL_CONTINUE ->
                            sasl_recv(Mod, Sock, Timeout);
                        Other ->
                            {error, Other}
                    end
            end;
        {error, closed} ->
            {error, bad_credentials};
        Unexpected ->
            {error, Unexpected}
    end.

%%====================================================================
%% Internal functions
%%====================================================================

do_while(Fun, CondFun) ->
    case CondFun(Fun()) of
        continue -> do_while(Fun, CondFun);
        Other -> Other
    end.

setopts(Sock, _Mod = gen_tcp, Opts) -> inet:setopts(Sock, Opts);
setopts(Sock, _Mod = ssl, Opts)     ->  ssl:setopts(Sock, Opts).

sasl_token(Challenge) ->
    <<(byte_size(Challenge)):32, Challenge/binary>>.

send_sasl_token(Challenge, Sock, Mod) when is_list(Challenge) ->
    ok = Mod:send(Sock, sasl_token(list_to_binary(Challenge))).
