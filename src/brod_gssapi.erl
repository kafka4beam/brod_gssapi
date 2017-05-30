%%%-------------------------------------------------------------------
%% @doc
%% SASL GSSAPI auth backend for brod
%% @end
%%%-------------------------------------------------------------------
-module(brod_gssapi).

-export([auth/6]).

-define(SASL_CONTINUE,           1).
-define(SASL_OK,                 0).
-define(SASL_FAIL,              -1).
-define(SASL_NOMEM,             -2).
-define(SASL_BUFOVER,           -3).
-define(SASL_NOMECH,            -4).
-define(SASL_BADPROT,           -5).
-define(SASL_NOTDONE,           -6).
-define(SASL_BADPARAM,          -7).
-define(SASL_TRYAGAIN,          -8).
-define(SASL_BADMAC,	        -9).
-define(SASL_NOTINIT,           -12).
-define(SASL_INTERACT,          2).
-define(SASL_BADSERV,           -10).
-define(SASL_WRONGMECH,         -11).
-define(SASL_BADAUTH,           -13).
-define(SASL_NOAUTHZ,           -14).
-define(SASL_TOOWEAK,           -15).
-define(SASL_ENCRYPT,           -16).
-define(SASL_TRANS,             -17).
-define(SASL_EXPIRED,           -18).
-define(SASL_DISABLED,          -19).
-define(SASL_NOUSER,            -20).
-define(SASL_BADVERS,           -23).
-define(SASL_UNAVAIL,           -24).
-define(SASL_NOVERIFY,          -26).
-define(SASL_PWLOCK,            -21).
-define(SASL_NOCHANGE,          -22).
-define(SASL_WEAKPASS,          -27).
-define(SASL_NOUSERPASS,        -28).
-define(SASL_NEED_OLD_PASSWD,   -29).
-define(SASL_CONSTRAINT_VIOLAT,	-30).
-define(SASL_BADBINDING,        -32).

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
