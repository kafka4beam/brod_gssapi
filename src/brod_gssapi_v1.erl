%%%-------------------------------------------------------------------
%% @doc
%% SASL GSSAPI auth backend for brod
%% @end
%%%-------------------------------------------------------------------
-module(brod_gssapi_v1).

-export([auth/6]).

-define(SASL_CONTINUE, 1).
-define(SASL_OK, 0).
-define(SASL_FAIL, -1).
-define(SASL_NOMEM, -2).
-define(SASL_BUFOVER, -3).
-define(SASL_NOMECH, -4).
-define(SASL_BADPROT, -5).
-define(SASL_NOTDONE, -6).
-define(SASL_BADPARAM, -7).
-define(SASL_TRYAGAIN, -8).
-define(SASL_BADMAC, -9).
-define(SASL_NOTINIT, -12).
-define(SASL_INTERACT, 2).
-define(SASL_BADSERV, -10).
-define(SASL_WRONGMECH, -11).
-define(SASL_BADAUTH, -13).
-define(SASL_NOAUTHZ, -14).
-define(SASL_TOOWEAK, -15).
-define(SASL_ENCRYPT, -16).
-define(SASL_TRANS, -17).
-define(SASL_EXPIRED, -18).
-define(SASL_DISABLED, -19).
-define(SASL_NOUSER, -20).
-define(SASL_BADVERS, -23).
-define(SASL_UNAVAIL, -24).
-define(SASL_NOVERIFY, -26).
-define(SASL_PWLOCK, -21).
-define(SASL_NOCHANGE, -22).
-define(SASL_WEAKPASS, -27).
-define(SASL_NOUSERPASS, -28).
-define(SASL_NEED_OLD_PASSWD, -29).
-define(SASL_CONSTRAINT_VIOLAT, -30).
-define(SASL_BADBINDING, -32).

%%%-------------------------------------------------------------------
%% @doc
%% Returns 'ok' if authentication successfully completed. See spec in behavior
%% @end
% Observed Sequence of handshake is as follows:

% a) After initial series of sasl_auth calls, you get a kerberos token with a status if auth succeeded or failed or it should be continued. We got and Token (1 continue, 0 done, -1 Fail)

% b) On getting the token, we do handshake with Kafka using SaslHandshake call with GSSAPI mechanism. If Kafka supports GSSAPI mechanism, we are OK to move ahead

% c) We send the token received in first step wrapped in Kafka Request using SaslAuthenticate, SaslAuthenticate returns a new token in its response, if successful.

% d) We then send this new Token to sasl_auth using method (sasl_client_step)to continue, this method returns {1 , []} i.e. continue with empty token

% e) We then send empty Token again to Kafka SaslAuthenticate wrapped in Kafka Request. We again get a Token in response, if successful

% f) We then send this new Token to sasl_auth using method (sasl_client_step)to continue, this method returns {0 , Token} i.e. Successful Auth with a token

% g) We sends this token to Kafka SaslAuthenticate wrapped in Kafka Request. Which if successful indicates a successful Handshake and authentication using Kerberos
%%%-------------------------------------------------------------------
auth(
    Host,
    Sock,
    Mod,
    ClientId,
    Timeout,
    _SaslOpts = {_Method = gssapi, Keytab, Principal}
) ->
    HandshakeVsn = 1,
    ?SASL_OK = sasl_auth:sasl_client_init(),
    {ok, _} = sasl_auth:kinit(ensure_binary(Keytab), ensure_binary(Principal)),

    case sasl_auth:sasl_client_new(<<"kafka">>, list_to_binary(Host), Principal) of
        ?SASL_OK ->
            sasl_auth:sasl_listmech(),
            CondFun =
                fun
                    (?SASL_INTERACT) ->
                        continue;
                    (Other) ->
                        Other
                end,
            StartCliFun =
                fun() ->
                    {SaslRes, Token} = sasl_auth:sasl_client_start(),
                    if
                        SaslRes >= 0 ->
                            ok = handshake(
                                Sock, Mod, Timeout, ClientId, <<"GSSAPI">>, HandshakeVsn
                            ),
                            NewToken =
                                send_sasl_token(Token, Sock, Mod, ClientId, Timeout, HandshakeVsn),
                            {SaslRes, NewToken};
                        true ->
                            SaslRes
                    end
                end,
            case do_while(StartCliFun, CondFun) of
                {?SASL_OK, _} ->
                    setopts(Sock, Mod, [{active, once}]);
                {?SASL_CONTINUE, {error, Error}} ->
                    {error, Error};
                {?SASL_CONTINUE, NewToken} ->
                    sasl_recv(Mod, Sock, Timeout, ClientId, NewToken, HandshakeVsn);
                Other ->
                    Other
            end;
        Other ->
            {error, Other}
    end.

sasl_recv(Mod, Sock, Timeout, ClientId, Challenge, HandshakeVsn) ->
    CondFun =
        fun
            (?SASL_INTERACT) ->
                continue;
            (Other) ->
                Other
        end,
    CliStepFun =
        fun() ->
            {SaslRes, Token} = sasl_auth:sasl_client_step(Challenge),
            if
                SaslRes >= 0 ->
                    NewToken = send_sasl_token(Token, Sock, Mod, ClientId, Timeout, HandshakeVsn),
                    {SaslRes, NewToken};
                true ->
                    SaslRes
            end
        end,
    case do_while(CliStepFun, CondFun) of
        {?SASL_OK, _} ->
            setopts(Sock, Mod, [{active, once}]);
        {?SASL_CONTINUE, {error, Error}} ->
            {error, Error};
        {?SASL_CONTINUE, NewToken} ->
            sasl_recv(Mod, Sock, Timeout, ClientId, NewToken, HandshakeVsn);
        Other ->
            Other
    end.

%%====================================================================
%% Internal functions
%%====================================================================

-spec ensure_binary(atom() | iodata()) -> binary().
ensure_binary(Atom) when is_atom(Atom) ->
    atom_to_binary(Atom, utf8);
ensure_binary(Str) ->
    iolist_to_binary(Str).

do_while(Fun, CondFun) ->
    case CondFun(Fun()) of
        continue ->
            do_while(Fun, CondFun);
        Other ->
            Other
    end.

setopts(Sock, _Mod = gen_tcp, Opts) ->
    inet:setopts(Sock, Opts);
setopts(Sock, _Mod = ssl, Opts) ->
    ssl:setopts(Sock, Opts).

send_sasl_token(Challenge, Sock, Mod, ClientId, Timeout, HandshakeVsn) when
    is_list(Challenge)
->
    Bytes = list_to_binary(Challenge),
    Req = kpro_req_lib:make(sasl_authenticate, HandshakeVsn, [{auth_bytes, Bytes}]),
    Rsp = kpro_lib:send_and_recv(Req, Sock, Mod, ClientId, Timeout),

    EC = kpro:find(error_code, Rsp),

    case EC =:= no_error of
        true ->
            kpro:find(auth_bytes, Rsp);
        false ->
            {error, kpro:find(error_message, Rsp)}
    end.

handshake(Sock, Mod, Timeout, ClientId, Mechanism, Vsn) ->
    Req = kpro_req_lib:make(sasl_handshake, Vsn, [{mechanism, Mechanism}]),
    Rsp = kpro_lib:send_and_recv(Req, Sock, Mod, ClientId, Timeout),
    ErrorCode = kpro:find(error_code, Rsp),
    case ErrorCode of
        no_error ->
            ok;
        unsupported_sasl_mechanism ->
            EnabledMechanisms = kpro:find(enabled_mechanisms, Rsp),
            Msg = io_lib:format(
                "sasl mechanism ~s is not enabled in "
                "kafka, enabled mechanism(s): ~s",
                [Mechanism, cs(EnabledMechanisms)]
            ),
            {error, iolist_to_binary(Msg)};
        Other ->
            {error, Other}
    end.

cs([]) ->
    "[]";
cs([X]) ->
    X;
cs([H | T]) ->
    [H, "," | cs(T)].
