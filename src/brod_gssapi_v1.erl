%%%-------------------------------------------------------------------
%% @doc
%% SASL GSSAPI auth backend for brod
%% @end
%%%-------------------------------------------------------------------
-module(brod_gssapi_v1).

-export([auth/6]).

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
    ok = sasl_auth:kinit(ensure_binary(Keytab), ensure_binary(Principal)),
    case sasl_auth:client_new(<<"kafka">>, ensure_binary(Host), ensure_binary(Principal)) of
        {ok, State} ->
            StartCliFun =
                fun() ->
                    case sasl_auth:client_start(State) of
                        {ok, {SaslRes, Token}} ->
                            ok = handshake(
                                Sock, Mod, Timeout, ClientId, <<"GSSAPI">>, HandshakeVsn
                            ),
                            case send_sasl_token(Token, Sock, Mod, ClientId, Timeout, HandshakeVsn) of  
                                {error, _} = Error -> 
                                    Error;
                                NewToken  ->
                                    {SaslRes, NewToken}
                            end;
                        Other ->
                            Other
                    end
                end,
            case do_while(StartCliFun) of
                {ok, {sasl_ok, _}} ->
                    setopts(Sock, Mod, [{active, once}]);
                {error, {sasl_continue, {error, Error}}} ->
                    {error, Error};
                {sasl_continue, NewToken} ->
                    sasl_recv(State, Mod, Sock, Timeout, ClientId, NewToken, HandshakeVsn);
                Other ->
                    Other
            end;
        Other ->
            {error, Other}
    end.

sasl_recv(State, Mod, Sock, Timeout, ClientId, Challenge, HandshakeVsn) ->
    CliStepFun =
        fun() ->
            case sasl_auth:client_step(State, Challenge) of
                {ok, {SaslRes, Token}} ->
                    NewToken = send_sasl_token(Token, Sock, Mod, ClientId, Timeout, HandshakeVsn),
                    {SaslRes, NewToken};
                Other ->
                    Other
            end
        end,
    case do_while(CliStepFun) of
        {sasl_ok, _} ->
            setopts(Sock, Mod, [{active, once}]);
        {sasl_continue, {error, Error}} ->
            {error, Error};
        {sasl_continue, NewToken} ->
            sasl_recv(State, Mod, Sock, Timeout, ClientId, NewToken, HandshakeVsn);
        Other ->
            Other
    end.

%%====================================================================
%% Internal functions
%%====================================================================

-spec ensure_binary(atom() | iodata()) -> binary().
ensure_binary(Atom) when is_atom(Atom) ->
    atom_to_binary(Atom, utf8);
ensure_binary(Str) when is_list(Str) ->
    iolist_to_binary(Str);
ensure_binary(Bin) when is_binary(Bin) ->
    Bin.

maybe_interact_continue(sasl_interact) ->
    continue;
maybe_interact_continue(Other) ->
    Other.

do_while(Fun) ->
    case maybe_interact_continue(Fun()) of
        continue ->
            do_while(Fun);
        Other ->
            Other
    end.

setopts(Sock, _Mod = gen_tcp, Opts) ->
    inet:setopts(Sock, Opts);
setopts(Sock, _Mod = ssl, Opts) ->
    ssl:setopts(Sock, Opts).

send_sasl_token(Challenge, Sock, Mod, ClientId, Timeout, HandshakeVsn) when
    is_binary(Challenge)
->
    Req = kpro_req_lib:make(sasl_authenticate, HandshakeVsn, [{auth_bytes, Challenge}]),
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
