%% @private
-module(brod_gssapi_v1).

-export([auth/1, auth/6]).

-define(HANDSHAKE_V1, 1).

%%% Flow
%%% -----------------------------------------------------------------
%%%  a) After initial series of sasl_auth calls, you get a kerberos token
%%%     with a status if auth succeeded or failed or it should be continued.
%%%     We got and Token (1 continue, 0 done, -1 Fail)
%%%
%%% b) On getting the token, we do handshake with Kafka using SaslHandshake
%%%    call with GSSAPI mechanism. If Kafka supports GSSAPI mechanism, we
%%%    are OK to move ahead

%%% c) We send the token received in first step wrapped in Kafka Request using
%%%    SaslAuthenticate, SaslAuthenticate returns a new token in its response,
%%%    if successful.
%%%
%%% d) We then send this new Token to sasl_auth using method (sasl_client_step)
%%%    to continue, this method returns {1 , []} i.e. continue with empty token
%%% e) We then send empty Token again to Kafka SaslAuthenticate wrapped in
%%%    Kafka Request. We again get a Token in response, if successful.
%%%
%%% f) We then send this new Token to sasl_auth using method (sasl_client_step)
%%%    to continue, this method returns {0 , Token} i.e. Successful Auth with a
%%%    token.
%%%
%%% g) We sends this token to Kafka SaslAuthenticate wrapped in Kafka Request.
%%%    Which if successful indicates a successful Handshake and authentication
%%%    using Kerberos.
%%% -------------------------------------------------------------------

%% For backwards compat with version <= 0.2
-spec auth(
    Host :: string(),
    Sock :: gen_tcp:socket() | ssl:sslsocket(),
    Mod :: gen_tcp | ssl,
    ClientId :: binary(),
    Timeout :: pos_integer(),
    SaslOpts :: term()
) -> ok | {error, Reason :: term()}.
auth(
    Host,
    Sock,
    Mod,
    ClientId,
    Timeout,
    Opts
) ->
    State = brod_gssapi:new(Host, Sock, Mod, ClientId, ?HANDSHAKE_V1, Timeout, Opts),
    auth(State).

%%%-------------------------------------------------------------------
%% @doc
%% Returns 'ok' if authentication successfully completed. See spec in behavior
%% @end
% Observed Sequence of handshake is as follows:
-spec auth(brod_gssapi:state()) -> ok | {error, Reason :: term()}.
auth(State) ->
    case auth_init(State) of
        {ok, State1} ->
            case auth_begin(State1) of
                {ok, SaslRes} ->
                    auth_continue(State1, SaslRes);
                Error ->
                    Error
            end;
        Error ->
            Error
    end.

-spec auth_init(State :: brod_gssapi:state()) -> {ok, brod_gssapi:state()} | {error, term()}.
auth_init(#{keytab := Keytab, principal := Principal, host := Host} = State) ->
    case sasl_auth:kinit(Keytab, Principal) of
        ok ->
            case sasl_auth:client_new(<<"kafka">>, Host, Principal) of
                {ok, SaslConn} ->
                    {ok, State#{sasl_conn => SaslConn}};
                Error ->
                    Error
            end;
        Error ->
            Error
    end.

-spec auth_begin(State :: brod_gssapi:state()) -> {ok, term()} | {error, term()}.
auth_begin(#{sasl_conn := Conn} = State) ->
    case sasl_auth:client_start(Conn) of
        {ok, SaslRes} ->
            case handshake(State) of
                ok ->
                    {ok, SaslRes};
                Error ->
                    Error
            end;
        Other ->
            Other
    end.

-spec auth_continue(State :: brod_gssapi:state(), {atom(), Challenge :: binary()}) ->
    ok | {error, term()}.
auth_continue(State, {sasl_ok, Challenge}) ->
    case send_sasl_token(State, Challenge) of
        {ok, _} ->
            set_sock_opts(State, [{active, once}]);
        Error ->
            Error
    end;
auth_continue(#{handshake_vsn := 1, sasl_conn := Conn} = State, {sasl_continue, Challenge}) ->
    case send_sasl_token(State, Challenge) of
        {ok, Token} ->
            case sasl_auth:client_step(Conn, Token) of
                {ok, SaslRes} ->
                    auth_continue(State, SaslRes);
                Other ->
                    Other
            end;
        Error ->
            Error
    end.

%%====================================================================
%% Internal functions
%%====================================================================

-dialyzer({nowarn_function, set_sock_opts/2}).
-spec set_sock_opts(State :: brod_gssapi:state(), [gen_tcp:option()]) -> ok | {error, inet:posix()}.
set_sock_opts(#{sock := Sock, transport_mod := gen_tcp}, Opts) ->
    inet:setopts(Sock, Opts);
set_sock_opts(#{sock := Sock, transport_mod := ssl}, Opts) ->
    ssl:setopts(Sock, Opts).

-spec send_sasl_token(State :: brod_gssapi:state(), Challenge :: binary()) ->
    {ok, binary()} | {error, term()}.
send_sasl_token(State, Challenge) ->
    #{handshake_vsn := HandshakeVsn, timeout := Timeout} = State,
    #{sock := Sock, transport_mod := Mod, client_id := ClientId} = State,
    Req = kpro_req_lib:make(sasl_authenticate, HandshakeVsn, [{auth_bytes, Challenge}]),
    Rsp = kpro_lib:send_and_recv(Req, Sock, Mod, ClientId, Timeout),

    case kpro:find(error_code, Rsp) of
        no_error ->
            {ok, kpro:find(auth_bytes, Rsp)};
        _ ->
            {error, kpro:find(error_message, Rsp)}
    end.

-spec handshake(State :: brod_gssapi:state()) -> ok | {error, term()}.
handshake(State) ->
    #{handshake_vsn := HandshakeVsn, mechanism := Mech, timeout := Timeout} = State,
    #{sock := Sock, transport_mod := Mod, client_id := ClientId} = State,
    Req = kpro_req_lib:make(sasl_handshake, HandshakeVsn, [{mechanism, Mech}]),
    Rsp = kpro_lib:send_and_recv(Req, Sock, Mod, ClientId, Timeout),
    case kpro:find(error_code, Rsp) of
        no_error ->
            ok;
        unsupported_sasl_mechanism ->
            EnabledMechanisms = kpro:find(enabled_mechanisms, Rsp),
            Msg = io_lib:format(
                "sasl mechanism ~s is not enabled in "
                "kafka, enabled mechanism(s): ~s",
                [Mech, string:join(EnabledMechanisms, ",")]
            ),
            {error, iolist_to_binary(Msg)};
        Other ->
            {error, Other}
    end.
