%% @private
-module(brod_gssapi_v1).

-export([auth/1, auth/6]).

-define(HANDSHAKE_V1, 1).

%%% Flow :
%%%
%%% Note any error is immediately returned back up the stack to kafka_protocol.
%%%
%%% -----------------------------------------------------------------
%%% 1) Initialize a TGT cache for the specified principal via
%%%    sasl_auth:kinit/2 and continue to step 2 if successfull.
%%%
%%% 2) Initial a new sasl context for the auth session and continue
%%%    to step 3 if successful.
%%%
%%% 3) Select a mechanism (GSSAPI) and start a sasl auth session.
%%%    A successful start returns our first sasl token which is used
%%%    in step 5. Move forward to step 3 if successful.
%%%
%%% 4) We now perform a handshake with Kafka using the SaslHandshake call
%%%    with GSSAPI mechanism (see references for detail).
%%%    If Kafka supports GSSAPI mechanism, we are OK to move ahead to step 5.
%%%
%%% 5) At this point we we send the token received via sasl_auth in step 3
%%%    to kafka. Kafka will respond with either a new token or an
%%%    error. Continue to step 6 if a token was received.
%%%
%%% 6) Now we send the token received from kafka in step 5 to our first
%%%    sasl_auth:client_step/2 call. If successfull, we get back
%%%    `{sasl_continue, Token}` if successful and we may continue to
%%%    step 7.
%%%
%%% 7. Now we simply repeat steps 4 and 6 until we sasl_auth:client_step/2
%%%    returns `{sasl_ok, Token}' or we receive an error from either
%%%    sasl_auth:client_step/2 or kafka.
%%%
%%% 8) Once we have received `{sasl_ok, Token}' from sasl_auth:client_step/2,
%%%    we are done but need to since this last returned sasl token to kafka
%%%    to ensure we are authenticated.
%%%
%%% -------------------------------------------------------------------

%%% References :
%%% The Kerberos V5 ("GSSAPI") SASL Mechnism - https://datatracker.ietf.org/doc/html/rfc4752
%%% KIP-43 - https://cwiki.apache.org/confluence/display/KAFKA/KIP-43%3A+Kafka+SASL+enhancements
%%% Introduction to SASL - https://docs.oracle.com/cd/E23824_01/html/819-2145/sasl.intro.20.html

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
