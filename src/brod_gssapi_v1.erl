%%%-------------------------------------------------------------------
%% @doc
%% SASL GSSAPI auth backend for brod
%% @end
%%%-------------------------------------------------------------------
-module(brod_gssapi_v1).

-export([auth/6]).

-type state() :: #{
    host := binary(),
    sock := gen_tcp:socket() | ssl:sslsocket(),
    transport_mod := gen_tcp | ssl,
    client_id := binary(),
    timeout := pos_integer(),
    method := any(),
    keytab := binary(),
    principal := binary(),
    mechanism := binary(),
    sasl_context := binary(),
    sasl_conn := sasl_auth:state() | undefined,
    handshake_vsn := non_neg_integer()
}.

%%%-------------------------------------------------------------------
%% @doc
%% Returns 'ok' if authentication successfully completed. See spec in behavior
%% @end
% Observed Sequence of handshake is as follows:
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
    HandshakeVsn = 1,

    State = new_state(Host, Sock, Mod, ClientId, HandshakeVsn, Timeout, Opts),
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

-spec auth_init(State :: state()) -> {ok, state()} | {error, term()}.
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

-spec auth_begin(State :: state()) -> {ok, term()} | {error, term()}.
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

-spec auth_continue(State :: state(), {atom(), Challenge :: binary()}) -> ok | {error, term()}.
auth_continue(State, {sasl_ok, Challenge}) ->
    case send_sasl_token(State, Challenge) of
        {ok, _} ->
            set_sock_opts(State, [{active, once}]);
        Error ->
            Error
    end;
auth_continue(#{sasl_conn := Conn} = State, {sasl_continue, Challenge}) ->
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

-spec new_state(
    Host :: string(),
    Sock :: gen_tcp:socket() | ssl:sslsocket(),
    Mod :: gen_tcp | ssl,
    ClientId :: binary(),
    HandshakeVsn :: non_neg_integer(),
    Timeout :: pos_integer(),
    SaslOpts :: term()
) -> state().
new_state(Host, Sock, Mod, ClientId, HandshakeVsn, Timeout, {Method, KeyTab, Principal}) ->
    #{
        host => ensure_binary(Host),
        sock => Sock,
        transport_mod => Mod,
        client_id => ClientId,
        timeout => Timeout,
        method => Method,
        mechanism => <<"GSSAPI">>,
        keytab => ensure_binary(KeyTab),
        principal => ensure_binary(Principal),
        sasl_context => <<"kafka">>,
        handshake_vsn => HandshakeVsn,
        sasl_conn => undefined
    }.

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

-dialyzer({nowarn_function, set_sock_opts/2}).
-spec set_sock_opts(State :: state(), [gen_tcp:option()]) -> ok | {error, inet:posix()}.
set_sock_opts(#{sock := Sock, transport_mod := gen_tcp}, Opts) ->
    inet:setopts(Sock, Opts);
set_sock_opts(#{sock := Sock, transport_mod := ssl}, Opts) ->
    ssl:setopts(Sock, Opts).

-spec send_sasl_token(State :: state(), Challenge :: binary()) -> {ok, binary()} | {error, term()}.
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

-spec handshake(State :: state()) -> ok | {error, term()}.
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
