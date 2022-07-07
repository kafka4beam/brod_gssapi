%% @private
-module(brod_gssapi_v0).

-export([auth/6]).

-define(HANDSHAKE_V0, 0).

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
    State = brod_gssapi:new(Host, Sock, Mod, ClientId, ?HANDSHAKE_V0, Timeout, Opts),
    auth(State).
%
auth(State) ->
    case auth_init(State) of
        {ok, State1} ->
            case auth_begin(State1) of
                {ok, SaslRes} ->
                    ok = set_sock_opts(State1, [{active, false}]),
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
            auth_continue(State, SaslRes);
        Other ->
            Other
    end.

auth_continue(
    #{sasl_conn := Conn, transport_mod := Mod, sock := Sock, timeout := Timeout} = State,
    {sasl_continue, Challenge}
) ->
    case send_sasl_token(State, Challenge) of
        ok ->
            case Mod:recv(Sock, 4, Timeout) of
                {ok, <<0:32>>} ->
                    %% we're done ?
                    ok = set_sock_opts(State, [{active, once}]);
                {ok, <<BrokerTokenSize:32>>} ->
                    case Mod:recv(Sock, BrokerTokenSize, Timeout) of
                        {ok, BrokerToken} ->
                            case sasl_auth:client_step(Conn, BrokerToken) of
                                {ok, SaslRes} ->
                                    auth_continue(State, SaslRes);
                                Other ->
                                    Other
                            end;
                        Error ->
                            Error
                    end
            end
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

sasl_token(Challenge) ->
    <<(byte_size(Challenge)):32, Challenge/binary>>.

send_sasl_token(#{sock := Sock, transport_mod := Mod}, Challenge) ->
    ok = Mod:send(Sock, sasl_token(Challenge)).
