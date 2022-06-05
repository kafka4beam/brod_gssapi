%%%-------------------------------------------------------------------
%% @doc
%% SASL GSSAPI auth backend for brod
%% @end
%%%-------------------------------------------------------------------
-module(brod_gssapi).

-export([auth/6, auth/7, new/7]).

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

-export_type([state/0]).

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
    auth(Host, Sock, Mod, ClientId, 0, Timeout, Opts).

%%%-------------------------------------------------------------------
%% @doc
%% Returns 'ok' if authentication successfully completed. See spec in behavior
%% @end
% Observed Sequence of handshake is as follows:
-spec auth(
    Host :: string(),
    Sock :: gen_tcp:socket() | ssl:sslsocket(),
    HandshakeVsn :: non_neg_integer(),
    Mod :: gen_tcp | ssl,
    ClientId :: binary(),
    Timeout :: pos_integer(),
    SaslOpts :: term()
) -> ok | {error, Reason :: term()}.
auth(
    Host,
    Sock,
    HandshakeVsn,
    Mod,
    ClientId,
    Timeout,
    Opts
) ->
    State = new(Host, Sock, HandshakeVsn, Mod, ClientId, Timeout, Opts),
    dispatch(State).

dispatch(#{handshake_vsn := 1} = State) ->
    brod_gssapi_v1:auth(State);
dispatch(#{handshake_vsn := 0} = State) ->
    brod_gssapi_v0:auth(State);
dispatch(_State) ->
    {error, undefined_handshake_vsn}.

%% Backwards compat where handshake isn't given
%auth(Host, Sock, Mod, _ClientId, Timeout, _SaslOpts = {_Method = gssapi, Keytab, Principal}) ->
%

-spec new(
    Host :: string(),
    Sock :: gen_tcp:socket() | ssl:sslsocket(),
    HandshakeVsn :: non_neg_integer(),
    Mod :: gen_tcp | ssl,
    ClientId :: binary(),
    Timeout :: pos_integer(),
    SaslOpts :: term()
) -> state().
new(Host, Sock, HandshakeVsn, Mod, ClientId, Timeout, {Method, KeyTab, Principal}) ->
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

-spec ensure_binary(atom() | iodata()) -> binary().
ensure_binary(Atom) when is_atom(Atom) ->
    atom_to_binary(Atom, utf8);
ensure_binary(Str) when is_list(Str) ->
    iolist_to_binary(Str);
ensure_binary(Bin) when is_binary(Bin) ->
    Bin.
