-module(brod_auth_backend).

-callback auth(Host :: string(), Sock :: gen_tcp:socket() | ssl:sslsocket(), Mod :: atom(), ClientId :: binary(), Timeout :: pos_integer(), SaslOpts :: term()) -> ok | {error, Reason :: term()}.