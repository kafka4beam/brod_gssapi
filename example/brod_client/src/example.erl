-module(example).

-export([main/1]).

main(_Args) ->
    try
        {ok, _} = application:ensure_all_started(brod),
        ok = application:load(brod_gssapi),
        application:set_env(brod_gssapi,
                            default_handshake_vsn,
                            1),
        KafkaBootstrapEndpoints = [{"kafka.kerberos-demo.local", 9093}],
        Topic = <<"mytest">>,
        Partition = 0,
        KeyTab = <<"/var/lib/secret/rig.key">>,
        Principal = <<"rig@TEST.CONFLUENT.IO">>,
        Config = [{sasl, {callback, brod_gssapi, {gssapi, KeyTab, Principal}}}],
        ok = brod:start_client(KafkaBootstrapEndpoints, client1, Config),
        ok = brod:start_producer(client1, Topic, _ProducerConfig = []),
        {ok, FirstOffset} = brod:produce_sync_offset(client1, Topic, Partition, <<"FistKey">>, <<"FirstValue">>),
        ok = brod:produce_sync(client1, Topic, Partition, <<"SecondKey">>, <<"SecondValue">>),
        SubscriberCallbackFun = fun(_Partition, Msg, ShellPid = CallbackState) ->
                                        ShellPid ! Msg, {ok, ack, CallbackState}
                                end,
        Receive = fun() ->
                          receive
                              Msg -> Msg
                          after 1000 -> timeout
                          end
                  end,
        brod_topic_subscriber:start_link(client1,
                                         Topic,
                                         _Partitions=[Partition],
                                         _ConsumerConfig=[{begin_offset, FirstOffset}],
                                         _CommittdOffsets=[], message, SubscriberCallbackFun,
                                         _CallbackState=self()),
        %AckCb = fun(Partition, BaseOffset) -> io:format(user, "\nProduced to partition ~p at base-offset ~p\n", [Partition, BaseOffset]) end,
        %ok = brod:produce_cb(client1, Topic, Partition, <<>>, [{<<"key3">>, <<"value3">>}], AckCb)
        timer:sleep(1000),
        {kafka_message,_,<<"FistKey">>,<<"FirstValue">>,_,_,_} = Receive(),
        {kafka_message,_,<<"SecondKey">>,<<"SecondValue">>,_,_,_} = Receive(),
        io:format("~n~n~n~n~n\033[0;32mSUCCESS\033[0m (Sent and received messages with brod)~n~n~n~n~n"),
        erlang:halt(0)
    catch
        ErrorClass : Reason : Stack -> 
            io:format("~n~n~n~n~n\033[0;31mFAIL\033[0m (Failed to send and receive messages with brod)~n~n ~p:~p:~p~n~n~n~n~n", [ErrorClass, Reason, Stack]),
            erlang:halt(1)
    end.

