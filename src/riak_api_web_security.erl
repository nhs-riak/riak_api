%% @doc Some security helper functions for Riak API endpoints
-module(riak_api_web_security).

-export([is_authorized/1,log_login_event/3,log_login_event/4]).

%% @doc Check if the user is authorized
-spec is_authorized(any()) -> {true, any()} | false | insecure.
is_authorized(ReqData) ->
    case riak_core_security:is_enabled() of
        true ->
            Scheme = wrq:scheme(ReqData),
            case Scheme == https of
                true ->
                    case wrq:get_req_header("Authorization", ReqData) of
                        "Basic " ++ Base64 ->
                            UserPass = base64:decode_to_string(Base64),
                            [User, Pass] = [list_to_binary(X) || X <-
                                                                 string:tokens(UserPass, ":")],
                            {ok, Peer} = inet_parse:address(wrq:peer(ReqData)),
                            case riak_core_security:authenticate(User, Pass,
                                    [{ip, Peer}])
                                of
                                {ok, Sec} ->
                                    {true, Sec};
                                {error, Reason} ->
                                    log_login_event(failure, ReqData, User, Reason),
                                    false
                            end;
                        _ ->
                            log_login_event(failure, ReqData, unknown, "missing Authorization header"),
                            false
                    end;
                false ->
                    %% security is enabled, but they're connecting over HTTP.
                    %% which means if they authed, the credentials would be in
                    %% plaintext
                    log_login_event(failure, ReqData, unknown, "insecure request when security is enabled"),
                    insecure
            end;
        false ->
            {true, undefined} %% no security context
    end.

%% @doc log HTTP login attempts
log_login_event(success, ReqData, User) ->
    login:info("Successful login for http ~p request against path: ~p for user: ~s from host: ~s. Query info: ~p with tokens: ~p",
        [wrq:method(ReqData), wrq:raw_path(ReqData), User, wrq:peer(ReqData), wrq:path_info(ReqData), wrq:path_tokens(ReqData)]).
log_login_event(failure, ReqData, User, Reason) ->
    login:error("Failed login for http ~p request against path: ~p for user: ~s from host: ~s with reason: ~p. Query info: ~p with tokens: ~p",
        [wrq:method(ReqData), wrq:raw_path(ReqData), User, wrq:peer(ReqData), Reason, wrq:path_info(ReqData), wrq:path_tokens(ReqData)]).