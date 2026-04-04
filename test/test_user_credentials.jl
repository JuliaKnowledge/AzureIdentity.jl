@testset "AzureIdentity user-interactive credentials" begin
    @testset "DeviceCodeCredential authenticates and persists tokens" begin
        prompts = Any[]
        calls = Ref(0)
        mktempdir() do dir
            options = TokenCachePersistenceOptions(name = "device", directory = dir, allow_unencrypted_storage = true, backend = AzureIdentity.PlaintextTokenCacheBackend())
            runtime = AzureIdentity.CredentialRuntime(
                http_request = (method, url; headers = Dict{String, String}(), body = nothing, query = Dict{String, Any}(), timeout = 10) -> begin
                    calls[] += 1
                    if occursin("/devicecode", url)
                        return json_response(200, Dict(
                            "device_code" => "device-code",
                            "interval" => 0,
                            "expires_in" => 300,
                            "message" => "Visit https://microsoft.com/devicelogin",
                        ))
                    elseif calls[] == 2
                        return json_response(400, Dict("error" => "authorization_pending"))
                    end
                    return json_response(200, Dict(
                        "access_token" => "device-token",
                        "expires_in" => 3600,
                        "refresh_token" => "device-refresh",
                        "id_token" => fake_jwt(Dict("preferred_username" => "device-user", "tid" => "tenant")),
                        "client_info" => AzureIdentity.base64url_encode(JSON3.write(Dict("uid" => "uid", "utid" => "utid"))),
                    ))
                end,
                sleep_fn = seconds -> nothing,
            )
            credential = DeviceCodeCredential(
                tenant_id = "tenant",
                cache_persistence_options = options,
                prompt_callback = info -> push!(prompts, info),
                runtime = runtime,
            )
            token = get_token_info(credential, "scope/.default")
            @test token.token == "device-token"
            @test credential.authentication_record.username == "device-user"
            @test length(prompts) == 1
            entries = AzureIdentity._load_token_entries(options)
            @test length(entries) == 1
            @test entries[1].refresh_token == "device-refresh"
        end
    end

    @testset "InteractiveBrowserCredential handles loopback redirect" begin
        runtime = AzureIdentity.CredentialRuntime(
            http_request = (method, url; headers = Dict{String, String}(), body = nothing, query = Dict{String, Any}(), timeout = 10) -> begin
                form = form_dict(String(body))
                @test form["grant_type"] == "authorization_code"
                @test form["code"] == "browser-code"
                return json_response(200, Dict(
                    "access_token" => "browser-token",
                    "expires_in" => 3600,
                    "refresh_token" => "browser-refresh",
                    "id_token" => fake_jwt(Dict("preferred_username" => "browser-user", "tid" => "tenant")),
                    "client_info" => AzureIdentity.base64url_encode(JSON3.write(Dict("uid" => "uid", "utid" => "utid"))),
                ))
            end,
            open_browser = url -> loopback_redirect(url),
        )
        credential = InteractiveBrowserCredential(
            tenant_id = "tenant",
            runtime = runtime,
        )
        token = get_token_info(credential, "scope/.default")
        @test token.token == "browser-token"
        @test credential.authentication_record.username == "browser-user"
    end

    @testset "AuthorizationCodeCredential exchanges code once and then uses cache" begin
        calls = Ref(0)
        runtime = AzureIdentity.CredentialRuntime(
            http_request = (method, url; headers = Dict{String, String}(), body = nothing, query = Dict{String, Any}(), timeout = 10) -> begin
                calls[] += 1
                return json_response(200, Dict(
                    "access_token" => "code-token",
                    "expires_in" => 3600,
                    "id_token" => fake_jwt(Dict("preferred_username" => "code-user", "tid" => "tenant")),
                    "client_info" => AzureIdentity.base64url_encode(JSON3.write(Dict("uid" => "uid", "utid" => "utid"))),
                ))
            end,
        )
        credential = AuthorizationCodeCredential(
            tenant_id = "tenant",
            client_id = "client",
            authorization_code = "auth-code",
            redirect_uri = "http://127.0.0.1/callback",
            runtime = runtime,
        )
        @test get_token_info(credential, "scope/.default").token == "code-token"
        @test get_token_info(credential, "scope/.default").token == "code-token"
        @test calls[] == 1
    end

    @testset "Interactive credentials can require explicit authenticate" begin
        credential = DeviceCodeCredential(disable_automatic_authentication = true)
        @test_throws AuthenticationRequiredError get_token_info(credential, "scope/.default")
    end
end
