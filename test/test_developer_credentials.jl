@testset "AzureIdentity developer credentials" begin
    @testset "AzureCliCredential parses CLI output" begin
        runtime = AzureIdentity.CredentialRuntime(
            run_process = (command; timeout = 10) -> AzureIdentity.ProcessResult(
                exitcode = 0,
                stdout = JSON3.write(Dict(
                    "accessToken" => "cli-token",
                    "expires_on" => string(AzureIdentity.datetime_to_epoch(Dates.now(Dates.UTC) + Dates.Hour(1))),
                )),
            ),
        )
        credential = AzureCliCredential(runtime = runtime)
        @test get_token_info(credential, "https://resource/.default").token == "cli-token"
        @test_throws CredentialUnavailableError get_token_info(credential, "https://resource/.default"; claims = "{\"access_token\":{}}")
    end

    @testset "AzureCliCredential treats expiresOn as local time" begin
        # `expiresOn` (no epoch field) is a naive LOCAL datetime; it must be converted to the
        # corresponding UTC instant, not interpreted as UTC.
        local_expiry = Dates.now() + Dates.Hour(1)
        expires_on_str = Dates.format(local_expiry, Dates.DateFormat("yyyy-mm-dd HH:MM:SS.s"))
        runtime = AzureIdentity.CredentialRuntime(
            run_process = (command; timeout = 10) -> AzureIdentity.ProcessResult(
                exitcode = 0,
                stdout = JSON3.write(Dict(
                    "accessToken" => "cli-local-token",
                    "expiresOn" => expires_on_str,
                )),
            ),
        )
        credential = AzureCliCredential(runtime = runtime)
        token = get_token_info(credential, "https://resource/.default")
        @test token.token == "cli-local-token"
        # Expiry should be ~1 hour from UTC now regardless of the machine's timezone.
        expected = AzureIdentity.local_naive_to_utc(Dates.DateTime(expires_on_str, Dates.DateFormat("yyyy-mm-dd HH:MM:SS.s")))
        @test abs(Dates.value(token.expires_on - expected)) < 2000
        @test abs(Dates.value(token.expires_on - (Dates.now(Dates.UTC) + Dates.Hour(1)))) < 5000
    end

    @testset "AzurePowerShellCredential parses prefixed output" begin
        runtime = AzureIdentity.CredentialRuntime(
            run_process = (command; timeout = 10) -> AzureIdentity.ProcessResult(
                exitcode = 0,
                stdout = "azsdk%pwsh-token%$(AzureIdentity.datetime_to_epoch(Dates.now(Dates.UTC) + Dates.Hour(1)))\n",
            ),
        )
        credential = AzurePowerShellCredential(runtime = runtime)
        @test get_token_info(credential, "https://resource/.default").token == "pwsh-token"
    end

    @testset "AzureDeveloperCliCredential supports claims" begin
        seen = Ref(``)
        runtime = AzureIdentity.CredentialRuntime(
            run_process = (command; timeout = 10) -> begin
                seen[] = command
                AzureIdentity.ProcessResult(
                    exitcode = 0,
                    stdout = JSON3.write(Dict(
                        "token" => "azd-token",
                        "expiresOn" => Dates.format(Dates.now(Dates.UTC) + Dates.Hour(1), Dates.DateFormat("yyyy-mm-ddTHH:MM:SSZ")),
                    )),
                )
            end,
        )
        credential = AzureDeveloperCliCredential(runtime = runtime)
        @test get_token_info(credential, "scope-one", "scope-two"; claims = "{\"a\":1}").token == "azd-token"
        @test occursin("--claims", sprint(show, seen[]))
    end

    @testset "SharedTokenCacheCredential refreshes expired entries" begin
        mktempdir() do dir
            options = TokenCachePersistenceOptions(name = "shared", directory = dir, allow_unencrypted_storage = true, backend = AzureIdentity.PlaintextTokenCacheBackend())
            entries = AzureIdentity.TokenStoreEntry[
                AzureIdentity.TokenStoreEntry(
                    scopes = ["scope/.default"],
                    access_token = "expired-token",
                    expires_on = Dates.now(Dates.UTC) - Dates.Minute(5),
                    refresh_token = "refresh-token",
                    client_id = "client",
                    tenant_id = "tenant",
                    authority = "https://login.microsoftonline.com",
                    username = "cached-user",
                    home_account_id = "uid.utid",
                ),
            ]
            AzureIdentity._save_token_entries(options, entries)
            runtime = AzureIdentity.CredentialRuntime(
                http_request = (method, url; headers = Dict{String, String}(), body = nothing, query = Dict{String, Any}(), timeout = 10) -> begin
                    form = form_dict(String(body))
                    @test form["grant_type"] == "refresh_token"
                    json_response(200, Dict(
                        "access_token" => "fresh-token",
                        "expires_in" => 3600,
                        "refresh_token" => "refresh-token-2",
                    ))
                end,
            )
            record = AuthenticationRecord(
                authority = "https://login.microsoftonline.com",
                client_id = "client",
                tenant_id = "tenant",
                username = "cached-user",
                home_account_id = "uid.utid",
            )
            credential = SharedTokenCacheCredential(
                client_id = "client",
                tenant_id = "tenant",
                authentication_record = record,
                cache_persistence_options = options,
                runtime = runtime,
            )
            @test get_token_info(credential, "scope/.default").token == "fresh-token"
        end
    end

    @testset "Persistent cache supports secure backends" begin
        mktempdir() do dir
            backend = AzureIdentity.InMemoryTokenCacheBackend()
            options = TokenCachePersistenceOptions(name = "secure", directory = dir, backend = backend)
            entries = AzureIdentity.TokenStoreEntry[
                AzureIdentity.TokenStoreEntry(
                    scopes = ["scope/.default"],
                    access_token = "secure-token",
                    expires_on = Dates.now(Dates.UTC) + Dates.Hour(1),
                    client_id = "client",
                    tenant_id = "tenant",
                    authority = "https://login.microsoftonline.com",
                ),
            ]
            AzureIdentity._save_token_entries(options, entries)
            @test haskey(backend.secrets, AzureIdentity._cache_file_path(options))
            @test read(AzureIdentity._cache_file_path(options), String) == ""
            loaded = AzureIdentity._load_token_entries(options)
            @test length(loaded) == 1
            @test loaded[1].access_token == "secure-token"
        end
    end

    @testset "VisualStudioCodeCredential loads auth record file" begin
        mktempdir() do dir
            options = TokenCachePersistenceOptions(name = "vscode", directory = dir, allow_unencrypted_storage = true, backend = AzureIdentity.PlaintextTokenCacheBackend())
            record = AuthenticationRecord(
                authority = "https://login.microsoftonline.com",
                client_id = "client",
                tenant_id = "tenant",
                username = "cached-user",
                home_account_id = "uid.utid",
            )
            record_path = joinpath(dir, "record.json")
            save_authentication_record(record_path, record)
            AzureIdentity._save_token_entries(options, AzureIdentity.TokenStoreEntry[
                AzureIdentity.TokenStoreEntry(
                    scopes = ["scope/.default"],
                    access_token = "cached-token",
                    expires_on = Dates.now(Dates.UTC) + Dates.Hour(1),
                    client_id = "client",
                    tenant_id = "tenant",
                    authority = "https://login.microsoftonline.com",
                    username = "cached-user",
                    home_account_id = "uid.utid",
                ),
            ])
            credential = VisualStudioCodeCredential(
                authentication_record_path = record_path,
                cache_persistence_options = options,
            )
            @test get_token_info(credential, "scope/.default").token == "cached-token"
        end
    end

    @testset "DefaultAzureCredential supports custom chains and env mode selection" begin
        struct FailingCredential <: AzureIdentity.AbstractAzureCredential end
        struct SucceedingCredential <: AzureIdentity.AbstractAzureCredential end

        AzureIdentity.get_token_info(::FailingCredential, scopes::Vararg{String}; kwargs...) = throw(CredentialUnavailableError("failed"))
        AzureIdentity.get_token_info(::SucceedingCredential, scopes::Vararg{String}; kwargs...) = AzureAccessTokenInfo(token = "success", expires_on = Dates.now(Dates.UTC) + Dates.Hour(1))

        credential = DefaultAzureCredential(credentials = AzureIdentity.AbstractAzureCredential[FailingCredential(), SucceedingCredential()])
        @test get_token_info(credential, "scope/.default").token == "success"

        withenv(Dict("AZURE_TOKEN_CREDENTIALS" => "dev")) do
            mode_credential = DefaultAzureCredential(exclude_interactive_browser_credential = true)
            @test all(inner -> !(inner isa EnvironmentCredential || inner isa ManagedIdentityCredential), mode_credential.credentials)
        end
    end
end
