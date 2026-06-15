@testset "AzureIdentity core" begin
    token = AzureAccessTokenInfo(
        token = "token",
        expires_on = Dates.now(Dates.UTC) + Dates.Hour(1),
        scopes = ["scope/.default"],
    )
    @test !is_expired(token)
    @test is_expired(AzureAccessTokenInfo(token = "old", expires_on = Dates.now(Dates.UTC) - Dates.Minute(1)))

    record = AuthenticationRecord(
        authority = "https://login.microsoftonline.com",
        client_id = "client-id",
        tenant_id = "tenant-id",
        username = "cached-user",
        home_account_id = "uid.utid",
    )
    roundtrip = deserialize_authentication_record(serialize_authentication_record(record))
    @test roundtrip.authority == record.authority
    @test roundtrip.client_id == record.client_id
    @test roundtrip.username == record.username
    @test roundtrip.home_account_id == record.home_account_id

    mutable struct MockCredential <: AzureIdentity.AbstractAzureCredential
        count::Int
    end

    function AzureIdentity.get_token_info(credential::MockCredential, scopes::Vararg{String}; kwargs...)
        credential.count += 1
        return AzureAccessTokenInfo(
            token = "mock-token-$(credential.count)",
            expires_on = Dates.now(Dates.UTC) + Dates.Hour(1),
            scopes = collect(scopes),
        )
    end

    cached = CachedCredential(MockCredential(0))
    @test get_token_info(cached, "scope/.default").token == get_token_info(cached, "scope/.default").token
    @test cached.inner.count == 1
    clear_cache!(cached)
    @test get_token_info(cached, "scope/.default").token != "mock-token-1"

    refresh_cache = AzureIdentity.AccessTokenCache()
    stale = AzureAccessTokenInfo(
        token = "stale",
        expires_on = Dates.now(Dates.UTC) + Dates.Hour(1),
        refresh_on = Dates.now(Dates.UTC) - Dates.Minute(1),
    )
    AzureIdentity.put_cached_token!(refresh_cache, "stale", stale)
    # A token whose refresh_on has passed but which is not expired is still usable.
    @test AzureIdentity.get_cached_token(refresh_cache, "stale"; now_fn = () -> Dates.now(Dates.UTC)) === stale
    # ...but its refresh status is RECOMMENDED so callers attempt a proactive refresh.
    _, status = AzureIdentity.cached_token_status(refresh_cache, "stale"; now_fn = () -> Dates.now(Dates.UTC))
    @test status == AzureIdentity.REFRESH_RECOMMENDED

    # An expired token is a hard miss.
    expired_cache = AzureIdentity.AccessTokenCache()
    AzureIdentity.put_cached_token!(expired_cache, "gone", AzureAccessTokenInfo(token = "gone", expires_on = Dates.now(Dates.UTC) - Dates.Minute(1)))
    @test AzureIdentity.get_cached_token(expired_cache, "gone"; now_fn = () -> Dates.now(Dates.UTC)) === nothing

    provider = get_bearer_token_provider(MockCredential(0), "scope/.default")
    @test startswith(provider(), "mock-token-")

    task = get_token_async(MockCredential(0), "scope/.default")
    @test fetch(task).token == "mock-token-1"
end
