abstract type AbstractAzureCredential end

abstract type AbstractTokenCacheBackend end

struct AutoTokenCacheBackend <: AbstractTokenCacheBackend end
struct PlaintextTokenCacheBackend <: AbstractTokenCacheBackend end

Base.@kwdef mutable struct InMemoryTokenCacheBackend <: AbstractTokenCacheBackend
    secrets::Dict{String, Vector{UInt8}} = Dict{String, Vector{UInt8}}()
end

Base.@kwdef mutable struct AzureAccessToken
    token::String
    expires_on::DateTime
    resource::Union{Nothing, String} = nothing
    token_type::String = "Bearer"
    refresh_on::Union{Nothing, DateTime} = nothing
end

Base.@kwdef mutable struct AzureAccessTokenInfo
    token::String
    expires_on::DateTime
    token_type::String = "Bearer"
    refresh_on::Union{Nothing, DateTime} = nothing
    resource::Union{Nothing, String} = nothing
    scopes::Vector{String} = String[]
    claims::Union{Nothing, String} = nothing
    tenant_id::Union{Nothing, String} = nothing
    extras::Dict{String, Any} = Dict{String, Any}()
end

AzureAccessToken(info::AzureAccessTokenInfo) = AzureAccessToken(
    token = info.token,
    expires_on = info.expires_on,
    resource = info.resource,
    token_type = info.token_type,
    refresh_on = info.refresh_on,
)

Base.@kwdef struct TokenRequestOptions
    claims::Union{Nothing, String} = nothing
    tenant_id::Union{Nothing, String} = nothing
    enable_cae::Bool = false
end

Base.@kwdef struct AuthenticationRecord
    authority::String
    client_id::String
    tenant_id::String
    username::Union{Nothing, String} = nothing
    home_account_id::Union{Nothing, String} = nothing
    version::String = "1.0"
end

Base.@kwdef struct TokenCachePersistenceOptions
    name::String = "azureidentity"
    directory::String = joinpath(homedir(), ".azureidentity")
    allow_unencrypted_storage::Bool = false
    backend::AbstractTokenCacheBackend = AutoTokenCacheBackend()
end

Base.@kwdef struct HTTPResult
    status::Int
    headers::Dict{String, String} = Dict{String, String}()
    body::String = ""
end

Base.@kwdef struct ProcessResult
    exitcode::Int
    stdout::String = ""
    stderr::String = ""
end

Base.@kwdef mutable struct AccessTokenCache
    tokens::Dict{String, AzureAccessTokenInfo} = Dict{String, AzureAccessTokenInfo}()
    last_refresh_attempt::Dict{String, DateTime} = Dict{String, DateTime}()
    lock::ReentrantLock = ReentrantLock()
end

Base.@kwdef mutable struct TokenStoreEntry
    scopes::Vector{String} = String[]
    access_token::Union{Nothing, String} = nothing
    expires_on::Union{Nothing, DateTime} = nothing
    refresh_on::Union{Nothing, DateTime} = nothing
    refresh_token::Union{Nothing, String} = nothing
    client_id::Union{Nothing, String} = nothing
    tenant_id::Union{Nothing, String} = nothing
    authority::Union{Nothing, String} = nothing
    username::Union{Nothing, String} = nothing
    home_account_id::Union{Nothing, String} = nothing
    claims::Union{Nothing, String} = nothing
    enable_cae::Bool = false
    token_type::String = "Bearer"
end

Base.@kwdef struct OAuthTokenResult
    token::AzureAccessTokenInfo
    refresh_token::Union{Nothing, String} = nothing
    id_token::Union{Nothing, String} = nothing
    client_info::Union{Nothing, String} = nothing
    raw::Dict{String, Any} = Dict{String, Any}()
end
