module AzureIdentity

using Base64
using Dates
using HTTP
using JSON3
using OpenSSL
using Random
using SHA
using Sockets
using UUIDs

include("exceptions.jl")
include("constants.jl")
include("types.jl")
include("utils.jl")
include("cache.jl")
include("oauth.jl")
include("credentials.jl")
include("_docstrings.jl")

export AbstractAzureCredential,
    AzureAccessToken,
    AzureAccessTokenInfo,
    TokenRequestOptions,
    AuthenticationRecord,
    TokenCachePersistenceOptions,
    AbstractAzureAuthError,
    AzureAuthError,
    ClientAuthenticationError,
    CredentialUnavailableError,
    AuthenticationRequiredError,
    TokenCachePersistenceError,
    get_token,
    get_token_info,
    authenticate,
    get_token_async,
    get_token_info_async,
    authenticate_async,
    is_expired,
    get_bearer_token_provider,
    serialize_authentication_record,
    deserialize_authentication_record,
    save_authentication_record,
    load_authentication_record,
    EnvironmentCredential,
    ClientSecretCredential,
    ClientAssertionCredential,
    CertificateCredential,
    UsernamePasswordCredential,
    WorkloadIdentityCredential,
    AzurePipelinesCredential,
    OnBehalfOfCredential,
    ManagedIdentityCredential,
    ChainedTokenCredential,
    DefaultAzureCredential,
    AzureCliCredential,
    AzureCLICredential,
    AzurePowerShellCredential,
    AzureDeveloperCliCredential,
    SharedTokenCacheCredential,
    VisualStudioCodeCredential,
    DeviceCodeCredential,
    InteractiveBrowserCredential,
    AuthorizationCodeCredential,
    CachedCredential,
    clear_cache!,
    AzureAuthorityHosts,
    KnownAuthorities,
    DEVELOPER_SIGN_ON_CLIENT_ID,
    AZURE_OPENAI_SCOPE,
    get_openai_token

end # module AzureIdentity
