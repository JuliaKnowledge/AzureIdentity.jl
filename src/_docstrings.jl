# Auto-attached docstrings for AzureIdentity exports. These are concise
# summaries; for the authoritative spec see the upstream Microsoft
# `azure-identity` documentation:
# https://learn.microsoft.com/python/api/azure-identity/azure.identity

# ── Core types ───────────────────────────────────────────────────────────────

@doc "Abstract supertype for all Azure credentials. Concrete subtypes implement `get_token` (and optionally `get_token_info`, `authenticate`)." AbstractAzureCredential
@doc "An access token returned by Azure AD: bearer string and absolute expiration timestamp." AzureAccessToken
@doc "Extended access-token information: bearer string, expiration, refresh-on hint, claims challenge, and tenant id." AzureAccessTokenInfo
@doc "Per-call options passed to `get_token`/`get_token_info`: tenant id, claims challenge, and proof-of-possession parameters." TokenRequestOptions
@doc "Persistent record describing an authenticated user — username, home-account id, tenant id, authority, and client id. Returned by `authenticate` and reusable across processes via `serialize_authentication_record` / `load_authentication_record`." AuthenticationRecord
@doc "Options controlling on-disk persistence of the MSAL token cache (filename, allow-unencrypted-storage flag)." TokenCachePersistenceOptions
@doc "Return `true` if the access token has already expired (with a small safety margin)." is_expired

# ── Token acquisition ────────────────────────────────────────────────────────

@doc "Acquire an Azure AD access token for the requested scope(s) using the supplied credential. Returns an `AzureAccessToken`." get_token
@doc "Like `get_token`, but returns an `AzureAccessTokenInfo` with extended metadata (refresh-on hint, tenant id, claims)." get_token_info
@doc "Trigger an interactive sign-in flow (where supported) and return an `AuthenticationRecord` for cache reuse." authenticate
@doc "Asynchronous wrapper around `get_token`, returning a `Task{AzureAccessToken}`." get_token_async
@doc "Asynchronous wrapper around `get_token_info`, returning a `Task{AzureAccessTokenInfo}`." get_token_info_async
@doc "Asynchronous wrapper around `authenticate`, returning a `Task{AuthenticationRecord}`." authenticate_async
@doc "Return a zero-argument closure `() -> bearer_string` that lazily acquires (and refreshes) tokens for a given scope. Useful as a callback for HTTP clients that accept a token-provider lambda." get_bearer_token_provider

# ── Authentication-record persistence ────────────────────────────────────────

@doc "Serialize an `AuthenticationRecord` to a JSON string." serialize_authentication_record
@doc "Parse an `AuthenticationRecord` from a JSON string previously produced by `serialize_authentication_record`." deserialize_authentication_record
@doc "Persist an `AuthenticationRecord` to a file path." save_authentication_record
@doc "Load an `AuthenticationRecord` from a file path previously written by `save_authentication_record`." load_authentication_record

# ── Service-principal credentials ────────────────────────────────────────────

@doc "Credential that reads its configuration from `AZURE_*` environment variables (client id, secret/certificate, tenant id, etc.). Useful for production and CI environments." EnvironmentCredential
@doc "Credential that authenticates a service principal using a tenant id, client id, and client secret." ClientSecretCredential
@doc "Credential that authenticates a service principal using a callback-supplied client assertion (typically a federated JWT)." ClientAssertionCredential
@doc "Credential that authenticates a service principal using an X.509 certificate (PEM/PFX file or in-memory bytes)." CertificateCredential
@doc "Credential that authenticates a user with username and password using the resource owner password credentials (ROPC) flow. Not recommended for production; use only when other flows are unavailable." UsernamePasswordCredential
@doc "Credential that authenticates a workload (e.g. AKS pod) via a federated identity token mounted by the Kubernetes service-account-token projection." WorkloadIdentityCredential
@doc "Credential that authenticates an Azure DevOps pipeline service connection using a federated OIDC token." AzurePipelinesCredential
@doc "Credential that authenticates *on behalf of* an upstream user-assertion JWT — the OAuth 2.0 OBO flow used by middle-tier APIs." OnBehalfOfCredential

# ── Managed-identity credentials ─────────────────────────────────────────────

@doc "Credential that authenticates using an Azure Managed Identity (system-assigned or user-assigned). Probes the IMDS, App Service, Azure Arc, Cloud Shell, and Service Fabric endpoints automatically." ManagedIdentityCredential

# ── Chained / default credentials ────────────────────────────────────────────

@doc "Credential that tries a sequence of underlying credentials in order, returning the first token acquired successfully." ChainedTokenCredential
@doc "Convenience credential that probes (in order) `EnvironmentCredential`, `WorkloadIdentityCredential`, `ManagedIdentityCredential`, `SharedTokenCacheCredential`, `AzureCliCredential`, `AzurePowerShellCredential`, `AzureDeveloperCliCredential`, and (optionally) `InteractiveBrowserCredential`. The recommended starting point for most apps." DefaultAzureCredential
@doc "Wrapper that caches the access token returned by an inner credential until it (nearly) expires, avoiding redundant network calls." CachedCredential
@doc "Clear any access token cached by a `CachedCredential` (or compatible credential)." clear_cache!

# ── Developer credentials ────────────────────────────────────────────────────

@doc "Credential that requests a token by shelling out to the Azure CLI (`az account get-access-token`). Requires `az login`." AzureCliCredential
@doc "Alias for `AzureCliCredential` matching upstream `azure-identity` casing (`AzureCLICredential`)." AzureCLICredential
@doc "Credential that requests a token by shelling out to Azure PowerShell (`Get-AzAccessToken`). Requires `Connect-AzAccount`." AzurePowerShellCredential
@doc "Credential that requests a token by shelling out to the Azure Developer CLI (`azd auth token`). Requires `azd auth login`." AzureDeveloperCliCredential
@doc "Credential backed by the MSAL shared token cache populated by other Microsoft developer tools (Visual Studio, etc.)." SharedTokenCacheCredential
@doc "Credential backed by a token cached by the Visual Studio Code Azure Account extension." VisualStudioCodeCredential

# ── Interactive credentials ──────────────────────────────────────────────────

@doc "Credential that prompts the user to complete the OAuth device-code flow at https://microsoft.com/devicelogin." DeviceCodeCredential
@doc "Credential that opens the system browser to complete the OAuth interactive authorization-code flow with PKCE." InteractiveBrowserCredential
@doc "Credential that exchanges a previously obtained authorization code for an access token (server-side flow)." AuthorizationCodeCredential

# ── Constants & utilities ────────────────────────────────────────────────────

@doc "Module containing well-known Azure AD authority hosts (`AZURE_PUBLIC_CLOUD`, `AZURE_GOVERNMENT`, `AZURE_CHINA`, etc.)." AzureAuthorityHosts
@doc "Alias for `AzureAuthorityHosts` matching upstream naming." KnownAuthorities
@doc "The `04b07795-…` Microsoft developer-tooling client id used by Azure CLI / PowerShell / azd." DEVELOPER_SIGN_ON_CLIENT_ID
@doc "Default OAuth scope for Azure OpenAI Cognitive Services (`https://cognitiveservices.azure.com/.default`)." AZURE_OPENAI_SCOPE
@doc "Convenience wrapper that returns a bearer token suitable for Azure OpenAI calls — equivalent to `get_token(cred, AZURE_OPENAI_SCOPE).token`." get_openai_token

# ── Exceptions ───────────────────────────────────────────────────────────────

@doc "Abstract supertype for all AzureIdentity errors." AbstractAzureAuthError
@doc "Generic Azure authentication error. Raised when no more specific subclass applies." AzureAuthError
@doc "Raised when authentication failed and was rejected by the identity provider (e.g. invalid secret, MFA challenge unmet)." ClientAuthenticationError
@doc "Raised when a credential is unable to attempt authentication (e.g. required environment variable missing). Caught by `ChainedTokenCredential` to fall through to the next credential." CredentialUnavailableError
@doc "Raised when interactive authentication is required but cannot be initiated (e.g. headless environment with no fallback)." AuthenticationRequiredError
@doc "Raised when the on-disk token cache cannot be read or written." TokenCachePersistenceError
