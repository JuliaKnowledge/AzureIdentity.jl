# API Reference

## Tokens and request options

```@docs
AzureIdentity.AbstractAzureCredential
AzureIdentity.AzureAccessToken
AzureIdentity.AzureAccessTokenInfo
AzureIdentity.TokenRequestOptions
AzureIdentity.AuthenticationRecord
AzureIdentity.TokenCachePersistenceOptions
AzureIdentity.is_expired
```

## Token acquisition

```@docs
AzureIdentity.get_token
AzureIdentity.get_token_info
AzureIdentity.authenticate
AzureIdentity.get_token_async
AzureIdentity.get_token_info_async
AzureIdentity.authenticate_async
AzureIdentity.get_bearer_token_provider
```

## Authentication-record persistence

```@docs
AzureIdentity.serialize_authentication_record
AzureIdentity.deserialize_authentication_record
AzureIdentity.save_authentication_record
AzureIdentity.load_authentication_record
```

## Service-principal credentials

```@docs
AzureIdentity.EnvironmentCredential
AzureIdentity.ClientSecretCredential
AzureIdentity.ClientAssertionCredential
AzureIdentity.CertificateCredential
AzureIdentity.UsernamePasswordCredential
AzureIdentity.WorkloadIdentityCredential
AzureIdentity.AzurePipelinesCredential
AzureIdentity.OnBehalfOfCredential
```

## Managed-identity credentials

```@docs
AzureIdentity.ManagedIdentityCredential
```

## Chained / default credentials

```@docs
AzureIdentity.ChainedTokenCredential
AzureIdentity.DefaultAzureCredential
AzureIdentity.CachedCredential
AzureIdentity.clear_cache!
```

## Developer credentials

```@docs
AzureIdentity.AzureCliCredential
AzureIdentity.AzureCLICredential
AzureIdentity.AzurePowerShellCredential
AzureIdentity.AzureDeveloperCliCredential
AzureIdentity.SharedTokenCacheCredential
AzureIdentity.VisualStudioCodeCredential
```

## Interactive credentials

```@docs
AzureIdentity.DeviceCodeCredential
AzureIdentity.InteractiveBrowserCredential
AzureIdentity.AuthorizationCodeCredential
```

## Constants & utilities

```@docs
AzureIdentity.AzureAuthorityHosts
AzureIdentity.KnownAuthorities
AzureIdentity.DEVELOPER_SIGN_ON_CLIENT_ID
AzureIdentity.AZURE_OPENAI_SCOPE
AzureIdentity.get_openai_token
```

## Exceptions

```@docs
AzureIdentity.AbstractAzureAuthError
AzureIdentity.AzureAuthError
AzureIdentity.ClientAuthenticationError
AzureIdentity.CredentialUnavailableError
AzureIdentity.AuthenticationRequiredError
AzureIdentity.TokenCachePersistenceError
```
