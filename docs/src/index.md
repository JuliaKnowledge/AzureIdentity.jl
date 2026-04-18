# AzureIdentity.jl

**AzureIdentity.jl** provides a Julia implementation of the
[Microsoft Azure Identity](https://learn.microsoft.com/azure/developer/python/sdk/authentication/credential-chains)
credential chain, mirroring the Python and .NET `azure-identity` SDKs. It
supplies token-acquisition primitives (`get_token`, `get_bearer_token_provider`)
and a comprehensive set of credentials suitable for development, production,
and CI environments — including `DefaultAzureCredential`,
`ChainedTokenCredential`, managed-identity, workload-identity, and
developer credentials (Azure CLI, Azure Developer CLI, PowerShell,
Visual Studio Code).

The package is the shared authentication layer used by the other Julia
ports in this ecosystem (`AgentFramework.jl`, `Mem0.jl`, `Graphiti.jl`,
`CopilotSDK.jl`, `MemPalace.jl`).

## Quick example

```julia
using AzureIdentity

cred = DefaultAzureCredential()
tok  = get_token(cred, "https://cognitiveservices.azure.com/.default")
@info "got token, expires at" expires_on=tok.expires_on
```

Pass the same credential to any package in the ecosystem to enable
managed-identity-based access without storing API keys:

```julia
using AgentFramework
client = OpenAIChatClient(; azure_credential = cred,
                            base_url = "https://my-aoai.openai.azure.com",
                            model    = "gpt-4o-mini")
```

## Contents

See the [API Reference](api.md) for the full surface, organised by
credential family.

## Module reference

`AzureIdentity` provides credential types and token-acquisition primitives
mirroring the Microsoft `azure-identity` SDK.
