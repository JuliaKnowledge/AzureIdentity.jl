# AzureIdentity.jl

AzureIdentity.jl provides Julia credentials and token helpers for Azure services. It includes service principal credentials, managed identity, workload identity, cached developer credentials, device code and browser sign-in flows, token providers, and persistent token cache support.

Planned repository: <https://github.com/JuliaKnowledge/AzureIdentity.jl>

## Installation

Until the package is registered:

```julia
using Pkg
Pkg.develop(path="path/to/AzureIdentity.jl")
```

After registration:

```julia
using Pkg
Pkg.add("AzureIdentity")
```

## Highlights

- Client secret, client assertion, certificate, on-behalf-of, and workload identity credentials
- Managed identity, Azure CLI, Azure PowerShell, Azure Developer CLI, and shared cache credentials
- Device code, interactive browser, and authorization code flows
- Bearer token provider helpers for Azure SDK and service integrations
- Platform-aware persistent cache backends and Julian async helpers

## License

MIT License. Copyright (c) 2026 Simon Frost.
