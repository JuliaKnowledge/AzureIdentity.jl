abstract type AbstractAzureAuthError <: Exception end

struct AzureAuthError <: AbstractAzureAuthError
    message::String
end

struct ClientAuthenticationError <: AbstractAzureAuthError
    message::String
end

struct CredentialUnavailableError <: AbstractAzureAuthError
    message::String
end

Base.@kwdef struct AuthenticationRequiredError <: AbstractAzureAuthError
    message::String = "Authentication is required."
    scopes::Vector{String} = String[]
    claims::Union{Nothing, String} = nothing
end

struct TokenCachePersistenceError <: AbstractAzureAuthError
    message::String
end

Base.showerror(io::IO, err::AzureAuthError) = print(io, "AzureAuthError: ", err.message)
Base.showerror(io::IO, err::ClientAuthenticationError) = print(io, "ClientAuthenticationError: ", err.message)
Base.showerror(io::IO, err::CredentialUnavailableError) = print(io, "CredentialUnavailableError: ", err.message)

function Base.showerror(io::IO, err::AuthenticationRequiredError)
    print(io, "AuthenticationRequiredError: ", err.message)
end

Base.showerror(io::IO, err::TokenCachePersistenceError) = print(io, "TokenCachePersistenceError: ", err.message)
