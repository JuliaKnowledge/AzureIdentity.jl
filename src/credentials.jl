function _with_cache(cache::AccessTokenCache, runtime::CredentialRuntime, key::String, acquire::Function)
    token, status = cached_token_status(cache, key; now_fn = runtime.now_fn)

    if status == REFRESH_NOT_NEEDED && token !== nothing
        return token
    end

    if status == REFRESH_RECOMMENDED && token !== nothing
        # Proactive refresh: attempt to refresh but keep the still-valid cached token if it
        # fails, and throttle repeat attempts via DEFAULT_TOKEN_REFRESH_RETRY_DELAY.
        mark_refresh_attempt!(cache, key, runtime.now_fn())
        try
            refreshed = acquire()
            put_cached_token!(cache, key, refreshed)
            return refreshed
        catch
            return token
        end
    end

    # REFRESH_REQUIRED (or no usable cached token): must acquire a new token.
    mark_refresh_attempt!(cache, key, runtime.now_fn())
    new_token = acquire()
    put_cached_token!(cache, key, new_token)
    return new_token
end

mutable struct CachedCredential <: AbstractAzureCredential
    inner::AbstractAzureCredential
    cache::AccessTokenCache
end

CachedCredential(inner::AbstractAzureCredential) = CachedCredential(inner, AccessTokenCache())

function get_token_info(credential::CachedCredential, scopes::Vararg{String}; options::Union{Nothing, TokenRequestOptions} = nothing, claims = nothing, tenant_id = nothing, enable_cae::Bool = false)
    opts = _coerce_options(; options, claims, tenant_id, enable_cae)
    merged_claims = _merge_claims(opts.claims, opts.enable_cae)
    key = _cache_key(scopes...; tenant_id = opts.tenant_id, claims = merged_claims, enable_cae = opts.enable_cae)
    return _with_cache(credential.cache, default_runtime(), key, () -> begin
        get_token_info(credential.inner, scopes...; claims = opts.claims, tenant_id = opts.tenant_id, enable_cae = opts.enable_cae)
    end)
end

clear_cache!(credential::CachedCredential) = clear_cache!(credential.cache)

Base.@kwdef mutable struct ClientSecretCredential <: AbstractAzureCredential
    tenant_id::String
    client_id::String
    client_secret::String
    authority::String = get_default_authority()
    additionally_allowed_tenants::Vector{String} = String[]
    runtime::CredentialRuntime = default_runtime()
    disable_instance_discovery::Bool = false
    cache::AccessTokenCache = AccessTokenCache()
end

function get_token_info(credential::ClientSecretCredential, scopes::Vararg{String}; options::Union{Nothing, TokenRequestOptions} = nothing, claims = nothing, tenant_id = nothing, enable_cae::Bool = false)
    normalized_scopes = normalize_scopes(scopes...)
    opts = _coerce_options(; options, claims, tenant_id, enable_cae)
    tenant = resolve_tenant(credential.tenant_id; tenant_id = opts.tenant_id, additionally_allowed_tenants = credential.additionally_allowed_tenants)
    authority = _validated_authority(credential.authority, credential.runtime; disable_instance_discovery = credential.disable_instance_discovery)
    merged_claims = _merge_claims(opts.claims, opts.enable_cae)
    key = _cache_key(normalized_scopes...; tenant_id = tenant, claims = merged_claims, enable_cae = opts.enable_cae)
    return _with_cache(credential.cache, credential.runtime, key, () -> begin
        _request_client_secret_token(credential.runtime, authority, tenant, credential.client_id, credential.client_secret, normalized_scopes; claims = opts.claims, enable_cae = opts.enable_cae).token
    end)
end

Base.@kwdef mutable struct ClientAssertionCredential <: AbstractAzureCredential
    tenant_id::String
    client_id::String
    func::Function
    authority::String = get_default_authority()
    additionally_allowed_tenants::Vector{String} = String[]
    runtime::CredentialRuntime = default_runtime()
    disable_instance_discovery::Bool = false
    cache::AccessTokenCache = AccessTokenCache()
end

function get_token_info(credential::ClientAssertionCredential, scopes::Vararg{String}; options::Union{Nothing, TokenRequestOptions} = nothing, claims = nothing, tenant_id = nothing, enable_cae::Bool = false)
    normalized_scopes = normalize_scopes(scopes...)
    opts = _coerce_options(; options, claims, tenant_id, enable_cae)
    tenant = resolve_tenant(credential.tenant_id; tenant_id = opts.tenant_id, additionally_allowed_tenants = credential.additionally_allowed_tenants)
    authority = _validated_authority(credential.authority, credential.runtime; disable_instance_discovery = credential.disable_instance_discovery)
    merged_claims = _merge_claims(opts.claims, opts.enable_cae)
    key = _cache_key(normalized_scopes...; tenant_id = tenant, claims = merged_claims, enable_cae = opts.enable_cae)
    return _with_cache(credential.cache, credential.runtime, key, () -> begin
        assertion = String(credential.func())
        _request_jwt_assertion_token(credential.runtime, authority, tenant, credential.client_id, assertion, normalized_scopes; claims = opts.claims, enable_cae = opts.enable_cae).token
    end)
end

Base.@kwdef mutable struct UsernamePasswordCredential <: AbstractAzureCredential
    tenant_id::String
    client_id::String
    username::String
    password::String
    authority::String = get_default_authority()
    additionally_allowed_tenants::Vector{String} = String[]
    runtime::CredentialRuntime = default_runtime()
    disable_instance_discovery::Bool = false
    cache::AccessTokenCache = AccessTokenCache()
end

function get_token_info(credential::UsernamePasswordCredential, scopes::Vararg{String}; options::Union{Nothing, TokenRequestOptions} = nothing, claims = nothing, tenant_id = nothing, enable_cae::Bool = false)
    normalized_scopes = normalize_scopes(scopes...)
    opts = _coerce_options(; options, claims, tenant_id, enable_cae)
    tenant = resolve_tenant(credential.tenant_id; tenant_id = opts.tenant_id, additionally_allowed_tenants = credential.additionally_allowed_tenants)
    authority = _validated_authority(credential.authority, credential.runtime; disable_instance_discovery = credential.disable_instance_discovery)
    merged_claims = _merge_claims(opts.claims, opts.enable_cae)
    key = _cache_key(normalized_scopes...; tenant_id = tenant, claims = merged_claims, enable_cae = opts.enable_cae)
    return _with_cache(credential.cache, credential.runtime, key, () -> begin
        _request_password_token(credential.runtime, authority, tenant, credential.client_id, credential.username, credential.password, normalized_scopes; claims = opts.claims, enable_cae = opts.enable_cae).token
    end)
end

Base.@kwdef struct CertificateMaterial
    private_key_pem::String
    certificate_pems::Vector{String}
    certificate_der::Vector{Vector{UInt8}}
    thumbprint::Vector{UInt8}
end

function _password_bytes(password)
    password === nothing && return nothing
    if password isa AbstractString
        return Vector{UInt8}(codeunits(String(password)))
    elseif password isa AbstractVector{UInt8}
        return Vector{UInt8}(password)
    end
    throw(ArgumentError("password must be a string, bytes, or nothing"))
end

function _password_cstring(password_bytes::Union{Nothing, Vector{UInt8}})
    password_bytes === nothing && return nothing
    return vcat(password_bytes, UInt8(0))
end

function _looks_like_pem(certificate_data::Vector{UInt8})
    sample = certificate_data[1:min(end, 256)]
    any(==(0x00), sample) && return false
    try
        return occursin("-----BEGIN", String(sample))
    catch
        return false
    end
end

function _extract_pem_blocks(pem_text::String, label::String)
    regex = Regex("-----BEGIN $(label)-----.*?-----END $(label)-----", "s")
    return [strip(match.match) for match in eachmatch(regex, pem_text)]
end

function _certificate_der(certificate::OpenSSL.X509Certificate)
    length = ccall((:i2d_X509, OpenSSL.libcrypto), Cint, (OpenSSL.X509Certificate, Ptr{Ptr{UInt8}}), certificate, C_NULL)
    length > 0 || throw(ArgumentError("Failed to convert certificate to DER"))
    buffer = Vector{UInt8}(undef, length)
    pointer_ref = Ref(pointer(buffer))
    result = ccall((:i2d_X509, OpenSSL.libcrypto), Cint, (OpenSSL.X509Certificate, Ref{Ptr{UInt8}}), certificate, pointer_ref)
    result > 0 || throw(ArgumentError("Failed to serialize certificate to DER"))
    return buffer
end

function _certificate_pem(certificate::OpenSSL.X509Certificate)
    bio = OpenSSL.BIO(OpenSSL.BIOMethodMemory())
    try
        ccall(
            (:PEM_write_bio_X509, OpenSSL.libcrypto),
            Cint,
            (OpenSSL.BIO, OpenSSL.X509Certificate),
            bio,
            certificate,
        ) == 1 || throw(ArgumentError("Failed to serialize certificate"))
        return String(copy(OpenSSL.bio_get_mem_data(bio)))
    finally
        OpenSSL.free(bio)
    end
end

function _private_key_pem(key::OpenSSL.EvpPKey)
    bio = OpenSSL.BIO(OpenSSL.BIOMethodMemory())
    try
        ccall(
            (:PEM_write_bio_PrivateKey, OpenSSL.libcrypto),
            Cint,
            (OpenSSL.BIO, OpenSSL.EvpPKey, OpenSSL.EvpCipher, Ptr{Cvoid}, Cint, Cint, Ptr{Cvoid}),
            bio,
            key,
            OpenSSL.EvpCipher(C_NULL),
            C_NULL,
            0,
            0,
            C_NULL,
        ) == 1 || throw(ArgumentError("Failed to serialize certificate private key"))
        return String(copy(OpenSSL.bio_get_mem_data(bio)))
    finally
        OpenSSL.free(bio)
    end
end

function _load_private_key(certificate_data::Vector{UInt8}, password_bytes::Union{Nothing, Vector{UInt8}})
    bio = OpenSSL.BIO(OpenSSL.BIOMethodMemory())
    try
        GC.@preserve certificate_data begin
            unsafe_write(bio, pointer(certificate_data), length(certificate_data))
        end
        password_cstr = _password_cstring(password_bytes)
        key_ptr = GC.@preserve password_cstr begin
            ccall(
                (:PEM_read_bio_PrivateKey, OpenSSL.libcrypto),
                Ptr{Cvoid},
                (OpenSSL.BIO, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}),
                bio,
                C_NULL,
                C_NULL,
                password_cstr === nothing ? C_NULL : pointer(password_cstr),
            )
        end
        key_ptr == C_NULL && throw(ArgumentError("Failed to deserialize certificate in PEM or PKCS12 format"))
        key = OpenSSL.EvpPKey(key_ptr)
        OpenSSL.get_key_type(key) in (OpenSSL.EVP_PKEY_RSA, OpenSSL.EVP_PKEY_RSA2) || throw(
            ArgumentError("The certificate must have an RSA private key because RS256 is used for signing"),
        )
        return key
    finally
        OpenSSL.free(bio)
    end
end

function _load_pem_certificate_material(certificate_data::Vector{UInt8}, password_bytes::Union{Nothing, Vector{UInt8}}, send_certificate_chain::Bool)
    key = _load_private_key(certificate_data, password_bytes)
    pem_text = try
        String(certificate_data)
    catch
        throw(ArgumentError("Failed to deserialize certificate in PEM or PKCS12 format"))
    end
    cert_blocks = _extract_pem_blocks(pem_text, "CERTIFICATE")
    isempty(cert_blocks) && throw(ArgumentError("The certificate must include at least one PEM certificate"))
    der_chain = [_certificate_der(OpenSSL.X509Certificate(block)) for block in cert_blocks]
    certs = send_certificate_chain ? cert_blocks : cert_blocks[1:1]
    ders = send_certificate_chain ? der_chain : der_chain[1:1]
    return CertificateMaterial(
        private_key_pem = _private_key_pem(key),
        certificate_pems = certs,
        certificate_der = ders,
        thumbprint = Vector{UInt8}(SHA.sha1(der_chain[1])),
    )
end

function _load_pkcs12_certificate_material(certificate_data::Vector{UInt8}, password_bytes::Union{Nothing, Vector{UInt8}}, send_certificate_chain::Bool)
    bio = OpenSSL.BIO(OpenSSL.BIOMethodMemory())
    try
        GC.@preserve certificate_data begin
            unsafe_write(bio, pointer(certificate_data), length(certificate_data))
        end
        pkcs12_ptr = ccall((:d2i_PKCS12_bio, OpenSSL.libcrypto), Ptr{Cvoid}, (OpenSSL.BIO, Ptr{Cvoid}), bio, C_NULL)
        pkcs12_ptr == C_NULL && throw(ArgumentError("Failed to deserialize certificate in PEM or PKCS12 format"))
        pkcs12 = OpenSSL.P12Object(pkcs12_ptr)
        key = OpenSSL.EvpPKey(C_NULL)
        cert = OpenSSL.X509Certificate(C_NULL)
        ca_chain = OpenSSL.StackOf{OpenSSL.X509Certificate}(C_NULL)
        password_cstr = _password_cstring(password_bytes)
        result = GC.@preserve password_cstr begin
            ccall(
                (:PKCS12_parse, OpenSSL.libcrypto),
                Cint,
                (OpenSSL.P12Object, Cstring, Ref{OpenSSL.EvpPKey}, Ref{OpenSSL.X509Certificate}, Ref{OpenSSL.StackOf{OpenSSL.X509Certificate}}),
                pkcs12,
                password_cstr === nothing ? C_NULL : pointer(password_cstr),
                key,
                cert,
                ca_chain,
            )
        end
        result == 1 || throw(ArgumentError("Failed to deserialize certificate in PEM or PKCS12 format"))
        key.evp_pkey == C_NULL && throw(ArgumentError("The certificate must include its private key"))
        cert.x509 == C_NULL && throw(ArgumentError("Failed to deserialize certificate in PEM or PKCS12 format"))
        OpenSSL.get_key_type(key) in (OpenSSL.EVP_PKEY_RSA, OpenSSL.EVP_PKEY_RSA2) || throw(
            ArgumentError("The certificate must have an RSA private key because RS256 is used for signing"),
        )

        certificate_pems = [_certificate_pem(cert)]
        certificate_der = [_certificate_der(cert)]
        if send_certificate_chain
            for _ in 1:length(ca_chain)
                extra = pop!(ca_chain)
                push!(certificate_pems, _certificate_pem(extra))
                push!(certificate_der, _certificate_der(extra))
            end
        end

        return CertificateMaterial(
            private_key_pem = _private_key_pem(key),
            certificate_pems = certificate_pems,
            certificate_der = certificate_der,
            thumbprint = Vector{UInt8}(SHA.sha1(certificate_der[1])),
        )
    finally
        OpenSSL.free(bio)
    end
end

function _sign_rs256(message::AbstractString, private_key_pem::String)
    key = OpenSSL.EvpPKey(private_key_pem)
    ctx = ccall((:EVP_MD_CTX_new, OpenSSL.libcrypto), Ptr{Nothing}, ())
    ctx == C_NULL && throw(ArgumentError("Failed to create OpenSSL digest context"))
    try
        digest = ccall((:EVP_sha256, OpenSSL.libcrypto), Ptr{Nothing}, ())
        ccall((:EVP_DigestSignInit, OpenSSL.libcrypto), Cint,
            (Ptr{Nothing}, Ptr{Ptr{Nothing}}, Ptr{Nothing}, Ptr{Nothing}, OpenSSL.EvpPKey),
            ctx, C_NULL, digest, C_NULL, key) == 1 || throw(ArgumentError("Failed to initialize certificate signing"))
        bytes = Vector{UInt8}(codeunits(String(message)))
        ccall((:EVP_DigestSignUpdate, OpenSSL.libcrypto), Cint,
            (Ptr{Nothing}, Ptr{UInt8}, Csize_t),
            ctx, pointer(bytes), length(bytes)) == 1 || throw(ArgumentError("Failed to update certificate signature"))
        size_ref = Ref{Csize_t}(0)
        ccall((:EVP_DigestSignFinal, OpenSSL.libcrypto), Cint,
            (Ptr{Nothing}, Ptr{UInt8}, Ref{Csize_t}),
            ctx, C_NULL, size_ref) == 1 || throw(ArgumentError("Failed to finalize certificate signature size"))
        signature = Vector{UInt8}(undef, size_ref[])
        ccall((:EVP_DigestSignFinal, OpenSSL.libcrypto), Cint,
            (Ptr{Nothing}, Ptr{UInt8}, Ref{Csize_t}),
            ctx, pointer(signature), size_ref) == 1 || throw(ArgumentError("Failed to finalize certificate signature"))
        resize!(signature, size_ref[])
        return signature
    finally
        ccall((:EVP_MD_CTX_free, OpenSSL.libcrypto), Cvoid, (Ptr{Nothing},), ctx)
    end
end

function _load_certificate_material(; certificate_path::Union{Nothing, String} = nothing, certificate_data::Union{Nothing, Vector{UInt8}} = nothing, password = nothing, send_certificate_chain::Bool = false)
    if (certificate_path === nothing) == (certificate_data === nothing)
        throw(ArgumentError("Specify exactly one of certificate_path or certificate_data"))
    end
    data = certificate_path === nothing ? copy(certificate_data) : read(certificate_path)
    password_bytes = _password_bytes(password)
    return _looks_like_pem(data) ?
        _load_pem_certificate_material(data, password_bytes, send_certificate_chain) :
        _load_pkcs12_certificate_material(data, password_bytes, send_certificate_chain)
end

function _build_client_assertion(material::CertificateMaterial, authority::String, tenant_id::String, client_id::String, now::DateTime)
    header = Dict{String, Any}(
        "alg" => "RS256",
        "typ" => "JWT",
        "x5t" => base64url_encode(material.thumbprint),
    )
    if length(material.certificate_der) > 0
        header["x5c"] = [base64encode(der) for der in material.certificate_der]
    end
    payload = Dict(
        "aud" => _token_endpoint(authority, tenant_id),
        "exp" => datetime_to_epoch(now + Dates.Minute(10)),
        "iss" => client_id,
        "jti" => string(uuid4()),
        "nbf" => max(0, datetime_to_epoch(now - Dates.Minute(1))),
        "sub" => client_id,
    )
    encoded_header = base64url_encode(JSON3.write(header))
    encoded_payload = base64url_encode(JSON3.write(payload))
    signing_input = string(encoded_header, ".", encoded_payload)
    signature = base64url_encode(_sign_rs256(signing_input, material.private_key_pem))
    return string(signing_input, ".", signature)
end

mutable struct CertificateCredential <: AbstractAzureCredential
    tenant_id::String
    client_id::String
    authority::String
    additionally_allowed_tenants::Vector{String}
    runtime::CredentialRuntime
    disable_instance_discovery::Bool
    cache::AccessTokenCache
    material::CertificateMaterial
end

function CertificateCredential(
    tenant_id::String,
    client_id::String;
    certificate_path::Union{Nothing, String} = nothing,
    certificate_data::Union{Nothing, Vector{UInt8}} = nothing,
    password = nothing,
    send_certificate_chain::Bool = false,
    authority::String = get_default_authority(),
    additionally_allowed_tenants::Vector{String} = String[],
    runtime::CredentialRuntime = default_runtime(),
    disable_instance_discovery::Bool = false,
)
    validate_tenant_id(tenant_id)
    material = _load_certificate_material(; certificate_path, certificate_data, password, send_certificate_chain)
    return CertificateCredential(tenant_id, client_id, normalize_authority(authority), additionally_allowed_tenants, runtime, disable_instance_discovery, AccessTokenCache(), material)
end

function get_token_info(credential::CertificateCredential, scopes::Vararg{String}; options::Union{Nothing, TokenRequestOptions} = nothing, claims = nothing, tenant_id = nothing, enable_cae::Bool = false)
    normalized_scopes = normalize_scopes(scopes...)
    opts = _coerce_options(; options, claims, tenant_id, enable_cae)
    tenant = resolve_tenant(credential.tenant_id; tenant_id = opts.tenant_id, additionally_allowed_tenants = credential.additionally_allowed_tenants)
    authority = _validated_authority(credential.authority, credential.runtime; disable_instance_discovery = credential.disable_instance_discovery)
    merged_claims = _merge_claims(opts.claims, opts.enable_cae)
    key = _cache_key(normalized_scopes...; tenant_id = tenant, claims = merged_claims, enable_cae = opts.enable_cae)
    return _with_cache(credential.cache, credential.runtime, key, () -> begin
        assertion = _build_client_assertion(credential.material, authority, tenant, credential.client_id, credential.runtime.now_fn())
        _request_jwt_assertion_token(credential.runtime, authority, tenant, credential.client_id, assertion, normalized_scopes; claims = opts.claims, enable_cae = opts.enable_cae).token
    end)
end

mutable struct WorkloadIdentityCredential <: AbstractAzureCredential
    token_file_path::String
    inner::ClientAssertionCredential
end

function WorkloadIdentityCredential(
    ;
    tenant_id::Union{Nothing, String} = nothing,
    client_id::Union{Nothing, String} = nothing,
    token_file_path::Union{Nothing, String} = nothing,
    authority::String = get_default_authority(),
    additionally_allowed_tenants::Vector{String} = String[],
    runtime::CredentialRuntime = default_runtime(),
    disable_instance_discovery::Bool = false,
)
    resolved_tenant = something(tenant_id, get(ENV, ENV_AZURE_TENANT_ID, nothing))
    resolved_client = something(client_id, get(ENV, ENV_AZURE_CLIENT_ID, nothing))
    resolved_path = something(token_file_path, get(ENV, ENV_AZURE_FEDERATED_TOKEN_FILE, nothing))
    resolved_tenant === nothing && throw(ArgumentError("tenant_id is required for WorkloadIdentityCredential"))
    resolved_client === nothing && throw(ArgumentError("client_id is required for WorkloadIdentityCredential"))
    resolved_path === nothing && throw(ArgumentError("token_file_path is required for WorkloadIdentityCredential"))
    loader = () -> strip(read(resolved_path, String))
    inner = ClientAssertionCredential(
        tenant_id = resolved_tenant,
        client_id = resolved_client,
        func = loader,
        authority = authority,
        additionally_allowed_tenants = additionally_allowed_tenants,
        runtime = runtime,
        disable_instance_discovery = disable_instance_discovery,
    )
    return WorkloadIdentityCredential(resolved_path, inner)
end

get_token_info(credential::WorkloadIdentityCredential, scopes::Vararg{String}; kwargs...) = get_token_info(credential.inner, scopes...; kwargs...)

function _validate_azure_pipelines_environment()
    haskey(ENV, ENV_SYSTEM_OIDCREQUESTURI) && !isempty(strip(ENV[ENV_SYSTEM_OIDCREQUESTURI])) && return nothing
    throw(CredentialUnavailableError(
        "Missing value for $ENV_SYSTEM_OIDCREQUESTURI. AzurePipelinesCredential is intended for Azure Pipelines. See $(AZURE_PIPELINES_TROUBLESHOOTING_GUIDE).",
    ))
end

function _azure_pipelines_oidc_token(runtime::CredentialRuntime, service_connection_id::String, system_access_token::String)
    _validate_azure_pipelines_environment()
    base_uri = rstrip(String(ENV[ENV_SYSTEM_OIDCREQUESTURI]), '/')
    response = runtime.http_request(
        "POST",
        base_uri;
        headers = Dict(
            "Content-Type" => "application/json",
            "Authorization" => "Bearer $system_access_token",
            "X-TFS-FedAuthRedirect" => "Suppress",
        ),
        query = Dict(
            "api-version" => AZURE_PIPELINES_OIDC_API_VERSION,
            "serviceConnectionId" => service_connection_id,
        ),
    )
    payload = try
        _decode_json_body(response.body)
    catch
        Dict{String, Any}()
    end
    response.status == 200 || throw(ClientAuthenticationError("Unexpected response from OIDC token endpoint."))
    haskey(payload, "oidcToken") || throw(ClientAuthenticationError("OIDC token not found in response."))
    return String(payload["oidcToken"])
end

mutable struct AzurePipelinesCredential <: AbstractAzureCredential
    service_connection_id::String
    system_access_token::String
    inner::ClientAssertionCredential
end

function AzurePipelinesCredential(
    ;
    tenant_id::String,
    client_id::String,
    service_connection_id::String,
    system_access_token::String,
    authority::String = get_default_authority(),
    additionally_allowed_tenants::Vector{String} = String[],
    runtime::CredentialRuntime = default_runtime(),
    disable_instance_discovery::Bool = false,
)
    isempty(strip(tenant_id)) && throw(ArgumentError("'tenant_id', 'client_id', 'service_connection_id', and 'system_access_token' are required. See $(AZURE_PIPELINES_TROUBLESHOOTING_GUIDE)."))
    isempty(strip(client_id)) && throw(ArgumentError("'tenant_id', 'client_id', 'service_connection_id', and 'system_access_token' are required. See $(AZURE_PIPELINES_TROUBLESHOOTING_GUIDE)."))
    isempty(strip(service_connection_id)) && throw(ArgumentError("'tenant_id', 'client_id', 'service_connection_id', and 'system_access_token' are required. See $(AZURE_PIPELINES_TROUBLESHOOTING_GUIDE)."))
    isempty(strip(system_access_token)) && throw(ArgumentError("'tenant_id', 'client_id', 'service_connection_id', and 'system_access_token' are required. See $(AZURE_PIPELINES_TROUBLESHOOTING_GUIDE)."))
    validate_tenant_id(tenant_id)
    inner = ClientAssertionCredential(
        tenant_id = tenant_id,
        client_id = client_id,
        func = () -> _azure_pipelines_oidc_token(runtime, service_connection_id, system_access_token),
        authority = authority,
        additionally_allowed_tenants = additionally_allowed_tenants,
        runtime = runtime,
        disable_instance_discovery = disable_instance_discovery,
    )
    return AzurePipelinesCredential(service_connection_id, system_access_token, inner)
end

get_token_info(credential::AzurePipelinesCredential, scopes::Vararg{String}; kwargs...) = get_token_info(credential.inner, scopes...; kwargs...)

mutable struct OnBehalfOfCredential <: AbstractAzureCredential
    tenant_id::String
    client_id::String
    client_secret::Union{Nothing, String}
    user_assertion::String
    client_assertion_func::Union{Nothing, Function}
    authority::String
    additionally_allowed_tenants::Vector{String}
    runtime::CredentialRuntime
    disable_instance_discovery::Bool
    cache::AccessTokenCache
end

function OnBehalfOfCredential(
    tenant_id::String,
    client_id::String;
    client_secret::Union{Nothing, String} = nothing,
    user_assertion::Union{Nothing, String} = nothing,
    client_assertion_func::Union{Nothing, Function} = nothing,
    authority::String = get_default_authority(),
    additionally_allowed_tenants::Vector{String} = String[],
    runtime::CredentialRuntime = default_runtime(),
    disable_instance_discovery::Bool = false,
)
    (client_secret === nothing) == (client_assertion_func === nothing) && throw(ArgumentError("Provide exactly one of client_secret or client_assertion_func"))
    user_assertion === nothing && throw(ArgumentError("user_assertion is required"))
    return OnBehalfOfCredential(tenant_id, client_id, client_secret, user_assertion, client_assertion_func, normalize_authority(authority), additionally_allowed_tenants, runtime, disable_instance_discovery, AccessTokenCache())
end

function get_token_info(credential::OnBehalfOfCredential, scopes::Vararg{String}; options::Union{Nothing, TokenRequestOptions} = nothing, claims = nothing, tenant_id = nothing, enable_cae::Bool = false)
    normalized_scopes = normalize_scopes(scopes...)
    opts = _coerce_options(; options, claims, tenant_id, enable_cae)
    tenant = resolve_tenant(credential.tenant_id; tenant_id = opts.tenant_id, additionally_allowed_tenants = credential.additionally_allowed_tenants)
    authority = _validated_authority(credential.authority, credential.runtime; disable_instance_discovery = credential.disable_instance_discovery)
    merged_claims = _merge_claims(opts.claims, opts.enable_cae)
    key = _cache_key(normalized_scopes...; tenant_id = tenant, claims = merged_claims, enable_cae = opts.enable_cae)
    return _with_cache(credential.cache, credential.runtime, key, () -> begin
        assertion = credential.client_assertion_func === nothing ? nothing : String(credential.client_assertion_func())
        _request_on_behalf_of_token(credential.runtime, authority, tenant, credential.client_id, credential.user_assertion, normalized_scopes;
            client_secret = credential.client_secret,
            client_assertion = assertion,
            claims = opts.claims,
            enable_cae = opts.enable_cae,
        ).token
    end)
end

struct EnvironmentCredential <: AbstractAzureCredential
    authority::String
    disable_instance_discovery::Bool
    runtime::CredentialRuntime
end

EnvironmentCredential(; authority::String = get_default_authority(), disable_instance_discovery::Bool = false, runtime::CredentialRuntime = default_runtime()) = EnvironmentCredential(normalize_authority(authority), disable_instance_discovery, runtime)

function _environment_inner(credential::EnvironmentCredential)
    if all(name -> haskey(ENV, name) && !isempty(ENV[name]), CLIENT_SECRET_VARS)
        return ClientSecretCredential(
            tenant_id = ENV[ENV_AZURE_TENANT_ID],
            client_id = ENV[ENV_AZURE_CLIENT_ID],
            client_secret = ENV[ENV_AZURE_CLIENT_SECRET],
            authority = credential.authority,
            runtime = credential.runtime,
            disable_instance_discovery = credential.disable_instance_discovery,
        )
    elseif all(name -> haskey(ENV, name) && !isempty(ENV[name]), CERTIFICATE_VARS)
        certificate_password = get(ENV, ENV_AZURE_CLIENT_CERTIFICATE_PASSWORD, nothing)
        return CertificateCredential(
            ENV[ENV_AZURE_TENANT_ID],
            ENV[ENV_AZURE_CLIENT_ID];
            certificate_path = ENV[ENV_AZURE_CLIENT_CERTIFICATE_PATH],
            password = certificate_password,
            send_certificate_chain = _truthy_env(ENV_AZURE_CLIENT_SEND_CERTIFICATE_CHAIN),
            authority = credential.authority,
            runtime = credential.runtime,
            disable_instance_discovery = credential.disable_instance_discovery,
        )
    elseif all(name -> haskey(ENV, name) && !isempty(ENV[name]), USERNAME_PASSWORD_VARS)
        tenant_id = get(ENV, ENV_AZURE_TENANT_ID, "organizations")
        return UsernamePasswordCredential(
            tenant_id = tenant_id,
            client_id = ENV[ENV_AZURE_CLIENT_ID],
            username = ENV[ENV_AZURE_USERNAME],
            password = ENV[ENV_AZURE_PASSWORD],
            authority = credential.authority,
            runtime = credential.runtime,
            disable_instance_discovery = credential.disable_instance_discovery,
        )
    end
    return nothing
end

function get_token_info(credential::EnvironmentCredential, scopes::Vararg{String}; kwargs...)
    inner = _environment_inner(credential)
    inner === nothing && throw(CredentialUnavailableError(
        "EnvironmentCredential authentication unavailable. Configure client secret, certificate, or username/password environment variables.",
    ))
    return get_token_info(inner, scopes...; kwargs...)
end

Base.@kwdef mutable struct ManagedIdentityCredential <: AbstractAzureCredential
    client_id::Union{Nothing, String} = get(ENV, ENV_AZURE_CLIENT_ID, nothing)
    identity_config::Dict{String, String} = Dict{String, String}()
    exclude_workload_identity_credential::Bool = false
    enable_imds_probe::Union{Nothing, Bool} = nothing
    runtime::CredentialRuntime = default_runtime()
    cache::AccessTokenCache = AccessTokenCache()
end

function _managed_identity_params(credential::ManagedIdentityCredential, style::Symbol)
    params = copy(credential.identity_config)
    if credential.client_id !== nothing
        key = style === :azure_ml ? "clientid" : "client_id"
        params[key] = credential.client_id
    end
    return params
end

function _parse_managed_identity_token(payload::Dict{String, Any}, resource::String, runtime::CredentialRuntime)
    now = runtime.now_fn()
    expires_in = haskey(payload, "expires_in") ? tryparse(Int, string(payload["expires_in"])) : nothing
    expires_on = if haskey(payload, "expires_on")
        _parse_expires_on(payload["expires_on"], runtime.now_fn)
    elseif expires_in !== nothing
        now + Dates.Second(expires_in)
    else
        now + Dates.Hour(1)
    end
    # Match Python's managed_identity_client: long-lived tokens get a half-life proactive refresh.
    refresh_on = if haskey(payload, "refresh_in")
        now + Dates.Second(parse(Int, string(payload["refresh_in"])))
    elseif expires_in !== nothing && expires_in >= 7200
        now + Dates.Second(expires_in ÷ 2)
    else
        nothing
    end
    return AzureAccessTokenInfo(
        token = String(payload["access_token"]),
        expires_on = expires_on,
        token_type = String(get(payload, "token_type", "Bearer")),
        refresh_on = refresh_on,
        resource = get(payload, "resource", resource),
        scopes = [resource],
        tenant_id = get(payload, "tenant", nothing),
        extras = payload,
    )
end

function _managed_identity_request(credential::ManagedIdentityCredential, method::String, url::String; headers::Dict{String, String} = Dict{String, String}(), query::Dict{String, <:Any} = Dict{String, String}(), body::Union{Nothing, String} = nothing)
    response = credential.runtime.http_request(method, url; headers, query, body)
    payload = try
        _decode_json_body(response.body)
    catch
        Dict{String, Any}("raw" => response.body)
    end
    return response, payload
end

function _managed_identity_from_workload(credential::ManagedIdentityCredential, scopes::Vector{String}; kwargs...)
    credential.exclude_workload_identity_credential && return nothing
    if haskey(ENV, ENV_AZURE_FEDERATED_TOKEN_FILE) && haskey(ENV, ENV_AZURE_TENANT_ID) && (credential.client_id !== nothing || haskey(ENV, ENV_AZURE_CLIENT_ID))
        workload = WorkloadIdentityCredential(
            tenant_id = get(ENV, ENV_AZURE_TENANT_ID, nothing),
            client_id = credential.client_id,
            token_file_path = get(ENV, ENV_AZURE_FEDERATED_TOKEN_FILE, nothing),
            runtime = credential.runtime,
        )
        return get_token_info(workload, scopes...; kwargs...)
    end
    return nothing
end

function _managed_identity_token(credential::ManagedIdentityCredential, scopes::Vector{String}; options::Union{Nothing, TokenRequestOptions} = nothing, claims = nothing, tenant_id = nothing, enable_cae::Bool = false)
    opts = _coerce_options(; options, claims, tenant_id, enable_cae)
    if opts.claims !== nothing
        throw(CredentialUnavailableError("ManagedIdentityCredential does not support claims challenges in this implementation."))
    end
    resource = _scopes_to_resource(scopes...)
    workload_token = _managed_identity_from_workload(credential, scopes; tenant_id = opts.tenant_id)
    workload_token !== nothing && return workload_token

    # Detection order mirrors Python's ManagedIdentityCredential: when IDENTITY_ENDPOINT is
    # set, IDENTITY_HEADER selects App Service / Service Fabric; Azure Arc is selected only
    # when IDENTITY_HEADER is absent and IMDS_ENDPOINT is present.
    if haskey(ENV, ENV_IDENTITY_ENDPOINT) && haskey(ENV, ENV_IDENTITY_HEADER) && haskey(ENV, ENV_IDENTITY_SERVER_THUMBPRINT)
        isempty(credential.identity_config) || throw(ClientAuthenticationError("Service Fabric does not support identity_config overrides."))
        credential.client_id === nothing || throw(ClientAuthenticationError("Service Fabric does not support specifying client_id."))
        url = ENV[ENV_IDENTITY_ENDPOINT]
        query = Dict("api-version" => "2019-07-01-preview", "resource" => resource)
        headers = Dict("Secret" => ENV[ENV_IDENTITY_HEADER])
        response, payload = _managed_identity_request(credential, "GET", url; headers, query)
        response.status == 200 || throw(CredentialUnavailableError(_oauth_error_message(payload, "Service Fabric managed identity unavailable.")))
        return _parse_managed_identity_token(payload, resource, credential.runtime)
    elseif haskey(ENV, ENV_IDENTITY_ENDPOINT) && haskey(ENV, ENV_IDENTITY_HEADER)
        url = ENV[ENV_IDENTITY_ENDPOINT]
        query = Dict("api-version" => "2019-08-01", "resource" => resource)
        merge!(query, _managed_identity_params(credential, :app_service))
        headers = Dict("X-IDENTITY-HEADER" => ENV[ENV_IDENTITY_HEADER])
        response, payload = _managed_identity_request(credential, "GET", url; headers, query)
        response.status == 200 || throw(CredentialUnavailableError(_oauth_error_message(payload, "App Service managed identity unavailable.")))
        return _parse_managed_identity_token(payload, resource, credential.runtime)
    elseif haskey(ENV, ENV_IDENTITY_ENDPOINT) && haskey(ENV, ENV_IMDS_ENDPOINT)
        # Azure Arc: real Arc hosts set IDENTITY_ENDPOINT and IMDS_ENDPOINT but NOT IDENTITY_HEADER.
        isempty(credential.identity_config) || throw(ClientAuthenticationError("Azure Arc does not support user-assigned managed identities (identity_config)."))
        credential.client_id === nothing || throw(ClientAuthenticationError("Azure Arc does not support specifying client_id."))
        url = ENV[ENV_IDENTITY_ENDPOINT]
        query = Dict("api-version" => "2020-06-01", "resource" => resource)
        headers = Dict("Metadata" => "true")
        response, payload = _managed_identity_request(credential, "GET", url; headers, query)
        if response.status == 401
            # Arc challenge: WWW-Authenticate carries the path to a secret file; retry with Basic auth.
            challenge = get(response.headers, "WWW-Authenticate", get(response.headers, "Www-Authenticate", nothing))
            challenge === nothing && throw(ClientAuthenticationError("Did not receive a value from WWW-Authenticate header"))
            parts = split(challenge, "=")
            length(parts) >= 2 || throw(ClientAuthenticationError("Did not receive a correct value from WWW-Authenticate header: $challenge"))
            secret_path = strip(parts[end], ['"', ' '])
            secret = read(secret_path, String)
            headers["Authorization"] = "Basic $secret"
            response, payload = _managed_identity_request(credential, "GET", url; headers, query)
        end
        response.status == 200 || throw(CredentialUnavailableError(_oauth_error_message(payload, "Azure Arc managed identity unavailable.")))
        return _parse_managed_identity_token(payload, resource, credential.runtime)
    elseif haskey(ENV, ENV_MSI_ENDPOINT) && haskey(ENV, ENV_MSI_SECRET)
        url = ENV[ENV_MSI_ENDPOINT]
        query = Dict("api-version" => "2017-09-01", "resource" => resource)
        merge!(query, _managed_identity_params(credential, :azure_ml))
        headers = Dict("secret" => ENV[ENV_MSI_SECRET])
        response, payload = _managed_identity_request(credential, "GET", url; headers, query)
        response.status == 200 || throw(CredentialUnavailableError(_oauth_error_message(payload, "Azure ML managed identity unavailable.")))
        return _parse_managed_identity_token(payload, resource, credential.runtime)
    elseif haskey(ENV, ENV_MSI_ENDPOINT)
        credential.client_id === nothing || throw(ClientAuthenticationError("Cloud Shell managed identity does not support specifying client_id."))
        isempty(credential.identity_config) || throw(ClientAuthenticationError("Cloud Shell managed identity does not support identity_config overrides."))
        url = ENV[ENV_MSI_ENDPOINT]
        headers = Dict("Metadata" => "true", "Content-Type" => "application/x-www-form-urlencoded")
        body = _form_encode(Dict("resource" => resource))
        response = credential.runtime.http_request("POST", url; headers, body)
        payload = try
            _decode_json_body(response.body)
        catch
            Dict{String, Any}("raw" => response.body)
        end
        response.status == 200 || throw(CredentialUnavailableError(_oauth_error_message(payload, "Cloud Shell managed identity unavailable.")))
        return _parse_managed_identity_token(payload, resource, credential.runtime)
    else
        url = string(get(ENV, ENV_AZURE_POD_IDENTITY_AUTHORITY_HOST, "http://169.254.169.254"), "/metadata/identity/oauth2/token")
        query = Dict("api-version" => "2018-02-01", "resource" => resource)
        merge!(query, _managed_identity_params(credential, :imds))
        headers = Dict("Metadata" => "true")
        response, payload = _managed_identity_request(credential, "GET", url; headers, query)
        if response.status == 400
            throw(CredentialUnavailableError(_oauth_error_message(payload, "Managed identity is unavailable for this resource.")))
        elseif response.status == 403 && occursin("unreachable", lowercase(response.body))
            throw(CredentialUnavailableError("Managed identity endpoint is unreachable."))
        elseif response.status != 200
            throw(CredentialUnavailableError(_oauth_error_message(payload, "Managed identity request failed.")))
        end
        return _parse_managed_identity_token(payload, resource, credential.runtime)
    end
end

function get_token_info(credential::ManagedIdentityCredential, scopes::Vararg{String}; options::Union{Nothing, TokenRequestOptions} = nothing, claims = nothing, tenant_id = nothing, enable_cae::Bool = false)
    normalized_scopes = normalize_scopes(scopes...)
    # Coerce options into the cache key (consistent with the other credentials) so that
    # requests differing only via `options` (enable_cae/tenant_id/claims) don't collide.
    opts = _coerce_options(; options, claims, tenant_id, enable_cae)
    merged_claims = _merge_claims(opts.claims, opts.enable_cae)
    key = _cache_key(normalized_scopes...; tenant_id = opts.tenant_id, claims = merged_claims, enable_cae = opts.enable_cae)
    return _with_cache(credential.cache, credential.runtime, key, () -> begin
        _managed_identity_token(credential, normalized_scopes; options, claims, tenant_id, enable_cae)
    end)
end

Base.@kwdef struct AzureCliCredential <: AbstractAzureCredential
    tenant_id::String = ""
    subscription::Union{Nothing, String} = nothing
    additionally_allowed_tenants::Vector{String} = String[]
    process_timeout::Int = 10
    runtime::CredentialRuntime = default_runtime()
end

const AzureCLICredential = AzureCliCredential

function _run_process(credential, command::Cmd)
    return credential.runtime.run_process(command; timeout = credential.process_timeout)
end

function _parse_azure_cli_token(output::String)
    payload = JSON3.read(output, Dict{String, Any})
    # Prefer the epoch `expires_on` field (newer az versions). Otherwise fall back to the
    # `expiresOn` string, which the CLI emits as a naive LOCAL datetime; convert it to the
    # corresponding UTC instant so is_expired comparisons against UTC `now` are correct.
    expires_on = if haskey(payload, "expires_on")
        _parse_expires_on(payload["expires_on"])
    else
        local_naive_to_utc(_parse_datetime_string(strip(String(payload["expiresOn"]))))
    end
    return AzureAccessTokenInfo(
        token = String(payload["accessToken"]),
        expires_on = expires_on,
        token_type = "Bearer",
        resource = get(payload, "resource", nothing),
        scopes = String[],
        extras = payload,
    )
end

function get_token_info(credential::AzureCliCredential, scopes::Vararg{String}; options::Union{Nothing, TokenRequestOptions} = nothing, claims = nothing, tenant_id = nothing, enable_cae::Bool = false)
    enable_cae && throw(CredentialUnavailableError("AzureCliCredential does not support CAE in this implementation."))
    opts = _coerce_options(; options, claims, tenant_id, enable_cae)
    opts.claims === nothing || throw(CredentialUnavailableError("AzureCliCredential does not support claims challenges."))
    resource = _scopes_to_resource(scopes...)
    tenant = resolve_tenant(credential.tenant_id; tenant_id = opts.tenant_id, additionally_allowed_tenants = credential.additionally_allowed_tenants)
    command = `az account get-access-token --output json --resource $resource`
    tenant != "" && (command = `$command --tenant $tenant`)
    credential.subscription !== nothing && (command = `$command --subscription $(credential.subscription)`)
    result = _run_process(credential, command)
    result.exitcode == 0 || throw(CredentialUnavailableError(isempty(result.stderr) ? "Azure CLI authentication unavailable." : strip(result.stderr)))
    token = _parse_azure_cli_token(result.stdout)
    token.resource = resource
    token.scopes = [resource]
    return token
end

Base.@kwdef struct AzurePowerShellCredential <: AbstractAzureCredential
    tenant_id::String = ""
    additionally_allowed_tenants::Vector{String} = String[]
    process_timeout::Int = 10
    runtime::CredentialRuntime = default_runtime()
end

function _parse_powershell_token(output::String)
    for line in split(output, '\n')
        startswith(line, "azsdk%") || continue
        parts = split(strip(line), "%")
        length(parts) == 3 || continue
        return AzureAccessTokenInfo(
            token = parts[2],
            expires_on = epoch_to_datetime(parse(Int, parts[3])),
        )
    end
    throw(ClientAuthenticationError("Unexpected Azure PowerShell output."))
end

function get_token_info(credential::AzurePowerShellCredential, scopes::Vararg{String}; options::Union{Nothing, TokenRequestOptions} = nothing, claims = nothing, tenant_id = nothing, enable_cae::Bool = false)
    enable_cae && throw(CredentialUnavailableError("AzurePowerShellCredential does not support CAE in this implementation."))
    opts = _coerce_options(; options, claims, tenant_id, enable_cae)
    opts.claims === nothing || throw(CredentialUnavailableError("AzurePowerShellCredential does not support claims challenges."))
    resource = _scopes_to_resource(scopes...)
    tenant = resolve_tenant(credential.tenant_id; tenant_id = opts.tenant_id, additionally_allowed_tenants = credential.additionally_allowed_tenants)
    script = """
    \$ErrorActionPreference = 'Stop'
    \$params = @{ 'ResourceUrl' = '$resource'; 'WarningAction' = 'Ignore' }
    if ('$tenant' -ne '') { \$params['TenantId'] = '$tenant' }
    \$token = Get-AzAccessToken @params
    Write-Output "azsdk%\$((\$token.Token | Out-String).Trim())%\$([int][double]::Parse((Get-Date \$token.ExpiresOn -UFormat %s)))"
    """
    executable = Sys.which("pwsh")
    executable === nothing && (executable = Sys.which("powershell"))
    executable === nothing && throw(CredentialUnavailableError("PowerShell is not installed."))
    command = `$executable -NoProfile -Command $script`
    result = _run_process(credential, command)
    result.exitcode == 0 || throw(CredentialUnavailableError(isempty(result.stderr) ? "Azure PowerShell authentication unavailable." : strip(result.stderr)))
    token = _parse_powershell_token(result.stdout)
    token.resource = resource
    token.scopes = [resource]
    return token
end

Base.@kwdef struct AzureDeveloperCliCredential <: AbstractAzureCredential
    tenant_id::String = ""
    additionally_allowed_tenants::Vector{String} = String[]
    process_timeout::Int = 10
    runtime::CredentialRuntime = default_runtime()
end

function _parse_azd_token(output::String)
    payload = JSON3.read(output, Dict{String, Any})
    return AzureAccessTokenInfo(
        token = String(payload["token"]),
        expires_on = _parse_expires_on(payload["expiresOn"]),
        scopes = get(payload, "scopes", String[]),
        extras = payload,
    )
end

function get_token_info(credential::AzureDeveloperCliCredential, scopes::Vararg{String}; options::Union{Nothing, TokenRequestOptions} = nothing, claims = nothing, tenant_id = nothing, enable_cae::Bool = false)
    opts = _coerce_options(; options, claims, tenant_id, enable_cae)
    normalized_scopes = normalize_scopes(scopes...)
    tenant = resolve_tenant(credential.tenant_id; tenant_id = opts.tenant_id, additionally_allowed_tenants = credential.additionally_allowed_tenants)
    command = `azd auth token --output json --no-prompt`
    for scope in normalized_scopes
        command = `$command --scope $scope`
    end
    tenant != "" && (command = `$command --tenant-id $tenant`)
    opts.claims !== nothing && (command = `$command --claims $(encode_base64(opts.claims))`)
    result = _run_process(credential, command)
    result.exitcode == 0 || throw(CredentialUnavailableError(isempty(result.stderr) ? "Azure Developer CLI authentication unavailable." : strip(result.stderr)))
    token = _parse_azd_token(result.stdout)
    token.scopes = normalized_scopes
    return token
end

function _default_shared_cache_options(name::String)
    return TokenCachePersistenceOptions(name = name, directory = DEFAULT_SHARED_CACHE_DIRECTORY)
end

Base.@kwdef mutable struct SharedTokenCacheCredential <: AbstractAzureCredential
    username::Union{Nothing, String} = nothing
    tenant_id::String = ""
    client_id::String = DEVELOPER_SIGN_ON_CLIENT_ID
    authority::String = get_default_authority()
    cache_persistence_options::TokenCachePersistenceOptions = _default_shared_cache_options("shared_token_cache")
    authentication_record::Union{Nothing, AuthenticationRecord} = nothing
    additionally_allowed_tenants::Vector{String} = String[]
    disable_instance_discovery::Bool = false
    runtime::CredentialRuntime = default_runtime()
    cache::AccessTokenCache = AccessTokenCache()
end

function _matching_entry(credential::SharedTokenCacheCredential, scopes::Vector{String}; tenant_id::Union{Nothing, String} = nothing, claims::Union{Nothing, String} = nothing, enable_cae::Bool = false)
    requested_username = credential.username
    if requested_username === nothing && credential.authentication_record !== nothing
        requested_username = credential.authentication_record.username
    end
    requested_home_account = credential.authentication_record === nothing ? nothing : credential.authentication_record.home_account_id
    requested_tenant = tenant_id === nothing || tenant_id == "" ? credential.tenant_id : tenant_id
    if requested_tenant == "" && credential.authentication_record !== nothing
        requested_tenant = credential.authentication_record.tenant_id
    end
    entries = _load_token_entries(credential.cache_persistence_options; enable_cae = enable_cae)
    exact = findfirst(entry ->
        (requested_username === nothing || entry.username == requested_username) &&
        (requested_home_account === nothing || entry.home_account_id == requested_home_account) &&
        (requested_tenant == "" || entry.tenant_id == requested_tenant) &&
        (claims === nothing || entry.claims == claims) &&
        sort(entry.scopes) == sort(scopes),
        entries,
    )
    exact !== nothing && return entries[exact]
    refresh = findfirst(entry ->
        entry.refresh_token !== nothing &&
        (requested_username === nothing || entry.username == requested_username) &&
        (requested_home_account === nothing || entry.home_account_id == requested_home_account) &&
        (requested_tenant == "" || entry.tenant_id == requested_tenant) &&
        (claims === nothing || entry.claims == claims),
        entries,
    )
    return refresh === nothing ? nothing : entries[refresh]
end

function get_token_info(credential::SharedTokenCacheCredential, scopes::Vararg{String}; options::Union{Nothing, TokenRequestOptions} = nothing, claims = nothing, tenant_id = nothing, enable_cae::Bool = false)
    normalized_scopes = normalize_scopes(scopes...)
    opts = _coerce_options(; options, claims, tenant_id, enable_cae)
    requested_tenant = resolve_tenant(credential.tenant_id; tenant_id = opts.tenant_id, additionally_allowed_tenants = credential.additionally_allowed_tenants)
    key = _cache_key(normalized_scopes...; tenant_id = requested_tenant, claims = opts.claims, enable_cae = opts.enable_cae)
    cached = get_cached_token(credential.cache, key; now_fn = credential.runtime.now_fn)
    cached !== nothing && return cached
    entry = _matching_entry(credential, normalized_scopes; tenant_id = requested_tenant, claims = opts.claims, enable_cae = opts.enable_cae)
    entry === nothing && throw(CredentialUnavailableError("No matching token was found in the shared token cache."))
    if entry.access_token !== nothing && entry.expires_on !== nothing
        token = _token_info_from_entry(entry)
        if !is_expired(token; now_fn = credential.runtime.now_fn) &&
            (token.refresh_on === nothing || credential.runtime.now_fn() < token.refresh_on)
            put_cached_token!(credential.cache, key, token)
            return token
        end
    end
    entry.refresh_token !== nothing || throw(CredentialUnavailableError("No usable refresh token was found in the shared token cache."))
    authority = _validated_authority(
        something(entry.authority, credential.authority),
        credential.runtime;
        disable_instance_discovery = credential.disable_instance_discovery,
    )
    tenant = requested_tenant == "" ? something(entry.tenant_id, requested_tenant, "") : requested_tenant
    tenant = tenant == "" ? something(entry.tenant_id, credential.tenant_id, "") : tenant
    refreshed = _request_refresh_token(credential.runtime, authority, tenant, something(entry.client_id, credential.client_id), entry.refresh_token, normalized_scopes; claims = opts.claims, enable_cae = opts.enable_cae)
    record = credential.authentication_record
    if record === nothing
        record = AuthenticationRecord(
            authority = authority,
            client_id = something(entry.client_id, credential.client_id),
            tenant_id = tenant,
            username = entry.username,
            home_account_id = entry.home_account_id,
        )
    end
    _store_token_result!(credential.cache_persistence_options, refreshed, normalized_scopes; client_id = something(entry.client_id, credential.client_id), authority = authority, tenant_id = tenant, record = record, claims = opts.claims, enable_cae = opts.enable_cae)
    put_cached_token!(credential.cache, key, refreshed.token)
    return refreshed.token
end

mutable struct VisualStudioCodeCredential <: AbstractAzureCredential
    inner::SharedTokenCacheCredential
    authentication_record_path::Union{Nothing, String}
end

function VisualStudioCodeCredential(
    ;
    tenant_id::String = "",
    additionally_allowed_tenants::Vector{String} = String[],
    authentication_record::Union{Nothing, AuthenticationRecord} = nothing,
    authentication_record_path::Union{Nothing, String} = joinpath(homedir(), ".azureidentity", "vscode-auth-record.json"),
    cache_persistence_options::TokenCachePersistenceOptions = _default_shared_cache_options("vscode"),
    disable_instance_discovery::Bool = false,
    runtime::CredentialRuntime = default_runtime(),
)
    record = authentication_record
    if record === nothing && authentication_record_path !== nothing && isfile(authentication_record_path)
        record = load_authentication_record(authentication_record_path)
    end
    inner = SharedTokenCacheCredential(
        tenant_id = tenant_id,
        cache_persistence_options = cache_persistence_options,
        authentication_record = record,
        additionally_allowed_tenants = additionally_allowed_tenants,
        disable_instance_discovery = disable_instance_discovery,
        runtime = runtime,
    )
    return VisualStudioCodeCredential(inner, authentication_record_path)
end

get_token_info(credential::VisualStudioCodeCredential, scopes::Vararg{String}; kwargs...) = get_token_info(credential.inner, scopes...; kwargs...)

function _store_interactive_result!(credential, result::OAuthTokenResult, scopes::Vector{String}; tenant_id::String, authority::Union{Nothing, String} = nothing, claims::Union{Nothing, String} = nothing, enable_cae::Bool = false)
    resolved_authority = something(authority, credential.authority)
    credential.authentication_record = _build_authentication_record(result, credential.client_id, resolved_authority, tenant_id)
    key = _cache_key(scopes...; tenant_id = tenant_id, claims = _merge_claims(claims, enable_cae), enable_cae = enable_cae)
    put_cached_token!(credential.cache, key, result.token)
    if credential.cache_persistence_options !== nothing
        _store_token_result!(credential.cache_persistence_options, result, scopes; client_id = credential.client_id, authority = resolved_authority, tenant_id = tenant_id, record = credential.authentication_record, claims = claims, enable_cae = enable_cae)
    end
    return result.token
end

function _try_shared_cache_token(credential, scopes::Vector{String}; tenant_id::Union{Nothing, String} = nothing, claims::Union{Nothing, String} = nothing, enable_cae::Bool = false)
    credential.cache_persistence_options === nothing && return nothing
    shared = SharedTokenCacheCredential(
        username = credential.authentication_record === nothing ? nothing : credential.authentication_record.username,
        tenant_id = something(tenant_id, credential.tenant_id),
        client_id = credential.client_id,
        authority = credential.authority,
        cache_persistence_options = credential.cache_persistence_options,
        authentication_record = credential.authentication_record,
        additionally_allowed_tenants = credential.additionally_allowed_tenants,
        disable_instance_discovery = credential.disable_instance_discovery,
        runtime = credential.runtime,
    )
    try
        return get_token_info(shared, scopes...; tenant_id, claims, enable_cae)
    catch err
        err isa AbstractAzureAuthError || rethrow()
        return nothing
    end
end

Base.@kwdef mutable struct AuthorizationCodeCredential <: AbstractAzureCredential
    tenant_id::String
    client_id::String
    authorization_code::Union{Nothing, String}
    redirect_uri::String
    client_secret::Union{Nothing, String} = nothing
    code_verifier::Union{Nothing, String} = nothing
    authority::String = get_default_authority()
    additionally_allowed_tenants::Vector{String} = String[]
    cache_persistence_options::Union{Nothing, TokenCachePersistenceOptions} = nothing
    authentication_record::Union{Nothing, AuthenticationRecord} = nothing
    runtime::CredentialRuntime = default_runtime()
    disable_instance_discovery::Bool = false
    cache::AccessTokenCache = AccessTokenCache()
end

function get_token_info(credential::AuthorizationCodeCredential, scopes::Vararg{String}; options::Union{Nothing, TokenRequestOptions} = nothing, claims = nothing, tenant_id = nothing, enable_cae::Bool = false)
    normalized_scopes = normalize_scopes(scopes...)
    opts = _coerce_options(; options, claims, tenant_id, enable_cae)
    tenant = resolve_tenant(credential.tenant_id; tenant_id = opts.tenant_id, additionally_allowed_tenants = credential.additionally_allowed_tenants)
    authority = _validated_authority(credential.authority, credential.runtime; disable_instance_discovery = credential.disable_instance_discovery)
    merged_claims = _merge_claims(opts.claims, opts.enable_cae)
    key = _cache_key(normalized_scopes...; tenant_id = tenant, claims = merged_claims, enable_cae = opts.enable_cae)
    cached = get_cached_token(credential.cache, key; now_fn = credential.runtime.now_fn)
    cached !== nothing && return cached
    persistent = _try_shared_cache_token(credential, normalized_scopes; tenant_id = tenant, claims = opts.claims, enable_cae = opts.enable_cae)
    persistent !== nothing && return put_cached_token!(credential.cache, key, persistent)
    credential.authorization_code === nothing && throw(AuthenticationRequiredError(message = "No authorization code is available.", scopes = normalized_scopes, claims = opts.claims))
    result = _request_authorization_code_token(credential.runtime, authority, tenant, credential.client_id, credential.authorization_code, credential.redirect_uri, normalized_scopes;
        code_verifier = credential.code_verifier,
        client_secret = credential.client_secret,
        claims = opts.claims,
        enable_cae = opts.enable_cae,
    )
    credential.authorization_code = nothing
    return _store_interactive_result!(credential, result, normalized_scopes; tenant_id = tenant, authority = authority, claims = opts.claims, enable_cae = opts.enable_cae)
end

Base.@kwdef mutable struct DeviceCodeCredential <: AbstractAzureCredential
    tenant_id::String = "organizations"
    client_id::String = DEVELOPER_SIGN_ON_CLIENT_ID
    authority::String = get_default_authority()
    additionally_allowed_tenants::Vector{String} = String[]
    cache_persistence_options::Union{Nothing, TokenCachePersistenceOptions} = nothing
    authentication_record::Union{Nothing, AuthenticationRecord} = nothing
    disable_automatic_authentication::Bool = false
    prompt_callback::Union{Nothing, Function} = nothing
    timeout::Int = 600
    runtime::CredentialRuntime = default_runtime()
    disable_instance_discovery::Bool = false
    cache::AccessTokenCache = AccessTokenCache()
end

function authenticate(credential::DeviceCodeCredential, scopes::Vararg{String}; claims = nothing, tenant_id = nothing, enable_cae::Bool = false)
    normalized_scopes = normalize_scopes(scopes...)
    tenant = resolve_tenant(credential.tenant_id; tenant_id = tenant_id, additionally_allowed_tenants = credential.additionally_allowed_tenants)
    authority = _validated_authority(credential.authority, credential.runtime; disable_instance_discovery = credential.disable_instance_discovery)
    device_code = _request_device_code(credential.runtime, authority, tenant, credential.client_id, normalized_scopes; claims = claims)
    if credential.prompt_callback !== nothing
        credential.prompt_callback(device_code)
    elseif haskey(device_code, "message")
        println(String(device_code["message"]))
    end
    interval = parse(Int, string(get(device_code, "interval", 5)))
    result = _poll_device_code_token(credential.runtime, authority, tenant, credential.client_id, String(device_code["device_code"]), normalized_scopes;
        claims = claims,
        enable_cae = enable_cae,
        timeout = min(credential.timeout, parse(Int, string(get(device_code, "expires_in", credential.timeout)))),
        interval = interval,
    )
    _store_interactive_result!(credential, result, normalized_scopes; tenant_id = tenant, authority = authority, claims = claims, enable_cae = enable_cae)
    return credential.authentication_record
end

function get_token_info(credential::DeviceCodeCredential, scopes::Vararg{String}; options::Union{Nothing, TokenRequestOptions} = nothing, claims = nothing, tenant_id = nothing, enable_cae::Bool = false)
    normalized_scopes = normalize_scopes(scopes...)
    opts = _coerce_options(; options, claims, tenant_id, enable_cae)
    tenant = resolve_tenant(credential.tenant_id; tenant_id = opts.tenant_id, additionally_allowed_tenants = credential.additionally_allowed_tenants)
    merged_claims = _merge_claims(opts.claims, opts.enable_cae)
    key = _cache_key(normalized_scopes...; tenant_id = tenant, claims = merged_claims, enable_cae = opts.enable_cae)
    cached = get_cached_token(credential.cache, key; now_fn = credential.runtime.now_fn)
    cached !== nothing && return cached
    persistent = _try_shared_cache_token(credential, normalized_scopes; tenant_id = tenant, claims = opts.claims, enable_cae = opts.enable_cae)
    persistent !== nothing && return put_cached_token!(credential.cache, key, persistent)
    credential.disable_automatic_authentication && throw(AuthenticationRequiredError(message = "Device code authentication is disabled.", scopes = normalized_scopes, claims = opts.claims))
    authenticate(credential, normalized_scopes...; claims = opts.claims, tenant_id = tenant, enable_cae = opts.enable_cae)
    refreshed = get_cached_token(credential.cache, key; now_fn = credential.runtime.now_fn)
    refreshed === nothing && throw(CredentialUnavailableError("Device code authentication did not produce a token."))
    return refreshed
end

Base.@kwdef mutable struct InteractiveBrowserCredential <: AbstractAzureCredential
    tenant_id::String = "organizations"
    client_id::String = DEVELOPER_SIGN_ON_CLIENT_ID
    authority::String = get_default_authority()
    additionally_allowed_tenants::Vector{String} = String[]
    redirect_uri::Union{Nothing, String} = nothing
    login_hint::Union{Nothing, String} = nothing
    cache_persistence_options::Union{Nothing, TokenCachePersistenceOptions} = nothing
    authentication_record::Union{Nothing, AuthenticationRecord} = nothing
    disable_automatic_authentication::Bool = false
    timeout::Int = 300
    runtime::CredentialRuntime = default_runtime()
    disable_instance_discovery::Bool = false
    cache::AccessTokenCache = AccessTokenCache()
end

function _pkce_pair(runtime::CredentialRuntime)
    verifier = base64url_encode(runtime.random_bytes(32))
    challenge = base64url_encode(Vector{UInt8}(SHA.sha256(verifier)))
    return verifier, challenge
end

function _loopback_listener(port::Int)
    server = Sockets.listen(ip"127.0.0.1", port)
    address = Sockets.getsockname(server)
    actual_port = hasproperty(address, :port) ? getproperty(address, :port) : address[end]
    return server, actual_port
end

function _wait_for_redirect_code(server; timeout::Int, state::String)
    task = @async begin
        socket = accept(server)
        try
            request_line = readline(socket)
            while !eof(socket)
                line = readline(socket)
                isempty(strip(line)) && break
            end
            parts = split(request_line)
            length(parts) >= 2 || throw(ClientAuthenticationError("Invalid loopback redirect request."))
            uri = HTTP.URIs.URI("http://localhost" * parts[2])
            params = Dict(String(key) => String(value) for (key, value) in HTTP.URIs.queryparams(uri))
            returned_state = get(params, "state", "")
            returned_state == state || throw(ClientAuthenticationError("The browser redirect state did not match."))
            if haskey(params, "error")
                throw(ClientAuthenticationError(get(params, "error_description", params["error"])))
            end
            code = get(params, "code", nothing)
            code === nothing && throw(ClientAuthenticationError("The browser redirect did not include an authorization code."))
            body = "Authentication complete. You can close this window."
            write(socket, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: $(length(body))\r\n\r\n$body")
            return code
        finally
            close(socket)
        end
    end
    status = timedwait(() -> istaskdone(task), timeout)
    close(server)
    status === :ok || throw(CredentialUnavailableError("Timed out waiting for the browser redirect."))
    return fetch(task)
end

function _authorization_url(authority::String, tenant_id::String, client_id::String, redirect_uri::String, scopes::Vector{String}, state::String, challenge::String; claims = nothing, login_hint = nothing)
    params = Dict(
        "client_id" => client_id,
        "response_type" => "code",
        "redirect_uri" => redirect_uri,
        "response_mode" => "query",
        "scope" => join(scopes, " "),
        "state" => state,
        "code_challenge" => challenge,
        "code_challenge_method" => "S256",
    )
    claims !== nothing && (params["claims"] = claims)
    login_hint !== nothing && (params["login_hint"] = login_hint)
    return _append_query(_authorize_endpoint(authority, tenant_id), params)
end

function authenticate(credential::InteractiveBrowserCredential, scopes::Vararg{String}; claims = nothing, tenant_id = nothing, enable_cae::Bool = false)
    normalized_scopes = normalize_scopes(scopes...)
    tenant = resolve_tenant(credential.tenant_id; tenant_id = tenant_id, additionally_allowed_tenants = credential.additionally_allowed_tenants)
    authority = _validated_authority(credential.authority, credential.runtime; disable_instance_discovery = credential.disable_instance_discovery)
    verifier, challenge = _pkce_pair(credential.runtime)
    server = nothing
    redirect_uri = credential.redirect_uri
    if redirect_uri === nothing
        server, port = _loopback_listener(0)
        redirect_uri = "http://127.0.0.1:$port/callback"
    else
        uri = HTTP.URIs.URI(redirect_uri)
        uri.host in ("127.0.0.1", "localhost") || throw(ArgumentError("InteractiveBrowserCredential only supports localhost redirect URIs in this implementation"))
        port = uri.port == 0 ? 80 : uri.port
        server, _ = _loopback_listener(port)
    end
    state = base64url_encode(credential.runtime.random_bytes(16))
    url = _authorization_url(authority, tenant, credential.client_id, redirect_uri, normalized_scopes, state, challenge; claims = claims, login_hint = credential.login_hint)
    credential.runtime.open_browser(url)
    code = _wait_for_redirect_code(server; timeout = credential.timeout, state = state)
    result = _request_authorization_code_token(credential.runtime, authority, tenant, credential.client_id, code, redirect_uri, normalized_scopes;
        code_verifier = verifier,
        claims = claims,
        enable_cae = enable_cae,
    )
    _store_interactive_result!(credential, result, normalized_scopes; tenant_id = tenant, authority = authority, claims = claims, enable_cae = enable_cae)
    return credential.authentication_record
end

function get_token_info(credential::InteractiveBrowserCredential, scopes::Vararg{String}; options::Union{Nothing, TokenRequestOptions} = nothing, claims = nothing, tenant_id = nothing, enable_cae::Bool = false)
    normalized_scopes = normalize_scopes(scopes...)
    opts = _coerce_options(; options, claims, tenant_id, enable_cae)
    tenant = resolve_tenant(credential.tenant_id; tenant_id = opts.tenant_id, additionally_allowed_tenants = credential.additionally_allowed_tenants)
    merged_claims = _merge_claims(opts.claims, opts.enable_cae)
    key = _cache_key(normalized_scopes...; tenant_id = tenant, claims = merged_claims, enable_cae = opts.enable_cae)
    cached = get_cached_token(credential.cache, key; now_fn = credential.runtime.now_fn)
    cached !== nothing && return cached
    persistent = _try_shared_cache_token(credential, normalized_scopes; tenant_id = tenant, claims = opts.claims, enable_cae = opts.enable_cae)
    persistent !== nothing && return put_cached_token!(credential.cache, key, persistent)
    credential.disable_automatic_authentication && throw(AuthenticationRequiredError(message = "Interactive browser authentication is disabled.", scopes = normalized_scopes, claims = opts.claims))
    authenticate(credential, normalized_scopes...; claims = opts.claims, tenant_id = tenant, enable_cae = opts.enable_cae)
    refreshed = get_cached_token(credential.cache, key; now_fn = credential.runtime.now_fn)
    refreshed === nothing && throw(CredentialUnavailableError("Interactive browser authentication did not produce a token."))
    return refreshed
end

Base.@kwdef struct ChainedTokenCredential <: AbstractAzureCredential
    credentials::Vector{AbstractAzureCredential}
    continue_on_error::Bool = false
end

function get_token_info(credential::ChainedTokenCredential, scopes::Vararg{String}; kwargs...)
    errors = String[]
    for inner in credential.credentials
        try
            return get_token_info(inner, scopes...; kwargs...)
        catch err
            if err isa CredentialUnavailableError || (credential.continue_on_error && err isa AbstractAzureAuthError)
                push!(errors, "$(typeof(inner)): $(sprint(showerror, err))")
                continue
            end
            rethrow()
        end
    end
    throw(AzureAuthError("ChainedTokenCredential failed. Tried:\n" * join(errors, "\n")))
end

mutable struct DefaultAzureCredential <: AbstractAzureCredential
    credentials::Vector{AbstractAzureCredential}
    developer_types::Set{DataType}
end

function _credential_mode_exclusions(exclude_flags::Dict{Symbol, Bool})
    selection = lowercase(strip(get(ENV, ENV_AZURE_TOKEN_CREDENTIALS, "")))
    if isempty(selection)
        return exclude_flags
    elseif selection == "dev"
        for key in keys(exclude_flags)
            exclude_flags[key] = !(key in (:shared_token_cache, :visual_studio_code, :cli, :powershell, :developer_cli))
        end
    elseif selection == "prod"
        for key in keys(exclude_flags)
            exclude_flags[key] = !(key in (:environment, :workload_identity, :managed_identity))
        end
    else
        valid = Dict(
            "environment" => :environment,
            "workload_identity" => :workload_identity,
            "managed_identity" => :managed_identity,
            "shared_token_cache" => :shared_token_cache,
            "visual_studio_code" => :visual_studio_code,
            "cli" => :cli,
            "powershell" => :powershell,
            "developer_cli" => :developer_cli,
            "interactive_browser" => :interactive_browser,
        )
        haskey(valid, selection) || throw(ArgumentError("Invalid value for $ENV_AZURE_TOKEN_CREDENTIALS: $selection"))
        selected = valid[selection]
        for key in keys(exclude_flags)
            exclude_flags[key] = key != selected
        end
    end
    return exclude_flags
end

function DefaultAzureCredential(
    ;
    credentials::Union{Nothing, Vector{AbstractAzureCredential}} = nothing,
    authority::String = get_default_authority(),
    exclude_environment_credential::Bool = false,
    exclude_workload_identity_credential::Bool = false,
    exclude_managed_identity_credential::Bool = false,
    exclude_shared_token_cache_credential::Bool = false,
    exclude_visual_studio_code_credential::Bool = false,
    exclude_cli_credential::Bool = false,
    exclude_powershell_credential::Bool = false,
    exclude_developer_cli_credential::Bool = false,
    exclude_interactive_browser_credential::Bool = true,
    managed_identity_client_id::Union{Nothing, String} = get(ENV, ENV_AZURE_CLIENT_ID, nothing),
    shared_cache_username::Union{Nothing, String} = nothing,
    shared_cache_tenant_id::String = "",
    process_timeout::Int = 10,
    cache_persistence_options::Union{Nothing, TokenCachePersistenceOptions} = nothing,
    require_envvar::Bool = false,
    disable_instance_discovery::Bool = false,
)
    if credentials !== nothing
        return DefaultAzureCredential(credentials, Set{DataType}())
    end
    require_envvar && get(ENV, ENV_AZURE_TOKEN_CREDENTIALS, "") == "" && throw(ArgumentError("$ENV_AZURE_TOKEN_CREDENTIALS must be set when require_envvar=true"))

    exclude_flags = Dict(
        :environment => exclude_environment_credential,
        :workload_identity => exclude_workload_identity_credential,
        :managed_identity => exclude_managed_identity_credential,
        :shared_token_cache => exclude_shared_token_cache_credential,
        :visual_studio_code => exclude_visual_studio_code_credential,
        :cli => exclude_cli_credential,
        :powershell => exclude_powershell_credential,
        :developer_cli => exclude_developer_cli_credential,
        :interactive_browser => exclude_interactive_browser_credential,
    )
    _credential_mode_exclusions(exclude_flags)

    built = AbstractAzureCredential[]
    !exclude_flags[:environment] && push!(built, EnvironmentCredential(authority = authority, disable_instance_discovery = disable_instance_discovery))
    if !exclude_flags[:workload_identity] && haskey(ENV, ENV_AZURE_FEDERATED_TOKEN_FILE) && haskey(ENV, ENV_AZURE_TENANT_ID) && (managed_identity_client_id !== nothing || haskey(ENV, ENV_AZURE_CLIENT_ID))
        push!(built, WorkloadIdentityCredential(authority = authority, client_id = managed_identity_client_id, disable_instance_discovery = disable_instance_discovery))
    end
    !exclude_flags[:managed_identity] && push!(built, ManagedIdentityCredential(client_id = managed_identity_client_id))
    !exclude_flags[:shared_token_cache] && push!(built, SharedTokenCacheCredential(username = shared_cache_username, tenant_id = shared_cache_tenant_id, cache_persistence_options = something(cache_persistence_options, _default_shared_cache_options("shared_token_cache")), disable_instance_discovery = disable_instance_discovery))
    !exclude_flags[:visual_studio_code] && push!(built, VisualStudioCodeCredential(cache_persistence_options = something(cache_persistence_options, _default_shared_cache_options("vscode")), disable_instance_discovery = disable_instance_discovery))
    !exclude_flags[:cli] && push!(built, AzureCliCredential(process_timeout = process_timeout))
    !exclude_flags[:powershell] && push!(built, AzurePowerShellCredential(process_timeout = process_timeout))
    !exclude_flags[:developer_cli] && push!(built, AzureDeveloperCliCredential(process_timeout = process_timeout))
    !exclude_flags[:interactive_browser] && push!(built, InteractiveBrowserCredential(cache_persistence_options = cache_persistence_options, disable_instance_discovery = disable_instance_discovery))

    developer_types = Set([SharedTokenCacheCredential, VisualStudioCodeCredential, AzureCliCredential, AzurePowerShellCredential, AzureDeveloperCliCredential, InteractiveBrowserCredential])
    return DefaultAzureCredential(built, developer_types)
end

function get_token_info(credential::DefaultAzureCredential, scopes::Vararg{String}; kwargs...)
    errors = String[]
    for inner in credential.credentials
        try
            return get_token_info(inner, scopes...; kwargs...)
        catch err
            if err isa CredentialUnavailableError || (err isa AbstractAzureAuthError && typeof(inner) in credential.developer_types)
                push!(errors, "$(typeof(inner)): $(sprint(showerror, err))")
                continue
            end
            rethrow()
        end
    end
    throw(AzureAuthError("DefaultAzureCredential failed. Tried:\n" * join(errors, "\n")))
end
