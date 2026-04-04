function get_cached_token(cache::AccessTokenCache, key::AbstractString; now_fn::Function = () -> Dates.now(Dates.UTC))
    lock(cache.lock) do
        token = get(cache.tokens, String(key), nothing)
        token === nothing && return nothing
        token.refresh_on !== nothing && now_fn() >= token.refresh_on && return nothing
        return is_expired(token; now_fn = now_fn) ? nothing : token
    end
end

function put_cached_token!(cache::AccessTokenCache, key::AbstractString, token::AzureAccessTokenInfo)
    lock(cache.lock) do
        cache.tokens[String(key)] = token
    end
    return token
end

function clear_cache!(cache::AccessTokenCache)
    lock(cache.lock) do
        empty!(cache.tokens)
    end
    return nothing
end

struct KeychainTokenCacheBackend <: AbstractTokenCacheBackend end
struct LibsecretTokenCacheBackend <: AbstractTokenCacheBackend end
struct WindowsProtectedTokenCacheBackend <: AbstractTokenCacheBackend end

const _KEYCHAIN_BACKEND = KeychainTokenCacheBackend()
const _LIBSECRET_BACKEND = LibsecretTokenCacheBackend()
const _WINDOWS_BACKEND = WindowsProtectedTokenCacheBackend()

const _KEYCHAIN_SERVICE = "AzureIdentity.jl.TokenCache"
const _LIBSECRET_LABEL = "AzureIdentity.jl token cache"
const _WINDOWS_CACHE_PREFIX = "AZUREIDENTITY-DPAPI-1\n"
const _ERRSEC_ITEM_NOT_FOUND = Int32(-25300)
const _SECURITY_FRAMEWORK = "/System/Library/Frameworks/Security.framework/Security"
const _COREFOUNDATION_FRAMEWORK = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"

function _cache_file_path(options::TokenCachePersistenceOptions; enable_cae::Bool = false)
    suffix = enable_cae ? CACHE_CAE_SUFFIX : CACHE_NON_CAE_SUFFIX
    return joinpath(options.directory, options.name * suffix)
end

_cache_secret_account(options::TokenCachePersistenceOptions; enable_cae::Bool = false) = _cache_file_path(options; enable_cae = enable_cae)

function _ensure_cache_storage!(options::TokenCachePersistenceOptions)
    mkpath(options.directory)
    return nothing
end

function _touch_cache_marker!(path::AbstractString)
    open(path, "w") do io
        write(io, "")
    end
    try
        chmod(path, 0o600)
    catch
    end
    return String(path)
end

function _write_cache_file(path::AbstractString, payload::AbstractString)
    open(path, "w") do io
        write(io, payload)
    end
    try
        chmod(path, 0o600)
    catch
    end
    return String(path)
end

function _read_cache_file(path::AbstractString)
    isfile(path) || return ""
    return read(path, String)
end

function _run_capture(command::Cmd; input::Union{Nothing, AbstractString} = nothing)
    stdout = Pipe()
    stderr = Pipe()
    process = if input === nothing
        run(pipeline(ignorestatus(command), stdout = stdout, stderr = stderr), wait = false)
    else
        run(pipeline(ignorestatus(command), stdin = IOBuffer(String(input)), stdout = stdout, stderr = stderr), wait = false)
    end
    close(stdout.in)
    close(stderr.in)
    wait(process)
    return ProcessResult(
        exitcode = process.exitcode,
        stdout = read(stdout, String),
        stderr = read(stderr, String),
    )
end

function _with_temp_env(vars::Dict{String, String}, f::Function)
    saved = Dict(key => get(ENV, key, nothing) for key in keys(vars))
    try
        for (key, value) in vars
            ENV[key] = value
        end
        return f()
    finally
        for (key, value) in saved
            if value === nothing
                haskey(ENV, key) && delete!(ENV, key)
            else
                ENV[key] = value
            end
        end
    end
end

function _cfrelease(ptr::Ptr{Cvoid})
    ptr == C_NULL && return nothing
    ccall((:CFRelease, _COREFOUNDATION_FRAMEWORK), Cvoid, (Ptr{Cvoid},), ptr)
    return nothing
end

function _macos_keychain_get(service::AbstractString, account::AbstractString)
    service_bytes = Vector{UInt8}(codeunits(String(service)))
    account_bytes = Vector{UInt8}(codeunits(String(account)))
    password_length = Ref{UInt32}(0)
    password_data = Ref{Ptr{UInt8}}(C_NULL)
    status = GC.@preserve service_bytes account_bytes begin
        ccall(
            (:SecKeychainFindGenericPassword, _SECURITY_FRAMEWORK),
            Int32,
            (Ptr{Cvoid}, UInt32, Ptr{UInt8}, UInt32, Ptr{UInt8}, Ref{UInt32}, Ref{Ptr{UInt8}}, Ptr{Ptr{Cvoid}}),
            C_NULL,
            UInt32(length(service_bytes)),
            pointer(service_bytes),
            UInt32(length(account_bytes)),
            pointer(account_bytes),
            password_length,
            password_data,
            C_NULL,
        )
    end
    status == _ERRSEC_ITEM_NOT_FOUND && return nothing
    status == 0 || throw(TokenCachePersistenceError("Keychain lookup failed with status $status."))
    try
        return copy(unsafe_wrap(Vector{UInt8}, password_data[], password_length[]; own = false))
    finally
        password_data[] != C_NULL && ccall(
            (:SecKeychainItemFreeContent, _SECURITY_FRAMEWORK),
            Int32,
            (Ptr{Cvoid}, Ptr{Cvoid}),
            C_NULL,
            password_data[],
        )
    end
end

function _macos_keychain_set(service::AbstractString, account::AbstractString, payload::Vector{UInt8})
    service_bytes = Vector{UInt8}(codeunits(String(service)))
    account_bytes = Vector{UInt8}(codeunits(String(account)))
    password_length = Ref{UInt32}(0)
    password_data = Ref{Ptr{UInt8}}(C_NULL)
    item_ref = Ref{Ptr{Cvoid}}(C_NULL)
    status = GC.@preserve service_bytes account_bytes begin
        ccall(
            (:SecKeychainFindGenericPassword, _SECURITY_FRAMEWORK),
            Int32,
            (Ptr{Cvoid}, UInt32, Ptr{UInt8}, UInt32, Ptr{UInt8}, Ref{UInt32}, Ref{Ptr{UInt8}}, Ref{Ptr{Cvoid}}),
            C_NULL,
            UInt32(length(service_bytes)),
            pointer(service_bytes),
            UInt32(length(account_bytes)),
            pointer(account_bytes),
            password_length,
            password_data,
            item_ref,
        )
    end
    try
        if status == 0
            GC.@preserve payload begin
                update_status = ccall(
                    (:SecKeychainItemModifyAttributesAndData, _SECURITY_FRAMEWORK),
                    Int32,
                    (Ptr{Cvoid}, Ptr{Cvoid}, UInt32, Ptr{Cvoid}),
                    item_ref[],
                    C_NULL,
                    UInt32(length(payload)),
                    pointer(payload),
                )
                update_status == 0 || throw(TokenCachePersistenceError("Keychain update failed with status $update_status."))
            end
            return nothing
        elseif status == _ERRSEC_ITEM_NOT_FOUND
            GC.@preserve service_bytes account_bytes payload begin
                add_status = ccall(
                    (:SecKeychainAddGenericPassword, _SECURITY_FRAMEWORK),
                    Int32,
                    (Ptr{Cvoid}, UInt32, Ptr{UInt8}, UInt32, Ptr{UInt8}, UInt32, Ptr{Cvoid}, Ptr{Ptr{Cvoid}}),
                    C_NULL,
                    UInt32(length(service_bytes)),
                    pointer(service_bytes),
                    UInt32(length(account_bytes)),
                    pointer(account_bytes),
                    UInt32(length(payload)),
                    pointer(payload),
                    C_NULL,
                )
                add_status == 0 || throw(TokenCachePersistenceError("Keychain write failed with status $add_status."))
            end
            return nothing
        end
        throw(TokenCachePersistenceError("Keychain lookup failed with status $status."))
    finally
        password_data[] != C_NULL && ccall(
            (:SecKeychainItemFreeContent, _SECURITY_FRAMEWORK),
            Int32,
            (Ptr{Cvoid}, Ptr{Cvoid}),
            C_NULL,
            password_data[],
        )
        _cfrelease(item_ref[])
    end
end

function _libsecret_get(service::AbstractString, account::AbstractString)
    result = _run_capture(`secret-tool lookup service $service account $account`)
    result.exitcode == 0 || return nothing
    return Vector{UInt8}(codeunits(chomp(result.stdout)))
end

function _libsecret_set(service::AbstractString, account::AbstractString, payload::AbstractString)
    result = _run_capture(
        `secret-tool store --label=$_LIBSECRET_LABEL service $service account $account`;
        input = payload,
    )
    result.exitcode == 0 || throw(TokenCachePersistenceError(isempty(result.stderr) ? "libsecret storage failed." : strip(result.stderr)))
    return nothing
end

function _powershell_executable()
    executable = Sys.which("powershell")
    executable === nothing && (executable = Sys.which("pwsh"))
    executable === nothing && throw(TokenCachePersistenceError("Windows persistent cache requires PowerShell or pwsh."))
    return executable
end

function _windows_protect(payload::AbstractString)
    script = raw"$bytes = [Convert]::FromBase64String($env:AZUREIDENTITY_CACHE_PAYLOAD); $protected = [Security.Cryptography.ProtectedData]::Protect($bytes, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser); [Console]::Out.Write([Convert]::ToBase64String($protected))"
    return _with_temp_env(Dict("AZUREIDENTITY_CACHE_PAYLOAD" => base64encode(String(payload)))) do
        result = _run_capture(`$(_powershell_executable()) -NoProfile -NonInteractive -Command $script`)
        result.exitcode == 0 || throw(TokenCachePersistenceError(isempty(result.stderr) ? "Windows data protection failed." : strip(result.stderr)))
        return strip(result.stdout)
    end
end

function _windows_unprotect(payload::AbstractString)
    script = raw"$bytes = [Security.Cryptography.ProtectedData]::Unprotect([Convert]::FromBase64String($env:AZUREIDENTITY_CACHE_PAYLOAD), $null, [Security.Cryptography.DataProtectionScope]::CurrentUser); [Console]::Out.Write([System.Text.Encoding]::UTF8.GetString($bytes))"
    return _with_temp_env(Dict("AZUREIDENTITY_CACHE_PAYLOAD" => String(payload))) do
        result = _run_capture(`$(_powershell_executable()) -NoProfile -NonInteractive -Command $script`)
        result.exitcode == 0 || throw(TokenCachePersistenceError(isempty(result.stderr) ? "Windows data protection failed." : strip(result.stderr)))
        return result.stdout
    end
end

function _resolve_cache_backend(options::TokenCachePersistenceOptions)
    if !(options.backend isa AutoTokenCacheBackend)
        return options.backend
    end

    if Sys.isapple()
        return _KEYCHAIN_BACKEND
    elseif Sys.iswindows()
        return _WINDOWS_BACKEND
    elseif Sys.islinux() && Sys.which("secret-tool") !== nothing
        return _LIBSECRET_BACKEND
    elseif options.allow_unencrypted_storage
        return PlaintextTokenCacheBackend()
    end

    throw(TokenCachePersistenceError(
        "Persistent cache encryption is unavailable in this environment. Set allow_unencrypted_storage=true to fall back to plaintext storage.",
    ))
end

function _load_cache_payload(options::TokenCachePersistenceOptions; enable_cae::Bool = false)
    _ensure_cache_storage!(options)
    path = _cache_file_path(options; enable_cae = enable_cae)
    backend = _resolve_cache_backend(options)
    try
        return _load_cache_payload(options, backend, path; enable_cae = enable_cae)
    catch err
        if options.backend isa AutoTokenCacheBackend && options.allow_unencrypted_storage && !(backend isa PlaintextTokenCacheBackend)
            return _read_cache_file(path)
        end
        rethrow(err)
    end
end

function _load_cache_payload(options::TokenCachePersistenceOptions, ::PlaintextTokenCacheBackend, path::String; enable_cae::Bool = false)
    return _read_cache_file(path)
end

function _load_cache_payload(options::TokenCachePersistenceOptions, backend::InMemoryTokenCacheBackend, path::String; enable_cae::Bool = false)
    bytes = get(backend.secrets, _cache_secret_account(options; enable_cae = enable_cae), nothing)
    bytes === nothing && return _read_cache_file(path)
    return String(bytes)
end

function _load_cache_payload(options::TokenCachePersistenceOptions, ::KeychainTokenCacheBackend, path::String; enable_cae::Bool = false)
    payload = _macos_keychain_get(_KEYCHAIN_SERVICE, _cache_secret_account(options; enable_cae = enable_cae))
    payload === nothing && return _read_cache_file(path)
    return String(payload)
end

function _load_cache_payload(options::TokenCachePersistenceOptions, ::LibsecretTokenCacheBackend, path::String; enable_cae::Bool = false)
    payload = _libsecret_get(_KEYCHAIN_SERVICE, _cache_secret_account(options; enable_cae = enable_cae))
    payload === nothing && return _read_cache_file(path)
    return String(payload)
end

function _load_cache_payload(options::TokenCachePersistenceOptions, ::WindowsProtectedTokenCacheBackend, path::String; enable_cae::Bool = false)
    payload = _read_cache_file(path)
    isempty(payload) && return payload
    if startswith(payload, _WINDOWS_CACHE_PREFIX)
        protected_payload = split(payload, '\n'; limit = 2)[2]
        return _windows_unprotect(protected_payload)
    end
    return payload
end

function _save_cache_payload(options::TokenCachePersistenceOptions, payload::AbstractString; enable_cae::Bool = false)
    _ensure_cache_storage!(options)
    path = _cache_file_path(options; enable_cae = enable_cae)
    backend = _resolve_cache_backend(options)
    try
        return _save_cache_payload(options, backend, path, String(payload); enable_cae = enable_cae)
    catch err
        if options.backend isa AutoTokenCacheBackend && options.allow_unencrypted_storage && !(backend isa PlaintextTokenCacheBackend)
            return _write_cache_file(path, payload)
        end
        rethrow(err)
    end
end

function _save_cache_payload(options::TokenCachePersistenceOptions, ::PlaintextTokenCacheBackend, path::String, payload::String; enable_cae::Bool = false)
    return _write_cache_file(path, payload)
end

function _save_cache_payload(options::TokenCachePersistenceOptions, backend::InMemoryTokenCacheBackend, path::String, payload::String; enable_cae::Bool = false)
    backend.secrets[_cache_secret_account(options; enable_cae = enable_cae)] = Vector{UInt8}(codeunits(payload))
    return _touch_cache_marker!(path)
end

function _save_cache_payload(options::TokenCachePersistenceOptions, ::KeychainTokenCacheBackend, path::String, payload::String; enable_cae::Bool = false)
    _macos_keychain_set(
        _KEYCHAIN_SERVICE,
        _cache_secret_account(options; enable_cae = enable_cae),
        Vector{UInt8}(codeunits(payload)),
    )
    return _touch_cache_marker!(path)
end

function _save_cache_payload(options::TokenCachePersistenceOptions, ::LibsecretTokenCacheBackend, path::String, payload::String; enable_cae::Bool = false)
    _libsecret_set(_KEYCHAIN_SERVICE, _cache_secret_account(options; enable_cae = enable_cae), payload)
    return _touch_cache_marker!(path)
end

function _save_cache_payload(options::TokenCachePersistenceOptions, ::WindowsProtectedTokenCacheBackend, path::String, payload::String; enable_cae::Bool = false)
    return _write_cache_file(path, _WINDOWS_CACHE_PREFIX * _windows_protect(payload))
end

function _token_store_entry_to_dict(entry::TokenStoreEntry)
    return Dict(
        "scopes" => entry.scopes,
        "access_token" => entry.access_token,
        "expires_on" => isnothing(entry.expires_on) ? nothing : Dates.format(entry.expires_on, dateformat"yyyy-mm-ddTHH:MM:SS"),
        "refresh_on" => isnothing(entry.refresh_on) ? nothing : Dates.format(entry.refresh_on, dateformat"yyyy-mm-ddTHH:MM:SS"),
        "refresh_token" => entry.refresh_token,
        "client_id" => entry.client_id,
        "tenant_id" => entry.tenant_id,
        "authority" => entry.authority,
        "username" => entry.username,
        "home_account_id" => entry.home_account_id,
        "claims" => entry.claims,
        "enable_cae" => entry.enable_cae,
        "token_type" => entry.token_type,
    )
end

function _token_store_entry_from_dict(data::Dict{String, Any})
    return TokenStoreEntry(
        scopes = [String(scope) for scope in get(data, "scopes", Any[])],
        access_token = get(data, "access_token", nothing),
        expires_on = isnothing(get(data, "expires_on", nothing)) ? nothing : _parse_datetime_string(String(data["expires_on"])),
        refresh_on = isnothing(get(data, "refresh_on", nothing)) ? nothing : _parse_datetime_string(String(data["refresh_on"])),
        refresh_token = get(data, "refresh_token", nothing),
        client_id = get(data, "client_id", nothing),
        tenant_id = get(data, "tenant_id", nothing),
        authority = get(data, "authority", nothing),
        username = get(data, "username", nothing),
        home_account_id = get(data, "home_account_id", nothing),
        claims = get(data, "claims", nothing),
        enable_cae = Bool(get(data, "enable_cae", false)),
        token_type = String(get(data, "token_type", "Bearer")),
    )
end

function _load_token_entries(options::TokenCachePersistenceOptions; enable_cae::Bool = false)
    payload = strip(_load_cache_payload(options; enable_cae = enable_cae))
    isempty(payload) && return TokenStoreEntry[]
    rows = JSON3.read(payload, Vector{Dict{String, Any}})
    return [_token_store_entry_from_dict(row) for row in rows]
end

function _entry_identity_key(entry::TokenStoreEntry)
    return join(sort(entry.scopes), " ") * "|" * something(entry.client_id, "") * "|" * something(entry.tenant_id, "") * "|" *
        something(entry.username, "") * "|" * something(entry.home_account_id, "") * "|" * something(entry.claims, "") * "|" *
        string(entry.enable_cae)
end

function _save_token_entries(options::TokenCachePersistenceOptions, entries::Vector{TokenStoreEntry}; enable_cae::Bool = false)
    return _save_cache_payload(
        options,
        JSON3.write([_token_store_entry_to_dict(entry) for entry in entries]);
        enable_cae = enable_cae,
    )
end

function _upsert_token_entry!(entries::Vector{TokenStoreEntry}, entry::TokenStoreEntry)
    key = _entry_identity_key(entry)
    index = findfirst(existing -> _entry_identity_key(existing) == key, entries)
    if index === nothing
        push!(entries, entry)
    else
        entries[index] = entry
    end
    return entries
end

function _token_info_from_entry(entry::TokenStoreEntry)
    entry.access_token === nothing && throw(CredentialUnavailableError("The shared token cache entry does not contain an access token."))
    entry.expires_on === nothing && throw(CredentialUnavailableError("The shared token cache entry is missing expires_on."))
    return AzureAccessTokenInfo(
        token = entry.access_token,
        expires_on = entry.expires_on,
        token_type = entry.token_type,
        refresh_on = entry.refresh_on,
        resource = isempty(entry.scopes) ? nothing : first(entry.scopes),
        scopes = copy(entry.scopes),
        claims = entry.claims,
        tenant_id = entry.tenant_id,
    )
end

function _store_token_result!(
    options::TokenCachePersistenceOptions,
    result::OAuthTokenResult,
    scopes::Vector{String};
    client_id::String,
    authority::String,
    tenant_id::String,
    record::Union{Nothing, AuthenticationRecord} = nothing,
    claims::Union{Nothing, String} = nothing,
    enable_cae::Bool = false,
)
    entry = TokenStoreEntry(
        scopes = copy(scopes),
        access_token = result.token.token,
        expires_on = result.token.expires_on,
        refresh_on = result.token.refresh_on,
        refresh_token = result.refresh_token,
        client_id = client_id,
        tenant_id = tenant_id,
        authority = normalize_authority(authority),
        username = isnothing(record) ? nothing : record.username,
        home_account_id = isnothing(record) ? nothing : record.home_account_id,
        claims = claims,
        enable_cae = enable_cae,
        token_type = result.token.token_type,
    )
    entries = _load_token_entries(options; enable_cae = enable_cae)
    _upsert_token_entry!(entries, entry)
    _save_token_entries(options, entries; enable_cae = enable_cae)
    return entry
end
