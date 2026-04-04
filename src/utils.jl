function get_token end

function get_token_info end

function authenticate end

datetime_to_epoch(dt::DateTime) = round(Int, Dates.datetime2unix(dt))
epoch_to_datetime(value::Integer) = Dates.unix2datetime(Int(value))

function is_expired(
    token::Union{AzureAccessToken, AzureAccessTokenInfo};
    offset::Dates.Period = DEFAULT_TOKEN_REFRESH_OFFSET,
    now_fn::Function = () -> Dates.now(Dates.UTC),
)
    now_fn() >= token.expires_on - offset
end

base64url_encode(bytes::AbstractVector{UInt8}) = replace(replace(base64encode(bytes), "+" => "-", "/" => "_"), "=" => "")
base64url_encode(text::AbstractString) = base64url_encode(Vector{UInt8}(codeunits(text)))
encode_base64(text::AbstractString) = base64encode(text)

function base64url_decode(text::AbstractString)
    padding = mod(length(text), 4)
    padded = padding == 0 ? text : text * repeat("=", 4 - padding)
    return base64decode(replace(replace(padded, "-" => "+"), "_" => "/"))
end

function normalize_authority(authority::AbstractString)
    stripped = String(rstrip(String(authority), [' ', '/']))
    isempty(stripped) && throw(ArgumentError("authority must not be empty"))
    if occursin("://", stripped)
        startswith(stripped, "https://") || throw(ArgumentError("authority must use https"))
        return stripped
    end
    return "https://$stripped"
end

get_default_authority() = normalize_authority(get(ENV, ENV_AZURE_AUTHORITY_HOST, AzureAuthorityHosts.AZURE_PUBLIC_CLOUD))

function validate_scope(scope::AbstractString)
    isempty(scope) && throw(ArgumentError("scope must not be empty"))
    occursin(r"^[A-Za-z0-9_\-.:/]+$", scope) || throw(ArgumentError("Invalid scope '$scope'"))
    return nothing
end

function validate_tenant_id(tenant_id::AbstractString)
    isempty(tenant_id) && throw(ArgumentError("tenant_id must not be empty"))
    occursin(r"^[A-Za-z0-9\-.]+$", tenant_id) || throw(ArgumentError("Invalid tenant ID '$tenant_id'"))
    return nothing
end

function validate_subscription(subscription::AbstractString)
    isempty(subscription) && throw(ArgumentError("subscription must not be empty"))
    occursin(r"^[A-Za-z0-9 _\-.]+$", subscription) || throw(ArgumentError("Invalid subscription '$subscription'"))
    return nothing
end

function normalize_scopes(scopes::Vararg{String})
    isempty(scopes) && throw(ArgumentError("At least one scope is required"))
    normalized = String[]
    for scope in scopes
        validate_scope(scope)
        push!(normalized, scope)
    end
    return normalized
end

function _scope_to_resource(scope::String)
    return endswith(scope, "/.default") ? scope[1:(end - 9)] : scope
end

function _scopes_to_resource(scopes::Vararg{String})
    length(scopes) == 1 || throw(ArgumentError("This credential accepts exactly one scope per request"))
    return _scope_to_resource(first(scopes))
end

_scopes_to_scope_string(scopes::Vararg{String}) = join(normalize_scopes(scopes...), " ")

function _coerce_options(; options::Union{Nothing, TokenRequestOptions} = nothing, claims = nothing, tenant_id = nothing, enable_cae::Bool = false)
    if options !== nothing
        claims = isnothing(claims) ? options.claims : claims
        tenant_id = isnothing(tenant_id) ? options.tenant_id : tenant_id
        enable_cae = enable_cae || options.enable_cae
    end
    return (claims = claims, tenant_id = tenant_id, enable_cae = enable_cae)
end

function resolve_tenant(
    default_tenant::Union{Nothing, String};
    tenant_id::Union{Nothing, String} = nothing,
    additionally_allowed_tenants::Vector{String} = String[],
)
    if isnothing(tenant_id) || tenant_id == default_tenant
        return something(default_tenant, tenant_id, "")
    end

    if get(ENV, ENV_AZURE_IDENTITY_DISABLE_MULTITENANTAUTH, "") != ""
        return something(default_tenant, tenant_id, "")
    end

    if isnothing(default_tenant) || isempty(default_tenant)
        return tenant_id
    end

    if "*" in additionally_allowed_tenants || tenant_id in additionally_allowed_tenants
        return tenant_id
    end

    if isempty(additionally_allowed_tenants) && default_tenant == "organizations"
        return tenant_id
    end

    throw(ClientAuthenticationError("The credential is not configured to acquire tokens for tenant $tenant_id."))
end

function _merge_claims(claims::Union{Nothing, String}, enable_cae::Bool)
    if !enable_cae
        return claims
    end

    claims_dict = claims === nothing ? Dict{String, Any}() : JSON3.read(claims, Dict{String, Any})
    access_token = get!(claims_dict, "access_token", Dict{String, Any}())
    access_token isa Dict{String, Any} || (access_token = Dict{String, Any}())
    access_token["xms_cc"] = Dict("values" => Any["CP1"])
    claims_dict["access_token"] = access_token
    return JSON3.write(claims_dict)
end

function serialize_authentication_record(record::AuthenticationRecord)
    return JSON3.write(Dict(
        "authority" => record.authority,
        "client_id" => record.client_id,
        "tenant_id" => record.tenant_id,
        "username" => record.username,
        "home_account_id" => record.home_account_id,
        "version" => record.version,
    ))
end

function deserialize_authentication_record(data::AbstractString)
    record = JSON3.read(String(data), Dict{String, Any})
    return AuthenticationRecord(
        authority = String(get(record, "authority", "")),
        client_id = String(get(record, "client_id", "")),
        tenant_id = String(get(record, "tenant_id", "")),
        username = get(record, "username", nothing),
        home_account_id = get(record, "home_account_id", nothing),
        version = String(get(record, "version", "1.0")),
    )
end

function save_authentication_record(path::AbstractString, record::AuthenticationRecord)
    mkpath(dirname(path))
    open(path, "w") do io
        write(io, serialize_authentication_record(record))
    end
    return path
end

load_authentication_record(path::AbstractString) = deserialize_authentication_record(read(path, String))

function _cache_key(scopes::Vararg{String}; tenant_id::Union{Nothing, String} = nothing, claims::Union{Nothing, String} = nothing, enable_cae::Bool = false)
    normalized_claims = claims === nothing ? "" : claims
    return join(normalize_scopes(scopes...), " ") * "|" * something(tenant_id, "") * "|" * normalized_claims * "|" * string(enable_cae)
end

function _truthy_env(name::AbstractString)
    value = lowercase(strip(get(ENV, String(name), "")))
    return value in ("1", "true", "yes", "on")
end

function _form_encode(data::Dict{String, <:Any})
    filtered = Dict{String, String}()
    for (key, value) in data
        isnothing(value) && continue
        filtered[key] = string(value)
    end
    return HTTP.URIs.escapeuri(filtered)
end

function _append_query(url::AbstractString, query::Dict{String, <:Any})
    isempty(query) && return String(url)
    return string(url, occursin("?", url) ? "&" : "?", _form_encode(query))
end

function _default_http_request(
    method::AbstractString,
    url::AbstractString;
    headers::Dict{String, String} = Dict{String, String}(),
    body::Union{Nothing, AbstractString, Vector{UInt8}} = nothing,
    query::Dict{String, <:Any} = Dict{String, String}(),
    timeout::Real = 10,
)
    response = HTTP.request(
        String(method),
        _append_query(url, query),
        collect(headers),
        something(body, "");
        connect_timeout = timeout,
        readtimeout = timeout,
        status_exception = false,
    )
    return HTTPResult(
        status = response.status,
        headers = Dict(String(key) => String(value) for (key, value) in response.headers),
        body = String(response.body),
    )
end

function _default_run_process(command::Cmd; timeout::Real = 10)
    stdout = Pipe()
    stderr = Pipe()
    process = nothing
    try
        process = run(pipeline(ignorestatus(command), stdout = stdout, stderr = stderr), wait = false)
    catch err
        throw(CredentialUnavailableError("Failed to start process $(command.exec[1]): $(sprint(showerror, err))"))
    end

    close(stdout.in)
    close(stderr.in)

    deadline = time() + timeout
    while process_running(process) && time() < deadline
        sleep(0.05)
    end

    if process_running(process)
        Base.kill(process)
        wait(process)
        throw(CredentialUnavailableError("Process timed out after $(timeout) seconds"))
    end

    wait(process)
    return ProcessResult(
        exitcode = process.exitcode,
        stdout = read(stdout, String),
        stderr = read(stderr, String),
    )
end

function _default_open_browser(url::AbstractString)
    command = if Sys.isapple()
        `open $url`
    elseif Sys.iswindows()
        `cmd /c start "" $url`
    else
        `xdg-open $url`
    end

    try
        run(command)
    catch err
        throw(CredentialUnavailableError("Failed to open browser: $(sprint(showerror, err))"))
    end

    return nothing
end

Base.@kwdef struct CredentialRuntime
    http_request::Function = _default_http_request
    run_process::Function = _default_run_process
    open_browser::Function = _default_open_browser
    sleep_fn::Function = sleep
    now_fn::Function = () -> Dates.now(Dates.UTC)
    random_bytes::Function = n -> rand(UInt8, n)
end

default_runtime() = CredentialRuntime()

const _KNOWN_AUTHORITY_HOSTS = Set(lowercase(String(host)) for host in values(KnownAuthorities))
const _VALIDATED_AUTHORITIES = Set{String}()
const _VALIDATED_AUTHORITIES_LOCK = ReentrantLock()

function _authority_host(authority::AbstractString)
    uri = HTTP.URIs.URI(normalize_authority(authority))
    uri.host === nothing && throw(ArgumentError("authority must include a host"))
    return lowercase(String(uri.host))
end

function _validated_authority(authority::AbstractString, runtime::CredentialRuntime; disable_instance_discovery::Bool = false)
    normalized = normalize_authority(authority)
    disable_instance_discovery && return normalized

    if _authority_host(normalized) in _KNOWN_AUTHORITY_HOSTS
        lock(_VALIDATED_AUTHORITIES_LOCK) do
            push!(_VALIDATED_AUTHORITIES, normalized)
        end
        return normalized
    end

    needs_validation = lock(_VALIDATED_AUTHORITIES_LOCK) do
        !(normalized in _VALIDATED_AUTHORITIES)
    end
    !needs_validation && return normalized

    response = runtime.http_request(
        "GET",
        INSTANCE_DISCOVERY_ENDPOINT;
        query = Dict(
            "api-version" => INSTANCE_DISCOVERY_API_VERSION,
            "authorization_endpoint" => _authorize_endpoint(normalized, "common"),
        ),
    )
    payload = try
        _decode_json_body(response.body)
    catch
        Dict{String, Any}()
    end
    response.status == 200 || throw(ClientAuthenticationError(
        "Authority validation failed for $normalized. " *
        _oauth_error_message(
            payload,
            "Set disable_instance_discovery=true to skip validation for a trusted private cloud authority.",
        ),
    ))

    lock(_VALIDATED_AUTHORITIES_LOCK) do
        push!(_VALIDATED_AUTHORITIES, normalized)
    end
    return normalized
end

function _parse_datetime_string(value::AbstractString)
    text = String(value)
    formats = (
        dateformat"yyyy-mm-dd HH:MM:SS.s",
        dateformat"yyyy-mm-dd HH:MM:SS",
        dateformat"yyyy-mm-ddTHH:MM:SS.s",
        dateformat"yyyy-mm-ddTHH:MM:SS",
        dateformat"yyyy-mm-ddTHH:MM:SS.sZ",
        dateformat"yyyy-mm-ddTHH:MM:SSZ",
        dateformat"mm/dd/yyyy HH:MM:SS",
        dateformat"mm/dd/yyyy HH:MM:SS p",
    )
    for format in formats
        try
            return DateTime(text, format)
        catch
        end
    end
    endswith(text, " +00:00") && return _parse_datetime_string(text[1:(end - 6)])
    throw(ArgumentError("Could not parse datetime '$text'"))
end

function _parse_expires_on(value, now_fn::Function = () -> Dates.now(Dates.UTC))
    if value isa Integer
        return epoch_to_datetime(value)
    elseif value isa AbstractFloat
        return epoch_to_datetime(round(Int, value))
    elseif value isa AbstractString
        stripped = strip(value)
        parsed_int = tryparse(Int, stripped)
        parsed_int !== nothing && return epoch_to_datetime(parsed_int)
        return _parse_datetime_string(stripped)
    end
    throw(ArgumentError("Unsupported expires_on value $(repr(value))"))
end

function _token_response_to_access_token_info(response::Dict{String, Any}, scopes::Vector{String}, claims::Union{Nothing, String}, tenant_id::Union{Nothing, String}, now_fn::Function)
    access_token = String(response["access_token"])
    expires_on = if haskey(response, "expires_on")
        _parse_expires_on(response["expires_on"], now_fn)
    elseif haskey(response, "expires_in")
        now_fn() + Dates.Second(parse(Int, string(response["expires_in"])))
    else
        now_fn() + Dates.Hour(1)
    end
    refresh_on = if haskey(response, "refresh_in")
        now_fn() + Dates.Second(parse(Int, string(response["refresh_in"])))
    elseif haskey(response, "refresh_on")
        _parse_expires_on(response["refresh_on"], now_fn)
    else
        nothing
    end
    return AzureAccessTokenInfo(
        token = access_token,
        expires_on = expires_on,
        token_type = String(get(response, "token_type", "Bearer")),
        refresh_on = refresh_on,
        resource = isempty(scopes) ? nothing : first(scopes),
        scopes = scopes,
        claims = claims,
        tenant_id = tenant_id,
        extras = response,
    )
end

function _decode_jwt_payload(token::AbstractString)
    parts = split(String(token), '.')
    length(parts) >= 2 || return Dict{String, Any}()
    try
        return JSON3.read(String(base64url_decode(parts[2])), Dict{String, Any})
    catch
        return Dict{String, Any}()
    end
end

function _decode_client_info(client_info::Union{Nothing, String})
    client_info === nothing && return Dict{String, Any}()
    try
        return JSON3.read(String(base64url_decode(client_info)), Dict{String, Any})
    catch
        return Dict{String, Any}()
    end
end

function _build_authentication_record(result::OAuthTokenResult, client_id::String, authority::String, tenant_id::String)
    claims = result.id_token === nothing ? Dict{String, Any}() : _decode_jwt_payload(result.id_token)
    client_info = _decode_client_info(result.client_info)
    username = get(claims, "preferred_username", get(claims, "upn", nothing))
    home_account_id = if haskey(client_info, "uid") && haskey(client_info, "utid")
        string(client_info["uid"], ".", client_info["utid"])
    else
        get(claims, "oid", nothing)
    end
    resolved_tenant = String(get(claims, "tid", tenant_id))
    return AuthenticationRecord(
        authority = normalize_authority(authority),
        client_id = client_id,
        tenant_id = resolved_tenant,
        username = username,
        home_account_id = home_account_id,
    )
end

function get_token(credential::AbstractAzureCredential, scopes::Vararg{String}; kwargs...)
    return AzureAccessToken(get_token_info(credential, scopes...; kwargs...))
end

get_token_async(credential::AbstractAzureCredential, scopes::Vararg{String}; kwargs...) = Threads.@spawn get_token(credential, scopes...; kwargs...)
get_token_info_async(credential::AbstractAzureCredential, scopes::Vararg{String}; kwargs...) = Threads.@spawn get_token_info(credential, scopes...; kwargs...)
authenticate_async(credential::AbstractAzureCredential, scopes::Vararg{String}; kwargs...) = Threads.@spawn authenticate(credential, scopes...; kwargs...)

function get_bearer_token_provider(credential::AbstractAzureCredential, scopes::Vararg{String}; kwargs...)
    return () -> get_token(credential, scopes...; kwargs...).token
end

get_openai_token(credential::AbstractAzureCredential) = get_token(credential, AZURE_OPENAI_SCOPE).token
