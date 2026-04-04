_token_endpoint(authority::String, tenant_id::String) = string(normalize_authority(authority), "/", tenant_id, "/oauth2/v2.0/token")
_device_code_endpoint(authority::String, tenant_id::String) = string(normalize_authority(authority), "/", tenant_id, "/oauth2/v2.0/devicecode")
_authorize_endpoint(authority::String, tenant_id::String) = string(normalize_authority(authority), "/", tenant_id, "/oauth2/v2.0/authorize")

function _decode_json_body(body::AbstractString)
    payload = strip(String(body))
    isempty(payload) && return Dict{String, Any}()
    return JSON3.read(payload, Dict{String, Any})
end

function _oauth_form_request(runtime::CredentialRuntime, url::String, form::Dict{String, <:Any})
    response = runtime.http_request(
        "POST",
        url;
        headers = Dict("Content-Type" => "application/x-www-form-urlencoded"),
        body = _form_encode(form),
    )
    payload = try
        _decode_json_body(response.body)
    catch
        Dict{String, Any}("raw" => response.body)
    end
    return response, payload
end

function _oauth_error_message(payload::Dict{String, Any}, default_message::String)
    error_code = get(payload, "error", nothing)
    error_description = get(payload, "error_description", nothing)
    if error_description !== nothing
        return String(error_description)
    elseif error_code !== nothing
        return String(error_code)
    end
    return default_message
end

function _oauth_token_result(payload::Dict{String, Any}, scopes::Vector{String}, claims::Union{Nothing, String}, tenant_id::Union{Nothing, String}, now_fn::Function)
    token = _token_response_to_access_token_info(payload, scopes, claims, tenant_id, now_fn)
    return OAuthTokenResult(
        token = token,
        refresh_token = get(payload, "refresh_token", nothing),
        id_token = get(payload, "id_token", nothing),
        client_info = get(payload, "client_info", nothing),
        raw = payload,
    )
end

function _request_client_secret_token(runtime::CredentialRuntime, authority::String, tenant_id::String, client_id::String, client_secret::String, scopes::Vector{String}; claims::Union{Nothing, String} = nothing, enable_cae::Bool = false)
    merged_claims = _merge_claims(claims, enable_cae)
    form = Dict(
        "grant_type" => "client_credentials",
        "client_id" => client_id,
        "client_secret" => client_secret,
        "scope" => join(scopes, " "),
    )
    merged_claims !== nothing && (form["claims"] = merged_claims)
    response, payload = _oauth_form_request(runtime, _token_endpoint(authority, tenant_id), form)
    response.status == 200 || throw(ClientAuthenticationError(_oauth_error_message(payload, "Token request failed with status $(response.status).")))
    return _oauth_token_result(payload, scopes, merged_claims, tenant_id, runtime.now_fn)
end

function _request_jwt_assertion_token(runtime::CredentialRuntime, authority::String, tenant_id::String, client_id::String, assertion::String, scopes::Vector{String}; claims::Union{Nothing, String} = nothing, enable_cae::Bool = false)
    merged_claims = _merge_claims(claims, enable_cae)
    form = Dict(
        "grant_type" => "client_credentials",
        "client_id" => client_id,
        "client_assertion_type" => "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion" => assertion,
        "scope" => join(scopes, " "),
    )
    merged_claims !== nothing && (form["claims"] = merged_claims)
    response, payload = _oauth_form_request(runtime, _token_endpoint(authority, tenant_id), form)
    response.status == 200 || throw(ClientAuthenticationError(_oauth_error_message(payload, "Token request failed with status $(response.status).")))
    return _oauth_token_result(payload, scopes, merged_claims, tenant_id, runtime.now_fn)
end

function _request_password_token(runtime::CredentialRuntime, authority::String, tenant_id::String, client_id::String, username::String, password::String, scopes::Vector{String}; claims::Union{Nothing, String} = nothing, enable_cae::Bool = false)
    merged_claims = _merge_claims(claims, enable_cae)
    form = Dict(
        "grant_type" => "password",
        "client_id" => client_id,
        "username" => username,
        "password" => password,
        "scope" => join(scopes, " "),
    )
    merged_claims !== nothing && (form["claims"] = merged_claims)
    response, payload = _oauth_form_request(runtime, _token_endpoint(authority, tenant_id), form)
    response.status == 200 || throw(ClientAuthenticationError(_oauth_error_message(payload, "Token request failed with status $(response.status).")))
    return _oauth_token_result(payload, scopes, merged_claims, tenant_id, runtime.now_fn)
end

function _request_refresh_token(runtime::CredentialRuntime, authority::String, tenant_id::String, client_id::String, refresh_token::String, scopes::Vector{String}; claims::Union{Nothing, String} = nothing, enable_cae::Bool = false)
    merged_claims = _merge_claims(claims, enable_cae)
    form = Dict(
        "grant_type" => "refresh_token",
        "client_id" => client_id,
        "refresh_token" => refresh_token,
        "scope" => join(scopes, " "),
    )
    merged_claims !== nothing && (form["claims"] = merged_claims)
    response, payload = _oauth_form_request(runtime, _token_endpoint(authority, tenant_id), form)
    response.status == 200 || throw(ClientAuthenticationError(_oauth_error_message(payload, "Refresh token request failed with status $(response.status).")))
    return _oauth_token_result(payload, scopes, merged_claims, tenant_id, runtime.now_fn)
end

function _request_authorization_code_token(runtime::CredentialRuntime, authority::String, tenant_id::String, client_id::String, code::String, redirect_uri::String, scopes::Vector{String}; code_verifier::Union{Nothing, String} = nothing, client_secret::Union{Nothing, String} = nothing, claims::Union{Nothing, String} = nothing, enable_cae::Bool = false)
    merged_claims = _merge_claims(claims, enable_cae)
    form = Dict(
        "grant_type" => "authorization_code",
        "client_id" => client_id,
        "code" => code,
        "redirect_uri" => redirect_uri,
        "scope" => join(scopes, " "),
    )
    code_verifier !== nothing && (form["code_verifier"] = code_verifier)
    client_secret !== nothing && (form["client_secret"] = client_secret)
    merged_claims !== nothing && (form["claims"] = merged_claims)
    response, payload = _oauth_form_request(runtime, _token_endpoint(authority, tenant_id), form)
    response.status == 200 || throw(ClientAuthenticationError(_oauth_error_message(payload, "Authorization code exchange failed with status $(response.status).")))
    return _oauth_token_result(payload, scopes, merged_claims, tenant_id, runtime.now_fn)
end

function _request_on_behalf_of_token(runtime::CredentialRuntime, authority::String, tenant_id::String, client_id::String, user_assertion::String, scopes::Vector{String}; client_secret::Union{Nothing, String} = nothing, client_assertion::Union{Nothing, String} = nothing, claims::Union{Nothing, String} = nothing, enable_cae::Bool = false)
    merged_claims = _merge_claims(claims, enable_cae)
    form = Dict(
        "grant_type" => "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "client_id" => client_id,
        "requested_token_use" => "on_behalf_of",
        "assertion" => user_assertion,
        "scope" => join(scopes, " "),
    )
    client_secret !== nothing && (form["client_secret"] = client_secret)
    if client_assertion !== nothing
        form["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        form["client_assertion"] = client_assertion
    end
    merged_claims !== nothing && (form["claims"] = merged_claims)
    response, payload = _oauth_form_request(runtime, _token_endpoint(authority, tenant_id), form)
    response.status == 200 || throw(ClientAuthenticationError(_oauth_error_message(payload, "On-behalf-of request failed with status $(response.status).")))
    return _oauth_token_result(payload, scopes, merged_claims, tenant_id, runtime.now_fn)
end

function _request_device_code(runtime::CredentialRuntime, authority::String, tenant_id::String, client_id::String, scopes::Vector{String}; claims::Union{Nothing, String} = nothing)
    form = Dict(
        "client_id" => client_id,
        "scope" => join(scopes, " "),
    )
    claims !== nothing && (form["claims"] = claims)
    response, payload = _oauth_form_request(runtime, _device_code_endpoint(authority, tenant_id), form)
    response.status == 200 || throw(ClientAuthenticationError(_oauth_error_message(payload, "Device code request failed with status $(response.status).")))
    return payload
end

function _poll_device_code_token(runtime::CredentialRuntime, authority::String, tenant_id::String, client_id::String, device_code::String, scopes::Vector{String}; claims::Union{Nothing, String} = nothing, enable_cae::Bool = false, timeout::Int = 600, interval::Int = 5)
    merged_claims = _merge_claims(claims, enable_cae)
    started = runtime.now_fn()
    wait_seconds = interval
    while Dates.value(runtime.now_fn() - started) / 1000 < timeout
        form = Dict(
            "grant_type" => "urn:ietf:params:oauth:grant-type:device_code",
            "client_id" => client_id,
            "device_code" => device_code,
        )
        merged_claims !== nothing && (form["claims"] = merged_claims)
        response, payload = _oauth_form_request(runtime, _token_endpoint(authority, tenant_id), form)
        if response.status == 200
            return _oauth_token_result(payload, scopes, merged_claims, tenant_id, runtime.now_fn)
        end
        error_code = String(get(payload, "error", ""))
        if error_code == "authorization_pending"
            runtime.sleep_fn(wait_seconds)
            continue
        elseif error_code == "slow_down"
            wait_seconds += 5
            runtime.sleep_fn(wait_seconds)
            continue
        end
        throw(ClientAuthenticationError(_oauth_error_message(payload, "Device code authentication failed with status $(response.status).")))
    end
    throw(CredentialUnavailableError("Timed out waiting for device code authentication."))
end
