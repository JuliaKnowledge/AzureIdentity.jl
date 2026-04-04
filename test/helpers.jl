const HTTP = AzureIdentity.HTTP
const JSON3 = AzureIdentity.JSON3
const OpenSSL = AzureIdentity.OpenSSL

const TEST_PRIVATE_KEY_PEM = """
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCf4A9Ugkb/BHTx
Th1SdbKEZMRNqdxP/cBJ2Viz9NJcMX3/+GT6zJ+HYsRu0t6Z75LWfhsrcax18qYx
idXvBQZRmhETRfjMaNcL+vPSzY2qhaTOFpU3YPgdZBQoaGCvP56SmZ6ZKWikAgbA
LP5Tfqal6kzljG5bB6hnXeM+CfIY7aUxg0rkPER/tFP91kF1RmidACUPEdNInBPi
Z5V+5zl1a0NGlnMCqjOzMXgvMhSHclnbbe3fEtUAXLe6gHlQYG4tk1XQzV27/lxK
eya+vyBa54OQfD3lhn7HA99ual4rYy6Jnts1EBEk0/Yy/aN9U+aWrdxNuMsVwveW
zn7AJB11AgMBAAECggEAMh0q0QOxO3jrK0SgHlv0ZFmtyuZmv9A7uSpfCrHAStPc
uiLjjFYd33NPPantyvT04zVOUPTl6WbxP3AEVlMN4wBXP+JcFb77Qa8dRMPYF06j
FVKw3VYREC1xwCTPwb9AdpWeyEXZnidgdFbmNcfqdvGVvxKg+PnSiOw+MhEuCS/d
9Oo4eksqnK0fQHTovqhONOnlcFHW9Oy5PqEK8H6ACLoz7mfUV4EsxC5wwnPl6P64
+uZHqtNQzpUQL6sa8mSHaxc5br5G2jhOrYInylejIYx6ihwWIWCQvHUvidBAE6Ap
0J1nI1FHEHXchhLlnKSBkNy++CqizD9otYP9ufZytQKBgQDTu65UqzzIz0itw/d0
TvmfcAJl1H4isCcm1NPOKpS04PJukCRbWuq/aKnrfSy9VBDZUe7iQ12p3jyzD/wP
rpJt873VtPwhn/tG0EQocGx3pu33BxJ6kbT2llFFXpYtKr5mk58sJRc/roPgDmtR
7nGTh4plL4gN64GqF2BQwCD9gwKBgQDBTNsQKVNdIpXLqojDdbevB0fqGCEgVGuH
HLog6NwjUFdTY/ChnTx6kT8yqUO7Tn1UTYo6ll/SuBPyHS+UEf27PizTRAjkxZnS
TIHr8ZceE79gdwlua5lg2TSNVqax+3gWjAWkwpRvStwksup58I6hGhnVpAiZsCpi
4gfkLX6/pwKBgQC8geAX6czYTBQ9ALgTiSydUrAP0TvrzkFNRTa92xNCZvPwk8yK
uUs+1wRRcMSgW3QUx+mS8L83OXF5SsXzgE1GLzfYSKYhmbmxtkK4bj9j1+8Ne/Jr
xcYDtJju1eOGmwOhd9TDDNLCE7G9jZjm/Q+Jdac1pzfOjNqIgP9zZVr52QKBgQCI
7H8UYKGbjH8daKw+AGnfwsGPMg5tDz+n0pKJ80jUfvmMqXNvl6iajb59jWbcDEo8
6DwtKg2wfxIp48CrG19nPjCUalH+c3Z1gBpb3qMT/BsJIuj8XZ2k+9b8809bLe0v
03m/7tEkUJvGJzJutBbkSU/ZhLtO2nn7126NlCh/awKBgFjPtU2LFkQ0g5vxObbo
lo0F0Xkni6D4wGFQ48ZC2BknC6FAVAPiHwiZIMtzdki6y+6tVNqXPv49W6oY+9Zx
FjKZ5jxf78hgD/RaNgvoRr9XFy1HQ3sXXdCr62aqSnzFbh4fPMUi/bNfkI9OERu6
tZ6j5m+0cd8xAjOgdNlqxazs
-----END PRIVATE KEY-----
"""

const TEST_CERT_PEM = """
-----BEGIN CERTIFICATE-----
MIIDGTCCAgGgAwIBAgIUDGQA39s8mMo5FZfASo/uJMNGWkIwDQYJKoZIhvcNAQEL
BQAwHDEaMBgGA1UEAwwRQXp1cmVJZGVudGl0eVRlc3QwHhcNMjYwNDAzMjIwMTMw
WhcNMjcwNDAzMjIwMTMwWjAcMRowGAYDVQQDDBFBenVyZUlkZW50aXR5VGVzdDCC
ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJ/gD1SCRv8EdPFOHVJ1soRk
xE2p3E/9wEnZWLP00lwxff/4ZPrMn4dixG7S3pnvktZ+GytxrHXypjGJ1e8FBlGa
ERNF+Mxo1wv689LNjaqFpM4WlTdg+B1kFChoYK8/npKZnpkpaKQCBsAs/lN+pqXq
TOWMblsHqGdd4z4J8hjtpTGDSuQ8RH+0U/3WQXVGaJ0AJQ8R00icE+JnlX7nOXVr
Q0aWcwKqM7MxeC8yFIdyWdtt7d8S1QBct7qAeVBgbi2TVdDNXbv+XEp7Jr6/IFrn
g5B8PeWGfscD325qXitjLome2zUQESTT9jL9o31T5pat3E24yxXC95bOfsAkHXUC
AwEAAaNTMFEwHQYDVR0OBBYEFP2g17aYJoMrSeszMQbxSqFxssXWMB8GA1UdIwQY
MBaAFP2g17aYJoMrSeszMQbxSqFxssXWMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZI
hvcNAQELBQADggEBAJ3SWODa7xibm+uUDiuo4ifD+0uXDlARy0eDFlj/GfUCX0qv
pSYjD+aYO+ItorwVgEryBsRCeoOwK9dMjbunrAnbH0198xdHyKLnytt1GabDYo6f
Yl7q1nv4G6k7qF8XlEwImZuIrNgGFZSfUV/UJPcQyLMc9csHbWxDS5yoQHkJ2vc5
CACrvlkibV9WzICKKjwquae66IAybSK8J1whe9PL0kfoAWWJvftXMdouffR1FR3r
r2oMmWVd1nBss0PuliAnHAqBweIZqVxYZ8FZVSUGW4HQYdx6/mRlh8dwtnFhsV07
C0In/e9qChE/CDE7xBc+5GOkYoqTuUf89twWpI8=
-----END CERTIFICATE-----
"""

function json_response(status::Int, payload::AbstractDict{String, <:Any}; headers::Dict{String, String} = Dict{String, String}())
    return AzureIdentity.HTTPResult(status = status, headers = headers, body = JSON3.write(Dict{String, Any}(payload)))
end

function fake_jwt(payload::AbstractDict{String, <:Any})
    header = Dict("alg" => "none", "typ" => "JWT")
    return string(
        AzureIdentity.base64url_encode(JSON3.write(header)),
        ".",
        AzureIdentity.base64url_encode(JSON3.write(Dict{String, Any}(payload))),
        ".",
    )
end

function form_dict(body::AbstractString)
    uri = HTTP.URIs.URI("http://localhost/?" * String(body))
    return Dict(String(k) => String(v) for (k, v) in HTTP.URIs.queryparams(uri))
end

function withenv(vars::AbstractDict{String, <:Any}, f::Function)
    saved = Dict(key => get(ENV, key, nothing) for key in keys(vars))
    try
        for (key, value) in vars
            if value === nothing
                haskey(ENV, key) && delete!(ENV, key)
            else
                ENV[key] = value
            end
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

withenv(f::Function, vars::AbstractDict{String, <:Any}) = withenv(vars, f)

function loopback_redirect(url::AbstractString; code::String = "browser-code")
    uri = HTTP.URIs.URI(String(url))
    params = Dict(String(k) => String(v) for (k, v) in HTTP.URIs.queryparams(uri))
    redirect_uri = HTTP.URIs.URI(params["redirect_uri"])
    host = String(redirect_uri.host)
    port = redirect_uri.port == 0 ? 80 : redirect_uri.port
    path = isempty(redirect_uri.path) ? "/" : String(redirect_uri.path)
    query = "code=$(HTTP.URIs.escapeuri(code))&state=$(HTTP.URIs.escapeuri(params["state"]))"
    @async begin
        sleep(0.1)
        HTTP.get("http://$(host):$(port)$(path)?$(query)"; status_exception = false)
    end
end

function encrypted_test_certificate_pem(password::AbstractString = "secret")
    key = OpenSSL.EvpPKey(TEST_PRIVATE_KEY_PEM)
    cipher = OpenSSL.EvpCipher(ccall((:EVP_aes_256_cbc, OpenSSL.libcrypto), Ptr{Cvoid}, ()))
    password_bytes = Vector{UInt8}(codeunits(String(password)))
    bio = OpenSSL.BIO(OpenSSL.BIOMethodMemory())
    try
        GC.@preserve password_bytes begin
            ccall(
                (:PEM_write_bio_PrivateKey, OpenSSL.libcrypto),
                Cint,
                (OpenSSL.BIO, OpenSSL.EvpPKey, OpenSSL.EvpCipher, Ptr{Cvoid}, Cint, Cint, Ptr{Cvoid}),
                bio,
                key,
                cipher,
                pointer(password_bytes),
                length(password_bytes),
                0,
                C_NULL,
            ) == 1 || error("Failed to encrypt test private key")
        end
        write(bio, TEST_CERT_PEM)
        return String(copy(OpenSSL.bio_get_mem_data(bio)))
    finally
        OpenSSL.free(bio)
    end
end

function test_pkcs12_bytes(password::AbstractString = "secret")
    key = OpenSSL.EvpPKey(TEST_PRIVATE_KEY_PEM)
    cert = OpenSSL.X509Certificate(TEST_CERT_PEM)
    password_bytes = vcat(Vector{UInt8}(codeunits(String(password))), UInt8(0))
    bio = OpenSSL.BIO(OpenSSL.BIOMethodMemory())
    try
        pkcs12_ptr = GC.@preserve password_bytes begin
            ccall(
                (:PKCS12_create, OpenSSL.libcrypto),
                Ptr{Cvoid},
                (Cstring, Cstring, OpenSSL.EvpPKey, OpenSSL.X509Certificate, Ptr{Cvoid}, Cint, Cint, Cint, Cint, Cint),
                pointer(password_bytes),
                C_NULL,
                key,
                cert,
                C_NULL,
                0,
                0,
                0,
                0,
                0,
            )
        end
        pkcs12_ptr == C_NULL && error("Failed to create PKCS12 test certificate")
        pkcs12 = OpenSSL.P12Object(pkcs12_ptr)
        ccall(
            (:i2d_PKCS12_bio, OpenSSL.libcrypto),
            Cint,
            (OpenSSL.BIO, OpenSSL.P12Object),
            bio,
            pkcs12,
        ) == 1 || error("Failed to serialize PKCS12 test certificate")
        return copy(OpenSSL.bio_get_mem_data(bio))
    finally
        OpenSSL.free(bio)
    end
end
