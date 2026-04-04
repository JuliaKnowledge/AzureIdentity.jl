@testset "AzureIdentity service credentials" begin
    @testset "ClientSecretCredential caches tokens" begin
        calls = Ref(0)
        runtime = AzureIdentity.CredentialRuntime(
            http_request = (method, url; headers = Dict{String, String}(), body = nothing, query = Dict{String, Any}(), timeout = 10) -> begin
                calls[] += 1
                @test method == "POST"
                form = form_dict(String(body))
                @test form["client_secret"] == "secret"
                @test form["scope"] == "https://example/.default"
                json_response(200, Dict("access_token" => "secret-token", "expires_in" => 3600))
            end,
        )
        credential = ClientSecretCredential(
            tenant_id = "tenant",
            client_id = "client",
            client_secret = "secret",
            runtime = runtime,
        )
        @test get_token_info(credential, "https://example/.default").token == "secret-token"
        @test get_token_info(credential, "https://example/.default").token == "secret-token"
        @test calls[] == 1
    end

    @testset "ClientAssertionCredential posts assertion" begin
        runtime = AzureIdentity.CredentialRuntime(
            http_request = (method, url; headers = Dict{String, String}(), body = nothing, query = Dict{String, Any}(), timeout = 10) -> begin
                form = form_dict(String(body))
                @test form["client_assertion"] == "signed-assertion"
                json_response(200, Dict("access_token" => "assertion-token", "expires_in" => 3600))
            end,
        )
        credential = ClientAssertionCredential(
            tenant_id = "tenant",
            client_id = "client",
            func = () -> "signed-assertion",
            runtime = runtime,
        )
        @test get_token_info(credential, "https://example/.default").token == "assertion-token"
    end

    @testset "CertificateCredential builds client assertion" begin
        seen_assertion = Ref("")
        runtime = AzureIdentity.CredentialRuntime(
            http_request = (method, url; headers = Dict{String, String}(), body = nothing, query = Dict{String, Any}(), timeout = 10) -> begin
                form = form_dict(String(body))
                seen_assertion[] = form["client_assertion"]
                json_response(200, Dict("access_token" => "cert-token", "expires_in" => 3600))
            end,
        )
        pem = Vector{UInt8}(codeunits(TEST_PRIVATE_KEY_PEM * "\n" * TEST_CERT_PEM))
        credential = CertificateCredential(
            "tenant",
            "client";
            certificate_data = pem,
            send_certificate_chain = true,
            runtime = runtime,
        )
        @test get_token_info(credential, "https://example/.default").token == "cert-token"
        parts = split(seen_assertion[], '.')
        @test length(parts) == 3
        header = JSON3.read(String(AzureIdentity.base64url_decode(parts[1])), Dict{String, Any})
        @test haskey(header, "x5t")
        @test haskey(header, "x5c")
    end

    @testset "CertificateCredential supports encrypted PEM and PKCS12" begin
        runtime = AzureIdentity.CredentialRuntime(
            http_request = (method, url; headers = Dict{String, String}(), body = nothing, query = Dict{String, Any}(), timeout = 10) -> begin
                form = form_dict(String(body))
                @test haskey(form, "client_assertion")
                json_response(200, Dict("access_token" => "cert-token", "expires_in" => 3600))
            end,
        )

        encrypted_pem = Vector{UInt8}(codeunits(encrypted_test_certificate_pem()))
        pem_credential = CertificateCredential(
            "tenant",
            "client";
            certificate_data = encrypted_pem,
            password = "secret",
            runtime = runtime,
        )
        @test get_token_info(pem_credential, "https://example/.default").token == "cert-token"

        pkcs12_credential = CertificateCredential(
            "tenant",
            "client";
            certificate_data = test_pkcs12_bytes(),
            password = "secret",
            runtime = runtime,
        )
        @test get_token_info(pkcs12_credential, "https://example/.default").token == "cert-token"
    end

    @testset "WorkloadIdentityCredential reads federated token file" begin
        mktemp() do path, io
            write(io, "federated-token")
            close(io)
            runtime = AzureIdentity.CredentialRuntime(
                http_request = (method, url; headers = Dict{String, String}(), body = nothing, query = Dict{String, Any}(), timeout = 10) -> begin
                    form = form_dict(String(body))
                    @test form["client_assertion"] == "federated-token"
                    json_response(200, Dict("access_token" => "workload-token", "expires_in" => 3600))
                end,
            )
            credential = WorkloadIdentityCredential(
                tenant_id = "tenant",
                client_id = "client",
                token_file_path = path,
                runtime = runtime,
            )
            @test get_token_info(credential, "https://example/.default").token == "workload-token"
        end
    end

    @testset "AzurePipelinesCredential exchanges OIDC token" begin
        withenv(Dict("SYSTEM_OIDCREQUESTURI" => "https://dev.azure.com/org/_apis/distributedtask/hubs/build/plans/1/jobs/2/oidctoken")) do
            calls = Ref(String[])
            runtime = AzureIdentity.CredentialRuntime(
                http_request = (method, url; headers = Dict{String, String}(), body = nothing, query = Dict{String, Any}(), timeout = 10) -> begin
                    if occursin("dev.azure.com", url)
                        push!(calls[], "oidc")
                        @test headers["Authorization"] == "Bearer system-token"
                        @test headers["X-TFS-FedAuthRedirect"] == "Suppress"
                        @test query["serviceConnectionId"] == "service-connection"
                        return json_response(200, Dict("oidcToken" => "pipeline-oidc"))
                    end
                    push!(calls[], "token")
                    form = form_dict(String(body))
                    @test form["client_assertion"] == "pipeline-oidc"
                    return json_response(200, Dict("access_token" => "pipeline-token", "expires_in" => 3600))
                end,
            )
            credential = AzurePipelinesCredential(
                tenant_id = "tenant",
                client_id = "client",
                service_connection_id = "service-connection",
                system_access_token = "system-token",
                runtime = runtime,
            )
            @test get_token_info(credential, "https://example/.default").token == "pipeline-token"
            @test calls[] == ["oidc", "token"]
        end

        withenv(Dict("SYSTEM_OIDCREQUESTURI" => nothing)) do
            credential = AzurePipelinesCredential(
                tenant_id = "tenant",
                client_id = "client",
                service_connection_id = "service-connection",
                system_access_token = "system-token",
                runtime = AzureIdentity.CredentialRuntime(
                    http_request = (method, url; headers = Dict{String, String}(), body = nothing, query = Dict{String, Any}(), timeout = 10) -> json_response(200, Dict("access_token" => "unused", "expires_in" => 3600)),
                ),
            )
            @test_throws CredentialUnavailableError get_token_info(credential, "https://example/.default")
        end
    end

    @testset "OnBehalfOfCredential exchanges user assertion" begin
        runtime = AzureIdentity.CredentialRuntime(
            http_request = (method, url; headers = Dict{String, String}(), body = nothing, query = Dict{String, Any}(), timeout = 10) -> begin
                form = form_dict(String(body))
                @test form["requested_token_use"] == "on_behalf_of"
                @test form["assertion"] == "user-jwt"
                @test form["client_secret"] == "secret"
                json_response(200, Dict("access_token" => "obo-token", "expires_in" => 3600))
            end,
        )
        credential = OnBehalfOfCredential(
            "tenant",
            "client";
            client_secret = "secret",
            user_assertion = "user-jwt",
            runtime = runtime,
        )
        @test get_token_info(credential, "https://example/.default").token == "obo-token"
    end

    @testset "EnvironmentCredential selects client secret flow" begin
        withenv(Dict(
            "AZURE_TENANT_ID" => "tenant",
            "AZURE_CLIENT_ID" => "client",
            "AZURE_CLIENT_SECRET" => "secret",
            "AZURE_CLIENT_CERTIFICATE_PATH" => nothing,
            "AZURE_USERNAME" => nothing,
            "AZURE_PASSWORD" => nothing,
        )) do
            runtime = AzureIdentity.CredentialRuntime(
                http_request = (method, url; headers = Dict{String, String}(), body = nothing, query = Dict{String, Any}(), timeout = 10) -> json_response(200, Dict("access_token" => "env-token", "expires_in" => 3600)),
            )
            credential = EnvironmentCredential(runtime = runtime)
            @test get_token_info(credential, "https://example/.default").token == "env-token"
        end
    end

    @testset "Credentials validate custom authorities unless disabled" begin
        calls = Ref(String[])
        validating_runtime = AzureIdentity.CredentialRuntime(
            http_request = (method, url; headers = Dict{String, String}(), body = nothing, query = Dict{String, Any}(), timeout = 10) -> begin
                if occursin("login.microsoft.com/common/discovery/instance", url)
                    push!(calls[], "discovery")
                    @test query["authorization_endpoint"] == "https://custom.example/common/oauth2/v2.0/authorize"
                    return json_response(200, Dict("tenant_discovery_endpoint" => "https://custom.example/common/discovery/keys"))
                end
                push!(calls[], "token")
                return json_response(200, Dict("access_token" => "validated-token", "expires_in" => 3600))
            end,
        )
        credential = ClientSecretCredential(
            tenant_id = "tenant",
            client_id = "client",
            client_secret = "secret",
            authority = "https://custom.example",
            runtime = validating_runtime,
        )
        @test get_token_info(credential, "https://example/.default").token == "validated-token"
        @test calls[] == ["discovery", "token"]

        skipped_calls = Ref(String[])
        skipping_runtime = AzureIdentity.CredentialRuntime(
            http_request = (method, url; headers = Dict{String, String}(), body = nothing, query = Dict{String, Any}(), timeout = 10) -> begin
                push!(skipped_calls[], url)
                occursin("login.microsoft.com/common/discovery/instance", url) && error("instance discovery should be skipped")
                return json_response(200, Dict("access_token" => "direct-token", "expires_in" => 3600))
            end,
        )
        direct_credential = ClientSecretCredential(
            tenant_id = "tenant",
            client_id = "client",
            client_secret = "secret",
            authority = "https://custom.example",
            runtime = skipping_runtime,
            disable_instance_discovery = true,
        )
        @test get_token_info(direct_credential, "https://example/.default").token == "direct-token"
        @test length(skipped_calls[]) == 1
    end

    @testset "ManagedIdentityCredential supports App Service, Cloud Shell, and IMDS" begin
        withenv(Dict(
            "IDENTITY_ENDPOINT" => "http://identity",
            "IDENTITY_HEADER" => "secret-header",
            "IDENTITY_SERVER_THUMBPRINT" => nothing,
            "IMDS_ENDPOINT" => nothing,
            "MSI_ENDPOINT" => nothing,
            "MSI_SECRET" => nothing,
            "AZURE_FEDERATED_TOKEN_FILE" => nothing,
        )) do
            runtime = AzureIdentity.CredentialRuntime(
                http_request = (method, url; headers = Dict{String, String}(), body = nothing, query = Dict{String, Any}(), timeout = 10) -> begin
                    @test headers["X-IDENTITY-HEADER"] == "secret-header"
                    @test query["api-version"] == "2019-08-01"
                    json_response(200, Dict("access_token" => "appservice-token", "expires_on" => string(AzureIdentity.datetime_to_epoch(Dates.now(Dates.UTC) + Dates.Hour(1)))))
                end,
            )
            credential = ManagedIdentityCredential(runtime = runtime)
            @test get_token_info(credential, "https://resource/.default").token == "appservice-token"
        end

        withenv(Dict(
            "IDENTITY_ENDPOINT" => nothing,
            "IDENTITY_HEADER" => nothing,
            "MSI_ENDPOINT" => "http://msi",
            "MSI_SECRET" => nothing,
            "AZURE_FEDERATED_TOKEN_FILE" => nothing,
        )) do
            runtime = AzureIdentity.CredentialRuntime(
                http_request = (method, url; headers = Dict{String, String}(), body = nothing, query = Dict{String, Any}(), timeout = 10) -> begin
                    @test method == "POST"
                    form = form_dict(String(body))
                    @test form["resource"] == "https://resource"
                    json_response(200, Dict("access_token" => "cloud-shell-token", "expires_on" => string(AzureIdentity.datetime_to_epoch(Dates.now(Dates.UTC) + Dates.Hour(1)))))
                end,
            )
            credential = ManagedIdentityCredential(runtime = runtime)
            @test get_token_info(credential, "https://resource/.default").token == "cloud-shell-token"
        end

        withenv(Dict(
            "IDENTITY_ENDPOINT" => nothing,
            "IDENTITY_HEADER" => nothing,
            "MSI_ENDPOINT" => nothing,
            "MSI_SECRET" => nothing,
            "AZURE_FEDERATED_TOKEN_FILE" => nothing,
        )) do
            runtime = AzureIdentity.CredentialRuntime(
                http_request = (method, url; headers = Dict{String, String}(), body = nothing, query = Dict{String, Any}(), timeout = 10) -> begin
                    @test occursin("169.254.169.254", url)
                    @test headers["Metadata"] == "true"
                    json_response(200, Dict("access_token" => "imds-token", "expires_on" => string(AzureIdentity.datetime_to_epoch(Dates.now(Dates.UTC) + Dates.Hour(1)))))
                end,
            )
            credential = ManagedIdentityCredential(runtime = runtime, client_id = "managed-client")
            @test get_token_info(credential, "https://resource/.default").token == "imds-token"
        end
    end
end
