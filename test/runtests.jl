using AzureIdentity
using Test

const Dates = AzureIdentity.Dates
const Random = AzureIdentity.Random
const Sockets = AzureIdentity.Sockets

include("helpers.jl")
include("test_core.jl")
include("test_service_credentials.jl")
include("test_developer_credentials.jl")
include("test_user_credentials.jl")
