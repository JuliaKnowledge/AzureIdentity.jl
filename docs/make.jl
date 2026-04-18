using Documenter
using AzureIdentity

makedocs(;
    sitename = "AzureIdentity.jl",
    modules = [AzureIdentity],
    remotes = nothing,
    format = Documenter.HTML(;
        prettyurls = get(ENV, "CI", "false") == "true",
        canonical = "https://juliaknowledge.github.io/AzureIdentity.jl",
        edit_link = "main",
        repolink = "https://github.com/JuliaKnowledge/AzureIdentity.jl",
    ),
    pages = [
        "Home" => "index.md",
        "API Reference" => "api.md",
    ],
    warnonly = [:missing_docs, :cross_references, :docs_block],
    checkdocs = :exports,
)

deploydocs(
    repo = "github.com/JuliaKnowledge/AzureIdentity.jl.git",
    devbranch = "main",
    push_preview = true,
)
