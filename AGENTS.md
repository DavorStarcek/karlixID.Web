# Agent Instructions

This repository is `KarlixID.Web` only.

## Scope

- Do not edit sibling projects unless explicitly requested.
- Default build command: `dotnet build .\KarlixID.Web.csproj`
- Do not run the application without explicit permission.
- Do not connect to production or remote databases.

## Sensitive Areas

Treat the following as sensitive:

- `appsettings*.json`
- `Program.cs` seeding
- OpenIddict clients
- Certificates
- SMTP configuration
- Passwords
- Connection strings

Do not commit secrets.

## Protected Files And Flows

- Do not change authentication, OpenIddict, tenant resolution, seeding, or authorization flow unless explicitly requested.
- Do not modify `bin`, `obj`, `.vs`, `*.user`, or `*.suo` files.

## Workflow

- Before coding, inspect existing code and propose a short plan.
- After coding, summarize changed files, build result, risks, and next steps.
