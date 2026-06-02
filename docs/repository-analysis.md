# Repository Analysis

## Project Purpose

`KarlixID.Web` is the identity and access-management application for the Karlix platform. It provides centralized login, ASP.NET Core Identity user management, tenant-aware administration, invitation-based onboarding, role and permission claims, and OpenID Connect/OAuth2 endpoints for downstream Karlix applications such as Portal and QMS.

This repository should be treated as `KarlixID.Web` only. The solution references sibling projects, but those projects are outside this repository's scope unless explicitly requested.

## Architecture Summary

- Framework: ASP.NET Core 8 MVC/Razor Pages application targeting `net8.0`.
- Data layer: Entity Framework Core with SQL Server via `ApplicationDbContext`.
- Identity: ASP.NET Core Identity with `ApplicationUser`, `IdentityRole`, and custom claims generation.
- OIDC provider: OpenIddict server, core, EF Core storage, and local validation.
- UI: MVC views plus scaffolded/customized Identity Razor Pages.
- Tenancy: host-based tenant lookup through `TenantResolverMiddleware`.
- Localization: resources under `Resources`, with Croatian as the default request culture and English also supported.
- Services: SMTP email sending, claims-principal enrichment, and Excel export support.
- Data protection: keys are persisted under common application data with application name `KarlixID`.

The default build command is:

```powershell
dotnet build .\KarlixID.Web.csproj
```

Do not run the application without explicit permission, because startup performs database reads and seeding.

## Authentication Flow

1. ASP.NET Core Identity handles local cookie authentication through the `/Identity/Account/Login` and `/Identity/Account/Logout` Razor Pages.
2. `Program.cs` configures Identity claim mappings so user id, name, role, and email align with OpenID Connect claim names.
3. `AppUserClaimsPrincipalFactory` enriches the Identity cookie principal with tenant claims and permission claims collected from role claims.
4. OpenIddict exposes authorization, token, introspection, and end-session endpoints:
   - `/connect/authorize`
   - `/connect/token`
   - `/connect/introspect`
   - `/connect/logout`
5. `AuthorizationController.Authorize` challenges unauthenticated users to the Identity login page, then issues OpenIddict principals for authenticated users.
6. Issued tokens include subject, name, email, role claims, permission claims, tenant id, and tenant name when available.
7. Startup seeding ensures base roles, role permissions, a global admin user, optional localhost tenant admin, and configured OpenIddict client applications.
8. In development, OpenIddict uses development certificates. In non-development, it requires configured certificate settings.

Authentication, OpenIddict clients, tenant resolution, startup seeding, and authorization policies are sensitive areas and should not be changed unless explicitly requested.

## API Dependencies

This project is mostly a web app and identity provider, but it depends on several platform and external APIs/libraries:

- SQL Server through `Microsoft.EntityFrameworkCore.SqlServer`.
- ASP.NET Core Identity storage through EF Core.
- OpenIddict for OIDC/OAuth server behavior and token validation.
- SMTP through `System.Net.Mail.SmtpClient` using configuration values under `Smtp`.
- ClosedXML for Excel export generation.
- ASP.NET Core localization and MVC/Razor Pages.
- Data Protection file-system key persistence.

Downstream client dependencies are seeded as OpenIddict clients for Karlix Portal and Karlix QMS. Their redirect/logout callback URLs are configured in startup seeding and must be treated carefully.

## Key Controllers

- `AuthorizationController`: Implements OIDC authorize/logout/userinfo endpoints and maps Identity claims into OpenIddict token claims.
- `HomeController`: Serves the main dashboard/home view.
- `InviteController`: Manages invitation listing, creation, resend, deletion, and anonymous invite acceptance/account activation.
- `TenantUsersController`: Manages tenant-scoped user listing, creation, editing, password reset, lock/unlock, and role assignment.
- `TenantsController`: Global-admin tenant CRUD and active/inactive toggling.
- `Controllers/TestMailController.cs`: Contains a `/test-mail` route for SMTP testing, but declares a second `HomeController` class outside the main namespace. This is a risk and should be reviewed before production use.

## Key View Models

- `CreateTenantUserVM`: Email, optional tenant selection, optional temporary password, and TenantAdmin assignment flag.
- `TenantUserEditVM`: Editable display name and, for GlobalAdmin, tenant assignment.
- `TenantUserRow`: User list projection with tenant, email confirmation, lockout, and roles summary.
- `EditRolesVM` and `RoleItem`: Role-editing form state, including locked role rows for non-global editors.
- `ResetPasswordVM`: Admin password reset form state.
- `InviteCreateVM`: Invitation recipient, tenant, optional role, and validity window.
- `InviteAcceptVM`: Anonymous invite activation form with password and password confirmation.

## Key Razor Views

- `Views/Home/Index.cshtml`: Main landing/dashboard screen with role-sensitive links to users, tenants, and invitations.
- `Views/Shared/_Layout.cshtml`: Shared navigation, tenant-aware branding, login/logout UI, and role-sensitive menu items.
- `Areas/Identity/Pages/Account/Login.cshtml`: Identity login page.
- `Areas/Identity/Pages/Account/Logout.cshtml`: Identity logout confirmation page.
- `Areas/Identity/Pages/Account/ForgotPassword.cshtml`: Password reset request UI.
- `Areas/Identity/Pages/Account/ResetPassword.cshtml`: Password reset completion UI.
- `Views/Tenants/Index.cshtml`, `Create.cshtml`, `Edit.cshtml`: Tenant administration UI.
- `Views/TenantUsers/Index.cshtml`, `Create.cshtml`, `Edit.cshtml`, `EditRoles.cshtml`, `ResetPassword.cshtml`: Tenant-user administration UI.
- `Views/Invite/Index.cshtml`, `Create.cshtml`, `Accept.cshtml`, `Invalid.cshtml`, `Expired.cshtml`: Invitation management and acceptance UI.
- `Views/Shared/Error.cshtml`: Error display.

The `Views/Admin` folder appears to contain older or unused admin views; no matching `AdminController` was found during inspection.

## Risks

- Secrets appear to be present in configuration files and startup seeding. Do not commit new secrets, and plan secret rotation/removal from source control.
- The solution references sibling projects outside this repository. Use the project build command by default to avoid unintended cross-project work.
- Running the application can connect to configured databases and perform startup seeding. Do not run it without explicit permission.
- Remote/production database connection strings exist in configuration. Do not connect to production or remote databases from agent sessions.
- `Program.cs` contains sensitive auth setup, OpenIddict client seeding, default users, default passwords, and client secrets.
- `Controllers/TestMailController.cs` declares another `HomeController` class and sends a hard-coded test email. This may cause controller discovery confusion and leaks operational behavior.
- There is no visible test project, so changes to auth, tenant scope, invite acceptance, or role claims have limited automated safety coverage.
- `RolesAndPermissionsSeeder` uses `permission` as a claim type while the active `Program.cs`/`AppPermissionInfo` path uses `perm`; this inconsistency may confuse future changes.
- Tenant resolution blocks most non-static paths when no active tenant matches the host, including some diagnostic or utility routes.
- `TenantsController.Delete` can remove tenants without currently enforcing a user-existence guard.
- User/IDE/build artifacts exist in the working tree. Agents must avoid modifying `bin`, `obj`, `.vs`, `*.user`, and `*.suo` files.
- Access token encryption is disabled for debug convenience, so token contents are readable by holders of the token.

## Recommended Next 10 Development Tasks

1. Remove committed secrets from configuration files and migrate sensitive values to user secrets, environment variables, or a secret store.
2. Rotate any credentials, SMTP passwords, database passwords, default admin passwords, and OpenIddict client secrets that have been committed.
3. Add a focused test project for Identity, authorization policies, tenant scoping, invite acceptance, and OpenIddict claim issuance.
4. Review and either remove or rename `Controllers/TestMailController.cs` so it does not declare a duplicate `HomeController`.
5. Add CI that runs `dotnet build .\KarlixID.Web.csproj` and the future test suite.
6. Clarify and consolidate permission claim types so `perm` and `permission` cannot drift.
7. Move startup seeding into a dedicated, idempotent seeding service with clear environment controls.
8. Add explicit safeguards around tenant deletion, especially when users, invites, or downstream data may exist.
9. Document local development setup with a safe local database profile that never points at production or remote databases.
10. Review OpenIddict production hardening, including certificate handling, client-secret management, redirect URI governance, and token encryption policy.
