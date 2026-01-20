using KarlixID.Web.Data;
using KarlixID.Web.Models;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using System.Security.Claims;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace KarlixID.Web.Controllers
{
    public class AuthorizationController : Controller
    {
        private readonly ApplicationDbContext _db;

        public AuthorizationController(ApplicationDbContext db)
        {
            _db = db;
        }

        // GET/POST /connect/authorize
        [HttpGet("~/connect/authorize"), HttpPost("~/connect/authorize")]
        [IgnoreAntiforgeryToken] // OIDC middleware rješava CSRF
        public async Task<IActionResult> Authorize()
        {
            var request = HttpContext.GetOpenIddictServerRequest()
                          ?? throw new InvalidOperationException("OIDC request unavailable.");

            // Ako nije prijavljen → redirect na login i vrati se natrag na ovaj authorize zahtjev
            if (!(User?.Identity?.IsAuthenticated ?? false))
            {
                IEnumerable<KeyValuePair<string, string?>> pairs =
                    Request.HasFormContentType
                        ? Request.Form.Select(kv => new KeyValuePair<string, string?>(kv.Key, kv.Value.ToString()))
                        : Request.Query.Select(kv => new KeyValuePair<string, string?>(kv.Key, kv.Value.ToString()));

                var redirectUri = (Request.PathBase + Request.Path + QueryString.Create(pairs)).ToString();

                return Challenge(
                    authenticationSchemes: new[] { IdentityConstants.ApplicationScheme },
                    properties: new AuthenticationProperties { RedirectUri = redirectUri }
                );
            }

            // Složi OpenIddict identity (schema mora biti OpenIddict server)
            var identity = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

            // sub/name/email
            // Kod tebe je NameIdentifier mapiran na "sub" (OpenIddict Claims.Subject) kroz IdentityOptions,
            // pa ovdje uzimamo najstabilnije što postoji.
            var sub =
                User.FindFirstValue(Claims.Subject) ??
                User.FindFirstValue(ClaimTypes.NameIdentifier) ??
                User.Identity!.Name ??
                throw new InvalidOperationException("User subject is missing.");

            var name =
                User.FindFirstValue(Claims.Name) ??
                User.Identity!.Name ??
                sub;

            var email =
                User.FindFirstValue(Claims.Email) ??
                User.FindFirstValue(ClaimTypes.Email);

            identity.AddClaim(new Claim(Claims.Subject, sub)
                .SetDestinations(Destinations.AccessToken, Destinations.IdentityToken));

            identity.AddClaim(new Claim(Claims.Name, name)
                .SetDestinations(Destinations.AccessToken, Destinations.IdentityToken));

            if (!string.IsNullOrWhiteSpace(email))
            {
                identity.AddClaim(new Claim(Claims.Email, email)
                    .SetDestinations(Destinations.AccessToken, Destinations.IdentityToken));
            }

            // ------------------------------------------------------------
            // ROLES: pokupi i ClaimTypes.Role i "role"
            // ------------------------------------------------------------
            var roleValues = User.Claims
                .Where(c =>
                    string.Equals(c.Type, ClaimTypes.Role, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(c.Type, Claims.Role, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(c.Type, "role", StringComparison.OrdinalIgnoreCase))
                .Select(c => c.Value)
                .Where(v => !string.IsNullOrWhiteSpace(v))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            foreach (var r in roleValues)
            {
                identity.AddClaim(new Claim(Claims.Role, r)
                    .SetDestinations(Destinations.AccessToken, Destinations.IdentityToken));
            }

            // ------------------------------------------------------------
            // PERMISSIONS: podrži "perm" i "permission"
            // U tokenu emitiramo "perm" (da bude konzistentno s tvojim QMS API očekivanjem)
            // ------------------------------------------------------------
            const string TokenPermClaimType = "perm";

            var permValues = User.Claims
                .Where(c =>
                    string.Equals(c.Type, TokenPermClaimType, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(c.Type, "permission", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(c.Type, AppPermissionInfo.PermissionClaimType, StringComparison.OrdinalIgnoreCase))
                .Select(c => c.Value)
                .Where(v => !string.IsNullOrWhiteSpace(v))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            foreach (var p in permValues)
            {
                identity.AddClaim(new Claim(TokenPermClaimType, p)
                    .SetDestinations(Destinations.AccessToken, Destinations.IdentityToken));
            }

            // ------------------------------------------------------------
            // TENANT CLAIM – GUID
            // ------------------------------------------------------------
            var tenantClaim =
                User.Claims.FirstOrDefault(c => c.Type == "tenant") ??
                User.Claims.FirstOrDefault(c => c.Type == "tenant_id") ??
                User.Claims.FirstOrDefault(c => c.Type == "tenant:name");

            if (tenantClaim is not null && !string.IsNullOrWhiteSpace(tenantClaim.Value))
            {
                identity.AddClaim(new Claim("tenant", tenantClaim.Value)
                    .SetDestinations(Destinations.AccessToken, Destinations.IdentityToken));

                // Tenant name (ako postoji u bazi)
                if (Guid.TryParse(tenantClaim.Value, out var tenantId) && tenantId != Guid.Empty)
                {
                    var tenantEntity = await _db.Tenants
                        .AsNoTracking()
                        .FirstOrDefaultAsync(t => t.Id == tenantId);

                    if (tenantEntity is not null && !string.IsNullOrWhiteSpace(tenantEntity.Name))
                    {
                        identity.AddClaim(new Claim("tenant_name", tenantEntity.Name)
                            .SetDestinations(Destinations.AccessToken, Destinations.IdentityToken));
                    }
                }
            }

            // Scope-ovi iz zahtjeva ili default
            var requested = request.GetScopes();
            var scopes = !requested.IsDefaultOrEmpty
                ? requested.ToArray()
                : new[] { Scopes.OpenId, Scopes.Profile, Scopes.Email, Scopes.Roles };

            identity.SetScopes(scopes);

            var principal = new ClaimsPrincipal(identity);
            return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        // POST/GET /connect/logout – end-session endpoint za SSO logout
        [HttpGet("~/connect/logout"), HttpPost("~/connect/logout")]
        [IgnoreAntiforgeryToken]
        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync(IdentityConstants.ApplicationScheme);
            return SignOut(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        // GET /connect/userinfo (informativno)
        [HttpGet("~/connect/userinfo")]
        [Authorize]
        public IActionResult Userinfo()
        {
            var claims = new Dictionary<string, object?>
            {
                [Claims.Subject] = User.FindFirstValue(Claims.Subject) ?? User.FindFirstValue(ClaimTypes.NameIdentifier) ?? User.Identity?.Name,
                [Claims.Name] = User.FindFirstValue(Claims.Name) ?? User.Identity?.Name,
                [Claims.Email] = User.FindFirstValue(Claims.Email) ?? User.FindFirstValue(ClaimTypes.Email),
                ["tenant"] = User.FindFirstValue("tenant") ?? User.FindFirstValue("tenant_id"),
                ["perm"] = User.Claims.Where(c => c.Type == "perm").Select(c => c.Value).ToArray(),
                [Claims.Role] = User.Claims.Where(c => c.Type == Claims.Role || c.Type == ClaimTypes.Role || c.Type == "role").Select(c => c.Value).ToArray()
            };
            return Ok(claims);
        }
    }
}
