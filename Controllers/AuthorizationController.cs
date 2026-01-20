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
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;

        public AuthorizationController(
            ApplicationDbContext db,
            UserManager<ApplicationUser> userManager,
            RoleManager<IdentityRole> roleManager)
        {
            _db = db;
            _userManager = userManager;
            _roleManager = roleManager;
        }

        // GET/POST /connect/authorize
        [HttpGet("~/connect/authorize"), HttpPost("~/connect/authorize")]
        [IgnoreAntiforgeryToken]
        public async Task<IActionResult> Authorize()
        {
            var request = HttpContext.GetOpenIddictServerRequest()
                          ?? throw new InvalidOperationException("OIDC request unavailable.");

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

            // Složi OpenIddict identity
            var identity = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

            var sub = User.FindFirstValue(Claims.Subject)
                      ?? User.FindFirstValue(ClaimTypes.NameIdentifier)
                      ?? User.Identity!.Name
                      ?? throw new InvalidOperationException("Missing subject.");

            var name = User.FindFirstValue(Claims.Name) ?? User.Identity!.Name ?? sub;
            var email = User.FindFirstValue(Claims.Email) ?? User.FindFirstValue(ClaimTypes.Email);

            identity.AddClaim(new Claim(Claims.Subject, sub)
                .SetDestinations(Destinations.AccessToken, Destinations.IdentityToken));

            identity.AddClaim(new Claim(Claims.Name, name)
                .SetDestinations(Destinations.AccessToken, Destinations.IdentityToken));

            if (!string.IsNullOrEmpty(email))
            {
                identity.AddClaim(new Claim(Claims.Email, email)
                    .SetDestinations(Destinations.AccessToken, Destinations.IdentityToken));
            }

            // ==========================
            // ✅ ROLES: fix (role claim type je "role", ne ClaimTypes.Role)
            // ==========================
            var roleValues = User.Claims
                .Where(c =>
                    string.Equals(c.Type, Claims.Role, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(c.Type, ClaimTypes.Role, StringComparison.OrdinalIgnoreCase))
                .Select(c => c.Value)
                .Where(v => !string.IsNullOrWhiteSpace(v))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            foreach (var r in roleValues)
            {
                identity.AddClaim(new Claim(Claims.Role, r)
                    .SetDestinations(Destinations.AccessToken, Destinations.IdentityToken));
            }

            // ==========================
            // ✅ PERMISSIONS: povuci iz RoleClaims (ClaimType="perm")
            // ==========================
            // (a) Load user from DB to be safe
            var appUser = await _userManager.FindByIdAsync(sub);
            if (appUser != null)
            {
                // Roles from store (authoritative)
                var storeRoles = await _userManager.GetRolesAsync(appUser);

                var permSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                foreach (var roleName in storeRoles)
                {
                    var role = await _roleManager.FindByNameAsync(roleName);
                    if (role == null) continue;

                    var claims = await _roleManager.GetClaimsAsync(role);
                    foreach (var c in claims)
                    {
                        if (string.Equals(c.Type, AppPermissionInfo.PermissionClaimType, StringComparison.OrdinalIgnoreCase) &&
                            !string.IsNullOrWhiteSpace(c.Value))
                        {
                            permSet.Add(c.Value);
                        }
                    }
                }

                // (b) Optional: user-level perm overrides (AspNetUserClaims)
                var userClaims = await _userManager.GetClaimsAsync(appUser);
                foreach (var c in userClaims)
                {
                    if (string.Equals(c.Type, AppPermissionInfo.PermissionClaimType, StringComparison.OrdinalIgnoreCase) &&
                        !string.IsNullOrWhiteSpace(c.Value))
                    {
                        permSet.Add(c.Value);
                    }
                }

                foreach (var perm in permSet)
                {
                    // perm treba samo API-ju => AccessToken je dosta
                    identity.AddClaim(new Claim(AppPermissionInfo.PermissionClaimType, perm)
                        .SetDestinations(Destinations.AccessToken));
                }
            }

            // ==========================
            // TENANT CLAIM
            // ==========================
            var tenantClaim =
                User.Claims.FirstOrDefault(c => c.Type == "tenant")
                ?? User.Claims.FirstOrDefault(c => c.Type == "tenant_id")
                ?? User.Claims.FirstOrDefault(c => c.Type == "tenant:name");

            if (tenantClaim is not null && !string.IsNullOrWhiteSpace(tenantClaim.Value))
            {
                identity.AddClaim(new Claim("tenant", tenantClaim.Value)
                    .SetDestinations(Destinations.AccessToken, Destinations.IdentityToken));

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

            // Scope-ovi
            var requested = request.GetScopes();
            var scopes = !requested.IsDefaultOrEmpty
                ? requested.ToArray()
                : new[] { Scopes.OpenId, Scopes.Profile, Scopes.Email };

            identity.SetScopes(scopes);

            var principal = new ClaimsPrincipal(identity);
            return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        [HttpGet("~/connect/logout"), HttpPost("~/connect/logout")]
        [IgnoreAntiforgeryToken]
        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync(IdentityConstants.ApplicationScheme);
            return SignOut(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        [HttpGet("~/connect/userinfo")]
        [Authorize]
        public IActionResult Userinfo()
        {
            var claims = new Dictionary<string, object?>
            {
                [Claims.Subject] = User.FindFirstValue(ClaimTypes.NameIdentifier) ?? User.Identity?.Name,
                [Claims.Name] = User.Identity?.Name,
                [Claims.Email] = User.FindFirstValue(ClaimTypes.Email)
            };
            return Ok(claims);
        }
    }
}
