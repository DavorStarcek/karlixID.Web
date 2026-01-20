using KarlixID.Web.Data;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using System.Linq;
using System.Security.Claims;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace KarlixID.Web.Controllers
{
    public class AuthorizationController : Controller
    {
        private readonly ApplicationDbContext _db;
        private readonly UserManager<Models.ApplicationUser> _userManager;

        public AuthorizationController(ApplicationDbContext db, UserManager<Models.ApplicationUser> userManager)
        {
            _db = db;
            _userManager = userManager;
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

            // sub/name/email/roles
            var sub = User.FindFirstValue(ClaimTypes.NameIdentifier) ?? User.Identity!.Name!;
            var name = User.Identity!.Name ?? sub;
            var email = User.FindFirstValue(ClaimTypes.Email);

            identity.AddClaim(new Claim(Claims.Subject, sub)
                .SetDestinations(Destinations.AccessToken, Destinations.IdentityToken));

            identity.AddClaim(new Claim(Claims.Name, name)
                .SetDestinations(Destinations.AccessToken, Destinations.IdentityToken));

            if (!string.IsNullOrEmpty(email))
            {
                identity.AddClaim(new Claim(Claims.Email, email)
                    .SetDestinations(Destinations.AccessToken, Destinations.IdentityToken));
            }

            // Role iz postojećeg korisničkog principal-a
            foreach (var role in User.Claims.Where(c => c.Type == ClaimTypes.Role))
            {
                identity.AddClaim(new Claim(Claims.Role, role.Value)
                    .SetDestinations(Destinations.AccessToken, Destinations.IdentityToken));
            }

            // 🔹 TENANT CLAIM – GUID
            var tenantClaim =
                User.Claims.FirstOrDefault(c => c.Type == "tenant")
                ?? User.Claims.FirstOrDefault(c => c.Type == "tenant_id")
                ?? User.Claims.FirstOrDefault(c => c.Type == "tenant:name");

            if (tenantClaim is not null && !string.IsNullOrWhiteSpace(tenantClaim.Value))
            {
                // U OpenIddict tokene ga zovemo "tenant"
                identity.AddClaim(new Claim("tenant", tenantClaim.Value)
                    .SetDestinations(Destinations.AccessToken, Destinations.IdentityToken));

                // 🔹 TENANT NAME – ako postoji u bazi i nije Guid.Empty, dodaj i "tenant_name"
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

            // =========================================================
            // ✅ PERMISSIONS (perm claims) – iz Identity tablica
            // =========================================================
            // Standard: perm claims držiš u AspNetRoleClaims i/ili AspNetUserClaims:
            //  - ClaimType = "perm"
            //  - ClaimValue = "qms.rin.write.RECEIVED" itd.
            //
            // API će kasnije raditi policies po "perm".
            //
            // Napomena: perm claimove stavljamo u ACCESS TOKEN jer je to bitno za API.
            // Identity token nije nužan za ovo; ako želiš, možeš dodati i tamo.
            // =========================================================

            // Dohvati user iz baze (da imamo UserId za AspNetUserClaims)
            // sub kod tebe je IdentityUser.Id (string), jer koristiš IdentityOptions sub mapping.
            var appUser = await _userManager.FindByIdAsync(sub);

            // permissions set (dedupe)
            var perms = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            // 1) RoleClaims -> perm
            var roleNames = User.Claims
                .Where(c => c.Type == ClaimTypes.Role)
                .Select(c => c.Value)
                .Where(v => !string.IsNullOrWhiteSpace(v))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            if (roleNames.Count > 0)
            {
                // AspNetRoles: Id (string), Name
                var roleIds = await _db.Roles
                    .AsNoTracking()
                    .Where(r => roleNames.Contains(r.Name!))
                    .Select(r => r.Id)
                    .ToListAsync();

                if (roleIds.Count > 0)
                {
                    var rolePerms = await _db.RoleClaims
                        .AsNoTracking()
                        .Where(rc => roleIds.Contains(rc.RoleId) && rc.ClaimType == "perm")
                        .Select(rc => rc.ClaimValue)
                        .ToListAsync();

                    foreach (var p in rolePerms)
                    {
                        if (!string.IsNullOrWhiteSpace(p))
                            perms.Add(p.Trim());
                    }
                }
            }

            // 2) UserClaims -> perm (override/extra)
            if (appUser != null)
            {
                var userPerms = await _db.UserClaims
                    .AsNoTracking()
                    .Where(uc => uc.UserId == appUser.Id && uc.ClaimType == "perm")
                    .Select(uc => uc.ClaimValue)
                    .ToListAsync();

                foreach (var p in userPerms)
                {
                    if (!string.IsNullOrWhiteSpace(p))
                        perms.Add(p.Trim());
                }
            }

            // 3) Emit perm claims
            // U access token (za API). Ako želiš i u identity token, dodaj i Destinations.IdentityToken.
            foreach (var p in perms.OrderBy(x => x, StringComparer.OrdinalIgnoreCase))
            {
                identity.AddClaim(new Claim("perm", p)
                    .SetDestinations(Destinations.AccessToken));
            }

            // Scope-ovi iz zahtjeva ili default
            var requested = request.GetScopes(); // ImmutableArray<string>
            var scopes = !requested.IsDefaultOrEmpty
                ? requested.ToArray()
                : new[] { Scopes.OpenId, Scopes.Profile, Scopes.Email };

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
                [Claims.Subject] = User.FindFirstValue(ClaimTypes.NameIdentifier) ?? User.Identity?.Name,
                [Claims.Name] = User.Identity?.Name,
                [Claims.Email] = User.FindFirstValue(ClaimTypes.Email)
            };
            return Ok(claims);
        }
    }
}
