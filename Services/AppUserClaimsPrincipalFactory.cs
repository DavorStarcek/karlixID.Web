using KarlixID.Web.Data;
using KarlixID.Web.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using System.Security.Claims;

namespace KarlixID.Web.Services
{
    public class AppUserClaimsPrincipalFactory :
        UserClaimsPrincipalFactory<ApplicationUser, IdentityRole>
    {
        private readonly ApplicationDbContext _db;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly UserManager<ApplicationUser> _userManager;

        public AppUserClaimsPrincipalFactory(
            UserManager<ApplicationUser> userManager,
            RoleManager<IdentityRole> roleManager,
            IOptions<IdentityOptions> optionsAccessor,
            ApplicationDbContext db)
            : base(userManager, roleManager, optionsAccessor)
        {
            _db = db;
            _roleManager = roleManager;
            _userManager = userManager;
        }

        protected override async Task<ClaimsIdentity> GenerateClaimsAsync(ApplicationUser user)
        {
            var identity = await base.GenerateClaimsAsync(user);

            // ------------------------------------------------------------
            // TENANT claims (tvoja postojeća logika)
            // ------------------------------------------------------------
            var tenantId = user.TenantId ?? Guid.Empty;

            // standardiziraj: koristimo tenant_id i tenant_name u cookie principalu
            identity.AddClaim(new Claim("tenant_id", tenantId.ToString()));

            var tname = await _db.Tenants
                .AsNoTracking()
                .Where(t => t.Id == tenantId)
                .Select(t => t.Name)
                .FirstOrDefaultAsync();

            if (!string.IsNullOrWhiteSpace(tname))
                identity.AddClaim(new Claim("tenant_name", tname));

            // ------------------------------------------------------------
            // PERMISSIONS from RoleClaims -> u cookie principal
            // ------------------------------------------------------------
            // Permission claim type definiran u tvojoj AppPermissionInfo klasi
            // (seed već dodaje claims u AspNetRoleClaims)
            var permissionType = AppPermissionInfo.PermissionClaimType;

            // Role names for user
            var roles = await _userManager.GetRolesAsync(user);

            // Da ne dodajemo duplikate
            var existingPerms = new HashSet<string>(
                identity.Claims
                    .Where(c => string.Equals(c.Type, permissionType, StringComparison.OrdinalIgnoreCase))
                    .Select(c => c.Value),
                StringComparer.OrdinalIgnoreCase);

            foreach (var roleName in roles.Distinct(StringComparer.OrdinalIgnoreCase))
            {
                var role = await _roleManager.FindByNameAsync(roleName);
                if (role == null) continue;

                var roleClaims = await _roleManager.GetClaimsAsync(role);
                foreach (var rc in roleClaims.Where(c => string.Equals(c.Type, permissionType, StringComparison.OrdinalIgnoreCase)))
                {
                    if (string.IsNullOrWhiteSpace(rc.Value)) continue;
                    if (existingPerms.Add(rc.Value))
                    {
                        identity.AddClaim(new Claim(permissionType, rc.Value));
                    }
                }
            }

            return identity;
        }
    }
}
