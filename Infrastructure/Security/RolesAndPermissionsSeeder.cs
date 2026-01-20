using Microsoft.AspNetCore.Identity;
using System.Security.Claims;

namespace KarlixID.Web.Infrastructure.Security;

public static class RolesAndPermissionsSeeder
{
    public const string PermissionClaimType = "permission";

    public static async Task SeedAsync(RoleManager<IdentityRole> roleManager)
    {
        // 1) roles
        await EnsureRoleExists(roleManager, "GlobalAdmin");
        await EnsureRoleExists(roleManager, "TenantAdmin");
        await EnsureRoleExists(roleManager, "TenantUser");

        // 2) permissions by role
        await EnsureRoleHasPermissions(roleManager, "TenantAdmin", QmsPerms.TenantAdminAll);
        await EnsureRoleHasPermissions(roleManager, "TenantUser", QmsPerms.TenantUserDefault);

        // GlobalAdmin: opcija A) ne treba perms (ako API radi GlobalAdmin bypass)
        // Opcija B) dodaj sve perms i njemu (ja volim B jer je konzistentno):
        await EnsureRoleHasPermissions(roleManager, "GlobalAdmin", QmsPerms.TenantAdminAll);
    }

    private static async Task EnsureRoleExists(RoleManager<IdentityRole> roleManager, string roleName)
    {
        if (!await roleManager.RoleExistsAsync(roleName))
            await roleManager.CreateAsync(new IdentityRole(roleName));
    }

    private static async Task EnsureRoleHasPermissions(RoleManager<IdentityRole> roleManager, string roleName, IEnumerable<string> permissions)
    {
        var role = await roleManager.FindByNameAsync(roleName);
        if (role == null) return;

        var existing = await roleManager.GetClaimsAsync(role);
        var existingPerms = new HashSet<string>(
            existing.Where(c => c.Type == PermissionClaimType).Select(c => c.Value),
            StringComparer.OrdinalIgnoreCase);

        foreach (var p in permissions)
        {
            if (!existingPerms.Contains(p))
                await roleManager.AddClaimAsync(role, new Claim(PermissionClaimType, p));
        }
    }
}
