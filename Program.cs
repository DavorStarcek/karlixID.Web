using KarlixID.Web.Data;
using KarlixID.Web.Middleware;
using KarlixID.Web.Models;
using KarlixID.Web.Services;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using System.Globalization;
using static OpenIddict.Abstractions.OpenIddictConstants;
using System.Security.Cryptography.X509Certificates;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);
var env = builder.Environment;
var isDev = env.IsDevelopment();

// dodatno: flag za detaljne greške (čita se iz env var)
var detailedErrorsEnv = Environment.GetEnvironmentVariable("ASPNETCORE_DETAILEDERRORS");
var showDevErrors =
    isDev ||
    string.Equals(detailedErrorsEnv, "true", StringComparison.OrdinalIgnoreCase);

// ========= DB =========
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");
builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    options.UseSqlServer(connectionString);
    options.UseOpenIddict();
});

// ========= Identity =========
builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    options.SignIn.RequireConfirmedAccount = false;
    options.Password.RequireDigit = false;
    options.Password.RequireNonAlphanumeric = false;
    options.Password.RequireUppercase = false;
    options.Password.RequireLowercase = true;
})
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders()
.AddDefaultUI();

// Mapiranje claim tipova na OIDC standard
builder.Services.Configure<IdentityOptions>(o =>
{
    o.ClaimsIdentity.UserIdClaimType = Claims.Subject; // "sub"
    o.ClaimsIdentity.UserNameClaimType = Claims.Name;  // "name"
    o.ClaimsIdentity.RoleClaimType = Claims.Role;      // "role"
    o.ClaimsIdentity.EmailClaimType = Claims.Email;    // "email"
});

// Cookie
builder.Services.ConfigureApplicationCookie(opts =>
{
    opts.LoginPath = "/Identity/Account/Login";
    opts.LogoutPath = "/Identity/Account/Logout";
    opts.AccessDeniedPath = "/Identity/Account/AccessDenied";
    opts.SlidingExpiration = true;
    opts.ExpireTimeSpan = TimeSpan.FromHours(8);
});

// Claims factory
builder.Services.AddScoped<IUserClaimsPrincipalFactory<ApplicationUser>, AppUserClaimsPrincipalFactory>();

// Authorization politike (NET 8)
builder.Services.AddAuthorizationBuilder()
    .AddPolicy("GlobalAdminOnly", p => p.RequireRole(AppRoleInfo.GlobalAdmin))
    .AddPolicy("TenantAdminOrGlobal", p => p.RequireRole(AppRoleInfo.GlobalAdmin, AppRoleInfo.TenantAdmin));

// Ostali servisi
builder.Services.AddHttpContextAccessor();
builder.Services.AddTransient<EmailService>();
builder.Services.AddTransient<ExcelExportService>();

// Lokalizacija + MVC/Razor
builder.Services.AddLocalization(opts => { opts.ResourcesPath = "Resources"; });
builder.Services.AddControllersWithViews()
    .AddViewLocalization()
    .AddDataAnnotationsLocalization();
builder.Services.AddRazorPages();

// Data Protection ključevi (za sada isto i u DEV i u PROD)
var keysPath = Path.Combine(
    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
    "KarlixID", "keys"
);
Directory.CreateDirectory(keysPath);

builder.Services
    .AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo(keysPath))
    .SetApplicationName("KarlixID");

// ========= OpenIddict 7.x =========
builder.Services.AddOpenIddict()
    .AddCore(options =>
    {
        options.UseEntityFrameworkCore()
               .UseDbContext<ApplicationDbContext>();
    })
    .AddServer(options =>
    {
        options
            .SetAuthorizationEndpointUris("/connect/authorize")
            .SetTokenEndpointUris("/connect/token")
            .SetIntrospectionEndpointUris("/connect/introspect")
            .SetEndSessionEndpointUris("/connect/logout");

        options
            .AllowAuthorizationCodeFlow()
            .AllowRefreshTokenFlow();

        options.RegisterScopes(Scopes.OpenId, Scopes.Profile, Scopes.Email, Scopes.Roles, Scopes.OfflineAccess);

        // ✅ Stabilni ključevi (NE ephemeral)
        // DEV: koristi development cert (persistira, ne mijenja se na restart)
        // PROD: koristi PFX cert iz konfiguracije
        if (isDev)
        {
            options
                .AddDevelopmentEncryptionCertificate()
                .AddDevelopmentSigningCertificate();
        }
        else
        {
            var certPath = builder.Configuration["OpenIddict:Certificates:Signing:Path"];
            var certPassword = builder.Configuration["OpenIddict:Certificates:Signing:Password"];

            if (string.IsNullOrWhiteSpace(certPath))
                throw new InvalidOperationException("Missing OpenIddict signing certificate path (OpenIddict:Certificates:Signing:Path).");

            options
                .AddEncryptionCertificate(new X509Certificate2(certPath, certPassword))
                .AddSigningCertificate(new X509Certificate2(certPath, certPassword));
        }

        options.UseAspNetCore()
            .EnableAuthorizationEndpointPassthrough()
            .EnableEndSessionEndpointPassthrough();

        // Tokeni u plain JWT obliku (lakše debugiranje)
        options.DisableAccessTokenEncryption();
    })
    .AddValidation(options =>
    {
        options.UseLocalServer();
        options.UseAspNetCore();
    });

var app = builder.Build();

// ========= Pipeline =========
var supportedCultures = new[] { new CultureInfo("hr"), new CultureInfo("en") };
app.UseRequestLocalization(new RequestLocalizationOptions
{
    DefaultRequestCulture = new Microsoft.AspNetCore.Localization.RequestCulture("hr"),
    SupportedCultures = supportedCultures,
    SupportedUICultures = supportedCultures
});

// umjesto if (!isDev) -> koristimo showDevErrors
if (showDevErrors)
{
    app.UseDeveloperExceptionPage();
}
else
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();

// Multitenant Middleware
app.UseTenantResolver();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.MapRazorPages();

// ========= Seed: uloge, admin i OpenIddict klijenti =========
using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;
    var context = services.GetRequiredService<ApplicationDbContext>();
    var userManager = services.GetRequiredService<UserManager<ApplicationUser>>();
    var roleManager = services.GetRequiredService<RoleManager<IdentityRole>>();
    var appManager = services.GetRequiredService<IOpenIddictApplicationManager>();

    // context.Database.Migrate(); // ako želiš

    // --------------------------
    // Helperi za seed
    // --------------------------
    static async Task<IdentityRole> EnsureRoleAsync(RoleManager<IdentityRole> rm, string roleName)
    {
        var role = await rm.FindByNameAsync(roleName);
        if (role != null) return role;

        var create = await rm.CreateAsync(new IdentityRole(roleName));
        if (!create.Succeeded)
        {
            var msg = string.Join("; ", create.Errors.Select(e => $"{e.Code}:{e.Description}"));
            throw new InvalidOperationException($"Ne mogu kreirati rolu '{roleName}': {msg}");
        }

        role = await rm.FindByNameAsync(roleName)
               ?? throw new InvalidOperationException($"Rola '{roleName}' je kreirana ali nije pronađena nakon toga.");
        return role;
    }

    static async Task EnsureRolePermAsync(RoleManager<IdentityRole> rm, IdentityRole role, string perm)
    {
        // koristimo ClaimType="perm" (standard za permissions)
        var existing = await rm.GetClaimsAsync(role);
        if (existing.Any(c => c.Type == "perm" && string.Equals(c.Value, perm, StringComparison.OrdinalIgnoreCase)))
            return;

        var add = await rm.AddClaimAsync(role, new Claim("perm", perm));
        if (!add.Succeeded)
        {
            var msg = string.Join("; ", add.Errors.Select(e => $"{e.Code}:{e.Description}"));
            throw new InvalidOperationException($"Ne mogu dodati perm '{perm}' roli '{role.Name}': {msg}");
        }
    }

    // --------------------------
    // 1) Roles
    // --------------------------
    var globalAdminRole = await EnsureRoleAsync(roleManager, AppRoleInfo.GlobalAdmin);
    var tenantAdminRole = await EnsureRoleAsync(roleManager, AppRoleInfo.TenantAdmin);
    var tenantUserRole = await EnsureRoleAsync(roleManager, AppRoleInfo.TenantUser);

    // --------------------------
    // 2) QMS Permissions (Option B: odvojeno RIN/UN)
    // --------------------------
    // TenantUser: read-only perms
    var qmsTenantUserPerms = new[]
    {
        "qms.read",
        "qms.actions.read"
    };

    // TenantAdmin + GlobalAdmin: full perms
    var qmsAllPerms = new[]
    {
        // read
        "qms.read",
        "qms.actions.read",

        // actions
        "qms.actions.write.basic",
        "qms.actions.verify",
        "qms.actions.write.all",

        // RIN phase writes
        "qms.rin.write.RECEIVED",
        "qms.rin.write.IN_PROGRESS",
        "qms.rin.write.CLOSED",

        // UN phase writes
        "qms.un.write.RECEIVED",
        "qms.un.write.IN_PROGRESS",
        "qms.un.write.CLOSED",

        // admin
        "qms.admin"
    };

    foreach (var p in qmsTenantUserPerms)
        await EnsureRolePermAsync(roleManager, tenantUserRole, p);

    foreach (var p in qmsAllPerms)
        await EnsureRolePermAsync(roleManager, tenantAdminRole, p);

    foreach (var p in qmsAllPerms)
        await EnsureRolePermAsync(roleManager, globalAdminRole, p);

    // --------------------------
    // 3) GlobalAdmin user (seed)
    // --------------------------
    var globalAdmin = await userManager.FindByEmailAsync("admin@karlix.eu");
    if (globalAdmin == null)
    {
        var user = new ApplicationUser
        {
            UserName = "admin@karlix.eu",
            Email = "admin@karlix.eu",
            EmailConfirmed = true,
            TenantId = Guid.Empty
        };

        var result = await userManager.CreateAsync(user, "Admin123!");
        if (result.Succeeded)
            await userManager.AddToRoleAsync(user, AppRoleInfo.GlobalAdmin);
    }

    // --------------------------
    // 4) (Opcionalno) TenantAdmin za 'localhost'
    // --------------------------
    var localhostTenant = context.Tenants.FirstOrDefault(t => t.Hostname == "localhost");
    if (localhostTenant != null)
    {
        var taEmail = "tenant.admin@localhost";
        var ta = await userManager.FindByEmailAsync(taEmail);
        if (ta == null)
        {
            var u = new ApplicationUser
            {
                UserName = taEmail,
                Email = taEmail,
                EmailConfirmed = true,
                TenantId = localhostTenant.Id
            };
            var res = await userManager.CreateAsync(u, "TempPass123!");
            if (res.Succeeded)
                await userManager.AddToRoleAsync(u, AppRoleInfo.TenantAdmin);
        }
    }

    // ===== Karlix MVC (Portal) =====
    {
        var existing = await appManager.FindByClientIdAsync("karlix_mvc");

        if (existing is null)
        {
            var descriptor = new OpenIddictApplicationDescriptor
            {
                ClientId = "karlix_mvc",
                ClientSecret = "super-tajna-rijec-za-dev", // PROD: promijeni!
                DisplayName = "Karlix MVC (Portal)",
                ClientType = ClientTypes.Confidential,
                ConsentType = ConsentTypes.Implicit,
                Permissions =
                {
                    Permissions.Endpoints.Authorization,
                    Permissions.Endpoints.Token,
                    Permissions.Endpoints.Introspection,
                    Permissions.Endpoints.EndSession,
                    Permissions.GrantTypes.AuthorizationCode,
                    Permissions.GrantTypes.RefreshToken,
                    Permissions.ResponseTypes.Code,
                    Scopes.OpenId,
                    Scopes.Profile,
                    Scopes.Email,
                    Scopes.Roles,
                    Scopes.OfflineAccess
                }
            };

            // Dev redirecti
            descriptor.RedirectUris.Add(new Uri("https://localhost:5003/signin-oidc"));
            descriptor.PostLogoutRedirectUris.Add(new Uri("https://localhost:5003/signout-callback-oidc"));

            // Prod redirecti
            descriptor.RedirectUris.Add(new Uri("https://portal.karlix.eu/signin-oidc"));
            descriptor.PostLogoutRedirectUris.Add(new Uri("https://portal.karlix.eu/signout-callback-oidc"));

            await appManager.CreateAsync(descriptor);
        }
        else
        {
            var descriptor = new OpenIddictApplicationDescriptor();
            await appManager.PopulateAsync(descriptor, existing);

            // Osiguraj redirect URI-je (DEV + PROD)
            var redirectSet = new HashSet<Uri>(descriptor.RedirectUris ?? Enumerable.Empty<Uri>());
            redirectSet.Add(new Uri("https://localhost:5003/signin-oidc"));
            redirectSet.Add(new Uri("https://portal.karlix.eu/signin-oidc"));
            descriptor.RedirectUris.Clear();
            foreach (var uri in redirectSet) descriptor.RedirectUris.Add(uri);

            // Osiguraj post-logout URI-je
            var postLogoutSet = new HashSet<Uri>(descriptor.PostLogoutRedirectUris ?? Enumerable.Empty<Uri>());
            postLogoutSet.Add(new Uri("https://localhost:5003/signout-callback-oidc"));
            postLogoutSet.Add(new Uri("https://portal.karlix.eu/signout-callback-oidc"));
            descriptor.PostLogoutRedirectUris.Clear();
            foreach (var uri in postLogoutSet) descriptor.PostLogoutRedirectUris.Add(uri);

            await appManager.UpdateAsync(existing, descriptor);
        }
    }

    // ===== Karlix QMS (Web) =====
    {
        var existing = await appManager.FindByClientIdAsync("karlix_qms");

        if (existing is null)
        {
            var descriptor = new OpenIddictApplicationDescriptor
            {
                ClientId = "karlix_qms",
                ClientSecret = "super-tajna-rijec-za-dev-qms", // PROD: promijeni!
                DisplayName = "Karlix QMS (Quality Management System)",
                ClientType = ClientTypes.Confidential,
                ConsentType = ConsentTypes.Implicit,
                Permissions =
                {
                    Permissions.Endpoints.Authorization,
                    Permissions.Endpoints.Token,
                    Permissions.Endpoints.Introspection,
                    Permissions.Endpoints.EndSession,
                    Permissions.GrantTypes.AuthorizationCode,
                    Permissions.GrantTypes.RefreshToken,
                    Permissions.ResponseTypes.Code,
                    Scopes.OpenId,
                    Scopes.Profile,
                    Scopes.Email,
                    Scopes.Roles,
                    Scopes.OfflineAccess
                }
            };

            // Dev redirecti
            descriptor.RedirectUris.Add(new Uri("https://localhost:5005/signin-oidc"));
            descriptor.PostLogoutRedirectUris.Add(new Uri("https://localhost:5005/signout-callback-oidc"));

            // Prod redirecti – QMS web
            descriptor.RedirectUris.Add(new Uri("https://qms.karlix.eu/signin-oidc"));
            descriptor.PostLogoutRedirectUris.Add(new Uri("https://qms.karlix.eu/signout-callback-oidc"));

            await appManager.CreateAsync(descriptor);
        }
        else
        {
            var descriptor = new OpenIddictApplicationDescriptor();
            await appManager.PopulateAsync(descriptor, existing);

            // Redirect URIs
            var redirectSet = new HashSet<Uri>(descriptor.RedirectUris ?? Enumerable.Empty<Uri>());
            redirectSet.Add(new Uri("https://localhost:5005/signin-oidc"));
            redirectSet.Add(new Uri("https://qms.karlix.eu/signin-oidc"));
            descriptor.RedirectUris.Clear();
            foreach (var uri in redirectSet) descriptor.RedirectUris.Add(uri);

            // Post-logout URIs
            var postLogoutSet = new HashSet<Uri>(descriptor.PostLogoutRedirectUris ?? Enumerable.Empty<Uri>());
            postLogoutSet.Add(new Uri("https://localhost:5005/signout-callback-oidc"));
            postLogoutSet.Add(new Uri("https://qms.karlix.eu/signout-callback-oidc"));
            descriptor.PostLogoutRedirectUris.Clear();
            foreach (var uri in postLogoutSet) descriptor.PostLogoutRedirectUris.Add(uri);

            await appManager.UpdateAsync(existing, descriptor);
        }
    }
}

app.Run();
