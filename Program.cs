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

        // Ephemeral ključevi – ne diraju cert store
        options
            .AddEphemeralEncryptionKey()
            .AddEphemeralSigningKey();

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
    // DEV ili ASPNETCORE_DETAILEDERRORS=true → full stack
    app.UseDeveloperExceptionPage();
}
else
{
    // klasični production handling
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

    // Role
    if (!await roleManager.RoleExistsAsync(AppRoleInfo.GlobalAdmin))
        await roleManager.CreateAsync(new IdentityRole(AppRoleInfo.GlobalAdmin));

    if (!await roleManager.RoleExistsAsync(AppRoleInfo.TenantAdmin))
        await roleManager.CreateAsync(new IdentityRole(AppRoleInfo.TenantAdmin));

    // GlobalAdmin
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

    // (Opcionalno) TenantAdmin za 'localhost'
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
