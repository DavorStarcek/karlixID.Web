namespace KarlixID.Web.Infrastructure.Security;

public static class QmsPerms
{
    // ACTIONS
    public const string ActionsRead = "qms.actions.read";
    public const string ActionsWriteBasic = "qms.actions.write.basic";
    public const string ActionsVerify = "qms.actions.verify";

    // CASES
    public const string CasesRead = "qms.cases.read";

    // LOOKUPS (ako želiš zaključati lookups endpoint-e)
    public const string LookupsRead = "qms.lookups.read";

    public static readonly string[] TenantAdminAll =
    {
        // “full” za tenant
        CasesRead,
        ActionsRead,
        ActionsWriteBasic,
        ActionsVerify,
        LookupsRead
    };

    public static readonly string[] TenantUserDefault =
    {
        // standardno: read-only
        CasesRead,
        ActionsRead,
        LookupsRead
    };
}
