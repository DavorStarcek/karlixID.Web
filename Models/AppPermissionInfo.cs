namespace KarlixID.Web.Models;

public static class AppPermissionInfo
{
    // Claim type
    public const string PermissionClaimType = "perm";

    // QMS permissions
    public const string QmsAdmin = "qms.admin";
    public const string QmsRead = "qms.read";

    public const string QmsActionsRead = "qms.actions.read";
    public const string QmsActionsWriteBasic = "qms.actions.write.basic";
    public const string QmsActionsVerify = "qms.actions.verify";
    public const string QmsActionsWriteAll = "qms.actions.write.all";

    // (kasnije) RIN/UN phase perms kad krenemo na Cases
    public const string QmsRinWriteReceived = "qms.rin.write.RECEIVED";
    public const string QmsRinWriteInProgress = "qms.rin.write.IN_PROGRESS";
    public const string QmsRinWriteClosed = "qms.rin.write.CLOSED";

    public const string QmsUnWriteReceived = "qms.un.write.RECEIVED";
    public const string QmsUnWriteInProgress = "qms.un.write.IN_PROGRESS";
    public const string QmsUnWriteClosed = "qms.un.write.CLOSED";
}
