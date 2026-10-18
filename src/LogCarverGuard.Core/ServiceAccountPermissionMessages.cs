using Microsoft.Data.SqlClient;

namespace LogCarverGuard.Core;

/// <summary>
/// Guard does not police which grants an AI's SQL login has - that is the
/// administrator's call. What it does owe them is a clear answer when a step
/// needs a permission that is missing, and in particular WHO is missing it:
/// the caller's own login (SQL Server's own message is usually fine there) or
/// Guard's service account (SQL Server's wording does not say). These turn the
/// two service-account failures into messages that name the account and the
/// permission. Both return null for any other error, so callers keep the
/// original behaviour for everything else.
/// </summary>
public static class ServiceAccountPermissionMessages
{
    /// <summary>
    /// "EXECUTE AS LOGIN" failed. SQL Server error 15406 lumps three causes together
    /// (the login does not exist, it cannot be impersonated, or no permission).
    /// </summary>
    public static string? DescribeImpersonationFailure(SqlException ex, string sqlLogin) =>
        ex.Number != 15406
            ? null
            : $"Guard's service account could not act as the SQL login '{sqlLogin}'. " +
              $"Check that this login exists (the API key may point at a wrong name) and that the service account " +
              $"has been granted IMPERSONATE on it: GRANT IMPERSONATE ON LOGIN::[{sqlLogin}] TO [<service account>]. " +
              $"SQL Server said: {ex.Message}";

    /// <summary>
    /// Reading the transaction log with fn_dblog failed for lack of permission.
    /// fn_dblog needs sysadmin; View Server State and db_owner were each tried and are not enough.
    /// </summary>
    public static string? DescribeLogReadFailure(SqlException ex) =>
        !IsLogReadPermissionError(ex)
            ? null
            : "Guard's service account (not the caller's own login) needs the sysadmin role to read the transaction log " +
              "with fn_dblog, which is how undo SQL is produced. The write itself ran and was audited. " +
              $"SQL Server said: {ex.Message}";

    private static bool IsLogReadPermissionError(SqlException ex) =>
        ex.Number switch
        {
            229 => ex.Message.Contains("fn_dblog", StringComparison.OrdinalIgnoreCase),
            297 or 300 => true,
            _ => false,
        };
}
