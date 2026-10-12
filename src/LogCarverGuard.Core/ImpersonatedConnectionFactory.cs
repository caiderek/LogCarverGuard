using Microsoft.Data.SqlClient;

namespace LogCarverGuard.Core;

/// <summary>
/// Opens a connection under the proxy's single service account, then
/// switches the session's security context to the real SQL Server login an
/// API key maps to via EXECUTE AS LOGIN (規劃書 三-5) - so SQL Server's own
/// GRANT/DENY permissions apply per real person, without the proxy managing
/// N real credentials or reinventing an authorization system. The proxy
/// itself never holds or sees any credential but its own single service
/// account's.
///
/// Verified empirically against a real local SQL Server 2026-10-02 that
/// EXECUTE AS LOGIN accepts a parameterized value the same way ADO.NET
/// binds SqlParameter (via sp_executesql), not just a string literal -
/// confirmed via sqlcmd before relying on it here, since this isn't
/// something either of us should guess at for a security-context switch.
///
/// Connection pooling is forced off for this connection string: EXECUTE AS
/// LOGIN's session context is session-scoped, and pooled connections carry
/// their session state to whoever the pool hands them to next - without
/// this, a later caller could silently inherit an earlier caller's
/// impersonated identity. That's a real security leak, not a theoretical
/// one, so this trades a little per-call connection-setup latency for a
/// guarantee that no session ever crosses callers.
/// </summary>
public sealed class ImpersonatedConnectionFactory(string serviceAccountConnectionString)
{
    private readonly string _connectionString = DisablePooling(serviceAccountConnectionString);

    public async Task<SqlConnection> OpenAsync(string sqlLogin, CancellationToken ct = default)
    {
        var connection = new SqlConnection(_connectionString);
        try
        {
            await connection.OpenAsync(ct);
            // Tried `WITH NO REVERT` here as defense-in-depth, 2026-10-07 -
            // reverted after it failed empirically against a real SQL Server
            // ("'No Revert' or 'Cookie' option can only be used in specific
            // levels of 'Execute As' statement"). SqlStatementGuard blocking
            // the caller's own REVERT/EXECUTE AS statements outright is the
            // actual, sole defense against the security-context-switch
            // vulnerability this was meant to backstop - verified correct
            // there instead (see SqlStatementGuard.cs).
            await using var impersonate = new SqlCommand("EXECUTE AS LOGIN = @login;", connection);
            impersonate.Parameters.AddWithValue("@login", sqlLogin);
            await impersonate.ExecuteNonQueryAsync(ct);
            return connection;
        }
        catch
        {
            await connection.DisposeAsync();
            throw;
        }
    }

    private static string DisablePooling(string connectionString) =>
        new SqlConnectionStringBuilder(connectionString) { Pooling = false }.ConnectionString;
}
