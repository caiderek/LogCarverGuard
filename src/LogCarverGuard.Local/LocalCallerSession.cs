using LogCarverGuard.Server;
using Microsoft.Data.SqlClient;

namespace LogCarverGuard.Local;

/// <summary>
/// The local host's caller: whoever runs this process, on the connection
/// the operator configured. There is no per-user identity and no
/// impersonation, so SQL Server sees exactly the login in the connection
/// string.
/// </summary>
public sealed class LocalCallerSession(string connectionString) : ICallerSession
{
    private readonly string _owner = Environment.UserName;

    public async Task<CallerConnection> OpenAsync(CancellationToken ct)
    {
        var connection = new SqlConnection(connectionString);
        try
        {
            await connection.OpenAsync(ct);
            return new CallerConnection(_owner, connection);
        }
        catch
        {
            await connection.DisposeAsync();
            throw;
        }
    }
}
