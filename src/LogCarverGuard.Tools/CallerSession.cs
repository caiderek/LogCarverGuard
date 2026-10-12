using Microsoft.Data.SqlClient;

namespace LogCarverGuard.Server;

/// <summary>An open connection together with the name the audit log records for whoever is calling.</summary>
public sealed class CallerConnection(string owner, SqlConnection connection) : IAsyncDisposable
{
    public string Owner { get; } = owner;
    public SqlConnection Connection { get; } = connection;

    public ValueTask DisposeAsync() => Connection.DisposeAsync();
}

/// <summary>
/// Who is calling and which connection their statement runs on. The
/// central service resolves an API key and impersonates that person's own
/// SQL login; the local stdio host simply uses the configured connection.
/// </summary>
public interface ICallerSession
{
    Task<CallerConnection> OpenAsync(CancellationToken ct);
}
