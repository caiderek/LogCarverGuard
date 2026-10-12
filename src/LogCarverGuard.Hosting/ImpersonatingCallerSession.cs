using LogCarverGuard.Core;

namespace LogCarverGuard.Server;

/// <summary>
/// The central service's caller session: the API key in the request header
/// names a person, and the statement runs on a connection that impersonates
/// that person's own SQL login, so their grants apply.
/// </summary>
public sealed class ImpersonatingCallerSession(
    CallerResolver callerResolver,
    ImpersonatedConnectionFactory connectionFactory) : ICallerSession
{
    public async Task<CallerConnection> OpenAsync(CancellationToken ct)
    {
        var apiKeyInfo = await callerResolver.ResolveAsync(ct);
        var connection = await connectionFactory.OpenAsync(apiKeyInfo.SqlLogin, ct);
        return new CallerConnection(apiKeyInfo.Owner, connection);
    }
}
