using LogCarverGuard.Core;
using Microsoft.Data.SqlClient;
using ModelContextProtocol;

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
        try
        {
            var connection = await connectionFactory.OpenAsync(apiKeyInfo.SqlLogin, ct);
            return new CallerConnection(apiKeyInfo.Owner, connection);
        }
        catch (SqlException ex) when (ServiceAccountPermissionMessages.DescribeImpersonationFailure(ex, apiKeyInfo.SqlLogin) is not null)
        {
            // An unhandled exception reaches the agent only as "An error occurred"; an
            // McpException's message is passed through, so the administrator can act on it.
            throw new McpException(ServiceAccountPermissionMessages.DescribeImpersonationFailure(ex, apiKeyInfo.SqlLogin)!, ex);
        }
    }
}
