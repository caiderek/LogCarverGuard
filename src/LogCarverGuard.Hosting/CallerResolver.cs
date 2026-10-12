using LogCarverGuard.Core;
using LogCarverGuard.Server.Tools;
using Microsoft.AspNetCore.Http;
using ModelContextProtocol;

namespace LogCarverGuard.Server;

/// <summary>
/// Maps the current MCP call's API-key header to the real SQL login and
/// owner it stands for. Shared by every tool class, so the
/// front-door check lives in exactly one place.
/// </summary>
public sealed class CallerResolver(IHttpContextAccessor httpContextAccessor, ApiKeyStore apiKeyStore)
{
    public async Task<ApiKeyInfo> ResolveAsync(CancellationToken ct)
    {
        var httpContext = httpContextAccessor.HttpContext
            ?? throw new McpException("No HTTP context available for this call.");

        if (!httpContext.Request.Headers.TryGetValue(SqlTools.ApiKeyHeaderName, out var values) || values.Count == 0)
            throw new McpException($"Missing required '{SqlTools.ApiKeyHeaderName}' header.");

        return await apiKeyStore.ValidateAsync(values[0]!, ct)
            ?? throw new McpException("Invalid or revoked API key.");
    }
}
