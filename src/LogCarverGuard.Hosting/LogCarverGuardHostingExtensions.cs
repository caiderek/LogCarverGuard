using System.Net;
using LogCarverGuard.Core;
using LogCarverGuard.Server.Tools;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using ModelContextProtocol.AspNetCore;

namespace LogCarverGuard.Server;

/// <summary>Request-pipeline settings parsed once at startup and read back by <c>UseLogCarverGuard</c>.</summary>
public sealed record GuardHostOptions(ClientIpAllowlist ClientIpAllowlist, ForwardedHeadersOptions? ForwardedHeaders);

/// <summary>
/// Everything that makes up the free edition's server, as two calls so a
/// host (this one, or one that adds extensions on top) is a few lines.
/// </summary>
public static class LogCarverGuardHostingExtensions
{
    public const string ServiceAccountConnectionStringKey = "LOGCARVERGUARD_SQLSERVER_CONNECTION_STRING";

    /// <summary>
    /// 規劃書 三-4: the SQL Server service-account credential is injected via
    /// env var/mounted secret at startup, held only in memory, never written
    /// to disk. SecretConfig.Read supports both a direct env var and a
    /// *_FILE variable pointing at a mounted secret file.
    /// </summary>
    public static string ReadServiceAccountConnectionString(IConfiguration configuration) =>
        SecretConfig.Read(configuration, ServiceAccountConnectionStringKey)
            ?? throw new InvalidOperationException(
                $"{ServiceAccountConnectionStringKey} (or _FILE) is required - the proxy's single service account connection string.");

    public static string ReadAuditDbPath(IConfiguration configuration) =>
        configuration["LOGCARVERGUARD_AUDIT_DB_PATH"] ?? "logcarverguard-audit.db";

    public static WebApplicationBuilder AddLogCarverGuard(this WebApplicationBuilder builder)
    {
        var configuration = builder.Configuration;
        string serviceAccountConnectionString = ReadServiceAccountConnectionString(configuration);

        string auditDbPath = ReadAuditDbPath(configuration);
        string apiKeysDbPath = configuration["LOGCARVERGUARD_APIKEYS_DB_PATH"] ?? "logcarverguard-apikeys.db";

        var guardPolicy = new GuardPolicy(
            GuardPolicy.ParseList(configuration["LOGCARVERGUARD_TRUNCATE_ALLOWLIST"]),
            GuardPolicy.ParseList(configuration["LOGCARVERGUARD_EXEC_WHITELIST"]),
            GuardPolicy.ParseList(configuration["LOGCARVERGUARD_ALTER_DROP_COLUMN_ALLOWLIST"]));

        // Unset/empty = no restriction (see ClientIpAllowlist's own doc
        // comment for why that's the deliberate default). A malformed entry
        // throws at startup, not silently - fail loudly rather than quietly
        // leave the proxy wide open.
        var clientIpAllowlist = ClientIpAllowlist.Parse(configuration["LOGCARVERGUARD_ALLOWED_CLIENT_IPS"]);

        // LOGCARVERGUARD_ALLOWED_CLIENT_IPS checks context.Connection.RemoteIpAddress,
        // which is the directly-connected peer - behind a reverse proxy/ingress
        // that's always the proxy's own IP, never the real caller's. Opt-in and
        // off by default: only trust X-Forwarded-For when the operator
        // explicitly lists which immediate peers are allowed to set it -
        // blindly trusting the header from anyone would let any caller spoof
        // whatever IP it wants and walk straight through the allowlist.
        ForwardedHeadersOptions? forwardedHeadersOptions = null;
        string? trustedProxiesRaw = configuration["LOGCARVERGUARD_TRUSTED_PROXIES"];
        if (!string.IsNullOrWhiteSpace(trustedProxiesRaw))
        {
            forwardedHeadersOptions = new ForwardedHeadersOptions { ForwardedHeaders = ForwardedHeaders.XForwardedFor };
            foreach (var entry in trustedProxiesRaw.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                if (System.Net.IPNetwork.TryParse(entry, out var network))
                    forwardedHeadersOptions.KnownIPNetworks.Add(network);
                else if (IPAddress.TryParse(entry, out var address))
                    forwardedHeadersOptions.KnownProxies.Add(address);
                else
                    throw new InvalidOperationException(
                        $"LOGCARVERGUARD_TRUSTED_PROXIES has an entry that isn't a valid IP or CIDR range: '{entry}'.");
            }
        }

        var services = builder.Services;
        services.AddHttpContextAccessor();
        services.AddSingleton(guardPolicy);
        services.AddSingleton(new GuardHostOptions(clientIpAllowlist, forwardedHeadersOptions));
        services.AddSingleton(new ImpersonatedConnectionFactory(serviceAccountConnectionString));
        services.AddSingleton<CallerResolver>();

        // Factory-delegate registration (not AddSingleton(instance)) so the DI
        // container actually owns and disposes these on shutdown - it only
        // tracks and disposes singletons it creates itself, which left their
        // SQLite file handles open past host shutdown during testing.
        services.AddSingleton(_ => new ApiKeyStore(apiKeysDbPath));
        services.AddSingleton(_ => new SqliteAuditSink(auditDbPath));
        services.AddSingleton<IAuditSink>(sp => sp.GetRequiredService<SqliteAuditSink>());
        services.AddSingleton<IAuditReader>(sp => sp.GetRequiredService<SqliteAuditSink>());

        services.AddMcpServer()
            .WithTools<SqlTools>()
            .WithHttpTransport(options =>
            {
                // Each tool call authenticates and resolves its own SQL login
                // via the API key header - no cross-call session state is
                // needed, so stateless mode is both simpler and (per the SDK's
                // own guidance) the one that scales without session affinity.
                options.SessionMode = HttpServerSessionMode.Stateless;
            });

        return builder;
    }

    public static WebApplication UseLogCarverGuard(this WebApplication app)
    {
        var options = app.Services.GetRequiredService<GuardHostOptions>();

        // Must run before the IP-allowlist check below, so RemoteIpAddress
        // has already been rewritten to the real client's IP by the time
        // that check runs - only takes effect when LOGCARVERGUARD_TRUSTED_PROXIES
        // is set; otherwise RemoteIpAddress stays the direct peer.
        if (options.ForwardedHeaders is not null)
            app.UseForwardedHeaders(options.ForwardedHeaders);

        // Runs before auth, before routing, before anything else - a request
        // from a disallowed IP never even reaches the API-key check.
        // Independent of (and in addition to) whatever the host's firewall does.
        app.Use(async (context, next) =>
        {
            if (!options.ClientIpAllowlist.IsAllowed(context.Connection.RemoteIpAddress))
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                await context.Response.WriteAsync("Forbidden: this client IP is not in LOGCARVERGUARD_ALLOWED_CLIENT_IPS.");
                return;
            }
            await next();
        });

        app.MapMcp();
        return app;
    }
}
