using LogCarverGuard.Core;
using LogCarverGuard.Local;
using LogCarverGuard.Server;
using LogCarverGuard.Server.Tools;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

// Only real environment variables configure this host. The default builder
// would also read appsettings.json from the current directory and the
// command line, so a repository that ships its own appsettings.json could
// quietly change the allow-lists of a tool launched from inside it.
var builder = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings { DisableDefaults = true });
builder.Configuration.AddEnvironmentVariables();

// stdout is the MCP protocol channel - anything else written there corrupts it.
builder.Logging.AddConsole(o => o.LogToStandardErrorThreshold = LogLevel.Trace);

LocalSettings settings;
SqliteAuditSink auditSink;
try
{
    settings = LocalSettings.Read(builder.Configuration);

    try
    {
        string? auditDirectory = Path.GetDirectoryName(settings.AuditDbPath);
        if (!string.IsNullOrEmpty(auditDirectory))
            Directory.CreateDirectory(auditDirectory);

        auditSink = new SqliteAuditSink(settings.AuditDbPath);

        // The log holds full SQL text, literals included: keep it to the user.
        if (!OperatingSystem.IsWindows() && File.Exists(settings.AuditDbPath))
            File.SetUnixFileMode(settings.AuditDbPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }
    catch (Exception ex)
    {
        throw new InvalidOperationException(
            $"Cannot use the audit log at '{settings.AuditDbPath}' (LOGCARVERGUARD_AUDIT_DB_PATH): {ex.Message}", ex);
    }
}
catch (Exception ex)
{
    Console.Error.WriteLine($"LogCarverGuard.Local could not start: {ex.Message}");
    return 1;
}

var configuration = builder.Configuration;
var guardPolicy = new GuardPolicy(
    GuardPolicy.ParseList(configuration["LOGCARVERGUARD_TRUNCATE_ALLOWLIST"]),
    GuardPolicy.ParseList(configuration["LOGCARVERGUARD_EXEC_WHITELIST"]),
    GuardPolicy.ParseList(configuration["LOGCARVERGUARD_ALTER_DROP_COLUMN_ALLOWLIST"]),
    settings.ReadOnly);

builder.Services.AddSingleton(guardPolicy);
builder.Services.AddSingleton<ICallerSession>(new LocalCallerSession(settings.ConnectionString));
builder.Services.AddSingleton(_ => auditSink);
builder.Services.AddSingleton<IAuditSink>(sp => sp.GetRequiredService<SqliteAuditSink>());
builder.Services
    .AddMcpServer()
    .WithStdioServerTransport()
    .WithTools<SqlTools>();

await builder.Build().RunAsync();
return 0;
