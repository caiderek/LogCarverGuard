using LogCarverGuard.Core;
using LogCarverGuard.Local;
using LogCarverGuard.Server;
using LogCarverGuard.Server.Tools;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

var builder = Host.CreateApplicationBuilder(args);

// stdout is the MCP protocol channel - anything else written there corrupts it.
builder.Logging.ClearProviders();
builder.Logging.AddConsole(o => o.LogToStandardErrorThreshold = LogLevel.Trace);

LocalSettings settings;
try
{
    settings = LocalSettings.Read(builder.Configuration);
}
catch (Exception ex) when (ex is InvalidOperationException or IOException)
{
    Console.Error.WriteLine(ex.Message);
    return 1;
}

string? auditDirectory = Path.GetDirectoryName(settings.AuditDbPath);
if (!string.IsNullOrEmpty(auditDirectory))
    Directory.CreateDirectory(auditDirectory);

var configuration = builder.Configuration;
var guardPolicy = new GuardPolicy(
    GuardPolicy.ParseList(configuration["LOGCARVERGUARD_TRUNCATE_ALLOWLIST"]),
    GuardPolicy.ParseList(configuration["LOGCARVERGUARD_EXEC_WHITELIST"]),
    GuardPolicy.ParseList(configuration["LOGCARVERGUARD_ALTER_DROP_COLUMN_ALLOWLIST"]),
    settings.ReadOnly);

builder.Services.AddSingleton(guardPolicy);
builder.Services.AddSingleton<ICallerSession>(new LocalCallerSession(settings.ConnectionString));
builder.Services.AddSingleton(_ => new SqliteAuditSink(settings.AuditDbPath));
builder.Services.AddSingleton<IAuditSink>(sp => sp.GetRequiredService<SqliteAuditSink>());
builder.Services
    .AddMcpServer()
    .WithStdioServerTransport()
    .WithTools<SqlTools>();

await builder.Build().RunAsync();
return 0;
