using Microsoft.Data.SqlClient;
using ModelContextProtocol.Client;

namespace LogCarverGuard.Local.Tests;

/// <summary>
/// Real SQL Server plus the real local host as a child process over stdio.
/// The sandbox database carries the "LogCarverGuard_" prefix so this can
/// never touch an unrelated database.
/// </summary>
public sealed class LocalFixture : IAsyncLifetime
{
    public const string DatabaseName = "LogCarverGuard_LocalTests";
    private const string Master = "Server=localhost;Database=master;Integrated Security=true;TrustServerCertificate=true";
    public static string DatabaseConnection => $"Server=localhost;Database={DatabaseName};Integrated Security=true;TrustServerCertificate=true";

    public string AuditDbPath { get; } = Path.Combine(Path.GetTempPath(), $"lcg-local-audit-{Guid.NewGuid():N}.db");
    public string ReadOnlyAuditDbPath { get; } = Path.Combine(Path.GetTempPath(), $"lcg-local-audit-ro-{Guid.NewGuid():N}.db");

    public McpClient Client { get; private set; } = null!;
    public McpClient ReadOnlyClient { get; private set; } = null!;

    public async Task InitializeAsync()
    {
        AssertSafeName(DatabaseName);
        await DropAsync();
        await ExecAsync(Master, $"CREATE DATABASE [{DatabaseName}];");
        await ExecAsync(DatabaseConnection, SeedSql);

        Client = await StartAsync(AuditDbPath, readOnly: false);
        ReadOnlyClient = await StartAsync(ReadOnlyAuditDbPath, readOnly: true);
    }

    public async Task DisposeAsync()
    {
        if (Client is not null) await Client.DisposeAsync();
        if (ReadOnlyClient is not null) await ReadOnlyClient.DisposeAsync();
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        foreach (var path in new[] { AuditDbPath, ReadOnlyAuditDbPath })
        {
            try { if (File.Exists(path)) File.Delete(path); } catch (IOException) { }
        }
        await DropAsync();
    }

    private const string SeedSql = """
        IF OBJECT_ID('dbo.Copy') IS NOT NULL DROP TABLE dbo.Copy;
        IF OBJECT_ID('dbo.Orders') IS NOT NULL DROP TABLE dbo.Orders;
        CREATE TABLE dbo.Orders (Id INT NOT NULL PRIMARY KEY, Customer NVARCHAR(50) NOT NULL, Status NVARCHAR(20) NOT NULL);
        INSERT dbo.Orders VALUES (1, N'Wang Xiaoming', 'Pending'), (2, N'Alice', 'Shipped'), (3, N'Bob', 'Pending');
        """;

    /// <summary>Puts the data back, so no test depends on which one ran before it.</summary>
    public Task ResetAsync() => ExecAsync(DatabaseConnection, SeedSql);

    private static async Task<McpClient> StartAsync(string auditDbPath, bool readOnly)
    {
        var env = new Dictionary<string, string?>
        {
            ["LOGCARVERGUARD_CONNECTION_STRING"] = DatabaseConnection,
            ["LOGCARVERGUARD_AUDIT_DB_PATH"] = auditDbPath,
        };
        if (readOnly) env["LOGCARVERGUARD_READ_ONLY"] = "true";

        var transport = new StdioClientTransport(new StdioClientTransportOptions
        {
            Name = readOnly ? "logcarverguard-local-ro" : "logcarverguard-local",
            Command = "dotnet",
            Arguments = [ServerDllPath()],
            EnvironmentVariables = env,
        });
        return await McpClient.CreateAsync(transport);
    }

    public static string ServerDllPath()
    {
        // .../tests/LogCarverGuard.Local.Tests/bin/<Config>/net10.0/
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        string config = dir.Parent!.Name;
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "LogCarverGuard.slnx")))
            dir = dir.Parent;
        if (dir is null)
            throw new InvalidOperationException("Could not find the repository root (LogCarverGuard.slnx).");

        string path = Path.Combine(dir.FullName, "src", "LogCarverGuard.Local", "bin", config, "net10.0", "LogCarverGuard.Local.dll");
        return File.Exists(path) ? path : throw new FileNotFoundException("Local host build output not found.", path);
    }

    private static async Task DropAsync()
    {
        AssertSafeName(DatabaseName);
        await ExecAsync(Master, $"""
            IF DB_ID(N'{DatabaseName}') IS NOT NULL
            BEGIN
                ALTER DATABASE [{DatabaseName}] SET SINGLE_USER WITH ROLLBACK IMMEDIATE;
                DROP DATABASE [{DatabaseName}];
            END
            """);
    }

    private static async Task ExecAsync(string connectionString, string sql)
    {
        await using var connection = new SqlConnection(connectionString);
        await connection.OpenAsync();
        await using var command = new SqlCommand(sql, connection) { CommandTimeout = 60 };
        await command.ExecuteNonQueryAsync();
    }

    private static void AssertSafeName(string name)
    {
        if (!name.StartsWith("LogCarverGuard_", StringComparison.Ordinal))
            throw new InvalidOperationException($"Refusing to touch '{name}': test databases must start with 'LogCarverGuard_'.");
    }
}

[CollectionDefinition("Local")]
public sealed class LocalCollection : ICollectionFixture<LocalFixture>;
