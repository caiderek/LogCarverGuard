using LogCarverGuard.Core;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.SqlClient;

namespace LogCarverGuard.Server.Tests;

/// <summary>
/// Hosts the free composition (LogCarverGuard.Server) in-process against a
/// real local SQL Server sandbox database, with the same shape a production
/// install has: the proxy's service account is a plain SQL login that is NOT
/// sysadmin and has nothing but IMPERSONATE on the one login the API key maps
/// to - so it must work with no elevated rights at all.
///
/// Everything it creates is prefixed "LogCarverGuard_" (the safety convention
/// the other test projects use).
/// </summary>
public sealed class ServerFixture : WebApplicationFactory<Program>, IAsyncLifetime
{
    private const string DatabaseName = "LogCarverGuard_FreeServerTests";
    private const string MasterConnectionString = "Server=localhost;Database=master;Integrated Security=true;TrustServerCertificate=true;";
    private const string CallerLogin = "LogCarverGuard_FreeHostCaller";
    private const string ServiceLogin = "LogCarverGuard_FreeHostService";
    private const string Password = "LogCarverGuard_FreeHost_P@ssw0rd_2026!";

    public const string TableName = "dbo.FreeHostTest";
    public string RawApiKey { get; private set; } = null!;
    public string AuditDbPath { get; } = Path.Combine(Path.GetTempPath(), $"logcarverguard-freehost-audit-{Guid.NewGuid():N}.db");
    private readonly string _apiKeysDbPath = Path.Combine(Path.GetTempPath(), $"logcarverguard-freehost-apikeys-{Guid.NewGuid():N}.db");

    /// <summary>The proxy service account's own connection string (SQL auth, not sysadmin).</summary>
    public string ServiceConnectionString { get; } =
        $"Server=localhost;Database={DatabaseName};User Id={ServiceLogin};Password={Password};TrustServerCertificate=true;";

    public async Task InitializeAsync()
    {
        AssertSafeName(DatabaseName);

        await using (var master = new SqlConnection(MasterConnectionString))
        {
            await master.OpenAsync();
            await DropIfExistsAsync(master);
            await ExecAsync(master, $"CREATE DATABASE [{DatabaseName}];");
            // Service login first: it holds IMPERSONATE on the caller login, and a
            // login that has been granted a permission cannot be dropped.
            await DropLoginAsync(master, ServiceLogin);
            await DropLoginAsync(master, CallerLogin);
            await ExecAsync(master, $"CREATE LOGIN [{CallerLogin}] WITH PASSWORD = '{Password}', CHECK_POLICY = OFF;");
            await ExecAsync(master, $"CREATE LOGIN [{ServiceLogin}] WITH PASSWORD = '{Password}', CHECK_POLICY = OFF;");
            // The ONLY server-level right the service account gets.
            await ExecAsync(master, $"GRANT IMPERSONATE ON LOGIN::[{CallerLogin}] TO [{ServiceLogin}];");
        }

        await using (var conn = new SqlConnection(MasterConnectionString.Replace("Database=master", $"Database={DatabaseName}")))
        {
            await conn.OpenAsync();
            await ExecAsync(conn, $"CREATE TABLE {TableName} (Id INT NOT NULL PRIMARY KEY, Name NVARCHAR(50) NULL);");
            await ExecAsync(conn, $"INSERT INTO {TableName} (Id, Name) VALUES (1, 'seed'), (2, 'other');");
            await ExecAsync(conn, $"""
                CREATE USER [{CallerLogin}] FOR LOGIN [{CallerLogin}];
                GRANT SELECT, UPDATE, INSERT ON {TableName} TO [{CallerLogin}];
                CREATE USER [{ServiceLogin}] FOR LOGIN [{ServiceLogin}];
                """);
        }

        await using (var keyStore = new ApiKeyStore(_apiKeysDbPath))
        {
            RawApiKey = (await keyStore.IssueAsync("free-user", CallerLogin)).RawKey;
        }

        // The host reads its configuration inline at startup, so real process
        // environment variables are what reach it - which is also exactly how
        // the product is configured.
        Environment.SetEnvironmentVariable("LOGCARVERGUARD_SQLSERVER_CONNECTION_STRING", ServiceConnectionString);
        Environment.SetEnvironmentVariable("LOGCARVERGUARD_AUDIT_DB_PATH", AuditDbPath);
        Environment.SetEnvironmentVariable("LOGCARVERGUARD_APIKEYS_DB_PATH", _apiKeysDbPath);
    }

    /// <summary>Issues an additional key for the caller login, for tests that need to revoke one.</summary>
    public async Task<IssuedApiKey> IssueExtraKeyAsync()
    {
        await using var store = new ApiKeyStore(_apiKeysDbPath);
        return await store.IssueAsync("extra", CallerLogin);
    }

    public async Task RevokeKeyAsync(long id)
    {
        await using var store = new ApiKeyStore(_apiKeysDbPath);
        await store.RevokeAsync(id);
    }

    /// <summary>Puts the test table back to its seed rows, so no test depends on which ran before it.</summary>
    public async Task ResetTableAsync()
    {
        await using var conn = new SqlConnection(MasterConnectionString.Replace("Database=master", $"Database={DatabaseName}"));
        await conn.OpenAsync();
        await ExecAsync(conn, $"DELETE FROM {TableName}; INSERT INTO {TableName} (Id, Name) VALUES (1, 'seed'), (2, 'other');");
    }

    async Task IAsyncLifetime.DisposeAsync()
    {
        await base.DisposeAsync();

        // A pooled session under the service login would block DROP LOGIN.
        SqlConnection.ClearAllPools();

        await using var master = new SqlConnection(MasterConnectionString);
        await master.OpenAsync();
        await DropIfExistsAsync(master);
        await DropLoginAsync(master, ServiceLogin);
        await DropLoginAsync(master, CallerLogin);

        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        if (File.Exists(AuditDbPath)) File.Delete(AuditDbPath);
        if (File.Exists(_apiKeysDbPath)) File.Delete(_apiKeysDbPath);
    }

    private static async Task DropIfExistsAsync(SqlConnection master)
    {
        AssertSafeName(DatabaseName);
        await ExecAsync(master, $"""
            IF DB_ID('{DatabaseName}') IS NOT NULL
            BEGIN
                ALTER DATABASE [{DatabaseName}] SET SINGLE_USER WITH ROLLBACK IMMEDIATE;
                DROP DATABASE [{DatabaseName}];
            END
            """);
    }

    private static async Task DropLoginAsync(SqlConnection master, string login)
    {
        AssertSafeName(login);
        await ExecAsync(master, $"IF SUSER_ID('{login}') IS NOT NULL DROP LOGIN [{login}];");
    }

    private static async Task ExecAsync(SqlConnection conn, string sql)
    {
        await using var cmd = new SqlCommand(sql, conn);
        await cmd.ExecuteNonQueryAsync();
    }

    private static void AssertSafeName(string name)
    {
        if (!name.StartsWith("LogCarverGuard_", StringComparison.Ordinal))
            throw new InvalidOperationException($"Refusing to touch '{name}': test objects must start with 'LogCarverGuard_'.");
    }
}

[CollectionDefinition("Server")]
public sealed class ServerCollection : ICollectionFixture<ServerFixture>;
