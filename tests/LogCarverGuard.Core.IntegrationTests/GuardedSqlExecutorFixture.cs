using Microsoft.Data.SqlClient;
using Xunit;

namespace LogCarverGuard.Core.IntegrationTests;

/// <summary>
/// Disposable sandbox database for the real-SQL-Server tests - kept under
/// its own "LogCarverGuard_" prefix so these tests can never collide with
/// or wipe an unrelated database on the same instance.
/// </summary>
public sealed class GuardedSqlExecutorFixture : IAsyncLifetime
{
    private const string DatabaseName = "LogCarverGuard_IntegrationTests";
    private const string MasterConnectionString = "Server=localhost;Database=master;Integrated Security=true;TrustServerCertificate=true;";

    public string ConnectionString { get; } =
        $"Server=localhost;Database={DatabaseName};Integrated Security=true;TrustServerCertificate=true;";

    public const string TableName = "dbo.GuardTest";
    public const string ParentTableName = "dbo.GuardParent";

    /// <summary>
    /// What ImpersonatedConnectionFactory's tests use as "the proxy's single
    /// service account" - in this sandbox it's the same Windows-integrated
    /// connection as everything else, since what's actually under test is
    /// EXECUTE AS LOGIN's effect, not how the service account itself
    /// authenticates.
    /// </summary>
    public string ServiceAccountConnectionString => ConnectionString;

    public const string RestrictedLoginName = "LogCarverGuard_RestrictedTestLogin";
    private const string RestrictedLoginPassword = "LogCarverGuard_Test_P@ssw0rd_2026!";

    public async Task InitializeAsync()
    {
        AssertSafeDatabaseName(DatabaseName);

        await using (var master = new SqlConnection(MasterConnectionString))
        {
            await master.OpenAsync();
            await DropIfExistsAsync(master);
            await ExecAsync(master, $"CREATE DATABASE [{DatabaseName}];");

            await DropLoginIfExistsAsync(master);
            await ExecAsync(master, $"""
                CREATE LOGIN [{RestrictedLoginName}] WITH PASSWORD = '{RestrictedLoginPassword}', CHECK_POLICY = OFF;
                """);
        }

        await using var conn = new SqlConnection(ConnectionString);
        await conn.OpenAsync();

        await ExecAsync(conn, $"CREATE TABLE {TableName} (Id INT NOT NULL PRIMARY KEY, Name NVARCHAR(50) NULL);");
        await ExecAsync(conn, $"INSERT INTO {TableName} (Id, Name) VALUES (1, 'seed');");
        await ExecAsync(conn, $"""
            CREATE TABLE {ParentTableName} (Id INT NOT NULL PRIMARY KEY, Name NVARCHAR(50) NULL);
            INSERT INTO {ParentTableName} (Id, Name) VALUES (1, 'ParentRow');
            """);

        // Deliberately narrow: SELECT+UPDATE on GuardTest only, nothing on
        // GuardParent - proves EXECUTE AS LOGIN's permission checks follow
        // the impersonated login, not the service account that opened the
        // connection (which is sysadmin in this dev sandbox).
        await ExecAsync(conn, $"""
            CREATE USER [{RestrictedLoginName}] FOR LOGIN [{RestrictedLoginName}];
            GRANT SELECT, UPDATE ON {TableName} TO [{RestrictedLoginName}];
            """);
    }

    public async Task DisposeAsync()
    {
        await using var master = new SqlConnection(MasterConnectionString);
        await master.OpenAsync();
        await DropIfExistsAsync(master);
        await DropLoginIfExistsAsync(master);
    }

    private static async Task DropLoginIfExistsAsync(SqlConnection master)
    {
        await ExecAsync(master, $"""
            IF SUSER_ID('{RestrictedLoginName}') IS NOT NULL DROP LOGIN [{RestrictedLoginName}];
            """);
    }

    private static async Task DropIfExistsAsync(SqlConnection master)
    {
        AssertSafeDatabaseName(DatabaseName);
        await ExecAsync(master, $"""
            IF DB_ID('{DatabaseName}') IS NOT NULL
            BEGIN
                ALTER DATABASE [{DatabaseName}] SET SINGLE_USER WITH ROLLBACK IMMEDIATE;
                DROP DATABASE [{DatabaseName}];
            END
            """);
    }

    private static async Task ExecAsync(SqlConnection conn, string sql)
    {
        await using var cmd = new SqlCommand(sql, conn);
        await cmd.ExecuteNonQueryAsync();
    }

    private static void AssertSafeDatabaseName(string name)
    {
        if (!name.StartsWith("LogCarverGuard_", StringComparison.Ordinal))
            throw new InvalidOperationException(
                $"Refusing to operate on database '{name}': integration tests may only touch databases prefixed 'LogCarverGuard_'.");
    }
}

[CollectionDefinition("GuardSqlServer")]
public sealed class GuardSqlServerCollection : ICollectionFixture<GuardedSqlExecutorFixture>;
