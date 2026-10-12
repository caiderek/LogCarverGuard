using Microsoft.Data.Sqlite;
using Microsoft.Data.SqlClient;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;

namespace LogCarverGuard.Local.Tests;

[Collection("Local")]
public class LocalHostTests(LocalFixture fixture) : IAsyncLifetime
{
    public Task InitializeAsync() => fixture.ResetAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    private static string TextOf(CallToolResult result) =>
        string.Concat(result.Content.OfType<TextContentBlock>().Select(c => c.Text));

    private static async Task<CallToolResult> ExecuteAsync(McpClient client, string sql) =>
        await client.CallToolAsync("execute_sql", new Dictionary<string, object?> { ["sql"] = sql });

    private static long AuditCount(string auditDbPath, string where)
    {
        if (!File.Exists(auditDbPath)) return 0;
        using var connection = new SqliteConnection($"Data Source={auditDbPath};Mode=ReadOnly");
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = $"SELECT COUNT(*) FROM AuditRecords WHERE {where};";
        return Convert.ToInt64(command.ExecuteScalar());
    }

    private static async Task<long> OrdersAsync(string where)
    {
        await using var connection = new SqlConnection(LocalFixture.DatabaseConnection);
        await connection.OpenAsync();
        await using var command = new SqlCommand($"SELECT COUNT(*) FROM dbo.Orders WHERE {where};", connection);
        return Convert.ToInt64(await command.ExecuteScalarAsync());
    }

    [Fact]
    public async Task OnlyExecuteSql_IsExposed()
    {
        var tools = await fixture.Client.ListToolsAsync();

        Assert.Equal(["execute_sql"], tools.Select(t => t.Name).ToArray());
    }

    [Fact]
    public async Task Select_ReturnsRows()
    {
        var result = await ExecuteAsync(fixture.Client, "SELECT Id, Customer FROM dbo.Orders ORDER BY Id;");

        var text = TextOf(result);
        Assert.NotEqual(true, result.IsError);
        Assert.Contains("Query returned 3 rows", text);
        Assert.Contains("Customer=Wang Xiaoming", text);
    }

    [Fact]
    public async Task DropTable_IsBlocked_AndTheBlockIsAudited()
    {
        long before = AuditCount(fixture.AuditDbPath, "Outcome = 'Blocked'");

        var result = await ExecuteAsync(fixture.Client, "DROP TABLE dbo.Orders;");

        Assert.StartsWith("BLOCKED:", TextOf(result));
        Assert.Equal(3, await OrdersAsync("1 = 1"));
        Assert.Equal(before + 1, AuditCount(fixture.AuditDbPath, "Outcome = 'Blocked'"));
    }

    [Fact]
    public async Task Update_IsExecuted_AndAuditedUnderTheLocalUser()
    {
        var result = await ExecuteAsync(fixture.Client, "UPDATE dbo.Orders SET Status = 'Shipped' WHERE Id = 1;");

        Assert.Contains("EXECUTED. Rows affected: 1.", TextOf(result));
        Assert.Equal(1, await OrdersAsync("Id = 1 AND Status = 'Shipped'"));
        string user = Environment.UserName.Replace("'", "''");
        Assert.True(AuditCount(fixture.AuditDbPath, $"Outcome = 'Executed' AND User = '{user}' AND Sql LIKE 'UPDATE%'") >= 1);
    }

    [Fact]
    public async Task SqlServerRejection_ReturnsItsReason()
    {
        var result = await ExecuteAsync(fixture.Client, "SELECT * FROM dbo.DoesNotExistAnywhere;");

        Assert.True(result.IsError);
        Assert.Contains("SQL Server rejected the statement", TextOf(result));
        Assert.Contains("DoesNotExistAnywhere", TextOf(result));
    }

    [Fact]
    public async Task ReadOnlyMode_AllowsQueries()
    {
        var result = await ExecuteAsync(fixture.ReadOnlyClient, "SELECT COUNT(*) AS N FROM dbo.Orders;");

        Assert.NotEqual(true, result.IsError);
        Assert.Contains("N=3", TextOf(result));
    }

    [Theory]
    [InlineData("UPDATE dbo.Orders SET Status = 'Hacked';")]
    [InlineData("DELETE FROM dbo.Orders;")]
    [InlineData("SELECT * INTO dbo.Copy FROM dbo.Orders;")]
    [InlineData("SELECT 1; DELETE FROM dbo.Orders;")]
    public async Task ReadOnlyMode_BlocksEverythingElse_AndLeavesTheDataAlone(string sql)
    {
        long blockedBefore = AuditCount(fixture.ReadOnlyAuditDbPath, "Outcome = 'Blocked'");

        var result = await ExecuteAsync(fixture.ReadOnlyClient, sql);

        Assert.StartsWith("BLOCKED:", TextOf(result));
        Assert.Contains("read-only", TextOf(result), StringComparison.OrdinalIgnoreCase);
        Assert.Equal(3, await OrdersAsync("1 = 1"));
        Assert.Equal(0, await OrdersAsync("Status = 'Hacked'"));
        Assert.Equal(blockedBefore + 1, AuditCount(fixture.ReadOnlyAuditDbPath, "Outcome = 'Blocked'"));
    }
}
