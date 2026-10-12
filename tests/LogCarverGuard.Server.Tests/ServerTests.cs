using LogCarverGuard.Server.Tools;
using Microsoft.Data.Sqlite;
using Microsoft.Data.SqlClient;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;

namespace LogCarverGuard.Server.Tests;

[Collection("Server")]
public class ServerTests(ServerFixture fixture) : IAsyncLifetime
{
    public Task InitializeAsync() => fixture.ResetTableAsync();

    public Task DisposeAsync() => Task.CompletedTask;

    private async Task<McpClient> ConnectAsync(string? apiKey = null)
    {
        var httpClient = fixture.CreateClient();
        var headers = new Dictionary<string, string> { [SqlTools.ApiKeyHeaderName] = apiKey ?? fixture.RawApiKey };
        var transport = new HttpClientTransport(
            new HttpClientTransportOptions { Endpoint = httpClient.BaseAddress!, AdditionalHeaders = headers },
            httpClient);
        return await McpClient.CreateAsync(transport);
    }

    private static string TextOf(CallToolResult result) =>
        string.Concat(result.Content.OfType<TextContentBlock>().Select(c => c.Text));

    private async Task<CallToolResult> ExecuteAsync(McpClient client, string sql) =>
        await client.CallToolAsync("execute_sql", new Dictionary<string, object?> { ["sql"] = sql });

    private async Task<long> ScalarAsync(string auditSql)
    {
        // The audit file is created by the first write, so a test that runs
        // before any other has nothing to read yet: that is zero rows.
        if (!File.Exists(fixture.AuditDbPath))
            return 0;

        // The host keeps its own connection to this SQLite file; a second
        // read-only connection is fine.
        await using var connection = new SqliteConnection($"Data Source={fixture.AuditDbPath};Mode=ReadOnly");
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = auditSql;
        return Convert.ToInt64(await command.ExecuteScalarAsync());
    }

    [Fact]
    public async Task OnlyExecuteSql_IsExposed()
    {
        await using var client = await ConnectAsync();

        var tools = await client.ListToolsAsync();

        var tool = Assert.Single(tools);
        Assert.Equal("execute_sql", tool.Name);
    }

    [Fact]
    public async Task Select_ReturnsRows()
    {
        await using var client = await ConnectAsync();

        var result = await ExecuteAsync(client, $"SELECT Id, Name FROM {ServerFixture.TableName} ORDER BY Id;");

        Assert.NotEqual(true, result.IsError);
        var text = TextOf(result);
        Assert.Contains("Query returned 2 rows", text);
        Assert.Contains("Name=seed", text);
    }

    [Fact]
    public async Task DropTable_IsBlocked_BeforeReachingTheDatabase()
    {
        await using var client = await ConnectAsync();

        var result = await ExecuteAsync(client, $"DROP TABLE {ServerFixture.TableName};");

        Assert.StartsWith("BLOCKED:", TextOf(result));
        var stillThere = await ExecuteAsync(client, $"SELECT COUNT(*) AS N FROM {ServerFixture.TableName};");
        Assert.Contains("N=2", TextOf(stillThere));
    }

    [Fact]
    public async Task Update_IsExecutedAndAudited()
    {
        await using var client = await ConnectAsync();

        var result = await ExecuteAsync(client, $"UPDATE {ServerFixture.TableName} SET Name = 'changed' WHERE Id = 1;");

        var text = TextOf(result);
        Assert.NotEqual(true, result.IsError);
        Assert.Contains("EXECUTED. Rows affected: 1.", text);
        Assert.Equal("EXECUTED. Rows affected: 1.", text.Substring(text.IndexOf("EXECUTED", StringComparison.Ordinal)));
        Assert.True(await ScalarAsync(
            "SELECT COUNT(*) FROM AuditRecords WHERE Outcome = 'Executed' AND Sql LIKE 'UPDATE%';") >= 1);
    }

    [Fact]
    public async Task CallersOwnPermissionsApply_DeleteIsDeniedByTheDatabase()
    {
        await using var client = await ConnectAsync();

        var result = await ExecuteAsync(client, $"DELETE FROM {ServerFixture.TableName} WHERE Id = 2;");

        // The agent must be told why, not just that "an error occurred".
        Assert.True(result.IsError);
        Assert.Contains("SQL Server rejected the statement", TextOf(result), StringComparison.OrdinalIgnoreCase);
        // SQL Server's own wording follows the server's language, but it always names the object.
        Assert.Contains("FreeHostTest", TextOf(result));
        var remaining = await ExecuteAsync(client, $"SELECT COUNT(*) AS N FROM {ServerFixture.TableName};");
        Assert.Contains("N=2", TextOf(remaining));
    }

    [Fact]
    public async Task ServiceAccount_IsNotSysadmin_YetEverythingAboveWorks()
    {
        await using var connection = new SqlConnection(fixture.ServiceConnectionString);
        await connection.OpenAsync();
        await using var command = new SqlCommand("SELECT IS_SRVROLEMEMBER('sysadmin');", connection);

        var isSysadmin = Convert.ToInt32(await command.ExecuteScalarAsync());

        Assert.Equal(0, isSysadmin);
    }

    [Fact]
    public async Task MissingOrInvalidKey_IsRejected()
    {
        await using var client = await ConnectAsync("lcg_this_key_was_never_issued");

        var result = await ExecuteAsync(client, "SELECT 1;");

        Assert.True(result.IsError);
    }

    [Fact]
    public async Task BlockedStatement_IsWrittenToTheAuditLog()
    {
        await using var client = await ConnectAsync();
        long before = await ScalarAsync("SELECT COUNT(*) FROM AuditRecords WHERE Outcome = 'Blocked';");

        var result = await ExecuteAsync(client, $"DROP TABLE {ServerFixture.TableName};");

        Assert.StartsWith("BLOCKED:", TextOf(result));
        Assert.Equal(before + 1, await ScalarAsync("SELECT COUNT(*) FROM AuditRecords WHERE Outcome = 'Blocked';"));
    }

    [Fact]
    public async Task RevokedKey_StopsWorking()
    {
        var extra = await fixture.IssueExtraKeyAsync();
        await using (var client = await ConnectAsync(extra.RawKey))
        {
            var ok = await ExecuteAsync(client, $"SELECT COUNT(*) AS N FROM {ServerFixture.TableName};");
            Assert.NotEqual(true, ok.IsError);
        }

        await fixture.RevokeKeyAsync(extra.Id);

        await using var revoked = await ConnectAsync(extra.RawKey);
        var result = await ExecuteAsync(revoked, "SELECT 1;");
        Assert.True(result.IsError);
    }

    [Fact]
    public async Task HugeSelect_ReportsTheTrueCount_ButShowsOnlyTheFirst100()
    {
        await using var client = await ConnectAsync();

        var result = await ExecuteAsync(client,
            "SELECT TOP (2500) ROW_NUMBER() OVER (ORDER BY (SELECT NULL)) AS N FROM sys.all_objects a CROSS JOIN sys.all_objects b;");

        var text = TextOf(result);
        Assert.Contains("Query returned 2500 rows", text);
        Assert.Contains("and 2400 more row(s), not shown", text);
    }
}
