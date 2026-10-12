namespace LogCarverGuard.Cli.Tests;

public sealed class CliSurfaceTests : IDisposable
{
    private readonly string _dbPath = Path.Combine(Path.GetTempPath(), $"logcarverguard-cli-test-{Guid.NewGuid():N}.db");

    public void Dispose()
    {
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        if (File.Exists(_dbPath)) File.Delete(_dbPath);
    }

    [Fact]
    public void NoArguments_PrintsUsage_ExitsZero()
    {
        var result = CliRunner.Run();
        Assert.Equal(0, result.ExitCode);
        Assert.Contains("Usage:", result.StdOut);
    }

    [Fact]
    public void UnknownCommand_ExitsNonZero_AndPrintsUsage()
    {
        var result = CliRunner.Run("frobnicate");
        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains("Unknown command", result.StdErr);
    }

    [Fact]
    public void IssueKey_WithoutRequiredFlags_ExitsNonZero()
    {
        var result = CliRunner.Run("issue-key", "--owner", "alice");
        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains("requires --owner", result.StdErr);
    }

    [Fact]
    public void RevokeKey_WithNonNumericId_ExitsNonZero()
    {
        var result = CliRunner.Run("revoke-key", "--id", "not-a-number", "--apikeys-db", _dbPath);
        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains("requires --id", result.StdErr);
    }

    [Fact]
    public void IssueKey_PrintsTheRawKeyOnce_AndThenAppearsInListKeys()
    {
        var issueResult = CliRunner.Run("issue-key", "--owner", "alice", "--login", "alice_sql_login", "--apikeys-db", _dbPath);
        Assert.Equal(0, issueResult.ExitCode);
        Assert.Contains("lcg_", issueResult.StdOut);
        Assert.Contains("Id 1", issueResult.StdOut);

        var listResult = CliRunner.Run("list-keys", "--apikeys-db", _dbPath);
        Assert.Equal(0, listResult.ExitCode);
        Assert.Contains("alice", listResult.StdOut);
        Assert.Contains("alice_sql_login", listResult.StdOut);
        Assert.Contains("active", listResult.StdOut);
        Assert.DoesNotContain("lcg_", listResult.StdOut); // the raw key itself must never be listed back
    }

    [Fact]
    public void RevokeKey_ThenListKeys_ShowsItAsRevoked()
    {
        CliRunner.Run("issue-key", "--owner", "alice", "--login", "alice_sql_login", "--apikeys-db", _dbPath);

        var revokeResult = CliRunner.Run("revoke-key", "--id", "1", "--apikeys-db", _dbPath);
        Assert.Equal(0, revokeResult.ExitCode);

        var secondRevokeResult = CliRunner.Run("revoke-key", "--id", "1", "--apikeys-db", _dbPath);
        Assert.NotEqual(0, secondRevokeResult.ExitCode);
        Assert.Contains("No active key", secondRevokeResult.StdErr);

        var listResult = CliRunner.Run("list-keys", "--apikeys-db", _dbPath);
        Assert.Contains("revoked", listResult.StdOut);
    }

    [Fact]
    public void ListKeys_OnAFreshDatabase_ReportsNoKeysIssuedYet()
    {
        var result = CliRunner.Run("list-keys", "--apikeys-db", _dbPath);
        Assert.Equal(0, result.ExitCode);
        Assert.Contains("No API keys issued yet.", result.StdOut);
    }

    [Fact]
    public void ApiKeysDbPath_FallsBackToTheEnvironmentVariable_WhenTheFlagIsOmitted()
    {
        var psi = new System.Diagnostics.ProcessStartInfo("dotnet")
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        psi.ArgumentList.Add(CliRunner.DllPath);
        psi.ArgumentList.Add("issue-key");
        psi.ArgumentList.Add("--owner");
        psi.ArgumentList.Add("alice");
        psi.ArgumentList.Add("--login");
        psi.ArgumentList.Add("alice_sql_login");
        psi.Environment["LOGCARVERGUARD_APIKEYS_DB_PATH"] = _dbPath;

        using var process = System.Diagnostics.Process.Start(psi)!;
        process.WaitForExit(30_000);

        Assert.Equal(0, process.ExitCode);
        Assert.True(File.Exists(_dbPath));
    }
}
