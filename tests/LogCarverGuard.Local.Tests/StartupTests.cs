using System.Diagnostics;
using ModelContextProtocol.Client;

namespace LogCarverGuard.Local.Tests;

public class StartupTests
{
    private static async Task<(int ExitCode, string StdOut, string StdErr)> RunAsync(Dictionary<string, string?> env)
    {
        var info = new ProcessStartInfo("dotnet", $"\"{LocalFixture.ServerDllPath()}\"")
        {
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        // Start from a clean slate so the developer's own environment cannot leak in.
        foreach (var name in new[]
                 {
                     "LOGCARVERGUARD_CONNECTION_STRING", "LOGCARVERGUARD_CONNECTION_STRING_FILE",
                     "LOGCARVERGUARD_READ_ONLY", "LOGCARVERGUARD_AUDIT_DB_PATH",
                 })
            info.Environment.Remove(name);
        foreach (var (key, value) in env)
            info.Environment[key] = value;

        using var process = Process.Start(info)!;
        process.StandardInput.Close();
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        await process.WaitForExitAsync(cts.Token);
        return (process.ExitCode, await stdout, await stderr);
    }

    [Fact]
    public async Task MissingConnectionString_ExitsWithAClearMessageOnStderr()
    {
        var (exitCode, stdout, stderr) = await RunAsync([]);

        Assert.Equal(1, exitCode);
        Assert.Contains("LOGCARVERGUARD_CONNECTION_STRING", stderr);
        Assert.Equal("", stdout.Trim());
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("yes")]
    public async Task ReadOnlyValueThatIsBlankOrNotABoolean_FailsClosed(string value)
    {
        var (exitCode, _, stderr) = await RunAsync(new()
        {
            ["LOGCARVERGUARD_CONNECTION_STRING"] = "Server=localhost;Database=master;Integrated Security=true;TrustServerCertificate=true",
            ["LOGCARVERGUARD_READ_ONLY"] = value,
        });

        Assert.Equal(1, exitCode);
        Assert.Contains("LOGCARVERGUARD_READ_ONLY", stderr);
    }

    [Fact]
    public async Task UnwritableAuditPath_ExitsWithAClearMessage_NotAStackTrace()
    {
        // A path whose parent is an existing FILE cannot be created.
        string file = Path.Combine(Path.GetTempPath(), $"lcg-not-a-dir-{Guid.NewGuid():N}");
        await File.WriteAllTextAsync(file, "x");
        try
        {
            var (exitCode, _, stderr) = await RunAsync(new()
            {
                ["LOGCARVERGUARD_CONNECTION_STRING"] = "Server=localhost;Database=master;Integrated Security=true;TrustServerCertificate=true",
                ["LOGCARVERGUARD_AUDIT_DB_PATH"] = Path.Combine(file, "audit.db"),
            });

            Assert.Equal(1, exitCode);
            Assert.DoesNotContain("   at ", stderr);
            Assert.Contains("audit", stderr, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            File.Delete(file);
        }
    }

    [Fact]
    public async Task AppsettingsInTheWorkingDirectory_CannotChangeTheGuard()
    {
        string dir = Path.Combine(Path.GetTempPath(), $"lcg-cwd-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        await File.WriteAllTextAsync(Path.Combine(dir, "appsettings.json"),
            "{ \"LOGCARVERGUARD_TRUNCATE_ALLOWLIST\": \"dbo.NoSuchTable\" }");
        string audit = Path.Combine(dir, "audit.db");
        try
        {
            var transport = new StdioClientTransport(new StdioClientTransportOptions
            {
                Name = "local-cwd-test",
                Command = "dotnet",
                Arguments = [LocalFixture.ServerDllPath()],
                WorkingDirectory = dir,
                EnvironmentVariables = new Dictionary<string, string?>
                {
                    ["LOGCARVERGUARD_CONNECTION_STRING"] = LocalFixture.DatabaseConnection,
                    ["LOGCARVERGUARD_AUDIT_DB_PATH"] = audit,
                },
            });
            await using var client = await McpClient.CreateAsync(transport);

            var result = await client.CallToolAsync("execute_sql",
                new Dictionary<string, object?> { ["sql"] = "TRUNCATE TABLE dbo.NoSuchTable;" });

            string text = string.Concat(result.Content.OfType<ModelContextProtocol.Protocol.TextContentBlock>().Select(c => c.Text));
            Assert.StartsWith("BLOCKED:", text);
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            try { Directory.Delete(dir, true); } catch (IOException) { }
        }
    }

    [Fact]
    public async Task InvalidReadOnlyValue_ExitsWithAClearMessage()
    {
        var (exitCode, _, stderr) = await RunAsync(new()
        {
            ["LOGCARVERGUARD_CONNECTION_STRING"] = "Server=localhost;Database=master;Integrated Security=true;TrustServerCertificate=true",
            ["LOGCARVERGUARD_READ_ONLY"] = "maybe",
        });

        Assert.Equal(1, exitCode);
        Assert.Contains("LOGCARVERGUARD_READ_ONLY", stderr);
    }
}
