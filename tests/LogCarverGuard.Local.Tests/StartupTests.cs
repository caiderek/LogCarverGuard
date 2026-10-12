using System.Diagnostics;

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
