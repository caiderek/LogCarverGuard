using System.Diagnostics;
using System.Reflection;

namespace LogCarverGuard.Cli.Tests;

internal readonly record struct CliResult(int ExitCode, string StdOut, string StdErr);

/// <summary>
/// Runs the real built LogCarverGuard.Cli.dll as a child `dotnet` process
/// and captures its exit code and output. The CLI's top-level
/// statements compile into compiler-generated methods, so there is no in-process
/// seam to call directly. This CLI is plain framework-dependent (no AOT /
/// win-x64 publish; it targets Linux), so it is invoked via
/// `dotnet <dll>` rather than a native per-RID exe, and it has no license
/// file or temp-folder state to isolate - every test passes its own
/// --apikeys-db path explicitly, which is isolation enough.
/// </summary>
internal static class CliRunner
{
    public static readonly string DllPath = ResolveDllPath();

    public static CliResult Run(params string[] args)
    {
        var psi = new ProcessStartInfo("dotnet")
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        psi.ArgumentList.Add(DllPath);
        foreach (var arg in args)
            psi.ArgumentList.Add(arg);

        using var process = Process.Start(psi) ?? throw new InvalidOperationException("Failed to start dotnet.");
        Task<string> stdOutTask = process.StandardOutput.ReadToEndAsync();
        Task<string> stdErrTask = process.StandardError.ReadToEndAsync();

        if (!process.WaitForExit(30_000))
        {
            process.Kill(entireProcessTree: true);
            throw new TimeoutException($"'dotnet {DllPath} {string.Join(' ', args)}' did not exit within 30s.");
        }

        return new CliResult(process.ExitCode, stdOutTask.GetAwaiter().GetResult(), stdErrTask.GetAwaiter().GetResult());
    }

    private static string ResolveDllPath()
    {
        string? path = Assembly.GetExecutingAssembly()
            .GetCustomAttributes<AssemblyMetadataAttribute>()
            .FirstOrDefault(a => a.Key == "CliDllPath")?.Value;

        if (string.IsNullOrEmpty(path))
            throw new InvalidOperationException("CliDllPath assembly metadata was not set - check LogCarverGuard.Cli.Tests.csproj.");

        string fullPath = Path.GetFullPath(path);
        if (!File.Exists(fullPath))
            throw new FileNotFoundException(
                $"LogCarverGuard.Cli.dll not found at '{fullPath}'. Build the project first.", fullPath);

        return fullPath;
    }
}
