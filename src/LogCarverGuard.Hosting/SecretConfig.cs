using Microsoft.Extensions.Configuration;

namespace LogCarverGuard.Server;

/// <summary>
/// Reads a secret value the way 規劃書 三-4 actually specifies: "透過環境變數
/// 或掛載的 secret 檔案". Until now Program.cs only implemented the env-var
/// half - this adds the mounted-file half, following the same "_FILE"
/// suffix convention Docker Compose secrets and most container-aware .NET
/// apps use (e.g. a Docker secret mounted at /run/secrets/x is referenced
/// as X_FILE=/run/secrets/x, keeping the actual secret out of the
/// environment variable listing itself, which process-inspection tools and
/// crash dumps can both expose more readily than a file an attacker would
/// need separate read access to).
/// </summary>
public static class SecretConfig
{
    /// <returns>The secret's value, read from the file named by "{name}_FILE" if that variable is set, otherwise from the "{name}" variable directly.</returns>
    public static string? Read(IConfiguration configuration, string name)
    {
        string? filePath = configuration[$"{name}_FILE"];
        if (!string.IsNullOrEmpty(filePath))
            return File.ReadAllText(filePath).Trim();

        return configuration[name];
    }
}
