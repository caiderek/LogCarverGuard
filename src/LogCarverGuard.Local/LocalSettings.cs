using Microsoft.Extensions.Configuration;

namespace LogCarverGuard.Local;

public sealed record LocalSettings(string ConnectionString, string AuditDbPath, bool ReadOnly)
{
    public const string ConnectionStringKey = "LOGCARVERGUARD_CONNECTION_STRING";

    /// <summary>Reads the settings, or throws with a message that says what to fix.</summary>
    public static LocalSettings Read(IConfiguration configuration)
    {
        string? connectionString = ReadSecret(configuration, ConnectionStringKey);
        if (string.IsNullOrWhiteSpace(connectionString))
            throw new InvalidOperationException(
                $"{ConnectionStringKey} is not set (or {ConnectionStringKey}_FILE pointing at a file containing it). " +
                "Example: Server=localhost;Database=MyDb;Integrated Security=true;TrustServerCertificate=true");

        // A blank value must not become "Data Source=" (a throw-away temporary
        // database that silently loses the audit log), so blank means default.
        string? auditRaw = configuration["LOGCARVERGUARD_AUDIT_DB_PATH"];
        string auditDbPath = string.IsNullOrWhiteSpace(auditRaw)
            ? Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "LogCarverGuard", "audit.db")
            : auditRaw.Trim();

        bool readOnly = false;
        // Present-but-blank (for example an unexpanded variable in a client
        // config) is an error, not "off": the safe reading of an unclear
        // read-only setting is to refuse to start.
        string? readOnlyRaw = configuration["LOGCARVERGUARD_READ_ONLY"];
        if (readOnlyRaw is not null && !bool.TryParse(readOnlyRaw.Trim(), out readOnly))
            throw new InvalidOperationException(
                $"LOGCARVERGUARD_READ_ONLY must be true or false (got '{readOnlyRaw}').");

        return new LocalSettings(connectionString, auditDbPath, readOnly);
    }

    private static string? ReadSecret(IConfiguration configuration, string name)
    {
        string? filePath = configuration[$"{name}_FILE"];
        return string.IsNullOrEmpty(filePath) ? configuration[name] : File.ReadAllText(filePath).Trim();
    }
}
