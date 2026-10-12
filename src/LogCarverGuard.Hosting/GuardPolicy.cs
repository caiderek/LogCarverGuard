using LogCarverGuard.Core;

namespace LogCarverGuard.Server;

/// <summary>
/// The admin-maintained allowlists SqlStatementGuard needs (規劃書 三-3), plus
/// a couple of other operator-level knobs that belong in the same place -
/// loaded once at startup from configuration/env vars, not per-request, since
/// these are operator decisions, not something an API key's owner can change
/// themselves.
/// </summary>
public sealed class GuardPolicy
{
    public IReadOnlySet<(string Schema, string Table)> TruncateAllowedTables { get; }
    public IReadOnlySet<(string Schema, string Procedure)> ExecWhitelist { get; }
    public IReadOnlySet<(string Schema, string Table)> AlterTableDropColumnAllowedTables { get; }

    public GuardPolicy(
        IReadOnlySet<(string Schema, string Table)> truncateAllowedTables,
        IReadOnlySet<(string Schema, string Procedure)> execWhitelist,
        IReadOnlySet<(string Schema, string Table)>? alterTableDropColumnAllowedTables = null)
    {
        TruncateAllowedTables = truncateAllowedTables;
        ExecWhitelist = execWhitelist;
        AlterTableDropColumnAllowedTables = alterTableDropColumnAllowedTables ?? new HashSet<(string, string)>();
    }

    /// <summary>
    /// Parses a comma-separated "schema.name,schema.name" list, defaulting
    /// the schema to "dbo" when omitted. Built with
    /// CaseInsensitiveNameTupleComparer (see that class's own doc comment) -
    /// SQL Server identifiers are case-insensitive under the default
    /// collation, so an admin-approved "dbo.Customers" must still match a
    /// statement that spells it "dbo.customers".
    /// </summary>
    public static IReadOnlySet<(string Schema, string Name)> ParseList(string? raw)
    {
        var result = new HashSet<(string, string)>(CaseInsensitiveNameTupleComparer.Instance);
        if (string.IsNullOrWhiteSpace(raw)) return result;

        foreach (var entry in raw.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var parts = entry.Split('.', 2);
            result.Add(parts.Length == 2 ? (Unquote(parts[0]), Unquote(parts[1])) : ("dbo", Unquote(parts[0])));
        }
        return result;
    }

    /// <summary>"[dbo]" and "\"dbo\"" mean dbo, the same way T-SQL reads them.</summary>
    private static string Unquote(string part)
    {
        part = part.Trim();
        if (part.Length >= 2 && part[0] == '[' && part[^1] == ']')
            return part[1..^1].Replace("]]", "]");
        if (part.Length >= 2 && part[0] == '"' && part[^1] == '"')
            return part[1..^1].Replace("\"\"", "\"");
        return part;
    }
}
