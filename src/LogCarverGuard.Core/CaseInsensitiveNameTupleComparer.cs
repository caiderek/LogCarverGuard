namespace LogCarverGuard.Core;

/// <summary>
/// Case-insensitive equality for a (schema, name) pair - SQL Server
/// identifiers are case-insensitive under the default collation, so an
/// admin-approved allowlist entry ("dbo.Customers") must still match
/// however an AI agent happens to capitalize it in the SQL text it
/// actually writes ("dbo.customers"). Use this to construct every
/// HashSet&lt;(string,string)&gt; that SqlStatementGuard checks a
/// resolved identifier against - TruncateAllowedTables, ExecWhitelist,
/// AlterTableDropColumnAllowedTables.
///
/// Deliberately lives on the set's own comparer, not as a normalization
/// step in the lookup code or in whatever builds the set - that way it
/// can't be silently bypassed by a caller that constructs the set a
/// different way than GuardPolicy.ParseList does. Found missing in
/// independent review 2026-10-04; the first fix attempt (lowercasing in
/// GuardPolicy.ParseList plus lowercasing the lookup key in
/// SqlStatementGuard) only worked for sets that went through ParseList -
/// a test building `new HashSet&lt;(string, string)&gt; { ("DBO", "Staging") }`
/// directly reproduced the exact same bug, which is what caught this.
/// </summary>
public sealed class CaseInsensitiveNameTupleComparer : IEqualityComparer<(string Schema, string Name)>
{
    public static readonly CaseInsensitiveNameTupleComparer Instance = new();

    public bool Equals((string Schema, string Name) x, (string Schema, string Name) y) =>
        string.Equals(x.Schema, y.Schema, StringComparison.OrdinalIgnoreCase)
        && string.Equals(x.Name, y.Name, StringComparison.OrdinalIgnoreCase);

    public int GetHashCode((string Schema, string Name) obj) =>
        HashCode.Combine(
            obj.Schema.ToUpperInvariant(),
            obj.Name.ToUpperInvariant());
}
