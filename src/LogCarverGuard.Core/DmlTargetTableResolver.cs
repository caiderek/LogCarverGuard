using Microsoft.SqlServer.TransactSql.ScriptDom;

namespace LogCarverGuard.Core;

/// <summary>
/// Database is null for an ordinary two-part name ("schema.table") - the
/// statement runs against whatever database the connection is currently in,
/// so there's nothing to switch to. It's populated only for an explicit
/// three-part name ("database.schema.table"), which is the one case where a
/// consumer has to look in a database other than the default one.
/// </summary>
public readonly record struct SchemaTable(string Schema, string Table, string? Database = null);

/// <summary>
/// Finds the first INSERT/UPDATE/DELETE target table in a SQL batch, so
/// GuardedSqlExecutor knows which table a write targets (reported to
/// execution observers) and which statements to run inside its own
/// transaction.
///
/// Only resolves a direct NamedTableReference (ordinary "INSERT INTO
/// schema.table" / "UPDATE schema.table" / "DELETE FROM schema.table").
///
/// Known limitation, not solved here: "WITH cte AS (...) UPDATE cte SET
/// ..." resolves to the literal identifier ("dbo.cte"), not the CTE's real
/// underlying table - this isn't distinguished from an ordinary table name
/// at this level. Left unsolved deliberately rather than guessed at,
/// because it degrades safely: a nonexistent "dbo.cte" simply resolves to
/// nothing, which is an honest "couldn't resolve" outcome, not a silently
/// wrong one.
/// </summary>
public static class DmlTargetTableResolver
{
    public static SchemaTable? ResolvePrimaryTarget(string sql)
    {
        var parser = new TSql170Parser(initialQuotedIdentifiers: true);
        using var reader = new StringReader(sql);
        var fragment = parser.Parse(reader, out var errors);
        if (errors.Count > 0)
            return null;

        var visitor = new TargetVisitor();
        fragment.Accept(visitor);
        return visitor.Target;
    }

    private sealed class TargetVisitor : TSqlFragmentVisitor
    {
        public SchemaTable? Target { get; private set; }

        public override void Visit(InsertStatement node) =>
            Target ??= ResolveNamedTable(node.InsertSpecification?.Target);

        public override void Visit(UpdateStatement node) =>
            Target ??= ResolveNamedTable(node.UpdateSpecification?.Target);

        public override void Visit(DeleteStatement node) =>
            Target ??= ResolveNamedTable(node.DeleteSpecification?.Target);

        private static SchemaTable? ResolveNamedTable(TableReference? target)
        {
            if (target is not NamedTableReference named) return null;
            if (named.SchemaObject?.BaseIdentifier?.Value is not { } table) return null;
            string schema = named.SchemaObject.SchemaIdentifier?.Value ?? "dbo";
            string? database = named.SchemaObject.DatabaseIdentifier?.Value;
            return new SchemaTable(schema, table, database);
        }
    }
}
