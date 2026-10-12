using Microsoft.SqlServer.TransactSql.ScriptDom;

namespace LogCarverGuard.Core;

/// <summary>
/// Decides whether a statement is safe to run inside the proxy's own
/// explicit transaction (see GuardedSqlExecutor's 2026-10-07 wrap-and-
/// capture fix for the wrong-transaction-anchor concurrency bug).
///
/// In practice this is a defense-in-depth safety net, not the primary
/// filter: GuardedSqlExecutor only ever wraps a statement when
/// DmlTargetTableResolver found an INSERT/UPDATE/DELETE anchor, which
/// already excludes every DDL/BACKUP/RESTORE/RECONFIGURE/SELECT/EXEC
/// statement on its own. This class exists for the rarer case of a
/// multi-statement batch that *does* contain an anchor-matching DML
/// statement but *also* contains something incompatible with an explicit
/// transaction later in the same batch (e.g. "UPDATE t SET x=1; BACKUP
/// DATABASE ...;") - DmlTargetTableResolver only looks for the first DML
/// target, so it would never notice.
///
/// The deny list below is grounded in a real spike against a live SQL
/// Server (2026-10-07, see this project's status memory): BACKUP inside an
/// explicit transaction fails with error 3021 ("Backup and restore
/// operations are not allowed within a transaction"); RECONFIGURE fails
/// with error 574 ("... statement cannot be used inside a user
/// transaction"). CREATE/ALTER/DROP DATABASE and full-text catalog/index
/// statements are included by the same well-documented SQL Server rule
/// (database-level DDL cannot run inside a user transaction) even though
/// they weren't each individually spiked.
/// </summary>
public static class ExplicitTransactionCompatibility
{
    public static bool CanWrap(string sql)
    {
        var parser = new TSql170Parser(initialQuotedIdentifiers: true);
        using var reader = new StringReader(sql);
        var fragment = parser.Parse(reader, out var errors);

        // Let the statement's own parse/syntax error surface naturally when
        // it actually runs, unwrapped, rather than this check guessing at
        // broken SQL.
        if (errors.Count > 0) return true;

        // A literal "GO" batch separator produces more than one TSqlBatch
        // here, even though it isn't valid mid-command T-SQL and SQL Server
        // itself will reject it the same way whether wrapped or not - skip
        // wrapping so that rejection isn't confused with a transaction
        // control error.
        if (fragment is TSqlScript { Batches.Count: > 1 }) return false;

        var visitor = new IncompatibilityVisitor();
        fragment.Accept(visitor);
        return !visitor.FoundIncompatibleStatement;
    }

    private sealed class IncompatibilityVisitor : TSqlFragmentVisitor
    {
        public bool FoundIncompatibleStatement { get; private set; }

        public override void Visit(BackupStatement node) => FoundIncompatibleStatement = true;
        public override void Visit(RestoreStatement node) => FoundIncompatibleStatement = true;
        public override void Visit(ReconfigureStatement node) => FoundIncompatibleStatement = true;
        public override void Visit(CreateDatabaseStatement node) => FoundIncompatibleStatement = true;
        public override void Visit(AlterDatabaseStatement node) => FoundIncompatibleStatement = true;
        public override void Visit(DropDatabaseStatement node) => FoundIncompatibleStatement = true;
        public override void Visit(CreateFullTextCatalogStatement node) => FoundIncompatibleStatement = true;
        public override void Visit(CreateFullTextIndexStatement node) => FoundIncompatibleStatement = true;

        // The caller's own transaction-control statements are blocked
        // outright by SqlStatementGuard (2026-10-07) before this is ever
        // reached, so no case for BEGIN/COMMIT/ROLLBACK/SAVE TRAN is needed
        // here - this is belt-and-suspenders only in case that guard rule
        // is ever relaxed without revisiting this file too.
        public override void Visit(BeginTransactionStatement node) => FoundIncompatibleStatement = true;
        public override void Visit(CommitTransactionStatement node) => FoundIncompatibleStatement = true;
        public override void Visit(RollbackTransactionStatement node) => FoundIncompatibleStatement = true;
        public override void Visit(SaveTransactionStatement node) => FoundIncompatibleStatement = true;
    }
}
