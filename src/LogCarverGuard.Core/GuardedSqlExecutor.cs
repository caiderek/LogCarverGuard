using Microsoft.Data.SqlClient;

namespace LogCarverGuard.Core;

public enum GuardedExecutionOutcome { Executed, Blocked }

public sealed record AuditRecord(
    DateTimeOffset At,
    string User,
    string Sql,
    GuardedExecutionOutcome Outcome,
    string? BlockReason,
    int? RowsAffected)
{
    /// <summary>
    /// Assigned by the audit sink at record time (not part of the primary
    /// constructor above, so existing positional-argument call sites don't
    /// need to change) - callers surface it so a later request can refer to
    /// this record.
    /// </summary>
    public long Id { get; init; }

    /// <summary>
    /// The rows a SELECT (or an OUTPUT-clause DML) returned, for the
    /// caller's immediate response only - deliberately NOT part of what
    /// <see cref="IAuditSink"/> persists: the audit log records that a
    /// statement ran, not a snapshot of arbitrary query results. Null for
    /// a statement that returned no result set (ordinary INSERT/UPDATE/
    /// DELETE/DDL); never null (possibly empty) for one that did.
    /// </summary>
    public IReadOnlyList<IReadOnlyDictionary<string, object?>>? ResultRows { get; init; }

    /// <summary>
    /// Text contributed by the registered <see cref="IExecutionObserver"/>s,
    /// appended to the confirmation of an executed write. Not persisted.
    /// </summary>
    public string? ObserverText { get; init; }

    /// <summary>
    /// How many rows the statement's first result set really contained.
    /// <see cref="ResultRows"/> holds at most
    /// <see cref="GuardedSqlExecutor.MaxCapturedResultRows"/> of them, so a
    /// huge SELECT cannot exhaust the proxy's memory.
    /// </summary>
    public int? ResultRowCount { get; init; }
}

/// <summary>
/// Where audit records go. In-memory for now (see LogCarverGuard project
/// status memory - dedicated persistent storage is a separate, not-yet-built
/// piece); this seam is what a real store will plug into later without
/// GuardedSqlExecutor itself changing.
/// </summary>
public interface IAuditSink
{
    /// <returns>The id the sink assigned this record - callers (e.g. the MCP tool) surface it so a later request can refer to this record.</returns>
    Task<long> RecordAsync(AuditRecord record, CancellationToken ct = default);
}

public sealed class InMemoryAuditSink : IAuditSink
{
    private readonly List<AuditRecord> _records = [];
    public IReadOnlyList<AuditRecord> Records => _records;

    public Task<long> RecordAsync(AuditRecord record, CancellationToken ct = default)
    {
        _records.Add(record);
        return Task.FromResult((long)_records.Count);
    }
}

/// <summary>
/// The write-path engine from 規劃書 流程圖②: evaluate the statement through
/// SqlStatementGuard first (blocking happens before the statement ever
/// reaches SQL Server, not after); if allowed, execute it for real, write
/// every outcome - blocked or executed - to the audit sink, and then tell
/// the optional <see cref="IExecutionObserver"/>s about the committed write.
///
/// Statements whose target table DmlTargetTableResolver can find are
/// wrapped in an explicit transaction so the committing transaction's own
/// CURRENT_TRANSACTION_ID() can be read from inside it, right before the
/// commit - an autocommit transaction closes before ADO.NET returns control.
/// That is skipped for anything that can't be anchored (DDL, SELECT,
/// TRUNCATE, EXEC), and for the rarer batch ExplicitTransactionCompatibility
/// flags as unsafe to wrap (BACKUP/RESTORE/RECONFIGURE/database-level DDL
/// appearing later in the same multi-statement batch as an anchored DML
/// statement). The wrap also makes a multi-statement DML batch all-or-nothing.
/// </summary>
public static class GuardedSqlExecutor
{
    /// <summary>Rows of a result set kept in memory; the rest are read, counted and discarded.</summary>
    public const int MaxCapturedResultRows = 1000;

    /// <param name="observers">Called after the statement committed and its audit record was written; null or empty = none.</param>
    public static async Task<AuditRecord> ExecuteAsync(
        SqlConnection executionConnection,
        string sql,
        string user,
        IReadOnlySet<(string Schema, string Table)> truncateAllowedTables,
        IReadOnlySet<(string Schema, string Procedure)> execWhitelist,
        IAuditSink auditSink,
        CancellationToken ct = default,
        IReadOnlySet<(string Schema, string Table)>? alterTableDropColumnAllowedTables = null,
        IReadOnlyList<IExecutionObserver>? observers = null,
        bool readOnly = false)
    {
        var verdict = SqlStatementGuard.Evaluate(
            sql, truncateAllowedTables, execWhitelist, alterTableDropColumnAllowedTables, readOnly);

        if (verdict.Decision == GuardDecision.Block)
        {
            var blocked = new AuditRecord(
                DateTimeOffset.UtcNow, user, sql, GuardedExecutionOutcome.Blocked,
                verdict.Reason, RowsAffected: null);
            long blockedId = await auditSink.RecordAsync(blocked, ct);
            return blocked with { Id = blockedId };
        }

        var anchorTable = DmlTargetTableResolver.ResolvePrimaryTarget(sql);

        // Only statements DmlTargetTableResolver can find a target for are
        // worth wrapping - anything else (DDL, SELECT, TRUNCATE, EXEC)
        // executes exactly as before.
        // ExplicitTransactionCompatibility is the narrower, rarer safety net
        // for a multi-statement batch that contains both such a DML
        // statement and something later in the same batch that can't run
        // inside an explicit transaction (e.g. "UPDATE t SET x=1; BACKUP
        // DATABASE ...;").
        bool wrapInOwnTransaction = anchorTable is not null && ExplicitTransactionCompatibility.CanWrap(sql);

        await using var command = executionConnection.CreateCommand();
        command.CommandText = sql;

        SqlTransaction? ownTransaction = null;
        if (wrapInOwnTransaction)
        {
            ownTransaction = (SqlTransaction)await executionConnection.BeginTransactionAsync(ct);
            command.Transaction = ownTransaction;
        }

        // ExecuteReaderAsync (not ExecuteNonQueryAsync, the original choice)
        // so a SELECT's rows are actually available to return - found for
        // real 2026-10-02 via stress testing that execute_sql could not
        // return query results at all (ExecuteNonQueryAsync always returns
        // -1 and discards any result set), which meant an AI agent calling
        // this tool to read data got nothing back, not even for `SELECT 1`.
        // Only the FIRST result set's rows are captured (a known, simple
        // v1 choice - multi-statement batches that return more than one
        // result set are a rarer shape than "run one query, get its rows"),
        // but every result set is still drained so RecordsAffected comes
        // back correct for ordinary multi-statement DML batches.
        IReadOnlyList<IReadOnlyDictionary<string, object?>>? resultRows = null;
        int? resultRowCount = null;
        int rowsAffected;
        long? xactId = null;
        try
        {
            await using (var reader = await command.ExecuteReaderAsync(ct))
            {
                if (reader.FieldCount > 0)
                {
                    string[] columnNames = [.. Enumerable.Range(0, reader.FieldCount).Select(reader.GetName)];
                    var rows = new List<IReadOnlyDictionary<string, object?>>();
                    int totalRows = 0;
                    while (await reader.ReadAsync(ct))
                    {
                        totalRows++;
                        if (rows.Count >= MaxCapturedResultRows)
                            continue;

                        var row = new Dictionary<string, object?>(columnNames.Length);
                        for (int i = 0; i < columnNames.Length; i++)
                            row[columnNames[i]] = await reader.IsDBNullAsync(i, ct) ? null : reader.GetValue(i);
                        rows.Add(row);
                    }
                    resultRows = rows;
                    resultRowCount = totalRows;
                }

                while (await reader.NextResultAsync(ct)) { /* drain remaining result sets */ }
                rowsAffected = reader.RecordsAffected;
            }

            if (ownTransaction is not null)
            {
                // A separate command on the same transaction, not appended
                // to the caller's own SQL text - avoids colliding with the
                // "return the caller's first result set" logic just above
                // (which would otherwise have to account for an extra,
                // caller-invisible trailing result set) and avoids any
                // SQL-text-concatenation edge case (caller SQL ending in a
                // line comment, missing a trailing semicolon, etc).
                await using var idCommand = new SqlCommand("SELECT CURRENT_TRANSACTION_ID();", executionConnection, ownTransaction);
                xactId = (long?)await idCommand.ExecuteScalarAsync(ct);
                await ownTransaction.CommitAsync(ct);
            }
        }
        finally
        {
            // Disposing an already-committed transaction is a no-op; disposing
            // one that never committed (the write itself threw, or the
            // CURRENT_TRANSACTION_ID()/commit step above threw) rolls it back.
            // No catch block here deliberately - the caller's own SqlException
            // must propagate completely unchanged, not wrapped or replaced by
            // a transaction-related error from this cleanup.
            if (ownTransaction is not null)
                await ownTransaction.DisposeAsync();
        }

        // The statement above already committed for real. The audit record is
        // written FIRST, before any observer runs: a write with zero audit
        // trail is the one failure mode this project treats as unacceptable,
        // and a slow or failing observer must never be able to cause it.
        var executed = new AuditRecord(
            DateTimeOffset.UtcNow, user, sql, GuardedExecutionOutcome.Executed,
            BlockReason: null, rowsAffected)
        { ResultRows = resultRows, ResultRowCount = resultRowCount };
        long executedId = await auditSink.RecordAsync(executed, ct);
        executed = executed with { Id = executedId };

        if (observers is not { Count: > 0 })
            return executed;

        var statement = new ExecutedStatement(
            executedId, user, sql, anchorTable, xactId, rowsAffected, verdict.AllowedByAllowList, executionConnection);
        var texts = new List<string>();
        foreach (var observer in observers)
        {
            try
            {
                if (await observer.ObserveAsync(statement, ct) is { } text)
                    texts.Add(text);
            }
            catch (Exception)
            {
                // The write and its audit record are already safe; say so
                // rather than failing a statement that did happen.
                texts.Add(" NOTE: a post-execution extension failed; the statement was executed and audited.");
            }
        }

        return texts.Count == 0 ? executed : executed with { ObserverText = string.Concat(texts) };
    }
}
