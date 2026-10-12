using System.ComponentModel;
using System.Text;
using LogCarverGuard.Core;
using Microsoft.Data.SqlClient;
using ModelContextProtocol;
using ModelContextProtocol.Server;

namespace LogCarverGuard.Server.Tools;

/// <summary>
/// The MCP tool an AI agent calls to read and write - 規劃書 流程圖②/③.
/// Who is calling, and on which connection, is the <see cref="ICallerSession"/>'s
/// business: the central service checks an API key header and impersonates
/// that person's login, the local host uses its configured connection.
///
/// Anything extra in the response of an executed write comes from the
/// registered <see cref="IExecutionObserver"/>s; with none, nothing is added.
/// </summary>
[McpServerToolType]
public sealed class SqlTools(
    ICallerSession callerSession,
    IAuditSink auditSink,
    GuardPolicy guardPolicy,
    IEnumerable<IExecutionObserver> observers)
{
    public const string ApiKeyHeaderName = "X-LogCarverGuard-Key";

    [McpServerTool(Name = "execute_sql"), Description(
        "Execute a SQL statement against the guarded database, under your own identity. " +
        "Ordinary INSERT/UPDATE/DELETE/ALTER TABLE run and are audited. DROP TABLE, " +
        "unapproved TRUNCATE, unapproved EXEC, and your own BEGIN/COMMIT/ROLLBACK TRAN statements " +
        "are blocked before they ever reach the database - if blocked, the reason is returned so " +
        "you can adjust and retry. A batch containing INSERT/UPDATE/DELETE runs in one transaction " +
        "that is rolled back if any statement fails; DDL, TRUNCATE and EXEC run as they are and are " +
        "not rolled back as part of a batch.")]
    public async Task<string> ExecuteSql(
        [Description("The SQL statement to execute.")] string sql,
        CancellationToken ct)
    {
        // The caller's own identity does the write, so SQL Server enforces
        // their actual GRANT/DENY. Any extra privileged work belongs to an
        // execution observer, which opens its own connection if it needs one.
        await using var caller = await callerSession.OpenAsync(ct);

        AuditRecord record;
        try
        {
            record = await GuardedSqlExecutor.ExecuteAsync(
                caller.Connection, sql, caller.Owner,
                guardPolicy.TruncateAllowedTables, guardPolicy.ExecWhitelist,
                auditSink, ct,
                alterTableDropColumnAllowedTables: guardPolicy.AlterTableDropColumnAllowedTables,
                observers: [.. observers],
                readOnly: guardPolicy.ReadOnly);
        }
        catch (SqlException ex)
        {
            // The statement was rejected by SQL Server itself under the
            // caller's own login (permission denied, syntax error, constraint
            // violation...). Say why, or an agent has nothing to adjust from
            // and just sees "An error occurred".
            throw new McpException("SQL Server rejected the statement: " + ex.Message);
        }

        return Format(record);
    }

    /// <summary>Response rows are capped for display, not truncated silently - a caller running a broad SELECT should see that it was capped, not assume this is everything.</summary>
    private const int MaxDisplayedRows = 100;

    private static string Format(AuditRecord record)
    {
        if (record.Outcome == GuardedExecutionOutcome.Blocked)
            return $"BLOCKED: {record.BlockReason}";

        if (record.ResultRows is { } rows)
            return FormatResultRows(record.Id, rows, record.ResultRowCount ?? rows.Count);

        var sb = new StringBuilder();
        sb.Append("Audit record Id: ").Append(record.Id).Append(". ");
        sb.Append("EXECUTED. Rows affected: ").Append(record.RowsAffected).Append('.');

        if (record.ObserverText is { } extra)
            sb.Append(extra);

        return sb.ToString();
    }

    private static string FormatResultRows(
        long auditId, IReadOnlyList<IReadOnlyDictionary<string, object?>> rows, int totalRows)
    {
        var sb = new StringBuilder();
        sb.Append("Audit record Id: ").Append(auditId).Append(". ");
        sb.Append("Query returned ").Append(totalRows).Append(totalRows == 1 ? " row." : " rows.");

        if (rows.Count == 0)
            return sb.ToString();

        sb.Append('\n');
        foreach (var row in rows.Take(MaxDisplayedRows))
        {
            sb.Append("  -- ");
            sb.AppendJoin(", ", row.Select(kv => $"{kv.Key}={FormatValue(kv.Value)}"));
            sb.Append('\n');
        }

        if (totalRows > MaxDisplayedRows)
            sb.Append("  ...and ").Append(totalRows - MaxDisplayedRows).Append(" more row(s), not shown.");

        return sb.ToString().TrimEnd('\n');
    }

    private static string FormatValue(object? value) => value switch
    {
        null => "NULL",
        byte[] bytes => $"<binary, {bytes.Length} bytes>",
        _ => value.ToString() ?? "NULL",
    };
}
