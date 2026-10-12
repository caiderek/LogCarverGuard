using Microsoft.Data.SqlClient;

namespace LogCarverGuard.Core;

/// <summary>What a host can know about a statement that has just committed.</summary>
/// <param name="AuditRecordId">The id the audit sink assigned to this statement's record.</param>
/// <param name="TargetTable">
/// The INSERT/UPDATE/DELETE target <see cref="DmlTargetTableResolver"/> found,
/// or null when the statement has none (SELECT, DDL, EXEC...).
/// </param>
/// <param name="TransactionId">
/// CURRENT_TRANSACTION_ID() read inside the proxy-managed transaction right
/// before it committed; null when the statement was not wrapped.
/// </param>
/// <param name="AllowedByAllowList">The statement was only let through because an admin allow-list named its target.</param>
/// <param name="ExecutionConnection">The caller's own (impersonated) connection.</param>
public sealed record ExecutedStatement(
    long AuditRecordId,
    string User,
    string Sql,
    SchemaTable? TargetTable,
    long? TransactionId,
    int RowsAffected,
    bool AllowedByAllowList,
    SqlConnection ExecutionConnection);

/// <summary>
/// Extension point called once per executed statement, after it has
/// committed and after its audit record was written. An observer can do
/// further bookkeeping and may return text that is appended to the caller's
/// confirmation of an executed write (starting with a space), or null.
/// A failing observer never affects the already-committed write or its
/// audit record.
/// </summary>
public interface IExecutionObserver
{
    Task<string?> ObserveAsync(ExecutedStatement statement, CancellationToken ct);
}
