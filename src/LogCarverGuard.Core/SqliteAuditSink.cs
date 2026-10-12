using Microsoft.Data.Sqlite;

namespace LogCarverGuard.Core;

public sealed record StoredAuditRecord(
    long Id, DateTimeOffset At, string User, string Sql, string Outcome,
    string? BlockReason, int? RowsAffected);

/// <summary>
/// Persists AuditRecord to a local SQLite file: one more real database
/// service is one more thing to operate and secure, which is not worth it at
/// this scale.
///
/// Every public method serializes on <see cref="_lock"/> around the one
/// long-lived <see cref="_connection"/>: Microsoft.Data.Sqlite does not
/// guarantee a single SqliteConnection is safe for concurrent command
/// execution from multiple callers. A collision inside RecordAsync would be
/// an exception after the statement already committed, i.e. a write whose
/// audit record was lost.
/// </summary>
public sealed class SqliteAuditSink : IAuditSink, IAuditReader, IAsyncDisposable
{
    private readonly SqliteConnection _connection;
    private readonly SemaphoreSlim _lock = new(1, 1);

    public SqliteAuditSink(string databasePath)
    {
        _connection = new SqliteConnection($"Data Source={databasePath}");
        _connection.Open();
        EnsureSchema();
    }

    private void EnsureSchema()
    {
        using var cmd = _connection.CreateCommand();
        cmd.CommandText = """
            CREATE TABLE IF NOT EXISTS AuditRecords (
                Id INTEGER PRIMARY KEY AUTOINCREMENT,
                AtUtc TEXT NOT NULL,
                User TEXT NOT NULL,
                Sql TEXT NOT NULL,
                Outcome TEXT NOT NULL,
                BlockReason TEXT NULL,
                RowsAffected INTEGER NULL
            );
            """;
        cmd.ExecuteNonQuery();
    }

    public async Task<long> RecordAsync(AuditRecord record, CancellationToken ct = default)
    {
        await _lock.WaitAsync(ct);
        try
        {
            await using var insert = _connection.CreateCommand();
            insert.CommandText = """
                INSERT INTO AuditRecords (AtUtc, User, Sql, Outcome, BlockReason, RowsAffected)
                VALUES ($at, $user, $sql, $outcome, $reason, $rows);
                SELECT last_insert_rowid();
                """;
            insert.Parameters.AddWithValue("$at", record.At.UtcDateTime.ToString("O"));
            insert.Parameters.AddWithValue("$user", record.User);
            insert.Parameters.AddWithValue("$sql", record.Sql);
            insert.Parameters.AddWithValue("$outcome", record.Outcome.ToString());
            insert.Parameters.AddWithValue("$reason", (object?)record.BlockReason ?? DBNull.Value);
            insert.Parameters.AddWithValue("$rows", (object?)record.RowsAffected ?? DBNull.Value);
            return (long)(await insert.ExecuteScalarAsync(ct))!;
        }
        finally
        {
            _lock.Release();
        }
    }

    /// <summary>Newest first. For manual inspection and testing.</summary>
    public async Task<IReadOnlyList<StoredAuditRecord>> GetRecentAsync(int limit = 100, CancellationToken ct = default)
    {
        await _lock.WaitAsync(ct);
        try
        {
            var records = new List<StoredAuditRecord>();
            await using var select = _connection.CreateCommand();
            select.CommandText = """
                SELECT Id, AtUtc, User, Sql, Outcome, BlockReason, RowsAffected
                FROM AuditRecords ORDER BY Id DESC LIMIT $limit;
                """;
            select.Parameters.AddWithValue("$limit", limit);
            await using var reader = await select.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
                records.Add(Read(reader));
            return records;
        }
        finally
        {
            _lock.Release();
        }
    }

    public async Task<StoredAuditRecord?> GetByIdAsync(long id, CancellationToken ct = default)
    {
        await _lock.WaitAsync(ct);
        try
        {
            await using var select = _connection.CreateCommand();
            select.CommandText = """
                SELECT Id, AtUtc, User, Sql, Outcome, BlockReason, RowsAffected
                FROM AuditRecords WHERE Id = $id;
                """;
            select.Parameters.AddWithValue("$id", id);
            await using var reader = await select.ExecuteReaderAsync(ct);
            return await reader.ReadAsync(ct) ? Read(reader) : null;
        }
        finally
        {
            _lock.Release();
        }
    }

    private static StoredAuditRecord Read(SqliteDataReader reader) => new(
        reader.GetInt64(0),
        DateTimeOffset.Parse(reader.GetString(1)),
        reader.GetString(2),
        reader.GetString(3),
        reader.GetString(4),
        reader.IsDBNull(5) ? null : reader.GetString(5),
        reader.IsDBNull(6) ? null : reader.GetInt32(6));

    public async ValueTask DisposeAsync()
    {
        await _connection.DisposeAsync();
        _lock.Dispose();
    }
}
