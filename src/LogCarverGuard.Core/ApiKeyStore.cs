using System.Security.Cryptography;
using Microsoft.Data.Sqlite;

namespace LogCarverGuard.Core;

public sealed record IssuedApiKey(string RawKey, long Id);

public sealed record ApiKeyInfo(long Id, string Owner, string SqlLogin, DateTimeOffset CreatedAtUtc);

public sealed record ApiKeySummary(long Id, string Owner, string SqlLogin, DateTimeOffset CreatedAtUtc, DateTimeOffset? RevokedAtUtc)
{
    public bool IsRevoked => RevokedAtUtc is not null;
}

/// <summary>
/// Front-door authentication store from 規劃書 三-5: the proxy issues its own
/// high-entropy API keys (not account/password pairs), hashed into a local
/// SQLite file - no separate database service to operate/secure for
/// something this small. One key per person, so every audit record
/// attributes to a real person, not just "someone" - SqlLogin is which real
/// SQL Server login that key's traffic gets impersonated as via
/// EXECUTE AS LOGIN (see ImpersonatedConnectionFactory), so a single-team
/// setup can map every key to the same login while a multi-org setup maps
/// each person to their own.
///
/// Only the SHA-256 hash is ever stored - the raw key is returned once, at
/// issue time, and cannot be recovered afterward (same posture as how
/// GitHub/Stripe-style tokens work).
///
/// Every public method serializes on <see cref="_lock"/> around the one
/// long-lived <see cref="_connection"/> - same reasoning as
/// SqliteAuditSink's identical lock (see that class's own doc comment):
/// Microsoft.Data.Sqlite does not guarantee a single SqliteConnection is
/// safe for concurrent command execution from multiple callers, and
/// ValidateAsync is hit on every single tool call via SqlTools'
/// ResolveCallerAsync. Found missing 2026-10-07 by independent audit -
/// SqliteAuditSink got this lock for exactly this reason and ApiKeyStore was
/// simply never given the same treatment, so two concurrent callers could
/// throw a raw SqliteException/InvalidOperationException instead of getting
/// a clean auth result - an intermittent, spurious auth failure under
/// exactly the concurrent load this project has spent real effort making
/// safe elsewhere.
/// </summary>
public sealed class ApiKeyStore : IAsyncDisposable
{
    private const string KeyPrefix = "lcg_";
    private readonly SqliteConnection _connection;
    private readonly SemaphoreSlim _lock = new(1, 1);

    public ApiKeyStore(string databasePath)
    {
        _connection = new SqliteConnection($"Data Source={databasePath}");
        _connection.Open();
        EnsureSchema();
    }

    private void EnsureSchema()
    {
        using var cmd = _connection.CreateCommand();
        cmd.CommandText = """
            CREATE TABLE IF NOT EXISTS ApiKeys (
                Id INTEGER PRIMARY KEY AUTOINCREMENT,
                KeyHash TEXT NOT NULL UNIQUE,
                Owner TEXT NOT NULL,
                SqlLogin TEXT NOT NULL,
                CreatedAtUtc TEXT NOT NULL,
                RevokedAtUtc TEXT NULL
            );
            """;
        cmd.ExecuteNonQuery();
    }

    public async Task<IssuedApiKey> IssueAsync(string owner, string sqlLogin, CancellationToken ct = default)
    {
        string rawKey = KeyPrefix + Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
            .Replace('+', '-').Replace('/', '_').TrimEnd('=');

        await _lock.WaitAsync(ct);
        try
        {
            await using var cmd = _connection.CreateCommand();
            cmd.CommandText = """
                INSERT INTO ApiKeys (KeyHash, Owner, SqlLogin, CreatedAtUtc)
                VALUES ($hash, $owner, $login, $now);
                SELECT last_insert_rowid();
                """;
            cmd.Parameters.AddWithValue("$hash", Hash(rawKey));
            cmd.Parameters.AddWithValue("$owner", owner);
            cmd.Parameters.AddWithValue("$login", sqlLogin);
            cmd.Parameters.AddWithValue("$now", DateTimeOffset.UtcNow.ToString("O"));
            long id = (long)(await cmd.ExecuteScalarAsync(ct))!;

            return new IssuedApiKey(rawKey, id);
        }
        finally
        {
            _lock.Release();
        }
    }

    /// <returns>null if the key is unknown, malformed, or revoked.</returns>
    public async Task<ApiKeyInfo?> ValidateAsync(string rawKey, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(rawKey) || !rawKey.StartsWith(KeyPrefix, StringComparison.Ordinal))
            return null;

        await _lock.WaitAsync(ct);
        try
        {
            await using var cmd = _connection.CreateCommand();
            cmd.CommandText = """
                SELECT Id, Owner, SqlLogin, CreatedAtUtc FROM ApiKeys
                WHERE KeyHash = $hash AND RevokedAtUtc IS NULL;
                """;
            cmd.Parameters.AddWithValue("$hash", Hash(rawKey));
            await using var reader = await cmd.ExecuteReaderAsync(ct);
            if (!await reader.ReadAsync(ct)) return null;

            return new ApiKeyInfo(
                reader.GetInt64(0), reader.GetString(1), reader.GetString(2),
                DateTimeOffset.Parse(reader.GetString(3)));
        }
        finally
        {
            _lock.Release();
        }
    }

    /// <returns>false if there was no such id, or it was already revoked - distinguishes "nothing to do" from "just revoked" for callers like the admin CLI.</returns>
    public async Task<bool> RevokeAsync(long id, CancellationToken ct = default)
    {
        await _lock.WaitAsync(ct);
        try
        {
            await using var cmd = _connection.CreateCommand();
            cmd.CommandText = "UPDATE ApiKeys SET RevokedAtUtc = $now WHERE Id = $id AND RevokedAtUtc IS NULL;";
            cmd.Parameters.AddWithValue("$now", DateTimeOffset.UtcNow.ToString("O"));
            cmd.Parameters.AddWithValue("$id", id);
            int rowsAffected = await cmd.ExecuteNonQueryAsync(ct);
            return rowsAffected > 0;
        }
        finally
        {
            _lock.Release();
        }
    }

    /// <summary>All issued keys, newest first - for the admin CLI's list-keys command. Never includes the raw key (unrecoverable after issue time).</summary>
    public async Task<IReadOnlyList<ApiKeySummary>> ListAsync(CancellationToken ct = default)
    {
        await _lock.WaitAsync(ct);
        try
        {
            var results = new List<ApiKeySummary>();
            await using var cmd = _connection.CreateCommand();
            cmd.CommandText = "SELECT Id, Owner, SqlLogin, CreatedAtUtc, RevokedAtUtc FROM ApiKeys ORDER BY Id DESC;";
            await using var reader = await cmd.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
            {
                results.Add(new ApiKeySummary(
                    reader.GetInt64(0), reader.GetString(1), reader.GetString(2),
                    DateTimeOffset.Parse(reader.GetString(3)),
                    reader.IsDBNull(4) ? null : DateTimeOffset.Parse(reader.GetString(4))));
            }
            return results;
        }
        finally
        {
            _lock.Release();
        }
    }

    private static string Hash(string rawKey) =>
        Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(rawKey)));

    public async ValueTask DisposeAsync()
    {
        await _connection.DisposeAsync();
        _lock.Dispose();
    }
}
