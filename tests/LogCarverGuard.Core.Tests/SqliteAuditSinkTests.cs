using Microsoft.Data.Sqlite;

namespace LogCarverGuard.Core.Tests;

public sealed class SqliteAuditSinkTests : IDisposable
{
    private readonly string _dbPath = Path.Combine(Path.GetTempPath(), $"logcarverguard-audit-test-{Guid.NewGuid():N}.db");

    public void Dispose()
    {
        // Microsoft.Data.Sqlite pools connections by default, which keeps a
        // file handle open even after the SqliteConnection itself is
        // disposed - clear the pool first or the file delete below races
        // against it and intermittently fails with "being used by another process".
        SqliteConnection.ClearAllPools();
        if (File.Exists(_dbPath)) File.Delete(_dbPath);
    }

    private static AuditRecord Executed(string user, string sql, int rows = 1) =>
        new(DateTimeOffset.UtcNow, user, sql, GuardedExecutionOutcome.Executed, BlockReason: null, RowsAffected: rows);

    [Fact]
    public async Task BlockedRecord_RoundTrips()
    {
        await using var sink = new SqliteAuditSink(_dbPath);
        var record = new AuditRecord(
            DateTimeOffset.UtcNow, "alice", "DROP TABLE dbo.T;", GuardedExecutionOutcome.Blocked,
            "DROP TABLE 一律封鎖", RowsAffected: null);

        await sink.RecordAsync(record);
        var stored = Assert.Single(await sink.GetRecentAsync());

        Assert.Equal("alice", stored.User);
        Assert.Equal("DROP TABLE dbo.T;", stored.Sql);
        Assert.Equal("Blocked", stored.Outcome);
        Assert.Equal("DROP TABLE 一律封鎖", stored.BlockReason);
        Assert.Null(stored.RowsAffected);
    }

    [Fact]
    public async Task ExecutedRecord_RoundTrips()
    {
        await using var sink = new SqliteAuditSink(_dbPath);

        await sink.RecordAsync(Executed("bob", "UPDATE dbo.T SET Name='new' WHERE Id=1;"));
        var stored = Assert.Single(await sink.GetRecentAsync());

        Assert.Equal("bob", stored.User);
        Assert.Equal("Executed", stored.Outcome);
        Assert.Null(stored.BlockReason);
        Assert.Equal(1, stored.RowsAffected);
    }

    [Fact]
    public async Task RecordAsync_ReturnsTheStoredId()
    {
        await using var sink = new SqliteAuditSink(_dbPath);

        long first = await sink.RecordAsync(Executed("alice", "UPDATE dbo.T SET X = 1;"));
        long second = await sink.RecordAsync(Executed("alice", "UPDATE dbo.T SET X = 2;"));

        Assert.Equal(first + 1, second);
        Assert.Equal("UPDATE dbo.T SET X = 2;", (await sink.GetByIdAsync(second))!.Sql);
    }

    [Fact]
    public async Task MultipleRecords_AreReturnedNewestFirst()
    {
        await using var sink = new SqliteAuditSink(_dbPath);
        for (int i = 1; i <= 3; i++)
            await sink.RecordAsync(Executed("alice", $"UPDATE dbo.T SET X = {i};"));

        var stored = await sink.GetRecentAsync();

        Assert.Equal(3, stored.Count);
        Assert.Equal("UPDATE dbo.T SET X = 3;", stored[0].Sql);
        Assert.Equal("UPDATE dbo.T SET X = 2;", stored[1].Sql);
        Assert.Equal("UPDATE dbo.T SET X = 1;", stored[2].Sql);
    }

    [Fact]
    public async Task GetRecentAsync_RespectsLimit()
    {
        await using var sink = new SqliteAuditSink(_dbPath);
        for (int i = 0; i < 5; i++)
            await sink.RecordAsync(Executed("alice", "UPDATE dbo.T SET X = 1;"));

        Assert.Equal(2, (await sink.GetRecentAsync(limit: 2)).Count);
    }

    [Fact]
    public async Task GetByIdAsync_ReturnsTheMatchingRecord()
    {
        await using var sink = new SqliteAuditSink(_dbPath);
        await sink.RecordAsync(Executed("bob", "UPDATE dbo.T SET Name='new' WHERE Id=1;"));

        var all = await sink.GetRecentAsync();
        var byId = await sink.GetByIdAsync(all[0].Id);

        Assert.NotNull(byId);
        Assert.Equal(all[0].Id, byId.Id);
        Assert.Equal("bob", byId.User);
    }

    [Fact]
    public async Task GetByIdAsync_ReturnsNullForAnUnknownId()
    {
        await using var sink = new SqliteAuditSink(_dbPath);
        Assert.Null(await sink.GetByIdAsync(999999));
    }

    [Fact]
    public async Task PersistsAcrossSeparateSinkInstances_OnTheSameFile()
    {
        await using (var firstSink = new SqliteAuditSink(_dbPath))
            await firstSink.RecordAsync(Executed("alice", "UPDATE dbo.T SET X = 1;"));

        await using var secondSink = new SqliteAuditSink(_dbPath);
        Assert.Single(await secondSink.GetRecentAsync());
    }
}
