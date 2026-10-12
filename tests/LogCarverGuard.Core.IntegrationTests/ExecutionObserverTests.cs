using Microsoft.Data.SqlClient;
using Xunit;

namespace LogCarverGuard.Core.IntegrationTests;

[Collection("GuardSqlServer")]
public class ExecutionObserverTests(GuardedSqlExecutorFixture fixture)
{
    private static readonly IReadOnlySet<(string, string)> Nothing = new HashSet<(string, string)>();

    private sealed class RecordingObserver(string? text) : IExecutionObserver
    {
        public List<ExecutedStatement> Seen { get; } = [];

        public Task<string?> ObserveAsync(ExecutedStatement statement, CancellationToken ct)
        {
            Seen.Add(statement);
            return Task.FromResult(text);
        }
    }

    private sealed class FailingObserver : IExecutionObserver
    {
        public Task<string?> ObserveAsync(ExecutedStatement statement, CancellationToken ct) =>
            throw new InvalidOperationException("boom");
    }

    private async Task<SqlConnection> OpenAsync()
    {
        var connection = new SqlConnection(fixture.ConnectionString);
        await connection.OpenAsync();
        return connection;
    }

    [Fact]
    public async Task Observer_IsToldWhatCommitted_AfterTheAuditRecordWasWritten()
    {
        await using var connection = await OpenAsync();
        var sink = new InMemoryAuditSink();
        var observer = new RecordingObserver(" EXTRA");

        var record = await GuardedSqlExecutor.ExecuteAsync(
            connection, $"UPDATE {GuardedSqlExecutorFixture.TableName} SET Name = 'observed' WHERE Id = 1;", "alice",
            Nothing, Nothing, sink, observers: [observer]);

        var seen = Assert.Single(observer.Seen);
        Assert.Equal(record.Id, seen.AuditRecordId);
        Assert.Equal("alice", seen.User);
        Assert.Equal(1, seen.RowsAffected);
        Assert.Equal(("dbo", "GuardTest"), (seen.TargetTable!.Value.Schema, seen.TargetTable.Value.Table));
        Assert.NotNull(seen.TransactionId);
        Assert.False(seen.AllowedByAllowList);
        Assert.Equal(" EXTRA", record.ObserverText);
        Assert.Single(sink.Records);
    }

    [Fact]
    public async Task FailingObserver_NeverLosesTheAuditRecord_OrFailsTheWrite()
    {
        await using var connection = await OpenAsync();
        var sink = new InMemoryAuditSink();

        var record = await GuardedSqlExecutor.ExecuteAsync(
            connection, $"UPDATE {GuardedSqlExecutorFixture.TableName} SET Name = 'still-written' WHERE Id = 1;", "alice",
            Nothing, Nothing, sink, observers: [new FailingObserver()]);

        Assert.Equal(GuardedExecutionOutcome.Executed, record.Outcome);
        Assert.Equal(1, record.RowsAffected);
        Assert.Single(sink.Records);
        Assert.Contains("post-execution extension failed", record.ObserverText);
    }

    [Fact]
    public async Task BlockedStatement_IsNeverShownToObservers()
    {
        await using var connection = await OpenAsync();
        var observer = new RecordingObserver(" EXTRA");

        var record = await GuardedSqlExecutor.ExecuteAsync(
            connection, $"DROP TABLE {GuardedSqlExecutorFixture.TableName};", "alice",
            Nothing, Nothing, new InMemoryAuditSink(), observers: [observer]);

        Assert.Equal(GuardedExecutionOutcome.Blocked, record.Outcome);
        Assert.Empty(observer.Seen);
        Assert.Null(record.ObserverText);
    }

    [Fact]
    public async Task AllowListedTruncate_IsFlaggedToTheObserver()
    {
        await using var connection = await OpenAsync();
        await using (var create = new SqlCommand(
            "IF OBJECT_ID('dbo.GuardObserverStaging') IS NULL CREATE TABLE dbo.GuardObserverStaging (Id INT);", connection))
            await create.ExecuteNonQueryAsync();
        var observer = new RecordingObserver(null);
        var allowed = new HashSet<(string, string)>(CaseInsensitiveNameTupleComparer.Instance) { ("dbo", "GuardObserverStaging") };

        var record = await GuardedSqlExecutor.ExecuteAsync(
            connection, "TRUNCATE TABLE dbo.GuardObserverStaging;", "alice",
            allowed, Nothing, new InMemoryAuditSink(), observers: [observer]);

        Assert.Equal(GuardedExecutionOutcome.Executed, record.Outcome);
        Assert.True(Assert.Single(observer.Seen).AllowedByAllowList);
        Assert.Null(record.ObserverText);
    }
}
