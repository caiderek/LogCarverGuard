using Microsoft.Data.Sqlite;

namespace LogCarverGuard.Core.Tests;

public sealed class ApiKeyStoreTests : IDisposable
{
    private readonly string _dbPath = Path.Combine(Path.GetTempPath(), $"logcarverguard-apikeys-test-{Guid.NewGuid():N}.db");

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        if (File.Exists(_dbPath)) File.Delete(_dbPath);
    }

    private ApiKeyStore OpenStore() => new(_dbPath);

    [Fact]
    public async Task IssuedKey_HasTheDocumentedPrefix_AndIsHighEntropy()
    {
        await using var store = OpenStore();
        var issued = await store.IssueAsync("alice", "alice_login");

        Assert.StartsWith("lcg_", issued.RawKey);
        Assert.True(issued.RawKey.Length > 30);
    }

    [Fact]
    public async Task ValidKey_ResolvesToItsOwnerAndSqlLogin()
    {
        await using var store = OpenStore();
        var issued = await store.IssueAsync("alice", "alice_login");

        var info = await store.ValidateAsync(issued.RawKey);

        Assert.NotNull(info);
        Assert.Equal("alice", info.Owner);
        Assert.Equal("alice_login", info.SqlLogin);
    }

    [Fact]
    public async Task UnknownKey_FailsValidation()
    {
        await using var store = OpenStore();
        Assert.Null(await store.ValidateAsync("lcg_this_was_never_issued"));
    }

    [Theory]
    [InlineData("")]
    [InlineData("not-even-the-right-prefix")]
    public async Task MalformedKey_FailsValidationWithoutThrowing(string key)
    {
        await using var store = OpenStore();
        Assert.Null(await store.ValidateAsync(key));
    }

    [Fact]
    public async Task RevokedKey_NoLongerValidates()
    {
        await using var store = OpenStore();
        var issued = await store.IssueAsync("alice", "alice_login");
        Assert.NotNull(await store.ValidateAsync(issued.RawKey));

        Assert.True(await store.RevokeAsync(issued.Id));

        Assert.Null(await store.ValidateAsync(issued.RawKey));
    }

    [Fact]
    public async Task RevokeAsync_OnAnUnknownId_ReturnsFalse()
    {
        await using var store = OpenStore();
        Assert.False(await store.RevokeAsync(999_999));
    }

    [Fact]
    public async Task RevokeAsync_OnAnAlreadyRevokedKey_ReturnsFalseTheSecondTime()
    {
        await using var store = OpenStore();
        var issued = await store.IssueAsync("alice", "alice_login");

        Assert.True(await store.RevokeAsync(issued.Id));
        Assert.False(await store.RevokeAsync(issued.Id));
    }

    [Fact]
    public async Task ListAsync_ReturnsAllIssuedKeys_NewestFirst_NeverIncludingTheRawKey()
    {
        await using var store = OpenStore();
        var alice = await store.IssueAsync("alice", "alice_login");
        var bob = await store.IssueAsync("bob", "bob_login");
        await store.RevokeAsync(alice.Id);

        var summaries = await store.ListAsync();

        Assert.Equal(2, summaries.Count);
        Assert.Equal(bob.Id, summaries[0].Id); // newest first
        Assert.Equal(alice.Id, summaries[1].Id);
        Assert.True(summaries[1].IsRevoked);
        Assert.False(summaries[0].IsRevoked);
        Assert.Null(summaries[0].RevokedAtUtc);
        Assert.NotNull(summaries[1].RevokedAtUtc);
    }

    [Fact]
    public async Task TwoIssuedKeys_AreDistinctAndEachResolvesToItsOwnOwner()
    {
        await using var store = OpenStore();
        var alice = await store.IssueAsync("alice", "alice_login");
        var bob = await store.IssueAsync("bob", "bob_login");

        Assert.NotEqual(alice.RawKey, bob.RawKey);
        Assert.Equal("alice", (await store.ValidateAsync(alice.RawKey))!.Owner);
        Assert.Equal("bob", (await store.ValidateAsync(bob.RawKey))!.Owner);
    }

    [Fact]
    public async Task ConcurrentValidateAsyncCalls_DoNotThrow()
    {
        // Real bug, found 2026-10-07 by independent audit: ApiKeyStore shared
        // one long-lived SqliteConnection with no lock, unlike its sibling
        // SqliteAuditSink (which was given a SemaphoreSlim for exactly this
        // reason - see that class's own doc comment, and Microsoft.Data.Sqlite's
        // own documented guidance that a single connection isn't safe for
        // concurrent command execution). ValidateAsync is hit on every single
        // tool call via SqlTools.ResolveCallerAsync.
        //
        // Bug-injection note: temporarily removing the lock here did NOT
        // reliably reproduce a thrown exception in this sandboxed test
        // environment across several runs (SQLite's own file-level locking
        // apparently absorbs this volume of concurrent async-task access
        // without surfacing a .NET-level exception here, unlike the original
        // SqliteAuditSink bug this mirrors, which involved a background sync
        // service on a genuinely separate thread). The fix matches the
        // documented API contract and this project's own established pattern
        // regardless - this test is a real regression/correctness check
        // (concurrent calls must return the right data), just not one that
        // independently proves the race via failed bug-injection the way
        // this project's other fixes today were verified.
        await using var store = OpenStore();
        var issued = await store.IssueAsync("alice", "alice_login");

        // Mix concurrent reads (ValidateAsync) with concurrent writes
        // (IssueAsync), both sets started together (not one after the
        // other) at high volume - the original SqliteAuditSink bug this
        // mirrors was specifically a read racing an unrelated write on the
        // same connection, not reads racing each other alone.
        var validateTasks = Enumerable.Range(0, 100)
            .Select(_ => store.ValidateAsync(issued.RawKey)).ToArray();
        var issueTasks = Enumerable.Range(0, 100)
            .Select(i => store.IssueAsync($"concurrent-{i}", "some_login")).ToArray();

        var results = await Task.WhenAll(validateTasks); // must not throw
        await Task.WhenAll(issueTasks); // must not throw

        Assert.All(results, info => Assert.Equal("alice", info?.Owner));
    }
}
