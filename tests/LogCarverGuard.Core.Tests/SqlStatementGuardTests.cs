namespace LogCarverGuard.Core.Tests;

public class SqlStatementGuardTests
{
    private static readonly IReadOnlySet<(string, string)> NoTruncateAllowed = new HashSet<(string, string)>(CaseInsensitiveNameTupleComparer.Instance);
    private static readonly IReadOnlySet<(string, string)> NoExecWhitelist = new HashSet<(string, string)>(CaseInsensitiveNameTupleComparer.Instance);

    private static GuardVerdict Evaluate(string sql,
        IReadOnlySet<(string, string)>? truncateAllowed = null,
        IReadOnlySet<(string, string)>? execWhitelist = null,
        IReadOnlySet<(string, string)>? alterDropColumnAllowed = null) =>
        SqlStatementGuard.Evaluate(
            sql, truncateAllowed ?? NoTruncateAllowed, execWhitelist ?? NoExecWhitelist, alterDropColumnAllowed);

    [Theory]
    [InlineData("UPDATE dbo.T SET Name = 'x' WHERE Id = 1;")]
    [InlineData("INSERT INTO dbo.T (Id, Name) VALUES (1, 'x');")]
    [InlineData("DELETE FROM dbo.T WHERE Id = 1;")]
    [InlineData("ALTER TABLE dbo.T ADD NewCol INT;")]
    [InlineData("WITH cte AS (SELECT Id, Name FROM dbo.T) UPDATE cte SET Name = 'x' WHERE Id = 1;")]
    public void OrdinaryDmlAndAlterTable_AreAllowed(string sql) =>
        Assert.Equal(GuardDecision.Allow, Evaluate(sql).Decision);

    [Fact]
    public void DropTable_IsAlwaysBlocked() =>
        Assert.Equal(GuardDecision.Block, Evaluate("DROP TABLE dbo.T;").Decision);

    [Fact]
    public void TruncateTable_IsBlockedByDefault() =>
        Assert.Equal(GuardDecision.Block, Evaluate("TRUNCATE TABLE dbo.Staging;").Decision);

    [Fact]
    public void TruncateTable_IsAllowedWhenTableIsOnTheAllowlist()
    {
        var allowed = new HashSet<(string, string)>(CaseInsensitiveNameTupleComparer.Instance) { ("dbo", "Staging") };
        Assert.Equal(GuardDecision.Allow, Evaluate("TRUNCATE TABLE dbo.Staging;", truncateAllowed: allowed).Decision);
    }

    [Fact]
    public void TruncateTable_IsAllowedWhenAllowlistCaseDiffersFromTheSqlText()
    {
        // SQL Server identifiers are case-insensitive under the default
        // collation - an admin approving "dbo.Staging" must still match
        // an AI writing "dbo.STAGING" or "DBO.staging".
        var allowed = new HashSet<(string, string)>(CaseInsensitiveNameTupleComparer.Instance) { ("DBO", "Staging") };
        Assert.Equal(GuardDecision.Allow, Evaluate("TRUNCATE TABLE dbo.STAGING;", truncateAllowed: allowed).Decision);
    }

    [Fact]
    public void TruncateTable_OnADifferentTable_StillBlockedEvenWithAnAllowlist()
    {
        var allowed = new HashSet<(string, string)>(CaseInsensitiveNameTupleComparer.Instance) { ("dbo", "Staging") };
        Assert.Equal(GuardDecision.Block, Evaluate("TRUNCATE TABLE dbo.RealData;", truncateAllowed: allowed).Decision);
    }

    [Theory]
    [InlineData("-- TRUNCATE TABLE dbo.T\nUPDATE dbo.T SET Name = 'x' WHERE Id = 1;")]
    [InlineData("UPDATE dbo.T SET Name = 'please truncate table later' WHERE Id = 1;")]
    public void FakeKeywordsInCommentsOrStringLiterals_DoNotTriggerBlocking(string sql) =>
        Assert.Equal(GuardDecision.Allow, Evaluate(sql).Decision);

    [Fact]
    public void MultiStatementBatch_WithADangerousStatementHidden_IsBlocked() =>
        Assert.Equal(GuardDecision.Block, Evaluate("UPDATE dbo.T SET Name='x' WHERE Id=1; TRUNCATE TABLE dbo.T;").Decision);

    [Fact]
    public void NamedProcedureCall_IsBlockedByDefault() =>
        Assert.Equal(GuardDecision.Block, Evaluate("EXEC dbo.sp_RefreshStagingData;").Decision);

    [Fact]
    public void NamedProcedureCall_IsAllowedWhenOnTheWhitelist()
    {
        var whitelist = new HashSet<(string, string)>(CaseInsensitiveNameTupleComparer.Instance) { ("dbo", "sp_RefreshStagingData") };
        Assert.Equal(GuardDecision.Allow, Evaluate("EXEC dbo.sp_RefreshStagingData;", execWhitelist: whitelist).Decision);
    }

    [Theory]
    [InlineData("EXEC('TRUNCATE TABLE dbo.T');")]
    [InlineData("DECLARE @sql NVARCHAR(MAX) = 'TRUNCATE TABLE dbo.T'; EXEC(@sql);")]
    public void DynamicSqlExecution_IsAlwaysBlocked(string sql) =>
        Assert.Equal(GuardDecision.Block, Evaluate(sql).Decision);

    [Fact]
    public void SpExecuteSql_IsNeverWhitelistable_EvenIfAdminTriesToAllowIt()
    {
        // 這個就是今天實測抓到的分類漏洞:sp_executesql 如果照一般白名單邏輯處理,
        // 會被誤判成普通具名呼叫。管理者就算真的把它加進白名單,也不能放行。
        var whitelist = new HashSet<(string, string)>(CaseInsensitiveNameTupleComparer.Instance) { ("dbo", "sp_executesql") };
        Assert.Equal(GuardDecision.Block, Evaluate("EXEC sp_executesql N'TRUNCATE TABLE dbo.T';", execWhitelist: whitelist).Decision);
    }

    [Fact]
    public void XpCmdshell_IsNeverWhitelistable()
    {
        var whitelist = new HashSet<(string, string)>(CaseInsensitiveNameTupleComparer.Instance) { ("dbo", "xp_cmdshell") };
        Assert.Equal(GuardDecision.Block, Evaluate("EXEC xp_cmdshell 'dir';", execWhitelist: whitelist).Decision);
    }

    [Fact]
    public void ExecWithVariableTarget_CannotBeStaticallyResolved_SoItIsBlocked() =>
        Assert.Equal(GuardDecision.Block, Evaluate("DECLARE @proc NVARCHAR(100) = 'sp_Foo'; EXEC @proc;").Decision);

    [Fact]
    public void DropDatabase_IsAlwaysBlocked() =>
        Assert.Equal(GuardDecision.Block, Evaluate("DROP DATABASE SomeDb;").Decision);

    [Fact]
    public void RestoreDatabase_IsAlwaysBlocked() =>
        Assert.Equal(GuardDecision.Block, Evaluate("RESTORE DATABASE SomeDb FROM DISK = 'C:\\backup.bak';").Decision);

    [Fact]
    public void RestoreLog_IsAlwaysBlocked() =>
        Assert.Equal(GuardDecision.Block, Evaluate("RESTORE LOG SomeDb FROM DISK = 'C:\\backup.trn';").Decision);

    [Theory]
    [InlineData("RESTORE HEADERONLY FROM DISK = 'C:\\backup.bak';")]
    [InlineData("RESTORE FILELISTONLY FROM DISK = 'C:\\backup.bak';")]
    [InlineData("RESTORE VERIFYONLY FROM DISK = 'C:\\backup.bak';")]
    public void RestoreOfInformationalKinds_IsAllowed_NoDataIsChanged(string sql) =>
        Assert.Equal(GuardDecision.Allow, Evaluate(sql).Decision);

    [Theory]
    [InlineData("ALTER DATABASE SomeDb SET SINGLE_USER WITH ROLLBACK IMMEDIATE;")]
    [InlineData("ALTER DATABASE SomeDb SET OFFLINE;")]
    public void AlterDatabaseSet_IsAlwaysBlocked_CanTakeTheWholeDatabaseDown(string sql) =>
        Assert.Equal(GuardDecision.Block, Evaluate(sql).Decision);

    [Fact]
    public void AlterTableDropColumn_IsBlockedByDefault() =>
        Assert.Equal(GuardDecision.Block, Evaluate("ALTER TABLE dbo.T DROP COLUMN OldCol;").Decision);

    [Fact]
    public void AlterTableDropColumn_IsAllowedWhenTableIsOnItsOwnAllowlist()
    {
        var allowed = new HashSet<(string, string)>(CaseInsensitiveNameTupleComparer.Instance) { ("dbo", "T") };
        Assert.Equal(GuardDecision.Allow, Evaluate("ALTER TABLE dbo.T DROP COLUMN OldCol;", alterDropColumnAllowed: allowed).Decision);
    }

    [Fact]
    public void AlterTableDropColumn_OnADifferentTable_StillBlockedEvenWithAnAllowlist()
    {
        var allowed = new HashSet<(string, string)>(CaseInsensitiveNameTupleComparer.Instance) { ("dbo", "Other") };
        Assert.Equal(GuardDecision.Block, Evaluate("ALTER TABLE dbo.T DROP COLUMN OldCol;", alterDropColumnAllowed: allowed).Decision);
    }

    [Fact]
    public void AlterTableDropConstraint_IsAllowed_NoColumnDataIsLost() =>
        // Dropping a constraint (not a column) doesn't lose any row data -
        // the TRUNCATE-style allowlist gate exists for DROP COLUMN specifically.
        Assert.Equal(GuardDecision.Allow, Evaluate("ALTER TABLE dbo.T DROP CONSTRAINT CK_SomeCheck;").Decision);

    // The caller's own transaction-control statements are blocked outright: the
    // executor's `BEGIN TRAN; ...; SELECT CURRENT_TRANSACTION_ID(); COMMIT;` wrap
    // assumes the proxy is the only thing opening/closing a transaction around a
    // statement; otherwise `BEGIN TRAN; UPDATE ...; ROLLBACK;` would be recorded as
    // Executed despite nothing being committed.
    [Theory]
    [InlineData("BEGIN TRANSACTION;")]
    [InlineData("BEGIN TRAN;")]
    [InlineData("COMMIT TRANSACTION;")]
    [InlineData("COMMIT;")]
    [InlineData("ROLLBACK TRANSACTION;")]
    [InlineData("ROLLBACK;")]
    [InlineData("SAVE TRANSACTION sp1;")]
    [InlineData("BEGIN TRAN; UPDATE dbo.T SET Name = 'x' WHERE Id = 1; ROLLBACK;")]
    public void CallerOwnTransactionControlStatements_AreAlwaysBlocked(string sql) =>
        Assert.Equal(GuardDecision.Block, Evaluate(sql).Decision);

    // REVERT / EXECUTE AS must always be blocked: a caller's own `REVERT;` could switch
    // the connection's security context back to the proxy's own service account
    // (ImpersonatedConnectionFactory's EXECUTE AS LOGIN runs on a connection opened as
    // that account), bypassing the real login's own GRANT/DENY.
    // `EXECUTE AS LOGIN = 'sa';` is the same hole from the other direction.
    // GRANT/DENY/REVOKE/SETUSER/SHUTDOWN/KILL are administrative/identity-changing
    // statements that are not meant to be reachable through this proxy at all.
    [Theory]
    [InlineData("REVERT;")]
    [InlineData("EXECUTE AS LOGIN = 'sa';")]
    [InlineData("EXECUTE AS USER = 'dbo';")]
    [InlineData("GRANT SELECT ON dbo.T TO [SomeLogin];")]
    [InlineData("DENY SELECT ON dbo.T TO [SomeLogin];")]
    [InlineData("REVOKE SELECT ON dbo.T FROM [SomeLogin];")]
    [InlineData("SETUSER 'dbo';")]
    [InlineData("SHUTDOWN;")]
    [InlineData("KILL 52;")]
    [InlineData("REVERT; UPDATE dbo.Payroll SET Salary = 0;")] // the actual exploit shape
    public void IdentitySwitchingAndPrivilegeStatements_AreAlwaysBlocked(string sql) =>
        Assert.Equal(GuardDecision.Block, Evaluate(sql).Decision);

    // SET IMPLICIT_TRANSACTIONS ON parses as a PredicateSetStatement, not
    // BeginTransactionStatement, so it needs its own block: the same
    // audit-disagrees-with-commit-state risk (a caller-opened implicit
    // transaction around a bare EXEC that GuardedSqlExecutor never anchors
    // could roll back silently on connection disposal while still being
    // recorded as Executed).
    [Theory]
    [InlineData("SET IMPLICIT_TRANSACTIONS ON;")]
    [InlineData("SET NOCOUNT ON; SET IMPLICIT_TRANSACTIONS ON;")]
    public void SetImplicitTransactionsOn_IsAlwaysBlocked(string sql) =>
        Assert.Equal(GuardDecision.Block, Evaluate(sql).Decision);

    [Theory]
    [InlineData("SET IMPLICIT_TRANSACTIONS OFF;")] // OFF is the default state, not a hazard
    [InlineData("SET NOCOUNT ON;")]
    [InlineData("SET ANSI_NULLS ON;")]
    public void OtherSetOptions_AreNotBlocked(string sql) =>
        Assert.Equal(GuardDecision.Allow, Evaluate(sql).Decision);
}
