namespace LogCarverGuard.Core.Tests;

/// <summary>
/// Shapes that must not slip past the
/// guard: INSERT ... EXEC carries its EXEC inside an INSERT source rather
/// than as an ExecuteStatement, and allow-list matching used to ignore a
/// database or server qualifier.
/// </summary>
public class GuardBypassRegressionTests
{
    private static HashSet<(string, string)> Names(params (string, string)[] names) =>
        new(names, CaseInsensitiveNameTupleComparer.Instance);

    private static GuardVerdict Evaluate(
        string sql,
        IReadOnlySet<(string, string)>? truncateAllowed = null,
        IReadOnlySet<(string, string)>? execWhitelist = null,
        IReadOnlySet<(string, string)>? alterDropColumnAllowed = null) =>
        SqlStatementGuard.Evaluate(sql, truncateAllowed ?? Names(), execWhitelist ?? Names(), alterDropColumnAllowed);

    [Theory]
    [InlineData("INSERT INTO dbo.T EXEC('DROP TABLE dbo.X');")]
    [InlineData("DECLARE @s NVARCHAR(MAX) = N'DROP TABLE dbo.X'; INSERT dbo.T EXEC(@s);")]
    [InlineData("INSERT dbo.T EXEC dbo.AnyProc;")]
    [InlineData("INSERT dbo.T EXEC xp_cmdshell 'dir';")]
    [InlineData("INSERT dbo.T EXEC sp_executesql N'SELECT 1';")]
    [InlineData("INSERT dbo.T (a) EXEC [srv].db.dbo.AnyProc;")]
    public void InsertExec_IsGuardedLikeAPlainExec(string sql) =>
        Assert.Equal(GuardDecision.Block, Evaluate(sql).Decision);

    [Fact]
    public void InsertExec_OfAWhitelistedProcedure_IsAllowed() =>
        Assert.Equal(
            GuardDecision.Allow,
            Evaluate("INSERT dbo.T EXEC dbo.ApprovedProc;", execWhitelist: Names(("dbo", "ApprovedProc"))).Decision);

    [Theory]
    [InlineData("TRUNCATE TABLE ProdOther.dbo.Staging;")]
    [InlineData("TRUNCATE TABLE [srv].ProdOther.dbo.Staging;")]
    public void Truncate_WithADatabaseOrServerQualifier_IsNotMatchedAgainstTheLocalAllowList(string sql) =>
        Assert.Equal(GuardDecision.Block, Evaluate(sql, truncateAllowed: Names(("dbo", "Staging"))).Decision);

    [Fact]
    public void Truncate_OfTheAllowedLocalTable_StillWorks() =>
        Assert.Equal(
            GuardDecision.Allow,
            Evaluate("TRUNCATE TABLE dbo.Staging;", truncateAllowed: Names(("dbo", "Staging"))).Decision);

    [Theory]
    [InlineData("EXEC [srv].db.dbo.ApprovedProc;")]
    [InlineData("EXEC OtherDb.dbo.ApprovedProc;")]
    public void Exec_WithADatabaseOrServerQualifier_IsNotMatchedAgainstTheLocalWhitelist(string sql) =>
        Assert.Equal(GuardDecision.Block, Evaluate(sql, execWhitelist: Names(("dbo", "ApprovedProc"))).Decision);

    [Fact]
    public void DropColumn_WithADatabaseQualifier_IsNotMatchedAgainstTheLocalAllowList() =>
        Assert.Equal(
            GuardDecision.Block,
            Evaluate("ALTER TABLE OtherDb.dbo.T DROP COLUMN c;", alterDropColumnAllowed: Names(("dbo", "T"))).Decision);
}
