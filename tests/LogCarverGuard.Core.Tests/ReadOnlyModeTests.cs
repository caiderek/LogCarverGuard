namespace LogCarverGuard.Core.Tests;

/// <summary>Read-only mode lets queries through and refuses everything else.</summary>
public class ReadOnlyModeTests
{
    private static HashSet<(string, string)> Names(params (string, string)[] names) =>
        new(names, CaseInsensitiveNameTupleComparer.Instance);

    private static GuardVerdict ReadOnly(string sql, IReadOnlySet<(string, string)>? execWhitelist = null) =>
        SqlStatementGuard.Evaluate(sql, Names(), execWhitelist ?? Names(), null, readOnly: true);

    [Theory]
    [InlineData("SELECT * FROM dbo.T;")]
    [InlineData("SELECT Id, Name FROM dbo.T WHERE Id = 1 ORDER BY Name;")]
    [InlineData("WITH cte AS (SELECT Id FROM dbo.T) SELECT * FROM cte;")]
    [InlineData("SELECT * FROM dbo.T WHERE Id IN (SELECT Id FROM dbo.U);")]
    [InlineData("SELECT a.Id FROM dbo.T a JOIN dbo.U b ON a.Id = b.Id;")]
    [InlineData("SET NOCOUNT ON; SELECT 1;")]
    [InlineData("DECLARE @id INT = 5; SELECT * FROM dbo.T WHERE Id = @id;")]
    [InlineData("SELECT 1 AS One UNION ALL SELECT 2;")]
    [InlineData("SELECT * FROM dbo.T -- UPDATE dbo.T SET x = 1\n;")]
    [InlineData("SELECT 'DROP TABLE dbo.T; UPDATE dbo.T SET x = 1' AS s;")]
    public void Queries_AreAllowed(string sql) =>
        Assert.Equal(GuardDecision.Allow, ReadOnly(sql).Decision);

    [Theory]
    [InlineData("UPDATE dbo.T SET Name = 'x' WHERE Id = 1;")]
    [InlineData("INSERT INTO dbo.T (Id) VALUES (1);")]
    [InlineData("DELETE FROM dbo.T WHERE Id = 1;")]
    [InlineData("SELECT * INTO dbo.Copy FROM dbo.T;")]
    [InlineData("SELECT 1; UPDATE dbo.T SET x = 1;")]
    [InlineData("SELECT * FROM dbo.T; DELETE FROM dbo.T;")]
    [InlineData("WITH cte AS (SELECT Id FROM dbo.T) UPDATE cte SET Id = 2;")]
    [InlineData("CREATE TABLE dbo.X (Id INT);")]
    [InlineData("ALTER TABLE dbo.T ADD c INT;")]
    [InlineData("MERGE dbo.T AS t USING dbo.U AS u ON t.Id = u.Id WHEN MATCHED THEN DELETE;")]
    [InlineData("INSERT dbo.T EXEC dbo.AnyProc;")]
    [InlineData("INSERT dbo.T EXEC('SELECT 1');")]
    [InlineData("SELECT NEXT VALUE FOR dbo.Seq;")]
    [InlineData("IF 1 = 1 UPDATE dbo.T SET x = 1;")]
    [InlineData("BEGIN UPDATE dbo.T SET x = 1; END")]
    [InlineData("TRUNCATE TABLE dbo.T;")]
    [InlineData("DROP TABLE dbo.T;")]
    public void Writes_AndSchemaChanges_AreBlocked(string sql)
    {
        var verdict = ReadOnly(sql);

        Assert.Equal(GuardDecision.Block, verdict.Decision);
        Assert.Contains("read-only", verdict.Reason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Exec_IsBlocked_EvenWhenWhitelisted() =>
        Assert.Equal(
            GuardDecision.Block,
            ReadOnly("EXEC dbo.ApprovedProc;", execWhitelist: Names(("dbo", "ApprovedProc"))).Decision);

    [Fact]
    public void WithoutTheFlag_WritesStillFollowTheOrdinaryRules() =>
        Assert.Equal(
            GuardDecision.Allow,
            SqlStatementGuard.Evaluate("UPDATE dbo.T SET Name = 'x' WHERE Id = 1;", Names(), Names()).Decision);

    [Fact]
    public void UnparseableSql_IsBlocked_InReadOnlyModeToo() =>
        Assert.Equal(GuardDecision.Block, ReadOnly("SELEC * FRM dbo.T").Decision);
}
