namespace LogCarverGuard.Core.Tests;

/// <summary>
/// Read-only mode must not let a plain SELECT write through a remote
/// source, and must catch INTO wherever the parser puts it.
/// </summary>
public class ReadOnlyRemoteAccessTests
{
    private static HashSet<(string, string)> Names() =>
        new(CaseInsensitiveNameTupleComparer.Instance);

    private static GuardVerdict ReadOnly(string sql) =>
        SqlStatementGuard.Evaluate(sql, Names(), Names(), null, readOnly: true);

    [Theory]
    [InlineData("SELECT * FROM OPENQUERY(LinkedSrv, 'UPDATE dbo.T SET x = 1; SELECT 1');")]
    [InlineData("SELECT * FROM OPENROWSET('SQLNCLI', 'Server=x;Trusted_Connection=yes;', 'EXEC dbo.p');")]
    [InlineData("SELECT * FROM OPENROWSET(BULK 'C:/data.txt', SINGLE_CLOB) AS f;")]
    [InlineData("SELECT * FROM OPENDATASOURCE('SQLNCLI', 'Data Source=x').db.dbo.T;")]
    [InlineData("SELECT a FROM dbo.X WHERE a IN (SELECT a FROM OPENQUERY(LinkedSrv, 'SELECT 1 AS a'));")]
    public void RemoteSources_AreBlocked_BecauseTheyCanRunWritesRemotely(string sql)
    {
        var verdict = ReadOnly(sql);

        Assert.Equal(GuardDecision.Block, verdict.Decision);
        Assert.Contains("read-only", verdict.Reason, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("SELECT a INTO dbo.C FROM dbo.X UNION SELECT b FROM dbo.Y;")]
    [InlineData("WITH c AS (SELECT 1 AS a) SELECT a INTO dbo.C FROM c;")]
    [InlineData("SELECT a INTO #t FROM dbo.X;")]
    [InlineData("(SELECT a INTO dbo.C FROM dbo.X);")]
    public void SelectInto_IsBlocked_InEveryShape(string sql) =>
        Assert.Equal(GuardDecision.Block, ReadOnly(sql).Decision);

    [Fact]
    public void FourPartNameRead_IsStillAllowed_ItIsOnlyARead() =>
        Assert.Equal(GuardDecision.Allow, ReadOnly("SELECT * FROM LinkedSrv.db.dbo.T;").Decision);

    [Fact]
    public void OpenJson_AndOpenXml_StayAllowed_TheyOnlyParseLocalText() =>
        Assert.Equal(
            GuardDecision.Allow,
            ReadOnly("SELECT * FROM OPENJSON('[1,2]');").Decision);
}
