namespace LogCarverGuard.Core.Tests;

public class DmlTargetTableResolverTests
{
    [Fact]
    public void Insert_ResolvesTargetTable()
    {
        var target = DmlTargetTableResolver.ResolvePrimaryTarget("INSERT INTO dbo.T (Id) VALUES (1);");
        Assert.Equal(new SchemaTable("dbo", "T"), target);
    }

    [Fact]
    public void Update_ResolvesTargetTable()
    {
        var target = DmlTargetTableResolver.ResolvePrimaryTarget("UPDATE sales.Orders SET Qty = 2 WHERE Id = 1;");
        Assert.Equal(new SchemaTable("sales", "Orders"), target);
    }

    [Fact]
    public void Delete_ResolvesTargetTable()
    {
        var target = DmlTargetTableResolver.ResolvePrimaryTarget("DELETE FROM dbo.T WHERE Id = 1;");
        Assert.Equal(new SchemaTable("dbo", "T"), target);
    }

    [Fact]
    public void Update_DefaultsToDboWhenSchemaOmitted()
    {
        var target = DmlTargetTableResolver.ResolvePrimaryTarget("UPDATE T SET Name = 'x' WHERE Id = 1;");
        Assert.Equal(new SchemaTable("dbo", "T"), target);
    }

    [Fact]
    public void Update_ThreePartName_CapturesTheDatabase()
    {
        var target = DmlTargetTableResolver.ResolvePrimaryTarget(
            "UPDATE OtherDb.dbo.T SET Name = 'x' WHERE Id = 1;");
        Assert.Equal(new SchemaTable("dbo", "T", "OtherDb"), target);
    }

    [Fact]
    public void Update_TwoPartName_LeavesDatabaseNull()
    {
        var target = DmlTargetTableResolver.ResolvePrimaryTarget("UPDATE dbo.T SET Name = 'x' WHERE Id = 1;");
        Assert.Null(target!.Value.Database);
    }

    [Fact]
    public void UpdateViaCte_ResolvesTheCteAliasNotTheRealTable()
    {
        // Known limitation (see the class doc comment): this degrades safely
        // downstream rather than silently guessing the real table.
        var target = DmlTargetTableResolver.ResolvePrimaryTarget(
            "WITH cte AS (SELECT Id, Name FROM dbo.T) UPDATE cte SET Name = 'x' WHERE Id = 1;");
        Assert.Equal(new SchemaTable("dbo", "cte"), target);
    }

    [Fact]
    public void AlterTableAlone_HasNoDmlTarget() =>
        Assert.Null(DmlTargetTableResolver.ResolvePrimaryTarget("ALTER TABLE dbo.T ADD NewCol INT;"));

    [Fact]
    public void InvalidSql_ReturnsNullRatherThanThrowing() =>
        Assert.Null(DmlTargetTableResolver.ResolvePrimaryTarget("THIS IS NOT valid !! SQL (("));

    [Fact]
    public void FirstDmlStatementInABatch_WinsOverLaterOnes()
    {
        var target = DmlTargetTableResolver.ResolvePrimaryTarget(
            "UPDATE dbo.First SET X = 1; DELETE FROM dbo.Second WHERE Id = 1;");
        Assert.Equal(new SchemaTable("dbo", "First"), target);
    }
}
