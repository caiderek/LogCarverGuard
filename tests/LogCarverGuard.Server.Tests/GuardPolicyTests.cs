using LogCarverGuard.Server;

namespace LogCarverGuard.Server.Tests;

public class GuardPolicyTests
{
    [Theory]
    [InlineData("dbo.Staging", "dbo", "Staging")]
    [InlineData("[dbo].[Staging]", "dbo", "Staging")]
    [InlineData("\"dbo\".\"Staging\"", "dbo", "Staging")]
    [InlineData("Staging", "dbo", "Staging")]
    [InlineData("[Sales].[Order Items]", "Sales", "Order Items")]
    public void AllowListEntries_AcceptBracketsAndQuotes(string entry, string schema, string name)
    {
        var set = GuardPolicy.ParseList(entry);

        Assert.Contains((schema, name), set);
    }

    [Fact]
    public void AllowListMatching_IsCaseInsensitive() =>
        Assert.Contains(("DBO", "staging"), GuardPolicy.ParseList("dbo.Staging"));

    [Fact]
    public void EmptyOrMissing_MeansNothingIsAllowed()
    {
        Assert.Empty(GuardPolicy.ParseList(null));
        Assert.Empty(GuardPolicy.ParseList("  "));
    }
}
