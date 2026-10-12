using System.Net;
using LogCarverGuard.Server;

namespace LogCarverGuard.Server.Tests;

public class ClientIpAllowlistTests
{
    [Fact]
    public void UnsetOrEmpty_AllowsEverything()
    {
        Assert.True(ClientIpAllowlist.Parse(null).IsAllowed(IPAddress.Parse("203.0.113.5")));
        Assert.True(ClientIpAllowlist.Parse("").IsAllowed(IPAddress.Parse("203.0.113.5")));
        Assert.False(ClientIpAllowlist.Parse(null).IsRestricted);
    }

    [Fact]
    public void ExactIp_OnlyMatchesItself()
    {
        var allowlist = ClientIpAllowlist.Parse("10.0.0.5");
        Assert.True(allowlist.IsRestricted);
        Assert.True(allowlist.IsAllowed(IPAddress.Parse("10.0.0.5")));
        Assert.False(allowlist.IsAllowed(IPAddress.Parse("10.0.0.6")));
    }

    [Fact]
    public void CidrRange_MatchesAnyAddressInsideIt()
    {
        var allowlist = ClientIpAllowlist.Parse("10.0.0.0/24");
        Assert.True(allowlist.IsAllowed(IPAddress.Parse("10.0.0.200")));
        Assert.False(allowlist.IsAllowed(IPAddress.Parse("10.0.1.1")));
    }

    [Fact]
    public void MultipleEntries_AnyMatchIsEnough()
    {
        var allowlist = ClientIpAllowlist.Parse("10.0.0.5, 192.168.1.0/24");
        Assert.True(allowlist.IsAllowed(IPAddress.Parse("10.0.0.5")));
        Assert.True(allowlist.IsAllowed(IPAddress.Parse("192.168.1.50")));
        Assert.False(allowlist.IsAllowed(IPAddress.Parse("172.16.0.1")));
    }

    [Fact]
    public void NullRemoteIp_IsNeverAllowed_WhenRestricted() =>
        Assert.False(ClientIpAllowlist.Parse("10.0.0.5").IsAllowed(null));

    [Fact]
    public void Ipv4MappedIpv6Address_IsUnwrappedBeforeMatching()
    {
        var allowlist = ClientIpAllowlist.Parse("10.0.0.5");
        var mapped = IPAddress.Parse("::ffff:10.0.0.5");
        Assert.True(allowlist.IsAllowed(mapped));
    }

    [Fact]
    public void MalformedEntry_ThrowsAtParseTime() =>
        Assert.Throws<InvalidOperationException>(() => ClientIpAllowlist.Parse("not-an-ip"));
}
