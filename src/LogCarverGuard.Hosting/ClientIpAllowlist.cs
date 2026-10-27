using System.Net;

namespace LogCarverGuard.Server;

/// <summary>
/// Restricts which client IPs may reach the MCP endpoint at all, independent
/// of API-key auth and independent of the host's own firewall:
/// relying on an operator to correctly scope their firewall is not a safe
/// assumption, while this proxy's own fixed listening port is something an operator
/// is far less likely to misconfigure than a firewall rule they have to
/// remember to write themselves.
///
/// Unset/empty means "no restriction" (every request's IP is allowed) -
/// deliberately the default, since most self-hosted deployments run the
/// proxy and the AI agent on the same trusted network and shouldn't need to
/// configure this to get started.
/// </summary>
public sealed class ClientIpAllowlist
{
    private readonly IReadOnlyList<IPNetwork> _allowed;

    public bool IsRestricted => _allowed.Count > 0;

    private ClientIpAllowlist(IReadOnlyList<IPNetwork> allowed) => _allowed = allowed;

    /// <summary>
    /// Parses LOGCARVERGUARD_ALLOWED_CLIENT_IPS - a comma-separated list of
    /// individual IPs ("10.0.0.5") and/or CIDR ranges ("10.0.0.0/24",
    /// "::1/128"). Throws on a genuinely malformed entry rather than
    /// silently ignoring it - a typo here should fail startup loudly, not
    /// quietly leave the proxy wide open.
    /// </summary>
    public static ClientIpAllowlist Parse(string? raw)
    {
        var list = new List<IPNetwork>();
        if (!string.IsNullOrWhiteSpace(raw))
        {
            foreach (var entry in raw.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                if (IPNetwork.TryParse(entry, out var network))
                {
                    list.Add(network);
                }
                else if (IPAddress.TryParse(entry, out var address))
                {
                    int prefixLength = address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? 128 : 32;
                    list.Add(new IPNetwork(address, prefixLength));
                }
                else
                {
                    throw new InvalidOperationException(
                        $"LOGCARVERGUARD_ALLOWED_CLIENT_IPS has an entry that isn't a valid IP or CIDR range: '{entry}'.");
                }
            }
        }
        return new ClientIpAllowlist(list);
    }

    public bool IsAllowed(IPAddress? remoteIp)
    {
        if (!IsRestricted) return true;
        if (remoteIp is null) return false;

        // A dual-stack listener can hand back an IPv4 address wrapped as
        // IPv4-mapped IPv6 (e.g. "::ffff:10.0.0.5") - unwrap it so an
        // operator's plain IPv4 entries still match.
        var candidate = remoteIp.IsIPv4MappedToIPv6 ? remoteIp.MapToIPv4() : remoteIp;
        return _allowed.Any(network => network.Contains(candidate));
    }
}
