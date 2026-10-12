using LogCarverGuard.Core;

// Admin-side management for the API keys 規劃書 三-5 describes ("每人一把
// 獨立 key,申請制(跟團隊負責人要)") - a CLI rather than a web admin UI or a
// second HTTP surface on the server, for the same reason the proxy itself
// uses SQLite instead of a real database service: one more thing exposed to
// the network is one more thing to secure, and issuing/revoking keys is an
// infrequent, already-on-the-box operation for whoever administers this
// deployment. Operates directly on the same SQLite file the running server
// uses (same LOGCARVERGUARD_APIKEYS_DB_PATH env var convention), so no
// server restart or API round-trip is needed to pick up a change.

const string ApiKeyHeaderName = "X-LogCarverGuard-Key"; // must match SqlTools.ApiKeyHeaderName

if (args.Length == 0 || args[0] is "-h" or "--help" or "help")
{
    PrintUsage();
    return 0;
}

string dbPath = GetFlag(args, "--apikeys-db")
    ?? Environment.GetEnvironmentVariable("LOGCARVERGUARD_APIKEYS_DB_PATH")
    ?? "logcarverguard-apikeys.db";

return args[0] switch
{
    "issue-key" => await IssueKeyAsync(args, dbPath),
    "revoke-key" => await RevokeKeyAsync(args, dbPath),
    "list-keys" => await ListKeysAsync(dbPath),
    _ => Unknown(args[0]),
};

async Task<int> IssueKeyAsync(string[] args, string dbPath)
{
    string? owner = GetFlag(args, "--owner");
    string? login = GetFlag(args, "--login");
    if (owner is null || login is null)
    {
        Console.Error.WriteLine("issue-key requires --owner <name> and --login <real-sql-login>.");
        return 1;
    }

    await using var store = new ApiKeyStore(dbPath);
    var issued = await store.IssueAsync(owner, login);

    Console.WriteLine($"Issued key Id {issued.Id} for '{owner}' -> SQL login '{login}'.");
    Console.WriteLine();
    Console.WriteLine($"  {issued.RawKey}");
    Console.WriteLine();
    Console.WriteLine("This is shown once and cannot be recovered - store it now");
    Console.WriteLine($"(e.g. the MCP client's '{ApiKeyHeaderName}' header).");
    return 0;
}

static async Task<int> RevokeKeyAsync(string[] args, string dbPath)
{
    string? idText = GetFlag(args, "--id");
    if (idText is null || !long.TryParse(idText, out long id))
    {
        Console.Error.WriteLine("revoke-key requires --id <number> (see list-keys for ids).");
        return 1;
    }

    await using var store = new ApiKeyStore(dbPath);
    bool revoked = await store.RevokeAsync(id);

    if (revoked)
    {
        Console.WriteLine($"Revoked key Id {id}.");
        return 0;
    }

    Console.Error.WriteLine($"No active key with Id {id} (already revoked, or never existed).");
    return 1;
}

static async Task<int> ListKeysAsync(string dbPath)
{
    await using var store = new ApiKeyStore(dbPath);
    var keys = await store.ListAsync();

    if (keys.Count == 0)
    {
        Console.WriteLine("No API keys issued yet.");
        return 0;
    }

    Console.WriteLine($"{"Id",-6} {"Owner",-20} {"SQL Login",-25} {"Created (UTC)",-20} Status");
    foreach (var key in keys)
    {
        string status = key.IsRevoked ? $"revoked {key.RevokedAtUtc:yyyy-MM-dd HH:mm}" : "active";
        Console.WriteLine($"{key.Id,-6} {key.Owner,-20} {key.SqlLogin,-25} {key.CreatedAtUtc,-20:yyyy-MM-dd HH:mm} {status}");
    }
    return 0;
}

static string? GetFlag(string[] args, string name)
{
    for (int i = 0; i < args.Length - 1; i++)
    {
        if (args[i] == name) return args[i + 1];
    }
    return null;
}

static int Unknown(string command)
{
    Console.Error.WriteLine($"Unknown command '{command}'.");
    PrintUsage();
    return 1;
}

static void PrintUsage()
{
    Console.WriteLine("""
        LogCarverGuard admin CLI - manage API keys for the MCP proxy.

        Usage:
          issue-key  --owner <name> --login <real-sql-login> [--apikeys-db <path>]
          revoke-key --id <id>                                [--apikeys-db <path>]
          list-keys                                            [--apikeys-db <path>]

        --apikeys-db defaults to the LOGCARVERGUARD_APIKEYS_DB_PATH environment
        variable (the same one the running server reads), or
        "logcarverguard-apikeys.db" if neither is set.
        """);
}
