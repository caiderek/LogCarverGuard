# LogCarverGuard

**English | [繁體中文](README.zh-TW.md)**

An [MCP](https://modelcontextprotocol.io) proxy that lets an AI coding agent (Claude Code, Cursor, …) read and write a **production** SQL Server without handing it the real credentials or a free hand. Every statement runs under the caller's own SQL login and grants, dangerous statements are blocked before they reach the database, and everything is written to an audit log.

> **Status:** early (v0.1).

## What it does

```
AI agent --(MCP, API key)--> LogCarverGuard proxy --(EXECUTE AS the caller's own login)--> SQL Server
```

- **One tool, `execute_sql`.** Reads and writes go through it. A `SELECT` returns its rows (first 100 shown, with a count of the rest). A write is executed and audited.
- **A real T-SQL parser decides what is allowed**, not keyword matching, so a fake keyword inside a comment or string does nothing.
- **The AI never sees the database password.** The proxy holds one service login. Each person gets an API key that maps to their own SQL login, and the proxy impersonates it, so their existing `GRANT`/`DENY` still decide what they can do.
- **The service login does not need sysadmin.** It needs `IMPERSONATE` on each user's login, and a database user in the target database so it can connect. The host tests run SELECT, UPDATE and a permission-denied DELETE through a service account that is not sysadmin.
- **Data changes run in a transaction the proxy controls.** A batch containing `INSERT` / `UPDATE` / `DELETE` is rolled back as a whole if any statement fails. DDL (`ALTER TABLE`…), `TRUNCATE` and `EXEC` run as they are and are not rolled back as part of a batch. `BEGIN TRAN` / `COMMIT` / `ROLLBACK` from the caller is blocked.
- **Audit log** in a local SQLite file: who, when, which SQL, and whether it was blocked or executed. Executed statements are recorded after they commit. A statement that SQL Server rejects (for example permission denied) or a request with a bad key is not recorded.

### Always blocked

`DROP TABLE`, `DROP DATABASE`, `RESTORE DATABASE` / `RESTORE LOG`, `ALTER DATABASE … SET`, `sp_executesql`, `xp_cmdshell`, dynamic `EXEC` of a variable or string, identity switching (`REVERT`, `EXECUTE AS`, `SETUSER`), permission changes (`GRANT`, `DENY`, `REVOKE`), and caller-managed transactions (`BEGIN TRAN`, `COMMIT`, `ROLLBACK`, `SAVE TRANSACTION`).

### Blocked unless the admin allow-lists it

`TRUNCATE TABLE`, `ALTER TABLE … DROP COLUMN`, and `EXEC` of a named stored procedure (including `INSERT … EXEC`). Allow-list entries are written as `schema.name`; a statement that names a database or a server (`OtherDb.dbo.T`, `[srv].db.dbo.P`) is never matched against them.

This list is deliberately narrow. It is not "everything an AI could break": `DROP INDEX`, `sp_rename`, `BACKUP DATABASE`, or a Linked Server `OPENQUERY` are not specially handled and run if the real login may run them. **The real security boundary is the SQL login's own grants**, so issue each API key against an account with the least privilege you can accept, never sysadmin or db_owner.

## Install

Needs a Linux host with Docker, and a SQL Server with TCP/IP enabled and **mixed-mode authentication**.

1. **Create the service login** and let it impersonate each user's own login:

   ```sql
   CREATE LOGIN logcarverguard_svc WITH PASSWORD = '…';
   GRANT IMPERSONATE ON LOGIN::[alice_sql_login] TO logcarverguard_svc;
   ```

   In the target database, create a database user for the service login **and** one for each person's login, then give each person the permissions they normally have; the proxy never widens them:

   ```sql
   CREATE USER logcarverguard_svc FOR LOGIN logcarverguard_svc;
   CREATE USER alice_sql_login FOR LOGIN alice_sql_login;
   GRANT SELECT, UPDATE ON dbo.Orders TO alice_sql_login;
   ```

2. **Clone and configure**

   ```bash
   git clone https://github.com/caiderek/LogCarverGuard
   cd LogCarverGuard
   ```

   Edit `docker-compose.yml` and set `LOGCARVERGUARD_SQLSERVER_CONNECTION_STRING`. For production prefer a mounted secret file and `LOGCARVERGUARD_SQLSERVER_CONNECTION_STRING_FILE`.

3. **Start**

   ```bash
   docker compose up -d --build
   docker compose logs -f
   ```

4. **Issue an API key** (`--login` is the user's own SQL login, not the service login). The key is printed once:

   ```bash
   docker compose exec logcarverguard dotnet cli/LogCarverGuard.Cli.dll \
     issue-key --owner alice --login alice_sql_login
   ```

5. Point your MCP client at `http://<host>:8080/` and send the key in the header `X-LogCarverGuard-Key`.

Other key commands: `list-keys` (never prints the key itself) and `revoke-key --id <n>`.

## Configuration

All settings are environment variables; they take priority over `appsettings.json`.

| Variable | Purpose | Default |
|---|---|---|
| `LOGCARVERGUARD_SQLSERVER_CONNECTION_STRING` (or `_FILE`) | The proxy's service login | required |
| `LOGCARVERGUARD_AUDIT_DB_PATH` | Audit log SQLite file | `logcarverguard-audit.db` |
| `LOGCARVERGUARD_APIKEYS_DB_PATH` | API key SQLite file | `logcarverguard-apikeys.db` |
| `LOGCARVERGUARD_TRUNCATE_ALLOWLIST` | Tables where `TRUNCATE` is allowed | empty (all blocked) |
| `LOGCARVERGUARD_EXEC_WHITELIST` | Stored procedures that may be `EXEC`'d | empty (all blocked) |
| `LOGCARVERGUARD_ALTER_DROP_COLUMN_ALLOWLIST` | Tables where `DROP COLUMN` is allowed | empty (all blocked) |
| `LOGCARVERGUARD_ALLOWED_CLIENT_IPS` | IPs / CIDR ranges allowed to connect, checked before the key | empty (no restriction) |
| `LOGCARVERGUARD_TRUSTED_PROXIES` | Peers trusted to set `X-Forwarded-For` (only behind a reverse proxy) | empty (header never read) |
| `ASPNETCORE_URLS` | Listen address | deployment dependent |

Set `Initial Catalog` in the connection string to the database the agent should work in.

## Hardening for production

- **Do not leave `TrustServerCertificate=true` in production.** The sample connection string uses it for convenience; it turns off validation of SQL Server's certificate, so install a trusted certificate and drop it.
- **Use TLS.** The key travels in an HTTP header; over plain HTTP it can be sniffed and gives whoever holds it that person's whole SQL access. Put a TLS-terminating reverse proxy in front. The compose file binds to `127.0.0.1` by default for that reason.
- **Restrict who can connect** with `LOGCARVERGUARD_ALLOWED_CLIENT_IPS`, in addition to the host firewall. Behind a reverse proxy also set `LOGCARVERGUARD_TRUSTED_PROXIES`, otherwise every request appears to come from the proxy.
- **Back up the `/data` volume.** It holds the audit log and the key hashes.
- Keep the .NET runtime and the MCP SDK updated.

## Known limits

- SQL Server only, and Linux only for now.
- It only governs SQL sent through this MCP connection. If the agent has other tools (files, APIs, cloud consoles), this proxy cannot see or stop those.
- The API key is a single static secret: no mTLS, no device binding, no short-lived tokens.
- No mask-on-read: if an account can `SELECT` sensitive data, the agent can read it.
- SQL Server's own error text is returned to the caller as it is. It can name databases, objects and logins, and features such as `OPENROWSET` / `OPENQUERY` are not blocked, so an agent holding a key with enough permission can use them to probe what the SQL Server can reach.
- A `SELECT` keeps at most 1000 rows in memory (the first 100 are shown, the true count is reported).
- The audit log is a SQLite file read directly; there is no MCP tool for browsing it.

## Build and test

```bash
dotnet build
dotnet test
```

The integration tests need a local SQL Server and a Windows login that is sysadmin; they create and drop their own `LogCarverGuard_*` databases and logins.

## Related

[LogCarver](https://github.com/caiderek/LogCarver) (free, MIT) reads deleted rows from a SQL Server transaction log. [LogCarver.Mcp](https://github.com/caiderek/LogCarver.Mcp) exposes it to AI assistants over MCP.

## License

MIT, see [LICENSE](LICENSE).
