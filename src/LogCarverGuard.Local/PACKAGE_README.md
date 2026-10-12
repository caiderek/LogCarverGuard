<!-- mcp-name: io.github.caiderek/logcarverguard -->

# LogCarverGuard.Local

A local [MCP](https://modelcontextprotocol.io) server that puts a statement guard, an optional read-only mode and an audit log between an AI agent and your SQL Server. It runs on your own machine, started by your AI tool over stdio: no server, no Docker, no API keys.

> **A guardrail, not a security boundary.** It protects against an agent doing something destructive by accident. See "What it is, and is not" below.

## Install

```
dotnet tool install -g LogCarverGuard.Local
claude mcp add logcarverguard --env LOGCARVERGUARD_CONNECTION_STRING="Server=localhost;Database=MyDb;Integrated Security=true;TrustServerCertificate=true" -- logcarverguard
```

To run it without installing, end the command with `-- dotnet dnx LogCarverGuard.Local --yes`.

## What it does

One tool, `execute_sql`.

- A `SELECT` returns its rows (the first 100 shown, with the true count).
- A real T-SQL parser blocks `DROP TABLE`, `DROP DATABASE`, `RESTORE`, `ALTER DATABASE ... SET`, dynamic `EXEC`, `sp_executesql`, `xp_cmdshell`, identity switching (`REVERT`, `EXECUTE AS`), permission changes and caller-managed transactions. `TRUNCATE`, `DROP COLUMN` and named `EXEC` are blocked unless you allow-list them.
- Data changes run in a transaction the proxy controls, so a batch of `INSERT` / `UPDATE` / `DELETE` is rolled back as a whole if one fails.
- Every blocked or executed statement is written to a local SQLite audit log.
- If SQL Server rejects a statement, the agent gets the reason instead of a generic error.

## Settings

Environment variables only. An `appsettings.json` in the working directory is ignored.

| Variable | Purpose | Default |
|---|---|---|
| `LOGCARVERGUARD_CONNECTION_STRING` (or `_FILE`) | The login the statements run as | required |
| `LOGCARVERGUARD_READ_ONLY` | `true` allows queries only | `false` |
| `LOGCARVERGUARD_AUDIT_DB_PATH` | Audit log SQLite file | `LogCarverGuard/audit.db` under your local application data folder |
| `LOGCARVERGUARD_TRUNCATE_ALLOWLIST` | `schema.table` entries where `TRUNCATE` is allowed | empty |
| `LOGCARVERGUARD_EXEC_WHITELIST` | `schema.procedure` entries that may be `EXEC`'d | empty |
| `LOGCARVERGUARD_ALTER_DROP_COLUMN_ALLOWLIST` | `schema.table` entries where `DROP COLUMN` is allowed | empty |

A blank `LOGCARVERGUARD_READ_ONLY` or an unwritable audit path stops the server with a message instead of starting in a weaker state.

## Read-only mode

Lets `SELECT` (without `INTO`) through, plus `SET`, `DECLARE` and `PRINT`. Everything else is blocked with a reason, including `EXEC` even when it is allow-listed, `NEXT VALUE FOR`, and the remote or file sources `OPENQUERY`, `OPENROWSET` and `OPENDATASOURCE`, which can run a write on another server.

Not covered: a `SELECT` that calls a CLR or extended-procedure function with side effects, long-running or expensive queries, and locks. Give the login only the permissions it needs; the guard is a second line of defence, not the first.

## What it is, and is not

- The connection string, and so the credentials, live on your machine and in your AI tool's configuration. An agent that can run shell commands or read that configuration can connect to SQL Server directly and skip this server.
- Every statement runs as the one login in the connection string. There is no per-person identity; the audit log records the operating-system user name and is a local file.
- It governs only the SQL sent through this MCP connection.
- For a real boundary, use the central service in the [repository](https://github.com/caiderek/LogCarverGuard): SQL Server accepts connections only from the proxy, and each person has their own login.

Tested on Windows with integrated authentication.

## Links

- Source, central service and full documentation: https://github.com/caiderek/LogCarverGuard
- [繁體中文說明](https://github.com/caiderek/LogCarverGuard/blob/master/README.zh-TW.md)
- MIT licensed.
