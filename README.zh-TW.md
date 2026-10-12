# LogCarverGuard

**[English](README.md) | 繁體中文**

讓 AI coding agent(Claude Code、Cursor 等)透過 [MCP](https://modelcontextprotocol.io) 讀寫**正式環境**的 SQL Server,但不用把真正的帳密或放任的權限交給它。每句 SQL 都以呼叫者自己的 SQL 登入身分執行,危險語句在碰到資料庫之前就被擋下,所有操作都寫進稽核紀錄。

> **狀態:** 早期版本(v0.1)。

## 它做什麼

```
AI agent --(MCP, API key)--> LogCarverGuard proxy --(用呼叫者自己的登入 EXECUTE AS)--> SQL Server
```

- **只有一個 tool:`execute_sql`。** 讀跟寫都走它。`SELECT` 會回傳查詢結果(最多顯示 100 列,超過會註明還有多少列沒顯示);寫入會被執行並留下稽核紀錄。
- **用真正的 T-SQL 剖析器判斷語句**,不是關鍵字比對,在註解或字串裡塞假關鍵字沒有用。
- **AI 永遠看不到資料庫密碼。** proxy 自己只持有一個服務登入。每個人拿到的是 proxy 發的 API key,對應到他自己的 SQL 登入,proxy 用 `EXECUTE AS` 模擬那個身分,所以原本的 `GRANT`/`DENY` 仍然決定他能做什麼。
- **服務登入不需要 sysadmin。** 它只需要對每個使用者的登入有 `IMPERSONATE`,以及在目標資料庫裡有一個資料庫使用者才能連線。主機測試用非 sysadmin 的服務帳號跑過 SELECT、UPDATE,以及一個權限不足而被拒絕的 DELETE。
- **資料變更在 proxy 自己控制的交易裡執行。** 含 `INSERT` / `UPDATE` / `DELETE` 的批次,只要其中一句失敗就整批回滾。DDL(`ALTER TABLE`…)、`TRUNCATE`、`EXEC` 照原樣執行,不會跟著批次一起回滾。呼叫者自己寫 `BEGIN TRAN` / `COMMIT` / `ROLLBACK` 會被擋下。
- **稽核紀錄**存在本機 SQLite:誰、什麼時候、哪句 SQL、被擋下還是已執行。已執行的語句是在 commit 之後才記錄;被 SQL Server 拒絕的語句(例如權限不足)和帶錯 key 的請求不會被記錄。

### 一律封鎖

`DROP TABLE`、`DROP DATABASE`、`RESTORE DATABASE` / `RESTORE LOG`、`ALTER DATABASE … SET`、`sp_executesql`、`xp_cmdshell`、對變數或字串的動態 `EXEC`、切換執行身份(`REVERT`、`EXECUTE AS`、`SETUSER`)、權限變更(`GRANT`、`DENY`、`REVOKE`)、由呼叫端自己管理交易(`BEGIN TRAN`、`COMMIT`、`ROLLBACK`、`SAVE TRANSACTION`)。

### 預設封鎖,管理者可以逐項核准

`TRUNCATE TABLE`、`ALTER TABLE … DROP COLUMN`、具名預存程序的 `EXEC`(包含 `INSERT … EXEC`)。允許清單的項目寫成 `schema.名稱`;語句裡帶了資料庫或伺服器名稱(`OtherDb.dbo.T`、`[srv].db.dbo.P`)就一律不會比對到清單。

這份清單是刻意限定範圍的,**不是「擋住 AI 能做的所有壞事」**:`DROP INDEX`、`sp_rename`、`BACKUP DATABASE`、透過 Linked Server 的 `OPENQUERY` 都沒有特別處理,只要那個真實登入有權限就會執行。**真正的安全邊界是 SQL 登入自己的 GRANT/DENY**,所以每把 API key 請對應到你能接受的最小權限帳號,不要給 sysadmin 或 db_owner。

## 本機模式

在你自己的機器上執行,由 AI 工具透過 stdio 啟動。不需要伺服器、不需要 Docker、不需要 API key。設定只讀取環境變數(不讀 `appsettings.json` 或命令列參數)。在 Windows 與整合式驗證下測試過。

```
dotnet tool install -g LogCarverGuard.Local
claude mcp add logcarverguard --env LOGCARVERGUARD_CONNECTION_STRING="Server=localhost;Database=MyDb;Integrated Security=true;TrustServerCertificate=true" -- logcarverguard
```

也可以不安裝,透過 `dnx` 直接執行(指令結尾改成 `-- dotnet dnx LogCarverGuard.Local --yes`)。

| 環境變數 | 用途 | 預設值 |
|---|---|---|
| `LOGCARVERGUARD_CONNECTION_STRING`(或 `_FILE`) | 語句以哪個登入身分執行 | 必填 |
| `LOGCARVERGUARD_READ_ONLY` | `true` 時只允許查詢 | `false` |
| `LOGCARVERGUARD_AUDIT_DB_PATH` | 稽核紀錄 SQLite 路徑 | 本機應用程式資料夾下的 `LogCarverGuard/audit.db` |
| `LOGCARVERGUARD_TRUNCATE_ALLOWLIST`、`LOGCARVERGUARD_EXEC_WHITELIST`、`LOGCARVERGUARD_ALTER_DROP_COLUMN_ALLOWLIST` | 跟中央服務相同的白名單 | 空(全部擋) |

**唯讀模式**只放行 `SELECT`(不含 `INTO`),以及 `SET`、`DECLARE`、`PRINT`。其他一律擋下並說明原因,包含即使在白名單上的 `EXEC`、`NEXT VALUE FOR`,以及遠端或檔案來源 `OPENQUERY`、`OPENROWSET`、`OPENDATASOURCE`(它們可以在別的伺服器上執行寫入)。唯讀模式沒有涵蓋的:`SELECT` 呼叫有副作用的 CLR 或擴充預存程序函式、執行很久或很耗資源的查詢,以及鎖定。登入帳號本身也請只給它需要的權限,guard 是第二道防線,不是第一道。

**本機模式是什麼、不是什麼。** 它是防止 agent 手滑做出破壞性操作的護欄,**不是安全邊界**:

- 連線字串(也就是帳密)在你的機器上,也在 AI 工具的設定檔裡。能執行 shell 指令或讀取那份設定的 agent,可以直接連 SQL Server 繞過這個 proxy。
- 所有語句都以連線字串裡那一個登入身分執行,沒有逐人身分;稽核紀錄記的是作業系統使用者名稱,而且是本機檔案。
- 要真正的邊界,請用下面的中央服務:SQL Server 只接受 proxy 的連線,而且每個人有自己的登入。

## 安裝中央服務

需要一台跑 Docker 的 Linux 主機,以及開啟 TCP/IP、啟用**混合驗證模式**的 SQL Server。

1. **建立服務登入**,並讓它能模擬每個使用者自己的登入:

   ```sql
   CREATE LOGIN logcarverguard_svc WITH PASSWORD = '…';
   GRANT IMPERSONATE ON LOGIN::[alice_sql_login] TO logcarverguard_svc;
   ```

   在目標資料庫裡,替服務登入**以及**每個人的登入各建立一個資料庫使用者,再依平常該有的權限授權,proxy 不會放大任何人的權限:

   ```sql
   CREATE USER logcarverguard_svc FOR LOGIN logcarverguard_svc;
   CREATE USER alice_sql_login FOR LOGIN alice_sql_login;
   GRANT SELECT, UPDATE ON dbo.Orders TO alice_sql_login;
   ```

2. **Clone 並設定**

   ```bash
   git clone https://github.com/caiderek/LogCarverGuard
   cd LogCarverGuard
   ```

   編輯 `docker-compose.yml`,填入 `LOGCARVERGUARD_SQLSERVER_CONNECTION_STRING`。正式環境建議改用掛載的密鑰檔,設定 `LOGCARVERGUARD_SQLSERVER_CONNECTION_STRING_FILE`。

3. **啟動**

   ```bash
   docker compose up -d --build
   docker compose logs -f
   ```

4. **發一把 API key**(`--login` 是使用者自己的 SQL 登入,不是服務登入)。這把 key 只會印出一次:

   ```bash
   docker compose exec logcarverguard dotnet cli/LogCarverGuard.Cli.dll \
     issue-key --owner alice --login alice_sql_login
   ```

5. 把 MCP client 指到 `http://<主機>:8080/`,並在 header `X-LogCarverGuard-Key` 帶上這把 key。

其他 key 指令:`list-keys`(不會印出金鑰本身)、`revoke-key --id <n>`。

## 設定

全部設定都是環境變數,優先權高於 `appsettings.json`。

| 環境變數 | 用途 | 預設值 |
|---|---|---|
| `LOGCARVERGUARD_SQLSERVER_CONNECTION_STRING`(或 `_FILE`) | proxy 的服務登入 | 必填 |
| `LOGCARVERGUARD_AUDIT_DB_PATH` | 稽核紀錄 SQLite 路徑 | `logcarverguard-audit.db` |
| `LOGCARVERGUARD_APIKEYS_DB_PATH` | API key SQLite 路徑 | `logcarverguard-apikeys.db` |
| `LOGCARVERGUARD_TRUNCATE_ALLOWLIST` | 允許 `TRUNCATE` 的表 | 空(全部擋) |
| `LOGCARVERGUARD_EXEC_WHITELIST` | 允許 `EXEC` 的預存程序 | 空(全部擋) |
| `LOGCARVERGUARD_ALTER_DROP_COLUMN_ALLOWLIST` | 允許 `DROP COLUMN` 的表 | 空(全部擋) |
| `LOGCARVERGUARD_ALLOWED_CLIENT_IPS` | 允許連進來的 IP / CIDR,在驗證 key 之前檢查 | 空(不限制) |
| `LOGCARVERGUARD_TRUSTED_PROXIES` | 信任其 `X-Forwarded-For` 的直連來源(只有架在反向代理後面才需要) | 空(不讀這個 header) |
| `ASPNETCORE_URLS` | 監聽位址 | 依部署方式 |

連線字串請設定 `Initial Catalog` 為 agent 要作業的資料庫。

## 正式環境的資安強化

- **正式環境不要留著 `TrustServerCertificate=true`。** 範例連線字串為了方便用了它,它會關掉對 SQL Server 憑證的驗證;請安裝受信任的憑證並拿掉它。
- **一定要用 TLS。** key 是放在 HTTP header 裡傳的,明文 HTTP 下被側錄,拿到的人就等於拿到那個人在 SQL Server 上的全部權限。前面加一層會終止 TLS 的反向代理。compose 檔預設只綁 `127.0.0.1` 就是這個原因。
- **限制誰能連進來**:除了主機防火牆,再用 `LOGCARVERGUARD_ALLOWED_CLIENT_IPS` 加一層。架在反向代理後面時還要設 `LOGCARVERGUARD_TRUSTED_PROXIES`,否則每個請求看起來都來自代理本身。
- **備份 `/data` 這個 volume**,稽核紀錄和 key 的雜湊都在裡面。
- .NET runtime 與 MCP SDK 要保持更新。

## 已知限制

- 只支援 SQL Server。中央服務跑在 Linux(Docker);本機模式在 Windows 與整合式驗證下測試過。
- 只管得到透過這個 MCP 連線送出的 SQL。如果 agent 還有別的工具(讀寫檔案、呼叫 API、雲端主控台),proxy 看不到也擋不了。
- API key 只是一把固定的密鑰,沒有 mTLS、沒有裝置綁定、沒有短期 token。
- 沒有讀取時遮蔽(mask-on-read):帳號能 `SELECT` 到的敏感資料,agent 一樣讀得到。
- SQL Server 自己的錯誤訊息會原樣回傳給呼叫者,可能包含資料庫、物件、登入名稱;`OPENROWSET` / `OPENQUERY` 這類功能也沒有被擋,持有權限足夠的 key 的 agent 可以用它們探測這台 SQL Server 連得到哪裡。
- `SELECT` 最多在記憶體裡保留 1000 列(顯示前 100 列,並回報實際總列數)。
- 稽核紀錄是直接讀 SQLite 檔,沒有提供瀏覽用的 MCP tool。

## 建置與測試

```bash
dotnet build
dotnet test
```

整合測試需要本機有 SQL Server,以及 sysadmin 的 Windows 登入;測試會自己建立並刪除 `LogCarverGuard_*` 開頭的資料庫與登入。

## 相關專案

[LogCarver](https://github.com/caiderek/LogCarver)(免費、MIT)從 SQL Server 交易記錄檔讀出被刪除的資料列。[LogCarver.Mcp](https://github.com/caiderek/LogCarver.Mcp) 把它以 MCP 提供給 AI 助理。

## 授權

MIT,見 [LICENSE](LICENSE)。
