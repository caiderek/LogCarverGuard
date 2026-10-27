using Microsoft.SqlServer.TransactSql.ScriptDom;

namespace LogCarverGuard.Core;

public enum GuardDecision { Allow, Block }

public sealed record GuardVerdict(GuardDecision Decision, string? Reason, bool AllowedByAllowList = false)
{
    public static GuardVerdict Allow(bool allowedByAllowList = false) => new(GuardDecision.Allow, null, allowedByAllowList);
    public static GuardVerdict Block(string reason) => new(GuardDecision.Block, reason);
}

/// <summary>
/// 決定一句 SQL 能不能透過 proxy 送到 SQL Server。
/// 用官方 T-SQL 剖析器(ScriptDom)做分類,不是正規表示式/關鍵字比對,
/// 這樣註解、字串值裡的假關鍵字不會被誤判。
///
/// 呼叫端要在送到 SQL Server 之前先呼叫這個檢查——封鎖必須發生在送出去之前,
/// 不是等 SQL Server 回應之後。
/// </summary>
public static class SqlStatementGuard
{
    // 這幾個是 SQL Server 內建、本質上就是動態 SQL/作業系統逃逸通道的系統預存程序,
    // 永遠封鎖,不走白名單邏輯——放進白名單等於又開回動態 SQL 的後門。
    private static readonly HashSet<string> HardBlockedProcedures = new(StringComparer.OrdinalIgnoreCase)
    {
        "sp_executesql",
        "xp_cmdshell",
    };

    public static GuardVerdict Evaluate(
        string sql,
        IReadOnlySet<(string Schema, string Table)> truncateAllowedTables,
        IReadOnlySet<(string Schema, string Procedure)> execWhitelist,
        IReadOnlySet<(string Schema, string Table)>? alterTableDropColumnAllowedTables = null,
        bool readOnly = false)
    {
        var parser = new TSql170Parser(initialQuotedIdentifiers: true);
        using var reader = new StringReader(sql);
        var fragment = parser.Parse(reader, out var errors);

        if (errors.Count > 0)
            return GuardVerdict.Block($"SQL 剖析失敗,保守拒絕:{string.Join("; ", errors.Select(e => e.Message))}");

        // Read-only mode is an allow-list of statement shapes, checked on top of
        // (not instead of) the ordinary rules below.
        if (readOnly && ReadOnlyViolation(fragment) is { } violation)
            return GuardVerdict.Block(violation);

        var visitor = new GuardVisitor(
            truncateAllowedTables, execWhitelist,
            alterTableDropColumnAllowedTables ?? new HashSet<(string, string)>(),
            HardBlockedProcedures);
        fragment.Accept(visitor);

        return visitor.Verdict;
    }

    private static string? ReadOnlyViolation(TSqlFragment fragment)
    {
        if (fragment is not TSqlScript script)
            return "唯讀模式(read-only mode)只允許查詢:無法辨識這段 SQL 的結構";

        foreach (var batch in script.Batches)
        {
            foreach (var statement in batch.Statements)
            {
                bool allowed = statement switch
                {
                    SelectStatement select => select.Into is null,
                    PredicateSetStatement => true,
                    DeclareVariableStatement => true,
                    SetVariableStatement => true,
                    PrintStatement => true,
                    _ => false,
                };
                if (!allowed)
                    return $"唯讀模式(read-only mode)只允許查詢,這句不是查詢:{DescribeStatement(statement)}";
            }
        }

        // A SELECT that advances a sequence changes state, so it is not a query here.
        var sequenceUse = new NextValueForFinder();
        script.Accept(sequenceUse);
        if (sequenceUse.Found)
            return "唯讀模式(read-only mode)不允許 NEXT VALUE FOR,它會改變序列的目前值";

        // OPENQUERY / OPENROWSET / OPENDATASOURCE hand a command string to
        // another server (or read a file), and that command can be a write.
        // The audit log and this guard would both record it as a plain SELECT.
        var remote = new RemoteSourceFinder();
        script.Accept(remote);
        return remote.Found
            ? "唯讀模式(read-only mode)不允許 OPENQUERY / OPENROWSET / OPENDATASOURCE:它們會把任意指令交給別的伺服器或讀取檔案,可能在遠端寫入"
            : null;
    }

    private static string DescribeStatement(TSqlStatement statement) => statement switch
    {
        SelectStatement => "SELECT ... INTO",
        _ => statement.GetType().Name.Replace("Statement", "", StringComparison.Ordinal).ToUpperInvariant(),
    };

    private sealed class NextValueForFinder : TSqlFragmentVisitor
    {
        public bool Found { get; private set; }
        public override void Visit(NextValueForExpression node) => Found = true;
    }

    private sealed class RemoteSourceFinder : TSqlFragmentVisitor
    {
        public bool Found { get; private set; }
        public override void Visit(OpenQueryTableReference node) => Found = true;
        public override void Visit(OpenRowsetTableReference node) => Found = true;
        public override void Visit(BulkOpenRowset node) => Found = true;
        public override void Visit(AdHocTableReference node) => Found = true;
    }

    private sealed class GuardVisitor(
        IReadOnlySet<(string Schema, string Table)> truncateAllowedTables,
        IReadOnlySet<(string Schema, string Procedure)> execWhitelist,
        IReadOnlySet<(string Schema, string Table)> alterTableDropColumnAllowedTables,
        IReadOnlySet<string> hardBlockedProcedures) : TSqlFragmentVisitor
    {
        // 一個批次裡只要有任何一個語句被判定封鎖,整批就拒絕——
        // 不要只擋掉危險那一句、放行其餘的,那樣 AI 可能利用批次夾帶繞過。
        private GuardVerdict? _blockedVerdict;
        private bool _allowedByAllowList;
        public GuardVerdict Verdict => _blockedVerdict ?? GuardVerdict.Allow(_allowedByAllowList);

        private void Block(string reason) => _blockedVerdict ??= GuardVerdict.Block(reason);

        public override void Visit(DropTableStatement node) =>
            Block("DROP TABLE 一律封鎖:整張資料表連同結構一起消失,沒有可靠的復原辦法");

        // 跟 DROP TABLE 同等級,影響範圍是整個資料庫(不是一張表),
        // 不走白名單邏輯——沒有理由讓 AI coding agent 需要用到這幾個指令。
        public override void Visit(DropDatabaseStatement node) =>
            Block("DROP DATABASE 一律封鎖:影響整個資料庫,沒有任何復原機制可言");

        public override void Visit(RestoreStatement node)
        {
            // HEADERONLY/FILELISTONLY/VERIFYONLY/LABELONLY/REWINDONLY 只是讀取
            // 備份檔案的中繼資訊,不會改動資料庫本身,不需要擋。
            if (node.Kind == RestoreStatementKind.Database)
                Block("RESTORE DATABASE 一律封鎖:會用備份整個覆蓋現在的資料,效果等同整庫回滾,沒有復原辦法可言");
            else if (node.Kind == RestoreStatementKind.TransactionLog)
                Block("RESTORE LOG 一律封鎖:會套用交易記錄回補資料庫狀態,效果等同整庫回滾,沒有復原辦法可言");
        }

        public override void Visit(AlterDatabaseSetStatement node) =>
            Block("ALTER DATABASE ... SET 一律封鎖:可以讓整個資料庫離線/切成單人模式等,不需要真的刪資料就能癱瘓服務");

        // 呼叫端自己在 SQL 裡寫交易控制語句,會造成稽核紀錄跟實際 commit 狀態不一致——
        // 例如 `BEGIN TRAN; UPDATE ...; ROLLBACK;` 會被記成 Executed、留下看起來正常的稽核紀錄,即使
        // 實際上什麼都沒真的 commit。一律封鎖,不走白名單:這個 proxy 本來就
        // 會為每句語句自己管理交易邊界,呼叫端
        // 沒有正當理由需要自己再開一層。
        public override void Visit(BeginTransactionStatement node) =>
            Block("BEGIN TRANSACTION 一律封鎖:交易邊界由 proxy 自己管理,呼叫端自行控制會讓稽核紀錄跟實際 commit 狀態不一致");

        public override void Visit(CommitTransactionStatement node) =>
            Block("COMMIT TRANSACTION 一律封鎖:交易邊界由 proxy 自己管理,呼叫端自行控制會讓稽核紀錄跟實際 commit 狀態不一致");

        public override void Visit(RollbackTransactionStatement node) =>
            Block("ROLLBACK TRANSACTION 一律封鎖:交易邊界由 proxy 自己管理,呼叫端自行控制會讓稽核紀錄跟實際 commit 狀態不一致");

        public override void Visit(SaveTransactionStatement node) =>
            Block("SAVE TRANSACTION 一律封鎖:交易邊界由 proxy 自己管理,呼叫端自行控制會讓稽核紀錄跟實際 commit 狀態不一致");

        // REVERT / EXECUTE AS 一律封鎖。ImpersonatedConnectionFactory 用 EXECUTE AS LOGIN 把連線
        // 切換成呼叫端對應的真實帳號,但這個連線本身是用 proxy 自己的
        // 服務帳號開的。如果呼叫端的 SQL 裡夾帶一句
        // `REVERT;`,就會切回服務帳號的身份,後面接的任何語句都繞過了「SQL
        // Server 原生 GRANT/DENY 套用在真人身上」這整個權限模型——稽核紀錄
        // 還是會正常產生,完全看不出異常。`EXECUTE AS LOGIN = 'sa';`
        // 之類的語句是同一個洞的另一個面向。一律封鎖,不走白名單:呼叫端沒有
        // 任何正當理由需要在自己的語句裡切換執行身份。
        public override void Visit(RevertStatement node) =>
            Block("REVERT 一律封鎖:會把執行身份切回 proxy 自己的服務帳號,完全繞過每個人的 SQL Server 權限");

        public override void Visit(ExecuteAsStatement node) =>
            Block("EXECUTE AS 一律封鎖:會改變這句之後的執行身份,完全繞過每個人的 SQL Server 權限");

        // 同一類:這幾句不該讓任何 AI agent 透過這個 proxy 執行。
        public override void Visit(GrantStatement node) =>
            Block("GRANT 一律封鎖:權限管理不應該透過這個 proxy 執行");

        public override void Visit(DenyStatement node) =>
            Block("DENY 一律封鎖:權限管理不應該透過這個 proxy 執行");

        public override void Visit(RevokeStatement node) =>
            Block("REVOKE 一律封鎖:權限管理不應該透過這個 proxy 執行");

        public override void Visit(SetUserStatement node) =>
            Block("SETUSER 一律封鎖:會改變這句之後的執行身份,完全繞過每個人的 SQL Server 權限");

        public override void Visit(ShutdownStatement node) =>
            Block("SHUTDOWN 一律封鎖:會關閉整個 SQL Server 執行個體");

        public override void Visit(KillStatement node) =>
            Block("KILL 一律封鎖:會強制終止其他工作階段,不應該透過這個 proxy 執行");

        // `SET IMPLICIT_TRANSACTIONS ON` 解析出來的節點類型是 PredicateSetStatement
        // (SetOnOffStatement 的子類別),不是 BeginTransactionStatement,
        // 不會被上面那組 Visit 攔到。危害跟 BEGIN TRAN 一樣:後面接的 EXEC 如果
        // 沒有可辨識的 INSERT/UPDATE/DELETE 目標(DmlTargetTableResolver 找不到
        // 錨點),GuardedSqlExecutor 就不會把它包進自己的交易,呼叫端開的隱性
        // 交易在連線釋放時悄悄回滾,但稽核紀錄仍然記成 Executed。
        // 一律封鎖不會擋到任何正常用法(呼叫端沒有理由需要自己開隱性交易模式)。
        public override void Visit(PredicateSetStatement node)
        {
            // Confirmed via reflection against the installed ScriptDom
            // 180.117.0 package (not guessed): PredicateSetStatement is the
            // concrete node type for `SET <option>[, <option>...] ON|OFF`,
            // a subclass of SetOnOffStatement (base, not the other way
            // around), with its own Options (a [Flags] SetOptions) and the
            // inherited IsOn bool - a batch could in principle combine
            // IMPLICIT_TRANSACTIONS with other options in one SET statement.
            if (node.Options.HasFlag(SetOptions.ImplicitTransactions) && node.IsOn)
                Block("SET IMPLICIT_TRANSACTIONS ON 一律封鎖:交易邊界由 proxy 自己管理,呼叫端自行開啟隱性交易模式會讓稽核紀錄跟實際 commit 狀態不一致");
        }

        public override void Visit(TruncateTableStatement node)
        {
            if (HasDatabaseOrServerQualifier(node.TableName))
            {
                Block("TRUNCATE TABLE 封鎖:目標含資料庫或伺服器名稱,允許清單只比對 schema.表名,保守拒絕");
                return;
            }

            var target = ResolveSchemaTable(node.TableName);
            if (target is { } t && truncateAllowedTables.Contains(t))
            {
                _allowedByAllowList = true; // 白名單表,放行
                return;
            }
            Block($"TRUNCATE TABLE 封鎖:{(target is { } t2 ? $"{t2.Schema}.{t2.Table}" : "目標表")} 不在允許清單上,TRUNCATE 會清空整張表,沒有逐列的復原辦法");
        }

        public override void Visit(AlterTableDropTableElementStatement node)
        {
            // DROP CONSTRAINT/INDEX/PERIOD 是結構調整,不會遺失資料列裡的值 -
            // 只有 DROP COLUMN 真的會把資料丟掉。
            bool dropsAColumn = node.AlterTableDropTableElements
                .Any(e => e.TableElementType == TableElementType.Column);
            if (!dropsAColumn) return;

            if (HasDatabaseOrServerQualifier(node.SchemaObjectName))
            {
                Block("ALTER TABLE ... DROP COLUMN 封鎖:目標含資料庫或伺服器名稱,允許清單只比對 schema.表名,保守拒絕");
                return;
            }

            var target = ResolveSchemaTable(node.SchemaObjectName);
            if (target is { } t && alterTableDropColumnAllowedTables.Contains(t))
            {
                _allowedByAllowList = true; // 白名單表,放行
                return;
            }
            Block($"ALTER TABLE ... DROP COLUMN 封鎖:{(target is { } t2 ? $"{t2.Schema}.{t2.Table}" : "目標表")} 不在允許清單上,刪欄位會遺失資料,沒有欄位層級的復原辦法");
        }

        // ExecuteSpecification, not ExecuteStatement: INSERT ... EXEC carries its
        // EXEC inside an INSERT source, which never appears as a statement of its
        // own, so visiting only ExecuteStatement let it past every EXEC rule.
        public override void Visit(ExecuteSpecification node)
        {
            var entity = node.ExecutableEntity;

            if (entity is ExecutableStringList)
            {
                Block("EXEC 動態 SQL(字串/變數)一律封鎖:無法靜態判定實際會執行什麼");
                return;
            }

            if (entity is ExecutableProcedureReference procRef)
            {
                var name = procRef.ProcedureReference?.ProcedureReference?.Name;
                string? procName = name?.BaseIdentifier?.Value;

                if (procName is null)
                {
                    Block("EXEC 呼叫目標無法靜態解析(可能是變數呼叫)→ 保守拒絕");
                    return;
                }

                if (hardBlockedProcedures.Contains(procName))
                {
                    Block($"EXEC {procName} 永遠封鎖:這是動態 SQL/系統逃逸通道,不接受白名單核准");
                    return;
                }

                if (name!.ServerIdentifier is not null || name.DatabaseIdentifier is not null)
                {
                    Block($"EXEC {procName} 含資料庫或伺服器名稱,白名單只比對 schema.名稱,保守拒絕");
                    return;
                }

                string schema = name.SchemaIdentifier?.Value ?? "dbo";
                if (!execWhitelist.Contains((schema, procName)))
                    Block($"EXEC {schema}.{procName} 不在白名單上,需要管理者先核准才能被 AI 呼叫");

                return;
            }

            Block($"無法分類的 EXEC 目標類型({entity?.GetType().Name ?? "null"})→ 保守拒絕");
        }

        /// <summary>
        /// 保留原始大小寫,方便錯誤訊息顯示 AI 實際寫的那個名稱。比對白名單時
        /// 的大小寫不分是靠傳入的 set 本身用 CaseInsensitiveNameTupleComparer
        /// 建的(見該類別的註解),不是在這裡處理 - 這樣不管白名單從哪裡建出來
        /// 都一定正確,不會因為忘了正規化而悄悄比對失敗。
        /// </summary>
        private static bool HasDatabaseOrServerQualifier(SchemaObjectName? name) =>
            name is { DatabaseIdentifier: not null } or { ServerIdentifier: not null };

        private static (string Schema, string Table)? ResolveSchemaTable(SchemaObjectName? name)
        {
            if (name?.BaseIdentifier?.Value is not { } table) return null;
            string schema = name.SchemaIdentifier?.Value ?? "dbo";
            return (schema, table);
        }
    }
}
