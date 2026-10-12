namespace LogCarverGuard.Core;

/// <summary>Reading back what was recorded.</summary>
public interface IAuditReader
{
    Task<IReadOnlyList<StoredAuditRecord>> GetRecentAsync(int limit = 100, CancellationToken ct = default);
    Task<StoredAuditRecord?> GetByIdAsync(long id, CancellationToken ct = default);
}
