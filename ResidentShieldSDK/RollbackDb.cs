using System.Globalization;
using LiteDB;

namespace Malward.ResidentShield;

public sealed class RemediationRecord
{
    public int      Id          { get; set; }
    public int      Pid         { get; set; }
    public string   FilePath    { get; set; } = "";
    public DateTime Timestamp   { get; set; }
    public int      ProcessesKilled  { get; set; }
    public int      FilesHandled     { get; set; }
    public int      PersistenceRemoved { get; set; }
}

public sealed class RollbackDb : IDisposable
{
    private readonly LiteDatabase?                       _db;
    private readonly ILiteCollection<RemediationRecord>? _audit;

    private static string ShieldDir => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "Malward", "shield");

    public RollbackDb()
    {
        string path;
        try
        {
            Directory.CreateDirectory(ShieldDir);
            path = Path.Combine(ShieldDir, "remediation.db");
        }
        catch (Exception ex)
        {
            Log.Warn("Rollback", $"Audit directory unavailable ({ex.GetType().Name}) — neutralisations will not be recorded.");
            return;
        }

        if (TryOpen(path, out _db, out _audit))
            return;

        if (Quarantine(path) && TryOpen(path, out _db, out _audit))
        {
            Log.Info("Rollback", "Audit log recreated after the old file could not be opened.");
            return;
        }

        Log.Warn("Rollback", "Audit log unavailable — neutralisations will still be performed, only not recorded.");
    }

    private static bool TryOpen(string path,
                                out LiteDatabase? db,
                                out ILiteCollection<RemediationRecord>? audit)
    {
        db = null;
        audit = null;
        try
        {
            var cs = new ConnectionString
            {
                Filename  = path,
                Collation = new Collation(CultureInfo.InvariantCulture.LCID, CompareOptions.Ordinal),
            };
            var opened = new LiteDatabase(cs);
            var col    = opened.GetCollection<RemediationRecord>("audit");
            col.EnsureIndex(x => x.Timestamp);
            db    = opened;
            audit = col;
            return true;
        }
        catch (Exception ex)
        {
            Log.Warn("Rollback", $"Cannot open the audit log ({ex.GetType().Name}: {ex.Message.Split('\n')[0]}).");
            try { db?.Dispose(); } catch { }
            db = null;
            audit = null;
            return false;
        }
    }

    private static bool Quarantine(string path)
    {
        try
        {
            if (!File.Exists(path))
                return false;

            var stamp  = DateTime.UtcNow.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture);
            var broken = $"{path}.{stamp}.bad";
            File.Move(path, broken);

            foreach (var side in new[] { path + "-log", path + "-tmp" })
                try { if (File.Exists(side)) File.Delete(side); } catch { }

            Log.Warn("Rollback", $"Unusable audit log moved aside: {Path.GetFileName(broken)}");
            return true;
        }
        catch (Exception ex)
        {
            Log.Warn("Rollback", $"Cannot move the unusable audit log aside ({ex.GetType().Name}).");
            return false;
        }
    }

    public void AuditNeutralize(int pid, string filePath, int killed, int filesHandled, int persistRemoved)
    {
        if (_audit == null)
            return;
        try
        {
            _audit.Insert(new RemediationRecord
            {
                Pid = pid, FilePath = filePath, Timestamp = DateTime.UtcNow,
                ProcessesKilled = killed, FilesHandled = filesHandled,
                PersistenceRemoved = persistRemoved,
            });
        }
        catch {  }
    }

    public void Dispose()
    {
        try { _db?.Dispose(); } catch { }
    }
}
