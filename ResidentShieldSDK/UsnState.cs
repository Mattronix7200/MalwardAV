using System.Collections.Concurrent;
using System.Text.Json;

namespace Malward.ResidentShield;

public sealed class UsnState
{
    private sealed class VolState
    {
        public ulong JournalId { get; set; }
        public ulong NextUsn   { get; set; }
    }

    private readonly ConcurrentDictionary<string, VolState> _vols;
    private long _lastSaveTicks;
    private readonly object _saveLock = new();

    private static string StatePath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "Malward", "data", "usn-state.json");

    private UsnState(ConcurrentDictionary<string, VolState> vols) => _vols = vols;

    public static UsnState Load()
    {
        try
        {
            if (File.Exists(StatePath))
            {
                var raw = File.ReadAllText(StatePath);
                var dict = JsonSerializer.Deserialize<Dictionary<string, VolState>>(raw);
                if (dict != null)
                    return new UsnState(new ConcurrentDictionary<string, VolState>(dict, StringComparer.OrdinalIgnoreCase));
            }
        }
        catch {  }
        return new UsnState(new ConcurrentDictionary<string, VolState>(StringComparer.OrdinalIgnoreCase));
    }

    public ulong ResolveStart(string volume, ulong journalId, long currentNextUsn)
    {
        if (_vols.TryGetValue(volume, out var st) && st.JournalId == journalId
            && st.NextUsn > 0 && st.NextUsn <= (ulong)currentNextUsn)
        {
            return st.NextUsn;
        }

        _vols[volume] = new VolState { JournalId = journalId, NextUsn = (ulong)currentNextUsn };
        return (ulong)currentNextUsn;
    }

    public void Update(string volume, ulong journalId, ulong nextUsn)
    {
        _vols[volume] = new VolState { JournalId = journalId, NextUsn = nextUsn };

        long now = Environment.TickCount64;
        if (now - Interlocked.Read(ref _lastSaveTicks) >= 5000)
        {
            Interlocked.Exchange(ref _lastSaveTicks, now);
            Save();
        }
    }

    public void Save()
    {
        lock (_saveLock)
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(StatePath)!);
                var plain = new Dictionary<string, VolState>(_vols, StringComparer.OrdinalIgnoreCase);
                File.WriteAllText(StatePath, JsonSerializer.Serialize(plain,
                    new JsonSerializerOptions { WriteIndented = true }));
            }
            catch {  }
        }
    }
}
