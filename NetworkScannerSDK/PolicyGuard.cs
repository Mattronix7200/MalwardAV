using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Win32;

namespace Malward.NetworkScanner;

public static class PolicyGuard
{
    public static readonly string DataDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "Malward", "data");

    public sealed record Policy(string Key, string Name, RegistryValueKind Kind, object Value, string Product);

    private sealed record Saved(
        [property: JsonPropertyName("key")]     string Key,
        [property: JsonPropertyName("name")]    string Name,
        [property: JsonPropertyName("existed")] bool Existed,
        [property: JsonPropertyName("kind")]    int Kind,
        [property: JsonPropertyName("value")]   string? Value);

    private static RegistryKey Base() =>
        RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);

    public static IReadOnlyList<string> Apply(IEnumerable<Policy> policies, string snapshotPath, string area)
    {
        var saved = new List<Saved>();
        var touched = new List<string>();

        foreach (var policy in policies)
        {
            try
            {
                using var root = Base();
                using var key = root.CreateSubKey(policy.Key, writable: true);
                if (key == null) continue;

                object? current = key.GetValue(policy.Name);
                if (current != null && current.ToString() == policy.Value.ToString()) continue;

                saved.Add(new Saved(policy.Key, policy.Name, current != null,
                                    (int)(current == null ? RegistryValueKind.Unknown
                                                          : key.GetValueKind(policy.Name)),
                                    current?.ToString()));
                key.SetValue(policy.Name, policy.Value, policy.Kind);
                if (!touched.Contains(policy.Product)) touched.Add(policy.Product);
            }
            catch (Exception ex)
            {
                Log.Warn(area, $"cannot enforce {policy.Key}\\{policy.Name}: {ex.Message}");
            }
        }

        if (saved.Count > 0)
        {
            try
            {
                Directory.CreateDirectory(DataDir);
                var merged = Load(snapshotPath);
                foreach (var s in saved)
                    if (!merged.Any(m => m.Key == s.Key && m.Name == s.Name)) merged.Add(s);
                File.WriteAllText(snapshotPath, JsonSerializer.Serialize(merged));
            }
            catch (Exception ex) { Log.Warn(area, $"snapshot not written: {ex.Message}"); }
        }

        return touched;
    }

    public static int Restore(string snapshotPath, string area)
    {
        var saved = Load(snapshotPath);
        if (saved.Count == 0) return 0;

        foreach (var s in saved)
        {
            try
            {
                using var root = Base();
                using var key = root.OpenSubKey(s.Key, writable: true);
                if (key == null) continue;

                if (!s.Existed) key.DeleteValue(s.Name, throwOnMissingValue: false);
                else if (s.Value != null)
                {
                    var kind = (RegistryValueKind)s.Kind;
                    object value = kind == RegistryValueKind.DWord
                        ? (int.TryParse(s.Value, out var n) ? n : 0)
                        : s.Value;
                    key.SetValue(s.Name, value, kind);
                }
            }
            catch (Exception ex) { Log.Warn(area, $"cannot restore {s.Key}\\{s.Name}: {ex.Message}"); }
        }

        try { File.Delete(snapshotPath); } catch { }
        return saved.Count;
    }

    private static List<Saved> Load(string snapshotPath)
    {
        try
        {
            if (!File.Exists(snapshotPath)) return new List<Saved>();
            return JsonSerializer.Deserialize<List<Saved>>(File.ReadAllText(snapshotPath))
                   ?? new List<Saved>();
        }
        catch { return new List<Saved>(); }
    }
}
