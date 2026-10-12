using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace Malward.AppGUI.Services;

public sealed class ResidentQuarantineStore
{
    private readonly string _indexPath;
    private readonly string _quarantineDir;

    public const string IdPrefix = "rs:";

    public ResidentQuarantineStore(string appDataDir)
    {
        _quarantineDir = Path.Combine(appDataDir, "quarantine");
        _indexPath = Path.Combine(_quarantineDir, "index.jsonl");
    }

    public List<QuarantineItem> Read()
    {
        var list = new List<QuarantineItem>();
        if (!File.Exists(_indexPath)) return list;

        string[] lines;
        try { lines = File.ReadAllLines(_indexPath); }
        catch { return list; }

        foreach (var line in lines)
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            try
            {
                using var doc = JsonDocument.Parse(line);
                var root = doc.RootElement;
                string stored = Get(root, "Stored");
                if (string.IsNullOrEmpty(stored)) continue;

                var storedPath = Path.Combine(_quarantineDir, stored);
                if (!File.Exists(storedPath)) continue;

                string original  = Get(root, "Original");
                string detection = Get(root, "Detection");
                string time      = NormalizeTime(Get(root, "Time"));

                list.Add(new QuarantineItem(IdPrefix + stored, time,
                    string.IsNullOrEmpty(detection) ? "Malware" : detection,
                    original));
            }
            catch {  }
        }
        return list;
    }

    public bool Delete(string prefixedId)
    {
        var stored = StripPrefix(prefixedId);
        if (stored == null) return false;
        try
        {
            var p = Path.Combine(_quarantineDir, stored);
            if (File.Exists(p)) File.Delete(p);
            RemoveFromIndex(stored);
            return true;
        }
        catch { return false; }
    }

    public bool Restore(string prefixedId, string? destOverride)
    {
        var stored = StripPrefix(prefixedId);
        if (stored == null) return false;
        try
        {
            var src = Path.Combine(_quarantineDir, stored);
            if (!File.Exists(src)) return false;

            var original = FindOriginal(stored);
            string? dest = destOverride;
            if (string.IsNullOrEmpty(dest))
                dest = original;

            else if (Directory.Exists(dest) || EndsWithSeparator(dest))
            {
                var nazwa = string.IsNullOrEmpty(original) ? stored : Path.GetFileName(original);
                if (string.IsNullOrEmpty(nazwa)) return false;
                dest = Path.Combine(dest, nazwa);
            }
            if (string.IsNullOrEmpty(dest)) return false;

            var dir = Path.GetDirectoryName(dest);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

            if (Malward.ResidentShield.QuarantineCrypto.IsContainer(src))
            {
                if (!Malward.ResidentShield.QuarantineCrypto.DecryptFile(src, dest)) return false;
                try { File.Delete(src); } catch { }
            }
            else File.Move(src, dest, overwrite: true);

            RemoveFromIndex(stored);
            return true;
        }
        catch { return false; }
    }

    public string? Extract(string prefixedId, string destDir, string? nameHint)
    {
        var stored = StripPrefix(prefixedId);
        if (stored == null || string.IsNullOrWhiteSpace(destDir)) return null;
        try
        {
            var src = Path.Combine(_quarantineDir, stored);
            if (!File.Exists(src)) return null;

            var name = SafeName(nameHint) ?? SafeName(FindOriginal(stored));
            if (name == null) return null;

            Directory.CreateDirectory(destDir);
            var dest = UniquePath(Path.Combine(destDir, name));

            if (Malward.ResidentShield.QuarantineCrypto.IsContainer(src))
                return Malward.ResidentShield.QuarantineCrypto.DecryptFile(src, dest) ? dest : null;

            File.Copy(src, dest, overwrite: false);
            return dest;
        }
        catch { return null; }
    }

    private static string? SafeName(string? candidate)
    {
        if (string.IsNullOrWhiteSpace(candidate)) return null;
        string name;
        try { name = Path.GetFileName(candidate.Trim()); }
        catch { return null; }
        if (string.IsNullOrEmpty(name)) return null;
        return name.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 ? null : name;
    }

    private static string UniquePath(string path)
    {
        if (!File.Exists(path)) return path;
        var dir  = Path.GetDirectoryName(path) ?? "";
        var stem = Path.GetFileNameWithoutExtension(path);
        var ext  = Path.GetExtension(path);
        for (int i = 2; i < 1000; i++)
        {
            var candidate = Path.Combine(dir, $"{stem} ({i}){ext}");
            if (!File.Exists(candidate)) return candidate;
        }
        return path;
    }

    private static bool EndsWithSeparator(string p) =>
        p.EndsWith(Path.DirectorySeparatorChar) || p.EndsWith(Path.AltDirectorySeparatorChar);

    public static bool IsResidentId(string id) => id != null && id.StartsWith(IdPrefix, StringComparison.Ordinal);

    public string? ResolveStoredPath(string prefixedId)
    {
        var stored = StripPrefix(prefixedId);
        if (stored == null) return null;
        var p = System.IO.Path.Combine(_quarantineDir, stored);
        return File.Exists(p) ? p : null;
    }

    private static string? StripPrefix(string id)
        => id != null && id.StartsWith(IdPrefix, StringComparison.Ordinal) ? id[IdPrefix.Length..] : null;

    private string? FindOriginal(string stored)
    {
        try
        {
            foreach (var line in File.ReadAllLines(_indexPath))
            {
                if (string.IsNullOrWhiteSpace(line)) continue;

                try
                {
                    using var doc = JsonDocument.Parse(line);
                    if (string.Equals(Get(doc.RootElement, "Stored"), stored, StringComparison.OrdinalIgnoreCase))
                        return Get(doc.RootElement, "Original");
                }
                catch {  }
            }
        }
        catch { }
        return null;
    }

    private void RemoveFromIndex(string stored)
    {
        try
        {
            if (!File.Exists(_indexPath)) return;
            var kept = new List<string>();
            foreach (var line in File.ReadAllLines(_indexPath))
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                try
                {
                    using var doc = JsonDocument.Parse(line);
                    if (string.Equals(Get(doc.RootElement, "Stored"), stored, StringComparison.OrdinalIgnoreCase))
                        continue;
                }
                catch { }
                kept.Add(line);
            }
            File.WriteAllLines(_indexPath, kept);
        }
        catch { }
    }

    private static string Get(JsonElement e, string prop)
        => e.TryGetProperty(prop, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";

    private static string NormalizeTime(string iso)
    {
        if (DateTimeOffset.TryParse(iso, out var dt))
            return dt.LocalDateTime.ToString("yyyy-MM-dd HH:mm:ss");
        return iso;
    }
}
