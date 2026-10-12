using System.Diagnostics;
using System.Globalization;

namespace Malward.BackupEngine;

internal sealed class VolumeShadowCopy
{
    public sealed class Shadow
    {
        public string ShadowId { get; set; } = "";
        public DateTime CreatedUtc { get; set; }
        public string ShadowCopyVolume { get; set; } = "";
        public string OriginalVolume { get; set; } = "";
    }

    private static List<Shadow>? _cache;
    private static DateTime _cacheAt = DateTime.MinValue;
    private static readonly object _lock = new();

    public List<Shadow> ListShadows(bool useCache = true)
    {
        lock (_lock)
        {
            if (useCache && _cache != null && (DateTime.UtcNow - _cacheAt).TotalSeconds < 60)
                return _cache;
        }
        var result = new List<Shadow>();
        try
        {
            var psi = new ProcessStartInfo("vssadmin.exe", "list shadows")
            {
                UseShellExecute = false, RedirectStandardOutput = true,
                CreateNoWindow = true, StandardOutputEncoding = System.Text.Encoding.UTF8,
            };
            using var proc = Process.Start(psi);
            if (proc == null) return result;
            var output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(15_000);
            ParseVssadminOutput(output, result);
        }
        catch (Exception ex)
        {
            Log.Warn("VSS", $"vssadmin list shadows failed: {ex.Message}");
        }
        lock (_lock) { _cache = result; _cacheAt = DateTime.UtcNow; }
        Log.Info("VSS", $"Found {result.Count} shadow copies");
        return result;
    }

    private static void ParseVssadminOutput(string output, List<Shadow> result)
    {
        Shadow? current = null;
        DateTime? lastCreated = null;
        foreach (var raw in output.Split('\n'))
        {
            var line = raw.Trim();
            if (line.StartsWith("Contained ", StringComparison.OrdinalIgnoreCase))
            {
                int idx = line.IndexOf(':');
                if (idx > 0)
                {
                    var ds = line[(idx + 1)..].Trim();
                    if (DateTime.TryParse(ds, CultureInfo.InvariantCulture,
                            DateTimeStyles.AssumeLocal, out var dt))
                        lastCreated = dt.ToUniversalTime();
                }
            }
            else if (line.StartsWith("Shadow Copy ID:", StringComparison.OrdinalIgnoreCase))
            {
                if (current != null) result.Add(current);
                current = new Shadow
                {
                    ShadowId = line[(line.IndexOf(':') + 1)..].Trim(),
                    CreatedUtc = lastCreated ?? DateTime.MinValue,
                };
            }
            else if (line.StartsWith("Original Volume:", StringComparison.OrdinalIgnoreCase)
                     && current != null)
            {
                var v = line[(line.IndexOf(':') + 1)..].Trim();

                int paren1 = v.IndexOf('(');
                int paren2 = v.IndexOf(')');
                if (paren1 >= 0 && paren2 > paren1)
                    current.OriginalVolume = v.Substring(paren1 + 1, paren2 - paren1 - 1) + @"\";
            }
            else if (line.StartsWith("Shadow Copy Volume:", StringComparison.OrdinalIgnoreCase)
                     && current != null)
            {
                current.ShadowCopyVolume = line[(line.IndexOf(':') + 1)..].Trim();
            }
        }
        if (current != null) result.Add(current);
    }

    public Shadow? FindShadowBefore(string path, DateTime cutoff)
    {
        var vol = Path.GetPathRoot(path);
        if (string.IsNullOrEmpty(vol)) return null;
        var shadows = ListShadows()
            .Where(s => string.Equals(s.OriginalVolume, vol, StringComparison.OrdinalIgnoreCase))
            .Where(s => s.CreatedUtc < cutoff)
            .OrderByDescending(s => s.CreatedUtc)
            .ToList();
        return shadows.FirstOrDefault();
    }

    public bool RestoreFromShadow(Shadow shadow, string originalPath, string targetPath)
    {
        try
        {
            var relative = originalPath;
            if (originalPath.Length > 2 && originalPath[1] == ':')
                relative = originalPath[2..];

            var shadowRoot = shadow.ShadowCopyVolume.TrimEnd('\\');
            var shadowPath = shadowRoot + relative;

            if (!File.Exists(shadowPath))
            {
                Log.Debug("VSS", $"Not present in shadow: {shadowPath}");
                return false;
            }
            Directory.CreateDirectory(Path.GetDirectoryName(targetPath)!);
            File.Copy(shadowPath, targetPath, overwrite: true);
            return true;
        }
        catch (Exception ex)
        {
            Log.Warn("VSS", $"RestoreFromShadow {originalPath}: {ex.Message}");
            return false;
        }
    }
}
