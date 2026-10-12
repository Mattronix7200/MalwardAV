using System.IO.Compression;
using System.Reflection;
using Malward.Engine.Util;

namespace Malward.Engine.Heuristic;

public static class EmbeddedHeurScanner
{
    private const string ResourceName = "heurscanner.exe";
    private const string PackedResourceName = "heurscanner.exe.gz";
    private static readonly object Gate = new();
    private static string? _cachedPath;

    private static byte[]? ReadPayload()
    {
        var asm = typeof(EmbeddedHeurScanner).Assembly;

        using (var packed = asm.GetManifestResourceStream(PackedResourceName))
        {
            if (packed != null)
            {
                using var gz = new GZipStream(packed, CompressionMode.Decompress);
                using var ms = new MemoryStream(4 * 1024 * 1024);
                gz.CopyTo(ms);
                return ms.ToArray();
            }
        }

        using (var raw = asm.GetManifestResourceStream(ResourceName))
        {
            if (raw == null) return null;
            using var ms = new MemoryStream((int)Math.Max(raw.Length, 1024));
            raw.CopyTo(ms);
            return ms.ToArray();
        }
    }

    public static string? EnsureExtracted()
    {
        if (_cachedPath != null && File.Exists(_cachedPath)) return _cachedPath;
        lock (Gate)
        {
            if (_cachedPath != null && File.Exists(_cachedPath)) return _cachedPath;

            var payload = ReadPayload();
            if (payload == null)
            {
                var loose = Paths.HeurScanner;
                _cachedPath = File.Exists(loose) ? loose : null;
                return _cachedPath;
            }

            var dir = Path.Combine(Paths.AppDataDir, "engine");
            Directory.CreateDirectory(dir);
            var dest = Path.Combine(dir, ResourceName);

            try
            {
                bool needWrite = !File.Exists(dest) || new FileInfo(dest).Length != payload.Length;
                if (needWrite)
                {
                    var tmp = dest + "." + Environment.ProcessId + ".tmp";
                    File.WriteAllBytes(tmp, payload);
                    try
                    {
                        if (File.Exists(dest)) File.Delete(dest);
                        File.Move(tmp, dest);
                    }
                    catch
                    {
                        try { File.Delete(tmp); } catch { }
                        if (File.Exists(dest) && new FileInfo(dest).Length == payload.Length) { _cachedPath = dest; return _cachedPath; }
                        _cachedPath = File.Exists(tmp) ? tmp : (File.Exists(dest) ? dest : null);
                        return _cachedPath;
                    }
                }
                _cachedPath = dest;
                return _cachedPath;
            }
            catch
            {
                var loose = Paths.HeurScanner;
                _cachedPath = File.Exists(loose) ? loose : null;
                return _cachedPath;
            }
        }
    }
}
