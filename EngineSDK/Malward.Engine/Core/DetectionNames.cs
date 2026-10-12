using System.Security.Cryptography;
using System.Text;

namespace Malward.Engine.Core;

public static class DetectionNames
{
    public const string Prefix = "Malware@";

    private static readonly string[] LegacyPrefixes = { "Generic.Malware@", "Cloud.Malware@", "malware@" };

    public static string ForFile(string? path)
    {
        try
        {
            if (!string.IsNullOrEmpty(path) && File.Exists(path))
            {
                var fi = new FileInfo(path);

                using var fs = File.OpenRead(path);
                var buffer = new byte[(int)Math.Min(fi.Length, 1024 * 1024)];
                int read = fs.Read(buffer, 0, buffer.Length);
                using var sha = SHA256.Create();
                return Prefix + Convert.ToHexString(sha.ComputeHash(buffer, 0, read))[..8].ToLowerInvariant();
            }
        }
        catch { }
        return ForText(path ?? "");
    }

    public static string Normalize(string? detection)
    {
        var d = (detection ?? "").Trim();
        if (d.Length == 0) return d;

        foreach (var legacy in LegacyPrefixes)
        {
            if (!d.StartsWith(legacy, StringComparison.OrdinalIgnoreCase)) continue;
            var rest = d[legacy.Length..];

            if (rest.StartsWith("ENG", StringComparison.OrdinalIgnoreCase) && rest.Length > 4)
                rest = rest[4..];
            return Prefix + rest.ToLowerInvariant();
        }

        if (d.StartsWith(Prefix, StringComparison.OrdinalIgnoreCase))
            return Prefix + d[Prefix.Length..].ToLowerInvariant();

        return d;
    }

    public static string ForText(string seed)
    {
        using var sha = SHA256.Create();
        var norm = (seed ?? "").Trim().ToLowerInvariant();
        return Prefix + Convert.ToHexString(sha.ComputeHash(Encoding.UTF8.GetBytes(norm)))[..8].ToLowerInvariant();
    }
}
