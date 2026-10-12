using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Malward.Engine.Util;

namespace Malward.Engine.Cloud;

internal static class SessionCache
{
    private static string Path_ => System.IO.Path.Combine(Paths.DataDir, "cloud-session.bin");

    private sealed record Entry(string Token, DateTime ExpiresUtc, string Psk, string Server);

    public static (string Token, DateTime ExpiresUtc)? Read(string pskFingerprint, string server)
    {
        try
        {
            if (!File.Exists(Path_)) return null;
            var jawne = ProtectedData.Unprotect(File.ReadAllBytes(Path_), null,
                                                DataProtectionScope.LocalMachine);
            var w = JsonSerializer.Deserialize<Entry>(Encoding.UTF8.GetString(jawne));
            if (w is null || string.IsNullOrEmpty(w.Token)) return null;
            if (!string.Equals(w.Psk, pskFingerprint, StringComparison.Ordinal)) return null;
            if (!string.Equals(w.Server, server, StringComparison.OrdinalIgnoreCase)) return null;

            if (DateTime.UtcNow.AddSeconds(60) >= w.ExpiresUtc) return null;
            return (w.Token, w.ExpiresUtc);
        }
        catch
        {
            return null;
        }
    }

    public static void Clear()
    {
        try { if (File.Exists(Path_)) File.Delete(Path_); }
        catch { }
    }

    public static void Write(string token, DateTime expiresUtc, string pskFingerprint, string server)
    {
        try
        {
            Directory.CreateDirectory(Paths.DataDir);
            var bajty = JsonSerializer.SerializeToUtf8Bytes(
                new Entry(token, expiresUtc, pskFingerprint, server));
            var zaszyfrowane = ProtectedData.Protect(bajty, null, DataProtectionScope.LocalMachine);

            var tmp = Path_ + "." + Environment.ProcessId + ".tmp";
            File.WriteAllBytes(tmp, zaszyfrowane);
            File.Move(tmp, Path_, overwrite: true);
        }
        catch
        {
        }
    }
}
