using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Malward.Engine.Data;

public static class SignatureStore
{
    private static readonly byte[] Magic = "MWSD"u8.ToArray();
    private const int SaltLen = 16, IvLen = 16, MacLen = 32, Iters = 50_000;

    public const string FileName = "sigdata.vdeb";

    private static readonly object Gate = new();
    private static JsonObject? _data;
    private static bool _tried;

    public static string? LoadError { get; private set; }

    private static byte[] BaseKey()
    {
        string s = "Malward" + ".sigdata.v1." + "jmSOFT";
        return SHA256.HashData(Encoding.UTF8.GetBytes(s));
    }

    private static (byte[] aes, byte[] mac) Derive(byte[] salt)
    {
        using var kdf = new Rfc2898DeriveBytes(BaseKey(), salt, Iters, HashAlgorithmName.SHA256);
        return (kdf.GetBytes(32), kdf.GetBytes(32));
    }

    public static void Write(string json, string destPath)
    {
        byte[] salt = RandomNumberGenerator.GetBytes(SaltLen);
        byte[] iv = RandomNumberGenerator.GetBytes(IvLen);
        var (aesKey, macKey) = Derive(salt);

        using var aes = Aes.Create();
        aes.Key = aesKey; aes.IV = iv; aes.Mode = CipherMode.CBC; aes.Padding = PaddingMode.PKCS7;
        byte[] cipher;
        using (var enc = aes.CreateEncryptor())
        {
            var plain = Encoding.UTF8.GetBytes(json);
            cipher = enc.TransformFinalBlock(plain, 0, plain.Length);
        }

        using var hmac = new HMACSHA256(macKey);
        var macInput = new byte[salt.Length + iv.Length + cipher.Length];
        Buffer.BlockCopy(salt, 0, macInput, 0, salt.Length);
        Buffer.BlockCopy(iv, 0, macInput, salt.Length, iv.Length);
        Buffer.BlockCopy(cipher, 0, macInput, salt.Length + iv.Length, cipher.Length);
        byte[] mac = hmac.ComputeHash(macInput);

        var dir = Path.GetDirectoryName(destPath);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
        using var fs = File.Create(destPath);
        fs.Write(Magic); fs.Write(salt); fs.Write(iv); fs.Write(mac); fs.Write(cipher);
    }

    private static IEnumerable<string> CandidatePaths()
    {
        yield return Path.Combine(Util.Paths.ExeDir, FileName);
        yield return Path.Combine(Util.Paths.DataDir, FileName);
    }

    private static JsonObject? Load()
    {
        if (_data != null || _tried) return _data;
        lock (Gate)
        {
            if (_data != null || _tried) return _data;
            _tried = true;
            foreach (var path in CandidatePaths())
            {
                try
                {
                    if (!File.Exists(path)) continue;
                    var raw = File.ReadAllBytes(path);
                    if (raw.Length < Magic.Length + SaltLen + IvLen + MacLen) continue;
                    if (!raw.AsSpan(0, Magic.Length).SequenceEqual(Magic)) continue;

                    int o = Magic.Length;
                    var salt = raw.AsSpan(o, SaltLen).ToArray(); o += SaltLen;
                    var iv = raw.AsSpan(o, IvLen).ToArray(); o += IvLen;
                    var mac = raw.AsSpan(o, MacLen).ToArray(); o += MacLen;
                    var cipher = raw.AsSpan(o).ToArray();

                    var (aesKey, macKey) = Derive(salt);
                    using (var hmac = new HMACSHA256(macKey))
                    {
                        var macInput = new byte[salt.Length + iv.Length + cipher.Length];
                        Buffer.BlockCopy(salt, 0, macInput, 0, salt.Length);
                        Buffer.BlockCopy(iv, 0, macInput, salt.Length, iv.Length);
                        Buffer.BlockCopy(cipher, 0, macInput, salt.Length + iv.Length, cipher.Length);
                        if (!CryptographicOperations.FixedTimeEquals(hmac.ComputeHash(macInput), mac))
                        { LoadError = $"{path}: uszkodzony (błędna suma kontrolna)"; continue; }
                    }

                    using var aes = Aes.Create();
                    aes.Key = aesKey; aes.IV = iv; aes.Mode = CipherMode.CBC; aes.Padding = PaddingMode.PKCS7;
                    using var dec = aes.CreateDecryptor();
                    var plain = dec.TransformFinalBlock(cipher, 0, cipher.Length);
                    _data = JsonNode.Parse(Encoding.UTF8.GetString(plain)) as JsonObject;
                    if (_data != null) { LoadError = null; return _data; }
                }
                catch (Exception ex) { LoadError = $"{path}: {ex.Message}"; }
            }

            LoadError ??= $"nie znaleziono {FileName} (uruchom publish.bat, aby go wygenerować)";

            Console.Error.WriteLine($"[!] Behaviour signature database unavailable: {LoadError}. " +
                                    "Ransomware and security-sabotage detection is limited.");
            return null;
        }
    }

    public static string[] List(string key)
    {
        try
        {
            if (Load()?[key] is JsonArray arr)
                return arr.Select(n => n?.GetValue<string>() ?? "").Where(s => s.Length > 0).ToArray();
        }
        catch { }
        return Array.Empty<string>();
    }

    public static bool Available => Load() != null;

    public static void Reset() { lock (Gate) { _data = null; _tried = false; LoadError = null; } }
}
