using System.Security.Cryptography;
using System.Text;

namespace Malward.Engine.Cloud;

public static class ConfigKeyFile
{
    public const string FileName = "config.vdeb";

    public const string LegacyFileName = "configKey";

    private static readonly byte[] Magic = "MWCK"u8.ToArray();
    private const byte Version = 1;
    private const int SaltLen = 16, IvLen = 16, MacLen = 32, Pbkdf2Iters = 120_000;

    private static byte[] BaseKey()
    {
        string s = "Malward" + ".configKey.v1." + "jmSOFT" + "/cloud-credentials";
        return SHA256.HashData(Encoding.UTF8.GetBytes(s));
    }

    private static (byte[] aes, byte[] mac) DeriveKeys(byte[] salt)
    {
        using var kdf = new Rfc2898DeriveBytes(BaseKey(), salt, Pbkdf2Iters, HashAlgorithmName.SHA256);
        return (kdf.GetBytes(32), kdf.GetBytes(32));
    }

    public static byte[] Protect(string json)
    {
        byte[] salt = RandomNumberGenerator.GetBytes(SaltLen);
        byte[] iv = RandomNumberGenerator.GetBytes(IvLen);
        var (aesKey, macKey) = DeriveKeys(salt);

        using var aes = Aes.Create();
        aes.Key = aesKey; aes.IV = iv; aes.Mode = CipherMode.CBC; aes.Padding = PaddingMode.PKCS7;
        byte[] cipher = aes.CreateEncryptor().TransformFinalBlock(
            Encoding.UTF8.GetBytes(json), 0, Encoding.UTF8.GetByteCount(json));

        using var hmac = new HMACSHA256(macKey);
        byte[] mac = hmac.ComputeHash(Concat(salt, iv, cipher));

        return Concat(Magic, new[] { Version }, salt, iv, mac, cipher);
    }

    public static bool LooksLikeContainer(byte[]? blob)
    {
        if (blob == null || blob.Length < Magic.Length + 1) return false;
        for (int i = 0; i < Magic.Length; i++) if (blob[i] != Magic[i]) return false;
        return true;
    }

    public static string? Unprotect(byte[]? blob)
    {
        try
        {
            int head = Magic.Length + 1 + SaltLen + IvLen + MacLen;
            if (blob == null || blob.Length <= head) return null;
            for (int i = 0; i < Magic.Length; i++) if (blob[i] != Magic[i]) return null;
            if (blob[Magic.Length] != Version) return null;

            int p = Magic.Length + 1;
            byte[] salt = blob[p..(p += SaltLen)];
            byte[] iv = blob[p..(p += IvLen)];
            byte[] mac = blob[p..(p += MacLen)];
            byte[] cipher = blob[p..];

            var (aesKey, macKey) = DeriveKeys(salt);
            using var hmac = new HMACSHA256(macKey);

            if (!CryptographicOperations.FixedTimeEquals(hmac.ComputeHash(Concat(salt, iv, cipher)), mac))
                return null;

            using var aes = Aes.Create();
            aes.Key = aesKey; aes.IV = iv; aes.Mode = CipherMode.CBC; aes.Padding = PaddingMode.PKCS7;
            return Encoding.UTF8.GetString(
                aes.CreateDecryptor().TransformFinalBlock(cipher, 0, cipher.Length));
        }
        catch { return null; }
    }

    private static byte[] Concat(params byte[][] parts)
    {
        var outBuf = new byte[parts.Sum(p => p.Length)];
        int o = 0;
        foreach (var part in parts) { Buffer.BlockCopy(part, 0, outBuf, o, part.Length); o += part.Length; }
        return outBuf;
    }
}
