using System.Security.Cryptography;

namespace Malward.Engine.Heuristic;

public static class Crypto
{
    public static readonly byte[] HEUR_PASSWORD =
        System.Text.Encoding.UTF8.GetBytes(Cloud.ClientSecrets.HeurPassword);

    public const int PBKDF2_ITERS = 200_000;

    public static byte[] DeriveKey(byte[] salt, int dkLen = 32)
        => Rfc2898DeriveBytes.Pbkdf2(HEUR_PASSWORD, salt, PBKDF2_ITERS, HashAlgorithmName.SHA256, dkLen);

    public static byte[] DecryptCbcPkcs7(byte[] ciphertext, byte[] key, byte[] iv)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        aes.IV = iv;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        using var dec = aes.CreateDecryptor();
        return dec.TransformFinalBlock(ciphertext, 0, ciphertext.Length);
    }

    public static byte[] EncryptCbcPkcs7(byte[] plaintext, byte[] key, byte[] iv)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        aes.IV = iv;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        using var enc = aes.CreateEncryptor();
        return enc.TransformFinalBlock(plaintext, 0, plaintext.Length);
    }

    public static byte[] DeriveIvForRule(byte[] ivSeed, byte ruleId)
    {
        using var h = new HMACSHA256(ivSeed);
        var full = h.ComputeHash(new[] { ruleId });
        return full.Take(16).ToArray();
    }
}
