using System.Security.Cryptography;

namespace Malward.BackupEngine;

internal sealed class CryptoEnvelope
{
    private readonly byte[] _masterKey;
    private readonly AesGcm _aes;
    private static readonly string DefaultKeyPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "Malward", "backup", "key.bin");

    public CryptoEnvelope(byte[] masterKey)
    {
        if (masterKey.Length != 32)
            throw new ArgumentException("Master key must be 32 bytes (AES-256).", nameof(masterKey));
        _masterKey = masterKey;
        _aes = new AesGcm(masterKey, BkfFormat.TagSize);
    }

    public static CryptoEnvelope GenerateNew()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        return new CryptoEnvelope(key);
    }

    public byte[] MasterKey => _masterKey;

    public static CryptoEnvelope LoadOrCreate(string? keyPath = null)
    {
        var path = keyPath ?? DefaultKeyPath;
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);

        if (File.Exists(path))
        {
            try
            {
                var protectedKey = File.ReadAllBytes(path);
                var key = System.Security.Cryptography.ProtectedData.Unprotect(
                    protectedKey, optionalEntropy: null,
                    System.Security.Cryptography.DataProtectionScope.LocalMachine);
                if (key.Length == 32) return new CryptoEnvelope(key);
                Log.Warn("Crypto", "key.bin has a wrong size — generating a new one");
            }
            catch (Exception ex)
            {
                Log.Warn("Crypto", $"key.bin read failed ({ex.Message}) — generating a new one");
            }
        }

        var fresh = GenerateNew();
        try
        {
            var protectedKey = System.Security.Cryptography.ProtectedData.Protect(
                fresh._masterKey, optionalEntropy: null,
                System.Security.Cryptography.DataProtectionScope.LocalMachine);

            var tmp = path + ".tmp";
            File.WriteAllBytes(tmp, protectedKey);
            if (File.Exists(path))
                File.Replace(tmp, path, destinationBackupFileName: null, ignoreMetadataErrors: true);
            else
                File.Move(tmp, path);
            Log.Info("Crypto", $"Generated new master key, DPAPI-protected → {path}");
        }
        catch (Exception ex)
        {
            Log.Error("Crypto", $"Failed to save key.bin: {ex.Message}. " +
                                "The key lives only in memory — a service restart means losing access to the BKF!");
        }
        return fresh;
    }

    public byte[] Encrypt(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> associatedData = default)
    {
        var nonce = RandomNumberGenerator.GetBytes(BkfFormat.NonceSize);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[BkfFormat.TagSize];
        _aes.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);

        var envelope = new byte[BkfFormat.NonceSize + ciphertext.Length + BkfFormat.TagSize];
        Buffer.BlockCopy(nonce, 0, envelope, 0, BkfFormat.NonceSize);
        Buffer.BlockCopy(ciphertext, 0, envelope, BkfFormat.NonceSize, ciphertext.Length);
        Buffer.BlockCopy(tag, 0, envelope, BkfFormat.NonceSize + ciphertext.Length, BkfFormat.TagSize);
        return envelope;
    }

    public byte[] Decrypt(ReadOnlySpan<byte> envelope, ReadOnlySpan<byte> associatedData = default)
    {
        if (envelope.Length < BkfFormat.NonceSize + BkfFormat.TagSize)
            throw new InvalidDataException("Envelope too short.");
        var nonce = envelope.Slice(0, BkfFormat.NonceSize);
        var tag = envelope.Slice(envelope.Length - BkfFormat.TagSize, BkfFormat.TagSize);
        var ciphertext = envelope.Slice(BkfFormat.NonceSize,
                                        envelope.Length - BkfFormat.NonceSize - BkfFormat.TagSize);
        var plaintext = new byte[ciphertext.Length];
        _aes.Decrypt(nonce, ciphertext, tag, plaintext, associatedData);
        return plaintext;
    }

    public void Dispose() => _aes.Dispose();
}
