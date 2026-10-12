using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Malward.ResidentShield;

public static class QuarantineCrypto
{
    private static readonly byte[] Magic = "MWQ1"u8.ToArray();
    private const int SaltLen = 16, IvLen = 16, MacLen = 32, Iters = 100_000;
    private static readonly int HeaderLen = Magic.Length + SaltLen + IvLen + MacLen;

    private static byte[] BaseKey()
    {
        string s = "Malward" + ".quarantine.v1." + "jmSOFT";
        return SHA256.HashData(Encoding.UTF8.GetBytes(s));
    }

    private static (byte[] aes, byte[] mac) Derive(byte[] salt)
    {
        using var kdf = new Rfc2898DeriveBytes(BaseKey(), salt, Iters, HashAlgorithmName.SHA256);
        return (kdf.GetBytes(32), kdf.GetBytes(32));
    }

    public static bool IsContainer(string path)
    {
        try
        {
            using var fs = File.OpenRead(path);
            Span<byte> head = stackalloc byte[4];
            return fs.Read(head) == 4 && head.SequenceEqual(Magic);
        }
        catch { return false; }
    }

    public static void EncryptFile(string sourcePath, string destPath)
    {
        using var src = File.OpenRead(sourcePath);
        EncryptStream(src, destPath);
    }

    public static void EncryptBytes(byte[] plain, string destPath)
    {
        using var src = new MemoryStream(plain, writable: false);
        EncryptStream(src, destPath);
    }

    private static void EncryptStream(Stream source, string destPath)
    {
        byte[] salt = RandomNumberGenerator.GetBytes(SaltLen);
        byte[] iv = RandomNumberGenerator.GetBytes(IvLen);
        var (aesKey, macKey) = Derive(salt);

        using var aes = Aes.Create();
        aes.Key = aesKey; aes.IV = iv; aes.Mode = CipherMode.CBC; aes.Padding = PaddingMode.PKCS7;

        using var dst = new FileStream(destPath, FileMode.Create, FileAccess.ReadWrite, FileShare.None);

        dst.Write(Magic);
        dst.Write(salt);
        dst.Write(iv);
        long macPos = dst.Position;
        dst.Write(new byte[MacLen]);

        using (var enc = aes.CreateEncryptor())
        using (var cs = new CryptoStream(dst, enc, CryptoStreamMode.Write, leaveOpen: true))
            source.CopyTo(cs);

        dst.Position = HeaderLen;
        using var hmac = new HMACSHA256(macKey);
        byte[] mac = hmac.ComputeHash(Prefixed(salt, iv, dst));
        dst.Position = macPos;
        dst.Write(mac);
    }

    public static bool DecryptFile(string containerPath, string destPath)
    {
        try
        {
            using var src = File.OpenRead(containerPath);
            var magic = new byte[Magic.Length];
            if (src.Read(magic, 0, magic.Length) != magic.Length || !magic.AsSpan().SequenceEqual(Magic))
                return false;

            var salt = new byte[SaltLen];
            var iv = new byte[IvLen];
            var mac = new byte[MacLen];
            src.ReadExactly(salt);
            src.ReadExactly(iv);
            src.ReadExactly(mac);

            var (aesKey, macKey) = Derive(salt);
            using (var hmac = new HMACSHA256(macKey))
            {
                long cipherStart = src.Position;
                byte[] actual = hmac.ComputeHash(Prefixed(salt, iv, src));
                if (!CryptographicOperations.FixedTimeEquals(actual, mac)) return false;
                src.Position = cipherStart;
            }

            using var aes = Aes.Create();
            aes.Key = aesKey; aes.IV = iv; aes.Mode = CipherMode.CBC; aes.Padding = PaddingMode.PKCS7;
            using var dst = new FileStream(destPath, FileMode.Create, FileAccess.Write, FileShare.None);
            using var dec = aes.CreateDecryptor();
            using var cs = new CryptoStream(src, dec, CryptoStreamMode.Read, leaveOpen: true);
            cs.CopyTo(dst);
            return true;
        }
        catch { return false; }
    }

    private static Stream Prefixed(byte[] salt, byte[] iv, Stream rest)
    {
        var ms = new MemoryStream();
        ms.Write(salt); ms.Write(iv);
        ms.Position = 0;
        return new ConcatStream(ms, rest);
    }

    private sealed class ConcatStream : Stream
    {
        private readonly Stream _first, _second;
        private bool _firstDone;

        public ConcatStream(Stream first, Stream second) { _first = first; _second = second; }

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (!_firstDone)
            {
                int n = _first.Read(buffer, offset, count);
                if (n > 0) return n;
                _firstDone = true;
            }
            return _second.Read(buffer, offset, count);
        }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
