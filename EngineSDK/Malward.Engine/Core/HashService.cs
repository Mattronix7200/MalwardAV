using System.Security.Cryptography;

namespace Malward.Engine.Core;

public readonly record struct FileHashes(string Md5Hex, string Sha256Hex);

public static class HashService
{
    private const int CHUNK = 1 << 20;

    public static string Sha256Hex(string filePath)
    {
        using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read,
            CHUNK, FileOptions.SequentialScan);
        using var sha = SHA256.Create();
        var buf = new byte[CHUNK];
        int n;
        while ((n = fs.Read(buf, 0, CHUNK)) > 0)
            sha.TransformBlock(buf, 0, n, null, 0);
        sha.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
        return Convert.ToHexString(sha.Hash!).ToLowerInvariant();
    }

    public static FileHashes HashBoth(string filePath)
    {
        using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read,
            CHUNK, FileOptions.SequentialScan);
        using var md5 = MD5.Create();
        using var sha = SHA256.Create();
        var buf = new byte[CHUNK];
        int n;
        while ((n = fs.Read(buf, 0, CHUNK)) > 0)
        {
            md5.TransformBlock(buf, 0, n, null, 0);
            sha.TransformBlock(buf, 0, n, null, 0);
        }
        md5.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
        sha.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
        return new FileHashes(
            Convert.ToHexString(md5.Hash!).ToLowerInvariant(),
            Convert.ToHexString(sha.Hash!).ToLowerInvariant());
    }
}
