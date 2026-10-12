using System.Security.Cryptography;

namespace Malward.Engine.Util;

public static class SecureFileEraser
{
    private const int CHUNK = 64 * 1024;

    public static void Shred(string path)
    {
        try
        {
            if (!File.Exists(path)) return;
            long size;
            try { size = new FileInfo(path).Length; }
            catch { size = 0; }

            if (size > 0)
            {
                try
                {
                    OverwriteWithRandom(path, size);
                }
                catch
                {
                }
            }
        }
        finally
        {
            try { File.Delete(path); } catch {  }
        }
    }

    private static void OverwriteWithRandom(string path, long size)
    {
        using var rng = RandomNumberGenerator.Create();

        using var fs = new FileStream(path, FileMode.Open, FileAccess.Write,
                                       FileShare.None, CHUNK,
                                       FileOptions.WriteThrough | FileOptions.SequentialScan);
        var buf = new byte[(int)Math.Min(CHUNK, size)];
        long left = size;
        while (left > 0)
        {
            int n = (int)Math.Min(buf.Length, left);
            rng.GetBytes(buf, 0, n);
            fs.Write(buf, 0, n);
            left -= n;
        }
        fs.Flush(flushToDisk: true);
    }
}
