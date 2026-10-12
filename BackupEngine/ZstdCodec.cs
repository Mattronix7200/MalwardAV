using System.IO.Compression;

namespace Malward.BackupEngine;

public enum CompressionMode : byte
{
    None = 0,

    Deflate = 1,

    Brotli = 2,
}

internal static class ZstdCodec
{
    public static byte[] Compress(ReadOnlySpan<byte> data, CompressionMode mode)
    {
        switch (mode)
        {
            case CompressionMode.None:
                return data.ToArray();

            case CompressionMode.Deflate:
            {
                using var output = new MemoryStream();
                using (var d = new DeflateStream(output, CompressionLevel.Fastest, leaveOpen: true))
                    d.Write(data);
                return output.ToArray();
            }

            case CompressionMode.Brotli:
            {
                using var output = new MemoryStream();
                using (var b = new BrotliStream(output, CompressionLevel.Optimal, leaveOpen: true))
                    b.Write(data);
                return output.ToArray();
            }

            default:
                return data.ToArray();
        }
    }

    public static byte[] Decompress(ReadOnlySpan<byte> compressed, CompressionMode mode)
    {
        switch (mode)
        {
            case CompressionMode.None:
                return compressed.ToArray();

            case CompressionMode.Deflate:
            {
                using var input = new MemoryStream(compressed.ToArray());
                using var d = new DeflateStream(input, System.IO.Compression.CompressionMode.Decompress);
                using var output = new MemoryStream();
                d.CopyTo(output, 64 * 1024);
                return output.ToArray();
            }

            case CompressionMode.Brotli:
            {
                using var input = new MemoryStream(compressed.ToArray());
                using var b = new BrotliStream(input, System.IO.Compression.CompressionMode.Decompress);
                using var output = new MemoryStream();
                b.CopyTo(output, 64 * 1024);
                return output.ToArray();
            }

            default:
                return compressed.ToArray();
        }
    }

    public static byte[] Compress(ReadOnlySpan<byte> data) => Compress(data, CompressionMode.Deflate);
    public static byte[] Decompress(ReadOnlySpan<byte> compressed) => Decompress(compressed, CompressionMode.Deflate);
}
