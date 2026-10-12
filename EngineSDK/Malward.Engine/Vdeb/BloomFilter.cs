using System.IO.MemoryMappedFiles;

namespace Malward.Engine.Vdeb;

public sealed class BloomFilter
{
    public const int BLOOM_SIZE_BYTES = 128 * 1024 * 1024;
    public const int BLOOM_HASH_COUNT = 7;
    public const uint FNV_OFFSET = 2166136261u;
    public const uint FNV_PRIME = 16777619u;

    private readonly MemoryMappedViewAccessor _view;
    private readonly long _bloomSize;
    private readonly long _sizeBits;

    public BloomFilter(MemoryMappedViewAccessor view, long bloomSize)
    {
        _view = view;
        _bloomSize = bloomSize;
        _sizeBits = bloomSize * 8L;
    }

    public static long[] Positions(string item, long bloomSizeBytes = BLOOM_SIZE_BYTES)
    {
        var lower = item.ToLowerInvariant();
        var bytes = new byte[lower.Length];
        int n = 0;
        foreach (var c in lower)
        {
            if (c < 128) bytes[n++] = (byte)c;
        }
        if (n != bytes.Length)
            Array.Resize(ref bytes, n);

        long sizeBits = bloomSizeBytes * 8L;
        var positions = new long[BLOOM_HASH_COUNT];
        for (int i = 0; i < BLOOM_HASH_COUNT; i++)
        {
            uint h = FNV_OFFSET;
            for (int j = 0; j < bytes.Length; j++)
            {
                h ^= bytes[j];
                h = unchecked(h * FNV_PRIME);
                h ^= (uint)(i * 31);
            }
            positions[i] = h % (ulong)sizeBits is var p ? (long)p : 0;
        }
        return positions;
    }

    public bool MightContain(string item)
    {
        foreach (var pos in Positions(item, _bloomSize))
        {
            long byteOffset = pos / 8;
            byte mask = (byte)(1 << (int)(pos % 8));
            byte b = _view.ReadByte(byteOffset);
            if ((b & mask) == 0)
                return false;
        }
        return true;
    }

    public byte ReadByteForDiag(long offset)
    {
        if (offset < 0 || offset >= _bloomSize) return 0;
        return _view.ReadByte(offset);
    }

    public long BloomSize => _bloomSize;
}
