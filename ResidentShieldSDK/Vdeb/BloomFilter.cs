using System.IO.MemoryMappedFiles;

namespace Malward.ResidentShield.Vdeb;

internal sealed class BloomFilter
{
    public const int  BLOOM_HASH_COUNT = 7;
    public const uint FNV_OFFSET = 2166136261u;
    public const uint FNV_PRIME  = 16777619u;

    private readonly MemoryMappedViewAccessor _view;
    private readonly long _bloomSize;

    public BloomFilter(MemoryMappedViewAccessor view, long bloomSize)
    {
        _view      = view;
        _bloomSize = bloomSize;
    }

    public bool MightContain(string item)
    {
        long sizeBits = _bloomSize * 8L;

        var lower = item.ToLowerInvariant();
        var bytes = new byte[lower.Length];
        int n = 0;
        foreach (var c in lower)
        {
            if (c < 128) bytes[n++] = (byte)c;
        }

        for (int i = 0; i < BLOOM_HASH_COUNT; i++)
        {
            uint h = FNV_OFFSET;
            for (int j = 0; j < n; j++)
            {
                h ^= bytes[j];
                h  = unchecked(h * FNV_PRIME);
                h ^= (uint)(i * 31);
            }

            long pos        = (long)(h % (ulong)sizeBits);
            long byteOffset = pos / 8;
            byte mask       = (byte)(1 << (int)(pos % 8));

            if ((_view.ReadByte(byteOffset) & mask) == 0)
                return false;
        }
        return true;
    }
}
