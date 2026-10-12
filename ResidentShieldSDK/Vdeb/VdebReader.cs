using System.IO.Compression;
using System.IO.MemoryMappedFiles;
using System.Runtime.CompilerServices;

namespace Malward.ResidentShield.Vdeb;

internal sealed class VdebReader : IDisposable
{
    private const uint   MAGIC            = 0x42454456;
    private const int    HEADER_SIZE      = 256;
    private const int    INDEX_ENTRY_SIZE = 32;
    private const uint   FLAG_COMPACT     = 0x2;

    private readonly struct IndexEntry
    {
        public long DataOffset      { get; init; }
        public uint CompressedSize  { get; init; }
        public uint UncompressedSize{ get; init; }
    }

    private readonly MemoryMappedFile         _mmf;
    private readonly MemoryMappedViewAccessor _bloomView;
    private readonly Dictionary<ushort, IndexEntry> _index = new();
    private readonly ShardCache  _cache;
    private readonly BloomFilter _bloom;
    private readonly bool        _isCompact;
    private readonly byte        _compactPrefix;

    public VdebReader(string vdebPath, int shardCacheCapacity = 16)
    {
        _mmf = MemoryMappedFile.CreateFromFile(
            vdebPath, FileMode.Open, mapName: null, capacity: 0,
            MemoryMappedFileAccess.Read);

        using var hv = _mmf.CreateViewAccessor(0, HEADER_SIZE, MemoryMappedFileAccess.Read);

        uint magic = hv.ReadUInt32(0);
        if (magic != MAGIC)
            throw new InvalidDataException($"Zły VDEB magic: 0x{magic:X8}");

        uint flags         = hv.ReadUInt32(8);
        long bloomOffset   = hv.ReadInt64(16);
        long bloomSize     = hv.ReadInt64(24);
        long indexOffset   = hv.ReadInt64(32);
        uint indexCount    = hv.ReadUInt32(40);
        uint indexEntrySize= hv.ReadUInt32(44);
        _compactPrefix     = hv.ReadByte(80);

        if (indexEntrySize != INDEX_ENTRY_SIZE)
            throw new InvalidDataException($"Nieoczekiwany index_entry_size: {indexEntrySize}");

        _isCompact = (flags & FLAG_COMPACT) != 0;

        _bloomView = _mmf.CreateViewAccessor(bloomOffset, bloomSize, MemoryMappedFileAccess.Read);
        _bloom = new BloomFilter(_bloomView, bloomSize);

        using var iv = _mmf.CreateViewAccessor(
            indexOffset, indexCount * (long)INDEX_ENTRY_SIZE, MemoryMappedFileAccess.Read);

        for (uint i = 0; i < indexCount; i++)
        {
            long o = i * INDEX_ENTRY_SIZE;
            byte k0 = iv.ReadByte(o + 0);
            byte k1 = iv.ReadByte(o + 1);
            ushort shardKey = (ushort)((HexNibble(k0) << 4) | HexNibble(k1));
            long  dataOff   = iv.ReadInt64(o + 4);
            uint  compSz    = iv.ReadUInt32(o + 12);
            uint  uncSz     = iv.ReadUInt32(o + 16);
            _index[shardKey] = new IndexEntry
            {
                DataOffset       = dataOff,
                CompressedSize   = compSz,
                UncompressedSize = uncSz,
            };
        }

        _cache = new ShardCache(shardCacheCapacity);
    }

    public string? TryFind(string sha256Hex) => TryFind(null, sha256Hex);

    public string? TryFind(string? md5Hex, string? sha256Hex)
    {
        if (!string.IsNullOrEmpty(sha256Hex))
        {
            var det = LookupSingle(sha256Hex!.ToLowerInvariant(), hashType: 0);
            if (det != null) return det;
        }
        if (!string.IsNullOrEmpty(md5Hex))
        {
            var det = LookupSingle(md5Hex!.ToLowerInvariant(), hashType: 1);
            if (det != null) return det;
        }
        return null;
    }

    private string? LookupSingle(string lowerHex, byte hashType)
    {
        int needHex = hashType switch { 0 => 64, 1 => 32, _ => -1 };
        if (needHex < 0 || lowerHex.Length < needHex) return null;

        if (!_bloom.MightContain(lowerHex)) return null;

        ushort key = (ushort)((HexNibble((byte)lowerHex[0]) << 4) | HexNibble((byte)lowerHex[1]));
        if (!_index.TryGetValue(key, out var entry)) return null;

        var payload = _cache.GetOrLoad(key, () => LoadShard(entry));

        return _isCompact
            ? LookupCompact(payload, lowerHex, hashType)
            : LookupFull(payload, lowerHex, hashType);
    }

    private string? LookupCompact(byte[] payload, string hashHexLower, byte hashType)
    {
        byte n = _compactPrefix;
        if (n == 0 || hashHexLower.Length < n * 2) return null;

        Span<byte> needle = stackalloc byte[n];
        HexToBytes(hashHexLower.AsSpan(0, n * 2), needle);

        if (!BinarySearchPrefixes(payload, needle, n))
            return null;

        return Malward.Engine.Core.DetectionNames.Prefix + hashHexLower[..12];
    }

    private static bool BinarySearchPrefixes(byte[] payload, ReadOnlySpan<byte> needle, int n)
    {
        int lo = 0, hi = payload.Length / n - 1;
        while (lo <= hi)
        {
            int mid = (lo + hi) >>> 1;
            int cmp = payload.AsSpan(mid * n, n).SequenceCompareTo(needle);
            if (cmp == 0) return true;
            if (cmp < 0) lo = mid + 1; else hi = mid - 1;
        }
        return false;
    }

    private string? LookupFull(byte[] payload, string targetHexLower, byte targetHashType)
    {
        int needleLen = targetHashType switch { 0 => 32, 1 => 16, 2 => 20, _ => -1 };
        if (needleLen < 0) return null;
        Span<byte> needle = stackalloc byte[needleLen];
        HexToBytes(targetHexLower.AsSpan(0, needleLen * 2), needle);

        int p = 0;
        while (p < payload.Length)
        {
            byte hashType = payload[p++];
            byte detFlag  = payload[p++];
            int  hashLen  = hashType switch { 0 => 32, 1 => 16, 2 => 20, _ => -1 };
            if (hashLen < 0) break;
            if (p + hashLen > payload.Length) break;

            bool match = hashType == targetHashType
                      && payload.AsSpan(p, hashLen).SequenceEqual(needle);
            p += hashLen;

            string? customDet = null;
            if (detFlag == 1)
            {
                if (p + 2 > payload.Length) break;
                int dl = payload[p] | (payload[p + 1] << 8);
                p += 2;
                if (p + dl > payload.Length) break;
                if (match) customDet = System.Text.Encoding.UTF8.GetString(payload, p, dl);
                p += dl;
            }
            p += 4;
            if (match)

                return customDet != null
                    ? Malward.Engine.Core.DetectionNames.Normalize(customDet)
                    : Malward.Engine.Core.DetectionNames.Prefix + targetHexLower[..12];
        }
        return null;
    }

    private byte[] LoadShard(IndexEntry entry)
    {
        var compressed = new byte[entry.CompressedSize];
        using var view = _mmf.CreateViewAccessor(
            entry.DataOffset, entry.CompressedSize, MemoryMappedFileAccess.Read);
        view.ReadArray(0, compressed, 0, (int)entry.CompressedSize);

        using var src = new MemoryStream(compressed);
        using var gz  = new GZipStream(src, CompressionMode.Decompress);
        using var dst = new MemoryStream(checked((int)entry.UncompressedSize));
        gz.CopyTo(dst);
        return dst.ToArray();
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static int HexNibble(byte ascii) => ascii switch
    {
        >= (byte)'0' and <= (byte)'9' => ascii - (byte)'0',
        >= (byte)'a' and <= (byte)'f' => 10 + (ascii - (byte)'a'),
        >= (byte)'A' and <= (byte)'F' => 10 + (ascii - (byte)'A'),
        _ => throw new InvalidDataException($"Non-hex: 0x{ascii:X2}"),
    };

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static int HexNibble(char c) => HexNibble((byte)c);

    private static void HexToBytes(ReadOnlySpan<char> hex, Span<byte> dest)
    {
        for (int i = 0; i < dest.Length; i++)
            dest[i] = (byte)((HexNibble(hex[i * 2]) << 4) | HexNibble(hex[i * 2 + 1]));
    }

    public void Dispose()
    {
        _bloomView.Dispose();
        _mmf.Dispose();
    }
}
