using System.IO.Compression;
using System.IO.MemoryMappedFiles;
using System.Runtime.CompilerServices;

namespace Malward.Engine.Vdeb;

public sealed class VdebReader : IDisposable
{
    public const uint MAGIC = 0x42454456;
    public const uint FLAG_GZIP = 0x1;
    public const uint FLAG_COMPACT = 0x2;
    public const int HEADER_SIZE = 256;
    public const int INDEX_ENTRY_SIZE = 32;

    public readonly struct IndexEntry
    {
        public ushort ShardKey { get; init; }
        public long DataOffset { get; init; }
        public uint CompressedSize { get; init; }
        public uint UncompressedSize { get; init; }
        public uint EntryCount { get; init; }
    }

    private readonly MemoryMappedFile _mmf;
    private readonly MemoryMappedViewAccessor _bloomView;
    private readonly Dictionary<ushort, IndexEntry> _index = new();
    private readonly ShardCache _cache;

    public BloomFilter Bloom { get; }
    public uint Flags { get; }
    public byte CompactPrefix { get; }
    public ulong TotalEntries { get; }
    public ulong CreatedTs { get; }
    public ulong LastTs { get; }
    public uint MalwareCount { get; }
    public uint CleanCount { get; }

    public bool IsCompact => (Flags & FLAG_COMPACT) != 0;

    public VdebReader(string vdebPath, int shardCacheCapacity = 16)
    {
        _mmf = MemoryMappedFile.CreateFromFile(
            vdebPath, FileMode.Open, mapName: null, capacity: 0,
            MemoryMappedFileAccess.Read);

        using var headerView = _mmf.CreateViewAccessor(0, HEADER_SIZE, MemoryMappedFileAccess.Read);
        uint magic = headerView.ReadUInt32(0);
        if (magic != MAGIC)
            throw new InvalidDataException($"Bad VDEB magic: 0x{magic:X8} (expected 0x{MAGIC:X8})");
        uint version = headerView.ReadUInt32(4);
        Flags = headerView.ReadUInt32(8);

        long bloomOffset = headerView.ReadInt64(16);
        long bloomSize = headerView.ReadInt64(24);
        long indexOffset = headerView.ReadInt64(32);
        uint indexCount = headerView.ReadUInt32(40);
        uint indexEntrySize = headerView.ReadUInt32(44);
        TotalEntries = headerView.ReadUInt64(48);
        LastTs = headerView.ReadUInt64(56);
        CreatedTs = headerView.ReadUInt64(64);
        MalwareCount = headerView.ReadUInt32(72);
        CleanCount = headerView.ReadUInt32(76);
        CompactPrefix = headerView.ReadByte(80);

        if (indexEntrySize != INDEX_ENTRY_SIZE)
            throw new InvalidDataException($"Unexpected index_entry_size {indexEntrySize}");

        _bloomView = _mmf.CreateViewAccessor(bloomOffset, bloomSize, MemoryMappedFileAccess.Read);
        Bloom = new BloomFilter(_bloomView, bloomSize);

        using var indexView = _mmf.CreateViewAccessor(
            indexOffset, indexCount * (long)INDEX_ENTRY_SIZE, MemoryMappedFileAccess.Read);
        for (uint i = 0; i < indexCount; i++)
        {
            long o = i * INDEX_ENTRY_SIZE;
            byte k0 = indexView.ReadByte(o + 0);
            byte k1 = indexView.ReadByte(o + 1);

            ushort shardKey = (ushort)((HexNibble(k0) << 4) | HexNibble(k1));
            long dataOff = indexView.ReadInt64(o + 4);
            uint compSz = indexView.ReadUInt32(o + 12);
            uint uncSz = indexView.ReadUInt32(o + 16);
            uint ec = indexView.ReadUInt32(o + 20);
            _index[shardKey] = new IndexEntry
            {
                ShardKey = shardKey,
                DataOffset = dataOff,
                CompressedSize = compSz,
                UncompressedSize = uncSz,
                EntryCount = ec,
            };
        }

        _cache = new ShardCache(shardCacheCapacity);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static int HexNibble(byte ascii) => ascii switch
    {
        >= (byte)'0' and <= (byte)'9' => ascii - (byte)'0',
        >= (byte)'a' and <= (byte)'f' => 10 + (ascii - (byte)'a'),
        >= (byte)'A' and <= (byte)'F' => 10 + (ascii - (byte)'A'),
        _ => throw new InvalidDataException($"Non-hex shard_key byte: 0x{ascii:X2}"),
    };

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
        int needHexLen = hashType switch { 0 => 64, 1 => 32, _ => -1 };
        if (needHexLen < 0 || lowerHex.Length < needHexLen) return null;

        if (!Bloom.MightContain(lowerHex)) return null;

        ushort key = (ushort)((HexNibble((byte)lowerHex[0]) << 4) | HexNibble((byte)lowerHex[1]));
        if (!_index.TryGetValue(key, out var entry)) return null;

        var payload = _cache.GetOrLoad(key, () => LoadShardPayload(entry));

        if (IsCompact)
        {
            byte n = CompactPrefix;
            if (n == 0) return null;
            if (lowerHex.Length < n * 2) return null;

            Span<byte> needle = stackalloc byte[n];
            HexToBytes(lowerHex.AsSpan(0, n * 2), needle);

            if (BinarySearchPrefixes(payload, needle, n))
                return Core.DetectionNames.Prefix + lowerHex.Substring(0, 12);
            return null;
        }

        return ScanFullPayload(payload, lowerHex, hashType);
    }

    public IndexEntry? IndexEntryFor(ushort shardKey)
        => _index.TryGetValue(shardKey, out var e) ? e : null;

    public IReadOnlyList<ushort> ShardKeys
    {
        get { var k = new List<ushort>(_index.Keys); k.Sort(); return k; }
    }

    public IEnumerable<(string HashHex, string HashType, string? Detection)> EnumerateShard(ushort shardKey)
    {
        if (!_index.TryGetValue(shardKey, out var entry)) yield break;
        var payload = _cache.GetOrLoad(shardKey, () => LoadShardPayload(entry));

        if (IsCompact)
        {
            int n = CompactPrefix;
            if (n <= 0) yield break;
            for (int i = 0; i + n <= payload.Length; i += n)
                yield return (Convert.ToHexString(payload, i, n).ToLowerInvariant(), "prefix", null);
            yield break;
        }

        int p = 0;
        while (p < payload.Length)
        {
            if (p + 2 > payload.Length) break;
            byte hashType = payload[p++];
            byte detFlag = payload[p++];
            int hashLen = hashType switch { 0 => 32, 1 => 16, 2 => 20, _ => -1 };
            if (hashLen < 0 || p + hashLen > payload.Length) break;
            string hex = Convert.ToHexString(payload, p, hashLen).ToLowerInvariant();
            p += hashLen;
            string? det = null;
            if (detFlag == 1)
            {
                if (p + 2 > payload.Length) break;
                int dl = payload[p] | (payload[p + 1] << 8);
                p += 2;
                if (p + dl > payload.Length) break;
                det = System.Text.Encoding.UTF8.GetString(payload, p, dl);
                p += dl;
            }
            p += 4;
            string tname = hashType switch { 0 => "sha256", 1 => "md5", 2 => "sha1", _ => "?" };
            yield return (hex, tname, det);
        }
    }

    public bool HasPrefixInShard(ushort shardKey, string prefixHex)
    {
        if (!_index.TryGetValue(shardKey, out var entry)) return false;
        if (!IsCompact) return false;
        int n = CompactPrefix;
        if (prefixHex.Length < n * 2) return false;
        Span<byte> needle = stackalloc byte[n];
        HexToBytes(prefixHex.AsSpan(0, n * 2), needle);
        var payload = _cache.GetOrLoad(shardKey, () => LoadShardPayload(entry));
        return BinarySearchPrefixes(payload, needle, n);
    }

    private byte[] LoadShardPayload(IndexEntry entry)
    {
        var compressed = new byte[entry.CompressedSize];
        using (var view = _mmf.CreateViewAccessor(
            entry.DataOffset, entry.CompressedSize, MemoryMappedFileAccess.Read))
        {
            view.ReadArray(0, compressed, 0, (int)entry.CompressedSize);
        }

        using var src = new MemoryStream(compressed);
        using var gz = new GZipStream(src, CompressionMode.Decompress);
        using var dst = new MemoryStream(checked((int)entry.UncompressedSize));
        gz.CopyTo(dst);
        return dst.ToArray();
    }

    private static bool BinarySearchPrefixes(byte[] payload, ReadOnlySpan<byte> needle, int n)
    {
        int count = payload.Length / n;
        int lo = 0, hi = count - 1;
        while (lo <= hi)
        {
            int mid = (lo + hi) >>> 1;
            int cmp = payload.AsSpan(mid * n, n).SequenceCompareTo(needle);
            if (cmp == 0) return true;
            if (cmp < 0) lo = mid + 1; else hi = mid - 1;
        }
        return false;
    }

    private string? ScanFullPayload(byte[] payload, string targetHexLower, byte targetHashType)
    {
        int needleLen = targetHashType switch { 0 => 32, 1 => 16, 2 => 20, _ => -1 };
        if (needleLen < 0) return null;
        Span<byte> needle = stackalloc byte[needleLen];
        HexToBytes(targetHexLower.AsSpan(0, needleLen * 2), needle);

        int p = 0;
        while (p < payload.Length)
        {
            byte hashType = payload[p++];
            byte detFlag = payload[p++];
            int hashLen = hashType switch
            {
                0 => 32,
                1 => 16,
                2 => 20,
                _ => -1,
            };
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
                    : Core.DetectionNames.Prefix + targetHexLower.Substring(0, 12);
        }
        return null;
    }

    private static void HexToBytes(ReadOnlySpan<char> hex, Span<byte> dest)
    {
        for (int i = 0; i < dest.Length; i++)
            dest[i] = (byte)((HexNibble((byte)hex[i * 2]) << 4) | HexNibble((byte)hex[i * 2 + 1]));
    }

    public void Dispose()
    {
        _bloomView.Dispose();
        _mmf.Dispose();
    }
}
