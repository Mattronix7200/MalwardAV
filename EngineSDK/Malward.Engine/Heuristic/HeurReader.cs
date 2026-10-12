using System.IO.Compression;

namespace Malward.Engine.Heuristic;

public sealed class HeurReader : IDisposable
{
    public sealed class RuleEntry
    {
        public byte RuleId;
        public string Name = "";
        public long Offset;
        public uint EncSize;
        public uint PlainSize;
    }

    public const uint MAGIC = 0x42445648;
    public const int HEADER_SIZE = 64;
    public const int INDEX_ENTRY_SIZE = 32;

    private readonly FileStream _fs;
    private readonly byte[] _salt = new byte[16];
    private readonly byte[] _ivSeed = new byte[16];
    private readonly byte[] _key;
    public IReadOnlyList<RuleEntry> Rules { get; }
    public uint CreatedTs { get; }
    public byte Version { get; }

    public HeurReader(string path)
    {
        _fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read,
                             1 << 16, FileOptions.RandomAccess);

        Span<byte> hdr = stackalloc byte[HEADER_SIZE];
        _fs.ReadExactly(hdr);
        if (BitConverter.ToUInt32(hdr[..4]) != MAGIC)
            throw new InvalidDataException("Bad HVDB magic");
        Version = hdr[4];

        ushort ruleCount = BitConverter.ToUInt16(hdr[6..8]);
        hdr.Slice(8, 16).CopyTo(_salt);
        hdr.Slice(24, 16).CopyTo(_ivSeed);
        CreatedTs = BitConverter.ToUInt32(hdr.Slice(40, 4));

        _key = Crypto.DeriveKey(_salt);

        var rules = new List<RuleEntry>(ruleCount);
        Span<byte> ent = stackalloc byte[INDEX_ENTRY_SIZE];
        for (int i = 0; i < ruleCount; i++)
        {
            _fs.ReadExactly(ent);
            byte id = ent[0];
            string name = System.Text.Encoding.ASCII.GetString(ent.Slice(2, 14)).TrimEnd('\0');
            long off = BitConverter.ToInt64(ent.Slice(16, 8));
            uint enc = BitConverter.ToUInt32(ent.Slice(24, 4));
            uint plain = BitConverter.ToUInt32(ent.Slice(28, 4));
            rules.Add(new RuleEntry { RuleId = id, Name = name, Offset = off, EncSize = enc, PlainSize = plain });
        }
        Rules = rules;
    }

    public string ExtractToTempFile(string ruleName)
    {
        var rule = Rules.FirstOrDefault(r =>
            string.Equals(r.Name, ruleName, StringComparison.OrdinalIgnoreCase))
            ?? throw new FileNotFoundException($"Rule {ruleName} not in heur.vdeb");

        var ct = new byte[rule.EncSize];
        _fs.Seek(rule.Offset, SeekOrigin.Begin);
        _fs.ReadExactly(ct);

        var iv = Crypto.DeriveIvForRule(_ivSeed, rule.RuleId);
        var gz = Crypto.DecryptCbcPkcs7(ct, _key, iv);

        var tmp = Path.Combine(Path.GetTempPath(), $"malward-{Guid.NewGuid():N}.yac");
        using (var src = new MemoryStream(gz))
        using (var dec = new GZipStream(src, CompressionMode.Decompress))
        using (var dst = new FileStream(tmp, FileMode.CreateNew, FileAccess.Write))
        {
            dec.CopyTo(dst);
        }
        return tmp;
    }

    public void Dispose() => _fs.Dispose();
}
