using System.Text;

namespace Malward.Engine.Quarantine;

public static class QbFormat
{
    public const int HEADER_SIZE = 64;
    public const byte VERSION = 2;
    public static readonly byte[] MAGIC_BYTES = { (byte)'M', (byte)'W', (byte)'Q', (byte)'B' };

    public sealed class Entry
    {
        public Guid Id;
        public string OriginalPath = "";
        public ulong Size;
        public byte[] Sha256 = Array.Empty<byte>();
        public string Detection = "";
        public ulong QuarantinedTs;
        public byte[] Iv = Array.Empty<byte>();
        public ulong PayloadSize;
    }

    public static byte[] BuildHeader(byte[] salt, uint entryCount)
    {
        var hdr = new byte[HEADER_SIZE];
        Buffer.BlockCopy(MAGIC_BYTES, 0, hdr, 0, 4);
        hdr[4] = VERSION;

        BitConverter.GetBytes(entryCount).CopyTo(hdr, 6);
        Buffer.BlockCopy(salt, 0, hdr, 10, 16);
        return hdr;
    }

    public static (byte[] salt, uint entryCount, byte version) ReadHeader(Stream s)
    {
        var hdr = new byte[HEADER_SIZE];
        if (s.Read(hdr, 0, HEADER_SIZE) != HEADER_SIZE)
            throw new InvalidDataException("QB header truncated");
        if (hdr[0] != MAGIC_BYTES[0] || hdr[1] != MAGIC_BYTES[1] ||
            hdr[2] != MAGIC_BYTES[2] || hdr[3] != MAGIC_BYTES[3])
            throw new InvalidDataException("Bad MWQB magic");
        byte ver = hdr[4];
        if (ver != VERSION)
            throw new InvalidDataException(
                $"Unsupported QB version {ver} (expected {VERSION}). Plik z poprzedniej wersji silnika — usuń quarantine.QB i pliki .bin obok niego.");
        uint entryCount = BitConverter.ToUInt32(hdr, 6);
        var salt = new byte[16];
        Buffer.BlockCopy(hdr, 10, salt, 0, 16);
        return (salt, entryCount, ver);
    }

    public static void WriteEntry(BinaryWriter bw, Entry e)
    {
        bw.Write(e.Id.ToByteArray());
        var path = Encoding.UTF8.GetBytes(e.OriginalPath);
        bw.Write((ushort)path.Length);
        bw.Write(path);
        bw.Write(e.Size);
        if (e.Sha256.Length != 32) throw new InvalidDataException("Sha256 must be 32 bytes");
        bw.Write(e.Sha256);
        var det = Encoding.UTF8.GetBytes(e.Detection);
        bw.Write((ushort)det.Length);
        bw.Write(det);
        bw.Write(e.QuarantinedTs);
        if (e.Iv.Length != 16) throw new InvalidDataException("IV must be 16 bytes");
        bw.Write(e.Iv);
        bw.Write(e.PayloadSize);
    }

    public static Entry ReadEntry(BinaryReader br)
    {
        var e = new Entry { Id = new Guid(br.ReadBytes(16)) };
        ushort pathLen = br.ReadUInt16();
        e.OriginalPath = Encoding.UTF8.GetString(br.ReadBytes(pathLen));
        e.Size = br.ReadUInt64();
        e.Sha256 = br.ReadBytes(32);
        ushort detLen = br.ReadUInt16();
        e.Detection = Encoding.UTF8.GetString(br.ReadBytes(detLen));
        e.QuarantinedTs = br.ReadUInt64();
        e.Iv = br.ReadBytes(16);
        e.PayloadSize = br.ReadUInt64();
        return e;
    }
}
