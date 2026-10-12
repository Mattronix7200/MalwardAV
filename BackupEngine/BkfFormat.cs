using System.Buffers.Binary;

namespace Malward.BackupEngine;

public static class BkfFormat
{
    public const uint Magic = 0x4B42574D;

    public const ushort Version = 2;

    public const ushort FlagEncrypted    = 0x0001;
    public const ushort FlagCompressed   = 0x0002;
    public const ushort FlagHashDedup    = 0x0004;

    public const int HeaderSize = 32;
    public const int IndexEntrySize = 37;
    public const int NonceSize = 12;
    public const int TagSize = 16;
    public const int Sha256Size = 32;

    public enum Trigger : byte
    {
        Manual      = 0,
        Schedule    = 1,
        FsWatch     = 2,
        PreRollback = 3,
    }

    public readonly struct Header
    {
        public uint Magic { get; init; }
        public ushort Version { get; init; }
        public ushort Flags { get; init; }
        public long CreatedMs { get; init; }
        public uint SnapCount { get; init; }
        public long IndexOffset { get; init; }

        public byte[] Serialize()
        {
            var buf = new byte[HeaderSize];
            BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(0, 4), Magic);
            BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(4, 2), Version);
            BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(6, 2), Flags);
            BinaryPrimitives.WriteInt64LittleEndian(buf.AsSpan(8, 8), CreatedMs);
            BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(16, 4), SnapCount);
            BinaryPrimitives.WriteInt64LittleEndian(buf.AsSpan(20, 8), IndexOffset);
            return buf;
        }

        public static Header Deserialize(ReadOnlySpan<byte> buf)
        {
            if (buf.Length < HeaderSize) throw new InvalidDataException("Truncated BKF header.");
            var magic = BinaryPrimitives.ReadUInt32LittleEndian(buf.Slice(0, 4));
            if (magic != BkfFormat.Magic) throw new InvalidDataException($"Bad BKF magic 0x{magic:X8}");
            return new Header
            {
                Magic = magic,
                Version = BinaryPrimitives.ReadUInt16LittleEndian(buf.Slice(4, 2)),
                Flags = BinaryPrimitives.ReadUInt16LittleEndian(buf.Slice(6, 2)),
                CreatedMs = BinaryPrimitives.ReadInt64LittleEndian(buf.Slice(8, 8)),
                SnapCount = BinaryPrimitives.ReadUInt32LittleEndian(buf.Slice(16, 4)),
                IndexOffset = BinaryPrimitives.ReadInt64LittleEndian(buf.Slice(20, 8)),
            };
        }
    }

    public readonly struct IndexEntry
    {
        public Guid SnapId { get; init; }
        public long Timestamp { get; init; }
        public long Offset { get; init; }
        public uint Size { get; init; }
        public Trigger Trig { get; init; }

        public byte[] Serialize()
        {
            var buf = new byte[IndexEntrySize];
            SnapId.TryWriteBytes(buf.AsSpan(0, 16));
            BinaryPrimitives.WriteInt64LittleEndian(buf.AsSpan(16, 8), Timestamp);
            BinaryPrimitives.WriteInt64LittleEndian(buf.AsSpan(24, 8), Offset);
            BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(32, 4), Size);
            buf[36] = (byte)Trig;
            return buf;
        }

        public static IndexEntry Deserialize(ReadOnlySpan<byte> buf)
        {
            if (buf.Length < IndexEntrySize) throw new InvalidDataException("Truncated index entry.");
            return new IndexEntry
            {
                SnapId = new Guid(buf.Slice(0, 16)),
                Timestamp = BinaryPrimitives.ReadInt64LittleEndian(buf.Slice(16, 8)),
                Offset = BinaryPrimitives.ReadInt64LittleEndian(buf.Slice(24, 8)),
                Size = BinaryPrimitives.ReadUInt32LittleEndian(buf.Slice(32, 4)),
                Trig = (Trigger)buf[36],
            };
        }
    }

    public sealed class FileEntry
    {
        public string Path { get; set; } = "";
        public long Size { get; set; }
        public long MtimeMs { get; set; }
        public byte[] Sha256 { get; set; } = Array.Empty<byte>();
        public long ChunkOffset { get; set; }
        public uint ChunkLength { get; set; }
        public uint ChunkOriginalLength { get; set; }
    }
}
