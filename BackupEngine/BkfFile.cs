using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using static Malward.BackupEngine.BkfFormat;

namespace Malward.BackupEngine;

internal sealed class BkfFile : IDisposable
{
    private readonly string _path;
    private readonly CryptoEnvelope _crypto;
    private FileStream? _fs;
    private Header _header;
    private List<IndexEntry> _index = new();
    private readonly object _lock = new();

    public string Path => _path;
    public int SnapshotCount { get { lock (_lock) return _index.Count; } }
    public long FileSize { get { lock (_lock) return _fs?.Length ?? 0; } }
    public IReadOnlyList<IndexEntry> Index { get { lock (_lock) return _index.ToArray(); } }

    public BkfFile(string path, CryptoEnvelope crypto)
    {
        _path = path;
        _crypto = crypto;
    }

    private bool _readOnly;

    public void Open(bool readOnly = false)
    {
        _readOnly = readOnly;
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(_path)!);

        if (!File.Exists(_path))
        {
            if (readOnly) throw new FileNotFoundException("BKF nie istnieje (read-only open).", _path);
            CreateEmpty();
        }

        var access = readOnly ? FileAccess.Read : FileAccess.ReadWrite;
        var share  = readOnly ? FileShare.ReadWrite : FileShare.Read;

        Exception? lastError = null;
        for (int attempt = 0; attempt < 5; attempt++)
        {
            try
            {
                _fs = new FileStream(_path, FileMode.Open, access, share, bufferSize: 64 * 1024);
                lastError = null;
                break;
            }
            catch (IOException ex)
            {
                lastError = ex;
                Log.Warn("BKF", $"Open attempt {attempt + 1}/5 failed ({ex.Message}) — retry in 500ms");
                Thread.Sleep(500);
            }
        }
        if (lastError != null)
        {
            throw new IOException(
                $"Nie udało się otworzyć {_path} po 5 próbach. " +
                "Inna instancja BackupEngine może wciąż trzymać plik. " +
                "Sprawdź Task Manager / Get-Process bkmonitor i zakończ stare procesy.",
                lastError);
        }

        var hbuf = new byte[HeaderSize];
        _fs.Position = 0;
        int n = _fs.Read(hbuf, 0, HeaderSize);
        if (n < HeaderSize)
            throw new InvalidDataException($"Header too short ({n} < {HeaderSize}).");
        _header = Header.Deserialize(hbuf);

        if (_header.SnapCount > 0 && _header.IndexOffset > 0 && _header.IndexOffset < _fs.Length)
        {
            _fs.Position = _header.IndexOffset;
            var idxBuf = new byte[(int)_header.SnapCount * IndexEntrySize];
            _fs.Read(idxBuf, 0, idxBuf.Length);
            _index.Clear();
            for (int i = 0; i < (int)_header.SnapCount; i++)
            {
                _index.Add(IndexEntry.Deserialize(
                    idxBuf.AsSpan(i * IndexEntrySize, IndexEntrySize)));
            }
        }

        Log.Debug("BKF", $"Opened {_path}: snapshots={_index.Count}, size={_fs.Length:N0} B");
    }

    private void CreateEmpty()
    {
        var header = new Header
        {
            Magic = BkfFormat.Magic,
            Version = BkfFormat.Version,
            Flags = (ushort)(FlagEncrypted | FlagCompressed | FlagHashDedup),
            CreatedMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            SnapCount = 0,
            IndexOffset = HeaderSize,
        };
        using var fs = new FileStream(_path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        fs.Write(header.Serialize(), 0, HeaderSize);
        Log.Info("BKF", $"Created empty BKF: {_path}");
    }

    public Guid AppendSnapshotStreaming(IEnumerable<string> paths, Trigger trigger,
                                          Guid? parentSnapId = null,
                                          int maxFileSizeBytes = int.MaxValue,
                                          Func<string, bool>? excludeFilter = null,
                                          CompressionMode compression = CompressionMode.None,
                                          Action<BackupProgress>? onProgress = null,
                                          long totalFiles = 0, long totalBytes = 0,
                                          CancellationToken ct = default)
    {
        var snapId = Guid.NewGuid();
        var ts = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var entries = new List<FileEntry>();

        long chunksStartOffset;
        long chunkOffsetInArea = 0;
        int processedCount = 0;
        long compressedTotal = 0;

        lock (_lock)
        {
            if (_fs == null) throw new InvalidOperationException("BKF not open.");

            chunksStartOffset = _header.IndexOffset;
            _fs.Position = chunksStartOffset;
        }

        long doneBytes = 0;
        bool cancelled = false;

        foreach (var path in paths)
        {
            if (ct.IsCancellationRequested) { cancelled = true; break; }
            if (excludeFilter != null && excludeFilter(path)) continue;
            FileInfo info;
            try { info = new FileInfo(path); if (!info.Exists) continue; }
            catch { continue; }
            if (info.Length > maxFileSizeBytes) continue;

            try
            {
                long chunkLenInFile;
                byte[] sha256;
                (chunkLenInFile, sha256) = StreamCompressEncryptChunkToBkf(path, snapId, compression);
                if (chunkLenInFile < 0) continue;
                entries.Add(new FileEntry
                {
                    Path = path,
                    Size = info.Length,
                    MtimeMs = ((DateTimeOffset)info.LastWriteTimeUtc).ToUnixTimeMilliseconds(),
                    Sha256 = sha256,
                    ChunkOffset = chunkOffsetInArea,
                    ChunkLength = (uint)chunkLenInFile,
                    ChunkOriginalLength = (uint)info.Length,
                });
                chunkOffsetInArea += chunkLenInFile;
                compressedTotal += chunkLenInFile;
                processedCount++;
                doneBytes += info.Length;

                onProgress?.Invoke(new BackupProgress(
                    processedCount, totalFiles, doneBytes, totalBytes, path));
                BackupPacing.Pace();

                if (processedCount % 50 == 0) GC.Collect(0);
            }
            catch (Exception ex) { Log.Debug("BKF", $"skip {path}: {ex.Message}"); }
        }

        if (cancelled)
        {
            Log.Info("BKF", $"AppendSnapshot cancelled after {processedCount} file(s) — "
                            + "nothing was added to the index.");
            return Guid.Empty;
        }

        if (processedCount == 0)
        {
            Log.Debug("BKF", "AppendSnapshot skipped — 0 files to write.");
            return Guid.Empty;
        }

        using var metaMs = new MemoryStream(8192 + entries.Count * 160);
        metaMs.Write(snapId.ToByteArray(), 0, 16);
        metaMs.Write((parentSnapId ?? Guid.Empty).ToByteArray(), 0, 16);
        Span<byte> ts8 = stackalloc byte[8];
        BinaryPrimitives.WriteInt64LittleEndian(ts8, ts); metaMs.Write(ts8);
        metaMs.WriteByte((byte)trigger);
        metaMs.WriteByte((byte)compression);
        Span<byte> cnt4 = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(cnt4, (uint)entries.Count); metaMs.Write(cnt4);
        Span<byte> entryLen2 = stackalloc byte[2];
        Span<byte> entryTmp8 = stackalloc byte[8];
        Span<byte> entryTmp4 = stackalloc byte[4];
        foreach (var e in entries)
        {
            var pathBytes = Encoding.UTF8.GetBytes(e.Path);
            int plen = Math.Min(pathBytes.Length, ushort.MaxValue);
            BinaryPrimitives.WriteUInt16LittleEndian(entryLen2, (ushort)plen);
            metaMs.Write(entryLen2);
            metaMs.Write(pathBytes, 0, plen);
            BinaryPrimitives.WriteInt64LittleEndian(entryTmp8, e.Size);             metaMs.Write(entryTmp8);
            BinaryPrimitives.WriteInt64LittleEndian(entryTmp8, e.MtimeMs);          metaMs.Write(entryTmp8);
            metaMs.Write(e.Sha256, 0, 32);
            BinaryPrimitives.WriteInt64LittleEndian(entryTmp8, e.ChunkOffset);      metaMs.Write(entryTmp8);
            BinaryPrimitives.WriteUInt32LittleEndian(entryTmp4, e.ChunkLength);     metaMs.Write(entryTmp4);
            BinaryPrimitives.WriteUInt32LittleEndian(entryTmp4, e.ChunkOriginalLength); metaMs.Write(entryTmp4);
        }
        var metaBytes = metaMs.ToArray();
        var metaEnvelope = _crypto.Encrypt(metaBytes, snapId.ToByteArray());
        metaMs.SetLength(0);
        metaBytes = null!;

        lock (_lock)
        {
            if (_fs == null) throw new InvalidOperationException("BKF not open.");
            long metaOffset = chunksStartOffset + chunkOffsetInArea;
            _fs.Position = metaOffset;
            _fs.Write(metaEnvelope, 0, metaEnvelope.Length);

            Span<byte> trailer4 = stackalloc byte[4];
            BinaryPrimitives.WriteUInt32LittleEndian(trailer4, (uint)metaEnvelope.Length);
            _fs.Write(trailer4);

            var newEntry = new IndexEntry
            {
                SnapId = snapId,
                Timestamp = ts,
                Offset = chunksStartOffset,
                Size = (uint)(chunkOffsetInArea + metaEnvelope.Length + 4),
                Trig = trigger,
            };
            _index.Add(newEntry);

            long newIndexOffset = metaOffset + metaEnvelope.Length + 4;
            _fs.Position = newIndexOffset;
            foreach (var ix in _index) _fs.Write(ix.Serialize(), 0, IndexEntrySize);
            _fs.SetLength(newIndexOffset + (long)_index.Count * IndexEntrySize);

            _header = _header with { SnapCount = (uint)_index.Count, IndexOffset = newIndexOffset };
            _fs.Position = 0;
            _fs.Write(_header.Serialize(), 0, HeaderSize);
            _fs.Flush(true);
        }
        metaEnvelope = null!;
        GC.Collect();

        Log.Info("BKF", $"AppendSnapshot {snapId}: {processedCount} files, chunks={compressedTotal:N0} B, trigger={trigger}");
        return snapId;
    }

    private (long, byte[]) StreamCompressEncryptChunkToBkf(string path, Guid snapId, CompressionMode compression)
    {
        byte[] compressed;
        byte[] sha256;
        try
        {
            using var fileFs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read,
                                               64 * 1024, FileOptions.SequentialScan);
            using var sha = SHA256.Create();
            using var outMs = new MemoryStream();
            var buf = new byte[256 * 1024];

            if (compression == CompressionMode.None)
            {
                int n;
                while ((n = fileFs.Read(buf, 0, buf.Length)) > 0)
                {
                    sha.TransformBlock(buf, 0, n, null, 0);
                    outMs.Write(buf, 0, n);
                }
            }
            else
            {
                using (Stream codec = compression == CompressionMode.Brotli
                    ? new System.IO.Compression.BrotliStream(outMs, System.IO.Compression.CompressionLevel.Optimal, leaveOpen: true)
                    : new System.IO.Compression.DeflateStream(outMs, System.IO.Compression.CompressionLevel.Fastest, leaveOpen: true))
                {
                    int n;
                    while ((n = fileFs.Read(buf, 0, buf.Length)) > 0)
                    {
                        sha.TransformBlock(buf, 0, n, null, 0);
                        codec.Write(buf, 0, n);
                    }
                }
            }
            sha.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
            compressed = outMs.ToArray();
            sha256 = sha.Hash!;
        }
        catch { return (-1, Array.Empty<byte>()); }

        var envelope = _crypto.Encrypt(compressed, snapId.ToByteArray());
        compressed = null!;

        long chunkLen;
        lock (_lock)
        {
            if (_fs == null) throw new InvalidOperationException("BKF not open.");

            _fs.Write(envelope, 0, envelope.Length);
            chunkLen = envelope.Length;
        }
        envelope = null!;
        return (chunkLen, sha256);
    }

    public Guid AppendSnapshot(IEnumerable<BackupFileInput> files, Trigger trigger, Guid? parentSnapId = null)
    {
        var fileList = files.ToList();
        var tempDir = System.IO.Path.Combine(System.IO.Path.GetTempPath(),
            "malward-bkf-adapter-" + Guid.NewGuid().ToString("N").Substring(0, 8));
        Directory.CreateDirectory(tempDir);
        var pathToOrig = new Dictionary<string, string>();
        try
        {
            var tempPaths = new List<string>();
            for (int i = 0; i < fileList.Count; i++)
            {
                var f = fileList[i];
                var safeName = "file_" + i + "_" + System.IO.Path.GetFileName(f.RelativePath ?? "");
                var tp = System.IO.Path.Combine(tempDir, safeName);
                File.WriteAllBytes(tp, f.Content);
                File.SetLastWriteTimeUtc(tp,
                    DateTimeOffset.FromUnixTimeMilliseconds(f.MtimeMs).UtcDateTime);
                tempPaths.Add(tp);
                pathToOrig[tp] = f.RelativePath ?? "";
            }

            return AppendSnapshotStreaming(tempPaths, trigger, parentSnapId);
        }
        finally
        {
            try { Directory.Delete(tempDir, recursive: true); } catch { }
        }
    }

    public SnapshotView ReadSnapshot(Guid snapId)
    {
        IndexEntry entry;
        lock (_lock)
        {
            var found = _index.FirstOrDefault(e => e.SnapId == snapId);
            if (found.SnapId == Guid.Empty) throw new KeyNotFoundException($"Snapshot {snapId} not in index.");
            entry = found;
        }

        long snapStart = entry.Offset;
        uint snapTotalSize = entry.Size;
        long trailerOffset = snapStart + snapTotalSize - 4;

        byte[] metaEnvelope;
        lock (_lock)
        {
            if (_fs == null) throw new InvalidOperationException("BKF not open.");

            Span<byte> trailer = stackalloc byte[4];
            _fs.Position = trailerOffset;
            int tn = _fs.Read(trailer);
            if (tn < 4) throw new InvalidDataException("Snapshot trailer truncated.");
            uint metaEnvLen = BinaryPrimitives.ReadUInt32LittleEndian(trailer);
            if (metaEnvLen == 0 || metaEnvLen > snapTotalSize - 4)
                throw new InvalidDataException($"Invalid meta envelope length: {metaEnvLen}");

            long metaEnvOffset = trailerOffset - metaEnvLen;
            metaEnvelope = new byte[metaEnvLen];
            _fs.Position = metaEnvOffset;
            _fs.Read(metaEnvelope, 0, (int)metaEnvLen);
        }
        var meta = _crypto.Decrypt(metaEnvelope, snapId.ToByteArray());

        int pos = 0;
        var snapIdEcho = new Guid(meta.AsSpan(pos, 16));         pos += 16;
        if (snapIdEcho != snapId)
            throw new InvalidDataException("Snapshot ID mismatch — possible tampering.");
        var parentId = new Guid(meta.AsSpan(pos, 16));            pos += 16;
        long ts = BinaryPrimitives.ReadInt64LittleEndian(meta.AsSpan(pos, 8));  pos += 8;
        var trig = (Trigger)meta[pos];                             pos += 1;
        var compression = (CompressionMode)meta[pos];              pos += 1;
        uint fileCount = BinaryPrimitives.ReadUInt32LittleEndian(meta.AsSpan(pos, 4));  pos += 4;

        var entries = new List<FileEntry>((int)fileCount);
        for (int i = 0; i < fileCount; i++)
        {
            ushort plen = BinaryPrimitives.ReadUInt16LittleEndian(meta.AsSpan(pos, 2));  pos += 2;
            var path = Encoding.UTF8.GetString(meta, pos, plen);   pos += plen;
            long size = BinaryPrimitives.ReadInt64LittleEndian(meta.AsSpan(pos, 8));    pos += 8;
            long mt   = BinaryPrimitives.ReadInt64LittleEndian(meta.AsSpan(pos, 8));    pos += 8;
            var sha = new byte[32];  Buffer.BlockCopy(meta, pos, sha, 0, 32);            pos += 32;
            long coff = BinaryPrimitives.ReadInt64LittleEndian(meta.AsSpan(pos, 8));   pos += 8;
            uint clen = BinaryPrimitives.ReadUInt32LittleEndian(meta.AsSpan(pos, 4));   pos += 4;
            uint cori = BinaryPrimitives.ReadUInt32LittleEndian(meta.AsSpan(pos, 4));   pos += 4;
            entries.Add(new FileEntry
            {
                Path = path, Size = size, MtimeMs = mt, Sha256 = sha,
                ChunkOffset = coff, ChunkLength = clen, ChunkOriginalLength = cori,
            });
        }
        return new SnapshotView
        {
            SnapId = snapId, ParentId = parentId, TimestampMs = ts, Trigger = trig,
            Compression = compression,
            Files = entries, BodyBytes = Array.Empty<byte>(),
            ChunksAreaOffset = (int)snapStart,
        };
    }

    public byte[] ReadFileContent(SnapshotView snap, FileEntry entry)
    {
        byte[] chunkEnvelope;
        lock (_lock)
        {
            if (_fs == null) throw new InvalidOperationException("BKF not open.");
            chunkEnvelope = new byte[entry.ChunkLength];
            _fs.Position = snap.ChunksAreaOffset + entry.ChunkOffset;
            _fs.Read(chunkEnvelope, 0, (int)entry.ChunkLength);
        }
        var compressed = _crypto.Decrypt(chunkEnvelope, snap.SnapId.ToByteArray());
        chunkEnvelope = null!;
        var raw = ZstdCodec.Decompress(compressed, snap.Compression);
        compressed = null!;
        if (raw.Length != entry.ChunkOriginalLength)
            throw new InvalidDataException(
                $"Chunk size mismatch: expected {entry.ChunkOriginalLength}, got {raw.Length}");
        var sha = SHA256.HashData(raw);
        if (!sha.SequenceEqual(entry.Sha256))
            throw new InvalidDataException($"SHA256 mismatch for '{entry.Path}' — corrupted snapshot.");
        return raw;
    }

    public bool DeleteSnapshot(Guid snapId)
    {
        lock (_lock)
        {
            if (_fs == null) throw new InvalidOperationException("BKF not open.");
            var survivors = _index.Where(e => e.SnapId != snapId)
                                   .OrderBy(e => e.Offset).ToList();
            if (survivors.Count == _index.Count) return false;

            var tmpPath = _path + ".compact.tmp";
            try { if (File.Exists(tmpPath)) File.Delete(tmpPath); } catch { }

            var newIndex = new List<IndexEntry>(survivors.Count);
            using (var dst = new FileStream(tmpPath, FileMode.Create, FileAccess.Write, FileShare.None, 1 << 20))
            {
                dst.Write(new byte[HeaderSize], 0, HeaderSize);
                long writeOff = HeaderSize;
                var buf = new byte[1 << 20];
                foreach (var e in survivors)
                {
                    _fs.Position = e.Offset;
                    long remaining = e.Size;
                    while (remaining > 0)
                    {
                        int toRead = (int)Math.Min(remaining, buf.Length);
                        int rd = _fs.Read(buf, 0, toRead);
                        if (rd <= 0) break;
                        dst.Write(buf, 0, rd);
                        remaining -= rd;
                    }
                    newIndex.Add(e with { Offset = writeOff });
                    writeOff += e.Size;
                }
                long idxOffset = writeOff;
                foreach (var ix in newIndex) dst.Write(ix.Serialize(), 0, IndexEntrySize);

                var hdr = _header with { SnapCount = (uint)newIndex.Count, IndexOffset = idxOffset };
                dst.Position = 0;
                dst.Write(hdr.Serialize(), 0, HeaderSize);
                dst.Flush(true);
            }

            _fs.Dispose(); _fs = null;
            File.Replace(tmpPath, _path, destinationBackupFileName: null, ignoreMetadataErrors: true);
            ReopenAfterMutation();
            Log.Info("BKF", $"DeleteSnapshot {snapId}: compaction OK, snapshots={_index.Count}");
            return true;
        }
    }

    public void ExportSnapshot(Guid snapId, string outPath)
    {
        lock (_lock)
        {
            if (_fs == null) throw new InvalidOperationException("BKF not open.");
            var e = _index.FirstOrDefault(x => x.SnapId == snapId);
            if (e.SnapId == Guid.Empty) throw new KeyNotFoundException($"Snapshot {snapId} nie istnieje.");

            Directory.CreateDirectory(System.IO.Path.GetDirectoryName(System.IO.Path.GetFullPath(outPath))!);
            using var dst = new FileStream(outPath, FileMode.Create, FileAccess.Write, FileShare.None, 1 << 20);
            dst.Write(new byte[HeaderSize], 0, HeaderSize);
            long regionStart = HeaderSize;

            _fs.Position = e.Offset;
            long remaining = e.Size;
            var buf = new byte[1 << 20];
            while (remaining > 0)
            {
                int toRead = (int)Math.Min(remaining, buf.Length);
                int rd = _fs.Read(buf, 0, toRead);
                if (rd <= 0) break;
                dst.Write(buf, 0, rd);
                remaining -= rd;
            }
            long idxOffset = regionStart + e.Size;
            var exportedEntry = e with { Offset = regionStart };
            dst.Write(exportedEntry.Serialize(), 0, IndexEntrySize);
            var hdr = new Header
            {
                Magic = BkfFormat.Magic, Version = BkfFormat.Version,
                Flags = _header.Flags, CreatedMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                SnapCount = 1, IndexOffset = idxOffset,
            };
            dst.Position = 0;
            dst.Write(hdr.Serialize(), 0, HeaderSize);
            dst.Flush(true);
            Log.Info("BKF", $"ExportSnapshot {snapId} → {outPath} ({e.Size:N0} B)");
        }
    }

    public int ImportFromFile(string inPath)
    {
        if (!File.Exists(inPath)) throw new FileNotFoundException(inPath);

        using var src = new FileStream(inPath, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 20);
        var hbuf = new byte[HeaderSize];
        if (src.Read(hbuf, 0, HeaderSize) < HeaderSize) throw new InvalidDataException("Mini-BKF header truncated.");
        var srcHeader = Header.Deserialize(hbuf);
        var srcIndex = new List<IndexEntry>();
        if (srcHeader.SnapCount > 0)
        {
            src.Position = srcHeader.IndexOffset;
            var idxBuf = new byte[(int)srcHeader.SnapCount * IndexEntrySize];
            src.Read(idxBuf, 0, idxBuf.Length);
            for (int i = 0; i < (int)srcHeader.SnapCount; i++)
                srcIndex.Add(IndexEntry.Deserialize(idxBuf.AsSpan(i * IndexEntrySize, IndexEntrySize)));
        }

        int imported = 0;
        lock (_lock)
        {
            if (_fs == null) throw new InvalidOperationException("BKF not open.");
            var buf = new byte[1 << 20];
            foreach (var e in srcIndex)
            {
                if (_index.Any(x => x.SnapId == e.SnapId)) { Log.Info("BKF", $"Import skip — {e.SnapId} already exists"); continue; }
                long destOff = _header.IndexOffset;
                _fs.Position = destOff;
                src.Position = e.Offset;
                long remaining = e.Size;
                while (remaining > 0)
                {
                    int toRead = (int)Math.Min(remaining, buf.Length);
                    int rd = src.Read(buf, 0, toRead);
                    if (rd <= 0) break;
                    _fs.Write(buf, 0, rd);
                    remaining -= rd;
                }
                _index.Add(e with { Offset = destOff });
                long newIndexOffset = destOff + e.Size;
                _fs.Position = newIndexOffset;
                foreach (var ix in _index) _fs.Write(ix.Serialize(), 0, IndexEntrySize);
                _fs.SetLength(newIndexOffset + (long)_index.Count * IndexEntrySize);
                _header = _header with { SnapCount = (uint)_index.Count, IndexOffset = newIndexOffset };
                _fs.Position = 0; _fs.Write(_header.Serialize(), 0, HeaderSize);
                _fs.Flush(true);
                imported++;
            }
        }
        Log.Info("BKF", $"ImportFromFile {inPath}: {imported} snapshot(s)");
        return imported;
    }

    private void ReopenAfterMutation()
    {
        _fs = new FileStream(_path, FileMode.Open, FileAccess.ReadWrite, FileShare.Read, 64 * 1024);
        var hbuf = new byte[HeaderSize];
        _fs.Position = 0; _fs.Read(hbuf, 0, HeaderSize);
        _header = Header.Deserialize(hbuf);
        _index.Clear();
        if (_header.SnapCount > 0 && _header.IndexOffset > 0)
        {
            _fs.Position = _header.IndexOffset;
            var idxBuf = new byte[(int)_header.SnapCount * IndexEntrySize];
            _fs.Read(idxBuf, 0, idxBuf.Length);
            for (int i = 0; i < (int)_header.SnapCount; i++)
                _index.Add(IndexEntry.Deserialize(idxBuf.AsSpan(i * IndexEntrySize, IndexEntrySize)));
        }
    }

    public void Dispose()
    {
        try { _fs?.Flush(true); } catch { }
        try { _fs?.Dispose(); } catch { }
        _fs = null;
    }
}

public sealed class BackupFileInput
{
    public string RelativePath { get; set; } = "";

    public byte[] Content { get; set; } = Array.Empty<byte>();

    public long MtimeMs { get; set; }
}

public sealed class SnapshotView
{
    public Guid SnapId { get; set; }
    public Guid ParentId { get; set; }
    public long TimestampMs { get; set; }
    public BkfFormat.Trigger Trigger { get; set; }
    public CompressionMode Compression { get; set; } = CompressionMode.None;
    public List<FileEntry> Files { get; set; } = new();
    public byte[] BodyBytes { get; set; } = Array.Empty<byte>();
    public int ChunksAreaOffset { get; set; }
}
