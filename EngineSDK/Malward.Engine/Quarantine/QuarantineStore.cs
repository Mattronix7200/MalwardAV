using System.Security.Cryptography;
using Malward.Engine.Heuristic;
using Malward.Engine.Util;

namespace Malward.Engine.Quarantine;

public sealed class QuarantineStore
{
    private readonly string _qbPath;
    private readonly string _payloadDir;
    private byte[] _salt = new byte[16];
    private byte[] _key = Array.Empty<byte>();
    private readonly List<QbFormat.Entry> _entries = new();
    private readonly object _lock = new();

    public long SizeLimitBytes { get; set; } = 5L * 1024 * 1024 * 1024;

    public QuarantineStore()
    {
        Paths.EnsureDirs();
        _qbPath = Paths.QuarantineFile;
        _payloadDir = Path.GetDirectoryName(_qbPath)!;
        if (File.Exists(_qbPath))
        {
            try { LoadExisting(); }
            catch (InvalidDataException ex)
            {
                BackupCorruptAndReset(ex.Message);
            }
            catch (Exception ex)
            {
                BackupCorruptAndReset($"unexpected: {ex.Message}");
            }
        }
        else CreateEmpty();
    }

    private void BackupCorruptAndReset(string reason)
    {
        var ts = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var bak = $"{_qbPath}.bak-{ts}";
        try { File.Move(_qbPath, bak); }
        catch {  }
        Console.Error.WriteLine($"[!] quarantine.QB unreadable ({reason}). Backup saved: {bak}. Creating a new empty one.");
        _entries.Clear();
        CreateEmpty();
    }

    private void CreateEmpty()
    {
        RandomNumberGenerator.Fill(_salt);
        _key = Crypto.DeriveKey(_salt);
        File.WriteAllBytes(_qbPath, QbFormat.BuildHeader(_salt, entryCount: 0));
    }

    private void LoadExisting()
    {
        using var fs = new FileStream(_qbPath, FileMode.Open, FileAccess.Read, FileShare.Read);
        var (salt, entryCount, _) = QbFormat.ReadHeader(fs);
        _salt = salt;
        _key = Crypto.DeriveKey(_salt);

        using var br = new BinaryReader(fs);
        for (int i = 0; i < entryCount; i++)
            _entries.Add(QbFormat.ReadEntry(br));
    }

    private string PayloadPath(Guid id) => Path.Combine(_payloadDir, $"{id:N}.bin");

    public Guid Add(string sourcePath, string detection, string sha256Hex)
    {
        if (!File.Exists(sourcePath)) throw new FileNotFoundException(sourcePath);

        lock (_lock)
        {
            var id = Guid.NewGuid();
            var iv = new byte[16];
            RandomNumberGenerator.Fill(iv);
            var plain = File.ReadAllBytes(sourcePath);
            var ct = Crypto.EncryptCbcPkcs7(plain, _key, iv);

            var payload = PayloadPath(id);
            using (var pf = new FileStream(payload, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                pf.Write(iv, 0, iv.Length);
                pf.Write(ct, 0, ct.Length);
            }

            var entry = new QbFormat.Entry
            {
                Id = id,
                OriginalPath = sourcePath,
                Size = (ulong)plain.LongLength,
                Sha256 = Convert.FromHexString(sha256Hex),
                Detection = detection,
                QuarantinedTs = (ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                Iv = iv,
                PayloadSize = (ulong)(iv.Length + ct.Length),
            };
            _entries.Add(entry);
            RewriteQb();

            EnforceSizeLimit();

            return id;
        }
    }

    public long TotalSize()
    {
        lock (_lock) return _entries.Sum(e => (long)e.PayloadSize);
    }

    public void EnforceSizeLimit()
    {
        long total = _entries.Sum(e => (long)e.PayloadSize);
        if (total <= SizeLimitBytes) return;

        var byAge = _entries.OrderBy(e => e.QuarantinedTs).ToList();
        int i = 0;
        while (total > SizeLimitBytes && i < byAge.Count - 1)
        {
            var victim = byAge[i++];
            var payload = PayloadPath(victim.Id);
            if (File.Exists(payload))
            {
                try { File.Delete(payload); } catch { }
            }
            _entries.RemoveAll(e => e.Id == victim.Id);
            total -= (long)victim.PayloadSize;
        }
        RewriteQb();
    }

    public IReadOnlyList<QbFormat.Entry> List()
    {
        lock (_lock) return _entries.ToArray();
    }

    public bool Restore(Guid id, string? destPath = null)
    {
        lock (_lock)
        {
            var e = _entries.FirstOrDefault(x => x.Id == id);
            if (e == null)
            {
                Console.Error.WriteLine($"[!] Quarantine: entry {id} not found");
                return false;
            }

            var payload = PayloadPath(id);
            if (!File.Exists(payload))
            {
                Console.Error.WriteLine($"[!] Missing payload: {payload}");
                return false;
            }

            byte[] plain;
            try
            {
                using var pf = new FileStream(payload, FileMode.Open, FileAccess.Read, FileShare.Read);
                var iv = new byte[16];
                pf.ReadExactly(iv);
                var ct = new byte[(int)e.PayloadSize - 16];
                pf.ReadExactly(ct);
                plain = Crypto.DecryptCbcPkcs7(ct, _key, iv);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[!] Decrypt failed: {ex.Message}");
                return false;
            }

            var dest = destPath ?? e.OriginalPath;
            if (!string.IsNullOrEmpty(destPath)
                && (Directory.Exists(destPath)
                    || destPath.EndsWith(Path.DirectorySeparatorChar)
                    || destPath.EndsWith(Path.AltDirectorySeparatorChar)))
            {
                var name = Path.GetFileName(e.OriginalPath);
                if (string.IsNullOrEmpty(name)) name = id.ToString("N");
                dest = Path.Combine(destPath, name);
            }
            if (TryWrite(dest, plain, out var err))
            {
                Console.WriteLine($"[+] Restored to: {dest}");
                return true;
            }

            var fallback = Path.Combine(_payloadDir,
                $"restored-{id:N}{Path.GetExtension(e.OriginalPath)}");
            if (TryWrite(fallback, plain, out var err2))
            {
                Console.Error.WriteLine($"[!] Cannot write to {dest}: {err}");
                Console.WriteLine($"[+] Fallback: {fallback}");
                return true;
            }

            Console.Error.WriteLine($"[!] Restore failed: {err2}");
            return false;
        }
    }

    private static bool TryWrite(string path, byte[] data, out string error)
    {
        try
        {
            var dir = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            File.WriteAllBytes(path, data);
            error = "";
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            error = ex.Message;
            return false;
        }
    }

    public string? Extract(Guid id, string destDir, string? nameHint = null)
    {
        if (string.IsNullOrWhiteSpace(destDir)) return null;
        var got = DecryptPayload(id);
        if (got == null) return null;

        var name = SafeName(nameHint) ?? SafeName(Path.GetFileName(got.Value.entry.OriginalPath));
        if (name == null)
        {
            Console.Error.WriteLine($"[!] Quarantine: entry {id} has no original file name");
            return null;
        }

        var dest = UniquePath(Path.Combine(destDir, name));
        if (!TryWrite(dest, got.Value.payload, out var err))
        {
            Console.Error.WriteLine($"[!] Cannot write to {dest}: {err}");
            return null;
        }
        return dest;
    }

    public string ExportContainer(Guid id, string destPath)
    {
        if (string.IsNullOrWhiteSpace(destPath)) return "no destination given";
        bool known;
        lock (_lock) known = _entries.Any(e => e.Id == id);
        if (!known) return "no such entry in the engine quarantine";

        var got = DecryptPayload(id);
        if (got == null) return "the entry is listed but its payload cannot be read or decrypted";

        try
        {
            var dir = Path.GetDirectoryName(destPath);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            Malward.ResidentShield.QuarantineCrypto.EncryptBytes(got.Value.payload, destPath);
            return "";
        }
        catch (Exception ex) { return ex.Message; }
    }

    private static string? SafeName(string? candidate)
    {
        if (string.IsNullOrWhiteSpace(candidate)) return null;
        string name;
        try { name = Path.GetFileName(candidate.Trim()); }
        catch { return null; }
        if (string.IsNullOrEmpty(name)) return null;
        return name.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 ? null : name;
    }

    private static string UniquePath(string path)
    {
        if (!File.Exists(path)) return path;
        var dir  = Path.GetDirectoryName(path) ?? "";
        var stem = Path.GetFileNameWithoutExtension(path);
        var ext  = Path.GetExtension(path);
        for (int i = 2; i < 1000; i++)
        {
            var candidate = Path.Combine(dir, $"{stem} ({i}){ext}");
            if (!File.Exists(candidate)) return candidate;
        }
        return path;
    }

    public (QbFormat.Entry entry, byte[] payload)? DecryptPayload(Guid id)
    {
        lock (_lock)
        {
            var e = _entries.FirstOrDefault(x => x.Id == id);
            if (e == null) return null;
            var payload = PayloadPath(id);
            if (!File.Exists(payload)) return null;
            try
            {
                using var pf = new FileStream(payload, FileMode.Open, FileAccess.Read, FileShare.Read);
                var iv = new byte[16];
                pf.ReadExactly(iv);
                var ct = new byte[(int)e.PayloadSize - 16];
                pf.ReadExactly(ct);
                var plain = Crypto.DecryptCbcPkcs7(ct, _key, iv);
                return (e, plain);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[!] Decrypt failed: {ex.Message}");
                return null;
            }
        }
    }

    public bool Delete(Guid id)
    {
        lock (_lock)
        {
            int idx = _entries.FindIndex(x => x.Id == id);
            if (idx < 0) return false;
            _entries.RemoveAt(idx);
            RewriteQb();

            var payload = PayloadPath(id);
            if (File.Exists(payload))
            {
                try { File.Delete(payload); }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"[!] Failed to delete payload {payload}: {ex.Message}");
                }
            }
            return true;
        }
    }

    private void RewriteQb()
    {
        var tmp = _qbPath + ".tmp";
        using (var fs = new FileStream(tmp, FileMode.Create, FileAccess.Write, FileShare.None))
        using (var bw = new BinaryWriter(fs))
        {
            fs.Write(QbFormat.BuildHeader(_salt, (uint)_entries.Count));
            foreach (var e in _entries) QbFormat.WriteEntry(bw, e);
        }
        if (File.Exists(_qbPath)) File.Delete(_qbPath);
        File.Move(tmp, _qbPath);
    }
}
