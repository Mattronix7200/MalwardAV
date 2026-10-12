using System.Runtime.InteropServices;
using Malward.Engine.Util;

namespace Malward.Engine.Archive;

internal sealed class SevenZipLib : IDisposable
{
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr LoadLibraryW(string path);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool FreeLibrary(IntPtr module);

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    private static extern IntPtr GetProcAddress(IntPtr module, string name);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int CreateObjectDelegate(ref Guid clsid, ref Guid iid,
        [MarshalAs(UnmanagedType.Interface)] out object outObject);

    private readonly IntPtr _module;
    private readonly CreateObjectDelegate _createObject;

    private static readonly object _initLock = new();
    private static SevenZipLib? _shared;
    private static bool _initFailed;

    public static SevenZipLib? Shared
    {
        get
        {
            if (_shared != null) return _shared;
            lock (_initLock)
            {
                if (_shared != null) return _shared;
                if (_initFailed) return null;
                try { _shared = new SevenZipLib(Paths.SevenZipDll); }
                catch (Exception ex)
                {
                    _initFailed = true;
                    Console.Error.WriteLine($"[!] 7z.dll unavailable ({ex.Message}) — falling back to 7z.exe");
                }
                return _shared;
            }
        }
    }

    private SevenZipLib(string dllPath)
    {
        if (!File.Exists(dllPath)) throw new FileNotFoundException("7z.dll", dllPath);
        _module = LoadLibraryW(dllPath);
        if (_module == IntPtr.Zero)
            throw new InvalidOperationException($"LoadLibrary rc={Marshal.GetLastWin32Error()}");
        var proc = GetProcAddress(_module, "CreateObject");
        if (proc == IntPtr.Zero)
        {
            FreeLibrary(_module);
            throw new InvalidOperationException("brak eksportu CreateObject");
        }
        _createObject = Marshal.GetDelegateForFunctionPointer<CreateObjectDelegate>(proc);
    }

    public void Dispose()
    {
        if (_module != IntPtr.Zero) FreeLibrary(_module);
    }

    private static Guid FormatGuid(byte id) =>
        new(0x23170F69, 0x40C1, 0x278A,
            0x10, 0x00, 0x00, 0x01, 0x10, id, 0x00, 0x00);

    private static byte[] HandlersFor(string ext) => ext.ToLowerInvariant() switch
    {
        ".7z"                        => new byte[] { 0x07 },
        ".zip" or ".zipx" or ".jar" or ".war" or ".ear" or ".apk" or ".ipa"
            or ".xpi" or ".crx" or ".odt" or ".ods" or ".odp" or ".epub" or ".nupkg"
                                     => new byte[] { 0x01 },
        ".rar"                       => new byte[] { 0xCC, 0x03 },
        ".cab"                       => new byte[] { 0x08 },
        ".tar"                       => new byte[] { 0xEE },
        ".gz" or ".tgz"              => new byte[] { 0xEF },
        ".bz2" or ".tbz" or ".tbz2"  => new byte[] { 0x02 },
        ".xz" or ".txz"              => new byte[] { 0x0C },
        ".lzma"                      => new byte[] { 0x0A },
        ".zst" or ".tzst"            => new byte[] { 0x0E },
        ".arj"                       => new byte[] { 0x04 },
        ".z" or ".taz"               => new byte[] { 0x05 },
        ".lzh" or ".lha"             => new byte[] { 0x06 },
        ".cpio"                      => new byte[] { 0xED },
        ".iso"                       => new byte[] { 0xE7 },
        ".udf"                       => new byte[] { 0xE0 },
        ".wim" or ".swm" or ".esd"   => new byte[] { 0xE6 },
        ".dmg"                       => new byte[] { 0xE4 },
        ".hfs"                       => new byte[] { 0xE3 },
        ".vhd"                       => new byte[] { 0xDC },
        ".vhdx"                      => new byte[] { 0xC4 },
        ".vmdk" or ".vdi" or ".qcow" or ".qcow2" or ".img"
                                     => new byte[] { 0xCA },
        ".squashfs"                  => new byte[] { 0xD2 },
        ".cramfs"                    => new byte[] { 0xD3 },
        ".ext" or ".fat" or ".ntfs" or ".gpt" or ".mbr"
                                     => new byte[] { 0xC7, 0xDA, 0xD9, 0xCB, 0xDB },
        ".rpm"                       => new byte[] { 0xEB },
        ".deb"                       => new byte[] { 0xEC },
        ".msi" or ".msp"             => new byte[] { 0xE5 },
        ".xar" or ".pkg"             => new byte[] { 0xE1 },
        ".msix" or ".appx"           => new byte[] { 0x01 },

        _                            => Array.Empty<byte>(),
    };

    private static readonly byte[] FallbackHandlers = { 0x07, 0x01, 0xCC, 0x03, 0x08, 0xEE, 0xEF, 0xE7 };

    public SevenZipArchive? Open(string path)
    {
        var ext = Path.GetExtension(path);
        var order = HandlersFor(ext);
        var tried = new HashSet<byte>();

        foreach (var id in order.Concat(FallbackHandlers))
        {
            if (!tried.Add(id)) continue;
            var archive = TryOpen(path, id);
            if (archive != null) return archive;
        }
        return null;
    }

    private static readonly bool Debug =
        Environment.GetEnvironmentVariable("MALWARD_7Z_DEBUG") == "1";

    private SevenZipArchive? TryOpen(string path, byte formatId)
    {
        FileStream? fs = null;
        try
        {
            var clsid = FormatGuid(formatId);
            var iid = typeof(IInArchive).GUID;
            int hrCreate = _createObject(ref clsid, ref iid, out object obj);
            if (Debug)
                Console.Error.WriteLine($"[7z] {Path.GetFileName(path)} fmt=0x{formatId:X2} " +
                                        $"clsid={clsid} CreateObject=0x{hrCreate:X8} obj={(obj == null ? "null" : obj.GetType().Name)}");
            if (hrCreate != 0 || obj is not IInArchive arc)
                return null;

            fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            var stream = new InStreamWrapper(fs);
            var openCb = new ArchiveOpenCallback();
            ulong checkPos = 1 << 23;

            int hrOpen = arc.Open(stream, ref checkPos, openCb);
            if (Debug) Console.Error.WriteLine($"[7z]   Open=0x{hrOpen:X8} pw={openCb.PasswordRequested}");
            if (hrOpen != 0)
            {
                bool encryptedHeader = openCb.PasswordRequested;
                try { arc.Close(); } catch { }
                Marshal.ReleaseComObject(arc);
                fs.Dispose();
                return encryptedHeader ? SevenZipArchive.EncryptedHeader() : null;
            }

            return new SevenZipArchive(arc, fs, openCb.PasswordRequested);
        }
        catch (Exception ex)
        {
            if (Debug) Console.Error.WriteLine($"[7z]   exception: {ex.GetType().Name}: {ex.Message}");
            fs?.Dispose();
            return null;
        }
    }
}

internal sealed class SevenZipArchive : IDisposable
{
    private readonly IInArchive _archive;
    private readonly FileStream _file;
    private bool _disposed;

    public bool Encrypted { get; }

    internal SevenZipArchive(IInArchive archive, FileStream file, bool encrypted)
    {
        _archive = archive;
        _file = file;
        Encrypted = encrypted;
    }

    private SevenZipArchive() { _archive = null!; _file = null!; Encrypted = true; HeaderEncrypted = true; }

    internal static SevenZipArchive EncryptedHeader() => new();

    public bool HeaderEncrypted { get; private init; }

    public sealed record Entry(uint Index, string Path, ulong Size, bool IsDirectory, bool Encrypted);

    public List<Entry> List()
    {
        var list = new List<Entry>();
        if (HeaderEncrypted || _archive == null) return list;
        if (_archive.GetNumberOfItems(out uint count) != 0) return list;

        using var prop = new PropVariantBuffer();
        for (uint i = 0; i < count; i++)
        {
            string? name;
            ulong size;
            bool isDir, enc;

            prop.Reset();
            _archive.GetProperty(i, ItemPropId.Path, prop.Ptr);
            name = prop.AsString();
            prop.ClearValue();
            if (string.IsNullOrEmpty(name))
            {
                name = Path.GetFileNameWithoutExtension(_file.Name);
                if (string.IsNullOrEmpty(name)) name = "data";
            }

            prop.Reset();
            _archive.GetProperty(i, ItemPropId.Size, prop.Ptr);
            size = prop.AsUInt64();
            prop.ClearValue();

            prop.Reset();
            _archive.GetProperty(i, ItemPropId.IsFolder, prop.Ptr);
            isDir = prop.AsBoolean();
            prop.ClearValue();

            prop.Reset();
            _archive.GetProperty(i, ItemPropId.Encrypted, prop.Ptr);
            enc = prop.AsBoolean();
            prop.ClearValue();

            list.Add(new Entry(i, name!, size, isDir, enc));
        }
        return list;
    }

    public bool ExtractTo(uint index, string destPath)
    {
        if (HeaderEncrypted || _archive == null) return false;
        ExtractCallback? cb = null;
        try
        {
            cb = new ExtractCallback(index, destPath);
            int hr = _archive.Extract(new[] { index }, 1, 0, cb);
            cb.CloseOutput();
            return hr == 0 && cb.Succeeded;
        }
        catch { return false; }
        finally { cb?.CloseOutput(); }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        if (_archive == null) return;
        try { _archive.Close(); } catch { }
        try { Marshal.ReleaseComObject(_archive); } catch { }
        try { _file.Dispose(); } catch { }
    }
}

internal sealed class InStreamWrapper : IInStream
{
    private readonly Stream _stream;
    public InStreamWrapper(Stream stream) => _stream = stream;

    private byte[] _buf = new byte[64 * 1024];

    public int Read(IntPtr data, uint size, IntPtr processedSize)
    {
        try
        {
            int want = (int)Math.Min(size, int.MaxValue);
            if (want > _buf.Length) _buf = new byte[want];
            int read = _stream.Read(_buf, 0, want);
            if (read > 0) Marshal.Copy(_buf, 0, data, read);
            if (processedSize != IntPtr.Zero) Marshal.WriteInt32(processedSize, read);
            return 0;
        }
        catch { return unchecked((int)0x80004005); }
    }

    public int Seek(long offset, uint seekOrigin, IntPtr newPosition)
    {
        try
        {
            long pos = _stream.Seek(offset, (SeekOrigin)seekOrigin);
            if (newPosition != IntPtr.Zero) Marshal.WriteInt64(newPosition, pos);
            return 0;
        }
        catch { return unchecked((int)0x80004005); }
    }
}

internal sealed class ArchiveOpenCallback : IArchiveOpenCallback, ICryptoGetTextPassword
{
    public bool PasswordRequested { get; private set; }

    public int SetTotal(IntPtr files, IntPtr bytes) => 0;
    public int SetCompleted(IntPtr files, IntPtr bytes) => 0;

    public int CryptoGetTextPassword(out string password)
    {
        PasswordRequested = true;
        password = "";
        return 0;
    }
}

internal sealed class ExtractCallback : IArchiveExtractCallback, ICryptoGetTextPassword
{
    private readonly uint _wantedIndex;
    private readonly string _destPath;
    private FileStream? _out;

    public bool Succeeded { get; private set; }
    public bool PasswordRequested { get; private set; }

    public ExtractCallback(uint index, string destPath)
    {
        _wantedIndex = index;
        _destPath = destPath;
    }

    public int SetTotal(ulong total) => 0;
    public int SetCompleted(ref ulong completeValue) => 0;

    public int GetStream(uint index, out ISequentialOutStream? outStream, uint askExtractMode)
    {
        outStream = null;

        if (index != _wantedIndex || askExtractMode != 0) return 0;
        try
        {
            var dir = Path.GetDirectoryName(_destPath);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            _out = new FileStream(_destPath, FileMode.Create, FileAccess.Write, FileShare.None);
            outStream = new OutStreamWrapper(_out);
            return 0;
        }
        catch { return unchecked((int)0x80004005); }
    }

    public int PrepareOperation(uint askExtractMode) => 0;

    public int SetOperationResult(uint result)
    {
        Succeeded = result == 0;
        CloseOutput();
        return 0;
    }

    public int CryptoGetTextPassword(out string password)
    {
        PasswordRequested = true;
        password = "";
        return 0;
    }

    public void CloseOutput()
    {
        try { _out?.Dispose(); } catch { }
        _out = null;
    }
}

internal sealed class OutStreamWrapper : ISequentialOutStream
{
    private readonly Stream _stream;
    public OutStreamWrapper(Stream stream) => _stream = stream;

    private byte[] _buf = new byte[64 * 1024];

    public int Write(IntPtr data, uint size, IntPtr processedSize)
    {
        try
        {
            int n = (int)Math.Min(size, int.MaxValue);
            if (n > _buf.Length) _buf = new byte[n];
            Marshal.Copy(data, _buf, 0, n);
            _stream.Write(_buf, 0, n);
            if (processedSize != IntPtr.Zero) Marshal.WriteInt32(processedSize, n);
            return 0;
        }
        catch { return unchecked((int)0x80004005); }
    }
}
