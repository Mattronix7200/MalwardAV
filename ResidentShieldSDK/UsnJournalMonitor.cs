using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Malward.ResidentShield;

public sealed class UsnJournalMonitor : IDisposable
{
    private readonly ShieldConfig      _config;
    private readonly Action<ScanEvent> _callback;
    private readonly UsnState          _state;

    private readonly List<Thread> _threads = new();
    private volatile bool _running = false;
    private HashSet<string> _watchedSet = new(StringComparer.OrdinalIgnoreCase);

    public UsnJournalMonitor(ShieldConfig config, Action<ScanEvent> callback)
    {
        _config   = config;
        _callback = callback;
        _state    = UsnState.Load();
    }

    public static HashSet<string> NtfsFixedVolumes()
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var d in DriveInfo.GetDrives())
        {
            try
            {
                if (d.DriveType == DriveType.Fixed && d.IsReady &&
                    string.Equals(d.DriveFormat, "NTFS", StringComparison.OrdinalIgnoreCase))
                    set.Add(d.Name.TrimEnd('\\'));
            }
            catch { }
        }
        return set;
    }

    public void Start()
    {
        _running = true;
        _watchedSet = new HashSet<string>(_config.WatchedExtensions, StringComparer.OrdinalIgnoreCase);

        foreach (var vol in NtfsFixedVolumes())
        {
            var t = new Thread(() => VolumeLoop(vol))
            {
                Name = $"USN-{vol}", IsBackground = true, Priority = ThreadPriority.BelowNormal,
            };
            _threads.Add(t);
            t.Start();
        }

        Log.Info("USN", $"NTFS journal monitor active for: {string.Join(", ", NtfsFixedVolumes())}");
    }

    public void Stop()
    {
        _running = false;
        _state.Save();
    }

    private void VolumeLoop(string volume)
    {
        SafeFileHandle? hVol = null;
        try
        {
            hVol = OpenVolume(volume);
            if (hVol.IsInvalid)
            {
                Log.Warn("USN", $"Cannot open volume {volume} — skipping (FSW will take over).");
                return;
            }

            if (!QueryJournal(hVol, out USN_JOURNAL_DATA jd))
            {
                if (!CreateJournal(hVol) || !QueryJournal(hVol, out jd))
                {
                    Log.Warn("USN", $"No USN journal on {volume} — FSW will take over.");
                    return;
                }
            }

            ulong nextUsn = _state.ResolveStart(volume, jd.UsnJournalID, jd.NextUsn);
            Log.Info("USN", $"{volume}: starting from USN {nextUsn} (JournalId={jd.UsnJournalID})");

            var buffer = new byte[64 * 1024];
            var dirCache = new Dictionary<ulong, string>();

            while (_running)
            {
                int bytes = ReadJournal(hVol, jd.UsnJournalID, nextUsn, buffer);
                if (bytes <= 8)
                {
                    Thread.Sleep(100);
                    continue;
                }

                nextUsn = BitConverter.ToUInt64(buffer, 0);
                ParseRecords(volume, buffer, bytes, dirCache, hVol);

                _state.Update(volume, jd.UsnJournalID, nextUsn);
            }
        }
        catch (Exception ex)
        {
            Log.Error("USN", $"{volume}: loop error — {ex.Message}");
        }
        finally
        {
            hVol?.Dispose();
            _state.Save();
        }
    }

    private void ParseRecords(string volume, byte[] buf, int bytes,
        Dictionary<ulong, string> dirCache, SafeFileHandle hVol)
    {
        int offset = 8;
        while (offset < bytes)
        {
            int recLen = BitConverter.ToInt32(buf, offset);
            if (recLen <= 0 || offset + recLen > bytes) break;

            ulong fileRef   = BitConverter.ToUInt64(buf, offset + 8);
            ulong parentRef = BitConverter.ToUInt64(buf, offset + 16);
            uint  reason    = BitConverter.ToUInt32(buf, offset + 40);
            uint  attrs     = BitConverter.ToUInt32(buf, offset + 52);
            ushort nameLen  = BitConverter.ToUInt16(buf, offset + 56);
            ushort nameOff  = BitConverter.ToUInt16(buf, offset + 58);

            bool isDir = (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0;
            const uint INTERESTING =
                USN_REASON_FILE_CREATE | USN_REASON_DATA_OVERWRITE |
                USN_REASON_DATA_EXTEND | USN_REASON_RENAME_NEW_NAME;

            if (!isDir && (reason & USN_REASON_CLOSE) != 0 && (reason & INTERESTING) != 0)
            {
                string name = Encoding.Unicode.GetString(buf, offset + nameOff, nameLen);
                if (PassesExtension(name))
                {
                    string? dir = ResolveDir(volume, parentRef, dirCache, hVol);
                    if (dir != null)
                    {
                        string full = Path.Combine(dir, name);
                        if (!IsExcluded(full))
                        {
                            var kind = (reason & USN_REASON_FILE_CREATE) != 0
                                ? ScanEventKind.FileCreated : ScanEventKind.FileModified;
                            Emit(kind, full);
                        }
                    }
                }
            }

            offset += recLen;
        }
    }

    private void Emit(ScanEventKind kind, string path)
    {
        try { _callback(new ScanEvent(kind, path, null, null, DateTimeOffset.UtcNow)); }
        catch (Exception ex) { Log.Error("USN", $"callback: {ex.Message}"); }
    }

    private string? ResolveDir(string volume, ulong parentRef,
        Dictionary<ulong, string> cache, SafeFileHandle hVol)
    {
        if (cache.TryGetValue(parentRef, out var cached)) return cached;

        string? path = OpenByIdAndGetPath(volume, parentRef, hVol);
        if (path != null)
        {
            if (cache.Count > 8192) cache.Clear();
            cache[parentRef] = path;
        }
        return path;
    }

    private static string? OpenByIdAndGetPath(string volume, ulong fileId, SafeFileHandle hVol)
    {
        var descriptor = new FILE_ID_DESCRIPTOR
        {
            dwSize = (uint)Marshal.SizeOf<FILE_ID_DESCRIPTOR>(),
            Type   = 0,
            FileId = (long)fileId,
        };

        SafeFileHandle h = OpenFileById(hVol, ref descriptor,
            FILE_READ_ATTRIBUTES, FILE_SHARE_ALL, IntPtr.Zero,
            FILE_FLAG_BACKUP_SEMANTICS);

        if (h.IsInvalid) { h.Dispose(); return null; }
        try
        {
            var sb = new StringBuilder(1024);
            int len = GetFinalPathNameByHandle(h, sb, sb.Capacity, FILE_NAME_NORMALIZED);
            if (len == 0) return null;
            string p = sb.ToString();

            if (p.StartsWith(@"\\?\", StringComparison.Ordinal)) p = p[4..];
            return p;
        }
        finally { h.Dispose(); }
    }

    private bool PassesExtension(string name)
    {
        if (_config.ScanAllExtensions) return true;
        var ext = Path.GetExtension(name);
        return !string.IsNullOrEmpty(ext) && _watchedSet.Contains(ext);
    }

    private bool IsExcluded(string fullPath)
    {
        var excl = _config.ExcludedPaths;
        for (int i = 0; i < excl.Count; i++)
            if (fullPath.StartsWith(excl[i], StringComparison.OrdinalIgnoreCase))
                return true;
        return false;
    }

    private static SafeFileHandle OpenVolume(string volume)

        => CreateFile($@"\\.\{volume}", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_ALL,
            IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);

    private static bool QueryJournal(SafeFileHandle hVol, out USN_JOURNAL_DATA jd)
    {
        jd = default;
        int size = Marshal.SizeOf<USN_JOURNAL_DATA>();
        IntPtr outBuf = Marshal.AllocHGlobal(size);
        try
        {
            bool ok = DeviceIoControl(hVol, FSCTL_QUERY_USN_JOURNAL, IntPtr.Zero, 0,
                outBuf, (uint)size, out _, IntPtr.Zero);
            if (ok) jd = Marshal.PtrToStructure<USN_JOURNAL_DATA>(outBuf);
            return ok;
        }
        finally { Marshal.FreeHGlobal(outBuf); }
    }

    private static bool CreateJournal(SafeFileHandle hVol)
    {
        var cd = new CREATE_USN_JOURNAL_DATA
        {
            MaximumSize        = 32 * 1024 * 1024,
            AllocationDelta    = 4  * 1024 * 1024,
        };
        int size = Marshal.SizeOf<CREATE_USN_JOURNAL_DATA>();
        IntPtr inBuf = Marshal.AllocHGlobal(size);
        try
        {
            Marshal.StructureToPtr(cd, inBuf, false);
            return DeviceIoControl(hVol, FSCTL_CREATE_USN_JOURNAL, inBuf, (uint)size,
                IntPtr.Zero, 0, out _, IntPtr.Zero);
        }
        finally { Marshal.FreeHGlobal(inBuf); }
    }

    private static int ReadJournal(SafeFileHandle hVol, ulong journalId, ulong startUsn, byte[] buffer)
    {
        var rd = new READ_USN_JOURNAL_DATA
        {
            StartUsn          = startUsn,
            ReasonMask        = 0xFFFFFFFF,
            ReturnOnlyOnClose = 1,
            Timeout           = 0,
            BytesToWaitFor    = 0,
            UsnJournalID      = journalId,
        };

        int inSize = Marshal.SizeOf<READ_USN_JOURNAL_DATA>();
        IntPtr inBuf = Marshal.AllocHGlobal(inSize);
        GCHandle gch = GCHandle.Alloc(buffer, GCHandleType.Pinned);
        try
        {
            Marshal.StructureToPtr(rd, inBuf, false);
            bool ok = DeviceIoControl(hVol, FSCTL_READ_USN_JOURNAL, inBuf, (uint)inSize,
                gch.AddrOfPinnedObject(), (uint)buffer.Length, out uint returned, IntPtr.Zero);
            return ok ? (int)returned : 0;
        }
        finally
        {
            Marshal.FreeHGlobal(inBuf);
            gch.Free();
        }
    }

    public void Dispose()
    {
        Stop();
        foreach (var t in _threads)
            try { t.Join(TimeSpan.FromMilliseconds(800)); } catch { }
        _threads.Clear();
    }

    private const uint GENERIC_READ            = 0x80000000;
    private const uint GENERIC_WRITE           = 0x40000000;
    private const uint FILE_SHARE_ALL          = 0x1 | 0x2 | 0x4;
    private const uint OPEN_EXISTING           = 3;
    private const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
    private const uint FILE_READ_ATTRIBUTES    = 0x0080;
    private const uint FILE_NAME_NORMALIZED    = 0x0;

    private const uint FILE_ATTRIBUTE_DIRECTORY = 0x10;

    private const uint USN_REASON_DATA_OVERWRITE  = 0x00000001;
    private const uint USN_REASON_DATA_EXTEND     = 0x00000002;
    private const uint USN_REASON_FILE_CREATE     = 0x00000100;
    private const uint USN_REASON_RENAME_NEW_NAME = 0x00002000;
    private const uint USN_REASON_CLOSE           = 0x80000000;

    private const uint FSCTL_QUERY_USN_JOURNAL  = 0x000900f4;
    private const uint FSCTL_READ_USN_JOURNAL   = 0x000900bb;
    private const uint FSCTL_CREATE_USN_JOURNAL = 0x000900e7;

    [StructLayout(LayoutKind.Sequential)]
    private struct USN_JOURNAL_DATA
    {
        public ulong UsnJournalID;
        public long  FirstUsn;
        public long  NextUsn;
        public long  LowestValidUsn;
        public long  MaxUsn;
        public ulong MaximumSize;
        public ulong AllocationDelta;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct CREATE_USN_JOURNAL_DATA
    {
        public ulong MaximumSize;
        public ulong AllocationDelta;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct READ_USN_JOURNAL_DATA
    {
        public ulong StartUsn;
        public uint  ReasonMask;
        public uint  ReturnOnlyOnClose;
        public ulong Timeout;
        public ulong BytesToWaitFor;
        public ulong UsnJournalID;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FILE_ID_DESCRIPTOR
    {
        public uint dwSize;
        public uint Type;
        public long FileId;
        private long _pad;
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern SafeFileHandle CreateFile(string name, uint access, uint share,
        IntPtr sec, uint disposition, uint flags, IntPtr template);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DeviceIoControl(SafeFileHandle h, uint code,
        IntPtr inBuf, uint inSize, IntPtr outBuf, uint outSize, out uint returned, IntPtr overlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern SafeFileHandle OpenFileById(SafeFileHandle hVol,
        ref FILE_ID_DESCRIPTOR desc, uint access, uint share, IntPtr sec, uint flags);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern int GetFinalPathNameByHandle(SafeFileHandle h,
        StringBuilder path, int size, uint flags);
}
