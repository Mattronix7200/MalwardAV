using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;

namespace Malward.ResidentShield;

public sealed class RemovableScanWatcher : IDisposable
{
    private readonly string _malscanPath;
    private readonly HashSet<string> _seen = new(StringComparer.OrdinalIgnoreCase);
    private Timer? _timer;
    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(4);

    public RemovableScanWatcher(string malscanPath) => _malscanPath = malscanPath;

    public void Start()
    {
        foreach (var d in EnumerateRemovableReady()) _seen.Add(d);
        _timer = new Timer(_ => Tick(), null, PollInterval, PollInterval);
        Log.Info("Removable", $"Watcher starting (baseline: {_seen.Count} volumes).");
    }

    public void Stop()
    {
        try { _timer?.Dispose(); } catch { }
        _timer = null;
    }

    private void Tick()
    {
        try
        {
            var current = EnumerateRemovableReady();
            foreach (var root in current)
            {
                if (_seen.Add(root))
                {
                    _ = Task.Run(() => RunMalscan(root));
                }
            }

            foreach (var gone in _seen.Where(x => !current.Contains(x)).ToList())
            {
                lock (UsbCache) UsbCache.Remove(gone.TrimEnd('\\'));
                _seen.Remove(gone);
            }
        }
        catch (Exception ex) { Log.Warn("Removable", $"tick error: {ex.Message}"); }
    }

    private static HashSet<string> EnumerateRemovableReady()
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            foreach (var d in DriveInfo.GetDrives())
            {
                try
                {
                    if (!IsRemovableMedium(d)) continue;
                    if (!d.IsReady) continue;
                    set.Add(d.RootDirectory.FullName);
                }
                catch { }
            }
        }
        catch { }
        return set;
    }

    private static bool IsRemovableMedium(DriveInfo d)
    {
        if (d.DriveType is DriveType.Removable or DriveType.CDRom) return true;

        return d.DriveType == DriveType.Fixed && IsUsbAttached(d.Name);
    }

    private const uint GENERIC_NONE = 0;
    private const uint FILE_SHARE_READ_WRITE = 0x00000003;
    private const uint OPEN_EXISTING = 3;
    private const uint IOCTL_STORAGE_QUERY_PROPERTY = 0x002D1400;
    private const int BusTypeUsb = 0x07;

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateFileW(string name, uint access, uint share, IntPtr sec,
                                             uint disposition, uint flags, IntPtr template);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DeviceIoControl(IntPtr device, uint code,
                                               byte[] inBuffer, int inSize,
                                               byte[] outBuffer, int outSize,
                                               out int returned, IntPtr overlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);

    private static readonly Dictionary<string, bool> UsbCache = new(StringComparer.OrdinalIgnoreCase);

    private static bool IsUsbAttached(string root)
    {
        var letter = root.TrimEnd('\\');
        if (letter.Length != 2 || letter[1] != ':') return false;

        lock (UsbCache)
        {
            if (UsbCache.TryGetValue(letter, out var cached)) return cached;
        }

        bool usb = QueryBusType(letter) == BusTypeUsb;
        lock (UsbCache)
        {
            if (UsbCache.Count > 64) UsbCache.Clear();
            UsbCache[letter] = usb;
        }
        return usb;
    }

    private static int QueryBusType(string letter)
    {
        IntPtr handle = IntPtr.Zero;
        try
        {
            handle = CreateFileW(@"\\.\" + letter, GENERIC_NONE, FILE_SHARE_READ_WRITE,
                                 IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
            if (handle == IntPtr.Zero || handle == new IntPtr(-1)) return -1;

            var query = new byte[12];
            var descriptor = new byte[512];
            if (!DeviceIoControl(handle, IOCTL_STORAGE_QUERY_PROPERTY,
                                 query, query.Length, descriptor, descriptor.Length,
                                 out int returned, IntPtr.Zero) || returned < 32)
                return -1;

            return BitConverter.ToInt32(descriptor, 28);
        }
        catch { return -1; }
        finally { if (handle != IntPtr.Zero && handle != new IntPtr(-1)) CloseHandle(handle); }
    }

    private static readonly string EventsFile = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "Malward", "data", "shield-events.jsonl");

    private static readonly string CancelFile = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "Malward", "data", "removable-cancel");

    private static bool CancelRequested(string root)
    {
        try
        {
            if (!File.Exists(CancelFile)) return false;
            var want = root.TrimEnd('\\');
            foreach (var line in File.ReadAllLines(CancelFile))
                if (line.Trim().TrimEnd('\\').Equals(want, StringComparison.OrdinalIgnoreCase))
                    return true;
        }
        catch { }
        return false;
    }

    private static void ClearCancel(string root)
    {
        try
        {
            if (!File.Exists(CancelFile)) return;
            var want = root.TrimEnd('\\');
            var keep = File.ReadAllLines(CancelFile)
                .Where(l => !l.Trim().TrimEnd('\\').Equals(want, StringComparison.OrdinalIgnoreCase))
                .ToArray();
            if (keep.Length == 0) File.Delete(CancelFile);
            else File.WriteAllLines(CancelFile, keep);
        }
        catch { }
    }

    private void RunMalscan(string root)
    {
        try
        {
            Log.Info("Removable", $"Scanning newly attached medium: {root}");
            ClearCancel(root);
            EmitEvent("removable.started", root, detection: null, threats: 0);

            int threats = 0;
            string? firstDetection = null;
            DateTime lastProgressEmit = DateTime.MinValue;

            var files = SafeEnumerate(root);
            int total = files.Count, done = 0;

            foreach (var file in files)
            {
                var detection = Malward.Engine.Core.SharedPipeline.ScanFile(file);
                done++;

                if (!string.IsNullOrEmpty(detection))
                {
                    threats++;
                    firstDetection ??= detection;
                    Log.Alert("Removable", $"DETECTION {detection}: {file}");
                }

                if ((DateTime.UtcNow - lastProgressEmit).TotalMilliseconds >= 250)
                {
                    lastProgressEmit = DateTime.UtcNow;
                    int pct = total > 0 ? (int)(100L * done / total) : 0;
                    EmitProgress(root, pct.ToString(), done.ToString(), total.ToString(), file);
                    if (CancelRequested(root))
                    {
                        Log.Info("Removable", $"Scan of {root} cancelled by the user after {done} file(s).");
                        break;
                    }
                }
            }

            ClearCancel(root);
            Log.Info("Removable", $"Scan of {root} finished (files: {done}, threats: {threats}).");
            EmitEvent("removable.finished", root, firstDetection, threats);
        }
        catch (Exception ex)
        {
            Log.Warn("Removable", $"malscan {root} failed: {ex.Message}");
            EmitEvent("removable.finished", root, null, 0);
        }
    }

    private static List<string> SafeEnumerate(string root)
    {
        try
        {
            return new List<string>(Directory.EnumerateFiles(root, "*", new EnumerationOptions
            {
                RecurseSubdirectories = true,
                IgnoreInaccessible = true,
                AttributesToSkip = FileAttributes.ReparsePoint,
            }));
        }
        catch (Exception ex)
        {
            Log.Warn("Removable", $"Failed to enumerate {root}: {ex.Message}");
            return new List<string>();
        }
    }

    private static string? ExtractField(string line, string key)
    {
        int idx = line.IndexOf(key, StringComparison.Ordinal);
        if (idx < 0) return null;
        int start = idx + key.Length;
        int end = line.IndexOf('\t', start);
        return end < 0 ? line[start..] : line[start..end];
    }

    private static void EmitEvent(string type, string root, string? detection, int threats)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(EventsFile)!);
            var json = JsonSerializer.Serialize(new
            {
                ts = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                type, root, detection, threats,
            });
            File.AppendAllText(EventsFile, json + Environment.NewLine);
        }
        catch { }
    }

    private static void EmitProgress(string root, string? pct, string? done, string? total, string? file)
    {
        try
        {
            int.TryParse(pct?.Replace(',', '.').Split('.')[0], out int pctI);
            int.TryParse(done, out int doneI);
            int.TryParse(total, out int totalI);
            Directory.CreateDirectory(Path.GetDirectoryName(EventsFile)!);
            var json = JsonSerializer.Serialize(new
            {
                ts = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                type = "removable.progress",
                root, pct = pctI, done = doneI, total = totalI, file = file ?? "",
            });
            File.AppendAllText(EventsFile, json + Environment.NewLine);
        }
        catch { }
    }

    public void Dispose() => Stop();
}
