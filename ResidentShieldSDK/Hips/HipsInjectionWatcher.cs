using System.Runtime.InteropServices;

namespace Malward.ResidentShield.Hips;

public sealed class HipsInjectionWatcher : IDisposable
{
    private const string RuleId = "proc.lsass_access";

    private readonly HipsConfig _hips;
    private readonly ActivityReporter _activity;
    private readonly Notifier _notify;
    private CancellationTokenSource? _cts;
    private Task? _loop;

    private readonly HashSet<int> _reported = new();

    public static IEnumerable<string> Detectors => new[] { "Injection:lsass" };

    public HipsInjectionWatcher(HipsConfig hips, ActivityReporter activity, Notifier notify)
    { _hips = hips; _activity = activity; _notify = notify; }

    public void Start()
    {
        _cts = new CancellationTokenSource();
        var ct = _cts.Token;
        _loop = Task.Run(async () =>
        {
            while (!ct.IsCancellationRequested)
            {
                try { Scan(); }
                catch (Exception ex) { Log.Debug("HIPS-Wstrzyk", ex.Message); }
                try { await Task.Delay(TimeSpan.FromSeconds(15), ct); } catch { break; }
            }
        }, ct);
        Log.Info("HIPS", "Credential process access monitoring started.");
    }

    public void Scan()
    {
        var (on, mode) = _hips.StateOf(RuleId);
        if (!_hips.EnabledNow || !on) return;

        int lsass = LsassPid();
        if (lsass <= 0) return;

        var handles = SystemHandles();
        if (handles.Count == 0) return;

        var candidates = new Dictionary<int, string>();
        foreach (var h in handles)
        {
            int pid = h.ProcessId;
            if (pid <= 4 || pid == Environment.ProcessId) continue;
            if (candidates.ContainsKey(pid)) continue;
            if (_reported.Contains(pid)) continue;

            var img = NativeProcess.GetImagePath(pid);
            if (string.IsNullOrEmpty(img)) continue;
            if (SystemGuard.IsOwnComponent(img)) continue;

            if (HipsTrust.IsTrustedProgram(img) && !HipsTrust.InUserWritableArea(img)) continue;
            if (_hips.IsExcepted(RuleId, img)) continue;

            candidates[pid] = img;
        }
        if (candidates.Count == 0) return;

        foreach (var h in handles)
        {
            if (!candidates.TryGetValue(h.ProcessId, out var img)) continue;
            if ((h.GrantedAccess & PROCESS_VM_READ) == 0) continue;
            if (!PointsAt(h, lsass)) continue;

            _reported.Add(h.ProcessId);
            Report(h.ProcessId, img, h.GrantedAccess, mode);
            break;
        }
    }

    public static bool ProcessHoldsHandleTo(int holderPid, int targetPid, int requiredAccess)
    {
        foreach (var h in SystemHandles())
        {
            if (h.ProcessId != holderPid) continue;
            if ((h.GrantedAccess & requiredAccess) != requiredAccess) continue;
            if (PointsAt(h, targetPid)) return true;
        }
        return false;
    }

    public static int ReadMemoryAccess => PROCESS_VM_READ;

    private void Report(int pid, string image, int access, HipsRules.Mode mode)
    {
        var rule = HipsRules.ById(RuleId);
        if (rule == null) return;

        string detail = $"Proces {Path.GetFileName(image)} (PID {pid}) trzyma uchwyt do lsass.exe " +
                        $"z prawem odczytu pamięci (0x{access:X}) — typowe dla wykradania poświadczeń. " +
                        $"Program: {image}";
        string action = mode == HipsRules.Mode.Block ? "block" : mode == HipsRules.Mode.Log ? "log" : "ask";
        _activity.ReportHips(RuleId, rule.Name, Path.GetFileName(image), image, detail, action);

        if (mode == HipsRules.Mode.Block)
        {
            bool killed = false;
            try { killed = NativeProcess.Terminate(pid); } catch { }
            Log.Alert("HIPS", $"[{rule.Name}] {detail} — {(killed ? "process terminated" : "FAILED to terminate the process")}");
            _notify.Threat(killed ? "Terminated a process reaching for credentials"
                                  : "Failed to terminate a process reaching for credentials",
                           image, rule.Name, AlertSeverity.High);
        }
        else if (mode == HipsRules.Mode.Ask)
        {
            Log.Alert("HIPS", $"[{rule.Name}] {detail} — reported (mode: ask, no automatic reaction)");
            _notify.Threat("Credential process access detected", image, rule.Name, AlertSeverity.High);
        }
        else Log.Info("HIPS", detail);
    }

    private static bool PointsAt(HandleEntry h, int targetPid)
    {
        IntPtr holder = IntPtr.Zero, dup = IntPtr.Zero;
        try
        {
            holder = OpenProcess(PROCESS_DUP_HANDLE, false, h.ProcessId);
            if (holder == IntPtr.Zero) return false;
            if (!DuplicateHandle(holder, (IntPtr)h.Handle, GetCurrentProcess(), out dup,
                                 0, false, DUPLICATE_SAME_ACCESS))
                return false;
            return GetProcessId(dup) == targetPid;
        }
        catch { return false; }
        finally
        {
            if (dup != IntPtr.Zero) CloseHandle(dup);
            if (holder != IntPtr.Zero) CloseHandle(holder);
        }
    }

    private static int LsassPid()
    {
        try
        {
            foreach (var (pid, _, name) in NativeProcess.Snapshot())
                if (string.Equals(name, "lsass.exe", StringComparison.OrdinalIgnoreCase))
                    return pid;
        }
        catch { }
        return 0;
    }

    private readonly record struct HandleEntry(int ProcessId, ushort Handle, int GrantedAccess, byte TypeIndex);

    private static List<HandleEntry> SystemHandles()
    {
        var list = new List<HandleEntry>();
        int size = 1 << 20;
        IntPtr buffer = IntPtr.Zero;
        try
        {
            for (int attempt = 0; attempt < 8; attempt++)
            {
                buffer = Marshal.AllocHGlobal(size);
                int status = NtQuerySystemInformation(SystemExtendedHandleInformation, buffer, size, out int needed);
                if (status == STATUS_INFO_LENGTH_MISMATCH)
                {
                    Marshal.FreeHGlobal(buffer);
                    buffer = IntPtr.Zero;

                    size = Math.Max(needed, size * 2);
                    continue;
                }
                if (status != 0) return list;

                long count = Marshal.ReadIntPtr(buffer).ToInt64();
                int entrySize = Marshal.SizeOf<SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX>();
                long offset = IntPtr.Size * 2;
                for (long i = 0; i < count; i++)
                {
                    var e = Marshal.PtrToStructure<SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX>(buffer + (int)(offset + i * entrySize));
                    list.Add(new HandleEntry((int)e.UniqueProcessId.ToInt64(), (ushort)e.HandleValue.ToInt64(),
                                             e.GrantedAccess, (byte)e.ObjectTypeIndex));
                }
                return list;
            }
        }
        catch { }
        finally { if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer); }
        return list;
    }

    private const int SystemExtendedHandleInformation = 64;
    private const int STATUS_INFO_LENGTH_MISMATCH = unchecked((int)0xC0000004);
    private const int PROCESS_DUP_HANDLE = 0x0040;
    private const int PROCESS_VM_READ = 0x0010;
    private const int DUPLICATE_SAME_ACCESS = 0x0002;

    [StructLayout(LayoutKind.Sequential)]
    private struct SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
    {
        public IntPtr Object;
        public IntPtr UniqueProcessId;
        public IntPtr HandleValue;
        public int    GrantedAccess;
        public ushort CreatorBackTraceIndex;
        public ushort ObjectTypeIndex;
        public int    HandleAttributes;
        public int    Reserved;
    }

    [DllImport("ntdll.dll")]
    private static extern int NtQuerySystemInformation(int infoClass, IntPtr buffer, int length, out int returnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(int access, bool inherit, int pid);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DuplicateHandle(IntPtr sourceProcess, IntPtr sourceHandle, IntPtr targetProcess,
                                               out IntPtr targetHandle, int access, bool inherit, int options);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern int GetProcessId(IntPtr handle);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);

    public void Dispose()
    {
        try { _cts?.Cancel(); } catch { }
        try { _loop?.Wait(2000); } catch { }
        _cts?.Dispose();
    }
}
