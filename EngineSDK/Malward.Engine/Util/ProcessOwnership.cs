using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;
using System.Text;

namespace Malward.Engine.Util;

[SupportedOSPlatform("windows")]
public static class ProcessOwnership
{
    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    private const uint TOKEN_QUERY = 0x0008;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr h);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(IntPtr h, uint access, out IntPtr token);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetTokenInformation(IntPtr token, int infoClass,
                                                   IntPtr info, int len, out int retLen);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsProcessCritical(IntPtr h, [MarshalAs(UnmanagedType.Bool)] out bool critical);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageName(
        IntPtr hProcess, uint dwFlags,
        [MarshalAs(UnmanagedType.LPWStr)] StringBuilder lpExeName,
        ref int lpdwSize);

    private const int TokenUser = 1;

    public static string? CurrentUserSid { get; } = WindowsIdentity.GetCurrent().User?.Value;

    public static string? GetOwnerSid(int pid)
    {
        var ph = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (ph == IntPtr.Zero) return null;
        try
        {
            if (!OpenProcessToken(ph, TOKEN_QUERY, out var tok)) return null;
            try
            {
                GetTokenInformation(tok, TokenUser, IntPtr.Zero, 0, out int needed);
                if (needed == 0) return null;
                var buf = Marshal.AllocHGlobal(needed);
                try
                {
                    if (!GetTokenInformation(tok, TokenUser, buf, needed, out _)) return null;

                    var pSid = Marshal.ReadIntPtr(buf);
                    var sid = new SecurityIdentifier(pSid);
                    return sid.Value;
                }
                finally { Marshal.FreeHGlobal(buf); }
            }
            finally { CloseHandle(tok); }
        }
        finally { CloseHandle(ph); }
    }

    public static bool IsCritical(int pid)
    {
        var ph = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (ph == IntPtr.Zero) return true;
        try
        {
            return IsProcessCritical(ph, out var c) && c;
        }
        finally { CloseHandle(ph); }
    }

    public static bool IsCurrentUserNonCritical(Process p)
    {
        try
        {
            int pid = p.Id;
            if (IsCritical(pid)) return false;
            var sid = GetOwnerSid(pid);
            if (sid == null) return false;
            if (sid != CurrentUserSid) return false;
            return true;
        }
        catch { return false; }
    }

    public static bool IsLocalSystem { get; } = ComputeIsLocalSystem();

    private static bool ComputeIsLocalSystem()
    {
        try
        {
            var sid = WindowsIdentity.GetCurrent().User;
            return sid != null && sid.IsWellKnown(WellKnownSidType.LocalSystemSid);
        }
        catch { return false; }
    }

    public static bool IsScannableProcess(Process p)
    {
        try
        {
            int pid = p.Id;
            if (IsCritical(pid)) return false;
            if (IsLocalSystem) return true;
            var sid = GetOwnerSid(pid);
            return sid != null && sid == CurrentUserSid;
        }
        catch { return false; }
    }

    public static string? TryGetImagePath(Process p)
    {
        try
        {
            var m = p.MainModule?.FileName;
            if (!string.IsNullOrEmpty(m)) return m;
        }
        catch {  }

        try
        {
            var ph = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, p.Id);
            if (ph == IntPtr.Zero) return null;
            try
            {
                var sb = new StringBuilder(4096);
                int size = sb.Capacity;
                return QueryFullProcessImageName(ph, 0, sb, ref size)
                    ? sb.ToString(0, size)
                    : null;
            }
            finally { CloseHandle(ph); }
        }
        catch { return null; }
    }

    public static bool IsSystemPath(string? path)
    {
        if (string.IsNullOrEmpty(path)) return true;
        var p = Path.GetFullPath(path);
        var win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        if (p.StartsWith(win + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            return true;
        var pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        if (!string.IsNullOrEmpty(pf) &&
            p.StartsWith(Path.Combine(pf, "Windows"), StringComparison.OrdinalIgnoreCase))
            return true;
        return false;
    }
}
