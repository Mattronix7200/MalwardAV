using System.Runtime.InteropServices;

namespace Malward.Engine.Core;

internal static class OfflineHive
{
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int RegLoadKey(IntPtr hKey, string lpSubKey, string lpFile);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int RegUnLoadKey(IntPtr hKey, string lpSubKey);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr h, uint access, out IntPtr token);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool LookupPrivilegeValue(string? host, string name, out long luid);

    [StructLayout(LayoutKind.Sequential)]
    private struct TOKEN_PRIVILEGES
    {
        public int Count;
        public long Luid;
        public int Attributes;
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool AdjustTokenPrivileges(IntPtr token, bool disableAll,
        ref TOKEN_PRIVILEGES newState, int len, IntPtr prev, IntPtr retLen);

    private static readonly IntPtr HKEY_USERS = new(unchecked((int)0x80000003));
    private const int SE_PRIVILEGE_ENABLED = 0x0002;
    private const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
    private const uint TOKEN_QUERY = 0x0008;

    private static bool _privilegesTried;

    private static void EnsurePrivileges()
    {
        if (_privilegesTried) return;
        _privilegesTried = true;
        try
        {
            if (!OpenProcessToken(System.Diagnostics.Process.GetCurrentProcess().Handle,
                                  TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out var token)) return;
            try
            {
                foreach (var nazwa in new[] { "SeRestorePrivilege", "SeBackupPrivilege" })
                {
                    if (!LookupPrivilegeValue(null, nazwa, out long luid)) continue;
                    var tp = new TOKEN_PRIVILEGES { Count = 1, Luid = luid, Attributes = SE_PRIVILEGE_ENABLED };
                    AdjustTokenPrivileges(token, false, ref tp, Marshal.SizeOf<TOKEN_PRIVILEGES>(),
                                          IntPtr.Zero, IntPtr.Zero);
                }
            }
            finally { try { Marshal.FreeHGlobal(IntPtr.Zero); } catch { } }
        }
        catch { }
    }

    public static bool TryLoad(string mountName, string hiveFile)
    {
        try
        {
            EnsurePrivileges();

            return RegLoadKey(HKEY_USERS, mountName, hiveFile) == 0;
        }
        catch { return false; }
    }

    public static void TryUnload(string mountName)
    {
        try
        {
            GC.Collect();
            GC.WaitForPendingFinalizers();
            RegUnLoadKey(HKEY_USERS, mountName);
        }
        catch { }
    }
}
