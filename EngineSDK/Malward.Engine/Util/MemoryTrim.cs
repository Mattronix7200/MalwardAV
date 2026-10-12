using System.Diagnostics;
using System.Runtime;
using System.Runtime.InteropServices;

namespace Malward.Engine.Util;

public static class MemoryTrim
{
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetProcessWorkingSetSize(IntPtr process, IntPtr min, IntPtr max);

    public static long AfterLongRun()
    {
        try
        {
            var proc = Process.GetCurrentProcess();
            proc.Refresh();
            long przed = proc.WorkingSet64;

            GCSettings.LargeObjectHeapCompactionMode = GCLargeObjectHeapCompactionMode.CompactOnce;
            GC.Collect(2, GCCollectionMode.Forced, blocking: true, compacting: true);
            GC.WaitForPendingFinalizers();
            GC.Collect(2, GCCollectionMode.Forced, blocking: true, compacting: true);

            SetProcessWorkingSetSize(proc.Handle, (IntPtr)(-1), (IntPtr)(-1));

            proc.Refresh();
            return przed - proc.WorkingSet64;
        }
        catch
        {
            return 0;
        }
    }
}
