using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Malward.Engine.Util;

public static class LaunchGuard
{
    private static readonly HashSet<string> InteractiveParents = new(StringComparer.OrdinalIgnoreCase)
    {
        "cmd", "powershell", "pwsh", "powershell_ise", "windowsterminal", "wt", "openconsole",
        "explorer", "bash", "sh", "wsl", "mintty", "conemu", "conemu64", "conemuc", "conemuc64",
        "cmder", "far", "totalcmd", "totalcmd64", "doublecmd", "hyper", "alacritty", "wezterm-gui",
        "tabby", "fluent terminal", "nu", "python", "pythonw", "py",
    };

    public static bool StartedFromShell(out string parentName)
    {
        parentName = "";
        try
        {
            int parent = ParentPid(Environment.ProcessId);
            if (parent <= 0) return false;
            using var p = Process.GetProcessById(parent);
            parentName = p.ProcessName;
            return InteractiveParents.Contains(parentName);
        }
        catch { return false; }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessBasicInformation
    {
        public IntPtr ExitStatus;
        public IntPtr PebBaseAddress;
        public IntPtr AffinityMask;
        public IntPtr BasePriority;
        public IntPtr UniqueProcessId;
        public IntPtr InheritedFromUniqueProcessId;
    }

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(IntPtr process, int infoClass,
        ref ProcessBasicInformation info, int size, out int returned);

    private static int ParentPid(int pid)
    {
        using var p = Process.GetProcessById(pid);
        var info = new ProcessBasicInformation();
        int status = NtQueryInformationProcess(p.Handle, 0, ref info, Marshal.SizeOf(info), out _);
        return status == 0 ? info.InheritedFromUniqueProcessId.ToInt32() : 0;
    }
}
