using System.Runtime.InteropServices;

namespace Malward.ResidentShield;

public static class SelfDefense
{
    private const int  DACL_SECURITY_INFORMATION = 0x00000004;
    private const uint SDDL_REVISION_1           = 1;

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(
        string StringSecurityDescriptor, uint StringSDRevision,
        out IntPtr SecurityDescriptor, out int SecurityDescriptorSize);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool SetKernelObjectSecurity(IntPtr Handle, int SecurityInformation, IntPtr SecurityDescriptor);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr hMem);

    public static bool HardenCurrentProcess()
    {
        IntPtr pSd = IntPtr.Zero;
        try
        {
            const string sddl = "D:(D;;0x1;;;WD)(A;;0x1FFFFF;;;SY)(A;;0x1FFFFF;;;BA)";
            if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, out pSd, out _))
                return false;
            return SetKernelObjectSecurity(GetCurrentProcess(), DACL_SECURITY_INFORMATION, pSd);
        }
        catch { return false; }
        finally { if (pSd != IntPtr.Zero) LocalFree(pSd); }
    }
}
