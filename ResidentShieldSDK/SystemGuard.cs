using System.Runtime.InteropServices;

namespace Malward.ResidentShield;

public static class SystemGuard
{
    private static readonly string WinDir =
        Environment.GetFolderPath(Environment.SpecialFolder.Windows).TrimEnd('\\');          
    private static readonly string ProgFiles =
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles).TrimEnd('\\');
    private static readonly string ProgFilesX86 =
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86).TrimEnd('\\');
    private static readonly string CommonAppData =
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData).TrimEnd('\\');

    private static readonly string DefenderDataDir =
        Path.Combine(CommonAppData, "Microsoft", "Windows Defender").TrimEnd('\\');

    private static readonly string[] ProtectedRoots =
    {
        WinDir + "\\",
        ProgFiles + "\\",
        ProgFilesX86 + "\\",
        DefenderDataDir + "\\",
    };

    private static readonly HashSet<string> OwnBinaries = new(StringComparer.OrdinalIgnoreCase)
    {
        "malward.exe", "malscan.exe", "heurscanner.exe", "mwshield.exe",
        "residentshield.exe", "shieldhook.dll", "netmonitor.exe",
        "7z.exe", "7za.exe", "7z.dll",
    };

    private static readonly string MalwardDataDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Malward");

    private static readonly string MalwardInstallDir =
        (Path.GetDirectoryName(Environment.ProcessPath ?? AppContext.BaseDirectory) ?? "")
        .TrimEnd('\\') + "\\";

    public static readonly string QuarantineDir = Path.Combine(MalwardDataDir, "quarantine");

    public static bool IsInQuarantine(string? path) => Under(path, QuarantineDir);

    private static bool Under(string? path, string dir)
    {
        if (string.IsNullOrEmpty(path) || string.IsNullOrEmpty(dir)) return false;
        var d = dir.TrimEnd('\\');
        if (d.Length == 0) return false;
        if (path!.Length == d.Length) return string.Equals(path, d, StringComparison.OrdinalIgnoreCase);
        return path.StartsWith(d + "\\", StringComparison.OrdinalIgnoreCase);
    }

    private static readonly HashSet<string> CriticalProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "system", "system idle process", "registry", "memory compression",
        "smss", "csrss", "wininit", "winlogon", "services", "lsass", "lsaiso",
        "svchost", "fontdrvhost", "dwm", "spoolsv", "wudfhost", "sihost",
        "ctfmon", "taskhostw", "runtimebroker", "wininit",

        "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe",
        "lsass.exe", "lsaiso.exe", "svchost.exe", "fontdrvhost.exe", "dwm.exe",
    };

    public static bool IsProtectedPath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return true;
        if (!path.Contains('\\')) return true;                 
        foreach (var root in ProtectedRoots)
            if (path.StartsWith(root, StringComparison.OrdinalIgnoreCase))
                return true;
        return false;
    }

    public static bool IsTrustedImage(string? imagePath) => IsProtectedPath(imagePath);

    public static bool IsOwnComponent(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;
        try
        {
            if (Under(path, MalwardDataDir)) return true;

            if (MalwardInstallDir.Length > 1 && Under(path, MalwardInstallDir)) return true;
            var name = Path.GetFileName(path);
            return !string.IsNullOrEmpty(name) && OwnBinaries.Contains(name);
        }
        catch { return false; }
    }

    private static readonly Malward.Engine.Util.VulnerableDriverList _byodList =
        new(System.IO.Path.Combine(Malward.Engine.Util.Paths.DataDir, "vps-ex04.vdeb"));

    private static bool IsKnownVulnerableDriver(string path)
    {
        try
        {
            using var stream = File.OpenRead(path);
            using var sha = System.Security.Cryptography.SHA256.Create();
            var hash = Convert.ToHexString(sha.ComputeHash(stream)).ToLowerInvariant();
            return _byodList.Match(hash, null) != null;
        }
        catch { return false; }
    }

    public static bool IsUntouchableForRepair(string? path)
    {
        if (IsOwnComponent(path)) return true;
        if (!IsProtectedPath(path)) return false;
        if (!string.IsNullOrEmpty(path) && IsKnownVulnerableDriver(path!)) return false;
        try { return Malward.Engine.Util.SystemFileCheck.IsGenuineSystemFile(path!); }
        catch { return true; }
    }

    public static bool IsUntouchable(string? path)
        => IsProtectedPath(path) || IsOwnComponent(path);

    public static bool IsCriticalProcess(int pid, string name, string imagePath)
    {
        if (pid <= 4) return true;
        if (string.IsNullOrEmpty(name)) return false;

        if (CriticalProcesses.Contains(StripExe(name))) return true;

        return false;
    }

    public static IEnumerable<string> FilterActionable(IEnumerable<string> paths)
        => paths.Where(p => !IsUntouchable(p));

    private static string StripExe(string name)
        => name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? name[..^4] : name;

    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, (DateTime mt, bool ok)>
        _sigCache = new(StringComparer.OrdinalIgnoreCase);

    public static bool HasValidSignature(string? imagePath)
    {
        if (string.IsNullOrEmpty(imagePath)) return false;
        try
        {
            if (!File.Exists(imagePath)) return false;
            var mt = File.GetLastWriteTimeUtc(imagePath);
            if (_sigCache.TryGetValue(imagePath, out var c) && c.mt == mt) return c.ok;
            bool ok = VerifyAuthenticode(imagePath);
            if (_sigCache.Count > 4096) _sigCache.Clear();
            _sigCache[imagePath] = (mt, ok);
            return ok;
        }
        catch { return false; }
    }

    private static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 =
        new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pFile;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = false)]
    private static extern uint WinVerifyTrust(IntPtr hwnd,
        [MarshalAs(UnmanagedType.LPStruct)] Guid pgActionID, IntPtr pWVTData);

    private static bool VerifyAuthenticode(string filePath)
    {
        const uint WTD_UI_NONE = 2, WTD_REVOKE_NONE = 0, WTD_CHOICE_FILE = 1;
        const uint WTD_STATEACTION_VERIFY = 1, WTD_STATEACTION_CLOSE = 2;
        IntPtr pFile = IntPtr.Zero, pData = IntPtr.Zero;
        try
        {
            var fi = new WINTRUST_FILE_INFO
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
                pcwszFilePath = filePath,
            };
            pFile = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
            Marshal.StructureToPtr(fi, pFile, false);

            var wd = new WINTRUST_DATA
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                dwUIChoice = WTD_UI_NONE,
                fdwRevocationChecks = WTD_REVOKE_NONE,
                dwUnionChoice = WTD_CHOICE_FILE,
                pFile = pFile,
                dwStateAction = WTD_STATEACTION_VERIFY,
            };
            pData = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_DATA>());
            Marshal.StructureToPtr(wd, pData, false);

            uint res = WinVerifyTrust(IntPtr.Zero, WINTRUST_ACTION_GENERIC_VERIFY_V2, pData);

            var wd2 = Marshal.PtrToStructure<WINTRUST_DATA>(pData);
            wd2.dwStateAction = WTD_STATEACTION_CLOSE;
            Marshal.StructureToPtr(wd2, pData, true);
            WinVerifyTrust(IntPtr.Zero, WINTRUST_ACTION_GENERIC_VERIFY_V2, pData);

            return res == 0;
        }
        catch { return false; }
        finally
        {
            if (pFile != IntPtr.Zero) Marshal.FreeHGlobal(pFile);
            if (pData != IntPtr.Zero) Marshal.FreeHGlobal(pData);
        }
    }
}
