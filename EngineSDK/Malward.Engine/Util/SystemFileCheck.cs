using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;

namespace Malward.Engine.Util;

[SupportedOSPlatform("windows")]
public static class SystemFileCheck
{
    private static readonly string[] _systemRootsLazy = BuildSystemRoots(includeWindows: true);

    private static readonly string[] _narrowRoots = BuildSystemRoots(includeWindows: false);

    private static string[] BuildSystemRoots(bool includeWindows)
    {
        var list = new List<string>();
        if (includeWindows)
        {
            try { list.Add(Environment.GetFolderPath(Environment.SpecialFolder.Windows)); } catch { }

            try
            {
                var pfApps = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
                if (!string.IsNullOrEmpty(pfApps)) list.Add(Path.Combine(pfApps, "WindowsApps"));
            }
            catch { }
        }
        try
        {
            var win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            if (!string.IsNullOrEmpty(win))
            {
                list.Add(Path.Combine(win, "WinSxS"));
                list.Add(Path.Combine(win, "Microsoft.NET"));
                list.Add(Path.Combine(win, "servicing"));
                list.Add(Path.Combine(win, "assembly"));
            }

            var pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            if (!string.IsNullOrEmpty(pf))
            {
                list.Add(Path.Combine(pf, "Windows Defender"));
                list.Add(Path.Combine(pf, "Windows Media Player"));
                list.Add(Path.Combine(pf, "Windows NT"));
                list.Add(Path.Combine(pf, "Windows Photo Viewer"));
                list.Add(Path.Combine(pf, "Windows Mail"));
                list.Add(Path.Combine(pf, "Common Files", "Microsoft Shared"));
            }
            var pfx86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
            if (!string.IsNullOrEmpty(pfx86))
            {
                list.Add(Path.Combine(pfx86, "Windows Defender"));
                list.Add(Path.Combine(pfx86, "Windows Media Player"));
                list.Add(Path.Combine(pfx86, "Windows NT"));
                list.Add(Path.Combine(pfx86, "Windows Photo Viewer"));
                list.Add(Path.Combine(pfx86, "Windows Mail"));
                list.Add(Path.Combine(pfx86, "Common Files", "Microsoft Shared"));
            }
        }
        catch { }
        return list.ToArray();
    }

    public static bool IsSystemFile(string filePath)
    {
        try
        {
            var full = Path.GetFullPath(filePath);

            foreach (var root in _systemRootsLazy)
            {
                if (string.IsNullOrEmpty(root)) continue;
                if (full.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) ||
                    full.Equals(root, StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            if (IsOwnedByTrustedInstaller(full)) return true;

            if (IsSignedByMicrosoft(full)) return true;
        }
        catch
        {
        }
        return false;
    }

    public static bool IsGenuineSystemFile(string filePath)
    {
        try
        {
            var full = Path.GetFullPath(filePath);

            if (HasBrokenSignature(full)) return false;

            if (IsPeExtension(full) && IsSystemBinaryDir(full) && !HasValidTrustedSignature(full)) return false;

            foreach (var root in _narrowRoots)
            {
                if (string.IsNullOrEmpty(root)) continue;
                if (full.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) ||
                    full.Equals(root, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            if (IsOwnedByTrustedInstaller(full)) return true;
            if (IsSignedByMicrosoft(full)) return true;
        }
        catch { return true; }
        return false;
    }

    private static bool IsPeExtension(string path)
    {
        var ext = Path.GetExtension(path).ToLowerInvariant();
        return ext is ".exe" or ".dll" or ".sys" or ".ocx" or ".drv" or ".cpl" or ".scr";
    }

    public static bool IsSystemBinaryDir(string fullPath)
    {
        try
        {
            var win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            if (string.IsNullOrEmpty(win)) return false;
            foreach (var sub in new[] { "System32", "SysWOW64" })
            {
                var root = Path.Combine(win, sub) + Path.DirectorySeparatorChar;
                if (fullPath.StartsWith(root, StringComparison.OrdinalIgnoreCase)) return true;
            }
        }
        catch { }
        return false;
    }

    public static bool IsOwnedByTrustedInstaller(string filePath)
    {
        try
        {
            var fs = new FileInfo(filePath);
            var ac = fs.GetAccessControl();
            var owner = ac.GetOwner(typeof(NTAccount));
            var name = owner?.Value;
            if (string.IsNullOrEmpty(name)) return false;

            return name.IndexOf("TrustedInstaller", StringComparison.OrdinalIgnoreCase) >= 0;
        }
        catch { return false; }
    }

    public static bool IsOwnedBySystemAuthority(string filePath)
    {
        var fs = new FileInfo(filePath);
        var owner = fs.GetAccessControl().GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
        if (owner == null) return false;
        if (owner.IsWellKnown(WellKnownSidType.LocalSystemSid)) return true;
        if (owner.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid)) return true;

        return owner.Value.Equals("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
                                  StringComparison.OrdinalIgnoreCase);
    }

    public static bool HasValidTrustedSignature(string filePath)
    {
        try
        {
            var key = filePath.ToLowerInvariant();
            var stamp = File.GetLastWriteTimeUtc(filePath).Ticks;
            if (SignatureMemo.TryGetValue(key, out var memo) && memo.Stamp == stamp)
                return memo.Trusted;

            bool ok = HasValidAuthenticodeSignature(filePath) || HasValidCatalogSignature(filePath);

            if (SignatureMemo.Count > 8192) SignatureMemo.Clear();
            SignatureMemo[key] = (stamp, ok);
            return ok;
        }
        catch { return false; }
    }

    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, (long Stamp, bool Trusted)>
        SignatureMemo = new();

    public static bool IsSignedByMicrosoft(string filePath)
    {
        try
        {
            if (HasValidAuthenticodeSignature(filePath))
                return SubjectIsMicrosoft(filePath);

            if (HasValidCatalogSignature(filePath, out var cat) && !string.IsNullOrEmpty(cat))
                return SubjectIsMicrosoft(cat);

            return false;
        }
        catch
        {
            return false;
        }
    }

    private static readonly string[] ThirdPartyAttestationSubjects =
    {
        "Hardware Compatibility Publisher",
        "Third Party Component",
        "Hardware Abstraction Layer Publisher",
        "UEFI CA",
    };

    private static bool IsThirdPartyAttestation(string subject)
    {
        foreach (var marker in ThirdPartyAttestationSubjects)
            if (subject.IndexOf(marker, StringComparison.OrdinalIgnoreCase) >= 0)
                return true;
        return false;
    }

    private static bool SubjectIsMicrosoft(string signedFile)
    {
        try
        {
            using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(signedFile));
            var subject = cert.Subject ?? "";
            if (IsThirdPartyAttestation(subject)) return false;
            return subject.IndexOf("Microsoft Corporation", StringComparison.OrdinalIgnoreCase) >= 0
                || subject.IndexOf("Microsoft Windows", StringComparison.OrdinalIgnoreCase) >= 0;
        }
        catch { return false; }
    }

    private static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 =
        new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    private const uint WTD_UI_NONE            = 2;
    private const uint WTD_REVOKE_NONE        = 0;
    private const uint WTD_CHOICE_FILE        = 1;
    private const uint WTD_STATEACTION_VERIFY = 1;
    private const uint WTD_STATEACTION_CLOSE  = 2;

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

    private static bool HasValidAuthenticodeSignature(string filePath) => AuthenticodeStatus(filePath) == 0;

    public static bool HasValidEmbeddedSignature(string filePath) => AuthenticodeStatus(filePath) == 0;

    private const uint TRUST_E_NOSIGNATURE = 0x800B0100;
    private const uint TRUST_E_BAD_DIGEST  = 0x80096010;

    public static bool HasBrokenSignature(string filePath)
    {
        try { return AuthenticodeStatus(filePath) == TRUST_E_BAD_DIGEST; }
        catch { return false; }
    }

    private static uint AuthenticodeStatus(string filePath)
    {
        IntPtr pFile = IntPtr.Zero;
        IntPtr pData = IntPtr.Zero;
        try
        {
            var fileInfo = new WINTRUST_FILE_INFO
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
                pcwszFilePath = filePath,
                hFile = IntPtr.Zero,
                pgKnownSubject = IntPtr.Zero,
            };
            pFile = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
            Marshal.StructureToPtr(fileInfo, pFile, false);

            var data = new WINTRUST_DATA
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                dwUIChoice = WTD_UI_NONE,
                fdwRevocationChecks = WTD_REVOKE_NONE,
                dwUnionChoice = WTD_CHOICE_FILE,
                pFile = pFile,
                dwStateAction = WTD_STATEACTION_VERIFY,
            };
            pData = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_DATA>());
            Marshal.StructureToPtr(data, pData, false);

            uint status = WinVerifyTrust(IntPtr.Zero, WINTRUST_ACTION_GENERIC_VERIFY_V2, pData);

            var dataClose = Marshal.PtrToStructure<WINTRUST_DATA>(pData);
            dataClose.dwStateAction = WTD_STATEACTION_CLOSE;
            Marshal.StructureToPtr(dataClose, pData, false);
            WinVerifyTrust(IntPtr.Zero, WINTRUST_ACTION_GENERIC_VERIFY_V2, pData);

            return status;
        }
        catch
        {
            return 0xFFFFFFFF;
        }
        finally
        {
            if (pFile != IntPtr.Zero)
            {
                try { Marshal.DestroyStructure<WINTRUST_FILE_INFO>(pFile); } catch { }
                Marshal.FreeHGlobal(pFile);
            }
            if (pData != IntPtr.Zero) Marshal.FreeHGlobal(pData);
        }
    }

    private const uint WTD_CHOICE_CATALOG = 2;

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_CATALOG_INFO
    {
        public uint cbStruct;
        public uint dwCatalogVersion;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszCatalogFilePath;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszMemberTag;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszMemberFilePath;
        public IntPtr hMemberFile;
        public IntPtr pbCalculatedFileHash;
        public uint cbCalculatedFileHash;
        public IntPtr pcCatalogContext;
        public IntPtr hCatAdmin;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CATALOG_INFO
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string wszCatalogFile;
    }

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATAdminAcquireContext(out IntPtr phCatAdmin, IntPtr pgSubsystem, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATAdminCalcHashFromFileHandle(
        IntPtr hFile, ref uint pcbHash, byte[]? pbHash, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern IntPtr CryptCATAdminEnumCatalogFromHash(
        IntPtr hCatAdmin, byte[] pbHash, uint cbHash, uint dwFlags, IntPtr phPrevCatInfo);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATAdminReleaseCatalogContext(IntPtr hCatAdmin, IntPtr hCatInfo, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATCatalogInfoFromContext(IntPtr hCatInfo, ref CATALOG_INFO psCatInfo, uint dwFlags);

    private static bool HasValidCatalogSignature(string filePath)
        => HasValidCatalogSignature(filePath, out _);

    private static bool HasValidCatalogSignature(string filePath, out string? catalogPath)
    {
        catalogPath = null;
        IntPtr hCatAdmin = IntPtr.Zero, hCatInfo = IntPtr.Zero, pHash = IntPtr.Zero, pCat = IntPtr.Zero, pData = IntPtr.Zero;
        FileStream? fs = null;
        try
        {
            if (!CryptCATAdminAcquireContext(out hCatAdmin, IntPtr.Zero, 0)) return false;

            fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            var handle = fs.SafeFileHandle.DangerousGetHandle();

            uint hashLen = 0;
            CryptCATAdminCalcHashFromFileHandle(handle, ref hashLen, null, 0);
            if (hashLen == 0) return false;
            var hash = new byte[hashLen];
            if (!CryptCATAdminCalcHashFromFileHandle(handle, ref hashLen, hash, 0)) return false;

            hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, hash, hashLen, 0, IntPtr.Zero);
            if (hCatInfo == IntPtr.Zero) return false;
            var ci = new CATALOG_INFO { cbStruct = (uint)Marshal.SizeOf<CATALOG_INFO>() };
            if (!CryptCATCatalogInfoFromContext(hCatInfo, ref ci, 0)) return false;
            catalogPath = ci.wszCatalogFile;

            var tag = Convert.ToHexString(hash);

            pHash = Marshal.AllocHGlobal(hash.Length);
            Marshal.Copy(hash, 0, pHash, hash.Length);

            var cat = new WINTRUST_CATALOG_INFO
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_CATALOG_INFO>(),
                pcwszCatalogFilePath = ci.wszCatalogFile,
                pcwszMemberTag = tag,
                pcwszMemberFilePath = filePath,
                hMemberFile = handle,
                pbCalculatedFileHash = pHash,
                cbCalculatedFileHash = hashLen,
                hCatAdmin = hCatAdmin,
            };
            pCat = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_CATALOG_INFO>());
            Marshal.StructureToPtr(cat, pCat, false);

            var data = new WINTRUST_DATA
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                dwUIChoice = WTD_UI_NONE,
                fdwRevocationChecks = WTD_REVOKE_NONE,
                dwUnionChoice = WTD_CHOICE_CATALOG,
                pFile = pCat,
                dwStateAction = WTD_STATEACTION_VERIFY,
            };
            pData = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_DATA>());
            Marshal.StructureToPtr(data, pData, false);

            uint status = WinVerifyTrust(IntPtr.Zero, WINTRUST_ACTION_GENERIC_VERIFY_V2, pData);

            var close = Marshal.PtrToStructure<WINTRUST_DATA>(pData);
            close.dwStateAction = WTD_STATEACTION_CLOSE;
            Marshal.StructureToPtr(close, pData, false);
            WinVerifyTrust(IntPtr.Zero, WINTRUST_ACTION_GENERIC_VERIFY_V2, pData);

            return status == 0;
        }
        catch { return false; }
        finally
        {
            if (pData != IntPtr.Zero) Marshal.FreeHGlobal(pData);
            if (pCat != IntPtr.Zero)
            {
                try { Marshal.DestroyStructure<WINTRUST_CATALOG_INFO>(pCat); } catch { }
                Marshal.FreeHGlobal(pCat);
            }
            if (pHash != IntPtr.Zero) Marshal.FreeHGlobal(pHash);
            fs?.Dispose();
            if (hCatInfo != IntPtr.Zero) try { CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0); } catch { }
            if (hCatAdmin != IntPtr.Zero) try { CryptCATAdminReleaseContext(hCatAdmin, 0); } catch { }
        }
    }
}
