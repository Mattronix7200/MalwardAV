using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Principal;

namespace Malward.ResidentShield;

public static class InstallFolderGuard
{
    private const string SidSystem = "*S-1-5-18";      
    private const string SidAdmins = "*S-1-5-32-544";  
    private const string SidUsers  = "*S-1-5-32-545";
    private const string SidAuthUsers = "*S-1-5-11";  
    private const string SidEveryone = "S-1-1-0";

    private static string MarkerPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "Malward", "data", "folder-guard.applied");

    public static string ProgramDataDir => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Malward");

    public static string InboxDir => Path.Combine(ProgramDataDir, "inbox");

    private static readonly string[] SensitiveNames = { "backup", "quarantine", "ca", "shield" };

    public static IEnumerable<string> SensitiveDirs()
    {
        foreach (var name in SensitiveNames)
            yield return Path.Combine(ProgramDataDir, name);
    }

    public static void EnsureApplied(string? installDir = null)
    {
        try
        {
            var dir = installDir ?? AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar);
            if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir)) return;

            if (!LooksLikeInstallDir(dir))
            {
                Log.Info("Guard", $"Folder guard skipped (does not look like an installation): {dir}");
                return;
            }

            if (IsGuarded(dir)) return;

            var (ok, detail) = Apply(dir);
            if (ok)
            {
                Directory.CreateDirectory(Path.GetDirectoryName(MarkerPath)!);
                File.WriteAllText(MarkerPath, dir);
                Log.Info("Guard", $"Program folder locked against writes and deletion: {dir}");
            }
            else Log.Warn("Guard", $"Failed to lock the program folder: {detail}");
        }
        catch (Exception ex) { Log.Warn("Guard", ex.Message); }
    }

    public static void EnsureProgramDataApplied()
    {
        try
        {
            var dir = ProgramDataDir;
            Directory.CreateDirectory(dir);
            if (!IsGuarded(dir))
            {
                var (ok, detail) = ApplyProgramData(dir);
                if (ok) Log.Info("Guard", $"Data folder locked against writes and deletion: {dir}");
                else Log.Warn("Guard", $"Failed to lock the data folder: {detail}");
            }
            EnsureSensitiveApplied();
            EnsureInbox();
        }
        catch (Exception ex) { Log.Warn("Guard", ex.Message); }
    }

    public static void EnsureSensitiveApplied()
    {
        foreach (var dir in SensitiveDirs())
        {
            try
            {
                Directory.CreateDirectory(dir);
                if (IsSensitiveGuarded(dir)) continue;

                var (ok, detail) = ApplySensitive(dir);
                if (ok)
                    Log.Info("Guard", $"Folder restricted to the system and administrators: {dir}");
                else
                    Log.Warn("Guard", $"Failed to restrict {dir}: {detail}");
            }
            catch (Exception ex) { Log.Warn("Guard", $"{dir}: {ex.Message}"); }
        }
    }

    public static void VerifyAll()
    {
        try
        {
            var dir = AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar);
            if (!string.IsNullOrEmpty(dir) && Directory.Exists(dir) && LooksLikeInstallDir(dir) && !IsGuarded(dir))
            {
                var (ok, detail) = Apply(dir);
                Log.Warn("Guard", ok
                    ? $"Program folder guard had been removed — restored: {dir}"
                    : $"Program folder guard had been removed and could not be restored: {detail}");
            }

            var pd = ProgramDataDir;
            if (Directory.Exists(pd) && !IsGuarded(pd))
            {
                var (ok, detail) = ApplyProgramData(pd);
                Log.Warn("Guard", ok
                    ? $"Data folder guard had been removed — restored: {pd}"
                    : $"Data folder guard had been removed and could not be restored: {detail}");
            }
            foreach (var sensitive in SensitiveDirs())
            {
                if (!Directory.Exists(sensitive) || IsSensitiveGuarded(sensitive)) continue;
                var (sok, sdetail) = ApplySensitive(sensitive);
                Log.Warn("Guard", sok
                    ? $"Permissions of {sensitive} had been changed — restored."
                    : $"Permissions of {sensitive} had been changed and could not be restored: {sdetail}");
            }

            if (Directory.Exists(pd)) EnsureInbox();
        }
        catch (Exception ex) { Log.Warn("Guard", ex.Message); }
    }

    private const FileSystemRights WriteMask =
        FileSystemRights.WriteData | FileSystemRights.AppendData
        | FileSystemRights.WriteAttributes | FileSystemRights.WriteExtendedAttributes
        | FileSystemRights.Delete | FileSystemRights.DeleteSubdirectoriesAndFiles
        | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership;

    private static readonly string[] TrustedSids = { "S-1-5-18", "S-1-5-32-544" };

    private static bool Trusted(string sid) => Array.IndexOf(TrustedSids, sid) >= 0;

    public static bool IsGuarded(string dir) => Inspect(dir, readOnlyForUsers: true);

    public static bool IsSensitiveGuarded(string dir) => Inspect(dir, readOnlyForUsers: false);

    private static bool Inspect(string dir, bool readOnlyForUsers)
    {
        try
        {
            var acl = new DirectoryInfo(dir).GetAccessControl(
                AccessControlSections.Access | AccessControlSections.Owner);

            if (!acl.AreAccessRulesProtected) return false;

            bool denyPresent = false;
            foreach (FileSystemAccessRule rule in
                     acl.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            {
                var sid = rule.IdentityReference.Value;

                if (rule.AccessControlType == AccessControlType.Deny)
                {
                    if (string.Equals(sid, SidEveryone, StringComparison.Ordinal)
                        && (rule.FileSystemRights & FileSystemRights.Delete) != 0)
                        denyPresent = true;
                    continue;
                }

                if (Trusted(sid)) continue;

                if ((rule.FileSystemRights & WriteMask) != 0) return false;
                if (!readOnlyForUsers) return false;
            }

            return denyPresent;
        }
        catch { }
        return false;
    }

    public static (bool ok, string detail) ApplySensitive(string dir)
    {
        var (ok, detail) = WriteDacl(dir, FileSystemRights.FullControl, null);
        if (!ok) return (false, detail);

        ResetChildren(dir);
        Icacls($"\"{dir}\" /setowner {SidSystem} /C /Q");
        return (true, "");
    }

    private const InheritanceFlags Both =
        InheritanceFlags.ObjectInherit | InheritanceFlags.ContainerInherit;

    private const FileSystemRights TamperRights =
        FileSystemRights.Delete | FileSystemRights.DeleteSubdirectoriesAndFiles
        | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership;

    private static (bool ok, string detail) WriteDacl(string dir, FileSystemRights adminRights,
                                                      FileSystemRights? userRights)
    {
        if (IsProtectedSystemLocation(dir))
        {
            Log.Warn("Guard", $"Refused to change permissions of a system location: {dir}");
            return (false, "refused: system location");
        }

        try
        {
            var acl = new DirectorySecurity();
            acl.SetAccessRuleProtection(true, false);

            acl.AddAccessRule(new FileSystemAccessRule(
                new SecurityIdentifier("S-1-5-18"), FileSystemRights.FullControl,
                Both, PropagationFlags.None, AccessControlType.Allow));
            acl.AddAccessRule(new FileSystemAccessRule(
                new SecurityIdentifier("S-1-5-32-544"), adminRights,
                Both, PropagationFlags.None, AccessControlType.Allow));

            if (userRights.HasValue)
                acl.AddAccessRule(new FileSystemAccessRule(
                    new SecurityIdentifier("S-1-5-32-545"), userRights.Value,
                    Both, PropagationFlags.None, AccessControlType.Allow));

            acl.AddAccessRule(new FileSystemAccessRule(
                new SecurityIdentifier(SidEveryone), TamperRights,
                InheritanceFlags.None, PropagationFlags.None, AccessControlType.Deny));

            new DirectoryInfo(dir).SetAccessControl(acl);
            return (true, "");
        }
        catch (Exception ex) { return (false, ex.Message); }
    }

    private static void ResetChildren(string dir)
    {
        if (IsProtectedSystemLocation(dir))
        {
            Log.Warn("Guard", $"Refused to reset permissions inside a system location: {dir}");
            return;
        }

        try
        {
            if (!Directory.EnumerateFileSystemEntries(dir).Any()) return;
            Icacls($"\"{Path.Combine(dir, "*")}\" /reset /T /C /Q");
        }
        catch { }
    }

    public static (bool ok, string detail) ApplyProgramData(string dir)
    {
        var (ok, detail) = WriteDacl(dir, FileSystemRights.FullControl,
                                     FileSystemRights.ReadAndExecute);
        if (!ok) return (false, detail);

        Icacls($"\"{dir}\" /setowner {SidSystem} /C /Q");

        EnsureInbox();
        return (true, "");
    }

    public static void EnsureInbox()
    {
        try
        {
            var inbox = InboxDir;
            Directory.CreateDirectory(inbox);
            Icacls($"\"{inbox}\" /grant {SidAuthUsers}:(OI)(CI)M /C /Q");
        }
        catch (Exception ex) { Log.Debug("Guard", $"inbox: {ex.Message}"); }
    }

    private static readonly string[] OwnBinaries =
        { "malward.exe", "mwshield.exe", "malscan.exe" };

    private static string Normalized(string path)
    {
        try { return Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar).ToLowerInvariant(); }
        catch { return (path ?? "").TrimEnd(Path.DirectorySeparatorChar).ToLowerInvariant(); }
    }

    public static bool IsProtectedSystemLocation(string dir)
    {
        if (string.IsNullOrWhiteSpace(dir)) return true;

        var d = Normalized(dir);
        if (d.Length <= 3) return true;

        if (d.Contains(@"\windowsapps") || d.Contains(@"\systemapps")
            || d.Contains(@"\assembly") || d.Contains(@"\winsxs"))
            return true;

        var windows = Normalized(Environment.GetFolderPath(Environment.SpecialFolder.Windows));
        if (d == windows || d.StartsWith(windows + Path.DirectorySeparatorChar, StringComparison.Ordinal))
            return true;

        foreach (var folder in new[]
                 {
                     Environment.SpecialFolder.ProgramFiles,
                     Environment.SpecialFolder.ProgramFilesX86,
                     Environment.SpecialFolder.CommonApplicationData,
                     Environment.SpecialFolder.UserProfile,
                     Environment.SpecialFolder.CommonProgramFiles,
                 })
        {
            var root = Normalized(Environment.GetFolderPath(folder));
            if (root.Length > 3 && d == root) return true;
        }

        return false;
    }

    private static bool LooksLikeInstallDir(string dir)
    {
        var d = dir.ToLowerInvariant();
        if (d.Contains(@"\bin\debug") || d.Contains(@"\bin\release") || d.Contains(@"\obj\")) return false;
        if (d.StartsWith(Path.GetTempPath().ToLowerInvariant(), StringComparison.Ordinal)) return false;
        if (IsProtectedSystemLocation(dir)) return false;

        foreach (var exe in OwnBinaries)
        {
            try { if (File.Exists(Path.Combine(dir, exe))) return true; }
            catch { }
        }
        return false;
    }

    public static (bool ok, string detail) Apply(string dir)
    {
        var (ok, detail) = WriteDacl(dir, FileSystemRights.ReadAndExecute,
                                     FileSystemRights.ReadAndExecute);
        if (!ok) return (false, detail);

        ResetChildren(dir);
        Icacls($"\"{dir}\" /setowner {SidSystem} /C /Q");

        return (true, "");
    }

    public static (bool ok, string detail) Remove(string dir)
    {
        Icacls($"\"{dir}\" /setowner {SidAdmins} /C /Q");
        var (rc, o) = Icacls($"\"{dir}\" /reset /T /C /Q");
        if (rc != 0) return (false, o);
        Icacls($"\"{dir}\" /inheritance:e");
        try { if (File.Exists(MarkerPath)) File.Delete(MarkerPath); } catch { }
        return (true, "");
    }

    private static (int rc, string output) Icacls(string args)
    {
        try
        {
            var psi = new ProcessStartInfo("icacls.exe", args)
            {
                UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardOutput = true, RedirectStandardError = true,
            };
            using var p = Process.Start(psi);
            if (p == null) return (-1, "failed to start icacls.exe");
            string outp = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
            if (!p.WaitForExit(60000)) { try { p.Kill(); } catch { } return (-1, "icacls: timeout"); }
            return (p.ExitCode, outp.Trim());
        }
        catch (Exception ex) { return (-1, ex.Message); }
    }
}
