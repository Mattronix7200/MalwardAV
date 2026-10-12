using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace Malward.AppGUI.Services;

public static class SystemHardening
{
    public sealed record Status(string SecureBoot, string BitLocker, bool BootBackupPresent);

    public static async Task<Status> GetAsync()
    {
        string sb = SecureBootState();
        string bl = await BitLockerOsStateAsync();
        return new Status(sb, bl, BootBackupPresent());
    }

    private static string SecureBootState()
    {
        try
        {
            using var k = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\SecureBoot\State");
            if (k?.GetValue("UEFISecureBootEnabled") is int v)
                return v == 1 ? "on" : "off";
        }
        catch { }
        return "unknown";
    }

    private static async Task<string> BitLockerOsStateAsync()
    {
        try
        {
            string sysDrive = Path.GetPathRoot(Environment.SystemDirectory)?.TrimEnd('\\') ?? "C:";
            var psi = new ProcessStartInfo("manage-bde.exe", $"-status {sysDrive}")
            {
                UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardOutput = true, RedirectStandardError = true,
                StandardOutputEncoding = Encoding.UTF8,
            };
            using var p = Process.Start(psi);
            if (p == null) return "unknown";
            var outTask = p.StandardOutput.ReadToEndAsync();
            bool exited = await Task.Run(() => p.WaitForExit(8000));
            if (!exited) { try { p.Kill(true); } catch { } return "unknown"; }
            string outp = (await outTask).ToLowerInvariant();

            if (outp.Contains("protection on") || outp.Contains("ochrona włączona") || outp.Contains("ochrona wlaczona"))
                return "on";
            if (outp.Contains("protection off") || outp.Contains("ochrona wyłączona") || outp.Contains("ochrona wylaczona")
                || outp.Contains("fully decrypted"))
                return "off";
        }
        catch { }
        return "unknown";
    }

    private static bool BootBackupPresent()
    {
        try
        {
            var dir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "Malward", "data", "boot-backup");
            return Directory.Exists(dir) && Directory.GetFiles(dir, "*.mbrbak").Length > 0;
        }
        catch { return false; }
    }
}
