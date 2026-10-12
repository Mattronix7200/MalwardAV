using Microsoft.Win32;
using System.Runtime.InteropServices;

namespace Malward.NetworkScanner;

public static class SystemProxyManager
{
    private const string KeyPath = @"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

    private static readonly string BackupPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "Malward", "data", "sys-proxy-backup.json");

    public static bool Enable(string host, int port, string? bypassList = null)
    {
        try
        {
            BackupCurrent();
            using var key = Registry.CurrentUser.OpenSubKey(KeyPath, writable: true);
            if (key == null) return false;
            key.SetValue("ProxyEnable", 1, RegistryValueKind.DWord);
            key.SetValue("ProxyServer", $"{host}:{port}", RegistryValueKind.String);

            key.SetValue("ProxyOverride", bypassList ?? "<local>;127.0.0.1;localhost", RegistryValueKind.String);
            InternetSettingsChanged();
            Log.Info("SysProxy", $"system proxy set: {host}:{port}");
            return true;
        }
        catch (Exception ex)
        {
            Log.Warn("SysProxy", $"Enable failed: {ex.Message}");
            return false;
        }
    }

    public static bool Restore()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(KeyPath, writable: true);
            if (key == null) return false;
            var backup = LoadBackup();
            if (backup != null)
            {
                key.SetValue("ProxyEnable", backup.Enable, RegistryValueKind.DWord);
                if (backup.Server != null) key.SetValue("ProxyServer", backup.Server, RegistryValueKind.String);
                else key.DeleteValue("ProxyServer", throwOnMissingValue: false);
                if (backup.Override != null) key.SetValue("ProxyOverride", backup.Override, RegistryValueKind.String);
                else key.DeleteValue("ProxyOverride", throwOnMissingValue: false);
            }
            else
            {
                key.SetValue("ProxyEnable", 0, RegistryValueKind.DWord);
            }
            InternetSettingsChanged();
            Log.Info("SysProxy", "system proxy restored");
            return true;
        }
        catch (Exception ex) { Log.Warn("SysProxy", $"Restore failed: {ex.Message}"); return false; }
    }

    private static void BackupCurrent()
    {
        try
        {
            if (File.Exists(BackupPath)) return;
            using var key = Registry.CurrentUser.OpenSubKey(KeyPath, writable: false);
            if (key == null) return;
            int enable = (int)(key.GetValue("ProxyEnable", 0) ?? 0);
            var server = key.GetValue("ProxyServer") as string;
            var over   = key.GetValue("ProxyOverride") as string;
            var b = new ProxyBackup { Enable = enable, Server = server, Override = over };
            Directory.CreateDirectory(Path.GetDirectoryName(BackupPath)!);
            File.WriteAllText(BackupPath, System.Text.Json.JsonSerializer.Serialize(b));
        }
        catch { }
    }

    private static ProxyBackup? LoadBackup()
    {
        try
        {
            if (!File.Exists(BackupPath)) return null;
            var raw = File.ReadAllText(BackupPath);
            var b = System.Text.Json.JsonSerializer.Deserialize<ProxyBackup>(raw);
            File.Delete(BackupPath);
            return b;
        }
        catch { return null; }
    }

    private sealed class ProxyBackup
    {
        public int Enable { get; set; }
        public string? Server { get; set; }
        public string? Override { get; set; }
    }

    [DllImport("wininet.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);

    private const int INTERNET_OPTION_SETTINGS_CHANGED = 39;
    private const int INTERNET_OPTION_REFRESH = 37;

    private static void InternetSettingsChanged()
    {
        try
        {
            InternetSetOption(IntPtr.Zero, INTERNET_OPTION_SETTINGS_CHANGED, IntPtr.Zero, 0);
            InternetSetOption(IntPtr.Zero, INTERNET_OPTION_REFRESH, IntPtr.Zero, 0);
        }
        catch { }
    }
}
