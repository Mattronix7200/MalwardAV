using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;

namespace Malward.AppGUI.Services;

public static class Startup
{
    [DllImport("user32.dll")] private static extern bool SetForegroundWindow(IntPtr hWnd);
    [DllImport("user32.dll")] private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    [DllImport("user32.dll")] private static extern bool IsIconic(IntPtr hWnd);
    [DllImport("user32.dll")] private static extern bool AllowSetForegroundWindow(uint dwProcessId);

    private const int SW_RESTORE = 9;
    private const int SW_SHOW = 5;

    public const string MutexName = "Local\\Malward.AppGUI.SingleInstance";

    public static bool IsHeadlessCommand(string[] args) => args.Any(a =>
        a.Equals("--scheduled-scan", StringComparison.OrdinalIgnoreCase) ||
        a.StartsWith("--scheduled-scan=", StringComparison.OrdinalIgnoreCase) ||
        a.Equals("--update-engine", StringComparison.OrdinalIgnoreCase));

    public static void ForwardScanRequest(string[] args)
    {
        var paths = new List<string>();
        for (int i = 0; i < args.Length - 1; i++)
            if (string.Equals(args[i], "--scan", StringComparison.OrdinalIgnoreCase))
                paths.Add(args[i + 1]);
        if (paths.Count > 0) ScanInbox.Append(paths);
    }

    public static void EnsureProgramDataWritable()
    {
        try
        {
            var dir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "Malward", "inbox");
            Directory.CreateDirectory(dir);

            var psi = new ProcessStartInfo("icacls", $"\"{dir}\" /grant *S-1-5-11:(OI)(CI)M /C /Q")
            {
                UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardOutput = true, RedirectStandardError = true,
            };
            using var p = Process.Start(psi);
            p?.WaitForExit(5000);
        }
        catch { }
    }

    public static void ActivateExistingInstance()
    {
        try
        {
            int my = Environment.ProcessId;
            var others = Process.GetProcessesByName("malward")
                .Concat(Process.GetProcessesByName("Malward.AppGUI"))
                .Where(p => p.Id != my)
                .ToList();
            foreach (var p in others)
            {
                try
                {
                    AllowSetForegroundWindow((uint)p.Id);
                    var h = p.MainWindowHandle;
                    if (h == IntPtr.Zero) continue;
                    if (IsIconic(h)) ShowWindow(h, SW_RESTORE);
                    else ShowWindow(h, SW_SHOW);
                    SetForegroundWindow(h);
                    return;
                }
                catch { }
            }
        }
        catch { }
    }

    public static void AutoRegisterShellMenuOnce()
    {
        try
        {
            RemoveLegacyShellPackageOnce();

            var engineDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Malward");
            var store = new GuiSettingsStore(engineDir);
            var gs = store.Read();
            if (gs.ContextMenu == false) return;
            if (gs.ContextMenu == null)
            {
                try { ShellContextMenuService.Register(); } catch { }
                try { store.Write(gs with { ContextMenu = true }); } catch { }
                return;
            }

            if (!ShellContextMenuService.IsRegistered())
                try { ShellContextMenuService.Register(); } catch { }
        }
        catch { }
    }

    private static void RemoveLegacyShellPackageOnce()
    {
        try
        {
            var marker = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "Malward", ".shellext-removed");
            if (File.Exists(marker)) return;
            var psi = new ProcessStartInfo("powershell.exe",
                "-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command " +
                "\"$p = Get-AppxPackage -Name 'Malward.CloudScanner.ShellExt'; if ($p) { Remove-AppxPackage $p.PackageFullName }\"")
            {
                UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardOutput = true, RedirectStandardError = true,
            };
            using (var p = Process.Start(psi)) { p?.WaitForExit(20000); }
            Directory.CreateDirectory(Path.GetDirectoryName(marker)!);
            File.WriteAllText(marker, DateTime.UtcNow.ToString("o"));
        }
        catch { }
    }

    public static bool WebModeRequested()
    {
        try
        {
            var dir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "Malward", "data");
            if (File.Exists(Path.Combine(dir, "web-ui"))) return true;

            var plik = Path.Combine(dir, "gui-settings.json");
            if (!File.Exists(plik)) return false;
            return System.Text.Json.Nodes.JsonNode.Parse(File.ReadAllText(plik))
                   is System.Text.Json.Nodes.JsonObject o
                && o["gui_mode"]?.GetValue<string>() == "web";
        }
        catch { return false; }
    }
}
