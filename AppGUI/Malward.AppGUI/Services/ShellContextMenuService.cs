using System;
using System.IO;
using Microsoft.Win32;

namespace Malward.AppGUI.Services;

public static class ShellContextMenuService
{
    private const string VerbKey = "MalwardScan";
    private const string Label   = "Skanuj w Malward Cloud Scanner";

    private static string ShellPath(string type) => $@"Software\Classes\{type}\shell\{VerbKey}";

    private static string ExePath()
    {
        var p = Environment.ProcessPath;
        if (string.IsNullOrEmpty(p)) p = Path.Combine(AppContext.BaseDirectory, "malward.exe");
        return p!;
    }

    public static bool IsRegistered()
    {
        try
        {
            using var k = Registry.CurrentUser.OpenSubKey(ShellPath("*"));
            return k != null;
        }
        catch { return false; }
    }

    public static (bool ok, string? error) Register()
    {
        try
        {
            string exe = ExePath();
            string dir = Path.GetDirectoryName(exe) ?? AppContext.BaseDirectory;
            string ctx = Path.Combine(dir, "MalwardCtx.exe");
            string icon = $"\"{exe}\",0";

            string cmd = File.Exists(ctx)
                ? $"\"{ctx}\" \"%1\""
                : $"\"{exe}\" --scan \"%1\"";
            foreach (var type in new[] { "*", "Directory" })
            {
                using var shell = Registry.CurrentUser.CreateSubKey(ShellPath(type));
                shell.SetValue(null, Label);
                shell.SetValue("Icon", icon);

                shell.SetValue("MultiSelectModel", "Document");
                using var command = shell.CreateSubKey("command");
                command.SetValue(null, cmd);
            }
            return (true, null);
        }
        catch (Exception ex) { return (false, ex.Message); }
    }

    public static (bool ok, string? error) Unregister()
    {
        try
        {
            foreach (var type in new[] { "*", "Directory" })
            {
                try { Registry.CurrentUser.DeleteSubKeyTree(ShellPath(type), throwOnMissingSubKey: false); }
                catch { }
            }
            return (true, null);
        }
        catch (Exception ex) { return (false, ex.Message); }
    }

    public static (bool ok, string? error) Set(bool enabled)
        => enabled ? Register() : Unregister();
}
