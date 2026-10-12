using System;
using System.Diagnostics;
using System.IO;

namespace Malward.AppGUI.Services;

public static class EngineLocator
{
    public static string GuiExeDir { get; } = ResolveGuiDir();

    private static string ResolveGuiDir()
    {
        try
        {
            var exe = Process.GetCurrentProcess().MainModule?.FileName;
            if (!string.IsNullOrEmpty(exe))
            {
                var d = Path.GetDirectoryName(exe);
                if (!string.IsNullOrEmpty(d)) return d;
            }
        }
        catch { }
        return AppContext.BaseDirectory;
    }

    public static string? FindMalscan(string? overridePath = null)
    {
        if (!string.IsNullOrEmpty(overridePath) && File.Exists(overridePath))
            return Path.GetFullPath(overridePath);

        var candidates = new[]
        {
            Path.Combine(GuiExeDir, "malscan.exe"),
            Path.Combine(GuiExeDir, "..", "..", "..", "EngineSDK", "bin", "malscan.exe"),
            Path.Combine(GuiExeDir, "..", "..", "EngineSDK", "bin", "malscan.exe"),
            Path.Combine(GuiExeDir, "..", "..", "..", "..", "EngineSDK", "bin", "malscan.exe"),
            Path.Combine(GuiExeDir, "..", "EngineSDK", "bin", "malscan.exe"),
        };
        foreach (var c in candidates)
        {
            try
            {
                var full = Path.GetFullPath(c);
                if (File.Exists(full)) return full;
            }
            catch { }
        }

        var path = Environment.GetEnvironmentVariable("PATH") ?? "";
        foreach (var dir in path.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
        {
            try
            {
                var p = Path.Combine(dir.Trim(), "malscan.exe");
                if (File.Exists(p)) return p;
            }
            catch { }
        }
        return null;
    }

    public static string? EngineDir(string? malscanPath = null)
    {
        malscanPath ??= FindMalscan();
        if (string.IsNullOrEmpty(malscanPath)) return null;
        return Path.GetDirectoryName(malscanPath);
    }
}
