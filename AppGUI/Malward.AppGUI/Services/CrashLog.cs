using System;
using System.IO;

namespace Malward.AppGUI.Services;

public static class CrashLog
{
    public static void Write(string tag, Exception? ex, string? note = null)
    {
        try
        {
            var dir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "Malward", "logs");
            Directory.CreateDirectory(dir);
            var line = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {tag}: {note}{ex}\n";
            File.AppendAllText(Path.Combine(dir, "gui-crash.log"), line);
        }
        catch { }
    }
}
