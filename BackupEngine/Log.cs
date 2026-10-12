using System.Text;

namespace Malward.BackupEngine;

internal static class Log
{
    private static readonly object _lock = new();
    private static readonly string LogPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "Malward", "logs", "backup.log");

    static Log()
    {
        try { Directory.CreateDirectory(Path.GetDirectoryName(LogPath)!); } catch { }
    }

    public static void Info(string tag, string msg)  => Write("INFO ", tag, msg);
    public static void Warn(string tag, string msg)  => Write("WARN ", tag, msg);
    public static void Error(string tag, string msg) => Write("ERROR", tag, msg);
    public static void Debug(string tag, string msg)
    {
        if (!Verbose) return;
        Write("DEBUG", tag, msg);
    }

    public static bool Verbose { get; set; } =
        Environment.GetEnvironmentVariable("MALWARD_BACKUP_VERBOSE") == "1";

    private static void Write(string level, string tag, string msg)
    {
        var line = $"[{DateTime.Now:HH:mm:ss.fff}] {level} [{tag}] {msg}";
        lock (_lock)
        {
            try { Console.Error.WriteLine(line); } catch { }
            try { File.AppendAllText(LogPath, line + Environment.NewLine, Encoding.UTF8); } catch { }
        }
    }
}
