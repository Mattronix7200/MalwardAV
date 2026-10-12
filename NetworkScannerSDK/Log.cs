using System.Collections.Concurrent;

namespace Malward.NetworkScanner;

public enum LogLevel { Debug = 0, Info = 1, Warn = 2, Error = 3, Alert = 4 }

public static class Log
{
    private static readonly BlockingCollection<string> _queue =
        new(new ConcurrentQueue<string>(), boundedCapacity: 8192);

    private static readonly Thread _worker;
    private static volatile bool _running = true;

    public static LogLevel MinLevel { get; set; } = LogLevel.Info;

    public static bool FileLoggingEnabled { get; set; } = false;

    private const long MaxLogBytes = 8 * 1024 * 1024;

    private static readonly string _logFile = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "Malward", "logs", "netmonitor.log");

    static Log()
    {
        _worker = new Thread(Drain) { IsBackground = true, Name = "Log-Drain" };
        _worker.Start();
    }

    public static void Debug(string tag, string msg) => Push(LogLevel.Debug, tag, msg);
    public static void Info (string tag, string msg) => Push(LogLevel.Info , tag, msg);
    public static void Warn (string tag, string msg) => Push(LogLevel.Warn , tag, msg);
    public static void Error(string tag, string msg) => Push(LogLevel.Error, tag, msg);
    public static void Alert(string tag, string msg) => Push(LogLevel.Alert, tag, msg);

    private static void Push(LogLevel lvl, string tag, string msg)
    {
        if (lvl < MinLevel) return;
        var line = $"[{DateTime.Now:HH:mm:ss}] [{lvl}] [{tag}] {msg}";
        try { _queue.TryAdd(line, 0); } catch {  }
    }

    private static readonly TextWriter _stdout = OpenStdout();

    private static TextWriter OpenStdout() => Open(() => Console.OpenStandardOutput());

    private static TextWriter Open(Func<Stream> handle)
    {
        try
        {
            var s = handle();
            if (s == Stream.Null) return TextWriter.Null;
            return TextWriter.Synchronized(
                new StreamWriter(s, new System.Text.UTF8Encoding(false)) { AutoFlush = true });
        }
        catch { return TextWriter.Null; }
    }

    private static void Drain()
    {
        FileStream? fs = null; StreamWriter? sw = null;

        while (_running || _queue.Count > 0)
        {
            try
            {
                if (!_queue.TryTake(out var line, 500)) continue;
                try { _stdout.WriteLine(line); } catch { }

                if (FileLoggingEnabled)
                {
                    if (sw == null)
                    {
                        try
                        {
                            Directory.CreateDirectory(Path.GetDirectoryName(_logFile)!);
                            fs = new FileStream(_logFile, FileMode.Append, FileAccess.Write, FileShare.Read);
                            sw = new StreamWriter(fs) { AutoFlush = true };
                        }
                        catch {  }
                    }
                    try
                    {
                        sw?.WriteLine(line);

                        if (sw != null && fs != null && fs.Length > MaxLogBytes)
                        {
                            sw.Dispose(); fs.Dispose(); sw = null; fs = null;
                            var stary = _logFile + ".1";
                            if (File.Exists(stary)) File.Delete(stary);
                            File.Move(_logFile, stary);
                        }
                    }
                    catch { sw = null; fs = null; }
                }
                else if (sw != null)
                {
                    try { sw.Dispose(); fs?.Dispose(); } catch { }
                    sw = null; fs = null;
                }
            }
            catch { }
        }
        try { sw?.Dispose(); fs?.Dispose(); } catch { }
    }

    public static void Shutdown()
    {
        _running = false;
        try { _worker.Join(2000); } catch { }
    }
}
