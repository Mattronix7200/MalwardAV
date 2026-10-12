using System.Collections.Concurrent;

namespace Malward.ResidentShield;

public enum LogLevel { Debug = 0, Info = 1, Warn = 2, Error = 3, Alert = 4 }

public static class Log
{
    private static readonly BlockingCollection<(LogLevel lvl, string msg)> _queue =
        new(new ConcurrentQueue<(LogLevel, string)>(), boundedCapacity: 8192);

    private static readonly Thread _worker;
    private static volatile bool _running = true;

    public static LogLevel MinLevel { get; set; } = LogLevel.Info;

    static Log()
    {
        _worker = new Thread(Drain)
        {
            Name         = "Log-Drain",
            IsBackground = true,
            Priority     = ThreadPriority.BelowNormal,
        };
        _worker.Start();
    }

    private static readonly string LogFile = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "Malward", "logs", "mwshield.log");

    private const long MaxLogBytes = 8 * 1024 * 1024;

    public static bool FileLoggingEnabled { get; set; } = true;

    private static readonly TextWriter _stdout = OpenStdout();
    private static readonly TextWriter _stderr = OpenStderr();

    private static TextWriter OpenStdout() => Open(() => Console.OpenStandardOutput());
    private static TextWriter OpenStderr() => Open(() => Console.OpenStandardError());

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
        StreamWriter? sw = null;
        long written = 0;

        foreach (var (lvl, msg) in _queue.GetConsumingEnumerable())
        {
            try
            {
                var w = lvl >= LogLevel.Error ? _stderr : _stdout;
                w.WriteLine(msg);
            }
            catch {  }

            if (!FileLoggingEnabled) continue;
            try
            {
                if (sw == null)
                {
                    Directory.CreateDirectory(Path.GetDirectoryName(LogFile)!);
                    try { written = File.Exists(LogFile) ? new FileInfo(LogFile).Length : 0; }
                    catch { written = 0; }
                    sw = new StreamWriter(new FileStream(LogFile, FileMode.Append, FileAccess.Write,
                                                         FileShare.Read)) { AutoFlush = true };
                }

                sw.WriteLine(msg);
                written += msg.Length + 2;

                if (written > MaxLogBytes)
                {
                    sw.Dispose(); sw = null; written = 0;
                    try
                    {
                        var stary = LogFile + ".1";
                        if (File.Exists(stary)) File.Delete(stary);
                        File.Move(LogFile, stary);
                    }
                    catch {  }
                }
            }
            catch { sw = null; }
        }

        try { sw?.Dispose(); } catch { }
    }

    private static void Enqueue(LogLevel lvl, string tag, string msg)
    {
        if (lvl < MinLevel) return;

        _queue.TryAdd((lvl, $"{Stamp()} {Prefix(lvl)} [{tag}] {msg}"));
    }

    private static string Stamp() => DateTime.Now.ToString("HH:mm:ss.fff");

    private static string Prefix(LogLevel lvl) => lvl switch
    {
        LogLevel.Debug => "DBG",
        LogLevel.Info  => "INF",
        LogLevel.Warn  => "WRN",
        LogLevel.Error => "ERR",
        LogLevel.Alert => ">>>",
        _              => "   ",
    };

    public static void Debug(string tag, string msg) => Enqueue(LogLevel.Debug, tag, msg);
    public static void Info (string tag, string msg) => Enqueue(LogLevel.Info,  tag, msg);
    public static void Warn (string tag, string msg) => Enqueue(LogLevel.Warn,  tag, msg);
    public static void Error(string tag, string msg) => Enqueue(LogLevel.Error, tag, msg);

    public static void Alert(string tag, string msg) => Enqueue(LogLevel.Alert, tag, msg);

    public static void Raw(string msg) => _queue.TryAdd((LogLevel.Info, msg));

    public static void Shutdown()
    {
        if (!_running) return;
        _running = false;
        _queue.CompleteAdding();
        try { _worker.Join(TimeSpan.FromSeconds(2)); } catch { }
    }
}
