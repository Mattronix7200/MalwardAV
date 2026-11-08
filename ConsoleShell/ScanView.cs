using System.Globalization;

namespace Malward.ConsoleShell;

public sealed class ScanView
{
    public sealed record Detection(string Name, string File, string Method, DateTime When);

    private readonly Screen _screen;
    private readonly SidebarInfo _info;
    private readonly List<Detection> _detections = new();
    private readonly List<string> _errors = new();
    private readonly List<string> _journal = new();
    private readonly object _gate = new();
    private readonly object _drawGate = new();

    private DateTime _lastDraw = DateTime.MinValue;
    private DateTime _lastFull = DateTime.MinValue;
    private string _lastPlain = "";
    private volatile bool _painting;

    public ScanView(Screen screen, SidebarInfo info)
    {
        _screen = screen;
        _info = info;
    }

    public Screen Surface => _screen;

    public string Mode = "QUICK";
    public string Stage = "Starting";
    public string Current = "";
    public string Cloud = "";
    public DateTime Started = DateTime.Now;

    public int Scanned;
    public int Errors;
    public int Infections;
    public int Total;
    public long Bytes;

    public int Unverified;

    public bool CloudEnabled;
    public bool Counting = true;
    public bool Finished;
    public bool Stopped;
    public int Threads = 1;

    public IReadOnlyList<(string Text, Tone Tone)>? Warning;
    public string WarningLine = "";

    public TimeSpan MinInterval { get; set; } = TimeSpan.FromMilliseconds(110);

    public IReadOnlyList<Detection> Detections { get { lock (_gate) return _detections.ToArray(); } }
    public IReadOnlyList<string> ErrorLines { get { lock (_gate) return _errors.ToArray(); } }
    public IReadOnlyList<string> Journal { get { lock (_gate) return _journal.ToArray(); } }

    public void AddDetection(string name, string file, string method)
    {
        lock (_gate)
        {
            _detections.Add(new Detection(name, file, method, DateTime.Now));
            Note($"[!] {name}  {file}  ({method})");
        }
    }

    public void AddError(string line)
    {
        lock (_gate)
        {
            _errors.Add(line);
            if (_errors.Count > 400) _errors.RemoveAt(0);
            Note("[!] " + line);
        }
    }

    public void Note(string line)
    {
        lock (_gate)
        {
            if (_journal.Count < 20000) _journal.Add(line);
        }
    }

    public double Percent
    {
        get
        {
            if (Finished && !Stopped) return 100;
            if (Counting || Total <= 0) return 0;
            return Math.Min(100.0, Scanned * 100.0 / Total);
        }
    }

    public TimeSpan Elapsed => DateTime.Now - Started;

    private string Eta()
    {
        if (Finished) return "00:00:00";
        if (Counting || Total <= 0 || Scanned <= 0) return "--:--:--";
        double perFile = Elapsed.TotalSeconds / Scanned;
        double left = perFile * Math.Max(0, Total - Scanned);
        if (left > TimeSpan.MaxValue.TotalSeconds - 1) return "--:--:--";
        return Span(TimeSpan.FromSeconds(left));
    }

    private static string Span(TimeSpan t)
        => ((int)t.TotalHours).ToString("00", CultureInfo.InvariantCulture)
           + t.ToString("\\:mm\\:ss", CultureInfo.InvariantCulture);

    public static string Data(long bytes)
    {
        string[] units = { "B", "KiB", "MiB", "GiB", "TiB" };
        double value = bytes;
        int unit = 0;
        while (value >= 1024 && unit < units.Length - 1) { value /= 1024; unit++; }
        return value.ToString(unit == 0 ? "F0" : "F1", CultureInfo.InvariantCulture) + " " + units[unit];
    }

    public static string Count(int n) => n.ToString("N0", CultureInfo.InvariantCulture);

    public sealed class Painter : IDisposable
    {
        private readonly ScanView _view;
        private readonly Thread _thread;
        private volatile bool _stop;

        public Painter(ScanView view)
        {
            _view = view;
            view._painting = true;
            _thread = new Thread(Loop) { IsBackground = true, Name = "malcsm-paint" };
            _thread.Start();
        }

        private void Loop()
        {
            while (!_stop)
            {
                _view.Render(false);
                Thread.Sleep(120);
            }
        }

        public void Dispose()
        {
            _stop = true;
            try { _thread.Join(400); } catch { }
            _view._painting = false;
        }
    }

    public Painter StartPainter() => new(this);

    public void Draw(bool force = false)
    {
        if (_painting) return;
        Render(force);
    }

    private void Render(bool force)
    {
        if (!Monitor.TryEnter(_drawGate)) return;
        try
        {
            var now = DateTime.UtcNow;
            if (!force && now - _lastDraw < MinInterval) return;
            _lastDraw = now;

            if (!_screen.Live) { DrawPlain(); return; }

            _screen.Sync();
            bool full = now - _lastFull > TimeSpan.FromSeconds(3);
            if (full) _lastFull = now;

            _screen.Clear();
            _screen.Sidebar(_info);
            DrawContent();
            _screen.Flush(full);
        }
        catch { }
        finally { Monitor.Exit(_drawGate); }
    }

    private void DrawContent()
    {
        int left = _screen.ContentLeft;
        int width = _screen.ContentWidth;
        int bottom = _screen.ContentBottom;
        int y = _screen.ContentTop;

        string title = Finished
            ? (Stopped ? "SCAN STOPPED - " + Mode : "SCAN FINISHED - " + Mode)
            : "SCANNING MODE - " + Mode;
        _screen.Put(left, y, title, Tone.Title);

        string cloud = Cloud.Length == 0 ? "" : "cloud: " + Cloud;
        if (cloud.Length > 0 && width > title.Length + cloud.Length + 3)
            _screen.Put(left + width - cloud.Length, y,
                        cloud, Cloud == "unavailable" ? Tone.Warn : Tone.Dim);
        y++;

        _screen.Rule(left, y++, width);

        var where = Counting && !Finished ? "Now listing:  " : "Now scanning: ";
        _screen.Put(left, y, where, Tone.Dim);
        _screen.Put(left + 14, y++, Screen.ClipPath(Current.Length == 0 ? Stage : Current, width - 14));
        y++;

        int column = left + Math.Min(38, width / 2 + 2);
        bool wide = width >= 62;

        bool listing = Counting && !Finished;
        _screen.Field(left, y, listing ? "Files found:" : "Scanned files:",
            listing ? Count(Total) : Count(Scanned) + (Total > 0 ? " / " + Count(Total) : ""), 16);
        if (wide) _screen.Field(column, y, "Time left:", Eta(), 14);
        y++;

        _screen.Field(left, y, "Progress:",
            listing
                ? "counting files"
                : Percent.ToString("F1", CultureInfo.InvariantCulture) + " %",
            16, Tone.Info);
        if (wide) _screen.Field(column, y, "Tested data:", Data(Bytes), 14);
        y++;

        _screen.Field(left, y, "Errors:", Count(Errors), 16, Errors > 0 ? Tone.Warn : Tone.Plain);
        if (wide) _screen.Field(column, y, "Elapsed:", Span(Elapsed), 14);
        y++;

        _screen.Field(left, y, "Infections:", Count(Infections), 16,
                      Infections > 0 ? Tone.Threat : Tone.Plain);
        if (wide) _screen.Field(column, y, "Threads:", Threads.ToString(CultureInfo.InvariantCulture), 14);
        y++;

        _screen.Rule(left, y++, width);

        foreach (var alert in Alerts())
        {
            if (y > bottom - 10) break;
            _screen.Put(left, y++, Screen.Clip(alert, width), Tone.Warn);
        }

        if (Warning is { Count: > 0 } warning && bottom - y > warning.Count + 8)
        {
            _screen.Box(left, y, width, warning);
            y += warning.Count + 2;
            y++;
        }
        else if (WarningLine.Length > 0)
        {
            _screen.Put(left, y++, Screen.Clip(WarningLine, width), Tone.Warn);
            y++;
        }

        int footer = bottom;
        int remaining = footer - 1 - y;
        if (remaining < 6) { DrawFooter(left, width, footer); return; }

        int errorBlock = Math.Clamp(remaining / 3, 4, 9);
        int detectionBlock = remaining - errorBlock - 1;
        if (detectionBlock < 3) { detectionBlock = remaining - 1; errorBlock = 0; }

        y = DrawDetections(left, width, y, detectionBlock);
        if (errorBlock > 0) DrawErrors(left, width, y, errorBlock);

        DrawFooter(left, width, footer);
    }

    public IReadOnlyList<string> Alerts()
    {
        var alerts = new List<string>();
        if (CloudEnabled && Cloud == "unavailable")
            alerts.Add("!  The cloud did not answer - detections below were not confirmed.");
        if (Unverified > 0)
            alerts.Add($"!  {Unverified} detection(s) could not be confirmed by the cloud "
                       + "and may be false positives.");
        return alerts;
    }

    private int DrawDetections(int left, int width, int y, int rows)
    {
        int nameWidth = 22;
        int methodWidth = 14;
        int timeWidth = 19;
        int fileWidth = Math.Max(12, width - nameWidth - methodWidth - timeWidth - 3);

        _screen.Put(left, y, "INFECTION".PadRight(nameWidth + 1)
                             + "FILE".PadRight(fileWidth + 1)
                             + "METHOD".PadRight(methodWidth + 1) + "DATE", Tone.Dim);
        y++;
        _screen.Rule(left, y++, width);

        int body = rows - 2;
        var items = Detections;
        int skip = Math.Max(0, items.Count - body);
        for (int i = 0; i < body; i++)
        {
            int index = skip + i;
            if (index >= items.Count)
            {
                if (i == 0 && items.Count == 0)
                    _screen.Put(left, y, Finished ? "No threats detected." : "Nothing found so far.",
                                Finished ? Tone.Info : Tone.Dim);
                y++;
                continue;
            }

            var d = items[index];
            var tone = d.Name.StartsWith("Heur", StringComparison.OrdinalIgnoreCase)
                ? Tone.Heuristic : Tone.Threat;
            _screen.Put(left, y, Screen.Clip(d.Name, nameWidth).PadRight(nameWidth + 1), tone);
            _screen.Put(left + nameWidth + 1, y,
                        Screen.ClipPath(d.File, fileWidth).PadRight(fileWidth + 1), tone);
            _screen.Put(left + nameWidth + fileWidth + 2, y,
                        Screen.Clip(d.Method, methodWidth).PadRight(methodWidth + 1), Tone.Dim);
            _screen.Put(left + nameWidth + fileWidth + methodWidth + 3, y,
                        d.When.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture), Tone.Dim);
            y++;
        }

        return y;
    }

    private void DrawErrors(int left, int width, int y, int rows)
    {
        _screen.Put(left, y++, "ERRORS:", Tone.Dim);
        _screen.Rule(left, y++, width);

        int body = rows - 2;
        var items = ErrorLines;
        int skip = Math.Max(0, items.Count - body);
        for (int i = 0; i < body; i++)
        {
            int index = skip + i;
            if (index >= items.Count)
            {
                if (i == 0 && items.Count == 0) _screen.Put(left, y, "none", Tone.Dim);
                y++;
                continue;
            }
            _screen.Put(left, y++, Screen.Clip(items[index], width), Tone.Warn);
        }
    }

    private void DrawFooter(int left, int width, int y)
    {
        _screen.Rule(left, y - 1, width);
        if (Finished)
        {
            _screen.Put(left, y, "[S] save report    [ENTER] continue", Tone.Info);
            return;
        }
        _screen.Put(left, y, "STOP SCAN - [Q]", Tone.Info);
        string hint = "Ctrl+C is blocked while a scan is running";
        if (width > hint.Length + 20) _screen.Put(left + width - hint.Length, y, hint, Tone.Dim);
    }

    private void DrawPlain()
    {
        string text = $"{Mode} | {Stage} | "
                      + (Counting && !Finished
                          ? $"found {Total}"
                          : $"scanned {Scanned}" + (Total > 0 ? "/" + Total : ""))
                      + $" | threats {Infections} | errors {Errors} | "
                      + Percent.ToString("F1", CultureInfo.InvariantCulture) + "%";
        if (text == _lastPlain) return;
        _lastPlain = text;
        _screen.Output.WriteLine(text);
    }
}
