using System.Text;

namespace Malward.Engine.Util;

public sealed class StatusBar : IDisposable
{
    private readonly object _lock = new();
    private readonly bool _interactive;
    private readonly bool _machine;
    private string _state = "";
    private int _done;
    private int _total;
    private string _file = "";
    private string _lastEmittedFile = "";
    private bool _hasBar;
    private long _lastEmitTicks;
    private long _windowStartTicks;
    private int _windowEmits;
    private const long WindowMs = 100;
    private const int BurstPerWindow = 25;

    public StatusBar()
    {
        _machine = Environment.GetEnvironmentVariable("MALWARD_MACHINE_OUTPUT") == "1";
        _interactive = !_machine && !Console.IsOutputRedirected;
        if (_interactive)
        {
            try { Console.OutputEncoding = Encoding.UTF8; } catch { }
        }
        else if (_machine)
        {
            try { Console.OutputEncoding = Encoding.UTF8; } catch { }
        }
    }

    private readonly List<(string Name, double Start, double End)> _bands = new();
    private double _bandStart, _bandEnd = 100.0;
    private long _doneGlobal, _totalGlobal;

    public void SetStagePlan(IEnumerable<(string Name, double Weight)> stages)
    {
        lock (_lock)
        {
            _bands.Clear();
            var list = stages.Where(x => x.Weight > 0).ToList();
            double sum = list.Sum(x => x.Weight);
            if (sum <= 0) return;
            double at = 0;
            foreach (var (name, w) in list)
            {
                double span = 100.0 * w / sum;
                _bands.Add((name, at, at + span));
                at += span;
            }
            _bandStart = 0;
            _bandEnd = _bands[0].End;
        }
    }

    public void BeginStage(string name, int total = 0)
    {
        lock (_lock)
        {
            foreach (var b in _bands)
                if (b.Name == name) { _bandStart = b.Start; _bandEnd = b.End; break; }
            _state = name;
            _total = Math.Max(0, total);
            _done = 0;
            _totalGlobal += _total;
            _hasBar = false;
        }
        Render();
    }

    public void CompleteStage()
    {
        lock (_lock) { _done = _total; _hasBar = false; }
        Render();
    }

    public void SetTotal(int total)
    {
        lock (_lock)
        {
            _totalGlobal += Math.Max(0, total) - _total;
            _total = Math.Max(0, total);
            _done = 0;
        }
        Render();
    }

    public void Step(string file = "")
    {
        lock (_lock) { _done++; _doneGlobal++; if (!string.IsNullOrEmpty(file)) _file = file; }
        Render();
    }

    public void State(string state, string? file = null)
    {
        lock (_lock) { _state = state; if (file != null) _file = file; }
        Render();
    }

    public void Log(string line)
    {
        lock (_lock)
        {
            if (_machine) { Console.WriteLine(line); return; }
            ClearBar();
            Console.WriteLine(line);
            DrawBar();
        }
    }

    public void LogError(string line)
    {
        lock (_lock)
        {
            if (_machine) { Console.Error.WriteLine(line); return; }
            ClearBar();
            Console.Error.WriteLine(line);
            DrawBar();
        }
    }

    public void Render()
    {
        lock (_lock)
        {
            if (_machine)
            {
                EmitMachine();
                return;
            }
            ClearBar();
            DrawBar();
        }
    }

    private void EmitMachine()
    {
        long now = Environment.TickCount64;
        bool fileChanged = !string.Equals(_file, _lastEmittedFile, StringComparison.Ordinal);

        if (fileChanged)
        {
            if (now - _windowStartTicks >= WindowMs) { _windowStartTicks = now; _windowEmits = 0; }
            if (_windowEmits >= BurstPerWindow && now - _lastEmitTicks < 100 && _hasBar) return;
            _windowEmits++;
        }
        else if (now - _lastEmitTicks < 100 && _hasBar) return;

        _lastEmitTicks = now;
        _lastEmittedFile = _file;
        _hasBar = true;

        double local = _total > 0 ? (double)_done / _total : 0.0;
        if (local > 1.0) local = 1.0;
        double pct = _bands.Count > 0
            ? _bandStart + (_bandEnd - _bandStart) * local
            : (_total > 0 ? 100.0 * _done / _total : 0.0);
        long doneOut  = _bands.Count > 0 ? _doneGlobal : _done;
        long totalOut = _bands.Count > 0 ? Math.Max(_totalGlobal, _doneGlobal) : _total;

        string s = (_state ?? "").Replace("\t", " ").Replace("\n", " ").Replace("\r", " ");
        string f = (_file ?? "").Replace("\t", " ").Replace("\n", " ").Replace("\r", " ");

        Console.Out.WriteLine(FormattableString.Invariant(
            $"PROGRESS\tdone={doneOut}\ttotal={totalOut}\tpct={pct:F1}\tstate={s}\tfile={f}"));
        Console.Out.Flush();
    }

    public void Clear()
    {
        lock (_lock)
        {
            ClearBar();
            _hasBar = false;
        }
    }

    public void ForceFinalRender()
    {
        lock (_lock)
        {
            _done = _total;
            _lastEmitTicks = 0;
            if (_machine) EmitMachine();
            else { ClearBar(); DrawBar(); }
        }
    }

    private void ClearBar()
    {
        if (!_interactive || !_hasBar) return;

        Console.Write("\r\x1b[2K");
        _hasBar = false;
    }

    private void DrawBar()
    {
        if (!_interactive) return;
        var bar = BuildBar();
        if (string.IsNullOrEmpty(bar)) return;
        Console.Write(bar);
        _hasBar = true;
    }

    private string BuildBar()
    {
        var sb = new StringBuilder();
        if (_total > 0)
        {
            double pct = _total > 0 ? (100.0 * _done / _total) : 0;
            sb.Append($"[{_done}/{_total} {pct,5:F1}%] ");
        }
        if (!string.IsNullOrEmpty(_state)) sb.Append(_state).Append(": ");
        if (!string.IsNullOrEmpty(_file))
        {
            var f = _file.Length > 60 ? "..." + _file[^57..] : _file;
            sb.Append(f);
        }

        int max;
        try { max = Math.Max(20, Console.WindowWidth - 1); }
        catch { max = 120; }
        if (sb.Length > max) sb.Length = max;
        return sb.ToString();
    }

    public void Dispose() => Clear();
}
