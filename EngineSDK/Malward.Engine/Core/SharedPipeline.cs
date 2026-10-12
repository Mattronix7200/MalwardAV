namespace Malward.Engine.Core;

public static class SharedPipeline
{
    public static Action<string, string>? Log { get; set; }

    private static ScanPipeline? _pipeline;
    private static DateTime _nextAttemptUtc = DateTime.MinValue;
    private static int _failures;
    private static readonly object Gate = new();

    public static int FailureCount { get { lock (Gate) return _failures; } }

    public static ScanPipeline? Get()
    {
        var p = _pipeline;
        if (p != null) return p;

        lock (Gate)
        {
            if (_pipeline != null) return _pipeline;
            if (DateTime.UtcNow < _nextAttemptUtc) return null;

            try
            {
                _pipeline = new ScanPipeline(Config.Settings.Load());
                if (_failures > 0) Log?.Invoke("Silnik", $"Silnik odbudowany po {_failures} nieudanych próbach.");
                _failures = 0;
                return _pipeline;
            }
            catch (Exception ex)
            {
                _failures++;
                var wait = TimeSpan.FromSeconds(Math.Min(60, 5 * _failures));
                _nextAttemptUtc = DateTime.UtcNow + wait;
                Log?.Invoke("Silnik", $"Nie udało się uruchomić silnika w procesie " +
                                      $"(próba {_failures}, ponowię za {wait.TotalSeconds:F0} s): {ex.Message}");
                return null;
            }
        }
    }

    public static DetectionResult? Scan(string path)
    {
        try
        {
            if (string.IsNullOrEmpty(path) || !File.Exists(path)) return null;
            var pipe = Get();
            return pipe?.ScanRealtime(path);
        }
        catch (Exception ex)
        {
            Log?.Invoke("Engine", $"scan {path}: {ex.Message}");
            return null;
        }
    }

    private static Repair.Repairer? _repairer;

    public static Repair.RepairOutcome? Repair(DetectionResult r)
    {
        try
        {
            _repairer ??= new Repair.Repairer(Config.Settings.Load());
            lock (_repairer) return _repairer.Repair(r);
        }
        catch (Exception ex)
        {
            Log?.Invoke("Repair", $"repair {r.Path}: {ex.Message}");
            return null;
        }
    }

    public static string? ScanFile(string path)
    {
        try
        {
            if (string.IsNullOrEmpty(path) || !File.Exists(path)) return null;
            var pipe = Get();
            if (pipe == null) return null;

            var r = pipe.ScanRealtime(path);
            if (r.Verdict != Verdict.Malware) return null;
            return string.IsNullOrEmpty(r.Detection) ? "Malware" : r.Detection;
        }
        catch (Exception ex)
        {
            Log?.Invoke("Engine", $"scan {path}: {ex.Message}");
            return null;
        }
    }
}
